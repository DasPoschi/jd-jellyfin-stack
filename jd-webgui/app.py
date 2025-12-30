#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import myjdapi
import paramiko
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# ============================================================
# Environment
# ============================================================
MYJD_EMAIL = os.environ.get("MYJD_EMAIL", "")
MYJD_PASSWORD = os.environ.get("MYJD_PASSWORD", "")
MYJD_DEVICE = os.environ.get("MYJD_DEVICE", "")

JELLYFIN_HOST = os.environ.get("JELLYFIN_HOST", "192.168.1.1")
JELLYFIN_PORT = int(os.environ.get("JELLYFIN_PORT", "22"))
JELLYFIN_USER = os.environ.get("JELLYFIN_USER", "")
JELLYFIN_SSH_KEY = os.environ.get("JELLYFIN_SSH_KEY", "/ssh/id_ed25519")

# Optional: getrennte Ziele für Filme/Serien
JELLYFIN_MOVIES_DIR = os.environ.get("JELLYFIN_MOVIES_DIR", "").rstrip("/")
JELLYFIN_SERIES_DIR = os.environ.get("JELLYFIN_SERIES_DIR", "").rstrip("/")

# Fallback-Ziel (wenn movies/series nicht gesetzt)
JELLYFIN_DEST_DIR = os.environ.get("JELLYFIN_DEST_DIR", "/srv/media/movies/inbox").rstrip("/")

# Auth (optional)
BASIC_AUTH_USER = os.environ.get("BASIC_AUTH_USER", "")
BASIC_AUTH_PASS = os.environ.get("BASIC_AUTH_PASS", "")

POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "5"))

# JDownloader speichert im Container nach /output
JD_OUTPUT_PATH = "/output"

URL_RE = re.compile(r"^https?://", re.I)

# gängige Videoformate
VIDEO_EXTS = {
    ".mkv", ".mp4", ".m4v", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".ts", ".m2ts", ".mts", ".mpg", ".mpeg", ".vob", ".ogv",
    ".3gp", ".3g2"
}
IGNORE_EXTS = {".part", ".tmp", ".crdownload"}

# Serien-Heuristik (S01E02 etc.)
SERIES_RE = re.compile(r"(?:^|[^a-z0-9])S(\d{1,2})E(\d{1,2})(?:[^a-z0-9]|$)", re.IGNORECASE)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# ============================================================
# Basic Auth (optional)
# ============================================================
def _auth_enabled() -> bool:
    return bool(BASIC_AUTH_USER and BASIC_AUTH_PASS)

def _check_basic_auth(req: Request) -> bool:
    if not _auth_enabled():
        return True
    hdr = req.headers.get("authorization", "")
    if not hdr.lower().startswith("basic "):
        return False
    b64 = hdr.split(" ", 1)[1].strip()
    try:
        raw = base64.b64decode(b64).decode("utf-8", "replace")
    except Exception:
        return False
    if ":" not in raw:
        return False
    user, pw = raw.split(":", 1)
    return user == BASIC_AUTH_USER and pw == BASIC_AUTH_PASS

def _auth_challenge() -> HTMLResponse:
    return HTMLResponse(
        "Authentication required",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="jd-webgui"'},
    )

@app.middleware("http")
async def basic_auth_middleware(request: Request, call_next):
    if not _check_basic_auth(request):
        return _auth_challenge()
    return await call_next(request)

# ============================================================
# Models / State
# ============================================================
@dataclass
class Job:
    id: str
    url: str
    package_name: str
    library: str  # movies|series|auto
    status: str   # queued|collecting|downloading|upload|finished|failed
    message: str

jobs: Dict[str, Job] = {}
lock = threading.Lock()

# ============================================================
# Helpers
# ============================================================
def ensure_env():
    missing = []
    for k, v in [
        ("MYJD_EMAIL", MYJD_EMAIL),
        ("MYJD_PASSWORD", MYJD_PASSWORD),
        ("MYJD_DEVICE", MYJD_DEVICE),
        ("JELLYFIN_USER", JELLYFIN_USER),
        ("JELLYFIN_SSH_KEY", JELLYFIN_SSH_KEY),
    ]:
        if not v:
            missing.append(k)
    # Zielverzeichnisse: entweder MOVIES/SERIES oder DEST
    if not (JELLYFIN_DEST_DIR or (JELLYFIN_MOVIES_DIR and JELLYFIN_SERIES_DIR)):
        missing.append("JELLYFIN_DEST_DIR or (JELLYFIN_MOVIES_DIR+JELLYFIN_SERIES_DIR)")
    if missing:
        raise RuntimeError("Missing env vars: " + ", ".join(missing))

def get_device():
    jd = myjdapi.myjdapi()
    jd.connect(MYJD_EMAIL, MYJD_PASSWORD)
    jd.getDevices()
    dev = jd.getDevice(name=MYJD_DEVICE)
    if dev is None:
        raise RuntimeError(f"MyJDownloader device not found: {MYJD_DEVICE}")
    return dev

def is_video_file(path: str) -> bool:
    name = os.path.basename(path).lower()
    _, ext = os.path.splitext(name)
    if ext in IGNORE_EXTS:
        return False
    return ext in VIDEO_EXTS

def md5_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def write_md5_sidecar(file_path: str, md5_hex: str) -> str:
    md5_path = file_path + ".md5"
    with open(md5_path, "w", encoding="utf-8") as f:
        f.write(f"{md5_hex}  {os.path.basename(file_path)}\n")
    return md5_path

def ffprobe_ok(path: str) -> bool:
    """
    Validiert, dass die Datei wirklich ein Video ist (Container/Streams lesbar).
    Erfordert ffprobe im Container (kommt über Dockerfile).
    """
    try:
        cp = subprocess.run(
            ["ffprobe", "-v", "error", "-show_streams", "-select_streams", "v:0", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        return cp.returncode == 0 and "codec_type=video" in (cp.stdout or "")
    except Exception:
        return False

def ssh_connect() -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=JELLYFIN_HOST,
        port=JELLYFIN_PORT,
        username=JELLYFIN_USER,
        key_filename=JELLYFIN_SSH_KEY,
        timeout=30,
    )
    return ssh

def sftp_mkdirs(sftp: paramiko.SFTPClient, remote_dir: str):
    parts = [p for p in remote_dir.split("/") if p]
    cur = ""
    for p in parts:
        cur += "/" + p
        try:
            sftp.stat(cur)
        except IOError:
            sftp.mkdir(cur)

def sftp_upload(ssh: paramiko.SSHClient, local_path: str, remote_path: str):
    sftp = ssh.open_sftp()
    try:
        sftp_mkdirs(sftp, os.path.dirname(remote_path))
        sftp.put(local_path, remote_path)
    finally:
        sftp.close()

def remote_md5sum(ssh: paramiko.SSHClient, remote_path: str) -> str:
    quoted = shlex.quote(remote_path)
    cmd = f"md5sum {quoted}"
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=120)
    out = stdout.read().decode("utf-8", "replace").strip()
    err = stderr.read().decode("utf-8", "replace").strip()
    if err and not out:
        raise RuntimeError(f"Remote md5sum failed: {err}")
    if not out:
        raise RuntimeError("Remote md5sum returned empty output")
    return out.split()[0]

def pick_library_target(library_choice: str, filename: str, package_name: str) -> str:
    """
    - library_choice: movies|series|auto
    - auto: heuristic SxxEyy in filename or package
    """
    if library_choice not in {"movies", "series", "auto"}:
        library_choice = "auto"

    if library_choice == "auto":
        if SERIES_RE.search(filename) or SERIES_RE.search(package_name or ""):
            library_choice = "series"
        else:
            library_choice = "movies"

    if library_choice == "movies" and JELLYFIN_MOVIES_DIR:
        return JELLYFIN_MOVIES_DIR
    if library_choice == "series" and JELLYFIN_SERIES_DIR:
        return JELLYFIN_SERIES_DIR

    # fallback
    return JELLYFIN_DEST_DIR

def query_links_and_packages(dev, jobid: str) -> Tuple[List[Dict[str, Any]], Dict[Any, Dict[str, Any]]]:
    links = dev.downloads.query_links([{
        "jobUUIDs": [int(jobid)] if jobid.isdigit() else [jobid],
        "maxResults": -1,
        "startAt": 0,
        "name": True,
        "finished": True,
        "running": True,
        "status": True,
        "packageUUID": True,
        "uuid": True,
    }])

    pkg_ids = sorted({l.get("packageUUID") for l in links if l.get("packageUUID") is not None})
    pkgs = dev.downloads.query_packages([{
        "packageUUIDs": pkg_ids,
        "maxResults": -1,
        "startAt": 0,
        "saveTo": True,
        "uuid": True,
        "finished": True,
        "running": True,
    }]) if pkg_ids else []
    pkg_map = {p.get("uuid"): p for p in pkgs}
    return links, pkg_map

def local_paths_from_links(links: List[Dict[str, Any]], pkg_map: Dict[Any, Dict[str, Any]]) -> List[str]:
    paths: List[str] = []
    for l in links:
        name = l.get("name")
        if not name:
            continue
        pkg = pkg_map.get(l.get("packageUUID"))
        save_to = pkg.get("saveTo") if pkg else None
        base = save_to if isinstance(save_to, str) else JD_OUTPUT_PATH
        paths.append(os.path.join(base, name))

    # dedupe
    out, seen = [], set()
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

def try_remove_from_jd(dev, links: List[Dict[str, Any]], pkg_map: Dict[Any, Dict[str, Any]]) -> Optional[str]:
    """
    Best effort removal. Wrapper/API version differences exist.
    """
    link_ids = [l.get("uuid") for l in links if l.get("uuid") is not None]
    pkg_ids = list(pkg_map.keys())

    # Try several known method names & payload styles
    candidates = [
        ("downloads", "removeLinks"),
        ("downloads", "remove_links"),
        ("downloads", "deleteLinks"),
        ("downloads", "delete_links"),
        ("downloadcontroller", "removeLinks"),
        ("downloadcontroller", "remove_links"),
    ]

    payloads = [
        {"linkUUIDs": link_ids, "packageUUIDs": pkg_ids},
        {"linkIds": link_ids, "packageIds": pkg_ids},
        {"linkUUIDs": link_ids},
        {"packageUUIDs": pkg_ids},
    ]

    for ns, fn in candidates:
        obj = getattr(dev, ns, None)
        if obj is None:
            continue
        meth = getattr(obj, fn, None)
        if meth is None:
            continue
        for payload in payloads:
            try:
                meth([payload])  # most wrappers expect list
                return None
            except Exception:
                continue

    return "JDownloader-API: Paket/Links konnten nicht entfernt werden (Wrapper-Methoden nicht vorhanden)."

# ============================================================
# Worker
# ============================================================
def worker(jobid: str):
    try:
        ensure_env()
        dev = get_device()

        while True:
            with lock:
                job = jobs.get(jobid)
            if not job:
                return

            links, pkg_map = query_links_and_packages(dev, jobid)

            if not links:
                with lock:
                    job.status = "collecting"
                    job.message = "Warte auf Link-Crawler…"
                time.sleep(POLL_SECONDS)
                continue

            all_finished = all(bool(l.get("finished")) for l in links)
            if not all_finished:
                with lock:
                    job.status = "downloading"
                    done = sum(1 for l in links if l.get("finished"))
                    job.message = f"Download läuft… ({done}/{len(links)} fertig)"
                time.sleep(POLL_SECONDS)
                continue

            local_paths = local_paths_from_links(links, pkg_map)
            video_files = [p for p in local_paths if is_video_file(p) and os.path.isfile(p)]

            if not video_files:
                with lock:
                    job.status = "failed"
                    job.message = "Keine Video-Datei gefunden (Whitelist)."
                return

            # ffprobe validation (only keep valid videos)
            valid_videos = [p for p in video_files if ffprobe_ok(p)]
            if not valid_videos:
                with lock:
                    job.status = "failed"
                    job.message = "ffprobe: keine gültige Video-Datei (oder ffprobe fehlt)."
                return

            with lock:
                job.status = "upload"
                job.message = f"Download fertig. MD5/Upload/Verify für {len(valid_videos)} Datei(en)…"

            ssh = ssh_connect()
            try:
                for f in valid_videos:
                    fn = os.path.basename(f)
                    target_dir = pick_library_target(job.library, fn, job.package_name)
                    remote_file = f"{target_dir}/{fn}"
                    remote_md5f = remote_file + ".md5"

                    # MD5 local
                    md5_hex = md5_file(f)
                    md5_path = write_md5_sidecar(f, md5_hex)

                    # Upload file + md5
                    sftp_upload(ssh, f, remote_file)
                    sftp_upload(ssh, md5_path, remote_md5f)

                    # Verify remote
                    remote_md5 = remote_md5sum(ssh, remote_file)
                    if remote_md5.lower() != md5_hex.lower():
                        raise RuntimeError(f"MD5 mismatch for {fn}: local={md5_hex} remote={remote_md5}")

                    # Cleanup local after successful verify
                    try:
                        os.remove(f)
                    except Exception:
                        pass
                    try:
                        os.remove(md5_path)
                    except Exception:
                        pass

            finally:
                ssh.close()

            # Cleanup JD package/links (best effort)
            jd_cleanup_msg = try_remove_from_jd(dev, links, pkg_map)

            with lock:
                job.status = "finished"
                job.message = "Upload + MD5 OK. " + (jd_cleanup_msg or "JDownloader: Paket/Links entfernt.")
            return

    except Exception as e:
        with lock:
            job = jobs.get(jobid)
            if job:
                job.status = "failed"
                job.message = str(e)

# ============================================================
# Web
# ============================================================
def render_page(error: str = "") -> str:
    rows = ""
    with lock:
        job_list = list(jobs.values())[::-1]
    for j in job_list:
        rows += (
            f"<tr>"
            f"<td><code>{j.id}</code></td>"
            f"<td style='max-width:560px; word-break:break-all;'>{j.url}</td>"
            f"<td>{j.package_name}</td>"
            f"<td>{j.library}</td>"
            f"<td><b>{j.status}</b><br/><small>{j.message}</small></td>"
            f"</tr>"
        )

    err_html = f"<p class='error'>{error}</p>" if error else ""
    auth_note = "aktiv" if _auth_enabled() else "aus"
    return f"""
    <html>
    <head>
      <link rel="stylesheet" href="/static/style.css">
      <meta charset="utf-8">
      <title>JD → Jellyfin</title>
    </head>
    <body>
      <h1>JD → Jellyfin</h1>
      {err_html}

      <form method="post" action="/submit">
        <div class="row">
          <label>Link</label><br/>
          <input name="url" placeholder="https://..." required />
        </div>
        <div class="row">
          <label>Paketname (optional)</label><br/>
          <input name="package_name" placeholder="z. B. Sister Act (1992)" />
        </div>
        <div class="row">
          <label>Ziel</label><br/>
          <select name="library">
            <option value="auto">auto</option>
            <option value="movies">movies</option>
            <option value="series">series</option>
          </select>
        </div>
        <button type="submit">Download starten</button>
      </form>

      <p class="hint">
        Auth: <b>{auth_note}</b> |
        JD Output: <code>{JD_OUTPUT_PATH}</code> |
        Video-Whitelist: {", ".join(sorted(VIDEO_EXTS))}
      </p>

      <table>
        <thead>
          <tr><th>JobID</th><th>URL</th><th>Paket</th><th>Ziel</th><th>Status</th></tr>
        </thead>
        <tbody>
          {rows if rows else "<tr><td colspan='5'><em>No jobs yet.</em></td></tr>"}
        </tbody>
      </table>
    </body>
    </html>
    """

@app.get("/", response_class=HTMLResponse)
def index():
    try:
        ensure_env()
        return HTMLResponse(render_page())
    except Exception as e:
        return HTMLResponse(render_page(str(e)), status_code=400)

@app.post("/submit")
def submit(url: str = Form(...), package_name: str = Form(""), library: str = Form("auto")):
    ensure_env()
    url = url.strip()
    package_name = (package_name or "").strip() or "WebGUI"
    library = (library or "auto").strip().lower()

    if not URL_RE.match(url):
        return HTMLResponse(render_page("Nur http(s) URLs erlaubt."), status_code=400)

    dev = get_device()
    resp = dev.linkgrabber.add_links([{
        "links": url,
        "autostart": True,
        "assignJobID": True,
        "packageName": package_name,
    }])

    jobid = str(resp.get("id", ""))
    if not jobid:
        return HTMLResponse(render_page(f"Unerwartete Antwort von add_links: {resp}"), status_code=500)

    with lock:
        jobs[jobid] = Job(
            id=jobid,
            url=url,
            package_name=package_name,
            library=library,
            status="queued",
            message="Download gestartet",
        )

    t = threading.Thread(target=worker, args=(jobid,), daemon=True)
    t.start()

    return RedirectResponse(url="/", status_code=303)
