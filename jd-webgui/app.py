#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from myjdapi import Myjdapi
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

JELLYFIN_MOVIES_DIR = os.environ.get("JELLYFIN_MOVIES_DIR", "").rstrip("/")
JELLYFIN_SERIES_DIR = os.environ.get("JELLYFIN_SERIES_DIR", "").rstrip("/")
JELLYFIN_DEST_DIR = os.environ.get("JELLYFIN_DEST_DIR", "/jellyfin/Filme").rstrip("/")

JELLYFIN_API_BASE = os.environ.get("JELLYFIN_API_BASE", "").rstrip("/")
JELLYFIN_API_KEY = os.environ.get("JELLYFIN_API_KEY", "")
JELLYFIN_LIBRARY_REFRESH = os.environ.get("JELLYFIN_LIBRARY_REFRESH", "false").lower() == "true"

TMDB_API_KEY = os.environ.get("TMDB_API_KEY", "")
TMDB_LANGUAGE = os.environ.get("TMDB_LANGUAGE", "de-DE")

CREATE_MOVIE_FOLDER = os.environ.get("CREATE_MOVIE_FOLDER", "true").lower() == "true"
CREATE_SERIES_FOLDERS = os.environ.get("CREATE_SERIES_FOLDERS", "true").lower() == "true"

MD5_DIR = os.environ.get("MD5_DIR", "/md5").rstrip("/")

BASIC_AUTH_USER = os.environ.get("BASIC_AUTH_USER", "")
BASIC_AUTH_PASS = os.environ.get("BASIC_AUTH_PASS", "")

POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "5"))

# JDownloader writes here inside container
JD_OUTPUT_PATH = "/output"

URL_RE = re.compile(r"^https?://", re.I)

VIDEO_EXTS = {
    ".mkv", ".mp4", ".m4v", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".ts", ".m2ts", ".mts", ".mpg", ".mpeg", ".vob", ".ogv",
    ".3gp", ".3g2",
}
IGNORE_EXTS = {".part", ".tmp", ".crdownload"}

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
# Core helpers
# ============================================================
def ensure_env():
    missing = []
    for k, v in [
        ("MYJD_EMAIL", MYJD_EMAIL),
        ("MYJD_PASSWORD", MYJD_PASSWORD),
        ("JELLYFIN_USER", JELLYFIN_USER),
        ("JELLYFIN_SSH_KEY", JELLYFIN_SSH_KEY),
    ]:
        if not v:
            missing.append(k)

    if not (JELLYFIN_DEST_DIR or (JELLYFIN_MOVIES_DIR and JELLYFIN_SERIES_DIR)):
        missing.append("JELLYFIN_DEST_DIR or (JELLYFIN_MOVIES_DIR+JELLYFIN_SERIES_DIR)")

    if JELLYFIN_LIBRARY_REFRESH and not (JELLYFIN_API_BASE and JELLYFIN_API_KEY):
        missing.append("JELLYFIN_API_BASE+JELLYFIN_API_KEY (required when JELLYFIN_LIBRARY_REFRESH=true)")

    if missing:
        raise RuntimeError("Missing env vars: " + ", ".join(missing))

def get_device():
    jd = Myjdapi()
    jd.connect(MYJD_EMAIL, MYJD_PASSWORD)

    # Try to retrieve device list across myjdapi versions
    devices = None

    # v1: update_devices() + attribute
    try:
        jd.update_devices()
        devices = getattr(jd, "devices", None)
    except Exception:
        devices = None

    # v2: list_devices() returns a list
    if devices is None:
        try:
            devices = jd.list_devices()
        except Exception:
            devices = None

    # v3: get_devices() / getDevices()
    if devices is None:
        for fn in ("get_devices", "getDevices"):
            try:
                devices = getattr(jd, fn)()
                break
            except Exception:
                continue

    if not devices:
        raise RuntimeError("No MyJDownloader devices available (JD online? correct credentials?)")

    # devices may be list[str] or list[dict]
    def dev_name(d):
        if isinstance(d, str):
            return d
        if isinstance(d, dict):
            return d.get("name") or d.get("deviceName") or d.get("id") or ""
        return ""

    names = [dev_name(d).strip() for d in devices]
    names = [n for n in names if n]

    if not names:
        raise RuntimeError(f"MyJDownloader returned devices but no names: {devices}")

    wanted = (MYJD_DEVICE or "").strip()
    if wanted:
        # exact match first
        for n in names:
            if n == wanted:
                return jd.get_device(n)
        # case-insensitive fallback
        for n in names:
            if n.lower() == wanted.lower():
                return jd.get_device(n)

    # Prefer "jdownloader" looking device
    for n in names:
        nl = n.lower()
        if "jdownloader" in nl or nl in {"jd", "jd2"}:
            return jd.get_device(n)

    # Otherwise first
    return jd.get_device(names[0])

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
    os.makedirs(MD5_DIR, exist_ok=True)
    base = os.path.basename(file_path)
    md5_path = os.path.join(MD5_DIR, base + ".md5")
    with open(md5_path, "w", encoding="utf-8") as f:
        f.write(f"{md5_hex}  {base}\n")
    return md5_path

def ffprobe_ok(path: str) -> bool:
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

# ============================================================
# SSH/SFTP
# ============================================================
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

# ============================================================
# TMDB & naming
# ============================================================
def _http_get_json(url: str, headers: Optional[Dict[str, str]] = None) -> Any:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

def tmdb_search_movie(query: str) -> Optional[Dict[str, Any]]:
    if not TMDB_API_KEY or not query.strip():
        return None
    q = urllib.parse.quote(query.strip())
    url = f"https://api.themoviedb.org/3/search/movie?api_key={TMDB_API_KEY}&language={urllib.parse.quote(TMDB_LANGUAGE)}&query={q}"
    data = _http_get_json(url)
    results = data.get("results") or []
    return results[0] if results else None

def tmdb_search_tv(query: str) -> Optional[Dict[str, Any]]:
    if not TMDB_API_KEY or not query.strip():
        return None
    q = urllib.parse.quote(query.strip())
    url = f"https://api.themoviedb.org/3/search/tv?api_key={TMDB_API_KEY}&language={urllib.parse.quote(TMDB_LANGUAGE)}&query={q}"
    data = _http_get_json(url)
    results = data.get("results") or []
    return results[0] if results else None

def sanitize_name(name: str) -> str:
    bad = '<>:"/\\|?*'
    out = "".join("_" if c in bad else c for c in name).strip()
    return re.sub(r"\s+", " ", out)

def pick_library_target(library_choice: str, filename: str, package_name: str) -> str:
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

    return JELLYFIN_DEST_DIR

def build_remote_paths(job_library: str, package_name: str, local_file: str) -> Tuple[str, str]:
    filename = os.path.basename(local_file)
    base_target = pick_library_target(job_library, filename, package_name)

    m = SERIES_RE.search(filename) or SERIES_RE.search(package_name or "")
    is_series = (job_library == "series") or (job_library == "auto" and m)

    if is_series:
        show_query = package_name or os.path.splitext(filename)[0]
        tv = tmdb_search_tv(show_query) if TMDB_API_KEY else None
        show_name = sanitize_name(tv["name"]) if tv and tv.get("name") else sanitize_name(show_query)

        season = int(m.group(1)) if m else 1
        episode = int(m.group(2)) if m else 1

        if CREATE_SERIES_FOLDERS:
            remote_dir = f"{base_target}/{show_name}/Season {season:02d}"
        else:
            remote_dir = base_target

        ext = os.path.splitext(filename)[1]
        remote_filename = f"{show_name} - S{season:02d}E{episode:02d}{ext}"
        return remote_dir, remote_filename

    movie_query = package_name or os.path.splitext(filename)[0]
    mv = tmdb_search_movie(movie_query) if TMDB_API_KEY else None
    title = mv.get("title") if mv else None
    date = mv.get("release_date") if mv else None
    year = date[:4] if isinstance(date, str) and len(date) >= 4 else None

    title_safe = sanitize_name(title) if title else sanitize_name(movie_query)
    year_safe = year if year else ""

    if CREATE_MOVIE_FOLDER:
        folder = f"{title_safe} ({year_safe})".strip() if year_safe else title_safe
        remote_dir = f"{base_target}/{folder}"
    else:
        remote_dir = base_target

    ext = os.path.splitext(filename)[1]
    remote_filename = f"{title_safe} ({year_safe}){ext}".strip() if year_safe else f"{title_safe}{ext}"
    return remote_dir, remote_filename

# ============================================================
# Jellyfin refresh (optional)
# ============================================================
def jellyfin_refresh_library():
    if not (JELLYFIN_API_BASE and JELLYFIN_API_KEY):
        return
    headers = {"X-MediaBrowser-Token": JELLYFIN_API_KEY}
    for path in ("/Library/Refresh", "/library/refresh"):
        try:
            url = JELLYFIN_API_BASE + path
            req = urllib.request.Request(url, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=20) as r:
                _ = r.read()
            return
        except Exception:
            continue

# ============================================================
# JDownloader queries/cleanup (best effort)
# ============================================================
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

    out, seen = [], set()
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

def try_remove_from_jd(dev, links: List[Dict[str, Any]], pkg_map: Dict[Any, Dict[str, Any]]) -> Optional[str]:
    link_ids = [l.get("uuid") for l in links if l.get("uuid") is not None]
    pkg_ids = list(pkg_map.keys())

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
                meth([payload])
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

            valid_videos = [p for p in video_files if ffprobe_ok(p)]
            if not valid_videos:
                with lock:
                    job.status = "failed"
                    job.message = "ffprobe: keine gültige Video-Datei."
                return

            with lock:
                job.status = "upload"
                job.message = f"Download fertig. MD5/Upload/Verify für {len(valid_videos)} Datei(en)…"

            ssh = ssh_connect()
            try:
                for f in valid_videos:
                    md5_hex = md5_file(f)
                    md5_path = write_md5_sidecar(f, md5_hex)

                    remote_dir, remote_name = build_remote_paths(job.library, job.package_name, f)
                    remote_file = f"{remote_dir}/{remote_name}"
                    remote_md5f = remote_file + ".md5"

                    sftp_upload(ssh, f, remote_file)
                    sftp_upload(ssh, md5_path, remote_md5f)

                    remote_md5 = remote_md5sum(ssh, remote_file)
                    if remote_md5.lower() != md5_hex.lower():
                        raise RuntimeError(f"MD5 mismatch for {os.path.basename(f)}: local={md5_hex} remote={remote_md5}")

                    # Cleanup local
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

            jd_cleanup_msg = try_remove_from_jd(dev, links, pkg_map)

            if JELLYFIN_LIBRARY_REFRESH:
                jellyfin_refresh_library()

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
@app.get("/favicon.ico")
def favicon():
    return HTMLResponse(status_code=204)

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
