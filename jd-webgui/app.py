#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import time
import threading
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple

import myjdapi
import paramiko
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# ---- ENV ----
MYJD_EMAIL = os.environ.get("MYJD_EMAIL", "")
MYJD_PASSWORD = os.environ.get("MYJD_PASSWORD", "")
MYJD_DEVICE = os.environ.get("MYJD_DEVICE", "")

JELLYFIN_HOST = os.environ.get("JELLYFIN_HOST", "192.168.1.1")
JELLYFIN_PORT = int(os.environ.get("JELLYFIN_PORT", "22"))
JELLYFIN_USER = os.environ.get("JELLYFIN_USER", "")
JELLYFIN_DEST_DIR = os.environ.get("JELLYFIN_DEST_DIR", "/srv/media/movies/inbox").rstrip("/")
JELLYFIN_SSH_KEY = os.environ.get("JELLYFIN_SSH_KEY", "/ssh/id_ed25519")

POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "5"))

# JD speichert im Container nach /output (wie von dir angegeben)
JD_OUTPUT_PATH = "/output"

URL_RE = re.compile(r"^https?://", re.I)

# “Gängige Videoformate” (Whitelist; bei Bedarf erweitern)
VIDEO_EXTS = {
    ".mkv", ".mp4", ".m4v", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".ts", ".m2ts", ".mts", ".mpg", ".mpeg", ".vob", ".ogv",
    ".3gp", ".3g2"
}

# Optional: auch Container/Archive ignorieren
IGNORE_EXTS = {".part", ".tmp", ".crdownload"}

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")


@dataclass
class Job:
    id: str
    url: str
    package_name: str
    status: str
    message: str


jobs: Dict[str, Job] = {}
lock = threading.Lock()


def ensure_env():
    missing = []
    for k, v in [
        ("MYJD_EMAIL", MYJD_EMAIL),
        ("MYJD_PASSWORD", MYJD_PASSWORD),
        ("MYJD_DEVICE", MYJD_DEVICE),
        ("JELLYFIN_USER", JELLYFIN_USER),
        ("JELLYFIN_DEST_DIR", JELLYFIN_DEST_DIR),
        ("JELLYFIN_SSH_KEY", JELLYFIN_SSH_KEY),
    ]:
        if not v:
            missing.append(k)
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


def md5_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def write_md5_sidecar(file_path: str, md5_hex: str) -> str:
    md5_path = file_path + ".md5"
    with open(md5_path, "w", encoding="utf-8") as f:
        f.write(md5_hex + "  " + os.path.basename(file_path) + "\n")
    return md5_path


def sftp_mkdirs(sftp: paramiko.SFTPClient, remote_dir: str):
    parts = [p for p in remote_dir.split("/") if p]
    cur = ""
    for p in parts:
        cur += "/" + p
        try:
            sftp.stat(cur)
        except IOError:
            sftp.mkdir(cur)


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


def sftp_upload(ssh: paramiko.SSHClient, local_path: str, remote_path: str):
    sftp = ssh.open_sftp()
    try:
        sftp_mkdirs(sftp, os.path.dirname(remote_path))
        sftp.put(local_path, remote_path)
    finally:
        sftp.close()


def remote_md5sum(ssh: paramiko.SSHClient, remote_path: str) -> str:
    # md5sum "<file>" | awk '{print $1}'
    cmd = f"md5sum '{remote_path.replace(\"'\", \"'\\\\''\")}' | awk '{{print $1}}'"
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
    out = stdout.read().decode("utf-8", "replace").strip()
    err = stderr.read().decode("utf-8", "replace").strip()
    if not out or "No such file" in err:
        raise RuntimeError(f"Remote md5sum failed. out='{out}' err='{err}'")
    # md5sum may return: "<hash>  <file>"
    # but awk ensures hash only. Still, keep first token safe:
    return out.split()[0]


def is_video_file(path: str) -> bool:
    name = os.path.basename(path).lower()
    _, ext = os.path.splitext(name)
    if ext in IGNORE_EXTS:
        return False
    return ext in VIDEO_EXTS


def query_links_and_packages_by_jobid(dev, jobid: str) -> Tuple[List[Dict[str, Any]], Dict[Any, Dict[str, Any]]]:
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
    Best effort removal. Different JD API versions / wrappers expose different method names.
    We try a few. If none exist, return a message.
    """
    link_ids = [l.get("uuid") for l in links if l.get("uuid") is not None]
    pkg_ids = list(pkg_map.keys())

    candidates = [
        ("downloads", "remove_links"),
        ("downloads", "removeLinks"),
        ("downloads", "delete_links"),
        ("downloads", "deleteLinks"),
        ("downloadcontroller", "remove_links"),
        ("downloadcontroller", "removeLinks"),
    ]

    payload_variants = [
        {"linkIds": link_ids, "packageIds": pkg_ids},
        {"linkIds": link_ids},
        {"packageIds": pkg_ids},
        {"linkUUIDs": link_ids, "packageUUIDs": pkg_ids},
    ]

    for ns, fn in candidates:
        obj = getattr(dev, ns, None)
        if obj is None:
            continue
        meth = getattr(obj, fn, None)
        if meth is None:
            continue
        for payload in payload_variants:
            try:
                meth([payload] if not isinstance(payload, list) else payload)  # some wrappers expect list
                return None
            except Exception:
                continue

    return "Could not remove package/links via API (method not available in this wrapper). Local files were deleted."


def worker(jobid: str):
    try:
        ensure_env()
        dev = get_device()

        while True:
            links, pkg_map = query_links_and_packages_by_jobid(dev, jobid)
            if not links:
                with lock:
                    jobs[jobid].status = "collecting"
                    jobs[jobid].message = "Warte auf Link-Crawler…"
                time.sleep(POLL_SECONDS)
                continue

            all_finished = all(bool(l.get("finished")) for l in links)

            if not all_finished:
                with lock:
                    jobs[jobid].status = "downloading"
                    done = sum(1 for l in links if l.get("finished"))
                    jobs[jobid].message = f"Download läuft… ({done}/{len(links)} fertig)"
                time.sleep(POLL_SECONDS)
                continue

            # Download finished -> build local file list
            local_paths = local_paths_from_links(links, pkg_map)
            # Filter to video files only
            video_files = [p for p in local_paths if is_video_file(p)]

            if not video_files:
                with lock:
                    jobs[jobid].status = "failed"
                    jobs[jobid].message = "Keine Video-Datei gefunden (Whitelist)."
                return

            # Compute local MD5 and write sidecar
            md5_records: List[Tuple[str, str, str]] = []  # (file, md5, md5file)
            for f in video_files:
                if not os.path.isfile(f):
                    continue
                md5_hex = md5_file(f)
                md5_path = write_md5_sidecar(f, md5_hex)
                md5_records.append((f, md5_hex, md5_path))

            with lock:
                jobs[jobid].status = "upload"
                jobs[jobid].message = f"Download fertig. Upload {len(md5_records)} Datei(en) + MD5…"

            ssh = ssh_connect()
            try:
                # Upload each file + its .md5, verify md5 remote, then cleanup local
                for f, md5_hex, md5_path in md5_records:
                    remote_file = f"{JELLYFIN_DEST_DIR}/{os.path.basename(f)}"
                    remote_md5f = remote_file + ".md5"

                    sftp_upload(ssh, f, remote_file)
                    sftp_upload(ssh, md5_path, remote_md5f)

                    remote_md5 = remote_md5sum(ssh, remote_file)
                    if remote_md5.lower() != md5_hex.lower():
                        raise RuntimeError(
                            f"MD5 mismatch for {os.path.basename(f)}: local={md5_hex} remote={remote_md5}"
                        )

                    # Remote ok -> delete local file and local md5
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

            # Remove package/container in JD (best effort)
            msg = try_remove_from_jd(dev, links, pkg_map)

            with lock:
                jobs[jobid].status = "finished"
                jobs[jobid].message = "Upload + MD5 OK. " + (msg or "JDownloader: Paket/Links entfernt.")
            return

    except Exception as e:
        with lock:
            jobs[jobid].status = "failed"
            jobs[jobid].message = str(e)


@app.get("/", response_class=HTMLResponse)
def index():
    rows = ""
    with lock:
        for j in sorted(jobs.values(), key=lambda x: x.id, reverse=True):
            rows += (
                f"<tr><td><code>{j.id}</code></td>"
                f"<td style='max-width:680px; word-break:break-all;'>{j.url}</td>"
                f"<td>{j.package_name}</td>"
                f"<td><b>{j.status}</b><br/><small>{j.message}</small></td></tr>"
            )

    return f"""
    <html>
    <head>
      <link rel="stylesheet" href="/static/style.css">
      <meta charset="utf-8"/>
      <title>JD → Jellyfin</title>
    </head>
    <body>
    <h1>JD → Jellyfin</h1>

    <form method="post">
      <div>
        <input name="url" placeholder="https://..." size="90" required />
      </div>
      <div>
        <input name="package_name" placeholder="Paketname (optional)" size="90" />
      </div>
      <button type="submit">Download starten</button>
    </form>

    <p>Hinweis: JDownloader muss nach <code>/output</code> speichern und der Container muss <code>/output</code> mounten.</p>
    <p>Video-Whitelist: {", ".join(sorted(VIDEO_EXTS))}</p>

    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>JobID</th><th>URL</th><th>Paket</th><th>Status</th></tr>
      {rows if rows else "<tr><td colspan='4'><em>No jobs yet</em></td></tr>"}
    </table>
    </body></html>
    """


@app.post("/")
def submit(url: str = Form(...), package_name: str = Form("")):
    ensure_env()
    url = url.strip()
    if not URL_RE.match(url):
        return HTMLResponse("Nur http(s) URLs erlaubt", status_code=400)

    dev = get_device()
    package_name = (package_name or "").strip() or "WebGUI"

    resp = dev.linkgrabber.add_links([{
        "links": url,
        "autostart": True,
        "assignJobID": True,
        "packageName": package_name,
    }])

    jobid = str(resp.get("id", ""))
    if not jobid:
        return HTMLResponse(f"Unerwartete Antwort von add_links: {resp}", status_code=500)

    with lock:
        jobs[jobid] = Job(jobid, url, package_name, "queued", "Download gestartet")

    threading.Thread(target=worker, args=(jobid,), daemon=True).start()
    return RedirectResponse("/", status_code=303)
