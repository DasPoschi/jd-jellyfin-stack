# JD → Jellyfin WebGUI (Docker)

Web GUI to:
- paste a URL (e.g. YouTube)
- download via **MyJDownloader**
- validate video with **ffprobe**
- compute **MD5** locally, upload via **SFTP**
- verify **MD5** on the Jellyfin VM
- cleanup local file + remove JD package/links (best effort)
- optional: **TMDB naming**, **movie/series folders**, **Jellyfin library refresh**

## Files
- `docker-compose.yml` – stack
- `.env.example` – copy to `.env` and fill in your values (**never commit `.env`!**)
- `jd-webgui/app.py` – FastAPI web app
- `jd-webgui/Dockerfile` – includes ffprobe

## Setup
1. Copy env file:
```bash
cp .env.example .env
```

2. Edit `.env`:
- `MYJD_EMAIL`, `MYJD_PASSWORD`
- `JELLYFIN_HOST`, `JELLYFIN_USER`, target dirs
- `SSH_KEY_PATH` (absolute path on Docker host)
- Optional: `JELLYFIN_API_KEY`, `TMDB_API_KEY`

3. Start:
```bash
docker compose up -d --build
```

4. Open WebGUI:
- `http://<docker-host>:${WEBGUI_PORT}`

## Notes
- JDownloader must be logged into MyJDownloader and appear as an online device.
- If `MYJD_DEVICE` is empty, the WebGUI will automatically pick the first available device.
- Ensure the SSH user can write to `/jellyfin/Filme` (and series dir if used).

## Security
- **Never commit `.env`** – it contains passwords and API keys. Only `.env.example` is tracked.
- **SSH host key verification**: For secure SFTP transfers, provide a `known_hosts` file:
  ```bash
  ssh-keyscan -p 22 192.168.1.1 > known_hosts
  ```
  Mount it in `docker-compose.yml` and set `SSH_KNOWN_HOSTS=/ssh/known_hosts`.
  Without it, any host key is accepted (MITM risk on untrusted networks).
- **Basic Auth** protects the WebGUI but transmits credentials in cleartext over HTTP. Use a reverse proxy with HTTPS (e.g. Traefik, Caddy) in production.

## Troubleshooting
- Device not found: list devices
```bash
docker exec -it jd-webgui python -c "from myjdapi import Myjdapi; import os; jd=Myjdapi(); jd.connect(os.environ['MYJD_EMAIL'], os.environ['MYJD_PASSWORD']); jd.update_devices(); print([d.get('name') for d in jd.devices])"
```
- Check container can see downloads:
```bash
docker exec -it jd-webgui ls -la /output | head
```
