# JDownloader → Jellyfin Automation Stack

Web-GUI:
- URL eingeben (z. B. YouTube)
- Download über MyJDownloader
- MD5 erzeugen
- Upload per SFTP zur Jellyfin-VM
- MD5-Verifikation
- Cleanup in JDownloader

## Start
```bash
docker compose up -d --build
