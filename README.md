# JD → Jellyfin WebGUI (Docker)

Web-GUI:
- Link einfügen (z. B. YouTube)
- Remote Download via MyJDownloader
- nur gängige Videoformate (Whitelist)
- ffprobe-Validierung (echtes Video)
- MD5 lokal + Upload per SFTP + MD5-Verify auf Jellyfin-VM
- Cleanup: lokale Datei + lokale .md5 löschen
- Cleanup: JDownloader Paket/Links entfernen (best effort, abhängig vom API-Wrapper)

## Voraussetzungen
- Docker + Docker Compose
- JDownloader-Container (im Compose enthalten)
- Jellyfin läuft auf einer VM (Beispiel: 192.168.1.1)
- SSH-Zugang zur Jellyfin-VM
- Zielordner auf Jellyfin-VM existiert + Schreibrechte für SSH-User
- Auf Jellyfin-VM muss `md5sum` vorhanden sein (i. d. R. coreutils)

## Quickstart
1) Repo klonen oder Dateien anlegen
2) SSH Key vorhanden (empfohlen):
   - auf dem Docker-Host: `~/.ssh/id_ed25519`
   - Public Key auf Jellyfin-VM in `~/.ssh/authorized_keys` des Upload-Users

3) docker-compose.yml anpassen:
   - MYJD_EMAIL / MYJD_PASSWORD / MYJD_DEVICE
   - JELLYFIN_HOST / JELLYFIN_USER
   - JELLYFIN_MOVIES_DIR / JELLYFIN_SERIES_DIR
   - BASIC_AUTH_USER/PASS (optional)

4) Start:
```bash
docker compose up -d --build
