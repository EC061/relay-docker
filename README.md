# tunnel-relay — autossh reverse tunnels + WebGUI

Single Docker container that runs your `autossh -R` reverse tunnels (replacement
for LXD `systemd` units like `uga-tunnel-us/cn.service`) with a tiny web UI.

**No tunnel details are baked into the image or repo.**
Everything is filled in from the WebGUI and stored in `./data/`:
- tunnels/jump hosts/forwards → `./data/tunnels.json`
- private keys → `./data/keys/` (chmod 600)
- logs → `./data/logs/`

## Deploy

Edit `GUI_PASS` inside `docker-compose.yml`, then:

```bash
docker compose up -d
# open http://host:8080  (login with GUI_USER/GUI_PASS from the yml)
```

Then in the WebGUI:
1. `Keys` → paste your private key content, save as e.g. `tunnel_key`.
   It lands at `/data/keys/<name>` with mode 600.
2. `Tunnels` → `+ New tunnel` (or edit the `example` placeholder):
   - jump user/host/port
   - pick the key file
   - add `-R` forwards as rows: `remote_port → target_host:target_port`
   - `Save` (auto-restarts if running)
3. `Start` / `Verify remote` / tail logs from the dashboard.

Config survives restarts via the `./data` volume.

## Build locally (optional)

```bash
docker compose -f docker-compose.build.yml up -d --build
```

Prebuilt images are published by GitHub Action to `ghcr.io/EC061/relay-docker:latest`
on every push to `main`.

## Files

- `app.py` — Flask UI + autossh process manager
- `Dockerfile` — python-slim + autossh + openssh-client
- `defaults/tunnels.json` — generic placeholder, copied to `/data` on first boot only
- `data/` — gitignored runtime state (your real hosts/keys live here, never committed)
