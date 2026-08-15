# HyperVM — Proxmox LXC + KVM control panel

Single-file Flask panel (backend, REST API, websocket console bridge and the whole
web UI live inside `hypervm.py`).

## Install

```bash
pip install -r hypervm-requirements.txt
```

## Configure

```bash
export PROXMOX_URL=https://192.168.1.10:8006
export PROXMOX_TOKEN_ID='admin@pam!hypervm'
export PROXMOX_TOKEN_SECRET=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export PROXMOX_VERIFY_TLS=false

# only needed for the interactive web console (Proxmox rejects API tokens there)
export PROXMOX_USER=root@pam
export PROXMOX_PASSWORD=super-secret

export HYPERVM_SECRET="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
export HYPERVM_HOST=0.0.0.0
export HYPERVM_PORT=8080
export HYPERVM_DB=hypervm.db
```

Setting `HYPERVM_SECRET` is important: without it a random key is generated on every
start and all sessions are dropped on restart.

## Run

```bash
python3 hypervm.py
# open http://127.0.0.1:8080
```

Default owner account: **admin / admin123** — change it in Settings immediately.

### Production

```bash
gunicorn -k gevent -w 1 -b 0.0.0.0:8080 hypervm:APP
```

Use one worker (or a sticky-session proxy): the console bridge and the in-memory
cache are per-process. Put nginx/Caddy in front for TLS.

## systemd

```ini
[Unit]
Description=HyperVM panel
After=network.target

[Service]
WorkingDirectory=/opt/hypervm
EnvironmentFile=/opt/hypervm/.env
ExecStart=/usr/bin/python3 /opt/hypervm/hypervm.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## What the panel does

- Dashboard: node/guest/memory/storage KPIs, node pressure, pandas insights
- Containers & VMs: search/filter, start, stop, reboot, console, CSV export
- Manage drawer: cores/memory/name edit, disk grow, snapshots (create, rollback,
  delete), backup, clone, migrate, destroy, raw config
- Create LXC and QEMU VMs (template/ISO, storage, network, cloud-init fields)
- Nodes, storage, cluster tasks, analytics, audit log with CSV export
- Users: roles (owner > admin > user), enable/disable, per-guest assignments,
  public registration toggle
- xterm.js console bridged to the Proxmox termproxy websocket

## Endpoints

`GET /` UI · `GET /api/health` · `GET /api/meta` · `/api/auth/*` · `/api/cluster` ·
`/api/nodes/*` · `/api/guest/<kind>/<node>/<vmid>/*` · `/api/create/lxc` ·
`/api/create/qemu` · `/api/users*` · `/api/audit*` · `/api/inventory.csv` ·
`/api/console/*` · `ws://…/ws/console/<token>`

## Notes

- The Proxmox token never reaches the browser.
- Passwords are PBKDF2-HMAC-SHA256, 310k iterations, per-user salt.
- Without `pandas` the panel still runs; the Analytics page degrades gracefully.
- Without `flask-sock` + `websocket-client` everything works except the web console.
