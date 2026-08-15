========================================
 HyperVM  -  Powered by HyperNET LTD
========================================

 A single-file, production-shaped Proxmox VE control panel that manages BOTH
 LXC containers and QEMU/KVM virtual machines, with a built-in web terminal
 console bridged directly to the Proxmox websocket API.

 Everything (backend, REST API, websocket console bridge, HTML, CSS and
 JavaScript front-end) lives inside this one Python file on purpose.

--------------------------------------------------------------------------------
 INSTALL
--------------------------------------------------------------------------------

     pip install flask flask-sock websocket-client requests pandas

--------------------------------------------------------------------------------
 RUN
--------------------------------------------------------------------------------

     python hypervm.py

     then open  http://127.0.0.1:8080

--------------------------------------------------------------------------------
 ENVIRONMENT
--------------------------------------------------------------------------------

     PROXMOX_URL=https://192.168.1.10:8006
     PROXMOX_TOKEN_ID=admin@pam!hypervm
     PROXMOX_TOKEN_SECRET=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     PROXMOX_VERIFY_TLS=false

     # Optional - only needed for the interactive console bridge, because
     # Proxmox refuses API-token authentication on /vncwebsocket.
     PROXMOX_USER=root@pam
     PROXMOX_PASSWORD=super-secret

     HYPERVM_SECRET=replace-with-a-long-random-secret
     HYPERVM_HOST=0.0.0.0
     HYPERVM_PORT=8080
     HYPERVM_DB=hypervm.db

--------------------------------------------------------------------------------
 DEFAULT OWNER ACCOUNT
--------------------------------------------------------------------------------

     username: admin
     password: admin123

     Change it immediately from Settings -> Security.

--------------------------------------------------------------------------------
 SECURITY MODEL
--------------------------------------------------------------------------------

 * The Proxmox API token never leaves the server process. The browser only
   ever talks to HyperVM's own REST API.
 * HyperVM users live in SQLite with PBKDF2-HMAC-SHA256 (310k iterations)
   password hashes and per-user random salts.
 * Three roles: owner > admin > user.
     - owner : everything, including user management and node level actions
     - admin : full guest lifecycle (create / delete / power / console)
     - user  : read-only dashboards plus power actions on assigned guests
 * Every mutating action is written to an immutable audit trail.
 * pandas is used for live fleet analytics (distribution, pressure scoring,
   capacity forecasting and top-talker ranking).
