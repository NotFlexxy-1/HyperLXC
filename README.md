## HyperVM - real single-file Proxmox LXC manager.

Install:
    ```pip install flask requests pandas```

Run:
    ```python hypervm.py```

Environment:
    ``PROXMOX_URL=https://192.168.1.10:8006
    PROXMOX_TOKEN_ID=admin@pam!hypervm
    PROXMOX_TOKEN_SECRET=YOUR_TOKEN_SECRET
    PROXMOX_VERIFY_TLS=false
    HYPERVM_SECRET=replace-with-a-long-random-secret``

Default HyperVM Owner:
   ``admin / admin123``

The Proxmox API token is server-side only. SQLite stores HyperVM users and
PBKDF2 password hashes. pandas performs live cluster data analysis.
