#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 HyperVM  -  Powered by HyperNET LTD
================================================================================

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

================================================================================
"""

import os
import io
import re
import ssl
import csv
import json
import time
import hmac
import string
import sqlite3
import secrets
import hashlib
import logging
import threading
import traceback
from functools import wraps
from datetime import datetime, timezone, timedelta
from urllib.parse import quote, urlparse

import requests
import urllib3

try:
    import pandas as pd
except Exception:                                     # pragma: no cover
    pd = None

from flask import (
    Flask,
    request,
    jsonify,
    session,
    Response,
)

try:
    from flask_sock import Sock
except Exception:                                     # pragma: no cover
    Sock = None

try:
    import websocket as ws_client                     # websocket-client
except Exception:                                     # pragma: no cover
    ws_client = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
LOG = logging.getLogger("hypervm")


# ==============================================================================
# SECTION 1 - CONFIGURATION
# ==============================================================================

APP_NAME = "HyperVM"
APP_VENDOR = "HyperNET LTD"
APP_TAGLINE = "Powered by HyperNET LTD"
APP_VERSION = "3.0.0"
LOGO_URL = "https://i.postimg.cc/VvWF53xk/hypernet-logo.png"

HOST = os.getenv("HYPERVM_HOST", "0.0.0.0")
PORT = int(os.getenv("HYPERVM_PORT", "8080"))
DB_PATH = os.getenv("HYPERVM_DB", "hypervm.db")

PROXMOX_URL = os.getenv("PROXMOX_URL", "").rstrip("/")
PROXMOX_TOKEN_ID = os.getenv("PROXMOX_TOKEN_ID", "")
PROXMOX_TOKEN_SECRET = os.getenv("PROXMOX_TOKEN_SECRET", "")
PROXMOX_USER = os.getenv("PROXMOX_USER", "")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "")
PROXMOX_VERIFY_TLS = os.getenv("PROXMOX_VERIFY_TLS", "false").lower() in {
    "1",
    "true",
    "yes",
    "on",
}

REQUEST_TIMEOUT = int(os.getenv("HYPERVM_TIMEOUT", "25"))
CACHE_TTL = float(os.getenv("HYPERVM_CACHE_TTL", "4"))

DEFAULT_LXC_TEMPLATES = [
    ("debian-12-standard_12.7-1_amd64.tar.zst", "Debian 12 (Bookworm)"),
    ("debian-11-standard_11.7-1_amd64.tar.zst", "Debian 11 (Bullseye)"),
    ("ubuntu-24.04-standard_24.04-2_amd64.tar.zst", "Ubuntu 24.04 LTS"),
    ("ubuntu-22.04-standard_22.04-1_amd64.tar.zst", "Ubuntu 22.04 LTS"),
    ("ubuntu-20.04-standard_20.04-1_amd64.tar.zst", "Ubuntu 20.04 LTS"),
    ("almalinux-9-default_20240911_amd64.tar.xz", "AlmaLinux 9"),
    ("rockylinux-9-default_20240912_amd64.tar.xz", "Rocky Linux 9"),
    ("alpine-3.20-default_20240908_amd64.tar.xz", "Alpine 3.20"),
    ("centos-9-stream-default_20240828_amd64.tar.xz", "CentOS 9 Stream"),
    ("fedora-40-default_20240909_amd64.tar.xz", "Fedora 40"),
]

OS_TYPES = [
    "debian",
    "ubuntu",
    "centos",
    "fedora",
    "alpine",
    "archlinux",
    "opensuse",
    "unmanaged",
]

QEMU_OS_TYPES = [
    ("l26", "Linux 2.6 - 6.x kernel"),
    ("win11", "Windows 11 / 2022"),
    ("win10", "Windows 10 / 2016 / 2019"),
    ("win8", "Windows 8 / 2012"),
    ("w2k8", "Windows 2008"),
    ("solaris", "Solaris"),
    ("other", "Other"),
]

LXC_ACTIONS = ("start", "stop", "shutdown", "reboot", "suspend", "resume")
QEMU_ACTIONS = ("start", "stop", "shutdown", "reboot", "reset", "suspend", "resume")

ROLE_ORDER = {"user": 1, "admin": 2, "owner": 3}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def human_bytes(value):
    try:
        value = float(value or 0)
    except Exception:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024.0
        index += 1
    return "%.2f %s" % (value, units[index])


def safe_int(value, fallback=0):
    try:
        return int(float(value))
    except Exception:
        return fallback


def safe_float(value, fallback=0.0):
    try:
        return float(value)
    except Exception:
        return fallback


def pct(part, whole, digits=1):
    part = safe_float(part)
    whole = safe_float(whole)
    if whole <= 0:
        return 0.0
    return round(part / whole * 100.0, digits)


def random_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def slugify(value, fallback="guest"):
    value = re.sub(r"[^a-zA-Z0-9-]+", "-", str(value or "")).strip("-").lower()
    value = re.sub(r"-{2,}", "-", value)
    return value[:60] or fallback


APP = Flask(__name__)
APP.secret_key = os.getenv("HYPERVM_SECRET", secrets.token_hex(32))
APP.config["SESSION_COOKIE_HTTPONLY"] = True
APP.config["SESSION_COOKIE_SAMESITE"] = "Lax"
APP.config["JSON_SORT_KEYS"] = False
APP.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

SOCK = Sock(APP) if Sock else None


# ==============================================================================
# SECTION 2 - DATABASE LAYER
# ==============================================================================

_DB_LOCK = threading.RLock()


def connection():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def db_run(sql, params=()):
    with _DB_LOCK:
        conn = connection()
        try:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def db_all(sql, params=()):
    conn = connection()
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def db_one(sql, params=()):
    rows = db_all(sql, params)
    return rows[0] if rows else None


SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT UNIQUE NOT NULL,
        email         TEXT,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL DEFAULT 'user',
        active        INTEGER NOT NULL DEFAULT 1,
        vm_limit      INTEGER NOT NULL DEFAULT 5,
        note          TEXT,
        last_login    TEXT,
        created_at    TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS assignments (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        node       TEXT NOT NULL,
        kind       TEXT NOT NULL,
        vmid       INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(user_id, node, kind, vmid)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        username   TEXT,
        role       TEXT,
        action     TEXT NOT NULL,
        target     TEXT,
        detail     TEXT,
        ip         TEXT,
        ok         INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS samples (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        node       TEXT NOT NULL,
        cpu        REAL,
        mem_used   REAL,
        mem_total  REAL,
        disk_used  REAL,
        disk_total REAL,
        guests     INTEGER,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS settings (
        key        TEXT PRIMARY KEY,
        value      TEXT,
        updated_at TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_samples_node ON samples(node, created_at DESC)",
]


def init_db():
    with _DB_LOCK:
        conn = connection()
        try:
            for statement in SCHEMA:
                conn.execute(statement)
            count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            if count == 0:
                conn.execute(
                    "INSERT INTO users(username,email,password_hash,role,active,"
                    "vm_limit,created_at) VALUES(?,?,?,?,?,?,?)",
                    (
                        "admin",
                        "admin@hypernet.local",
                        make_password("admin123"),
                        "owner",
                        1,
                        9999,
                        now_iso(),
                    ),
                )
                LOG.info("Seeded default owner account admin / admin123")
            conn.commit()
        finally:
            conn.close()


def setting_get(key, fallback=None):
    row = db_one("SELECT value FROM settings WHERE key=?", (key,))
    if not row:
        return fallback
    try:
        return json.loads(row["value"])
    except Exception:
        return row["value"]


def setting_set(key, value):
    db_run(
        "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
        "updated_at=excluded.updated_at",
        (key, json.dumps(value), now_iso()),
    )


# ==============================================================================
# SECTION 3 - PASSWORDS, SESSIONS AND ROLE GUARDS
# ==============================================================================

PBKDF2_ROUNDS = 310000


def make_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", str(password).encode("utf-8"), salt, PBKDF2_ROUNDS, 32
    )
    return salt.hex() + "$" + digest.hex()


def check_password(password, stored):
    try:
        salt_hex, digest = str(stored).split("$", 1)
        salt = bytes.fromhex(salt_hex)
        test = hashlib.pbkdf2_hmac(
            "sha256", str(password).encode("utf-8"), salt, PBKDF2_ROUNDS, 32
        ).hex()
        return hmac.compare_digest(test, digest)
    except Exception:
        return False


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db_one("SELECT * FROM users WHERE id=? AND active=1", (uid,))


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "-"


def write_audit(action, target="", detail="", ok=True):
    try:
        db_run(
            "INSERT INTO audit(username,role,action,target,detail,ip,ok,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                session.get("username", "system"),
                session.get("role", "system"),
                action,
                str(target)[:200],
                str(detail)[:2000],
                client_ip(),
                1 if ok else 0,
                now_iso(),
            ),
        )
    except Exception as exc:                          # pragma: no cover
        LOG.warning("audit failed: %s", exc)


def role_at_least(user, role):
    if not user:
        return False
    return ROLE_ORDER.get(user["role"], 0) >= ROLE_ORDER.get(role, 99)


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify(error="Authentication required"), 401
        return fn(*args, **kwargs)

    return wrapped


def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify(error="Authentication required"), 401
        if not role_at_least(user, "admin"):
            return jsonify(error="Admin or Owner role required"), 403
        return fn(*args, **kwargs)

    return wrapped


def owner_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify(error="Authentication required"), 401
        if user["role"] != "owner":
            return jsonify(error="Owner role required"), 403
        return fn(*args, **kwargs)

    return wrapped


def guest_allowed(user, node, kind, vmid):
    """Users only see guests assigned to them; admins and owners see all."""
    if role_at_least(user, "admin"):
        return True
    row = db_one(
        "SELECT id FROM assignments WHERE user_id=? AND node=? AND kind=? AND vmid=?",
        (user["id"], node, kind, safe_int(vmid)),
    )
    return bool(row)


def assigned_pairs(user):
    if role_at_least(user, "admin"):
        return None
    rows = db_all(
        "SELECT node, kind, vmid FROM assignments WHERE user_id=?", (user["id"],)
    )
    return set((r["node"], r["kind"], safe_int(r["vmid"])) for r in rows)


# ==============================================================================
# SECTION 4 - PROXMOX VE API CLIENT
# ==============================================================================


class ProxmoxError(RuntimeError):
    """Raised for any non-2xx response coming back from Proxmox VE."""

    def __init__(self, message, status=502):
        super(ProxmoxError, self).__init__(message)
        self.status = status


class TTLCache(object):
    """Tiny thread-safe TTL cache so the dashboard can poll aggressively."""

    def __init__(self, ttl=CACHE_TTL):
        self.ttl = ttl
        self._data = {}
        self._lock = threading.RLock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires, value = item
            if expires < time.time():
                self._data.pop(key, None)
                return None
            return value

    def put(self, key, value, ttl=None):
        with self._lock:
            self._data[key] = (time.time() + (ttl or self.ttl), value)
            return value

    def drop(self, prefix=""):
        with self._lock:
            for key in list(self._data):
                if not prefix or str(key).startswith(prefix):
                    self._data.pop(key, None)


CACHE = TTLCache()


class Proxmox(object):
    """Thin, complete-enough REST wrapper around the Proxmox VE API."""

    def __init__(self):
        self.base = PROXMOX_URL + "/api2/json" if PROXMOX_URL else ""
        self.http = requests.Session()
        self.http.headers["User-Agent"] = "HyperVM/%s (HyperNET LTD)" % APP_VERSION
        if PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET:
            self.http.headers["Authorization"] = (
                "PVEAPIToken=" + PROXMOX_TOKEN_ID + "=" + PROXMOX_TOKEN_SECRET
            )
        self._ticket = None
        self._ticket_at = 0.0
        self._ticket_lock = threading.RLock()

    # -- plumbing ------------------------------------------------------------

    def configured(self):
        return bool(self.base and PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET)

    def console_capable(self):
        return bool(self.base and PROXMOX_USER and PROXMOX_PASSWORD)

    def call(self, method, path, data=None, params=None):
        if not self.configured():
            raise ProxmoxError(
                "Proxmox is not configured. Set PROXMOX_URL, PROXMOX_TOKEN_ID "
                "and PROXMOX_TOKEN_SECRET in the environment.",
                503,
            )
        url = self.base + path
        try:
            response = self.http.request(
                method.upper(),
                url,
                data=data or None,
                params=params or None,
                verify=PROXMOX_VERIFY_TLS,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.SSLError as exc:
            raise ProxmoxError(
                "TLS handshake failed. Set PROXMOX_VERIFY_TLS=false for a "
                "self-signed Proxmox certificate. (%s)" % exc,
                502,
            )
        except requests.exceptions.ConnectionError as exc:
            raise ProxmoxError(
                "Cannot reach Proxmox at %s (%s)" % (PROXMOX_URL, exc), 502
            )
        except requests.exceptions.Timeout:
            raise ProxmoxError("Proxmox timed out after %ss" % REQUEST_TIMEOUT, 504)

        try:
            payload = response.json()
        except Exception:
            payload = {}

        if not response.ok:
            message = (
                payload.get("errors")
                or payload.get("message")
                or (response.text or "")[:400]
                or ("HTTP %s" % response.status_code)
            )
            raise ProxmoxError(str(message), response.status_code)

        return payload.get("data", payload)

    def get(self, path, params=None):
        return self.call("GET", path, params=params)

    def post(self, path, data=None):
        return self.call("POST", path, data=data)

    def put(self, path, data=None):
        return self.call("PUT", path, data=data)

    def delete(self, path, data=None):
        return self.call("DELETE", path, data=data)

    # -- ticket auth (needed for the websocket console) ----------------------

    def ticket(self):
        """Password ticket. Proxmox rejects API tokens on /vncwebsocket."""
        with self._ticket_lock:
            if self._ticket and (time.time() - self._ticket_at) < 3600:
                return self._ticket
            if not self.console_capable():
                raise ProxmoxError(
                    "Console needs PROXMOX_USER and PROXMOX_PASSWORD because "
                    "Proxmox does not allow API tokens on the websocket endpoint.",
                    503,
                )
            response = requests.post(
                self.base + "/access/ticket",
                data={"username": PROXMOX_USER, "password": PROXMOX_PASSWORD},
                verify=PROXMOX_VERIFY_TLS,
                timeout=REQUEST_TIMEOUT,
            )
            if not response.ok:
                raise ProxmoxError("Proxmox login failed for the console user", 401)
            data = (response.json() or {}).get("data") or {}
            self._ticket = {
                "ticket": data.get("ticket"),
                "CSRFPreventionToken": data.get("CSRFPreventionToken"),
            }
            self._ticket_at = time.time()
            return self._ticket

    def ticket_call(self, method, path, data=None):
        """Call the API using the password ticket instead of the token."""
        tk = self.ticket()
        headers = {"CSRFPreventionToken": tk["CSRFPreventionToken"] or ""}
        cookies = {"PVEAuthCookie": tk["ticket"] or ""}
        response = requests.request(
            method.upper(),
            self.base + path,
            data=data or None,
            headers=headers,
            cookies=cookies,
            verify=PROXMOX_VERIFY_TLS,
            timeout=REQUEST_TIMEOUT,
        )
        try:
            payload = response.json()
        except Exception:
            payload = {}
        if not response.ok:
            raise ProxmoxError(
                str(
                    payload.get("errors")
                    or payload.get("message")
                    or response.text[:300]
                ),
                response.status_code,
            )
        return payload.get("data", payload)

    # -- cluster -------------------------------------------------------------

    def version(self):
        return self.get("/version")

    def nodes(self):
        return self.get("/nodes") or []

    def cluster_resources(self, kind=None):
        params = {"type": kind} if kind else None
        return self.get("/cluster/resources", params=params) or []

    def cluster_status(self):
        return self.get("/cluster/status") or []

    def cluster_tasks(self):
        return self.get("/cluster/tasks") or []

    def next_id(self):
        try:
            return safe_int(self.get("/cluster/nextid"), 0) or self._fallback_id()
        except Exception:
            return self._fallback_id()

    def _fallback_id(self):
        used = set()
        try:
            for item in self.cluster_resources():
                if item.get("vmid"):
                    used.add(safe_int(item["vmid"]))
        except Exception:
            pass
        candidate = 100
        while candidate in used:
            candidate += 1
        return candidate

    # -- nodes ---------------------------------------------------------------

    def node_status(self, node):
        return self.get("/nodes/%s/status" % quote(node, safe=""))

    def node_rrd(self, node, timeframe="hour"):
        return self.get(
            "/nodes/%s/rrddata" % quote(node, safe=""),
            params={"timeframe": timeframe, "cf": "AVERAGE"},
        ) or []

    def node_tasks(self, node, limit=60):
        return self.get(
            "/nodes/%s/tasks" % quote(node, safe=""),
            params={"limit": limit, "start": 0},
        ) or []

    def node_storage(self, node):
        return self.get("/nodes/%s/storage" % quote(node, safe="")) or []

    def node_networks(self, node):
        return self.get("/nodes/%s/network" % quote(node, safe="")) or []

    def storage_content(self, node, storage, content=None):
        params = {"content": content} if content else None
        return self.get(
            "/nodes/%s/storage/%s/content"
            % (quote(node, safe=""), quote(storage, safe="")),
            params=params,
        ) or []

    def templates(self, node):
        out = []
        for store in self.node_storage(node):
            if "vztmpl" not in str(store.get("content") or ""):
                continue
            try:
                for item in self.storage_content(node, store["storage"], "vztmpl"):
                    volid = item.get("volid") or ""
                    out.append(
                        {
                            "volid": volid,
                            "storage": store["storage"],
                            "name": volid.split("/")[-1],
                            "size": safe_int(item.get("size")),
                        }
                    )
            except Exception as exc:
                LOG.debug("template scan failed on %s: %s", store.get("storage"), exc)
        return out

    def isos(self, node):
        out = []
        for store in self.node_storage(node):
            if "iso" not in str(store.get("content") or ""):
                continue
            try:
                for item in self.storage_content(node, store["storage"], "iso"):
                    volid = item.get("volid") or ""
                    out.append(
                        {
                            "volid": volid,
                            "storage": store["storage"],
                            "name": volid.split("/")[-1],
                            "size": safe_int(item.get("size")),
                        }
                    )
            except Exception as exc:
                LOG.debug("iso scan failed: %s", exc)
        return out

    def task_status(self, node, upid):
        return self.get(
            "/nodes/%s/tasks/%s/status"
            % (quote(node, safe=""), quote(upid, safe=""))
        )

    def task_log(self, node, upid, limit=200):
        return self.get(
            "/nodes/%s/tasks/%s/log" % (quote(node, safe=""), quote(upid, safe="")),
            params={"limit": limit},
        ) or []

    # -- generic guest helpers (kind = 'lxc' or 'qemu') ----------------------

    @staticmethod
    def _kind(kind):
        kind = str(kind or "").lower()
        if kind in ("lxc", "ct", "container"):
            return "lxc"
        if kind in ("qemu", "vm", "kvm"):
            return "qemu"
        raise ProxmoxError("Unknown guest type '%s'" % kind, 400)

    def guest_base(self, node, kind, vmid):
        return "/nodes/%s/%s/%s" % (
            quote(node, safe=""),
            self._kind(kind),
            safe_int(vmid),
        )

    def guests(self, node, kind):
        return self.get(
            "/nodes/%s/%s" % (quote(node, safe=""), self._kind(kind))
        ) or []

    def guest_status(self, node, kind, vmid):
        return self.get(self.guest_base(node, kind, vmid) + "/status/current")

    def guest_config(self, node, kind, vmid):
        return self.get(self.guest_base(node, kind, vmid) + "/config")

    def guest_set_config(self, node, kind, vmid, data):
        return self.put(self.guest_base(node, kind, vmid) + "/config", data)

    def guest_rrd(self, node, kind, vmid, timeframe="hour"):
        return self.get(
            self.guest_base(node, kind, vmid) + "/rrddata",
            params={"timeframe": timeframe, "cf": "AVERAGE"},
        ) or []

    def guest_action(self, node, kind, vmid, action):
        kind = self._kind(kind)
        allowed = LXC_ACTIONS if kind == "lxc" else QEMU_ACTIONS
        if action not in allowed:
            raise ProxmoxError("Unsupported %s action '%s'" % (kind, action), 400)
        return self.post(self.guest_base(node, kind, vmid) + "/status/" + action)

    def guest_delete(self, node, kind, vmid, purge=True):
        return self.delete(
            self.guest_base(node, kind, vmid),
            {"purge": 1 if purge else 0, "destroy-unreferenced-disks": 1},
        )

    def guest_clone(self, node, kind, vmid, newid, name=None, full=True):
        data = {"newid": safe_int(newid), "full": 1 if full else 0}
        if name:
            data["hostname" if self._kind(kind) == "lxc" else "name"] = name
        return self.post(self.guest_base(node, kind, vmid) + "/clone", data)

    def guest_migrate(self, node, kind, vmid, target, online=True):
        data = {"target": target}
        if self._kind(kind) == "lxc":
            data["restart"] = 1 if online else 0
        else:
            data["online"] = 1 if online else 0
        return self.post(self.guest_base(node, kind, vmid) + "/migrate", data)

    def guest_snapshots(self, node, kind, vmid):
        return self.get(self.guest_base(node, kind, vmid) + "/snapshot") or []

    def guest_snapshot_create(self, node, kind, vmid, name, description=""):
        data = {"snapname": name}
        if description:
            data["description"] = description
        return self.post(self.guest_base(node, kind, vmid) + "/snapshot", data)

    def guest_snapshot_delete(self, node, kind, vmid, name):
        return self.delete(
            self.guest_base(node, kind, vmid) + "/snapshot/" + quote(name, safe="")
        )

    def guest_snapshot_rollback(self, node, kind, vmid, name):
        return self.post(
            self.guest_base(node, kind, vmid)
            + "/snapshot/"
            + quote(name, safe="")
            + "/rollback"
        )

    def guest_backup(self, node, kind, vmid, storage, mode="snapshot", compress="zstd"):
        return self.post(
            "/nodes/%s/vzdump" % quote(node, safe=""),
            {
                "vmid": safe_int(vmid),
                "storage": storage,
                "mode": mode,
                "compress": compress,
                "remove": 0,
            },
        )

    def guest_resize(self, node, kind, vmid, disk, size):
        return self.put(
            self.guest_base(node, kind, vmid) + "/resize",
            {"disk": disk, "size": size},
        )

    def guest_firewall_rules(self, node, kind, vmid):
        return self.get(self.guest_base(node, kind, vmid) + "/firewall/rules") or []

    # -- creation ------------------------------------------------------------

    def create_lxc(self, node, data):
        return self.post("/nodes/%s/lxc" % quote(node, safe=""), data)

    def create_qemu(self, node, data):
        return self.post("/nodes/%s/qemu" % quote(node, safe=""), data)

    # -- console -------------------------------------------------------------

    def term_proxy(self, node, kind, vmid):
        """Ask Proxmox for a term ticket, using password auth (token is refused)."""
        kind = self._kind(kind)
        path = "/nodes/%s/%s/%s/termproxy" % (
            quote(node, safe=""),
            kind,
            safe_int(vmid),
        )
        return self.ticket_call("POST", path)

    def node_term_proxy(self, node):
        return self.ticket_call("POST", "/nodes/%s/termproxy" % quote(node, safe=""))

    def vnc_proxy(self, node, kind, vmid):
        kind = self._kind(kind)
        return self.ticket_call(
            "POST",
            "/nodes/%s/%s/%s/vncproxy" % (quote(node, safe=""), kind, safe_int(vmid)),
            {"websocket": 1},
        )

    def agent_exec(self, node, vmid, command):
        """qemu-guest-agent command execution (VMs only)."""
        return self.post(
            "/nodes/%s/qemu/%s/agent/exec" % (quote(node, safe=""), safe_int(vmid)),
            {"command": command},
        )

    def agent_exec_status(self, node, vmid, pid):
        return self.get(
            "/nodes/%s/qemu/%s/agent/exec-status"
            % (quote(node, safe=""), safe_int(vmid)),
            params={"pid": safe_int(pid)},
        )


PVE = Proxmox()


# ==============================================================================
# SECTION 5 - FLEET AGGREGATION + PANDAS ANALYTICS
# ==============================================================================


def humanize_uptime(seconds):
    seconds = safe_int(seconds)
    if seconds <= 0:
        return "offline"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return "%dd %dh" % (days, hours)
    if hours:
        return "%dh %dm" % (hours, minutes)
    return "%dm" % minutes


def enrich_node(node):
    mem = safe_float(node.get("mem"))
    maxmem = safe_float(node.get("maxmem"))
    disk = safe_float(node.get("disk"))
    maxdisk = safe_float(node.get("maxdisk"))
    uptime = safe_float(node.get("uptime"))
    return {
        "node": node.get("node"),
        "status": node.get("status", "unknown"),
        "type": "node",
        "cpu_pct": round(safe_float(node.get("cpu")) * 100, 1),
        "cpus": safe_int(node.get("maxcpu")),
        "mem_used": mem,
        "mem_total": maxmem,
        "mem_pct": pct(mem, maxmem),
        "disk_used": disk,
        "disk_total": maxdisk,
        "disk_pct": pct(disk, maxdisk),
        "mem_used_h": human_bytes(mem),
        "mem_total_h": human_bytes(maxmem),
        "disk_used_h": human_bytes(disk),
        "disk_total_h": human_bytes(maxdisk),
        "uptime": uptime,
        "uptime_h": humanize_uptime(uptime),
        "level": node.get("level", ""),
    }


def enrich_guest(item):
    kind = "lxc" if item.get("type") in ("lxc", "ct") else "qemu"
    mem = safe_float(item.get("mem"))
    maxmem = safe_float(item.get("maxmem"))
    disk = safe_float(item.get("disk"))
    maxdisk = safe_float(item.get("maxdisk"))
    uptime = safe_float(item.get("uptime"))
    return {
        "vmid": safe_int(item.get("vmid")),
        "name": item.get("name")
        or item.get("hostname")
        or ("guest-%s" % item.get("vmid")),
        "node": item.get("node"),
        "kind": kind,
        "kind_label": "LXC" if kind == "lxc" else "VM",
        "status": item.get("status", "unknown"),
        "template": bool(safe_int(item.get("template"))),
        "locked": item.get("lock") or "",
        "tags": [t for t in str(item.get("tags") or "").split(";") if t],
        "cpus": safe_int(item.get("maxcpu") or item.get("cpus")),
        "cpu_pct": round(safe_float(item.get("cpu")) * 100, 1),
        "mem_used": mem,
        "mem_total": maxmem,
        "mem_pct": pct(mem, maxmem),
        "mem_used_h": human_bytes(mem),
        "mem_total_h": human_bytes(maxmem),
        "disk_used": disk,
        "disk_total": maxdisk,
        "disk_pct": pct(disk, maxdisk),
        "disk_total_h": human_bytes(maxdisk),
        "netin": safe_float(item.get("netin")),
        "netout": safe_float(item.get("netout")),
        "netin_h": human_bytes(item.get("netin")),
        "netout_h": human_bytes(item.get("netout")),
        "uptime": uptime,
        "uptime_h": humanize_uptime(uptime),
        "pool": item.get("pool") or "",
    }


def fleet_snapshot(force=False):
    """One cached round-trip that powers the entire dashboard."""
    if not force:
        cached = CACHE.get("fleet")
        if cached:
            return cached

    nodes = [enrich_node(n) for n in PVE.nodes()]
    guests = []
    try:
        resources = PVE.cluster_resources("vm")
        guests = [enrich_guest(r) for r in resources]
    except ProxmoxError:
        for node in nodes:
            for kind in ("lxc", "qemu"):
                try:
                    for item in PVE.guests(node["node"], kind):
                        item["node"] = node["node"]
                        item["type"] = kind
                        guests.append(enrich_guest(item))
                except ProxmoxError as exc:
                    LOG.warning(
                        "guest list failed on %s/%s: %s", node["node"], kind, exc
                    )

    storages = []
    for node in nodes:
        if node["status"] != "online":
            continue
        try:
            for store in PVE.node_storage(node["node"]):
                total = safe_float(store.get("total"))
                used = safe_float(store.get("used"))
                storages.append(
                    {
                        "node": node["node"],
                        "storage": store.get("storage"),
                        "type": store.get("type"),
                        "content": store.get("content"),
                        "enabled": bool(safe_int(store.get("enabled"), 1)),
                        "active": bool(safe_int(store.get("active"), 0)),
                        "total": total,
                        "used": used,
                        "avail": safe_float(store.get("avail")),
                        "total_h": human_bytes(total),
                        "used_h": human_bytes(used),
                        "avail_h": human_bytes(store.get("avail")),
                        "used_pct": pct(used, total),
                    }
                )
        except ProxmoxError as exc:
            LOG.debug("storage scan failed on %s: %s", node["node"], exc)

    snapshot = {
        "nodes": nodes,
        "guests": guests,
        "storages": storages,
        "generated_at": now_iso(),
    }
    CACHE.put("fleet", snapshot)
    record_samples(nodes, guests)
    return snapshot


def record_samples(nodes, guests):
    """Persist a lightweight time series so pandas has history to chew on."""
    try:
        if CACHE.get("sample_stamp"):
            return
        CACHE.put("sample_stamp", True, ttl=55)
        for node in nodes:
            count = len([g for g in guests if g["node"] == node["node"]])
            db_run(
                "INSERT INTO samples(node,cpu,mem_used,mem_total,disk_used,"
                "disk_total,guests,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    node["node"],
                    node["cpu_pct"],
                    node["mem_used"],
                    node["mem_total"],
                    node["disk_used"],
                    node["disk_total"],
                    count,
                    now_iso(),
                ),
            )
        db_run(
            "DELETE FROM samples WHERE created_at < ?",
            (
                (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(
                    timespec="seconds"
                ),
            ),
        )
    except Exception as exc:                          # pragma: no cover
        LOG.debug("sample write failed: %s", exc)


def compute_totals(snapshot):
    nodes = snapshot.get("nodes") or []
    guests = snapshot.get("guests") or []
    running = [g for g in guests if g["status"] == "running"]
    lxc = [g for g in guests if g["kind"] == "lxc"]
    qemu = [g for g in guests if g["kind"] == "qemu"]
    mem_used = sum(n["mem_used"] for n in nodes)
    mem_total = sum(n["mem_total"] for n in nodes)
    disk_used = sum(n["disk_used"] for n in nodes)
    disk_total = sum(n["disk_total"] for n in nodes)
    cpu_avg = round(sum(n["cpu_pct"] for n in nodes) / len(nodes), 1) if nodes else 0.0
    return {
        "nodes": len(nodes),
        "nodes_online": len([n for n in nodes if n["status"] == "online"]),
        "guests": len(guests),
        "running": len(running),
        "stopped": len(guests) - len(running),
        "lxc": len(lxc),
        "qemu": len(qemu),
        "lxc_running": len([g for g in lxc if g["status"] == "running"]),
        "qemu_running": len([g for g in qemu if g["status"] == "running"]),
        "vcpus": sum(g["cpus"] for g in guests),
        "cores": sum(n["cpus"] for n in nodes),
        "cpu_avg": cpu_avg,
        "mem_used": mem_used,
        "mem_total": mem_total,
        "mem_pct": pct(mem_used, mem_total),
        "mem_used_h": human_bytes(mem_used),
        "mem_total_h": human_bytes(mem_total),
        "disk_used": disk_used,
        "disk_total": disk_total,
        "disk_pct": pct(disk_used, disk_total),
        "disk_used_h": human_bytes(disk_used),
        "disk_total_h": human_bytes(disk_total),
        "net_in_h": human_bytes(sum(g["netin"] for g in guests)),
        "net_out_h": human_bytes(sum(g["netout"] for g in guests)),
    }


def analytics(snapshot):
    """pandas powered fleet intelligence."""
    guests = snapshot.get("guests") or []
    nodes = snapshot.get("nodes") or []
    empty = {
        "available": bool(pd),
        "by_node": [],
        "by_kind": [],
        "by_status": [],
        "top_cpu": [],
        "top_mem": [],
        "pressure": [],
        "forecast": [],
        "insights": [],
    }
    if not pd or not guests:
        return empty

    frame = pd.DataFrame(guests)
    node_frame = pd.DataFrame(nodes)

    by_node = (
        frame.groupby("node")
        .agg(
            guests=("vmid", "count"),
            running=("status", lambda s: int((s == "running").sum())),
            vcpus=("cpus", "sum"),
            mem=("mem_used", "sum"),
            cpu=("cpu_pct", "mean"),
        )
        .reset_index()
    )
    by_node["cpu"] = by_node["cpu"].round(1)
    by_node["mem_h"] = by_node["mem"].map(human_bytes)

    by_kind = (
        frame.groupby("kind_label")
        .agg(
            count=("vmid", "count"),
            running=("status", lambda s: int((s == "running").sum())),
            vcpus=("cpus", "sum"),
            mem=("mem_used", "sum"),
        )
        .reset_index()
    )
    by_kind["mem_h"] = by_kind["mem"].map(human_bytes)

    by_status = frame.groupby("status").agg(count=("vmid", "count")).reset_index()

    top_cpu = frame.sort_values("cpu_pct", ascending=False).head(8)[
        ["vmid", "name", "node", "kind_label", "cpu_pct", "mem_pct"]
    ]
    top_mem = frame.sort_values("mem_used", ascending=False).head(8)[
        ["vmid", "name", "node", "kind_label", "mem_used_h", "mem_pct"]
    ]

    pressure = []
    if not node_frame.empty:
        node_frame["score"] = (
            node_frame["cpu_pct"] * 0.4
            + node_frame["mem_pct"] * 0.4
            + node_frame["disk_pct"] * 0.2
        ).round(1)
        node_frame["band"] = pd.cut(
            node_frame["score"],
            bins=[-1, 45, 70, 85, 1000],
            labels=["healthy", "warm", "hot", "critical"],
        ).astype(str)
        pressure = (
            node_frame[["node", "score", "band", "cpu_pct", "mem_pct", "disk_pct"]]
            .sort_values("score", ascending=False)
            .to_dict("records")
        )

    forecast = []
    history = db_all(
        "SELECT node, mem_used, mem_total, created_at FROM samples "
        "WHERE created_at > ? ORDER BY created_at ASC",
        (
            (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(
                timespec="seconds"
            ),
        ),
    )
    if history:
        hist = pd.DataFrame(history)
        hist["created_at"] = pd.to_datetime(hist["created_at"], errors="coerce", utc=True)
        hist = hist.dropna(subset=["created_at"])
        for node_name, chunk in hist.groupby("node"):
            chunk = chunk.sort_values("created_at")
            if len(chunk) < 3:
                continue
            xs = (
                chunk["created_at"] - chunk["created_at"].iloc[0]
            ).dt.total_seconds() / 3600.0
            ys = chunk["mem_used"].astype(float)
            span = max(float(xs.iloc[-1]), 1e-6)
            slope = float((ys.iloc[-1] - ys.iloc[0]) / span)
            total = float(chunk["mem_total"].iloc[-1] or 0)
            used = float(ys.iloc[-1])
            hours_left = None
            if slope > 0 and total > used:
                hours_left = round((total - used) / slope, 1)
            forecast.append(
                {
                    "node": node_name,
                    "trend_per_hour": human_bytes(abs(slope))
                    + ("/h up" if slope >= 0 else "/h down"),
                    "hours_to_full": hours_left,
                    "samples": int(len(chunk)),
                }
            )

    insights = []
    stopped = frame[frame["status"] != "running"]
    if len(stopped):
        insights.append(
            "%d guest(s) are not running and still reserve %s of disk."
            % (len(stopped), human_bytes(stopped["disk_total"].sum()))
        )
    hot = frame[frame["mem_pct"] > 88]
    if len(hot):
        insights.append(
            "%d guest(s) are above 88%% memory: %s"
            % (len(hot), ", ".join(hot["name"].head(5).tolist()))
        )
    idle = frame[(frame["status"] == "running") & (frame["cpu_pct"] < 1.0)]
    if len(idle):
        insights.append(
            "%d running guest(s) are effectively idle (<1%% CPU) - reclaim candidates."
            % len(idle)
        )
    if not node_frame.empty:
        busiest = node_frame.sort_values("mem_pct", ascending=False).iloc[0]
        insights.append(
            "Highest memory pressure: %s at %.1f%%."
            % (busiest["node"], busiest["mem_pct"])
        )
    if not insights:
        insights.append("Fleet is balanced. No action recommended.")

    return {
        "available": True,
        "by_node": by_node.to_dict("records"),
        "by_kind": by_kind.to_dict("records"),
        "by_status": by_status.to_dict("records"),
        "top_cpu": top_cpu.to_dict("records"),
        "top_mem": top_mem.to_dict("records"),
        "pressure": pressure,
        "forecast": forecast,
        "insights": insights,
    }


# ==============================================================================
# SECTION 6 - REST API : AUTHENTICATION
# ==============================================================================


def public_user(row):
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row.get("email"),
        "role": row["role"],
        "active": bool(row["active"]),
        "vm_limit": row.get("vm_limit"),
        "note": row.get("note"),
        "last_login": row.get("last_login"),
        "created_at": row.get("created_at"),
    }


@APP.errorhandler(ProxmoxError)
def handle_proxmox_error(exc):
    LOG.warning("Proxmox error: %s", exc)
    return jsonify(error=str(exc)), getattr(exc, "status", 502)


@APP.errorhandler(Exception)
def handle_unexpected(exc):                            # pragma: no cover
    if isinstance(exc, ProxmoxError):
        return handle_proxmox_error(exc)
    code = getattr(exc, "code", 500)
    if isinstance(code, int) and 400 <= code < 600:
        return jsonify(error=getattr(exc, "description", str(exc))), code
    LOG.error("Unhandled: %s\n%s", exc, traceback.format_exc())
    return jsonify(error="Internal error: %s" % exc), 500


@APP.post("/api/auth/login")
def api_login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", ""))

    row = db_one("SELECT * FROM users WHERE username=?", (username,))
    if not row or not row["active"] or not check_password(password, row["password_hash"]):
        time.sleep(0.4)
        write_audit("login_failed", username, ok=False)
        return jsonify(error="Invalid username or password"), 401

    session.clear()
    session.permanent = True
    session["uid"] = row["id"]
    session["username"] = row["username"]
    session["role"] = row["role"]
    db_run("UPDATE users SET last_login=? WHERE id=?", (now_iso(), row["id"]))
    write_audit("login", row["username"])
    return jsonify(user=public_user(row))


@APP.post("/api/auth/signup")
def api_signup():
    if setting_get("signup_open", True) is False:
        return jsonify(error="Registration is currently closed"), 403
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", ""))
    email = str(body.get("email", "")).strip()[:120]

    if len(username) < 3 or len(username) > 32 or not username.replace("_", "").isalnum():
        return jsonify(error="Username must be 3-32 letters, numbers or underscores"), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400

    try:
        uid = db_run(
            "INSERT INTO users(username,email,password_hash,role,active,vm_limit,"
            "created_at) VALUES(?,?,?,?,?,?,?)",
            (username, email, make_password(password), "user", 1, 3, now_iso()),
        )
    except sqlite3.IntegrityError:
        return jsonify(error="That username is already taken"), 409

    session.clear()
    session["uid"] = uid
    session["username"] = username
    session["role"] = "user"
    write_audit("signup", username)
    row = db_one("SELECT * FROM users WHERE id=?", (uid,))
    return jsonify(user=public_user(row))


@APP.post("/api/auth/logout")
def api_logout():
    write_audit("logout")
    session.clear()
    return jsonify(ok=True)


@APP.get("/api/auth/me")
def api_me():
    user = current_user()
    return jsonify(
        user=public_user(user) if user else None,
        proxmox_configured=PVE.configured(),
        console_ready=PVE.console_capable() and bool(SOCK and ws_client),
        version=APP_VERSION,
    )


@APP.patch("/api/auth/password")
@login_required
def api_change_password():
    body = request.get_json(silent=True) or {}
    user = current_user()
    if not check_password(str(body.get("current", "")), user["password_hash"]):
        return jsonify(error="Current password is incorrect"), 400
    nxt = str(body.get("next", ""))
    if len(nxt) < 8:
        return jsonify(error="New password must be at least 8 characters"), 400
    db_run("UPDATE users SET password_hash=? WHERE id=?", (make_password(nxt), user["id"]))
    write_audit("password_changed", user["username"])
    return jsonify(ok=True)


# ==============================================================================
# SECTION 7 - REST API : USERS AND ASSIGNMENTS (owner only)
# ==============================================================================


@APP.get("/api/users")
@owner_required
def api_users():
    rows = db_all("SELECT * FROM users ORDER BY id ASC")
    out = []
    for row in rows:
        item = public_user(row)
        item["assignments"] = db_all(
            "SELECT node, kind, vmid FROM assignments WHERE user_id=?", (row["id"],)
        )
        out.append(item)
    return jsonify(users=out, signup_open=setting_get("signup_open", True))


@APP.post("/api/users")
@owner_required
def api_user_create():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", "")) or random_password()
    role = str(body.get("role", "user"))
    if role not in ROLE_ORDER:
        return jsonify(error="Unknown role"), 400
    if len(username) < 3:
        return jsonify(error="Username too short"), 400
    try:
        uid = db_run(
            "INSERT INTO users(username,email,password_hash,role,active,vm_limit,"
            "note,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                username,
                str(body.get("email", ""))[:120],
                make_password(password),
                role,
                1,
                safe_int(body.get("vm_limit"), 3),
                str(body.get("note", ""))[:300],
                now_iso(),
            ),
        )
    except sqlite3.IntegrityError:
        return jsonify(error="Username already exists"), 409
    write_audit("user_create", username, role)
    return jsonify(ok=True, id=uid, password=password)


@APP.patch("/api/users/<int:uid>")
@owner_required
def api_user_update(uid):
    body = request.get_json(silent=True) or {}
    row = db_one("SELECT * FROM users WHERE id=?", (uid,))
    if not row:
        return jsonify(error="User not found"), 404
    me = current_user()
    if row["id"] == me["id"] and body.get("role") and body["role"] != "owner":
        return jsonify(error="You cannot demote yourself"), 400

    fields, params = [], []
    if "role" in body and body["role"] in ROLE_ORDER:
        fields.append("role=?")
        params.append(body["role"])
    if "active" in body:
        fields.append("active=?")
        params.append(1 if body["active"] else 0)
    if "vm_limit" in body:
        fields.append("vm_limit=?")
        params.append(safe_int(body["vm_limit"], 3))
    if "email" in body:
        fields.append("email=?")
        params.append(str(body["email"])[:120])
    if "note" in body:
        fields.append("note=?")
        params.append(str(body["note"])[:300])
    if body.get("password"):
        new_password = str(body["password"])
        if len(new_password) < 8:
            return jsonify(error="Password must be at least 8 characters"), 400
        fields.append("password_hash=?")
        params.append(make_password(new_password))
    if not fields:
        return jsonify(error="Nothing to update"), 400
    params.append(uid)
    db_run("UPDATE users SET " + ", ".join(fields) + " WHERE id=?", params)
    write_audit("user_update", row["username"], ", ".join(fields))
    return jsonify(ok=True)


@APP.delete("/api/users/<int:uid>")
@owner_required
def api_user_delete(uid):
    me = current_user()
    if me["id"] == uid:
        return jsonify(error="You cannot delete your own account"), 400
    row = db_one("SELECT * FROM users WHERE id=?", (uid,))
    if not row:
        return jsonify(error="User not found"), 404
    db_run("DELETE FROM users WHERE id=?", (uid,))
    write_audit("user_delete", row["username"])
    return jsonify(ok=True)


@APP.post("/api/users/<int:uid>/assign")
@owner_required
def api_user_assign(uid):
    body = request.get_json(silent=True) or {}
    node = str(body.get("node", "")).strip()
    kind = "lxc" if str(body.get("kind")) == "lxc" else "qemu"
    vmid = safe_int(body.get("vmid"))
    if not node or not vmid:
        return jsonify(error="node and vmid are required"), 400
    try:
        db_run(
            "INSERT INTO assignments(user_id,node,kind,vmid,created_at) VALUES(?,?,?,?,?)",
            (uid, node, kind, vmid, now_iso()),
        )
    except sqlite3.IntegrityError:
        return jsonify(error="Already assigned"), 409
    write_audit("assign", "%s/%s/%s" % (node, kind, vmid), "user=%s" % uid)
    return jsonify(ok=True)


@APP.delete("/api/users/<int:uid>/assign")
@owner_required
def api_user_unassign(uid):
    body = request.get_json(silent=True) or {}
    db_run(
        "DELETE FROM assignments WHERE user_id=? AND node=? AND kind=? AND vmid=?",
        (
            uid,
            str(body.get("node", "")),
            str(body.get("kind", "")),
            safe_int(body.get("vmid")),
        ),
    )
    write_audit("unassign", str(body.get("vmid")), "user=%s" % uid)
    return jsonify(ok=True)


@APP.post("/api/settings/signup")
@owner_required
def api_toggle_signup():
    body = request.get_json(silent=True) or {}
    value = bool(body.get("open"))
    setting_set("signup_open", value)
    write_audit("signup_toggle", "", str(value))
    return jsonify(ok=True, signup_open=value)


# ==============================================================================
# SECTION 8 - REST API : CLUSTER, NODES, STORAGE, TASKS
# ==============================================================================


def visible_guests(user, guests):
    allowed = assigned_pairs(user)
    if allowed is None:
        return guests
    return [g for g in guests if (g["node"], g["kind"], g["vmid"]) in allowed]


@APP.get("/api/cluster")
@login_required
def api_cluster():
    user = current_user()
    if not PVE.configured():
        blank = {"nodes": [], "guests": [], "storages": []}
        return jsonify(
            connected=False,
            reason="Proxmox credentials are not configured on the server.",
            nodes=[],
            guests=[],
            storages=[],
            totals=compute_totals(blank),
            analytics=analytics(blank),
        )
    snapshot = fleet_snapshot(force=request.args.get("force") == "1")
    guests = visible_guests(user, snapshot["guests"])
    scoped = {
        "nodes": snapshot["nodes"],
        "guests": guests,
        "storages": snapshot["storages"],
    }
    return jsonify(
        connected=True,
        generated_at=snapshot["generated_at"],
        nodes=snapshot["nodes"],
        guests=guests,
        storages=snapshot["storages"],
        totals=compute_totals(scoped),
        analytics=analytics(scoped),
    )


@APP.get("/api/nodes")
@login_required
def api_nodes():
    return jsonify(nodes=[enrich_node(n) for n in PVE.nodes()])


@APP.get("/api/nodes/<node>/status")
@admin_required
def api_node_status(node):
    return jsonify(status=PVE.node_status(node))


@APP.get("/api/nodes/<node>/rrd")
@login_required
def api_node_rrd(node):
    return jsonify(series=PVE.node_rrd(node, request.args.get("timeframe", "hour")))


@APP.get("/api/nodes/<node>/networks")
@admin_required
def api_node_networks(node):
    return jsonify(networks=PVE.node_networks(node))


@APP.get("/api/nodes/<node>/storage")
@admin_required
def api_node_storage(node):
    return jsonify(storage=PVE.node_storage(node))


@APP.get("/api/nodes/<node>/templates")
@admin_required
def api_node_templates(node):
    return jsonify(templates=PVE.templates(node), suggested=DEFAULT_LXC_TEMPLATES)


@APP.get("/api/nodes/<node>/isos")
@admin_required
def api_node_isos(node):
    return jsonify(isos=PVE.isos(node))


@APP.get("/api/tasks")
@login_required
def api_tasks():
    node = request.args.get("node")
    if node:
        return jsonify(tasks=PVE.node_tasks(node, safe_int(request.args.get("limit"), 60)))
    try:
        return jsonify(tasks=PVE.cluster_tasks())
    except ProxmoxError:
        tasks = []
        for item in PVE.nodes():
            try:
                tasks.extend(PVE.node_tasks(item["node"], 30))
            except ProxmoxError:
                continue
        return jsonify(tasks=tasks)


@APP.get("/api/tasks/<node>/<path:upid>/log")
@admin_required
def api_task_log(node, upid):
    return jsonify(log=PVE.task_log(node, upid), status=PVE.task_status(node, upid))


@APP.get("/api/nextid")
@admin_required
def api_nextid():
    return jsonify(vmid=PVE.next_id())


# ==============================================================================
# SECTION 9 - REST API : GUEST LIFECYCLE (LXC + QEMU share these routes)
# ==============================================================================


def _guard(kind, node, vmid, level="user"):
    user = current_user()
    if not user:
        raise ProxmoxError("Authentication required", 401)
    if not role_at_least(user, "admin") and not guest_allowed(user, node, kind, vmid):
        raise ProxmoxError("You do not have access to this guest", 403)
    if level != "user" and not role_at_least(user, level):
        raise ProxmoxError("Insufficient role for this operation", 403)
    return user


@APP.get("/api/guests")
@login_required
def api_guests():
    snapshot = fleet_snapshot()
    guests = visible_guests(current_user(), snapshot["guests"])
    kind = request.args.get("kind")
    if kind in ("lxc", "qemu"):
        guests = [g for g in guests if g["kind"] == kind]
    node = request.args.get("node")
    if node:
        guests = [g for g in guests if g["node"] == node]
    search = (request.args.get("q") or "").strip().lower()
    if search:
        guests = [
            g for g in guests
            if search in str(g["name"]).lower() or search in str(g["vmid"])
        ]
    return jsonify(guests=guests)


@APP.get("/api/guest/<kind>/<node>/<int:vmid>")
@login_required
def api_guest_detail(kind, node, vmid):
    _guard(kind, node, vmid)
    detail = {
        "status": PVE.guest_status(node, kind, vmid),
        "config": PVE.guest_config(node, kind, vmid),
    }
    try:
        detail["snapshots"] = PVE.guest_snapshots(node, kind, vmid)
    except ProxmoxError:
        detail["snapshots"] = []
    try:
        detail["rrd"] = PVE.guest_rrd(
            node, kind, vmid, request.args.get("timeframe", "hour")
        )
    except ProxmoxError:
        detail["rrd"] = []
    detail["kind"] = kind
    detail["node"] = node
    detail["vmid"] = vmid
    return jsonify(detail)


@APP.post("/api/guest/<kind>/<node>/<int:vmid>/action/<action>")
@login_required
def api_guest_action(kind, node, vmid, action):
    _guard(kind, node, vmid)
    result = PVE.guest_action(node, kind, vmid, action)
    CACHE.drop("fleet")
    write_audit("guest_%s" % action, "%s/%s/%s" % (node, kind, vmid), str(result))
    return jsonify(ok=True, task=result)


@APP.patch("/api/guest/<kind>/<node>/<int:vmid>/config")
@admin_required
def api_guest_config_update(kind, node, vmid):
    body = request.get_json(silent=True) or {}
    payload = {}
    for key in (
        "cores", "memory", "swap", "name", "hostname", "description",
        "onboot", "tags", "cpulimit", "cpuunits",
    ):
        if key in body and body[key] not in ("", None):
            payload[key] = body[key]
    if not payload:
        return jsonify(error="Nothing to change"), 400
    result = PVE.guest_set_config(node, kind, vmid, payload)
    CACHE.drop("fleet")
    write_audit("guest_reconfigure", "%s/%s/%s" % (node, kind, vmid), json.dumps(payload))
    return jsonify(ok=True, result=result)


@APP.post("/api/guest/<kind>/<node>/<int:vmid>/resize")
@admin_required
def api_guest_resize(kind, node, vmid):
    body = request.get_json(silent=True) or {}
    disk = str(body.get("disk") or ("rootfs" if kind == "lxc" else "scsi0"))
    size = str(body.get("size") or "+1G")
    result = PVE.guest_resize(node, kind, vmid, disk, size)
    write_audit("guest_resize", "%s/%s/%s" % (node, kind, vmid), "%s %s" % (disk, size))
    return jsonify(ok=True, task=result)


@APP.delete("/api/guest/<kind>/<node>/<int:vmid>")
@admin_required
def api_guest_delete(kind, node, vmid):
    status = {}
    try:
        status = PVE.guest_status(node, kind, vmid) or {}
    except ProxmoxError:
        pass
    if status.get("status") == "running":
        try:
            PVE.guest_action(node, kind, vmid, "stop")
            time.sleep(3)
        except ProxmoxError as exc:
            LOG.warning("stop before delete failed: %s", exc)
    result = PVE.guest_delete(node, kind, vmid, purge=True)
    db_run("DELETE FROM assignments WHERE node=? AND kind=? AND vmid=?", (node, kind, vmid))
    CACHE.drop("fleet")
    write_audit("guest_delete", "%s/%s/%s" % (node, kind, vmid))
    return jsonify(ok=True, task=result)


@APP.post("/api/guest/<kind>/<node>/<int:vmid>/clone")
@admin_required
def api_guest_clone(kind, node, vmid):
    body = request.get_json(silent=True) or {}
    newid = safe_int(body.get("newid")) or PVE.next_id()
    result = PVE.guest_clone(
        node, kind, vmid, newid, body.get("name"), bool(body.get("full", True))
    )
    CACHE.drop("fleet")
    write_audit("guest_clone", "%s/%s/%s" % (node, kind, vmid), "-> %s" % newid)
    return jsonify(ok=True, newid=newid, task=result)


@APP.post("/api/guest/<kind>/<node>/<int:vmid>/migrate")
@admin_required
def api_guest_migrate(kind, node, vmid):
    body = request.get_json(silent=True) or {}
    target = str(body.get("target", "")).strip()
    if not target:
        return jsonify(error="target node is required"), 400
    result = PVE.guest_migrate(node, kind, vmid, target, bool(body.get("online", True)))
    CACHE.drop("fleet")
    write_audit("guest_migrate", "%s/%s/%s" % (node, kind, vmid), "-> %s" % target)
    return jsonify(ok=True, task=result)


@APP.get("/api/guest/<kind>/<node>/<int:vmid>/snapshots")
@login_required
def api_snapshots(kind, node, vmid):
    _guard(kind, node, vmid)
    return jsonify(snapshots=PVE.guest_snapshots(node, kind, vmid))


@APP.post("/api/guest/<kind>/<node>/<int:vmid>/snapshots")
@admin_required
def api_snapshot_create(kind, node, vmid):
    body = request.get_json(silent=True) or {}
    name = slugify(
        body.get("name") or ("snap-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    )
    result = PVE.guest_snapshot_create(
        node, kind, vmid, name, str(body.get("description", ""))[:200]
    )
    write_audit("snapshot_create", "%s/%s/%s" % (node, kind, vmid), name)
    return jsonify(ok=True, name=name, task=result)


@APP.delete("/api/guest/<kind>/<node>/<int:vmid>/snapshots/<name>")
@admin_required
def api_snapshot_delete(kind, node, vmid, name):
    result = PVE.guest_snapshot_delete(node, kind, vmid, name)
    write_audit("snapshot_delete", "%s/%s/%s" % (node, kind, vmid), name)
    return jsonify(ok=True, task=result)


@APP.post("/api/guest/<kind>/<node>/<int:vmid>/snapshots/<name>/rollback")
@admin_required
def api_snapshot_rollback(kind, node, vmid, name):
    result = PVE.guest_snapshot_rollback(node, kind, vmid, name)
    write_audit("snapshot_rollback", "%s/%s/%s" % (node, kind, vmid), name)
    return jsonify(ok=True, task=result)


@APP.post("/api/guest/<kind>/<node>/<int:vmid>/backup")
@admin_required
def api_backup(kind, node, vmid):
    body = request.get_json(silent=True) or {}
    storage = str(body.get("storage") or "local")
    result = PVE.guest_backup(
        node, kind, vmid, storage, str(body.get("mode", "snapshot"))
    )
    write_audit("backup", "%s/%s/%s" % (node, kind, vmid), storage)
    return jsonify(ok=True, task=result)


# ==============================================================================
# SECTION 10 - REST API : PROVISIONING
# ==============================================================================


def build_net0(body):
    bridge = str(body.get("bridge") or "vmbr0")
    ip = str(body.get("ip") or "dhcp").strip()
    parts = ["name=eth0", "bridge=" + bridge]
    if str(body.get("firewall", "")).lower() in ("1", "true", "on", "yes"):
        parts.append("firewall=1")
    if body.get("vlan"):
        parts.append("tag=%d" % safe_int(body["vlan"]))
    if ip and ip.lower() != "dhcp":
        parts.append("ip=" + ip)
        if body.get("gateway"):
            parts.append("gw=" + str(body["gateway"]))
    else:
        parts.append("ip=dhcp")
    if body.get("rate"):
        parts.append("rate=%s" % safe_int(body["rate"]))
    return ",".join(parts)


@APP.post("/api/create/lxc")
@admin_required
def api_create_lxc():
    body = request.get_json(silent=True) or {}
    node = str(body.get("node", "")).strip()
    if not node:
        return jsonify(error="node is required"), 400

    vmid = safe_int(body.get("vmid")) or PVE.next_id()
    password = str(body.get("password") or "") or random_password()
    hostname = slugify(body.get("hostname") or ("ct-%s" % vmid))
    template = str(body.get("template", "")).strip()
    if not template:
        return jsonify(error="A container template (ostemplate) is required"), 400
    storage = str(body.get("storage") or "local-lvm")

    payload = {
        "vmid": vmid,
        "hostname": hostname,
        "ostemplate": template,
        "storage": storage,
        "rootfs": "%s:%d" % (storage, safe_int(body.get("disk"), 8)),
        "cores": safe_int(body.get("cores"), 1),
        "memory": safe_int(body.get("memory"), 1024),
        "swap": safe_int(body.get("swap"), 512),
        "password": password,
        "net0": build_net0(body),
        "unprivileged": 1 if body.get("unprivileged", True) else 0,
        "features": "nesting=1" if body.get("nesting", True) else "",
        "onboot": 1 if body.get("onboot", True) else 0,
        "start": 1 if body.get("start", True) else 0,
    }
    if body.get("ostype") in OS_TYPES:
        payload["ostype"] = body["ostype"]
    if body.get("nameserver"):
        payload["nameserver"] = str(body["nameserver"])
    if body.get("sshkeys"):
        payload["ssh-public-keys"] = str(body["sshkeys"])
    if body.get("description"):
        payload["description"] = str(body["description"])[:500]
    if body.get("tags"):
        payload["tags"] = slugify(body["tags"], "hypervm")
    payload = dict((k, v) for k, v in payload.items() if v not in ("", None))

    task = PVE.create_lxc(node, payload)
    CACHE.drop("fleet")
    write_audit("create_lxc", "%s/lxc/%s" % (node, vmid), hostname)

    if body.get("owner_id"):
        try:
            db_run(
                "INSERT OR IGNORE INTO assignments(user_id,node,kind,vmid,created_at) "
                "VALUES(?,?,?,?,?)",
                (safe_int(body["owner_id"]), node, "lxc", vmid, now_iso()),
            )
        except Exception as exc:
            LOG.debug("assign after create failed: %s", exc)

    return jsonify(ok=True, vmid=vmid, password=password, hostname=hostname, task=task)


@APP.post("/api/create/qemu")
@admin_required
def api_create_qemu():
    body = request.get_json(silent=True) or {}
    node = str(body.get("node", "")).strip()
    if not node:
        return jsonify(error="node is required"), 400

    vmid = safe_int(body.get("vmid")) or PVE.next_id()
    name = slugify(body.get("name") or ("vm-%s" % vmid))
    storage = str(body.get("storage") or "local-lvm")
    disk_gb = safe_int(body.get("disk"), 32)
    bus = str(body.get("bus") or "scsi0")
    ostype = str(body.get("ostype") or "l26")

    payload = {
        "vmid": vmid,
        "name": name,
        "cores": safe_int(body.get("cores"), 2),
        "sockets": safe_int(body.get("sockets"), 1),
        "memory": safe_int(body.get("memory"), 2048),
        "ostype": ostype,
        "scsihw": str(body.get("scsihw") or "virtio-scsi-single"),
        "net0": "virtio,bridge=%s%s"
        % (
            str(body.get("bridge") or "vmbr0"),
            (",tag=%d" % safe_int(body["vlan"])) if body.get("vlan") else "",
        ),
        bus: "%s:%d,discard=on,iothread=1" % (storage, disk_gb),
        "agent": "1" if body.get("agent", True) else "0",
        "onboot": 1 if body.get("onboot", True) else 0,
        "boot": "order=%s;ide2" % bus,
        "cpu": str(body.get("cpu") or "host"),
    }
    if body.get("iso"):
        payload["ide2"] = "%s,media=cdrom" % str(body["iso"])
    if body.get("bios") == "ovmf":
        payload["bios"] = "ovmf"
        payload["efidisk0"] = "%s:1,efitype=4m,pre-enrolled-keys=1" % storage
        if ostype.startswith("win"):
            payload["machine"] = "q35"
            payload["tpmstate0"] = "%s:1,version=v2.0" % storage
    if body.get("ciuser"):
        payload["ciuser"] = str(body["ciuser"])
        payload["cipassword"] = str(body.get("cipassword") or random_password())
        payload["ipconfig0"] = str(body.get("ipconfig0") or "ip=dhcp")
        payload["ide0"] = "%s:cloudinit" % storage
    if body.get("sshkeys"):
        payload["sshkeys"] = quote(str(body["sshkeys"]), safe="")
    if body.get("description"):
        payload["description"] = str(body["description"])[:500]
    if body.get("tags"):
        payload["tags"] = slugify(body["tags"], "hypervm")
    payload = dict((k, v) for k, v in payload.items() if v not in ("", None))

    task = PVE.create_qemu(node, payload)
    CACHE.drop("fleet")
    write_audit("create_qemu", "%s/qemu/%s" % (node, vmid), name)

    if body.get("start", True):
        for _ in range(10):
            time.sleep(1.5)
            try:
                PVE.guest_action(node, "qemu", vmid, "start")
                break
            except ProxmoxError:
                continue

    if body.get("owner_id"):
        try:
            db_run(
                "INSERT OR IGNORE INTO assignments(user_id,node,kind,vmid,created_at) "
                "VALUES(?,?,?,?,?)",
                (safe_int(body["owner_id"]), node, "qemu", vmid, now_iso()),
            )
        except Exception as exc:
            LOG.debug("assign after create failed: %s", exc)

    return jsonify(ok=True, vmid=vmid, name=name, task=task)


# ==============================================================================
# SECTION 11 - REST API : AUDIT, EXPORT, HEALTH
# ==============================================================================


@APP.get("/api/audit")
@admin_required
def api_audit():
    limit = min(safe_int(request.args.get("limit"), 200), 1000)
    return jsonify(entries=db_all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)))


@APP.get("/api/audit/export.csv")
@owner_required
def api_audit_export():
    rows = db_all("SELECT * FROM audit ORDER BY id DESC LIMIT 5000")
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["id", "created_at", "username", "role", "action", "target", "detail", "ip", "ok"]
    )
    for row in rows:
        writer.writerow(
            [row["id"], row["created_at"], row["username"], row["role"], row["action"],
             row["target"], row["detail"], row["ip"], row["ok"]]
        )
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=hypervm-audit.csv"},
    )


@APP.get("/api/inventory.csv")
@admin_required
def api_inventory_export():
    snapshot = fleet_snapshot()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["vmid", "name", "kind", "node", "status", "cpus", "cpu_pct",
         "mem_used", "mem_total", "disk_total", "uptime"]
    )
    for g in snapshot["guests"]:
        writer.writerow(
            [g["vmid"], g["name"], g["kind_label"], g["node"], g["status"], g["cpus"],
             g["cpu_pct"], g["mem_used"], g["mem_total"], g["disk_total"], g["uptime_h"]]
        )
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=hypervm-inventory.csv"},
    )


@APP.get("/api/health")
def api_health():
    state = {
        "app": APP_NAME,
        "vendor": APP_VENDOR,
        "version": APP_VERSION,
        "time": now_iso(),
        "proxmox_configured": PVE.configured(),
        "console_ready": PVE.console_capable() and bool(SOCK and ws_client),
        "pandas": bool(pd),
    }
    if PVE.configured():
        try:
            state["proxmox_version"] = PVE.version()
            state["reachable"] = True
        except ProxmoxError as exc:
            state["reachable"] = False
            state["error"] = str(exc)
    return jsonify(state)


# ==============================================================================
# SECTION 12 - WEB CONSOLE : ticket issuing + websocket bridge
# ==============================================================================

CONSOLE_SESSIONS = {}
CONSOLE_LOCK = threading.RLock()


def console_put(payload):
    token = secrets.token_urlsafe(24)
    with CONSOLE_LOCK:
        CONSOLE_SESSIONS[token] = {"payload": payload, "created": time.time()}
        for key in list(CONSOLE_SESSIONS):
            if time.time() - CONSOLE_SESSIONS[key]["created"] > 300:
                CONSOLE_SESSIONS.pop(key, None)
    return token


def console_take(token):
    with CONSOLE_LOCK:
        item = CONSOLE_SESSIONS.get(token)
    if not item:
        return None
    if time.time() - item["created"] > 300:
        with CONSOLE_LOCK:
            CONSOLE_SESSIONS.pop(token, None)
        return None
    return item["payload"]


@APP.post("/api/console/<kind>/<node>/<int:vmid>")
@login_required
def api_console_open(kind, node, vmid):
    _guard(kind, node, vmid)
    if not (SOCK and ws_client):
        return jsonify(
            error="Console bridge unavailable. Install flask-sock and websocket-client."
        ), 503
    data = PVE.term_proxy(node, kind, vmid) or {}
    token = console_put(
        {
            "node": node,
            "kind": "lxc" if kind in ("lxc", "ct") else "qemu",
            "vmid": vmid,
            "ticket": data.get("ticket"),
            "port": data.get("port"),
            "user": data.get("user") or PROXMOX_USER,
        }
    )
    write_audit("console_open", "%s/%s/%s" % (node, kind, vmid))
    return jsonify(ok=True, token=token, port=data.get("port"))


@APP.post("/api/console/node/<node>")
@owner_required
def api_console_node(node):
    if not (SOCK and ws_client):
        return jsonify(error="Console bridge unavailable"), 503
    data = PVE.node_term_proxy(node) or {}
    token = console_put(
        {
            "node": node,
            "kind": "node",
            "vmid": 0,
            "ticket": data.get("ticket"),
            "port": data.get("port"),
            "user": data.get("user") or PROXMOX_USER,
        }
    )
    write_audit("console_open_node", node)
    return jsonify(ok=True, token=token, port=data.get("port"))


@APP.post("/api/console/vnc/<kind>/<node>/<int:vmid>")
@login_required
def api_console_vnc(kind, node, vmid):
    """Returns a noVNC URL served by Proxmox itself (graphical console)."""
    _guard(kind, node, vmid)
    data = PVE.vnc_proxy(node, kind, vmid) or {}
    host = urlparse(PROXMOX_URL)
    url = "%s://%s/?console=%s&novnc=1&node=%s&resize=scale&vmid=%s" % (
        host.scheme or "https",
        host.netloc,
        "kvm" if kind == "qemu" else "lxc",
        quote(node, safe=""),
        vmid,
    )
    return jsonify(
        ok=True, url=url, port=data.get("port"), ticket_issued=bool(data.get("ticket"))
    )


def _proxmox_ws_url(node, kind, vmid, port, ticket):
    host = urlparse(PROXMOX_URL)
    scheme = "wss" if (host.scheme or "https") == "https" else "ws"
    if kind == "node":
        path = "/api2/json/nodes/%s/vncwebsocket" % quote(node, safe="")
    else:
        path = "/api2/json/nodes/%s/%s/%s/vncwebsocket" % (
            quote(node, safe=""),
            kind,
            safe_int(vmid),
        )
    return "%s://%s%s?port=%s&vncticket=%s" % (
        scheme,
        host.netloc,
        path,
        quote(str(port), safe=""),
        quote(str(ticket), safe=""),
    )


if SOCK and ws_client:

    @SOCK.route("/ws/console/<token>")
    def ws_console(sock, token):
        """Bridge browser xterm.js <-> Proxmox termproxy websocket."""
        payload = console_take(token)
        if not payload:
            sock.send("\r\n\x1b[31mConsole token expired. Reopen the console.\x1b[0m\r\n")
            return

        url = _proxmox_ws_url(
            payload["node"],
            payload["kind"],
            payload["vmid"],
            payload["port"],
            payload["ticket"],
        )
        try:
            tk = PVE.ticket()
        except ProxmoxError as exc:
            sock.send("\r\n\x1b[31m%s\x1b[0m\r\n" % exc)
            return

        headers = ["Cookie: PVEAuthCookie=%s" % (tk["ticket"] or "")]
        sslopt = None if PROXMOX_VERIFY_TLS else {"cert_reqs": ssl.CERT_NONE}

        try:
            upstream = ws_client.create_connection(
                url,
                header=headers,
                sslopt=sslopt,
                subprotocols=["binary"],
                timeout=15,
            )
        except Exception as exc:
            sock.send("\r\n\x1b[31mConsole connection failed: %s\x1b[0m\r\n" % exc)
            return

        # Proxmox expects "user:ticket\n" as the very first frame.
        try:
            upstream.send("%s:%s\n" % (payload["user"], payload["ticket"]))
        except Exception as exc:
            sock.send("\r\n\x1b[31mConsole handshake failed: %s\x1b[0m\r\n" % exc)
            upstream.close()
            return

        stop = threading.Event()

        def pump_up():
            """Proxmox -> browser."""
            try:
                while not stop.is_set():
                    frame = upstream.recv()
                    if frame is None:
                        break
                    if isinstance(frame, bytes):
                        frame = frame.decode("utf-8", "replace")
                    if frame:
                        sock.send(frame)
            except Exception:
                pass
            finally:
                stop.set()

        def keepalive():
            while not stop.wait(25):
                try:
                    upstream.send("2")
                except Exception:
                    break

        threading.Thread(target=pump_up, daemon=True).start()
        threading.Thread(target=keepalive, daemon=True).start()

        try:
            while not stop.is_set():
                message = sock.receive(timeout=30)
                if message is None:
                    continue
                if isinstance(message, bytes):
                    message = message.decode("utf-8", "replace")
                if message.startswith("\x01RESIZE:"):
                    try:
                        _, cols, rows = message.split(":")
                        upstream.send("1:%s:%s:" % (safe_int(cols, 80), safe_int(rows, 24)))
                    except Exception:
                        pass
                    continue
                upstream.send("0:%d:%s" % (len(message), message))
        except Exception:
            pass
        finally:
            stop.set()
            try:
                upstream.close()
            except Exception:
                pass


# ==============================================================================
# SECTION 13 - META ENDPOINT
# ==============================================================================


@APP.get("/api/meta")
def api_meta():
    return jsonify(
        app=APP_NAME,
        vendor=APP_VENDOR,
        tagline=APP_TAGLINE,
        version=APP_VERSION,
        logo=LOGO_URL,
        os_types=OS_TYPES,
        qemu_os_types=[{"value": v, "label": l} for v, l in QEMU_OS_TYPES],
        lxc_templates=[{"value": v, "label": l} for v, l in DEFAULT_LXC_TEMPLATES],
        lxc_actions=list(LXC_ACTIONS),
        qemu_actions=list(QEMU_ACTIONS),
        signup_open=bool(setting_get("signup_open", True)),
    )


# ==============================================================================
# SECTION 14 - FRONT-END (single page app, served inline)
# ==============================================================================

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>HyperVM - Powered by HyperNET LTD</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css"/>
<style>
:root{
  --bg:#070b14; --panel:#0d1424; --panel2:#111b30; --line:#1d2942;
  --txt:#e8eefc; --dim:#8fa2c4; --accent:#2f81f7; --accent2:#19c37d;
  --warn:#f5a623; --bad:#f2545b; --radius:14px;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
  font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif;font-size:14px}
a{color:var(--accent);text-decoration:none}
button{font:inherit;cursor:pointer}
.hidden{display:none !important}
.btn{background:var(--accent);color:#fff;border:0;border-radius:10px;
  padding:9px 14px;font-weight:600}
.btn:hover{filter:brightness(1.1)}
.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
.btn.ok{background:var(--accent2)} .btn.warn{background:var(--warn);color:#20160a}
.btn.bad{background:var(--bad)} .btn.sm{padding:5px 10px;font-size:12px;border-radius:8px}
input,select,textarea{background:var(--panel2);border:1px solid var(--line);
  color:var(--txt);border-radius:10px;padding:9px 11px;width:100%;outline:none}
input:focus,select:focus{border-color:var(--accent)}
label{display:block;font-size:12px;color:var(--dim);margin:0 0 5px}
.field{margin-bottom:12px}
.grid{display:grid;gap:12px}
.g2{grid-template-columns:repeat(2,1fr)} .g3{grid-template-columns:repeat(3,1fr)}
.g4{grid-template-columns:repeat(4,1fr)}
@media(max-width:900px){.g2,.g3,.g4{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:16px}
.card h3{margin:0 0 12px;font-size:14px;letter-spacing:.3px}
.kpi{font-size:26px;font-weight:700} .kpi small{font-size:12px;color:var(--dim);font-weight:500}
table{width:100%;border-collapse:collapse}
th,td{padding:9px 8px;text-align:left;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase}
tbody tr:hover{background:#0f182b}
.badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;
  border:1px solid var(--line);color:var(--dim)}
.badge.run{color:#0a2418;background:var(--accent2);border-color:transparent}
.badge.stop{color:#fff;background:#3b4560;border-color:transparent}
.bar{height:6px;border-radius:99px;background:#1a2338;overflow:hidden}
.bar i{display:block;height:100%;background:var(--accent)}
.bar i.hot{background:var(--warn)} .bar i.crit{background:var(--bad)}
#login{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;
  background:radial-gradient(1000px 500px at 50% -10%,#12244a,transparent),var(--bg)}
#login .card{width:100%;max-width:390px}
.brand{display:flex;align-items:center;gap:10px}
.brand img{height:34px;border-radius:8px}
.brand b{font-size:17px} .brand span{display:block;font-size:11px;color:var(--dim)}
#shell{display:flex;min-height:100vh}
aside{width:230px;background:var(--panel);border-right:1px solid var(--line);
  padding:16px;display:flex;flex-direction:column;gap:6px;position:sticky;top:0;height:100vh}
aside nav{display:flex;flex-direction:column;gap:4px;margin-top:14px;overflow:auto}
aside nav button{background:transparent;border:0;color:var(--dim);text-align:left;
  padding:9px 11px;border-radius:10px;font-weight:600}
aside nav button:hover{background:var(--panel2);color:var(--txt)}
aside nav button.active{background:var(--accent);color:#fff}
main{flex:1;padding:22px;max-width:100%;overflow:hidden}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;gap:10px;flex-wrap:wrap}
h2{margin:0;font-size:19px}
.muted{color:var(--dim);font-size:12px}
.modal{position:fixed;inset:0;background:rgba(3,6,14,.75);display:flex;
  align-items:center;justify-content:center;padding:20px;z-index:50}
.modal .card{width:100%;max-width:760px;max-height:88vh;overflow:auto}
.toast{position:fixed;right:18px;bottom:18px;z-index:99;display:flex;
  flex-direction:column;gap:8px}
.toast div{background:var(--panel2);border:1px solid var(--line);border-left:3px solid var(--accent);
  padding:11px 14px;border-radius:10px;max-width:360px}
.toast div.bad{border-left-color:var(--bad)} .toast div.ok{border-left-color:var(--accent2)}
#term{height:60vh;background:#000;border-radius:10px;padding:6px}
.rowline{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.scroll{overflow:auto;max-height:60vh}
pre{background:#060a12;border:1px solid var(--line);border-radius:10px;padding:12px;
  overflow:auto;font-size:12px;max-height:50vh}
</style>
</head>
<body>

<div id="login">
  <div class="card">
    <div class="brand" style="margin-bottom:18px">
      <img id="logo1" alt="logo"/>
      <div><b>HyperVM</b><span>Powered by HyperNET LTD</span></div>
    </div>
    <div id="loginBox">
      <div class="field"><label>Username</label><input id="lu" autocomplete="username"/></div>
      <div class="field"><label>Password</label><input id="lp" type="password" autocomplete="current-password"/></div>
      <button class="btn" style="width:100%" onclick="doLogin()">Sign in</button>
      <p class="muted" style="margin-top:12px">
        No account? <a href="#" onclick="toggleAuth(1);return false">Create one</a>
      </p>
    </div>
    <div id="signBox" class="hidden">
      <div class="field"><label>Username</label><input id="su"/></div>
      <div class="field"><label>Email (optional)</label><input id="se"/></div>
      <div class="field"><label>Password (min 8)</label><input id="sp" type="password"/></div>
      <button class="btn ok" style="width:100%" onclick="doSignup()">Create account</button>
      <p class="muted" style="margin-top:12px">
        <a href="#" onclick="toggleAuth(0);return false">Back to sign in</a>
      </p>
    </div>
  </div>
</div>

<div id="shell" class="hidden">
  <aside>
    <div class="brand"><img id="logo2" alt="logo"/><div><b>HyperVM</b><span id="ver"></span></div></div>
    <nav id="nav"></nav>
    <div style="margin-top:auto">
      <div class="muted" id="whoami"></div>
      <button class="btn ghost sm" style="width:100%;margin-top:8px" onclick="doLogout()">Sign out</button>
    </div>
  </aside>
  <main>
    <div class="topbar">
      <div><h2 id="pageTitle">Dashboard</h2><div class="muted" id="pageSub"></div></div>
      <div class="rowline">
        <button class="btn ghost sm" onclick="refresh(true)">Refresh</button>
        <button class="btn sm" onclick="openCreate('lxc')">New LXC</button>
        <button class="btn sm" onclick="openCreate('qemu')">New VM</button>
      </div>
    </div>
    <div id="view"></div>
  </main>
</div>

<div id="modalRoot"></div>
<div class="toast" id="toast"></div>

<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
<script>
var ME=null, META=null, DATA={nodes:[],guests:[],storages:[],totals:{},analytics:{}}, PAGE_ID="dash", TIMER=null;

function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];});}
function toast(msg,kind){var t=document.getElementById("toast");var d=document.createElement("div");
  d.className=kind||"";d.textContent=msg;t.appendChild(d);setTimeout(function(){d.remove();},5200);}
function pctClass(v){return v>=90?"crit":(v>=70?"hot":"");}

async function api(path,opts){
  opts=opts||{};
  var res=await fetch(path,{method:opts.method||"GET",
    headers:{"Content-Type":"application/json"},
    credentials:"same-origin",
    body:opts.body?JSON.stringify(opts.body):undefined});
  var data={};
  try{data=await res.json();}catch(e){}
  if(!res.ok){throw new Error(data.error||("Request failed ("+res.status+")"));}
  return data;
}

function toggleAuth(sign){
  document.getElementById("loginBox").classList.toggle("hidden",!!sign);
  document.getElementById("signBox").classList.toggle("hidden",!sign);
}
async function doLogin(){
  try{await api("/api/auth/login",{method:"POST",body:{
    username:document.getElementById("lu").value,password:document.getElementById("lp").value}});
    await boot();}catch(e){toast(e.message,"bad");}
}
async function doSignup(){
  try{await api("/api/auth/signup",{method:"POST",body:{
    username:document.getElementById("su").value,email:document.getElementById("se").value,
    password:document.getElementById("sp").value}});
    await boot();}catch(e){toast(e.message,"bad");}
}
async function doLogout(){try{await api("/api/auth/logout",{method:"POST"});}catch(e){}
  clearInterval(TIMER);ME=null;location.reload();}

var PAGES=[
  {id:"dash",label:"Dashboard",role:"user"},
  {id:"guests",label:"Containers & VMs",role:"user"},
  {id:"nodes",label:"Nodes",role:"user"},
  {id:"storage",label:"Storage",role:"user"},
  {id:"tasks",label:"Tasks",role:"user"},
  {id:"analytics",label:"Analytics",role:"user"},
  {id:"users",label:"Users",role:"owner"},
  {id:"audit",label:"Audit log",role:"admin"},
  {id:"settings",label:"Settings",role:"user"}
];
var RANK={user:1,admin:2,owner:3};
function can(role){return ME&&RANK[ME.role]>=RANK[role];}

function drawNav(){
  var nav=document.getElementById("nav");nav.innerHTML="";
  PAGES.filter(function(p){return can(p.role);}).forEach(function(p){
    var b=document.createElement("button");b.textContent=p.label;
    b.className=(p.id===PAGE_ID?"active":"");
    b.onclick=function(){PAGE_ID=p.id;drawNav();render();};
    nav.appendChild(b);
  });
}

async function boot(){
  META=await api("/api/meta");
  document.getElementById("logo1").src=META.logo;
  document.getElementById("logo2").src=META.logo;
  document.getElementById("ver").textContent="v"+META.version;
  var me=await api("/api/auth/me");
  ME=me.user;
  if(!ME){document.getElementById("login").classList.remove("hidden");
    document.getElementById("shell").classList.add("hidden");return;}
  document.getElementById("login").classList.add("hidden");
  document.getElementById("shell").classList.remove("hidden");
  document.getElementById("whoami").textContent=ME.username+" ("+ME.role+")";
  drawNav();
  await refresh(false);
  clearInterval(TIMER);TIMER=setInterval(function(){refresh(false);},15000);
}

async function refresh(force){
  try{
    DATA=await api("/api/cluster"+(force?"?force=1":""));
    if(!DATA.connected){document.getElementById("pageSub").textContent=DATA.reason||"Proxmox not connected";}
    else{document.getElementById("pageSub").textContent="Updated "+new Date().toLocaleTimeString();}
  }catch(e){toast(e.message,"bad");}
  render();
}

function render(){
  var page=PAGES.filter(function(p){return p.id===PAGE_ID;})[0]||PAGES[0];
  document.getElementById("pageTitle").textContent=page.label;
  var v=document.getElementById("view");
  if(PAGE_ID==="dash")v.innerHTML=viewDash();
  else if(PAGE_ID==="guests")v.innerHTML=viewGuests();
  else if(PAGE_ID==="nodes")v.innerHTML=viewNodes();
  else if(PAGE_ID==="storage")v.innerHTML=viewStorage();
  else if(PAGE_ID==="tasks"){v.innerHTML='<div class="card">Loading tasks...</div>';loadTasks();}
  else if(PAGE_ID==="analytics")v.innerHTML=viewAnalytics();
  else if(PAGE_ID==="users"){v.innerHTML='<div class="card">Loading users...</div>';loadUsers();}
  else if(PAGE_ID==="audit"){v.innerHTML='<div class="card">Loading audit...</div>';loadAudit();}
  else if(PAGE_ID==="settings")v.innerHTML=viewSettings();
}

function kpi(label,value,sub){
  return '<div class="card"><div class="muted">'+esc(label)+'</div>'+
    '<div class="kpi">'+esc(value)+'</div><div class="muted">'+esc(sub||"")+'</div></div>';
}
function barRow(pct){
  return '<div class="bar"><i class="'+pctClass(pct)+'" style="width:'+Math.min(100,pct||0)+'%"></i></div>';
}

function viewDash(){
  var t=DATA.totals||{};
  var html='<div class="grid g4">'+
    kpi("Nodes online",(t.nodes_online||0)+" / "+(t.nodes||0),(t.cores||0)+" CPU cores")+
    kpi("Guests running",(t.running||0)+" / "+(t.guests||0),(t.lxc||0)+" LXC - "+(t.qemu||0)+" VM")+
    kpi("Memory",(t.mem_pct||0)+"%",(t.mem_used_h||"0 B")+" of "+(t.mem_total_h||"0 B"))+
    kpi("Storage",(t.disk_pct||0)+"%",(t.disk_used_h||"0 B")+" of "+(t.disk_total_h||"0 B"))+
  '</div>';
  html+='<div class="grid g2" style="margin-top:12px"><div class="card"><h3>Node pressure</h3>'+nodeTable()+'</div>';
  html+='<div class="card"><h3>Insights</h3><ul class="muted" style="padding-left:18px;line-height:1.8">'+
    ((DATA.analytics&&DATA.analytics.insights)||["No analytics available."]).map(function(i){
      return "<li>"+esc(i)+"</li>";}).join("")+"</ul></div></div>";
  html+='<div class="card" style="margin-top:12px"><h3>Recent guests</h3>'+guestTable((DATA.guests||[]).slice(0,10))+'</div>';
  return html;
}

function nodeTable(){
  var rows=(DATA.nodes||[]).map(function(n){
    return "<tr><td><b>"+esc(n.node)+"</b><div class='muted'>"+esc(n.uptime_h)+"</div></td>"+
      "<td>"+(n.status==="online"?"<span class='badge run'>online</span>":"<span class='badge stop'>"+esc(n.status)+"</span>")+"</td>"+
      "<td>"+n.cpu_pct+"% <div class='muted'>"+n.cpus+" cores</div></td>"+
      "<td style='min-width:120px'>"+barRow(n.mem_pct)+"<div class='muted'>"+esc(n.mem_used_h)+" / "+esc(n.mem_total_h)+"</div></td>"+
      "<td style='min-width:120px'>"+barRow(n.disk_pct)+"<div class='muted'>"+esc(n.disk_used_h)+" / "+esc(n.disk_total_h)+"</div></td>"+
      "</tr>";}).join("");
  return "<div class='scroll'><table><thead><tr><th>Node</th><th>Status</th><th>CPU</th><th>Memory</th><th>Disk</th></tr></thead><tbody>"+
    (rows||"<tr><td colspan='5' class='muted'>No nodes.</td></tr>")+"</tbody></table></div>";
}

function guestTable(list){
  var rows=list.map(function(g){
    var run=g.status==="running";
    return "<tr><td><b>"+esc(g.name)+"</b><div class='muted'>"+g.vmid+" - "+esc(g.node)+"</div></td>"+
      "<td><span class='badge'>"+esc(g.kind_label)+"</span></td>"+
      "<td><span class='badge "+(run?"run":"stop")+"'>"+esc(g.status)+"</span></td>"+
      "<td>"+g.cpu_pct+"%<div class='muted'>"+g.cpus+" vCPU</div></td>"+
      "<td style='min-width:110px'>"+barRow(g.mem_pct)+"<div class='muted'>"+esc(g.mem_used_h)+" / "+esc(g.mem_total_h)+"</div></td>"+
      "<td class='muted'>"+esc(g.uptime_h)+"</td>"+
      "<td class='rowline'>"+
        (run?"<button class='btn sm warn' onclick=\"act('"+g.kind+"','"+esc(g.node)+"',"+g.vmid+",'shutdown')\">Stop</button>":
             "<button class='btn sm ok' onclick=\"act('"+g.kind+"','"+esc(g.node)+"',"+g.vmid+",'start')\">Start</button>")+
        "<button class='btn sm ghost' onclick=\"act('"+g.kind+"','"+esc(g.node)+"',"+g.vmid+",'reboot')\">Reboot</button>"+
        "<button class='btn sm ghost' onclick=\"openConsole('"+g.kind+"','"+esc(g.node)+"',"+g.vmid+")\">Console</button>"+
        "<button class='btn sm ghost' onclick=\"openGuest('"+g.kind+"','"+esc(g.node)+"',"+g.vmid+")\">Manage</button>"+
      "</td></tr>";}).join("");
  return "<div class='scroll'><table><thead><tr><th>Guest</th><th>Type</th><th>Status</th><th>CPU</th><th>Memory</th><th>Uptime</th><th></th></tr></thead><tbody>"+
    (rows||"<tr><td colspan='7' class='muted'>Nothing here yet.</td></tr>")+"</tbody></table></div>";
}

var FILTER={q:"",kind:"all",status:"all"};
function viewGuests(){
  var list=(DATA.guests||[]).filter(function(g){
    if(FILTER.kind!=="all"&&g.kind!==FILTER.kind)return false;
    if(FILTER.status!=="all"&&g.status!==FILTER.status)return false;
    if(FILTER.q&&(g.name+" "+g.vmid+" "+g.node).toLowerCase().indexOf(FILTER.q.toLowerCase())<0)return false;
    return true;});
  return '<div class="card"><div class="grid g4" style="margin-bottom:12px">'+
    '<input placeholder="Search name, vmid, node" value="'+esc(FILTER.q)+'" oninput="FILTER.q=this.value;render();this.focus()"/>'+
    '<select onchange="FILTER.kind=this.value;render()">'+opt(["all","lxc","qemu"],FILTER.kind)+'</select>'+
    '<select onchange="FILTER.status=this.value;render()">'+opt(["all","running","stopped"],FILTER.status)+'</select>'+
    '<a class="btn ghost sm" style="text-align:center;padding:9px" href="/api/inventory.csv">Export CSV</a>'+
    '</div>'+guestTable(list)+'</div>';
}
function opt(values,sel){return values.map(function(v){
  return '<option value="'+esc(v)+'"'+(v===sel?" selected":"")+'>'+esc(v)+'</option>';}).join("");}

function viewNodes(){return '<div class="card">'+nodeTable()+'</div>';}

function viewStorage(){
  var rows=(DATA.storages||[]).map(function(s){
    return "<tr><td><b>"+esc(s.storage)+"</b><div class='muted'>"+esc(s.node)+"</div></td>"+
      "<td class='muted'>"+esc(s.type)+"</td><td class='muted'>"+esc(s.content||"")+"</td>"+
      "<td style='min-width:140px'>"+barRow(s.used_pct)+"<div class='muted'>"+esc(s.used_h)+" / "+esc(s.total_h)+"</div></td>"+
      "<td class='muted'>"+esc(s.avail_h)+"</td></tr>";}).join("");
  return "<div class='card'><table><thead><tr><th>Storage</th><th>Type</th><th>Content</th><th>Used</th><th>Free</th></tr></thead><tbody>"+
    (rows||"<tr><td colspan='5' class='muted'>No storage visible.</td></tr>")+"</tbody></table></div>";
}

function viewAnalytics(){
  var a=DATA.analytics||{};
  if(!a.available)return '<div class="card">Analytics needs pandas installed on the server.</div>';
  function tbl(title,rows,cols){
    return '<div class="card"><h3>'+esc(title)+'</h3><table><thead><tr>'+
      cols.map(function(c){return "<th>"+esc(c[0])+"</th>";}).join("")+'</tr></thead><tbody>'+
      ((rows||[]).map(function(r){return "<tr>"+cols.map(function(c){
        return "<td>"+esc(r[c[1]])+"</td>";}).join("")+"</tr>";}).join("")||
        "<tr><td class='muted' colspan='"+cols.length+"'>No data.</td></tr>")+
      '</tbody></table></div>';
  }
  return '<div class="grid g2">'+
    tbl("By node",a.by_node,[["Node","node"],["Guests","guests"],["Running","running"],["vCPU","vcpus"],["Memory","mem_h"],["CPU %","cpu"]])+
    tbl("By type",a.by_kind,[["Type","kind_label"],["Count","count"],["Running","running"],["vCPU","vcpus"],["Memory","mem_h"]])+
    tbl("Top CPU",a.top_cpu,[["VMID","vmid"],["Name","name"],["Node","node"],["CPU %","cpu_pct"],["Mem %","mem_pct"]])+
    tbl("Top memory",a.top_mem,[["VMID","vmid"],["Name","name"],["Node","node"],["Memory","mem_used_h"],["Mem %","mem_pct"]])+
    tbl("Pressure",a.pressure,[["Node","node"],["Score","score"],["Band","band"],["CPU %","cpu_pct"],["Mem %","mem_pct"]])+
    tbl("Memory forecast",a.forecast,[["Node","node"],["Trend","trend_per_hour"],["Hours to full","hours_to_full"],["Samples","samples"]])+
  '</div>';
}

async function loadTasks(){
  try{var d=await api("/api/tasks");
    var rows=(d.tasks||[]).slice(0,80).map(function(t){
      var ok=(t.status==="OK"||t.status===undefined);
      return "<tr><td class='muted'>"+esc(t.node||"")+"</td><td>"+esc(t.type||"")+"</td>"+
        "<td class='muted'>"+esc(t.id||"")+"</td><td class='muted'>"+esc(t.user||"")+"</td>"+
        "<td><span class='badge "+(ok?"run":"stop")+"'>"+esc(t.status||"running")+"</span></td>"+
        "<td class='muted'>"+esc(t.starttime?new Date(t.starttime*1000).toLocaleString():"")+"</td></tr>";}).join("");
    document.getElementById("view").innerHTML="<div class='card'><table><thead><tr><th>Node</th><th>Type</th><th>Target</th><th>User</th><th>Status</th><th>Started</th></tr></thead><tbody>"+
      (rows||"<tr><td colspan='6' class='muted'>No tasks.</td></tr>")+"</tbody></table></div>";
  }catch(e){document.getElementById("view").innerHTML="<div class='card'>"+esc(e.message)+"</div>";}
}

async function loadAudit(){
  try{var d=await api("/api/audit?limit=200");
    var rows=(d.entries||[]).map(function(a){
      return "<tr><td class='muted'>"+esc(a.created_at)+"</td><td>"+esc(a.username)+"</td>"+
        "<td>"+esc(a.action)+"</td><td class='muted'>"+esc(a.target)+"</td>"+
        "<td class='muted'>"+esc(a.detail)+"</td><td class='muted'>"+esc(a.ip)+"</td>"+
        "<td>"+(a.ok?"<span class='badge run'>ok</span>":"<span class='badge stop'>fail</span>")+"</td></tr>";}).join("");
    document.getElementById("view").innerHTML="<div class='card'><div class='rowline' style='margin-bottom:10px'>"+
      (can("owner")?"<a class='btn ghost sm' href='/api/audit/export.csv'>Export CSV</a>":"")+"</div>"+
      "<div class='scroll'><table><thead><tr><th>When</th><th>User</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th><th></th></tr></thead><tbody>"+
      (rows||"<tr><td colspan='7' class='muted'>Empty.</td></tr>")+"</tbody></table></div></div>";
  }catch(e){document.getElementById("view").innerHTML="<div class='card'>"+esc(e.message)+"</div>";}
}

async function loadUsers(){
  try{var d=await api("/api/users");
    var rows=(d.users||[]).map(function(u){
      return "<tr><td><b>"+esc(u.username)+"</b><div class='muted'>"+esc(u.email||"")+"</div></td>"+
        "<td><select class='sm' onchange=\"updUser("+u.id+",{role:this.value})\">"+
          opt(["user","admin","owner"],u.role)+"</select></td>"+
        "<td>"+(u.active?"<span class='badge run'>active</span>":"<span class='badge stop'>disabled</span>")+"</td>"+
        "<td class='muted'>"+esc(u.vm_limit)+"</td>"+
        "<td class='muted'>"+esc(u.last_login||"never")+"</td>"+
        "<td class='muted'>"+((u.assignments||[]).map(function(a){return a.kind+":"+a.vmid;}).join(", ")||"all/none")+"</td>"+
        "<td class='rowline'>"+
          "<button class='btn sm ghost' onclick=\"updUser("+u.id+",{active:"+(u.active?0:1)+"})\">"+(u.active?"Disable":"Enable")+"</button>"+
          "<button class='btn sm ghost' onclick=\"assignPrompt("+u.id+")\">Assign</button>"+
          "<button class='btn sm bad' onclick=\"delUser("+u.id+")\">Delete</button>"+
        "</td></tr>";}).join("");
    document.getElementById("view").innerHTML=
      "<div class='card' style='margin-bottom:12px'><h3>Create user</h3><div class='grid g4'>"+
      "<input id='nu' placeholder='username'/><input id='ne' placeholder='email'/>"+
      "<input id='np' placeholder='password (blank = generated)'/>"+
      "<select id='nr'>"+opt(["user","admin","owner"],"user")+"</select></div>"+
      "<button class='btn' style='margin-top:10px' onclick='createUser()'>Create</button>"+
      "<label style='margin-top:14px'><input type='checkbox' style='width:auto' "+(d.signup_open?"checked":"")+
      " onchange='toggleSignup(this.checked)'/> Public registration open</label></div>"+
      "<div class='card'><table><thead><tr><th>User</th><th>Role</th><th>State</th><th>Limit</th><th>Last login</th><th>Assigned</th><th></th></tr></thead><tbody>"+
      rows+"</tbody></table></div>";
  }catch(e){document.getElementById("view").innerHTML="<div class='card'>"+esc(e.message)+"</div>";}
}
async function createUser(){
  try{var r=await api("/api/users",{method:"POST",body:{
    username:document.getElementById("nu").value,email:document.getElementById("ne").value,
    password:document.getElementById("np").value,role:document.getElementById("nr").value}});
    toast("User created. Password: "+r.password,"ok");loadUsers();}catch(e){toast(e.message,"bad");}
}
async function updUser(id,patch){try{await api("/api/users/"+id,{method:"PATCH",body:patch});
  toast("User updated","ok");loadUsers();}catch(e){toast(e.message,"bad");}}
async function delUser(id){if(!confirm("Delete this user?"))return;
  try{await api("/api/users/"+id,{method:"DELETE"});loadUsers();}catch(e){toast(e.message,"bad");}}
async function toggleSignup(open){try{await api("/api/settings/signup",{method:"POST",body:{open:!!open}});
  toast("Saved","ok");}catch(e){toast(e.message,"bad");}}
async function assignPrompt(id){
  var v=prompt("Assign guest as node/kind/vmid  (example: pve/lxc/101)");
  if(!v)return;var p=v.split("/");
  try{await api("/api/users/"+id+"/assign",{method:"POST",
    body:{node:p[0],kind:p[1],vmid:parseInt(p[2],10)}});loadUsers();}catch(e){toast(e.message,"bad");}
}

function viewSettings(){
  return '<div class="grid g2"><div class="card"><h3>Change password</h3>'+
    '<div class="field"><label>Current password</label><input id="pw0" type="password"/></div>'+
    '<div class="field"><label>New password</label><input id="pw1" type="password"/></div>'+
    '<button class="btn" onclick="changePw()">Update password</button></div>'+
    '<div class="card"><h3>Session</h3><p class="muted">Signed in as <b>'+esc(ME.username)+
    '</b> with role <b>'+esc(ME.role)+'</b>.</p>'+
    '<p class="muted">HyperVM '+esc(META.version)+' - '+esc(META.tagline)+'</p>'+
    '<button class="btn ghost" onclick="healthCheck()">Run health check</button></div></div>';
}
async function changePw(){
  try{await api("/api/auth/password",{method:"PATCH",body:{
    current:document.getElementById("pw0").value,next:document.getElementById("pw1").value}});
    toast("Password updated","ok");}catch(e){toast(e.message,"bad");}
}
async function healthCheck(){try{var h=await api("/api/health");
  modal("Health","<pre>"+esc(JSON.stringify(h,null,2))+"</pre>");}catch(e){toast(e.message,"bad");}}

function modal(title,html,wide){
  document.getElementById("modalRoot").innerHTML=
    '<div class="modal" onclick="if(event.target===this)closeModal()"><div class="card" '+
    (wide?'style="max-width:1000px"':'')+'><div class="topbar"><h2>'+esc(title)+'</h2>'+
    '<button class="btn ghost sm" onclick="closeModal()">Close</button></div>'+html+'</div></div>';
}
function closeModal(){document.getElementById("modalRoot").innerHTML="";if(window.__ws){try{window.__ws.close();}catch(e){}window.__ws=null;}}

async function act(kind,node,vmid,action){
  try{await api("/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid+"/action/"+action,{method:"POST"});
    toast(action+" sent to "+vmid,"ok");setTimeout(function(){refresh(true);},2500);}
  catch(e){toast(e.message,"bad");}
}

async function openGuest(kind,node,vmid){
  try{
    var d=await api("/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid);
    var snaps=(d.snapshots||[]).map(function(s){
      return "<tr><td>"+esc(s.name)+"</td><td class='muted'>"+esc(s.description||"")+"</td>"+
        "<td class='rowline'>"+
        "<button class='btn sm ghost' onclick=\"snapAction('"+kind+"','"+esc(node)+"',"+vmid+",'"+esc(s.name)+"','rollback')\">Rollback</button>"+
        "<button class='btn sm bad' onclick=\"snapAction('"+kind+"','"+esc(node)+"',"+vmid+",'"+esc(s.name)+"','delete')\">Delete</button>"+
        "</td></tr>";}).join("");
    var nodes=(DATA.nodes||[]).map(function(n){return n.node;});
    var cfg=d.config||{};
    modal("Manage "+(((d.status||{}).name)||vmid),
      '<div class="grid g2"><div class="card"><h3>Resources</h3>'+
      '<div class="field"><label>Cores</label><input id="mCores" value="'+esc(cfg.cores||"")+'"/></div>'+
      '<div class="field"><label>Memory (MB)</label><input id="mMem" value="'+esc(cfg.memory||"")+'"/></div>'+
      '<div class="field"><label>Name / hostname</label><input id="mName" value="'+esc(cfg.hostname||cfg.name||"")+'"/></div>'+
      '<button class="btn" onclick="saveGuest(\''+kind+'\',\''+esc(node)+'\','+vmid+')">Save changes</button> '+
      '<button class="btn ghost" onclick="resizeGuest(\''+kind+'\',\''+esc(node)+'\','+vmid+')">Grow disk +8G</button>'+
      '</div><div class="card"><h3>Operations</h3><div class="rowline">'+
      '<button class="btn ghost" onclick="openConsole(\''+kind+'\',\''+esc(node)+'\','+vmid+')">Console</button>'+
      '<button class="btn ghost" onclick="backupGuest(\''+kind+'\',\''+esc(node)+'\','+vmid+')">Backup</button>'+
      '<button class="btn ghost" onclick="cloneGuest(\''+kind+'\',\''+esc(node)+'\','+vmid+')">Clone</button>'+
      '<button class="btn bad" onclick="destroyGuest(\''+kind+'\',\''+esc(node)+'\','+vmid+')">Destroy</button></div>'+
      '<div class="field" style="margin-top:14px"><label>Migrate to node</label>'+
      '<select id="mTarget">'+opt(nodes,node)+'</select></div>'+
      '<button class="btn ghost" onclick="migrateGuest(\''+kind+'\',\''+esc(node)+'\','+vmid+')">Migrate</button>'+
      '</div></div>'+
      '<div class="card" style="margin-top:12px"><h3>Snapshots</h3>'+
      '<div class="rowline" style="margin-bottom:10px"><input id="snapName" placeholder="snapshot name" style="max-width:260px"/>'+
      '<button class="btn sm" onclick="snapCreate(\''+kind+'\',\''+esc(node)+'\','+vmid+')">Create snapshot</button></div>'+
      '<table><tbody>'+(snaps||"<tr><td class='muted'>No snapshots.</td></tr>")+'</tbody></table></div>'+
      '<div class="card" style="margin-top:12px"><h3>Raw config</h3><pre>'+esc(JSON.stringify(cfg,null,2))+'</pre></div>',
      true);
  }catch(e){toast(e.message,"bad");}
}
async function saveGuest(kind,node,vmid){
  var body={cores:document.getElementById("mCores").value,memory:document.getElementById("mMem").value};
  var nm=document.getElementById("mName").value;
  if(nm){if(kind==="lxc")body.hostname=nm;else body.name=nm;}
  try{await api("/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid+"/config",{method:"PATCH",body:body});
    toast("Saved","ok");refresh(true);}catch(e){toast(e.message,"bad");}
}
async function resizeGuest(kind,node,vmid){
  try{await api("/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid+"/resize",
    {method:"POST",body:{disk:kind==="lxc"?"rootfs":"scsi0",size:"+8G"}});
    toast("Disk resize requested","ok");}catch(e){toast(e.message,"bad");}
}
async function backupGuest(kind,node,vmid){
  var storage=prompt("Backup storage","local");if(!storage)return;
  try{await api("/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid+"/backup",
    {method:"POST",body:{storage:storage}});toast("Backup started","ok");}catch(e){toast(e.message,"bad");}
}
async function cloneGuest(kind,node,vmid){
  var name=prompt("Name for the clone");if(!name)return;
  try{var r=await api("/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid+"/clone",
    {method:"POST",body:{name:name,full:true}});toast("Clone started as "+r.newid,"ok");
    closeModal();refresh(true);}catch(e){toast(e.message,"bad");}
}
async function migrateGuest(kind,node,vmid){
  var target=document.getElementById("mTarget").value;
  try{await api("/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid+"/migrate",
    {method:"POST",body:{target:target,online:true}});toast("Migration started","ok");
    closeModal();refresh(true);}catch(e){toast(e.message,"bad");}
}
async function destroyGuest(kind,node,vmid){
  if(prompt("Type the VMID to permanently destroy this guest")!==String(vmid))return;
  try{await api("/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid,{method:"DELETE"});
    toast("Guest destroyed","ok");closeModal();refresh(true);}catch(e){toast(e.message,"bad");}
}
async function snapCreate(kind,node,vmid){
  try{await api("/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid+"/snapshots",
    {method:"POST",body:{name:document.getElementById("snapName").value}});
    toast("Snapshot requested","ok");openGuest(kind,node,vmid);}catch(e){toast(e.message,"bad");}
}
async function snapAction(kind,node,vmid,name,what){
  if(what==="delete"&&!confirm("Delete snapshot "+name+"?"))return;
  var base="/api/guest/"+kind+"/"+encodeURIComponent(node)+"/"+vmid+"/snapshots/"+encodeURIComponent(name);
  try{await api(what==="delete"?base:base+"/rollback",{method:what==="delete"?"DELETE":"POST"});
    toast("Done","ok");openGuest(kind,node,vmid);}catch(e){toast(e.message,"bad");}
}

async function openConsole(kind,node,vmid){
  try{
    var r=await api("/api/console/"+kind+"/"+encodeURIComponent(node)+"/"+vmid,{method:"POST"});
    modal("Console - "+node+"/"+vmid,'<div id="term"></div>',true);
    var term=new Terminal({fontSize:13,cursorBlink:true,theme:{background:"#000000"}});
    var fit=new FitAddon.FitAddon();term.loadAddon(fit);
    term.open(document.getElementById("term"));fit.fit();
    var proto=location.protocol==="https:"?"wss":"ws";
    var ws=new WebSocket(proto+"://"+location.host+"/ws/console/"+r.token);
    window.__ws=ws;
    ws.onopen=function(){term.writeln("\x1b[32mConnected.\x1b[0m");
      ws.send("\x01RESIZE:"+term.cols+":"+term.rows);};
    ws.onmessage=function(ev){term.write(ev.data);};
    ws.onclose=function(){term.writeln("\r\n\x1b[31mDisconnected.\x1b[0m");};
    term.onData(function(d){if(ws.readyState===1)ws.send(d);});
    window.addEventListener("resize",function(){try{fit.fit();
      if(ws.readyState===1)ws.send("\x01RESIZE:"+term.cols+":"+term.rows);}catch(e){}});
  }catch(e){toast(e.message,"bad");}
}

async function openCreate(kind){
  if(!can("admin")){toast("Admins only","bad");return;}
  var nodes=(DATA.nodes||[]).map(function(n){return n.node;});
  if(!nodes.length){toast("No nodes available","bad");return;}
  var stores=(DATA.storages||[]).map(function(s){return s.storage;})
    .filter(function(v,i,a){return a.indexOf(v)===i;});
  if(!stores.length)stores=["local-lvm"];
  var common='<div class="grid g3">'+
    '<div class="field"><label>Node</label><select id="cNode">'+opt(nodes,nodes[0])+'</select></div>'+
    '<div class="field"><label>VMID (blank = next free)</label><input id="cVmid"/></div>'+
    '<div class="field"><label>Storage</label><select id="cStore">'+opt(stores,stores[0])+'</select></div>'+
    '<div class="field"><label>Cores</label><input id="cCores" value="'+(kind==="lxc"?"1":"2")+'"/></div>'+
    '<div class="field"><label>Memory (MB)</label><input id="cMem" value="'+(kind==="lxc"?"1024":"2048")+'"/></div>'+
    '<div class="field"><label>Disk (GB)</label><input id="cDisk" value="'+(kind==="lxc"?"8":"32")+'"/></div>'+
    '<div class="field"><label>Bridge</label><input id="cBridge" value="vmbr0"/></div>'+
    '<div class="field"><label>IP (dhcp or CIDR)</label><input id="cIp" value="dhcp"/></div>'+
    '<div class="field"><label>Gateway</label><input id="cGw"/></div>'+
    '</div>';
  var extra;
  if(kind==="lxc"){
    var tpls=(META.lxc_templates||[]).map(function(t){
      return '<option value="local:vztmpl/'+esc(t.value)+'">'+esc(t.label)+'</option>';}).join("");
    extra='<div class="grid g3">'+
      '<div class="field"><label>Hostname</label><input id="cName" placeholder="ct-name"/></div>'+
      '<div class="field"><label>Template</label><select id="cTpl">'+tpls+'</select></div>'+
      '<div class="field"><label>Root password (blank = generated)</label><input id="cPass"/></div>'+
      '</div>';
  }else{
    var os=(META.qemu_os_types||[]).map(function(t){
      return '<option value="'+esc(t.value)+'">'+esc(t.label)+'</option>';}).join("");
    extra='<div class="grid g3">'+
      '<div class="field"><label>Name</label><input id="cName" placeholder="vm-name"/></div>'+
      '<div class="field"><label>Guest OS</label><select id="cOs">'+os+'</select></div>'+
      '<div class="field"><label>ISO (storage:iso/file.iso)</label><input id="cIso"/></div>'+
      '</div>';
  }
  modal("Create "+(kind==="lxc"?"LXC container":"virtual machine"),
    '<div class="card">'+common+extra+
    '<label><input type="checkbox" id="cStart" checked style="width:auto"/> Start after creation</label>'+
    '<div style="margin-top:14px"><button class="btn" onclick="submitCreate(\''+kind+'\')">Create</button></div></div>',true);
}
async function submitCreate(kind){
  var v=function(id){var e=document.getElementById(id);return e?e.value:"";};
  var body={node:v("cNode"),vmid:v("cVmid"),storage:v("cStore"),cores:v("cCores"),
    memory:v("cMem"),disk:v("cDisk"),bridge:v("cBridge"),ip:v("cIp"),gateway:v("cGw"),
    start:document.getElementById("cStart").checked};
  if(kind==="lxc"){body.hostname=v("cName");body.template=v("cTpl");body.password=v("cPass");}
  else{body.name=v("cName");body.ostype=v("cOs");if(v("cIso"))body.iso=v("cIso");}
  try{var r=await api("/api/create/"+kind,{method:"POST",body:body});
    closeModal();
    toast("Created "+r.vmid+(r.password?" - root password: "+r.password:""),"ok");
    setTimeout(function(){refresh(true);},3000);}catch(e){toast(e.message,"bad");}
}

document.addEventListener("keydown",function(e){if(e.key==="Escape")closeModal();});
document.addEventListener("keypress",function(e){
  if(e.key==="Enter"&&!document.getElementById("login").classList.contains("hidden")){
    if(document.getElementById("signBox").classList.contains("hidden"))doLogin();else doSignup();}});

boot().catch(function(e){console.error(e);toast(e.message,"bad");});
</script>
</body>
</html>
"""


@APP.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


@APP.get("/favicon.ico")
def favicon():
    return Response("", status=204)


# ==============================================================================
# SECTION 15 - ENTRY POINT
# ==============================================================================


def bootstrap():
    init_db()
    LOG.info("%s %s - %s", APP_NAME, APP_VERSION, APP_TAGLINE)
    LOG.info("Database: %s", DB_PATH)
    if PVE.configured():
        LOG.info("Proxmox endpoint: %s", PROXMOX_URL)
    else:
        LOG.warning(
            "Proxmox is not configured. Set PROXMOX_URL, PROXMOX_TOKEN_ID and "
            "PROXMOX_TOKEN_SECRET, then restart."
        )
    if not (SOCK and ws_client):
        LOG.warning(
            "Console bridge disabled. Install flask-sock and websocket-client."
        )
    if not pd:
        LOG.warning("pandas is not installed - analytics will be limited.")


bootstrap()


if __name__ == "__main__":
    LOG.info("Listening on http://%s:%s", HOST, PORT)
    APP.run(host=HOST, port=PORT, threaded=True, debug=False)
