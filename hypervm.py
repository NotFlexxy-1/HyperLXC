
#!/usr/bin/env python3
"""
HyperVM - real single-file Proxmox LXC manager.

Install:
    pip install flask requests pandas

Run:
    python hypervm.py

Environment:
    PROXMOX_URL=https://192.168.1.10:8006
    PROXMOX_TOKEN_ID=admin@pam!hypervm
    PROXMOX_TOKEN_SECRET=YOUR_TOKEN_SECRET
    PROXMOX_VERIFY_TLS=false
    HYPERVM_SECRET=replace-with-a-long-random-secret

Default HyperVM Owner:
    admin / admin123

The Proxmox API token is server-side only. SQLite stores HyperVM users and
PBKDF2 password hashes. pandas performs live cluster data analysis.
"""

import os
import sqlite3
import secrets
import hashlib
import hmac
from functools import wraps
from datetime import datetime, timezone
from urllib.parse import quote

import requests
import pandas as pd
from flask import Flask, request, jsonify, session, render_template_string

APP = Flask(__name__)
APP.secret_key = os.getenv("HYPERVM_SECRET", secrets.token_hex(32))
APP.config["SESSION_COOKIE_HTTPONLY"] = True
APP.config["SESSION_COOKIE_SAMESITE"] = "Lax"

HOST = os.getenv("HYPERVM_HOST", "0.0.0.0")
PORT = int(os.getenv("HYPERVM_PORT", "8080"))
DB = os.getenv("HYPERVM_DB", "hypervm.db")

PROXMOX_URL = os.getenv("PROXMOX_URL", "").rstrip("/")
PROXMOX_TOKEN_ID = os.getenv("PROXMOX_TOKEN_ID", "")
PROXMOX_TOKEN_SECRET = os.getenv("PROXMOX_TOKEN_SECRET", "")
PROXMOX_VERIFY_TLS = os.getenv("PROXMOX_VERIFY_TLS", "false").lower() in {
    "1", "true", "yes"
}

LOGO = "https://i.postimg.cc/VvWF53xk/hypernet-logo.png"


# =========================
# Database / authentication
# =========================

def connection():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def make_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 310_000, 32
    )
    return salt.hex() + "$" + digest.hex()


def check_password(password, stored):
    try:
        salt_hex, digest = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        test = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 310_000, 32
        ).hex()
        return hmac.compare_digest(test, digest)
    except Exception:
        return False


def init_db():
    c = connection()
    c.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "password_hash TEXT NOT NULL,"
        "role TEXT NOT NULL DEFAULT 'user',"
        "active INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS audit ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT,"
        "action TEXT NOT NULL,"
        "detail TEXT,"
        "created_at TEXT NOT NULL)"
    )
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        c.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            (
                "admin",
                make_password("admin123"),
                "owner",
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ),
        )
    c.commit()
    c.close()


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    c = connection()
    row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    c.close()
    return dict(row) if row else None


def write_audit(action, detail=""):
    c = connection()
    c.execute(
        "INSERT INTO audit(username,action,detail,created_at) VALUES(?,?,?,?)",
        (
            session.get("username", "system"),
            action,
            str(detail)[:1200],
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ),
    )
    c.commit()
    c.close()


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
        u = current_user()
        if not u:
            return jsonify(error="Authentication required"), 401
        if u["role"] not in ("owner", "admin"):
            return jsonify(error="Admin or Owner role required"), 403
        return fn(*args, **kwargs)
    return wrapped


def owner_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        u = current_user()
        if not u:
            return jsonify(error="Authentication required"), 401
        if u["role"] != "owner":
            return jsonify(error="Owner role required"), 403
        return fn(*args, **kwargs)
    return wrapped


# =========================
# Proxmox REST API
# =========================

class Proxmox:
    def __init__(self):
        self.base = (
            PROXMOX_URL + "/api2/json"
            if PROXMOX_URL
            else ""
        )
        self.http = requests.Session()
        if PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET:
            self.http.headers["Authorization"] = (
                "PVEAPIToken=" + PROXMOX_TOKEN_ID + "=" + PROXMOX_TOKEN_SECRET
            )

    def configured(self):
        return bool(
            self.base and PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET
        )

    def call(self, method, path, data=None):
        if not self.configured():
            raise RuntimeError(
                "Proxmox is not configured. Set PROXMOX_URL, "
                "PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET."
            )
        response = self.http.request(
            method,
            self.base + path,
            data=data or {},
            verify=PROXMOX_VERIFY_TLS,
            timeout=20,
        )
        try:
            payload = response.json()
        except Exception:
            payload = {}
        if not response.ok:
            message = (
                payload.get("errors")
                or payload.get("message")
                or response.text[:500]
            )
            raise RuntimeError(str(message))
        return payload.get("data", payload)

    def nodes(self):
        return self.call("GET", "/nodes")

    def lxcs(self, node):
        return self.call(
            "GET", "/nodes/" + quote(node, safe="") + "/lxc"
        )

    def lxc_status(self, node, vmid):
        return self.call(
            "GET",
            "/nodes/" + quote(node, safe="") +
            "/lxc/" + str(int(vmid)) + "/status/current",
        )

    def lxc_config(self, node, vmid):
        return self.call(
            "GET",
            "/nodes/" + quote(node, safe="") +
            "/lxc/" + str(int(vmid)) + "/config",
        )

    def lxc_action(self, node, vmid, action):
        if action not in (
            "start", "stop", "shutdown", "reboot", "suspend", "resume"
        ):
            raise ValueError("Unsupported LXC action")
        return self.call(
            "POST",
            "/nodes/" + quote(node, safe="") +
            "/lxc/" + str(int(vmid)) + "/status/" + action,
        )

    def create_lxc(self, node, data):
        return self.call(
            "POST",
            "/nodes/" + quote(node, safe="") + "/lxc",
            data,
        )


PVE = Proxmox()


def enriched_nodes():
    result = []
    for node in PVE.nodes() or []:
        mem = float(node.get("mem") or 0)
        maxmem = float(node.get("maxmem") or 0)
        disk = float(node.get("disk") or 0)
        maxdisk = float(node.get("maxdisk") or 0)
        result.append(
            {
                **node,
                "cpu_pct": round(float(node.get("cpu") or 0) * 100, 1),
                "mem_pct": round(mem / maxmem * 100, 1) if maxmem else 0,
                "disk_pct": round(disk / maxdisk * 100, 1) if maxdisk else 0,
                "mem_used": mem,
                "mem_total": maxmem,
                "disk_used": disk,
                "disk_total": maxdisk,
                "uptime_hours": round(
                    float(node.get("uptime") or 0) / 3600, 1
                ),
            }
        )
    return result


def all_containers(nodes):
    rows = []
    for node in nodes:
        try:
            for x in PVE.lxcs(node["node"]) or []:
                rows.append(
                    {
                        **x,
                        "node": node["node"],
                        "cpu_pct": round(
                            float(x.get("cpu") or 0) * 100, 1
                        ),
                        "mem_mb": round(
                            float(x.get("mem") or 0) / 1024 / 1024, 1
                        ),
                        "disk_gb": round(
                            float(x.get("disk") or 0)
                            / 1024 / 1024 / 1024,
                            2,
                        ),
                    }
                )
        except Exception as exc:
            rows.append({"node": node["node"], "error": str(exc)})
    return rows


# =========================
# Authentication API
# =========================

@APP.post("/api/auth/login")
def api_login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", ""))

    c = connection()
    row = c.execute(
        "SELECT * FROM users WHERE username=?", (username,)
    ).fetchone()
    c.close()

    if (
        not row
        or not row["active"]
        or not check_password(password, row["password_hash"])
    ):
        return jsonify(error="Invalid username or password"), 401

    session.clear()
    session["uid"] = row["id"]
    session["username"] = row["username"]
    write_audit("login")

    return jsonify(
        user={
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
        }
    )


@APP.post("/api/auth/signup")
def api_signup():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", ""))

    if (
        len(username) < 3
        or len(username) > 32
        or not username.replace("_", "").isalnum()
    ):
        return jsonify(error="Username must be 3-32 letters/numbers/underscores"), 400

    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400

    c = connection()
    try:
        cur = c.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            (
                username,
                make_password(password),
                "user",
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ),
        )
        c.commit()
        uid = cur.lastrowid
    except sqlite3.IntegrityError:
        c.close()
        return jsonify(error="Username already exists"), 409
    c.close()

    session.clear()
    session["uid"] = uid
    session["username"] = username
    write_audit("signup")

    return jsonify(
        user={"id": uid, "username": username, "role": "user"}
    )


@APP.post("/api/auth/logout")
def api_logout():
    write_audit("logout")
    session.clear()
    return jsonify(ok=True)


@APP.get("/api/auth/me")
def api_me():
    u = current_user()
    if not u:
        return jsonify(user=None)
    return jsonify(
        user={"id": u["id"], "username": u["username"], "role": u["role"]}
    )


@APP.patch("/api/auth/password")
@login_required
def api_password():
    body = request.get_json(silent=True) or {}
    u = current_user()
    if not check_password(
        str(body.get("current", "")), u["password_hash"]
    ):
        return jsonify(error="Current password is incorrect"), 400

    new_password = str(body.get("next", ""))
    if len(new_password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400

    c = connection()
    c.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        (make_password(new_password), u["id"]),
    )
    c.commit()
    c.close()
    write_audit("password_changed")
    return jsonify(ok=True)


# =========================
# Proxmox API routes
# =========================

@APP.get("/api/cluster")
@login_required
def api_cluster():
    try:
        nodes = enriched_nodes()
        return jsonify(
            connected=True,
            nodes=nodes,
            containers=all_containers(nodes),
        )
    except Exception as exc:
        return jsonify(connected=False, error=str(exc)), 503


@APP.get("/api/nodes")
@login_required
def api_nodes():
    try:
        return jsonify(nodes=enriched_nodes())
    except Exception as exc:
        return jsonify(error=str(exc)), 503


@APP.get("/api/lxc/<node>/<int:vmid>")
@login_required
def api_lxc_detail(node, vmid):
    try:
        return jsonify(
            status=PVE.lxc_status(node, vmid),
            config=PVE.lxc_config(node, vmid),
        )
    except Exception as exc:
        return jsonify(error=str(exc)), 503


@APP.post("/api/lxc/<node>/<int:vmid>/<action>")
@admin_required
def api_lxc_action(node, vmid, action):
    try:
        task = PVE.lxc_action(node, vmid, action)
        write_audit("lxc_action", f"{node}/{vmid}: {action}")
        return jsonify(ok=True, task=task)
    except Exception as exc:
        return jsonify(error=str(exc)), 503


@APP.post("/api/lxc/<node>/create")
@admin_required
def api_lxc_create(node):
    body = request.get_json(silent=True) or {}
    allowed = {
        "vmid", "ostemplate", "hostname", "storage", "rootfs",
        "memory", "swap", "cores", "password", "net0",
        "unprivileged", "start",
    }
    data = {
        key: value
        for key, value in body.items()
        if key in allowed and value not in ("", None)
    }
    try:
        task = PVE.create_lxc(node, data)
        write_audit("lxc_create", f"{node}: {data}")
        return jsonify(ok=True, task=task)
    except Exception as exc:
        return jsonify(error=str(exc)), 503


# =========================
# User / role management
# =========================

@APP.get("/api/users")
@admin_required
def api_users():
    c = connection()
    rows = c.execute(
        "SELECT id,username,role,active,created_at FROM users ORDER BY id"
    ).fetchall()
    c.close()
    return jsonify(users=[dict(x) for x in rows])


@APP.post("/api/users")
@admin_required
def api_user_create():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", ""))

    if len(username) < 3 or len(password) < 8:
        return jsonify(error="Username/password is too short"), 400

    c = connection()
    try:
        c.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            (
                username,
                make_password(password),
                "user",
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ),
        )
        c.commit()
    except sqlite3.IntegrityError:
        c.close()
        return jsonify(error="Username already exists"), 409
    c.close()

    write_audit("user_created", username)
    return jsonify(ok=True)


@APP.patch("/api/users/<int:uid>")
@owner_required
def api_user_update(uid):
    if uid == 1:
        return jsonify(error="Main Owner account is protected"), 403

    body = request.get_json(silent=True) or {}
    changes = []
    values = []

    if "role" in body:
        role = body["role"]
        if role not in ("user", "admin"):
            return jsonify(error="Role must be user or admin"), 400
        changes.append("role=?")
        values.append(role)

    if "active" in body:
        changes.append("active=?")
        values.append(1 if body["active"] else 0)

    if not changes:
        return jsonify(ok=True)

    values.append(uid)
    c = connection()
    c.execute(
        "UPDATE users SET " + ",".join(changes) + " WHERE id=?",
        values,
    )
    c.commit()
    c.close()
    write_audit("user_updated", f"id={uid}, changes={changes}")
    return jsonify(ok=True)


# =========================
# Pandas data analysis
# =========================

@APP.get("/api/analytics")
@login_required
def api_analytics():
    try:
        nodes = enriched_nodes()
        containers = all_containers(nodes)

        node_df = pd.DataFrame(nodes)
        lxc_df = pd.DataFrame(containers)

        def mean_column(name):
            if name not in node_df:
                return 0
            values = pd.to_numeric(
                node_df[name], errors="coerce"
            ).fillna(0)
            return round(float(values.mean()), 1)

        def max_column(name):
            if name not in node_df:
                return 0
            values = pd.to_numeric(
                node_df[name], errors="coerce"
            ).fillna(0)
            return round(float(values.max()), 1)

        running = (
            int((lxc_df["status"] == "running").sum())
            if "status" in lxc_df
            else 0
        )

        risks = []
        for _, row in node_df.iterrows():
            flags = []
            if float(row.get("cpu_pct", 0)) >= 80:
                flags.append("CPU")
            if float(row.get("mem_pct", 0)) >= 85:
                flags.append("RAM")
            if float(row.get("disk_pct", 0)) >= 85:
                flags.append("Disk")
            if flags:
                risks.append(
                    {"node": row.get("node"), "risks": flags}
                )

        return jsonify(
            summary={
                "nodes": len(nodes),
                "containers": len(containers),
                "avg_cpu": mean_column("cpu_pct"),
                "avg_memory": mean_column("mem_pct"),
                "avg_disk": mean_column("disk_pct"),
                "peak_cpu": max_column("cpu_pct"),
                "running": running,
                "stopped": len(containers) - running,
                "risk_nodes": len(risks),
            },
            node_rows=[
                {
                    "node": x["node"],
                    "cpu": x["cpu_pct"],
                    "memory": x["mem_pct"],
                    "disk": x["disk_pct"],
                }
                for x in nodes
            ],
            risk_nodes=risks,
        )
    except Exception as exc:
        return jsonify(error=str(exc)), 503


# =========================
# Modern frontend
# =========================

HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HyperVM — Proxmox LXC Manager</title>
<link rel="icon" href="{{logo}}">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#050811;--panel:#0b1220;--panel2:#101a2c;--line:#1d2c45;--text:#edf4ff;--muted:#8294ae;--blue:#3b8cff;--purple:#7958ff;--green:#2ee39b;--red:#ff667d;--yellow:#f4c85b}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 450px at 15% -10%,#163b79 0,transparent 65%),radial-gradient(850px 500px at 100% 0,#281b64 0,transparent 65%),var(--bg);color:var(--text);font:14px Inter,system-ui,sans-serif}button,input,select{font:inherit}button{cursor:pointer}::-webkit-scrollbar{width:8px}::-webkit-scrollbar-thumb{background:#263957;border-radius:99px}
.login{min-height:100vh;display:grid;place-items:center;padding:22px}.loginbox{width:min(430px,100%);padding:30px;border:1px solid var(--line);border-radius:25px;background:#0a1120f2;box-shadow:0 25px 80px #0009;backdrop-filter:blur(20px)}
.brand{display:flex;align-items:center;gap:12px}.brand img{width:52px;height:52px;object-fit:contain}.brand b{font-size:26px}.brand small{display:block;color:var(--muted)}.tabs{display:grid;grid-template-columns:1fr 1fr;background:#070d17;border:1px solid var(--line);padding:4px;border-radius:10px;margin:25px 0 17px}.tabs button{border:0;background:transparent;color:var(--muted);padding:10px;border-radius:8px}.tabs .on{background:#17243b;color:white}
.field{margin:13px 0}.field label{display:block;color:#879ab5;font-size:10px;text-transform:uppercase;letter-spacing:.09em;margin-bottom:7px}.field input,.field select{width:100%;padding:12px;background:#080e19;border:1px solid var(--line);color:white;border-radius:10px;outline:0}.field input:focus,.field select:focus{border-color:#418fff}.btn{padding:10px 13px;border-radius:9px;border:1px solid #2a3b59;background:#111d30;color:#fff}.btn:hover{filter:brightness(1.13)}.primary{border:0;background:linear-gradient(110deg,#318dff,#7756ff)}.notice{padding:12px;border:1px solid var(--line);border-radius:10px;background:#09111e;color:#91a3bc;font-size:12px;line-height:1.55}.error{border-color:#5d2d39;background:#201016;color:#ffadb9}.ok{border-color:#1c5b48;background:#09221b;color:#91f1cd}
.layout{min-height:100vh;display:grid;grid-template-columns:248px 1fr}aside{height:100vh;position:sticky;top:0;padding:18px 14px;background:#070b13ed;border-right:1px solid var(--line);backdrop-filter:blur(20px)}aside .brand{padding:4px 8px 22px}.nav button{width:100%;border:0;background:transparent;color:#8799b3;text-align:left;padding:11px 12px;border-radius:9px;margin:2px 0}.nav button:hover,.nav .active{background:#132036;color:#fff}.section{font-size:10px;color:#536680;text-transform:uppercase;letter-spacing:.12em;margin:19px 11px 6px}.bottom{position:absolute;left:14px;right:14px;bottom:16px}.main{max-width:1650px;width:100%;margin:auto;padding:27px 31px}.head{display:flex;justify-content:space-between;gap:15px;align-items:center;margin-bottom:22px}.head h1{margin:0;font-size:29px}.sub{color:var(--muted);margin-top:5px}.identity{display:flex;align-items:center;gap:9px}.avatar{width:36px;height:36px;border-radius:50%;display:grid;place-items:center;font-weight:800;background:linear-gradient(135deg,var(--blue),var(--purple))}.badge{font-size:10px;padding:5px 9px;border-radius:99px;background:#17243a;color:#aec0d8}.badge.owner{background:#2d204b;color:#d5c2ff}.badge.admin{background:#10362d;color:#8df1c7}
.grid{display:grid;gap:15px}.stats{grid-template-columns:repeat(4,1fr)}.two{grid-template-columns:1.4fr 1fr}.three{grid-template-columns:repeat(3,1fr)}.card{background:#0c1423e8;border:1px solid var(--line);border-radius:16px;padding:17px;box-shadow:0 8px 35px #0003}.card h3{margin:0 0 14px}.label{font-size:10px;color:#7e91ad;text-transform:uppercase;letter-spacing:.1em}.big{font-size:29px;font-weight:850;margin:7px 0}.tiny,.muted{color:var(--muted);font-size:11px}.toolbar{display:flex;align-items:center;justify-content:space-between;gap:10px}.actions{display:flex;gap:7px;flex-wrap:wrap}.kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}.mini{background:#080f1b;border:1px solid var(--line);border-radius:10px;padding:11px}.mini span{display:block;color:#71849f;font-size:10px}.mini b{font-size:19px;display:block;margin-top:4px}.progress{height:7px;background:#070e19;border-radius:99px;overflow:hidden}.progress i{display:block;height:100%;background:linear-gradient(90deg,#318cff,#7856ff);border-radius:99px}
table{width:100%;border-collapse:collapse}th,td{padding:12px 9px;border-bottom:1px solid #18263c;text-align:left}th{font-size:10px;color:#71839e;text-transform:uppercase;letter-spacing:.09em}td{font-size:13px}.status{display:inline-flex;align-items:center;gap:6px}.dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px #2ee39a99}.dot.off{background:#5e6e85;box-shadow:none}.green{color:#82f0c4}.danger{color:#ff9ba9}.lxcgrid{grid-template-columns:repeat(3,1fr)}.lxc .row{display:flex;justify-content:space-between;margin:10px 0}.chart{height:280px}.empty{text-align:center;padding:42px;color:#71839e}.modalback{position:fixed;z-index:50;inset:0;background:#000c;display:grid;place-items:center;padding:20px}.modal{width:min(620px,100%);max-height:90vh;overflow:auto;background:#0d1626;border:1px solid var(--line);border-radius:18px;padding:21px;box-shadow:0 25px 80px #000}.toast{position:fixed;z-index:100;right:20px;bottom:20px;background:#111d31;border:1px solid var(--line);border-radius:10px;padding:12px 15px;box-shadow:0 15px 50px #0009}
@media(max-width:1100px){.stats,.lxcgrid{grid-template-columns:repeat(2,1fr)}.two{grid-template-columns:1fr}}@media(max-width:720px){.layout{display:block}aside{height:auto;position:relative;border-right:0;border-bottom:1px solid var(--line)}.nav{display:flex;overflow:auto}.nav button{width:auto;white-space:nowrap}.section{display:none}.bottom{position:static;margin-top:8px}.main{padding:17px 13px}.stats,.lxcgrid,.three,.kpis{grid-template-columns:1fr}.head{align-items:flex-start;flex-direction:column}}
</style>
</head>
<body>
<div id="root"></div>
<script>
let ME=null,CL={nodes:[],containers:[]},charts=[];
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const toast=m=>{const x=document.createElement("div");x.className="toast";x.textContent=m;document.body.appendChild(x);setTimeout(()=>x.remove(),2600)};
const api=async(u,o={})=>{const r=await fetch(u,{credentials:"same-origin",...o,headers:{"Content-Type":"application/json",...(o.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||"Request failed");return d};
const bytes=n=>{n=+n||0;for(const u of["B","KB","MB","GB","TB"]){if(n<1024)return n.toFixed(n<10?1:0)+" "+u;n/=1024}return n.toFixed(1)+" PB"};
function modal(s){const x=document.createElement("div");x.className="modalback";x.id="modal";x.innerHTML='<div class="modal">'+s+"</div>";document.body.appendChild(x)}
function closeModal(){document.getElementById("modal")?.remove()}
function stat(a,b,c){return `<div class="card"><div class="label">${a}</div><div class="big">${b}</div><div class="tiny">${c}</div></div>`}
function mini(a,b){return `<div class="mini"><span>${a}</span><b>${b}</b></div>`}
function auth(mode="login"){
root.innerHTML=`<div class="login"><div class="loginbox"><div class="brand"><img src="{{logo}}"><div><b>HyperVM</b><small>Real Proxmox LXC Manager</small></div></div><div class="tabs"><button class="${mode==="login"?"on":""}" onclick="auth('login')">Sign in</button><button class="${mode==="signup"?"on":""}" onclick="auth('signup')">Sign up</button></div><form id="af"><div class="field"><label>Username</label><input id="u" required></div><div class="field"><label>Password</label><input id="p" type="password" required></div>${mode==="signup"?'<div class="field"><label>Confirm password</label><input id="p2" type="password" required></div>':""}<button class="btn primary" style="width:100%">${mode==="login"?"Sign in":"Create account"}</button></form>${mode==="login"?'<div class="notice" style="margin-top:14px"><b>Initial Owner</b><br>admin / admin123<br><br>Change it immediately after first login.</div>':""}<div class="notice" style="margin-top:10px">No email verification. Accounts are stored server-side in SQLite.</div></div></div>`;
af.onsubmit=async e=>{e.preventDefault();try{const name=u.value.trim(),pw=p.value;if(mode==="signup"){if(pw!==p2.value)throw Error("Passwords do not match");ME=(await api("/api/auth/signup",{method:"POST",body:JSON.stringify({username:name,password:pw})})).user}else ME=(await api("/api/auth/login",{method:"POST",body:JSON.stringify({username:name,password:pw})})).user;dashboard()}catch(err){toast(err.message)}}
}
function shell(active,title,sub,html){
root.innerHTML=`<div class="layout"><aside><div class="brand"><img src="{{logo}}"><div><b>HyperVM</b><small>Proxmox Console</small></div></div><div class="nav"><div class="section">Workspace</div><button class="${active==="dashboard"?"active":""}" onclick="dashboard()">▦ &nbsp; Dashboard</button><button class="${active==="lxc"?"active":""}" onclick="lxcs()">□ &nbsp; LXC Containers</button><button class="${active==="nodes"?"active":""}" onclick="nodes()">◈ &nbsp; Proxmox Nodes</button><div class="section">Insights</div><button class="${active==="analytics"?"active":""}" onclick="analytics()">◒ &nbsp; Data Analysis</button>${ME.role!=="user"?'<div class="section">Administration</div><button class="'+(active==="users"?"active":"")+'" onclick="users()">♙ &nbsp; Users & Roles</button>':""}<button class="${active==="settings"?"active":""}" onclick="settings()">⚙ &nbsp; Settings</button></div><div class="bottom"><button class="btn" style="width:100%" onclick="logout()">⇥ &nbsp; Sign out</button></div></aside><main class="main"><div class="head"><div><h1>${title}</h1><div class="sub">${sub}</div></div><div class="identity"><span>${esc(ME.username)}</span><span class="badge ${ME.role}">${esc(ME.role)}</span><span class="avatar">${esc(ME.username[0].toUpperCase())}</span></div></div>${html}</main></div>`
}
function fail(e){return `<div class="card error"><b>Proxmox API unavailable</b><p>${esc(e.message)}</p><p class="tiny">Configure PROXMOX_URL, PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET on the Python server.</p><button class="btn primary" onclick="settings()">Open Settings</button></div>`}
async function loadCluster(){CL=await api("/api/cluster");return CL}
async function dashboard(){
try{
await loadCluster();const n=CL.nodes,c=CL.containers,r=c.filter(x=>x.status==="running").length;
const cpu=n.length?Math.round(n.reduce((a,x)=>a+x.cpu_pct,0)/n.length):0;
const ram=n.length?Math.round(n.reduce((a,x)=>a+x.mem_pct,0)/n.length):0;
shell("dashboard","Dashboard","Live Proxmox infrastructure and LXC health",
`<div class="grid stats">${stat("Proxmox nodes",n.length,"Live API result")}${stat("LXC containers",c.length,r+" running")}${stat("Average CPU",cpu+"%","Across nodes")}${stat("Average RAM",ram+"%","Across nodes")}</div><div class="grid two" style="margin-top:15px"><div class="card"><div class="toolbar"><h3>Cluster utilization</h3><button class="btn" onclick="analytics()">Analyze</button></div><div class="chart"><canvas id="mainChart"></canvas></div></div><div class="card"><h3>Node health</h3>${n.length?n.map(x=>`<div style="margin:15px 0"><div class="toolbar"><b>${esc(x.node)}</b><span class="status"><i class="dot"></i>${esc(x.status||"online")}</span></div><div class="tiny">CPU ${x.cpu_pct}% · RAM ${x.mem_pct}% · Disk ${x.disk_pct}%</div><div class="progress" style="margin-top:7px"><i style="width:${x.cpu_pct}%"></i></div></div>`).join(""):"<div class='empty'>No nodes.</div>"}</div></div><div class="card" style="margin-top:15px"><div class="toolbar"><h3>Recent LXC inventory</h3><button class="btn" onclick="lxcs()">Manage</button></div>${table(c.slice(0,10))}</div>`);
drawMain(n)
}catch(e){shell("dashboard","Dashboard","Connection status",fail(e))}
}
function drawMain(n){
charts.forEach(c=>c.destroy());charts=[];
if(!window.Chart)return;
charts.push(new Chart(document.getElementById("mainChart"),{type:"bar",data:{labels:n.map(x=>x.node),datasets:[{label:"CPU %",data:n.map(x=>x.cpu_pct),borderRadius:6},{label:"RAM %",data:n.map(x=>x.mem_pct),borderRadius:6},{label:"Disk %",data:n.map(x=>x.disk_pct),borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,scales:{y:{min:0,max:100,grid:{color:"#18263b"},ticks:{color:"#8294ae"}},x:{grid:{display:false},ticks:{color:"#8294ae"}}},plugins:{legend:{labels:{color:"#9db0c9"}}}}}))
}
function table(a){
if(!a.length)return"<div class='empty'>No LXC containers.</div>";
return`<table><thead><tr><th>VMID</th><th>Name</th><th>Node</th><th>Status</th><th>CPU</th><th>RAM</th><th></th></tr></thead><tbody>${a.map(x=>`<tr><td>${x.vmid}</td><td><b>${esc(x.name||"CT "+x.vmid)}</b></td><td>${esc(x.node)}</td><td><span class="status"><i class="dot ${x.status==="running"?"":"off"}"></i>${esc(x.status)}</span></td><td>${x.cpu_pct}%</td><td>${x.mem_mb} MB</td><td><button class="btn" onclick="detail('${esc(x.node)}',${x.vmid})">Details</button></td></tr>`).join("")}</tbody></table>`
}
async function lxcs(){try{await loadCluster();renderLxcs(CL.containers)}catch(e){shell("lxc","LXC Containers","Live Proxmox inventory",fail(e))}}
function renderLxcs(a){
shell("lxc","LXC Containers","Real start, shutdown, reboot and provisioning controls",
`<div class="toolbar"><input id="search" class="field" style="max-width:310px;margin:0" placeholder="Search VMID, name, node..." oninput="filterLxcs()"><div class="actions"><button class="btn" onclick="lxcs()">↻ Refresh</button>${ME.role!=="user"?'<button class="btn primary" onclick="createModal()">+ Create LXC</button>':""}</div></div><div id="cards" class="grid lxcgrid" style="margin-top:15px">${cards(a)}</div>`)
}
function cards(a){
if(!a.length)return"<div class='card empty' style='grid-column:1/-1'>No containers found.</div>";
return a.map(x=>`<div class="card lxc"><div class="toolbar"><div><b>${esc(x.name||"CT "+x.vmid)}</b><div class="tiny">VMID ${x.vmid} · ${esc(x.node)}</div></div><span class="status"><i class="dot ${x.status==="running"?"":"off"}"></i>${esc(x.status)}</span></div><div class="row"><span class="muted">CPU</span><b>${x.cpu_pct}%</b></div><div class="progress"><i style="width:${Math.min(100,x.cpu_pct)}%"></i></div><div class="row"><span class="muted">Memory</span><b>${x.mem_mb} MB</b></div><div class="row"><span class="muted">Disk</span><b>${x.disk_gb} GB</b></div><div class="actions">${x.status==="running"?`<button class="btn danger" onclick="action('${esc(x.node)}',${x.vmid},'shutdown')">Shutdown</button><button class="btn" onclick="action('${esc(x.node)}',${x.vmid},'reboot')">Reboot</button>`:`<button class="btn green" onclick="action('${esc(x.node)}',${x.vmid},'start')">Start</button>`}<button class="btn" onclick="detail('${esc(x.node)}',${x.vmid})">Details</button></div></div>`).join("")
}
function filterLxcs(){const q=search.value.toLowerCase();document.getElementById("cards").innerHTML=cards(CL.containers.filter(x=>(x.vmid+" "+x.name+" "+x.node+" "+x.status).toLowerCase().includes(q)))}
async function action(n,id,a){try{await api(`/api/lxc/${encodeURIComponent(n)}/${id}/${a}`,{method:"POST"});toast(a+" task submitted");setTimeout(lxcs,900)}catch(e){toast(e.message)}}
async function detail(n,id){
try{const d=await api(`/api/lxc/${encodeURIComponent(n)}/${id}`);modal(`<h2>Container ${id}</h2><p class="muted">${esc(n)}</p><h3>Status</h3><pre>${esc(JSON.stringify(d.status,null,2))}</pre><h3>Configuration</h3><pre>${esc(JSON.stringify(d.config,null,2))}</pre><div class="actions" style="justify-content:flex-end"><button class="btn" onclick="closeModal()">Close</button></div>`)}catch(e){toast(e.message)}
}
function createModal(){
modal(`<h2>Create LXC</h2><div class="notice">This sends a real Proxmox POST request using the server-side API token.</div><div class="field"><label>Node</label><select id="cn">${CL.nodes.map(x=>`<option>${esc(x.node)}</option>`).join("")}</select></div><div class="field"><label>VMID</label><input id="vmid" type="number"></div><div class="field"><label>Hostname</label><input id="hostname" placeholder="hypervm-101"></div><div class="field"><label>Template</label><input id="template" placeholder="local:vztmpl/debian-12-standard_*.tar.zst"></div><div class="field"><label>Storage</label><input id="storage" value="local-lvm"></div><div class="field"><label>Root disk GB</label><input id="root" type="number" value="8"></div><div class="field"><label>Memory MB</label><input id="memory" type="number" value="1024"></div><div class="field"><label>CPU cores</label><input id="cores" type="number" value="1"></div><div class="actions" style="justify-content:flex-end"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="createLxc()">Create</button></div>`)
}
async function createLxc(){
try{const b={hostname:hostname.value,ostemplate:template.value,storage:storage.value,rootfs:`${storage.value}:${+root.value}`,memory:+memory.value,cores:+cores.value};if(vmid.value)b.vmid=+vmid.value;await api(`/api/lxc/${encodeURIComponent(cn.value)}/create`,{method:"POST",body:JSON.stringify(b)});closeModal();toast("Creation task submitted");setTimeout(lxcs,1000)}catch(e){toast(e.message)}
}
async function nodes(){
try{const d=await api("/api/nodes");shell("nodes","Proxmox Nodes","Live capacity and resource pressure",`<div class="grid three">${d.nodes.map(x=>`<div class="card"><div class="toolbar"><h3>${esc(x.node)}</h3><span class="status"><i class="dot"></i>${esc(x.status)}</span></div><p class="tiny">CPU ${x.cpu_pct}%</p><div class="progress"><i style="width:${x.cpu_pct}%"></i></div><p class="tiny">RAM ${x.mem_pct}% · ${bytes(x.mem_used)} / ${bytes(x.mem_total)}</p><div class="progress"><i style="width:${x.mem_pct}%"></i></div><p class="tiny">Disk ${x.disk_pct}% · ${bytes(x.disk_used)} / ${bytes(x.disk_total)}</p><div class="progress"><i style="width:${x.disk_pct}%"></i></div><p class="tiny">Uptime ${x.uptime_hours} hours</p></div>`).join("")}</div>`)}catch(e){shell("nodes","Proxmox Nodes","Connection status",fail(e))}
}
async function analytics(){
try{
const d=await api("/api/analytics"),s=d.summary;
shell("analytics","Data Analysis","Pandas-powered analysis of the live Proxmox snapshot",
`<div class="grid stats">${stat("Average CPU",s.avg_cpu+"%","Mean across nodes")}${stat("Peak CPU",s.peak_cpu+"%","Maximum node")}${stat("Running LXC",s.running,"Current state")}${stat("Risk nodes",s.risk_nodes,"Threshold flags")}</div><div class="grid two" style="margin-top:15px"><div class="card"><div class="toolbar"><h3>Resource comparison</h3><span class="tiny">live snapshot</span></div><div class="chart"><canvas id="analysisChart"></canvas></div></div><div class="card"><h3>Capacity findings</h3><div class="kpis">${mini("Nodes",s.nodes)}${mini("Containers",s.containers)}${mini("Stopped",s.stopped)}</div>${d.risk_nodes.length?`<div class="notice error" style="margin-top:14px"><b>Attention</b><br>${d.risk_nodes.map(x=>esc(x.node)+" — "+x.risks.join(", ")).join("<br>")}</div>`:`<div class="notice ok" style="margin-top:14px">No node crossed the high-utilization thresholds.</div>`}<div class="notice" style="margin-top:10px">Calculations are performed by pandas on the Python server from the current Proxmox API snapshot.</div></div></div>`);
charts.forEach(c=>c.destroy());charts=[];charts.push(new Chart(document.getElementById("analysisChart"),{type:"bar",data:{labels:d.node_rows.map(x=>x.node),datasets:[{label:"CPU %",data:d.node_rows.map(x=>x.cpu),borderRadius:6},{label:"RAM %",data:d.node_rows.map(x=>x.memory),borderRadius:6},{label:"Disk %",data:d.node_rows.map(x=>x.disk),borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,scales:{y:{min:0,max:100},x:{grid:{display:false}}}}}))
}catch(e){shell("analytics","Data Analysis","Connection status",fail(e))}
}
async function users(){
try{const d=await api("/api/users");shell("users","Users & Roles","The Owner controls promotions; promoted accounts display Admin",
`<div class="card"><div class="toolbar"><h3>HyperVM accounts</h3><button class="btn primary" onclick="newUser()">+ Add user</button></div><table><thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead><tbody>${d.users.map(u=>`<tr><td><b>${esc(u.username)}</b>${u.id===ME.id?" <span class='muted'>(you)</span>":""}</td><td><span class="badge ${u.role}">${esc(u.role)}</span></td><td>${u.active?"Active":"Disabled"}</td><td>${esc(u.created_at)}</td><td>${u.id===1?"<span class='muted'>Protected Owner</span>":`<button class="btn" onclick="role(${u.id},'${u.role==="admin"?"user":"admin"}')">${u.role==="admin"?"Demote":"Promote to Admin"}</button> <button class="btn" onclick="toggleUser(${u.id},${!u.active})">${u.active?"Disable":"Enable"}</button>`}</td></tr>`).join("")}</tbody></table></div>`)}catch(e){toast(e.message)}
}
function newUser(){modal(`<h2>Create user</h2><div class="field"><label>Username</label><input id="nu"></div><div class="field"><label>Password</label><input id="np" type="password"></div><div class="actions" style="justify-content:flex-end"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="saveUser()">Create</button></div>`)}
async function saveUser(){try{await api("/api/users",{method:"POST",body:JSON.stringify({username:nu.value,password:np.value})});closeModal();users();toast("User created")}catch(e){toast(e.message)}}
async function role(id,r){try{await api("/api/users/"+id,{method:"PATCH",body:JSON.stringify({role:r})});users();toast("Role updated")}catch(e){toast(e.message)}}
async function toggleUser(id,v){try{await api("/api/users/"+id,{method:"PATCH",body:JSON.stringify({active:v})});users();toast("User updated")}catch(e){toast(e.message)}}
function settings(){
shell("settings","Settings","Server-side Proxmox connection and account security",
`<div class="grid two"><div class="card"><h3>Proxmox connection</h3><div class="notice">The Proxmox token lives only in the Python process environment. It is never exposed to browser JavaScript.</div><div class="field"><label>PROXMOX_URL</label><input disabled value="Configured on Python server"></div><div class="field"><label>PROXMOX_TOKEN_ID</label><input disabled value="Configured on Python server"></div><div class="field"><label>TLS verification</label><input disabled value="PROXMOX_VERIFY_TLS environment variable"></div><p class="tiny">Use a dedicated least-privilege API token for production.</p></div><div class="card"><h3>Change password</h3><form id="pw"><div class="field"><label>Current password</label><input id="oldpw" type="password" required></div><div class="field"><label>New password</label><input id="newpw" type="password" required></div><div class="field"><label>Confirm</label><input id="newpw2" type="password" required></div><button class="btn primary">Change password</button></form></div></div><div class="card" style="margin-top:15px"><h3>Deployment</h3><pre>pip install flask requests pandas
set PROXMOX_URL=https://YOUR-PROXMOX:8006
set PROXMOX_TOKEN_ID=USER@pam!TOKEN
set PROXMOX_TOKEN_SECRET=TOKEN_SECRET
set PROXMOX_VERIFY_TLS=false
python hypervm.py</pre></div>`);
pw.onsubmit=async e=>{e.preventDefault();try{if(newpw.value!==newpw2.value)throw Error("Passwords do not match");await api("/api/auth/password",{method:"PATCH",body:JSON.stringify({current:oldpw.value,next:newpw.value})});toast("Password changed")}catch(e){toast(e.message)}}
}
async function logout(){await api("/api/auth/logout",{method:"POST"}).catch(()=>{});ME=null;auth()}
async function boot(){try{const d=await api("/api/auth/me");if(d.user){ME=d.user;dashboard()}else auth()}catch(e){auth()}}
boot();
</script>
</body>
</html>
"""

@APP.get("/")
def index():
    return render_template_string(HTML, logo=LOGO)


@APP.get("/health")
def health():
    return jsonify(
        ok=True,
        proxmox_configured=PVE.configured(),
        database=DB,
    )


if __name__ == "__main__":
    init_db()
    print()
    print("HyperVM — Real Proxmox LXC Manager")
    print("URL: http://127.0.0.1:" + str(PORT))
    print("Default Owner: admin / admin123")
    print("Proxmox configured:", PVE.configured())
    print()
    APP.run(host=HOST, port=PORT, debug=False)
