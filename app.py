#!/usr/bin/env python3
"""Single-container autossh reverse-tunnel manager with tiny WebGUI.

All tunnel details (jump hosts, forwards, keys) are entered via the WebGUI
and stored in $DATA_DIR/tunnels.json. Nothing sensitive is baked into the image.

Config:  $DATA_DIR/tunnels.json
Keys:    $DATA_DIR/keys/*
Logs:    $DATA_DIR/logs/<name>.log
"""
import atexit
import hmac
import json
import os
import shlex
import signal
import subprocess
import threading
import time
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, Response, flash, get_flashed_messages,
    redirect, render_template, request, url_for,
)

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CONFIG_FILE = DATA_DIR / "tunnels.json"
DEFAULTS_FILE = Path("/app/defaults/tunnels.json")
KEYS_DIR = DATA_DIR / "keys"
LOGS_DIR = DATA_DIR / "logs"
GUI_USER = os.environ.get("GUI_USER", "admin")
GUI_PASS = os.environ.get("GUI_PASS", "changeme")
PORT = int(os.environ.get("PORT", "8080"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

_lock = threading.Lock()
_procs: dict[str, subprocess.Popen] = {}
_started_at: dict[str, float] = {}
_stop_requested: set[str] = set()

AUTOSSH_ENV = {
    "AUTOSSH_GATETIME": "0",
    "AUTOSSH_POLL": "30",
}


# ---------- config ----------

def ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists() and DEFAULTS_FILE.exists():
        CONFIG_FILE.write_text(DEFAULTS_FILE.read_text())
    # harden any existing keys
    for f in KEYS_DIR.glob("*"):
        try:
            if f.is_file():
                os.chmod(f, 0o600)
        except OSError:
            pass


def load_config() -> dict:
    ensure_dirs()
    if not CONFIG_FILE.exists():
        return {"tunnels": []}
    try:
        data = json.loads(CONFIG_FILE.read_text())
        if isinstance(data, dict) and isinstance(data.get("tunnels"), list):
            return data
        return {"tunnels": []}
    except (json.JSONDecodeError, OSError):
        return {"tunnels": []}


def save_config(data: dict):
    ensure_dirs()
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(CONFIG_FILE)


def get_tunnel(name: str) -> dict | None:
    for t in load_config().get("tunnels", []):
        if t.get("name") == name:
            return t
    return None


# ---------- auth ----------

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not GUI_PASS:  # empty pass = auth disabled (isolated net only)
            return f(*args, **kwargs)
        auth = request.authorization
        ok = (
            auth is not None
            and hmac.compare_digest(auth.username or "", GUI_USER)
            and hmac.compare_digest(auth.password or "", GUI_PASS)
        )
        if not ok:
            return Response(
                "Login required", 401,
                {"WWW-Authenticate": 'Basic realm="tunnel-manager"'},
            )
        return f(*args, **kwargs)
    return wrapper


# ---------- autossh ----------

def build_command(t: dict) -> list[str]:
    """Rebuild the exact autossh invocation from the old systemd units."""
    key_file = t.get("key_file", "")
    cmd = ["/usr/bin/autossh", "-M", "0", "-N"]
    # drop -q so logs are useful in the GUI; keep everything else identical
    for opt in t.get("ssh_options", []):
        # stored as e.g. "ServerAliveInterval 30" -> -o "ServerAliveInterval 30"
        cmd += ["-o", opt]
    if key_file:
        cmd += ["-i", key_file]
    bind_default = t.get("bind_address", "127.0.0.1") or "127.0.0.1"
    for fw in t.get("forwards", []):
        bind = fw.get("bind") or bind_default
        rport = fw["remote_port"]
        thost = fw["target_host"]
        tport = fw["target_port"]
        cmd += ["-R", f"{bind}:{rport}:{thost}:{tport}"]
    cmd += [f"{t['jump_user']}@{t['jump_host']}", "-p", str(t["jump_port"])]
    return cmd


def log_path(name: str) -> Path:
    return LOGS_DIR / f"{name}.log"


def is_running(name: str) -> bool:
    p = _procs.get(name)
    return p is not None and p.poll() is None


def start_tunnel(name: str) -> tuple[bool, str]:
    with _lock:
        t = get_tunnel(name)
        if t is None:
            return False, f"unknown tunnel {name!r}"
        if is_running(name):
            return True, "already running"
        key = t.get("key_file", "")
        if not key or not Path(key).exists():
            return False, f"key file missing: {key!r} — paste it under Keys first"
        try:
            os.chmod(key, 0o600)
        except OSError as e:
            return False, f"chmod 600 {key} failed: {e}"
        cmd = build_command(t)
        ensure_dirs()
        lf = open(log_path(name), "ab")
        env = dict(os.environ)
        env.update(AUTOSSH_ENV)
        try:
            p = subprocess.Popen(
                cmd, env=env, stdout=lf, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except FileNotFoundError:
            lf.close()
            return False, "autossh binary not found in image"
        except OSError as e:
            lf.close()
            return False, f"failed to start: {e}"
        _procs[name] = p
        _started_at[name] = time.time()
        _stop_requested.discard(name)
        with open(log_path(name), "ab") as la:
            la.write(
                f"\n===== {datetime.now().isoformat(timespec='seconds')} "
                f"START pid={p.pid} :: {' '.join(shlex.quote(c) for c in cmd)} =====\n".encode()
            )
        return True, f"started (pid {p.pid})"


def stop_tunnel(name: str) -> tuple[bool, str]:
    with _lock:
        p = _procs.get(name)
        _stop_requested.add(name)
        if p is None or p.poll() is not None:
            _procs.pop(name, None)
            return True, "already stopped"
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
        _procs.pop(name, None)
        _started_at.pop(name, None)
        with open(log_path(name), "ab") as la:
            la.write(
                f"===== {datetime.now().isoformat(timespec='seconds')} STOPPED =====\n".encode()
            )
        return True, "stopped"


def restart_tunnel(name: str):
    stop_tunnel(name)
    _stop_requested.discard(name)
    time.sleep(1)
    return start_tunnel(name)


def autostart():
    for t in load_config().get("tunnels", []):
        if t.get("enabled", True):
            ok, msg = start_tunnel(t["name"])
            print(f"[autostart] {t['name']}: {msg}", flush=True)


def shutdown_all(*_a):
    for name in list(_procs.keys()):
        try:
            stop_tunnel(name)
        except Exception as e:  # noqa: BLE001
            print(f"shutdown {name}: {e}", flush=True)


atexit.register(shutdown_all)
signal.signal(signal.SIGTERM, lambda *_: shutdown_all())


def tail_log(name: str, n: int = 100) -> str:
    p = log_path(name)
    if not p.exists():
        return "(no log yet)"
    try:
        lines = p.read_bytes().splitlines()[-n:]
        return "\n".join(l.decode(errors="replace") for l in lines) or "(empty)"
    except OSError as e:
        return f"(cannot read log: {e})"


def verify_remote(t: dict) -> tuple[bool, str]:
    """SSH to the jump host and check each -R listener shows up in `ss -tln`."""
    key = t.get("key_file", "")
    cmd = [
        "ssh", "-i", key,
        "-p", str(t["jump_port"]),
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        f"{t['jump_user']}@{t['jump_host']}",
        "ss -tln",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    except subprocess.TimeoutExpired:
        return False, "verify timed out after 25s"
    except OSError as e:
        return False, f"ssh failed: {e}"
    if r.returncode != 0:
        return False, f"ssh to jump host failed: {(r.stderr or r.stdout).strip()[:500]}"
    out = r.stdout
    missing = [str(fw["remote_port"]) for fw in t.get("forwards", [])
               if f":{fw['remote_port']}" not in out]
    if missing:
        return False, f"jump host reachable, but NOT listening on: {', '.join(missing)}"
    return True, f"jump host reachable, all {len(t.get('forwards', []))} remote ports listening"


# ---------- routes ----------

@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
@auth_required
def index():
    cfg = load_config()
    rows = []
    for t in cfg.get("tunnels", []):
        name = t["name"]
        rows.append({
            "cfg": t,
            "running": is_running(name),
            "pid": _procs[name].pid if is_running(name) else None,
            "uptime": (time.time() - _started_at[name]) if is_running(name) and name in _started_at else 0,
            "log": tail_log(name, 25),
            "cmd": " ".join(shlex.quote(c) for c in build_command(t)),
        })
    keys = sorted(p.name for p in KEYS_DIR.glob("*") if p.is_file()) if KEYS_DIR.exists() else []
    return render_template("index.html", rows=rows, keys=keys,
                           gui_user=GUI_USER, auth_disabled=not bool(GUI_PASS))


@app.post("/tunnel/<name>/start")
@auth_required
def route_start(name):
    ok, msg = start_tunnel(name)
    flash(f"{name}: {msg}", "ok" if ok else "err")
    return redirect(url_for("index"))


@app.post("/tunnel/<name>/stop")
@auth_required
def route_stop(name):
    ok, msg = stop_tunnel(name)
    flash(f"{name}: {msg}", "ok" if ok else "err")
    return redirect(url_for("index"))


@app.post("/tunnel/<name>/restart")
@auth_required
def route_restart(name):
    ok, msg = restart_tunnel(name)
    flash(f"{name}: {msg}", "ok" if ok else "err")
    return redirect(url_for("index"))


@app.post("/tunnel/<name>/toggle")
@auth_required
def route_toggle(name):
    cfg = load_config()
    for t in cfg["tunnels"]:
        if t["name"] == name:
            t["enabled"] = not t.get("enabled", True)
    save_config(cfg)
    return redirect(url_for("index"))


@app.get("/tunnel/new")
@auth_required
def route_new():
    return render_template("edit.html", t={
        "name": "", "jump_user": "", "jump_host": "",
        "jump_port": 22, "key_file": str(KEYS_DIR / "tunnel_key"),
        "bind_address": "127.0.0.1", "enabled": True,
        "ssh_options": ["ServerAliveInterval 30", "ServerAliveCountMax 3",
                        "ExitOnForwardFailure=yes", "StrictHostKeyChecking=no"],
        "forwards": [],
    }, is_new=True, keys=list_keys())


@app.get("/tunnel/<name>/edit")
@auth_required
def route_edit(name):
    t = get_tunnel(name)
    if not t:
        flash(f"unknown tunnel {name}", "err")
        return redirect(url_for("index"))
    return render_template("edit.html", t=t, is_new=False, keys=list_keys())


def list_keys() -> list[str]:
    if not KEYS_DIR.exists():
        return []
    return sorted(p.name for p in KEYS_DIR.glob("*") if p.is_file())


def parse_edit_form(form, existing: dict | None) -> tuple[dict, str]:
    name = (form.get("name") or "").strip()
    if not name or not name.replace("-", "").replace("_", "").isalnum():
        raise ValueError("name must be alphanumeric/dash/underscore")
    jump_user = form.get("jump_user", "").strip()
    jump_host = form.get("jump_host", "").strip()
    if not jump_user or not jump_host:
        raise ValueError("jump user and host are required")
    try:
        jump_port = int(form.get("jump_port", "22"))
    except ValueError:
        raise ValueError("jump port must be a number")
    key_select = form.get("key_select", "").strip()
    key_custom = form.get("key_file", "").strip()
    key_file = key_custom or (str(KEYS_DIR / key_select) if key_select else "")
    if not key_file:
        raise ValueError("pick or type a key file path")
    bind_address = form.get("bind_address", "127.0.0.1").strip() or "127.0.0.1"
    raw_opts = form.get("ssh_options", "")
    ssh_options = [l.strip() for l in raw_opts.splitlines() if l.strip()]
    # forwards come as parallel lists
    rports = form.getlist("fw_remote")
    thosts = form.getlist("fw_target_host")
    tports = form.getlist("fw_target_port")
    binds = form.getlist("fw_bind")
    forwards = []
    seen_ports = set()
    for rp, th, tp, b in zip(rports, thosts, tports, binds):
        rp, th, tp = rp.strip(), th.strip(), tp.strip()
        if not rp and not th and not tp:
            continue  # blank row
        try:
            rpi, tpi = int(rp), int(tp)
        except ValueError:
            raise ValueError(f"bad forward ports: {rp!r} -> {th!r}:{tp!r}")
        if not th:
            raise ValueError(f"missing target host for remote port {rpi}")
        if rpi in seen_ports:
            raise ValueError(f"duplicate remote port {rpi} within this tunnel")
        seen_ports.add(rpi)
        forwards.append({"remote_port": rpi, "target_host": th,
                         "target_port": tpi, "bind": (b or "").strip() or None})
    if not forwards:
        raise ValueError("add at least one -R forward")
    return {
        "name": name,
        "enabled": bool(form.get("enabled")),
        "jump_user": jump_user, "jump_host": jump_host, "jump_port": jump_port,
        "key_file": key_file, "bind_address": bind_address,
        "ssh_options": ssh_options, "forwards": forwards,
    }, name


@app.post("/tunnel/save")
@auth_required
def route_save():
    cfg = load_config()
    old_name = request.form.get("old_name", "").strip()
    is_new = not old_name
    try:
        t, new_name = parse_edit_form(request.form, None)
    except ValueError as e:
        flash(str(e), "err")
        return redirect(url_for("route_new") if is_new else url_for("route_edit", name=old_name))
    names = [x["name"] for x in cfg["tunnels"]]
    if is_new and new_name in names:
        flash(f"tunnel {new_name} already exists", "err")
        return redirect(url_for("route_new"))
    if not is_new and new_name != old_name and new_name in names:
        flash(f"rename to {new_name} collides with existing tunnel", "err")
        return redirect(url_for("route_edit", name=old_name))
    was_running = is_running(old_name) if old_name else False
    if was_running:
        stop_tunnel(old_name)
    if is_new:
        cfg["tunnels"].append(t)
    else:
        for i, x in enumerate(cfg["tunnels"]):
            if x["name"] == old_name:
                # preserve enabled if checkbox unchecked confusion? form already has it
                cfg["tunnels"][i] = t
                break
    save_config(cfg)
    if was_running or (is_new and t.get("enabled")):
        ok, msg = start_tunnel(new_name)
        flash(f"saved, {msg}", "ok" if ok else "err")
    else:
        flash("saved", "ok")
    return redirect(url_for("index"))


@app.post("/tunnel/<name>/delete")
@auth_required
def route_delete(name):
    stop_tunnel(name)
    cfg = load_config()
    cfg["tunnels"] = [x for x in cfg["tunnels"] if x.get("name") != name]
    save_config(cfg)
    flash(f"{name} deleted", "ok")
    return redirect(url_for("index"))


@app.get("/verify/<name>")
@auth_required
def route_verify(name):
    t = get_tunnel(name)
    if not t:
        flash(f"unknown tunnel {name}", "err")
        return redirect(url_for("index"))
    ok, msg = verify_remote(t)
    flash(f"{name} verify: {msg}", "ok" if ok else "err")
    return redirect(url_for("index"))


@app.get("/logs/<name>")
@auth_required
def route_logs(name):
    n = int(request.args.get("n", "500"))
    return Response(tail_log(name, n), mimetype="text/plain")


@app.get("/keys")
@auth_required
def route_keys():
    items = []
    if KEYS_DIR.exists():
        for p in sorted(KEYS_DIR.glob("*")):
            if p.is_file():
                items.append({"name": p.name, "path": str(p),
                              "size": p.stat().st_size,
                              "mode": oct(p.stat().st_mode & 0o777)})
    return render_template("keys.html", items=items,
                           default_path=str(KEYS_DIR / "tunnel_key"))


@app.post("/keys/save")
@auth_required
def route_keys_save():
    filename = (request.form.get("filename") or "").strip() or "tunnel_key"
    filename = Path(filename).name  # no directories / traversal
    content = request.form.get("content", "")
    if "PRIVATE KEY" not in content:
        flash("that doesn't look like a private key (missing 'PRIVATE KEY')", "err")
        return redirect(url_for("route_keys"))
    ensure_dirs()
    dest = KEYS_DIR / filename
    dest.write_text(content.strip() + "\n")
    os.chmod(dest, 0o600)
    flash(f"key saved to {dest} (600)", "ok")
    return redirect(url_for("index"))


if __name__ == "__main__":
    ensure_dirs()
    autostart()
    app.run(host="0.0.0.0", port=PORT)
