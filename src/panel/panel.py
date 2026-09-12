#!/usr/bin/env python3
"""web_zapret2 — lightweight management panel (stdlib-only HTTP+JSON API).

Endpoints
    GET  /                          single-file HTML UI
    GET  /api/status                services, strategy, exit mode, uptime
    GET  /api/strategies            list of available strategies
    GET  /api/strategy              current strategy
    POST /api/strategy {"id": ...}  switch strategy -> restart nfqws
    GET  /api/exit                  current exit mode
    POST /api/exit {"mode": ...}    switch exit mode -> reload fw + restart
    GET  /api/logs?src=<svc>&n=<N>  tail a service log

CLI: python3 panel.py [--check] [--help]
"""
import base64
import hmac
import json
import os
import re
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WZ_SRC = "/opt/webzapret"
WZ_CFG = "/etc/webzapret"
WZ_RUN = "/run/webzapret"
WZ_LOG = "/var/log/webzapret"
WZ_STATE = "/opt/webzapret/state"

SERVICES = ["ss-server", "sockd", "nfqws", "redsocks", "ss-local", "udprelay"]
STRATEGIES_FILE = os.path.join(WZ_SRC, "config/strategies.json")
APPLY = "/opt/webzapret/scripts/wz-apply.sh"
HTTPD_HOST = os.environ.get("PANEL_BIND", "0.0.0.0")
HTTPD_PORT = int(os.environ.get("PANEL_PORT", "8080"))
AUTH_USER = os.environ.get("PANEL_USER", "")
AUTH_PASS = os.environ.get("PANEL_PASSWORD", "")


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def state_get(key, default=""):
    try:
        with open(os.path.join(WZ_STATE, key), "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return default


def pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except Exception:
        return False
    return True


def service_state(name):
    pid = ""
    try:
        with open(os.path.join(WZ_RUN, name + ".pid"), "r", encoding="utf-8") as f:
            pid = f.read().strip()
    except Exception:
        pass
    if pid and not pid.isdigit():
        pid = ""
    return {"name": name, "running": pid_alive(pid), "pid": pid}


def strategies():
    return read_json(STRATEGIES_FILE, {"strategies": []}).get("strategies", [])


def strategy_ids():
    return [s.get("id", "") for s in strategies()]


def active_strategy():
    cur = state_get("strategy", "standard")
    return cur if cur in strategy_ids() else ""


def active_exit_mode():
    return state_get("exit_mode", "direct")


def apply(args):
    try:
        r = subprocess.run(
            [APPLY] + args,
            capture_output=True, text=True, timeout=90,
        )
        return {
            "ok": r.returncode == 0,
            "rc": r.returncode,
            "stdout": (r.stdout or "")[-6000:],
            "stderr": (r.stderr or "")[-2000:],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -1, "stdout": "", "stderr": "timed out (90s)"}


def status():
    strat = active_strategy()
    entry = {}
    for s in strategies():
        if s.get("id") == strat:
            entry = s
            break
    return {
        "version": "0.1.0",
        "uptime": int(time.time() - BOOT_TIME),
        "exit_mode": active_exit_mode(),
        "strategy": {
            "id": strat,
            "name": entry.get("name", strat),
            "nfqws_opt": entry.get("nfqws_opt", ""),
        },
        "services": [service_state(s) for s in SERVICES],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "web_zapret2-panel/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("panel: %s\n" % (fmt % args))

    # -- auth ------------------------------------------------------------
    def authed(self):
        if not AUTH_USER:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            user, _, pw = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        except Exception:
            return False
        return hmac.compare_digest(user, AUTH_USER) and hmac.compare_digest(pw, AUTH_PASS)

    def _auth_required(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="web_zapret2"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- helpers ---------------------------------------------------------
    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0 or length > 1_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def _send(self, code, obj, ctype="application/json; charset=utf-8"):
        if isinstance(obj, (dict, list)):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        elif isinstance(obj, str):
            body = obj.encode("utf-8")
        else:
            body = b""
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        if not self.authed():
            return self._auth_required()
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(WZ_SRC, "panel/index.html"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/status":
            return self._send(200, status())
        if path == "/api/strategies":
            return self._send(200, {
                "strategies": [
                    {"id": s.get("id"), "name": s.get("name"),
                     "desc": s.get("desc", "")} for s in strategies()
                ]
            })
        if path == "/api/strategy":
            return self._send(200, {"id": active_strategy()})
        if path == "/api/exit":
            return self._send(200, {"mode": active_exit_mode()})
        if path == "/api/logs":
            q = dict(pair.split("=", 1) for pair in
                     self.path.split("?", 1)[1].split("&") if "=" in pair)
            src = q.get("src", "nfqws")
            n = int(q.get("n", "200") or "200")
            return self._send(200, {"src": src, "log": tail_log(src, n)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.authed():
            return self._auth_required()
        path = self.path.split("?", 1)[0]
        if path == "/api/strategy":
            body = self._read_body()
            sid = str(body.get("id", ""))
            if sid not in strategy_ids():
                return self._send(400, {"ok": False, "error": "unknown strategy '%s'" % sid})
            res = apply(["strategy", sid])
            return self._send(200, dict(res, strategy=sid))
        if path == "/api/exit":
            body = self._read_body()
            mode = str(body.get("mode", ""))
            if mode not in ("direct", "socks5", "ss"):
                return self._send(400, {"ok": False, "error": "mode must be direct|socks5|ss"})
            res = apply(["exit", mode])
            return self._send(200, dict(res, mode=mode))
        return self._send(404, {"error": "not found"})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()


BOOT_TIME = time.time()


def check():
    """Validate the setup without starting the server (used by Makefile)."""
    s = status()
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        return 0
    if "--check" in sys.argv:
        return check()
    httpd = ThreadingHTTPServer((HTTPD_HOST, HTTPD_PORT), Handler)
    print("panel listening on %s:%s" % (HTTPD_HOST, HTTPD_PORT), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())