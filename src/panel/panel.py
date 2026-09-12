#!/usr/bin/env python3
"""web_zapret2 — lightweight management panel (stdlib-only HTTP+JSON API).

Endpoints
    GET  /                          single-file HTML UI
    GET  /api/status                services, strategy, exit mode, uptime, traffic
    GET  /api/strategies            list of available strategies
    GET  /api/strategy              current strategy
    POST /api/strategy {"id": ...}  switch strategy -> restart nfqws
    POST /api/strategy/import       import custom strategy from JSON
    GET  /api/exit                  current exit mode
    POST /api/exit {"mode": ...}    switch exit mode -> reload fw + restart
    GET  /api/logs?src=<svc>&n=<N>  tail a service log
    GET  /api/traffic               nfqws traffic counters (in/out bytes)

CLI: python3 panel.py [--check] [--help]
"""
import base64
import hmac
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request
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

# --- access layer endpoints (used to build client connection strings) --------
SS_LISTEN_PORT = int(os.environ.get("SS_LISTEN_PORT", "8388") or 8388)
SOCKS5_LISTEN_PORT = int(os.environ.get("SOCKS5_LISTEN_PORT", "1080") or 1080)
SS_PASSWORD = os.environ.get("SS_PASSWORD", "change-me")
SS_METHOD = os.environ.get("SS_METHOD", "aes-256-gcm")
# Public address clients use to reach this gateway; empty => auto-detect.
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "").strip()


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, obj):
    """Write JSON to a file atomically."""
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return True
    except Exception:
        return False


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


def tail_log(src, n=200):
    """Tail a service log file (last n lines); tolerant to bad input."""
    try:
        n = max(1, min(int(n), 5000))
    except (TypeError, ValueError):
        n = 200
    if not re.fullmatch(r"[a-z0-9_-]{1,64}", src or ""):
        return "(bad log source)"
    path = os.path.join(WZ_LOG, src + ".log")
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 256 * 1024))   # read at most the last 256 KiB
            data = f.read().decode("utf-8", "replace")
        lines = data.splitlines()
        if size > 256 * 1024 and lines:
            lines = lines[1:]                    # drop a possibly truncated line
        return "\n".join(lines[-n:]) + "\n"
    except FileNotFoundError:
        return "(no log for %s)" % src
    except Exception as e:
        return "(log read error: %s)" % e


_IP_CACHE = {"host": "", "source": "", "ts": 0.0}


def detect_public_host():
    """Address clients should connect to: PUBLIC_HOST env wins, else the
    public IP via an echo service (cached 10 min), else the local egress IP."""
    if PUBLIC_HOST:
        return PUBLIC_HOST, "env"
    now = time.time()
    if _IP_CACHE["host"] and now - _IP_CACHE["ts"] < 600:
        return _IP_CACHE["host"], _IP_CACHE["source"]
    host, source = "", ""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=4) as r:
                t = r.read(64).decode("ascii", "ignore").strip()
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", t):
                host, source = t, "auto"
                break
        except Exception:
            continue
    if not host:
        try:  # fallback: local egress address (docker bridge, not public)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 53))
                host = s.getsockname()[0] or ""
            finally:
                s.close()
            source = "local" if host else ""
        except Exception:
            pass
    if host:
        _IP_CACHE.update(host=host, source=source, ts=now)
    return host, source


def ss_uri(host):
    """SIP002 Shadowsocks URI of the local ss-server."""
    raw = "%s:%s" % (SS_METHOD, SS_PASSWORD)
    userinfo = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    return "ss://%s@%s:%d#web_zapret2" % (userinfo, host, SS_LISTEN_PORT)


def connected_devices():
    """Unique client IPs with ESTABLISHED TCP connections to the access-layer
    listen ports. TCP only: UDP client endpoints are not visible in /proc."""
    port_svc = {}
    if SS_LISTEN_PORT:
        port_svc[SS_LISTEN_PORT] = "ss-server"
    if SOCKS5_LISTEN_PORT:
        port_svc[SOCKS5_LISTEN_PORT] = "sockd"
    per_service = {v: set() for v in port_svc.values()}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r") as f:
                rows = f.read().splitlines()[1:]
        except Exception:
            continue
        for row in rows:
            cols = row.split()
            if len(cols) < 4 or cols[3] != "01":     # 01 == ESTABLISHED
                continue
            try:
                lport = int(cols[1].rsplit(":", 1)[1], 16)
            except Exception:
                continue
            svc = port_svc.get(lport)
            if svc:
                per_service[svc].add(cols[2].rsplit(":", 1)[0])

    def dec(x):
        if len(x) == 8:  # /proc ipv4 addresses are little-endian hex
            try:
                return socket.inet_ntoa(struct.pack("<I", int(x, 16)))
            except Exception:
                return x
        return x or "(?)"

    ips = sorted({dec(x) for s in per_service.values() for x in s})
    return {
        "count": len(ips),
        "per_service": {k: len(v) for k, v in sorted(per_service.items())},
        "ips": ips[:64],
    }


def get_traffic_stats():
    """Read nfqws traffic counters from state files."""
    try:
        bytes_in = int(state_get("nfqws_bytes_in", "0") or "0")
        bytes_out = int(state_get("nfqws_bytes_out", "0") or "0")
        return {
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "total": bytes_in + bytes_out,
        }
    except Exception:
        return {"bytes_in": 0, "bytes_out": 0, "total": 0}


def import_strategy_from_json(data):
    """Import a custom strategy from the provided JSON format (domain-based test results)."""
    try:
        domain = data.get("domain", "custom")
        timestamp = data.get("timestamp", "")
        strategies_list = data.get("strategies", [])
        
        if not strategies_list:
            return {"ok": False, "error": "No strategies found in import data"}
        
        # Take the best strategy (first one with highest success rate)
        best = max(strategies_list, key=lambda s: (s.get("success_rate", 0), -s.get("median_latency_ms", 9999)))
        
        # Generate a unique ID for this custom strategy
        strategy_id = "custom_%s_%s" % (
            re.sub(r"[^a-z0-9]", "", domain.lower())[:20],
            timestamp[:10].replace("-", "") if timestamp else int(time.time())
        )
        
        # Build nfqws_opt from the args
        nfqws_opt = best.get("args", "")
        protocol = best.get("protocol", "HTTPS/TLS1.2")
        
        new_strategy = {
            "id": strategy_id,
            "name": "Custom: %s (%s)" % (domain, protocol),
            "desc": "Imported from %s test results. Success rate: %.1f%%, Latency: %dms" % (
                domain, 
                best.get("success_rate", 0) * 100,
                best.get("median_latency_ms", 0)
            ),
            "nfqws_opt": nfqws_opt,
            "imported": True,
            "import_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        # Load current strategies and append
        strat_data = read_json(STRATEGIES_FILE, {"strategies": []})
        strat_data.setdefault("strategies", [])
        
        # Remove any existing strategy with the same ID
        strat_data["strategies"] = [s for s in strat_data["strategies"] if s.get("id") != strategy_id]
        
        # Add the new strategy
        strat_data["strategies"].append(new_strategy)
        
        # Save back
        if not write_json(STRATEGIES_FILE, strat_data):
            return {"ok": False, "error": "Failed to write strategies file"}
        
        return {"ok": True, "strategy": new_strategy}
    
    except Exception as e:
        return {"ok": False, "error": str(e)}


def status():
    strat = active_strategy()
    entry = {}
    for s in strategies():
        if s.get("id") == strat:
            entry = s
            break
    host, host_src = detect_public_host()
    conns = connected_devices()
    traffic = get_traffic_stats()
    return {
        "version": "0.2.0",
        "uptime": int(time.time() - BOOT_TIME),
        "exit_mode": active_exit_mode(),
        "strategy": {
            "id": strat,
            "name": entry.get("name", strat),
            "nfqws_opt": entry.get("nfqws_opt", ""),
        },
        "services": [service_state(s) for s in SERVICES],
        "devices": conns,
        "traffic": traffic,
        "connect": {
            "host": host,
            "host_source": host_src,
            "ss": {
                "port": SS_LISTEN_PORT,
                "method": SS_METHOD,
                "uri": ss_uri(host) if host else "",
            },
            "socks5": {"port": SOCKS5_LISTEN_PORT, "auth": "none"},
        },
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
                     "desc": s.get("desc", ""), "imported": s.get("imported", False)} for s in strategies()
                ]
            })
        if path == "/api/strategy":
            return self._send(200, {"id": active_strategy()})
        if path == "/api/exit":
            return self._send(200, {"mode": active_exit_mode()})
        if path == "/api/traffic":
            return self._send(200, get_traffic_stats())
        if path == "/api/logs":
            q = dict(pair.split("=", 1) for pair in
                     self.path.split("?", 1)[1].split("&") if "=" in pair)
            src = q.get("src", "nfqws")
            try:
                n = int(q.get("n", "200") or "200")
            except ValueError:
                n = 200
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
        if path == "/api/strategy/import":
            body = self._read_body()
            res = import_strategy_from_json(body)
            return self._send(200 if res.get("ok") else 400, res)
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