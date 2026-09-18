#!/usr/bin/env python3
"""web_zapret2 — lightweight management panel (stdlib-only HTTP+JSON API).

Endpoints
    GET  /                          single-file HTML UI
    GET  /api/status                services, strategy, exit mode, uptime, traffic
    GET  /api/strategies            list of available strategies
    GET  /api/strategy              current strategy
    POST /api/strategy {"id": ...}  switch strategy -> restart nfqws
    POST /api/strategy/import       import custom strategy from JSON
    POST /api/strategy/test {"id","url","timeout"}
                                    test a strategy on an ISOLATED test nfqws
                                    process with a yt-dlp probe (live nfqws is
                                    never touched; the video file is deleted
                                    when the test finishes)
    POST /api/strategy/delete {"id"}  remove a strategy from the catalog
    GET  /api/testinfo              Test tab defaults (URL, timeout, queue, yt-dlp)
    GET  /api/bcw                   "Strategy selection" overview: settings,
                                    schedule, availability, job and last results
    POST /api/bcw/settings          persist parameter overrides (panel over .env)
    POST /api/bcw/reset             drop overrides -> .env defaults again
    POST /api/bcw/run               start a scan+check run (blockcheckw, embedded)
    POST /api/bcw/cancel            stop the running selection
    POST /api/bcw/import            import working strategies into the catalog
    POST /api/bcw/schedule          configure the time-based scheduler
    GET  /api/exit                  current exit mode
    POST /api/exit {"mode": ...}    switch exit mode -> reload fw + restart
    GET  /api/logs?src=<svc>&n=<N>  tail a service log
    GET  /api/logs/export           download one merged connection log (all modules)
    GET  /api/traffic               nfqws traffic counters (in/out bytes)

CLI: python3 panel.py [--check] [--help]
"""
import base64
import hmac
import json
import os
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
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

# --- strategy testing (Test tab): isolated nfqws + yt-dlp probe --------------
WZ_TEST = "/opt/webzapret/scripts/wz-test.sh"
TEST_YTDLP_BIN = os.environ.get("TEST_YTDLP_BIN", "/opt/webzapret/bin/yt-dlp")
TEST_YTDLP_URL = os.environ.get(
    "TEST_YTDLP_URL",
    "https://www.youtube.com/watch?v=kJQP7kiw5Fk"
    "&list=RDkJQP7kiw5Fk&start_radio=1&pp=ygUKZGVzcGFjaXRvIKAHAQ%3D%3D")
try:
    TEST_YTDLP_TIMEOUT = int(os.environ.get("TEST_YTDLP_TIMEOUT", "120") or 120)
except ValueError:
    TEST_YTDLP_TIMEOUT = 120
try:
    TEST_QUEUE = int(os.environ.get("QNUM_TEST", "212") or 212)
except ValueError:
    TEST_QUEUE = 212
_TEST_URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)

# --- strategy selection ("Select" tab): blockcheckw wrapper -------------------
# The engine (src/blockcheck.py) is stdlib-only and lives next to strategy.py;
# it is optional at import time so a damaged image cannot take the panel down.
WZ_BCW = "/opt/webzapret/scripts/wz-bcw.sh"
BCW_SCRIPTS_DIR = "/opt/webzapret/scripts"
if BCW_SCRIPTS_DIR not in sys.path and os.path.isdir(BCW_SCRIPTS_DIR):
    sys.path.insert(0, BCW_SCRIPTS_DIR)
try:
    import blockcheck as bcw          # noqa: E402  (optional feature module)
except ImportError:
    bcw = None

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
    print("panel: apply: %s" % " ".join(args), flush=True)
    try:
        r = subprocess.run(
            [APPLY] + args,
            capture_output=True, text=True, timeout=90,
        )
        print("panel: apply rc=%d ok=%s" % (r.returncode, r.returncode == 0), flush=True)
        return {
            "ok": r.returncode == 0,
            "rc": r.returncode,
            "stdout": (r.stdout or "")[-6000:],
            "stderr": (r.stderr or "")[-2000:],
        }
    except subprocess.TimeoutExpired:
        print("panel: apply TIMED OUT (90s): %s" % " ".join(args), flush=True)
        return {"ok": False, "rc": -1, "stdout": "", "stderr": "timed out (90s)"}


_TS_RE = re.compile(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\]")
LOG_MODULES = ["actions", "ss-server", "sockd", "nfqws", "redsocks", "ss-local",
               "udprelay", "panel", "test", "bcw"]


def _read_file_lines(path, max_bytes=256 * 1024):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read().decode("utf-8", "replace")
        lines = data.splitlines()
        if size > max_bytes and lines:
            lines = lines[1:]                    # drop a possibly truncated line
        return lines
    except FileNotFoundError:
        return None
    except Exception as e:
        return ["(log read error: %s)" % e]


# Maximum bytes read from a single module log during an export. Bounds the
# download size / memory for busy gateways while keeping "the whole log" for
# typical traffic volumes.
LOG_EXPORT_MAX_BYTES = 8 * 1024 * 1024


def _collected_entries(tail_bytes):
    """Return time-ordered, [module]-tagged entries across all module logs.

    Each entry is (timestamp, module_rank, line_seq, text). Lines without
    timestamps inherit the last known timestamp from their file so
    multi-line entries stay grouped. ``tail_bytes`` sets how many bytes are
    read per module log; it may be a callable(module) for per-module limits
    or a plain int. The actions.log already carries its own [module] tags,
    so it is never re-prefixed.
    """
    entries = []
    for rank, mod in enumerate(LOG_MODULES):
        path = os.path.join(WZ_LOG, mod + ".log")
        max_bytes = tail_bytes(mod) if callable(tail_bytes) else tail_bytes
        lines = _read_file_lines(path, max_bytes)
        if lines is None:
            continue
        last_ts = ""
        for seq, ln in enumerate(lines):
            m = _TS_RE.match(ln)
            if m:
                last_ts = m.group(1)
            tag_prefix = "" if mod == "actions" else ("[%s] " % mod)
            entries.append((last_ts, rank, seq, tag_prefix + ln))

    entries.sort(key=lambda e: (e[0], e[1], e[2]))
    return entries


def merged_log(n=200):
    """Merged, time-ordered view of all module logs with [module] tags.

    Lines without timestamps inherit the last known timestamp from their
    file so multi-line entries stay grouped.
    """
    entries = _collected_entries(
        lambda mod: 256 * 1024 if mod == "actions" else 64 * 1024)
    if not entries:
        return "(no log entries available across modules)\n"
    return "\n".join(e[3] for e in entries[-n:]) + "\n"


def export_logs():
    """Full merged connection log across ALL modules as a single text blob.

    Unlike merged_log() this is not truncated to the last N lines — every
    module log is read (up to LOG_EXPORT_MAX_BYTES each) and merged in
    time order, prefixed with a header explaining the contents.
    """
    lines = [e[3] for e in _collected_entries(LOG_EXPORT_MAX_BYTES)]
    if not lines:
        lines = ["(no log entries available across modules)"]
    header = [
        "# ================================================================",
        "# web_zapret2 — connection log export (all modules, one file)",
        "# generated: %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "# modules:   %s" % " ".join(LOG_MODULES),
        "# fetch:     GET /api/logs/export  (HTTP Basic auth if enabled)",
        "# ================================================================",
    ]
    for mod in LOG_MODULES:
        try:
            size = os.path.getsize(os.path.join(WZ_LOG, mod + ".log"))
        except OSError:
            size = -1
        header.append("# %-10s %s bytes" % (mod, size if size >= 0 else "n/a"))
    header.append("# ================================================================")
    return "\n".join(header + lines) + "\n"


def tail_log(src, n=200):
    """Tail a service log file (last n lines); tolerant to bad input."""
    try:
        n = max(1, min(int(n), 5000))
    except (TypeError, ValueError):
        n = 200
    if not re.fullmatch(r"[a-z0-9_-]{1,64}", src or ""):
        return "(bad log source)"
    if src == "all":
        return merged_log(n)
    path = os.path.join(WZ_LOG, src + ".log")
    lines = _read_file_lines(path, 256 * 1024)
    if lines is None:
        return "(no log for %s)\n" % src
    return "\n".join(lines[-n:]) + "\n"


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
    """Read nfqws traffic counters from iptables byte counters.

    Egress bytes ("out") come from NFQUEUE rules in the WZFW mangle/OUTPUT
    chain — packets desynced by nfqws.  Ingress bytes ("in") come from the
    NFQIN counting chain in mangle/PREROUTING — return traffic from remote
    servers.  Counters persist across nfqws restarts and reset when the
    firewall is reloaded (exit-mode change).  Falls back to state files
    when iptables is unavailable.
    """
    bytes_in = 0
    bytes_out = 0
    try:
        r = subprocess.run(
            ["/usr/sbin/iptables", "-t", "mangle", "-L", "WZFW",
             "-v", "-n", "-x", "-w", "1"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == "NFQUEUE":
                try:
                    bytes_out += int(parts[1])
                except ValueError:
                    pass
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["/usr/sbin/iptables", "-t", "mangle", "-L", "NFQIN",
             "-v", "-n", "-x", "-w", "1"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == "RETURN":
                try:
                    bytes_in += int(parts[1])
                except ValueError:
                    pass
    except Exception:
        pass

    # Fallback to state files when iptables is unavailable
    if bytes_in == 0 and bytes_out == 0:
        bytes_in = int(state_get("nfqws_bytes_in", "0") or "0")
        bytes_out = int(state_get("nfqws_bytes_out", "0") or "0")

    return {
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "total": bytes_in + bytes_out,
    }


def translate_nfqws_args(args, protocol):
    """Translate zapret2 test-result args to nfqws CLI args.

    Test results use --payload and --lua-desync (from zapret2's Lua-based
    desync). This translates them to the --filter-tcp/udp --dpi-desync
    family of options understood by the nfqws binary in this image.
    If the args already use the nfqws format, they are returned as-is.
    """
    if not args or ("--payload=" not in args and "--lua-desync=" not in args):
        return args

    # Determine filter (protocol + port) from the protocol field
    if protocol and ("QUIC" in protocol or "UDP" in protocol):
        filter_opt = "--filter-udp=443"
    elif protocol and "HTTP" in protocol and "TLS" not in protocol:
        filter_opt = "--filter-tcp=80"
    else:
        filter_opt = "--filter-tcp=443"

    # Parse --lua-desync entries (there may be multiple)
    lua_specs = re.findall(r"--lua-desync=([^\s]+)", args)
    if not lua_specs:
        return filter_opt

    desync_modes = []
    split_positions = []
    fooling = []
    repeats = None

    for spec in lua_specs:
        tokens = spec.split(":")
        method = tokens[0]

        # Map lua-desync method to nfqws dpi_desync modes
        method_map = {
            "fake": ["fake"],
            "fakeddisorder": ["fake", "multidisorder"],
            "multidisorder": ["multidisorder"],
            "fakedsplit": ["fake", "fakedsplit"],
            "multisplit": ["multisplit"],
            "disorder": ["disorder"],
            "split": ["split"],
        }
        desync_modes.extend(method_map.get(method, [method]))

        for token in tokens[1:]:
            if token.startswith("pos="):
                pos_val = token.split("=", 1)[1]
                if pos_val == "midsld":
                    split_positions.append("midsld")
                else:
                    split_positions.append(pos_val)
            elif token.startswith("repeats="):
                repeats = int(token.split("=")[1])
            elif token.startswith("tcp_ack="):
                fooling.append("badseq")
            elif token == "tcp_ts_up":
                fooling.append("ts")
            elif token.startswith("tls_mod="):
                mods = token.split("=")[1].split(",")
                if "rnd" in mods and "ts" not in fooling:
                    fooling.append("ts")
                if "dupsid" in mods and "badseq" not in fooling:
                    fooling.append("badseq")
                if "padencap" in mods and "badseq" not in fooling:
                    fooling.append("badseq")

    # Dedupe while preserving order
    desync_modes = list(dict.fromkeys(desync_modes))
    split_positions = list(dict.fromkeys(split_positions))
    fooling = list(dict.fromkeys(fooling))

    parts = [filter_opt]
    if desync_modes:
        parts.append("--dpi-desync=" + ",".join(desync_modes))
    if split_positions:
        # Prepend '1,' (first packet) when midsld is used, matching existing strategies
        if "midsld" in split_positions and "1" not in split_positions:
            split_positions.insert(0, "1")
        parts.append("--dpi-desync-split-pos=" + ",".join(split_positions))
    if fooling:
        parts.append("--dpi-desync-fooling=" + ",".join(fooling))
    if repeats is not None:
        parts.append("--dpi-desync-repeats=%d" % repeats)

    return " ".join(parts)


def import_strategy_from_json(data):
    """Import custom strategies from the provided JSON format (domain-based test results).

    Imports every entry of the "strategies" array (there may be several),
    ranked best-first (highest success_rate, then lowest latency).
    """
    try:
        domain = data.get("domain", "custom")
        timestamp = data.get("timestamp", "")
        strategies_list = data.get("strategies", [])
        if not strategies_list:
            return {"ok": False, "error": "No strategies found in import data"}

        # Rank best-first: highest success_rate, then lowest latency
        ranked = sorted(strategies_list,
                        key=lambda s: (-s.get("success_rate", 0),
                                       s.get("median_latency_ms", 9999)))

        domain_slug = re.sub(r"[^a-z0-9]", "", domain.lower())[:20]
        date_slug = timestamp[:10].replace("-", "") if timestamp else str(int(time.time()))
        id_base = "custom_%s_%s" % (domain_slug, date_slug)

        # Load current strategies
        strat_data = read_json(STRATEGIES_FILE, {"strategies": []})
        strat_data.setdefault("strategies", [])

        imported = []
        for idx, s in enumerate(ranked):
            strategy_id = id_base if idx == 0 else "%s_%d" % (id_base, idx + 1)

            protocol = s.get("protocol", "HTTPS/TLS1.2")
            original_args = s.get("args", "")
            if not isinstance(original_args, str) or not original_args.strip():
                raise ValueError("Strategy args must be a non-empty string")
            shlex.split(original_args)
            nfqws_opt = original_args

            # Detect if translation was needed
            translated = False
            # Imported TLS/HTTPS strategies desync on the TLS ClientHello. nfqws
            # buffers and DROPS every packet until the whole hello reassembles; if
            # a segment of a multi-segment hello is lost the connection hangs
            # forever (YouTube/Google CDN hosts on low-MSS paths). New imports
            # disable that reassembly so the first segment is desynced immediately.
            tokens = shlex.split(original_args)
            no_reasm = any("tls_client_hello" in t for t in tokens) or any(
                t.startswith("--filter-tcp=443") for t in tokens)

            new_strategy = {
                "id": strategy_id,
                "name": "Custom: %s (%s)" % (domain, protocol),
                "desc": "Imported from %s test results (%.1f%% success, %dms latency)%s" % (
                    domain,
                    s.get("success_rate", 0) * 100,
                    int(s.get("median_latency_ms", 0)),
                    " [args translated from zapret2 test format]" if translated else "",
                ),
                "nfqws_opt": nfqws_opt,
                "lua_opt": original_args if "--lua-desync=" in original_args else "",
                "protocol": protocol,
                "imported": True,
                "import_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "import_original_args": original_args,
            }
            # see no_reasm detection above; keep the flag on the saved strategy so
            # nfqws renders it with --reasm-disable=<payload>
            if no_reasm:
                new_strategy["no_reasm"] = True

            # Replace any previous import of the same domain+date batch, append
            strat_data["strategies"] = [x for x in strat_data["strategies"]
                                        if x.get("id") != strategy_id]
            strat_data["strategies"].append(new_strategy)
            imported.append(new_strategy)

        if not write_json(STRATEGIES_FILE, strat_data):
            return {"ok": False, "error": "Failed to write strategies file"}

        return {"ok": True, "strategy": imported[0], "strategies": imported,
                "count": len(imported)}

    except Exception as e:
        return {"ok": False, "error": str(e)}


def test_strategy(strategy_id, url="", timeout=None):
    """Test a strategy on an ISOLATED nfqws process via wz-test.sh.

    The harness runs a separate test nfqws (its own NFQUEUE queue) and a
    yt-dlp probe of a real URL as the dedicated 'testuser' uid, so the live
    nfqws and the active gateway strategy are never touched. The downloaded
    video file is deleted by the harness after the run.
    """
    if strategy_id not in strategy_ids():
        return {"ok": False, "error": "unknown strategy '%s'" % strategy_id}
    url = (url or TEST_YTDLP_URL).strip()
    if not url or len(url) > 2048 or not _TEST_URL_RE.match(url):
        return {"ok": False, "error": "test URL must be a single http(s) URL"}
    try:
        timeout = max(10, min(int(timeout or TEST_YTDLP_TIMEOUT), 600))
    except (TypeError, ValueError):
        timeout = TEST_YTDLP_TIMEOUT
    print("panel: strategy test: id=%s url=%s timeout=%ss"
          % (strategy_id, url, timeout), flush=True)
    try:
        r = subprocess.run(
            [WZ_TEST, strategy_id, url, str(timeout)],
            capture_output=True, text=True, timeout=timeout + 180,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "test harness timed out"}
    raw = r.stdout or ""
    res = {}
    # tolerate ANY stray output around the JSON (leading log lines, trailing
    # noise): raw_decode parses the first JSON value and ignores the rest, so
    # a successful download is never reported as 'malformed harness output'
    start = raw.find("{")
    if start >= 0:
        try:
            res, _ = json.JSONDecoder().raw_decode(raw[start:])
        except ValueError:
            res = {}
    if not isinstance(res, dict) or "ok" not in res:
        res = {"ok": False, "error": ("malformed test harness output (rc=%d): %s"
                                      % (r.returncode, (raw or r.stderr or "")[-800:]))}
    return res


def delete_strategy(strategy_id):
    """Remove a strategy from config/strategies.json (idempotent)."""
    sid = str(strategy_id or "")
    if sid not in strategy_ids():
        return {"ok": False, "error": "unknown strategy '%s'" % sid}
    if sid == "none":
        return {"ok": False, "error": "the built-in 'none' strategy cannot be deleted"}
    if sid == active_strategy():
        return {"ok": False, "error": "cannot delete the ACTIVE strategy — switch to another one first"}
    strat = read_json(STRATEGIES_FILE, {"strategies": []}) or {"strategies": []}
    strat["strategies"] = [s for s in strat.get("strategies", []) if s.get("id") != sid]
    if not write_json(STRATEGIES_FILE, strat):
        return {"ok": False, "error": "failed to write strategies file"}
    print("panel: strategy deleted: %s" % sid, flush=True)
    return {"ok": True, "id": sid,
            "strategies": [s.get("id") for s in strat.get("strategies", [])]}


# ---------------------------------------------------------------------------
# "Strategy selection" (blockcheckw): strategy generation grid (scan), the
# multithreaded SO_MARK prober, the two-axis false-positive filter (check) and
# a time-based scheduler.  Every parameter comes from .env (BCW_*) and can be
# overridden live from the panel (persisted in $WZ_STATE/bcw_settings.json).
# The live gateway is never touched: blockcheckw runs in embedded mode
# (--no-conflict-cleanup) on its own NFQUEUE and its own nft table.
# ---------------------------------------------------------------------------
BCW_STATE_DIR = os.path.join(WZ_STATE, "bcw")
BCW_RUNS_DIR = os.path.join(BCW_STATE_DIR, "runs")
BCW_KEEP_RUNS = int(os.environ.get("BCW_KEEP_RUNS", "10") or 10)
BCW_PROTOCOL_NAMES = {"http": "HTTP", "tls12": "HTTPS/TLS1.2",
                      "tls13": "HTTPS/TLS1.3"}
_BCW_LOCK = threading.Lock()
_BCW_SCHED_TICK = int(os.environ.get("BCW_SCHED_TICK", "15") or 15)


def bcw_ready():
    if bcw is None:
        return False, "engine module missing (blockcheck.py not installed)"
    if not os.access(WZ_BCW, os.X_OK):
        return False, "harness missing: %s" % WZ_BCW
    return True, ""


def _nfqueue_bound(qnum):
    """True when the queue is bound by ANY process (procfs lists all queues)."""
    try:
        with open("/proc/net/netfilter/nfnetlink_queue") as handle:
            for row in handle:
                cols = row.split()
                if cols and cols[0] == str(int(qnum)):
                    return True
    except (OSError, ValueError):
        pass
    return False


def bcw_availability():
    """Cheap health readout for the Select tab (no blockcheckw invocation)."""
    if bcw is None:
        return {"engine": False}
    settings = bcw.env_defaults()
    base = os.environ.get("BCW_ZAPRET_BASE", "/opt/zapret2")
    version = ""
    try:
        with open(bcw.BCW_VERSION_FILE, "r", encoding="utf-8") as handle:
            version = handle.read().strip()
    except OSError:
        pass
    ready, error = bcw_ready()
    return {
        "engine": ready,
        "engine_error": error,
        "version": version,
        "binary": settings.get("bin", ""),
        "binary_present": os.access(settings.get("bin", ""), os.X_OK),
        "nft_present": bool(shutil.which("nft")),
        "zapret_base": base,
        "nfqws2_present": os.path.exists(os.path.join(base, "nfq2", "nfqws2")),
        "lua_present": all(os.path.exists(os.path.join(base, "lua", name))
                           for name in ("zapret-lib.lua", "zapret-antidpi.lua")),
        "queue": bcw.BCW_QUEUE_FIXED,
        "queue_free": not _nfqueue_bound(bcw.BCW_QUEUE_FIXED),
    }


def _bcw_last_summary(last):
    """Compact, UI-friendly view of the last finished run."""
    if not last:
        return None
    domains = []
    for dom in last.get("domains") or []:
        domains.append({
            "domain": dom.get("domain"),
            "block_type": dom.get("block_type"),
            "scanned": dom.get("scanned", 0),
            "checked": dom.get("checked", 0),
            "inconclusive": dom.get("inconclusive", False),
            "working_count": len(dom.get("working") or []),
            "refused_count": len(dom.get("refused") or []),
            "working": (dom.get("working") or [])[:12],
        })
    return {
        "run_id": last.get("run_id"),
        "started_at": last.get("started_at"),
        "finished_at": last.get("finished_at"),
        "took_s": last.get("took_s"),
        "ok": last.get("ok", False),
        "success": last.get("success", False),
        "errors": last.get("errors") or [],
        "summary": bcw.summarize(last) if last else "",
        "domains": domains,
    }



def bcw_overview():
    """Everything the Select tab needs in one GET."""
    ready, error = bcw_ready()
    if not ready:
        return {"ok": True, "available": False, "error": error,
                "availability": {"engine": False}, "settings": {}, "schedule": {},
                "job": {"state": "idle"}, "last": None}
    settings, warnings, errors = bcw.load_settings(BCW_STATE_DIR)
    schedule, swarnings, serrors = bcw.load_schedule(BCW_STATE_DIR)
    sched_state = bcw.read_json(bcw.state_path(BCW_STATE_DIR, bcw.SCHEDULE_FILE),
                                {}) or {}
    job = bcw.load_job(BCW_STATE_DIR)
    running = job.get("state") == "running" and pid_alive(job.get("pid"))
    if job.get("state") == "running" and not running:
        job["state"] = "lost"          # the panel restarted mid-run
        bcw.save_job(BCW_STATE_DIR, job)
    return {
        "ok": True,
        "available": True,
        "availability": bcw_availability(),
        "settings": settings,
        "settings_warnings": warnings,
        "settings_errors": errors,
        "schedule": dict(schedule,
                         next_run=sched_state.get("next_run"),
                         next_run_local=bcw.format_local(sched_state.get("next_run")),
                         last_run=sched_state.get("last_run"),
                         last_run_local=bcw.format_local(sched_state.get("last_run"))),
        "schedule_warnings": swarnings,
        "schedule_errors": serrors,
        "job": dict(job, running=running),
        "last": _bcw_last_summary(
            bcw.read_json(bcw.state_path(BCW_STATE_DIR, bcw.LAST_RUN_FILE))),
    }


def bcw_start_run(overrides=None, source="manual"):
    """Persist (optional) overrides and launch one scan+check run in background."""
    ready, error = bcw_ready()
    if not ready:
        return {"ok": False, "error": error}
    with _BCW_LOCK:
        job = bcw.load_job(BCW_STATE_DIR)
        if job.get("state") == "running" and pid_alive(job.get("pid")):
            return {"ok": False, "error": "a run is already in progress (run %s)"
                    % job.get("run_id", "?")}
        if overrides:
            _merged, warnings, errors, saved = bcw.save_settings(BCW_STATE_DIR,
                                                                 overrides)
            if not saved:
                return {"ok": False, "error": "cannot persist settings"}
        else:
            warnings, errors = [], []
        settings, warnings, errors = bcw.load_settings(BCW_STATE_DIR)
        if errors:
            return {"ok": False, "error": "; ".join(errors), "errors": errors,
                    "warnings": warnings}
        run_id = time.strftime("%Y%m%d-%H%M%S")
        run_dir = os.path.join(BCW_RUNS_DIR, run_id)
        settings_file = os.path.join(run_dir, "settings.json")
        try:
            os.makedirs(run_dir, exist_ok=True)
        except OSError as exc:
            return {"ok": False, "error": "cannot create run dir: %s" % exc}
        bcw.write_json(settings_file, settings)
        job = {"state": "running", "source": source, "run_id": run_id,
               "run_dir": run_dir, "pid": None, "rc": None,
               "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        bcw.save_job(BCW_STATE_DIR, job)
        try:
            proc = subprocess.Popen(
                [WZ_BCW, "run", settings_file, run_dir],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True)
        except OSError as exc:
            job["state"] = "error"
            bcw.save_job(BCW_STATE_DIR, job)
            return {"ok": False, "error": "cannot start the harness: %s" % exc}
        job["pid"] = proc.pid
        bcw.save_job(BCW_STATE_DIR, job)
        threading.Thread(target=_bcw_collect, args=(proc, job), daemon=True).start()
    print("panel: bcw run %s started (%s)" % (run_id, source), flush=True)
    return {"ok": True, "run_id": run_id, "pid": proc.pid, "settings": settings,
            "warnings": warnings}


def _bcw_collect(proc, job):
    """Wait for the harness, parse the result, persist it, maybe import/apply."""
    out = b""
    if proc.stdout:
        out = proc.stdout.read()
        proc.stdout.close()
    rc = proc.wait()
    res = {}
    start = out.find(b"{")
    if start >= 0:
        try:
            res, _ = json.JSONDecoder().raw_decode(
                out[start:].decode("utf-8", "replace"))
        except ValueError:
            res = {}
    if not isinstance(res, dict) or not res:
        res = bcw.read_json(os.path.join(job["run_dir"], "result.json"), {}) or {}
    state = "done" if res.get("ok") else "error"
    job = dict(job, state=state, rc=rc,
               finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    bcw.save_job(BCW_STATE_DIR, job)
    if res.get("ok"):
        bcw.write_json(bcw.state_path(BCW_STATE_DIR, bcw.LAST_RUN_FILE), res)
    try:
        bcw.prune_runs(BCW_RUNS_DIR, BCW_KEEP_RUNS)
    except Exception:
        pass
    summary = bcw.summarize(res) if res else "no result"
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print("panel: bcw run %s finished rc=%s: %s" % (job.get("run_id"), rc, summary),
          flush=True)
    try:
        with open(os.path.join(WZ_LOG, "actions.log"), "a", encoding="utf-8") as handle:
            handle.write("[%s] [bcw] run %s: %s\n" % (stamp, job.get("run_id"),
                                                      summary))
    except OSError:
        pass
    if res.get("success") and (res.get("settings") or {}).get("auto_import"):
        imported = bcw_import(run_id=job.get("run_id"))
        if imported.get("ok"):
            first = (imported.get("imported") or [{}])[0].get("id", "")
            print("panel: bcw auto-imported: %s" % ", ".join(imported.get("ids", [])),
                  flush=True)
            if first and (res.get("settings") or {}).get("auto_apply"):
                applied = apply(["strategy", first])
                print("panel: bcw auto-apply '%s': ok=%s"
                      % (first, applied.get("ok")), flush=True)


def bcw_cancel():
    """SIGTERM the whole harness process group (blockcheckw cleans up after it)."""
    with _BCW_LOCK:
        job = bcw.load_job(BCW_STATE_DIR)
        if job.get("state") != "running" or not pid_alive(job.get("pid")):
            return {"ok": False, "error": "no running selection"}
        pid = int(job["pid"])
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except OSError:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                return {"ok": False, "error": "process already gone"}
        job["state"] = "cancelling"
        bcw.save_job(BCW_STATE_DIR, job)
    print("panel: bcw run %s cancelled" % job.get("run_id"), flush=True)
    return {"ok": True, "run_id": job.get("run_id")}


def bcw_import(run_id=None, protocols=None, limit=None):
    """Import the selected (false-positive-filtered) strategies of a finished
    run into the live catalog.  Returns the created catalog entries."""
    ready, error = bcw_ready()
    if not ready:
        return {"ok": False, "error": error}
    path = (os.path.join(BCW_RUNS_DIR, str(run_id), "result.json") if run_id
            else bcw.state_path(BCW_STATE_DIR, bcw.LAST_RUN_FILE))
    result = bcw.read_json(path)
    if not isinstance(result, dict) or not result.get("ok"):
        return {"ok": False, "error": "no finished run to import from (%s)" % path}
    rows = rows if isinstance(rows, list) else None
    if rows:
        # explicit selection from the UI (protocol+args pairs, still validated)
        domain = ""
        for dom in result.get("domains") or []:
            if dom.get("domain"):
                domain = dom["domain"]
                break
        clean = []
        for row in rows:
            if not isinstance(row, dict) or not row.get("args"):
                continue
            clean.append({
                "protocol": str(row.get("protocol") or "HTTPS/TLS1.2"),
                "args": str(row.get("args")),
                "passes_ok": row.get("passes_ok", 0),
                "passes_total": row.get("passes_total", 0),
                "median_share": row.get("median_share"),
                "median_latency_ms": row.get("median_latency_ms", 0),
                "success_rate": row.get("success_rate", 1.0),
                "admits": row.get("admits") or [],
                "observed": row.get("observed", ""),
                "working": True,
            })
        result = dict(result, domains=[{"domain": domain or "manual",
                                        "block_type": "", "working": clean}])
    settings, _, _ = bcw.load_settings(BCW_STATE_DIR)
    if limit is not None:
        try:
            settings = dict(settings, max_import=max(0, min(int(limit), 100)))
        except (TypeError, ValueError):
            pass
    if protocols:
        allowed = {BCW_PROTOCOL_NAMES.get(str(p).strip().lower()) for p in protocols}
        allowed.discard(None)
        result = dict(result, domains=[
            dict(dom, working=[row for row in dom.get("working") or []
                               if row.get("protocol") in allowed])
            for dom in result.get("domains") or []])
    entries, skipped = bcw.plan_import(result, settings, strategies(),
                                       run_id=str(run_id or "last"))
    if not entries:
        return {"ok": False, "error": "nothing to import", "skipped": skipped}
    catalog = read_json(STRATEGIES_FILE, {"strategies": []}) or {"strategies": []}
    merged = bcw.merge_catalog(catalog, entries)
    if not write_json(STRATEGIES_FILE, merged):
        return {"ok": False, "error": "failed to write strategies file"}
    ids = [entry["id"] for entry in entries]
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print("panel: bcw imported %s" % ", ".join(ids), flush=True)
    try:
        with open(os.path.join(WZ_LOG, "actions.log"), "a", encoding="utf-8") as handle:
            handle.write("[%s] [bcw] imported strategies: %s\n" % (stamp, ", ".join(ids)))
    except OSError:
        pass
    return {"ok": True, "ids": ids, "count": len(ids),
            "strategies": [{"id": e["id"], "name": e["name"],
                            "protocol": e["protocol"]} for e in entries],
            "skipped": skipped}


def _bcw_scheduler():
    """Background loop firing the time-based selection runs (requirement 4)."""
    while True:
        time.sleep(max(5, _BCW_SCHED_TICK))
        try:
            if bcw is None or not bcw_ready()[0]:
                continue
            schedule, _, _ = bcw.load_schedule(BCW_STATE_DIR)
            state_path = bcw.state_path(BCW_STATE_DIR, bcw.SCHEDULE_FILE)
            state = bcw.read_json(state_path, {}) or {}
            now = time.time()
            if not schedule.get("enabled"):
                if state.get("next_run"):
                    state.pop("next_run", None)
                    bcw.write_json(state_path, state)
                continue
            if not state.get("next_run"):
                state["next_run"] = bcw.next_run_at(schedule, now, state.get("last_run"))
                bcw.write_json(state_path, state)
                continue
            if not bcw.schedule_due(schedule, now, state.get("next_run")):
                continue
            fired = state["next_run"]
            state["last_run"] = fired
            state["next_run"] = bcw.next_run_at(schedule, now, fired)
            bcw.write_json(state_path, state)
            print("panel: bcw scheduler fires a run (slot %s)"
                  % bcw.format_local(fired), flush=True)
            res = bcw_start_run(None, source="scheduled")
            if not res.get("ok"):
                print("panel: bcw scheduled run refused: %s" % res.get("error"),
                      flush=True)
        except Exception as exc:            # never let the thread die silently
            print("panel: bcw scheduler error: %s" % exc, flush=True)


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
            "nfqws_opt": entry.get("lua_opt") or entry.get("nfqws_opt", ""),
            "lua_init": entry.get("lua_init", []),
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
        if path == "/api/testinfo":
            return self._send(200, {
                "test_url": TEST_YTDLP_URL,
                "test_timeout": TEST_YTDLP_TIMEOUT,
                "test_queue": TEST_QUEUE,
                "yt_dlp_available": os.path.exists(TEST_YTDLP_BIN),
            })
        if path == "/api/bcw":
            return self._send(200, bcw_overview())
        if path == "/api/strategy":
            return self._send(200, {"id": active_strategy()})
        if path == "/api/exit":
            return self._send(200, {"mode": active_exit_mode()})
        if path == "/api/traffic":
            return self._send(200, get_traffic_stats())
        if path == "/api/logs/export":
            body = export_logs().encode("utf-8")
            stamp = time.strftime("%Y%m%d-%H%M%S")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="webzapret-logs-%s.log"' % stamp)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/logs":
            q = dict(pair.split("=", 1) for pair in
                     self.path.split("?", 1)[1].split("&") if "=" in pair)
            src = q.get("src", "all")
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
        if path == "/api/strategy/test":
            body = self._read_body()
            res = test_strategy(
                str(body.get("id", "")),
                str(body.get("url", "") or TEST_YTDLP_URL),
                body.get("timeout"),
            )
            return self._send(200 if res.get("ok") else 400, res)
        if path == "/api/strategy/delete":
            body = self._read_body()
            res = delete_strategy(str(body.get("id", "")))
            return self._send(200 if res.get("ok") else 400, res)
        if path == "/api/bcw/settings":
            if bcw is None:
                return self._send(400, {"ok": False,
                                        "error": "strategy selection unavailable"})
            merged, warnings, errors, saved = bcw.save_settings(
                BCW_STATE_DIR, self._read_body())
            return self._send(200 if saved and not errors else 400,
                              {"ok": bool(saved) and not errors, "settings": merged,
                               "warnings": warnings, "errors": errors})
        if path == "/api/bcw/reset":
            if bcw is None:
                return self._send(400, {"ok": False,
                                        "error": "strategy selection unavailable"})
            return self._send(200, {"ok": True,
                                    "settings": bcw.reset_settings(BCW_STATE_DIR)})
        if path == "/api/bcw/run":
            body = self._read_body()
            overrides = body.get("settings") if isinstance(body.get("settings"),
                                                           dict) else None
            res = bcw_start_run(overrides, source="manual")
            return self._send(200 if res.get("ok") else 400, res)
        if path == "/api/bcw/cancel":
            res = bcw_cancel()
            return self._send(200 if res.get("ok") else 400, res)
        if path == "/api/bcw/import":
            body = self._read_body()
            res = bcw_import(body.get("run_id"), body.get("protocols"),
                             body.get("limit"), body.get("rows"))
            return self._send(200 if res.get("ok") else 400, res)
        if path == "/api/bcw/schedule":
            if bcw is None:
                return self._send(400, {"ok": False,
                                        "error": "strategy selection unavailable"})
            merged, warnings, errors, saved = bcw.save_schedule(
                BCW_STATE_DIR, self._read_body())
            if saved and not errors:
                # (re)arm immediately: next tick stores/computes the slot
                state_path = bcw.state_path(BCW_STATE_DIR, bcw.SCHEDULE_FILE)
                state = bcw.read_json(state_path, {}) or {}
                state.pop("next_run", None)
                bcw.write_json(state_path, state)
            return self._send(200 if saved and not errors else 400,
                              {"ok": bool(saved) and not errors, "schedule": merged,
                               "warnings": warnings, "errors": errors})
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
    if bcw is not None and os.access(WZ_BCW, os.X_OK):
        threading.Thread(target=_bcw_scheduler, daemon=True).start()
    httpd = ThreadingHTTPServer((HTTPD_HOST, HTTPD_PORT), Handler)
    print("panel listening on %s:%s" % (HTTPD_HOST, HTTPD_PORT), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
