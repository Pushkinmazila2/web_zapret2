#!/bin/bash
# =============================================================================
# wz-common.sh — shared environment/defaults and helpers for web_zapret2
# Sourced by wz-fw.sh / wz-svc.sh / wz-apply.sh / entrypoint.sh
# =============================================================================

WZ_SRC=/opt/webzapret
WZ_BIN=/opt/webzapret/bin
WZ_CFG=/etc/webzapret
WZ_RUN=/run/webzapret
WZ_LOG=/var/log/webzapret
WZ_STATE=/opt/webzapret/state

# binaries (shared across all wz-* scripts)
IPT=/usr/sbin/iptables
IP=/usr/sbin/ip

# fixed defaults (override from env)
: "${WAN_IFACE:=eth0}"
: "${SS_LISTEN_PORT:=8388}"
: "${SOCKS5_LISTEN_PORT:=1080}"
: "${SS_PASSWORD:=change-me}"
: "${SS_METHOD:=aes-256-gcm}"
: "${PANEL_PORT:=8080}"
: "${PANEL_USER:=}"
: "${PANEL_PASSWORD:=}"
: "${EXIT_MODE:=direct}"
: "${UDP_PROXY:=relay}"
: "${STRATEGY:=standard}"
: "${UPSTREAM_SOCKS5_HOST:=}"
: "${UPSTREAM_SOCKS5_PORT:=}"
: "${UPSTREAM_SOCKS5_USER:=}"
: "${UPSTREAM_SOCKS5_PASSWORD:=}"
: "${UPSTREAM_SS_HOST:=}"
: "${UPSTREAM_SS_PORT:=8388}"
: "${UPSTREAM_SS_PASSWORD:=}"
: "${UPSTREAM_SS_METHOD:=aes-256-gcm}"

# load nfqws/firewall constants (may be overridden by env)
[ -r "$WZ_CFG/zapret.default" ] && . "$WZ_CFG/zapret.default" 2>/dev/null || true
: "${DESYNC_MARK:=0x40000000}"
: "${QNUM_TCP:=210}"
: "${QNUM_UDP:=211}"
: "${QNUM_TEST:=212}"          # NFQUEUE queue bound by the ISOLATED test nfqws
: "${NFQ_TCP_PORTS:=80,443}"
: "${NFQ_UDP_PORTS:=443}"
: "${NFQWS_TCP_PKT_OUT:=9}"
: "${NFQWS_UDP_PKT_OUT:=9}"

# strategy testing (panel Test tab / API): probe a real URL with yt-dlp through
# a SEPARATE test nfqws process — the active strategy on the live queue is never
# touched and real clients keep their service. The video yt-dlp downloads is
# always deleted when the test ends.
: "${TEST_YTDLP_BIN:=/opt/webzapret/bin/yt-dlp}"
: "${TEST_YTDLP_URL:=https://www.youtube.com/watch?v=kJQP7kiw5Fk&list=RDkJQP7kiw5Fk&start_radio=1&pp=ygUKZGVzcGFjaXRvIKAHAQ%3D%3D}"
: "${TEST_YTDLP_TIMEOUT:=120}"
: "${TEST_YTDLP_FORMAT:=bv*[height<=360]+ba/b/worst}"
: "${TEST_YTDLP_MAX_FILESIZE:=80M}"
: "${REDSOCKS_PORT:=1060}"
: "${SS_LOCAL_PORT:=1090}"
: "${UDP_MARK:=0x1}"
: "${UTUN:=utun0}"
: "${RT_TABLE_UDP:=100}"

# ---------------------------------------------------------------------------
# computed upstream exit endpoints (call compute_upstream after EXIT_MODE is
# finalized — it is derived from the effective mode, not just the env)
# ---------------------------------------------------------------------------
UP_TCP_PORT=            # port redsocks/ss-local connect to (exit flows, TCP)
UP_UDP_PORT=            # port used for UDP data channel (exit flows, UDP)
UP_TR_HOST=             # host wz-udprelay must attach to
UP_TR_PORT=             # port wz-udprelay must attach to

compute_upstream()
{
    UP_TCP_PORT=
    UP_UDP_PORT=
    UP_TR_HOST=
    UP_TR_PORT=
    case "$EXIT_MODE" in
        socks5)
            UP_TCP_PORT=$UPSTREAM_SOCKS5_PORT
            UP_UDP_PORT=$UPSTREAM_SOCKS5_PORT
            UP_TR_HOST=$UPSTREAM_SOCKS5_HOST
            UP_TR_PORT=$UPSTREAM_SOCKS5_PORT
            ;;
        ss)
            UP_TCP_PORT=$UPSTREAM_SS_PORT
            UP_UDP_PORT=$UPSTREAM_SS_PORT
            UP_TR_HOST=127.0.0.1
            UP_TR_PORT=$SS_LOCAL_PORT
            ;;
    esac
}
compute_upstream

# ---------------------------------------------------------------------------
# helpers and tagged action logging
# ---------------------------------------------------------------------------
WZ_ACTIONS_LOG="$WZ_LOG/actions.log"

_actions_append()
{
    printf '%s\n' "$1" >> "$WZ_ACTIONS_LOG" 2>/dev/null || true
}

# log_module <module> <message...>
# Outputs a timestamped, tagged line to stdout and appends it to actions.log.
log_module()
{
    local mod=$1 line
    shift
    line="[$(date -u +%FT%TZ)] [$mod] $*"
    echo "$line"
    _actions_append "$line"
}

# log_err <module> <message...>
# Outputs an error line to stderr and appends it to actions.log.
log_err()
{
    local mod=$1 line
    shift
    line="[$(date -u +%FT%TZ)] [$mod] ERROR: $*"
    echo "$line" >&2
    _actions_append "$line"
}

wz_log() { log_module "wz" "$*"; }
wz_err() { log_err "wz" "$*"; }

valid_exit_mode()
{
    case "$1" in direct|socks5|ss) return 0 ;; esac
    return 1
}

valid_strategy_id()
{
    # $1 - strategy id; returns 0 if listed in strategies.json
    [ -n "$1" ] || return 1
    python3 - "$1" <<'PY' 2>/dev/null
import json, sys
try:
    with open("/opt/webzapret/config/strategies.json", "r") as f:
        data = json.load(f)
    ids = {s["id"] for s in data["strategies"]}
    sys.exit(0 if sys.argv[1] in ids else 1)
except Exception:
    sys.exit(1)
PY
}

strategy_opt()
{
    # prints nfqws options for strategy id $1, or empty string
    python3 - "$1" <<'PY'
import json, sys
with open("/opt/webzapret/config/strategies.json", "r") as f:
    data = json.load(f)
for s in data["strategies"]:
    if s["id"] == sys.argv[1]:
        print(s.get("nfqws_opt", ""))
        break
PY
}

# current active strategy id (from state, seeded by entrypoint)
active_strategy()
{
    if [ -f "$WZ_STATE/strategy" ]; then cat "$WZ_STATE/strategy"; else echo "$STRATEGY"; fi
}

active_exit_mode()
{
    if [ -f "$WZ_STATE/exit_mode" ]; then cat "$WZ_STATE/exit_mode"; else echo "$EXIT_MODE"; fi
}

# ---------------------------------------------------------------------------
# simple pidfile based process management (used by wz-svc.sh and panel/status)
# ---------------------------------------------------------------------------
pidfile() { echo "$WZ_RUN/$1.pid"; }

pid_read()
{
    local f; f=$(pidfile "$1")
    [ -f "$f" ] && cat "$f" || true
}

pid_alive()
{
    local p=$1
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

svc_running()
{
    local p; p=$(pid_read "$1")
    pid_alive "$p"
}

log_tail()
{
    # $1 service, $2 lines (default 200)
    local f="$WZ_LOG/$1.log" n=${2:-200}
    [ -f "$f" ] && tail -n "$n" "$f" || echo "(no log for $1)"
}

# ---------------------------------------------------------------------------
# traffic counters (nfqws in/out bytes via iptables byte counters)
# ---------------------------------------------------------------------------
nfqws_traffic_counters()
{
    # Read iptables byte counters for nfqws traffic.
    #   egress ("out"): NFQUEUE rules in WZFW (mangle/OUTPUT)
    #   ingress ("in"):  RETURN rule in NFQIN (mangle/PREROUTING)
    # Output: "bytes_in bytes_out"
    local bytes_in=0 bytes_out=0 pkt byt target
    local output

    output=$($IPT -t mangle -L WZFW -v -n -x -w 1 2>/dev/null || true)
    while read -r pkt byt target rest; do
        [ "$target" = "NFQUEUE" ] && bytes_out=$((bytes_out + byt))
    done <<< "$output"

    output=$($IPT -t mangle -L NFQIN -v -n -x -w 1 2>/dev/null || true)
    while read -r pkt byt target rest; do
        [ "$target" = "RETURN" ] && bytes_in=$((bytes_in + byt))
    done <<< "$output"

    echo "$bytes_in $bytes_out"
}
accumulate_traffic_counters()
{
    # Read current iptables counters and accumulate them into state files
    # so they persist across firewall reloads / nfqws restarts.
    # Sequence: read -> zero -> add (avoids double-counting in the panel).
    local counters bytes_in bytes_out cum_in cum_out
    counters=$(nfqws_traffic_counters 2>/dev/null || echo "0 0")
    read -r bytes_in bytes_out <<< "$counters"
    # Zero iptables counters first so only new traffic is counted afterwards
    $IPT -t mangle -Z WZFW 2>/dev/null || true
    $IPT -t mangle -Z NFQIN 2>/dev/null || true
    cum_in=$(cat "$WZ_STATE/nfqws_bytes_in" 2>/dev/null || echo 0)
    cum_out=$(cat "$WZ_STATE/nfqws_bytes_out" 2>/dev/null || echo 0)
    printf '%s\n' "$((cum_in + bytes_in))" > "$WZ_STATE/nfqws_bytes_in"
    printf '%s\n' "$((cum_out + bytes_out))" > "$WZ_STATE/nfqws_bytes_out"
    chmod 0640 "$WZ_STATE/nfqws_bytes_in" "$WZ_STATE/nfqws_bytes_out" 2>/dev/null || true
}