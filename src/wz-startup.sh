#!/bin/bash
# =============================================================================
# wz-startup.sh — start-up diagnostics, written to files even when the panel is dead
#
#   $WZ_LOG/startup.log     timestamped notes: boot facts, then a health sample
#                           every few seconds for the first minute
#   $WZ_LOG/startup-report  one-shot report at T+60s: what runs, what listens,
#                           panel probe, import check, and the first minute of every
#                           service log (the container's logs are fresh at each start)
#
# The report is also printed to `docker logs` between ==== markers, and served by
# the panel at /api/startup. Read it without the panel:
#   docker exec <container> cat /var/log/webzapret/startup-report
# Secrets (PASSWORD/SECRET/KEY/TOKEN env vars) are masked.
# =============================================================================
set -u
. /opt/webzapret/scripts/wz-common.sh

SLOG="$WZ_LOG/startup.log"
REPORT="$WZ_LOG/startup-report"
PORT="${PANEL_PORT:-8080}"
BOOT_EPOCH=$(date +%s)
WINDOW=${STARTUP_WINDOW:-60}

note() { printf '[%s +%3ss] %s\n' "$(date -u +%FT%TZ)" "$(( $(date +%s) - BOOT_EPOCH ))" "$*" >> "$SLOG"; }
mask_env() { env | sort | sed -E 's/^([A-Za-z0-9_]*(PASSWORD|PASS|SECRET|KEY|TOKEN)[A-Za-z0-9_]*)=.*/\1=***/'; }
panel_pid() { cat "$(pidfile panel)" 2>/dev/null; }
probe() { curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null || true; }
listens() { ss -ltn 2>/dev/null | awk -v p=":$PORT\$" '$4 ~ p {f=1} END {print f ? "yes" : "no"}'; }

: > "$SLOG"
note "boot: panel port inside container = $PORT (host port is set by compose 'ports:')"
note "boot: python $(python3 --version 2>&1), kernel $(uname -r), user $(id -un)"

# --- sampling loop for the first minute --------------------------------------
sampled_dead=0
for t in 1 2 3 5 8 12 17 25 35 45 60; do
    while [ $(( $(date +%s) - BOOT_EPOCH )) -lt "$t" ]; do sleep 0.5; done
    pid=$(panel_pid)
    if [ -z "$pid" ]; then
        state="not started yet"
    elif kill -0 "$pid" 2>/dev/null; then
        state="alive pid=$pid"
    else
        state="DEAD pid=$pid"
        if [ "$sampled_dead" = 0 ]; then
            sampled_dead=1
            note "panel process died; last panel.log lines:"
            tail -n 40 "$WZ_LOG/panel.log" 2>/dev/null | sed 's/^/    | /' >> "$SLOG"
        fi
    fi
    note "panel: $state, port $PORT listening: $(listens), GET /healthz -> HTTP $(probe)"
    [ "$t" -ge "$WINDOW" ] && break
done

# --- one-shot report ---------------------------------------------------------
{
    echo "web_zapret2 start-up report  ($(date -u +%FT%TZ), first ${WINDOW}s)"
    echo
    echo "== summary =="
    pid=$(panel_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then echo "panel process: alive (pid $pid)"; else echo "panel process: NOT RUNNING"; fi
    echo "panel listens on :$PORT inside container: $(listens)"
    echo "panel GET /healthz: HTTP $(probe)  (200 = up; /api/* answers 401 until you log in)"
    echo "compose must publish  <host-port>:$PORT  (container side must equal PANEL_PORT=$PORT)"
    echo
    echo "== start-up notes =="
    cat "$SLOG"
    echo
    echo "== listening sockets =="
    ss -ltnup 2>&1 | head -40
    echo
    echo "== processes =="
    ps -eo pid,ppid,etime,args --width 160 2>&1 | grep -v "ps -eo" | head -40
    echo
    echo "== python module check (what the panel imports) =="
    ( cd /opt/webzapret/panel && python3 - <<'PY' 2>&1
import sys, traceback
sys.path.insert(0, "/opt/webzapret/scripts")
for name in ("strategy", "blockcheck", "flows", "nfqtrace", "conntrack", "verdict"):
    try:
        __import__(name)
        print("ok      ", name)
    except Exception:
        print("FAILED  ", name)
        traceback.print_exc()
PY
    )
    echo
    echo "== files =="
    ls -l /opt/webzapret/panel /opt/webzapret/scripts 2>&1 | head -50
    echo
    echo "== network (container view) =="
    ip -br addr 2>&1 | head -10
    echo
    echo "== environment (secrets masked) =="
    mask_env
    echo
    echo "== conntrack =="
    echo "/proc/net/nf_conntrack readable: $([ -r /proc/net/nf_conntrack ] && echo yes || echo NO)  acct=$(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null || echo n/a)"
    ls -l /proc/net/nf_conntrack /proc/net/ip_conntrack 2>&1 | head -3
    echo "conntrack tool: $(command -v conntrack || echo missing)"
    if command -v conntrack >/dev/null 2>&1; then
        echo "-- conntrack -L -p tcp -o extended | head -5  (netlink; rc shown)"
        conntrack -L -p tcp -o extended 2>&1 | head -5; echo "rc=${PIPESTATUS[0]}"
    fi
    echo "modules: $(grep -E '^(nf_conntrack|nfnetlink|nf_conntrack_netlink|xt_connbytes|nfnetlink_queue) ' /proc/modules 2>/dev/null | cut -d' ' -f1 | tr '\n' ' ')"
    for f in actions panel nfqws ss-server sockd tinyproxy blockcheck; do
        echo
        echo "== log: $f.log (first minute, newest 80 lines) =="
        if [ -s "$WZ_LOG/$f.log" ]; then tail -n 80 "$WZ_LOG/$f.log" | cut -c1-300; else echo "(empty or missing)"; fi
    done
} > "$REPORT" 2>&1

echo "==================== START-UP REPORT (first ${WINDOW}s) ===================="
cat "$REPORT"
echo "==================== END OF START-UP REPORT ===================="
