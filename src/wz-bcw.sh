#!/bin/bash
# =============================================================================
# wz-bcw.sh — "Strategy selection" harness (blockcheckw wrapper)
#
# Runs the blockcheckw pipeline (scan + check) for the panel's Strategy
# selection tab.  The engine itself is src/panel/blockcheck.py (pure Python);
# this wrapper only guards the privileged environment:
#
#   * single-flight lock (blockcheckw holds its own instance lock as well);
#   * preflight: binary, nft, the /opt/zapret2 layout blockcheckw expects and a
#     FREE NFQUEUE 200 — blockcheckw's base queue is a compile-time constant, so
#     the live gateway must own different queues (QNUM_TCP/QNUM_UDP = 210/211);
#   * embedded mode: the engine always passes --no-conflict-cleanup, so
#     blockcheckw never touches our nfqws2/nftables/iptables state;
#   * optional sysctl raise for high worker counts (net.netfilter.*);
#   * pidfile for the panel's Cancel button (SIGTERM the process group).
#
# Usage:
#   wz-bcw.sh --check                          local sanity checks (no scan)
#   wz-bcw.sh run <settings.json> <run_dir>    run one selection
#
# Prints a single JSON object on real stdout (fd3); everything else goes to
# /var/log/webzapret/blockcheck.log.  The engine also writes <run_dir>/result.json.
# =============================================================================
set -u
. /opt/webzapret/scripts/wz-common.sh

BCW_MODULE=/opt/webzapret/scripts/blockcheck.py
BCW_LOG="$WZ_LOG/blockcheck.log"
BCW_LOCK="$WZ_RUN/bcw.lock"
BCW_PIDFILE="$WZ_RUN/bcw.pid"
BCW_BIN="${BCW_BIN:-/opt/webzapret/bin/blockcheckw}"
BCW_ZAPRET_BASE="${BCW_ZAPRET_BASE:-/opt/zapret2}"
BCW_QUEUE="${BCW_QUEUE:-200}"
BCW_LOCK_WAIT="${WZ_LOCK_WAIT:-30}"

mkdir -p "$WZ_RUN" "$WZ_LOG"

# stdout hygiene — the FINAL JSON must be the ONLY thing on real stdout (fd3);
# all harness chatter goes to the dedicated log, like wz-test.sh does.
exec 3>&1

emit_err()
{
    python3 -c 'import json,sys; print(json.dumps({"ok": False, "error": sys.argv[1]}, ensure_ascii=False))' "$1" 1>&3
    exit 1
}

log()
{
    printf '[%s] [bcw] %s\n' "$(date -u +%FT%TZ)" "$*" >>"$BCW_LOG"
}

queue_busy()
{
    # exit 0 when the queue is bound by SOME process (procfs lists all queues)
    [ -r /proc/net/netfilter/nfnetlink_queue ] || return 1
    awk -v q="$1" '$1 == q { found=1 } END { exit !found }' \
        /proc/net/netfilter/nfnetlink_queue
}

raise_limits()
{
    # $1 settings.json — best-effort kernel headroom for high worker counts
    [ "$(python3 -c 'import json,sys;print(1 if json.load(open(sys.argv[1])).get("raise_limits") else 0)' "$1" 2>/dev/null)" = 1 ] || return 0
    local qmax cmax
    qmax=$(python3 -c 'import json,sys;print(int(json.load(open(sys.argv[1])).get("nf_queue_maxlen") or 0))' "$1" 2>/dev/null)
    cmax=$(python3 -c 'import json,sys;print(int(json.load(open(sys.argv[1])).get("nf_conntrack_max") or 0))' "$1" 2>/dev/null)
    [ -n "$qmax" ] && [ "$qmax" -gt 0 ] 2>/dev/null && \
        sysctl -w "net.netfilter.nf_queue_maxlen=$qmax" >>"$BCW_LOG" 2>&1 || true
    [ -n "$cmax" ] && [ "$cmax" -gt 0 ] 2>/dev/null && \
        sysctl -w "net.netfilter.nf_conntrack_max=$cmax" >>"$BCW_LOG" 2>&1 || true
}

# ---------------------------------------------------------------------------
# preflight — cheap, fail-fast checks; blockcheckw re-verifies the deep ones
# (nfqws2 --filter-mark, smoke start) itself and exits 6 with a clear message.
# ---------------------------------------------------------------------------
preflight()
{
    local ok=1
    {
        echo "== strategy selection preflight =="
        if [ -x "$BCW_BIN" ]; then
            echo "   ok: blockcheckw binary $BCW_BIN"
        else
            echo "   FAIL: blockcheckw binary missing/not executable: $BCW_BIN"; ok=0
        fi
        if command -v nft >/dev/null 2>&1; then
            echo "   ok: nft present"
        else
            echo "   FAIL: nft missing (apt install nftables)"; ok=0
        fi
        if [ -x "$BCW_ZAPRET_BASE/nfq2/nfqws2" ]; then
            echo "   ok: engine $BCW_ZAPRET_BASE/nfq2/nfqws2"
        else
            echo "   FAIL: $BCW_ZAPRET_BASE/nfq2/nfqws2 missing (image layout broken)"; ok=0
        fi
        for lua in zapret-lib.lua zapret-antidpi.lua; do
            if [ -r "$BCW_ZAPRET_BASE/lua/$lua" ]; then
                echo "   ok: $BCW_ZAPRET_BASE/lua/$lua"
            else
                echo "   FAIL: $BCW_ZAPRET_BASE/lua/$lua missing"; ok=0
            fi
        done
        if [ -r "$BCW_MODULE" ]; then
            echo "   ok: engine module $BCW_MODULE"
        else
            echo "   FAIL: $BCW_MODULE missing"; ok=0
        fi
        if queue_busy "$BCW_QUEUE"; then
            echo "   FAIL: NFQUEUE $BCW_QUEUE is already bound (see /proc/net/netfilter/nfnetlink_queue) —"
            echo "         the live gateway must use other queues: set QNUM_TCP=210 QNUM_UDP=211 in .env"
            ok=0
        else
            echo "   ok: NFQUEUE $BCW_QUEUE free for blockcheckw"
        fi
        echo "== preflight $([ "$ok" = 1 ] && echo OK || echo FAILED) =="
    }
    return $((1 - ok))
}

# ---------------------------------------------------------------------------
# --check : local sanity, no scan (used by smoke.sh / diagnostics)
# ---------------------------------------------------------------------------
if [ "${1:-}" = --check ]; then
    if preflight >>"$BCW_LOG" 2>&1; then
        echo "wz-bcw OK"
        exit 0
    fi
    echo "wz-bcw preflight failed — see $BCW_LOG" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# run <settings.json> <run_dir>
# ---------------------------------------------------------------------------
[ $# -ge 3 ] || { echo "usage: $0 {--check|run <settings.json> <run_dir>}" >&2; exit 2; }
[ "$1" = run ] || { echo "usage: $0 {--check|run <settings.json> <run_dir>}" >&2; exit 2; }
SETTINGS=$2
RUN_DIR=$3
[ -r "$SETTINGS" ] || emit_err "settings file not readable: $SETTINGS"

mkdir -p "$RUN_DIR"
echo $$ > "$BCW_PIDFILE"
trap 'rm -f "$BCW_PIDFILE"' EXIT
log "harness started (settings=$SETTINGS run_dir=$RUN_DIR)"

if PF=$(preflight 2>&1); then
    printf '%s\n' "$PF" >>"$BCW_LOG"
else
    printf '%s\n' "$PF" >>"$BCW_LOG"
    log "preflight failed"
    emit_err "strategy-selection preflight failed: $(printf '%s\n' "$PF" | grep FAIL | head -n 3 | tr '\n' ' ')"
fi

raise_limits "$SETTINGS"

RC=0
(
    if ! flock -w "$BCW_LOCK_WAIT" 9; then
        log "lock busy after ${BCW_LOCK_WAIT}s — another run in progress"
        exit 9
    fi
    python3 "$BCW_MODULE" run "$SETTINGS" "$RUN_DIR"
) >>"$BCW_LOG" 2>&1 9>"$BCW_LOCK" || RC=$?

log "harness finished rc=$RC"
RESULT="$RUN_DIR/result.json"
if [ -s "$RESULT" ]; then
    cat "$RESULT" 1>&3
    exit 0
fi
if [ "$RC" = 9 ]; then
    emit_err "another strategy-selection run is already in progress"
fi
emit_err "strategy-selection harness produced no result (rc=$RC) — see $BCW_LOG"