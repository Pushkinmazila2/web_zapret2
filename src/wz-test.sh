#!/bin/bash
# =============================================================================
# wz-test.sh — test a zapret2 (nfqws) strategy against a real URL with yt-dlp
#
# The strategy is applied on a SEPARATE nfqws process bound to its own NFQUEUE
# queue ($QNUM_TEST), so the LIVE nfqws and the active gateway strategy are
# never touched — real clients keep their service while the test runs.
#
# Test traffic comes only from the dedicated "testuser" uid (the yt-dlp probe)
# and is diverted to the test queue by a temporary WZTEST chain inserted at the
# top of mangle/OUTPUT, BEFORE the live WZFW jump.
#
# Usage:
#   wz-test.sh --check                          local sanity checks (no network)
#   wz-test.sh <strategy-id> [url] [timeout]    run one test
#
# Prints a single JSON object to stdout:
#   {ok, success, strategy, url, timeout, started_at, finished_at, took_s,
#    rc, reason, bytes, files[], log}
#   ok=true     the harness ran; success tells pass/fail
#   ok=false    operational error (error field has details)
#
# The video file downloaded by yt-dlp is ALWAYS deleted when the test ends.
# =============================================================================
set -u
. /opt/webzapret/scripts/wz-common.sh

TEST_DIR="$WZ_RUN/test"
TEST_LOG="$WZ_LOG/test.log"
TEST_NFQ_LOG="$WZ_LOG/test-nfqws.log"
TEST_PIDFILE="$WZ_RUN/test-nfqws.pid"
TEST_LOCK="$WZ_RUN/test.lock"
TEST_CHAIN="WZTEST"
TEST_UID=$(id -u testuser 2>/dev/null || echo 2003)

mkdir -p "$WZ_RUN" "$WZ_LOG"

emit_err()
{
    # prints {"ok": false, "error": ...} and exits 1
    python3 -c 'import json,sys; print(json.dumps({"ok": False, "error": sys.argv[1]}, ensure_ascii=False))' "$1"
    exit 1
}

# ---------------------------------------------------------------------------
# --check : local sanity checks, no network (used by smoke.sh / diagnostics)
# ---------------------------------------------------------------------------
if [ "${1:-}" = --check ]; then
    local_ok=1
    [ -x "$TEST_YTDLP_BIN" ] || { echo "FAIL: yt-dlp binary missing ($TEST_YTDLP_BIN)"; local_ok=0; }
    [ -x "$WZ_BIN/nfqws2" ]   || { echo "FAIL: nfqws2 binary missing ($WZ_BIN/nfqws2)"; local_ok=0; }
    id testuser >/dev/null 2>&1 || { echo "FAIL: 'testuser' uid missing"; local_ok=0; }
    command -v runuser >/dev/null 2>&1 || { echo "FAIL: runuser (util-linux) missing"; local_ok=0; }
    command -v timeout >/dev/null 2>&1 || { echo "FAIL: timeout (coreutils) missing"; local_ok=0; }
    command -v flock  >/dev/null 2>&1 || { echo "FAIL: flock (util-linux) missing"; local_ok=0; }
    [ "$local_ok" = 1 ] && { echo "wz-test OK"; exit 0; }
    exit 1
fi
[ $# -ge 1 ] || { echo "usage: $0 <strategy-id> [url] [timeout] | --check" >&2; exit 2; }
SID=$1
URL=${2:-$TEST_YTDLP_URL}
TIMEOUT=${3:-$TEST_YTDLP_TIMEOUT}

# sanitize the wall-clock timeout (>=10s, <=600s, numeric)
case "$TIMEOUT" in
    ''|*[!0-9]*) TIMEOUT=$TEST_YTDLP_TIMEOUT ;;
esac
{ [ "$TIMEOUT" -ge 10 ] && [ "$TIMEOUT" -le 600 ]; } 2>/dev/null || TIMEOUT=$TEST_YTDLP_TIMEOUT

[ -x "$TEST_YTDLP_BIN" ] || emit_err "yt-dlp is not installed ($TEST_YTDLP_BIN)"
case "$URL" in
    http://*|https://*) ;;
    *) emit_err "test URL must start with http:// or https://" ;;
esac
valid_strategy_id "$SID" || emit_err "unknown strategy '$SID'"

STARTED=$(date -u +%FT%TZ)

# ---------------------------------------------------------------------------
# one test at a time (flock on a dedicated lock; released on process exit)
# ---------------------------------------------------------------------------
exec 9>"$TEST_LOCK"
flock -n 9 || emit_err "another strategy test is already running (lock $TEST_LOCK)"

# ---------------------------------------------------------------------------
# idempotent teardown — iptables chain, test nfqws, downloaded files
# ---------------------------------------------------------------------------
cleanup_all()
{
    $IPT -t mangle -D OUTPUT -j "$TEST_CHAIN" 2>/dev/null || true
    $IPT -t mangle -F "$TEST_CHAIN" 2>/dev/null || true
    $IPT -t mangle -X "$TEST_CHAIN" 2>/dev/null || true
    local p
    p=$(cat "$TEST_PIDFILE" 2>/dev/null || true)
    if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
        log_module test "stopping test nfqws (pid $p)"
        kill "$p" 2>/dev/null || true
        for i in 1 2 3 4 5; do
            kill -0 "$p" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$p" 2>/dev/null || true
    fi
    rm -f "$TEST_PIDFILE"
    # delete the downloaded test video + scratch dir (always, success or not)
    rm -rf "$TEST_DIR"
}
trap cleanup_all EXIT
cleanup_all   # remove leftovers from a crashed earlier run

# ---------------------------------------------------------------------------
# setup: isolated test nfqws on its own queue (strategy 'none' = baseline probe)
# ---------------------------------------------------------------------------
setup_test_nfqws()
{
    [ "$SID" = none ] && {
        log_module test "strategy 'none': running baseline probe WITHOUT nfqws"
        : > "$TEST_NFQ_LOG"
        return 0
    }
    local argfile args=()
    argfile=$(mktemp "$WZ_RUN/test-args.XXXXXX") || return 1
    if ! python3 "$WZ_SRC/scripts/strategy.py" "$SID" > "$argfile"; then
        rm -f "$argfile"
        log_err test "strategy.py failed to render strategy '$SID'"
        return 1
    fi
    mapfile -d '' -t args < "$argfile"
    rm -f "$argfile"
    log_module test "starting isolated nfqws (queue $QNUM_TEST) for strategy '$SID'"
    setsid "$WZ_BIN/nfqws2" "--qnum=$QNUM_TEST" "--fwmark=$DESYNC_MARK" --debug=1 \
        "--lua-init=@$WZ_SRC/lua/zapret-lib.lua" \
        "--lua-init=@$WZ_SRC/lua/zapret-antidpi.lua" \
        "--lua-init=@$WZ_SRC/lua/zapret-auto.lua" \
        "${args[@]}" 9>&- >>"$TEST_NFQ_LOG" 2>&1 &
    local p=$!
    echo "$p" > "$TEST_PIDFILE"
    sleep 0.6
    if ! kill -0 "$p" 2>/dev/null; then
        log_err test "test nfqws died instantly; tail of test-nfqws.log:"
        tail -n 15 "$TEST_NFQ_LOG" 2>/dev/null | sed 's/^/    /' >&2
        rm -f "$TEST_PIDFILE"
        return 1
    fi
    log_module test "test nfqws started (pid $p)"
    return 0
}
# temporary chain: divert ONLY testuser traffic to the test queue, before the
# live WZFW jump, and never re-queue nfqws re-injected packets (DESYNC_MARK).
install_rules()
{
    $IPT -t mangle -N "$TEST_CHAIN" 2>/dev/null || $IPT -t mangle -F "$TEST_CHAIN"
    $IPT -t mangle -A "$TEST_CHAIN" -m mark --mark "$DESYNC_MARK/$DESYNC_MARK" -j RETURN
    $IPT -t mangle -A "$TEST_CHAIN" -o lo -j RETURN
    if [ "$SID" != none ]; then
        $IPT -t mangle -A "$TEST_CHAIN" -p tcp -m owner --uid-owner "$TEST_UID" \
            -m multiport --dports "$NFQ_TCP_PORTS" \
            -j NFQUEUE --queue-num "$QNUM_TEST" --queue-bypass
        $IPT -t mangle -A "$TEST_CHAIN" -p udp -m owner --uid-owner "$TEST_UID" \
            -m multiport --dports "$NFQ_UDP_PORTS" \
            -j NFQUEUE --queue-num "$QNUM_TEST" --queue-bypass
    fi
    # the jump MUST sit above the live "-j WZFW" while the test runs
    $IPT -t mangle -I OUTPUT 1 -j "$TEST_CHAIN"
}

# yt-dlp probe as 'testuser' with a hard wall-clock timeout.
# Format selection is retried so a probe can never fail merely because one
# `--format` selector is unavailable on the target video:
#   $TEST_YTDLP_FORMAT (360p merged / composite / worst)
#   -> "worst" single   -> audio-only (small, merge-free)   -> yt-dlp default
# A connection that completes a non-empty download means the strategy works.
run_ytdlp()
{
    local out="$TEST_DIR/out" rc f now left
    local attempts=("$TEST_YTDLP_FORMAT" "worst" "ba[ext=m4a]/ba" "")
    local deadline=$(( $(date +%s) + TIMEOUT ))   # shared wall-clock budget
    mkdir -p "$out"
    chown "$TEST_UID" "$TEST_DIR" "$out" 2>/dev/null || true
    log_module test "yt-dlp probe: strategy='$SID' url='$URL' timeout=${TIMEOUT}s (shared across attempts)"
    rc=2
    for f in "${attempts[@]}"; do
        now=$(date +%s)
        left=$(( deadline - now ))
        [ "$left" -le 5 ] && { log_module test "yt-dlp deadline reached, stopping"; break; }
        log_module test "yt-dlp attempt: format='${f:-<default>}' budget=${left}s"
        runuser -u testuser -- env HOME="$out" XDG_CACHE_HOME="$TEST_DIR/cache" \
            timeout --kill-after=10 -s TERM "$left" "$TEST_YTDLP_BIN" \
            --no-warnings --no-playlist --no-part --no-mtime --no-cache-dir \
            --no-write-info-json --no-progress \
            ${f:+--format "$f"} \
            --socket-timeout 20 \
            --retries 1 --fragment-retries 1 \
            --max-filesize "$TEST_YTDLP_MAX_FILESIZE" \
            --output "$out/%(id)s.%(ext)s" \
            --paths "$out" \
            "$URL" >>"$TEST_LOG" 2>&1
        rc=$?
        # a real timeout is final — do not burn the remaining budget on retries
        [ "$rc" = 124 ] && break
        # download may have completed media despite a nonzero rc (edge cases)
        if [ "$rc" -ne 0 ] && find "$out" -type f -size +0c 2>/dev/null | grep -q .; then
            rc=0
        fi
        [ "$rc" = 0 ] && break
    done
    log_module test "yt-dlp finished rc=$rc"
    return $rc
}

# gather downloaded payload (sizes) BEFORE the EXIT trap deletes the files
collect_files()
{
    local f size total=0 names=()
    while IFS= read -r -d '' f; do
        size=$(stat -c %s "$f" 2>/dev/null || echo 0)
        total=$((total + size))
        names+=("$(basename "$f")")
    done < <(find "$TEST_DIR/out" -type f -size +0c -print0 2>/dev/null)
    TEST_BYTES=$total
    TEST_FILES_CSV=$(IFS=,; echo "${names[*]}")
}

emit_result()
{
    local success=$1 reason=$2 rc=$3 logtail_file=$4 finished
    finished=$(date -u +%FT%TZ)
    # NOTE: no heredoc here — a CRLF-checked-out script would break the
    # terminator; -c receives the program as an argument instead.
    python3 -c '
import json, sys
from datetime import datetime

sid, url, timeout, started, finished, success, reason, rc, byt, files, logfile = sys.argv[1:]

def ts(x):
    try:
        return datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None

took = None
s, f = ts(started), ts(finished)
if s and f:
    took = round((f - s).total_seconds(), 1)

# the yt-dlp log tail may contain arbitrary bytes; read it with replace so a
# broken sequence can never break the JSON we emit
log = "(no log)"
try:
    with open(logfile, "r", encoding="utf-8", errors="replace") as fh:
        log = fh.read()
except Exception:
    log = "(log read error)"

try:
    byt = int(byt)
except Exception:
    byt = 0
try:
    rcc = int(rc)
except Exception:
    rcc = None
files = [x for x in files.split(",") if x] if files else []

out = {
    "ok": True,
    "success": success == "true",
    "strategy": sid,
    "url": url,
    "timeout": int(timeout),
    "started_at": started,
    "finished_at": finished,
    "took_s": took,
    "rc": rcc,
    "reason": reason,
    "bytes": byt,
    "files": files,
    "log": log,
}
print(json.dumps(out, ensure_ascii=True))
' "$SID" "$URL" "$TIMEOUT" "$STARTED" "$finished" "$success" "$reason" "$rc" \
    "$TEST_BYTES" "$TEST_FILES_CSV" "$logtail_file"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if ! setup_test_nfqws; then
    log_err test "could not start the isolated test nfqws"
    emit_err "failed to start the isolated test nfqws for strategy '$SID'"
fi

install_rules || { log_err test "could not install test firewall rules"; emit_err "failed to install test firewall rules"; }

run_ytdlp
RC=$?

TEST_BYTES=0
TEST_FILES_CSV=""
collect_files

if [ "$RC" = 124 ]; then
    SUCCESS=false
    REASON="timeout after ${TIMEOUT}s — no reliable download in time"
elif [ "$RC" -ne 0 ]; then
    SUCCESS=false
    REASON="yt-dlp failed (rc=$RC) — strategy did not produce a working stream"
elif [ "$TEST_BYTES" -gt 0 ]; then
    SUCCESS=true
    REASON="download completed (${TEST_BYTES} bytes)"
else
    SUCCESS=false
    REASON="yt-dlp exited 0 but produced no output file"
fi

LOGTAIL_FILE="$TEST_DIR/logtail.tmp"
tail -n 40 "$TEST_LOG" 2>/dev/null | head -c 6000 > "$LOGTAIL_FILE" 2>/dev/null || true
emit_result "$SUCCESS" "$REASON" "$RC" "$LOGTAIL_FILE"
exit 0