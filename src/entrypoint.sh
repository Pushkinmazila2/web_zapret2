#!/bin/bash
# =============================================================================
# entrypoint.sh — web_zapret2 container entrypoint
#  1. seed persistent state (exit_mode, strategy) from env on first start
#  2. render service configs from templates
#  3. prepare kernel/networking (sysctls, /dev/net/tun)
#  4. start access + exit services (utun must exist first), then firewall,
#     then nfqws
#  5. start the web panel; keep the container alive; stop services on exit
# =============================================================================
set -u
. /opt/webzapret/scripts/wz-common.sh

mkdir -p "$WZ_RUN" "$WZ_LOG" "$WZ_STATE" "$WZ_CFG"
chown proxy:proxy "$WZ_LOG" "$WZ_RUN" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 1. persistent state: env seeds state on first boot, panel/apply mutate state
# ---------------------------------------------------------------------------
if [ ! -f "$WZ_STATE/exit_mode" ]; then
    printf '%s\n' "$EXIT_MODE" > "$WZ_STATE/exit_mode"
fi
if [ ! -f "$WZ_STATE/strategy" ]; then
    printf '%s\n' "$STRATEGY" > "$WZ_STATE/strategy"
fi
EXIT_MODE=$(cat "$WZ_STATE/exit_mode")
STRATEGY=$(cat "$WZ_STATE/strategy")

valid_exit_mode "$EXIT_MODE" || EXIT_MODE=direct
valid_strategy_id "$STRATEGY" || STRATEGY=none
printf '%s\n' "$EXIT_MODE" > "$WZ_STATE/exit_mode"
printf '%s\n' "$STRATEGY" > "$WZ_STATE/strategy"
compute_upstream

# ---------------------------------------------------------------------------
# 2. render configs (static templates -> /etc/webzapret)
# ---------------------------------------------------------------------------
cp /opt/webzapret/config/zapret.default "$WZ_CFG/zapret.default"
cp /opt/webzapret/config/strategies.json "$WZ_CFG/strategies.json"
/opt/webzapret/scripts/wz-svc.sh render

# ---------------------------------------------------------------------------
# 3. kernel / networking
# ---------------------------------------------------------------------------
# ip_forward may be forbidden on some LXC/VPS hosts; compose sets it via
# docker sysctls when permitted. Non-fatal here: on the host it is often
# already enabled.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || \
    wz_err "sysctl ip_forward denied (host restriction?) - upstream NAT may need it"
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
# tun device (ioctl TUNSETIFF handled by wz-udprelay; CAP set on the binary)
if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 4. services + firewall
#    order matters: the UDP relay must create utun0 BEFORE wz-fw.sh installs
#    the policy route that points into it; nfqws starts last.
# ---------------------------------------------------------------------------
/opt/webzapret/scripts/wz-svc.sh start ss-server || exit 1
/opt/webzapret/scripts/wz-svc.sh start sockd || exit 1
/opt/webzapret/scripts/wz-svc.sh start redsocks || true
/opt/webzapret/scripts/wz-svc.sh start ss-local || true
/opt/webzapret/scripts/wz-svc.sh start udprelay || true

/opt/webzapret/scripts/wz-fw.sh start || {
    wz_err "firewall could not be installed (NFQUEUE/netfilter unavailable?)"
    wz_err "verify: --cap-add NET_ADMIN NET_RAW, kernel nfnetlink loaded"
    exit 1
}

/opt/webzapret/scripts/wz-svc.sh start nfqws || {
    wz_err "nfqws failed to start; showing status:"
    /opt/webzapret/scripts/wz-svc.sh status
    exit 1
}

# ---------------------------------------------------------------------------
# 5. panel + keep-alive
# ---------------------------------------------------------------------------
python3 /opt/webzapret/panel/panel.py >>"$WZ_LOG/panel.log" 2>&1 &
PANEL_PID=$!
echo "$PANEL_PID" > "$(pidfile panel)"

cleanup()
{
    wz_log "shutting down..."
    kill "$PANEL_PID" 2>/dev/null || true
    /opt/webzapret/scripts/wz-svc.sh stop 2>/dev/null || true
    /opt/webzapret/scripts/wz-fw.sh stop 2>/dev/null || true
    exit 0
}
trap cleanup INT TERM EXIT

wz_log "web_zapret2 ready. exit_mode=$EXIT_MODE strategy=$STRATEGY"

# stream logs to stdout for docker logs; wait until container is stopped
tail -F "$WZ_LOG/nfqws.log" "$WZ_LOG/ss-server.log" "$WZ_LOG/sockd.log" \
    "$WZ_LOG/panel.log" /dev/null 2>/dev/null &
TAIL_PID=$!
while kill -0 "$TAIL_PID" 2>/dev/null || kill -0 "$PANEL_PID" 2>/dev/null; do
    sleep 2
done
wait