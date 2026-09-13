#!/bin/bash
# =============================================================================
# wz-apply.sh — apply a strategy or exit-mode change with a zapret2 restart
#   wz-apply.sh strategy <id>     - persist + restart nfqws with new options
#   wz-apply.sh exit <mode>       - persist + reload firewall + restart exit layer
#                                   (direct|socks5|ss)
#   wz-apply.sh status            - dump current effective config
#
# Atomic state writes: write to a temp file, then rename into place.
# =============================================================================
set -uo pipefail
. /opt/webzapret/scripts/wz-common.sh

WZ_APPLY_LOCK="${WZ_RUN}/wz-apply.lock"
WZ_LOCK_WAIT="${WZ_LOCK_WAIT:-30}"

state_write()
{
    # $1 variable name, $2 value
    local tmp
    tmp=$(mktemp "$WZ_STATE/.$1.XXXXXX")
    printf '%s\n' "$2" > "$tmp"
    mv -f "$tmp" "$WZ_STATE/$1"
    chmod 0640 "$WZ_STATE/$1"
    log_module apply "state updated: $1=$2"
}

with_lock()
{
    # serialize apply/restart loops against concurrent panel requests.
    # A timeout prevents permanent wedging if another process stalls.
    # Child processes spawned during apply (services) MUST have fd 9 closed
    # so they do not inherit the lock and hold it forever.
    (
        if ! flock -w "$WZ_LOCK_WAIT" 9; then
            log_err apply "apply lock busy after ${WZ_LOCK_WAIT}s — another operation in progress? aborting"
            exit 1
        fi
        log_module apply "lock acquired: $*"
        "$@"
    ) 9>"$WZ_APPLY_LOCK"
}

do_strategy()
{
    local id=$1 new
    valid_strategy_id "$id" || { log_err apply "unknown strategy '$id'"; return 2; }
    new=$(cat "$WZ_STATE/strategy" 2>/dev/null || echo "")
    if [ "$new" = "$id" ]; then
        log_module apply "strategy '$id' already active — no restart needed"
        return 0
    fi

    log_module apply "switching strategy '$new' -> '$id'"
    state_write strategy "$id"
    log_module apply "restarting nfqws..."
    /opt/webzapret/scripts/wz-svc.sh restart nfqws
    if [ "$(active_strategy)" = "$id" ]; then
        log_module apply "nfqws restarted with strategy '$id'"
        return 0
    fi
    log_err apply "failed to activate strategy '$id'"
    return 3
}

do_exit()
{
    local mode=$1
    valid_exit_mode "$mode" || { log_err apply "unknown exit mode '$mode' (direct|socks5|ss)"; return 2; }
    if [ "$(active_exit_mode)" = "$mode" ]; then
        log_module apply "exit mode '$mode' already active"
        return 0
    fi

    log_module apply "changing exit mode to '$mode'..."
    state_write exit_mode "$mode"
    /opt/webzapret/scripts/wz-svc.sh render

    log_module apply "restarting exit layer (brings utun up for the UDP relay)..."
    /opt/webzapret/scripts/wz-svc.sh restart redsocks || true
    /opt/webzapret/scripts/wz-svc.sh restart ss-local || true
    /opt/webzapret/scripts/wz-svc.sh restart udprelay || true

    # Accumulate counters into state files before firewall reload (which resets them)
    accumulate_traffic_counters

    log_module apply "reloading firewall..."
    /opt/webzapret/scripts/wz-fw.sh start || { log_err apply "firewall apply failed"; return 3; }

    log_module apply "restarting nfqws with the new mode..."
    /opt/webzapret/scripts/wz-svc.sh restart nfqws
    log_module apply "exit mode is now '$mode'"
    return 0
}

do_status()
{
    EXIT_MODE=$(active_exit_mode)
    compute_upstream
    echo "exit_mode=$EXIT_MODE"
    echo "strategy=$(active_strategy)"
    echo "udp_proxy=$UDP_PROXY"
    echo "nfqws_tcp_ports=$NFQ_TCP_PORTS nfqws_udp_ports=$NFQ_UDP_PORTS"
    echo "upstream_tcp=$UP_TCP_PORT upstream_udp=$UP_UDP_PORT"
    /opt/webzapret/scripts/wz-svc.sh status
}

case "${1:-}" in
    strategy)
        [ $# -ge 2 ] || { echo "usage: $0 strategy <id>" >&2; exit 1; }
        with_lock do_strategy "$2"
        ;;
    exit)
        [ $# -ge 2 ] || { echo "usage: $0 exit <direct|socks5|ss>" >&2; exit 1; }
        with_lock do_exit "$2"
        ;;
    status)
        do_status
        ;;
    *)
        echo "usage: $0 {strategy <id>|exit <mode>|status}" >&2
        exit 1
        ;;
esac
exit $?