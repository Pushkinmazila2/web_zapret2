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

state_write()
{
    # $1 variable name, $2 value
    local tmp
    tmp=$(mktemp "$WZ_STATE/.$1.XXXXXX")
    printf '%s\n' "$2" > "$tmp"
    mv -f "$tmp" "$WZ_STATE/$1"
    chmod 0640 "$WZ_STATE/$1"
}

with_lock()
{
    # expose apply+restart loop atomic against concurrent panel requests
    (
        flock -x 9 || exit 1
        "$@"
    ) 9>"$WZ_APPLY_LOCK"
}

do_strategy()
{
    local id=$1 new
    valid_strategy_id "$id" || { echo "ERROR: unknown strategy '$id'" >&2; return 2; }
    new=$(cat "$WZ_STATE/strategy" 2>/dev/null || echo "")
    [ "$new" = "$id" ] && { echo "strategy '$id' already active"; return 0; }

    state_write strategy "$id"
    echo "applying strategy '$id', restarting nfqws..."
    /opt/webzapret/scripts/wz-svc.sh restart nfqws
    echo "nfqws restarted with strategy '$id'"
    [ "$(active_strategy)" = "$id" ] || return 3
    return 0
}

do_exit()
{
    local mode=$1
    valid_exit_mode "$mode" || { echo "ERROR: unknown exit mode '$mode' (direct|socks5|ss)" >&2; return 2; }
    if [ "$(active_exit_mode)" = "$mode" ]; then
        echo "exit mode '$mode' already active"
        return 0
    fi

    state_write exit_mode "$mode"
    echo "changing exit mode to '$mode'..."
    /opt/webzapret/scripts/wz-svc.sh render

    echo "restarting exit layer (brings utun up for the UDP relay)..."
    /opt/webzapret/scripts/wz-svc.sh restart redsocks || true
    /opt/webzapret/scripts/wz-svc.sh restart ss-local || true
    /opt/webzapret/scripts/wz-svc.sh restart udprelay || true

    echo "reloading firewall..."
    /opt/webzapret/scripts/wz-fw.sh start || { echo "ERROR: firewall apply failed" >&2; return 3; }

    echo "restarting nfqws with the new mode..."
    /opt/webzapret/scripts/wz-svc.sh restart nfqws
    echo "exit mode is now '$mode'"
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