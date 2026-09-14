#!/bin/bash
# =============================================================================
# wz-svc.sh — web_zapret2 service supervisor
#   start|stop|restart|status [service]     (all services by default)
#   render                                   (render configs from templates)
#   nfqws: gets desync options from the active strategy (state file)
# =============================================================================
set -u
. /opt/webzapret/scripts/wz-common.sh

# Never let child services inherit the apply lock (fd 9). If nfqws or another
# daemon holds fd 9 open, subsequent strategy switches hang permanently on flock.
exec 9>&- 2>/dev/null || true

# effective exit mode comes from state, not env — recompute upstream endpoints
EXIT_MODE=$(active_exit_mode)
compute_upstream

SERVICES="ss-server sockd nfqws redsocks ss-local udprelay"

# ---------------------------------------------------------------------------
# config rendering (templates live in /opt/webzapret/config)
# ---------------------------------------------------------------------------
render_ss_server_json()
{
    python3 - "$SS_LISTEN_PORT" "$SS_PASSWORD" "$SS_METHOD" <<'PY'
import json, sys
conf = {
    "server": "0.0.0.0",
    "server_port": int(sys.argv[1]),
    "password": sys.argv[2],
    "method": sys.argv[3],
    "mode": "tcp_and_udp",
    "timeout": 300,
    "fast_open": False,
    "workers": 2,
}
json.dump(conf, sys.stdout, indent=2)
print()
PY
}

render_ss_local_json()
{
    # $1 - upstream host (resolve to IP at render time), $2 - port, $3 - pwd, $4 - method
    python3 - "$1" "$2" "$3" "$4" "$SS_LOCAL_PORT" <<'PY'
import json, sys
conf = {
    "server": sys.argv[1],
    "server_port": int(sys.argv[2]),
    "password": sys.argv[3],
    "method": sys.argv[4],
    "mode": "tcp_and_udp",
    "timeout": 60,
    "local_address": "127.0.0.1",
    "local_port": int(sys.argv[5]),
    "fast_open": False,
}
json.dump(conf, sys.stdout, indent=2)
print()
PY
}

render_sockd_conf()
{
    sed -e "s/__SOCKS5_PORT__/$SOCKS5_LISTEN_PORT/g" \
        -e "s/__WAN_IFACE__/$WAN_IFACE/g" \
        /opt/webzapret/config/sockd.conf
}

render_redsocks_conf()
{
    # $1 - upstream ip, $2 - upstream port, $3 - user, $4 - password
    cat <<EOF
base {
    log_debug = off;
    log_info = on;
    daemon = off;
    redirector = iptables;
    user = "exituser";
}
redsocks {
    local_ip = 127.0.0.1;
    local_port = $REDSOCKS_PORT;
    type = socks5;
    ip = $1;
    port = $2;
    login = "$3";
    password = "$4";
}
EOF
}

render_all()
{
    mkdir -p "$WZ_CFG"
    EXIT_MODE=$(active_exit_mode)   # upstream endpoints follow the effective mode
    compute_upstream
    log_module svc "rendering configs to $WZ_CFG (exit_mode=$EXIT_MODE)"
    render_ss_server_json > "$WZ_CFG/ss-server.json"
    render_sockd_conf > "$WZ_CFG/sockd.conf"

    # upstream configs (only meaningful in upstream modes)
    case "$(active_exit_mode)" in
        socks5)
            local ip pwd user
            if [ -n "$UPSTREAM_SOCKS5_HOST" ]; then
                ip=$(getent ahostsv4 "$UPSTREAM_SOCKS5_HOST" | awk 'NR==1{print $1}') || true
                [ -n "$ip" ] || ip=$UPSTREAM_SOCKS5_HOST
            else
                ip=127.0.0.1
            fi
            pwd=${UPSTREAM_SOCKS5_PASSWORD}
            user=${UPSTREAM_SOCKS5_USER}
            render_redsocks_conf "$ip" "$UP_TCP_PORT" "$user" "$pwd" > "$WZ_CFG/redsocks.conf"
            ;;
        ss)
            local ip
            if [ -n "$UPSTREAM_SS_HOST" ]; then
                ip=$(getent ahostsv4 "$UPSTREAM_SS_HOST" | awk 'NR==1{print $1}') || true
                [ -n "$ip" ] || ip=$UPSTREAM_SS_HOST
            else
                ip=127.0.0.1
            fi
            render_ss_local_json "$ip" "$UP_TCP_PORT" "$UPSTREAM_SS_PASSWORD" "$UPSTREAM_SS_METHOD" \
                > "$WZ_CFG/ss-local.json"
            render_redsocks_conf 127.0.0.1 "$SS_LOCAL_PORT" "" "" > "$WZ_CFG/redsocks.conf"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# pidfile based spawn/stop
# ---------------------------------------------------------------------------
spawn_svc()
{
    # $1 name, $2 user ("" = root), $3.. cmdline
    local name=$1 user=$2 p
    shift 2
    log_module "$name" "starting: $*"
    stop_svc "$name"
    if [ -z "$user" ] || [ "$user" = root ]; then
        setsid "$@" 9>&- >>"$WZ_LOG/$name.log" 2>&1 &
    else
        setsid setpriv --reuid="$user" --regid="$user" --init-groups "$@" \
            9>&- >>"$WZ_LOG/$name.log" 2>&1 &
    fi
    p=$!
    echo "$p" > "$(pidfile "$name")"
    sleep 0.3
    if ! pid_alive "$p"; then
        log_err "$name" "failed to start; tail of $name.log:"
        tail -n 20 "$WZ_LOG/$name.log" 2>/dev/null | sed 's/^/    /'
        rm -f "$(pidfile "$name")"
        return 1
    fi
    log_module "$name" "started (pid $p)"
    return 0
}

stop_svc()
{
    local name=$1 p i
    p=$(pid_read "$name")
    if pid_alive "$p"; then
        log_module "$name" "stopping (pid $p)"
        kill "$p" 2>/dev/null
        for i in 1 2 3 4 5; do
            pid_alive "$p" || break
            sleep 0.2
        done
        if pid_alive "$p"; then
            log_module "$name" "escalating to SIGKILL (pid $p)"
            kill -9 "$p" 2>/dev/null
        fi
        log_module "$name" "stopped"
    fi
    rm -f "$(pidfile "$name")"
}

# ---------------------------------------------------------------------------
# per-service start commands
# ---------------------------------------------------------------------------
start_ss_server()
{
    render_ss_server_json > "$WZ_CFG/ss-server.json"
    # -v: connection-level logging (accept/close + client endpoint) to ss-server.log
    spawn_svc ss-server proxy /usr/bin/ss-server -c "$WZ_CFG/ss-server.json" -v
}
start_sockd()
{
    # resolve the dante binary (name/path differs across distros: sockd/danted)
    local bin
    if [ -n "${SOCKD_BIN:-}" ] && [ -x "$SOCKD_BIN" ]; then
        bin=$SOCKD_BIN
    else
        bin=$(command -v sockd 2>/dev/null || command -v danted 2>/dev/null || true)
        [ -n "$bin" ] || for c in /usr/sbin/sockd /usr/bin/sockd /usr/sbin/danted; do
            [ -x "$c" ] && { bin=$c; break; }
        done
    fi
    if [ -z "$bin" ]; then
        log_err sockd "dante (sockd) binary not found — is the dante-server package installed?"
        return 1
    fi
    log_module sockd "using binary: $bin"

    # Полностью очищаем старые системные конфиги и ссылки во избежание коллизий
    rm -f /etc/sockd.conf

    # Вызываем встроенный генератор проекта и пишем результат прямо в системный путь
    render_sockd_conf > /etc/sockd.conf

    # Запускаем Dante с явным указанием конфигурационного файла
    spawn_svc sockd "" "$bin" -f /etc/sockd.conf
}



start_redsocks()
{
    [ "$(active_exit_mode)" = direct ] && return 0
    [ -f "$WZ_CFG/redsocks.conf" ] || render_all
    spawn_svc redsocks "" /usr/sbin/redsocks -c "$WZ_CFG/redsocks.conf"
}

start_ss_local()
{
    [ "$(active_exit_mode)" = ss ] || return 0
    [ -f "$WZ_CFG/ss-local.json" ] || render_all
    # -v: connection-level logging (each upstream tunnel) to ss-local.log
    spawn_svc ss-local exituser /usr/bin/ss-local -c "$WZ_CFG/ss-local.json" -u -v
}

start_udprelay()
{
    [ "$(active_exit_mode)" = direct ] && return 0
    [ "$UDP_PROXY" = relay ] || return 0
    local args=(--tun "$UTUN" --socks-host "$UP_TR_HOST" --socks-port "$UP_TR_PORT" --verbose)
    [ -n "${UPSTREAM_SOCKS5_USER:-}" ] && args+=(--socks-user "$UPSTREAM_SOCKS5_USER")
    [ -n "${UPSTREAM_SOCKS5_PASSWORD:-}" ] && args+=(--socks-password "$UPSTREAM_SOCKS5_PASSWORD")
    spawn_svc udprelay exituser /opt/webzapret/bin/wz-udprelay "${args[@]}"
}

start_nfqws()
{
    local sid argfile
    local args=()
    sid=$(active_strategy)
    log_module nfqws "resolved strategy: '$sid'"
    if ! valid_strategy_id "$sid"; then
        log_err nfqws "strategy '$sid' not found in strategies.json; falling back to 'none'"
        sid=none
        echo "$sid" > "$WZ_STATE/strategy"
    fi
    if [ "$sid" = none ]; then
        log_module nfqws "strategy '$sid' disables nfqws — keeping stopped"
        stop_svc nfqws
        return 0
    fi
    argfile=$(mktemp "$WZ_RUN/strategy.XXXXXX") || return 1
    python3 "$WZ_SRC/scripts/strategy.py" "$sid" > "$argfile" || { rm -f "$argfile"; return 1; }
    mapfile -d '' -t args < "$argfile"
    rm -f "$argfile"
    # --debug=1: connection-level nfqws logging (per-flow acks to nfqws.log)
    local base=("--qnum=$QNUM_TCP" "--fwmark=$DESYNC_MARK" --debug=1
        "--lua-init=@$WZ_SRC/lua/zapret-lib.lua"
        "--lua-init=@$WZ_SRC/lua/zapret-antidpi.lua"
        "--lua-init=@$WZ_SRC/lua/zapret-auto.lua")
    log_module nfqws "nfqws2 options: ${args[*]}"
    spawn_svc nfqws "" "$WZ_BIN/nfqws2" "${base[@]}" "${args[@]}"
}

# ---------------------------------------------------------------------------
# actions
# ---------------------------------------------------------------------------
svc_status()
{
    local s p
    printf '%-12s %-8s %s\n' SERVICE RUNNING PID
    for s in $SERVICES; do
        p=$(pid_read "$s")
        if pid_alive "$p"; then
            printf '%-12s yes      %s\n' "$s" "$p"
        else
            printf '%-12s no\n' "$s"
        fi
    done
}

# dispatcher: service names contain '-', bash function names cannot
start_one()
{
    local fn
    case "$1" in
        ss-server) fn=start_ss_server ;;
        ss-local)  fn=start_ss_local ;;
        sockd|nfqws|redsocks|udprelay) fn=start_$1 ;;
        *) log_err svc "unknown service '$1'"; return 2 ;;
    esac
    $fn
}

cmd_start()
{
    log_module svc "starting all services"
    local s
    for s in ss-server sockd; do start_one "$s"; done
    # exit layer + nfqws
    for s in redsocks ss-local udprelay nfqws; do start_one "$s"; done
}

cmd_stop()
{
    log_module svc "stopping all services"
    local s
    for s in nfqws udprelay ss-local redsocks sockd ss-server; do stop_svc "$s"; done
}

cmd_status()
{
    svc_status
}

case "${1:-}" in
    start)  shift && { [ $# -gt 0 ] && start_one "$1" || cmd_start; } ;;
    stop)   shift && { [ $# -gt 0 ] && stop_svc "$1" || cmd_stop; } ;;
    restart) shift; if [ $# -gt 0 ]; then stop_svc "$1"; start_one "$1"; else cmd_stop; cmd_start; fi ;;
    status) cmd_status ;;
    render) render_all ;;
    *)
        echo "usage: $0 {start|stop|restart|status|render} [service]" >&2
        echo "services: $SERVICES" >&2
        exit 1
        ;;
esac
