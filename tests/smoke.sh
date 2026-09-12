#!/bin/bash
# =============================================================================
# smoke.sh — Stage 1 runtime verification (run INSIDE the container)
#   docker compose exec gateway /opt/webzapret/tests/smoke.sh
#
# Checks:
#   1. core binaries exist                       (nfqws --version)
#   2. services up (ss-server, sockd, nfqws)     (pidfiles)
#   3. required listeners inside the container   (ss/nc)
#   4. firewall rules installed                  (WZFW chain, NOQUEUE)
#   5. panel API serving                         (GET /api/status)
#   6. strategy round-trip with restart          (POST /api/strategy)
# Exits non-zero on first failure.
# =============================================================================
set -u
FAIL=0
step() { echo "== $*"; }
ok()   { echo "   ok: $*"; }
bad()  { echo "   FAIL: $*" >&2; FAIL=1; }

step "1. binaries"
for b in /opt/webzapret/bin/nfqws /usr/bin/ss-server /usr/sbin/sockd \
         /usr/sbin/redsocks /usr/bin/ss-local /opt/webzapret/bin/wz-udprelay; do
    [ -x "$b" ] && ok "$b" || bad "missing executable $b"
done
/opt/webzapret/bin/nfqws --version >/dev/null 2>&1 && ok "nfqws --version" \
    || bad "nfqws --version failed"

step "2. services up"
for s in ss-server sockd nfqws; do
    if [ -f "/run/webzapret/$s.pid" ] && kill -0 "$(cat /run/webzapret/$s.pid)" 2>/dev/null; then
        ok "$s (pid $(cat /run/webzapret/$s.pid))"
    else
        bad "$s not running"
    fi
done

step "3. listeners (defaults: ss 8388, socks 1080, panel 8080)"
for port in 8388 1080; do
    if (command -v nc >/dev/null && nc -z 127.0.0.1 "$port"); then
        ok "listening on $port"
    elif [ "$(ss -lnt 2>/dev/null | awk -v p=":$port " '$4 ~ p' | wc -l)" -gt 0 ]; then
        ok "listening on $port (ss)"
    else
        bad "nothing listening on $port"
    fi
done

step "4. firewall"
iptables -t mangle -S WZFW >/dev/null 2>&1 && ok "WZFW chain present" \
    || bad "WZFW chain missing (wz-fw.sh start needed)"
iptables -t mangle -S WZFW 2>/dev/null | grep -q NFQUEUE && ok "NFQUEUE rules present" \
    || bad "no NFQUEUE rules in WZFW"

step "5. panel API"
S=$(curl -fsS --max-time 5 http://127.0.0.1:8080/api/status) || { bad "panel unreachable"; S=""; }
if [ -n "$S" ]; then
    echo "$S" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["exit_mode"] in ("direct","socks5","ss"); assert d["strategy"]["id"]' \
        && ok "status JSON well-formed (exit_mode=$(echo "$S" | python3 -c 'import json,sys;print(json.load(sys.stdin)["exit_mode"])'))" \
        || bad "status JSON invalid"
fi

step "6. strategy round-trip"
BEFORE=$(cat /opt/webzapret/state/strategy 2>/dev/null)
BEFORE_PID=$(cat /run/webzapret/nfqws.pid 2>/dev/null)
R=$(curl -fsS --max-time 60 -X POST http://127.0.0.1:8080/api/strategy \
      -H 'Content-Type: application/json' -d '{"id":"split"}' 2>/dev/null)
echo "$R" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok")' \
    && ok "POST /api/strategy split ok" || bad "strategy switch failed: $(echo "$R" | head -c 300)"
sleep 1
AFTER=$(cat /opt/webzapret/state/strategy 2>/dev/null)
AFTER_PID=$(cat /run/webzapret/nfqws.pid 2>/dev/null)
[ "$AFTER" = "split" ] && [ "$BEFORE_PID" != "$AFTER_PID" ] && ok "strategy persisted + nfqws restarted (pid $BEFORE_PID -> $AFTER_PID)" \
    || bad "strategy state or restart check failed (before=$BEFORE after=$AFTER)"

# restore
curl -fsS --max-time 60 -X POST http://127.0.0.1:8080/api/strategy \
      -H 'Content-Type: application/json' -d "{\"id\":\"$BEFORE\"}" >/dev/null 2>&1 && \
    ok "restored strategy '$BEFORE'" || bad "could not restore strategy '$BEFORE'"

echo
[ "$FAIL" = 0 ] && echo "SMOKE OK" || { echo "SMOKE FAILED"; exit 1; }