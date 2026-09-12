start_one()
{
    local fn
    case "$1" in
        ss-server) fn=start_ss_server ;;
        ss-local)  fn=start_ss_local ;;
        sockd|nfqws|redsocks|udprelay) fn=start_$1 ;;
        *) echo "unknown service '$1'" >&2; return 2 ;;
    esac
    echo "dispatch $1 -> $fn"
}
for s in ss-server ss-local sockd nfqws redsocks udprelay bogus; do
    start_one "$s" || echo "rc=$? for $s"
done
