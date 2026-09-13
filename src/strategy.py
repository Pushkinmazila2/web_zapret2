"""Render strategy entries as native zapret2 command-line arguments."""
import json
import shlex
import sys


def native_options(text, protocol=""):
    args = shlex.split(text)
    if not any(a.startswith("--dpi-desync") for a in args):
        if args and protocol and not any(a.startswith("--filter-") for a in args):
            proto = protocol.upper()
            prefix = "--filter-udp=443" if "QUIC" in proto or "UDP" in proto else (
                "--filter-tcp=80" if proto.startswith("HTTP") and not proto.startswith("HTTPS") and "TLS" not in proto else "--filter-tcp=443")
            args.insert(0, prefix)
        return args
    if not args:
        return []
    # Keep old profiles usable while making the Lua engine the execution path.
    profiles = [[]]
    for arg in args:
        if arg == "--new":
            profiles.append([])
        else:
            profiles[-1].append(arg)
    result = []
    for profile in profiles:
        filters = [a for a in profile if not a.startswith("--dpi-desync")]
        if not filters:
            continue
        udp = any(a.startswith("--filter-udp=") for a in filters)
        http = "--filter-tcp=80" in filters
        payload, blob = ("quic_initial", "quic") if udp else (("http_req", "http") if http else ("tls_client_hello", "tls"))
        modes = []
        split_pos = "2"
        repeats = "1"
        fooling = []
        for arg in profile:
            key, _, value = arg.partition("=")
            if key == "--dpi-desync":
                modes.extend(value.split(","))
            elif key == "--dpi-desync-split-pos":
                split_pos = value
            elif key == "--dpi-desync-repeats":
                repeats = value
            elif key == "--dpi-desync-fooling":
                fooling = value.split(",")
            elif key.startswith("--dpi-desync"):
                raise ValueError("Unsupported legacy option: " + key)
        if result:
            result.append("--new")
        result.extend(filters + ["--payload=" + payload])
        for mode in modes:
            mode = {"split": "multisplit", "disorder": "multidisorder"}.get(mode, mode)
            if mode in {"fake", "fakedsplit"}:
                spec = [mode, "repeats=" + repeats]
                spec.append("blob=fake_default_" + blob if mode == "fake" else "pos=" + split_pos.split(",")[-1])
                if set(fooling) - {"md5sig", "badseq", "ts"}:
                    raise ValueError("Unsupported legacy fooling")
                if "md5sig" in fooling:
                    spec.append("tcp_md5")
                if "badseq" in fooling:
                    spec.extend(["tcp_seq=-10000", "tcp_ack=-66000"])
                if "ts" in fooling:
                    spec.append("tcp_ts=-600000")
                result.append("--lua-desync=" + ":".join(spec))
            elif mode in {"multisplit", "multidisorder"}:
                result.append("--lua-desync=%s:pos=%s" % (mode, split_pos))
            else:
                raise ValueError("Unsupported legacy mode: " + mode)
    return result


def strategy_args(entry):
    text = entry.get("lua_opt") or entry.get("nfqws_opt", "")
    args = native_options(text, entry.get("protocol", ""))
    for arg in args:
        if "\0" in arg or not arg.startswith("--") or arg.split("=", 1)[0] in {
            "--qnum", "--fwmark", "--daemon", "--pidfile", "--intercept", "--dry-run", "--version", "--chdir"}:
            raise ValueError("Invalid strategy argument: " + arg)
    scripts = entry.get("lua_init", [])
    if not isinstance(scripts, list) or not all(isinstance(s, str) and s.startswith("/") and "\0" not in s for s in scripts):
        raise ValueError("lua_init must be a list of absolute container file paths")
    return ["--lua-init=@" + s for s in scripts] + args


if __name__ == "__main__":
    with open("/opt/webzapret/config/strategies.json", encoding="utf-8") as f:
        entries = json.load(f)["strategies"]
    entry = next(s for s in entries if s["id"] == sys.argv[1])
    sys.stdout.buffer.write(b"\0".join(a.encode() for a in strategy_args(entry)) + b"\0")
