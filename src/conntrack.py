"""/proc/net/nf_conntrack -> what the NETWORK side of each TCP connection did.

nfqws only logs outbound packets, so the server's side of the story (did it
answer, how much came back, was the connection reset) has to come from the
kernel connection tracker. This module parses /proc/net/nf_conntrack on a
timer and keeps, per egress tuple (sport, dst ip, dst port):

  * the TCP state timeline  (SYN_SENT -> ESTABLISHED -> CLOSE ...),
  * reply bytes/packets and WHEN the reply counter last grew
    (needs net.netfilter.nf_conntrack_acct=1; without it the byte fields are
    None and the verdicts fall back to state/[ASSURED] only),
  * [UNREPLIED] (nothing ever came back), [ASSURED], and when the entry vanished.

State meanings used by verdict.py: CLOSE = a RST was seen (either direction),
FIN_WAIT/CLOSE_WAIT/LAST_ACK/TIME_WAIT = orderly FIN teardown.

Stdlib only."""
import collections
import re
import threading
import time

_PAIR = re.compile(r"(\w+)=(\S+)")
_TCP_STATES = {"SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT",
               "LAST_ACK", "TIME_WAIT", "CLOSE", "NONE", "LISTEN"}


def parse_line(line):
    """One /proc/net/nf_conntrack line -> dict (tcp only) or None."""
    parts = line.split()
    if len(parts) < 6 or parts[2] != "tcp":
        return None
    state = parts[5] if parts[5] in _TCP_STATES else ""
    rest = " ".join(parts[5:])
    flags = set(re.findall(r"\[(\w+)\]", rest))
    orig, reply, cur = {}, {}, None
    for key, value in _PAIR.findall(rest):
        if key == "src":
            cur = reply if orig.get("src") else orig
        if cur is None:
            continue
        if key in ("src", "dst", "sport", "dport", "packets", "bytes"):
            cur[key] = value
    try:
        out = {
            "state": state, "timeout": int(parts[4]),
            "src": orig["src"], "dst": orig["dst"],
            "sport": int(orig["sport"]), "dport": int(orig["dport"]),
            "unreplied": "UNREPLIED" in flags, "assured": "ASSURED" in flags,
            "orig_packets": int(orig["packets"]) if "packets" in orig else None,
            "orig_bytes": int(orig["bytes"]) if "bytes" in orig else None,
            "reply_packets": int(reply["packets"]) if "packets" in reply else None,
            "reply_bytes": int(reply["bytes"]) if "bytes" in reply else None,
        }
    except (KeyError, ValueError):
        return None
    return out


class Conntrack(object):
    """Tracks egress TCP connections across polls."""

    def __init__(self, maxlen=4000, ignore_dports=(), clock=time.time, keep_after_gone=1800):
        self.clock = clock
        self.maxlen = maxlen
        self.ignore_dports = set(int(p) for p in ignore_dports)
        self.keep_after_gone = keep_after_gone
        self.records = collections.OrderedDict()     # (sport, dst, dport) -> rec
        self.lock = threading.RLock()
        self.polls = 0
        self.acct = None                             # True/False once seen, None = unknown
        self.last_error = ""
        self.source = ""                             # 'proc' | 'netlink'

    def ingest(self, text, now=None):
        """Apply one full snapshot of /proc/net/nf_conntrack."""
        now = now or self.clock()
        live = set()
        with self.lock:
            for line in text.splitlines():
                ent = parse_line(line)
                if ent is None or ent["dport"] in self.ignore_dports:
                    continue
                if ent["state"] in ("", "LISTEN", "NONE"):
                    continue
                key = (ent["sport"], ent["dst"], ent["dport"])
                live.add(key)
                if ent["reply_bytes"] is not None:
                    self.acct = True
                elif self.acct is None:
                    self.acct = False
                rec = self.records.get(key)
                if rec is None:
                    rec = {"sport": key[0], "dst_ip": key[1], "dst_port": key[2],
                           "src_ip": ent["src"], "first": now, "gone_at": None,
                           "states": [], "reply_bytes": None, "reply_packets": None,
                           "orig_bytes": None, "reply_grew_at": None,
                           "reply_prev": None, "unreplied": True, "assured": False,
                           "state": ""}
                    self.records[key] = rec
                    while len(self.records) > self.maxlen:
                        self.records.popitem(last=False)
                if ent["state"] != rec["state"]:
                    rec["states"].append((now, ent["state"]))
                    rec["state"] = ent["state"]
                rec["unreplied"], rec["assured"] = ent["unreplied"], ent["assured"]
                rec["gone_at"] = None
                rb = ent["reply_bytes"]
                if rb is not None:
                    if rec["reply_prev"] is None or rb > rec["reply_prev"]:
                        if rb > 0:
                            rec["reply_grew_at"] = now
                    rec["reply_prev"] = rb
                    rec["reply_bytes"], rec["reply_packets"] = rb, ent["reply_packets"]
                    rec["orig_bytes"] = ent["orig_bytes"]
                rec["last_seen"] = now
            for key, rec in self.records.items():
                if key not in live and rec["gone_at"] is None:
                    rec["gone_at"] = now
            cutoff = now - self.keep_after_gone
            for key in [k for k, r in self.records.items()
                        if r["gone_at"] and r["gone_at"] < cutoff]:
                self.records.pop(key, None)
            self.polls += 1

    def get(self, sport, dst_ip, dst_port):
        with self.lock:
            rec = self.records.get((sport, dst_ip, dst_port))
            return self.public(rec) if rec else None

    def find_by_dst(self, dst_ip, dst_port, since, until):
        with self.lock:
            return [self.public(r) for r in self.records.values()
                    if r["dst_ip"] == dst_ip and r["dst_port"] == dst_port
                    and since <= r["first"] <= until]

    @staticmethod
    def public(rec):
        out = dict(rec)
        out["states"] = [(t, s) for t, s in rec["states"]]
        out.pop("reply_prev", None)
        return out


def read_snapshot(path="/proc/net/nf_conntrack", runner=None):
    """-> (text, source). /proc first; where the kernel/namespace does not expose it,
    fall back to the `conntrack` tool (netlink): `conntrack -L -o extended` prints the
    same layout, including the leading 'ipv4 2' family columns."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(), "proc"
    except OSError as proc_err:
        run = runner or _run_conntrack_tool
        text = run()
        if text is None:
            raise OSError("%s; and the `conntrack` tool is unavailable or failed" % proc_err)
        return text, "netlink"


def _run_conntrack_tool():
    import subprocess
    try:
        out = subprocess.run(["conntrack", "-L", "-p", "tcp", "-o", "extended"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 and not out.stdout:
        return None
    return out.stdout.decode("utf-8", "replace")


class ConntrackPoller(threading.Thread):
    def __init__(self, tracker, path="/proc/net/nf_conntrack", interval=1.0, runner=None):
        threading.Thread.__init__(self, daemon=True)
        self.tracker, self.path, self.interval, self.runner = tracker, path, interval, runner
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            try:
                text, source = read_snapshot(self.path, self.runner)
                self.tracker.source = source
                self.tracker.ingest(text)
                self.tracker.last_error = ""
            except Exception as exc:                  # noqa: BLE001 - keep polling
                self.tracker.last_error = str(exc)[:200]
            self._stop.wait(self.interval if self.tracker.source != "netlink"
                            else max(self.interval, 2.0))
