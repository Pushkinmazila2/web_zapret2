"""nfqws debug log -> per-connection trace (what nfqws SAW and DID to the packets).

Source: nfqws2 --debug=1 output (nfqws.log). Facts about that log that shape
this module (checked on a real sample, tests/fixtures/nfqws_sample.log):

  * there are NO timestamps — the time of an event is the moment we read the
    line, so the tailer must poll fast (flows.py uses 0.1 s);
  * only packets handed to the queue (outbound) appear; replies, RSTs and
    FINs from the server never do — "did the server answer" must come from
    conntrack (conntrack.py), not from here;
  * a connection is identified by its egress tuple (local sport, dst ip,
    dst port) — the same tuple dante logs as "out_ip.out_port -> dst" and
    conntrack lists as the original direction;
  * the TLS facts (SNI, versions, ALPN, ECH) are printed BEFORE the
    'dpi desync src=..' line that names the tuple, so they are parked and
    attached when the tuple becomes known.

Stdlib only. Not thread-safe by itself: the owner (FlowStore) serialises."""
import collections
import re
import time

_BLOCK = re.compile(r"^packet: id=(\d+) len=(\d+)")
_VERDICT = re.compile(r"^packet: id=(\d+) (drop|pass unmodified|modified|pass)\b")
_PACKET = re.compile(
    r"IP([46]): (\S+) => (\S+) proto=(\w+).*?sport=(\d+) dport=(\d+) flags=(\w+)"
    r"(?: seq=(\d+))?")
_DESYNC = re.compile(
    r"^dpi desync src=(\S+):(\d+) dst=(\S+):(\d+) .*?connection_proto=(\w+) "
    r"payload_type=(\w+)")
_PROFILE = re.compile(r"(?:desync profile|cached desync profile) (\d+)(?: \(([^)]*)\))?")
_LUA_ACTION = re.compile(r"^\* lua '([^']+)' : desync$")
_SPLIT = re.compile(r"LUA: (\w+): resolved split pos: (.+)$")
_PART = re.compile(r"LUA: (\w+): sending part (\d+) (\d+)-(\d+) len=(\d+)")
_FAKE = re.compile(r"^LUA: (fake\w*): [0-9A-F]{2} ")
_RAW = re.compile(r"^rawsend_dissect repeats=(\d+) size=(\d+)")
_TLS = {
    "record": re.compile(r"^TLS record layer version : (.+)$"),
    "handshake": re.compile(r"^TLS handshake version : (.+)$"),
    "versions": re.compile(r"^TLS supported versions ext : (.+)$"),
    "alpn": re.compile(r"^TLS ALPN ext : (.+)$"),
    "ech": re.compile(r"^TLS ECH ext : (.+)$"),
}
_HOST = re.compile(r"^hostname: (\S+)$")


def _norm_ip(text):
    return text.strip("[]")


class NfqTrace(object):
    """Per-egress-tuple records built from the nfqws debug log."""

    def __init__(self, maxlen=4000, clock=time.time):
        self.clock = clock
        self.maxlen = maxlen
        self.records = collections.OrderedDict()    # (sport, ip, dport) -> rec
        self._pending = {}                          # TLS facts waiting for a tuple
        self._cur = None                            # key of the packet block being read
        self._block_acts = []
        self.lines = 0

    # -- records -----------------------------------------------------------
    def _rec(self, key):
        rec = self.records.get(key)
        now = self.clock()
        if rec is None:
            rec = {"sport": key[0], "dst_ip": key[1], "dst_port": key[2],
                   "first": now, "last": now, "sni": "", "tls": {}, "l7": "",
                   "profile": "", "syn": 0, "hello_ts": None, "hello_size": 0,
                   "actions": [], "splits": [], "parts": 0, "fakes": 0,
                   "raw_sent": 0, "dropped": 0, "retrans": 0, "packets": 0,
                   "_seen": collections.deque(maxlen=24)}
            self.records[key] = rec
            while len(self.records) > self.maxlen:
                self.records.popitem(last=False)
        rec["last"] = now
        return rec

    # -- feeding -----------------------------------------------------------
    def feed(self, line):
        """Consume one nfqws.log line."""
        line = line.rstrip("\r\n")
        self.lines += 1
        m = _BLOCK.match(line)
        if m:                                       # new packet: forget the previous one
            self._cur, self._pending, self._block_acts = None, {}, []
            return
        m = _VERDICT.match(line)
        if m:
            if self._cur and m.group(2) == "drop":
                self._rec(self._cur)["dropped"] += 1
            return
        if not line:
            return

        for name, rx in _TLS.items():
            m = rx.match(line)
            if m:
                value = m.group(1).strip()
                if name == "versions" or name == "alpn":
                    self._pending.setdefault(name, [])
                    if value not in self._pending[name]:
                        self._pending[name].append(value)
                else:
                    self._pending[name] = value
                return
        m = _HOST.match(line)
        if m:
            self._pending["sni"] = m.group(1)
            return

        m = _PACKET.search(line)
        if m:
            sport, dport, flags = int(m.group(5)), int(m.group(6)), m.group(7)
            replay = line.startswith("REPLAY")
            self._cur = (sport, _norm_ip(m.group(3)), dport)
            rec = self._rec(self._cur)
            if not replay:
                rec["packets"] += 1
                seq = m.group(8)
                if "S" in flags and "A" not in flags:
                    rec["syn"] += 1
                if seq is not None:
                    sig = (flags, seq)
                    if sig in rec["_seen"]:
                        rec["retrans"] += 1
                    rec["_seen"].append(sig)
            return

        m = _DESYNC.match(line)
        if m:
            key = (int(m.group(2)), _norm_ip(m.group(3)), int(m.group(4)))
            self._cur = key
            rec = self._rec(key)
            rec["l7"] = m.group(5)
            if m.group(6) == "tls_client_hello" and rec["hello_ts"] is None:
                rec["hello_ts"] = self.clock()
            if self._pending:
                tls = rec["tls"]
                for k in ("record", "handshake", "ech"):
                    if k in self._pending:
                        tls[k] = self._pending[k]
                for k in ("versions", "alpn"):
                    if k in self._pending:
                        tls[k] = list(self._pending[k])
                if self._pending.get("sni"):
                    rec["sni"] = self._pending["sni"]
                self._pending = {}
            return

        if self._cur is None:
            return
        rec = self.records.get(self._cur)
        if rec is None:
            return
        m = _PROFILE.search(line)
        if m and ("matches" in line or "cached" in line):
            rec["profile"] = "%s%s" % (m.group(1), " " + m.group(2) if m.group(2) else "")
            return
        m = _LUA_ACTION.match(line)
        if m:
            if m.group(1) not in self._block_acts:
                self._block_acts.append(m.group(1))
                if m.group(1) not in rec["actions"]:
                    rec["actions"].append(m.group(1))
            return
        m = _SPLIT.match(line)
        if m:
            rec["splits"] = [{"fn": m.group(1), "pos": m.group(2).split()}]
            return
        m = _PART.match(line)
        if m:
            rec["parts"] += 1
            return
        if _FAKE.match(line):
            rec["fakes"] += 1
            return
        m = _RAW.match(line)
        if m:
            rec["raw_sent"] += int(m.group(1))
            if rec["hello_ts"] is not None and not rec["hello_size"]:
                rec["hello_size"] = int(m.group(2))
            return

    # -- lookups -----------------------------------------------------------
    def get(self, sport, dst_ip, dst_port):
        rec = self.records.get((sport, dst_ip, dst_port))
        return self.public(rec) if rec else None

    def find_by_dst(self, dst_ip, dst_port, since, until):
        """Records towards dst_ip:dst_port first seen in [since, until]."""
        out = [r for r in self.records.values()
               if r["dst_ip"] == dst_ip and r["dst_port"] == dst_port
               and since <= r["first"] <= until]
        return [self.public(r) for r in out]

    @staticmethod
    def public(rec):
        out = {k: v for k, v in rec.items() if not k.startswith("_")}
        out["desynced"] = bool(rec["actions"])
        return out
