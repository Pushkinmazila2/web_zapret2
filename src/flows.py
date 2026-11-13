#!/usr/bin/env python3
"""web_zapret2 — traffic flows (Traffic tab backend).

Turns the logs the container already writes (dante, ss-server, tinyproxy) and,
optionally, the sing-box Clash API into ONE table of flows with meaning:
who, to which host, what kind of traffic, which protocol, how many bytes, what
happened — instead of raw log lines.

Sources and what each really knows (verified against real logs):
  dante (sockd.log)   tcp/connect open+close lines: client, outbound 5-tuple, bytes
                      up/down, duration, close reason.  IPs ONLY — no hostnames.
  ss-server.log       "connect to HOST:PORT" — hostname, but no ports/bytes/ids.
  tinyproxy.log       Request lines (CONNECT host:port / GET url) — hostname.
  sing-box Clash API  /connections: real client IP, sniffed host, destination IP,
                      chain (outbound), matched rule, upload/download.  Active
                      connections only, so closed ones are kept here by id.

The two sides are joined by destination IP:port (or host) and time — never by
source port: sing-box does not expose its outbound socket's local port.

Stdlib only; everything is in memory with a TTL (hostnames of users are
sensitive, nothing is written to disk).
"""
import collections
import datetime
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

MATCH_WINDOW = 8.0        # s: max start-time distance when joining the two sides
LOST_AFTER = 10.0         # s: a flow sent to the container but unseen there after this

# ---------------------------------------------------------------------------
# protocol / service guess
# ---------------------------------------------------------------------------
_TCP_SERVICES = {
    80: "HTTP", 443: "TLS (HTTPS)", 8080: "HTTP (alt)", 8443: "TLS (alt)",
    22: "SSH", 21: "FTP", 25: "SMTP", 465: "SMTP over TLS", 587: "SMTP submission",
    143: "IMAP", 993: "IMAP over TLS", 110: "POP3", 995: "POP3 over TLS",
    53: "DNS over TCP", 853: "DNS over TLS", 5222: "XMPP", 1935: "RTMP",
    3478: "STUN/TURN", 5228: "Google push (FCM)",
}
_UDP_SERVICES = {
    443: "QUIC (HTTP/3)", 53: "DNS", 123: "NTP", 3478: "STUN/TURN",
    5353: "mDNS", 51820: "WireGuard", 1194: "OpenVPN",
}


def service_for(transport, port):
    """Best guess of the application protocol from transport+port.

    Deliberately labelled as a guess ('basis': 'port'): logs of a proxy cannot
    tell TLS 1.2 from 1.3 or QUIC from other UDP — that needs the nfqws trace."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"service": "", "basis": ""}
    table = _UDP_SERVICES if transport == "udp" else _TCP_SERVICES
    name = table.get(port)
    if name:
        return {"service": name, "basis": "port"}
    return {"service": "", "basis": ""}


def shape_for(up, down, duration):
    """Behavioural hint from byte counts: what a flow LOOKS like."""
    up, down = int(up or 0), int(down or 0)
    duration = float(duration or 0)
    total = up + down
    if total == 0:
        return ""
    if down >= 2_000_000 and down > 4 * max(up, 1):
        return "bulk download / stream"
    if up >= 2_000_000 and up > 4 * max(down, 1):
        return "bulk upload"
    if duration >= 20 and total < 40_000:
        return "idle / keep-alive"
    if duration < 5 and down < 200_000:
        return "short request"
    return "mixed"


# ---------------------------------------------------------------------------
# host classification (rules in config/traffic_classes.json)
# ---------------------------------------------------------------------------
def load_classes(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        rules = [r for r in data.get("rules", []) if r.get("suffix") and r.get("class")]
        return rules
    except (OSError, ValueError):
        return []


def classify_host(host, rules):
    """-> {'class', 'label', 'basis'}; the class is a guess from the hostname."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return {"class": "", "label": "", "basis": ""}
    for rule in rules:
        suffix = str(rule["suffix"]).lower()
        if host == suffix or host.endswith("." + suffix):
            return {"class": rule["class"], "label": rule.get("label", ""),
                    "basis": "host-rule"}
    return {"class": "other", "label": "", "basis": ""}


# ---------------------------------------------------------------------------
# log line parsers
# ---------------------------------------------------------------------------
_ADDR = r"((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]+)\.(\d+)"
_DANTE_TS = re.compile(r"\((\d{9,11}(?:\.\d+)?)\)")
_DANTE_OPEN = re.compile(
    r"tcp/connect \[: %s %s -> %s %s\s*$" % ((_ADDR,) * 4))
# One "tcp/connect ]" line carries BOTH halves: client<->proxy and proxy<->target.
#   A -> client proxy -> B, C -> out target -> D: reason.  Session duration: Ns
# Orientation (checked on real logs, down > up every time): the SECOND pair is
# canonical — C = bytes sent to the target (upload), D = bytes received (download).
_DANTE_CLOSE = re.compile(
    r"tcp/connect \]: (\d+) -> %s %s -> (\d+), (\d+) -> %s %s -> (\d+): "
    r"(.*?)\.\s+Session duration: (\d+)s" % ((_ADDR,) * 4))


def parse_dante_line(line):
    """sockd.log line -> event dict or None."""
    ts_match = _DANTE_TS.search(line)
    if not ts_match:
        return None
    ts = float(ts_match.group(1))
    m = _DANTE_OPEN.search(line)
    if m:
        g = m.groups()
        return {"kind": "open", "ts": ts, "transport": "tcp",
                "client_ip": g[0], "client_port": int(g[1]),
                "proxy_ip": g[2], "proxy_port": int(g[3]),
                "out_ip": g[4], "out_port": int(g[5]),
                "dst_ip": g[6], "dst_port": int(g[7])}
    m = _DANTE_CLOSE.search(line)
    if m:
        g = m.groups()
        return {"kind": "close", "ts": ts, "transport": "tcp",
                "client_ip": g[1], "client_port": int(g[2]),
                "proxy_ip": g[3], "proxy_port": int(g[4]),
                "out_ip": g[7], "out_port": int(g[8]),
                "dst_ip": g[9], "dst_port": int(g[10]),
                "up": int(g[5]), "down": int(g[11]),
                "reason": g[12].strip(), "duration": int(g[13])}
    return None


_SS_CONNECT = re.compile(
    r"^\s*(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \w+: (?:\[\d+\] )?connect to (.+):(\d+)\s*$")
_SS_GAUGE = re.compile(
    r"^\s*(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \w+: .*?(\d+) opened (client|remote) connections")


def _local_epoch(text, fmt):
    try:
        return time.mktime(time.strptime(text, fmt))
    except (ValueError, OverflowError):
        return time.time()


def parse_ss_line(line):
    """ss-server.log line -> event dict or None (times are container-local)."""
    m = _SS_CONNECT.match(line)
    if m:
        host = m.group(2).strip("[]")
        return {"kind": "connect", "ts": _local_epoch(m.group(1), "%Y-%m-%d %H:%M:%S"),
                "host": host, "port": int(m.group(3))}
    m = _SS_GAUGE.match(line)
    if m:
        return {"kind": "gauge", "ts": _local_epoch(m.group(1), "%Y-%m-%d %H:%M:%S"),
                "side": m.group(3), "n": int(m.group(2))}
    return None


_TP_REQUEST = re.compile(r"Request \(file descriptor \d+\): ([A-Z]+) (\S+) HTTP/[\d.]+")
_TP_TIME = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\b")


def _split_hostport(target, default_port):
    if target.startswith("["):                       # [v6]:port
        host, _, rest = target[1:].partition("]")
        return host, int(rest.lstrip(":") or default_port)
    host, sep, port = target.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host, int(port)
    return target, default_port


def parse_tinyproxy_line(line, now=None):
    """tinyproxy.log line -> event dict or None.

    Format is taken from tinyproxy's documented log style (no real sample was
    available yet) — kept tolerant; unparsed lines are counted and shown in the
    panel's debug view so it can be corrected from real output."""
    m = _TP_REQUEST.search(line)
    if not m:
        return None
    method, target = m.group(1), m.group(2)
    now = now or time.time()
    ts = now
    t = _TP_TIME.search(line)
    if t:
        try:
            year = time.localtime(now).tm_year
            ts = time.mktime(time.strptime("%s %s %s %s" % (year, t.group(1), t.group(2),
                                                            t.group(3)), "%Y %b %d %H:%M:%S"))
            if ts - now > 86400:                      # log from last December
                ts = time.mktime(time.strptime("%s %s %s %s" % (year - 1, t.group(1),
                                 t.group(2), t.group(3)), "%Y %b %d %H:%M:%S"))
        except (ValueError, OverflowError):
            ts = now
    if method == "CONNECT":
        host, port = _split_hostport(target, 443)
        return {"kind": "request", "ts": ts, "method": method, "host": host, "port": port}
    m2 = re.match(r"^(?:https?://)?([^/:]+)(?::(\d+))?(/.*)?$", target)
    if not m2:
        return None
    port = int(m2.group(2) or (443 if target.startswith("https") else 80))
    return {"kind": "request", "ts": ts, "method": method, "host": m2.group(1),
            "port": port, "path": m2.group(3) or "/"}


# ---------------------------------------------------------------------------
# sing-box Clash API
# ---------------------------------------------------------------------------
_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_rfc3339(text):
    """'2026-11-10T18:43:25.149848188+03:30' -> epoch (nanoseconds are trimmed)."""
    try:
        return datetime.datetime.fromisoformat(
            _FRACTION.sub(r"\1", str(text))).timestamp()
    except ValueError:
        return time.time()


def normalize_clash(conn):
    """One /connections entry -> flow fields."""
    meta = conn.get("metadata") or {}
    chains = [str(c) for c in (conn.get("chains") or [])]
    try:
        dst_port = int(meta.get("destinationPort") or 0)
    except (TypeError, ValueError):
        dst_port = 0
    try:
        client_port = int(meta.get("sourcePort") or 0)
    except (TypeError, ValueError):
        client_port = 0
    return {
        "id": "c:" + str(conn.get("id")),
        "t_start": parse_rfc3339(conn.get("start")),
        "client": meta.get("sourceIP") or "", "client_port": client_port,
        "dst_ip": meta.get("destinationIP") or "", "dst_port": dst_port,
        "host": meta.get("host") or "", "transport": (meta.get("network") or "tcp").lower(),
        "inbound": meta.get("type") or "",
        "chains": chains, "rule": conn.get("rule") or "",
        "up": int(conn.get("upload") or 0), "down": int(conn.get("download") or 0),
    }


def fetch_clash(url, secret="", timeout=3.0, opener=None):
    """GET <url>/connections -> list of raw connection dicts (raises on failure)."""
    request = urllib.request.Request(url.rstrip("/") + "/connections")
    if secret:
        request.add_header("Authorization", "Bearer " + secret)
    open_fn = opener or urllib.request.urlopen
    with open_fn(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8", "replace"))
    return list(payload.get("connections") or [])


# ---------------------------------------------------------------------------
# the store
# ---------------------------------------------------------------------------
def _family(ip):
    if not ip:
        return ""
    return "ipv6" if ":" in ip else "ipv4"


class FlowStore(object):
    """Thread-safe in-memory flow table (ring buffer + TTL)."""

    def __init__(self, rules=None, maxlen=3000, ttl=3600, container_outbound="zapretDPI",
                 clock=time.time):
        self.rules = rules or []
        self.maxlen = maxlen
        self.ttl = ttl
        self.container_outbound = container_outbound
        self.clock = clock
        self.lock = threading.RLock()
        self.flows = collections.OrderedDict()      # id -> raw flow
        self._dante_open = {}                       # (client_ip, port) -> flow id
        self.ip_host = {}                           # dst ip -> host (learned from sing-box)
        self.ss_gauge = {"client": None, "remote": None}
        self.parsed = collections.Counter()
        self.unparsed = collections.deque(maxlen=25)
        self.clash = {"enabled": False, "ok": None, "error": "", "last_ok": 0.0, "n": 0}
        self._seq = 0

    # -- helpers -----------------------------------------------------------
    def _new_id(self, prefix):
        self._seq += 1
        return "%s:%d" % (prefix, self._seq)

    def _base(self, source):
        return {"source": source, "t_start": self.clock(), "t_end": None, "state": "open",
                "client": "", "client_port": 0, "dst_ip": "", "dst_port": 0, "host": "",
                "host_src": "", "transport": "tcp", "access": "", "inbound": "",
                "chains": [], "rule": "", "up": 0, "down": 0, "reason": "",
                "duration": None}

    def _trim(self):
        now = self.clock()
        for fid in [k for k, f in self.flows.items()
                    if (f["t_end"] or f["t_start"]) < now - self.ttl and f["state"] != "open"]:
            self.flows.pop(fid, None)
        while len(self.flows) > self.maxlen:
            self.flows.popitem(last=False)
        live = set(self.flows)
        self._dante_open = {k: v for k, v in self._dante_open.items() if v in live}

    # -- feeding -----------------------------------------------------------
    def feed(self, kind, line):
        """Feed one raw log line of kind 'dante' | 'ss' | 'http'."""
        with self.lock:
            if kind == "dante":
                if "tcp/accept" in line:
                    return                       # duplicates the "tcp/connect" line
                ev = parse_dante_line(line)
                if ev is None:
                    if "danted" in line or "sockd" in line:
                        self._note_unparsed(kind, line)
                    return
                self._on_dante(ev)
            elif kind == "ss":
                ev = parse_ss_line(line)
                if ev is None:
                    return                       # most ss-server lines are chatter
                if ev["kind"] == "gauge":
                    self.ss_gauge[ev["side"]] = ev["n"]
                else:
                    self._on_hostname(ev, "ss")
            elif kind == "http":
                ev = parse_tinyproxy_line(line, self.clock())
                if ev is None:
                    if "Request" in line or "CONNECT" in line:
                        self._note_unparsed(kind, line)
                    return
                self._on_hostname(ev, "http")
            else:
                return
            self.parsed[kind] += 1
            self._trim()

    def _note_unparsed(self, kind, line):
        self.parsed[kind + "_unparsed"] += 1
        self.unparsed.append("%s: %s" % (kind, line.rstrip()[:300]))

    def _on_dante(self, ev):
        key = (ev["client_ip"], ev["client_port"])
        fid = self._dante_open.get(key)
        flow = self.flows.get(fid) if fid else None
        if ev["kind"] == "open":
            flow = self._base("container")
            flow.update({"t_start": ev["ts"], "client": ev["client_ip"],
                         "client_port": ev["client_port"], "dst_ip": ev["dst_ip"],
                         "dst_port": ev["dst_port"], "transport": ev["transport"],
                         "access": "socks5"})
            fid = self._new_id("d")
            self.flows[fid] = flow
            self._dante_open[key] = fid
            return
        if flow is None:                          # started before we began tailing
            flow = self._base("container")
            fid = self._new_id("d")
            self.flows[fid] = flow
        flow.update({"t_start": ev["ts"] - ev["duration"], "t_end": ev["ts"],
                     "client": ev["client_ip"], "client_port": ev["client_port"],
                     "dst_ip": ev["dst_ip"], "dst_port": ev["dst_port"],
                     "transport": ev["transport"], "access": "socks5",
                     "up": ev["up"], "down": ev["down"], "duration": ev["duration"],
                     "reason": ev["reason"], "state": "closed"})
        self._dante_open.pop(key, None)

    def _on_hostname(self, ev, access):
        flow = self._base("container")
        flow.update({"t_start": ev["ts"], "host": ev["host"], "host_src": access,
                     "dst_port": ev["port"], "access": access, "state": "seen"})
        if ev.get("method"):
            flow["reason"] = ev["method"]
        self.flows[self._new_id("h")] = flow

    def update_clash(self, connections, now=None):
        """Apply one /connections poll: new ones are added, vanished ones closed."""
        now = now or self.clock()
        with self.lock:
            present = set()
            for raw in connections:
                norm = normalize_clash(raw)
                fid = norm["id"]
                present.add(fid)
                flow = self.flows.get(fid)
                if flow is None:
                    flow = self._base("singbox")
                    self.flows[fid] = flow
                flow.update({"t_start": norm["t_start"], "client": norm["client"],
                             "client_port": norm["client_port"], "dst_ip": norm["dst_ip"],
                             "dst_port": norm["dst_port"], "transport": norm["transport"],
                             "inbound": norm["inbound"], "chains": norm["chains"],
                             "rule": norm["rule"], "up": norm["up"], "down": norm["down"]})
                if norm["host"]:
                    flow["host"], flow["host_src"] = norm["host"], "sniff"
                    if norm["dst_ip"]:
                        self.ip_host[norm["dst_ip"]] = norm["host"]
                flow["to_container"] = self.container_outbound in norm["chains"]
            for fid, flow in self.flows.items():
                if flow["source"] == "singbox" and flow["state"] == "open" \
                        and fid not in present:
                    flow["state"], flow["t_end"] = "closed", now
                    flow["duration"] = max(0, int(now - flow["t_start"]))
            self.clash.update({"enabled": True, "ok": True, "error": "", "last_ok": now,
                               "n": len(present)})
            if len(self.ip_host) > 5000:
                self.ip_host.clear()
            self.parsed["clash"] += 1
            self._trim()

    def clash_failed(self, error):
        with self.lock:
            self.clash.update({"enabled": True, "ok": False, "error": str(error)[:200]})

    # -- joined view -------------------------------------------------------
    def _match(self, sflow, candidates, used):
        """Find the container-side flow for a sing-box flow handed to the container."""
        best, best_dt = None, MATCH_WINDOW + 1
        for cand_id, cand in candidates:
            if cand_id in used:
                continue
            dt = abs(cand["t_start"] - sflow["t_start"])
            if dt > MATCH_WINDOW or cand["dst_port"] != sflow["dst_port"]:
                continue
            if cand["dst_ip"] and sflow["dst_ip"]:
                same = cand["dst_ip"] == sflow["dst_ip"]
            elif cand["host"] and sflow["host"]:
                same = cand["host"].lower() == sflow["host"].lower()
            else:
                same = False
            if same and dt < best_dt:
                best, best_dt = cand_id, dt
        return best

    def _decorate(self, row):
        host = row.get("host") or ""
        if not host and row.get("dst_ip") and row["dst_ip"] in self.ip_host:
            host, row["host"], row["host_src"] = self.ip_host[row["dst_ip"]], \
                self.ip_host[row["dst_ip"]], "ip-map"
        row["family"] = _family(row.get("dst_ip"))
        row.update(service_for(row.get("transport"), row.get("dst_port")))
        cls = classify_host(host, self.rules)
        row["class"], row["class_label"], row["class_basis"] = \
            cls["class"], cls["label"], cls["basis"]
        end = row["t_end"] or self.clock()
        if row["duration"] is None:
            row["duration"] = max(0, int(end - row["t_start"]))
        total = (row["up"] or 0) + (row["down"] or 0)
        row["shape"] = shape_for(row["up"], row["down"], row["duration"])
        row["rate_kbps"] = round(row["down"] * 8 / 1000.0 / row["duration"], 1) \
            if row["duration"] else 0.0
        row["bytes_total"] = total
        return row

    def snapshot(self):
        """Unified flow list (newest first) + the join bookkeeping."""
        with self.lock:
            now = self.clock()
            sb = [(k, f) for k, f in self.flows.items() if f["source"] == "singbox"]
            ct = sorted(((k, f) for k, f in self.flows.items() if f["source"] == "container"),
                        key=lambda kv: kv[1]["t_start"])
            ct_alive = self.parsed["dante"] + self.parsed["ss"] + self.parsed["http"] > 0
            used, rows = set(), []
            for fid, flow in sb:
                row = dict(flow)
                row["id"] = fid
                row["chains"] = list(flow["chains"])
                row["seen_by_container"] = None
                row["container"] = None
                if flow.get("to_container"):
                    match = self._match(flow, ct, used)
                    if match:
                        used.add(match)
                        c = self.flows[match]
                        row["seen_by_container"] = True
                        row["container"] = {"access": c["access"], "up": c["up"],
                                            "down": c["down"], "duration": c["duration"],
                                            "state": c["state"], "reason": c["reason"]}
                        row["access"] = c["access"]
                    elif ct_alive and flow["transport"] == "tcp" \
                            and now - flow["t_start"] > LOST_AFTER:
                        row["seen_by_container"] = False
                rows.append(self._decorate(row))
            for fid, flow in ct:
                if fid in used:
                    continue
                row = dict(flow)
                row["id"] = fid
                row["to_container"] = True
                row["seen_by_container"] = True
                row["container"] = None
                rows.append(self._decorate(row))
            rows.sort(key=lambda r: r["t_start"], reverse=True)
            return rows

    def flows_view(self, limit=200, cls="", transport="", access="", q="", only_open=False):
        rows = self.snapshot()
        q = (q or "").lower()
        out = []
        for r in rows:
            if cls and r["class"] != cls:
                continue
            if transport and r["transport"] != transport:
                continue
            if access and r["access"] != access:
                continue
            if only_open and r["state"] == "closed":
                continue
            if q and q not in ("%s %s %s" % (r["host"], r["dst_ip"], r["client"])).lower():
                continue
            out.append(r)
            if len(out) >= limit:
                break
        return out

    def hosts_view(self, limit=100):
        """Per-host aggregate — where the sing-box side and the container side meet."""
        agg = {}
        for r in self.snapshot():
            key = r["host"] or r["dst_ip"] or "?"
            h = agg.setdefault(key, {
                "host": key, "is_ip": not r["host"], "class": r["class"],
                "class_label": r["class_label"], "flows": 0, "open": 0, "up": 0,
                "down": 0, "to_container": 0, "direct_or_other": 0, "not_seen": 0,
                "clients": set(), "outbounds": set(), "services": set(), "last": 0})
            h["flows"] += 1
            h["open"] += 1 if r["state"] != "closed" else 0
            h["up"] += r["up"] or 0
            h["down"] += r["down"] or 0
            if r["source"] == "singbox":
                if r.get("to_container"):
                    h["to_container"] += 1
                else:
                    h["direct_or_other"] += 1
            if r.get("seen_by_container") is False:
                h["not_seen"] += 1
            if r["client"]:
                h["clients"].add(r["client"])
            if r["chains"]:
                h["outbounds"].add(" > ".join(r["chains"]))
            if r["service"]:
                h["services"].add(r["service"])
            h["last"] = max(h["last"], r["t_end"] or r["t_start"])
        out = []
        for h in agg.values():
            h["clients"] = len(h["clients"])
            h["outbounds"] = sorted(h["outbounds"])
            h["services"] = sorted(h["services"])
            out.append(h)
        out.sort(key=lambda h: h["last"], reverse=True)
        return out[:limit]

    def summary(self):
        """The 'pipeline' counters: does traffic reach the container, and where not."""
        rows = self.snapshot()
        now = self.clock()
        recent = [r for r in rows if (r["t_end"] or now) > now - 300]
        sb = [r for r in rows if r["source"] == "singbox"]
        to_c = [r for r in sb if r.get("to_container")]
        by_outbound = collections.Counter(
            (" > ".join(r["chains"]) or "?") for r in sb if r["state"] == "open")
        by_class = collections.Counter(r["class"] or "unknown" for r in recent)
        by_service = collections.Counter(
            ("%s/%s" % (r["service"] or "other", r["transport"])) for r in recent)
        by_access = collections.Counter(r["access"] or "?" for r in rows
                                        if r["source"] == "container" or r.get("container"))
        with self.lock:
            clash = dict(self.clash)
            gauge = dict(self.ss_gauge)
            parsed = dict(self.parsed)
            unparsed = list(self.unparsed)
        return {
            "singbox": dict(clash, active=sum(1 for r in sb if r["state"] == "open"),
                            tracked=len(sb), to_container=len(to_c),
                            to_container_open=sum(1 for r in to_c if r["state"] == "open"),
                            by_outbound=dict(by_outbound),
                            container_outbound=self.container_outbound),
            "container": {"access": dict(by_access), "ss_open_clients": gauge["client"],
                          "ss_open_remotes": gauge["remote"],
                          "flows": sum(1 for r in rows if r["source"] == "container"
                                       or r.get("container"))},
            "join": {"matched": sum(1 for r in to_c if r.get("seen_by_container") is True),
                     "not_seen": sum(1 for r in to_c if r.get("seen_by_container") is False),
                     "unknown": sum(1 for r in to_c if r.get("seen_by_container") is None)},
            "recent": {"classes": dict(by_class), "services": dict(by_service)},
            "debug": {"parsed": parsed, "unparsed": unparsed},
        }


# ---------------------------------------------------------------------------
# background collectors
# ---------------------------------------------------------------------------
class LogTailer(threading.Thread):
    """Follow a log file (rotation/truncation-safe) and feed lines to the store."""

    def __init__(self, path, kind, store, backfill=131072, poll=0.5):
        threading.Thread.__init__(self, daemon=True)
        self.path, self.kind, self.store = path, kind, store
        self.backfill, self.poll = backfill, poll
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        handle, inode, first = None, None, True
        while not self._stop.is_set():
            try:
                st = os.stat(self.path)
            except OSError:
                time.sleep(self.poll * 4)
                continue
            if handle is None or st.st_ino != inode or st.st_size < handle.tell():
                if handle:
                    handle.close()
                handle = open(self.path, "r", encoding="utf-8", errors="replace")
                inode = st.st_ino
                if first:
                    handle.seek(max(0, st.st_size - self.backfill))
                    if handle.tell():
                        handle.readline()                 # drop a partial line
                    first = False
            line = handle.readline()
            if not line:
                time.sleep(self.poll)
                continue
            if not line.endswith("\n"):                   # half-written line: retry
                handle.seek(handle.tell() - len(line.encode("utf-8", "replace")))
                time.sleep(self.poll)
                continue
            try:
                self.store.feed(self.kind, line)
            except Exception:                             # a bad line must not kill the tailer
                pass
        if handle:
            handle.close()


class ClashPoller(threading.Thread):
    def __init__(self, store, url, secret="", interval=3.0, fetch=fetch_clash):
        threading.Thread.__init__(self, daemon=True)
        self.store, self.url, self.secret = store, url, secret
        self.interval, self.fetch = interval, fetch
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        self.store.clash["enabled"] = True
        while not self._stop.is_set():
            try:
                self.store.update_clash(self.fetch(self.url, self.secret))
            except (urllib.error.URLError, OSError, ValueError) as exc:
                self.store.clash_failed(exc)
            self._stop.wait(self.interval)


def start_collectors(store, log_dir, singbox_url="", singbox_secret="", interval=3.0):
    """Start the tailers (+ the Clash poller when configured); returns the threads."""
    threads = [LogTailer(os.path.join(log_dir, "sockd.log"), "dante", store),
               LogTailer(os.path.join(log_dir, "ss-server.log"), "ss", store),
               LogTailer(os.path.join(log_dir, "tinyproxy.log"), "http", store)]
    if singbox_url:
        threads.append(ClashPoller(store, singbox_url, singbox_secret, interval))
    for thread in threads:
        thread.start()
    return threads
