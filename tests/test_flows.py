"""Traffic tab backend (src/flows.py) — parsers are checked against REAL log lines
captured from a running deployment (client addresses replaced by documentation
ranges)."""
import datetime
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src" / "panel"))
import flows
import panel

T0 = 1794323300.0

DANTE_OPEN = ("Nov 10 15:08:25 (1794323305.804211) danted[730506]: info: pass(1): "
              "tcp/connect [: 172.22.0.1.56302 172.22.0.4.1080 -> 172.22.0.4.56302 173.194.151.65.443")
DANTE_CLOSE = ("Nov 10 15:08:36 (1794323316.217148) danted[730506]: info: pass(1): tcp/connect ]: "
               "4802 -> 172.22.0.1.58886 172.22.0.4.1080 -> 4216, 4216 -> 172.22.0.4.58886 "
               "172.217.119.4.443 -> 4802: remote peer closed.  Session duration: 298s")
DANTE_ACCEPT = ("Nov 10 15:08:36 (1794323316.217179) danted[730506]: info: pass(1): tcp/accept ]: "
                "4802 -> 172.22.0.1.58886 172.22.0.4.1080 -> 4216: remote peer closed.  Session duration: 298s")
DANTE_CLOSE_CF = ("Nov 10 15:08:36 (1794323316.245222) danted[722035]: info: pass(1): tcp/connect ]: "
                  "13254 -> 172.22.0.1.44792 172.22.0.4.1080 -> 3941, 3941 -> 172.22.0.4.44792 "
                  "188.114.97.0.443 -> 13254: remote peer closed.  Session duration: 669s")
SS_HOST = "2026-11-10 13:34:59 INFO: [8388] connect to rr1---sn-g5njvh-n8vl.googlevideo.com:443"
SS_IP = " 2026-11-10 13:35:23 INFO: [8388] connect to 142.251.20.94:443"
SS_GAUGE = "2026-11-10 13:34:59 INFO: new connection from client, 22 opened client connections"

RULE = ("rule_set=[geosite-ru-blocked geosite-telegram geoip-telegram] => route(ServerNL)")


def clash_conn(cid, host="", dst_ip="", port="443", chain=("zapretDPI",), start=T0,
               up=100, down=2000, client="203.0.113.7", network="tcp", rule=RULE):
    tz = datetime.timezone(datetime.timedelta(hours=3, minutes=30))     # as sing-box reports it
    dt = datetime.datetime.fromtimestamp(start, tz)
    stamp = dt.strftime("%Y-%m-%dT%H:%M:%S") + (".%06d" % dt.microsecond) + "000+03:30"
    return {"chains": list(chain), "download": down, "id": cid,
            "metadata": {"destinationIP": dst_ip, "destinationPort": port, "dnsMode": "normal",
                         "host": host, "network": network, "processPath": "",
                         "sourceIP": client, "sourcePort": "58144", "type": "vless/vless-9889"},
            "rule": rule, "rulePayload": "", "start": stamp, "upload": up}


class ParserTests(unittest.TestCase):
    def test_dante_open(self):
        ev = flows.parse_dante_line(DANTE_OPEN)
        self.assertEqual((ev["kind"], ev["client_ip"], ev["client_port"]),
                         ("open", "172.22.0.1", 56302))
        self.assertEqual((ev["dst_ip"], ev["dst_port"]), ("173.194.151.65", 443))
        self.assertAlmostEqual(ev["ts"], 1794323305.804211, places=3)

    def test_dante_close_has_bytes_direction_and_duration(self):
        ev = flows.parse_dante_line(DANTE_CLOSE)
        self.assertEqual(ev["kind"], "close")
        self.assertEqual((ev["client_ip"], ev["client_port"]), ("172.22.0.1", 58886))
        self.assertEqual((ev["dst_ip"], ev["dst_port"]), ("172.217.119.4", 443))
        # second pair is canonical: C = up (to target), D = down (from target)
        self.assertEqual((ev["up"], ev["down"]), (4216, 4802))
        self.assertEqual((ev["reason"], ev["duration"]), ("remote peer closed", 298))
        cf = flows.parse_dante_line(DANTE_CLOSE_CF)
        self.assertEqual((cf["up"], cf["down"]), (3941, 13254))      # down > up, as in practice

    def test_dante_accept_line_is_ignored_and_not_reported_as_unparsed(self):
        store = flows.FlowStore()
        store.feed("dante", DANTE_ACCEPT)
        self.assertEqual(len(store.flows), 0)
        self.assertEqual(len(store.unparsed), 0)

    def test_dante_unknown_format_is_surfaced_for_debugging(self):
        store = flows.FlowStore()
        store.feed("dante", "Nov 10 15:08:36 (1794323316.1) danted[1]: info: udp/udpassociate [: x")
        self.assertEqual(len(store.unparsed), 1)
        self.assertEqual(store.parsed["dante_unparsed"], 1)

    def test_ss_connect_gauge_and_ip_only(self):
        ev = flows.parse_ss_line(SS_HOST)
        self.assertEqual((ev["kind"], ev["host"], ev["port"]),
                         ("connect", "rr1---sn-g5njvh-n8vl.googlevideo.com", 443))
        self.assertEqual(flows.parse_ss_line(SS_IP)["host"], "142.251.20.94")
        g = flows.parse_ss_line(SS_GAUGE)
        self.assertEqual((g["kind"], g["side"], g["n"]), ("gauge", "client", 22))
        self.assertIsNone(flows.parse_ss_line(
            "2026-11-10 13:34:59 INFO: found address name v4 address rr1.googlevideo.com"))

    def test_tinyproxy_connect_and_plain_get(self):
        ev = flows.parse_tinyproxy_line(
            "CONNECT   Nov 10 15:08:25 [123]: Request (file descriptor 7): "
            "CONNECT rr1.googlevideo.com:443 HTTP/1.1", now=1794323305)
        self.assertEqual((ev["host"], ev["port"], ev["method"]),
                         ("rr1.googlevideo.com", 443, "CONNECT"))
        ev = flows.parse_tinyproxy_line(
            "CONNECT   Nov 10 15:08:25 [123]: Request (file descriptor 7): "
            "GET http://example.com/a/b.jpg HTTP/1.1", now=1794323305)
        self.assertEqual((ev["host"], ev["port"], ev["path"]), ("example.com", 80, "/a/b.jpg"))
        self.assertIsNone(flows.parse_tinyproxy_line("INFO Nov 10 Closed connection"))

    def test_rfc3339_with_nanoseconds_and_odd_offset(self):
        got = flows.parse_rfc3339("2026-11-10T18:43:25.149848188+03:30")
        want = datetime.datetime(2026, 11, 10, 15, 13, 25, 149848,
                                 tzinfo=datetime.timezone.utc).timestamp()
        self.assertAlmostEqual(got, want, places=4)


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.rules = flows.load_classes(str(ROOT / "config" / "traffic_classes.json"))

    def test_shipped_rules_load(self):
        self.assertGreater(len(self.rules), 10)

    def test_youtube_hosts(self):
        c = lambda h: flows.classify_host(h, self.rules)["class"]
        self.assertEqual(c("rr1---sn-g5njvh-n8vl.googlevideo.com"), "video")
        self.assertEqual(c("i.ytimg.com"), "image")
        self.assertEqual(c("youtubei.googleapis.com"), "api")
        self.assertEqual(c("s.youtube.com"), "web")
        self.assertEqual(c("www.speedtest.net"), "test")

    def test_suffix_must_be_a_label_boundary(self):
        self.assertEqual(flows.classify_host("notgooglevideo.com", self.rules)["class"], "other")
        self.assertEqual(flows.classify_host("", self.rules)["class"], "")

    def test_service_and_shape_guesses(self):
        self.assertEqual(flows.service_for("tcp", 443)["service"], "TLS (HTTPS)")
        self.assertEqual(flows.service_for("udp", 443)["service"], "QUIC (HTTP/3)")
        self.assertEqual(flows.service_for("tcp", 22)["service"], "SSH")
        self.assertEqual(flows.service_for("tcp", 49999)["service"], "")
        self.assertEqual(flows.shape_for(1000, 5_000_000, 30), "bulk download / stream")
        self.assertEqual(flows.shape_for(2000, 2000, 300), "idle / keep-alive")
        self.assertEqual(flows.shape_for(500, 3000, 1), "short request")
        self.assertEqual(flows.shape_for(0, 0, 10), "")

    def test_clash_normalization(self):
        n = flows.normalize_clash(clash_conn("abc", host="s.youtube.com", port="443"))
        self.assertEqual((n["id"], n["host"], n["dst_port"], n["transport"]),
                         ("c:abc", "s.youtube.com", 443, "tcp"))
        self.assertEqual(n["chains"], ["zapretDPI"])
        self.assertAlmostEqual(n["t_start"], T0, places=2)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.now = T0 + 1000
        rules = flows.load_classes(str(ROOT / "config" / "traffic_classes.json"))
        self.store = flows.FlowStore(rules=rules, ttl=10 ** 9, clock=lambda: self.now)

    def test_dante_open_then_close_is_one_flow_with_bytes(self):
        o = DANTE_OPEN.replace("56302", "58886").replace("173.194.151.65", "172.217.119.4")
        self.store.feed("dante", o)
        rows = self.store.snapshot()
        self.assertEqual((len(rows), rows[0]["state"]), (1, "open"))
        self.store.feed("dante", DANTE_CLOSE)
        rows = self.store.snapshot()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["state"], r["up"], r["down"], r["duration"]),
                         ("closed", 4216, 4802, 298))
        self.assertEqual((r["access"], r["service"], r["family"]), ("socks5", "TLS (HTTPS)", "ipv4"))

    def test_close_without_open_still_makes_a_flow(self):
        self.store.feed("dante", DANTE_CLOSE_CF)
        r = self.store.snapshot()[0]
        self.assertEqual((r["down"], r["state"]), (13254, "closed"))
        self.assertAlmostEqual(r["t_start"], 1794323316.245222 - 669, places=2)

    def test_ss_and_http_hostnames_become_flows_with_a_class(self):
        self.store.feed("ss", SS_HOST)
        self.store.feed("ss", SS_GAUGE)
        self.store.feed("http", "CONNECT   Nov 10 15:08:25 [1]: Request (file descriptor 7): "
                                "CONNECT i.ytimg.com:443 HTTP/1.1")
        rows = {r["host"]: r for r in self.store.snapshot()}
        self.assertEqual(rows["rr1---sn-g5njvh-n8vl.googlevideo.com"]["class"], "video")
        self.assertEqual(rows["rr1---sn-g5njvh-n8vl.googlevideo.com"]["access"], "ss")
        self.assertEqual(rows["i.ytimg.com"]["access"], "http")
        self.assertEqual(self.store.summary()["container"]["ss_open_clients"], 22)

    def test_clash_state_is_enabled_as_soon_as_data_or_an_error_arrives(self):
        self.assertFalse(self.store.summary()["singbox"]["enabled"])
        self.store.clash_failed("boom")
        s = self.store.summary()["singbox"]
        self.assertEqual((s["enabled"], s["ok"], s["error"]), (True, False, "boom"))
        self.store.update_clash([clash_conn("a", host="s.youtube.com")])
        s = self.store.summary()["singbox"]
        self.assertEqual((s["enabled"], s["ok"], s["error"]), (True, True, ""))

    def test_clash_polls_add_update_and_close(self):
        self.store.update_clash([clash_conn("a", host="s.youtube.com", dst_ip="")], now=T0 + 1)
        r = self.store.snapshot()[0]
        self.assertEqual((r["state"], r["to_container"], r["host_src"]), ("open", True, "sniff"))
        self.store.update_clash([clash_conn("a", host="s.youtube.com", up=500, down=9000)], now=T0 + 5)
        self.assertEqual(self.store.snapshot()[0]["down"], 9000)
        self.store.update_clash([], now=T0 + 9)                       # gone -> closed, kept
        r = self.store.snapshot()[0]
        self.assertEqual((r["state"], r["down"]), ("closed", 9000))
        self.assertEqual(r["duration"], 9)

    def test_ip_to_host_map_names_ip_only_container_flows(self):
        self.store.update_clash([clash_conn("a", host="www.speedtest.net",
                                            dst_ip="173.194.151.65", chain=("direct",))])
        self.store.feed("dante", DANTE_OPEN)                           # dst 173.194.151.65
        row = [r for r in self.store.snapshot() if r["source"] == "container"][0]
        self.assertEqual((row["host"], row["host_src"], row["class"]),
                         ("www.speedtest.net", "ip-map", "test"))

    def test_join_by_destination_ip_and_time(self):
        self.store.update_clash([clash_conn("a", host="", dst_ip="173.194.151.65",
                                            start=1794323305.0)])
        self.store.feed("dante", DANTE_OPEN)
        rows = self.store.snapshot()
        self.assertEqual(len(rows), 1, "container flow must be merged, not listed twice")
        r = rows[0]
        self.assertTrue(r["seen_by_container"])
        self.assertEqual(r["access"], "socks5")
        self.assertEqual(r["container"]["access"], "socks5")

    def test_join_by_host_when_the_ip_is_unknown(self):
        self.store.update_clash([clash_conn("a", host="rr1---sn-g5njvh-n8vl.googlevideo.com",
                                            dst_ip="", start=1794306899.0)])
        self.store.feed("ss", SS_HOST)                                  # 13:34:59 local
        with patch.object(flows, "_local_epoch", lambda text, fmt: 1794306900.0):
            self.store.feed("ss", SS_HOST)
        self.assertTrue(any(r["seen_by_container"] for r in self.store.snapshot()
                            if r["source"] == "singbox"))

    def test_join_does_not_match_a_different_port_or_a_far_away_flow(self):
        self.store.update_clash([clash_conn("a", dst_ip="173.194.151.65", port="80",
                                            start=1794323305.0),
                                 clash_conn("b", dst_ip="173.194.151.65", port="443",
                                            start=1794323305.0 - 60)])
        self.store.feed("dante", DANTE_OPEN)
        sb = [r for r in self.store.snapshot() if r["source"] == "singbox"]
        self.assertTrue(all(r["seen_by_container"] is not True for r in sb))
        self.assertEqual(len([r for r in self.store.snapshot() if r["source"] == "container"]), 1)

    def test_not_seen_only_when_the_container_logs_are_alive_and_tcp(self):
        conn = clash_conn("a", dst_ip="198.51.100.9", start=T0)
        self.store.update_clash([conn])
        self.assertIsNone(self.store.snapshot()[0]["seen_by_container"])     # no log data yet
        self.store.feed("dante", DANTE_CLOSE_CF)                              # logs are alive
        sb = [r for r in self.store.snapshot() if r["source"] == "singbox"][0]
        self.assertIs(sb["seen_by_container"], False)
        self.store.update_clash([clash_conn("u", dst_ip="198.51.100.9", network="udp")])
        udp = [r for r in self.store.snapshot() if r["id"] == "c:u"][0]
        self.assertIsNone(udp["seen_by_container"], "UDP is not matched yet")

    def test_non_container_flows_are_never_flagged(self):
        self.store.feed("dante", DANTE_CLOSE_CF)
        self.store.update_clash([clash_conn("a", dst_ip="198.51.100.9", chain=("ServerNL",))])
        sb = [r for r in self.store.snapshot() if r["source"] == "singbox"][0]
        self.assertFalse(sb["to_container"])
        self.assertIsNone(sb["seen_by_container"])

    def test_hosts_view_and_summary(self):
        self.store.update_clash([
            clash_conn("a", host="s.youtube.com", dst_ip="", chain=("zapretDPI",), up=10, down=20),
            clash_conn("b", host="api.github.com", dst_ip="140.82.121.6", chain=("ServerNL",)),
            clash_conn("c", host="api.github.com", dst_ip="140.82.121.6", chain=("direct",))])
        hosts = {h["host"]: h for h in self.store.hosts_view()}
        self.assertEqual(hosts["api.github.com"]["flows"], 2)
        self.assertEqual(hosts["api.github.com"]["direct_or_other"], 2)
        self.assertEqual(hosts["s.youtube.com"]["to_container"], 1)
        sb = self.store.summary()["singbox"]
        self.assertEqual((sb["active"], sb["to_container"]), (3, 1))
        self.assertEqual(sb["by_outbound"], {"zapretDPI": 1, "ServerNL": 1, "direct": 1})

    def test_filters(self):
        self.store.feed("ss", SS_HOST)
        self.store.feed("ss", SS_IP)
        self.assertEqual(len(self.store.flows_view(cls="video")), 1)
        self.assertEqual(len(self.store.flows_view(q="142.251")), 1)
        self.assertEqual(len(self.store.flows_view(access="http")), 0)
        self.assertEqual(len(self.store.flows_view(limit=1)), 1)

    def test_size_limit_drops_the_oldest(self):
        small = flows.FlowStore(maxlen=3, ttl=10 ** 9, clock=lambda: self.now)
        for _ in range(6):
            small.feed("ss", SS_HOST)
        self.assertEqual(len(small.flows), 3)

    def test_ttl_expires_finished_flows_but_never_open_ones(self):
        clock = {"now": 1794323320.0}
        store = flows.FlowStore(ttl=60, clock=lambda: clock["now"])
        store.feed("dante", DANTE_CLOSE_CF)                         # closed at ...316
        store.feed("dante", DANTE_OPEN)                             # still open
        self.assertEqual(len(store.snapshot()), 2)                  # age 4 s: kept
        clock["now"] += 7200
        with patch.object(flows, "_local_epoch", lambda text, fmt: clock["now"]):
            store.feed("ss", SS_HOST)                               # triggers a trim
        states = sorted(r["state"] for r in store.snapshot())
        self.assertEqual(states, ["open", "seen"], "closed flow expired, open one kept")


class CollectorTests(unittest.TestCase):
    def wait_for(self, predicate, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    def test_tailer_follows_appends_and_survives_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sockd.log")
            Path(path).write_text(DANTE_CLOSE + "\n")
            store = flows.FlowStore(ttl=10 ** 9)
            tailer = flows.LogTailer(path, "dante", store, poll=0.02)
            tailer.start()
            try:
                self.assertTrue(self.wait_for(lambda: len(store.flows) == 1), "backfill")
                with open(path, "a") as handle:
                    handle.write(DANTE_CLOSE_CF + "\n")
                self.assertTrue(self.wait_for(lambda: len(store.flows) == 2), "append")
                os.rename(path, path + ".1")                               # rotation
                Path(path).write_text(DANTE_OPEN + "\n")
                self.assertTrue(self.wait_for(lambda: len(store.flows) == 3), "rotation")
            finally:
                tailer.stop()
                tailer.join(timeout=3)

    def test_tailer_waits_for_a_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "later.log")
            store = flows.FlowStore(ttl=10 ** 9)
            tailer = flows.LogTailer(path, "ss", store, poll=0.02)
            tailer.start()
            try:
                time.sleep(0.2)
                Path(path).write_text(SS_HOST + "\n")
                self.assertTrue(self.wait_for(lambda: len(store.flows) == 1))
            finally:
                tailer.stop()
                tailer.join(timeout=3)

    def test_poller_reports_errors_and_recovers(self):
        store = flows.FlowStore()
        calls = {"n": 0}

        def fetch(url, secret):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("connection refused")
            return [clash_conn("a", host="s.youtube.com")]
        poller = flows.ClashPoller(store, "http://x", "s", interval=0.02, fetch=fetch)
        poller.start()
        try:
            self.assertTrue(self.wait_for(lambda: store.clash["ok"] is True))
            self.assertEqual(store.clash["n"], 1)
        finally:
            poller.stop()
            poller.join(timeout=3)
        self.assertGreaterEqual(calls["n"], 2)

    def test_fetch_clash_sends_the_bearer_secret(self):
        seen = {}

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps({"connections": [clash_conn("a")]}).encode()

        def opener(request, timeout):
            seen["auth"] = request.get_header("Authorization")
            seen["url"] = request.full_url
            return Resp()
        got = flows.fetch_clash("http://sb:9090/", "sekret", opener=opener)
        self.assertEqual(len(got), 1)
        self.assertEqual(seen, {"auth": "Bearer sekret", "url": "http://sb:9090/connections"})


class PackagingTests(unittest.TestCase):
    def test_image_ships_the_module_and_the_rules(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("src/flows.py", dockerfile)
        self.assertRegex(dockerfile, r"COPY config/ /opt/webzapret/config/")
        self.assertTrue((ROOT / "config" / "traffic_classes.json").is_file())

    def test_env_example_documents_the_traffic_settings(self):
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        for key in ("SINGBOX_API_URL", "SINGBOX_API_SECRET", "SINGBOX_CONTAINER_OUTBOUND",
                    "TRAFFIC_BUFFER", "TRAFFIC_TTL"):
            self.assertIn(key + "=", text)

    def test_tab_is_wired_in_the_page(self):
        page = (ROOT / "src" / "panel" / "index.html").read_text(encoding="utf-8")
        self.assertIn('data-tab="traffic"', page)
        self.assertIn('id="page-traffic"', page)
        for route in ("/api/flows/summary", "/api/flows/hosts", "/api/flows?"):
            self.assertIn(route, page)


class HTTPTests(unittest.TestCase):
    def _serve(self, store):
        patches = [patch.object(panel, "FLOWS", store), patch.object(panel, "AUTH_USER", "")]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        server = panel.ThreadingHTTPServer(("127.0.0.1", 0), panel.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.addCleanup(stop)
        return server.server_port

    @staticmethod
    def _get(port, path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read())
        finally:
            conn.close()

    def test_endpoints(self):
        store = flows.FlowStore(ttl=10 ** 9, rules=flows.load_classes(
            str(ROOT / "config" / "traffic_classes.json")))
        store.feed("ss", SS_HOST)
        store.feed("dante", DANTE_CLOSE)
        port = self._serve(store)
        status, body = self._get(port, "/api/flows?limit=10")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["flows"]), 2)
        status, body = self._get(port, "/api/flows?class=video&access=ss")
        self.assertEqual([f["class"] for f in body["flows"]], ["video"])
        status, body = self._get(port, "/api/flows/hosts")
        self.assertEqual(status, 200)
        self.assertTrue(body["hosts"])
        status, body = self._get(port, "/api/flows/summary")
        self.assertEqual(body["container"]["access"], {"ss": 1, "socks5": 1})
        self.assertIn("unparsed", body["debug"])

    def test_bad_numeric_limit_is_not_a_server_error(self):
        store = flows.FlowStore(ttl=10 ** 9)
        store.feed("ss", SS_HOST)
        port = self._serve(store)
        for bad in ("abc", "-5", "99999999", ""):
            status, body = self._get(port, "/api/flows?limit=" + bad)
            self.assertEqual(status, 200, bad)
            self.assertLessEqual(len(body["flows"]), 1000)

    def test_unavailable_module_is_a_clean_503(self):
        port = self._serve(None)
        status, body = self._get(port, "/api/flows")
        self.assertEqual(status, 503)
        self.assertFalse(body["ok"])


if __name__ == "__main__":
    unittest.main()


class EgressVerdictTest(unittest.TestCase):
    """dante tuple + nfqws trace + conntrack -> verdict on the flow row."""

    def test_reset_after_hello_is_reported(self):
        t = [1794323305.0]
        store = flows.FlowStore(clock=lambda: t[0])
        store.feed("dante", "Nov 10 15:08:25 (1794323305.804211) danted[1]: info: pass(1): "
                   "tcp/connect [: 172.22.0.1.56302 172.22.0.4.1080 -> 172.22.0.4.50042 "
                   "173.194.18.71.443")
        for line in ("packet: id=1 len=60 mark=0 ifin=(0) ifout=eth0(2)",
                      "IP4: 172.22.0.4 => 173.194.18.71 proto=tcp ttl=64 sport=50042 "
                      "dport=443 flags=S seq=5 ack_seq=0",
                      "hostname: x.googlevideo.com",
                      "dpi desync src=172.22.0.4:50042 dst=173.194.18.71:443 "
                      "track_direction=out fixed_direction=out connection_proto=tls "
                      "payload_type=tls_client_hello"):
            store.nfq.feed(line)
        store.ct.ingest("ipv4 2 tcp 6 9 CLOSE src=172.22.0.4 dst=173.194.18.71 sport=50042 "
                        "dport=443 packets=5 bytes=900 src=173.194.18.71 dst=172.22.0.4 "
                        "sport=443 dport=50042 packets=1 bytes=40 mark=0 use=1", now=t[0])
        t[0] += 2
        row = store.snapshot()[0]
        self.assertEqual(row["verdict"]["code"], "reset_after_hello")
        self.assertEqual(row["host"], "x.googlevideo.com")
        self.assertTrue(row["timeline"])
        intel = store.intel()
        self.assertEqual(intel["bad"], 1)
        json.dumps(row)                       # must be serialisable for the API

    def test_no_evidence_means_no_verdict(self):
        store = flows.FlowStore(clock=lambda: time.mktime((2026, 11, 13, 10, 44, 5, 0, 0, -1)))
        store.feed("http", "CONNECT   Nov 13 10:44:03.958 [87]: Request (file descriptor 16): "
                   "CONNECT s.youtube.com:443 HTTP/1.1")
        self.assertNotIn("verdict", store.snapshot()[0])
