"""nfqtrace against a REAL nfqws2 --debug=1 log (tests/fixtures/nfqws_sample.log)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import nfqtrace

SAMPLE = ROOT / "tests" / "fixtures" / "nfqws_sample.log"


class RealSampleTest(unittest.TestCase):
    def setUp(self):
        self.t = [100.0]
        self.tr = nfqtrace.NfqTrace(clock=lambda: self.t[0])
        for line in SAMPLE.read_text(encoding="utf-8").splitlines():
            self.tr.feed(line)

    def test_clienthello_flow(self):
        rec = self.tr.get(50042, "173.194.18.71", 443)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["sni"], "r2---sn-4g5lzns7.googlevideo.com")
        self.assertEqual(rec["l7"], "tls")
        self.assertEqual(rec["profile"], "2 noname")
        self.assertTrue(rec["desynced"])
        self.assertEqual(rec["actions"], ["fake_2_1", "multidisorder_2_2"])
        self.assertEqual(rec["tls"]["ech"], "present")
        self.assertEqual(rec["tls"]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(rec["tls"]["versions"], ["GREASE", "TLS 1.3", "TLS 1.2"])
        self.assertEqual(rec["splits"][0]["pos"], ["1", "1728"])
        self.assertEqual(rec["parts"], 3)
        self.assertEqual(rec["fakes"], 1)
        self.assertEqual(rec["dropped"], 1)
        self.assertIsNotNone(rec["hello_ts"])

    def test_plain_handshake_flow_untouched(self):
        rec = self.tr.get(52904, "173.194.18.71", 443)
        self.assertEqual(rec["syn"], 1)
        self.assertFalse(rec["desynced"])
        self.assertIsNone(rec["hello_ts"])
        self.assertEqual(rec["sni"], "")

    def test_syn_retransmit_counted(self):
        pkt = ("IP4: 172.22.0.4 => 1.2.3.4 proto=tcp ttl=64 sport=40000 dport=443 "
               "flags=S seq=777 ack_seq=0")
        for _ in range(3):
            self.tr.feed("packet: id=9 len=60 mark=00000000 ifin=(0) ifout=eth0(2)")
            self.tr.feed(pkt)
        rec = self.tr.get(40000, "1.2.3.4", 443)
        self.assertEqual((rec["syn"], rec["retrans"]), (3, 2))

    def test_find_by_dst_window(self):
        found = self.tr.find_by_dst("173.194.18.71", 443, 90, 110)
        self.assertEqual(sorted(r["sport"] for r in found), [50042, 52904])
        self.assertEqual(self.tr.find_by_dst("173.194.18.71", 443, 0, 50), [])


if __name__ == "__main__":
    unittest.main()
