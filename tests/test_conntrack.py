"""conntrack parser/tracker on lines in the kernel's /proc/net/nf_conntrack format."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import conntrack

EST = ("ipv4     2 tcp      6 431998 ESTABLISHED src=172.22.0.4 dst=173.194.18.71 "
       "sport=50042 dport=443 packets=12 bytes=3100 src=173.194.18.71 dst=172.22.0.4 "
       "sport=443 dport=50042 packets=20 bytes=%d [ASSURED] mark=0 zone=0 use=2")
SYN = ("ipv4     2 tcp      6 117 SYN_SENT src=172.22.0.4 dst=1.2.3.4 sport=40000 "
       "dport=443 [UNREPLIED] src=1.2.3.4 dst=172.22.0.4 sport=443 dport=40000 "
       "mark=0 zone=0 use=2")
RST = ("ipv4     2 tcp      6 9 CLOSE src=172.22.0.4 dst=1.2.3.4 sport=40001 dport=443 "
       "packets=5 bytes=900 src=1.2.3.4 dst=172.22.0.4 sport=443 dport=40001 "
       "packets=1 bytes=40 mark=0 zone=0 use=1")
NOACCT = ("ipv4     2 tcp      6 100 ESTABLISHED src=172.22.0.4 dst=9.9.9.9 sport=40002 "
          "dport=443 src=9.9.9.9 dst=172.22.0.4 sport=443 dport=40002 [ASSURED] "
          "mark=0 zone=0 use=2")
UDP = "ipv4     2 udp      17 20 src=1.1.1.1 dst=2.2.2.2 sport=1 dport=2 src=2.2.2.2 dst=1.1.1.1 sport=2 dport=1 mark=0 use=1"


class ParseTest(unittest.TestCase):
    def test_established_with_acct(self):
        e = conntrack.parse_line(EST % 16000)
        self.assertEqual((e["state"], e["sport"], e["dport"], e["reply_bytes"]),
                         ("ESTABLISHED", 50042, 443, 16000))
        self.assertTrue(e["assured"] and not e["unreplied"])

    def test_syn_unreplied(self):
        e = conntrack.parse_line(SYN)
        self.assertEqual(e["state"], "SYN_SENT")
        self.assertTrue(e["unreplied"])
        self.assertIsNone(e["reply_bytes"])

    def test_udp_ignored(self):
        self.assertIsNone(conntrack.parse_line(UDP))


class TrackerTest(unittest.TestCase):
    def test_timeline_growth_and_gone(self):
        ct = conntrack.Conntrack()
        ct.ingest(SYN, now=100.0)
        ct.ingest(EST % 5000, now=101.0)
        ct.ingest(EST % 16000, now=102.0)
        ct.ingest(EST % 16000, now=110.0)
        rec = ct.get(50042, "173.194.18.71", 443)
        self.assertEqual(rec["reply_bytes"], 16000)
        self.assertEqual(rec["reply_grew_at"], 102.0)        # frozen since t=102
        ct.ingest("", now=120.0)
        self.assertEqual(ct.get(50042, "173.194.18.71", 443)["gone_at"], 120.0)
        self.assertTrue(ct.acct)

    def test_state_history(self):
        ct = conntrack.Conntrack()
        ct.ingest(SYN, now=1.0)
        ct.ingest(SYN.replace("SYN_SENT", "ESTABLISHED"), now=2.0)
        states = [s for _, s in ct.get(40000, "1.2.3.4", 443)["states"]]
        self.assertEqual(states, ["SYN_SENT", "ESTABLISHED"])

    def test_without_acct(self):
        ct = conntrack.Conntrack()
        ct.ingest(NOACCT, now=1.0)
        self.assertFalse(ct.acct)
        self.assertIsNone(ct.get(40002, "9.9.9.9", 443)["reply_bytes"])

    def test_ignore_listen_ports(self):
        ct = conntrack.Conntrack(ignore_dports=[443])
        ct.ingest(EST % 1, now=1.0)
        self.assertEqual(len(ct.records), 0)


if __name__ == "__main__":
    unittest.main()
