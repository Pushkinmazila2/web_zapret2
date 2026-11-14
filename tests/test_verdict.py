"""Verdict rules + TSPU dossier."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import verdict


def ct(**kw):
    base = {"first": 100.0, "gone_at": None, "states": [(100.0, "SYN_SENT")],
            "reply_bytes": 0, "reply_packets": 0, "orig_bytes": 600, "reply_grew_at": None,
            "unreplied": False, "assured": True, "state": "ESTABLISHED", "sport": 1,
            "dst_ip": "1.1.1.1", "dst_port": 443}
    base.update(kw)
    return base


def nfq(**kw):
    base = {"first": 100.0, "hello_ts": 100.5, "syn": 1, "retrans": 0, "sni": "a.example",
            "actions": ["fake_2_1", "multidisorder_2_2"], "desynced": True}
    base.update(kw)
    return base


class JudgeTest(unittest.TestCase):
    def test_no_reply(self):
        v = verdict.judge(ct(state="SYN_SENT", unreplied=True, assured=False), nfq(syn=3), 110)
        self.assertEqual(v["code"], "no_reply")

    def test_connecting_is_not_yet_a_verdict(self):
        v = verdict.judge(ct(state="SYN_SENT", unreplied=True, assured=False), None, 102)
        self.assertEqual(v["code"], "connecting")

    def test_stall_after_hello(self):
        v = verdict.judge(ct(reply_bytes=0), nfq(), 115)
        self.assertEqual((v["code"], v["confidence"]), ("stall_after_hello", "high"))
        self.assertGreaterEqual(v["stalled_for"], 8)

    def test_reset_after_hello(self):
        v = verdict.judge(ct(state="CLOSE", reply_bytes=40), nfq(), 105)
        self.assertEqual(v["code"], "reset_after_hello")

    def test_reset_mid_transfer(self):
        v = verdict.judge(ct(state="CLOSE", reply_bytes=50000), nfq(), 105)
        self.assertEqual(v["code"], "reset_mid")

    def test_cutoff_16k(self):
        v = verdict.judge(ct(reply_bytes=16384, reply_grew_at=102.0), nfq(), 120)
        self.assertEqual(v["code"], "cutoff_suspected")

    def test_flowing_and_ok(self):
        self.assertEqual(verdict.judge(ct(reply_bytes=900000, reply_grew_at=119.0), nfq(),
                                       120)["code"], "flowing")
        self.assertEqual(verdict.judge(ct(state="TIME_WAIT", reply_bytes=900000, gone_at=130.0),
                                       nfq(), 140)["code"], "ok")

    def test_no_acct_is_honest(self):
        v = verdict.judge(ct(reply_bytes=None), nfq(), 120)
        self.assertEqual(v["code"], "established")
        self.assertEqual(v["confidence"], "low")

    def test_no_conntrack(self):
        self.assertEqual(verdict.judge(None, None, 1)["code"], "unknown")

    def test_timeline_ordered(self):
        tl = verdict.timeline(ct(reply_grew_at=102.0), nfq(), 120)
        self.assertEqual([e["dt"] for e in tl], sorted(e["dt"] for e in tl))
        self.assertTrue(any("SNI a.example" in e["text"] for e in tl))


class IntelTest(unittest.TestCase):
    def row(self, host, ip, code, desynced=True):
        return {"host": host, "dst_ip": ip, "verdict": {"code": code},
                "egress": {"desynced": desynced, "actions": ["fake_2_1"] if desynced else []}}

    def test_sni_filter_hypothesis(self):
        rows = [self.row("good.example", "9.9.9.9", "ok"),
                self.row("bad.example", "9.9.9.9", "reset_after_hello")]
        intel = verdict.build_intel(rows)
        kinds = [h["kind"] for h in intel["hypotheses"]]
        self.assertIn("sni_filter", kinds)
        self.assertIn("rst_injection", kinds)
        self.assertEqual(intel["bad"], 1)

    def test_strategy_effect(self):
        rows = [self.row("a", "1.1.1.1", "ok") for _ in range(5)] + \
               [self.row("b", "2.2.2.2", "stall_after_hello", desynced=False) for _ in range(5)]
        kinds = [h["kind"] for h in verdict.build_intel(rows)["hypotheses"]]
        self.assertIn("strategy_effect", kinds)

    def test_ignores_undecided(self):
        intel = verdict.build_intel([self.row("a", "1.1.1.1", "connecting")])
        self.assertEqual(intel["judged"], 0)


if __name__ == "__main__":
    unittest.main()
