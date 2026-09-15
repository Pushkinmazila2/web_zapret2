import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "panel"))
import panel  # noqa: E402  (stdlib-only, safe to import standalone)


class PanelStrategyTestTests(unittest.TestCase):
    """Strategy testing API: must validate input, call the wz-test.sh harness
    with the right arguments and surface its JSON result (the harness runs the
    strategy on an ISOLATED test nfqws; the live nfqws is never touched)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="wz-panel-test-")
        cls.strategies_file = str(Path(cls.tmp) / "strategies.json")
        panel.STRATEGIES_FILE = cls.strategies_file
        Path(cls.strategies_file).write_text(json.dumps({"strategies": [
            {"id": "standard", "name": "Standard", "nfqws_opt": "--filter-tcp=443 --dpi-desync=fake"},
            {"id": "custom_x", "name": "Custom x", "lua_opt": "--payload=tls_client_hello --lua-desync=fake"},
            {"id": "none", "name": "Disabled", "nfqws_opt": ""},
        ]}), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _mock_run(self, payload, rc=0):
        calls = {}
        real_run = panel.subprocess.run

        def fake_run(cmd, **kw):
            calls["cmd"] = cmd
            calls["parent"] = kw.get("parent")
            class R:
                returncode = rc
                stdout = json.dumps(payload)
                stderr = ""
            return R()
        panel.subprocess.run = fake_run
        self.addCleanup(lambda: setattr(panel.subprocess, "run", real_run))
        return calls

    def test_unknown_strategy_rejected(self):
        res = panel.test_strategy("does_not_exist", "https://example.com/v")
        self.assertFalse(res.get("ok"))
        self.assertIn("unknown strategy", res.get("error", ""))

    def test_bad_url_rejected(self):
        # NOTE: an empty url falls back to TEST_YTDLP_URL (see
        # test_default_url_used_when_empty); only non-empty bad values error.
        for url in ("ftp://example.com/v", "not a url", "x" * 3000):
            with self.subTest(url=url[:20]):
                res = panel.test_strategy("standard", url)
                self.assertFalse(res.get("ok"))
                self.assertIn("URL", res.get("error", ""))

    def test_harness_called_with_args_and_result_surfaced(self):
        payload = {"ok": True, "success": True, "strategy": "standard",
                   "url": "https://www.youtube.com/watch?v=x", "timeout": 77,
                   "took_s": 9.1, "rc": 0, "reason": "download completed",
                   "bytes": 1234, "files": ["x.m4a"], "log": "ok"}
        calls = self._mock_run(payload)
        res = panel.test_strategy("standard", "https://www.youtube.com/watch?v=x", 77)
        self.assertTrue(res.get("ok"))
        self.assertTrue(res.get("success"))
        self.assertEqual(calls["cmd"][0], panel.WZ_TEST)
        self.assertEqual(calls["cmd"][1:], ["standard", "https://www.youtube.com/watch?v=x", "77"])
        self.assertEqual(res["bytes"], 1234)

    def test_timeout_clamped(self):
        calls = self._mock_run({"ok": True, "success": False, "rc": 124,
                                "reason": "timeout", "log": ""})
        panel.test_strategy("standard", "https://example.com/v", 5)
        self.assertEqual(calls["cmd"][3], "10")     # below min -> clamp up
        panel.test_strategy("standard", "https://example.com/v", 99999)
        self.assertEqual(calls["cmd"][3], "600")    # above max -> clamp down
        panel.test_strategy("standard", "https://example.com/v", "bogus")
        self.assertEqual(calls["cmd"][3], str(panel.TEST_YTDLP_TIMEOUT))

    def test_default_url_used_when_empty(self):
        calls = self._mock_run({"ok": True, "success": False, "rc": 1,
                                "reason": "failed", "log": ""})
        panel.test_strategy("custom_x", "", None)
        self.assertEqual(calls["cmd"][2], panel.TEST_YTDLP_URL)

    def test_malformed_harness_output(self):
        real_run = panel.subprocess.run

        def fake_run(cmd, **kw):
            class R:
                returncode = 1
                stdout = "definitely not json"
                stderr = ""
            return R()
        panel.subprocess.run = fake_run
        self.addCleanup(lambda: setattr(panel.subprocess, "run", real_run))
        res = panel.test_strategy("standard", "https://example.com/v")
        self.assertFalse(res.get("ok"))
        self.assertIn("malformed", res.get("error", ""))

    def test_harness_timeout(self):
        real_run = panel.subprocess.run

        def fake_run(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 0))
        panel.subprocess.run = fake_run
        self.addCleanup(lambda: setattr(panel.subprocess, "run", real_run))
        res = panel.test_strategy("standard", "https://example.com/v")
        self.assertFalse(res.get("ok"))
        self.assertIn("timed out", res.get("error", ""))


if __name__ == "__main__":
    unittest.main()