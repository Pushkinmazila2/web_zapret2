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

    def test_leading_noise_is_tolerated(self):
        """log_module() lines that once leaked into harness stdout (before AND
        after the JSON) must not break the result — the panel raw_decodes the
        first JSON object, so a SUCCESSFUL download is never reported as
        'malformed output'."""
        real_run = panel.subprocess.run
        payload = ('[2026-09-15T13:26:30Z] [test] starting isolated nfqws (queue 202)\n'
                   '[2026-09-15T13:26:31Z] [test] test nfqws started (pid 197)\n'
                   '[2026-09-15T13:26:32Z] [test] yt-dlp attempt: format=\'bv*[height<=360]+ba/b/worst\'\n'
                   + json.dumps({"ok": True, "success": True, "strategy": "standard",
                                 "rc": 0, "reason": "download completed (12577365 bytes)",
                                 "bytes": 12577365, "files": ["pfsRxTjNGvo.f396.mp4"],
                                 "log": "[youtube] Extracting URL: ..."}))
        noise = ('[2026-09-15T13:26:32Z] [test] yt-dlp finished rc=0\n'
                 '[2026-09-15T13:26:33Z] [test] stopping test nfqws (pid 197)\n')

        def fake_run(cmd, **kw):
            class R:
                returncode = 0
                stdout = payload + noise
                stderr = ""
            return R()
        panel.subprocess.run = fake_run
        self.addCleanup(lambda: setattr(panel.subprocess, "run", real_run))
        res = panel.test_strategy("standard", "https://example.com/v")
        self.assertTrue(res.get("ok"), res)
        self.assertTrue(res.get("success"), res)
        self.assertEqual(res.get("bytes"), 12577365)


class PanelStrategyDeleteTests(unittest.TestCase):
    """POST /api/strategy/delete: removes a strategy from the catalog.
    The built-in 'none' and the currently ACTIVE strategy are protected."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wz-panel-del-")
        self.strategies_file = str(Path(self.tmp) / "strategies.json")
        self.state_dir = str(Path(self.tmp) / "state")
        Path(self.state_dir).mkdir()
        panel.STRATEGIES_FILE = self.strategies_file
        panel.WZ_STATE = self.state_dir
        self._write_catalog([
            {"id": "standard", "name": "Standard", "nfqws_opt": "--dpi-desync=fake"},
            {"id": "custom_x", "name": "Custom x",
             "lua_opt": "--payload=tls_client_hello --lua-desync=fake"},
            {"id": "custom_y", "name": "Custom y",
             "lua_opt": "--payload=tls_client_hello --lua-desync=multisplit:pos=2"},
            {"id": "none", "name": "Disabled", "nfqws_opt": ""},
        ])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_catalog(self, strategies):
        Path(self.strategies_file).write_text(
            json.dumps({"strategies": strategies}), encoding="utf-8")

    def _catalog_ids(self):
        data = json.loads(Path(self.strategies_file).read_text(encoding="utf-8"))
        return [s["id"] for s in data["strategies"]]

    def test_delete_unknown_rejected(self):
        res = panel.delete_strategy("does_not_exist")
        self.assertFalse(res.get("ok"))
        self.assertIn("unknown strategy", res.get("error", ""))

    def test_delete_none_rejected(self):
        res = panel.delete_strategy("none")
        self.assertFalse(res.get("ok"))
        self.assertIn("'none'", res.get("error", ""))
        self.assertIn("none", self._catalog_ids())

    def test_delete_active_rejected(self):
        (Path(self.state_dir) / "strategy").write_text("custom_x\n", encoding="utf-8")
        self.assertEqual(panel.active_strategy(), "custom_x")
        res = panel.delete_strategy("custom_x")
        self.assertFalse(res.get("ok"))
        self.assertIn("ACTIVE", res.get("error", ""))
        self.assertIn("custom_x", self._catalog_ids())

    def test_delete_success(self):
        res = panel.delete_strategy("custom_x")
        self.assertTrue(res.get("ok"), res)
        self.assertEqual(res.get("id"), "custom_x")
        self.assertEqual(res.get("strategies"), ["standard", "custom_y", "none"])
        self.assertNotIn("custom_x", self._catalog_ids())

    def test_delete_is_idempotent_after_removal(self):
        panel.delete_strategy("custom_x")
        res = panel.delete_strategy("custom_x")
        self.assertFalse(res.get("ok"))
        self.assertIn("unknown strategy", res.get("error", ""))


if __name__ == "__main__":
    unittest.main()