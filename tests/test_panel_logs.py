import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "panel"))
import panel  # noqa: E402  (stdlib-only, safe to import standalone)


class PanelLogExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="wz-panel-logs-")
        panel.WZ_LOG = cls.tmp

    def setUp(self):
        # One small module log per module so the export covers every source.
        # Timestamps deliberately out of file order to verify global time-sort.
        self.files = {
            "actions": "[2026-09-10T00:00:00Z] [apply] strategy 'standard' activated\n",
            "ss-server": "[2026-09-10T00:00:01Z] accept: 1.2.3.4:5555\n",
            "sockd": "[2026-09-10T00:00:02Z] connection from 1.2.3.4:8888 to 93.184.216.34:443\n",
            "nfqws": "[2026-09-10T00:00:03Z] connection: 1.2.3.4:6000 -> 93.184.216.34:443\n"
                     "    continuation line without its own timestamp\n",
        }
        for mod, txt in self.files.items():
            (Path(self.tmp) / (mod + ".log")).write_text(txt, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_export_contains_all_modules(self):
        out = panel.export_logs()
        # header lists every module
        modules_line = next(l for l in out.splitlines() if l.startswith("# modules:"))
        for mod in panel.LOG_MODULES:
            self.assertIn(mod, modules_line)
        # per-module size summary lines
        for mod in panel.LOG_MODULES:
            self.assertTrue(any(l.startswith("# %-10s" % mod) for l in out.splitlines()))
        # content tagged with its module (actions already carries its own tags)
        self.assertIn("[ss-server] [2026-09-10T00:00:01Z] accept: 1.2.3.4:5555", out)
        self.assertIn("[nfqws] [2026-09-10T00:00:03Z] connection: 1.2.3.4:6000 -> 93.184.216.34:443", out)
        self.assertIn("[apply] strategy 'standard' activated", out)

    def test_export_empty_log_dir(self):
        import os
        for mod, _ in list(self.files.items()):
            os.unlink(os.path.join(panel.WZ_LOG, mod + ".log"))
        out = panel.export_logs()
        self.assertIn("(no log entries available across modules)", out)

    def test_export_is_time_ordered_and_inherits_timestamps(self):
        out = panel.export_logs()
        idx = [out.index(ln) for ln in (
            "[2026-09-10T00:00:00Z] [apply] strategy 'standard' activated",
            "[ss-server] [2026-09-10T00:00:01Z] accept: 1.2.3.4:5555",
            "[sockd] [2026-09-10T00:00:02Z] connection from 1.2.3.4:8888 to 93.184.216.34:443",
            "[nfqws] [2026-09-10T00:00:03Z] connection: 1.2.3.4:6000 -> 93.184.216.34:443",
            "[nfqws]     continuation line without its own timestamp",
        )]
        self.assertEqual(idx, sorted(idx), "merged export must be time-ordered")

    def test_merged_log_tail(self):
        all_lines = panel.merged_log(200)
        self.assertIn("[sockd] [2026-09-10T00:00:02Z] connection from 1.2.3.4:8888", all_lines)
        last = panel.merged_log(1).strip()
        self.assertEqual(last, "[nfqws]     continuation line without its own timestamp")


if __name__ == "__main__":
    unittest.main()