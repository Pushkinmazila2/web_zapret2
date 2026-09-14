import json
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "panel"))
import panel  # noqa: E402  (stdlib-only, safe to import standalone)


class PanelStrategyImportTests(unittest.TestCase):
    """Imported TLS ClientHello strategies must be flagged no_reasm so nfqws
    does not buffer/drop the whole connection waiting for the whole ClientHello
    (a lost segment hangs the connection forever on low-MSS paths)."""

    def _import(self, payload, domain="youtube.com"):
        strategies_file = str(Path(self.tmp) / "strategies.json")
        panel.STRATEGIES_FILE = strategies_file
        res = panel.import_strategy_from_json({
            "domain": domain,
            "timestamp": "2026-09-12",
            "strategies": [{
                "protocol": "HTTPS/TLS1.2",
                "args": payload,
                "success_rate": 1.0,
                "median_latency_ms": 100,
            }],
        })
        self.assertTrue(res.get("ok"), res)
        saved = json.loads(Path(strategies_file).read_text(encoding="utf-8"))
        return saved["strategies"][0]

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wz-panel-import-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tls_client_hello_import_gets_no_reasm(self):
        entry = self._import("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls")
        self.assertTrue(entry.get("no_reasm"))

    def test_tcp443_import_gets_no_reasm(self):
        entry = self._import("--filter-tcp=443 --lua-desync=multisplit:pos=2")
        self.assertTrue(entry.get("no_reasm"))

    def test_http_import_keeps_reasm(self):
        entry = self._import("--filter-tcp=80 --payload=http_req --lua-desync=fake:blob=fake_default_http",
                             domain="example.org")
        self.assertNotIn("no_reasm", entry)


if __name__ == "__main__":
    unittest.main()