import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src" / "panel"))
import blockcheck
import panel


class ScheduleHTTPTests(unittest.TestCase):
    def test_rejected_schedule_preserves_saved_configuration(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(panel, "BCW_STATE_DIR", tmp), \
                patch.object(panel, "bcw", blockcheck), \
                patch.object(panel, "AUTH_USER", ""), \
                patch.dict(os.environ, {}, clear=True):
            server = panel.ThreadingHTTPServer(("127.0.0.1", 0), panel.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=5)
            try:
                def post(payload):
                    connection.request("POST", "/api/bcw/schedule",
                                       json.dumps(payload),
                                       {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    return response.status, json.loads(response.read())

                status, body = post({"enabled": True, "mode": "daily", "at": "05:30"})
                self.assertEqual(status, 200)
                self.assertTrue(body["ok"])
                path = Path(tmp) / blockcheck.SCHEDULE_FILE
                before = path.read_bytes()
                status, body = post({"at": "25:99"})
                self.assertEqual(status, 400)
                self.assertFalse(body["ok"])
                self.assertTrue(body["errors"])
                self.assertEqual(path.read_bytes(), before)
                saved, _, errors = blockcheck.load_schedule(tmp)
                self.assertEqual(errors, [])
                self.assertEqual(saved["at"], "05:30")
                self.assertTrue(saved["enabled"])
            finally:
                connection.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


class ImportHTTPTests(unittest.TestCase):
    """POST /api/bcw/import — regression: bcw_import() lacked a `rows` parameter,
    so "Import selected" died with TypeError and the plain call with
    UnboundLocalError."""

    ROW = {"protocol": "HTTPS/TLS1.2", "median_share": 0.9, "passes_ok": 3,
           "passes_total": 3, "median_latency_ms": 120, "success_rate": 1.0,
           "admits": ["Good"], "observed": "Bytes", "working": True,
           "args": "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls"}

    def _env(self, tmp):
        state = Path(tmp) / "state"
        state.mkdir()
        catalog = Path(tmp) / "strategies.json"
        catalog.write_text(json.dumps({"_comment": "keep", "strategies": []}))
        last = {"ok": True, "run_id": "20260101-000000",
                "domains": [{"domain": "youtube.com", "block_type": "SNI blocked",
                             "working": [dict(self.ROW)]}]}
        (state / blockcheck.LAST_RUN_FILE).write_text(json.dumps(last))
        return state, catalog

    def _serve(self, state, catalog):
        patches = [patch.object(panel, "BCW_STATE_DIR", str(state)),
                   patch.object(panel, "STRATEGIES_FILE", str(catalog)),
                   patch.object(panel, "WZ_LOG", str(state)),
                   patch.object(panel, "bcw", blockcheck),
                   patch.object(panel, "bcw_ready", lambda: (True, "")),
                   patch.object(panel, "AUTH_USER", "")]
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
    def _post(port, payload):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("POST", "/api/bcw/import", json.dumps(payload),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_import_selected_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, catalog = self._env(tmp)
            port = self._serve(state, catalog)
            status, body = self._post(port, {"rows": [
                {"protocol": "HTTPS/TLS1.2", "args": self.ROW["args"]}]})
            self.assertEqual(status, 200, body)
            self.assertTrue(body["ok"])
            saved = json.loads(catalog.read_text())
            self.assertEqual(saved["_comment"], "keep")
            self.assertEqual([s["id"] for s in saved["strategies"]], body["ids"])
            self.assertTrue(saved["strategies"][0]["no_reasm"])

    def test_import_all_working_of_the_last_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, catalog = self._env(tmp)
            port = self._serve(state, catalog)
            status, body = self._post(port, {"protocols": ["tls12"], "limit": 5})
            self.assertEqual(status, 200, body)
            self.assertEqual(body["count"], 1)

    def test_import_direct_call_without_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, catalog = self._env(tmp)
            self._serve(state, catalog)
            res = panel.bcw_import(run_id=None)
            self.assertTrue(res["ok"], res)


class CollectStateTests(unittest.TestCase):
    """_bcw_collect(): job state shown (and coloured) in the UI."""

    class FakeProc:
        def __init__(self, payload, rc=0):
            import io
            self.stdout = io.BytesIO(payload)
            self._rc = rc

        def wait(self):
            return self._rc

    def _collect(self, result, rc=0):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "runs" / "r1"
            run_dir.mkdir(parents=True)
            job = {"state": "running", "run_id": "r1", "run_dir": str(run_dir),
                   "pid": 1}
            payload = json.dumps(result).encode() if result is not None else b"noise"
            with patch.object(panel, "BCW_STATE_DIR", tmp), \
                    patch.object(panel, "BCW_RUNS_DIR", str(Path(tmp) / "runs")), \
                    patch.object(panel, "WZ_LOG", tmp), \
                    patch.object(panel, "bcw", blockcheck):
                panel._bcw_collect(self.FakeProc(payload, rc), job)
            saved_job = blockcheck.load_job(tmp)
            last = blockcheck.read_json(Path(tmp) / blockcheck.LAST_RUN_FILE)
            return saved_job, last

    def test_success_is_done(self):
        job, last = self._collect({"ok": True, "success": True, "errors": [],
                                   "domains": [{"domain": "d", "working": [{}]}]})
        self.assertEqual(job["state"], "done")
        self.assertEqual(job["error"], "")
        self.assertIsNotNone(last)

    def test_clean_run_without_candidates_is_done(self):
        job, _ = self._collect({"ok": True, "success": False, "errors": [],
                                "domains": [{"domain": "d", "working": []}]})
        self.assertEqual(job["state"], "done")

    def test_errors_without_a_result_are_an_error_and_replace_the_stale_last_run(self):
        job, last = self._collect({"ok": True, "success": False,
                                   "errors": ["d: scan produced no readable report"],
                                   "domains": [{"domain": "d", "working": []}]})
        self.assertEqual(job["state"], "error")
        self.assertIn("no readable report", job["error"])
        self.assertEqual(last["errors"], ["d: scan produced no readable report"])

    def test_preflight_failure_message_reaches_the_job(self):
        job, last = self._collect({"ok": False, "error": "preflight failed: FAIL nft"},
                                  rc=1)
        self.assertEqual(job["state"], "error")
        self.assertIn("preflight failed", job["error"])
        self.assertIsNone(last)

    def test_no_output_at_all_is_an_error_with_a_hint(self):
        job, _ = self._collect(None, rc=1)
        self.assertEqual(job["state"], "error")
        self.assertIn("blockcheck.log", job["error"])


if __name__ == "__main__":
    unittest.main()
