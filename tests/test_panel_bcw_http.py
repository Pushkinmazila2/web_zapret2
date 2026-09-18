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


if __name__ == "__main__":
    unittest.main()
