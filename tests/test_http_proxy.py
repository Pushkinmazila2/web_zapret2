import http.server
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "panel"))
import panel  # noqa: E402


class TinyproxyConfigRenderTests(unittest.TestCase):
    """Test rendering of tinyproxy.conf template under various environment settings."""

    def test_render_default_no_auth(self):
        template = (ROOT / "config" / "tinyproxy.conf").read_text(encoding="utf-8")
        rendered = template.replace("__HTTP_PORT__", "8888").replace("__AUTH__", "")
        self.assertIn("Port 8888", rendered)
        self.assertIn("User proxy", rendered)
        self.assertIn("Group proxy", rendered)
        self.assertIn("DisableViaHeader Yes", rendered)
        self.assertNotIn("BasicAuth", rendered)

    def test_render_with_basic_auth(self):
        template = (ROOT / "config" / "tinyproxy.conf").read_text(encoding="utf-8")
        auth = "BasicAuth testuser testpass"
        rendered = template.replace("__HTTP_PORT__", "8085").replace("__AUTH__", auth)
        self.assertIn("Port 8085", rendered)
        self.assertIn("BasicAuth testuser testpass", rendered)


class PanelHTTPConnectorStatusTests(unittest.TestCase):
    """Test that panel.py correctly reports the HTTP connector status and endpoints."""

    def test_panel_services_and_modules(self):
        self.assertIn("tinyproxy", panel.SERVICES)
        self.assertIn("tinyproxy", panel.LOG_MODULES)

    def test_status_connect_http(self):
        s = panel.status()
        self.assertIn("connect", s)
        self.assertIn("http", s["connect"])
        http_info = s["connect"]["http"]
        self.assertEqual(http_info["port"], panel.HTTP_LISTEN_PORT)
        self.assertEqual(http_info["auth"], "none")

    def test_status_connect_http_with_auth(self):
        old_user, old_pass = panel.HTTP_USER, panel.HTTP_PASSWORD
        try:
            panel.HTTP_USER = "singuser"
            panel.HTTP_PASSWORD = "singpass"
            s = panel.status()
            self.assertEqual(s["connect"]["http"]["auth"], "basic")
        finally:
            panel.HTTP_USER = old_user
            panel.HTTP_PASSWORD = old_pass


class TinyproxyLiveProxyTests(unittest.TestCase):
    """Live proxy tests (GET and CONNECT) when tinyproxy is available in the environment."""

    @classmethod
    def setUpClass(cls):
        cls.has_tinyproxy = subprocess.run(
            ["which", "tinyproxy"], capture_output=True
        ).returncode == 0
        if not cls.has_tinyproxy:
            return

        # Start a dummy HTTP backend server on an ephemeral port
        class EchoHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"hello from backend"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), EchoHandler)
        cls.backend_port = cls.httpd.server_port
        cls.httpd_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.httpd_thread.start()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "httpd"):
            cls.httpd.shutdown()
            cls.httpd.server_close()

    def setUp(self):
        if not self.has_tinyproxy:
            self.skipTest("tinyproxy not installed")

    def _find_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_http_get_and_connect_proxying(self):
        proxy_port = self._find_free_port()
        with tempfile.TemporaryDirectory() as tmp:
            conf_path = os.path.join(tmp, "tinyproxy.conf")
            with open(conf_path, "w") as f:
                f.write(f"""
Port {proxy_port}
Timeout 10
LogLevel Info
MaxClients 10
DisableViaHeader Yes
""")
            proc = subprocess.Popen(["tinyproxy", "-d", "-c", conf_path],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                # Wait for proxy to listen
                time.sleep(0.5)

                # 1. Test HTTP GET via proxy
                cmd = [
                    "curl", "-s",
                    "-x", f"http://127.0.0.1:{proxy_port}",
                    f"http://127.0.0.1:{self.backend_port}/"
                ]
                env = os.environ.copy()
                env["NO_PROXY"] = ""
                env["no_proxy"] = ""
                res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(res.stdout, "hello from backend")

                # 2. Test HTTP CONNECT method
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as s:
                    req = f"CONNECT 127.0.0.1:{self.backend_port} HTTP/1.1\r\nHost: 127.0.0.1:{self.backend_port}\r\n\r\n"
                    s.sendall(req.encode("ascii"))
                    resp = s.recv(1024).decode("latin1", errors="replace")
                    self.assertTrue(resp.startswith("HTTP/1.0 200") or resp.startswith("HTTP/1.1 200"), resp)

                    # Tunnel HTTP GET through established CONNECT tunnel
                    s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    tunnel_resp = s.recv(4096).decode("utf-8", errors="replace")
                    self.assertIn("hello from backend", tunnel_resp)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()

    def test_http_basic_auth(self):
        proxy_port = self._find_free_port()
        with tempfile.TemporaryDirectory() as tmp:
            conf_path = os.path.join(tmp, "tinyproxy.conf")
            with open(conf_path, "w") as f:
                f.write(f"""
Port {proxy_port}
Timeout 10
LogLevel Info
MaxClients 10
DisableViaHeader Yes
BasicAuth myuser mypass
""")
            proc = subprocess.Popen(["tinyproxy", "-d", "-c", conf_path],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                time.sleep(0.5)
                env = os.environ.copy()
                env["NO_PROXY"] = ""
                env["no_proxy"] = ""

                # Request without auth -> 407
                res_noauth = subprocess.run([
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "-x", f"http://127.0.0.1:{proxy_port}",
                    f"http://127.0.0.1:{self.backend_port}/"
                ], env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(res_noauth.stdout.strip(), "407")

                # Request with wrong credentials -> 401
                res_badauth = subprocess.run([
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "-x", f"http://127.0.0.1:{proxy_port}",
                    "--proxy-user", "myuser:wrongpass",
                    f"http://127.0.0.1:{self.backend_port}/"
                ], env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(res_badauth.stdout.strip(), "401")

                # Request with correct credentials -> 200
                res_goodauth = subprocess.run([
                    "curl", "-s",
                    "-x", f"http://127.0.0.1:{proxy_port}",
                    "--proxy-user", "myuser:mypass",
                    f"http://127.0.0.1:{self.backend_port}/"
                ], env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(res_goodauth.stdout, "hello from backend")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
