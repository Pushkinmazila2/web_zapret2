import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from strategy import native_options, strategy_args


class StrategyTests(unittest.TestCase):
    def test_catalog(self):
        data = json.loads((ROOT / "config/strategies.json").read_text(encoding="utf-8"))
        for entry in data["strategies"]:
            with self.subTest(id=entry["id"]):
                args = strategy_args(entry)
                self.assertFalse(any(a.startswith("--dpi-desync") for a in args))
                if entry["id"] != "none":
                    self.assertTrue(any(a.startswith("--lua-desync=") for a in args))

    def test_native_preserves_order_and_quotes(self):
        args = native_options('--lua-init="x = 1" --payload=tls_client_hello --lua-desync=custom:a=1 --lua-desync=custom:a=2', "HTTPS")
        self.assertEqual(args[0], "--filter-tcp=443")
        self.assertEqual(args[1], "--lua-init=x = 1")
        self.assertEqual(args[-2:], ["--lua-desync=custom:a=1", "--lua-desync=custom:a=2"])

    def test_protocols(self):
        for protocol, port in [("HTTP", "tcp=80"), ("HTTPS", "tcp=443"), ("QUIC", "udp=443")]:
            self.assertEqual(native_options("--lua-desync=pass", protocol)[0], "--filter-" + port)

    def test_scripts(self):
        self.assertEqual(strategy_args({"lua_init": ["/custom/example.lua"], "lua_opt": "--lua-desync=custom"})[0], "--lua-init=@/custom/example.lua")

    def test_invalid_arguments(self):
        for text in ["--qnum=9", "--daemon", "@file", "--lua-init='broken", "--filter-tcp=443 --dpi-desync=unsupported"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                strategy_args({"lua_opt": text})


if __name__ == "__main__":
    unittest.main()
