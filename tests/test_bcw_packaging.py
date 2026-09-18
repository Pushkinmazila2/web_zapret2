"""Offline integration checks; never change firewall rules or probe the network."""
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import blockcheck


def bash_binary():
    if os.name == "nt":
        for name in (r"C:\Program Files\Git\bin\bash.exe",
                     r"C:\Program Files\Git\usr\bin\bash.exe"):
            if Path(name).is_file():
                return name
        return None
    return shutil.which("bash")


class PackagingTests(unittest.TestCase):
    def test_env_documents_every_run_and_schedule_setting(self):
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        names = set(re.findall(r"^([A-Z_]+)=", text, re.M))
        for prefix, spec in (("BCW_", blockcheck.SETTINGS_SPEC),
                             ("BCW_SCHEDULE_", blockcheck.SCHEDULE_SPEC)):
            for key in spec:
                self.assertIn(prefix + key.upper(), names)

    def test_shell_syntax(self):
        bash = bash_binary()
        if not bash:
            self.skipTest("Bash is not installed")
        for path in list((ROOT / "src").glob("*.sh")) + [ROOT / "tests/smoke.sh"]:
            with self.subTest(path=path.name):
                result = subprocess.run([bash, "-n"], input=path.read_bytes(),
                                        capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_preflight_preserves_failure_status(self):
        bash = bash_binary()
        if not bash:
            self.skipTest("Bash is not installed")
        source = (ROOT / "src/wz-bcw.sh").read_text(encoding="utf-8")
        function = source[source.index("preflight()\n"):]
        function = function[:function.index("\n}\n") + 3]
        setup = """
set -u
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/nfq2" "$work/lua"
cp /bin/sh "$work/nfq2/nfqws2"
touch "$work/lua/zapret-lib.lua" "$work/lua/zapret-antidpi.lua" "$work/module.py"
BCW_BIN=/bin/sh
BCW_MODULE="$work/module.py"
BCW_ZAPRET_BASE="$work"
BCW_LOG="$work/log"
BCW_QUEUE=200
command() { return 0; }
queue_busy() { return "$busy"; }
"""
        for busy, missing, expected in ((1, False, 0), (0, False, 1),
                                         (1, True, 1)):
            with self.subTest(busy=busy, missing=missing):
                script = setup + function + "\nbusy=%d\n" % busy
                if missing:
                    script += 'BCW_BIN="$work/missing"\n'
                script += "preflight\n"
                result = subprocess.run([bash], input=script.encode(),
                                        capture_output=True, timeout=15)
                self.assertEqual(result.returncode, expected,
                                 (result.stdout + result.stderr).decode())


if __name__ == "__main__":
    unittest.main()
