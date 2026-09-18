"""Unit tests for the blockcheckw strategy-selection engine (src/blockcheck.py).

Covers the requested capabilities:
  1. the strategy generation grid (scan argv + report parsing),
  2. multithreaded SO_MARK probing parameters (workers/profiles/via),
  3. the false-positive filter (two-axis check + selection rules),
  4. the time-based scheduler,
  5. settings coming from .env or from the panel (normalize/save/load).
"""
import io
import contextlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import blockcheck  # noqa: E402  (stdlib-only, safe to import standalone)

SCAN_REPORT = {
    "domain": "youtube.com",
    "timestamp": "2026-09-17_10-00",
    "block_type": "SNI blocked",
    "dns_spoofed": False,
    "total": 13943,
    "working": 3,
    "blocked": ["HTTPS/TLS1.2"],
    "protocols": [{"protocol": "HTTPS/TLS1.2", "total": 3,
                   "strategies": ["--payload=tls_client_hello --lua-desync=fake"]}],
    "strategies": [
        {"protocol": "HTTPS/TLS1.2",
         "args": "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls",
         "coverage": 1},
        {"protocol": "HTTPS/TLS1.3",
         "args": "--payload=tls_client_hello --lua-desync=tcpseg:pos=0,1",
         "coverage": 1},
    ],
}

CHECK_REPORT = {
    "domain": "youtube.com",
    "timestamp": "2026-09-17_10-05",
    "total": 3,
    "working": 2,
    "elapsed_secs": 42.5,
    "inconclusive": False,
    "control": {"observed": "NoConnect", "admits": ["Dead"]},
    "strategies": [
        {"protocol": "HTTPS/TLS1.2",
         "args": "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls",
         "coverage": 1, "working": True, "success_rate": 1.0,
         "median_latency_ms": 120, "median_speed_kbps": 812.0, "passes_ok": 3,
         "passes_total": 3, "median_share": 0.98, "longest_silence_ms": 310,
         "observed": "Bytes", "admits": ["Good"]},
        {"protocol": "HTTPS/TLS1.2",
         "args": "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:repeats=5",
         "coverage": 1, "working": False, "success_rate": 0.33,
         "median_latency_ms": 900, "median_speed_kbps": 0.0, "passes_ok": 1,
         "passes_total": 3, "median_share": 0.2, "longest_silence_ms": None,
         "observed": "Inconsistent", "admits": ["Mirage"]},
        {"protocol": "HTTPS/TLS1.3",
         "args": "--payload=tls_client_hello --lua-desync=tcpseg:pos=0,1",
         "coverage": 1, "working": True, "success_rate": 1.0,
         "median_latency_ms": 210, "median_speed_kbps": 120.0, "passes_ok": 2,
         "passes_total": 2, "median_share": 0.4, "longest_silence_ms": 400,
         "observed": "Bytes", "admits": ["Grinding"]},
    ],
}


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wz-bcw-cfg-")
        self.env = {"BCW_WORKERS": "32", "BCW_DOMAINS": "a.example,b.example",
                    "BCW_PROTOCOLS": "tls13", "BCW_GRID_FILE": "/tmp/grid.txt",
                    "BCW_SCHEDULE_AT": "05:30"}

    def test_env_defaults_come_from_dotenv(self):
        defaults = blockcheck.env_defaults(self.env)
        self.assertEqual(defaults["workers"], 32)
        self.assertEqual(defaults["domains"], ["a.example", "b.example"])
        self.assertEqual(defaults["protocols"], ["tls13"])
        self.assertEqual(defaults["queue"], blockcheck.BCW_QUEUE_FIXED)

    def test_env_defaults_ignore_garbage(self):
        defaults = blockcheck.env_defaults({"BCW_WORKERS": "many"})
        self.assertEqual(defaults["workers"],
                         blockcheck.SETTINGS_SPEC["workers"]["default"])

    def test_normalize_clamps_and_warns(self):
        base = blockcheck.env_defaults(self.env)
        payload = {"workers": 99999, "profiles_per_instance": 65535}
        out, warnings, errors = blockcheck.normalize(payload, base)
        self.assertEqual(errors, [])
        self.assertEqual(out["workers"], 2048)
        self.assertTrue(any("clamped" in w for w in warnings), warnings)

    def test_normalize_cross_field_errors(self):
        base = blockcheck.env_defaults({"BCW_PROTOCOLS": "tls13"})
        for payload, needle in [
            ({"protocols": ""}, "protocols"),
            ({"domains": ""}, "domains"),
            ({"via": "10.0.0.1", "reference_via": "10.0.0.2"}, "mutually exclusive"),
            ({"grid": "file", "grid_file": ""}, "grid=file"),
            ({"workers": 512, "profiles_per_instance": 64}, "exceeds"),
            ({"probe_path": "robots.txt"}, "absolute path"),
        ]:
            with self.subTest(payload=payload):
                _, _, errors = blockcheck.normalize(payload, base)
                self.assertTrue(any(needle in e for e in errors), (payload, errors))

    def test_queue_is_pinned_to_the_upstream_constant(self):
        base = blockcheck.env_defaults(self.env)
        out, warnings, errors = blockcheck.normalize({"queue": 999}, base)
        self.assertEqual(errors, [])
        self.assertEqual(out["queue"], blockcheck.BCW_QUEUE_FIXED)
        self.assertTrue(any("compile-time constant" in w for w in warnings), warnings)

    def test_panel_overrides_persist_over_env(self):
        settings, _, errors, ok = blockcheck.save_settings(
            self.tmp, {"workers": 256, "passes": 5}, self.env)
        self.assertTrue(ok)
        self.assertEqual(errors, [])
        self.assertEqual(settings["workers"], 256)
        loaded, _, _ = blockcheck.load_settings(self.tmp, self.env)
        self.assertEqual(loaded["workers"], 256)
        self.assertEqual(loaded["passes"], 5)
        self.assertEqual(loaded["domains"], ["a.example", "b.example"])
        reset = blockcheck.reset_settings(self.tmp, self.env)
        self.assertEqual(reset["workers"], 32)


class PersistenceValidationTests(unittest.TestCase):
    def test_invalid_updates_do_not_change_saved_files(self):
        cases = (
            (blockcheck.save_settings, blockcheck.SETTINGS_FILE,
             {"workers": 32}, {"domains": ""}),
            (blockcheck.save_schedule, blockcheck.SCHEDULE_FILE,
             {"enabled": True, "at": "05:30"}, {"at": "25:99"}),
        )
        for save, filename, valid, invalid in cases:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                _, _, errors, saved = save(tmp, valid, environ={})
                self.assertTrue(saved)
                self.assertEqual(errors, [])
                path = Path(blockcheck.state_path(tmp, filename))
                before = path.read_bytes()
                _, _, errors, saved = save(tmp, invalid, environ={})
                self.assertFalse(saved)
                self.assertTrue(errors)
                self.assertEqual(path.read_bytes(), before)

    def test_invalid_first_update_does_not_create_file(self):
        cases = (
            (blockcheck.save_settings, blockcheck.SETTINGS_FILE, {"domains": ""}),
            (blockcheck.save_schedule, blockcheck.SCHEDULE_FILE, {"at": "25:99"}),
        )
        for save, filename, invalid in cases:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                _, _, errors, saved = save(tmp, invalid, environ={})
                self.assertFalse(saved)
                self.assertTrue(errors)
                self.assertFalse(Path(blockcheck.state_path(tmp, filename)).exists())


class CommandLineTests(unittest.TestCase):
    """Requirement 1 + 2: the grid scan and the multithreaded SO_MARK knobs."""

    def setUp(self):
        self.settings = blockcheck.env_defaults({})

    def test_scan_uses_the_whole_grid_and_stays_embedded(self):
        argv = blockcheck.scan_argv(self.settings, "youtube.com", "/run/scan.json")
        self.assertEqual(argv[0], self.settings["bin"])
        self.assertIn("--no-conflict-cleanup", argv)
        self.assertIn("--auto", argv)
        self.assertEqual(argv[argv.index("-w") + 1], str(self.settings["workers"]))
        self.assertEqual(argv[argv.index("--profiles-per-instance") + 1],
                         str(self.settings["profiles_per_instance"]))
        self.assertEqual(argv[argv.index("scan") + 1], "-d")
        self.assertNotIn("--from-file", argv)

    def test_scan_from_file_uses_a_custom_corpus(self):
        settings, _, _ = blockcheck.normalize(
            {"grid": "file", "grid_file": "/data/corpus.txt"}, self.settings)
        argv = blockcheck.scan_argv(settings, "youtube.com", "/run/scan.json")
        self.assertEqual(argv[argv.index("--from-file") + 1], "/data/corpus.txt")

    def test_check_carries_every_false_positive_knob(self):
        argv = blockcheck.check_argv(self.settings, "youtube.com",
                                     "/run/scan.json", "/run/check.json")
        self.assertNotIn("-w", argv)                # `check` verifies sequentially
        for flag, value in [("--from-file", "/run/scan.json"), ("-d", "youtube.com"),
                            ("--passes", "3"), ("--take", "3"), ("--timeout", "3"),
                            ("--idle-ms", "1000"), ("--probe-path", "/"),
                            ("--identity-path", "/robots.txt"),
                            ("-o", "/run/check.json")]:
            with self.subTest(flag=flag):
                self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("check", argv)

    def test_profiles_floor_keeps_clap_validation_happy(self):
        settings, _, _ = blockcheck.normalize({"profiles_per_instance": 4}, self.settings)
        argv = blockcheck.check_argv(settings, "d.example", "/s.json", "/c.json")
        self.assertGreaterEqual(int(argv[argv.index("--profiles-per-instance") + 1]), 8)

    def test_via_is_forwarded_for_both_steps(self):
        settings, _, _ = blockcheck.normalize({"via": "socks5://10.0.0.1:1080"},
                                              self.settings)
        for argv in (blockcheck.scan_argv(settings, "d.example", "/s.json"),
                     blockcheck.check_argv(settings, "d.example", "/s.json", "/c.json")):
            self.assertEqual(argv[argv.index("--via") + 1], "socks5://10.0.0.1:1080")

    def test_reference_via_is_only_added_to_check(self):
        settings, _, _ = blockcheck.normalize({"reference_via": "100.64.0.9"},
                                              self.settings)
        scan = blockcheck.scan_argv(settings, "d.example", "/s.json")
        check = blockcheck.check_argv(settings, "d.example", "/s.json", "/c.json")
        self.assertNotIn("--reference-via", scan)
        self.assertEqual(check[check.index("--reference-via") + 1], "100.64.0.9")

    def test_plan_creates_paths_per_domain(self):
        settings, _, _ = blockcheck.normalize({"domains": "a.example,b.example"},
                                              self.settings)
        planned = blockcheck.plan(settings, "/run/1")
        self.assertEqual([r["domain"] for r in planned["runs"]],
                         ["a.example", "b.example"])
        self.assertTrue(planned["runs"][0]["scan_out"].endswith("scan_a_example.json"))
        check = planned["runs"][1]["check"]
        self.assertEqual(check[check.index("--from-file") + 1],
                         os.path.join("/run/1", "scan_b_example.json"))
        self.assertEqual(planned["home"], os.path.join("/run/1", "home"))
class ReportTests(unittest.TestCase):
    """Requirement 3: the false-positive filter over the two axes."""

    def setUp(self):
        self.settings = blockcheck.env_defaults({})

    def test_parse_scan_report(self):
        report = blockcheck.parse_scan_report(json.dumps(SCAN_REPORT))
        self.assertEqual(report["block_type"], "SNI blocked")
        self.assertEqual(len(report["strategies"]), 2)
        self.assertEqual(report["strategies"][0]["protocol"], "HTTPS/TLS1.2")

    def test_parse_scan_report_rejects_garbage(self):
        self.assertIsNone(blockcheck.parse_scan_report("not json"))
        self.assertIsNone(blockcheck.parse_scan_report('{"domain":"x"}'))

    def test_parse_check_report_keeps_both_axes(self):
        report = blockcheck.parse_check_report(json.dumps(CHECK_REPORT))
        self.assertEqual(report["working"], 2)
        self.assertEqual(report["strategies"][0]["admits"], ["Good"])
        self.assertEqual(report["strategies"][0]["passes_ok"], 3)
        self.assertAlmostEqual(report["strategies"][2]["median_share"], 0.4)

    def test_selection_drops_mirage_and_low_volume(self):
        settings, _, _ = blockcheck.normalize({"min_share": 0.9}, self.settings)
        report = blockcheck.parse_check_report(CHECK_REPORT)
        accepted, refused = blockcheck.select_working(report["strategies"], settings)
        self.assertEqual(len(accepted), 1)
        self.assertEqual(accepted[0]["protocol"], "HTTPS/TLS1.2")
        reasons = " | ".join(r["reason"] for r in refused)
        self.assertIn("mirage", reasons)
        self.assertIn("reference volume", reasons)

    def test_selection_without_share_gate_keeps_working_rows(self):
        report = blockcheck.parse_check_report(CHECK_REPORT)
        accepted, refused = blockcheck.select_working(report["strategies"], self.settings)
        self.assertEqual(len(accepted), 2)     # the Mirage row is not `working`
        self.assertTrue(all(r["working"] for r in accepted))
        self.assertEqual(len(refused), 1)

    def test_rank_prefers_full_delivery_then_share_then_latency(self):
        rows = [dict(r, working=True) for r in (
            {"success_rate": 1.0, "median_share": 0.5, "median_latency_ms": 100},
            {"success_rate": 1.0, "median_share": 0.9, "median_latency_ms": 400},
            {"success_rate": 0.5, "median_share": 1.0, "median_latency_ms": 50},
        )]
        self.assertAlmostEqual(blockcheck.rank(rows)[0]["median_share"], 0.9)

    def test_min_share_without_reference_is_refused(self):
        settings, _, _ = blockcheck.normalize({"min_share": 0.5}, self.settings)
        row = {"protocol": "HTTPS/TLS1.2", "args": "--lua-desync=fake", "working": True,
               "admits": ["Good"], "observed": "Bytes", "median_share": None}
        self.assertIn("reference", blockcheck.filter_reason(row, settings))
class ImportTests(unittest.TestCase):
    """Survivors of a run become real catalog entries (with reasm protection)."""

    def setUp(self):
        self.settings = blockcheck.env_defaults({})
        report = blockcheck.parse_check_report(CHECK_REPORT)
        accepted, _ = blockcheck.select_working(report["strategies"], self.settings)
        self.result = {"domains": [{"domain": "youtube.com", "block_type": "SNI blocked",
                                    "working": accepted}]}

    def test_entries_are_ranked_capped_and_deduplicated(self):
        entries, skipped = blockcheck.plan_import(self.result, self.settings, [])
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["id"], "bcw_youtube_com_https_tls1_2")
        self.assertTrue(entries[0]["no_reasm"], "TLS strategy must disable reasm")
        self.assertEqual(entries[0]["protocol"], "HTTPS/TLS1.2")
        self.assertIn("3/3 full passes", entries[0]["desc"])
        self.assertEqual(entries[0]["bcw"]["domain"], "youtube.com")
        self.assertEqual(skipped, [])

        again, skipped2 = blockcheck.plan_import(self.result, self.settings, entries)
        self.assertEqual(again, [])
        self.assertTrue(all(s["reason"] == "already in the catalog" for s in skipped2))

    def test_max_import_caps_each_protocol(self):
        settings, _, _ = blockcheck.normalize({"max_import": 1}, self.settings)
        rows = [{"protocol": "HTTPS/TLS1.2", "args": "--lua-desync=fake:repeats=%d" % n,
                 "working": True, "admits": ["Good"], "passes_ok": 3, "passes_total": 3,
                 "median_share": 1.0, "median_latency_ms": 10 * n} for n in (1, 2)]
        result = {"domains": [{"domain": "youtube.com", "working": rows}]}
        entries, skipped = blockcheck.plan_import(result, settings, [])
        self.assertEqual(len(entries), 1)
        self.assertIn("max_import", skipped[0]["reason"])

    def test_forbidden_arguments_are_refused(self):
        rows = [{"protocol": "HTTPS/TLS1.2", "args": "--qnum=9 --lua-desync=fake",
                 "working": True, "admits": ["Good"]}]
        entries, skipped = blockcheck.plan_import(
            {"domains": [{"domain": "d.example", "working": rows}]}, self.settings, [])
        self.assertEqual(entries, [])
        self.assertIn("forbidden", skipped[0]["reason"])

    def test_merge_catalog_replaces_same_id(self):
        entries, _ = blockcheck.plan_import(self.result, self.settings, [])
        catalog = blockcheck.merge_catalog(
            {"_comment": "keep me", "strategies": [{"id": "standard"},
                                                   dict(entries[0], desc="stale")]},
            entries)
        self.assertEqual(catalog["_comment"], "keep me")
        ids = [s["id"] for s in catalog["strategies"]]
        self.assertEqual(ids.count(entries[0]["id"]), 1)
        self.assertEqual(len(ids), 1 + len(entries))
        self.assertNotEqual([s for s in catalog["strategies"]
                             if s["id"] == entries[0]["id"]][0]["desc"], "stale")


class SchedulerTests(unittest.TestCase):
    """Requirement 4: time-based runs."""

    def test_interval_without_history(self):
        schedule = {"enabled": True, "mode": "interval", "interval_min": 60,
                    "run_on_start": False}
        now = 1_700_000_000
        self.assertEqual(blockcheck.next_run_at(schedule, now, None), now + 3600)

    def test_interval_never_bursts_after_downtime(self):
        schedule = {"enabled": True, "mode": "interval", "interval_min": 30}
        now = 1_700_000_000
        last = now - 10 * 3600        # ten hours of downtime
        target = blockcheck.next_run_at(schedule, now, last)
        self.assertGreater(target, now)
        self.assertLessEqual(target, now + 30 * 60)

    def test_interval_run_on_start_fires_immediately(self):
        schedule = {"enabled": True, "mode": "interval", "interval_min": 60,
                    "run_on_start": True}
        now = 1_700_000_000
        self.assertEqual(blockcheck.next_run_at(schedule, now, None), now)

    def test_daily_at_next_occurrence(self):
        schedule = {"enabled": True, "mode": "daily", "at": "04:00"}
        now = time.mktime((2026, 9, 17, 10, 0, 0, 0, 0, -1))
        target = blockcheck.next_run_at(schedule, now, None)
        local = time.localtime(target)
        self.assertEqual((local.tm_hour, local.tm_min), (4, 0))
        self.assertGreater(blockcheck.next_run_at(schedule, now, now), now)

    def test_weekly_lands_on_the_configured_day(self):
        schedule = {"enabled": True, "mode": "weekly", "at": "03:30", "days": ["mon"]}
        now = time.mktime((2026, 9, 17, 10, 0, 0, 0, 0, -1))     # Thursday
        target = blockcheck.next_run_at(schedule, now, None)
        self.assertEqual(blockcheck.DAYS[time.localtime(target).tm_wday], "mon")
        self.assertGreater(target, now)

    def test_disabled_schedule_never_fires(self):
        schedule = {"enabled": False, "mode": "daily", "at": "04:00"}
        self.assertIsNone(blockcheck.next_run_at(schedule, 1_700_000_000, None))
        self.assertFalse(blockcheck.schedule_due(schedule, 1_700_000_000, 0))

    def test_due_when_the_stored_instant_arrived(self):
        schedule = {"enabled": True, "mode": "daily", "at": "04:00"}
        self.assertTrue(blockcheck.schedule_due(schedule, 1000, 999))
        self.assertFalse(blockcheck.schedule_due(schedule, 998, 999))

    def test_schedule_settings_validate(self):
        base = blockcheck.env_defaults({}, blockcheck.SCHEDULE_SPEC, "BCW_SCHEDULE_")
        out, warnings, errors = blockcheck.normalize_schedule(
            {"mode": "weekly", "at": "25:99", "days": "mon,bogus"}, base)
        self.assertTrue(any("HH:MM" in e for e in errors), errors)
        self.assertEqual(out["days"], ["mon"])

    def test_schedule_round_trip_in_state(self):
        tmp = tempfile.mkdtemp(prefix="wz-bcw-sched-")
        schedule, _, _, ok = blockcheck.save_schedule(
            tmp, {"enabled": True, "mode": "interval", "interval_min": 15})
        self.assertTrue(ok)
        self.assertEqual(schedule["interval_min"], 15)
        loaded, _, errors = blockcheck.load_schedule(tmp)
        self.assertEqual(errors, [])
        self.assertTrue(loaded["enabled"])


class RunTests(unittest.TestCase):
    """Full scan+check pipeline with a stubbed blockcheckw binary."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wz-bcw-run-")
        self.settings, _, _ = blockcheck.normalize({}, blockcheck.env_defaults({}))
        self.calls = []
        real = blockcheck._run_step
        self.addCleanup(lambda: setattr(blockcheck, "_run_step", real))

    def _stub(self, scan_report=SCAN_REPORT, check_report=CHECK_REPORT, rc=0):
        def fake(cmd, log_path, timeout, env, cwd):
            self.calls.append({"cmd": list(cmd), "env": dict(env), "cwd": cwd,
                               "timeout": timeout})
            with open(log_path, "a", encoding="utf-8") as log:
                log.write("fake run: %s\n" % " ".join(cmd))
            path = cmd[cmd.index("-o") + 1]
            report = check_report if "--from-file" in cmd else scan_report
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(report, handle)
            return rc, None
        return fake

    def test_pipeline_selects_only_trusted_strategies(self):
        blockcheck._run_step = self._stub()
        result = blockcheck.run(self.settings, self.tmp)
        self.assertTrue(result["ok"])
        self.assertTrue(result["success"])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(result["domains"][0]["working"]), 2)
        self.assertEqual(len(result["domains"][0]["refused"]), 1)
        self.assertEqual(result["domains"][0]["block_type"], "SNI blocked")
        self.assertIn("working 2", blockcheck.summarize(result))
        self.assertTrue((Path(self.tmp) / "result.json").exists())
        self.assertIn("fake run", result["log"])

    def test_run_isolates_the_blockcheckw_home(self):
        blockcheck._run_step = self._stub()
        blockcheck.run(self.settings, self.tmp)
        self.assertEqual(self.calls[0]["env"]["HOME"], str(Path(self.tmp) / "home"))
        self.assertNotIn("SUDO_USER", self.calls[0]["env"])
        self.assertEqual(self.calls[0]["cwd"], self.tmp)

    def test_no_candidates_skips_check(self):
        empty = dict(SCAN_REPORT, strategies=[], working=0, block_type="available")
        blockcheck._run_step = self._stub(scan_report=empty)
        result = blockcheck.run(self.settings, self.tmp)
        self.assertTrue(result["ok"])
        self.assertFalse(result["success"])
        self.assertEqual(len(self.calls), 1)
        self.assertIsNone(result["domains"][0]["check_rc"])

    def test_scan_failure_is_reported(self):
        blockcheck._run_step = self._stub(rc=6)
        result = blockcheck.run(self.settings, self.tmp)
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])
        self.assertIn("scan failed", result["errors"][0])

    def test_import_from_a_realised_run(self):
        blockcheck._run_step = self._stub()
        result = blockcheck.run(self.settings, self.tmp)
        entries, skipped = blockcheck.plan_import(result, self.settings, [])
        self.assertEqual(len(entries), 2)
        self.assertEqual(skipped, [])
        catalog = blockcheck.merge_catalog({"strategies": [{"id": "standard"}]}, entries)
        self.assertEqual(len(catalog["strategies"]), 3)


class CliTests(unittest.TestCase):
    def test_defaults_command_prints_both_blocks(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = blockcheck.main(["defaults"])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("workers", payload["settings"])
        self.assertIn("interval_min", payload["schedule"])

    def test_plan_and_run_commands(self):
        tmp = tempfile.mkdtemp(prefix="wz-bcw-cli-")
        settings_file = str(Path(tmp) / "settings.json")
        Path(settings_file).write_text(
            json.dumps({"domains": "example.com", "bin": "/bin/true"}),
            encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = blockcheck.main(["plan", settings_file, tmp])
        self.assertEqual(rc, 0)
        plan = json.loads(buf.getvalue())["plan"]
        self.assertEqual(plan["runs"][0]["domain"], "example.com")

        buf = io.StringIO()
        with contextlib.redirect_stderr(io.StringIO()):
            rc = blockcheck.main(["plan", settings_file])
        self.assertEqual(rc, 2)                      # run_dir is required

    def test_next_command_reports_the_next_slot(self):
        tmp = tempfile.mkdtemp(prefix="wz-bcw-cli2-")
        schedule_file = str(Path(tmp) / "schedule.json")
        Path(schedule_file).write_text(
            json.dumps({"enabled": True, "mode": "daily", "at": "04:00"}),
            encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = blockcheck.main(["next", schedule_file])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertTrue(payload["next_run"] > time.time())
        self.assertTrue(payload["next_run_local"])

    def test_run_command_reports_validation_errors(self):
        tmp = tempfile.mkdtemp(prefix="wz-bcw-cli3-")
        settings_file = str(Path(tmp) / "settings.json")
        Path(settings_file).write_text(json.dumps({"protocols": ""}), encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = blockcheck.main(["run", settings_file, tmp])
        self.assertEqual(rc, 2)
        self.assertFalse(json.loads(buf.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()