#!/usr/bin/env python3
"""web_zapret2 — "Strategy selection" engine (blockcheckw wrapper).

Wraps rcd27/blockcheckw (a parallel DPI-bypass strategy scanner).  The panel's
"Strategy selection" tab drives this module through /api/bcw/*; wz-bcw.sh is the
privileged launcher around it.

Pipeline (per domain):
    scan   walk the whole generated strategy corpus (the "grid" — ~14k
           strategies) in parallel and keep the candidates that moved bytes;
    check  verify every candidate with REAL data transfer: `passes` byte-axis
           measurements (--probe-path) plus one authenticity probe
           (--identity-path).  A strategy is `working` only if authenticity is
           not refuted (admits != [Mirage]) AND every one of the M passes
           delivered the reference volume.  That two-axis measurement is the
           false-positive filter (Good/Grinding/Mirage/Trap/Dead).

Multithreaded SO_MARK: blockcheckw probes with socket2 + SO_MARK before connect
and spreads the corpus over `workers` in-flight probes (--workers) while one
nfqws2 process keeps up to --profiles-per-instance strategies as profiles.

Embedded mode is ALWAYS on (--no-conflict-cleanup): blockcheckw leaves foreign
nft tables and nfqws2 processes alone, so the LIVE gateway nfqws2 and the
iptables WZFW/NFQIN chains are never touched.  Its own NFQUEUE base number is
the compile-time constant 200 (BCW_QUEUE, no CLI flag upstream), therefore the
gateway keeps queues 210/211 (QNUM_TCP/QNUM_UDP) and the isolated test harness
212 (QNUM_TEST) free for it.

Every parameter comes from .env (BCW_*, BCW_SCHEDULE_*) and can be overridden
live from the panel; overrides persist in $WZ_STATE/bcw_settings.json.

CLI (used by wz-bcw.sh, the panel and the tests):
    blockcheck.py defaults                    effective .env defaults (JSON)
    blockcheck.py plan <settings.json> <dir>  exact command lines (JSON)
    blockcheck.py run  <settings.json> <dir>  execute the pipeline, print result
    blockcheck.py next <schedule.json>        next run time (JSON)
"""
import json
import os
import re
import shlex
import subprocess
import sys
import time

BCW_BIN_DEFAULT = "/opt/webzapret/bin/blockcheckw"
BCW_VERSION_FILE = "/opt/webzapret/config/blockcheckw.version"
# blockcheckw's NFQUEUE base number is a compile-time constant (CoreConfig
# default, no CLI flag / env upstream).  The live gateway must keep it free.
BCW_QUEUE_FIXED = 200

PROTOCOLS = ("http", "tls12", "tls13")
DNS_MODES = ("auto", "system", "doh")
GRID_MODES = ("corpus", "file")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MIN_PROFILES_FOR_CHECK = 8      # nfqws2 plan sizes below clap's default -w 8

# ---------------------------------------------------------------------------
# settings spec: (kind, default, low, high, choices)
# kinds: bool | int | float | str | csv | enum
# ---------------------------------------------------------------------------
def _spec(kind, default, lo=None, hi=None, choices=None):
    return {"kind": kind, "default": default, "lo": lo, "hi": hi,
            "choices": choices}


SETTINGS_SPEC = {
    # --- master switch / grid (requirement 1: strategy generation grid) -----
    "enabled":      _spec("bool", True),
    "bin":          _spec("str", BCW_BIN_DEFAULT),
    "grid":         _spec("enum", "corpus", choices=GRID_MODES),
    "grid_file":    _spec("str", ""),
    "domains":      _spec("csv", ["youtube.com"]),
    "protocols":    _spec("csv", ["tls12", "tls13"]),
    "dns":          _spec("enum", "auto", choices=DNS_MODES),
    # --- multithreaded SO_MARK probing (requirement 2) ---------------------
    "workers":      _spec("int", 64, 1, 2048),
    "profiles_per_instance": _spec("int", 1024, 1, 65535),
    "queue":        _spec("int", BCW_QUEUE_FIXED, 1, 65535),
    "via":          _spec("str", ""),
    "alive_via":    _spec("str", ""),
    # --- scan (grid) tuning -------------------------------------------------
    "scan_timeout": _spec("int", 0, 0, 3600),
    "scan_top":     _spec("int", 5, 0, 1000),
    # --- false-positive filter (requirement 3) -----------------------------
    "passes":       _spec("int", 3, 0, 10),
    "take":         _spec("int", 3, 0, 1000),
    "check_timeout": _spec("int", 3, 1, 60),
    "idle_ms":      _spec("int", 1000, 100, 60000),
    "probe_path":   _spec("str", "/"),
    "identity_path": _spec("str", "/robots.txt"),
    "reference_via": _spec("str", ""),
    "min_share":    _spec("float", 0.0, 0.0, 10.0),
    "exclude_mirage": _spec("bool", True),
    # --- importing the survivors into the live catalog ----------------------
    "max_import":   _spec("int", 5, 0, 100),
    "import_prefix": _spec("str", "bcw"),
    "auto_import":  _spec("bool", False),
    "auto_apply":   _spec("bool", False),
    # --- run guards ---------------------------------------------------------
    "job_timeout":  _spec("int", 3600, 60, 14400),
    "log_lines":    _spec("int", 400, 50, 5000),
    "raise_limits": _spec("bool", True),
    "nf_queue_maxlen": _spec("int", 65536, 1024, 1048576),
    "nf_conntrack_max": _spec("int", 131072, 1024, 4194304),
}

SCHEDULE_SPEC = {
    "enabled":      _spec("bool", False),
    "mode":         _spec("enum", "daily", choices=("interval", "daily", "weekly")),
    "interval_min": _spec("int", 360, 5, 10080),
    "at":           _spec("str", "04:00"),
    "days":         _spec("csv", list(DAYS)),
    "run_on_start": _spec("bool", False),
}

_ENV_PREFIX = "BCW_"
_TRUE = ("1", "true", "yes", "on", "enabled", "y")
_FALSE = ("0", "false", "no", "off", "disabled", "n", "")

# ---------------------------------------------------------------------------
# value coercion / validation
# ---------------------------------------------------------------------------
def as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return default


def as_int(value, default, lo=None, hi=None):
    """Coerce to int, clamping into [lo, hi]; raises ValueError on garbage."""
    if isinstance(value, bool):
        raise ValueError("not a number: %r" % value)
    text = str(value).strip()
    if not re.fullmatch(r"[+-]?\d+", text or ""):
        raise ValueError("not a number: %r" % value)
    number = int(text)
    if lo is not None:
        number = max(lo, number)
    if hi is not None:
        number = min(hi, number)
    return number


def as_float(value, default, lo=None, hi=None):
    if isinstance(value, bool):
        raise ValueError("not a number: %r" % value)
    text = str(value).strip()
    try:
        number = float(text)
    except (TypeError, ValueError):
        raise ValueError("not a number: %r" % value)
    if lo is not None:
        number = max(lo, number)
    if hi is not None:
        number = min(hi, number)
    return number


def as_csv(value):
    """Split a comma/space separated value into a list of clean tokens."""
    if isinstance(value, (list, tuple)):
        items = list(value)
    else:
        items = re.split(r"[,\s]+", str(value or ""))
    return [str(x).strip() for x in items if str(x).strip()]


def coerce(kind, raw, spec):
    """Coerce one raw value per its spec; raises ValueError when unusable."""
    default = spec["default"]
    if kind == "bool":
        return as_bool(raw, default)
    if kind == "int":
        return as_int(raw, default, spec["lo"], spec["hi"])
    if kind == "float":
        return as_float(raw, default, spec["lo"], spec["hi"])
    if kind == "csv":
        if raw is None:
            return list(default)
        return as_csv(raw)
    if kind == "enum":
        text = str(raw if raw is not None else "").strip().lower()
        choices = spec["choices"] or ()
        return text if text in choices else default
    if kind == "str":
        return str(raw if raw is not None else default).strip()
    raise ValueError("unknown kind %r" % kind)


def env_name(key, prefix=_ENV_PREFIX):
    return prefix + key.upper()


def env_defaults(environ=None, spec=None, prefix=_ENV_PREFIX):
    """Effective defaults for a whole settings block, taken from .env."""
    environ = os.environ if environ is None else environ
    spec = SETTINGS_SPEC if spec is None else spec
    out = {}
    for key, item in spec.items():
        raw = environ.get(env_name(key, prefix))
        default = list(item["default"]) if item["kind"] == "csv" else item["default"]
        try:
            out[key] = coerce(item["kind"], raw, item) if raw is not None else default
        except ValueError:
            out[key] = default
    return out
def _clamp_warning(key, raw, value, spec):
    """Human warning when a numeric value was clamped into its allowed range."""
    try:
        numeric = float(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if abs(numeric - float(value)) > 1e-9:
        return "%s: %s clamped to %s (allowed %s..%s)" % (
            key, raw, value, spec["lo"], spec["hi"])
    return None


def normalize(values, base, spec=None):
    """Merge `values` over `base`, coercing and validating every key.

    Returns (settings, warnings, errors).  Out-of-range numbers are clamped
    (warning); cross-field contradictions are errors — the caller must refuse to
    run rather than guess.  The cross-field block is only applied to the full
    settings spec (the schedule spec has its own in normalize_schedule).
    """
    spec = SETTINGS_SPEC if spec is None else spec
    full = spec is SETTINGS_SPEC
    out = dict(base)
    warnings = []
    errors = []
    for key, item in spec.items():
        if key not in (values or {}):
            continue
        raw = values[key]
        try:
            out[key] = coerce(item["kind"], raw, item)
        except ValueError as exc:
            warnings.append("%s: %s — keeping %r" % (key, exc, base.get(key)))
            continue
        if item["kind"] in ("int", "float"):
            drift = _clamp_warning(key, raw, out[key], item)
            if drift:
                warnings.append(drift)
    if not full:
        return out, warnings, errors

    unknown = [k for k in (values or {}) if k not in spec]
    if unknown:
        warnings.append("ignoring unknown settings: %s" % ",".join(sorted(unknown)))

    # --- cross-field rules --------------------------------------------------
    bad = [p for p in out.get("protocols", []) if p not in PROTOCOLS]
    if bad:
        warnings.append("protocols: ignoring unknown %s" % ",".join(bad))
    out["protocols"] = [p for p in dict.fromkeys(out.get("protocols", []))
                        if p in PROTOCOLS]
    if not out["protocols"]:
        errors.append("protocols: at least one of %s is required" % ",".join(PROTOCOLS))

    out["domains"] = [d for d in dict.fromkeys(as_csv(out.get("domains", []))) if d]
    for domain in out["domains"]:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,253}", domain):
            errors.append("domains: %r is not a valid domain" % domain)
    if not out["domains"]:
        errors.append("domains: at least one domain is required")

    if out.get("grid") == "file" and not out.get("grid_file"):
        errors.append("grid=file needs grid_file (a strategy corpus for --from-file)")
    if out.get("via") and out.get("reference_via"):
        errors.append("via and reference_via are mutually exclusive (blockcheckw: "
                      "the whole run already goes through the gateway)")
    for key in ("probe_path", "identity_path"):
        if not str(out.get(key, "")).startswith("/"):
            errors.append("%s: must be an absolute path" % key)
    if out.get("workers") > out.get("profiles_per_instance"):
        errors.append("workers (%d) exceeds profiles_per_instance (%d) — "
                      "blockcheckw would exit 2" % (out["workers"],
                                                    out["profiles_per_instance"]))
    if out.get("queue") != BCW_QUEUE_FIXED:
        warnings.append("queue=%s has no effect: blockcheckw's NFQUEUE base is the "
                        "compile-time constant %d" % (out.get("queue"), BCW_QUEUE_FIXED))
        out["queue"] = BCW_QUEUE_FIXED
    return out, warnings, errors


def normalize_schedule(values, base, spec=None):
    """Same as normalize() for the scheduler block (days/at/interval rules)."""
    spec = SCHEDULE_SPEC if spec is None else spec
    out, warnings, errors = normalize(values, base, spec)
    known = [d for d in out.get("days", []) if d in DAYS]
    if len(known) != len(as_csv(out.get("days", []))):
        warnings.append("days: ignoring unknown values")
    out["days"] = list(dict.fromkeys(known)) or list(DAYS)
    if out.get("mode") in ("daily", "weekly") and not valid_hhmm(out.get("at")):
        errors.append("at: expected HH:MM, got %r" % out.get("at"))
    out["interval_min"] = max(5, min(int(out.get("interval_min", 360)), 10080))
    return out, warnings, errors


def valid_hhmm(text):
    return bool(re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d", str(text or "").strip()))
# ---------------------------------------------------------------------------
# JSON / state helpers (panel and harness share them)
# ---------------------------------------------------------------------------
def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def write_json(path, obj):
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return True
    except Exception:
        return False


SETTINGS_FILE = "bcw_settings.json"
SCHEDULE_FILE = "bcw_schedule.json"
LAST_RUN_FILE = "bcw_last.json"
JOB_FILE = "bcw_job.json"


def state_path(state_dir, name):
    return os.path.join(state_dir, name)


def load_settings(state_dir, environ=None):
    """Effective settings: .env defaults + panel overrides from the state file."""
    base = env_defaults(environ)
    persisted = read_json(state_path(state_dir, SETTINGS_FILE), {}) or {}
    settings, warnings, errors = normalize(persisted, base)
    return settings, warnings, errors


def save_settings(state_dir, values, environ=None):
    """Persist a panel override set (partial updates are merged)."""
    base = env_defaults(environ)
    persisted = read_json(state_path(state_dir, SETTINGS_FILE), {}) or {}
    for key, value in (values or {}).items():
        if key in SETTINGS_SPEC:
            persisted[key] = value
    merged, warnings, errors = normalize(persisted, base)
    if errors:
        return merged, warnings, errors, False
    ok = write_json(state_path(state_dir, SETTINGS_FILE), persisted)
    return merged, warnings, errors, ok


def reset_settings(state_dir, environ=None):
    """Drop panel overrides — .env defaults apply again."""
    try:
        os.unlink(state_path(state_dir, SETTINGS_FILE))
    except OSError:
        pass
    return env_defaults(environ)


def load_schedule(state_dir, environ=None):
    base = env_defaults(environ, SCHEDULE_SPEC, _ENV_PREFIX + "SCHEDULE_")
    persisted = read_json(state_path(state_dir, SCHEDULE_FILE), {}) or {}
    schedule, warnings, errors = normalize_schedule(persisted, base)
    return schedule, warnings, errors


def save_schedule(state_dir, values, environ=None):
    base = env_defaults(environ, SCHEDULE_SPEC, _ENV_PREFIX + "SCHEDULE_")
    persisted = read_json(state_path(state_dir, SCHEDULE_FILE), {}) or {}
    for key, value in (values or {}).items():
        if key in SCHEDULE_SPEC:
            persisted[key] = value
    merged, warnings, errors = normalize_schedule(persisted, base)
    if errors:
        return merged, warnings, errors, False
    ok = write_json(state_path(state_dir, SCHEDULE_FILE), persisted)
    return merged, warnings, errors, ok


# ---------------------------------------------------------------------------
# scheduler (requirement 4: time-based strategy selection)
# ---------------------------------------------------------------------------
MINUTE = 60
_DAY_INDEX = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def next_run_at(schedule, now=None, last_run=None):
    """Epoch seconds of the next scheduled run (None when disabled).

    The panel keeps this value in state and fires when `now` reaches it; after
    every run it recomputes from the previous SCHEDULED instant (`last_run`) so
    a long outage never produces a burst of catch-up runs.

        interval — `interval_min` after `last_run` (after now + interval when
                   there is no previous run; run_on_start fires immediately);
        daily    — the next local occurrence of `at` (HH:MM);
        weekly   — the next occurrence of `at` on one of `days`.
    """
    now = time.time() if now is None else float(now)
    if not schedule.get("enabled"):
        return None
    mode = schedule.get("mode", "daily")
    if mode == "interval":
        step = max(5, int(schedule.get("interval_min", 360))) * MINUTE
        if last_run is None:
            return now if schedule.get("run_on_start") else now + step
        target = float(last_run) + step
        while target <= now:                      # never burst after downtime
            target += step
        return target

    if not valid_hhmm(schedule.get("at")):
        return None
    hour, minute = [int(x) for x in str(schedule["at"]).split(":")]
    days = [d for d in schedule.get("days", list(DAYS)) if d in _DAY_INDEX] or list(DAYS)
    anchor = max(now, float(last_run)) if last_run is not None else now
    for offset in range(0, 9):
        stamp = time.localtime(anchor + offset * 24 * 3600)
        candidate = int(time.mktime((stamp.tm_year, stamp.tm_mon, stamp.tm_mday,
                                     hour, minute, 0, stamp.tm_wday, stamp.tm_yday,
                                     stamp.tm_isdst)))
        if candidate <= anchor:
            continue
        if mode == "weekly" and DAYS[time.localtime(candidate).tm_wday] not in days:
            continue
        return candidate
    return None


def schedule_due(schedule, now=None, next_run=None):
    """True when the stored `next_run` instant has arrived."""
    now = time.time() if now is None else float(now)
    if not schedule.get("enabled") or next_run is None:
        return False
    return now >= float(next_run)


def format_local(stamp):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stamp)) if stamp else ""
# ---------------------------------------------------------------------------
# command lines (multithreaded SO_MARK probing, embedded mode)
# ---------------------------------------------------------------------------
def _globals(settings, workers=None):
    """Global blockcheckw flags.  --no-conflict-cleanup (embedded mode) is not
    optional here: without it blockcheckw would kill our nfqws2 and drop the
    live firewall because it mistakes them for a conflicting zapret2 instance."""
    args = [settings["bin"]]
    if workers is not None:
        args += ["-w", str(workers)]
    args += ["--profiles-per-instance",
             str(max(MIN_PROFILES_FOR_CHECK, int(settings["profiles_per_instance"])))]
    args += ["--auto", "--no-conflict-cleanup"]
    if settings.get("via"):
        args += ["--via", settings["via"]]
    return args


def scan_argv(settings, domain, scan_out):
    """`scan` — the full strategy grid for one domain (candidates JSON)."""
    args = _globals(settings, workers=int(settings["workers"]))
    args += ["scan", "-d", domain, "-p", ",".join(settings["protocols"]),
             "--dns", settings["dns"], "--timeout", str(int(settings["scan_timeout"])),
             "--top", str(int(settings["scan_top"])), "-o", scan_out]
    if settings.get("alive_via"):
        args += ["--alive-via", settings["alive_via"]]
    if settings.get("grid") == "file" and settings.get("grid_file"):
        args += ["--from-file", settings["grid_file"]]
    return args


def check_argv(settings, domain, scan_out, check_out):
    """`check` — the false-positive filter: M byte-axis passes + authenticity.

    No -w: `check` verifies sequentially by design (blockcheckw warns about it);
    workers only widen the parallel scan.
    """
    args = _globals(settings)
    args += ["check", "--from-file", scan_out, "-d", domain,
             "--dns", settings["dns"],
             "--timeout", str(int(settings["check_timeout"])),
             "--idle-ms", str(int(settings["idle_ms"])),
             "--take", str(int(settings["take"])),
             "--passes", str(int(settings["passes"])),
             "--probe-path", settings["probe_path"],
             "--identity-path", settings["identity_path"],
             "-o", check_out]
    if settings.get("reference_via"):
        args += ["--reference-via", settings["reference_via"]]
    return args


def slug(text, limit=40):
    return re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")[:limit] or "x"


def run_paths(run_dir, domain):
    base = slug(domain)
    return {
        "domain": domain,
        "scan_out": os.path.join(run_dir, "scan_%s.json" % base),
        "check_out": os.path.join(run_dir, "check_%s.json" % base),
        "log": os.path.join(run_dir, "bcw_%s.log" % base),
    }


def plan(settings, run_dir):
    """Exact command lines for every domain (used by the harness and tests)."""
    runs = []
    for domain in settings["domains"]:
        paths = run_paths(run_dir, domain)
        runs.append(dict(
            paths,
            scan=scan_argv(settings, domain, paths["scan_out"]),
            check=check_argv(settings, domain, paths["scan_out"], paths["check_out"]),
        ))
    return {
        "bin": settings["bin"],
        "queue": settings["queue"],
        "home": os.path.join(run_dir, "home"),
        "runs": runs,
    }


# ---------------------------------------------------------------------------
# report parsing
# ---------------------------------------------------------------------------
def parse_scan_report(data):
    """Normalise a `scan` JSON report (also accepts an already parsed dict)."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return None
    if not isinstance(data, dict) or "strategies" not in data:
        return None
    rows = []
    for item in data.get("strategies") or []:
        if not isinstance(item, dict) or not item.get("args"):
            continue
        rows.append({
            "protocol": str(item.get("protocol", "")),
            "args": str(item.get("args", "")),
            "coverage": int(item.get("coverage", 1) or 1),
        })
    return {
        "domain": str(data.get("domain", "")),
        "block_type": str(data.get("block_type", "")),
        "dns_spoofed": bool(data.get("dns_spoofed", False)),
        "blocked": list(data.get("blocked") or []),
        "total": int(data.get("total", 0) or 0),
        "working": int(data.get("working", 0) or 0),
        "strategies": rows,
    }


def parse_check_report(data):
    """Normalise a `check` JSON report; keeps the two axes side by side."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return None
    if not isinstance(data, dict) or "strategies" not in data:
        return None
    rows = []
    for item in data.get("strategies") or []:
        if not isinstance(item, dict) or not item.get("args"):
            continue
        share = item.get("median_share")
        rows.append({
            "protocol": str(item.get("protocol", "")),
            "args": str(item.get("args", "")),
            "coverage": int(item.get("coverage", 1) or 1),
            "working": bool(item.get("working", False)),
            "success_rate": float(item.get("success_rate", 0.0) or 0.0),
            "passes_ok": int(item.get("passes_ok", 0) or 0),
            "passes_total": int(item.get("passes_total", 0) or 0),
            "median_share": None if share is None else float(share),
            "median_latency_ms": int(item.get("median_latency_ms", 0) or 0),
            "median_speed_kbps": float(item.get("median_speed_kbps", 0.0) or 0.0),
            "longest_silence_ms": item.get("longest_silence_ms"),
            "observed": str(item.get("observed", "")),
            "admits": [str(x) for x in (item.get("admits") or [])],
        })
    return {
        "domain": str(data.get("domain", "")),
        "total": int(data.get("total", 0) or 0),
        "working": int(data.get("working", 0) or 0),
        "elapsed_secs": float(data.get("elapsed_secs", 0.0) or 0.0),
        "inconclusive": bool(data.get("inconclusive", False)),
        "strategies": rows,
    }


def read_report(path):
    """Read a scan/check report from disk (None when missing/unreadable)."""
    return read_json(path)


# ---------------------------------------------------------------------------
# false-positive filter + ranking
# ---------------------------------------------------------------------------
def filter_reason(row, settings):
    """Why a checked strategy is refused; None when it passes every filter.

    `working` already means "authenticity not refuted AND full delivery on every
    pass"; the extra knobs let the operator tighten it further (volume share,
    mirage exclusion).
    """
    if not row.get("working"):
        if row.get("admits") == ["Mirage"]:
            return "mirage (authenticity refuted)"
        return str(row.get("observed") or "not working")
    if settings.get("exclude_mirage") and row.get("admits") == ["Mirage"]:
        return "mirage (authenticity refuted)"
    min_share = float(settings.get("min_share", 0.0) or 0.0)
    if min_share > 0:
        share = row.get("median_share")
        if share is None:
            return "no volume reference (--reference-via needed to judge share)"
        if share < min_share:
            return "delivered %.0f%% of the reference volume (< %.0f%%)" % (
                share * 100, min_share * 100)
    return None


def rank(rows):
    """Best-first: working, then full-pass rate, then volume share, then latency."""
    return sorted(
        rows,
        key=lambda r: (0 if r.get("working") else 1,
                       -float(r.get("success_rate", 0.0)),
                       -(float(r["median_share"]) if r.get("median_share") is not None else 0.0),
                       int(r.get("median_latency_ms", 0) or 0)))


def select_working(rows, settings):
    """Split checked rows into (accepted, refused) per the false-positive filter."""
    accepted, refused = [], []
    for row in rank(rows):
        reason = filter_reason(row, settings)
        if reason is None:
            accepted.append(row)
        else:
            refused.append(dict(row, reason=reason))
    return accepted, refused
# ---------------------------------------------------------------------------
# importing the survivors into the live strategy catalog
# ---------------------------------------------------------------------------
# nfqws2 options a discovered strategy may carry: the scanner emits real zapret2
# argument strings, but nothing that would hijack the engine's queue/identity
# (the same denylist strategy.py enforces).
FORBIDDEN_ARGS = {
    "--qnum", "--fwmark", "--daemon", "--pidfile", "--intercept", "--dry-run",
    "--version", "--chdir", "--uid", "--user", "--lua-init", "--writable",
}


def validate_args(text):
    """Return the whitespace-normalised argument string; raise if unusable."""
    try:
        tokens = shlex.split(text or "")
    except ValueError as exc:
        raise ValueError("unparsable strategy args: %s" % exc)
    if not tokens:
        raise ValueError("empty strategy args")
    for token in tokens:
        if "\0" in token or not token.startswith("--"):
            raise ValueError("invalid strategy argument: %r" % token)
        if token.split("=", 1)[0] in FORBIDDEN_ARGS:
            raise ValueError("forbidden strategy argument: %s" % token.split("=", 1)[0])
    return " ".join(tokens)


def _needs_no_reasm(args, protocol):
    """TLS ClientHello strategies must disable nfqws hello reassembly (see
    config/strategies.json _no_reasm_note): otherwise a lost segment of a
    multi-segment hello hangs the connection forever."""
    if "--filter-tcp=443" in args or "--payload=tls_client_hello" in args:
        return True
def plan_import(result, settings, existing_entries, run_id=""):
    """Catalog entries for the selected strategies of a finished run.

    Best-first, capped at `max_import` per protocol, skipping arguments that are
    already in the catalog.  Returns (entries, skipped) — skipped rows carry a
    `reason`.
    """
    limit = int(settings.get("max_import", 5) or 0)
    prefix = slug(settings.get("import_prefix") or "bcw", 16)
    known_args, known_ids = set(), set()
    for entry in existing_entries or []:
        for key in ("nfqws_opt", "lua_opt"):
            if entry.get(key):
                known_args.add(" ".join(str(entry[key]).split()))
        if entry.get("id"):
            known_ids.add(str(entry["id"]))

    entries, skipped, per_protocol = [], [], {}
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    for dom in (result.get("domains") if isinstance(result, dict) else None) or []:
        domain = str(dom.get("domain", ""))
        for row in dom.get("working") or []:
            protocol = str(row.get("protocol") or "HTTPS/TLS1.2")
            try:
                args = validate_args(row.get("args", ""))
            except ValueError as exc:
                skipped.append({"domain": domain, "protocol": protocol,
                                "args": str(row.get("args", "")), "reason": str(exc)})
                continue
            if args in known_args:
                skipped.append({"domain": domain, "protocol": protocol, "args": args,
                                "reason": "already in the catalog"})
                continue
            if limit and per_protocol.get(protocol, 0) >= limit:
                skipped.append({"domain": domain, "protocol": protocol, "args": args,
                                "reason": "over max_import=%d for this protocol" % limit})
                continue
            stem = "%s_%s_%s" % (prefix, slug(domain, 20), slug(protocol, 16))
            strategy_id, counter = stem, 1
            while strategy_id in known_ids:
                counter += 1
                strategy_id = "%s_%d" % (stem, counter)
            shares = row.get("median_share")
            entry = {
                "id": strategy_id,
                "name": "blockcheckw: %s (%s)" % (domain or "domain", protocol),
                "desc": ("Selected by blockcheckw: %d/%d full passes, %s of the "
                         "reference volume, %d ms, authenticity: %s%s" % (
                             row.get("passes_ok", 0), row.get("passes_total", 0),
                             ("%.0f%%" % (shares * 100)) if shares is not None else "n/a",
                             int(row.get("median_latency_ms", 0) or 0),
                             ",".join(row.get("admits") or [])
                             or row.get("observed", "n/a"),
                             " (domain: %s)" % domain if domain else "")),
                "nfqws_opt": args,
                "lua_opt": args if "--lua-desync=" in args else "",
                "protocol": protocol,
                "imported": True,
                "import_time": now,
                "import_original_args": args,
                "bcw": {
                    "domain": domain,
                    "block_type": dom.get("block_type", ""),
                    "run_id": run_id,
                    "passes_ok": row.get("passes_ok", 0),
                    "passes_total": row.get("passes_total", 0),
                    "median_share": shares,
                    "median_latency_ms": row.get("median_latency_ms", 0),
                    "success_rate": row.get("success_rate", 0.0),
                    "admits": row.get("admits") or [],
                    "observed": row.get("observed", ""),
                },
            }
            if _needs_no_reasm(args, protocol):
                entry["no_reasm"] = True
            entries.append(entry)
            known_ids.add(strategy_id)
            known_args.add(args)
            per_protocol[protocol] = per_protocol.get(protocol, 0) + 1
    return entries, skipped


def merge_catalog(catalog, entries):
    """Return a new catalog dict with `entries` replacing same-id strategies."""
    data = dict(catalog or {})
    data.setdefault("strategies", [])
    ids = {str(e.get("id")) for e in entries}
    data["strategies"] = [s for s in data["strategies"] if str(s.get("id")) not in ids]
    data["strategies"].extend(entries)
    return data
    upper = (protocol or "").upper()
    return upper.startswith("HTTPS") and "TLS1" in upper
# ---------------------------------------------------------------------------
# job state (panel) + run orchestration (harness)
# ---------------------------------------------------------------------------
def tail_file(path, lines=400, max_bytes=256 * 1024):
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            data = handle.read().decode("utf-8", "replace")
    except OSError:
        return ""
    rows = data.splitlines()
    if size > max_bytes and rows:
        rows = rows[1:]
    return "\n".join(rows[-int(lines):])


def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def load_job(state_dir):
    return read_json(state_path(state_dir, JOB_FILE), {}) or {}


def save_job(state_dir, job):
    return write_json(state_path(state_dir, JOB_FILE), job)


def prune_runs(runs_dir, keep=10):
    """Keep only the newest `keep` run directories (old reports are bulky)."""
    try:
        names = sorted((n for n in os.listdir(runs_dir)
                        if os.path.isdir(os.path.join(runs_dir, n))), reverse=True)
    except OSError:
        return []
    removed = []
    for name in names[int(keep):]:
        path = os.path.join(runs_dir, name)
        try:
            for entry in os.listdir(path):
                try:
                    os.unlink(os.path.join(path, entry))
                except OSError:
                    pass
            os.rmdir(path)
            removed.append(name)
        except OSError:
            pass
    return removed


def _run_step(cmd, log_path, timeout, env, cwd):
    """Run one blockcheckw step, streaming its output into log_path."""
    with open(log_path, "a", encoding="utf-8", errors="replace") as log:
        log.write("\n$ %s\n" % " ".join(cmd))
        log.flush()
        try:
            proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=log,
                                  stderr=subprocess.STDOUT, timeout=timeout)
            return proc.returncode, None
        except subprocess.TimeoutExpired:
            log.write("\n!! step timed out after %ss\n" % timeout)
            return 124, "timeout after %ss" % timeout
        except OSError as exc:
            log.write("\n!! cannot run %s: %s\n" % (cmd[0], exc))
            return 127, str(exc)


def run(settings, run_dir, log_path=None, environ=None):
    """Execute scan+check for every configured domain; return the result dict.

    This is what wz-bcw.sh invokes; the panel parses result.json afterwards.
    Nothing here touches the live gateway: blockcheckw runs in embedded mode,
    on its own NFQUEUE and its own nft table.
    """
    started = time.time()
    deadline = started + float(settings.get("job_timeout", 3600))
    os.makedirs(run_dir, exist_ok=True)
    home = os.path.join(run_dir, "home")
    os.makedirs(home, exist_ok=True)
    log_path = log_path or os.path.join(run_dir, "bcw.log")
    plans = plan(settings, run_dir)["runs"]
    result = {
        "ok": False,
        "success": False,
        "run_id": os.path.basename(os.path.normpath(run_dir)),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "finished_at": None,
        "took_s": None,
        "queue": settings.get("queue", BCW_QUEUE_FIXED),
        "settings": {key: settings.get(key) for key in SETTINGS_SPEC},
        "plans": plans,
        "domains": [],
        "errors": [],
        "log": "",
    }
    env = dict(os.environ if environ is None else environ)
    env["HOME"] = home            # isolate blockcheckw's persisted CLI defaults
    env.pop("SUDO_USER", None)    # ... so it cannot read/chown the caller's config

    for item in plans:
        dom = {"domain": item["domain"], "scan_rc": None, "check_rc": None,
               "block_type": "", "blocked": [], "scanned": 0, "checked": 0,
               "inconclusive": False, "working": [], "refused": [],
               "scan": None, "check": None}
        budget = max(5, deadline - time.time())
        rc, note = _run_step(item["scan"], log_path, budget, env, run_dir)
        dom["scan_rc"] = rc
        if rc != 0:
            result["errors"].append("%s: scan failed (rc=%s%s)" % (
                item["domain"], rc, ": " + note if note else ""))
            result["domains"].append(dom)
            continue
        scan = parse_scan_report(read_report(item["scan_out"]))
        if scan is None:
            result["errors"].append("%s: scan produced no readable report" % item["domain"])
            result["domains"].append(dom)
            continue
        dom.update(block_type=scan["block_type"], blocked=scan["blocked"],
                   scanned=len(scan["strategies"]), scan=scan)
        if not scan["strategies"]:
            result["domains"].append(dom)
            continue
        budget = max(5, deadline - time.time())
        rc, note = _run_step(item["check"], log_path, budget, env, run_dir)
        dom["check_rc"] = rc
        if rc != 0:
            result["errors"].append("%s: check failed (rc=%s%s)" % (
                item["domain"], rc, ": " + note if note else ""))
            result["domains"].append(dom)
            continue
        check = parse_check_report(read_report(item["check_out"]))
        if check is None:
            result["errors"].append("%s: check produced no readable report" % item["domain"])
            result["domains"].append(dom)
            continue
        accepted, refused = select_working(check["strategies"], settings)
        dom.update(checked=len(check["strategies"]), inconclusive=check["inconclusive"],
                   check=check, working=accepted, refused=refused[:100])
        result["domains"].append(dom)

    result["ok"] = any(d["scan_rc"] == 0 for d in result["domains"])
    result["success"] = any(d["working"] for d in result["domains"])
    result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result["took_s"] = round(time.time() - started, 1)
    result["log"] = tail_file(log_path, settings.get("log_lines", 400))
    write_json(os.path.join(run_dir, "result.json"), result)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def settings_from_file(path, environ=None):
    """Load a settings JSON and normalize it over the .env defaults."""
    return normalize(read_json(path, {}) or {}, env_defaults(environ))


def summarize(result):
    """One-glance summary of a finished run (panel + actions log)."""
    parts = []
    for dom in result.get("domains") or []:
        bits = ["%s: %s" % (dom.get("domain"), dom.get("block_type") or "?"),
                "scanned %d" % int(dom.get("scanned") or 0)]
        if dom.get("checked"):
            bits.append("checked %d" % int(dom["checked"]))
        bits.append("working %d" % len(dom.get("working") or []))
        if dom.get("inconclusive"):
            bits.append("CONTROL PASSED — domain is not blocked")
        parts.append(", ".join(bits))
    if result.get("errors"):
        parts.append("%d error(s)" % len(result["errors"]))
    return " | ".join(parts) or "no domains"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    command = argv[0]
    if command == "defaults":
        out = {"settings": env_defaults(),
               "schedule": env_defaults(None, SCHEDULE_SPEC, _ENV_PREFIX + "SCHEDULE_")}
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    if command in ("plan", "run"):
        if len(argv) < 3:
            print("usage: blockcheck.py %s <settings.json> <run_dir>" % command,
                  file=sys.stderr)
            return 2
        settings, warnings, errors = settings_from_file(argv[1])
        if errors:
            print(json.dumps({"ok": False, "errors": errors, "warnings": warnings},
                             ensure_ascii=False, indent=2))
            return 2
        if command == "plan":
            print(json.dumps({"warnings": warnings,
                              "plan": plan(settings, argv[2])},
                             ensure_ascii=False, indent=2))
            return 0
        result = run(settings, argv[2])
        result["warnings"] = warnings
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1
    if command == "next":
        values = read_json(argv[1], {}) if len(argv) > 1 else {}
        base = env_defaults(None, SCHEDULE_SPEC, _ENV_PREFIX + "SCHEDULE_")
        schedule, warnings, errors = normalize_schedule(values, base)
        now = float(argv[2]) if len(argv) > 2 else time.time()
        stamp = next_run_at(schedule, now, values.get("last_run"))
        print(json.dumps({"schedule": schedule, "warnings": warnings, "errors": errors,
                          "next_run": stamp, "next_run_local": format_local(stamp)},
                         ensure_ascii=False, indent=2))
        return 0
    print("unknown command %r (defaults|plan|run|next)" % command, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())