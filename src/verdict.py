"""Verdicts ("did this connection hang / get reset / get cut off?") and the
TSPU intelligence that is aggregated from them.

EVERYTHING HERE IS A GUESS FROM CIRCUMSTANTIAL EVIDENCE. The container cannot
see inside TLS and has no packet capture; it sees (a) what nfqws did to the
outbound ClientHello (nfqtrace) and (b) what the kernel's connection tracker
recorded about the connection (conntrack). Every verdict therefore carries its
evidence and a confidence, and the UI shows both.

Inputs per connection:
  ct   conntrack.Conntrack.public(rec) dict, or None
  nfq  nfqtrace.NfqTrace.public(rec) dict, or None
  now  current epoch seconds

Stdlib only."""
import collections

NO_REPLY_AFTER = 6.0        # s without any answer to SYN
STALL_AFTER = 8.0           # s of silence after ClientHello / frozen download
HELLO_REPLY_MIN = 1000      # a real ServerHello+cert flight is bigger than this
CUTOFF_MIN, CUTOFF_MAX = 10 * 1024, 26 * 1024   # the "freeze after ~16-20 KB" zone
FLOWING_WITHIN = 5.0

GOOD = ("ok", "flowing")
BAD = ("no_reply", "reset_after_hello", "reset_mid", "stall_after_hello",
       "cutoff_suspected", "closed_early")

LABELS = {
    "no_reply": "нет ответа на SYN",
    "reset_after_hello": "сброс (RST) после ClientHello",
    "reset_mid": "сброс (RST) посреди передачи",
    "stall_after_hello": "завис после ClientHello",
    "cutoff_suspected": "заморожен после ~16–20 КБ",
    "closed_early": "закрыт без данных",
    "ok": "работает/завершён нормально",
    "flowing": "данные идут",
    "established": "соединение есть (байты не считаются)",
    "idle": "тихо",
    "connecting": "соединяется",
    "unknown": "нет данных со стороны сети",
}
_FIN_STATES = ("FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT")


def _kb(n):
    return "%.1f КБ" % (n / 1024.0)


def judge(ct, nfq, now):
    """-> {code, label, confidence, evidence[], stalled_for, bytes_back}."""
    ev = []
    if ct is None:
        if nfq and nfq.get("syn", 0) > 1 and nfq.get("retrans", 0) >= 1:
            return _out("no_reply", "medium", ["nfqws видел %d SYN-пакетов (повторы)" % nfq["syn"],
                                               "conntrack запись не найдена"], None, None)
        return _out("unknown", "low", ["conntrack не видел это соединение"], None, None)

    ref = ct["gone_at"] or now
    age = ref - ct["first"]
    state = ct["state"]
    rb = ct["reply_bytes"]
    hello_ts = nfq.get("hello_ts") if nfq else None
    has_hello = hello_ts is not None
    sent_hello = has_hello or (ct.get("orig_bytes") or 0) > 200
    if nfq and nfq.get("desynced"):
        ev.append("nfqws обработал ClientHello (%s)" % ", ".join(nfq["actions"]))
    if rb is not None:
        ev.append("ответ сервера: %s" % _kb(rb))

    # 1 -- the SYN never got an answer
    if state == "SYN_SENT" or (ct["unreplied"] and not ct["assured"]
                               and not any(s == "ESTABLISHED" for _, s in ct["states"])):
        if age >= NO_REPLY_AFTER or ct["gone_at"]:
            if nfq and nfq.get("syn", 0) > 1:
                ev.append("SYN отправлен %d раз(а)" % nfq["syn"])
            ev.append("ни одного пакета в ответ за %.0f с" % age)
            return _out("no_reply", "high", ev, age, 0)
        return _out("connecting", "low", ev, None, None)

    # 2 -- RST seen (conntrack CLOSE)
    if state == "CLOSE":
        if sent_hello and (rb is None or rb < HELLO_REPLY_MIN):
            ev.append("состояние CLOSE = увидели RST; ответ меньше ServerHello")
            conf = "high" if rb is not None else "medium"
            return _out("reset_after_hello", conf, ev, None, rb)
        if rb is not None and rb >= HELLO_REPLY_MIN:
            ev.append("состояние CLOSE = RST после %s данных" % _kb(rb))
            return _out("reset_mid", "medium", ev, None, rb)
        return _out("reset_mid", "low", ev + ["состояние CLOSE = RST"], None, rb)

    # 3 -- alive
    if ct["gone_at"] is None and state in ("ESTABLISHED", "SYN_RECV"):
        if rb is None:
            if sent_hello and ct["unreplied"]:
                return _out("stall_after_hello", "low", ev + ["[UNREPLIED] после ClientHello"],
                            None, None)
            return _out("established", "low",
                        ev + ["байты не считаются (nf_conntrack_acct=0)"], None, None)
        quiet = now - (ct["reply_grew_at"] or hello_ts or ct["first"])
        if has_hello and rb < HELLO_REPLY_MIN and (now - hello_ts) >= STALL_AFTER:
            ev.append("после ClientHello тишина %.0f с" % (now - hello_ts))
            return _out("stall_after_hello", "high", ev, now - hello_ts, rb)
        if CUTOFF_MIN <= rb <= CUTOFF_MAX and quiet >= STALL_AFTER:
            ev.append("счётчик замер на %s уже %.0f с" % (_kb(rb), quiet))
            return _out("cutoff_suspected", "medium", ev, quiet, rb)
        if rb > 0 and quiet <= FLOWING_WITHIN:
            return _out("flowing", "high", ev, None, rb)
        if rb > 0:
            return _out("idle", "low", ev + ["последние данные %.0f с назад" % quiet], quiet, rb)
        return _out("connecting", "low", ev, None, rb)

    # 4 -- finished
    if rb is not None and rb >= HELLO_REPLY_MIN:
        return _out("ok", "high" if state in _FIN_STATES or ct["gone_at"] else "medium",
                    ev, None, rb)
    if sent_hello:
        return _out("closed_early", "medium",
                    ev + ["закрыто (%s) почти без ответа" % (state or "gone")], None, rb)
    return _out("unknown", "low", ev, None, rb)


def _out(code, conf, evidence, stalled_for, bytes_back):
    return {"code": code, "label": LABELS.get(code, code), "confidence": conf,
            "evidence": evidence, "stalled_for": None if stalled_for is None
            else round(stalled_for, 1), "bytes_back": bytes_back,
            "bad": code in BAD}


def timeline(ct, nfq, now):
    """Ordered [{t, dt, text}] for the flow detail view (dt = seconds since first event)."""
    ev = []
    if ct:
        ev.append((ct["first"], "conntrack: соединение замечено"))
        for t, s in ct["states"]:
            ev.append((t, "TCP-состояние → %s" % s))
        if ct.get("reply_grew_at"):
            ev.append((ct["reply_grew_at"], "последний прирост ответа (%s)"
                       % (_kb(ct["reply_bytes"]) if ct["reply_bytes"] is not None else "?")))
        if ct["gone_at"]:
            ev.append((ct["gone_at"], "запись conntrack исчезла"))
    if nfq:
        ev.append((nfq["first"], "nfqws: первый пакет (%d SYN)" % nfq.get("syn", 0)))
        if nfq.get("hello_ts"):
            parts = ["ClientHello"]
            if nfq.get("sni"):
                parts.append("SNI " + nfq["sni"])
            if nfq.get("actions"):
                parts.append("nfqws: " + " + ".join(nfq["actions"]))
            ev.append((nfq["hello_ts"], " · ".join(parts)))
    ev.sort(key=lambda e: e[0])
    t0 = ev[0][0] if ev else now
    return [{"t": t, "dt": round(t - t0, 2), "text": text} for t, text in ev]


# ---------------------------------------------------------------------------
# TSPU intelligence
# ---------------------------------------------------------------------------
def _hypotheses(totals, ips, hosts, strategies):
    """Plain-language conclusions, each with the evidence that supports it."""
    out = []
    n_bad = sum(totals.get(c, 0) for c in BAD)
    if not n_bad:
        return out
    sni_ips = [ip for ip, d in ips.items() if d["ok_hosts"] and d["bad_hosts"]]
    if sni_ips:
        out.append({"kind": "sni_filter", "confidence": "high" if len(sni_ips) > 1 else "medium",
                    "text": "Блокировка по SNI: на одном IP одни имена работают, другие нет",
                    "evidence": ["%s: ok %s | плохо %s" % (
                        i, ", ".join(sorted(ips[i]["ok_hosts"])[:2]),
                        ", ".join(sorted(ips[i]["bad_hosts"])[:2])) for i in sni_ips[:3]]})
    ip_block = [ip for ip, d in ips.items() if d["bad"] >= 2 and not d["ok"]
                and d["codes"].get("no_reply", 0) >= 2]
    if ip_block:
        out.append({"kind": "ip_block", "confidence": "medium",
                    "text": "Блокировка по IP/порту: SYN вообще без ответа",
                    "evidence": ["%s: %d без ответа" % (i, ips[i]["codes"]["no_reply"])
                                 for i in ip_block[:3]]})
    if totals.get("reset_after_hello", 0):
        out.append({"kind": "rst_injection", "confidence": "medium",
                    "text": "Инъекция RST после ClientHello (характерно для ТСПУ по SNI)",
                    "evidence": ["потоков: %d" % totals["reset_after_hello"]]})
    if totals.get("stall_after_hello", 0):
        out.append({"kind": "hello_drop", "confidence": "medium",
                    "text": "ClientHello молча отбрасывается (ответа нет, RST нет)",
                    "evidence": ["потоков: %d" % totals["stall_after_hello"]]})
    if totals.get("cutoff_suspected", 0):
        out.append({"kind": "throttle_cutoff", "confidence": "low",
                    "text": "Заморозка после ~16–20 КБ (известный приём ТСПУ против CDN)",
                    "evidence": ["потоков: %d (может быть и обычная пауза)" % totals["cutoff_suspected"]]})
    with_d = strategies.get("desync")
    without = strategies.get("plain")
    if with_d and without and with_d["n"] >= 3 and without["n"] >= 3:
        r1, r0 = with_d["ok"] / with_d["n"], without["ok"] / without["n"]
        out.append({"kind": "strategy_effect",
                    "confidence": "medium" if min(with_d["n"], without["n"]) >= 10 else "low",
                    "text": ("nfqws помогает: успех %d%% с обработкой против %d%% без"
                             if r1 > r0 + 0.15 else
                             "Эффекта от nfqws не видно: успех %d%% с обработкой, %d%% без")
                    % (round(r1 * 100), round(r0 * 100)),
                    "evidence": ["с обработкой %d/%d, без %d/%d" % (
                        with_d["ok"], with_d["n"], without["ok"], without["n"])]})
    return out


def build_intel(rows):
    """rows: flow dicts with host, dst_ip, verdict{code}, egress{desynced, actions,
    profile}. -> aggregated dossier."""
    totals = collections.Counter()
    ips, hosts = {}, {}
    strat = {"desync": {"n": 0, "ok": 0}, "plain": {"n": 0, "ok": 0}}
    by_actions = collections.defaultdict(lambda: {"n": 0, "ok": 0, "bad": 0})
    for r in rows:
        v = r.get("verdict")
        if not v or v["code"] in ("unknown", "connecting", "established", "idle"):
            continue
        code = v["code"]
        good, bad = code in GOOD, code in BAD
        totals[code] += 1
        host = r.get("host") or ""
        ip = r.get("dst_ip") or ""
        egress = r.get("egress") or {}
        if ip:
            d = ips.setdefault(ip, {"ok": 0, "bad": 0, "ok_hosts": set(), "bad_hosts": set(),
                                    "codes": collections.Counter()})
            d["ok"] += good
            d["bad"] += bad
            d["codes"][code] += 1
            if host:
                (d["ok_hosts"] if good else d["bad_hosts"] if bad else set()).add(host)
        if host:
            h = hosts.setdefault(host, {"host": host, "n": 0, "ok": 0, "bad": 0,
                                        "codes": collections.Counter(), "ips": set()})
            h["n"] += 1
            h["ok"] += good
            h["bad"] += bad
            h["codes"][code] += 1
            if ip:
                h["ips"].add(ip)
        if good or bad:
            k = "desync" if egress.get("desynced") else "plain"
            strat[k]["n"] += 1
            strat[k]["ok"] += good
            key = " + ".join(egress.get("actions") or []) or "(без обработки)"
            by_actions[key]["n"] += 1
            by_actions[key]["ok"] += good
            by_actions[key]["bad"] += bad
    hyp = _hypotheses(totals, ips, hosts, strat)
    host_rows = []
    for h in hosts.values():
        host_rows.append({"host": h["host"], "n": h["n"], "ok": h["ok"], "bad": h["bad"],
                          "codes": dict(h["codes"]), "ips": len(h["ips"])})
    host_rows.sort(key=lambda h: (h["bad"], h["n"]), reverse=True)
    return {
        "totals": dict(totals),
        "judged": sum(totals.values()),
        "bad": sum(totals.get(c, 0) for c in BAD),
        "hosts": host_rows[:40],
        "strategies": [dict(actions=k, **v) for k, v in sorted(
            by_actions.items(), key=lambda kv: -kv[1]["n"])][:10],
        "hypotheses": hyp,
        "note": "Выводы — догадки по косвенным признакам (nfqws-лог + conntrack), "
                "не по перехвату пакетов.",
    }
