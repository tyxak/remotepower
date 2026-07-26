"""RemotePower — the shared reading of posture stores.

Risk and the Security Advisory answer different questions and deliberately stay
separate systems: Risk is a cardinal, additive, per-DEVICE score ("which of my
hosts do I look at?"); the Advisory is an ordinal list grouped by PROBLEM
("what do I fix this morning?"). Merging them would make both worse — sum the
Advisory's findings and you lose the ordering that is its entire product; group
Risk's factors across hosts and there is no per-asset score left to sort by.

What they *should* share is the layer below that: how a store is read. That is
where the duplication actually was, and it had already produced a real bug —
Risk applied the CVE ignore list and the Advisory did not, so a CVE an operator
had accepted vanished from one and kept driving the other. Two implementations
of "read the CVE store" will diverge again the moment either is touched.

So the rule for this module is narrow and worth stating: it holds the
EXTRACTION (which rows count, which decorations apply, what shape comes out),
never the INTERPRETATION (points, severities, wording). A function here returns
plain data both callers can map their own way. Nothing in here imports api —
the callers pass the stores in, same contract as advisory.py.
"""


def decorated_cve_findings(
    cve_rec, dev_id, ignore_data=None, kev=None, epss=None, scanner=None, enrich=None
):
    """The findings list for one device, with the read-time decorations applied.

    `ignored` and `kev` are NOT stored — the scanner stamps `ignored` onto a
    copy at read time, and `kev` comes from a feed cache keyed by vuln id. A
    caller that reads the raw store therefore sees neither, which is exactly
    how the Advisory ended up recommending CVEs the operator had accepted.

    Returns a NEW list of NEW dicts: the caller may hold a `load()` result that
    other code reads afterwards, and a derived field written back into it would
    persist into the store on the next save.
    """
    finds = cve_rec.get("findings") if isinstance(cve_rec, dict) else cve_rec
    if not isinstance(finds, list):
        return []
    out = [dict(f) for f in finds if isinstance(f, dict)]
    if ignore_data and scanner is not None:
        try:
            out = [dict(f) for f in scanner.apply_ignore_list(out, ignore_data, dev_id)]
        except Exception:
            pass
    if kev and enrich is not None:
        try:
            enrich(out, kev, epss or {})
        except Exception:
            pass
    return out


def live_cve_findings(cve_rec, dev_id, **kw):
    """`decorated_cve_findings` minus anything the operator has accepted."""
    return [f for f in decorated_cve_findings(cve_rec, dev_id, **kw) if not f.get("ignored")]


def stale_backups_by_device(backup_state, monitors=None):
    """{device_id: ['label — 96h old (threshold 24h)', …]}.

    The store is keyed `<device_id>:<path>`, so a caller that iterates it
    without splitting gives every host every other host's failures. Labels and
    thresholds come from the configured monitors where one matches.
    """
    mons = {m["path"]: m for m in (monitors or []) if isinstance(m, dict) and m.get("path")}
    out = {}
    for key, entry in (backup_state or {}).items():
        if ":" not in str(key) or not isinstance(entry, dict):
            continue
        if entry.get("ok", True):
            continue
        did, path = str(key).split(":", 1)
        mon = mons.get(path) or {}
        age = entry.get("age_h")
        try:
            age_s = f"{float(age):.0f}h old" if age else "missing"
        except (TypeError, ValueError):
            age_s = "missing"
        try:
            max_h = f'{float(mon.get("max_age_hours", 24)):.0f}h'
        except (TypeError, ValueError):
            max_h = "24h"
        out.setdefault(did, []).append(f'{mon.get("label") or path} — {age_s} (threshold {max_h})')
    return out


def live_secret_findings(secrets_rec):
    """Unmuted secret-scanner findings for one device. A muted fingerprint is
    the operator saying "that is a placeholder" — it must not count anywhere."""
    finds = (secrets_rec or {}).get("findings") if isinstance(secrets_rec, dict) else None
    if not isinstance(finds, list):
        return []
    return [f for f in finds if isinstance(f, dict) and not f.get("muted")]


def av_verdict(av_rec, tools):
    """{'infected': int, 'realtime_off': bool} for one device's AV record.

    An EMPTY record means "no AV data", not "clean" and certainly not
    "infected" — most hosts have no record at all, and a caller that treats
    absence as a finding produces noise on the whole fleet.
    """
    if not isinstance(av_rec, dict) or not av_rec:
        return {"infected": 0, "realtime_off": False}
    infected = 0
    for t in tools:
        try:
            infected += int((av_rec.get(t) or {}).get("infected") or 0)
        except (TypeError, ValueError):
            pass
    off = any(isinstance(av_rec.get(t), dict) and av_rec[t].get("realtime") is False for t in tools)
    return {"infected": infected, "realtime_off": off}


def image_cve_counts(img_rec):
    """(critical, high) summed across a device's running container images."""
    imgs = (img_rec or {}).get("images") if isinstance(img_rec, dict) else None
    if not isinstance(imgs, list):
        return (0, 0)
    crit = high = 0
    for i in imgs:
        if not isinstance(i, dict):
            continue
        try:
            crit += int(i.get("critical") or 0)
            high += int(i.get("high") or 0)
        except (TypeError, ValueError):
            pass
    return (crit, high)
