"""RemotePower — the shared reading of posture stores.

Risk and the Security Advisory answer different questions and stay
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

import math


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
    if not isinstance(backup_state, dict):
        return {}
    mons = {m["path"]: m for m in (monitors or []) if isinstance(m, dict) and m.get("path")}
    out = {}
    for key, entry in backup_state.items():
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


# Pool and array states that mean healthy, lower case. The Checks row, the Fleet Query facet, the fleet report, the dashboard
# count and (since 7.5.0) the advisory take "is this pool unhealthy" from here; they had four copies of the set. Everything not in
# it is unhealthy, `unknown` and `inactive` included: the agent writes `unknown` for an md array whose /proc/mdstat line it could
# not read, and a pool nobody can read is not one nobody needs to look at. The storage ALERT and the risk score keep their own
# lists of known-bad words on purpose: they page and score, and a host that has always reported `unknown` should not do either.
POOL_OK = frozenset({"online", "active", "clean", "healthy", "ok"})


def pool_unhealthy(state):
    """True when a pool or array state is not one of the healthy words. An empty state says nothing and is not unhealthy."""
    s = str(state or "").strip().lower()
    return bool(s) and s not in POOL_OK


# The statuses that mean a backup check is failing NOW. handle_heartbeat fires backup_verify_failed and restore_drill_failed on
# these same sets, so the alert, the advisory, the risk score and the compliance report cannot disagree about "failing".
# `tool_missing` is a drill state the heartbeat remembers so that a drill which works again clears its alert; it is not a
# failure of the backup (a host without the tool has not been tested).
VERIFY_BAD = ("failed", "timeout", "error", "unreachable")
DRILL_BAD = ("failed", "timeout", "error")


def failed_backup_checks_by_device(backup_state, monitors=None):
    """{device_id: ['label — integrity check failed (restic)', 'label — restore drill failed'], …}.

    7.5.0. A backup can be fresh and not restorable: the file is young and the repository is corrupt, or the drill that
    restores a file from it fails. Both are stored (`verify_status`, `drill_status`) and both page the operator
    (backup_verify_failed, restore_drill_failed), and the compliance report, the advisory and the risk score read freshness
    only, so a host whose backup could not be restored still passed A1.2, E8-8 and HIPAA 164.308(a)(7)(ii)(A).
    Keyed like stale_backups_by_device: `<device_id>:<path>`, split on the first colon.
    """
    if not isinstance(backup_state, dict):
        return {}
    mons = {m["path"]: m for m in (monitors or []) if isinstance(m, dict) and m.get("path")}
    out = {}
    for key, entry in backup_state.items():
        if ":" not in str(key) or not isinstance(entry, dict):
            continue
        did, path = str(key).split(":", 1)
        label = (mons.get(path) or {}).get("label") or path
        if entry.get("verify_status") in VERIFY_BAD:
            tool = str(entry.get("verify_tool") or "").strip()[:24]
            out.setdefault(did, []).append(f"{label} — integrity check {entry['verify_status']}" + (f" ({tool})" if tool else ""))
        if entry.get("drill_status") in DRILL_BAD:
            out.setdefault(did, []).append(f"{label} — restore drill {entry['drill_status']}")
    return out


def risky_accounts(hw_rec):
    """([users with no password], [users with UID 0 besides root]) from a host's stored account list; both empty when the host
    reported no list.

    7.5.0. The Linux agent tags these (`empty_password`, `uid0`) on every account it reads and the server keeps the list; they
    raise events (empty_password_account, rogue_uid0) and a Checks row, and counted for nothing in the risk score and nowhere in
    the compliance report, which said it held no inventory of standing privilege. This is that inventory's two worst lines.
    Note `empty_password` needs the agent to run as root (it reads /etc/shadow), so a host whose agent does not is silent here."""
    acc = hw_rec.get("accounts") if isinstance(hw_rec, dict) else None
    blank, uid0 = [], []
    if isinstance(acc, list):
        for a in acc[:500]:
            flags = a.get("flags") if isinstance(a, dict) else None
            if not isinstance(flags, list):
                continue
            user = str(a.get("user") or "?")[:64]
            if "empty_password" in flags:
                blank.append(user)
            if "uid0" in flags:
                uid0.append(user)
    return blank, uid0


# The certificate files a host reports are the ones its own services use. The system CA bundle holds hundreds of certificates
# nobody renews: the agent does not scan those directories, and these prefixes drop them again for an older agent.
CA_BUNDLE_PREFIXES = ("/etc/ssl/certs/", "/etc/pki/ca-trust", "/usr/share/ca-certificates", "/etc/ca-certificates")
CERT_FILE_DEFAULT_DAYS = 21


def cert_file_days(cfg):
    """The warning window for a host's certificate files in days, or None when the operator turned certificate-file expiry off.

    7.5.0. One switch and one window (Settings, Alert parameters) for the alert, the Checks row, the Needs-attention item, the
    risk factor, the compliance control and the advisory. Before this the alert was the only reader: an expired
    /etc/nginx/ssl/site.pem raised one event and showed up nowhere else."""
    cfg = cfg if isinstance(cfg, dict) else {}
    if not cfg.get("cert_expiry_alerts_enabled", True):
        return None
    try:
        days = int(cfg.get("cert_file_expiring_days", CERT_FILE_DEFAULT_DAYS) or CERT_FILE_DEFAULT_DAYS)
    except (TypeError, ValueError, OverflowError):
        return CERT_FILE_DEFAULT_DAYS
    return days if days > 0 else CERT_FILE_DEFAULT_DAYS


def service_cert_files(certs):
    """The certificate files in a host's stored list that name a path and a real expiry, the system CA bundle left out."""
    if not isinstance(certs, list):
        return []
    out = []
    for c in certs[:500]:
        if not isinstance(c, dict):
            continue
        path, na = c.get("path"), c.get("not_after")
        if not isinstance(path, str) or not path or isinstance(na, bool) or not isinstance(na, (int, float)):
            continue
        if not (0 < na < math.inf) or path.startswith(CA_BUNDLE_PREFIXES):
            continue
        out.append(c)
    return out


def expiring_cert_files(certs, now, days):
    """[{path, not_after, days_left, expired}] for the service certificate files that expire within `days` days of `now` or
    already have, soonest first. `days_left` is whole days to the expiry and 0 for a file that has expired; read `expired` for
    that. `days` None (the signal is off) gives nothing."""
    if days is None:
        return []
    soon = now + days * 86400
    out = []
    for c in service_cert_files(certs):
        try:
            na = int(c["not_after"])
        except (TypeError, ValueError, OverflowError):
            continue
        if na <= soon:
            out.append({"path": c["path"], "not_after": na, "days_left": max(0, (na - now) // 86400), "expired": na <= now})
    out.sort(key=lambda r: (r["not_after"], r["path"]))
    return out


def expired_cert_files(certs, now):
    """The service certificate files whose expiry has passed, soonest first (a window of no days)."""
    return expiring_cert_files(certs, now, 0)


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
    # 7.5.0: the store's key is `realtime_enabled` (what the Windows agent's parser writes and _ingest_av keeps). This read
    # `realtime`, which nothing writes, so Defender switched off was invisible to the risk score and to the compliance AV control
    # while the alert, the Checks row and the AI index all saw it. Three test fixtures carried the same wrong key.
    off = any(isinstance(av_rec.get(t), dict) and av_rec[t].get("realtime_enabled") is False for t in tools)
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
