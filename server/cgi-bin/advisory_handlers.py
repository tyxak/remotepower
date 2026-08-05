"""RemotePower — Security Advisory — prioritized, cross-layer findings from already-collected data

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers /
rack_ipam_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.save / …
    working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` so a test that patches
    one of them is seen by its caller.

Constants stay in api.py and are read here through A. Pure logic goes in a
sibling module (imported directly, like dmarc_monitor / tls_monitor).
"""


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {name!r}') from None


A = None


def bind(api_globals):
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


import time

import advisory
import posture_signals


def _advisory_scope(qs):
    """(devices, label) for the requested scope, already filtered to what the
    caller may see.

    _scope_filter_devices folds in BOTH role scope and tenant isolation (a
    tenant admin has scope=None but must not advise on another tenant's fleet),
    so every path below starts from its output — never from the raw store.
    """
    devs = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    kind = (qs.get('scope', [''])[0] or 'all').lower()
    target = (qs.get('target', [''])[0] or '').strip()
    if kind == 'host':
        if not target:
            A.respond(400, {'error': 'target is required for scope=host'})
        dev = devs.get(target)
        if not isinstance(dev, dict):
            # 404 rather than 403: a cross-tenant id must not be distinguishable
            # from one that does not exist.
            A.respond(404, {'error': 'device not found'})
        return {target: dev}, (dev.get('name') or target)
    if kind == 'tag':
        if not target:
            A.respond(400, {'error': 'target is required for scope=tag'})
        return ({d: v for d, v in devs.items()
                 if isinstance(v, dict) and target in [str(t) for t in (v.get('tags') or [])]},
                f'tag "{target}"')
    if kind == 'group':
        if not target:
            A.respond(400, {'error': 'target is required for scope=group'})
        return ({d: v for d, v in devs.items()
                 if isinstance(v, dict) and str(v.get('group', '')) == target},
                f'group "{target}"')
    return devs, 'the whole fleet'


def _failed_protect_checks(devs):
    """{device_id: [failing check, …]} for the protect/baseline check types.

    Read from the per-device state the ingest sweep already maintains, so this
    costs one config read rather than re-evaluating every check.
    """
    out = {}
    defs = {str(c.get('id')): c for c in (A._config_ro().get('custom_checks') or [])
            if isinstance(c, dict) and c.get('id')}
    for did, dev in devs.items():
        if not isinstance(dev, dict):
            continue
        rows = []
        for cid, st in (dev.get('custom_check_state') or {}).items():
            if not isinstance(st, dict) or st.get('status') not in ('critical', 'warning'):
                continue
            cdef = defs.get(str(cid)) or {}
            if cdef.get('kind') != 'protect':
                continue
            rows.append({'id': cid, 'name': cdef.get('name') or cid,
                         'status': st.get('status'), 'output': st.get('output')})
        if rows:
            out[did] = rows
    return out


def _advisory_brute_force(ids):
    """{device_id: [{unit, source_ip, count}, …]} for hosts under active
    guessing, using the same store and window the Home page reads.

    advisory.py used to look for this under `sysinfo.brute_force`, a key
    nothing has ever written.
    """
    if not A._config_ro().get('brute_force_enabled', True):
        return {}
    try:
        store = A._load_ro(A.BRUTE_FORCE_FILE) or {}
    except Exception:
        return {}
    cfg = A._config_ro()
    window = int(cfg.get('brute_force_window_seconds') or A.BRUTE_WINDOW_SECONDS)
    thresh = int(cfg.get('brute_force_threshold') or A.BRUTE_THRESHOLD)
    cutoff = int(time.time()) - window
    out = {}
    for did in ids:
        try:
            rows = A._bf_active(store.get(did) or {}, cutoff, thresh)
        except Exception:
            continue
        if rows:
            out[did] = rows
    return out


def _advisory_stale_backups(ids, devs):
    """{device_id: ['label — 96h old (threshold 24h)', …]}, scoped to `ids`.

    The fold itself is posture_signals' job — Risk reads the same store the
    same way, and two implementations of "which backups are stale" is exactly
    the divergence this module was carved out to prevent.
    """
    bs_file = A.DATA_DIR / 'backup_state.json'
    if not A.backend_exists(bs_file):
        return {}
    try:
        state = A._load_ro(bs_file) or {}
    except Exception:
        return {}
    all_stale = posture_signals.stale_backups_by_device(
        state, A._config_ro().get('backup_monitors') or [])
    return {d: v for d, v in all_stale.items() if d in ids}


def _advisory_tls_expiring():
    """[{label, days_left}] for monitored TLS targets at or past their warning
    window — fleet-level, since the TLS monitor probes targets, not devices."""
    try:
        targets = A._load_ro(A.TLS_TARGETS_FILE) or {}
        results = A._load_ro(A.TLS_RESULTS_FILE) or {}
    except Exception:
        return []
    out = []
    for tid, res in results.items():
        if not isinstance(res, dict) or res.get('dns_error') or res.get('tls_error'):
            continue
        if not res.get('expires_at'):
            continue
        tgt = targets.get(tid) if isinstance(targets.get(tid), dict) else {}
        host = tgt.get('host') or res.get('host') or tid
        port = tgt.get('port') or res.get('port')
        label = f'{host}:{port}' if port and int(port) != 443 else str(host)
        try:
            days = A.tls_monitor.days_until_expiry(res)
        except Exception:
            continue
        if days <= 14:
            out.append({'label': label, 'days_left': days})
    out.sort(key=lambda c: c['days_left'])
    return out[:25]


def _advisory_agent_tamper(devs):
    """{device_id: 'mismatch'|'update_rejected'} — the agent-binary integrity
    verdicts that previously reached nothing but a badge on the device row.

    `mismatch` outranks `update_rejected`: a rejected update is the tripwire
    working, a hash mismatch is the tripwire having already failed.
    """
    out = {}
    for did, dev in devs.items():
        if not isinstance(dev, dict):
            continue
        try:
            st = A._agent_integrity_status(dev, A._canonical_agent_sha_for(dev),
                                           A.SERVER_VERSION)
        except Exception:
            st = None
        if st == 'mismatch':
            out[did] = 'mismatch'
        elif dev.get('agent_update_rejected'):
            out[did] = 'update_rejected'
    return out


def _advisory_weak_ssh_keys(ids):
    """{device_id: ['user — ssh-dss', …]} from the authorized-keys baseline.

    "A key was ADDED" is an event and already an alert; the baseline is
    rewritten on every heartbeat, so a delta read here would always be empty.
    The key's ALGORITHM is a durable state, which is what makes this one
    answerable from the store (the same reason the port-baseline delta is not).
    """
    try:
        store = A._load_ro(A.SSH_KEY_BASELINE_FILE) or {}
    except Exception:
        return {}
    weak = set(A._WEAK_SSH_TYPES)
    out = {}
    for did, users in store.items():
        if did not in ids or not isinstance(users, dict):
            continue
        rows = []
        for uname, keys in users.items():
            for k in (keys or [])[:200]:
                ktype = str(k).split(None, 1)[0].lower() if k else ''
                if ktype in weak:
                    rows.append(f'{uname} — {ktype}')
        if rows:
            out[did] = rows
    return out


def _advisory_risky_accounts(ids):
    """{device_id: {'empty': ['user (login)', …], 'stale': ['user — 812 days', …]}}
    from the per-host local-account posture the agent already reports.

    v6.4.2: the agent has tagged `empty_password` and `stale_password` since
    v3.14.0 and the server has persisted both into `hardware.json` just as long.
    Only `uid0` and `sudo` were ever consumed — so the one question the
    `id.sshempty` finding literally instructs the operator to go and answer by
    hand ("audit for accounts that actually have a blank password") was
    answerable from the store that finding is already reading.

    A durable state, not a delta, so it belongs here rather than in the event
    stream (the same reasoning as `_advisory_weak_ssh_keys` above — and the
    blank-password EDGE does now fire its own alert, from the accounts ingest).
    """
    try:
        store = A._load_ro(A.HARDWARE_FILE) or {}
    except Exception:
        return {}
    out = {}
    for did, rec in store.items():
        if did not in ids or not isinstance(rec, dict):
            continue
        empty, stale = [], []
        for a in (rec.get('accounts') or [])[:500]:
            if not isinstance(a, dict):
                continue
            flags = a.get('flags') or []
            user = str(a.get('user') or '')[:64]
            if not user:
                continue
            if 'empty_password' in flags:
                empty.append(user + (' (login shell)' if a.get('login')
                                     else ' (no login shell)'))
            if 'stale_password' in flags:
                age = a.get('age_days')
                stale.append(f'{user} — {int(age)} days'
                             if isinstance(age, (int, float)) else user)
        if empty or stale:
            out[did] = {'empty': empty, 'stale': stale}
    return out


def _build_advisory(devs):
    """Assemble the advisory. Every store is read read-only and passed in — the
    pure logic lives in advisory.py."""
    ids = set(devs)
    cve = {}
    ignore = A._load_ro(A.CVE_IGNORE_FILE) or {}
    _kev, _epss = A._kev_epss()
    for d, v in (A._load_ro(A.CVE_FINDINGS_FILE) or {}).items():
        if d not in ids or not isinstance(v, dict):
            continue
        # `ignored` and `kev` are read-time decorations the store does not
        # carry — one shared reading, so Risk and the Advisory cannot disagree
        # about which CVEs still count.
        cve[d] = {'findings': posture_signals.decorated_cve_findings(
            v, d, ignore_data=ignore, kev=_kev, epss=_epss,
            scanner=A.cve_scanner, enrich=A._enrich_cve_findings)}
    pkgs = A._load_ro(A.PACKAGES_FILE) or {}
    eol = {}
    for d, dev in devs.items():
        try:
            eol[d] = A._device_os_eol(dev, pkgs.get(d) or {}) or {}
        except Exception:
            eol[d] = {}
    scans = {}
    for s in (A._load_ro(A.SCANS_FILE) or {}).values():
        if not isinstance(s, dict):
            continue
        tdid = s.get('target_device_id') or ''
        if tdid in ids:
            scans.setdefault(tdid, []).append(s)
    secrets = {d: posture_signals.live_secret_findings(v)
               for d, v in (A._load_ro(A.SECRETS_FILE) or {}).items()
               if d in ids and isinstance(v, dict)}
    return advisory.build(
        devs, cve_by_dev=cve, eol_by_dev=eol, scans_by_dev=scans,
        failed_checks_by_dev=A._failed_protect_checks(devs),
        exposure_mutes=(A._config_ro().get('exposure_mutes') or []),
        muted_fn=A._exposure_muted,
        bf_by_dev=A._advisory_brute_force(ids),
        secrets_by_dev=secrets,
        backups_by_dev=A._advisory_stale_backups(ids, devs),
        tls_expiring=A._advisory_tls_expiring(),
        scap_by_dev={d: v for d, v in (A._load_ro(A.SCAP_FILE) or {}).items()
                     if d in ids and isinstance(v, dict)},
        agent_tamper_by_dev=A._advisory_agent_tamper(devs),
        weak_keys_by_dev=A._advisory_weak_ssh_keys(ids),
        accounts_by_dev=A._advisory_risky_accounts(ids),
        now=int(time.time()))


# ── handlers ─────────────────────────────────────────────────────────────────
def handle_security_advisory():
    """GET /api/security/advisory?scope=all|host|tag|group&target=… — the
    prioritized, cross-layer advisory built from already-collected data.

    Read-only and on demand at any scope; nothing is scanned or contacted.
    """
    A.require_auth()
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    devs, label = A._advisory_scope(qs)
    out = A._build_advisory(devs)
    out['scope_label'] = label
    A.respond(200, out)


def handle_security_advisory_brief():
    """POST /api/security/advisory/brief {scope, target} — the REDACTED brief the
    AI advisor is given.

    The client posts this text to /api/ai/chat with system='security_advisory',
    so the existing AI plumbing (provider config, token budget, model picker,
    audit) is reused unchanged. Redaction happens HERE, on the server, because
    the provider may be off-box: only titles, layers, severities and host counts
    leave — never the evidence, which carries hostnames, paths, URLs and matched
    log content. Building the brief client-side from the loaded advisory would
    have sent all of it.
    """
    A.require_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    qs = {'scope': [str(body.get('scope', 'all'))],
          'target': [str(body.get('target', ''))]}
    devs, label = A._advisory_scope(qs)
    adv = A._build_advisory(devs)
    A.respond(200, {'brief': advisory.summarize_for_ai(adv, label),
                    'scope_label': label, 'counts': adv.get('counts') or {}})
