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


def _build_advisory(devs):
    """Assemble the advisory. Every store is read read-only and passed in — the
    pure logic lives in advisory.py."""
    ids = set(devs)
    cve = {d: v for d, v in (A._load_ro(A.CVE_FINDINGS_FILE) or {}).items() if d in ids}
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
    return advisory.build(
        devs, cve_by_dev=cve, eol_by_dev=eol, scans_by_dev=scans,
        failed_checks_by_dev=A._failed_protect_checks(devs),
        exposure_mutes=(A._config_ro().get('exposure_mutes') or []),
        muted_fn=A._exposure_muted, now=int(time.time()))


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
