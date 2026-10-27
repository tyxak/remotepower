"""RemotePower — Integrations bound to a host, for the host drawer

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


# ── handlers ─────────────────────────────────────────────────────────────────
# def handle_device_integrations_example():
#     """GET /api/device_integrations/example."""
#     A.require_auth()
#     A.respond(200, {'ok': True})


# The most that is sent back: the last hundred polls are all the history there is, a strip of
# sixty is plenty to see a flap, and a probe rarely has more than a dozen things worth a line.
_STRIP_MAX = 60
_SERIES_MAX = 100
_METRICS_MAX = 24
_DETAIL_MAX = 300      # a probe's detail can carry a string a remote service chose
_STATUS_ORDER = {'critical': 0, 'warning': 1, 'unknown': 2, 'ok': 3}


def _scalar_metrics(metrics):
    """The latest values to list: numbers, booleans and short strings. A metric is whatever a
    remote service said, so nested data and long strings are cut down to what a line can show."""
    out = {}
    if not isinstance(metrics, dict):
        return out
    for k, v in metrics.items():
        if len(out) >= _METRICS_MAX:
            break
        if isinstance(v, bool) or (isinstance(v, (int, float)) and v == v
                                   and v not in (float('inf'), float('-inf'))):
            out[str(k)[:64]] = v
        elif isinstance(v, str):
            out[str(k)[:64]] = v[:64]
    return out


def _series(history):
    """{metric: [{ts, val}, ...]} from the numbers the poll kept, oldest first."""
    out = {}
    for e in history[-_SERIES_MAX:]:
        if not isinstance(e, dict) or not isinstance(e.get('m'), dict):
            continue
        for name, val in e['m'].items():
            out.setdefault(name, []).append({'ts': e.get('ts'), 'val': val})
    return out


def handle_device_integrations(dev_id):
    """GET /api/devices/<id>/integrations -- what runs on this host that the host cannot
    report itself (v7.4.2, #44).

    A Hubitat hub, a NAS app or a printer has no agent and may not answer SNMP, so its health
    comes from integrations bound to it ("Runs on host"). Binding already routed their alerts
    through the host; this is the other half, their status, latest values and history on the
    host's own card. Read-only, any signed-in role, like the Integrations page; the address and
    the credentials of an instance are not part of the answer. The path is under
    /api/devices/<id>/, so the pre-dispatch gate has already refused a host the caller may not
    see (another tenant's, or outside a scoped role)."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id) or A.device_get(dev_id) is None:
        A.respond(404, {'error': 'Host not found'})
    cfg = A._config_ro()
    if cfg.get('show_homelab', True) is False:
        A.respond(200, {'integrations': [], 'show_homelab': False})
    state = A._load_ro(A.INTEG_STATE_FILE) or {}
    latest = state.get('latest') or {}
    hist = state.get('history') or {}
    mod = A.integrations_mod
    rows = []
    for inst in A._get_integrations(cfg):
        if not isinstance(inst, dict) or inst.get('device_id') != dev_id:
            continue
        key = str(inst.get('id') or inst.get('label'))
        enabled = bool(inst.get('enabled'))
        r = latest.get(key) if enabled and isinstance(latest.get(key), dict) else {}
        h = hist.get(key) if enabled and isinstance(hist.get(key), list) else []
        metrics = _scalar_metrics(r.get('metrics'))
        rows.append({
            'id':         key,
            'label':      inst.get('label') or key,
            'type':       inst.get('type') or '',
            'type_label': (mod.CONNECTORS.get(inst.get('type')) or {}).get('label') or inst.get('type') or '',
            'enabled':    enabled,
            'status':     (r.get('status') or 'unknown') if enabled else 'unknown',
            'detail':     str(r.get('detail') or '')[:_DETAIL_MAX] if enabled else 'disabled',
            'checked':    r.get('checked'),
            'version':    r.get('version'),
            'metrics':    metrics,
            'stats':      mod.format_stats(inst.get('type'), r.get('metrics')),
            'series':     _series(h),
            'history':    [{'ts': e.get('ts'), 'status': e.get('status')}
                           for e in h[-_STRIP_MAX:] if isinstance(e, dict)],
        })
    rows.sort(key=lambda x: (_STATUS_ORDER.get(x['status'], 9), str(x['label']).lower()))
    A.respond(200, {'integrations': rows, 'show_homelab': True})
