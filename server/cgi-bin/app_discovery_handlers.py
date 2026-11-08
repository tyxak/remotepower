"""RemotePower — App discovery: the apps a host runs, and the monitor and connector each one offers (8.0.0)

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
# The Linux agent says which apps of the catalog (app_catalog.py) its host runs (`sysinfo.discovered`); an older agent says nothing and the apps are worked out here from the
# listening ports and containers it did report. Each app found comes with what can be done about it: a monitor of its port, run from the host's own agent (`via_host`, the
# 7.4.9 probes), and the connector that reads its API, started with the address filled in. Nothing is created without a person pressing a button.

import app_catalog
import re

_HTTPS_PORTS = (443, 6443, 8443, 8920, 8971)     # where the app answers TLS by default
_MAX_ROWS = 200
_DISMISSED_KEY = 'app_discovery_dismissed'
_ID_RE = re.compile(r'^[a-z0-9_]{1,32}$')


def _dismissed(cfg, dev_id):
    """The app ids hidden for this host. The setting is a map of host id to a list; anything else in it is nothing."""
    raw = (cfg or {}).get(_DISMISSED_KEY)
    mine = raw.get(dev_id) if isinstance(raw, dict) else None
    return {a for a in mine if isinstance(a, str)} if isinstance(mine, list) else set()


def _found_for(dev_id, dev, containers):
    """(source, found) for a host: what its agent said, or what is worked out here from the listening ports and containers an older agent reported."""
    si = dev.get('sysinfo') if isinstance(dev.get('sysinfo'), dict) else {}
    if isinstance(si.get('discovered'), list):
        return 'agent', app_catalog.clean_found(si['discovered'])
    if A._device_os_family(dev) != 'linux':
        return 'server', []         # the catalog knows the process names and services of Linux: a Windows or macOS agent says neither, and its ports would only be guessed at
    ports = si.get('listening_ports') if isinstance(si.get('listening_ports'), list) else []
    items = ((containers or {}).get(dev_id) or {}).get('items')
    return 'server', app_catalog.discover(ports, items if isinstance(items, list) else [], [])


def _hostport(mtype, target):
    """(host, port) a monitor's target names, or None: `host:port` for tcp, a URL for http (the port of the scheme when it names none)."""
    t = str(target or '').strip()
    try:
        if mtype == 'http':
            m = re.match(r'^(https?)://([^/:?#]+|\[[0-9a-fA-F:]+\])(?::(\d+))?', t)
            return (m.group(2).strip('[]').lower(), int(m.group(3) or (443 if m.group(1) == 'https' else 80))) if m else None
        host, _, port = t.rpartition(':')
        return (host.strip('[]').lower(), int(port)) if host and port.isdigit() else None
    except ValueError:
        return None


def _names_of(dev):
    return {str(dev.get(k) or '').strip().lower() for k in ('ip', 'hostname', 'name')} - {''}


def _monitored(cfg, dev_id, dev, port):
    """Whether a monitor already looks at this port of this host: one its agent runs (`via_host`) against its own loopback or address, or one the server runs against the
    host's address, name or hostname."""
    mine = _names_of(dev) | {'127.0.0.1', 'localhost', '::1'}
    for m in (cfg or {}).get('monitors') or []:
        if not isinstance(m, dict) or m.get('type') not in ('tcp', 'http'):
            continue
        hp = _hostport(m['type'], m.get('target'))
        if hp is None or hp[1] != port:
            continue
        if m.get('via_host') == dev_id and hp[0] in mine:
            return True
        if not m.get('via_host') and not m.get('via_satellite') and hp[0] in _names_of(dev):
            return True
    return False


def _connected(cfg, dev_id, dev, connector, port, integrations):
    """Whether an integration of this connector already reads this host: bound to it ("Runs on host"), or pointed at its address on this port."""
    mine = _names_of(dev)
    for inst in integrations or []:
        if not isinstance(inst, dict) or inst.get('type') != connector:
            continue
        if inst.get('device_id') == dev_id:
            return True
        m = re.match(r'^https?://([^/:?#]+|\[[0-9a-fA-F:]+\])(?::(\d+))?', str(inst.get('url') or '').strip())
        if m and m.group(1).strip('[]').lower() in mine and (m.group(2) is None or int(m.group(2)) == port):
            return True
    return False


def _row(found, dev_id, dev, cfg, integrations, dismissed, probe_problem):
    app = app_catalog.describe(found['id'])
    port = found['port']
    scope = found['scope']
    host = str(dev.get('ip') or dev.get('hostname') or '').strip()
    connector = None
    if app['connector']:
        reachable = bool(host) and port is not None and scope != 'local'
        scheme = 'https' if (port in _HTTPS_PORTS or app.get('scheme') == 'https') else 'http'
        connector = {'type': app['connector'],
                     'label': (A.integrations_mod.CONNECTORS.get(app['connector']) or {}).get('label') or app['connector'],
                     'url': ('%s://%s:%d' % (scheme, host, port)) if reachable else '',
                     'reachable': reachable,
                     'connected': _connected(cfg, dev_id, dev, app['connector'], port, integrations)}
    return {'id': app['id'], 'name': app['name'], 'kind': app['kind'], 'port': port, 'scope': scope, 'via': found['via'], 'container': found['container'],
            'can_monitor': port is not None and not probe_problem,
            'monitored': port is not None and _monitored(cfg, dev_id, dev, port),
            'connector': connector, 'dismissed': found['id'] in dismissed}


def _rows_for(dev_id, dev, cfg, integrations, containers):
    """(source, rows, why a monitor cannot be run from this host or ''): the same check a saved monitor goes through (a Linux agent that runs tcp checks, not in audit mode)."""
    source, found = _found_for(dev_id, dev, containers)
    hidden = _dismissed(cfg, dev_id)
    problem = A.host_probe_validate(dev_id, 'tcp', {'type': 'tcp', 'target': '127.0.0.1:80', 'target_kind': 'host'})
    return source, [_row(f, dev_id, dev, cfg, integrations, hidden, problem) for f in found], problem


def explorer_rows(devices, containers):
    """Data Explorer `apps` (8.0.0): one row per (host, app found on it) for the hosts given. The hosts are already the caller's (the caller filters them), and the
    rows come from the same read the host's page uses, so "which hosts run Jellyfin" and the drawer's list cannot disagree."""
    out = []
    for dev_id, dev in sorted(devices.items(), key=lambda kv: str((kv[1] or {}).get('name') or kv[0]).lower()):
        if not isinstance(dev, dict) or dev.get('agentless') or dev.get('decommissioned'):
            continue
        source, found = _found_for(dev_id, dev, containers)
        for f in found:
            app = app_catalog.describe(f['id'])
            if not app:
                continue
            out.append({'device_id': dev_id, 'device_name': dev.get('name') or dev_id, 'app': app['id'], 'name': app['name'], 'kind': app['kind'],
                        'port': f['port'], 'scope': f['scope'], 'via': ', '.join(f['via']), 'container': f['container'], 'source': source})
    return out


def hosts_running(devices, containers, needle):
    """Ids of the hosts of `devices` that have an app found on them whose id or name contains `needle` (any case): the Fleet Query `app` criterion (8.0.0)."""
    needle = str(needle or '').strip().lower()
    out = set()
    if not needle:
        return out
    for dev_id, dev in devices.items():
        if not isinstance(dev, dict) or dev.get('agentless') or dev.get('decommissioned'):
            continue
        for f in _found_for(dev_id, dev, containers)[1]:
            app = app_catalog.describe(f['id'])
            if app and (needle in str(app['id']).lower() or needle in str(app['name']).lower()):
                out.add(dev_id)
                break
    return out


def handle_device_apps(dev_id):
    """GET /api/devices/<id>/apps -- the apps this host runs, each with what can be done about it (8.0.0).

    Read-only, any signed-in role: it says nothing the host's own page does not (its ports and containers). The path is under /api/devices/<id>/, so the pre-dispatch
    gate has already refused a host the caller may not see (another tenant's, or outside a scoped role)."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict):
        A.respond(404, {'error': 'Host not found'})
    cfg = A._config_ro()
    containers = A._load_ro(A.CONTAINERS_FILE) if A.backend_exists(A.CONTAINERS_FILE) else {}
    source, rows, problem = _rows_for(dev_id, dev, cfg, A._get_integrations(cfg), containers)
    # the Integrations switch (Settings -> Advanced, `show_homelab`) turns the connectors off everywhere, so then nothing offers one
    homelab = cfg.get('show_homelab', True) is not False
    if not homelab:
        for r in rows:
            r['connector'] = None
    A.respond(200, {'device_id': dev_id, 'source': source, 'monitor_problem': problem, 'show_homelab': homelab,
                    'apps': [r for r in rows if not r['dismissed']], 'dismissed': [r for r in rows if r['dismissed']]})


def handle_app_discovery():
    """GET /api/app-discovery -- the apps found on the hosts the caller may see that a connector could read and nothing reads yet (8.0.0): the list behind "Found on your
    hosts" on the Integrations page. A host's own page lists everything it runs; this is the part worth a connector."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    cfg = A._config_ro()
    if cfg.get('show_homelab', True) is False:
        A.respond(200, {'apps': [], 'hosts': 0, 'found': 0, 'show_homelab': False})
    devices = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    containers = A._load_ro(A.CONTAINERS_FILE) if A.backend_exists(A.CONTAINERS_FILE) else {}
    integrations = A._get_integrations(cfg)
    out, hosts, found_total = [], 0, 0
    for dev_id, dev in sorted(devices.items(), key=lambda kv: str(kv[1].get('name') or kv[0]).lower()):
        if not isinstance(dev, dict) or dev.get('agentless') or dev.get('decommissioned'):
            continue
        _source, rows, _problem = _rows_for(dev_id, dev, cfg, integrations, containers)
        found_total += len(rows)
        mine = [r for r in rows if r['connector'] and r['connector']['reachable'] and not r['connector']['connected'] and not r['dismissed']]
        if mine:
            hosts += 1
        for r in mine:
            if len(out) < _MAX_ROWS:
                out.append({'device_id': dev_id, 'device_name': dev.get('name') or dev_id, 'id': r['id'], 'name': r['name'], 'port': r['port'], 'scope': r['scope'],
                            'connector': r['connector']})
    A.respond(200, {'apps': out, 'hosts': hosts, 'found': found_total, 'show_homelab': True})


def _unique_label(existing, base):
    taken = {str(m.get('label')) for m in existing if isinstance(m, dict)}
    label, n = base, 2
    while label in taken:
        label = '%s (%d)' % (base, n)
        n += 1
    return label


def handle_device_app_monitor(dev_id):
    """POST /api/devices/<id>/apps/monitor {app} -- a tcp monitor of one app's port, run from this host's own agent against the host's loopback (8.0.0). The app and its
    port are the ones the host reports now, not ones the body names, so the request cannot aim a host's agent at another port. A monitor that already looks at the port is
    answered, not doubled. Admin of the install, like every other write to the monitor list."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_instance_admin_auth('Monitors')
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    body = A._read_valid(A.request_models.AppDiscoveryRequest)
    app_id = str(body.get('app') or '').strip()
    if not _ID_RE.match(app_id) or app_catalog.describe(app_id) is None:
        A.respond(400, {'error': 'app must be one of the catalog'})
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict):
        A.respond(404, {'error': 'Host not found'})
    if dev.get('agentless'):
        A.respond(400, {'error': 'an agentless host has no agent to probe from'})
    cfg = A._config_ro()
    containers = A._load_ro(A.CONTAINERS_FILE) if A.backend_exists(A.CONTAINERS_FILE) else {}
    _source, rows, _problem = _rows_for(dev_id, dev, cfg, A._get_integrations(cfg), containers)
    row = next((r for r in rows if r['id'] == app_id), None)
    if row is None:
        A.respond(404, {'error': 'this host does not report that app (refresh after its next check-in)'})
    if row['port'] is None:
        A.respond(400, {'error': 'no listening port is known for that app on this host, so there is nothing to monitor'})
    target, why = A._sanitize_monitor_target('tcp', '127.0.0.1:%d' % row['port'], with_reason=True, allow_loopback=True)
    if target is None:
        A.respond(400, {'error': why or 'invalid target'})
    entry = {'type': 'tcp', 'target': target, 'target_kind': 'host', 'paused': False, 'via_host': dev_id}
    problem = A.host_probe_validate(dev_id, 'tcp', dict(entry, label='x'))
    if problem:
        A.respond(400, {'error': problem})
    existing_label = ''
    with A._LockedUpdate(A.CONFIG_FILE) as cfg_w:
        mons = cfg_w.get('monitors') if isinstance(cfg_w.get('monitors'), list) else []
        for m in mons:
            if isinstance(m, dict) and m.get('type') == 'tcp' and m.get('target') == target and m.get('via_host') == dev_id:
                existing_label = str(m.get('label') or '')
                break
        else:
            if len(mons) >= 500:
                A.respond(400, {'error': 'there are 500 monitors already'})
            entry['label'] = _unique_label(mons, ('%s on %s' % (row['name'], dev.get('name') or dev_id))[:120])
            mons.append(entry)
            cfg_w['monitors'] = mons
    if existing_label:
        A.respond(200, {'ok': True, 'existing': True, 'label': existing_label})
    A.audit_log(actor, 'app_discovery_monitor', 'device=%s app=%s port=%d label=%r' % (dev_id, app_id, row['port'], entry['label']))
    A.respond(200, {'ok': True, 'existing': False, 'label': entry['label'], 'monitor': entry})


def handle_device_app_dismiss(dev_id):
    """POST /api/devices/<id>/apps/dismiss {app, dismissed?} -- hide an app from this host's list, or show it again with `dismissed: false` (8.0.0). Admin of the install:
    the choice is kept in the settings, for everybody."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_instance_admin_auth('App discovery')
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    body = A._read_valid(A.request_models.AppDiscoveryRequest)
    app_id = str(body.get('app') or '').strip()
    if not _ID_RE.match(app_id) or app_catalog.describe(app_id) is None:
        A.respond(400, {'error': 'app must be one of the catalog'})
    if not isinstance(A.device_get(dev_id), dict):
        A.respond(404, {'error': 'Host not found'})
    hide = body.get('dismissed') is not False
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        raw = cfg.get(_DISMISSED_KEY) if isinstance(cfg.get(_DISMISSED_KEY), dict) else {}
        mine = [a for a in (raw.get(dev_id) if isinstance(raw.get(dev_id), list) else []) if isinstance(a, str) and a != app_id]
        if hide:
            mine.append(app_id)
        if mine:
            raw[dev_id] = sorted(set(mine))
        else:
            raw.pop(dev_id, None)
        cfg[_DISMISSED_KEY] = raw
    A.audit_log(actor, 'app_discovery_dismiss', 'device=%s app=%s dismissed=%s' % (dev_id, app_id, hide))
    A.respond(200, {'ok': True, 'dismissed': hide})
