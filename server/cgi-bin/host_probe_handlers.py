"""RemotePower — Monitors probed from a host's agent: which monitors a host runs, and what it reports back (7.4.9)

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

The server probes from where it is and a satellite from its own network. A monitor can also name a host (`via_host`): the host's
agent probes from there, which is the only way to watch a service on the host's own loopback or on a network only that host can
reach. The monitors ride the heartbeat response to that agent, which runs them on the monitor interval and reports the results with
a later heartbeat. Results go where a satellite's go: the last result of each monitor, the history and the down and up
transitions.
"""

import re


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


SUPPORTED = ('tcp', 'http', 'ping')
MAX_PER_HOST = 20
MAX_RESULTS = 200

_HOST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$')


def _target_problem(mtype, target):
    """Why this monitor's target may not be probed from a host, or ''. The address checks are the server's own, with the
    loopback allowed: a host's own loopback is the point of probing from it. A cloud metadata or link-local address is never
    allowed, here or for the server, since it would turn a monitor into a way to read what the host's cloud keeps for it."""
    target = str(target or '').strip()
    if mtype == 'ping':
        if not _HOST_RE.match(target):
            return 'expected a hostname or IP address'
        host = target
    elif mtype == 'tcp':
        host, _, port_s = target.rpartition(':')
        host = host.strip('[]')
        try:
            port = int(port_s)
        except (TypeError, ValueError):
            return 'expected host:port'
        if not 0 < port < 65536:
            return 'the port must be 1–65535'
        if not (_HOST_RE.match(host) or re.fullmatch(r'[0-9A-Fa-f:.]{2,45}', host)):
            return 'expected host:port'
    else:
        parsed = A.urllib.parse.urlparse(target)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return 'an HTTP monitor needs a full URL starting with http:// or https://'
        host = parsed.hostname
        if A._url_targets_local_or_meta(parsed, allow_loopback=True):
            return 'that address is not allowed (link-local or cloud metadata)'
        return ''
    if A._url_targets_local_or_meta(A.urllib.parse.urlparse(f'//{host}', scheme='tcp'), allow_loopback=True):
        return 'that address is not allowed (link-local or cloud metadata)'
    return ''


def _unsupported(mtype, m):
    """The reason a monitor is refused for what it asks of the agent, or ''. The agent compares a status code and a text the page
    must contain. A check that also asks for a regex, a missing text, a JSON field or a latency limit would pass where the
    server would fail it, so it is refused instead of run without them."""
    if mtype != 'http':
        return ''
    bm = m.get('body_match')
    if isinstance(bm, dict) and bm.get('value'):
        if bm.get('mode') == 'regex':
            return 'a regex body check is only available when the server probes it: use "Body must contain", or probe from the server'
        if bm.get('mode') == 'not_contains':
            return '"Body must NOT contain" is only available when the server probes it: use "Body must contain", or probe from the server'
    ej = m.get('expect_json')
    if isinstance(ej, dict) and str(ej.get('path', '')).strip():
        return 'a JSON field check is only available when the server probes it'
    ml = m.get('max_latency_ms')
    if isinstance(ml, (int, float)) and 0 < ml <= 600000:
        return 'a latency limit is only available when the server probes it'
    return ''


def host_probe_validate(dev_id, mtype, m):
    """'' when the monitor `m` of type `mtype` may be probed by the agent of host `dev_id`, otherwise the reason it may not. The
    host has to exist, run a Linux agent (the Windows and macOS agents do not probe) and not be agentless, the type has to be
    one the agent runs, the monitor has to name one address and not a tag or group of hosts, it may ask only for what the agent
    checks, and the address has to be one a probe may reach."""
    if not A._validate_id(dev_id):
        return 'the host is not a valid host id'
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict):
        return 'it probes from a host that is not enrolled'
    if dev.get('agentless'):
        return 'it probes from a host that has no agent'
    if A._device_os_family(dev) != 'linux':
        return 'only the Linux agent probes: a Windows or macOS host cannot run it'
    if (dev.get('sysinfo') or {}).get('audit_mode'):
        return 'that host is in audit mode (read-only) and does not run probes'
    if mtype not in SUPPORTED:
        return 'a host probes tcp, http and ping monitors'
    if m.get('target_kind', 'host') not in ('host', None, ''):
        return 'a monitor that runs from a host names one address, not a tag or a group'
    return _unsupported(mtype, m) or _target_problem(mtype, m.get('target', ''))


def host_monitors_for(dev_id, dev):
    """The monitors assigned to this host, as the specs its agent runs, or None for a host that is not a Linux agent host (the
    key is then left out of its heartbeat response). An empty list is sent when there are none, so a monitor that was removed
    stops being probed. A paused monitor is not sent."""
    if not isinstance(dev, dict) or dev.get('agentless') or A._device_os_family(dev) != 'linux':
        return None
    out = []
    for m in (A._config_ro().get('monitors') or []):
        if not isinstance(m, dict) or m.get('via_host') != dev_id or m.get('paused'):
            continue
        bm = m.get('body_match') if isinstance(m.get('body_match'), dict) else None
        out.append({
            'label': A._sanitize_str(m.get('label', m.get('target', '')), 128),
            'type': m.get('type', 'ping'),
            'target': A._sanitize_str(m.get('target', ''), 512),
            'expect_status': m.get('expect_status'),
            'expect_contains': bm.get('value') if bm and bm.get('mode') == 'contains' else None,
            'method': m.get('method'),
            'verify_tls': m.get('verify_tls'),
        })
        if len(out) >= MAX_PER_HOST:
            break
    return out


def clean_latency(lat):
    """A latency a probe reported, in milliseconds, as a number to keep, or None. A boolean, text, a negative number, one that is not
    finite and one too large to be a latency are not kept. An integer of 400 digits is compared and never converted, since
    float() of it raises."""
    if isinstance(lat, bool) or not isinstance(lat, (int, float)):
        return None
    if not 0 <= lat < 10 ** 7:          # false for NaN as well
        return None
    return round(float(lat), 1)


def host_probe_ingest(dev_id, raw):
    """Called for every heartbeat that carries `monitor_results`. A result is taken only for a monitor assigned to THIS host: a
    host cannot report on the server's monitors, a satellite's or another host's. Never raises. Returns how many were taken."""
    if not isinstance(raw, list):
        return 0
    cfg = A._config_ro()
    owned = {A._sanitize_str(m.get('label', m.get('target', '')), 128)
             for m in (cfg.get('monitors') or []) if isinstance(m, dict) and m.get('via_host') == dev_id}
    if not owned:
        return 0
    now = int(A.time.time())
    results = []
    for r in raw[:MAX_RESULTS]:
        if not isinstance(r, dict):
            continue
        label = A._sanitize_str(str(r.get('label', '')), 128)
        if label not in owned:
            continue
        res = {'label': label, 'type': A._sanitize_str(str(r.get('type', 'ping')), 16),
               'target': A._sanitize_str(str(r.get('target', '')), 256), 'ok': r.get('ok') is True,
               'detail': A._sanitize_str(str(r.get('detail', '')), 256), 'checked': now}
        lat = clean_latency(r.get('latency_ms'))
        if lat is not None:
            res['latency_ms'] = lat
        results.append(res)
    if not results:
        return 0
    store = A.load(A.SATELLITE_MON_FILE) or {}
    for res in results:
        store[res['label']] = res          # the last result of each monitor, like a satellite's
    A._persist_monitor_results(results)    # history, and the monitor_down and monitor_up transitions
    A.save(A.SATELLITE_MON_FILE, store)
    return len(results)
