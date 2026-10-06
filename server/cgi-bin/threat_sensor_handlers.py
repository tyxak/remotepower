"""RemotePower — Threat sensor intake: the agent's summaries of web server, WAF, fail2ban and CrowdSec logs

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


import re
import time

import threat_evidence

MAX_EVENTS = 300
MAX_SOURCES = 40
_SOURCE_KINDS = ('web', 'err', 'waf', 'f2b', 'cs')
_SOURCE_STATES = ('ok', 'idle', 'missing', 'denied', 'unparsed', 'unsupported', 'error')
_SOURCE_FMTS = ('combined', 'custom', 'json', 'generic', 'native', 'nginx', 'apache')
_PATH_RE = re.compile(r'(?:/[A-Za-z0-9._@+:/-]{1,299}|cscli|fail2ban)')


def _count(v, hi=10 ** 9):
    if isinstance(v, bool):
        return 0
    try:
        return max(0, min(hi, int(v)))
    except (TypeError, ValueError, OverflowError):
        return 0


def _clean_sources(raw):
    """The agent's per-log health, reduced to a fixed shape. The path is shown to
    the operator, so it has to look like one; the state and format come from a
    short list."""
    out = []
    for s in (raw if isinstance(raw, list) else [])[:MAX_SOURCES]:
        if not isinstance(s, dict):
            continue
        kind, path = s.get('kind'), s.get('path')
        if kind not in _SOURCE_KINDS or not isinstance(path, str) or not _PATH_RE.fullmatch(path):
            continue
        row = {'kind': kind, 'path': path,
               'state': s['state'] if s.get('state') in _SOURCE_STATES else 'error',
               'lines': _count(s.get('lines')), 'parsed': _count(s.get('parsed')),
               'events': _count(s.get('events'))}
        if s.get('fmt') in _SOURCE_FMTS:
            row['fmt'] = s['fmt']
        if kind == 'web' and 'proxied' in s:
            row['proxied'] = bool(s['proxied'])
        out.append(row)
    return out


def threat_sensor_config_for(dev):
    """The `threat_sensor` object for a heartbeat response, or None. Linux agents
    only: the sensor reads Linux log layouts and neither of the other agents
    carries it, so offering it there would be a switch that does nothing."""
    try:
        pol = A.ip_intel_policy()
        if not pol.get('sensor_enabled'):
            return None
        if not isinstance(dev, dict) or dev.get('agentless') or A._device_os_family(dev) != 'linux':
            return None
        return {'enabled': True, 'paths': list(pol.get('sensor_paths') or [])[:20]}
    except Exception:  # nosec B110
        return None            # the heartbeat must never fail over an optional feature


def handle_threat_events():
    """POST /api/threat-events — a Linux agent's summary of what its logs say
    about source addresses (see threat_evidence for the shape). Authenticated by
    the DEVICE token in the body, exactly like /api/logs: no user session is ever
    accepted, and a device can only speak for itself.

    Nothing the agent sends is trusted. Each address is rebuilt from the fixed
    vocabulary and anything else is dropped; Cloudflare edge addresses are not
    queued (the web server logged the proxy, not the visitor); and one host can
    add at most SENSOR_EVENTS_PER_HOUR addresses an hour, so a compromised one
    cannot spend the install's report budget on invented sources."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.ThreatEventsRequest)
    dev_id = str(body.get('device_id', '')).strip()
    token = str(body.get('token', '')).strip()
    if not A._validate_id(dev_id):
        A.respond(403, {'error': 'Unauthorized device'})
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict) or not A._device_token_ok(dev, token):
        A.respond(403, {'error': 'Unauthorized device'})
    pol = A.ip_intel_policy()
    if not pol.get('sensor_enabled') or dev.get('agentless') or A._device_os_family(dev) != 'linux':
        # Not an error: the agent may not have heard that it was switched off yet.
        A.respond(200, {'ok': True, 'enabled': False})
    now = int(time.time())
    raw = body.get('events') if isinstance(body.get('events'), list) else []
    ignored, events = {}, []
    for item in raw[:MAX_EVENTS]:
        ev = threat_evidence.normalize_event(item, now=now)
        if ev is None:
            ignored['invalid'] = ignored.get('invalid', 0) + 1
        elif threat_evidence.infra_reason(ev['ip']):
            ignored['cloudflare'] = ignored.get('cloudflare', 0) + 1
        else:
            events.append(ev)
    if len(raw) > MAX_EVENTS:
        ignored['over_limit'] = len(raw) - MAX_EVENTS
    res = A.ip_intel_note_evidence(
        dev_id, events,
        {'sources': _clean_sources(body.get('sources')), 'ignored': ignored,
         'dropped': _count(body.get('dropped'), 10 ** 6)}, now)
    A.respond(200, {'ok': True, 'enabled': True, 'accepted': res['queued'],
                    'throttled': res['throttled'], 'ignored': ignored})
