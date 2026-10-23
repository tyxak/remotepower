"""RemotePower — Appliance sensor: threat evidence from the syslog of firewalls and routers

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


import threading
import time

import appliance_evidence
import threat_evidence

STATUS_EVERY_S = 60        # how often a device's source counts are written, without a hit to write
KEEP_DEVICE_S = 7 * 86400  # a device that has sent nothing for this long is forgotten
LISTED_KEEP_S = 30 * 86400 # a reputation-list hit is shown beside an address for this long
LISTED_MAX = 2000          # addresses remembered per device; the oldest go first, so a flood cannot grow the document

# The day's line counts per device, kept in this process and written with the scan
# state. A batch that settles nothing (a pass, a line nobody reads) would otherwise
# cost a write of the whole scan document for a number.
_pending = {}              # device id -> {kind: [lines, parsed, events]}
_noted = {}                # device id -> when this process last wrote the device's status
_lock = threading.Lock()

# What a failed login looks like, cheaply: the counter below compiles real patterns,
# but loads the config to know its threshold, and this runs on every batch.
_LOGIN_MARKS = ('login failure', 'Failed password', 'Invalid user', 'authentication failure',
                'authentication error', 'Connection closed by invalid user')


def _remember(dev_id, stats):
    with _lock:
        row = _pending.setdefault(dev_id, {})
        for kind, d in stats.items():
            c = row.setdefault(kind, [0, 0, 0])
            c[0] += d['lines']
            c[1] += d['parsed']
            c[2] += d['events']


def _take(dev_id):
    with _lock:
        return _pending.pop(dev_id, {})


def _enabled():
    """The operator's switch, read without building the whole policy: this runs on
    every syslog batch from every device, and the switch is off unless asked for."""
    stored = (A._config_ro() or {}).get('ip_intel')
    return bool(isinstance(stored, dict) and stored.get('appliance_enabled'))


def _login_failures(dev_id, name, lines):
    """A firewall's or router's own logins that failed. The brute-force counter has
    the thresholds, the alert and the queue for Threat Intel; it only needs to be
    shown the lines. A failed SSH login keeps its SSH category, the rest are counted
    under `syslog`."""
    if not any(mark in line for line in lines for mark in _LOGIN_MARKS):
        return
    A._detect_brute_force(dev_id, name, 'sshd.service', lines)
    A._detect_brute_force(dev_id, name, 'syslog', lines)


def merge_listed(old, new, now):
    """The reputation-list hits a device has seen, {address: {'at': last time, 'l': {list: count}}}:
    `new` ({address: {list: count}}) added to `old`, what is older than LISTED_KEEP_S dropped, and
    the oldest addresses dropped past LISTED_MAX. Context for the Threat Intel page and nothing
    else: no report, lookup or block is made of it."""
    out = {}
    for ip, r in (old if isinstance(old, dict) else {}).items():
        if isinstance(r, dict) and isinstance(r.get('l'), dict) and now - int(r.get('at') or 0) <= LISTED_KEEP_S:
            out[ip] = {'at': int(r['at']), 'l': {str(k): int(v) for k, v in r['l'].items()}}
    for ip, lists in (new or {}).items():
        row = out.setdefault(ip, {'at': now, 'l': {}})
        row['at'] = now
        for name, n in lists.items():
            row['l'][name] = row['l'].get(name, 0) + int(n)
    if len(out) > LISTED_MAX:
        for ip in sorted(out, key=lambda k: out[k]['at'])[:len(out) - LISTED_MAX]:
            out.pop(ip)
    return out


def _repeat_bar():
    """Blocked hits from a reputation-listed address before it is reported; 0 is off."""
    try:
        return max(0, int(A.ip_intel_policy().get('report_listed_after') or 0))
    except (TypeError, ValueError):
        return 0


def listed_repeats(before, after, new, bar):
    """Evidence for the addresses whose reputation-list hits reached `bar` in this batch.

    A reputation hit names no attack, so one is context. The same address blocked again
    and again is a host that keeps trying: the sensor counts the hits it has kept (30 days)
    and, once an address reaches `bar`, says so as port scanning, with every hit so far on
    the crossing and only the new ones after it. `rep` carries the count; the report is
    made on it (threat_evidence.qualifies)."""
    if bar < 1:
        return []

    def total(doc, ip):
        r = (doc or {}).get(ip) if isinstance(doc, dict) else None
        lists = r.get('l') if isinstance(r, dict) and isinstance(r.get('l'), dict) else {}
        return sum(int(v) for v in lists.values())

    out = []
    for ip, lists in (new or {}).items():
        now_n, was = total(after, ip), total(before, ip)
        if now_n < bar:
            continue
        n = now_n if was < bar else sum(int(v) for v in lists.values())
        out.append({'ip': ip, 'src': {}, 'tok': {'ids': {'ids:port_scan': n}}, 'rep': n})
    return out


def listed_for(scan_doc, device_ids, now=None):
    """{address: {'at': newest, 'l': {list: count}}} across the devices in `device_ids`, from the
    scan document, for the addresses Threat Intel shows."""
    now = int(now or time.time())
    out = {}
    for dev_id, rec in (scan_doc or {}).items():
        if dev_id not in device_ids or not isinstance(rec, dict) or not isinstance(rec.get('listed'), dict):
            continue
        for ip, r in rec['listed'].items():
            if not (isinstance(r, dict) and isinstance(r.get('l'), dict)) or now - int(r.get('at') or 0) > LISTED_KEEP_S:
                continue
            row = out.setdefault(ip, {'at': 0, 'l': {}, 'on': []})
            row['at'] = max(row['at'], int(r['at']))
            row['on'].append(dev_id)
            for name, n in r['l'].items():
                row['l'][name] = row['l'].get(name, 0) + int(n)
    return out


def crowdsec_alert_lines(body):
    """Lines for the Logs tab from what CrowdSec's HTTP notification posts: a list of
    alerts, or one. An empty list when none is worth keeping, and None when the body
    is not CrowdSec's at all, so the caller treats it as it treated it before. Every
    object has to name a scenario: a log shipper's records are objects too (fluent-bit
    posts `[{"date": ..., "log": ...}]`), and the endpoint keeps those as lines."""
    if isinstance(body, dict) and 'scenario' in body:
        body = [body]
    if not (isinstance(body, list) and body
            and all(isinstance(x, dict) and 'scenario' in x for x in body[:5])):
        return None
    return appliance_evidence.crowdsec_lines(body[:A._SYSLOG_MAX_LINES_PER_POST])


def appliance_sensor_ingest(dev_id, dev, lines, now=None):
    """Read a batch of a device's new syslog lines for evidence about the addresses
    behind them. Called by the syslog intake after the lines are in the log buffer,
    for every device, and does nothing unless Threat Intel's `appliance_enabled` is
    on. What it finds joins the queue the agents' sensors feed, so lookups, reports
    and the daily limits are the ones the rest of Threat Intel uses.

    Three kinds of line are read (see appliance_evidence for the formats): refused
    and decoy-port packets, which only mean something once an address has done it
    enough times, so they are counted over thirty minutes in a small document of
    their own; intrusion detection and CrowdSec alerts, which settle themselves; and
    failed logins, which the brute-force counter takes."""
    if not lines or not _enabled():
        return
    now = int(now or time.time())
    # A host with an agent has its logins counted from the journal already, and the
    # same failures forwarded as syslog would be counted a second time.
    if not (isinstance(dev, dict) and not dev.get('agentless')):
        _login_failures(dev_id, str((dev or {}).get('name') or dev_id), lines)
    listed, repeats = {}, []
    hits, events, stats = appliance_evidence.scan(lines, listed)
    if not stats:
        return
    for ev in events:
        ev['first'] = ev['last'] = now
    _remember(dev_id, stats)
    status_due = now - _noted.get(dev_id, 0) >= STATUS_EVERY_S
    if not (hits or events or listed or status_due):
        return
    day = time.strftime('%Y-%m-%d', time.gmtime(now))
    counts = _take(dev_id)
    with A._LockedUpdate(A.IPINTEL_SCAN_FILE) as st:
        rec = st.get(dev_id) if isinstance(st.get(dev_id), dict) else {}
        table = rec.get('scan') if isinstance(rec.get('scan'), dict) else {}
        fresh = appliance_evidence.track(table, hits, now)
        if fresh:
            counts.setdefault('fw', [0, 0, 0])[2] += len(fresh)
        today = rec.get('n') if rec.get('day') == day and isinstance(rec.get('n'), dict) else {}
        for kind, c in counts.items():
            row = today.setdefault(kind, [0, 0, 0])
            for i in range(3):
                row[i] += c[i]
        if listed or rec.get('listed'):
            before = rec.get('listed')
            rec['listed'] = merge_listed(before, listed, now)
            repeats = listed_repeats(before, rec['listed'], listed, _repeat_bar())
        rec.update({'scan': table, 'day': day, 'n': today, 'at': now})
        st[dev_id] = rec
        for d in [d for d, r in st.items() if isinstance(r, dict) and now - int(r.get('at') or 0) > KEEP_DEVICE_S]:
            st.pop(d, None)
        rows = [{'kind': k, 'path': 'syslog', 'lines': c[0], 'parsed': c[1], 'events': c[2],
                 'state': 'ok' if c[1] else 'unparsed'}
                for k, c in sorted(today.items()) if c[0]]
    ignored, evs = {}, []
    for raw in events + fresh + repeats:
        ev = threat_evidence.normalize_event(raw, now=now, families=threat_evidence.APPLIANCE_SOURCES)
        if ev is None:
            ignored['invalid'] = ignored.get('invalid', 0) + 1
        elif threat_evidence.infra_reason(ev['ip']):
            ignored['cloudflare'] = ignored.get('cloudflare', 0) + 1
        else:
            evs.append(ev)
    if evs or status_due:
        _noted[dev_id] = now
        A.ip_intel_note_evidence(dev_id, evs, {'sources': rows, 'ignored': ignored, 'dropped': 0}, now)
