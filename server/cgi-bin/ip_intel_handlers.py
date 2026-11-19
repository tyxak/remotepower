"""RemotePower — AbuseIPDB / SniffCat lookups, reports and timed auto-blocks
for brute-force sources.

Flow: `_detect_brute_force` (heartbeat path) calls `ip_intel_note_attack` when a
public source address crosses the threshold. That only appends to a queue; no
network call ever happens on the heartbeat. `run_ip_intel_if_due` (cadence
sweep) then looks the address up, optionally reports it, optionally blocks it
on the attacked host for `block_ttl_hours`, and lifts expired blocks.

All three behaviours are off until an admin turns them on, and blocking goes
through `_queue_command_batch`, so maintenance mode, quarantine, audit mode and
four-eyes approval apply exactly as they do to a person's command.

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


import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import edge_blocklist
import edge_evidence
import ip_intel
import textfmt
import threat_evidence

QUEUE_CAP = 500            # pending addresses kept between sweeps
ATTACKER_CAP = 5000        # addresses remembered
ATTACKER_KEEP_DAYS = 90    # an address not seen for this long is forgotten, so the table does not fill with the past
PAGE_ROWS = 1000           # addresses the page is sent: the most recent
PER_SWEEP = 25             # addresses processed per sweep
REPORT_EVERY_S = 86400     # report an address to a provider at most daily
SWEEP_EVERY_S = 60


# ── config ─────────────────────────────────────────────────────────────────────

def _policy():
    cfg = A._config_ro() or {}
    pol = dict(ip_intel.DEFAULTS)
    stored = cfg.get('ip_intel')
    if isinstance(stored, dict):
        pol.update({k: stored[k] for k in ip_intel.DEFAULTS if k in stored})
    pol['keys'] = {'abuseipdb': str(cfg.get('abuseipdb_api_key') or ''),
                   'sniffcat': str(cfg.get('sniffcat_api_key') or '')}
    pol['edge_token'] = str(cfg.get('edge_cloudflare_token') or '')
    pol['edge_list_token'] = str(cfg.get('edge_list_token') or '')
    # Derived, not settings: what the report decisions test an address against.
    addrs, classes = pol.get('ignore_addresses'), pol.get('ignore_classes')
    pol['ignore_nets'] = ip_intel.parse_cidrs(addrs if isinstance(addrs, list) else [])
    pol['ignore_kinds'] = {c for c in (classes if isinstance(classes, list) else [])
                           if c in threat_evidence.CLASSES}
    return pol


def _any_enabled(pol):
    return bool(pol.get('lookup_enabled') or pol.get('report_enabled')
                or pol.get('block_enabled'))


def ip_intel_policy():
    """The operator's policy with the API keys resolved. Read-only."""
    return _policy()


def _ignore_why(ip, ev, legacy_units, pol):
    """The reason this address is not to be reported because the operator chose to
    ignore it, or ''. `ev` is the evidence a report would be made of (the day's
    ledger and what is waiting, merged) or None; `legacy_units` are the units of
    the brute-force counter's own entries for it. Three places decide whether a
    report can happen and all three ask here, so the rule cannot hold at one and
    not another: the claim that rations network calls, the catch-up that revisits
    a qualified ledger, and the report itself."""
    nets, ignored = pol.get('ignore_nets') or [], pol.get('ignore_kinds') or set()
    if not nets and not ignored:
        return ''
    kinds = set()
    if ignored:
        if isinstance(ev, dict):
            kinds |= threat_evidence.report_classes(ev)
        for unit in legacy_units:
            # a counter entry that fits no class is '?', which no ignore list can
            # cover, so it is never held back by one
            kinds.add(ip_intel.LEGACY_KIND_CLASS.get(ip_intel.attack_kind(unit), '?'))
    return ip_intel.ignore_reason(ip, nets, kinds, ignored)


# ── the heartbeat-side hook ────────────────────────────────────────────────────

def ip_intel_note_attacks(dev_id, unit, sources, window_s):
    """Queue the brute-force sources one heartbeat found, under ONE lock.
    `sources` is [(ip, count), ...]. Cheap and silent: a disabled feature, a
    private address or a hostname is skipped.

    The queue is written to the intake document (see _intake_ro), not the table
    of addresses: every write rewrites the whole document it lands in, and that
    table costs 57 to 125 ms to rewrite on SQLite and 132 to 334 ms on the JSON
    backend with 5,000 addresses recorded. A heartbeat that took one lock per
    source made a botnet's burst of forty sources cost ten seconds on the request
    the host was waiting for; one lock per heartbeat costs one write whatever the
    burst. The queue is trimmed the way the sensor's is, keeping what a ban engine
    decided on over the newest arrivals."""
    try:
        pol = _policy()
        if not _any_enabled(pol):
            return
        now = int(time.time())
        rows = []
        for ip, count in sources or []:
            ip = ip_intel.parse_ip(ip)
            if not ip or not ip_intel.is_public(ip) or threat_evidence.infra_reason(ip):
                continue
            rows.append({'ip': ip, 'device_id': dev_id, 'unit': str(unit)[:64],
                         'count': int(count or 0), 'window_s': int(window_s or 0),
                         'at': now})
        if not rows:
            return
        with A._LockedUpdate(A.IPINTEL_INTAKE_FILE) as intake:
            _intake_adopt(intake)
            q = intake['queue']
            q.extend(rows)
            intake['queue'] = _trim_queue(q)
    except Exception:  # nosec B110
        # Never let enrichment break brute-force detection.
        pass


def ip_intel_note_attack(dev_id, unit, ip, count, window_s):
    """One brute-force source for the sweep; see ip_intel_note_attacks."""
    A.ip_intel_note_attacks(dev_id, unit, [(ip, count)], window_s)


# ── the threat sensor's side of the queue ──────────────────────────────────────

SENSOR_EVENTS_PER_HOUR = 3000       # accepted from one host in an hour
INTAKE_LOG_KEEP = 200               # what hosts sent, kept so a missing address can be traced (8.0.1)
SENSOR_STATUS_KEEP_S = 30 * 86400   # a host that has not reported for a month is forgotten


def _queue_priority(item):
    """How much an entry deserves to stay when the queue is full: an address a
    ban engine already decided on, then the others by how much they did."""
    ev = item.get('evidence') if isinstance(item, dict) else None
    if isinstance(ev, dict):
        return (1_000_000 if threat_evidence.confirmed_by(ev) else 0) + threat_evidence.hostile_count(ev)
    return 500_000 + int((item or {}).get('count') or 0)      # the brute-force counter's own


def _fair_order(q, tiered, newest_first):
    """The indexes of `q` in the order to take them: each host's entries by how much they matter (`_queue_priority`), and the hosts in
    turn, so that the best entry of every host comes before the second of any. One host that sends more, or sends entries that rank
    higher, takes no more of a short list than the next host does. `tiered` puts the brute-force counter's entries (no evidence) first,
    first come first served within a host, as the sweep always did; `newest_first` breaks a tie for the later entry (the trim keeps the
    newest of equals, the claim handles the oldest)."""
    def is_sensor(item):
        return isinstance(item, dict) and isinstance(item.get('evidence'), dict)

    def tier(item):
        return 1 if (not tiered or is_sensor(item)) else 0

    def within(i):
        if tier(q[i]) == 0:
            return (0, i)
        return (-_queue_priority(q[i]) if isinstance(q[i], dict) else 0, -i if newest_first else i)

    groups = {}
    for i, item in enumerate(q):
        host = str(item.get('device_id') or '') if isinstance(item, dict) else ''
        groups.setdefault((tier(item), host), []).append(i)
    rank = {}
    for (t, _host), idxs in groups.items():
        for r, i in enumerate(sorted(idxs, key=within)):
            rank[i] = (t, r, within(i))
    return sorted(range(len(q)), key=lambda i: rank[i])


def _trim_queue(q):
    """The queue at QUEUE_CAP entries, keeping the ones that matter and the
    original order. Plain "keep the newest" let a flood of one-hit addresses push
    out an address that had been banned a minute earlier, and plain "keep the
    strongest" let one host that sent more of them push out the evidence of every
    other host: the hosts are taken in turn (see `_fair_order`)."""
    if len(q) <= QUEUE_CAP:
        return q
    keep = _fair_order(q, tiered=False, newest_first=True)[:QUEUE_CAP]
    return [q[i] for i in sorted(keep)]


# ── the intake: what arrives between sweeps ────────────────────────────────────
#
# The queue, each host's sensor record and the edge feeds' place in their logs
# (`cursors`, by feed) are written whenever a heartbeat or a poll has something to
# say. They live in a document of their own, a few hundred kilobytes at most, so
# such a write costs what it carries and does not wait on the sweep or on the
# table of addresses. The SQL backends cannot hold two locks at once (they share
# one connection), so no operation here spans both documents: the sweep claims its
# batch from the intake, and then works on the table in a second step.

def _legacy_intake(st):
    """The intake as the main store held it before it had a document of its own:
    `queue` and `sensors` at the top, the feeds' places as `edge.cf_to` and
    `edge.trap_to`."""
    st = st if isinstance(st, dict) else {}
    edge = st.get('edge') if isinstance(st.get('edge'), dict) else {}
    cursors = {}
    for feed in ('cf', 'trap'):
        try:
            t = int(edge.get(feed + '_to') or 0)
        except (TypeError, ValueError, OverflowError):
            t = 0
        if t > 0:
            cursors[feed] = t
    return {'queue': st['queue'] if isinstance(st.get('queue'), list) else [],
            'sensors': st['sensors'] if isinstance(st.get('sensors'), dict) else {},
            'cursors': cursors}


def _intake_ro():
    """The intake, read-only. Until the first write after an upgrade the document
    does not exist and the queue is still in the main store; that is read instead,
    so the page and the sweep see the same queue either way."""
    if A.backend_exists(A.IPINTEL_INTAKE_FILE):
        intake = A._load_ro(A.IPINTEL_INTAKE_FILE) or {}
        if intake.get('adopted'):
            return intake
    return _legacy_intake(_store_ro())


def _intake_adopt(intake):
    """Call first under the intake's lock. Takes over, once, what the main store
    still holds (the older entries go first), and makes sure the three parts exist
    and have the right shape. The main store's copies are dropped by the next
    sweep; until then nothing reads them, because `adopted` is set."""
    if not intake.get('adopted'):
        old = _legacy_intake(_store_ro())
        fresh = intake.get('queue') if isinstance(intake.get('queue'), list) else []
        intake['queue'] = _trim_queue(list(old['queue']) + fresh)
        sensors = intake.get('sensors') if isinstance(intake.get('sensors'), dict) else {}
        for dev_id, rec in old['sensors'].items():
            sensors.setdefault(dev_id, rec)
        intake['sensors'] = sensors
        cursors = intake.get('cursors') if isinstance(intake.get('cursors'), dict) else {}
        for feed, t in old['cursors'].items():
            cursors[feed] = max(int(cursors.get(feed) or 0), t)
        intake['cursors'] = cursors
        intake['adopted'] = True
    for key, kind in (('queue', list), ('sensors', dict), ('cursors', dict)):
        if not isinstance(intake.get(key), kind):
            intake[key] = kind()
    return intake


def _note_evidence_into(intake, dev_id, events, status=None, now=None):
    """The queueing half of ip_intel_note_evidence, over an intake dict the caller
    already holds the lock on, so a caller that has more to write (the edge
    feeds' cursor) can do both in one transaction. The edge ids are queued
    without the per-host hourly allowance and without a sensor record: they are
    not hosts, and their volume is bounded by the read itself."""
    _intake_adopt(intake)
    now = int(now or time.time())
    status = status if isinstance(status, dict) else {}
    edge = dev_id in ip_intel.EDGE_DEVICES
    queued = throttled = 0
    sensors = intake['sensors']
    rec = sensors.get(dev_id) if isinstance(sensors.get(dev_id), dict) else {}
    hour = now // 3600
    used = int((rec.get('hour') or {}).get('n') or 0) if (rec.get('hour') or {}).get('h') == hour else 0
    q = intake['queue']
    index = {(x.get('ip'), x.get('device_id')): i for i, x in enumerate(q)
             if isinstance(x, dict) and isinstance(x.get('evidence'), dict)}
    infra = 0
    for ev in events:
        if threat_evidence.infra_reason(ev.get('ip')):
            infra += 1       # Cloudflare's own address: each feeder drops it, and so does the door they all come through
            continue
        if not edge and used >= SENSOR_EVENTS_PER_HOUR:
            throttled += 1
            continue
        used += 1
        queued += 1
        key = (ev['ip'], dev_id)
        if key in index:
            item = q[index[key]]
            item['evidence'] = threat_evidence.merge(item['evidence'], ev)
            item['count'] = threat_evidence.hostile_count(item['evidence'])
            item['window_s'] = threat_evidence.window_seconds(item['evidence'])
            item['at'] = now
        else:
            q.append({'ip': ev['ip'], 'device_id': dev_id,
                      'unit': 'edge-feed' if edge else 'threat-sensor',
                      'count': threat_evidence.hostile_count(ev),
                      'window_s': threat_evidence.window_seconds(ev), 'at': now, 'evidence': ev})
            index[key] = len(q) - 1
    intake['queue'] = _trim_queue(q)
    ignored = dict(status.get('ignored') or {})
    if infra:
        ignored['cloudflare'] = ignored.get('cloudflare', 0) + infra
    if not edge and (events or any(ignored.values())):
        # What the host sent, whether or not it came to anything: the one place that says an address reached the server.
        # A pass with nothing to say (a status only) is not a line.
        log = intake['log'] if isinstance(intake.get('log'), list) else []
        log.append({'at': now, 'device_id': dev_id, 'n': len(events), 'queued': queued, 'throttled': throttled,
                    'ignored': {str(k)[:24]: int(v) for k, v in ignored.items() if isinstance(v, (int, float)) and v},
                    'dropped': int(status.get('dropped') or 0), 'ips': [ev['ip'] for ev in events[:5]]})
        intake['log'] = log[-INTAKE_LOG_KEEP:]
    if not edge:
        sensors[dev_id] = {
            'at': now, 'sources': list(status.get('sources') or []),
            'events': queued, 'throttled': throttled,
            'dropped': int(status.get('dropped') or 0),
            'ignored': ignored,
            'hour': {'h': hour, 'n': used},
        }
        for d in [d for d, r in sensors.items()
                  if isinstance(r, dict) and now - int(r.get('at') or 0) > SENSOR_STATUS_KEEP_S]:
            sensors.pop(d, None)
    return {'queued': queued, 'throttled': throttled}


def ip_intel_note_evidence(dev_id, events, status=None, now=None):
    """Queue what a host's logs said about each address and record the host's
    sensor status, under one lock. `events` are threat_evidence summaries that
    have already been validated. An address already waiting for this host has the
    new evidence added to its entry, so a minute-by-minute attack is one entry,
    not sixty. Returns {'queued': n, 'throttled': n}."""
    with A._LockedUpdate(A.IPINTEL_INTAKE_FILE) as intake:
        return _note_evidence_into(intake, dev_id, events, status, now)


# ── what other surfaces read ───────────────────────────────────────────────────

KNOWN_BAD_SCORE = 75          # "a provider says this address is abusive"
RECENT_S = 7 * 86400          # how long an attack counts towards a host's posture


def ip_intel_annotate(dev_id, rows):
    """Brute-force source rows ({source_ip, …}) with what IP intel knows about
    each: the merged reputation score, country and network, and whether the
    address is blocked on this host right now. Rows IP intel has never seen
    come back unchanged. Read-only; never raises."""
    try:
        st = _store_ro()
    except Exception:  # nosec B110 — enrichment is optional
        return list(rows or [])
    atts = st.get('attackers') if isinstance(st.get('attackers'), dict) else {}
    blocks = (st.get('blocks') or {}).get(dev_id) if isinstance(st.get('blocks'), dict) else None
    blocks = blocks if isinstance(blocks, dict) else {}
    out = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        r = dict(r)
        ip = ip_intel.parse_ip(r.get('source_ip'))
        v = ((atts.get(ip) or {}).get('verdict') or {}) if ip else {}
        if isinstance(v, dict) and v.get('score') is not None:
            r['score'] = v.get('score')
            for k in ('country', 'isp'):
                if v.get(k):
                    r[k] = v[k]
        r['blocked'] = bool(ip and ip in blocks)
        out.append(r)
    return out


def ip_intel_by_device(now=None):
    """{device_id: {attackers, known_bad, known_bad_unblocked, blocked, top}} for
    attacks seen in the last week. `known_bad` is an address a provider scores
    at KNOWN_BAD_SCORE or above; `top` lists the worst few for evidence. One
    read of the store for the whole fleet, so callers hoist it out of any
    per-device loop."""
    now = int(now or time.time())
    try:
        st = _store_ro()
    except Exception:  # nosec B110 — enrichment is optional
        return {}
    atts = st.get('attackers') if isinstance(st.get('attackers'), dict) else {}
    blocks = st.get('blocks') if isinstance(st.get('blocks'), dict) else {}
    out = {}
    for ip, a in atts.items():
        if not isinstance(a, dict):
            continue
        score = (a.get('verdict') or {}).get('score') if isinstance(a.get('verdict'), dict) else None
        for did, seen in (a.get('devices') or {}).items():
            if did in ip_intel.EDGE_DEVICES:
                continue                 # not a host: nothing to score or block
            if not isinstance(seen, dict) or now - int(seen.get('at') or 0) > RECENT_S:
                continue
            rec = out.setdefault(did, {'attackers': 0, 'known_bad': 0,
                                       'known_bad_unblocked': 0, 'blocked': 0, 'top': []})
            rec['attackers'] += 1
            blocked = ip in (blocks.get(did) or {})
            if blocked:
                rec['blocked'] += 1
            if isinstance(score, int) and score >= KNOWN_BAD_SCORE:
                rec['known_bad'] += 1
                if not blocked:
                    rec['known_bad_unblocked'] += 1
            rec['top'].append({'ip': ip, 'score': score, 'count': int(seen.get('count') or 0),
                               'blocked': blocked})
    for rec in out.values():
        rec['top'] = sorted(rec['top'], key=lambda t: (-(t['score'] or -1), -t['count']))[:5]
    return out


# ── HTTP ───────────────────────────────────────────────────────────────────────

# ── a log of what was asked of the two services ────────────────────────────────
#
# One line for each request RemotePower sends to AbuseIPDB or SniffCat: when, which service and
# request, for which address, the HTTP status, how long it took, and the service's own sentence.
# It is there so "why was this not reported" is answered by reading what the service said. The
# key, the headers and the body of a request are never in it. Lines are collected in memory and
# written to the store by whatever holds its lock next (the sweep, the manual lookup, a blocklist
# sync), so a request does not cost a rewrite of the store.

REQLOG_KEEP = 300           # lines kept in the store
REQLOG_SHOWN = 150          # lines the page is sent, newest first
_REQLOG_HOSTS = {'api.abuseipdb.com': 'abuseipdb', 'api.sniffcat.com': 'sniffcat'}
_REQLOG_PENDING = []
_REQLOG_LOCK = threading.Lock()


def _req_ip(req):
    """The address a request is about, or ''. A lookup carries it in the query, a report in its body."""
    q = urllib.parse.parse_qs(urllib.parse.urlparse(req['url']).query)
    for k in ('ipAddress', 'ip'):
        if q.get(k):
            return ip_intel.parse_ip(q[k][0]) or ''
    body = req.get('body')
    if isinstance(body, (bytes, bytearray)) and body:
        try:
            text = bytes(body).decode('utf-8', 'replace')
            if text.lstrip().startswith('{'):
                value = json.loads(text).get('ip')
            else:
                value = (urllib.parse.parse_qs(text).get('ip') or [''])[0]
            return ip_intel.parse_ip(value) or ''
        except (ValueError, AttributeError):
            return ''
    return ''


def _req_cats(req):
    """The category ids a report request files the address under, or []. AbuseIPDB's body is a form
    and SniffCat's is JSON; the ids are ours (threat_evidence.CLASSES), read back from what was sent."""
    body = req.get('body')
    if not isinstance(body, (bytes, bytearray)) or not body:
        return []
    try:
        text = bytes(body).decode('utf-8', 'replace')
        if text.lstrip().startswith('{'):
            raw = json.loads(text).get('categories')
        else:
            raw = (urllib.parse.parse_qs(text).get('categories') or [''])[0]
    except (ValueError, AttributeError):
        return []
    return _clean_cats(raw if isinstance(raw, list) else str(raw or '').split(','))


def _clean_cats(items):
    """Category ids as a short list of small whole numbers, or []. Both services number their categories from 1 and
    neither goes past two digits. Only plain digits count (`str.isdigit` also says yes to a superscript two, which `int`
    refuses), so this cannot raise; it is used where a request is logged and where a stored line is read back."""
    out = []
    for c in items if isinstance(items, list) else []:
        if isinstance(c, bool) or not isinstance(c, (int, str)):
            continue
        text = str(c).strip()
        if text.isascii() and text.isdigit() and len(text) <= 2 and 1 <= int(text) and int(text) not in out:
            out.append(int(text))
    return out[:8]


def _reqlog_note(req, status, body, started):
    """Add one line for this request to the pending ones. Only the two services are logged. A report's
    line also says which categories the address was filed under: the text of a report is never kept
    here, and the numbers are what tells two reports about one address apart."""
    parsed = urllib.parse.urlparse(req['url'])
    prov = _REQLOG_HOSTS.get(parsed.netloc.lower())
    if not prov:
        return
    op = parsed.path.rstrip('/').rsplit('/', 1)[-1]
    result, note = ip_intel.describe_answer(status, body)
    entry = {'at': int(time.time()), 'prov': prov, 'op': op if op in ('check', 'report', 'blacklist') else 'other',
             'ip': _req_ip(req), 'status': int(status), 'ms': int(max(0, time.monotonic() - started) * 1000),
             'result': result, 'note': note}
    if entry['op'] == 'report':
        cats = _req_cats(req)
        if cats:
            entry['cats'] = cats
    with _REQLOG_LOCK:
        _REQLOG_PENDING.append(entry)
        del _REQLOG_PENDING[:-REQLOG_KEEP]


def _reqlog_flush(st):
    """Move the lines made since the last write into the store. Call under the store's lock."""
    with _REQLOG_LOCK:
        new = list(_REQLOG_PENDING)
        del _REQLOG_PENDING[:]
    if new:
        cur = st.get('reqlog') if isinstance(st.get('reqlog'), list) else []
        st['reqlog'] = (cur + new)[-REQLOG_KEEP:]


def _reqlog_view(st):
    """The lines the page shows, newest first. A line's category ids are checked again on the way out: the store can
    be edited by hand, and the page joins them into a cell."""
    rows = st.get('reqlog') if isinstance(st.get('reqlog'), list) else []
    out = []
    for e in reversed(rows):
        if not isinstance(e, dict):
            continue
        if 'cats' in e:
            e = dict(e)
            cats = _clean_cats(e.pop('cats'))
            if cats:
                e['cats'] = cats
        out.append(e)
        if len(out) >= REQLOG_SHOWN:
            break
    return out


def _whole(x):
    """int(x), or 0 for anything that is not a number: a damaged or hand-edited store must not take the page down."""
    try:
        return int(x or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _intake_log_view(intake, names):
    """What hosts sent, as lines of the same shape as the requests RemotePower made: the host is in the service column and
    the address is the first one the pass carried. `names` is {device id: name}. It never raises on a stored row of the wrong
    kind (store_shapes repairs the document where it is read, and this reads what is left with defaults)."""
    rows = intake.get('log') if isinstance(intake.get('log'), list) else []
    out = []
    for e in reversed(rows):
        if not isinstance(e, dict):
            continue
        ips = [i for i in (e.get('ips') if isinstance(e.get('ips'), list) else []) if isinstance(i, str)]
        n, queued, throttled, dropped = _whole(e.get('n')), _whole(e.get('queued')), _whole(e.get('throttled')), _whole(e.get('dropped'))
        note = f'queued {queued} of {n}'
        if throttled:
            note += f", {throttled} held back by the hour's limit"
        ignored = e.get('ignored') if isinstance(e.get('ignored'), dict) else {}
        aside = sum(_whole(v) for v in ignored.values() if isinstance(v, (int, float)))
        if aside:
            note += f', {aside} set aside'
        if dropped:
            note += f', {dropped} left out by the host'
        if ips:
            note += ': ' + ', '.join(ips) + (f' and {n - len(ips)} more' if n > len(ips) else '')
        host = e.get('device_id') if isinstance(e.get('device_id'), str) else ''
        out.append({'at': _whole(e.get('at')), 'prov': str(names.get(host) or host)[:80],
                    'op': 'received', 'ip': ips[0] if ips else '', 'status': 200, 'ms': 0,
                    'result': 'ok' if queued else 'refused', 'note': note[:300]})
    return out


def _request_lines(st, intake, names):
    """Requests sent and what hosts sent, newest first, for the Request log card."""
    lines = _reqlog_view(st) + _intake_log_view(intake, names)
    lines.sort(key=lambda r: -int(r.get('at') or 0))
    return lines[:REQLOG_SHOWN]


def _ip_intel_http(req):
    """(status, parsed_json_or_None). Every request to a provider goes through here, and the two
    services' are logged (see _reqlog_note); a log line never fails a request."""
    started = time.monotonic()
    status, parsed = _ip_intel_http_send(req)
    try:
        _reqlog_note(req, status, parsed, started)
    except Exception:  # nosec B110 — a log line must not take a lookup or a report down with it
        pass
    return status, parsed


def _ip_intel_http_send(req):
    """(status, parsed_json_or_None). Through the SSRF-guarded opener with
    redirects refused, so an API key can never be replayed to another host."""
    r = urllib.request.Request(req['url'], data=req.get('body'), method=req['method'])
    for k, v in (req.get('headers') or {}).items():
        r.add_header(k, v)
    # Without this urllib sends `Python-urllib/3.x`, which SniffCat's Cloudflare
    # refuses with a 403 (error 1010) before the key is looked at.
    if not r.has_header('User-agent'):
        r.add_header('User-Agent', f'RemotePower/{A.SERVER_VERSION}')
    opener = A._ssrf_safe_opener(allow_loopback=False, no_redirect=True)
    # A provider's answer is small. Cloudflare's grouped events and Worker logs
    # are not, so a request can ask for a longer wait and a larger read (capped).
    timeout = max(1, min(60, int(req.get('timeout') or 8)))
    cap = max(65536, min(8_000_000, int(req.get('max_bytes') or 262144)))
    try:
        with opener.open(r, timeout=timeout) as resp:  # nosec B310  # nosemgrep: dynamic-urllib-use-detected -- fixed https provider bases in ip_intel.py and edge_evidence.py
            raw = resp.read(cap)
            status = resp.status
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read(65536)
    except (urllib.error.URLError, OSError) as e:
        return 0, {'message': f'unreachable: {type(e).__name__}'}
    try:
        return status, json.loads(raw or b'{}')
    except ValueError:
        return status, None


# ── the sweep ──────────────────────────────────────────────────────────────────

def _budget_today(b, today):
    """The day's counts as the code reads them. A new day starts empty. A record written before 8.0.1 (it has no `v`) counted every
    request RemotePower sent, including the ones a service never answered, and a service that was down for a day filled the whole
    report allowance that way. The report counts of such a record are not trusted: they read as empty and the next write drops them,
    once. The lookup counts stay, because they were not what went wrong."""
    b = b if isinstance(b, dict) else {}
    if b.get('day') != today:
        return {'day': today, 'v': ip_intel.BUDGET_VERSION}
    if b.get('v') != ip_intel.BUDGET_VERSION:
        return dict({k: n for k, n in b.items() if not str(k).startswith('report:')}, v=ip_intel.BUDGET_VERSION)
    return b


def _budget_left(st, pol, today):
    """{provider: lookups still allowed today} from the stored counters."""
    b = _budget_today(st.get('budget'), today)
    return {p: max(0, ip_intel.limit_for(pol, p, 'lookups') - int(b.get(p, 0))) for p in ip_intel.PROVIDERS}


def _report_budget_left(st, pol, today):
    """{provider: reports still allowed today}. Reports are counted under
    `report:<provider>` in the same daily record as lookups."""
    b = _budget_today(st.get('budget'), today)
    return {p: max(0, ip_intel.limit_for(pol, p, 'reports') - int(b.get('report:' + p, 0))) for p in ip_intel.PROVIDERS}


def _add_spend(st, today, spent):
    b = dict(_budget_today(st.get('budget'), today))
    for p, n in spent.items():
        if n == 0 and str(p).startswith('host:'):
            continue                  # a host's count that went up and came back (a request the service never answered)
        b[p] = int(b.get(p, 0)) + n
    st['budget'] = b


HOST_SHARE_MIN = 5   # the least of a day's lookups, and of its reports to one service, a host can count on; a fleet bigger than the limit cannot give every host more


class _HostShares:
    """The day's lookups and reports, shared out among the hosts that can send evidence.

    The day's limits are the installation's (900 of each for each service, unless the operator set others), and the evidence that
    spends them comes from hosts. A compromised host can make up addresses (a fail2ban jail in its summary is all it takes for one to
    qualify), and the per-hour limit on what a host may add only bounds the work and the space it asks for: at 3,000 an hour it is
    larger than the day's whole allowance. Without a share for each host, one host spent the allowance of both services in half an
    hour, 900 invented addresses were filed under the operator's keys, and the evidence of every other host was refused for the rest
    of the day.

    A host's share of a service's limit is the limit divided by the number of hosts (at least HOST_SHARE_MIN), and what a host has used
    is counted under `host:<id>:<l or r>:<service>` in the day's record, beside the service's own counts. The sum of the shares is
    the limit, so the allowance of the others is still there whatever one host does. With one host the share is the whole limit.

    Hosts are the Linux agents of the installation, every host that sent evidence in the last month and every host in the batch; the
    two edge feeds count as one each while they are switched on, since they spend from the same day."""

    def __init__(self, pol, budget, devices, sensors, batch_hosts):
        hosts = {d for d, v in (devices or {}).items()
                 if isinstance(v, dict) and not v.get('agentless') and A._device_os_family(v) == 'linux'}
        hosts |= {str(d) for d in (sensors or {})}
        hosts |= {d for d in batch_hosts if d and d not in ip_intel.EDGE_DEVICES}
        edge = 0
        if pol.get('edge_enabled'):
            edge = int(bool(pol.get('edge_cf_events'))) + int(bool(pol.get('edge_trap')))
        self.pol = pol
        self.n = max(1, len(hosts) + edge)
        self.used = {k: v for k, v in (budget or {}).items()
                     if str(k).startswith('host:') and isinstance(v, int) and not isinstance(v, bool)}

    @staticmethod
    def key(dev, prov, kind):
        return 'host:%s:%s:%s' % (dev, 'l' if kind == 'lookups' else 'r', prov)

    def share(self, prov, kind):
        limit = ip_intel.limit_for(self.pol, prov, kind)
        return max(HOST_SHARE_MIN, limit // self.n) if limit > 0 else 0

    def left(self, dev, prov, kind):
        return max(0, self.share(prov, kind) - self.used.get(self.key(dev, prov, kind), 0))

    def any_left(self, dev, kind):
        """True when the host has some of its share for a service that has a key."""
        return any(self.pol['keys'].get(p) and self.left(dev, p, kind) > 0 for p in ip_intel.PROVIDERS)

    def charge(self, dev, prov, kind, spent, n=1):
        k = self.key(dev, prov, kind)
        self.used[k] = self.used.get(k, 0) + n
        spent[k] = spent.get(k, 0) + n

    def payer(self, group, prov, kind):
        """The host of the first entry of an address that still has its share of `prov`, or None. An address several hosts saw is one
        report, and it is charged to the first of them that can pay for it."""
        for p in group:
            if self.left(p['dev_id'], prov, kind) > 0:
                return p['dev_id']
        return None


def _fetch_verdict(ip, pol, allowance, spent, down=None, host=None):
    """Ask every provider that has a key and allowance left. Network only:
    always called with no lock held. Returns (verdict or None, {provider: error}).

    `down` is the sweep's count of answers each provider did not give. A provider that
    has failed ip_intel.TRANSIENT_BREAKER times is not asked again in that sweep, and a
    failed ask is not charged to the day's allowance. The manual lookup passes none and
    asks as before: its "budget is used up" answer reads `spent`.

    `host` is (the shares, the host that pays) for a lookup the sweep makes for a host's
    evidence: a service the host has used its share of is not asked, and each ask is
    counted against the host as well as the service."""
    results = {}
    for prov in ip_intel.PROVIDERS:
        key = pol['keys'].get(prov)
        if not key or allowance.get(prov, 0) <= 0:
            continue
        if host is not None and host[0].left(host[1], prov, 'lookups') <= 0:
            continue
        if down is not None and down.get(prov, 0) >= ip_intel.TRANSIENT_BREAKER:
            results[prov] = {'ok': False, 'error': 'the service is not answering'}
            continue
        allowance[prov] -= 1
        spent[prov] = spent.get(prov, 0) + 1
        if host is not None:
            host[0].charge(host[1], prov, 'lookups', spent)
        build, parse = ip_intel.CHECK[prov]
        status, body = A._ip_intel_http(build(ip, key))
        results[prov] = parse(status, body)
        if down is not None and results[prov].get('transient'):
            allowance[prov] += 1
            spent[prov] -= 1
            if host is not None:
                host[0].charge(host[1], prov, 'lookups', spent, -1)
            down[prov] = down.get(prov, 0) + 1
    errors = {p: r.get('error') for p, r in results.items() if not r.get('ok')}
    if not any(r.get('ok') for r in results.values()):
        return None, errors
    return ip_intel.merge(results), errors


# The audit actions that say a person signed in and was given a session, one for each place that mints one: the password form (LDAP
# is a way to pass it, and ends in the same record), a passkey, SAML and OIDC. The address of such a sign-in is where an
# administrator works from, so it is never blocked, reported or listed. A failed sign-in is not on the list, on purpose: it is
# the very thing the block is for. tests/test_v802_threat_protected_sign_ins.py lists the places that mint a session by syntax
# tree and fails when one of them writes an action that is not here.
SIGN_IN_ACTIONS = ('login', 'login_webauthn', 'login_saml', 'login_oidc')


def _protected_networks(pol, devices):
    """Addresses that must never be blocked: the fleet's own, the operator's
    UI allow-list, the configured never-block list, and where RemotePower's
    users and SSH-gateway sessions have come from in the last 30 days."""
    cfg = A._config_ro() or {}
    nets = ip_intel.parse_cidrs(pol.get('never_block'))
    nets += ip_intel.parse_cidrs(cfg.get('ip_allowlist'))
    own = []
    for dev in (devices or {}).values():
        if isinstance(dev, dict):
            for k in ('ip', 'public_ip', 'wan_ip'):
                if dev.get(k):
                    own.append(dev[k])
            # 7.5.0: the addresses the agent really sends. This read `sysinfo.ip_addresses`, which no agent has ever sent, so a host's
            # other addresses (a second NIC, an IPv6 address, a public one) could be blocked by the host's own blocklist. The list of
            # every address (host_addresses) and the interface list both count.
            si = dev.get('sysinfo') if isinstance(dev.get('sysinfo'), dict) else {}
            addrs, nics = si.get('host_addresses'), si.get('network')
            for a in (addrs if isinstance(addrs, list) else [])[:64]:
                own.append(a if isinstance(a, str) else (a.get('address') if isinstance(a, dict) else None))
            for n in (nics if isinstance(nics, list) else [])[:20]:
                if isinstance(n, dict):
                    own.append(n.get('ip'))
    cutoff = int(time.time()) - 30 * 86400
    try:
        for e in ((A._load_ro(A.AUDIT_LOG_FILE) or {}).get('entries') or [])[-5000:]:
            if isinstance(e, dict) and e.get('action') in SIGN_IN_ACTIONS and int(e.get('ts') or 0) >= cutoff:
                own.append(e.get('source_ip'))
    except Exception:  # nosec B110
        pass  # the audit log is an extra source; the fleet and the lists still apply
    try:
        for r in ((A._load_ro(A.SSHGW_SESSIONS_FILE) or {}).get('sessions') or [])[-2000:]:
            if isinstance(r, dict) and int(r.get('started') or 0) >= cutoff:
                own.append(r.get('client_ip'))
    except Exception:  # nosec B110
        pass  # as above
    for a in own:
        ip = ip_intel.parse_ip(a)
        if ip:
            nets += ip_intel.parse_cidrs([ip])
    return nets


def _blocks_last_hour(blocks, dev_id, now):
    return sum(1 for b in (blocks.get(dev_id) or {}).values()
               if isinstance(b, dict) and now - int(b.get('at') or 0) < 3600)


def _agent_online(dev, now, ttl):
    """True when an agent host has checked in within the online window. A command queued
    for a host that has not waits there until it comes back, so a block meant for every
    host is only sent to the ones that can run it now: a host that is off for a month would
    otherwise collect a block for every address the edge saw in that time."""
    try:
        return now - int((dev or {}).get('last_seen') or 0) < ttl
    except (TypeError, ValueError, OverflowError):
        return False


def _drop_unrun_block(dev_id, ip):
    """True when the block for `ip` was still waiting in the host's command queue and is
    gone from it now. A block that never ran has nothing to lift, so the expiry takes the
    command out of the queue instead of queueing an unblock behind it."""
    cmd = 'exec:' + ip_intel.block_command(ip)
    with A._LockedUpdate(A.CMDS_FILE) as cmds:
        queue = cmds.get(dev_id)
        if isinstance(queue, list) and any(c == cmd for c in queue):
            queue[:] = [c for c in queue if c != cmd]
            return True
    return False


def _store_ro():
    return (A._load_ro(A.IPINTEL_FILE) or {}) if A.backend_exists(A.IPINTEL_FILE) else {}


EDGE_FANOUT_PER_SWEEP = 100  # host blocks queued per sweep for edge-found addresses
NET_PER_SWEEP = 25          # addresses per sweep that cost a network call
SWEEP_MAX = 500             # addresses per sweep in all: the ones that cost nothing are free
LEDGER_S = 86400            # how long an address's evidence is kept before it starts over
REPORT_LOG_KEEP = 3         # what was sent, kept per address so the page can show it


def _fresh_ledger(att, now):
    ev = (att or {}).get('ev')
    if isinstance(ev, dict) and now - int(ev.get('first') or now) <= LEDGER_S:
        return ev
    return None


# ── who a ledger was collected by ──────────────────────────────────────────────
#
# One address has one row and one evidence ledger for the whole installation: the sweep adds up what every host's logs said, so
# an address is reported once however many hosts saw it. The ledger holds the request paths, the jail names, the CVE ids and the
# counts of the hosts that collected it, and those belong to the hosts' owners. So a ledger is stored with `hosts`, the ids of the
# places (hosts, and the edge feeds) whose evidence is in it, and the page shows a ledger only to a caller who reads all of them
# (`_readable_ledger`). The report log keeps the same list on each entry, for the text a report was made of.

LEDGER_HOSTS_MAX = 200      # places named on one ledger; one that was seen by more is the operator's alone


def _cap_hosts(hosts):
    """The place ids of a ledger as a sorted list. Past LEDGER_HOSTS_MAX the list ends in '*', which is no place a caller reads, so
    the ledger is shown to a caller who reads everything and to nobody else."""
    out = sorted({str(h) for h in hosts if h})
    return out if len(out) <= LEDGER_HOSTS_MAX else out[:LEDGER_HOSTS_MAX] + ['*']


def _ledger_hosts(att, ledger):
    """The places whose evidence is in `ledger`, the live ledger of `att`. A ledger stored before the places were recorded names
    every place that has seen the address, which holds the ones that added to it."""
    if not ledger:
        return []
    hosts = (att or {}).get('ev_hosts')
    if isinstance(hosts, list):
        return [str(h) for h in hosts]
    devs = (att or {}).get('devices')
    return [str(d) for d in devs] if isinstance(devs, dict) else []


LEDGER_BY_MAX = 20          # places whose own part of a ledger is kept; a ledger that more of them added to is the operator's alone


def _add_to_ledger(att, group, now):
    """(ledger, hosts, by): the evidence ledger of `att` after the entries of this sweep (`group`) are added, the places it is made
    of, and the part each of them collected.

    `by` is {place: ledger} and exists only while two or more places have added to the ledger, because one place's part is the whole of
    it: it is what lets a tenant read their own hosts' part of an address that another tenant's host also saw (see _readable_ledger),
    without a second copy of every ledger. It is None when there is no way to tell the parts apart (a ledger several places added to
    before they were kept apart, or one that more than LEDGER_BY_MAX did) and the ledger is then shown only to a caller who reads all of
    its places."""
    prior = _fresh_ledger(att, now)
    hosts = _ledger_hosts(att, prior)
    new = _entry_evidence(group)
    if not new:
        by = att.get('ev_by') if prior and isinstance(att.get('ev_by'), dict) else None
        return prior, hosts, by
    own = {}                                    # place -> what its entries of this sweep said
    for q in group:
        e = q['item'].get('evidence')
        if isinstance(e, dict):
            own[q['dev_id']] = threat_evidence.merge(own.get(q['dev_id']), e)
    cur = threat_evidence.slim(threat_evidence.merge(prior, new))
    if prior is None:
        by = {}                                 # a ledger that starts now: each place's part is known from its first line
    elif isinstance(att.get('ev_by'), dict):
        by = dict(att['ev_by'])
    elif len(hosts) == 1:
        by = {hosts[0]: prior}                  # one place so far: the ledger is its own part
    else:
        by = None                               # several places added to it before the parts were kept
    hosts = hosts + list(own)
    if by is not None:
        for place, e in own.items():
            by[place] = threat_evidence.slim(threat_evidence.merge(by.get(place), e))
        by = by if 2 <= len(by) <= LEDGER_BY_MAX else None
    return cur, hosts, by


def _entry_evidence(group):
    """The evidence in a group's queue entries, added together, or None."""
    ev = None
    for p in group:
        e = p['item'].get('evidence')
        if isinstance(e, dict):
            ev = threat_evidence.merge(ev, e)
    return ev


def _may_report(item, att, pol, now):
    """Could this entry lead to a report? Decided without the network, so the
    sweep can ration the work that does need it."""
    if not pol.get('report_enabled'):
        return False
    att = att or {}
    need = int(pol['report_min_count'])
    cf_min = pol.get('edge_report_after')
    waf_min = pol.get('report_waf_after')
    ev = item.get('evidence')
    if pol.get('ignore_nets') or pol.get('ignore_kinds'):
        ledger = _fresh_ledger(att, now)
        seen = threat_evidence.merge(ledger, ev) if (ledger and isinstance(ev, dict)) else (
            ev if isinstance(ev, dict) else ledger)
        counter = [item.get('unit')] if not isinstance(ev, dict) and not item.get('_catchup') else []
        if _ignore_why(ip_intel.parse_ip(item.get('ip')) or '', seen, counter, pol):
            return False
    if isinstance(ev, dict):
        ledger = _fresh_ledger(att, now)
        ok, _why = threat_evidence.qualifies(
            threat_evidence.merge(ledger, ev) if ledger else ev, need, cf_min, waf_min)
    elif item.get('_catchup'):
        ledger = _fresh_ledger(att, now)
        ok = bool(ledger) and threat_evidence.qualifies(ledger, need, cf_min, waf_min)[0]
    else:
        ok = int(item.get('count') or 0) >= need
    if not ok:
        return False
    reported, retry = att.get('reported') or {}, att.get('retry') or {}
    return any(pol['keys'].get(p) and now - int(reported.get(p) or 0) >= REPORT_EVERY_S
               and now >= int(retry.get(p) or 0) for p in ip_intel.PROVIDERS)


def _needs_network(item, att, pol, now, shares=None):
    """Whether handling this entry costs a call to a service. An entry whose host has used its share of the day's lookups (or reports)
    has no call to make and does not take one of the sweep's places from the hosts that have."""
    att = att or {}
    dev = str(item.get('device_id') or '')
    fresh = (now - int(att.get('checked_at') or 0)) < int(pol['cache_hours']) * 3600
    if ((pol.get('lookup_enabled') or pol.get('block_enabled')) and not (fresh and att.get('verdict'))
            and (shares is None or shares.any_left(dev, 'lookups'))):
        return True
    return _may_report(item, att, pol, now) and (shares is None or shares.any_left(dev, 'reports'))


def _claim_batch(queue, atts, pol, now, shares=None):
    """(batch, rest): the queue entries this sweep handles, in the order to handle
    them. The brute-force counter's entries keep their place at the front, first
    come first served; the sensor's follow, strongest first, so when a day's lookup
    and report allowance runs short it goes to the addresses that earned it. Each
    kind is taken from the hosts in turn (see `_fair_order`), so a host that sends
    the most, or the entries that rank highest, does not take the places the others'
    need. Work that costs a network call is rationed to NET_PER_SWEEP addresses;
    entries that cost nothing (already looked up, nothing to report) are taken
    freely."""
    order = _fair_order(queue, tiered=True, newest_first=False)
    taken, net = [], 0
    for i in order:
        item = queue[i]
        if isinstance(item, dict):
            att = atts.get(ip_intel.parse_ip(item.get('ip')) or '')
            if _needs_network(item, att, pol, now, shares):
                if net >= NET_PER_SWEEP:
                    continue
                net += 1
        taken.append(i)
        if len(taken) >= SWEEP_MAX:
            break
    gone = set(taken)
    return ([queue[i] for i in taken],
            [q for i, q in enumerate(queue) if i not in gone])


def _report_plan(group, pol):
    """(plan, why_not) for one address: what to report and how to say it, or the
    reason there is nothing to report yet. `group` is every queue entry for the
    address in this sweep, so one address is one report however many hosts or
    detectors saw it."""
    own = _entry_evidence(group)
    ledger = group[0].get('ledger')
    ev = threat_evidence.merge(ledger, own) if (own and ledger) else (own or ledger)
    legacy = [p for p in group if not isinstance(p['item'].get('evidence'), dict)]
    need = int(pol['report_min_count'])
    ev_ok, ev_why = (threat_evidence.qualifies(ev, need, pol.get('edge_report_after'),
                                               pol.get('report_waf_after'))
                     if ev else (False, ''))
    lead = max(legacy, key=lambda p: int(p['item'].get('count') or 0)) if legacy else None
    legacy_n = int(lead['item'].get('count') or 0) if lead else 0
    legacy_ok = lead is not None and legacy_n >= need
    if not (ev_ok or legacy_ok):
        return None, (ev_why if ev else f'{legacy_n} of {need} attempts so far')
    kind = ip_intel.attack_kind(lead['item'].get('unit')) if legacy_ok else None
    cats = {}
    for prov in ip_intel.PROVIDERS:
        c = list(threat_evidence.categories(ev, prov)) if ev_ok else []
        if legacy_ok:
            c += [x for x in ip_intel.CATEGORIES[kind][prov] if x not in c]
        cats[prov] = c
    if ev_ok:
        comment = ip_intel.evidence_comment(ev, pol.get('report_comment'), bool(pol.get('report_samples')))
        label = '+'.join(c for c, _n in threat_evidence.dominant(ev, 3)) or 'other'
        when = int(ev.get('last') or 0) or None
    else:
        comment = ip_intel.report_comment(kind, legacy_n, lead['item'].get('window_s'),
                                          pol.get('report_comment'))
        label, when = kind, None
    return {'cats': cats, 'comment': comment, 'label': label, 'when': when,
            'ev': ev if ev_ok else None}, ''


CATCHUP_MAX = 50           # ledger-only addresses one sweep takes up


def _ledger_catchup(st, pol, now):
    """Queue entries for addresses whose evidence ledger now qualifies and that a
    service they are meant for has not been told about. The ledger adds up what
    the logs said over a day; without this, an address that crosses a threshold
    the operator has just lowered would wait for its next hit to be reported.
    The entries are made here and dropped from the queue the sweep keeps."""
    if not pol.get('report_enabled'):
        return []
    keyed = [prov for prov in ip_intel.PROVIDERS if pol['keys'].get(prov)]
    if not keyed:
        return []
    need = int(pol['report_min_count'])
    cf_min = pol.get('edge_report_after')
    waf_min = pol.get('report_waf_after')
    out = []
    atts = st.get('attackers') if isinstance(st.get('attackers'), dict) else {}
    for ip, att in atts.items():
        if not isinstance(att, dict):
            continue
        ev = _fresh_ledger(att, now)
        if not ev:
            continue
        if _ignore_why(ip, ev, [], pol):
            continue
        told, retry = att.get('reported') or {}, att.get('retry') or {}
        if not any(now - int(told.get(p) or 0) >= REPORT_EVERY_S and now >= int(retry.get(p) or 0)
                   for p in keyed):
            continue
        if not threat_evidence.qualifies(ev, need, cf_min, waf_min)[0]:
            continue
        devs = att.get('devices') if isinstance(att.get('devices'), dict) else {}
        dev = next(iter(devs), '')
        if not dev:
            continue
        out.append({'ip': ip, 'device_id': dev, 'unit': 'ledger', 'count': 0, 'window_s': 0,
                    'at': now, '_catchup': True})
        if len(out) >= CATCHUP_MAX:
            break
    return out


def run_ip_intel_if_due():
    """Cadence sweep. Three phases, so no lock is held across a network call:

      1. under the store lock: claim a batch from the queue, lift expired
         blocks, and note which addresses need a lookup;
      2. with no lock held: ask the providers, and report;
      3. under the store lock: record the answers and decide blocks.

    Commands and audit lines go out after the lock is released.

    An address is looked up once and reported once per sweep however many hosts
    or detectors saw it. What it was reported FOR comes from the evidence the
    hosts' logs gave (several sources agreeing), or from the brute-force
    counter's own entry; an address is reported when a ban engine decided on it,
    the WAF refused it repeatedly, or it did enough on its own.
    """
    pol = _policy()
    now = int(time.time())
    today = time.strftime('%Y-%m-%d', time.gmtime(now))
    st_ro = _store_ro()
    if now - int(st_ro.get('last_sweep') or 0) < SWEEP_EVERY_S:
        return
    has_expired = any(isinstance(b, dict) and int(b.get('until') or 0) <= now
                      for per in (st_ro.get('blocks') or {}).values() if isinstance(per, dict)
                      for b in per.values())
    if (not _intake_ro().get('queue') and not has_expired and not _ledger_catchup(st_ro, pol, now)
            and not _stale_addresses(st_ro.get('attackers'), now, pol)):
        return

    edge_fanout = 0      # host blocks queued this sweep for edge-found addresses
    online_ttl = A.get_online_ttl()
    commands = []        # (dev_id or None, command or None, audit action, detail)
    expired = []         # (dev_id, ip) of the blocks whose time ran out this sweep
    newly_reported = []  # (address, services told) for the ip_reported event

    # ── phase 1 ──
    # The batch is claimed from the intake first, ranked against the table as this
    # sweep read it; the table's own step comes second. The SQL backends share one
    # connection and cannot hold both locks, and the batch only has to be in this
    # sweep's hands by then.
    devices = A._load_ro(A.DEVICES_FILE) or {}
    with A._LockedUpdate(A.IPINTEL_INTAKE_FILE) as intake:
        _intake_adopt(intake)
        ranked = st_ro.get('attackers') if isinstance(st_ro.get('attackers'), dict) else {}
        waiting = list(intake['queue']) + _ledger_catchup(st_ro, pol, now)
        sensor_hosts = set(intake['sensors'])
        # What each host has used of the day is read from the table as this sweep found it, so that a host that has used its share does
        # not take one of the places that are rationed to the hosts that have not (the count is made again under the table's lock).
        claim_shares = _HostShares(pol, _budget_today(st_ro.get('budget'), today), devices, sensor_hosts,
                                   {str(q.get('device_id') or '') for q in waiting if isinstance(q, dict)})
        batch, rest = _claim_batch(waiting, ranked, pol, now, claim_shares)
        intake['queue'] = [q for q in rest if not (isinstance(q, dict) and q.get('_catchup'))]
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        st['last_sweep'] = now
        # What the intake adopted from this table is dropped here, once the intake
        # holds it (the claim above adopted it).
        for stale in ('queue', 'sensors'):
            st.pop(stale, None)
        if isinstance(st.get('edge'), dict):
            for stale in ('cf_to', 'trap_to'):
                st['edge'].pop(stale, None)
        blocks = st.get('blocks') if isinstance(st.get('blocks'), dict) else {}
        for dev_id, per in list(blocks.items()):
            if not isinstance(per, dict):
                blocks.pop(dev_id, None)
                continue
            for ip, b in list(per.items()):
                if isinstance(b, dict) and int(b.get('until') or 0) <= now:
                    per.pop(ip, None)
                    expired.append((dev_id, ip))
            if not per:
                blocks.pop(dev_id, None)
        st['blocks'] = blocks
        allowance = _budget_left(st, pol, today)
        report_allowance = _report_budget_left(st, pol, today)
        shares = _HostShares(pol, _budget_today(st.get('budget'), today), devices, sensor_hosts,
                             {str(i.get('device_id') or '') for i in batch if isinstance(i, dict)})
        atts = st.get('attackers') if isinstance(st.get('attackers'), dict) else {}
        plan = []
        for item in batch:
            ip = ip_intel.parse_ip(item.get('ip')) if isinstance(item, dict) else None
            dev_id = str(item.get('device_id') or '') if isinstance(item, dict) else ''
            if not ip or not dev_id:
                continue
            a = atts.get(ip) or {}
            fresh = (now - int(a.get('checked_at') or 0)) < int(pol['cache_hours']) * 3600
            ledger = _fresh_ledger(a, now)
            plan.append({
                'item': item, 'ip': ip, 'dev_id': dev_id,
                'lookup': bool(pol['lookup_enabled'] or pol['block_enabled'])
                          and not (fresh and a.get('verdict')),
                'cached': a.get('verdict'),
                'reported': dict(a.get('reported') or {}),
                'retry': dict(a.get('retry') or {}),
                'ledger': ledger,
                'ledger_hosts': _ledger_hosts(a, ledger),
            })

    # ── phase 2 ──
    spent = {}
    down = {}            # provider -> answers it did not give this sweep (see ip_intel.TRANSIENT_BREAKER)
    looked = {}          # ip -> (verdict, errors): one lookup per address per sweep
    protected = None
    groups = {}
    for p in plan:
        groups.setdefault(p['ip'], []).append(p)
        # The lookup is one for each address however many hosts saw it, and it is paid for by the first host that still has a share.
        if p['lookup'] and p['ip'] not in looked and shares.any_left(p['dev_id'], 'lookups'):
            looked[p['ip']] = _fetch_verdict(p['ip'], pol, allowance, spent, down, (shares, p['dev_id']))
        p['verdict'] = (looked.get(p['ip']) or (None, {}))[0] or p['cached']
        p['report_ok'], p['report_err'], p['report_retry'], p['report_log'] = {}, {}, {}, []
        ev = p['item'].get('evidence')
        p['kind'] = ('web' if threat_evidence.web_only(ev) else 'other') if isinstance(ev, dict) \
            else ip_intel.attack_kind(p['item'].get('unit'))
    for ip, group in groups.items():
        lead = group[0]                  # the address's one report is recorded once, on this entry
        if not pol['report_enabled'] or (lead['verdict'] or {}).get('whitelisted'):
            continue
        keyed = [prov for prov in ip_intel.PROVIDERS if pol['keys'].get(prov)]
        if not keyed:
            continue
        # What the operator said not to report is decided before anything is built
        # from the evidence, and said only for a service it has not been reported to
        # today, like the other reasons below.
        if pol.get('ignore_nets') or pol.get('ignore_kinds'):
            own_ev = _entry_evidence(group)
            led = lead.get('ledger')
            seen_ev = threat_evidence.merge(led, own_ev) if (own_ev and led) else (own_ev or led)
            counters = [p['item'].get('unit') for p in group
                        if not isinstance(p['item'].get('evidence'), dict)]
            ign = _ignore_why(ip, seen_ev, counters, pol)
            if ign:
                lead['report_err'] = {prov: f'not reported: {ign}' for prov in keyed
                                      if now - int(lead['reported'].get(prov) or 0) >= REPORT_EVERY_S}
                continue
        report, why = _report_plan(group, pol)
        if report is None:
            # Said only for a service it has not been reported to today: an
            # address reported this morning is not "not reported".
            lead['report_err'] = {prov: f'not reported: {why}' for prov in keyed
                                  if now - int(lead['reported'].get(prov) or 0) >= REPORT_EVERY_S}
            continue
        # A report is public and filed under the operator's account, so the
        # addresses that may never be blocked may never be reported either:
        # the fleet's own, the operator's allow-list, recent login sources, and
        # a proxy's edge. A misconfigured script failing logins from the office
        # is not an attacker, and a public report naming it is hard to take back.
        if protected is None:
            protected = _protected_networks(pol, devices)
        nb = ip_intel.never_block_reason(ip, protected)
        if nb:
            lead['report_err'] = {prov: f'not reported: {nb}' for prov in keyed}
            continue
        # The text of a report is made of the whole address's evidence, so it names every place that went into it: the ledger it
        # was added to and the entries of this sweep (a counter's entry too: its count is the largest of any host's).
        report_hosts = _cap_hosts(set(lead.get('ledger_hosts') or ()) | {q['dev_id'] for q in group})
        for prov in keyed:
            key = pol['keys'][prov]
            if now - int(lead['reported'].get(prov) or 0) < REPORT_EVERY_S:
                continue
            if now < int(lead['retry'].get(prov) or 0):
                continue                 # a service said 429 a moment ago; let its window pass
            if report_allowance.get(prov, 0) <= 0:
                lead['report_err'][prov] = 'not reported: the daily report limit is used up'
                continue
            payer = shares.payer(group, prov, 'reports')
            if payer is None:
                # None of the hosts that saw it has any of its share of the day's reports left. The address keeps its evidence for
                # tomorrow's sweep; the reports that are left are for the hosts that have not used theirs.
                lead['report_err'][prov] = "not reported: this host has used its share of the day's report limit"
                continue
            if down.get(prov, 0) >= ip_intel.TRANSIENT_BREAKER:
                # It has not answered this sweep: leave the rest of the queue alone with it, and try again later.
                lead['report_err'][prov] = 'not reported: the service is not answering'
                lead['report_retry'][prov] = now + ip_intel.TRANSIENT_RETRY_S
                continue
            report_allowance[prov] -= 1
            spent['report:' + prov] = spent.get('report:' + prov, 0) + 1
            shares.charge(payer, prov, 'reports', spent)
            build, parse = ip_intel.REPORT[prov]
            res = parse(*A._ip_intel_http(
                build(ip, key, report['cats'][prov], report['comment'], timestamp=report['when'])))
            entry = {'at': now, 'prov': prov, 'cats': list(report['cats'][prov]),
                     'comment': report['comment'], 'hosts': report_hosts}
            if res.get('transient'):
                # Nothing was filed. The day's allowance is not spent on it (a service that was down for a day
                # used up the whole of it before this), and the address waits instead of being tried again at its
                # next sighting.
                report_allowance[prov] += 1
                spent['report:' + prov] -= 1
                shares.charge(payer, prov, 'reports', spent, -1)
                down[prov] = down.get(prov, 0) + 1
                lead['report_retry'][prov] = now + ip_intel.TRANSIENT_RETRY_S
            if res.get('ok'):
                lead['report_ok'][prov] = now
                entry['ok'] = True
                commands.append((None, None, 'ip_intel_report',
                                 f"ip={ip} provider={prov} kind={report['label']}"))
            elif res.get('duplicate'):
                # It was reported moments ago (often by fail2ban on the same host,
                # under the same key). That report exists, so this one is done.
                lead['report_ok'][prov] = now
                lead['report_err'][prov] = res.get('error')
                entry['ok'] = True
                entry['duplicate'] = True
            else:
                lead['report_err'][prov] = res.get('error')
                entry['error'] = res.get('error')
                if res.get('rate_limited'):
                    lead['report_retry'][prov] = now + ip_intel.REPORT_RETRY_S[prov]
            lead['report_log'].append(entry)
        if lead['report_ok']:
            lead['archived'] = report['ev']

    # ── phase 3 ──
    sensors = _intake_ro().get('sensors')
    sensors = sensors if isinstance(sensors, dict) else {}
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        _reqlog_flush(st)
        _add_spend(st, today, spent)
        atts = st.setdefault('attackers', {})
        blocks = st.setdefault('blocks', {})
        done = set()
        for p in plan:
            ip, dev_id, item, verdict = p['ip'], p['dev_id'], p['item'], p['verdict']
            att = atts.setdefault(ip, {})
            catchup = bool(item.get('_catchup'))
            if not catchup:
                att.setdefault('first_seen', now)
                att['last_seen'] = now
            if ip in looked:
                v, errs = looked[ip]
                att['checked_at'] = now
                att['errors'] = errs
                if v:
                    att['verdict'] = v
            first_of_address = ip not in done
            done.add(ip)
            if first_of_address:
                if p['report_ok']:
                    newly_reported.append((ip, sorted(p['report_ok'])))
                    att.setdefault('reported', {}).update(p['report_ok'])
                    for prov in p['report_ok']:         # an old reason no longer applies
                        if prov not in p['report_err']:
                            (att.get('errors') or {}).pop(prov, None)
                if p['report_err']:
                    att.setdefault('errors', {}).update(p['report_err'])
                if p['report_retry']:
                    att.setdefault('retry', {}).update(p['report_retry'])
                if p['report_log']:
                    att['report_log'] = (list(att.get('report_log') or []) + p['report_log'])[-REPORT_LOG_KEEP:]
                # The evidence ledger: everything the logs said about this address
                # in the last day, added up across sweeps, so a slow attacker still
                # adds up. A report starts it over; what it said is kept to show.
                # It is kept with the places that collected it and, while more than one
                # did, the part of each (see _add_to_ledger).
                cur, hosts, by = _add_to_ledger(att, groups[ip], now)
                # A report starts the ledger over, but only once every service it
                # is meant for has been told: if one took it and the other was
                # busy, the evidence stays so the other can still be sent it.
                told = att.get('reported') or {}
                everyone = all(now - int(told.get(prov) or 0) < REPORT_EVERY_S
                               for prov in ip_intel.PROVIDERS if pol['keys'].get(prov))
                if p.get('archived') and cur and everyone:
                    att['ev_reported'] = {'at': now, 'ev': cur, 'hosts': _cap_hosts(hosts)}
                    if by:
                        att['ev_reported']['by'] = by
                    cur = None
                att['ev'] = cur
                if cur is None:
                    for stale in ('ev', 'ev_hosts', 'ev_by'):
                        att.pop(stale, None)
                else:
                    att['ev_hosts'] = _cap_hosts(hosts)
                    if by:
                        att['ev_by'] = by
                    else:
                        att.pop('ev_by', None)
            if catchup:
                continue      # the ledger was reported; nothing was seen, so no sighting or block
            seen = att.setdefault('devices', {})
            ev = item.get('evidence')
            prior = seen.get(dev_id) if isinstance(seen.get(dev_id), dict) else {}
            count = int(item.get('count') or 0)
            if isinstance(ev, dict) and now - int(prior.get('at') or 0) <= LEDGER_S:
                count += int(prior.get('count') or 0)        # a running total for the day
            seen[dev_id] = {'count': count, 'unit': str(item.get('unit') or '')[:64],
                            'at': int(item.get('at') or now)}
            sure = threat_evidence.confirmed_by(ev) if isinstance(ev, dict) else ''
            ok, why = ip_intel.block_decision(pol, verdict, item.get('count'), sure)
            # A block that exists because a ban engine decided (the setting `block_confirmed`) and not because
            # of the score says so, in the block and in the audit line. The verdict can be missing: a new
            # scanner has no score, and that is the case this setting is for.
            by_ban = sure if (ok and sure and not ip_intel.block_decision(pol, verdict, item.get('count'))[0]) else ''
            score = (verdict or {}).get('score')
            note = {'why': by_ban} if by_ban else {}
            tail = f' confirmed={by_ban}' if by_ban else ''     # one of the four fixed phrases of confirmed_by
            if (ok and _edge_ban_ready(pol)
                    and (dev_id in ip_intel.EDGE_DEVICES or not A._tenancy_enforced())):
                # What is blocked on a host is banned at the edge too, so a
                # visitor arriving through Cloudflare is stopped as well. The
                # list is the whole account's, so on a multi-tenant install a
                # tenant's host does not write to it; the edge's own findings do.
                if protected is None:
                    protected = _protected_networks(pol, devices)
                if not ip_intel.never_block_reason(ip, protected):
                    _ban_at_edge(st, pol, ip, now)
            fanned = False
            if dev_id in ip_intel.EDGE_DEVICES:
                # The edge has no host of its own. With the operator's say-so the
                # address is blocked on every Linux agent instead, which stops
                # direct connections to the origin (a proxied visitor arrives from
                # Cloudflare's addresses and is only stopped by the edge list).
                # One tenant's edge data never blocks another tenant's hosts.
                fan = ok and pol.get('block_edge_hosts') and not A._tenancy_enforced()
                ok, why = False, 'seen at the edge only, so there is no host to block it on'
                if fan:
                    if protected is None:
                        protected = _protected_networks(pol, devices)
                    nb = ip_intel.never_block_reason(ip, protected)
                    if nb:
                        why = nb
                    else:
                        reached = 0
                        for hid, hd in sorted(devices.items()):
                            if edge_fanout >= EDGE_FANOUT_PER_SWEEP:
                                break
                            if (not isinstance(hd, dict) or hd.get('agentless')
                                    or A._device_os_family(hd) != 'linux'
                                    or not _agent_online(hd, now, online_ttl)
                                    or ip in (blocks.get(hid) or {})
                                    or _blocks_last_hour(blocks, hid, now) >= int(pol['block_max_per_hour'])):
                                continue
                            blocks.setdefault(hid, {})[ip] = {
                                'at': now, 'until': now + int(pol['block_ttl_hours']) * 3600,
                                'score': score, 'by': 'auto', 'kind': 'edge', **note}
                            commands.append((hid, 'exec:' + ip_intel.block_command(ip), 'ip_intel_block',
                                             f"device={hid} ip={ip} score={score} auto edge{tail}"))
                            edge_fanout += 1
                            reached += 1
                        fanned = True
                        why = '' if reached else 'already blocked on every host that is online, or the hourly limit was reached'
            dev = devices.get(dev_id)
            if ok and (not isinstance(dev, dict) or dev.get('agentless')
                       or A._device_os_family(dev) != 'linux'):
                ok, why = False, 'host is not a Linux agent'
            if ok and ip in (blocks.get(dev_id) or {}):
                ok, why = False, 'already blocked'
            if ok and isinstance(ev, dict) and threat_evidence.web_only(ev) \
                    and _web_is_proxied(sensors, dev_id):
                ok, why = False, 'web attacks arrive through a proxy'
            if ok:
                if protected is None:
                    protected = _protected_networks(pol, devices)
                nb = ip_intel.never_block_reason(ip, protected)
                if nb:
                    ok, why = False, nb
            if ok and _blocks_last_hour(blocks, dev_id, now) >= int(pol['block_max_per_hour']):
                ok, why = False, 'hourly block limit reached for this host'
            if ok:
                blocks.setdefault(dev_id, {})[ip] = {
                    'at': now, 'until': now + int(pol['block_ttl_hours']) * 3600,
                    'score': score, 'by': 'auto', 'kind': p['kind'], **note}
                commands.append((dev_id, 'exec:' + ip_intel.block_command(ip), 'ip_intel_block',
                                 f"device={dev_id} ip={ip} score={score} auto{tail}"))
            elif pol['block_enabled'] and not (fanned and not why):
                seen[dev_id]['not_blocked'] = why
        _forget_stale(atts, now, pol)
        if len(atts) > ATTACKER_CAP:
            oldest = sorted(atts, key=lambda k: int((atts[k] or {}).get('last_seen') or 0))
            for old in oldest[:len(atts) - ATTACKER_CAP]:
                atts.pop(old, None)

    if newly_reported:
        _announce_reports(newly_reported)

    # An expired block is lifted on the host. When the block is still waiting in the host's queue (the host has
    # been off since it was sent), it never ran, so it is taken out and no unblock is queued behind it.
    lifts = []
    for dev_id, ip in expired:
        try:
            if _drop_unrun_block(dev_id, ip):
                A.audit_log('ip-intel', 'ip_intel_unblock',
                            f'device={dev_id} ip={ip} reason=expired, the block had not run and was taken out of the queue')
                continue
        except Exception:  # nosec B110
            pass           # a queue that cannot be read gets the unblock below, as it did before
        lifts.append((dev_id, 'exec:' + ip_intel.unblock_command(ip),
                      'ip_intel_unblock', f'device={dev_id} ip={ip} reason=expired'))
    commands[:0] = lifts

    for dev_id, cmd, action, detail in commands:
        if cmd:
            try:
                res = (A._queue_command_batch([dev_id], cmd, 'ip-intel') or {}).get(dev_id) or {}
            except Exception as exc:          # a guard that raises rather than returns
                res = {'ok': False, 'error': type(exc).__name__}
            if not res.get('ok'):
                detail += f" refused={res.get('error') or 'unknown'}"
            elif res.get('approval_required'):
                detail += ' awaiting-approval'
        A.audit_log('ip-intel', action, detail[:500])


EDGE_AUTOBAN_PER_HOUR = 50     # automatic edge bans per hour: a cap on a runaway
REPORT_NAMES_IN_EVENT = 5      # addresses named in the ip_reported event; the rest are counted


def _announce_reports(reported):
    """One ip_reported event for a sweep that reported addresses, so a busy hour is one
    line to read and not one message per address. Telling the operator must not stop the sweep.

    Not sent when tenancy is on: an alert with no host is visible to every tenant, and this one
    names addresses that may have attacked another tenant's hosts. The platform operator reads
    the same reports on the Threat Intel page."""
    if A._tenancy_enforced():
        return
    services = sorted({s for _, told in reported for s in told})
    shown = [ip for ip, _ in reported[:REPORT_NAMES_IN_EVENT]]
    more = len(reported) - len(shown)
    detail = '%s reported to %s: %s%s' % (
        textfmt.plural(len(reported), 'address', 'addresses'),
        ' and '.join(ip_intel.PROVIDER_LABELS.get(s, s) for s in services),
        ', '.join(shown), ' and %d more' % more if more > 0 else '')
    try:
        A.fire_webhook('ip_reported', {'detail': detail[:300]})
    except Exception:   # nosec B110 — a failed notification must not stop the sweep
        pass


def _edge_ban_ready(pol):
    """True when the Edge blocklist is on and able to write: automatic blocks
    are then banned at the edge as well."""
    return bool(pol.get('edgelist_enabled') and pol.get('edge_list_token')
                and edge_evidence.valid_id(pol.get('edge_account_id')))


def _ban_at_edge(st, pol, ip, now):
    """Put `ip` in the stored edge bans for the block lifetime, which the next
    sync of the Cloudflare list carries. An address already banned is left alone."""
    key = edge_blocklist.canonical(ip)
    bans = st.get('edgeban') if isinstance(st.get('edgeban'), dict) else {}
    st['edgeban'] = bans
    if not key or int((bans.get(key) or {}).get('until') or 0) > now:
        return
    recent = sum(1 for b in bans.values() if isinstance(b, dict) and b.get('by') == 'auto'
                 and now - int(b.get('at') or 0) < 3600)
    if recent >= EDGE_AUTOBAN_PER_HOUR:
        return
    bans[key] = {'at': now, 'until': now + int(pol['block_ttl_hours']) * 3600, 'by': 'auto'}
    el = st.get('edgelist') if isinstance(st.get('edgelist'), dict) else {}
    el['attempt'] = 0                      # due now, as a ban by hand is
    st['edgelist'] = el


def _web_is_proxied(sensors, dev_id):
    """True when the host's web logs say visitors arrive through a proxy that
    restores their address. A host firewall rule drops packets from the visitor's
    address, which a proxied visitor's packets never carry, so such a rule would
    sit in the firewall and block nothing."""
    rec = (sensors or {}).get(dev_id)
    return bool(isinstance(rec, dict) and any(
        isinstance(s, dict) and s.get('kind') == 'web' and s.get('proxied')
        for s in rec.get('sources') or []))


# ── endpoints ──────────────────────────────────────────────────────────────────

def _settings_view(pol):
    out = {k: pol[k] for k in ip_intel.DEFAULTS}
    stored = pol.get('report_comment')
    out['report_comment'] = ip_intel.REPORT_COMMENT_DEFAULT if ip_intel.is_default_comment(stored) else stored
    out['sensor_enabled'] = bool(pol.get('sensor_enabled'))
    out['sensor_paths'] = list(pol.get('sensor_paths') or [])
    out['abuseipdb_key_set'] = bool(pol['keys'].get('abuseipdb'))
    out['sniffcat_key_set'] = bool(pol['keys'].get('sniffcat'))
    out['edge_token_set'] = bool(pol.get('edge_token'))
    out['edge_list_token_set'] = bool(pol.get('edge_list_token'))
    out['edgelist_always'] = list(pol.get('edgelist_always') or [])
    out['edge_zone_ids'] = list(pol.get('edge_zone_ids') or [])
    out['edge_workers'] = list(pol.get('edge_workers') or [])
    return out


def _within(hosts, places):
    """Whether `hosts`, a stored list of place ids, is made of places the caller reads. A list that is missing, empty or not a list
    names nobody, so it is not within anything: what is stored without its places is not shown to a caller who reads some."""
    return isinstance(hosts, list) and bool(hosts) and all(h in places for h in hosts)


def _readable_ledger(att, places):
    """(ledger, sent): the evidence ledger of an address as far as the caller may read it, or (None, ...). The day's ledger, else
    the one the last report was made of (`sent`).

    `places` is None for a caller who reads every place, and the ledger is then the sweep's own, added up over all of them. For any
    other caller it is the set of place ids they see. The ledger is a sum over every place that saw the address, so it is shown whole
    when each place in `hosts` is one they read. Otherwise they are given the sum of their own places' parts (`by`, kept while more
    than one place added to it), and nothing when there are none or the parts were never kept apart."""
    ev = att.get('ev') if isinstance(att.get('ev'), dict) else None
    hosts, by, sent = att.get('ev_hosts'), att.get('ev_by'), False
    if ev is None:
        rep = att.get('ev_reported')
        if isinstance(rep, dict) and isinstance(rep.get('ev'), dict):
            ev, hosts, by, sent = rep['ev'], rep.get('hosts'), rep.get('by'), True
    if not ev:
        return None, False
    if places is None:
        return ev, sent
    if not isinstance(hosts, list):
        # stored before the places were recorded: every place that has seen the address may have added to it
        devs = att.get('devices')
        hosts = list(devs) if isinstance(devs, dict) else []
    if _within(hosts, places):
        return ev, sent
    mine = [by[h] for h in hosts if h in places and isinstance(by, dict) and isinstance(by.get(h), dict)]
    part = None
    try:
        for ledger in mine:
            part = threat_evidence.merge(part, ledger)
    except Exception:       # a part that was edited by hand reads as no part: the page must not fail on it
        part = None
    return (part, sent) if part else (None, sent)


REPORT_ENTRY_OPEN = ('at', 'prov', 'ok', 'duplicate', 'error')   # what an entry says without the text of the report


def _report_log_view(att, places):
    """The last reports of an address for the page, each without its internal list of places. What was sent (`cats`, `comment`) is made
    of the evidence of those places, so a caller who does not read all of them is told that a report was made and what the service
    answered, and not what it said."""
    out = []
    for e in [e for e in (att.get('report_log') or []) if isinstance(e, dict)][-3:]:
        shown = {k: v for k, v in e.items() if k != 'hosts'}
        if places is not None and not _within(e.get('hosts'), places):
            shown = {k: v for k, v in shown.items() if k in REPORT_ENTRY_OPEN}
        out.append(shown)
    return out


def _errors_view(att, places):
    """The reasons stored beside an address: what a provider answered, and why nothing was reported. A reason of the second kind is
    worked out from the address's whole ledger ("7 of 10 attempts so far", "no attack category for the fail2ban jail ..."), so a caller
    who does not read every place that saw the address does not get it."""
    errs = att.get('errors') if isinstance(att.get('errors'), dict) else {}
    if places is None:
        return errs
    rep = att.get('ev_reported') if isinstance(att.get('ev_reported'), dict) else {}
    named = set()
    for src in (att.get('devices'), att.get('ev_hosts'), rep.get('hosts')):
        named |= {str(k) for k in src} if isinstance(src, (dict, list)) else set()
    if named <= places:
        return errs
    return {k: v for k, v in errs.items() if not str(v).startswith('not reported')}


def _evidence_view(att, places=None):
    """What the logs showed about one address, for the page: the classes it was
    seen doing, the sources that saw it, the rule ids and CVE ids, and who had
    already decided on it. From the day's ledger, or from what the last report
    was made of when the ledger has just been started over. None when the logs
    said nothing (an address only the brute-force counter knows), or when the
    ledger holds what a place outside `places` collected (see _readable_ledger)."""
    ev, sent = _readable_ledger(att, places)
    if not ev:
        return None
    src, tok = ev.get('src') or {}, ev.get('tok') or {}
    seen = []
    for fam in threat_evidence.SOURCES:
        if src.get(fam) or tok.get(fam) or (fam == 'f2b' and ev.get('ban')) \
                or (fam == 'cs' and ev.get('dec')) \
                or (fam == threat_evidence.trap_family(ev) and ev.get('trp')):
            seen.append({'id': fam, 'n': int(src.get(fam) or 0)})
    rules = {}
    for toks in tok.values():
        for t_, c in toks.items():
            if t_.startswith('crs:') and threat_evidence.crs_class(t_[4:]):
                rules[t_[4:]] = max(rules.get(t_[4:], 0), int(c))
    kinds = {}
    for t_, c in (tok.get('trap') or {}).items():
        if t_.startswith('trap:'):
            kinds[t_[5:]] = int(c)
    return {
        'classes': [{'id': c, 'n': n} for c, n in threat_evidence.dominant(ev, 5)],
        'sources': seen,
        'kinds': [{'id': k, 'n': n} for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])[:5]],
        'rules': [r for r, _n in sorted(rules.items(), key=lambda kv: -kv[1])[:5]],
        'cves': list(ev.get('cve') or [])[:3], 'jails': list(ev.get('ban') or [])[:4],
        # what the logs showed the address asking for, and the CrowdSec scenarios that named it. A ledger is read back from
        # storage, so each sample is rebuilt here too; the page escapes what it prints either way.
        'samples': threat_evidence.normalize_samples(ev.get('smp'), None, threat_evidence.SOURCES),
        'scenarios': [{'id': n_, 'n': c_, 'class': k_ or ''} for n_, c_, k_ in threat_evidence.cs_scenarios(ev)],
        'ans': int(ev.get('ans') or 0), 'blk': int(ev.get('blk') or 0),
        'confirmed': threat_evidence.confirmed_by(ev),
        'first': ev.get('first'), 'last': ev.get('last'), 'sent': sent,
    }


SYSLOG_ROW_FRESH_S = 86400   # a firewall's source row is written when its lines arrive; after a day without one it says "quiet"


def _aged(src, at, now):
    """A source row as the page should show it. What an agent reports is rewritten every pass, so it is
    always current. What the server read from a firewall's syslog is written only when a line arrives, so
    a row from last week still said "Not understood" and read like today's verdict."""
    if (isinstance(src, dict) and src.get('path') == 'syslog' and now - int(at or 0) > SYSLOG_ROW_FRESH_S
            and src.get('state') in ('ok', 'unparsed', 'engine')):
        return dict(src, state='idle')
    return src


def _sensor_rows(intake, visible):
    """Each visible host's sensor health: what its agent reads, or what the server
    read from its syslog, and whether it could. Hosts the caller cannot see are not
    listed."""
    rows = []
    now = int(time.time())
    for dev_id, rec in (intake.get('sensors') if isinstance(intake.get('sensors'), dict) else {}).items():
        if dev_id not in visible or not isinstance(rec, dict):
            continue
        rows.append({'device_id': dev_id, 'name': (visible[dev_id] or {}).get('name') or dev_id,
                     'at': rec.get('at'), 'sources': [_aged(x, rec.get('at'), now) for x in (rec.get('sources') or [])],
                     'events': rec.get('events'), 'dropped': rec.get('dropped'),
                     'throttled': rec.get('throttled'), 'ignored': dict(rec.get('ignored') or {})})
    rows.sort(key=lambda r: str(r['name']).lower())
    return rows


def _is_operator():
    """An administrator, and on a multi-tenant install only the platform operator.
    The edge feeds and the Cloudflare list belong to the instance, not to a tenant."""
    try:
        role = A.verify_token(A.get_token_from_request())[1]
    except Exception:
        return False
    return bool(A._resolve_role(role).get('admin')) and (
        not A._tenancy_enforced() or A._caller_is_superadmin())


def _reads_all_hosts():
    """True when nothing a host collected is kept from the caller: tenancy is off or the caller is the platform operator, and neither
    the role nor the API key carries a host scope. Any other caller reads the hosts they are shown and no others, and so reads only
    the evidence of those (see _readable_ledger). When the answer cannot be worked out it is no."""
    try:
        if A._tenancy_enforced() and not A._caller_is_superadmin():
            return False
        return A._caller_scope() is None
    except Exception:
        return False


WIDGET_WINDOW_S = 86400
WIDGET_PROBLEM_STATES = ('missing', 'denied', 'unparsed', 'unsupported', 'error')
WIDGET_FEED_PROBLEMS = ('no_access', 'refused', 'error', 'no_account', 'no_zones')


def ip_intel_widget(visible, now=None):
    """The numbers of the small Threat Intel widget on Home, for the hosts `visible` (the caller's own view, so another
    tenant's addresses and sources are not in them): addresses seen in the last day, how many were reported in that day,
    blocks in force, and how many hosts have a log source in trouble. The edge feeds are the operator's and count only
    for the operator. {'on': False} when nothing of Threat Intel is switched on. Never raises: a widget must not take the
    dashboard down."""
    try:
        now = int(now or time.time())
        pol = _policy()
        if not (_any_enabled(pol) or pol.get('sensor_enabled') or pol.get('appliance_enabled') or pol.get('edge_enabled')):
            return {'on': False}
        operator = _is_operator()
        ids = set(visible or {})
        if operator:
            ids |= set(ip_intel.EDGE_DEVICES)
        st, since = _store_ro(), now - WIDGET_WINDOW_S
        seen = reported = 0
        for a in (st.get('attackers') or {}).values():
            devs = a.get('devices') if isinstance(a, dict) and isinstance(a.get('devices'), dict) else {}
            if not any(d in ids for d in devs):
                continue
            seen += 1 if int(a.get('last_seen') or 0) >= since else 0
            told = a.get('reported') if isinstance(a.get('reported'), dict) else {}
            reported += 1 if any(isinstance(t, (int, float)) and int(t) >= since for t in told.values()) else 0
        blocked = sum(1 for dev, per in (st.get('blocks') or {}).items() if dev in ids and isinstance(per, dict)
                      for b in per.values() if isinstance(b, dict) and int(b.get('until') or 0) > now)
        problems = 0
        sensors = _intake_ro().get('sensors')
        for dev_id, rec in (sensors.items() if isinstance(sensors, dict) else ()):
            if dev_id in (visible or {}) and isinstance(rec, dict) and any(
                    isinstance(x, dict) and _aged(x, rec.get('at'), now).get('state') in WIDGET_PROBLEM_STATES
                    for x in (rec.get('sources') or [])):
                problems += 1
        if operator and pol.get('edge_enabled'):
            edge = A.edge_intel_status(st, pol)
            problems += sum(1 for k in ('cf', 'trap') if (edge.get(k) or {}).get('state') in WIDGET_FEED_PROBLEMS)
        return {'on': True, 'seen': seen, 'reported': reported, 'blocked': blocked, 'problems': problems}
    except Exception:
        return {}


def edge_metrics(now=None):
    """Instance-level numbers for the metrics export: whether each edge feed's last
    read worked and how long ago it was, what the Cloudflare list holds and whether
    its last sync needs a person, how many bans are live, and how many addresses
    the day's logs and edge feeds named. {} when nothing here is switched on."""
    now = int(now or time.time())
    pol = _policy()
    st = _store_ro()
    out = {}
    edge = st.get('edge') if isinstance(st.get('edge'), dict) else {}
    if pol.get('edge_enabled'):
        feeds = {}
        for key, name in (('cf', 'cloudflare'), ('trap', 'honeypot')):
            f = edge.get(key) if isinstance(edge.get(key), dict) else None
            if f is None:
                continue
            at = int(f.get('at') or 0)
            feeds[name] = {'up': 1 if f.get('state') == 'ok' else 0,
                           'age': max(0, now - at) if at else None}
        out['feeds'] = feeds
    if pol.get('edgelist_enabled'):
        el = st.get('edgelist') if isinstance(st.get('edgelist'), dict) else {}
        last = el.get('last') if isinstance(el.get('last'), dict) else {}
        lst = last.get('list') if isinstance(last.get('list'), dict) else {}
        state = str(last.get('state') or '')
        at = int(last.get('at') or 0)
        out['blocklist'] = {
            'entries': int(lst.get('items') or 0),
            'age': max(0, now - at) if at else None,
            'up': 1 if state in ('ok', 'pending', '') else 0,
            'held': 1 if state in ('held', 'needs_adopt') else 0,
            'bans': len(edge_blocklist.active_bans(st.get('edgeban'), now)),
        }
    atts = st.get('attackers') if isinstance(st.get('attackers'), dict) else {}
    recent = sum(1 for a in atts.values()
                 if isinstance(a, dict) and now - int(a.get('last_seen') or 0) < 86400)
    if out or atts:
        out['attackers_24h'] = recent
    return out


def edge_report(now, days=30):
    """What the edge sources saw in the last `days`, for the posture report, or
    None when there is nothing to say. Instance-level: the caller decides whether
    the reader may have it."""
    pol = _policy()
    st = _store_ro()
    cutoff = int(now) - int(days) * 86400
    seen = reported = listed = 0
    atts = st.get('attackers') if isinstance(st.get('attackers'), dict) else {}
    for a in atts.values():
        if not isinstance(a, dict):
            continue
        devs = a.get('devices') if isinstance(a.get('devices'), dict) else {}
        if not any(d in ip_intel.EDGE_DEVICES and isinstance(x, dict)
                   and int(x.get('at') or 0) >= cutoff for d, x in devs.items()):
            continue
        seen += 1
        if any(int(t or 0) >= cutoff for t in (a.get('reported') or {}).values()):
            reported += 1
        if a.get('in_list'):
            listed += 1
    on = bool(pol.get('edge_enabled') or pol.get('edgelist_enabled'))
    if not on and not seen:
        return None
    el = st.get('edgelist') if isinstance(st.get('edgelist'), dict) else {}
    last = el.get('last') if isinstance(el.get('last'), dict) else {}
    lst = last.get('list') if isinstance(last.get('list'), dict) else {}
    return {'seen': seen, 'reported': reported, 'in_list': listed,
            'list_entries': int(lst.get('items') or 0) if pol.get('edgelist_enabled') else None,
            'bans': len(edge_blocklist.active_bans(st.get('edgeban'), int(now)))}


def explorer_rows(visible):
    """Rows for the Data Explorer's `attackers` entity: one per (source address,
    place that saw it). `visible` is the caller's device map.

    A place is a host the caller can see, or, for the platform operator, one of the
    two edge sources (Cloudflare's firewall events, the honeypot Worker). An address
    only the edge saw has no host, so without those rows "which addresses has the
    honeypot caught and are they in the blocklist" could not be asked at all. Edge
    rows and the list/ban columns stay empty for everyone else."""
    st = _store_ro()
    blocks = st.get('blocks') if isinstance(st.get('blocks'), dict) else {}
    operator = _is_operator()
    # The classes of an address come from its evidence ledger, which a caller reads only when every place that went into it is one
    # they see (_readable_ledger): the Data Explorer is a second door to what the Threat Intel page shows.
    places = None if _reads_all_hosts() else set(visible) | (set(ip_intel.EDGE_DEVICES) if operator else set())
    now = int(time.time())
    bans = edge_blocklist.active_bans(st.get('edgeban'), now) if operator else {}
    out = []
    for ip, a in (st.get('attackers') or {}).items():
        if not isinstance(a, dict):
            continue
        v = a.get('verdict') if isinstance(a.get('verdict'), dict) else {}
        rep = a.get('reported') if isinstance(a.get('reported'), dict) else {}
        ev, _sent = _readable_ledger(a, places)
        classes = ''
        if isinstance(ev, dict):
            classes = ','.join(c for c, _n in threat_evidence.dominant(ev, 5))
        canon = edge_blocklist.canonical(ip)
        for did, seen in (a.get('devices') or {}).items():
            if not isinstance(seen, dict):
                continue
            edge = did in ip_intel.EDGE_DEVICES
            if edge and not operator:
                continue
            if not edge and did not in visible:
                continue
            out.append({
                'ip': ip, 'device_id': did,
                'device_name': (ip_intel.EDGE_DEVICES[did] if edge
                                else (visible[did] or {}).get('name') or did),
                'unit': seen.get('unit') or '', 'count': int(seen.get('count') or 0),
                'score': v.get('score'), 'reports': v.get('reports'),
                'country': v.get('country') or '', 'isp': v.get('isp') or '',
                'usage': v.get('usage') or '',
                'blocked': ip in (blocks.get(did) or {}),
                'reported': bool(rep),
                'first_seen': int(a.get('first_seen') or 0),
                'last_seen': int(seen.get('at') or a.get('last_seen') or 0),
                'source': 'edge' if edge else 'host',
                'classes': classes,
                'reported_to': ','.join(sorted(str(k) for k in rep)),
                'in_edge_list': (bool(a.get('in_list')) if operator else None),
                'edge_banned': ((canon in bans) if operator and canon else None),
            })
    return out


def _listed_view(row, visible):
    """What the page shows of an address's reputation-list hits: {'lists': {name: count}, 'at': last,
    'hosts': [names]}, or None. The names are the hosts' own, as the caller may see them."""
    if not row:
        return None
    return {'lists': dict(sorted(row['l'].items(), key=lambda kv: -kv[1])), 'at': row['at'],
            'hosts': sorted({str((visible.get(d) or {}).get('name') or d) for d in row['on']})}


def handle_ip_intel():
    """GET /api/ip-intel — settings (keys as booleans), recent attackers with
    their reputation and what the logs showed, active blocks, each host's log
    sensor, and today's lookup budget. Attackers, blocks and sensors are limited
    to devices the caller can see, and what the logs showed to what those hosts
    collected (see _readable_ledger); the settings, the budget and the edge feeds
    are the platform operator's (an administrator on a single-organisation install)."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    role = A.verify_token(A.get_token_from_request())[1]
    is_admin = bool(A._resolve_role(role).get('admin'))
    pol = _policy()
    # `?limit=` asks for more of the table than the page's default (the page's
    # "Load all"); it never exceeds what is kept.
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    try:
        limit = int((qs.get('limit') or [PAGE_ROWS])[0])
    except (TypeError, ValueError, OverflowError):
        limit = PAGE_ROWS
    limit = PAGE_ROWS if limit < 1 else min(ATTACKER_CAP, limit)
    visible = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    st = _store_ro()
    intake = _intake_ro()
    # The edge feeds belong to the instance, not to a host: only the operator who
    # set them up sees what they queued.
    operator = is_admin and (not A._tenancy_enforced() or A._caller_is_superadmin())
    # How many Linux agents a ban "on every host" would reach, for the dialog.
    ban_hosts = sum(1 for v in visible.values()
                    if isinstance(v, dict) and not v.get('agentless') and A._device_os_family(v) == 'linux')
    # What the operator banned by hand and has not lifted, and what the list holds.
    bans = edge_blocklist.active_bans(st.get('edgeban'), int(time.time())) if operator else {}
    if operator:
        visible = dict(visible)
        for did, name in ip_intel.EDGE_DEVICES.items():
            visible[did] = {'name': name}
    blocks = st.get('blocks') if isinstance(st.get('blocks'), dict) else {}
    # Reputation-list hits a firewall's IDS saw (Spamhaus, Dshield, CINS...), from the hosts the
    # caller can see. Context beside an address; it is never evidence.
    listed = A.listed_for(A._load_ro(A.IPINTEL_SCAN_FILE) or {}, set(visible), int(time.time()))
    # What an address's ledger, its reports and its reasons say is made of every host that saw it, and the row is one for the whole
    # installation. A caller who does not read all the hosts is given what they collected themselves and nothing of the others.
    places = None if _reads_all_hosts() else set(visible)
    attackers = []
    for ip, a in (st.get('attackers') or {}).items():
        if not isinstance(a, dict):
            continue
        devs = {d: v for d, v in (a.get('devices') or {}).items() if d in visible}
        if not devs:
            continue
        v = a.get('verdict') or {}
        attackers.append({
            'ip': ip, 'first_seen': a.get('first_seen'), 'last_seen': a.get('last_seen'),
            'devices': [{'device_id': d, 'name': (visible[d] or {}).get('name') or d,
                         'count': x.get('count'), 'unit': x.get('unit'),
                         'not_blocked': x.get('not_blocked', '')}
                        for d, x in devs.items() if isinstance(x, dict)],
            'score': v.get('score'), 'reports': v.get('reports'),
            'country': v.get('country', ''), 'isp': v.get('isp', ''),
            'usage': v.get('usage', ''), 'providers': v.get('providers', {}),
            'checked_at': a.get('checked_at'), 'reported': a.get('reported', {}),
            'errors': _errors_view(a, places),
            'in_list': a.get('in_list') if operator else None,
            'ignored': bool(pol.get('ignore_nets') and ip_intel.in_any(ip, pol['ignore_nets'])),
            'edge_ban': ({'until': bans[edge_blocklist.canonical(ip)]}
                         if edge_blocklist.canonical(ip) in bans else None),
            'evidence': _evidence_view(a, places),
            'listed': _listed_view(listed.get(ip), visible),
            'report_log': _report_log_view(a, places),
        })
    attackers.sort(key=lambda r: int(r.get('last_seen') or 0), reverse=True)
    rows = []
    for dev_id, per in blocks.items():
        if dev_id not in visible or not isinstance(per, dict):
            continue
        for ip, b in per.items():
            if isinstance(b, dict):
                rows.append(dict(b, device_id=dev_id, ip=ip,
                                 name=(visible[dev_id] or {}).get('name') or dev_id))
    rows.sort(key=lambda r: int(r.get('at') or 0), reverse=True)
    budget = _budget_today(st.get('budget'), time.strftime('%Y-%m-%d', time.gmtime(int(time.time()))))   # today's, as the sweep reads it
    # The settings, the day's counts and the length of the queue are the installation's: its never-block list holds the operator's own
    # addresses, its Cloudflare account and list are named in it, and the counts are what its API keys have spent. The edge feeds, the list
    # and the request log above are the operator's for the same reason, so these follow them. What a tenant is told is the number of
    # addresses waiting from the hosts it can see.
    queue = intake.get('queue') if isinstance(intake.get('queue'), list) else []
    queued = len(queue) if operator else sum(1 for q in queue if isinstance(q, dict) and q.get('device_id') in visible)
    # The page is sent the most recent `limit` addresses (PAGE_ROWS unless it asked
    # for more). `attackers_total` says how many there are, so a list cut short says
    # so instead of looking complete.
    A.respond(200, {'ok': True, 'is_admin': is_admin, 'operator': bool(operator),
                    'settings': _settings_view(pol) if operator else {},
                    'attackers': attackers[:limit], 'attackers_total': len(attackers),
                    'blocks': rows,
                    'sensor_enabled': bool(pol.get('sensor_enabled')),
                    'appliance_enabled': bool(pol.get('appliance_enabled')),
                    'sensors': _sensor_rows(intake, visible),
                    'edge': A.edge_intel_status(st, pol) if operator else None,
                    'edge_list': A.edge_list_status(st, pol) if operator else None,
                    'requests': _request_lines(st, intake, {d: (v or {}).get('name') for d, v in visible.items()}) if operator else None,
                    'ban_hosts': ban_hosts,
                    'can_ignore': bool(operator),
                    'budget': budget if operator else {}, 'queued': queued})


def handle_ip_intel_settings():
    """POST /api/ip-intel/settings — admin, instance-wide. API keys are
    write-only: an empty value keeps the stored key, `clear_<provider>_key`
    removes it."""
    actor = A.require_admin_auth()
    if A._tenancy_enforced() and not A._caller_is_superadmin():
        A.respond(403, {'error': 'Instance settings are managed by the platform operator.'})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.IpIntelSettingsRequest)
    changed = []
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        pol = dict(cfg.get('ip_intel')) if isinstance(cfg.get('ip_intel'), dict) else {}
        for k in ('lookup_enabled', 'report_enabled', 'block_enabled', 'sensor_enabled', 'appliance_enabled',
                  'edge_enabled', 'edge_cf_events', 'edge_trap', 'edge_count_list_rules', 'edge_planted_decides',
                  'edge_bait_decides',
                  'edgelist_enabled', 'edgelist_own', 'edgelist_abuseipdb', 'edgelist_sniffcat',
                  'block_edge_hosts', 'block_confirmed', 'sensor_samples', 'report_samples'):
            if body.get(k) is not None:
                pol[k] = bool(body[k])
                changed.append(f'{k}={pol[k]}')
        for k, lo, hi in (('block_min_score', 1, 100), ('block_ttl_hours', 1, 24 * 90),
                          ('block_max_per_hour', 1, 1000), ('report_min_count', 1, 100000),
                          ('cache_hours', 1, 24 * 30), ('daily_lookup_budget', 0, 1000000),
                          ('daily_report_budget', 0, 1000000), ('edge_poll_minutes', 5, 1440),
                          ('edge_report_after', 1, 50), ('report_waf_after', 1, 50), ('report_listed_after', 0, 50), ('edgelist_own_score', 1, 100),
                          ('edgelist_own_days', 1, 365), ('edgelist_abuseipdb_conf', 25, 100),
                          ('edgelist_abuseipdb_limit', 100, 50000), ('edgelist_sniffcat_conf', 30, 100),
                          ('edgelist_sniffcat_limit', 10, 30000), ('edgelist_hours', 1, 168),
                          ('edgelist_max', 100, 500000)):
            if body.get(k) not in (None, ''):
                try:
                    pol[k] = max(lo, min(hi, int(body[k])))
                except (TypeError, ValueError, OverflowError):
                    A.respond(400, {'error': f'{k} must be a number'})
                changed.append(f'{k}={pol[k]}')
        for prov in ip_intel.PROVIDERS:
            for kind, hi in (('lookups', 1000000), ('reports', 1000000), ('downloads', 1000)):
                k = 'limit_%s_%s' % (prov, kind)
                if body.get(k) is None:
                    continue                          # not sent: left as it was
                if body[k] == '':
                    pol.pop(k, None)                  # blank: this service uses the general number again
                    changed.append(f'{k}=general')
                    continue
                try:
                    pol[k] = max(0, min(hi, int(body[k])))
                except (TypeError, ValueError, OverflowError):
                    A.respond(400, {'error': 'limit must be a number', 'field': k})   # a fixed sentence the dictionary translates
                changed.append(f'{k}={pol[k]}')
        if body.get('report_comment') is not None:
            text = ip_intel.clean_comment_template(body['report_comment'])
            if ip_intel.is_default_comment(text):
                pol.pop('report_comment', None)       # blank, or the default text, stores nothing
                changed.append('report_comment=default')
            else:
                bad = ip_intel.comment_template_error(text)
                if bad:
                    A.respond(400, {'error': bad})
                pol['report_comment'] = text
                changed.append('report_comment=custom')
        if body.get('sensor_paths') is not None:
            paths, bad = ip_intel.clean_sensor_paths(body['sensor_paths'])
            if bad:
                A.respond(400, {'error': bad})
            pol['sensor_paths'] = paths
            changed.append(f'sensor_paths={len(paths)}')
        if body.get('edge_account_id') is not None:
            acct = str(body['edge_account_id']).strip().lower()
            if acct and not ip_intel.clean_cf_ids([acct], 1)[0]:
                A.respond(400, {'error': 'The account id is 32 hex digits'})
            pol['edge_account_id'] = acct
            changed.append('edge_account_id=' + ('set' if acct else 'cleared'))
        if body.get('edge_zone_ids') is not None:
            ids, bad = ip_intel.clean_cf_ids(body['edge_zone_ids'])
            if bad:
                A.respond(400, {'error': bad})
            pol['edge_zone_ids'] = ids
            changed.append(f'edge_zone_ids={len(ids)}')
        if body.get('edge_workers') is not None:
            names, bad = ip_intel.clean_workers(body['edge_workers'])
            if bad:
                A.respond(400, {'error': bad})
            pol['edge_workers'] = names or list(ip_intel.DEFAULTS['edge_workers'])
            changed.append(f"edge_workers={len(pol['edge_workers'])}")
        if body.get('edgelist_name') is not None:
            nm = str(body['edgelist_name']).strip()
            if not edge_blocklist.valid_name(nm):
                A.respond(400, {'error': 'The list name may use lower-case letters, digits and underscores, '
                                         'and starts with a letter'})
            pol['edgelist_name'] = nm
            changed.append('edgelist_name=' + nm)
        if body.get('edgelist_always') is not None:
            entries, bad = edge_blocklist.clean_entries(body['edgelist_always'])
            if bad:
                A.respond(400, {'error': bad})
            pol['edgelist_always'] = entries
            changed.append(f'edgelist_always={len(entries)}')
        if body.get('never_block') is not None:
            raw = body['never_block']
            items = raw if isinstance(raw, list) else str(raw).replace(',', '\n').splitlines()
            nets = []
            for it in items[:500]:
                it = str(it).strip()
                if not it:
                    continue
                if not ip_intel.parse_cidrs([it]):
                    A.respond(400, {'error': f'Not an address or network: {it[:60]}'})
                nets.append(it)
            pol['never_block'] = nets
            changed.append(f'never_block={len(nets)}')
        if body.get('ignore_addresses') is not None:
            entries, bad = ip_intel.clean_ignore_addresses(body['ignore_addresses'])
            if bad:
                A.respond(400, {'error': bad})
            pol['ignore_addresses'] = entries
            changed.append(f'ignore_addresses={len(entries)}')
        if body.get('ignore_classes') is not None:
            ids, bad = ip_intel.clean_ignore_classes(body['ignore_classes'])
            if bad:
                A.respond(400, {'error': bad})
            pol['ignore_classes'] = ids
            changed.append(f'ignore_classes={len(ids)}')
        cfg['ip_intel'] = pol
        if body.get('clear_edge_token'):
            cfg.pop('edge_cloudflare_token', None)
            changed.append('edge_cloudflare_token=cleared')
        elif body.get('edge_cloudflare_token'):
            tok = str(body['edge_cloudflare_token']).strip()
            if not ip_intel.valid_cf_token(tok):
                A.respond(400, {'error': 'The Cloudflare API token has an unexpected format'})
            cfg['edge_cloudflare_token'] = tok
            changed.append('edge_cloudflare_token=set')
        # the token that can EDIT lists is a second secret, kept apart so the one
        # the feeds read with stays read-only
        if body.get('clear_edge_list_token'):
            cfg.pop('edge_list_token', None)
            changed.append('edge_list_token=cleared')
        elif body.get('edge_list_token'):
            tok = str(body['edge_list_token']).strip()
            if not ip_intel.valid_cf_token(tok):
                A.respond(400, {'error': 'The Cloudflare API token has an unexpected format'})
            cfg['edge_list_token'] = tok
            changed.append('edge_list_token=set')
        for prov in ip_intel.PROVIDERS:
            name = f'{prov}_api_key'
            if body.get(f'clear_{prov}_key'):
                cfg.pop(name, None)
                changed.append(f'{name}=cleared')
            elif body.get(name):
                key = str(body[name]).strip()
                if not ip_intel.valid_api_key(key):
                    A.respond(400, {'error': f'The {prov} API key has an unexpected format'})
                cfg[name] = key
                changed.append(f'{name}=set')
    A._invalidate_load_cache(A.CONFIG_FILE)
    A.audit_log(actor, 'ip_intel_settings', ' '.join(changed)[:500])
    A.respond(200, {'ok': True, 'settings': _settings_view(_policy())})


def handle_ip_intel_lookup():
    """POST /api/ip-intel/lookup {ip} — admin. Ask both services now: ignores
    the cache, spends today's budget."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    # The API keys and the daily budget are the instance's, configured by the
    # platform operator; a tenant admin spending them is spending someone
    # else's quota.
    if A._tenancy_enforced() and not A._caller_is_superadmin():
        A.respond(403, {'error': 'Lookups use the instance API keys and are run by the platform operator.'})
    body = A._read_valid(A.request_models.IpIntelLookupRequest)
    ip = ip_intel.parse_ip(body.get('ip'))
    if not ip or not ip_intel.is_public(ip):
        A.respond(400, {'error': 'Enter a public IP address'})
    pol = _policy()
    if not any(pol['keys'].values()):
        A.respond(409, {'error': 'Add an AbuseIPDB or SniffCat API key first'})
    now = int(time.time())
    today = time.strftime('%Y-%m-%d', time.gmtime(now))
    allowance, spent = _budget_left(_store_ro(), pol, today), {}
    verdict, errors = _fetch_verdict(ip, pol, allowance, spent)
    if not spent:
        A.respond(429, {'error': "Today's lookup budget is used up"})
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        _reqlog_flush(st)
        _add_spend(st, today, spent)
        att = (st.get('attackers') or {}).get(ip)
        if isinstance(att, dict):
            att['checked_at'] = now
            att['errors'] = errors
            if verdict:
                att['verdict'] = verdict
    A.audit_log(actor, 'ip_intel_lookup', f'ip={ip}')
    A.respond(200, {'ok': True, 'ip': ip, 'verdict': verdict or {}, 'errors': errors})


def _block_target():
    # Authenticate before reading the body or touching the device store, so an
    # anonymous caller cannot tell an existing device from a missing one by the
    # status code. The per-device permission check follows in the caller.
    A.require_auth()
    body = A._read_valid(A.request_models.IpIntelBlockRequest)
    dev_id = str(body.get('device_id') or '')
    ip = ip_intel.parse_ip(body.get('ip'))
    if not A._validate_id(dev_id) or not ip:
        A.respond(400, {'error': 'device_id and a valid ip are required'})
    A._scope_block_device(dev_id)
    return body, dev_id, ip


def handle_ip_intel_block():
    """POST /api/ip-intel/block {device_id, ip, hours?} — block an address on
    one host by hand. Needs the 'command' permission on that host, and the
    never-block rules apply exactly as they do to auto-block."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body, dev_id, ip = _block_target()
    actor = A.require_perm('command', [dev_id])
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict):
        A.respond(404, {'error': 'Host not found'})
    if dev.get('agentless') or A._device_os_family(dev) != 'linux':
        A.respond(409, {'error': 'Blocking is available on Linux agents only'})
    pol = _policy()
    why = ip_intel.never_block_reason(ip, _protected_networks(pol, A._load_ro(A.DEVICES_FILE) or {}))
    if why:
        A.respond(409, {'error': f'Not blocking {ip}: {why}'})
    try:
        hours = max(1, min(24 * 90, int(body.get('hours') or pol['block_ttl_hours'])))
    except (TypeError, ValueError, OverflowError):
        hours = int(pol['block_ttl_hours'])
    now = int(time.time())
    res = (A._queue_command_batch([dev_id], 'exec:' + ip_intel.block_command(ip), actor)
           or {}).get(dev_id) or {}
    if not res.get('ok'):
        A.respond(409, {'error': res.get('error') or 'The command was refused'})
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        st.setdefault('blocks', {}).setdefault(dev_id, {})[ip] = {
            'at': now, 'until': now + hours * 3600, 'by': actor, 'kind': 'manual'}
    A.audit_log(actor, 'ip_intel_block', f'device={dev_id} ip={ip} hours={hours} manual')
    A.respond(200, {'ok': True, 'approval_required': bool(res.get('approval_required'))})


def handle_ip_intel_unblock():
    """POST /api/ip-intel/unblock {device_id, ip} — lift a block now."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    _body, dev_id, ip = _block_target()
    actor = A.require_perm('command', [dev_id])
    res = (A._queue_command_batch([dev_id], 'exec:' + ip_intel.unblock_command(ip), actor)
           or {}).get(dev_id) or {}
    if not res.get('ok'):
        A.respond(409, {'error': res.get('error') or 'The command was refused'})
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        blocks = st.setdefault('blocks', {})
        per = blocks.get(dev_id) if isinstance(blocks.get(dev_id), dict) else {}
        per.pop(ip, None)
        if per:
            blocks[dev_id] = per
        else:
            blocks.pop(dev_id, None)
    A.audit_log(actor, 'ip_intel_unblock', f'device={dev_id} ip={ip} manual')
    A.respond(200, {'ok': True})


# ── clearing what is recorded ──────────────────────────────────────────────────

def _stale_addresses(atts, now, pol):
    """The addresses nobody has seen for ATTACKER_KEEP_DAYS (longer when the Edge
    blocklist is set to look further back, so the list never loses an address it still
    wants), and the leftovers of a clear once the day they were kept for has passed."""
    keep_s = max(ATTACKER_KEEP_DAYS, int(pol.get('edgelist_own_days') or 0)) * 86400
    gone = []
    for ip, att in (atts or {}).items():
        if not isinstance(att, dict):
            gone.append(ip)
        elif att.get('last_seen'):
            if now - int(att['last_seen']) > keep_s:
                gone.append(ip)
        elif set(att) <= {'reported', 'retry'} and _reported_marker(att, now) is None:
            gone.append(ip)           # what a clear left, and the day it was kept for is over
    return gone


def _forget_stale(atts, now, pol):
    """Drop _stale_addresses from `atts`. Returns how many went."""
    gone = _stale_addresses(atts, now, pol)
    for ip in gone:
        atts.pop(ip, None)
    return len(gone)


def _held_by_blocklist(st, pol, now):
    """The addresses the Edge blocklist takes from this table at its next sync, as
    the list spells them. A clear keeps what the list reads of them (see
    _cleared_marker): the list is kept equal to its sources, so forgetting one here
    would drop it from Cloudflare at the next sync without anybody having asked for
    that. Empty while the list cannot write or its "found by RemotePower" source is
    off, when nothing depends on the table."""
    if not (_edge_ban_ready(pol) and pol.get('edgelist_own')):
        return set()
    return set(edge_blocklist.own_candidates(
        st.get('attackers'), now, pol['edgelist_own_score'], pol['edgelist_own_days']))


def _reported_marker(att, now):
    """What a cleared address keeps: when each service was last told about it, for
    the day a report holds, and any wait a service asked for. Without it the next
    sighting reports the same address again. None when there is nothing to keep."""
    told = {p: int(t) for p, t in (att.get('reported') or {}).items()
            if isinstance(t, (int, float)) and now - int(t) < REPORT_EVERY_S}
    wait = {p: int(t) for p, t in (att.get('retry') or {}).items()
            if isinstance(t, (int, float)) and int(t) > now}
    out = {}
    if told:
        out['reported'] = told
    if wait:
        out['retry'] = wait
    return out or None


def _cleared_marker(att, told, listed):
    """What a cleared address leaves behind, or None for nothing at all.

    `told` is _reported_marker(att, now), which every address keeps.

    An address the Edge blocklist takes from this table (`listed`) keeps what the list
    reads of it as well, and nothing more: its last sighting, its score and the services
    it was reported to (see edge_blocklist.own_candidates). The row names no host, so the
    page, the Data Explorer and the counts do not show it, and the next sync makes the
    same list. It goes with the table's other old rows (_stale_addresses). `in_list` is
    the sync's own stamp, which the next sync sets again; keeping it stops a row that
    comes back before then from saying the list does not hold it."""
    out = dict(told or {})
    if not listed:
        return out or None
    reported = att.get('reported') if isinstance(att.get('reported'), dict) else {}
    kept = {p: int(t) for p, t in reported.items()
            if isinstance(t, (int, float)) and not isinstance(t, bool)}
    if kept:
        out['reported'] = kept          # all of it: own_candidates asks only whether it is empty
    out['last_seen'] = int(att.get('last_seen') or 0)
    verdict = att.get('verdict') if isinstance(att.get('verdict'), dict) else {}
    if verdict.get('score') is not None:
        out['verdict'] = {'score': int(verdict['score'])}
    if att.get('in_list'):
        out['in_list'] = att['in_list']
    return out


def handle_ip_intel_clear():
    """POST /api/ip-intel/clear — administrator. Forget the addresses Threat Intel
    has recorded, and what is waiting to be looked up, for the hosts the caller can
    see; the platform operator also clears what the edge feeds queued.

    Left alone, because each has an effect or a lifetime of its own:
      * blocks on hosts and bans at the edge: each expires by itself and has its own
        Unblock or Unban, and the sweep lifts what runs out;
      * settings and keys, the day's lookup and report counts, the feeds' place in
        their logs and each host's sensor status;
      * the scans a firewall has only half counted (ip_intel_scan.json): thirty
        minutes of soft state that expires by itself.

    Every address leaves the table, and two things stay of an address, as a row with
    no host (see _cleared_marker):
      * when it was last reported, for a day (see _reported_marker);
      * what the Edge blocklist reads of it, for an address the list takes from this
        table (see _held_by_blocklist). Such an address used to stay in the table
        whole, and on an instance with the list on that was nearly every row, so the
        button cleared almost nothing.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    A._read_valid(A.request_models.IpIntelClearRequest)
    pol = _policy()
    # The platform operator (an administrator on a single-organisation install)
    # clears everything. A tenant's administrator clears the sightings from the
    # hosts that tenant can see, and an address stays while another tenant's host
    # still saw it.
    operator = _is_operator()
    mine = set(A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {}))
    now = int(time.time())
    cleared = remembered = kept_listed = queue_cleared = 0
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        atts = st.get('attackers') if isinstance(st.get('attackers'), dict) else {}
        held = _held_by_blocklist(st, pol, now)
        for ip in list(atts):
            att = atts[ip]
            if not isinstance(att, dict):
                atts.pop(ip, None)
                continue
            devs = att.get('devices') if isinstance(att.get('devices'), dict) else {}
            theirs = list(devs) if operator else [d for d in devs if d in mine]
            if not operator and not theirs:
                continue                  # none of this caller's hosts saw it
            had_sightings = bool(devs)
            if had_sightings:
                cleared += 1
            rep = att.get('ev_reported') if isinstance(att.get('ev_reported'), dict) else {}
            for d in theirs:
                devs.pop(d, None)
                # what these hosts added to the address's evidence goes with their sightings (the sum keeps their share, which
                # only the operator reads, until the day's ledger is started over)
                for parts in (att.get('ev_by'), rep.get('by')):
                    if isinstance(parts, dict):
                        parts.pop(d, None)
            if devs:
                continue                  # another tenant's host saw it too: it stays for them
            listed = bool(held) and edge_blocklist.canonical(ip) in held
            told = _reported_marker(att, now)
            marker = _cleared_marker(att, told, listed)
            if marker:
                atts[ip] = marker
                if told:
                    remembered += 1
                if listed and had_sightings:
                    kept_listed += 1
            else:
                atts.pop(ip, None)
        st['attackers'] = atts
    # The queue is in the intake, a document of its own, so this is a second step.
    # A clear that stops between the two is finished by clearing again.
    with A._LockedUpdate(A.IPINTEL_INTAKE_FILE) as intake:
        _intake_adopt(intake)
        queue = intake['queue']
        if operator:
            keep = []
        else:
            keep = [q for q in queue if not (isinstance(q, dict) and q.get('device_id') in mine)]
        queue_cleared = len(queue) - len(keep)
        intake['queue'] = keep
    A.audit_log(actor, 'ip_intel_clear',
                f'cleared={cleared} kept_listed={kept_listed} remembered={remembered} '
                f'queue={queue_cleared}'[:300])
    A.respond(200, {'ok': True, 'cleared': cleared, 'kept_listed': kept_listed,
                    'remembered': remembered, 'queue': queue_cleared})


def handle_ip_intel_ignore():
    """POST /api/ip-intel/ignore {ip} — the platform operator. Add one address to
    the list of addresses that are never reported. The list is the instance's (the
    same one Settings edits), so on a multi-tenant install a tenant's administrator
    cannot change it, as they cannot change the provider settings.

    It only ever does LESS in public: an ignored address is still recorded, looked
    up and, when blocking is on, blocked. Taking an address back off the list is
    done in Settings, where the whole list is."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    if A._tenancy_enforced() and not A._caller_is_superadmin():
        A.respond(403, {'error': 'The ignore list is managed by the platform operator.'})
    body = A._read_valid(A.request_models.IpIntelIgnoreRequest)
    ip = ip_intel.parse_ip(body.get('ip'))
    if not ip:
        A.respond(400, {'error': 'Enter an IP address'})
    if not ip_intel.is_public(ip):
        # never looked up, reported or blocked anyway, so an entry could never
        # match; the Settings list stays free to name private networks
        A.respond(400, {'error': 'Not a public address'})
    already = False
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        pol = dict(cfg.get('ip_intel')) if isinstance(cfg.get('ip_intel'), dict) else {}
        cur = [str(x) for x in (pol.get('ignore_addresses') or [])] \
            if isinstance(pol.get('ignore_addresses'), list) else []
        if ip_intel.in_any(ip, ip_intel.parse_cidrs(cur)):
            already = True
        else:
            if len(cur) >= ip_intel.IGNORE_MAX:
                A.respond(409, {'error': f'The list holds {ip_intel.IGNORE_MAX} entries already'})
            cur.append(ip)
            pol['ignore_addresses'] = cur
            cfg['ip_intel'] = pol
    A._invalidate_load_cache(A.CONFIG_FILE)
    if not already:
        A.audit_log(actor, 'ip_intel_ignore', f'ip={ip}')
    A.respond(200, {'ok': True, 'already': already, 'ip': ip})
