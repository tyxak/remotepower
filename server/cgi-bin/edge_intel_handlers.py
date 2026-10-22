"""RemotePower — Edge feeds for Threat intel: Cloudflare firewall events and the honeypot Worker's log

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

import edge_evidence
import ip_intel

POLL_MIN_S = 300              # never poll Cloudflare more often than this
ZONES_TTL_S = 6 * 3600        # the zone list is kept this long
RULES_TTL_S = 3600            # so are a zone's custom rules
LOOKBACK_S = 6 * 3600         # a read never goes back further, like the host sensor: older is not evidence
LAG_S = 90                    # events take a moment to show up in analytics
RULE_ZONES = 12               # zones whose rules are kept
RULES_PER_ZONE = 60
RULES_BUDGET_S = 20           # time one poll spends reading rules; the rest wait for the next
FIREWALL_BUDGET_S = 45        # and reading events; a window half read does not move the cursor
MODE_PROBE_S = 6 * 3600       # a zone read as single events asks for the grouped view again this often
TEST_ZONES = 12               # zones Test connection reads
FEEDS = (('cf', 'edge:cloudflare'), ('trap', 'edge:trap'))
FEED_LABELS = {'cf': 'Cloudflare firewall events', 'trap': 'Honeypot Worker log'}
FEED_FAILING = ('no_access', 'error', 'refused')   # nothing could be read
FEED_ALERT_AFTER = 2                               # failed reads in a row before anyone is told
_FEED_WORDS = {'no_access': 'the token was refused', 'error': 'the read failed',
               'refused': 'Cloudflare refused the dataset'}


def _store_ro():
    return (A._load_ro(A.IPINTEL_FILE) or {}) if A.backend_exists(A.IPINTEL_FILE) else {}


def _fail(res):
    """A feed's state from a parser's refusal. 'refused' is Cloudflare refusing a
    dataset to a zone: it words that about the zone, and a token without Analytics
    and a plan without the dataset both produce it, so it is not called a
    permission. 'no_access' is the token being refused, and 'error' is anything
    else. The sentence is the provider's, already cut and cleaned."""
    if res.get('dataset'):
        return {'state': 'refused', 'error': str(res.get('error') or '')[:200]}
    return {'state': 'no_access' if res.get('auth') else 'error',
            'error': str(res.get('error') or '')[:200]}


def _zone_error(z, res):
    """The provider's sentence, with the zone it was about."""
    return ('%s: %s' % (z.get('name') or str(z.get('id'))[:8], res.get('error') or ''))[:200]


def _read_zone(token, zone_id, since, until, prefer_events, limit=None):
    """(result, mode) for one zone's firewall events: the grouped dataset first,
    and the zone's single events when Cloudflare refuses the grouped one, which a
    Free plan does. A zone already known to need the events asks for them first,
    and asks for the grouped view again now and then, in case its plan changed.
    One zone to a request, so a zone Cloudflare refuses cannot blank the others."""
    def grouped():
        return edge_evidence.parse_firewall(*A._ip_intel_http(edge_evidence.firewall_request(
            token, [zone_id], since, until, limit or edge_evidence.MAX_ROWS)))

    def events():
        n = limit or edge_evidence.MAX_EVENTS
        return edge_evidence.parse_events(*A._ip_intel_http(edge_evidence.events_request(
            token, [zone_id], since, until, n)), limit=n)

    if prefer_events:
        res = events()
        if res['ok'] or not res.get('dataset'):
            return res, 'events'
        alt = grouped()
        return (alt, 'groups') if alt['ok'] else (res, 'events')
    res = grouped()
    if res['ok'] or not res.get('dataset'):
        return res, 'groups'
    return events(), 'events'


# ── the sweep ──────────────────────────────────────────────────────────────────

def _zones(token, pol, edge, now):
    """(zones, refusal): the zones to read, from the operator's list or from the
    token, with the listing kept for a few hours."""
    cached = [z for z in (edge.get('zones') or []) if isinstance(z, dict)]
    names = {z.get('id'): z.get('name', '') for z in cached}
    ids = [z for z in (pol.get('edge_zone_ids') or []) if edge_evidence.valid_id(z)]
    if ids:
        return [{'id': i, 'name': names.get(i, '')} for i in ids[:edge_evidence.MAX_ZONES]], None
    if cached and now - int(edge.get('zones_at') or 0) < ZONES_TTL_S:
        return cached, None
    res = edge_evidence.parse_zones(*A._ip_intel_http(
        edge_evidence.zones_request(token, pol.get('edge_account_id') or '')))
    if not res['ok']:
        return cached, res
    return res['zones'], None


def _poll_cf(token, pol, edge, now):
    """What Cloudflare refused in the window since the last read, as evidence."""
    zones, refused = _zones(token, pol, edge, now)
    if not zones:
        if refused:
            return dict(_fail(refused), at=now)
        return {'state': 'no_zones', 'at': now}
    since = max(int(edge.get('cf_to') or 0), now - LOOKBACK_S)
    until = now - LAG_S
    prev_cf = edge.get('cf') if isinstance(edge.get('cf'), dict) else {}
    prev_modes = prev_cf.get('modes') if isinstance(prev_cf.get('modes'), dict) else {}
    out = {'state': 'ok', 'at': now, 'zones': [{'name': z.get('name') or z['id'][:8]} for z in zones],
           'zone_list': zones, 'zones_at': now if refused is None else int(edge.get('zones_at') or 0),
           'modes': dict(prev_modes)}
    if prev_cf.get('mode'):
        out['mode'] = prev_cf['mode']
    # Rules: read once an hour per zone, so a rule that also blocks an IP list is
    # known and the operator's own description can choose a class. A zone whose
    # rules cannot be read is still counted; the page says so.
    rules, cache, unreadable = {}, {}, False
    old = edge.get('rules') if isinstance(edge.get('rules'), dict) else {}
    started = time.monotonic()
    for z in zones[:RULE_ZONES]:
        got = old.get(z['id']) if isinstance(old.get(z['id']), dict) else None
        if got and now - int(got.get('at') or 0) < RULES_TTL_S:
            rules[z['id']] = got.get('r') or {}
            cache[z['id']] = got
            continue
        if time.monotonic() - started > RULES_BUDGET_S:
            unreadable = True             # a slow answer must not hold the poll up
            if got:
                rules[z['id']] = got.get('r') or {}
                cache[z['id']] = got
            continue
        res = edge_evidence.parse_rules(*A._ip_intel_http(edge_evidence.rules_request(token, z['id'])))
        if res['ok']:
            r = dict(list(res['rules'].items())[:RULES_PER_ZONE])
            rules[z['id']] = r
            cache[z['id']] = {'at': now, 'r': r}
        else:
            unreadable = True
            if got:
                rules[z['id']] = got.get('r') or {}
                cache[z['id']] = got
    out['rules'] = cache
    out['rules_unreadable'] = unreadable
    if until - since < 60:
        out['skipped'] = True
        return out
    # One zone to a request. Cloudflare answers a dataset a zone's plan does not
    # have with an error that names the zone and fails the whole request, and the
    # grouped dataset is exactly what a Free plan lacks: so each zone is asked for
    # the grouped view and, when that is refused, for its single events.
    rows, truncated, refusals, modes, used = [], False, [], {}, set()
    started = time.monotonic()
    for z in zones:
        if time.monotonic() - started > FIREWALL_BUDGET_S:
            # a slow answer must not hold the poll up, and a window half read must
            # not move the cursor
            return dict(out, state='error', error='too many zones to read in one pass')
        known = prev_modes.get(z['id']) if isinstance(prev_modes.get(z['id']), dict) else {}
        prefer = known.get('m') == 'events' and now - int(known.get('p') or 0) < MODE_PROBE_S
        res, mode = _read_zone(token, z['id'], since, until, prefer)
        modes[z['id']] = {'m': mode,
                          'p': int(known.get('p') or now) if (prefer and mode == 'events') else now}
        if res['ok']:
            rows += res['rows']
            truncated = truncated or bool(res['truncated'])
            used.add(mode)
        elif res.get('dataset') or res.get('auth'):
            refusals.append((z, res))
        else:
            return dict(out, **_fail(res))      # Cloudflare failed: the cursor stays
    out['modes'] = modes
    if not used:
        z, res = refusals[0]
        fail = _fail(res)
        fail['error'] = _zone_error(z, res)
        return dict(out, **fail)
    events, stats = edge_evidence.cf_events(
        rows, rules, now, since, until,
        include_carriers=bool(pol.get('edge_count_list_rules')))
    out.update(events=events, rows=stats['rows'], kept=stats['kept'], ignored=stats['ignored'],
               truncated=truncated, to=until,
               mode='groups' if used == {'groups'} else 'events' if used == {'events'} else 'mixed')
    if refusals:
        # some zones were read and these were not: the page says which, and the
        # window still moves on, because a zone Cloudflare refuses stays refused
        out['refused'] = len(refusals)
        out['error'] = '; '.join(_zone_error(z, r) for z, r in refusals)[:200]
    return out


def _poll_trap(token, pol, edge, now):
    """What the honeypot Worker logged since the last read, as evidence."""
    acct = pol.get('edge_account_id') or ''
    if not edge_evidence.valid_id(acct):
        return {'state': 'no_account', 'at': now}
    workers = [w for w in (pol.get('edge_workers') or []) if edge_evidence.valid_worker(w)]
    workers = workers[:edge_evidence.MAX_WORKERS] or list(ip_intel.DEFAULTS['edge_workers'])
    since = max(int(edge.get('trap_to') or 0), now - LOOKBACK_S)
    until = now - 5
    if until - since < 30:
        return {'state': 'ok', 'at': now, 'skipped': True, 'workers': workers}
    hits, truncated = [], False
    for w in workers:
        res = edge_evidence.parse_trap(*A._ip_intel_http(
            edge_evidence.trap_request(token, acct, w, since * 1000, until * 1000)))
        if not res['ok']:
            return dict(_fail(res), at=now, workers=workers)
        hits += res['hits']
        truncated = truncated or res['truncated']
    events, stats = edge_evidence.trap_events(
        hits, now, decided_tokens=edge_evidence.PLANTED_TOKENS if pol.get('edge_planted_decides') else ())
    return {'state': 'ok', 'at': now, 'events': events, 'hits': stats['hits'], 'kept': stats['kept'],
            'ignored': stats['ignored'], 'truncated': truncated, 'to': until, 'workers': workers}


def _safely(fn, token, pol, edge, now):
    try:
        return fn(token, pol, edge, now)
    except Exception as exc:          # one feed's failure must not stop the other
        return {'state': 'error', 'at': now, 'error': type(exc).__name__}


def run_edge_intel_if_due():
    """Cadence sweep: read Cloudflare's firewall events and the honeypot's log
    and queue what they say, like a host's sensor does. Three phases, so no lock
    is held across a network call: claim the poll, read, then queue the evidence
    and move the cursors in ONE transaction (a crash cannot replay a window)."""
    pol = A.ip_intel_policy()
    token = pol.get('edge_token') or ''
    if not (pol.get('edge_enabled') and token):
        return
    now = int(time.time())
    every = max(POLL_MIN_S, int(pol.get('edge_poll_minutes') or 10) * 60)
    if now - int((_store_ro().get('edge') or {}).get('polled') or 0) < every:
        return
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        edge = st.get('edge') if isinstance(st.get('edge'), dict) else {}
        if now - int(edge.get('polled') or 0) < every:
            return                        # another worker took this poll
        edge['polled'] = now
        st['edge'] = edge
        prev = dict(edge)
    # Each feed's place in its log is kept with the queue it feeds (the intake), not
    # in the table of addresses.
    places = A._intake_ro().get('cursors')
    places = places if isinstance(places, dict) else {}
    for feed, _dev in FEEDS:
        prev[feed + '_to'] = int(places.get(feed) or 0)

    got = {}
    if pol.get('edge_cf_events'):
        got['cf'] = _safely(_poll_cf, token, pol, prev, now)
    if pol.get('edge_trap'):
        got['trap'] = _safely(_poll_trap, token, pol, prev, now)

    # The evidence and the feeds' places in their logs go in ONE transaction, in the
    # intake: a crash cannot replay a window that was queued or skip one that was not.
    with A._LockedUpdate(A.IPINTEL_INTAKE_FILE) as intake:
        A._intake_adopt(intake)
        for feed, dev in FEEDS:
            r = got.get(feed)
            if r is None:
                continue
            events = r.pop('events', None) or []
            if events:
                A._note_evidence_into(intake, dev, events, None, now)
            if r.get('state') == 'ok' and r.get('to'):
                intake['cursors'][feed] = int(r['to'])

    announce = []                         # (event, payload), fired after the lock is released
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        edge = st.get('edge') if isinstance(st.get('edge'), dict) else {}
        health = edge.get('health') if isinstance(edge.get('health'), dict) else {}
        for feed, _dev in FEEDS:
            r = got.get(feed)
            h = health.get(feed) if isinstance(health.get(feed), dict) else {}
            if r is None or r.get('state') not in FEED_FAILING:
                # Not failing (healthy, switched off, or not set up): an alert the
                # operator was sent is closed, and the streak starts over.
                if h.get('alerted'):
                    announce.append(('edge_feed_recovered', {'label': FEED_LABELS[feed]}))
                h = {}
            else:
                h['fails'] = int(h.get('fails') or 0) + 1
                if h['fails'] >= FEED_ALERT_AFTER and not h.get('alerted'):
                    h['alerted'] = True
                    why = _FEED_WORDS.get(r.get('state'), 'it could not be read')
                    sentence = str(r.get('error') or '')[:120]
                    announce.append(('edge_feed_down', {
                        'label': FEED_LABELS[feed],
                        'detail': (why + (': ' + sentence if sentence else ''))[:200]}))
            health[feed] = h
            if r is None:
                # Switched off: say so, rather than keep showing the last read as
                # though it were still being made.
                edge[feed] = {'state': 'off', 'at': now}
                continue
            if feed == 'cf':
                if r.get('zone_list') is not None:
                    edge['zones'] = r.pop('zone_list')[:edge_evidence.MAX_ZONES]
                    edge['zones_at'] = r.pop('zones_at', now)
                if 'rules' in r:
                    edge['rules'] = r.pop('rules')
            r.pop('zone_list', None)
            r.pop('zones_at', None)
            r.pop('to', None)
            edge[feed] = r
        edge['health'] = health
        edge['at'] = now
        st['edge'] = edge
    for event, payload in announce:
        try:
            A.fire_webhook(event, payload)
        except Exception:   # nosec B110 — telling the operator must not stop the poll
            pass


# ── what the page reads ────────────────────────────────────────────────────────

_FEED_KEYS = ('state', 'at', 'rows', 'hits', 'kept', 'ignored', 'truncated', 'error',
              'rules_unreadable', 'skipped', 'zones', 'workers', 'mode', 'refused')


def edge_intel_status(st, pol):
    """The edge feeds' state for the Threat intel page: whether they are on, when
    each was last read, how much it held and what was set aside and why. Only
    fixed words and numbers; the one free-text field is the provider's own error
    sentence, which the caller has already cut and cleaned."""
    e = st.get('edge') if isinstance(st.get('edge'), dict) else {}

    def feed(name):
        f = e.get(name) if isinstance(e.get(name), dict) else {}
        return {k: f[k] for k in _FEED_KEYS if k in f}
    return {'enabled': bool(pol.get('edge_enabled')), 'token_set': bool(pol.get('edge_token')),
            'polled': e.get('polled'), 'cf': feed('cf'), 'trap': feed('trap')}


def _check(res, **extra):
    if res.get('ok'):
        return dict({'state': 'ok'}, **extra)
    return _fail(res)


def handle_ip_intel_edge_test():
    """POST /api/ip-intel/edge-test {token?, account_id?} — admin. Try each thing
    the feeds need, one at a time, with the stored token or the one typed, so a
    missing permission shows as exactly that. Nothing is queued and nothing is
    saved."""
    actor = A.require_admin_auth()
    if A._tenancy_enforced() and not A._caller_is_superadmin():
        A.respond(403, {'error': 'Instance settings are managed by the platform operator.'})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.IpIntelEdgeTestRequest)
    pol = A.ip_intel_policy()
    token = str(body.get('token') or '').strip() or pol.get('edge_token') or ''
    if not ip_intel.valid_cf_token(token):
        A.respond(409, {'error': 'Add a Cloudflare API token first'})
    acct = str(body.get('account_id') or '').strip().lower() or pol.get('edge_account_id') or ''
    if acct and not edge_evidence.valid_id(acct):
        A.respond(400, {'error': 'The account id is 32 hex digits'})
    now = int(time.time())
    checks = {}
    res = edge_evidence.parse_zones(*A._ip_intel_http(edge_evidence.zones_request(token, acct)))
    zones = res.get('zones') or []
    checks['zones'] = _check(res, n=len(zones), names=[z['name'] for z in zones][:12])
    ids = [z for z in (pol.get('edge_zone_ids') or []) if edge_evidence.valid_id(z)] \
        or [z['id'] for z in zones]
    if ids:
        # Each zone on its own, as the poll reads them: the answer names the
        # zones Cloudflare refuses and says how the others were read.
        names = {z['id']: z['name'] for z in zones}
        modes, refusals = set(), []
        for zid in ids[:TEST_ZONES]:
            res, mode = _read_zone(token, zid, now - 900, now - LAG_S, False, limit=1)
            if res.get('ok'):
                modes.add(mode)
            elif res.get('dataset') or res.get('auth'):
                refusals.append(({'id': zid, 'name': names.get(zid, '')}, res))
            else:
                refusals.append(({'id': zid, 'name': names.get(zid, '')}, res))
                break
        if refusals:
            fail = _fail(refusals[0][1])
            fail['error'] = '; '.join(_zone_error(z, r) for z, r in refusals)[:200]
            checks['firewall'] = fail
        else:
            checks['firewall'] = {'state': 'ok', 'mode': (
                'groups' if modes == {'groups'} else 'events' if modes == {'events'} else 'mixed')}
        res = edge_evidence.parse_rules(*A._ip_intel_http(edge_evidence.rules_request(token, ids[0])))
        rows = [{'id': rid[:8], 'd': r['d'], 'c': r['c'], 'k': r['k']}
                for rid, r in list((res.get('rules') or {}).items())[:12]]
        checks['rules'] = _check(res, rules=rows)
    else:
        checks['firewall'] = checks['rules'] = {'state': 'skipped', 'error': 'no zones'}
    worker = (pol.get('edge_workers') or ip_intel.DEFAULTS['edge_workers'])[0]
    if edge_evidence.valid_id(acct):
        res = edge_evidence.parse_trap(*A._ip_intel_http(
            edge_evidence.trap_request(token, acct, worker, (now - 900) * 1000, now * 1000, 1)))
        checks['trap'] = _check(res, worker=worker)
    else:
        checks['trap'] = {'state': 'skipped', 'error': 'no account id'}
    A.audit_log(actor, 'ip_intel_edge_test',
                ' '.join(f"{k}={v.get('state')}" for k, v in checks.items())[:300])
    A.respond(200, {'ok': True, 'checks': checks})
