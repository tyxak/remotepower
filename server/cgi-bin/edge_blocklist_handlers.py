"""RemotePower — Edge blocklist: keep a Cloudflare IP list up to date from the sources the operator picks

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

What this module does that the edge feeds do not: it WRITES, to the operator's
Cloudflare account, and what it writes blocks traffic wherever a rule uses the
list. So it is off until asked for, it needs its own token (the feeds' token only
reads), it leaves a list it did not create alone until the operator says "take it
over", it shows what it would change before it changes it, and it will not empty
or halve a list on its own.
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

import edge_blocklist
import edge_evidence
import ip_intel

SYNC_MIN_S = 3600             # a scheduled sync never runs more often than hourly
PENDING_RECHECK_S = 300       # a bulk operation Cloudflare has not finished is looked at this often
PENDING_GIVE_UP_S = 3600      # and given up on after this long
OP_WAIT_S = 20                # how long one request waits for Cloudflare's bulk operation
READ_BUDGET_S = 60            # and the most it spends paging through the list's items
OP_STEP_S = 2
SAMPLE = 20                   # added and removed entries shown on the page

_FETCH = {
    'abuseipdb': (edge_blocklist.abuseipdb_request, edge_blocklist.abuseipdb_parse, 'AbuseIPDB'),
    'sniffcat': (edge_blocklist.sniffcat_request, edge_blocklist.sniffcat_parse, 'SniffCat'),
}


def _mono():
    return time.monotonic()


def _store_ro():
    return (A._load_ro(A.IPINTEL_FILE) or {}) if A.backend_exists(A.IPINTEL_FILE) else {}


def _el(st):
    e = (st or {}).get('edgelist')
    return e if isinstance(e, dict) else {}


def _why(res):
    """One sentence from a parser's refusal. Cloudflare's own is already cut and cleaned."""
    if res.get('list_limit'):
        return ("Cloudflare's list limit is reached. Delete a list you no longer use, or give the "
                "name of an existing list.")
    if res.get('busy'):
        return 'Cloudflare is still working on the last change.'
    if res.get('auth'):
        return 'The token cannot edit lists: ' + str(res.get('error') or 'refused')
    return str(res.get('error') or 'Cloudflare did not answer.')[:200]


# ── the sources ────────────────────────────────────────────────────────────────

def _gather(pol, el, now):
    """(got, cache, calls, failed). `got` is {source: {'ips', 'from', 'at'}}. A
    blacklist is downloaded at most CALLS_PER_DAY times a day and read from its
    last copy in between and when a download fails, for up to STALE_SOURCE_S; a
    source with neither is `failed`, and a sync that has a failed source is held."""
    hours = int(pol['edgelist_hours'])
    day = time.strftime('%Y-%m-%d', time.gmtime(now))
    prior = el.get('calls') if isinstance(el.get('calls'), dict) else {}
    calls = dict(prior) if prior.get('day') == day else {'day': day}
    cache = {k: dict(v) for k, v in (el.get('src') or {}).items() if isinstance(v, dict)}
    got, failed = {}, {}
    for name, (build, parse, label) in _FETCH.items():
        if not pol.get('edgelist_' + name):
            continue
        key = pol['keys'].get(name)
        if not key:
            failed[name] = f'{label} has no API key saved'
            continue
        have = cache.get(name) or {}
        ips = [x for x in str(have.get('ips') or '').split('\n') if x]
        age = now - int(have.get('at') or 0)
        if ips and age < hours * 3600:
            got[name] = {'ips': ips, 'from': 'copy', 'at': int(have.get('at') or 0)}
            continue
        err = ''
        if int(calls.get(name) or 0) < edge_blocklist.CALLS_PER_DAY:
            calls[name] = int(calls.get(name) or 0) + 1
            res = parse(*A._ip_intel_http(build(
                key, pol[f'edgelist_{name}_conf'], pol[f'edgelist_{name}_limit'])))
            if res.get('ok'):
                cache[name] = {'at': now, 'n': len(res['ips']), 'ips': '\n'.join(res['ips'])}
                got[name] = {'ips': res['ips'], 'from': 'download', 'at': now}
                continue
            err = str(res.get('error') or 'did not answer')
        else:
            err = f'{label} downloads are used up for today'
        if ips and age <= edge_blocklist.STALE_SOURCE_S:
            got[name] = {'ips': ips, 'from': 'copy', 'at': int(have.get('at') or 0), 'error': err}
        else:
            failed[name] = err
    return got, cache, calls, failed


def _protected(pol):
    devices = A._load_ro(A.DEVICES_FILE) or {}
    return A.ip_intel_handlers_mod._protected_networks(pol, devices)


# ── one sync ───────────────────────────────────────────────────────────────────

def _items_now(token, acct, list_id):
    """(entries, error, complete): everything in the list, a page at a time.
    `complete` is False when the pages ran out before the list did; the caller then
    neither trusts the entries as the whole list nor skips a write because they
    match."""
    out, cursor, complete = [], '', False
    deadline = _mono() + READ_BUDGET_S
    for _ in range(edge_blocklist.MAX_PAGES):
        r = edge_blocklist.parse_items(*A._ip_intel_http(
            edge_blocklist.items_request(token, acct, list_id, cursor)))
        if not r['ok']:
            return None, _why(r), False
        out += r['ips']
        cursor = r['cursor']
        if not cursor or not r['ips']:
            complete = True
            break
        if _mono() > deadline:        # a slow Cloudflare must not hold the sweep for minutes
            break
    return out, '', complete


def _wait(token, acct, op):
    """'completed', 'failed' (with a sentence) or 'pending', after at most OP_WAIT_S."""
    waited = 0
    while True:
        r = edge_blocklist.parse_operation(*A._ip_intel_http(
            edge_blocklist.operation_request(token, acct, op)))
        if r.get('ok') and r['state'] in ('completed', 'failed'):
            return r['state'], r.get('error') or ''
        if not r.get('ok') and not r.get('busy'):
            return 'pending', ''
        if waited >= OP_WAIT_S:
            return 'pending', ''
        time.sleep(OP_STEP_S)
        waited += OP_STEP_S


def _enabled_sources(pol):
    out = []
    if pol.get('edgelist_always'):
        out.append('always')
    if pol.get('edgelist_own'):
        out.append('own')
    for name in ('abuseipdb', 'sniffcat'):
        if pol.get('edgelist_' + name):
            out.append(name)
    return out


def _sync(pol, now, mode='apply', force=False):
    """One sync. `mode` is 'preview' (nothing is written to Cloudflare), 'apply'
    (the scheduled one: it will not touch a list it does not manage) or 'adopt'
    (the operator said to take the list over). `force` lets a sync past the guard
    against emptying or halving the list.

    Returns a dict. `state` is one of: preview, ok, held, needs_adopt, needs_setup,
    pending, error. Nothing is recorded here; the caller does that, with `_cache`
    and `_calls` (the copies of the sources and the day's download count)."""
    out = {'mode': mode, 'at': now, 'force': bool(force)}
    token = pol.get('edge_list_token') or ''
    acct = pol.get('edge_account_id') or ''
    name = pol.get('edgelist_name') or ''
    store = _store_ro()
    el = _el(store)
    if not token:
        return dict(out, state='needs_setup', why='Add a Cloudflare token that can edit lists.')
    if not edge_evidence.valid_id(acct):
        return dict(out, state='needs_setup', why='Add the Cloudflare account id under Edge sources.')
    if not edge_blocklist.valid_name(name):
        return dict(out, state='needs_setup',
                    why='The list name may use lower-case letters, digits and underscores.')

    res = edge_blocklist.parse_lists(*A._ip_intel_http(edge_blocklist.lists_request(token, acct)))
    if not res['ok']:
        return dict(out, state='error', why=_why(res), auth=bool(res.get('auth')))
    lists = res['lists']
    mine = next((x for x in lists if x['name'] == name), None)
    if mine and mine['kind'] != 'ip':
        return dict(out, state='needs_setup', why='A list with this name exists and is not an IP list.')
    capacity = edge_blocklist.capacity_for(pol['edgelist_max'], lists, mine['id'] if mine else None)
    mine_managed = bool(mine) and edge_blocklist.managed(mine['description'])
    out['capacity'] = capacity
    out['list'] = {'name': name, 'id': mine['id'] if mine else '', 'exists': bool(mine),
                   'items': mine['num_items'] if mine else 0, 'managed': mine_managed,
                   'description': (mine['description'] if mine else '')[:200]}
    needs_adopt = bool(mine) and not mine_managed
    if needs_adopt and mode == 'apply':
        return dict(out, state='needs_adopt',
                    why='A list with this name exists and RemotePower did not create it.')

    got, cache, calls, failed = _gather(pol, el, now)
    out['_cache'], out['_calls'] = cache, calls
    own = []
    if pol.get('edgelist_own'):
        own = edge_blocklist.own_candidates(
            store.get('attackers'), now, pol['edgelist_own_score'], pol['edgelist_own_days'])
    # the operator's own entries: the ones typed into the settings and the bans made
    # by hand, which expire; both are theirs, so both sit first
    bans = edge_blocklist.active_bans(store.get('edgeban'), now)
    always = list(pol.get('edgelist_always') or [])
    always += [b for b in bans if b not in always]
    built = edge_blocklist.build(
        always, own,
        (got.get('abuseipdb') or {}).get('ips') or [], (got.get('sniffcat') or {}).get('ips') or [],
        capacity, _protected(pol))
    out['_listed'] = [e for e, _s in built['items']]
    out.update(kept=built['kept'], offered=built['offered'], trimmed=built['trimmed'],
               dropped=built['dropped'], size=len(built['items']), bans=len(bans),
               sources={n: {'from': g.get('from'), 'at': g.get('at'), 'n': len(g.get('ips') or []),
                            'error': g.get('error') or ''} for n, g in got.items()},
               failed=failed)

    current, complete = [], True
    if mine:
        current, err, complete = _items_now(token, acct, mine['id'])
        if current is None:
            return dict(out, state='error', why=err)
    # the size the guard measures against is the larger of what was read and what
    # Cloudflare says the list holds, so a read that was cut short cannot make a
    # big list look small
    size_now = max(len(current), mine['num_items'] if mine else 0)
    added, removed = edge_blocklist.diff(current, [e for e, _s in built['items']])
    out.update(added=len(added), removed=len(removed), current=size_now,
               added_sample=added[:SAMPLE], removed_sample=removed[:SAMPLE])

    held = ''
    if failed:
        held = 'A source did not answer and has no recent copy.'
    elif not got and not (always or own) and size_now:
        held = 'No source is switched on, so nothing would be left in the list.'
    else:
        held = edge_blocklist.hold_reason(size_now, len(built['items']))
    if held and not force:
        return dict(out, state='held', why=held, can_force=True, needs_adopt=needs_adopt)
    if mode == 'preview':
        return dict(out, state='preview', needs_adopt=needs_adopt, held=held)

    desc = edge_blocklist.description(A.SERVER_VERSION, _enabled_sources(pol))
    list_id = mine['id'] if mine else ''
    if not mine:
        r = edge_blocklist.parse_created(*A._ip_intel_http(
            edge_blocklist.create_request(token, acct, name, desc)))
        if not r['ok']:
            return dict(out, state='error', why=_why(r))
        list_id = r['id']
        out['created'] = True
    elif mine['description'] != desc:
        r = edge_blocklist.parse_done(*A._ip_intel_http(
            edge_blocklist.describe_request(token, acct, list_id, desc)))
        if not r['ok']:
            return dict(out, state='error', why=_why(r))
    out['list']['id'] = list_id

    if not (added or removed) and mine and complete:
        return dict(out, state='ok', changed=False)
    if not built['items'] and not mine:
        return dict(out, state='ok', changed=False)
    r = edge_blocklist.parse_replace(*A._ip_intel_http(
        edge_blocklist.replace_request(token, acct, list_id, built['items'])))
    if not r['ok']:
        if r.get('busy'):
            return dict(out, state='pending', why=_why(r))
        return dict(out, state='error', why=_why(r))
    state, why = _wait(token, acct, r['operation_id'])
    if state == 'failed':
        return dict(out, state='error', why=why or 'Cloudflare could not apply the change.')
    if state == 'pending':
        return dict(out, state='pending', changed=True, op={'id': r['operation_id'], 'at': now},
                    why='Cloudflare is still applying the change.')
    return dict(out, state='ok', changed=True)


def _pending(pol, el, now):
    """(state, why) for the bulk operation a previous sync left running, or None
    when there is none. 'pending' means leave it alone."""
    op = el.get('op')
    if not isinstance(op, dict) or not edge_evidence.valid_id(op.get('id')):
        return None
    token, acct = pol.get('edge_list_token') or '', pol.get('edge_account_id') or ''
    if not token or not edge_evidence.valid_id(acct):
        return None
    r = edge_blocklist.parse_operation(*A._ip_intel_http(
        edge_blocklist.operation_request(token, acct, op['id'])))
    if not r.get('ok'):
        return ('pending', '')
    if r['state'] in ('pending', 'running'):
        if now - int(op.get('at') or 0) > PENDING_GIVE_UP_S:
            return ('error', 'Cloudflare did not finish the change in an hour.')
        return ('pending', '')
    if r['state'] == 'failed':
        return ('error', r.get('error') or 'Cloudflare could not apply the change.')
    return ('ok', '')


# ── recording ──────────────────────────────────────────────────────────────────

_KEEP = ('mode', 'at', 'state', 'why', 'list', 'capacity', 'kept', 'offered', 'trimmed', 'dropped', 'size',
         'sources', 'failed', 'added', 'removed', 'current', 'added_sample', 'removed_sample', 'changed',
         'created', 'can_force', 'needs_adopt', 'op', 'held', 'auth', 'bans')


LIST_ALERT_AFTER_ERRORS = 2     # failed syncs in a row before anyone is told


def _health_event(el, res):
    """(event, payload) when this result moves the list between healthy and
    needing a person, else None. A held sync and a missing adopt wait for an
    operator, so they are announced at once; a failed one needs two in a row,
    which is what separates a bad hour at Cloudflare from a revoked token."""
    state = res.get('state')
    h = el.get('health') if isinstance(el.get('health'), dict) else {}
    name = str((res.get('list') or {}).get('name') or
               ((el.get('last') or {}).get('list') or {}).get('name') or 'Cloudflare IP list')[:64]
    if state == 'ok' or (state == 'pending' and res.get('op')):
        el['health'] = {}
        return ('edge_list_synced', {'label': name}) if h.get('alerted') else None
    if state not in ('error', 'held', 'needs_adopt'):
        return None
    h['bad'] = int(h.get('bad') or 0) + 1
    el['health'] = h
    due = state != 'error' or h['bad'] >= LIST_ALERT_AFTER_ERRORS
    if due and not h.get('alerted'):
        h['alerted'] = True
        return ('edge_list_held', {'label': name, 'detail': str(
            res.get('why') or {'held': 'a sync is held and waits for you',
                               'needs_adopt': 'the list is not RemotePower\'s yet',
                               'error': 'Cloudflare could not apply the change'}[state])[:200]})
    return None


def _record(res, now, attempted=True):
    announce = None
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        el = st.get('edgelist') if isinstance(st.get('edgelist'), dict) else {}
        if attempted:
            el['attempt'] = now
        if '_cache' in res:
            el['src'] = res['_cache']
            el['calls'] = res['_calls']
        # a preview shows what a sync would do and is not what happened: it is kept
        # apart so the last real result is not overwritten by looking
        keep = {k: res[k] for k in _KEEP if k in res}
        if res.get('mode') == 'preview':
            el['preview'] = keep
        else:
            el['last'] = keep
            if res.get('op'):
                el['op'] = res['op']
            elif res.get('state') in ('ok', 'error', 'held', 'needs_adopt', 'needs_setup'):
                el.pop('op', None)
        st['edgelist'] = el
        if res.get('mode') in ('apply', 'adopt'):
            _prune_bans(st, now)
            # The list now holds (or, with a change in flight, will hold) exactly what
            # was built. A sync that was held, refused or only looked changed nothing,
            # so it leaves the markers alone.
            applied = res.get('state') == 'ok' or (res.get('state') == 'pending' and res.get('op'))
            if applied and res.get('_listed') is not None:
                _mark_listed(st, res['_listed'], now)
        if res.get('mode') in ('apply', 'adopt'):
            announce = _health_event(st['edgelist'], res)
    if announce:
        try:
            A.fire_webhook(*announce)
        except Exception:   # nosec B110 — telling the operator must not undo the record
            pass


def _prune_bans(st, now):
    bans = st.get('edgeban')
    if isinstance(bans, dict):
        keep = {ip: b for ip, b in bans.items() if isinstance(b, dict) and int(b.get('until') or 0) > now}
        if len(keep) != len(bans):
            st['edgeban'] = keep


def _mark_listed(st, listed, now):
    """Stamp each recorded attacker that is in the list, and clear the stamp from the
    ones that are not, so the Threat Intel table can say which addresses the list
    holds. Matching is by address, or by network for a range."""
    exact, nets = edge_blocklist.membership(listed)
    for ip, att in (st.get('attackers') or {}).items():
        if isinstance(att, dict):
            if edge_blocklist.is_listed(ip, exact, nets):
                att['in_list'] = now
            else:
                att.pop('in_list', None)


def _audit(actor, res):
    if res.get('mode') == 'preview':
        A.audit_log(actor, 'edge_list_preview',
                    f"list={(res.get('list') or {}).get('name', '')} state={res.get('state')} "
                    f"added={res.get('added', 0)} removed={res.get('removed', 0)}"[:300])
        return
    if res.get('state') in ('ok', 'pending') and res.get('changed'):
        A.audit_log(actor, 'edge_list_sync',
                    f"list={(res.get('list') or {}).get('name', '')} mode={res.get('mode')} "
                    f"size={res.get('size', 0)} added={res.get('added', 0)} removed={res.get('removed', 0)} "
                    f"state={res.get('state')}"[:300])
    elif res.get('state') in ('error', 'held', 'needs_adopt'):
        A.audit_log(actor, 'edge_list_sync',
                    f"list={(res.get('list') or {}).get('name', '')} state={res.get('state')} "
                    f"why={str(res.get('why') or '')[:160]}"[:300])


# ── the sweep ──────────────────────────────────────────────────────────────────

def _due(store, el, now, interval):
    """True when the last attempt is older than `interval`, or a ban made by hand has
    run out since it: an expired ban must leave the list when it expires, not at the
    next scheduled sync hours later."""
    attempt = int(el.get('attempt') or 0)
    if now - attempt >= interval:
        return True
    bans = store.get('edgeban') if isinstance(store.get('edgeban'), dict) else {}
    return any(isinstance(b, dict) and attempt < int(b.get('until') or 0) <= now for b in bans.values())


def run_edge_blocklist_if_due():
    """Cadence sweep: make the Cloudflare list match what the sources say, when the
    operator has switched it on and given it a token that can edit lists. Claims
    the attempt under the lock, then does the network work with no lock held."""
    pol = A.ip_intel_policy()
    if not (pol.get('edgelist_enabled') and pol.get('edge_list_token')):
        return
    now = int(time.time())
    store = _store_ro()
    el = _el(store)
    every = max(SYNC_MIN_S, int(pol['edgelist_hours']) * 3600)
    waiting = bool(el.get('op'))
    if not _due(store, el, now, PENDING_RECHECK_S if waiting else every):
        return
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        cur = st.get('edgelist') if isinstance(st.get('edgelist'), dict) else {}
        if not _due(st, cur, now, PENDING_RECHECK_S if cur.get('op') else every):
            return                        # another worker took this one
        cur['attempt'] = now
        st['edgelist'] = cur
    try:
        pend = _pending(pol, el, now)
        if pend and pend[0] == 'pending':
            return
        if pend and pend[0] == 'error':
            res = {'mode': 'apply', 'at': now, 'state': 'error', 'why': pend[1]}
        else:
            res = _sync(pol, now, 'apply')
    except Exception as exc:              # one bad answer must not stop the other sweeps
        res = {'mode': 'apply', 'at': now, 'state': 'error', 'why': type(exc).__name__}
    _record(res, now)
    _audit('ip-intel', res)


# ── what the page reads ────────────────────────────────────────────────────────

def edge_list_status(st, pol):
    """The blocklist's state for the Threat Intel page: whether it is on, what the
    last real sync and the last preview said, and how old each source copy is. The
    copies themselves are never sent; only counts and times."""
    el = _el(st)
    src = {}
    for name, v in (el.get('src') or {}).items():
        if isinstance(v, dict):
            src[name] = {'at': int(v.get('at') or 0), 'n': int(v.get('n') or 0)}
    calls = el.get('calls') if isinstance(el.get('calls'), dict) else {}
    return {
        'enabled': bool(pol.get('edgelist_enabled')),
        'token_set': bool(pol.get('edge_list_token')),
        'attempt': int(el.get('attempt') or 0),
        'last': el.get('last') if isinstance(el.get('last'), dict) else {},
        'preview': el.get('preview') if isinstance(el.get('preview'), dict) else {},
        'pending': bool(el.get('op')),
        'bans': len(edge_blocklist.active_bans(
            (st or {}).get('edgeban'), int(time.time()))),
        'src': src,
        'calls': {k: v for k, v in calls.items() if k in ('day', 'abuseipdb', 'sniffcat')},
        'per_day': edge_blocklist.CALLS_PER_DAY,
    }


# ── endpoints ──────────────────────────────────────────────────────────────────

def _operator():
    actor = A.require_admin_auth()
    if A._tenancy_enforced() and not A._caller_is_superadmin():
        A.respond(403, {'error': 'Instance settings are managed by the platform operator.'})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    return actor


def _public(res):
    return {k: v for k, v in res.items() if not k.startswith('_')}


def handle_edge_list_preview():
    """POST /api/ip-intel/edge-list/preview — admin. What a sync would do, without
    writing anything to Cloudflare. It reads the list and may download a source,
    which counts towards the day's downloads."""
    actor = _operator()
    A._read_valid(A.request_models.EdgeListActionRequest)
    pol = A.ip_intel_policy()
    now = int(time.time())
    res = _sync(pol, now, 'preview')
    _record(res, now, attempted=False)
    _audit(actor, res)
    A.respond(200, {'ok': True, 'result': _public(res)})


def handle_edge_list_sync():
    """POST /api/ip-intel/edge-list/sync {adopt, force} — admin. Sync now.
    `adopt` takes over a list RemotePower did not create; `force` goes ahead of
    the guard against emptying or halving the list."""
    actor = _operator()
    body = A._read_valid(A.request_models.EdgeListActionRequest)
    pol = A.ip_intel_policy()
    now = int(time.time())
    pend = _pending(pol, _el(_store_ro()), now)
    if pend and pend[0] == 'pending':
        A.respond(409, {'error': 'Cloudflare is still applying the last change. Try again in a minute.'})
    mode = 'adopt' if body.get('adopt') else 'apply'
    res = _sync(pol, now, mode, force=bool(body.get('force')))
    _record(res, now)
    _audit(actor, res)
    A.respond(200, {'ok': True, 'result': _public(res)})


# ── a ban by hand ──────────────────────────────────────────────────────────────
#
# One address, banned in the two places RemotePower can act: at the edge, which is
# the Cloudflare list this module keeps, and on hosts, which is a firewall rule
# queued to their agents (the same command a block uses). The two are separate
# switches because they stop different traffic: a host rule only drops connections
# that reach the host from the address itself, and a visitor proxied by Cloudflare
# arrives from Cloudflare's addresses, so only the edge ban stops those.
#
# Nothing here is new power. The host half is `handle_ip_intel_block` for many hosts
# at once, with its guards (the 'command' permission on each host, Linux agents only,
# the never-block rules, four-eyes approval); the edge half writes the list the
# operator already switched on, so it is operator-only and does nothing while the
# Edge blocklist is off.

BAN_HOURS_MAX = 24 * 90
BAN_MAX_HOSTS = 500
BAN_SHOWN = 20                # failures listed in an answer
BAN_CHUNK = 20                # hosts queued per step
BAN_BUDGET_S = 25             # a request stops starting new steps after this long


def _caller_is_operator():
    """An administrator, and on a multi-tenant install only the platform operator:
    the list is the instance's, not a tenant's."""
    role = A.verify_token(A.get_token_from_request())[1]
    return bool(A._resolve_role(role).get('admin')) and (
        not A._tenancy_enforced() or A._caller_is_superadmin())


def _edge_not_ready(pol):
    """Why a ban at the edge cannot take effect, or ''."""
    if not pol.get('edgelist_enabled'):
        return 'The Edge blocklist is off. Turn it on under Security → Threat Intel → Edge blocklist first.'
    if not pol.get('edge_list_token'):
        return 'The Edge blocklist has no token that can edit lists yet.'
    if not edge_evidence.valid_id(pol.get('edge_account_id')):
        return 'The Edge blocklist needs the Cloudflare account id under Edge sources.'
    return ''


def _ban_request():
    # Authenticate before anything about the body or the fleet is read, as the block
    # endpoint does, so a missing device and a forbidden one look the same.
    A.require_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.IpIntelBanRequest)
    ip = ip_intel.parse_ip(body.get('ip'))
    if not ip:
        A.respond(400, {'error': 'A valid ip is required'})
    return body, ip


def _which_hosts(raw):
    """'all', 'seen', a list of device ids, or '' for none."""
    if isinstance(raw, str):
        raw = raw.strip().lower()
        return raw if raw in ('all', 'seen') else ''
    if isinstance(raw, list):
        return [x for x in raw[:BAN_MAX_HOSTS] if isinstance(x, str) and A._validate_id(x)]
    return ''


def _host_targets(which, ip, store, visible):
    """([device ids], [ids skipped]). Only Linux agents the caller can see: `visible`
    already folds in the role's scope and the tenant."""
    agents = {d for d, v in visible.items()
              if isinstance(v, dict) and not v.get('agentless') and A._device_os_family(v) == 'linux'}
    if which == 'all':
        return sorted(agents)[:BAN_MAX_HOSTS], []
    if which == 'seen':
        seen = ((store.get('attackers') or {}).get(ip) or {}).get('devices') or {}
        return [d for d in seen if d in agents][:BAN_MAX_HOSTS], []
    if isinstance(which, list):
        return [d for d in which if d in agents], [d for d in which if d not in agents]
    return [], []


def _shown(results, visible):
    """The failures of a batch as [{'device_id', 'name', 'error'}], capped."""
    out = []
    for dev_id, r in results.items():
        if not r.get('ok'):
            out.append({'device_id': dev_id, 'name': (visible.get(dev_id) or {}).get('name') or dev_id,
                        'error': str(r.get('error') or 'refused')[:160]})
    return out[:BAN_SHOWN]


def _edge_state():
    """What the sync that just ran said, for the answer."""
    A._invalidate_load_cache(A.IPINTEL_FILE)
    last = _el(_store_ro()).get('last')
    last = last if isinstance(last, dict) else {}
    return {'state': last.get('state') or 'waiting', 'why': str(last.get('why') or '')[:200]}


def _sync_now():
    """Run the scheduled sync now, with the same claim and guards, so the answer can
    say whether the address is in the list. A failure here is the sync's to record."""
    A._invalidate_load_cache(A.IPINTEL_FILE)
    try:
        A.run_edge_blocklist_if_due()
    except Exception:  # nosec B110
        pass            # recorded by the sweep itself; the ban stays stored


def handle_ip_intel_ban():
    """POST /api/ip-intel/ban {ip, edge, hosts, hours} — ban an address by hand.

    `edge` adds it to the Cloudflare list for `hours` (operator only, and only
    while the Edge blocklist is on). `hosts` is 'all' (every Linux agent the caller
    can see), 'seen' (the hosts that saw it) or a list of device ids; each gets the
    block command, the same one a block queues. The never-block rules apply to
    both, and so does four-eyes approval on the host half."""
    body, ip = _ban_request()
    want_edge = bool(body.get('edge'))
    which = _which_hosts(body.get('hosts'))
    if not want_edge and not which:
        A.respond(400, {'error': 'Choose where to ban it: at the edge, on hosts, or both'})
    pol = A.ip_intel_policy()
    actor = None
    if want_edge:
        actor = A.require_admin_auth()
        if not _caller_is_operator():
            A.respond(403, {'error': 'Banning at the edge is for the platform operator.'})
    devices = A._load_ro(A.DEVICES_FILE) or {}
    why = ip_intel.never_block_reason(ip, A.ip_intel_handlers_mod._protected_networks(pol, devices))
    if why:
        A.respond(409, {'error': f'Not banning {ip}: {why}'})
    if want_edge:
        gap = _edge_not_ready(pol)
        if gap:
            A.respond(409, {'error': gap})
    visible = A._scope_filter_devices(devices)
    store = _store_ro()
    ids, skipped = _host_targets(which, ip, store, visible) if which else ([], [])
    if which:
        actor = A.require_perm('command', ids or None)
    try:
        hours = max(1, min(BAN_HOURS_MAX, int(body.get('hours') or pol['block_ttl_hours'])))
    except (TypeError, ValueError, OverflowError):
        hours = int(pol['block_ttl_hours'])
    now = int(time.time())
    until = now + hours * 3600

    blocks = store.get('blocks') if isinstance(store.get('blocks'), dict) else {}
    held = [d for d in ids if int(((blocks.get(d) or {}).get(ip) or {}).get('until') or 0) > now]
    todo = [d for d in ids if d not in held]

    # The record goes in BEFORE the commands, and what was not queued is taken out
    # after. A request that dies half way (a slow webhook on every host is enough
    # over a big fleet) then leaves a record for a rule that may exist, which the
    # expiry sweep lifts, and never a rule on a host that nothing remembers.
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        for d in held + todo:
            st.setdefault('blocks', {}).setdefault(d, {})[ip] = {
                'at': now, 'until': until, 'by': actor, 'kind': 'manual'}
        if want_edge:
            st.setdefault('edgeban', {})[ip] = {'at': now, 'until': until, 'by': actor}
            el = st.get('edgelist') if isinstance(st.get('edgelist'), dict) else {}
            el['attempt'] = 0           # due now: the ban goes in the list at once
            st['edgelist'] = el
    results, deferred = {}, []
    if todo:
        cmd = 'exec:' + ip_intel.block_command(ip)
        started = _mono()
        for i in range(0, len(todo), BAN_CHUNK):
            if i and _mono() - started > BAN_BUDGET_S:
                deferred = todo[i:]
                break
            results.update(A._queue_command_batch(todo[i:i + BAN_CHUNK], cmd, actor) or {})
    done = [d for d in todo if (results.get(d) or {}).get('ok')]
    approval = [d for d in done if results[d].get('approval_required')]
    undone = [d for d in todo if d not in done]
    if undone:
        with A._LockedUpdate(A.IPINTEL_FILE) as st:
            for d in undone:
                per = (st.get('blocks') or {}).get(d)
                if isinstance(per, dict):
                    per.pop(ip, None)
                    if not per:
                        st['blocks'].pop(d, None)
    A.audit_log(actor, 'ip_intel_ban',
                f"ip={ip} edge={int(want_edge)} hosts={len(done) + len(held)} approval={len(approval)} "
                f"deferred={len(deferred)} hours={hours}"[:300])

    out = {'ok': True, 'ip': ip, 'until': until, 'edge': None, 'hosts': None}
    if which:
        out['hosts'] = {'queued': len(done) - len(approval), 'approval': len(approval), 'extended': len(held),
                        'failed': _shown(results, visible), 'skipped': len(skipped),
                        'deferred': len(deferred), 'matched': len(ids)}
    if want_edge:
        _sync_now()
        out['edge'] = _edge_state()
    A.respond(200, out)


def handle_ip_intel_unban():
    """POST /api/ip-intel/unban {ip, edge, hosts} — lift what a ban set. `edge`
    takes the manual ban out of the list's next build (an address another source
    names stays in); `hosts` is 'all' (every host that has a block on this address
    and the caller can see), 'seen' or a list, and each gets the unblock command."""
    body, ip = _ban_request()
    want_edge = bool(body.get('edge'))
    which = _which_hosts(body.get('hosts'))
    if not want_edge and not which:
        A.respond(400, {'error': 'Choose what to lift: the edge ban, the host blocks, or both'})
    actor = None
    if want_edge:
        actor = A.require_admin_auth()
        if not _caller_is_operator():
            A.respond(403, {'error': 'Lifting an edge ban is for the platform operator.'})
    visible = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    store = _store_ro()
    blocks = store.get('blocks') if isinstance(store.get('blocks'), dict) else {}
    ids = []
    if which:
        blocked_on = [d for d, per in blocks.items()
                      if isinstance(per, dict) and ip in per and d in visible]
        if which == 'all':
            ids = blocked_on
        elif which == 'seen':
            seen = ((store.get('attackers') or {}).get(ip) or {}).get('devices') or {}
            ids = [d for d in blocked_on if d in seen]
        else:
            ids = [d for d in which if d in blocked_on]
        actor = A.require_perm('command', ids or None)
    results = {}
    if ids:
        results = A._queue_command_batch(ids, 'exec:' + ip_intel.unblock_command(ip), actor) or {}
    done = [d for d in ids if (results.get(d) or {}).get('ok')]
    removed = False
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        for d in done:
            per = (st.get('blocks') or {}).get(d)
            if isinstance(per, dict):
                per.pop(ip, None)
                if not per:
                    st['blocks'].pop(d, None)
        if want_edge and isinstance(st.get('edgeban'), dict) and ip in st['edgeban']:
            st['edgeban'].pop(ip, None)
            removed = True
            el = st.get('edgelist') if isinstance(st.get('edgelist'), dict) else {}
            el['attempt'] = 0
            st['edgelist'] = el
    A.audit_log(actor, 'ip_intel_unban', f"ip={ip} edge={int(removed)} hosts={len(done)}"[:300])
    out = {'ok': True, 'ip': ip, 'edge': None, 'hosts': None}
    if which:
        out['hosts'] = {'lifted': len(done), 'failed': _shown(results, visible)}
    if want_edge:
        out['edge'] = {'removed': removed}
        if removed:
            _sync_now()
            out['edge'].update(_edge_state())
    A.respond(200, out)
