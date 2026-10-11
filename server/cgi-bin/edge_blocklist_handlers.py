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
OP_STEP_S = 2
SAMPLE = 20                   # added and removed entries shown on the page

_FETCH = {
    'abuseipdb': (edge_blocklist.abuseipdb_request, edge_blocklist.abuseipdb_parse, 'AbuseIPDB'),
    'sniffcat': (edge_blocklist.sniffcat_request, edge_blocklist.sniffcat_parse, 'SniffCat'),
}


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
    el = _el(_store_ro())
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
            _store_ro().get('attackers'), now, pol['edgelist_own_score'], pol['edgelist_own_days'])
    built = edge_blocklist.build(
        pol.get('edgelist_always') or [], own,
        (got.get('abuseipdb') or {}).get('ips') or [], (got.get('sniffcat') or {}).get('ips') or [],
        capacity, _protected(pol))
    out.update(kept=built['kept'], offered=built['offered'], trimmed=built['trimmed'],
               dropped=built['dropped'], size=len(built['items']),
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
    elif not got and not (pol.get('edgelist_always') or own) and size_now:
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
         'created', 'can_force', 'needs_adopt', 'op', 'held', 'auth')


def _record(res, now, attempted=True):
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

def run_edge_blocklist_if_due():
    """Cadence sweep: make the Cloudflare list match what the sources say, when the
    operator has switched it on and given it a token that can edit lists. Claims
    the attempt under the lock, then does the network work with no lock held."""
    pol = A.ip_intel_policy()
    if not (pol.get('edgelist_enabled') and pol.get('edge_list_token')):
        return
    now = int(time.time())
    el = _el(_store_ro())
    every = max(SYNC_MIN_S, int(pol['edgelist_hours']) * 3600)
    waiting = bool(el.get('op'))
    if now - int(el.get('attempt') or 0) < (PENDING_RECHECK_S if waiting else every):
        return
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        cur = st.get('edgelist') if isinstance(st.get('edgelist'), dict) else {}
        if now - int(cur.get('attempt') or 0) < (PENDING_RECHECK_S if cur.get('op') else every):
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
    """The blocklist's state for the Threat intel page: whether it is on, what the
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
