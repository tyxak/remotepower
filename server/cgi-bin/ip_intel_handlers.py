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
import time
import urllib.error
import urllib.parse
import urllib.request

import ip_intel
import threat_evidence

QUEUE_CAP = 500            # pending addresses kept between sweeps
ATTACKER_CAP = 5000        # addresses remembered
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
    return pol


def _any_enabled(pol):
    return bool(pol.get('lookup_enabled') or pol.get('report_enabled')
                or pol.get('block_enabled'))


def ip_intel_policy():
    """The operator's policy with the API keys resolved. Read-only."""
    return _policy()


# ── the heartbeat-side hook ────────────────────────────────────────────────────

def ip_intel_note_attack(dev_id, unit, ip, count, window_s):
    """Queue a brute-force source for the sweep. Cheap and silent: a disabled
    feature, a private address or a hostname returns at once."""
    try:
        pol = _policy()
        if not _any_enabled(pol):
            return
        ip = ip_intel.parse_ip(ip)
        if not ip or not ip_intel.is_public(ip) or threat_evidence.infra_reason(ip):
            return
        now = int(time.time())
        with A._LockedUpdate(A.IPINTEL_FILE) as st:
            q = st.get('queue') if isinstance(st.get('queue'), list) else []
            q.append({'ip': ip, 'device_id': dev_id, 'unit': str(unit)[:64],
                      'count': int(count or 0), 'window_s': int(window_s or 0),
                      'at': now})
            st['queue'] = q[-QUEUE_CAP:]
    except Exception:  # nosec B110
        # Never let enrichment break brute-force detection.
        pass


# ── the threat sensor's side of the queue ──────────────────────────────────────

SENSOR_EVENTS_PER_HOUR = 3000       # accepted from one host in an hour
SENSOR_STATUS_KEEP_S = 30 * 86400   # a host that has not reported for a month is forgotten


def _queue_priority(item):
    """How much an entry deserves to stay when the queue is full: an address a
    ban engine already decided on, then the others by how much they did."""
    ev = item.get('evidence') if isinstance(item, dict) else None
    if isinstance(ev, dict):
        return (1_000_000 if threat_evidence.confirmed_by(ev) else 0) + threat_evidence.hostile_count(ev)
    return 500_000 + int((item or {}).get('count') or 0)      # the brute-force counter's own


def _trim_queue(q):
    """The queue at QUEUE_CAP entries, keeping the ones that matter and the
    original order. Plain "keep the newest" let a flood of one-hit addresses push
    out an address that had been banned a minute earlier."""
    if len(q) <= QUEUE_CAP:
        return q
    keep = sorted(range(len(q)), key=lambda i: (-_queue_priority(q[i]), -i))[:QUEUE_CAP]
    return [q[i] for i in sorted(keep)]


def ip_intel_note_evidence(dev_id, events, status=None, now=None):
    """Queue what a host's logs said about each address and record the host's
    sensor status, under one lock. `events` are threat_evidence summaries that
    have already been validated. An address already waiting for this host has the
    new evidence added to its entry, so a minute-by-minute attack is one entry,
    not sixty. Returns {'queued': n, 'throttled': n}."""
    now = int(now or time.time())
    status = status if isinstance(status, dict) else {}
    queued = throttled = 0
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        sensors = st.get('sensors') if isinstance(st.get('sensors'), dict) else {}
        rec = sensors.get(dev_id) if isinstance(sensors.get(dev_id), dict) else {}
        hour = now // 3600
        used = int((rec.get('hour') or {}).get('n') or 0) if (rec.get('hour') or {}).get('h') == hour else 0
        q = st.get('queue') if isinstance(st.get('queue'), list) else []
        index = {(x.get('ip'), x.get('device_id')): i for i, x in enumerate(q)
                 if isinstance(x, dict) and isinstance(x.get('evidence'), dict)}
        for ev in events:
            if used >= SENSOR_EVENTS_PER_HOUR:
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
                q.append({'ip': ev['ip'], 'device_id': dev_id, 'unit': 'threat-sensor',
                          'count': threat_evidence.hostile_count(ev),
                          'window_s': threat_evidence.window_seconds(ev), 'at': now, 'evidence': ev})
                index[key] = len(q) - 1
        st['queue'] = _trim_queue(q)
        sensors[dev_id] = {
            'at': now, 'sources': list(status.get('sources') or []),
            'events': queued, 'throttled': throttled,
            'dropped': int(status.get('dropped') or 0),
            'ignored': dict(status.get('ignored') or {}),
            'hour': {'h': hour, 'n': used},
        }
        for d in [d for d, r in sensors.items()
                  if isinstance(r, dict) and now - int(r.get('at') or 0) > SENSOR_STATUS_KEEP_S]:
            sensors.pop(d, None)
        st['sensors'] = sensors
    return {'queued': queued, 'throttled': throttled}


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

def _ip_intel_http(req):
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
    try:
        with opener.open(r, timeout=8) as resp:  # nosec B310  # nosemgrep: dynamic-urllib-use-detected -- fixed https provider bases in ip_intel.py
            raw = resp.read(262144)
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

def _budget_left(st, pol, today):
    """{provider: lookups still allowed today} from the stored counters."""
    b = st.get('budget') if isinstance(st.get('budget'), dict) else {}
    if b.get('day') != today:
        b = {'day': today}
    cap = int(pol.get('daily_lookup_budget') or 0)
    return {p: max(0, cap - int(b.get(p, 0))) for p in ip_intel.PROVIDERS}


def _report_budget_left(st, pol, today):
    """{provider: reports still allowed today}. Reports are counted under
    `report:<provider>` in the same daily record as lookups."""
    b = st.get('budget') if isinstance(st.get('budget'), dict) else {}
    if b.get('day') != today:
        b = {'day': today}
    cap = int(pol.get('daily_report_budget') or 0)
    return {p: max(0, cap - int(b.get('report:' + p, 0))) for p in ip_intel.PROVIDERS}


def _add_spend(st, today, spent):
    b = st.get('budget') if isinstance(st.get('budget'), dict) else {}
    if b.get('day') != today:
        b = {'day': today}
    for p, n in spent.items():
        b[p] = int(b.get(p, 0)) + n
    st['budget'] = b


def _fetch_verdict(ip, pol, allowance, spent):
    """Ask every provider that has a key and allowance left. Network only:
    always called with no lock held. Returns (verdict or None, {provider: error})."""
    results = {}
    for prov in ip_intel.PROVIDERS:
        key = pol['keys'].get(prov)
        if not key or allowance.get(prov, 0) <= 0:
            continue
        allowance[prov] -= 1
        spent[prov] = spent.get(prov, 0) + 1
        build, parse = ip_intel.CHECK[prov]
        status, body = A._ip_intel_http(build(ip, key))
        results[prov] = parse(status, body)
    errors = {p: r.get('error') for p, r in results.items() if not r.get('ok')}
    if not any(r.get('ok') for r in results.values()):
        return None, errors
    return ip_intel.merge(results), errors


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
            for a in ((dev.get('sysinfo') or {}).get('ip_addresses') or [])[:32]:
                own.append(a if isinstance(a, str) else (a or {}).get('address'))
    cutoff = int(time.time()) - 30 * 86400
    try:
        for e in ((A._load_ro(A.AUDIT_LOG_FILE) or {}).get('entries') or [])[-5000:]:
            if isinstance(e, dict) and e.get('action') == 'login' and int(e.get('ts') or 0) >= cutoff:
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


def _store_ro():
    return (A._load_ro(A.IPINTEL_FILE) or {}) if A.backend_exists(A.IPINTEL_FILE) else {}


NET_PER_SWEEP = 25          # addresses per sweep that cost a network call
SWEEP_MAX = 500             # addresses per sweep in all: the ones that cost nothing are free
LEDGER_S = 86400            # how long an address's evidence is kept before it starts over
REPORT_LOG_KEEP = 3         # what was sent, kept per address so the page can show it


def _fresh_ledger(att, now):
    ev = (att or {}).get('ev')
    if isinstance(ev, dict) and now - int(ev.get('first') or now) <= LEDGER_S:
        return ev
    return None


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
    ev = item.get('evidence')
    if isinstance(ev, dict):
        ledger = _fresh_ledger(att, now)
        ok, _why = threat_evidence.qualifies(threat_evidence.merge(ledger, ev) if ledger else ev, need)
    else:
        ok = int(item.get('count') or 0) >= need
    if not ok:
        return False
    reported, retry = att.get('reported') or {}, att.get('retry') or {}
    return any(pol['keys'].get(p) and now - int(reported.get(p) or 0) >= REPORT_EVERY_S
               and now >= int(retry.get(p) or 0) for p in ip_intel.PROVIDERS)


def _needs_network(item, att, pol, now):
    att = att or {}
    fresh = (now - int(att.get('checked_at') or 0)) < int(pol['cache_hours']) * 3600
    if (pol.get('lookup_enabled') or pol.get('block_enabled')) and not (fresh and att.get('verdict')):
        return True
    return _may_report(item, att, pol, now)


def _claim_batch(queue, atts, pol, now):
    """(batch, rest): the queue entries this sweep handles, in the order to handle
    them. The brute-force counter's entries keep their place at the front, first
    come first served; the sensor's follow, strongest first, so when a day's lookup
    and report allowance runs short it goes to the addresses that earned it. Work
    that costs a network call is rationed to NET_PER_SWEEP addresses; entries that
    cost nothing (already looked up, nothing to report) are taken freely."""
    def key(i):
        item = queue[i]
        if isinstance(item, dict) and isinstance(item.get('evidence'), dict):
            return (1, -_queue_priority(item), i)
        return (0, 0, i)
    order = sorted(range(len(queue)), key=key)
    taken, net = [], 0
    for i in order:
        item = queue[i]
        if isinstance(item, dict):
            att = atts.get(ip_intel.parse_ip(item.get('ip')) or '')
            if _needs_network(item, att, pol, now):
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
    ev_ok, ev_why = threat_evidence.qualifies(ev, need) if ev else (False, '')
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
        comment = ip_intel.evidence_comment(ev, pol.get('report_comment'))
        label = '+'.join(c for c, _n in threat_evidence.dominant(ev, 3)) or 'other'
        when = int(ev.get('last') or 0) or None
    else:
        comment = ip_intel.report_comment(kind, legacy_n, lead['item'].get('window_s'),
                                          pol.get('report_comment'))
        label, when = kind, None
    return {'cats': cats, 'comment': comment, 'label': label, 'when': when,
            'ev': ev if ev_ok else None}, ''


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
    if not st_ro.get('queue') and not has_expired:
        return

    commands = []        # (dev_id or None, command or None, audit action, detail)

    # ── phase 1 ──
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        st['last_sweep'] = now
        queue = st.get('queue') if isinstance(st.get('queue'), list) else []
        blocks = st.get('blocks') if isinstance(st.get('blocks'), dict) else {}
        for dev_id, per in list(blocks.items()):
            if not isinstance(per, dict):
                blocks.pop(dev_id, None)
                continue
            for ip, b in list(per.items()):
                if isinstance(b, dict) and int(b.get('until') or 0) <= now:
                    per.pop(ip, None)
                    commands.append((dev_id, 'exec:' + ip_intel.unblock_command(ip),
                                     'ip_intel_unblock', f'device={dev_id} ip={ip} reason=expired'))
            if not per:
                blocks.pop(dev_id, None)
        st['blocks'] = blocks
        allowance = _budget_left(st, pol, today)
        report_allowance = _report_budget_left(st, pol, today)
        atts = st.get('attackers') if isinstance(st.get('attackers'), dict) else {}
        batch, st['queue'] = _claim_batch(queue, atts, pol, now)
        plan = []
        for item in batch:
            ip = ip_intel.parse_ip(item.get('ip')) if isinstance(item, dict) else None
            dev_id = str(item.get('device_id') or '') if isinstance(item, dict) else ''
            if not ip or not dev_id:
                continue
            a = atts.get(ip) or {}
            fresh = (now - int(a.get('checked_at') or 0)) < int(pol['cache_hours']) * 3600
            plan.append({
                'item': item, 'ip': ip, 'dev_id': dev_id,
                'lookup': bool(pol['lookup_enabled'] or pol['block_enabled'])
                          and not (fresh and a.get('verdict')),
                'cached': a.get('verdict'),
                'reported': dict(a.get('reported') or {}),
                'retry': dict(a.get('retry') or {}),
                'ledger': _fresh_ledger(a, now),
            })

    # ── phase 2 ──
    spent = {}
    looked = {}          # ip -> (verdict, errors): one lookup per address per sweep
    devices = A._load_ro(A.DEVICES_FILE) or {}
    protected = None
    groups = {}
    for p in plan:
        groups.setdefault(p['ip'], []).append(p)
        if p['lookup'] and p['ip'] not in looked:
            looked[p['ip']] = _fetch_verdict(p['ip'], pol, allowance, spent)
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
        for prov in keyed:
            key = pol['keys'][prov]
            if now - int(lead['reported'].get(prov) or 0) < REPORT_EVERY_S:
                continue
            if now < int(lead['retry'].get(prov) or 0):
                continue                 # a service said 429 a moment ago; let its window pass
            if report_allowance.get(prov, 0) <= 0:
                lead['report_err'][prov] = 'not reported: the daily report limit is used up'
                continue
            report_allowance[prov] -= 1
            spent['report:' + prov] = spent.get('report:' + prov, 0) + 1
            build, parse = ip_intel.REPORT[prov]
            res = parse(*A._ip_intel_http(
                build(ip, key, report['cats'][prov], report['comment'], timestamp=report['when'])))
            entry = {'at': now, 'prov': prov, 'cats': list(report['cats'][prov]),
                     'comment': report['comment']}
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
    sensors = st_ro.get('sensors') if isinstance(st_ro.get('sensors'), dict) else {}
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        _add_spend(st, today, spent)
        atts = st.setdefault('attackers', {})
        blocks = st.setdefault('blocks', {})
        done = set()
        for p in plan:
            ip, dev_id, item, verdict = p['ip'], p['dev_id'], p['item'], p['verdict']
            att = atts.setdefault(ip, {})
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
                new = _entry_evidence(groups[ip])
                cur = _fresh_ledger(att, now)
                if new:
                    cur = threat_evidence.slim(threat_evidence.merge(cur, new))
                # A report starts the ledger over, but only once every service it
                # is meant for has been told: if one took it and the other was
                # busy, the evidence stays so the other can still be sent it.
                told = att.get('reported') or {}
                everyone = all(now - int(told.get(prov) or 0) < REPORT_EVERY_S
                               for prov in ip_intel.PROVIDERS if pol['keys'].get(prov))
                if p.get('archived') and cur and everyone:
                    att['ev_reported'] = {'at': now, 'ev': cur}
                    cur = None
                att['ev'] = cur
                if cur is None:
                    att.pop('ev', None)
            seen = att.setdefault('devices', {})
            ev = item.get('evidence')
            prior = seen.get(dev_id) if isinstance(seen.get(dev_id), dict) else {}
            count = int(item.get('count') or 0)
            if isinstance(ev, dict) and now - int(prior.get('at') or 0) <= LEDGER_S:
                count += int(prior.get('count') or 0)        # a running total for the day
            seen[dev_id] = {'count': count, 'unit': str(item.get('unit') or '')[:64],
                            'at': int(item.get('at') or now)}
            ok, why = ip_intel.block_decision(pol, verdict, item.get('count'))
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
                    'score': verdict.get('score'), 'by': 'auto', 'kind': p['kind']}
                commands.append((dev_id, 'exec:' + ip_intel.block_command(ip), 'ip_intel_block',
                                 f"device={dev_id} ip={ip} score={verdict.get('score')} auto"))
            elif pol['block_enabled']:
                seen[dev_id]['not_blocked'] = why
        if len(atts) > ATTACKER_CAP:
            oldest = sorted(atts, key=lambda k: int((atts[k] or {}).get('last_seen') or 0))
            for old in oldest[:len(atts) - ATTACKER_CAP]:
                atts.pop(old, None)

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
    return out


def _evidence_view(att):
    """What the logs showed about one address, for the page: the classes it was
    seen doing, the sources that saw it, the rule ids and CVE ids, and who had
    already decided on it. From the day's ledger, or from what the last report
    was made of when the ledger has just been started over. None when the logs
    said nothing (an address only the brute-force counter knows)."""
    ev = att.get('ev') if isinstance(att.get('ev'), dict) else None
    sent = False
    if ev is None:
        rep = att.get('ev_reported')
        ev = rep.get('ev') if isinstance(rep, dict) and isinstance(rep.get('ev'), dict) else None
        sent = ev is not None
    if not ev:
        return None
    src, tok = ev.get('src') or {}, ev.get('tok') or {}
    seen = []
    for fam in threat_evidence.SOURCES:
        if src.get(fam) or tok.get(fam) or (fam == 'f2b' and ev.get('ban')) or (fam == 'cs' and ev.get('dec')):
            seen.append({'id': fam, 'n': int(src.get(fam) or 0)})
    rules = {}
    for toks in tok.values():
        for t_, c in toks.items():
            if t_.startswith('crs:') and threat_evidence.crs_class(t_[4:]):
                rules[t_[4:]] = max(rules.get(t_[4:], 0), int(c))
    return {
        'classes': [{'id': c, 'n': n} for c, n in threat_evidence.dominant(ev, 5)],
        'sources': seen,
        'rules': [r for r, _n in sorted(rules.items(), key=lambda kv: -kv[1])[:5]],
        'cves': list(ev.get('cve') or [])[:3], 'jails': list(ev.get('ban') or [])[:4],
        'ans': int(ev.get('ans') or 0), 'blk': int(ev.get('blk') or 0),
        'confirmed': threat_evidence.confirmed_by(ev),
        'first': ev.get('first'), 'last': ev.get('last'), 'sent': sent,
    }


def _sensor_rows(st, visible):
    """Each visible host's sensor health: what its agent reads, and whether it
    could. Hosts the caller cannot see are not listed."""
    rows = []
    for dev_id, rec in (st.get('sensors') if isinstance(st.get('sensors'), dict) else {}).items():
        if dev_id not in visible or not isinstance(rec, dict):
            continue
        rows.append({'device_id': dev_id, 'name': (visible[dev_id] or {}).get('name') or dev_id,
                     'at': rec.get('at'), 'sources': list(rec.get('sources') or []),
                     'events': rec.get('events'), 'dropped': rec.get('dropped'),
                     'throttled': rec.get('throttled'), 'ignored': dict(rec.get('ignored') or {})})
    rows.sort(key=lambda r: str(r['name']).lower())
    return rows


def handle_ip_intel():
    """GET /api/ip-intel — settings (keys as booleans), recent attackers with
    their reputation and what the logs showed, active blocks, each host's log
    sensor, and today's lookup budget. Attackers, blocks and sensors are limited
    to devices the caller can see."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    role = A.verify_token(A.get_token_from_request())[1]
    is_admin = bool(A._resolve_role(role).get('admin'))
    pol = _policy()
    visible = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    st = _store_ro()
    blocks = st.get('blocks') if isinstance(st.get('blocks'), dict) else {}
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
            'errors': a.get('errors', {}),
            'evidence': _evidence_view(a),
            'report_log': [e for e in (a.get('report_log') or []) if isinstance(e, dict)][-3:],
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
    budget = st.get('budget') if isinstance(st.get('budget'), dict) else {}
    A.respond(200, {'ok': True, 'is_admin': is_admin,
                    'settings': _settings_view(pol) if is_admin else {},
                    'attackers': attackers[:1000], 'blocks': rows,
                    'sensor_enabled': bool(pol.get('sensor_enabled')),
                    'sensors': _sensor_rows(st, visible),
                    'budget': budget, 'queued': len(st.get('queue') or [])})


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
        for k in ('lookup_enabled', 'report_enabled', 'block_enabled', 'sensor_enabled'):
            if body.get(k) is not None:
                pol[k] = bool(body[k])
                changed.append(f'{k}={pol[k]}')
        for k, lo, hi in (('block_min_score', 1, 100), ('block_ttl_hours', 1, 24 * 90),
                          ('block_max_per_hour', 1, 1000), ('report_min_count', 1, 100000),
                          ('cache_hours', 1, 24 * 30), ('daily_lookup_budget', 0, 1000000),
                          ('daily_report_budget', 0, 1000000)):
            if body.get(k) not in (None, ''):
                try:
                    pol[k] = max(lo, min(hi, int(body[k])))
                except (TypeError, ValueError):
                    A.respond(400, {'error': f'{k} must be a number'})
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
        cfg['ip_intel'] = pol
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
        A.respond(404, {'error': 'Device not found'})
    if dev.get('agentless') or A._device_os_family(dev) != 'linux':
        A.respond(409, {'error': 'Blocking is available on Linux agents only'})
    pol = _policy()
    why = ip_intel.never_block_reason(ip, _protected_networks(pol, A._load_ro(A.DEVICES_FILE) or {}))
    if why:
        A.respond(409, {'error': f'Not blocking {ip}: {why}'})
    try:
        hours = max(1, min(24 * 90, int(body.get('hours') or pol['block_ttl_hours'])))
    except (TypeError, ValueError):
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
