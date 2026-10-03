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


# ── the heartbeat-side hook ────────────────────────────────────────────────────

def ip_intel_note_attack(dev_id, unit, ip, count, window_s):
    """Queue a brute-force source for the sweep. Cheap and silent: a disabled
    feature, a private address or a hostname returns at once."""
    try:
        pol = _policy()
        if not _any_enabled(pol):
            return
        ip = ip_intel.parse_ip(ip)
        if not ip or not ip_intel.is_public(ip):
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


# ── HTTP ───────────────────────────────────────────────────────────────────────

def _ip_intel_http(req):
    """(status, parsed_json_or_None). Through the SSRF-guarded opener with
    redirects refused, so an API key can never be replayed to another host."""
    r = urllib.request.Request(req['url'], data=req.get('body'), method=req['method'])
    for k, v in (req.get('headers') or {}).items():
        r.add_header(k, v)
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


def run_ip_intel_if_due():
    """Cadence sweep. Three phases, so no lock is held across a network call:

      1. under the store lock: claim a batch from the queue, lift expired
         blocks, and note which addresses need a lookup;
      2. with no lock held: ask the providers, and report;
      3. under the store lock: record the answers and decide blocks.

    Commands and audit lines go out after the lock is released.
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
        batch, st['queue'] = queue[:PER_SWEEP], queue[PER_SWEEP:]
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
        atts = st.get('attackers') if isinstance(st.get('attackers'), dict) else {}
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
            })

    # ── phase 2 ──
    spent = {}
    looked = {}          # ip -> (verdict, errors): one lookup per address per sweep
    for p in plan:
        ip, item = p['ip'], p['item']
        if p['lookup'] and ip not in looked:
            looked[ip] = _fetch_verdict(ip, pol, allowance, spent)
        p['verdict'] = (looked.get(ip) or (None, {}))[0] or p['cached']
        p['kind'] = ip_intel.attack_kind(item.get('unit'))
        p['report_ok'], p['report_err'] = {}, {}
        if not pol['report_enabled'] or (p['verdict'] or {}).get('whitelisted'):
            continue
        if int(item.get('count') or 0) < int(pol['report_min_count']):
            continue
        comment = ip_intel.report_comment(p['kind'], item.get('count'), item.get('window_s'))
        for prov in ip_intel.PROVIDERS:
            key = pol['keys'].get(prov)
            if not key or now - int(p['reported'].get(prov) or 0) < REPORT_EVERY_S:
                continue
            build, parse = ip_intel.REPORT[prov]
            res = parse(*A._ip_intel_http(
                build(ip, key, ip_intel.CATEGORIES[p['kind']][prov], comment)))
            if res.get('ok'):
                p['reported'][prov] = now
                p['report_ok'][prov] = now
                commands.append((None, None, 'ip_intel_report',
                                 f"ip={ip} provider={prov} kind={p['kind']}"))
            else:
                p['report_err'][prov] = res.get('error')

    # ── phase 3 ──
    devices = A._load_ro(A.DEVICES_FILE) or {}
    protected = None
    with A._LockedUpdate(A.IPINTEL_FILE) as st:
        _add_spend(st, today, spent)
        atts = st.setdefault('attackers', {})
        blocks = st.setdefault('blocks', {})
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
            if p['report_ok']:
                att.setdefault('reported', {}).update(p['report_ok'])
            if p['report_err']:
                att.setdefault('errors', {}).update(p['report_err'])
            seen = att.setdefault('devices', {})
            seen[dev_id] = {'count': int(item.get('count') or 0),
                            'unit': str(item.get('unit') or '')[:64],
                            'at': int(item.get('at') or now)}
            ok, why = ip_intel.block_decision(pol, verdict, item.get('count'))
            dev = devices.get(dev_id)
            if ok and (not isinstance(dev, dict) or dev.get('agentless')
                       or A._device_os_family(dev) != 'linux'):
                ok, why = False, 'host is not a Linux agent'
            if ok and ip in (blocks.get(dev_id) or {}):
                ok, why = False, 'already blocked'
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


# ── endpoints ──────────────────────────────────────────────────────────────────

def _settings_view(pol):
    out = {k: pol[k] for k in ip_intel.DEFAULTS}
    out['abuseipdb_key_set'] = bool(pol['keys'].get('abuseipdb'))
    out['sniffcat_key_set'] = bool(pol['keys'].get('sniffcat'))
    return out


def handle_ip_intel():
    """GET /api/ip-intel — settings (keys as booleans), recent attackers with
    their reputation, active blocks and today's lookup budget. Attackers and
    blocks are limited to devices the caller can see."""
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
        for k in ('lookup_enabled', 'report_enabled', 'block_enabled'):
            if body.get(k) is not None:
                pol[k] = bool(body[k])
                changed.append(f'{k}={pol[k]}')
        for k, lo, hi in (('block_min_score', 1, 100), ('block_ttl_hours', 1, 24 * 90),
                          ('block_max_per_hour', 1, 1000), ('report_min_count', 1, 100000),
                          ('cache_hours', 1, 24 * 30), ('daily_lookup_budget', 0, 1000000)):
            if body.get(k) not in (None, ''):
                try:
                    pol[k] = max(lo, min(hi, int(body[k])))
                except (TypeError, ValueError):
                    A.respond(400, {'error': f'{k} must be a number'})
                changed.append(f'{k}={pol[k]}')
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
