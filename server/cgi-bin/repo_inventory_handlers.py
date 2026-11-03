"""RemotePower — Package repository inventory: which repositories the hosts use, and what is wrong with them (7.4.9)

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

import hashlib
import json

import repo_inventory


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


MAX_ROWS = 500
HOSTS_PER_ROW = 20
TOUCH_EVERY_S = 6 * 3600   # an unchanged report only refreshes the time this often


def repo_inventory_ingest(dev_id, raw, now):
    """Called for every sysinfo a host reports that carries `repo_files`. The files are validated and capped, and the host's
    record is written only when they changed (or every few hours, to say the host still reports them), so a fleet that sends
    the same text every beat does not rewrite a store each time. Never raises."""
    files = repo_inventory.clean_files(raw)
    if not files:
        return False
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()[:24]
    cur = A._entity_read_one(A.REPO_INVENTORY_FILE, dev_id, None)
    if isinstance(cur, dict) and cur.get('hash') == digest and now - int(cur.get('ts') or 0) < TOUCH_EVERY_S:
        return False
    A._entity_write_one(A.REPO_INVENTORY_FILE, dev_id, {'ts': int(now), 'hash': digest, 'files': files})
    return True


def _host_rows(rec):
    """The parsed rows of one host's record with their findings attached, or [] for a record that cannot be read."""
    if not isinstance(rec, dict) or not isinstance(rec.get('files'), dict):
        return []
    files = repo_inventory.clean_files(rec['files'])
    rows = repo_inventory.parse(files)
    found = repo_inventory.evaluate(rows)
    out = []
    for r, f in zip(rows, found):
        out.append(dict(r, findings=f, counts=repo_inventory.count(f), worst=repo_inventory.worst(f)))
    return out


def handle_repositories():
    """GET /api/repositories — the package repositories the fleet's Linux hosts use, one row per repository.

    A row is a repository (its kind, URL and suite, and whether signatures and certificates are checked) with the findings
    worst first, how many hosts use it and the first of them. `?min=critical|high|medium|low` leaves out the repositories whose
    findings are all below that (default low, which is everything, including the ones with none); `?q=` filters on URL, host or
    host name; `?host=<id>` is one host's own list. `summary` counts the repositories by their worst finding, whatever the
    filter. A disabled repository is listed and has no findings. Hosts outside the caller's tenant or role scope are not
    listed, and `hosts_reporting` counts the hosts whose agent has sent its repository files."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    floor = (qs.get('min', ['low'])[0] or 'low').lower()
    if floor not in repo_inventory.RANK:
        floor = 'low'
    q = (qs.get('q', [''])[0] or '').strip().lower()[:100]
    only = (qs.get('host', [''])[0] or '').strip()[:64]
    devices = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    store = A.load(A.REPO_INVENTORY_FILE) or {}
    groups = {}
    reporting = 0
    for dev_id, rec in store.items():
        dev = devices.get(dev_id)
        if not isinstance(dev, dict) or (only and dev_id != only):
            continue
        rows = _host_rows(rec)
        if not isinstance(rec, dict):
            continue
        reporting += 1
        for r in rows:
            key = '|'.join((repo_inventory.key_of(r), str(r['signed']), str(r['tls_verify']), str(r['enabled'])))
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    'key': key, 'kind': r['kind'], 'url': r['url'], 'host': r['host'], 'scheme': r['scheme'], 'suite': r['suite'],
                    'components': r['components'], 'id': r['id'], 'enabled': r['enabled'], 'signed': r['signed'],
                    'tls_verify': r['tls_verify'], 'findings': r['findings'], 'counts': r['counts'], 'worst': r['worst'],
                    'types': r['types'], 'host_count': 0, 'hosts': [], '_seen': set()}
            if dev_id in g['_seen']:
                continue          # a host that lists one repository twice is one host of it
            g['_seen'].add(dev_id)
            g['host_count'] += 1
            if len(g['hosts']) < HOSTS_PER_ROW:
                g['hosts'].append({'device_id': dev_id, 'device': dev.get('name', dev_id), 'file': r['file'],
                                   'monitored': dev.get('monitored') is not False})
    summary = {s: 0 for s in repo_inventory.SEVERITIES}
    summary['clean'] = 0
    summary['third_party'] = 0
    out = []
    for g in groups.values():
        g.pop('_seen', None)
        summary[g['worst'] or 'clean'] += 1
        if any(f['rule'] == 'third_party' for f in g['findings']):
            summary['third_party'] += 1
        if floor != 'low' and not any(repo_inventory.RANK[f['severity']] <= repo_inventory.RANK[floor] for f in g['findings']):
            continue
        if q and q not in f"{g['url']} {g['host']} {' '.join(h['device'] for h in g['hosts'])}".lower():
            continue
        out.append(g)
    out.sort(key=lambda g: tuple(-g['counts'][s] for s in repo_inventory.SEVERITIES) + (-g['host_count'], g['url']))
    A.respond(200, {'repositories': out[:MAX_ROWS], 'truncated': len(out) > MAX_ROWS, 'summary': summary,
                    'hosts_reporting': reporting, 'rules': {k: {'severity': v[0], 'title': v[1]} for k, v in repo_inventory.RULES.items()}})
