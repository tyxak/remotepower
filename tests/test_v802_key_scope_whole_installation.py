#!/usr/bin/env python3
"""A key with a host scope does not download the whole installation, and no route that reads shows it a host outside its scope.

The full backup (`GET /api/backup/download`) and the export (`GET /api/export`) hold every host with its token and the accounts. They are on the
dispatcher's list of what belongs to the whole installation, which a tenant administrator is refused, but that list is a tenant rule: an
administrator key limited to one group is an administrator of the default tenant, which is the operator's, with tenant isolation on or off. It
downloaded both, archives that name every host of the fleet, while `GET /api/devices` showed it one group.

They were found by driving every exact GET route of the route table as a key limited to the group prod, on an instance with a host in another
group, and reading the answers for that host's name and id (the archives are opened: gzip and zip). Of 239 routes, 16 name that host to an unscoped
key (the control: a matrix that saw none would be blind), 14 of them answered the scoped key without it, and these two did not.

What this holds, with real keys and sessions through the real route table in a process of its own, with tenant isolation on and off:

* the two routes, and everything under /api/backup, refuse an administrator key that has a scope (403, `beyond_key_scope`) and send nothing;
* an administrator key with no scope and a signed-in administrator download both as before, and what is under /api/export/monitors is not one of
  the two (it is the operator organisation's monitors list) and stays open to the scoped key;
* a read-only key with a scope is not told it is "limited": it is refused as a read-only key is refused everywhere (the administrator check);
* the matrix itself is a test: every exact GET route is driven as the scoped key and as an unscoped key, none answers the scoped key with the name of
  a host outside its scope, and the unscoped key's answers name that host in enough routes to prove the instrument sees it;
* the two prefixes are read from the source and are on the dispatcher's platform list, so the gate and the list cannot drift apart.
"""
import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import real_stack  # noqa: E402

_CGI = real_stack.CGI

_DRIVER = r'''
import gzip, io, tarfile, zipfile
add_key('SKEY', 'svc', scope={'type': 'groups', 'values': ['prod']})        # an administrator key limited to the group prod: web1 inside, db1 outside
add_key('WIDE', 'boss')                                                       # an administrator key with no scope
add_key('SVIEW', 'viewbot', role='viewer', scope={'type': 'groups', 'values': ['prod']})
MARKERS = [b'db1', b'db-one']
SKIP = ('/api/login', '/api/logout', '/api/stream', '/api/events', '/api/sse', '/api/terminal', '/api/ws', '/api/agent', '/api/install', '/api/heartbeat')


def raw(method, path, token, body=None):
    """The status, the first bytes and the markers of a host outside the scope that the answer holds, archives opened."""
    api._LOAD_CACHE.clear()
    h = {'X-Token': token}
    kw = {}
    if body is not None:
        kw['data'] = json.dumps(body)
        h['Content-Type'] = 'application/json'
    try:
        r = client.open(path, method=method, headers=h, environ_overrides={'REMOTE_ADDR': '203.0.113.5'}, **kw)
    except Exception as e:
        return [599, str(e)[:60], [], '']
    d = r.get_data()
    blobs = [d]
    try:
        if d[:2] == b'\x1f\x8b':
            blobs = [gzip.decompress(d)]
            try:
                with tarfile.open(fileobj=io.BytesIO(blobs[0])) as tf:
                    blobs = [tf.extractfile(m).read() for m in tf.getmembers() if m.isfile()]
            except Exception:
                pass
        elif d[:2] == b'PK':
            with zipfile.ZipFile(io.BytesIO(d)) as zf:
                blobs = [zf.read(n) for n in zf.namelist()]
    except Exception:
        pass
    found = sorted({m.decode() for b in blobs for m in MARKERS if m in b})
    code = ''
    if r.headers.get('Content-Type', '').startswith('application/json'):
        try:
            code = (json.loads(d.decode()) or {}).get('code') or ''
        except Exception:
            pass
    return [r.status_code, d[:2].hex(), found, code]


def scene():
    res = {}
    res['backup_by_scoped_key'] = raw('GET', '/api/backup/download', 'SKEY')
    res['export_by_scoped_key'] = raw('GET', '/api/export', 'SKEY')
    res['restore_by_scoped_key'] = raw('POST', '/api/backup/restore', 'SKEY', {})
    res['test_restore_by_scoped_key'] = raw('POST', '/api/backup/test-restore', 'SKEY', {})
    res['monitors_export_by_scoped_key'] = raw('GET', '/api/export/monitors', 'SKEY')[:2]
    res['backup_by_unscoped_key'] = raw('GET', '/api/backup/download', 'WIDE')[:3]
    res['export_by_unscoped_key'] = raw('GET', '/api/export', 'WIDE')[:3]
    res['backup_by_person'] = raw('GET', '/api/backup/download', SESS['admin'])[:3]
    res['export_by_person'] = raw('GET', '/api/export', SESS['admin'])[:3]
    res['backup_by_scoped_viewer_key'] = raw('GET', '/api/backup/download', 'SVIEW')
    res['export_by_scoped_viewer_key'] = raw('GET', '/api/export', 'SVIEW')
    routes = sorted(p for (m, p) in api._build_exact_routes().keys() if m == 'GET' and '{' not in p and not p.startswith(SKIP))
    rows = [[p, raw('GET', p, 'SKEY'), raw('GET', p, 'WIDE')] for p in routes]
    res['routes'] = len(rows)
    res['control_names_the_host'] = sorted(p for p, s, w in rows if w[2])
    res['leaks'] = [[p, s[0], s[2]] for p, s, w in rows if s[0] == 200 and s[2]]
    return res


out['tenancy_on'] = scene()
put('CONFIG_FILE', {})                                  # the common install: tenant isolation off
out['tenancy_off'] = scene()
'''


class TestTheWholeInstallationIsNotAScopedKeysToDownload(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('flask is not installed')
        cls.out = real_stack.run(_DRIVER)

    def each(self):
        for state in ('tenancy_on', 'tenancy_off'):
            with self.subTest(isolation=state):
                yield self.out[state]

    def test_the_backup_and_the_export_are_refused_to_a_key_with_a_scope(self):
        for s in self.each():
            for name in ('backup_by_scoped_key', 'export_by_scoped_key', 'restore_by_scoped_key', 'test_restore_by_scoped_key'):
                status, first, found, code = s[name]
                self.assertEqual((status, code, found), (403, 'beyond_key_scope', []), name)

    def test_a_key_with_no_scope_and_a_person_download_both_as_before(self):
        for s in self.each():
            for name in ('backup_by_unscoped_key', 'export_by_unscoped_key', 'backup_by_person', 'export_by_person'):
                status, first, found = s[name]
                self.assertEqual(status, 200, name)
                self.assertEqual(found, ['db-one', 'db1'], '%s: the archive holds every host (the control: the instrument sees the host)' % name)
            self.assertEqual(s['backup_by_unscoped_key'][1], '1f8b', 'a gzip archive')
            self.assertEqual(s['export_by_unscoped_key'][1], '504b', 'a zip archive')

    def test_the_monitors_export_under_the_export_is_not_one_of_the_two(self):
        for s in self.each():
            self.assertEqual(s['monitors_export_by_scoped_key'][0], 200)

    def test_a_read_only_key_with_a_scope_is_refused_as_any_read_only_key_is(self):
        for s in self.each():
            for name in ('backup_by_scoped_viewer_key', 'export_by_scoped_viewer_key'):
                status, first, found, code = s[name]
                self.assertEqual(status, 403, name)
                self.assertNotEqual(code, 'beyond_key_scope', '%s: the answer of the administrator check, not "limited to part of the fleet"' % name)
                self.assertEqual(found, [])

    def test_no_route_that_reads_names_a_host_outside_the_scope(self):
        """The matrix. The population is the route table, so a route added later is driven too."""
        for s in self.each():
            self.assertGreaterEqual(s['routes'], 150, 'the matrix drove too few routes: the route table was not read')
            self.assertGreaterEqual(len(s['control_names_the_host']), 10,
                                    'the unscoped key sees the host in too few answers: the instrument is blind: %s' % s['control_names_the_host'])
            self.assertEqual(s['leaks'], [], 'a route answers the key limited to the group prod with a host of another group')


# ── the source ───────────────────────────────────────────────────────────────────────────────────────────────────────────────

def _tuple_of_strings(name):
    for node in ast.parse((_CGI / 'api.py').read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return [e.value if not isinstance(e, ast.Tuple) else e.elts[0].value for e in node.value.elts]
    return []


class TestTheGateAndTheListAgree(unittest.TestCase):

    def test_the_two_prefixes_are_on_the_dispatchers_platform_list(self):
        whole = _tuple_of_strings('_WHOLE_INSTALLATION_PREFIXES')
        platform = _tuple_of_strings('_PLATFORM_ROUTES')
        self.assertGreaterEqual(len(platform), 40, 'the platform list was not read')
        self.assertEqual(sorted(whole), ['/api/backup', '/api/export'])
        for prefix in whole:
            self.assertIn(prefix, platform, '%s is gated as one of the whole installation but is not on the platform list the gate reads' % prefix)


if __name__ == '__main__':
    unittest.main()
