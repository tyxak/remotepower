#!/usr/bin/env python3
"""A maintenance window created in one tenant covered every tenant.

A window does two things: it suppresses alerts for the hosts it covers, and
with `gate_exec` it holds their exec/upgrade commands until it is open. Neither
side carried a tenant. `handle_maintenance_add` is `require_admin_auth()`, which
a tenant admin passes, and a `global`-scoped window matched every device on the
instance — so one tenant admin could silence every other tenant's alerting, or
freeze their changes, with one POST. Update and delete had no scope check
either, so an existing window could be repointed or removed.

The scope-matching rule had FIVE copies (suppression, exec gating, scan gating,
SLA subtraction, Integrity Guard). That is how a check ends up on some of them,
so they now share one predicate, `_window_applies`.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# `_parse_iso` reads a naive ISO stamp as LOCAL time, so fixtures build their
# start/end with time.localtime. Building them in UTC shifts every window by the
# box's offset and the positive controls silently stop covering anything.

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702mw-'))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('api_v702mw', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-mw-'))
        self._saved = {n: getattr(api, n) for n in
                       ('MAINT_FILE', 'DEVICES_FILE', 'USERS_FILE',
                        'CONFIG_FILE', 'TENANTS_FILE')}
        for n in self._saved:
            setattr(api, n, self.d / f'{n.lower()}.json')
        self._fns = {n: getattr(api, n) for n in
                     ('respond', 'method', 'get_json_obj', 'get_json_body',
                      'audit_log', 'get_token_from_request', 'verify_token',
                      '_tenant_gate', '_tenancy_enforced', '_caller_is_superadmin')}
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'tok'
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {
            'a1': {'name': 'a-host', 'tenant': 'tenant-a', 'group': 'prod'},
            'b1': {'name': 'b-host', 'tenant': 'tenant-b', 'group': 'prod'}})
        api.save(api.USERS_FILE, {'aadmin': {'tenant_id': 'tenant-a'},
                                  'badmin': {'tenant_id': 'tenant-b'}})
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        # Keyed BY tenant id — a tenant missing here resolves to 'default',
        # which turns the fixture's tenant admin into a superadmin and makes
        # every isolation assertion below vacuous.
        api.save(api.TENANTS_FILE, {'tenant-a': {'name': 'A', 'status': 'active'},
                                    'tenant-b': {'name': 'B', 'status': 'active'}})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in list(self._saved.items()) + list(self._fns.items()):
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def _call(self, fn, *a):
        self.cap.clear()
        try:
            return 200, fn(*a)
        except api.HTTPError:
            return self.cap.get('status'), self.cap.get('data')

    def _as(self, tenant, user='badmin', role='admin'):
        api.verify_token = lambda _t=None: (user, role)
        api._tenant_gate = lambda: tenant
        api._tenancy_enforced = lambda: True
        api._caller_is_superadmin = lambda: tenant is None

    def _add_global(self, tenant='tenant-b', user='badmin', gate_exec=False):
        self._as(tenant, user)
        api.method = lambda: 'POST'
        now = int(time.time())
        body = {'scope': 'global', 'target': '', 'reason': 'ACME DB migration',
                'start': time.strftime('%Y-%m-%dT%H:%M:%S',
                                       time.localtime(now - 600)),
                'end': time.strftime('%Y-%m-%dT%H:%M:%S',
                                     time.localtime(now + 3600)),
                'gate_exec': gate_exec}
        api.get_json_body = lambda: body
        api.get_json_obj = api.get_json_body
        st, d = self._call(api.handle_maintenance_add)
        self.assertEqual(st, 200, d)
        return d['window']


class TestAGlobalWindowStopsAtTheTenantBoundary(_Base):

    def test_the_window_records_its_tenant(self):
        self.assertEqual(self._add_global()['tenant_gate'], 'tenant-b')

    def test_it_does_not_suppress_another_tenants_alerts(self):
        self._add_global()
        api._LOAD_CACHE.clear()
        ev = sorted(api.SUPPRESSIBLE_EVENTS)[0]
        self.assertIsNone(api.in_maintenance(ev, {'device_id': 'a1'}),
                          'one tenant silenced another tenant\'s alerting')

    def test_it_still_suppresses_its_own(self):
        """Control — a predicate that matched nothing would pass every
        assertion above and break maintenance windows outright."""
        self._add_global()
        api._LOAD_CACHE.clear()
        ev = sorted(api.SUPPRESSIBLE_EVENTS)[0]
        self.assertIsNotNone(api.in_maintenance(ev, {'device_id': 'b1'}))

    def test_it_does_not_freeze_another_tenants_commands(self):
        w = self._add_global(gate_exec=True)
        # Closed now, so a covered device is held.
        w['start'] = '2030-01-01T00:00:00'
        w['end'] = '2030-01-01T01:00:00'
        api.save(api.MAINT_FILE, {'windows': [w]})
        api._LOAD_CACHE.clear()
        devs = api.load(api.DEVICES_FILE)
        self.assertFalse(api._exec_gated('a1', devs['a1']),
                         'one tenant held every change on another tenant')
        self.assertTrue(api._exec_gated('b1', devs['b1']),
                        'control: it must still hold its own')

    def test_it_does_not_gate_another_tenants_scans(self):
        self._add_global()
        api._LOAD_CACHE.clear()
        devs = api.load(api.DEVICES_FILE)
        self.assertFalse(api._scan_window_active('a1', devs['a1']))
        self.assertTrue(api._scan_window_active('b1', devs['b1']))

    def test_it_does_not_subtract_from_another_tenants_sla(self):
        w = self._add_global()
        api._LOAD_CACHE.clear()
        wins = (api.load(api.MAINT_FILE) or {}).get('windows')
        devs = api.load(api.DEVICES_FILE)
        lo, hi = int(time.time()) - 86400, int(time.time()) + 86400
        self.assertEqual(
            api._maint_oneshot_intervals(wins, 'a1', 'prod', lo, hi, dev=devs['a1']), [])
        self.assertEqual(
            len(api._maint_oneshot_intervals(wins, 'b1', 'prod', lo, hi, dev=devs['b1'])), 1)
        self.assertEqual(w['scope'], 'global')

    def test_a_group_scoped_window_stops_there_too(self):
        """Both tenants have a `prod` group, so scope alone matches across the
        boundary."""
        self._as('tenant-b', 'badmin')
        api.method = lambda: 'POST'
        now = int(time.time())
        body = {'scope': 'group', 'target': 'prod', 'reason': 'rollout',
                'start': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now - 60)),
                'end': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now + 600))}
        api.get_json_body = lambda: body
        api.get_json_obj = api.get_json_body
        st, d = self._call(api.handle_maintenance_add)
        self.assertEqual(st, 200, d)
        api._LOAD_CACHE.clear()
        ev = sorted(api.SUPPRESSIBLE_EVENTS)[0]
        self.assertIsNone(api.in_maintenance(ev, {'device_id': 'a1'}))
        self.assertIsNotNone(api.in_maintenance(ev, {'device_id': 'b1'}))

    def test_integrity_guard_reads_the_same_predicate(self):
        import importlib.util as _u
        _s = _u.spec_from_file_location('gh_v702mw', _CGI / 'guard_handlers.py')
        gh = _u.module_from_spec(_s)
        _s.loader.exec_module(gh)
        gh.bind(globals()) if hasattr(gh, 'bind') else None
        gh.A = api
        self._add_global()
        api._LOAD_CACHE.clear()
        devs = api.load(api.DEVICES_FILE)
        fn = getattr(gh, '_guard_maintenance_active', None)
        self.assertTrue(fn, 'the guard maintenance check moved or was renamed')
        self.assertFalse(fn('a1', devs['a1']))
        self.assertTrue(fn('b1', devs['b1']))


class TestTheWindowListAndEdits(_Base):

    def test_another_tenant_cannot_see_it(self):
        """The reason is free text an operator writes about their own change,
        and the target names a host."""
        self._add_global()
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'GET'
        _st, d = self._call(api.handle_maintenance_list)
        self.assertEqual(d['windows'], [])

    def test_the_owner_still_sees_it(self):
        w = self._add_global()
        self._as('tenant-b', 'badmin')
        api.method = lambda: 'GET'
        _st, d = self._call(api.handle_maintenance_list)
        self.assertEqual([x['id'] for x in d['windows']], [w['id']])

    def test_another_tenant_cannot_repoint_it(self):
        w = self._add_global()
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'PUT'
        now2 = int(time.time())
        api.get_json_body = lambda: {
            'scope': 'global', 'target': '', 'reason': 'repointed',
            'start': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now2)),
            'end': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now2 + 60))}
        api.get_json_obj = api.get_json_body
        st, _d = self._call(api.handle_maintenance_update, w['id'])
        self.assertEqual(st, 404)

    def test_another_tenant_cannot_delete_it(self):
        w = self._add_global()
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'DELETE'
        st, _d = self._call(api.handle_maintenance_delete, w['id'])
        self.assertEqual(st, 404)
        api._LOAD_CACHE.clear()
        self.assertEqual(len((api.load(api.MAINT_FILE) or {})['windows']), 1)

    def test_the_owner_can_delete_it(self):
        w = self._add_global()
        self._as('tenant-b', 'badmin')
        api.method = lambda: 'DELETE'
        st, _d = self._call(api.handle_maintenance_delete, w['id'])
        self.assertEqual(st, 200)


class TestSingleTenantInstallsAreUnchanged(_Base):

    def test_a_global_window_covers_the_fleet(self):
        api.verify_token = lambda _t=None: ('alice', 'admin')
        api._tenant_gate = lambda: None
        api._tenancy_enforced = lambda: False
        api._caller_is_superadmin = lambda: False
        api.method = lambda: 'POST'
        now = int(time.time())
        body = {'scope': 'global', 'target': '', 'reason': 'patching',
                'start': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now - 60)),
                'end': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now + 600))}
        api.get_json_body = lambda: body
        api.get_json_obj = api.get_json_body
        st, _d = self._call(api.handle_maintenance_add)
        self.assertEqual(st, 200)
        api._LOAD_CACHE.clear()
        ev = sorted(api.SUPPRESSIBLE_EVENTS)[0]
        for dev_id in ('a1', 'b1'):
            self.assertIsNotNone(
                api.in_maintenance(ev, {'device_id': dev_id}), dev_id)

    def test_a_window_from_before_this_release_still_covers_everything(self):
        """No stamp and no resolvable author means no owner, so it keeps the
        reach it has today rather than silently narrowing."""
        now = int(time.time())
        api.save(api.MAINT_FILE, {'windows': [{
            'id': 'mw_old', 'scope': 'global', 'target': '', 'reason': 'legacy',
            'start': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now - 60)),
            'end': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now + 600))}]})
        api._LOAD_CACHE.clear()
        ev = sorted(api.SUPPRESSIBLE_EVENTS)[0]
        for dev_id in ('a1', 'b1'):
            self.assertIsNotNone(
                api.in_maintenance(ev, {'device_id': dev_id}), dev_id)


class TestTheRuleHasOneCopy(unittest.TestCase):

    def test_no_handwritten_scope_match_survives(self):
        """Five copies is how a tenant check lands on some of them. Counted
        over code, not comments."""
        import io
        import re
        import tokenize
        pat = re.compile(r"scope\s*==\s*'global'")
        bad = []
        for f in sorted(_CGI.glob('*.py')):
            src = f.read_text()
            # Blank out comments AND string literals — a docstring that
            # describes the rule is not a copy of it.
            lines = src.splitlines()
            try:
                for tok in tokenize.generate_tokens(io.StringIO(src).readline):
                    if tok.type in (tokenize.COMMENT, tokenize.STRING):
                        for ln in range(tok.start[0], tok.end[0] + 1):
                            lines[ln - 1] = ''
            except (tokenize.TokenError, IndentationError):
                pass
            for i, ln in enumerate(lines, 1):
                if pat.search(ln):
                    bad.append(f'{f.name}:{i}: {ln.strip()[:70]}')
        # _window_applies is the one place the rule is written.
        self.assertLessEqual(len(bad), 1, 'route these through _window_applies:\n'
                                          + '\n'.join(bad))


if __name__ == '__main__':
    unittest.main()
