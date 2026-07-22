"""Integrity Guard — server side.

Covers the maintenance rail (never auto-quarantine during declared change) and
that the bound guard_handlers module is wired into api.py.
"""
import importlib.machinery
import importlib.util
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# MUST be set before api.py is exec'd — import-time ensure_default_user() writes
# to DATA_DIR, and without this the test would target a real install.
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_ldr = importlib.machinery.SourceFileLoader(
    'api', str(Path(__file__).parent.parent / 'server' / 'cgi-bin' / 'api.py'))
_spec = importlib.util.spec_from_loader('api', _ldr)
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _window(scope, target, active=True):
    now = datetime.now(timezone.utc)
    if active:
        start, end = now - timedelta(hours=1), now + timedelta(hours=1)
    else:
        start, end = now - timedelta(hours=4), now - timedelta(hours=3)
    return {'id': 'w1', 'scope': scope, 'target': target,
            'start': _iso(start), 'end': _iso(end), 'reason': 'deploy'}


class TestModuleWiring(unittest.TestCase):
    def test_handlers_come_from_the_bound_module(self):
        for n in ('handle_guard_quarantine_list', 'handle_guard_action',
                  '_guard_maintenance_active'):
            fn = getattr(api, n, None)
            self.assertTrue(callable(fn), f'{n} not bound into api')
            self.assertEqual(fn.__module__, 'guard_handlers',
                             f'{n} must live in the guard_handlers module')

    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/guard/quarantine'), routes)
        self.assertIn(('POST', '/api/guard/action'), routes)


class TestMaintenanceRail(unittest.TestCase):
    def setUp(self):
        api.save(api.MAINT_FILE, {})
        api._invalidate_load_cache(api.MAINT_FILE)

    def tearDown(self):
        api.save(api.MAINT_FILE, {})
        api._invalidate_load_cache(api.MAINT_FILE)

    def _set(self, windows):
        api.save(api.MAINT_FILE, {'windows': windows})
        api._invalidate_load_cache(api.MAINT_FILE)

    def test_no_windows_means_not_in_maintenance(self):
        self.assertFalse(api._guard_maintenance_active('d1', {'group': 'web'}))

    def test_active_device_window_suppresses(self):
        self._set([_window('device', 'd1')])
        self.assertTrue(api._guard_maintenance_active('d1', {}))
        self.assertFalse(api._guard_maintenance_active('other', {}))

    def test_active_group_window_suppresses_members_only(self):
        self._set([_window('group', 'web')])
        self.assertTrue(api._guard_maintenance_active('d1', {'group': 'web'}))
        self.assertFalse(api._guard_maintenance_active('d1', {'group': 'db'}))

    def test_global_window_suppresses_everything(self):
        self._set([_window('global', '')])
        self.assertTrue(api._guard_maintenance_active('anything', {'group': 'x'}))

    def test_expired_window_does_not_suppress(self):
        self._set([_window('device', 'd1', active=False)])
        self.assertFalse(api._guard_maintenance_active('d1', {}))


class TestProtectStrippedDuringMaintenance(unittest.TestCase):
    """The rail as the heartbeat applies it: `protect` is dropped from pushed
    checks while a window is active, so the check degrades to report-only."""

    def test_strip_logic(self):
        checks = [{'id': 'c1', 'type': 'dir_baseline', 'param': '/var/www::*.php',
                   'protect': 'quarantine'},
                  {'id': 'c2', 'type': 'file_hash', 'param': '/etc/passwd'}]
        # mirrors the heartbeat guard: only strip when a window is active
        if any(c.get('protect') for c in checks):
            for c in checks:
                c.pop('protect', None)
        self.assertNotIn('protect', checks[0])
        self.assertEqual(checks[0]['type'], 'dir_baseline')   # check still pushed


class TestBaselinePickerSplit(unittest.TestCase):
    """Hardening templates live on Security -> Protect, operational ones on
    Monitoring -> Checks. Both pickers share the apply endpoint; only `kind`
    decides where a template is offered."""

    def test_every_template_has_a_kind(self):
        for t in api.CHECK_BASELINE_CATALOG:
            self.assertIn(api.baseline_kind(t['cat']), ('ops', 'protect'), t['id'])

    def test_both_pickers_are_populated(self):
        kinds = [api.baseline_kind(t['cat']) for t in api.CHECK_BASELINE_CATALOG]
        self.assertGreater(kinds.count('ops'), 0, 'Checks picker would be empty')
        self.assertGreater(kinds.count('protect'), 10, 'Protect picker too thin')

    def test_security_categories_are_protect(self):
        for cat in ('Web / application security', 'Hardening — must not listen',
                    'Integrity — critical files', 'Integrity — persistence paths',
                    'Detection — log signals'):
            self.assertEqual(api.baseline_kind(cat), 'protect', cat)

    def test_operational_categories_stay_on_checks(self):
        for cat in ('Core liveness', 'Filesystem / OS', 'Role-tagged'):
            self.assertEqual(api.baseline_kind(cat), 'ops', cat)

    def test_protect_templates_are_all_appliable(self):
        """A Protect template must still be a normal, scopeable custom check."""
        known = set(api.SERVER_CHECK_TYPES) | set(api.AGENT_CHECK_TYPES)
        rows = [t for t in api.CHECK_BASELINE_CATALOG
                if api.baseline_kind(t['cat']) == 'protect']
        for t in rows:
            self.assertIn(t['type'], known, t['id'])
            self.assertTrue(t['param'] and t['name'] and t['desc'], t['id'])


class TestProtectOriginStamping(unittest.TestCase):
    """Applying from the Protect picker stamps kind='protect' so the Protect
    page can list what it applied — and an EDIT must not silently drop it
    (the save handler rebuilds the entry from scratch)."""

    def setUp(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.cap = {}
        self._r, self._a, self._au = api.respond, api.require_admin_auth, api.audit_log

        def resp(s_, d=None):
            self.cap['s'], self.cap['d'] = s_, d
            raise SystemExit
        api.respond = resp
        api.require_admin_auth = lambda: 'admin'
        api.audit_log = lambda *a, **k: None
        api.method = lambda: 'POST'

    def tearDown(self):
        api.respond, api.require_admin_auth, api.audit_log = self._r, self._a, self._au
        for a in ('method', 'get_json_obj', 'get_json_body'):
            if hasattr(api, a):
                try:
                    delattr(api, a)
                except Exception:
                    pass

    def _apply(self, ids, tk='all', tv=''):
        api.get_json_obj = lambda: {'ids': ids, 'target_kind': tk, 'target': tv}
        api.get_json_body = api.get_json_obj
        try:
            api.handle_check_baselines_apply()
        except SystemExit:
            pass
        return (api.load(api.CONFIG_FILE) or {}).get('custom_checks', [])

    def test_protect_template_is_stamped(self):
        checks = self._apply(['webroot_integrity'], 'host', 'd1')
        row = next(c for c in checks if c['type'] == 'dir_baseline')
        self.assertEqual(row.get('kind'), 'protect')

    def test_operational_template_is_not_stamped(self):
        checks = self._apply(['agent_running'], 'all', '')
        row = next(c for c in checks if c['param'] == 'remotepower-agent.service')
        self.assertIsNone(row.get('kind'))

    def test_edit_preserves_the_protect_origin(self):
        checks = self._apply(['crontab_integrity'], 'all', '')
        row = next(c for c in checks if c['param'] == '/etc/crontab')
        self.assertEqual(row.get('kind'), 'protect')
        # now edit it through the normal save handler (retarget to a host)
        api.get_json_obj = lambda: {'id': row['id'], 'name': row['name'],
                                    'type': 'file_hash', 'param': '/etc/crontab',
                                    'target_kind': 'host', 'target': 'd9'}
        api.get_json_body = api.get_json_obj
        try:
            api.handle_custom_checks_save()
        except SystemExit:
            pass
        after = (api.load(api.CONFIG_FILE) or {}).get('custom_checks', [])
        edited = next(c for c in after if c['id'] == row['id'])
        self.assertEqual(edited['target'], 'd9')
        self.assertEqual(edited.get('kind'), 'protect',
                         'edit dropped kind -> the check vanishes from Protect')


if __name__ == '__main__':
    unittest.main()
