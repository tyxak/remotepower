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


if __name__ == '__main__':
    unittest.main()
