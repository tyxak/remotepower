"""v5.6.0 — timesheet "watch" grants.

Admin/finance already see everyone. A watch grant lets a specific non-finance
user view a specific other user's timesheet (read-only, no rates), targeting one
user or a whole team (ui_prefs.team). These tests pin the permission helper, the
team/user scope resolution, and the API wiring — including that the entries
export honours the same gate (no CSV side-channel).
"""
import importlib.util
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_tsw', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
_SRC = (_CGI / 'api.py').read_text()


class TestWatchResolution(unittest.TestCase):
    def setUp(self):
        api.save(api.USERS_FILE, {
            'alice': {'role': 'viewer', 'ui_prefs': {'team': 'support'}},
            'bob':   {'role': 'viewer', 'ui_prefs': {'team': 'support'}},
            'carol': {'role': 'viewer', 'ui_prefs': {'team': 'platform'}},
            'lead':  {'role': 'viewer', 'ui_prefs': {'team': 'platform'}},
        })
        api.save(api.TIMESHEET_WATCH_FILE, {'grants': [
            {'id': 'g1', 'watcher': 'lead', 'scope': 'user', 'value': 'alice'},
            {'id': 'g2', 'watcher': 'lead', 'scope': 'team', 'value': 'support'},
        ]})

    def tearDown(self):
        api.save(api.USERS_FILE, {})
        api.save(api.TIMESHEET_WATCH_FILE, {'grants': []})

    def test_user_and_team_grants_resolve(self):
        # lead has a direct 'alice' grant + the whole 'support' team (alice, bob)
        watchable = api._ts_watchable_users('lead')
        self.assertEqual(watchable, {'alice', 'bob'})

    def test_team_resolution_is_live(self):
        # move carol into support → lead can now watch her without a new grant
        users = api.load(api.USERS_FILE)
        users['carol']['ui_prefs']['team'] = 'support'
        api.save(api.USERS_FILE, users)
        self.assertIn('carol', api._ts_watchable_users('lead'))

    def test_watcher_excludes_self(self):
        # a self-referential team membership never lets you "watch yourself"
        users = api.load(api.USERS_FILE)
        users['lead']['ui_prefs']['team'] = 'support'
        api.save(api.USERS_FILE, users)
        self.assertNotIn('lead', api._ts_watchable_users('lead'))

    def test_no_grants_is_empty(self):
        self.assertEqual(api._ts_watchable_users('carol'), set())


class TestCanViewTimesheet(unittest.TestCase):
    def setUp(self):
        api.save(api.USERS_FILE, {
            'alice': {'role': 'viewer'}, 'bob': {'role': 'viewer'},
            'lead': {'role': 'viewer'},
        })
        api.save(api.TIMESHEET_WATCH_FILE, {'grants': [
            {'id': 'g1', 'watcher': 'lead', 'scope': 'user', 'value': 'alice'},
        ]})

    def tearDown(self):
        api.save(api.USERS_FILE, {})
        api.save(api.TIMESHEET_WATCH_FILE, {'grants': []})

    def test_self_always_allowed(self):
        self.assertTrue(api._can_view_timesheet('bob', 'bob'))

    def test_grant_allows(self):
        self.assertTrue(api._can_view_timesheet('lead', 'alice'))

    def test_unrelated_denied(self):
        self.assertFalse(api._can_view_timesheet('lead', 'bob'))
        self.assertFalse(api._can_view_timesheet('alice', 'bob'))

    def test_billing_view_overrides(self):
        # admin/finance see everyone regardless of grants
        orig = api._caller_billing_view
        api._caller_billing_view = lambda: True
        try:
            self.assertTrue(api._can_view_timesheet('bob', 'alice'))
        finally:
            api._caller_billing_view = orig


class TestApiWiring(unittest.TestCase):
    def test_handlers_exist(self):
        for fn in ('handle_timesheet_watchable', 'handle_timesheet_watchers',
                   'handle_timesheet_watcher_delete'):
            self.assertTrue(hasattr(api, fn), f'missing {fn}')

    def test_routes_registered(self):
        self.assertIn("('GET', '/api/timesheet/watchable'): handle_timesheet_watchable", _SRC)
        self.assertIn("('GET', '/api/timesheet/watchers'): handle_timesheet_watchers", _SRC)
        self.assertIn("('POST', '/api/timesheet/watchers'): handle_timesheet_watchers", _SRC)
        self.assertIn("/api/timesheet/watchers/') and m == 'DELETE'", _SRC)

    def test_mutations_admin_gated_and_audited(self):
        for fn in ('handle_timesheet_watcher_delete',):
            seg = _SRC[_SRC.index('def ' + fn): _SRC.index('def ' + fn) + 1200]
            self.assertIn('require_admin_auth()', seg)
            self.assertIn('audit_log(', seg)
        # the add path (POST branch of handle_timesheet_watchers)
        seg = _SRC[_SRC.index('def handle_timesheet_watchers'):
                   _SRC.index('def handle_timesheet_watcher_delete')]
        self.assertIn('require_admin_auth()', seg)
        self.assertIn("audit_log(actor, 'timesheet_watch_add'", seg)

    def test_timesheet_gate_uses_watch_helper(self):
        seg = _SRC[_SRC.index('def handle_timesheet('):
                   _SRC.index('def handle_timesheet(') + 1200]
        self.assertIn('_can_view_timesheet(actor, want_user)', seg)

    def test_entries_export_has_no_side_channel(self):
        # a watcher requesting ?user= must pass the same gate (no CSV bypass)
        seg = _SRC[_SRC.index('def handle_time_entries'):
                   _SRC.index('def handle_time_entries') + 2500]
        self.assertIn('_can_view_timesheet(actor, f_user)', seg)
        self.assertIn('cannot view another user', seg)   # 403 on a denied ?user=


class TestFrontendWiring(unittest.TestCase):
    def test_picker_and_admin_present(self):
        index = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="ts-watch-bar"', index)
        self.assertIn('id="tw-watcher"', index)
        self.assertIn('Timesheet watchers', index)
        billing = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-billing.js').read_text()
        for fn in ('function loadTimesheetWatchers', 'function addTimesheetWatcher',
                   'function tsPickWatch', 'function _tsRenderWatchBar'):
            self.assertIn(fn, billing)


if __name__ == '__main__':
    unittest.main()
