#!/usr/bin/env python3
"""
Tests for v3.14.0 — per-account sidebar favorites, per-container stale-image
badge, and the fleet thermal roll-up ("hottest hosts") page.

Holds the strict version-surface pins for this release (loosened to regex on the
next bump) plus functional tests for the three new features and client wiring
smoke checks.
"""
import os
import tempfile

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))
sys.path.insert(0, str(Path(__file__).parent))

_spec = importlib.util.spec_from_file_location("api_v3140", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

from clientjs import client_js

VERSION = "3.14.0"


class TestVersionBumps(unittest.TestCase):
    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, VERSION)

    def test_agent_version(self):
        txt = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertIn(f"VERSION      = '{VERSION}'", txt)

    def test_agent_extensionless_matches_py(self):
        a = (_ROOT / "client/remotepower-agent.py").read_bytes()
        b = (_ROOT / "client/remotepower-agent").read_bytes()
        self.assertEqual(a, b, "agent .py and extensionless copy diverged "
                               "(run cp client/remotepower-agent.py client/remotepower-agent)")

    def test_sw_cache_name(self):
        txt = (_ROOT / "server/html/sw.js").read_text()
        self.assertIn(f"remotepower-shell-v{VERSION}", txt)

    def test_index_cache_bust(self):
        txt = (_ROOT / "server/html/index.html").read_text()
        self.assertIn(f"?v={VERSION}", txt)
        self.assertNotIn("?v=3.13.0", txt)

    def test_readme_badge(self):
        txt = (_ROOT / "README.md").read_text()
        self.assertIn(f"version-{VERSION}-blue", txt)

    def test_changelog_top_entry(self):
        txt = (_ROOT / "CHANGELOG.md").read_text()
        self.assertIn(f"v{VERSION}", txt[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{VERSION}.md").exists())

    def test_whats_new_card_present(self):
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertIn(f"What's new — v{VERSION}", html)


class _HandlerBase(unittest.TestCase):
    """Drive handlers directly with stubbed auth/request/respond."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'DEVICES_FILE', 'CONTAINERS_FILE',
                     'HARDWARE_FILE', 'IMAGE_UPDATES_FILE', 'IMAGE_IGNORE_FILE'):
            self._files[attr] = getattr(api, attr)
            base = Path(getattr(api, attr)).name
            setattr(api, attr, self.d / base)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'verify_token', 'get_token_from_request',
                       'audit_log', 'respond', 'method', 'get_json_body')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api.audit_log = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestFavorites(_HandlerBase):
    def test_clean_favorites_validates_and_dedupes(self):
        raw = ['p:devices', 'a:showMonitorSection:section-ports', 'h:https://x',
               'p:devices',            # dup → dropped
               'bad', 'x:nope', '', 5, # malformed → dropped
               'p:' + 'z' * 300]       # too long → dropped
        clean = api._clean_favorites(raw)
        self.assertEqual(clean, ['p:devices',
                                 'a:showMonitorSection:section-ports',
                                 'h:https://x'])

    def test_clean_favorites_caps_count(self):
        raw = [f'p:page{i}' for i in range(api.MAX_FAVORITES + 20)]
        self.assertEqual(len(api._clean_favorites(raw)), api.MAX_FAVORITES)

    def test_me_returns_favorites(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin', 'created': 1,
                                            'favorites': ['p:devices', 'p:logs']}})
        api.method = lambda: 'GET'
        me = self.call(api.handle_me)
        self.assertEqual(me['favorites'], ['p:devices', 'p:logs'])

    def test_me_favorites_defaults_empty(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin', 'created': 1}})
        api.method = lambda: 'GET'
        me = self.call(api.handle_me)
        self.assertEqual(me['favorites'], [])

    def test_favorites_set_persists_clean_list(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin', 'created': 1}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'favorites': ['p:devices', 'bad!', 'p:logs', 'p:devices']}
        r = self.call(api.handle_favorites_set)
        self.assertTrue(r['ok'])
        self.assertEqual(r['favorites'], ['p:devices', 'p:logs'])
        saved = (api.load(api.USERS_FILE) or {}).get('jakob', {}).get('favorites')
        self.assertEqual(saved, ['p:devices', 'p:logs'])

    def test_favorites_set_accepts_bare_list(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin', 'created': 1}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: ['p:cve']
        r = self.call(api.handle_favorites_set)
        self.assertEqual(r['favorites'], ['p:cve'])

    def test_favorites_set_rejects_non_post(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin'}})
        api.method = lambda: 'GET'
        api.get_json_body = lambda: []
        self.call(api.handle_favorites_set)
        self.assertEqual(self.cap['s'], 405)


class TestContainerStaleBadge(_HandlerBase):
    def _seed(self, items):
        api.save(api.DEVICES_FILE, {'dev1': {'name': 'web'}})
        api.save(api.CONTAINERS_FILE, {'dev1': {'ts': 1, 'items': items}})

    def test_stale_when_digest_differs(self):
        self._seed([{'name': 'nginx', 'image': 'nginx', 'tag': 'latest',
                     'repo_digest': 'sha256:OLD'}])
        api.save(api.IMAGE_UPDATES_FILE,
                 {'images': {'nginx:latest': {'registry_digest': 'sha256:NEW'}}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_device_containers, 'dev1')
        self.assertTrue(r['items'][0]['update_available'])

    def test_not_stale_when_digest_matches(self):
        self._seed([{'name': 'nginx', 'image': 'nginx', 'tag': 'latest',
                     'repo_digest': 'sha256:SAME'}])
        api.save(api.IMAGE_UPDATES_FILE,
                 {'images': {'nginx:latest': {'registry_digest': 'sha256:SAME'}}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_device_containers, 'dev1')
        self.assertFalse(r['items'][0]['update_available'])

    def test_not_stale_for_local_image(self):
        # No reported repo_digest → locally built / loaded → never "update available".
        self._seed([{'name': 'app', 'image': 'app', 'tag': 'dev', 'repo_digest': ''}])
        api.save(api.IMAGE_UPDATES_FILE,
                 {'images': {'app:dev': {'registry_digest': 'sha256:NEW'}}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_device_containers, 'dev1')
        self.assertFalse(r['items'][0]['update_available'])

    def test_ignored_ref_not_flagged(self):
        self._seed([{'name': 'nginx', 'image': 'nginx', 'tag': 'latest',
                     'repo_digest': 'sha256:OLD'}])
        api.save(api.IMAGE_UPDATES_FILE,
                 {'images': {'nginx:latest': {'registry_digest': 'sha256:NEW'}}})
        api.save(api.IMAGE_IGNORE_FILE,
                 {'nginx:latest': {'acked_digest': 'sha256:NEW'}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_device_containers, 'dev1')
        self.assertFalse(r['items'][0]['update_available'])

    def test_drawer_matches_fleet_view(self):
        # The shared _image_stale primitive must give the drawer the same verdict
        # the fleet Image Updates page computes per host.
        self.assertTrue(api._image_stale('sha256:OLD', 'sha256:NEW'))
        self.assertFalse(api._image_stale('sha256:SAME', 'sha256:SAME'))
        self.assertFalse(api._image_stale('', 'sha256:NEW'))
        self.assertFalse(api._image_stale('sha256:OLD', ''))


class TestFleetThermal(_HandlerBase):
    def test_rollup_picks_hottest_sensor_per_host(self):
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web'},
            'd2': {'name': 'db', 'monitored': False},   # excluded
            'd3': {'name': 'cold'},
            'd4': {'name': 'no-temps'},                  # omitted (no sensors)
        })
        api.save(api.HARDWARE_FILE, {
            'd1': {'ts': 5, 'temps': [{'label': 'Package', 'current_c': 80.0},
                                      {'label': 'Core', 'current_c': 70}],
                   'smart': [{'device': '/dev/sda', 'temperature_c': 40}]},
            'd3': {'ts': 5, 'temps': [{'label': 'cpu', 'current_c': 45}]},
            'd4': {'ts': 5, 'temps': []},
        })
        api.method = lambda: 'GET'
        r = self.call(api.handle_fleet_thermal)
        self.assertEqual(r['count'], 2)            # d2 excluded, d4 omitted
        self.assertEqual(r['hot'], 1)              # only d1 >= 75
        # hottest-first
        self.assertEqual([h['device'] for h in r['hosts']], ['web', 'cold'])
        web = r['hosts'][0]
        self.assertEqual(web['max_temp'], 80.0)
        self.assertEqual(web['sensor_label'], 'Package')
        self.assertEqual(web['sensor_type'], 'sensor')
        self.assertEqual(web['sensors'], 3)
        self.assertTrue(web['hot'])
        self.assertFalse(web['critical'])

    def test_smart_temp_can_win(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api.save(api.HARDWARE_FILE, {
            'd1': {'ts': 5, 'temps': [{'label': 'cpu', 'current_c': 50}],
                   'smart': [{'device': '/dev/nvme0', 'temperature_c': 90}]},
        })
        api.method = lambda: 'GET'
        r = self.call(api.handle_fleet_thermal)
        host = r['hosts'][0]
        self.assertEqual(host['max_temp'], 90.0)
        self.assertEqual(host['sensor_type'], 'disk')
        self.assertEqual(host['sensor_label'], '/dev/nvme0')
        self.assertTrue(host['critical'])          # >= 85


class TestClientWiring(unittest.TestCase):
    JS = client_js()
    HTML = (_ROOT / "server/html/index.html").read_text()
    CSS = (_ROOT / "server/html/static/css/styles.css").read_text()

    def test_favorites_server_sync(self):
        self.assertIn("_pushFavoritesToServer", self.JS)
        self.assertIn("_hydrateFavoritesFromServer", self.JS)
        self.assertIn("'/favorites'", self.JS)

    def test_stale_badge_wiring(self):
        self.assertIn("_updBadge", self.JS)
        self.assertIn("update_available", self.JS)
        self.assertIn(".upd-badge", self.CSS)

    def test_thermal_page_wiring(self):
        self.assertIn("function loadThermal", self.JS)
        self.assertIn("function _renderThermal", self.JS)
        self.assertIn("if (name === 'thermal')", self.JS)
        self.assertIn('data-page="thermal"', self.HTML)
        self.assertIn('id="page-thermal"', self.HTML)
        self.assertIn('id="thermal-thead"', self.HTML)


if __name__ == "__main__":
    unittest.main()
