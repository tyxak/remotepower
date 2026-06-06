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
                     'HARDWARE_FILE', 'IMAGE_UPDATES_FILE', 'IMAGE_IGNORE_FILE',
                     'TOKENS_FILE', 'CONFIG_FILE', 'KEV_EPSS_FILE',
                     'CVE_FINDINGS_FILE', 'CVE_IGNORE_FILE', 'PACKAGES_FILE',
                     'SCHEDULE_FILE', 'CMDS_FILE', 'SCRIPTS_FILE'):
            self._files[attr] = getattr(api, attr)
            base = Path(getattr(api, attr)).name
            setattr(api, attr, self.d / base)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', 'verify_token',
                       'get_token_from_request', 'audit_log', 'respond',
                       'method', 'get_json_body')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
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

    # ── Tier-1 batch wiring (v3.14.0) ───────────────────────────────────
    def test_sessions_wiring(self):
        self.assertIn("function loadSessions", self.JS)
        self.assertIn("function revokeSession", self.JS)
        self.assertIn("revokeOtherSessions", self.JS)
        self.assertIn('id="acct-sessions"', self.HTML)

    def test_saved_views_wiring(self):
        self.assertIn("function saveDeviceView", self.JS)
        self.assertIn("function applyDeviceView", self.JS)
        self.assertIn("toggleViewsMenu", self.JS)
        self.assertIn('id="views-dropdown"', self.HTML)
        self.assertIn(".views-dropdown", self.CSS)

    def test_kev_epss_wiring(self):
        self.assertIn("kev-badge", self.JS)
        self.assertIn("epss-chip", self.JS)
        self.assertIn('data-col="kev"', self.HTML)
        self.assertIn(".kev-badge", self.CSS)

    def test_hw_sections_wiring(self):
        # wear column, GPU / accounts / cert-file cards in the hardware drawer
        self.assertIn("wear_pct", self.JS)
        self.assertIn("Local accounts", self.JS)
        self.assertIn("Local certificate files", self.JS)
        self.assertIn(">GPUs<", self.JS)

    def test_power_schedule_wiring(self):
        self.assertIn('value="suspend"', self.HTML)
        self.assertIn('value="wol"', self.HTML)


class TestSessions(_HandlerBase):
    def _seed(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin'}, 'bob': {'role': 'admin'}})
        now = 1_000_000
        api.save(api.TOKENS_FILE, {
            't':     {'user': 'jakob', 'created': now, 'ttl': 10 ** 12, 'ip': '10.0.0.1', 'ua': 'Firefox', 'last_seen': now},
            'other': {'user': 'jakob', 'created': now, 'ttl': 10 ** 12, 'ip': '10.0.0.2', 'ua': 'curl', 'last_seen': now},
            'bobs':  {'user': 'bob',   'created': now, 'ttl': 10 ** 9},
        })

    def test_lists_only_own_sessions_with_current_flag(self):
        self._seed()
        api.method = lambda: 'GET'
        r = self.call(api.handle_me_sessions)
        self.assertEqual(r['count'], 2)                       # jakob's two, not bob's
        ids = {s['id'] for s in r['sessions']}
        self.assertIn(api._session_id('t'), ids)
        self.assertNotIn(api._session_id('bobs'), ids)
        cur = next(s for s in r['sessions'] if s['current'])
        self.assertEqual(cur['id'], api._session_id('t'))     # 't' is the request token
        # raw tokens never leak
        self.assertNotIn('t', ids)

    def test_revoke_one_session(self):
        self._seed()
        api.method = lambda: 'DELETE'
        r = self.call(api.handle_me_session_revoke, api._session_id('other'))
        self.assertTrue(r['ok'])
        self.assertNotIn('other', api.load(api.TOKENS_FILE))
        self.assertIn('t', api.load(api.TOKENS_FILE))          # current kept

    def test_cannot_revoke_other_users_session(self):
        self._seed()
        api.method = lambda: 'DELETE'
        self.call(api.handle_me_session_revoke, api._session_id('bobs'))
        self.assertEqual(self.cap['s'], 404)
        self.assertIn('bobs', api.load(api.TOKENS_FILE))       # bob's session untouched

    def test_revoke_others_keeps_current(self):
        self._seed()
        api.method = lambda: 'POST'
        r = self.call(api.handle_me_sessions_revoke_others)
        self.assertEqual(r['revoked'], 1)                      # 'other'
        toks = api.load(api.TOKENS_FILE)
        self.assertIn('t', toks)                               # current kept
        self.assertNotIn('other', toks)
        self.assertIn('bobs', toks)                            # bob untouched


class TestSavedViews(unittest.TestCase):
    def test_sanitise_accepts_views(self):
        out = api._sanitise_ui_prefs({'views': [
            {'name': 'Offline', 'page': 'devices', 'state': {'status': 'offline', 'q': 'web'}},
        ]})
        self.assertEqual(len(out['views']), 1)
        self.assertEqual(out['views'][0]['name'], 'Offline')
        self.assertEqual(out['views'][0]['state']['status'], 'offline')

    def test_sanitise_drops_malformed_views(self):
        out = api._sanitise_ui_prefs({'views': [
            {'name': '', 'page': 'devices', 'state': {}},      # no name
            {'name': 'x', 'page': '', 'state': {}},            # no page
            {'name': 'y', 'page': 'devices'},                  # no state
            'notadict',
            {'name': 'ok', 'page': 'devices', 'state': {'q': 'a'}},
        ]})
        self.assertEqual([v['name'] for v in out.get('views', [])], ['ok'])

    def test_views_count_capped(self):
        many = [{'name': f'v{i}', 'page': 'devices', 'state': {'q': str(i)}}
                for i in range(api.MAX_UI_PREFS_VIEWS + 10)]
        out = api._sanitise_ui_prefs({'views': many})
        self.assertLessEqual(len(out['views']), api.MAX_UI_PREFS_VIEWS)


class TestCveKevEpss(_HandlerBase):
    def test_enrich_stamps_kev_and_epss(self):
        kev = {'CVE-2024-0001'}
        epss = {'CVE-2024-0001': 0.97, 'CVE-2024-0002': 0.10}
        findings = [
            {'vuln_id': 'CVE-2024-0001', 'aliases': []},
            {'vuln_id': 'CVE-2024-0002', 'aliases': []},
            {'vuln_id': 'CVE-2024-9999', 'aliases': []},
        ]
        kev_count, epss_max = api._enrich_cve_findings(findings, kev, epss)
        self.assertEqual(kev_count, 1)
        self.assertEqual(epss_max, 0.97)
        self.assertTrue(findings[0]['kev'])
        self.assertEqual(findings[0]['epss'], 0.97)
        self.assertFalse(findings[1]['kev'])
        self.assertEqual(findings[2]['epss'], 0.0)

    def test_enrich_matches_via_alias(self):
        kev = {'CVE-2024-1111'}
        findings = [{'vuln_id': 'GHSA-xxxx', 'aliases': ['CVE-2024-1111']}]
        kev_count, _ = api._enrich_cve_findings(findings, kev, {})
        self.assertEqual(kev_count, 1)
        self.assertTrue(findings[0]['kev'])

    def test_findings_view_prioritises_kev(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a'}, 'd2': {'name': 'b'}})
        api.save(api.PACKAGES_FILE, {'d1': {'ecosystem': 'Ubuntu', 'count': 1},
                                     'd2': {'ecosystem': 'Ubuntu', 'count': 1}})
        api.save(api.CVE_FINDINGS_FILE, {
            'd1': {'scanned_at': 1, 'findings': [{'vuln_id': 'CVE-X', 'severity': 'low', 'aliases': []}]},
            'd2': {'scanned_at': 1, 'findings': [{'vuln_id': 'CVE-KEV', 'severity': 'low', 'aliases': []}]},
        })
        api.save(api.KEV_EPSS_FILE, {'kev': ['CVE-KEV'], 'epss': {}})
        api.method = lambda: 'GET'
        # _scope_filter_devices passes through with admin/no scope
        r = self.call(api.handle_cve_findings)
        self.assertEqual(r['summary']['kev'], 1)
        self.assertEqual(r['devices'][0]['name'], 'b')   # KEV device sorted first


class TestHardwareIngest(_HandlerBase):
    def _ingest(self, body):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api._ingest_hardware('d1', 'web', body, 1234)
        return (api.load(api.HARDWARE_FILE) or {}).get('d1', {})

    def test_wear_pct_clamped(self):
        rec = self._ingest({'smart': [
            {'device': '/dev/sda', 'health': 'PASSED', 'wear_pct': 42},
            {'device': '/dev/sdb', 'health': 'PASSED', 'wear_pct': 999},  # out of range → dropped
        ]})
        self.assertEqual(rec['smart'][0]['wear_pct'], 42)
        self.assertNotIn('wear_pct', rec['smart'][1])

    def test_gpus_cert_files_accounts_ingested(self):
        rec = self._ingest({
            'gpus': [{'vendor': 'nvidia', 'name': 'RTX 4090', 'util_pct': 50, 'temp_c': 60, 'power_w': 200}],
            'cert_files': [{'path': '/etc/ssl/x.pem', 'subject': 'CN=x', 'issuer': 'CN=ca', 'not_after': 99999}],
            'accounts': [{'user': 'root', 'uid': 0, 'shell': '/bin/bash', 'login': True,
                          'sudo': True, 'flags': []},
                         {'user': 'bad', 'uid': 0, 'shell': '/bin/bash', 'flags': ['uid0']}],
        })
        self.assertEqual(rec['gpus'][0]['name'], 'RTX 4090')
        self.assertEqual(rec['gpus'][0]['temp_c'], 60.0)
        self.assertEqual(rec['cert_files'][0]['not_after'], 99999)
        self.assertEqual(rec['accounts'][1]['flags'], ['uid0'])

    def test_thermal_rollup_includes_gpu(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'rig'}})
        api.save(api.HARDWARE_FILE, {'d1': {'ts': 1, 'temps': [{'label': 'cpu', 'current_c': 55}],
                                            'gpus': [{'name': 'RTX', 'temp_c': 88}]}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_fleet_thermal)
        host = r['hosts'][0]
        self.assertEqual(host['max_temp'], 88.0)
        self.assertEqual(host['sensor_type'], 'gpu')
        self.assertTrue(host['critical'])


class TestPowerSchedule(_HandlerBase):
    def test_accepts_suspend_and_wol(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web', 'mac': 'aa:bb:cc:dd:ee:ff'}})
        api.save(api.SCHEDULE_FILE, {'jobs': []})
        for cmd in ('suspend', 'wol'):
            api.method = lambda: 'POST'
            api.get_json_body = lambda c=cmd: {'device_id': 'd1', 'command': c, 'cron': '0 3 * * *'}
            r = self.call(api.handle_schedule_add)
            self.assertTrue(r['ok'], cmd)
            self.assertEqual(r['job']['command'], cmd)

    def test_shutdown_without_mac_warns(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})   # no mac
        api.save(api.SCHEDULE_FILE, {'jobs': []})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1', 'command': 'shutdown', 'cron': '0 3 * * *'}
        r = self.call(api.handle_schedule_add)
        self.assertTrue(r['ok'])
        self.assertIn('Wake-on-LAN', r['warning'])


if __name__ == "__main__":
    unittest.main()
