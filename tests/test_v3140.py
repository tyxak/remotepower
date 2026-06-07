#!/usr/bin/env python3
"""
Tests for v3.14.0 — per-account sidebar favorites, per-container stale-image
badge, and the fleet thermal roll-up ("hottest hosts") page.

Holds the strict version-surface pins for this release (loosened to regex on the
next bump) plus functional tests for the three new features and client wiring
smoke checks.
"""
import os
import re
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
                     'SCHEDULE_FILE', 'CMDS_FILE', 'SCRIPTS_FILE',
                     'SSH_KEY_BASELINE_FILE', 'SMART_HIST_FILE', 'UPTIME_FILE',
                     'CONFIRMATIONS_FILE', 'TENANTS_FILE'):
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

    # ── Tier-2 net-new wiring ───────────────────────────────────────────
    def test_container_logs_wiring(self):
        self.assertIn("function fetchContainerLogs", self.JS)
        self.assertIn('id="container-logs-modal"', self.HTML)

    def test_ssh_keys_page_wiring(self):
        self.assertIn("function loadSshKeys", self.JS)
        self.assertIn('data-page="ssh-keys"', self.HTML)
        self.assertIn('id="ssh-keys-thead"', self.HTML)

    def test_omnisearch_wiring(self):
        self.assertIn("Alert: ", self.JS)
        self.assertIn("CVEs: ", self.JS)
        self.assertIn("/cve/findings", self.JS)

    def test_power_page_wiring(self):
        self.assertIn("function loadPower", self.JS)
        self.assertIn('data-page="power"', self.HTML)
        self.assertIn('id="power-thead"', self.HTML)

    def test_disk_health_page_wiring(self):
        self.assertIn("function loadDiskHealth", self.JS)
        self.assertIn('data-page="disk-health"', self.HTML)

    def test_report_builder_wiring(self):
        self.assertIn("function saveReportDef", self.JS)
        self.assertIn("function loadReportDefs", self.JS)
        self.assertIn('id="rdef-sections"', self.HTML)


class TestSshKeyAudit(_HandlerBase):
    def test_fleet_audit_fingerprints_and_reuse(self):
        # a valid base64 key blob reused on two hosts (guaranteed-valid base64)
        import base64 as _b64
        blob = _b64.b64encode(b'\x00\x00\x00\x0bssh-ed25519' + b'K' * 32).decode()
        line = f'ssh-ed25519 {blob} alice@laptop'
        weak = f'ssh-dss {_b64.b64encode(b"dss-key-blob!").decode()} bob@old'
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}, 'd2': {'name': 'db'}})
        api.save(api.SSH_KEY_BASELINE_FILE, {
            'd1': {'root': [line, weak]},
            'd2': {'root': [line]},
        })
        me = self.call(api.handle_ssh_keys_fleet)
        self.assertEqual(me['count'], 3)
        self.assertEqual(me['weak'], 1)
        # the ed25519 key appears on 2 hosts → reuse count 2, flagged reused
        ed = [r for r in me['keys'] if r['type'] == 'ssh-ed25519']
        self.assertTrue(all(r['hosts'] == 2 for r in ed))
        self.assertEqual(me['reused'], 2)
        self.assertTrue(all(r['fingerprint'].startswith('SHA256:') for r in ed))
        # weak key sorted first
        self.assertTrue(me['keys'][0]['weak'])


class TestFleetPower(_HandlerBase):
    def test_power_rollup_and_on_battery(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a'}, 'd2': {'name': 'b'},
                                    'd3': {'name': 'no-power'}})
        api.save(api.HARDWARE_FILE, {
            'd1': {'ups': [{'name': 'apc', 'status': 'OL', 'battery_pct': 100,
                            'load_pct': 30, 'power_w': 120}]},
            'd2': {'ups': [{'name': 'eaton', 'status': 'OB DISCHRG', 'battery_pct': 80,
                            'power_w': 90}]},
            'd3': {'gpus': [{'name': 'gpu', 'power_w': 0}]},
        })
        api.method = lambda: 'GET'
        r = self.call(api.handle_fleet_power)
        self.assertEqual(r['total_watts'], 210.0)
        self.assertEqual(r['on_battery'], 1)
        self.assertTrue(r['hosts'][0]['on_battery'])  # on-battery sorted first


class TestDiskHealthPrediction(_HandlerBase):
    def test_reactive_failed_disk_is_critical(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api.save(api.HARDWARE_FILE, {'d1': {'smart': [
            {'device': '/dev/sda', 'serial': 'S1', 'health': 'FAILED', 'failed': True},
        ]}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_disk_health)
        self.assertEqual(r['critical'], 1)
        self.assertEqual(r['disks'][0]['risk'], 'critical')

    def test_growing_pending_sectors_predicts_eta(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api.save(api.HARDWARE_FILE, {'d1': {'smart': [
            {'device': '/dev/sda', 'serial': 'S1', 'health': 'PASSED', 'pending_sectors': 30},
        ]}})
        # 4 daily snapshots, pending sectors growing 10/day
        day = 86400
        samples = [{'date': f'd{i}', 'ts': 1_000_000 + i * day,
                    'pending': i * 10, 'realloc': 0, 'wear': None, 'temp': 40}
                   for i in range(4)]
        api.save(api.SMART_HIST_FILE, {'d1': {'S1': {'device': '/dev/sda', 'samples': samples}}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_disk_health)
        self.assertTrue(r['count'] >= 1)
        disk = r['disks'][0]
        self.assertIn(disk['risk'], ('high', 'critical'))
        self.assertIsNotNone(disk['eta_days'])   # trend → projected ETA

    def test_healthy_disk_not_listed(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api.save(api.HARDWARE_FILE, {'d1': {'smart': [
            {'device': '/dev/sda', 'serial': 'S1', 'health': 'PASSED',
             'reallocated_sectors': 0, 'pending_sectors': 0, 'wear_pct': 5},
        ]}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_disk_health)
        self.assertEqual(r['count'], 0)


class TestUpsIngest(_HandlerBase):
    def test_ups_section_ingested(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api._ingest_hardware('d1', 'web', {'ups': [
            {'name': 'apc', 'driver': 'apcupsd', 'status': 'ONLINE',
             'battery_pct': 100, 'load_pct': 25, 'power_w': 110, 'runtime_s': 1800},
        ]}, 123)
        rec = (api.load(api.HARDWARE_FILE) or {}).get('d1', {})
        self.assertEqual(rec['ups'][0]['power_w'], 110.0)
        self.assertEqual(rec['ups'][0]['status'], 'ONLINE')


class TestReportBuilder(_HandlerBase):
    def test_section_filter_keeps_only_requested(self):
        report = {'generated_ts': 1, 'server_version': '3.14.0', 'server_name': 'x',
                  'devices': {'total': 3}, 'cve': {'critical': 1}, 'health': {'score': 90},
                  'patches': {'total_pending': 2}}
        out = api._filter_report_sections(report, ['devices', 'cve'])
        self.assertIn('devices', out)
        self.assertIn('cve', out)
        self.assertNotIn('health', out)
        self.assertNotIn('patches', out)
        self.assertIn('server_name', out)   # metadata always kept

    def test_clean_report_def_validates(self):
        d = api._clean_report_def({'name': 'Weekly', 'sections': ['devices', 'bogus'],
                                   'format': 'csv', 'cron': '0 8 * * 1', 'enabled': True,
                                   'recipients': ['ops@x.com', 'bad']})
        self.assertEqual(d['name'], 'Weekly')
        self.assertEqual(d['sections'], ['devices'])   # bogus dropped
        self.assertEqual(d['format'], 'csv')
        self.assertEqual(d['recipients'], ['ops@x.com'])
        self.assertTrue(d['id'])

    def test_clean_report_def_rejects_bad_cron(self):
        self.assertEqual(api._clean_report_def(
            {'name': 'x', 'enabled': True, 'cron': 'not a cron'}), 'badcron')

    def test_save_and_delete_definition(self):
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'name': 'Ops', 'sections': ['health', 'cve']}
        r = self.call(api.handle_report_defs_save)
        self.assertTrue(r['ok'])
        did = r['definition']['id']
        defs = (api.load(api.CONFIG_FILE) or {}).get('report_definitions')
        self.assertEqual(len(defs), 1)
        api.method = lambda: 'DELETE'
        r2 = self.call(api.handle_report_def_delete, did)
        self.assertTrue(r2['ok'])
        self.assertEqual((api.load(api.CONFIG_FILE) or {}).get('report_definitions'), [])


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


class TestContainerSbom(_HandlerBase):
    def test_sbom_includes_container_components(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web', 'os': 'Ubuntu'}})
        api.save(api.PACKAGES_FILE, {'d1': {'packages': [{'name': 'nginx', 'version': '1.0'}],
                                            'pkg_manager': 'apt', 'os_id': 'ubuntu'}})
        api.save(api.CONTAINERS_FILE, {'d1': {'items': [
            {'name': 'web', 'image': 'nginx', 'tag': 'latest', 'repo_digest': 'sha256:abc', 'runtime': 'docker'},
        ]}})
        doc = api._build_sbom_doc('d1', {'name': 'web', 'os': 'Ubuntu'}, 'cyclonedx')
        comps = doc['components']
        ctr = [c for c in comps if c.get('type') == 'container']
        self.assertEqual(len(ctr), 1)
        self.assertTrue(ctr[0]['purl'].startswith('pkg:docker/nginx@sha256'))
        # host packages still present
        self.assertTrue(any(c.get('type') == 'library' for c in comps))

    def test_spdx_includes_container_package(self):
        api.save(api.PACKAGES_FILE, {'d1': {'packages': [], 'pkg_manager': 'apt'}})
        api.save(api.CONTAINERS_FILE, {'d1': {'items': [
            {'name': 'db', 'image': 'postgres', 'tag': '16', 'repo_digest': ''},
        ]}})
        doc = api._build_sbom_doc('d1', {'name': 'db', 'os': 'Ubuntu'}, 'spdx')
        pkgs = [p for p in doc['packages'] if p['name'] == 'postgres']
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0]['versionInfo'], '16')


class TestDriftPolicy(_HandlerBase):
    def test_policy_mode_resolves_by_tag_and_group(self):
        api.save(api.CONFIG_FILE, {'drift_enforce_policies': [
            {'scope': 'tag', 'value': 'prod', 'mode': 'enforce'},
            {'scope': 'group', 'value': 'db', 'mode': 'apply'},
        ]})
        self.assertEqual(api._drift_policy_mode({'tags': ['prod']}), 'enforce')
        self.assertEqual(api._drift_policy_mode({'group': 'db'}), 'apply')
        # apply (group) beats enforce (tag) when both match
        self.assertEqual(api._drift_policy_mode({'tags': ['prod'], 'group': 'db'}), 'apply')
        self.assertIsNone(api._drift_policy_mode({'tags': ['staging']}))

    def test_set_policies_sanitizes(self):
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'policies': [
            {'scope': 'tag', 'value': 'prod', 'mode': 'enforce'},
            {'scope': 'bogus', 'value': 'x', 'mode': 'apply'},       # bad scope → dropped
            {'scope': 'group', 'value': 'web', 'mode': 'nope'},      # bad mode → dropped
            {'scope': 'tag', 'value': 'prod', 'mode': 'apply'},      # dup (tag,prod) → dropped
        ]}
        r = self.call(api.handle_drift_policies_set)
        self.assertEqual(r['policies'], [{'scope': 'tag', 'value': 'prod', 'mode': 'enforce'}])


class TestUnstableHosts(_HandlerBase):
    def test_flags_frequent_restarters(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'flappy', 'last_boot_reason': 'power-loss'},
                                    'd2': {'name': 'steady'}})
        now = int(__import__('time').time())
        day = 86400
        # d1: 4 offline→online returns within 7 days; d2: 1
        d1_events = []
        for i in range(4):
            d1_events.append({'ts': now - (6 - i) * day, 'online': False})
            d1_events.append({'ts': now - (6 - i) * day + 60, 'online': True})
        api.save(api.UPTIME_FILE, {
            'd1': {'name': 'flappy', 'events': d1_events},
            'd2': {'name': 'steady', 'events': [{'ts': now - 3 * day, 'online': False},
                                                {'ts': now - 3 * day + 60, 'online': True}]},
        })
        rows = api._unstable_hosts_view(days=7, threshold=3)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['device'], 'flappy')
        self.assertEqual(rows[0]['restarts'], 4)
        self.assertEqual(rows[0]['last_boot_reason'], 'power-loss')

    def test_disk_health_endpoint_includes_unstable(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'x'}})
        api.save(api.HARDWARE_FILE, {})
        api.save(api.UPTIME_FILE, {})
        api.method = lambda: 'GET'
        r = self.call(api.handle_disk_health)
        self.assertIn('unstable', r)
        self.assertIn('unstable_count', r)


class TestMetricsPush(_HandlerBase):
    def test_config_round_trip(self):
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'enabled': True, 'url': 'http://pg:9091', 'interval': 30, 'job': 'rp!!'}
        r = self.call(api.handle_metrics_push_set)
        self.assertTrue(r['ok'])
        self.assertEqual(r['job'], 'rp')   # sanitized
        api.method = lambda: 'GET'
        g = self.call(api.handle_metrics_push_get)
        self.assertTrue(g['enabled'])
        self.assertEqual(g['url'], 'http://pg:9091')
        self.assertEqual(g['interval'], 30)

    def test_enabled_requires_url(self):
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'enabled': True, 'url': ''}
        self.call(api.handle_metrics_push_set)
        self.assertEqual(self.cap['s'], 400)

    def test_push_posts_to_pushgateway_then_gates(self):
        api.METRICS_PUSH_STATE_FILE = self.d / 'mps.json'
        api.save(api.CONFIG_FILE, {'metrics_push': {'enabled': True, 'url': 'http://pg:9091',
                                                    'interval': 60, 'job': 'rp'}})
        cap = {}

        class _Resp:
            status = 200

        class _Opener:
            def open(self, req, timeout=10):
                cap['url'] = req.full_url
                cap['data'] = req.data
                return _Resp()

        saved = (api._build_metrics_ctx, api.prometheus_export.generate_metrics,
                 api._ssrf_safe_opener, api._get_ssl_context)
        api._build_metrics_ctx = lambda: {}
        api.prometheus_export.generate_metrics = lambda ctx: 'rp_metric 1\n'
        api._ssrf_safe_opener = lambda **k: _Opener()
        api._get_ssl_context = lambda: None
        try:
            api._maybe_push_metrics()
            self.assertEqual(cap.get('url'), 'http://pg:9091/metrics/job/rp')
            self.assertIn(b'rp_metric', cap['data'])
            cap.clear()
            api._maybe_push_metrics()                 # within interval → no push
            self.assertNotIn('url', cap)
        finally:
            (api._build_metrics_ctx, api.prometheus_export.generate_metrics,
             api._ssrf_safe_opener, api._get_ssl_context) = saved


class TestAlertEvents(_HandlerBase):
    NEW = ('disk_predict_fail', 'ups_on_battery', 'ups_on_line',
           'cert_file_expiring', 'rogue_uid0')

    def test_events_fully_wired(self):
        for ev in self.NEW:
            self.assertIn(ev, api.WEBHOOK_EVENT_NAMES, ev)
            self.assertIn(ev, api.EVENT_KIND_MAP, f'{ev} not in a channel kind')
            self.assertFalse(api._webhook_title(ev).startswith('RemotePower: '),
                             f'{ev} has no friendly title')
        for ev in ('disk_predict_fail', 'ups_on_battery', 'cert_file_expiring', 'rogue_uid0'):
            self.assertIn(ev, api._ALERT_RULES, ev)
        self.assertEqual(api._ALERT_RECOVER.get('ups_on_line'), 'ups_on_battery')

    def _ingest(self, body):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        fired = []
        orig = api.fire_webhook
        api.fire_webhook = lambda ev, pl: fired.append((ev, pl))
        try:
            api._ingest_hardware('d1', 'web', body, 1_000_000)
        finally:
            api.fire_webhook = orig
        return [e for e, _ in fired]

    def test_ups_on_battery_then_on_line(self):
        on = self._ingest({'ups': [{'name': 'apc', 'status': 'OB DISCHRG', 'battery_pct': 80}]})
        self.assertIn('ups_on_battery', on)
        # same state again → no re-fire
        again = self._ingest({'ups': [{'name': 'apc', 'status': 'OB DISCHRG', 'battery_pct': 75}]})
        self.assertNotIn('ups_on_battery', again)
        # back on line → resolve event
        back = self._ingest({'ups': [{'name': 'apc', 'status': 'OL', 'battery_pct': 100}]})
        self.assertIn('ups_on_line', back)

    def test_cert_off_by_default(self):
        # opt-in: with cert_expiry_alerts_enabled unset, an expiring cert is silent
        api.save(api.CONFIG_FILE, {})
        body = {'cert_files': [{'path': '/etc/ssl/x.pem', 'not_after': 1_000_000 + 10 * 86400}]}
        self.assertNotIn('cert_file_expiring', self._ingest(body))

    def test_cert_expiring_fires_once_when_enabled(self):
        api.save(api.CONFIG_FILE, {'cert_expiry_alerts_enabled': True})
        body = {'cert_files': [{'path': '/etc/ssl/x.pem', 'not_after': 1_000_000 + 10 * 86400}]}
        self.assertIn('cert_file_expiring', self._ingest(body))
        self.assertNotIn('cert_file_expiring', self._ingest(body))   # edge-triggered

    def test_cert_ca_bundle_ignored(self):
        # server-side defense: CA-bundle paths never alert even if reported
        api.save(api.CONFIG_FILE, {'cert_expiry_alerts_enabled': True})
        body = {'cert_files': [{'path': '/etc/ssl/certs/ca123.pem', 'not_after': 1_000_000 + 5 * 86400}]}
        self.assertNotIn('cert_file_expiring', self._ingest(body))

    def test_cert_far_off_does_not_fire(self):
        api.save(api.CONFIG_FILE, {'cert_expiry_alerts_enabled': True})
        body = {'cert_files': [{'path': '/etc/ssl/y.pem', 'not_after': 1_000_000 + 200 * 86400}]}
        self.assertNotIn('cert_file_expiring', self._ingest(body))

    def test_cert_alert_title_has_path_and_days(self):
        title = api._alert_title('cert_file_expiring',
                                 {'name': 'web', 'path': '/etc/ssl/x.pem', 'days': 10})
        self.assertIn('/etc/ssl/x.pem', title)
        self.assertIn('10', title)
        self.assertNotEqual(title, 'cert_file_expiring: web')   # not the generic fallback

    def test_rogue_uid0_fires(self):
        body = {'accounts': [{'user': 'root', 'uid': 0, 'flags': []},
                             {'user': 'sneaky', 'uid': 0, 'flags': ['uid0']}]}
        fired = self._ingest(body)
        self.assertIn('rogue_uid0', fired)

    def test_disk_predict_fail_periodic(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api.save(api.HARDWARE_FILE, {'d1': {'smart': [
            {'device': '/dev/sda', 'serial': 'S1', 'health': 'PASSED', 'pending_sectors': 30}]}})
        day = 86400
        samples = [{'date': f'd{i}', 'ts': 1_000_000 + i * day,
                    'pending': i * 10, 'realloc': 0, 'wear': None, 'temp': 40} for i in range(4)]
        api.save(api.SMART_HIST_FILE, {'d1': {'S1': {'device': '/dev/sda', 'samples': samples}}})
        api.save(api.CONFIG_FILE, {})   # last_disk_predict_check unset → runs
        fired = []
        orig = api.fire_webhook
        api.fire_webhook = lambda ev, pl: fired.append(ev)
        try:
            api._maybe_check_disk_predictions()
        finally:
            api.fire_webhook = orig
        self.assertIn('disk_predict_fail', fired)


class TestApprovalGates(_HandlerBase):
    """v3.14.0 #29 — 4-eyes change-approval gates on risky actions."""

    def setUp(self):
        super().setUp()
        self._orig_perm = api.require_perm
        api.require_perm = lambda perm, ids=None: 'jakob'
        api.save(api.DEVICES_FILE, {'dev1': {'name': 'web'}})

    def tearDown(self):
        api.require_perm = self._orig_perm
        super().tearDown()

    def _pending(self):
        return (api.load(api.CONFIRMATIONS_FILE) or {}).get('confirmations', [])

    def _enable(self):
        api.save(api.CONFIG_FILE, {'change_approval_enabled': True})

    # --- off by default: actions queue straight through ---
    def test_reboot_queues_when_disabled(self):
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        self.call(api.handle_reboot)
        self.assertIn('reboot', (api.load(api.CMDS_FILE) or {}).get('dev1', []))
        self.assertEqual(self._pending(), [])

    # --- enabled: risky actions are parked, not queued ---
    def test_reboot_parked_when_enabled(self):
        self._enable()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        r = self.call(api.handle_reboot)
        self.assertEqual(self.cap['s'], 202)
        self.assertTrue(r['approval_required'])
        self.assertNotIn('reboot', (api.load(api.CMDS_FILE) or {}).get('dev1', []))
        self.assertEqual(len(self._pending()), 1)

    def test_upgrade_parked_when_enabled(self):
        self._enable()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        r = self.call(api.handle_upgrade_device)
        self.assertEqual(self.cap['s'], 202)
        self.assertTrue(r['approval_required'])
        self.assertEqual((api.load(api.CMDS_FILE) or {}).get('dev1', []), [])
        self.assertEqual(self._pending()[0]['params']['kind'], 'upgrade')

    def test_uninstall_parked_and_leaves_no_trace(self):
        self._enable()
        api.method = lambda: 'POST'
        r = self.call(api.handle_uninstall_agent, 'dev1')
        self.assertEqual(self.cap['s'], 202)
        self.assertTrue(r['approval_required'])
        self.assertEqual((api.load(api.CMDS_FILE) or {}).get('dev1', []), [])
        # device record must NOT be flagged until a second admin approves
        self.assertNotIn('agent_uninstalled',
                         (api.load(api.DEVICES_FILE) or {}).get('dev1', {}))

    def test_container_action_parked_when_enabled(self):
        self._enable()
        api.save(api.CONTAINERS_FILE,
                 {'dev1': {'ts': 1, 'items': [{'id': 'abc123', 'name': 'nginx'}]}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'runtime': 'docker', 'action': 'restart',
                                     'container_id': 'abc123'}
        r = self.call(api.handle_device_container_action, 'dev1')
        self.assertEqual(self.cap['s'], 202)
        self.assertTrue(r['approval_required'])
        self.assertEqual((api.load(api.CMDS_FILE) or {}).get('dev1', []), [])

    # --- approving a parked queue_command actually queues it ---
    def test_approved_queue_command_executes(self):
        res = api._mcp_execute('queue_command', 'dev1',
                               {'command': 'reboot', 'kind': 'reboot'},
                               'second-admin', None, None)
        self.assertNotEqual(res.get('ok'), False)
        self.assertIn('reboot', (api.load(api.CMDS_FILE) or {}).get('dev1', []))

    def test_command_kind_classifier(self):
        self.assertEqual(api._command_kind('reboot'), 'reboot')
        self.assertEqual(api._command_kind('container:docker:restart:x'), 'container')
        self.assertEqual(api._command_kind('exec:rm -rf /'), 'exec')
        self.assertEqual(api._command_kind('poll_interval:60'), 'poll')


class TestI18nWiring(unittest.TestCase):
    """v3.14.0 #26 — UI-only i18n (5 languages, translate-by-source-text)."""

    HTML = (_ROOT / "server/html/index.html").read_text()
    I18N = (_ROOT / "server/html/static/js/i18n.js").read_text()
    SW = (_ROOT / "server/html/sw.js").read_text()
    JS = client_js()

    def test_supported_langs(self):
        self.assertEqual(api.SUPPORTED_LANGS, ('en', 'zh', 'hi', 'es', 'ar'))

    def test_i18n_loads_before_app(self):
        i = self.HTML.index('static/js/i18n.js')
        a = self.HTML.index('static/js/app.js')
        self.assertLess(i, a, "i18n.js must be loaded before app.js")

    def test_i18n_precached(self):
        self.assertIn('/static/js/i18n.js', self.SW)

    def test_language_card_present(self):
        self.assertIn('id="acct-lang"', self.HTML)
        self.assertIn('data-i18n="Language"', self.HTML)

    def test_app_adopts_server_lang(self):
        self.assertIn('RPi18n.adopt(me.lang)', self.JS)

    def test_i18n_langs_match_server(self):
        # the JS LANGS array must equal the server allowlist
        m = re.search(r"var LANGS = \[([^\]]*)\]", self.I18N)
        self.assertIsNotNone(m)
        js_langs = tuple(x.strip().strip("'\"") for x in m.group(1).split(','))
        self.assertEqual(js_langs, api.SUPPORTED_LANGS)

    def test_every_translation_row_is_complete(self):
        # each '{ zh: …, hi: …, es: …, ar: … }' row must carry all 4 languages
        rows = re.findall(r"\{\s*zh:.*?\}", self.I18N, re.S)
        self.assertGreater(len(rows), 40)
        for r in rows:
            for lang in ('zh', 'hi', 'es', 'ar'):
                self.assertIn(lang + ':', r, f"row missing {lang}: {r[:50]}")

    def test_rtl_for_arabic(self):
        # Arabic must drive dir=rtl
        self.assertIn("RTL = { ar: true }", self.I18N)
        self.assertIn("'rtl'", self.I18N)


class TestI18nLangEndpoint(_HandlerBase):
    def setUp(self):
        super().setUp()
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin', 'created': 1}})

    def test_me_lang_defaults_english(self):
        api.method = lambda: 'GET'
        me = self.call(api.handle_me)
        self.assertEqual(me['lang'], 'en')

    def test_set_lang_persists_and_returns(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'lang': 'ar'}
        r = self.call(api.handle_me_lang)
        self.assertTrue(r['ok'])
        self.assertEqual(r['lang'], 'ar')
        self.assertEqual((api.load(api.USERS_FILE) or {})['jakob']['lang'], 'ar')
        api.method = lambda: 'GET'
        self.assertEqual(self.call(api.handle_me)['lang'], 'ar')

    def test_set_lang_rejects_unknown(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'lang': 'tlh'}   # Klingon — not supported
        self.call(api.handle_me_lang)
        self.assertEqual(self.cap['s'], 400)
        self.assertNotIn('lang', (api.load(api.USERS_FILE) or {})['jakob'])

    def test_set_lang_rejects_get(self):
        api.method = lambda: 'GET'
        api.get_json_body = lambda: {'lang': 'es'}
        self.call(api.handle_me_lang)
        self.assertEqual(self.cap['s'], 405)


class TestDashboardCustomization(unittest.TestCase):
    """v3.14.0 #22 — per-account customizable Home dashboard."""

    HTML = (_ROOT / "server/html/index.html").read_text()
    JS = client_js()
    CSS = (_ROOT / "server/html/static/css/styles.css").read_text()

    def test_widget_keys_match_between_server_and_client(self):
        # server allowlist must equal the client DASH_WIDGETS key list
        m = re.search(r"DASH_WIDGETS = \[(.*?)\];", self.JS, re.S)
        self.assertIsNotNone(m)
        js_keys = tuple(re.findall(r"key:\s*'([a-z]+)'", m.group(1)))
        self.assertEqual(js_keys, api.DASHBOARD_WIDGETS)

    def test_every_widget_card_tagged(self):
        for key in api.DASHBOARD_WIDGETS:
            self.assertIn(f'data-widget="{key}"', self.HTML,
                          f'home card for {key} missing data-widget')

    def test_customize_ui_present(self):
        self.assertIn('data-action="toggleDashEdit"', self.HTML)
        self.assertIn('id="dash-edit-panel"', self.HTML)
        self.assertIn('.dash-off', self.CSS)

    def test_layout_applied_and_persisted(self):
        self.assertIn('applyDashboardLayout()', self.JS)
        self.assertIn('_uiPrefs.dashboard', self.JS)
        self.assertIn('_scheduleFlushUiPrefs()', self.JS)

    def test_sanitiser_keeps_known_widgets_drops_unknown(self):
        clean = api._sanitise_ui_prefs({'dashboard': [
            {'key': 'roster', 'on': False},
            {'key': 'health', 'on': True},
            {'key': 'bogus', 'on': True},      # unknown → dropped
            {'key': 'roster', 'on': True},     # dup → dropped
            'not-a-dict',                       # junk → dropped
        ]})
        self.assertEqual(clean['dashboard'],
                         [{'key': 'roster', 'on': False},
                          {'key': 'health', 'on': True}])

    def test_sanitiser_defaults_on_true(self):
        clean = api._sanitise_ui_prefs({'dashboard': [{'key': 'links'}]})
        self.assertEqual(clean['dashboard'], [{'key': 'links', 'on': True}])

    def test_sanitiser_ignores_non_list_dashboard(self):
        clean = api._sanitise_ui_prefs({'dashboard': 'nope'})
        self.assertNotIn('dashboard', clean)

    def test_no_emoji_arrows_use_svg(self):
        # reorder buttons must use Lucide-style SVG, not unicode arrows/emoji
        self.assertIn('_SVG_UP', self.JS)
        self.assertNotIn('↑</button>', self.JS)


class TestCmdbScope(_HandlerBase):
    """v3.14.0 — RBAC hardening: CMDB endpoints must honour device scope, so a
    scoped (non-admin) role can't read or write CMDB for out-of-scope devices.
    (Closes a gap found auditing the existing 'soft multi-tenancy'.)"""

    def setUp(self):
        super().setUp()
        api.CMDB_FILE = self.d / 'cmdb.json'
        api.save(api.DEVICES_FILE, {
            'in1':  {'name': 'prod-web', 'tags': ['prod']},
            'out1': {'name': 'dev-box',  'tags': ['dev']},
        })
        # Simulate an operator whose role is scoped to the 'prod' tag.
        self._orig_scope = api._caller_scope
        api._caller_scope = lambda: {'type': 'tags', 'values': ['prod']}

    def tearDown(self):
        api._caller_scope = self._orig_scope
        super().tearDown()

    def test_list_only_shows_in_scope_assets(self):
        api.method = lambda: 'GET'
        out = self.call(api.handle_cmdb_list)
        self.assertEqual({e['device_id'] for e in out}, {'in1'})

    def test_update_blocked_out_of_scope(self):
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'asset_id': 'X'}
        self.call(api.handle_cmdb_update, 'out1')
        self.assertEqual(self.cap['s'], 403)

    def test_update_allowed_in_scope(self):
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'asset_id': 'A1'}
        self.call(api.handle_cmdb_update, 'in1')
        self.assertNotEqual(self.cap['s'], 403)   # scope lets it through

    def test_doc_add_blocked_out_of_scope(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'title': 't', 'body': 'b'}
        self.call(api.handle_cmdb_doc_add, 'out1')
        self.assertEqual(self.cap['s'], 403)

    def test_doc_update_blocked_out_of_scope(self):
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'title': 't', 'body': 'b'}
        self.call(api.handle_cmdb_doc_update, 'out1', 'doc_x')
        self.assertEqual(self.cap['s'], 403)

    def test_doc_delete_blocked_out_of_scope(self):
        api.method = lambda: 'DELETE'
        self.call(api.handle_cmdb_doc_delete, 'out1', 'doc_x')
        self.assertEqual(self.cap['s'], 403)

    def test_admin_sees_everything(self):
        # all-scope (admin) — _caller_scope returns None → no filtering
        api._caller_scope = lambda: None
        api.method = lambda: 'GET'
        out = self.call(api.handle_cmdb_list)
        self.assertEqual({e['device_id'] for e in out}, {'in1', 'out1'})


class TestBranding(_HandlerBase):
    """v3.14.0 #45 — in-app white-label branding (name + default accent)."""

    def test_me_returns_brand(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin', 'created': 1}})
        api.save(api.CONFIG_FILE, {'brand_name': 'Acme Cloud', 'brand_accent': 'emerald'})
        api.method = lambda: 'GET'
        me = self.call(api.handle_me)
        self.assertEqual(me['brand']['name'], 'Acme Cloud')
        self.assertEqual(me['brand']['accent'], 'emerald')

    def test_save_validates_accent(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'brand_name': 'X Corp', 'brand_accent': 'bogus'}
        self.call(api.handle_config_save)
        cfg = api.load(api.CONFIG_FILE) or {}
        self.assertEqual(cfg.get('brand_name'), 'X Corp')
        self.assertEqual(cfg.get('brand_accent'), '')          # invalid → cleared

    def test_save_accepts_valid_accent(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'brand_accent': 'violet'}
        self.call(api.handle_config_save)
        self.assertEqual((api.load(api.CONFIG_FILE) or {}).get('brand_accent'), 'violet')

    def test_brand_accents_match_js_presets(self):
        js = client_js()
        m = re.search(r"ACCENT_PRESETS = \[([^\]]*)\]", js)
        self.assertIsNotNone(m)
        js_set = {x.strip().strip("'\"") for x in m.group(1).split(',')}
        self.assertEqual(js_set, set(api.BRAND_ACCENTS))

    def test_branding_ui_present(self):
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertIn('id="cfg-brand-name"', html)
        self.assertIn('data-action="saveBranding"', html)


class TestThemesWiring(unittest.TestCase):
    """v3.14.0 #46 — accent presets + theme (dark/light/auto) picker, CSP-safe."""

    JS = client_js()
    CSS = (_ROOT / "server/html/static/css/styles.css").read_text()
    HTML = (_ROOT / "server/html/index.html").read_text()

    def test_accent_presets_defined(self):
        for name in ('emerald', 'violet', 'amber', 'rose', 'cyan'):
            self.assertIn(f'body[data-accent="{name}"]', self.CSS)

    def test_theme_functions(self):
        for fn in ('applyAccent', 'setAccent', 'onThemeSelect', '_buildAppearancePicker',
                   '_effectiveLight'):
            self.assertIn(fn, self.JS)
        self.assertIn("'auto'", self.JS)   # the follow-system theme option

    def test_auto_follows_system(self):
        self.assertIn('prefers-color-scheme', self.JS)

    def test_appearance_card_present(self):
        self.assertIn('id="acct-theme"', self.HTML)
        self.assertIn('id="acct-accent"', self.HTML)


class TestChargeback(_HandlerBase):
    """v3.14.0 #41 — per-group/tag power aggregation for cost allocation."""

    def test_breakdown_groups_tags_total(self):
        devices = {
            'd1': {'name': 'a', 'group': 'web', 'tags': ['prod']},
            'd2': {'name': 'b', 'group': 'web', 'tags': ['prod', 'eu']},
            'd3': {'name': 'c', 'group': 'db', 'tags': ['prod']},
            'd4': {'name': 'd', 'group': 'web', 'monitored': False},   # excluded
            'd5': {'name': 'e', 'group': 'idle'},                       # no power → excluded
        }
        hw = {
            'd1': {'ups': [{'power_w': 100}]},
            'd2': {'gpus': [{'power_w': 200}]},
            'd3': {'ups': [{'power_w': 50}]},
            'd4': {'ups': [{'power_w': 999}]},
            'd5': {},
        }
        bd = api._chargeback_breakdown(devices, hw)
        web = next(r for r in bd['groups'] if r['name'] == 'web')
        self.assertEqual((web['watts'], web['hosts']), (300.0, 2))
        prod = next(r for r in bd['tags'] if r['name'] == 'prod')
        self.assertEqual((prod['watts'], prod['hosts']), (350.0, 3))
        self.assertEqual((bd['total']['watts'], bd['total']['hosts']), (350.0, 3))
        self.assertAlmostEqual(web['kwh_month'], 300 / 1000 * 24 * 30.44, places=0)

    def test_handler_shape(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a', 'group': 'g'}})
        api.save(api.HARDWARE_FILE, {'d1': {'ups': [{'power_w': 120}]}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_fleet_chargeback)
        self.assertIn('groups', r)
        self.assertEqual(r['total']['watts'], 120.0)


class TestKeyboardNav(unittest.TestCase):
    """v3.14.0 #43 — `g <key>` nav + `?` cheat sheet, driven by one `_G_NAV`
    list so the shortcuts and their documentation can never drift apart."""

    JS = client_js()
    HTML = (_ROOT / "server/html/index.html").read_text()

    def test_single_source_of_truth(self):
        # Both the keymap and the cheat-sheet render from _G_NAV.
        self.assertIn('const _G_NAV =', self.JS)
        self.assertIn('_G_NAV_MAP', self.JS)
        self.assertIn('_G_NAV.map', self.JS)          # cheat sheet renders from it
        # The old hard-coded inline map must be gone.
        self.assertNotIn("const map = {h:'home'", self.JS)

    def test_every_gnav_page_exists(self):
        import re
        pairs = re.findall(r"\['([a-z])',\s*'([a-z]+)'", self.JS)
        # at least the canonical set, each pointing at a real page-<id>
        keys = {k for k, _ in pairs}
        for need in ('h', 'd', 'l', 's'):
            self.assertIn(need, keys)
        for _, page in pairs:
            self.assertIn(f'id="page-{page}"', self.HTML,
                          f'g-nav target page-{page} missing from index.html')

    def test_core_keybinds_present(self):
        self.assertIn('showKeyboardShortcuts', self.JS)
        self.assertIn("e.key === '?'", self.JS)
        self.assertIn("e.key.toLowerCase() === 'k'", self.JS)


class TestPackageHold(_HandlerBase):
    """v3.14.0 #39 — package hold/pin (apt-mark / versionlock / zypper lock)."""

    def test_build_hold_cmd(self):
        h = api._build_hold_cmd(['nginx', 'curl'], hold=True)
        self.assertIn('apt-mark hold nginx curl', h)
        self.assertIn('versionlock add nginx curl', h)
        u = api._build_hold_cmd(['nginx'], hold=False)
        self.assertIn('apt-mark unhold nginx', u)
        self.assertIn('versionlock delete nginx', u)

    def test_hold_queues_exec_command(self):
        api.BATCH_JOBS_FILE = self.d / 'batch.json'
        api.log_command = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1', 'packages': 'nginx'}
        self.call(api.handle_hold_packages)
        queued = api.load(api.CMDS_FILE).get('d1', [])
        self.assertTrue(any('apt-mark hold nginx' in c for c in queued), queued)

    def test_invalid_package_name_rejected(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1', 'packages': 'bad;rm -rf /'}
        self.call(api.handle_hold_packages)
        self.assertEqual(self.cap['s'], 400)


class TestEvidencePack(_HandlerBase):
    """v3.14.0 #44 — compliance evidence pack (bundles existing read-only data)."""

    def test_pack_structure_and_period_filter(self):
        import time as _t
        api.AUDIT_LOG_FILE = self.d / 'audit.json'
        api.COMPLIANCE_HIST_FILE = self.d / 'comp.json'
        now = int(_t.time())
        api.save(api.AUDIT_LOG_FILE, {'entries': [
            {'ts': now - 3600, 'actor': 'a', 'action': 'login'},
            {'ts': now - 200 * 86400, 'actor': 'old', 'action': 'ancient'},  # outside 90d
        ]})
        api.save(api.COMPLIANCE_HIST_FILE, {'fleet': [
            {'ts': now - 86400, 'pct': 88},
            {'ts': now - 200 * 86400, 'pct': 50},                            # outside 90d
        ]})
        os.environ['QUERY_STRING'] = 'days=90'
        api.method = lambda: 'GET'
        try:
            pack = self.call(api.handle_evidence_pack)
        finally:
            os.environ.pop('QUERY_STRING', None)
        self.assertEqual(pack['schema'], 'remotepower.evidence.v1')
        self.assertEqual(pack['period_days'], 90)
        self.assertIn('posture', pack)
        self.assertIn('server_version', pack)
        self.assertEqual(pack['audit_count'], 1)                 # ancient excluded
        self.assertEqual(len(pack['compliance_history']), 1)     # old sample excluded


class TestErrorBudget(unittest.TestCase):
    """v3.14.0 #40 — SLO error budget derived from the existing uptime/SLA data."""

    def test_budget_is_allowed_downtime(self):
        win = 100 * 86400
        eb = api._error_budget(99.0, 0, win)        # 99% target → 1% of window
        self.assertEqual(eb['budget_seconds'], int(0.01 * win))
        self.assertEqual(eb['used_pct'], 0.0)
        self.assertEqual(eb['remaining_seconds'], eb['budget_seconds'])

    def test_half_used(self):
        win = 100 * 86400
        full = api._error_budget(99.0, 0, win)['budget_seconds']
        eb = api._error_budget(99.0, full // 2, win)
        self.assertAlmostEqual(eb['used_pct'], 50.0, delta=0.5)
        self.assertEqual(eb['remaining_seconds'], full - full // 2)

    def test_breach_negative_remaining(self):
        win = 30 * 86400
        eb = api._error_budget(99.9, win, win)      # downtime >> budget
        self.assertLess(eb['remaining_seconds'], 0)
        self.assertGreater(eb['used_pct'], 100.0)

    def test_no_target_returns_none(self):
        self.assertIsNone(api._error_budget(None, 0, 86400))

    def test_100pct_target_zero_budget(self):
        self.assertEqual(api._error_budget(100.0, 0, 86400)['used_pct'], 0.0)
        self.assertEqual(api._error_budget(100.0, 60, 86400)['used_pct'], 100.0)

    def test_ui_wired(self):
        js = client_js()
        self.assertIn('error_budget', js)
        self.assertIn('Error budget', js)


class TestTenancyP1(_HandlerBase):
    """v3.14.0 #24 — multi-tenancy P1 FOUNDATION (registry + assignment only;
    behaviour-neutral — nothing is filtered by tenant yet)."""

    def test_list_has_default(self):
        api.method = lambda: 'GET'
        r = self.call(api.handle_tenants_list)
        ids = {t['id'] for t in r['tenants']}
        self.assertIn('default', ids)
        self.assertTrue(next(t for t in r['tenants'] if t['id'] == 'default')['builtin'])

    def test_create_and_count(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'name': 'Acme'}
        r = self.call(api.handle_tenant_create)
        self.assertTrue(r['ok'])
        tid = r['id']
        api.method = lambda: 'GET'
        lst = self.call(api.handle_tenants_list)
        self.assertIn(tid, {t['id'] for t in lst['tenants']})

    def test_create_duplicate_name_409(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'name': 'Dup'}
        self.call(api.handle_tenant_create)
        self.call(api.handle_tenant_create)
        self.assertEqual(self.cap['s'], 409)

    def test_assign_user_and_me_reflects_it(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin', 'created': 1}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'name': 'TeamA'}
        tid = self.call(api.handle_tenant_create)['id']
        api.get_json_body = lambda: {'username': 'jakob'}
        self.call(api.handle_tenant_assign_user, tid)
        self.assertEqual(api.load(api.USERS_FILE)['jakob']['tenant_id'], tid)
        self.assertEqual(api._user_tenant('jakob'), tid)
        api.method = lambda: 'GET'
        me = self.call(api.handle_me)
        self.assertEqual(me['tenant'], tid)

    def test_cannot_delete_default(self):
        api.method = lambda: 'DELETE'
        self.call(api.handle_tenant_delete, 'default')
        self.assertEqual(self.cap['s'], 400)

    def test_cannot_delete_tenant_with_users(self):
        api.save(api.USERS_FILE, {'u1': {'role': 'viewer', 'tenant_id': 'tn_x'}})
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'builtin': True},
                                    'tn_x': {'name': 'X', 'status': 'active'}})
        api.method = lambda: 'DELETE'
        self.call(api.handle_tenant_delete, 'tn_x')
        self.assertEqual(self.cap['s'], 409)

    def test_unknown_tenant_falls_back_to_default(self):
        api.save(api.USERS_FILE, {'u2': {'role': 'viewer', 'tenant_id': 'gone'}})
        self.assertEqual(api._user_tenant('u2'), 'default')


class TestScim(_HandlerBase):
    """v3.14.0 #30 — SCIM 2.0 provisioning (IdP-driven create + deactivate)."""

    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {'scim_enabled': True, 'scim_token': 'sekret'})
        os.environ['HTTP_AUTHORIZATION'] = 'Bearer sekret'
        os.environ.pop('QUERY_STRING', None)

    def tearDown(self):
        os.environ.pop('HTTP_AUTHORIZATION', None)
        os.environ.pop('QUERY_STRING', None)
        super().tearDown()

    def _create(self, user='alice@corp.com', active=True):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'schemas': [api.SCIM_USER_SCHEMA], 'userName': user,
                                     'active': active, 'name': {'formatted': 'A'},
                                     'emails': [{'value': user, 'primary': True}]}
        return self.call(api.handle_scim_users_collection)

    def test_disabled_returns_404(self):
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'GET'
        self.call(api.handle_scim_users_collection)
        self.assertEqual(self.cap['s'], 404)

    def test_bad_token_401(self):
        os.environ['HTTP_AUTHORIZATION'] = 'Bearer wrong'
        api.method = lambda: 'GET'
        self.call(api.handle_scim_users_collection)
        self.assertEqual(self.cap['s'], 401)

    def test_create_provisions_viewer(self):
        r = self._create()
        self.assertEqual(self.cap['s'], 201)
        self.assertEqual(r['userName'], 'alice')        # local part of the email
        self.assertTrue(r['active'])
        rec = api.load(api.USERS_FILE)['alice']
        self.assertTrue(rec['scim_managed'])
        self.assertEqual(rec['role'], 'viewer')
        self.assertFalse(rec.get('disabled'))

    def test_create_duplicate_409(self):
        self._create(); self._create()
        self.assertEqual(self.cap['s'], 409)

    def test_list_filter_by_username(self):
        self._create('bob@corp.com')
        os.environ['QUERY_STRING'] = 'filter=userName eq "bob"'
        api.method = lambda: 'GET'
        r = self.call(api.handle_scim_users_collection)
        self.assertEqual(r['totalResults'], 1)
        self.assertEqual(r['Resources'][0]['userName'], 'bob')

    def test_patch_deactivate_kills_sessions(self):
        import time as _t
        self._create('carol@corp.com')
        api.save(api.TOKENS_FILE, {'tok1': {'user': 'carol', 'created': int(_t.time()), 'ttl': 3600}})
        self.assertEqual(self._orig['verify_token']('tok1')[0], 'carol')   # works pre-deactivation
        api.method = lambda: 'PATCH'
        api.get_json_body = lambda: {'schemas': [api.SCIM_PATCH_SCHEMA],
                                     'Operations': [{'op': 'replace', 'value': {'active': False}}]}
        self.call(api.handle_scim_user, 'carol')
        self.assertTrue(api.load(api.USERS_FILE)['carol']['disabled'])
        self.assertEqual(self._orig['verify_token']('tok1'), (None, None))  # session dead

    def test_delete_deactivates(self):
        self._create('dave@corp.com')
        api.method = lambda: 'DELETE'
        self.call(api.handle_scim_user, 'dave')
        self.assertEqual(self.cap['s'], 204)
        self.assertTrue(api.load(api.USERS_FILE)['dave']['disabled'])

    def test_cannot_deactivate_last_admin(self):
        api.save(api.USERS_FILE, {'root': {'role': 'admin', 'created': 1}})
        api.method = lambda: 'DELETE'
        self.call(api.handle_scim_user, 'root')
        self.assertEqual(self.cap['s'], 409)
        self.assertFalse(api.load(api.USERS_FILE)['root'].get('disabled'))

    def test_reactivate_clears_disabled(self):
        self._create('erin@corp.com')
        api.method = lambda: 'PATCH'
        api.get_json_body = lambda: {'Operations': [{'op': 'replace', 'path': 'active', 'value': False}]}
        self.call(api.handle_scim_user, 'erin')
        self.assertTrue(api.load(api.USERS_FILE)['erin']['disabled'])
        api.get_json_body = lambda: {'Operations': [{'op': 'replace', 'path': 'active', 'value': True}]}
        self.call(api.handle_scim_user, 'erin')
        self.assertFalse(api.load(api.USERS_FILE)['erin']['disabled'])


class TestMetricTimeseriesSqlite(unittest.TestCase):
    """v3.14.0 — append-only metric time-series on the SQLite backend (the store
    behind 30-day Trend charts; JSON keeps only the recent metrics.json window)."""

    def setUp(self):
        import storage
        self.S = storage
        self.d = Path(tempfile.mkdtemp())
        self.S.configure(self.d)
        self.S.close_connection()

    def tearDown(self):
        self.S.close_connection()

    def test_append_range_prune(self):
        now = int(__import__('time').time())
        for i in range(48):
            self.S.metric_append(self.d, 'h1', now - i * 3600, float(i % 7), 50.0, 5.0, 30.0)
        r = self.S.metric_range(self.d, 'h1', now - 86400, max_points=40)
        self.assertTrue(all(set(p) == {'ts', 'cpu', 'mem', 'swap', 'disk'} for p in r))
        self.assertGreater(len(r), 0)
        self.assertAlmostEqual(r[0]['mem'], 50.0, places=1)
        removed = self.S.metric_prune(self.d, now - 86400)
        self.assertGreater(removed, 0)
        left = self.S.metric_range(self.d, 'h1', now - 5 * 86400, max_points=100)
        self.assertTrue(all(p['ts'] >= now - 86400 - 3600 for p in left))


class TestSSOProvisioning(_HandlerBase):
    """v3.14.0 — shared SSO provisioning + session minting (SAML prerequisite;
    OIDC now routes through these, password/LDAP login unchanged)."""

    def test_provision_creates_user_with_metadata(self):
        api.save(api.USERS_FILE, {})
        rec = api._provision_or_promote_user('alice', 'viewer',
                                             {'oidc_subject': 'sub-1'}, 'oidc')
        self.assertEqual(rec['role'], 'viewer')
        self.assertEqual(rec['oidc_subject'], 'sub-1')
        self.assertTrue(rec['password_hash'].startswith('!'))   # never matches
        self.assertEqual(api.load(api.USERS_FILE)['alice']['role'], 'viewer')

    def test_promote_viewer_to_admin(self):
        api.save(api.USERS_FILE, {'bob': {'role': 'viewer', 'created': 1}})
        rec = api._provision_or_promote_user('bob', 'admin', {}, 'oidc')
        self.assertEqual(rec['role'], 'admin')
        self.assertEqual(api.load(api.USERS_FILE)['bob']['role'], 'admin')

    def test_never_auto_demotes_admin(self):
        api.save(api.USERS_FILE, {'carol': {'role': 'admin', 'created': 1}})
        rec = api._provision_or_promote_user('carol', 'viewer', {}, 'oidc')
        self.assertEqual(rec['role'], 'admin')                  # stays admin

    def test_mint_session_resolves_via_verify_token(self):
        api.save(api.USERS_FILE, {'dave': {'role': 'admin', 'created': 1}})
        token = api._mint_session('dave', extra={'oidc': True})
        rec = api.load(api.TOKENS_FILE)[token]
        self.assertEqual(rec['user'], 'dave')
        self.assertTrue(rec['oidc'])
        self.assertIn('last_seen', rec)
        # _HandlerBase stubs verify_token; use the real one to prove resolution.
        self.assertEqual(self._orig['verify_token'](token), ('dave', 'admin'))


class TestMetricChartsWiring(unittest.TestCase):
    """v3.14.0 — richer per-device metric charts (time axis + overlay)."""

    JS = client_js()
    CSS = (_ROOT / "server/html/static/css/styles.css").read_text()

    def test_chart_helpers_present(self):
        for fn in ('_metricSeriesChart', '_metricsOverlayChart', '_mcGrid', '_fmtClock'):
            self.assertIn(fn, self.JS, f'{fn} missing')

    def test_timestamped_axis(self):
        # the grid builder must place clock labels on the x-axis
        self.assertIn('_fmtClock(ts)', self.JS)
        self.assertIn('text-anchor="middle"', self.JS)

    def test_overlay_and_stats(self):
        self.assertIn('All metrics', self.JS)        # combined overlay chart
        self.assertIn('metric-stats', self.JS)       # min/avg/max line
        self.assertIn('.metric-svg', self.CSS)

    def test_csp_safe_no_inline_style_in_charts(self):
        # charts must color via SVG fill/stroke attrs, never a style="" attribute
        seg = self.JS[self.JS.index('_metricSeriesChart'):self.JS.index('function openMetrics')]
        self.assertNotIn('style=', seg)


class TestGitOps(_HandlerBase):
    """v3.14.0 #27 — GitOps: drift profiles + assignments synced from a Git manifest."""

    def setUp(self):
        super().setUp()
        api.GITOPS_STATE_FILE = self.d / 'gitops_state.json'
        self._orig_fetch = api._gitops_fetch_manifest

    def tearDown(self):
        api._gitops_fetch_manifest = self._orig_fetch
        os.environ.pop('QUERY_STRING', None)
        super().tearDown()

    def test_config_off_by_default_and_no_secret_leak(self):
        api.save(api.CONFIG_FILE, {'gitops': {'enabled': True, 'url': 'https://x/m.json',
                                              'auth_header': 'Bearer SECRET'}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_gitops_get)
        self.assertTrue(r['enabled'])
        self.assertTrue(r['auth_header_set'])
        self.assertNotIn('auth_header', r)          # raw token never returned

    def test_set_requires_url_when_enabled(self):
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'enabled': True, 'url': ''}
        self.call(api.handle_gitops_set)
        self.assertEqual(self.cap['s'], 400)

    def test_set_clamps_interval_and_keeps_token(self):
        api.save(api.CONFIG_FILE, {'gitops': {'auth_header': 'Bearer KEEP'}})
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'enabled': True, 'url': 'https://h/m.json', 'interval': 5}
        self.call(api.handle_gitops_set)
        gc = api.load(api.CONFIG_FILE)['gitops']
        self.assertEqual(gc['interval'], 300)               # clamped to floor
        self.assertEqual(gc['auth_header'], 'Bearer KEEP')  # absent in body → preserved

    def test_reconcile_creates_profiles_and_assignments(self):
        api.save(api.CONFIG_FILE, {})
        manifest = {
            'profiles': [{'name': 'web', 'files': ['/etc/nginx/nginx.conf', '/etc/ssl/x.crt']}],
            'assignments': [{'scope_type': 'tag', 'scope_value': 'web', 'profile': 'web'}],
        }
        summary = api._gitops_reconcile(manifest, dry=False)
        self.assertEqual(summary['added'], 1)
        dr = api.load(api.CONFIG_FILE)['drift']
        prof = dr['profiles'][0]
        self.assertEqual(prof['source'], 'gitops')
        self.assertEqual(prof['files'], ['/etc/nginx/nginx.conf', '/etc/ssl/x.crt'])
        self.assertEqual(dr['assignments'][0]['profile_id'], prof['id'])
        self.assertEqual(dr['assignments'][0]['source'], 'gitops')

    def test_reconcile_idempotent_and_removes_dropped(self):
        api.save(api.CONFIG_FILE, {})
        api._gitops_reconcile({'profiles': [{'name': 'a', 'files': ['/a']},
                                            {'name': 'b', 'files': ['/b']}]}, dry=False)
        s2 = api._gitops_reconcile({'profiles': [{'name': 'a', 'files': ['/a']}]}, dry=False)
        self.assertEqual(s2['removed'], 1)
        names = {p['name'] for p in api.load(api.CONFIG_FILE)['drift']['profiles']}
        self.assertEqual(names, {'a'})

    def test_reconcile_never_clobbers_manual_profile(self):
        api.save(api.CONFIG_FILE, {'drift': {'profiles': [
            {'id': 'dp_manual', 'name': 'web', 'files': ['/hand/made']}]}})  # no source = manual
        summary = api._gitops_reconcile(
            {'profiles': [{'name': 'web', 'files': ['/from/git']}]}, dry=False)
        self.assertIn('web', summary['skipped'])
        prof = api.load(api.CONFIG_FILE)['drift']['profiles'][0]
        self.assertEqual(prof['files'], ['/hand/made'])     # untouched
        self.assertNotEqual(prof.get('source'), 'gitops')

    def test_dry_run_does_not_write(self):
        api.save(api.CONFIG_FILE, {})
        s = api._gitops_reconcile({'profiles': [{'name': 'x', 'files': ['/x']}]}, dry=True)
        self.assertTrue(s['dry'])
        self.assertEqual(s['added'], 1)
        self.assertEqual((api.load(api.CONFIG_FILE).get('drift') or {}).get('profiles', []), [])

    def test_sync_via_stubbed_fetch(self):
        api.save(api.CONFIG_FILE, {'gitops': {'url': 'https://h/m.json'}})
        api._gitops_fetch_manifest = lambda gc: {'profiles': [{'name': 'p', 'files': ['/p']}]}
        api.method = lambda: 'POST'
        os.environ['QUERY_STRING'] = ''
        r = self.call(api.handle_gitops_sync)
        self.assertTrue(r['ok'])
        self.assertEqual(r['added'], 1)

    def test_reconcile_rejects_bad_manifest(self):
        with self.assertRaises(ValueError):
            api._gitops_reconcile({'nope': 1}, dry=True)

    def test_ui_wired(self):
        html = (_ROOT / "server/html/index.html").read_text()
        js = client_js()
        self.assertIn('id="cfg-gitops-url"', html)
        self.assertIn('data-action="saveGitops"', html)
        self.assertIn('data-action="syncGitops"', html)
        self.assertIn('function loadGitops', js)
        self.assertIn("'/gitops'", js)

    def test_periodic_registered(self):
        api_src = (_ROOT / "server/cgi-bin/api.py").read_text()
        self.assertIn("_safe(_maybe_gitops_sync", api_src)


if __name__ == "__main__":
    unittest.main()
