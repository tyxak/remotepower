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
import json
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


class TestProcessWatch(_HandlerBase):
    """v3.14.0 #36 — watched-process CPU/memory threshold alerting."""

    def setUp(self):
        super().setUp()
        self._pw_state = api.PROCESS_ALERT_STATE_FILE
        api.PROCESS_ALERT_STATE_FILE = self.d / 'process_alert_state.json'
        self._orig_fire = api.fire_webhook
        self.fired = []
        api.fire_webhook = lambda ev, pl: self.fired.append((ev, pl))

    def tearDown(self):
        api.PROCESS_ALERT_STATE_FILE = self._pw_state
        api.fire_webhook = self._orig_fire
        super().tearDown()

    def _watch(self, **kw):
        w = {'name': 'postgres', 'metric': 'cpu', 'threshold': 80}
        w.update(kw)
        api.save(api.CONFIG_FILE, {'process_watches': [w]})

    def test_breach_then_recover_edge_triggered(self):
        self._watch()
        # First breach → fires process_alert once.
        api._eval_process_watches('d1', 'web',
            [{'name': 'postgres', 'cpu': 92.0, 'mem': 5}], 1000)
        self.assertEqual([e for e, _ in self.fired], ['process_alert'])
        self.assertEqual(self.fired[0][1]['process'], 'postgres')
        self.assertEqual(self.fired[0][1]['value'], 92.0)
        # Still breaching → no duplicate fire.
        self.fired.clear()
        api._eval_process_watches('d1', 'web',
            [{'name': 'postgres', 'cpu': 95.0, 'mem': 5}], 1001)
        self.assertEqual(self.fired, [])
        # Drops below threshold → process_recovered.
        api._eval_process_watches('d1', 'web',
            [{'name': 'postgres', 'cpu': 10.0, 'mem': 5}], 1002)
        self.assertEqual([e for e, _ in self.fired], ['process_recovered'])

    def test_dropping_out_of_topn_recovers(self):
        self._watch()
        api._eval_process_watches('d1', 'web', [{'name': 'postgres', 'cpu': 90}], 1)
        self.fired.clear()
        # Process no longer in the top-N list at all → recovery.
        api._eval_process_watches('d1', 'web', [{'name': 'nginx', 'cpu': 5}], 2)
        self.assertEqual([e for e, _ in self.fired], ['process_recovered'])

    def test_mem_metric_and_no_match(self):
        self._watch(metric='mem', threshold=50)
        # CPU high but mem low → no fire (watch is on mem).
        api._eval_process_watches('d1', 'web',
            [{'name': 'postgres', 'cpu': 99, 'mem': 10}], 1)
        self.assertEqual(self.fired, [])
        # Mem crosses → fire.
        api._eval_process_watches('d1', 'web',
            [{'name': 'postgres', 'cpu': 1, 'mem': 70}], 2)
        self.assertEqual([e for e, _ in self.fired], ['process_alert'])
        self.assertEqual(self.fired[0][1]['metric'], 'mem')

    def test_config_validation(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'process_watches': [
            {'name': '  redis ', 'metric': 'MEM', 'threshold': 250},   # clamp 100, lower-case
            {'name': '', 'metric': 'cpu'},                              # dropped (no name)
            {'name': 'x', 'metric': 'bogus', 'threshold': 'nan'},      # metric→cpu, thr→80
        ]}
        self.call(api.handle_config_save)
        saved = (api.load(api.CONFIG_FILE) or {}).get('process_watches')
        self.assertEqual(len(saved), 2)
        self.assertEqual(saved[0], {'name': 'redis', 'metric': 'mem', 'threshold': 100.0})
        self.assertEqual(saved[1], {'name': 'x', 'metric': 'cpu', 'threshold': 80.0})

    def test_registries_wired(self):
        self.assertIn('process_alert', api.WEBHOOK_EVENT_NAMES)
        self.assertIn('process_recovered', api.WEBHOOK_EVENT_NAMES)
        self.assertEqual(api._alert_severity('process_alert',
            {'metric': 'cpu', 'value': 90, 'threshold': 80}), 'medium')
        self.assertEqual(api.EVENT_KIND_MAP.get('process_alert'), 'process')
        self.assertEqual(api._ALERT_RECOVER.get('process_recovered'), 'process_alert')
        title = api._alert_title('process_alert',
            {'name': 'web', 'process': 'postgres', 'metric': 'cpu',
             'value': 92.0, 'threshold': 80})
        self.assertIn('postgres', title)
        self.assertIn('CPU', title)


class TestSiemStreaming(_HandlerBase):
    """v3.14.0 #34 — stream fleet events / alerts to a SIEM (Splunk/Elastic/
    Loki/raw) with vendor-correct envelopes + auth schemes."""

    def _rec(self):
        return api._siem_record('device_offline',
                                {'device_id': 'd1', 'name': 'web'})

    def test_record_has_severity_and_title(self):
        r = self._rec()
        self.assertEqual(r['event'], 'device_offline')
        self.assertEqual(r['host'], 'web')
        self.assertEqual(r['severity'], 'critical')  # device_offline → _ALERT_RULES
        self.assertIn('web', r['title'])

    def test_splunk_envelope(self):
        t, body, h = api._siem_envelope('splunk', 'https://hec:8088/services/collector',
                                        self._rec(), 'TOK', 1000)
        self.assertEqual(t, 'https://hec:8088/services/collector')
        self.assertEqual(h['Authorization'], 'Splunk TOK')
        doc = json.loads(body)
        self.assertEqual(doc['time'], 1000)
        self.assertEqual(doc['event']['event'], 'device_offline')

    def test_elastic_envelope(self):
        t, body, h = api._siem_envelope('elastic', 'https://es:9200/rp/_doc',
                                        self._rec(), 'KEY', 1000)
        self.assertEqual(h['Authorization'], 'ApiKey KEY')
        self.assertIn('@timestamp', json.loads(body))

    def test_loki_envelope_appends_push_path(self):
        t, body, h = api._siem_envelope('loki', 'https://loki:3100',
                                        self._rec(), '', 1000)
        self.assertEqual(t, 'https://loki:3100/loki/api/v1/push')
        doc = json.loads(body)
        self.assertEqual(doc['streams'][0]['values'][0][0], str(1000 * 10**9))
        self.assertNotIn('Authorization', h)         # no token → no header

    def test_raw_envelope(self):
        t, body, h = api._siem_envelope('raw', 'https://x/ingest',
                                        self._rec(), 'B', 1000)
        self.assertEqual(h['Authorization'], 'Bearer B')
        self.assertEqual(json.loads(body)['source'], 'remotepower')

    def test_forward_respects_enabled_and_url(self):
        sent = []
        orig = api._siem_post
        api._siem_post = lambda url, data, headers, cfg: sent.append(url)
        try:
            api._forward_siem('device_offline', {'name': 'w'}, {})          # disabled
            api._forward_siem('device_offline', {'name': 'w'},
                              {'siem_enabled': True})                        # no url
            self.assertEqual(sent, [])
            api._forward_siem('device_offline', {'name': 'w'}, {
                'siem_enabled': True, 'siem_format': 'loki',
                'siem_url': 'https://loki:3100'})
            self.assertEqual(sent, ['https://loki:3100/loki/api/v1/push'])
        finally:
            api._siem_post = orig

    def test_config_validation_and_secret(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'siem_enabled': True, 'siem_format': 'splunk',
                                     'siem_url': 'https://hec:8088/x', 'siem_token': 'sekret'}
        self.call(api.handle_config_save)
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual(cfg['siem_format'], 'splunk')
        self.assertEqual(cfg['siem_token'], 'sekret')
        # GET must surface the *_set flag but never the token itself.
        api.method = lambda: 'GET'
        got = self.call(api.handle_config_get)
        self.assertTrue(got['siem_token_set'])
        self.assertNotIn('siem_token', got)

    def test_config_rejects_bad_format(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'siem_format': 'kafka'}
        self.call(api.handle_config_save)
        self.assertEqual(self.cap['s'], 400)


class TestHaBridge(_HandlerBase):
    """v3.14.0 #49 — read-only Home Assistant bridge at /api/ha."""

    def _set_qs(self, token):
        os.environ['QUERY_STRING'] = f'token={token}' if token is not None else ''

    def tearDown(self):
        os.environ.pop('QUERY_STRING', None)
        super().tearDown()

    def test_requires_token(self):
        api.save(api.CONFIG_FILE, {})           # no status token configured
        self._set_qs('x')
        self.call(api.handle_ha_bridge)
        self.assertEqual(self.cap['s'], 403)

    def test_rejects_wrong_token(self):
        api.save(api.CONFIG_FILE, {'status_token': 'correct'})
        self._set_qs('wrong')
        self.call(api.handle_ha_bridge)
        self.assertEqual(self.cap['s'], 403)

    def test_flat_ha_shape(self):
        api.save(api.CONFIG_FILE, {'status_token': 'tok'})
        now = int(__import__('time').time())
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'a', 'last_seen': now, 'monitored': True},
            'd2': {'name': 'b', 'last_seen': 1, 'monitored': True},      # offline
            'd3': {'name': 'c', 'last_seen': now, 'agentless': True},    # skipped
        })
        self._set_qs('tok')
        r = self.call(api.handle_ha_bridge)
        # HA needs a flat, scalar `state` + attributes (no nested dicts).
        self.assertIn(r['state'], ('ok', 'warning', 'critical'))
        self.assertIn(r['problem'], ('on', 'off'))
        self.assertEqual(r['devices_total'], 2)
        self.assertEqual(r['devices_online'], 1)
        self.assertEqual(r['devices_offline'], 1)
        for k in ('alerts_critical', 'alerts_warning', 'alerts_info', 'alerts_total'):
            self.assertIsInstance(r[k], int)
        # Every attribute must be a scalar (HA json_attributes can't nest).
        for v in r.values():
            self.assertNotIsInstance(v, (dict, list))

    def test_exempt_from_ip_allowlist(self):
        self.assertIn('/api/ha', api._IP_ALLOWLIST_EXEMPT_PATHS)


class TestBandwidth(unittest.TestCase):
    """v3.14.0 #37 — per-interface bandwidth (agent collector + ingest + UI)."""

    JS = client_js()
    API = (_ROOT / "server/cgi-bin/api.py").read_text()
    AGENT = (_ROOT / "client/remotepower-agent.py").read_text()
    AGENT_X = (_ROOT / "client/remotepower-agent").read_text()
    WIN = (_ROOT / "client/remotepower-agent-win.py").read_text()

    def test_agent_collects_net_io(self):
        self.assertIn('def collect_net_io', self.AGENT)
        self.assertIn('net_io_counters(pernic=True)', self.AGENT)
        self.assertIn("'network_io': collect_net_io()", self.AGENT)
        # diff-based rate needs a previous sample retained between heartbeats
        self.assertIn('_prev_net_io', self.AGENT)

    def test_extensionless_agent_in_sync(self):
        self.assertEqual(self.AGENT, self.AGENT_X)

    def test_windows_agent_parity(self):
        self.assertIn('_collect_net_io', self.WIN)
        self.assertIn("info['network_io']", self.WIN)

    def test_server_sanitizes_network_io(self):
        # The allowlist block must clamp the rate/total fields and keep iface.
        self.assertIn("'network_io' in si", self.API)
        self.assertIn("safe_si['network_io']", self.API)
        for k in ('rx_bps', 'tx_bps', 'rx_total', 'tx_total'):
            self.assertIn(k, self.API)

    def test_ui_renders_bandwidth_table(self):
        self.assertIn('_fmtBps', self.JS)
        self.assertIn('si.network_io', self.JS)
        self.assertIn('Network bandwidth', self.JS)
        # box-overflow rule: variable-row table must be capped/scrollable
        idx = self.JS.find('Network bandwidth')
        self.assertIn('scrollable-table-wrap', self.JS[idx:idx + 600])


class TestOtlpExport(_HandlerBase):
    """v3.14.0 #28 — OTLP/HTTP metrics export (push, interval-gated)."""

    def setUp(self):
        super().setUp()
        self._otlp_state = api.OTLP_STATE_FILE
        api.OTLP_STATE_FILE = self.d / 'otlp_state.json'
        self._orig_post = api._siem_post
        self.posts = []
        api._siem_post = lambda url, data, headers, cfg: self.posts.append((url, data, headers))

    def tearDown(self):
        api.OTLP_STATE_FILE = self._otlp_state
        api._siem_post = self._orig_post
        super().tearDown()

    def test_endpoint_appends_metrics_path(self):
        self.assertEqual(api._otlp_endpoint('http://c:4318'), 'http://c:4318/v1/metrics')
        self.assertEqual(api._otlp_endpoint('http://c:4318/v1/metrics'),
                         'http://c:4318/v1/metrics')
        self.assertEqual(api._otlp_endpoint(''), '')

    def test_payload_is_spec_shaped(self):
        p = api._otlp_payload([('remotepower.devices.online', 5)], 1700000000000000000)
        dp = p['resourceMetrics'][0]['scopeMetrics'][0]['metrics'][0]['gauge']['dataPoints'][0]
        # OTLP/JSON encodes int64 fields as STRINGS
        self.assertEqual(dp['asInt'], '5')
        self.assertEqual(dp['timeUnixNano'], '1700000000000000000')

    def test_export_gated_on_enabled_and_endpoint(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a', 'last_seen': 1, 'monitored': True}})
        api._export_otlp({})                                         # disabled
        api._export_otlp({'otlp_enabled': True})                     # no endpoint
        self.assertEqual(self.posts, [])
        api._export_otlp({'otlp_enabled': True, 'otlp_endpoint': 'http://c:4318'})
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.posts[0][0], 'http://c:4318/v1/metrics')

    def test_interval_gate(self):
        api.save(api.CONFIG_FILE, {'otlp_enabled': True, 'otlp_endpoint': 'http://c:4318',
                                   'otlp_interval': 60})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a', 'last_seen': 1}})
        api._maybe_export_otlp()
        api._maybe_export_otlp()            # immediately again — gated out
        self.assertEqual(len(self.posts), 1)

    def test_config_validation_and_secret(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'otlp_enabled': True,
                                     'otlp_endpoint': 'http://c:4318',
                                     'otlp_interval': 5, 'otlp_token': 'sk'}
        self.call(api.handle_config_save)
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual(cfg['otlp_interval'], 15)           # clamped up to floor
        self.assertEqual(cfg['otlp_token'], 'sk')
        api.method = lambda: 'GET'
        got = self.call(api.handle_config_get)
        self.assertTrue(got['otlp_token_set'])
        self.assertNotIn('otlp_token', got)

    def test_test_endpoint_requires_enabled(self):
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'POST'
        self.call(api.handle_otlp_test)
        self.assertEqual(self.cap['s'], 400)


class TestReleaseChannels(_HandlerBase):
    """v3.14.0 #38 — agent release channels (inert until a beta binary ships)."""

    def setUp(self):
        super().setUp()
        self._beta = api._AGENT_BETA_PATH
        api._AGENT_BETA_PATH = self.d / 'remotepower-agent-beta'

    def tearDown(self):
        api._AGENT_BETA_PATH = self._beta
        os.environ.pop('QUERY_STRING', None)
        super().tearDown()

    def test_defaults_to_stable(self):
        os.environ['QUERY_STRING'] = ''
        self.assertEqual(api._resolve_agent_channel(), 'stable')

    def test_beta_requested_but_not_published_is_stable(self):
        os.environ['QUERY_STRING'] = 'channel=beta'
        self.assertEqual(api._resolve_agent_channel(), 'stable')  # no beta binary

    def test_beta_resolves_only_when_published(self):
        api._AGENT_BETA_PATH.write_bytes(b'#!/usr/bin/env python3\n')
        os.environ['QUERY_STRING'] = 'channel=beta'
        self.assertEqual(api._resolve_agent_channel(), 'beta')

    def test_device_channel_via_query(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a', 'update_channel': 'beta'}})
        api._AGENT_BETA_PATH.write_bytes(b'x')
        os.environ['QUERY_STRING'] = 'device_id=d1'
        self.assertEqual(api._resolve_agent_channel(), 'beta')

    def test_device_update_validates_channel(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a'}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'update_channel': 'BETA'}
        self.call(api.handle_device_save_bulk, 'd1')
        self.assertEqual((api.load(api.DEVICES_FILE))['d1']['update_channel'], 'beta')
        api.get_json_body = lambda: {'update_channel': 'nonsense'}
        self.call(api.handle_device_save_bulk, 'd1')
        self.assertEqual((api.load(api.DEVICES_FILE))['d1']['update_channel'], 'stable')


class TestSecretsScan(_HandlerBase):
    """v3.14.0 #35 — secrets-on-disk scanning. Redaction + edge-trigger + mute."""

    def setUp(self):
        super().setUp()
        self._sec_file = api.SECRETS_FILE
        api.SECRETS_FILE = self.d / 'secret_findings.json'
        self._orig_fire = api.fire_webhook
        self.fired = []
        api.fire_webhook = lambda ev, pl: self.fired.append((ev, pl))

    def tearDown(self):
        api.SECRETS_FILE = self._sec_file
        api.fire_webhook = self._orig_fire
        super().tearDown()

    def _finding(self, fp='abc123', rule='aws_access_key', **kw):
        f = {'fingerprint': fp, 'rule': rule, 'path': '/etc/app.env',
             'line': 3, 'preview': 'AKIA****…(20)'}
        f.update(kw)
        return f

    def test_value_is_never_stored(self):
        # Even if a (buggy/malicious) agent includes the raw secret, the server
        # allowlist must drop it — only redacted fields survive.
        api._ingest_secret_findings('d1', 'web',
            [self._finding(value='AKIAIOSFODNN7EXAMPLE', secret='supersecret')])
        rec = (api.load(api.SECRETS_FILE))['d1']['findings'][0]
        self.assertNotIn('value', rec)
        self.assertNotIn('secret', rec)
        self.assertEqual(rec['preview'], 'AKIA****…(20)')

    def test_edge_trigger_once_per_new_fingerprint(self):
        api._ingest_secret_findings('d1', 'web', [self._finding(fp='f1')])
        self.assertEqual([e for e, _ in self.fired], ['secret_exposed'])
        self.assertEqual(self.fired[0][1]['count'], 1)
        # Same fingerprint again → no re-fire.
        self.fired.clear()
        api._ingest_secret_findings('d1', 'web', [self._finding(fp='f1')])
        self.assertEqual(self.fired, [])
        # A new one fires again.
        api._ingest_secret_findings('d1', 'web',
            [self._finding(fp='f1'), self._finding(fp='f2')])
        self.assertEqual([e for e, _ in self.fired], ['secret_exposed'])

    def test_muted_fingerprint_does_not_fire(self):
        api.save(api.CONFIG_FILE, {'secrets_mutes': ['f9']})
        api._ingest_secret_findings('d1', 'web', [self._finding(fp='f9')])
        self.assertEqual(self.fired, [])
        rec = (api.load(api.SECRETS_FILE))['d1']['findings'][0]
        self.assertTrue(rec['muted'])

    def test_mute_endpoint_round_trip(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'fingerprint': 'fX'}
        self.call(api.handle_secrets_mute)
        self.assertIn('fX', (api.load(api.CONFIG_FILE))['secrets_mutes'])
        api.get_json_body = lambda: {'fingerprint': 'fX', 'unmute': True}
        self.call(api.handle_secrets_mute)
        self.assertNotIn('fX', (api.load(api.CONFIG_FILE))['secrets_mutes'])

    def test_fleet_endpoint_scoped_and_counts(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api.save(api.CONFIG_FILE, {'secrets_scan_enabled': True, 'secrets_mutes': ['m1']})
        api.save(api.SECRETS_FILE, {'d1': {'findings': [
            self._finding(fp='a1'), self._finding(fp='m1')], 'ts': 1}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_fleet_secrets)
        self.assertTrue(r['enabled'])
        self.assertEqual(r['total_active'], 1)            # m1 is muted
        self.assertEqual(len(r['devices'][0]['findings']), 2)

    def test_config_validation(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'secrets_scan_enabled': True,
                                     'secrets_scan_paths': ['/etc', '/etc', '  '],
                                     'secrets_mutes': ['x', 'x', 'y']}
        self.call(api.handle_config_save)
        cfg = api.load(api.CONFIG_FILE)
        self.assertTrue(cfg['secrets_scan_enabled'])
        self.assertEqual(cfg['secrets_scan_paths'], ['/etc'])   # deduped, blank dropped
        self.assertEqual(cfg['secrets_mutes'], ['x', 'y'])

    def test_registries_wired(self):
        self.assertIn('secret_exposed', api.WEBHOOK_EVENT_NAMES)
        self.assertEqual(api._alert_severity('secret_exposed',
            {'rule': 'aws_access_key', 'path': '/x'}), 'high')
        self.assertEqual(api.EVENT_KIND_MAP.get('secret_exposed'), 'secrets')
        t = api._alert_title('secret_exposed',
            {'name': 'web', 'rule': 'aws_access_key', 'path': '/etc/x', 'count': 2})
        self.assertIn('aws_access_key', t)
        self.assertIn('+1 more', t)


class TestSecretsAgentParity(unittest.TestCase):
    """v3.14.0 #35 — both agents scan + redact; the Linux scanner never emits a
    raw secret value (the load-bearing privacy property)."""

    AGENT = (_ROOT / "client/remotepower-agent.py").read_text()
    AGENT_X = (_ROOT / "client/remotepower-agent").read_text()
    WIN = (_ROOT / "client/remotepower-agent-win.py").read_text()

    def test_both_agents_have_scanner(self):
        for src in (self.AGENT, self.WIN):
            self.assertIn('def collect_secret_findings', src)
            self.assertIn('def _redact_secret', src)
            self.assertIn('fingerprint', src)

    def test_extensionless_in_sync(self):
        self.assertEqual(self.AGENT, self.AGENT_X)

    def test_linux_scanner_redacts(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("rp_agent_sec",
                                                      _ROOT / "client/remotepower-agent.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        import shutil
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)   # don't litter /tmp with the fixture
        (Path(d) / 'creds.env').write_text(
            "AWS_KEY = AKIAIOSFODNN7EXAMPLE\npassword = supersecret12345\n")
        findings = mod.collect_secret_findings([d])
        self.assertTrue(findings)
        for f in findings:
            # No raw secret anywhere in what we'd transmit.
            blob = json.dumps(f)
            self.assertNotIn('AKIAIOSFODNN7EXAMPLE', blob)
            self.assertNotIn('supersecret12345', blob)
            self.assertEqual(len(f['fingerprint']), 16)


class TestCisRemediation(_HandlerBase):
    """v3.14.0 #31 — one-click CIS remediation (opt-in, gated via _queue_command)."""

    def setUp(self):
        super().setUp()
        self._orig_fire = api.fire_webhook
        api.fire_webhook = lambda ev, pl: None      # avoid heavy side effects

    def tearDown(self):
        api.fire_webhook = self._orig_fire
        super().tearDown()

    def test_remediation_map_is_distro_aware_and_partial(self):
        dev = {'sysinfo': {'packages': {'manager': 'apt'}}}
        self.assertEqual(api._cis_remediation('cis-reboot', dev)['command'], 'reboot')
        self.assertEqual(api._cis_remediation('cis-failed', dev)['command'],
                         'exec:systemctl reset-failed')
        self.assertEqual(api._cis_remediation('cis-patches', dev)['command'],
                         'exec:apt-get -y upgrade')
        # No safe auto-fix for these → advisory only.
        self.assertIsNone(api._cis_remediation('cis-disk', dev))
        self.assertIsNone(api._cis_remediation('cis-swap', dev))
        # No package manager known → no patch remediation.
        self.assertIsNone(api._cis_remediation('cis-patches', {'sysinfo': {}}))

    def test_requires_per_host_optin(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})   # opt-in NOT set
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1', 'check_id': 'cis-reboot'}
        self.call(api.handle_compliance_remediate)
        self.assertEqual(self.cap['s'], 403)

    def test_queues_fix_when_opted_in(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web', 'remediation_enabled': True}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1', 'check_id': 'cis-reboot'}
        self.call(api.handle_compliance_remediate)
        self.assertIn('reboot', (api.load(api.CMDS_FILE) or {}).get('d1', []))

    def test_non_remediable_check_rejected(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web', 'remediation_enabled': True}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1', 'check_id': 'cis-swap'}
        self.call(api.handle_compliance_remediate)
        self.assertEqual(self.cap['s'], 400)

    def test_report_exposes_remediable(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web', 'remediation_enabled': True,
            'sysinfo': {'reboot_required': True,
                        'packages': {'manager': 'apt', 'upgradable': 5}}}})
        d = api._compute_compliance(api.load(api.DEVICES_FILE))['devices'][0]
        self.assertTrue(d['remediation_enabled'])
        self.assertIn('cis-reboot', d['remediable'])   # reboot_required → fails + fixable
        self.assertIn('cis-patches', d['remediable'])  # 5 pending → fails + fixable

    def test_device_save_validates_flag(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'remediation_enabled': True}
        self.call(api.handle_device_save_bulk, 'd1')
        self.assertTrue((api.load(api.DEVICES_FILE))['d1']['remediation_enabled'])


class TestLogOutbox(unittest.TestCase):
    """v3.14.0 #47 — store-and-forward: a failed log submission is buffered and
    folded into the next successful one (oldest first), not dropped."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "rp_agent_outbox", _ROOT / "client/remotepower-agent.py")
        cls.ag = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.ag)

    def setUp(self):
        import shutil
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.ag.STATE_DIR = self.d
        self.ag.LOG_OUTBOX_FILE = self.d / 'log_outbox.json'
        self.addCleanup(setattr, self.ag, 'http_post', self.ag.http_post)
        self.addCleanup(setattr, self.ag, 'get_unit_logs', self.ag.get_unit_logs)
        self.creds = {'server_url': 'http://x', 'device_id': 'd', 'token': 't'}

    def test_merge_orders_buffered_first_and_caps(self):
        m = self.ag._merge_log_payloads({'u': [1, 2]}, {'u': [3, 4]})
        self.assertEqual(m['u'], [1, 2, 3, 4])      # buffered (older) first
        big = {'u': list(range(self.ag._LOG_OUTBOX_MAX_LINES + 100))}
        capped = self.ag._merge_log_payloads(big, {'u': [999]})
        self.assertLessEqual(sum(len(v) for v in capped.values()),
                             self.ag._LOG_OUTBOX_MAX_LINES)
        self.assertEqual(capped['u'][-1], 999)      # newest kept

    def test_buffer_on_failure_then_replay_on_success(self):
        self.ag.get_unit_logs = lambda unit: ['oops-line']
        def boom(*a, **k):
            raise OSError('server down')
        self.ag.http_post = boom
        self.assertFalse(self.ag.submit_unit_logs(self.creds, ['sshd']))
        self.assertTrue(self.ag.LOG_OUTBOX_FILE.exists())     # buffered, not lost

        sent = {}
        def ok_post(url, payload, timeout=15):
            sent.update(payload)
            return {}
        self.ag.get_unit_logs = lambda unit: ['fresh-line']
        self.ag.http_post = ok_post
        self.assertTrue(self.ag.submit_unit_logs(self.creds, ['sshd']))
        # Both the buffered and the fresh line went out, oldest first…
        self.assertEqual(sent['units']['sshd'], ['oops-line', 'fresh-line'])
        # …and the outbox is cleared once the backlog is delivered.
        self.assertFalse(self.ag.LOG_OUTBOX_FILE.exists())


class TestWebPushCrypto(unittest.TestCase):
    """v3.14.0 #42 — Web Push crypto: the RFC 8188 §3.1 vector + a full RFC 8291
    ECDH round-trip + VAPID JWT structure."""

    @classmethod
    def setUpClass(cls):
        import importlib
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        cls.wp = importlib.import_module("webpush")

    def test_rfc8188_section_3_1_vector(self):
        wp = self.wp
        ikm = wp.b64u_decode("yqdlZ-tYemfogSmv7Ws5PQ")
        salt = wp.b64u_decode("I1BsxtFttlv3u_Oo94xnmw")
        out = wp.aes128gcm_record(b"I am the walrus", ikm, salt, keyid=b'', rs=4096)
        self.assertEqual(
            wp.b64u_encode(out),
            "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg")

    def test_full_ecdh_roundtrip(self):
        wp = self.wp
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os
        ua_priv = ec.generate_private_key(ec.SECP256R1())
        ua_pub = ua_priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        auth = os.urandom(16)
        body = wp.encrypt(b'{"title":"hi"}', wp.b64u_encode(ua_pub), wp.b64u_encode(auth))
        salt, idlen = body[:16], body[20]
        as_pub_bytes, ct = body[21:21 + idlen], body[21 + idlen:]
        as_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_pub_bytes)
        ecdh = ua_priv.exchange(ec.ECDH(), as_pub)
        ikm = HKDF(hashes.SHA256(), 32, auth,
                   b'WebPush: info\x00' + ua_pub + as_pub_bytes).derive(ecdh)
        cek = HKDF(hashes.SHA256(), 16, salt, b'Content-Encoding: aes128gcm\x00').derive(ikm)
        nonce = HKDF(hashes.SHA256(), 12, salt, b'Content-Encoding: nonce\x00').derive(ikm)
        self.assertEqual(AESGCM(cek).decrypt(nonce, ct, None).rstrip(b'\x02'), b'{"title":"hi"}')

    def test_vapid_jwt_structure(self):
        wp = self.wp
        pem, pub = wp.generate_vapid_keys()
        h = wp.vapid_headers('https://fcm.googleapis.com/fcm/send/x', pem, 'mailto:a@b.c', now=1000)
        self.assertTrue(h['Authorization'].startswith('vapid t='))
        jwt = h['Authorization'].split('t=', 1)[1].split(',')[0].strip()
        self.assertEqual(len(jwt.split('.')), 3)        # header.payload.sig
        hdr = json.loads(wp.b64u_decode(jwt.split('.')[0]))
        self.assertEqual(hdr['alg'], 'ES256')


class TestWebPushServer(_HandlerBase):
    """v3.14.0 #42 — subscription storage, send-gating, secret handling."""

    def setUp(self):
        super().setUp()
        self._subs = api.PUSH_SUBS_FILE
        api.PUSH_SUBS_FILE = self.d / 'push_subscriptions.json'

    def tearDown(self):
        api.PUSH_SUBS_FILE = self._subs
        super().tearDown()

    def _sub_body(self, ep='https://push.example/abc'):
        return {'subscription': {'endpoint': ep,
                                 'keys': {'p256dh': 'BPxxx', 'auth': 'YWJj'}}}

    def test_subscribe_then_unsubscribe(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: self._sub_body()
        self.call(api.handle_push_subscribe)
        self.assertEqual(len((api.load(api.PUSH_SUBS_FILE))['jakob']), 1)
        api.get_json_body = lambda: {'endpoint': 'https://push.example/abc'}
        self.call(api.handle_push_unsubscribe)
        self.assertNotIn('jakob', api.load(api.PUSH_SUBS_FILE) or {})

    def test_subscribe_rejects_bad(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'subscription': {'endpoint': 'http://insecure', 'keys': {}}}
        self.call(api.handle_push_subscribe)
        self.assertEqual(self.cap['s'], 400)

    def test_subscribe_blocks_internal_endpoint(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'subscription': {
            'endpoint': 'https://127.0.0.1/x', 'keys': {'p256dh': 'B', 'auth': 'a'}}}
        self.call(api.handle_push_subscribe)
        self.assertEqual(self.cap['s'], 400)        # SSRF guard

    def test_send_hook_only_high_critical(self):
        api.save(api.CONFIG_FILE, {'webpush_enabled': True})
        sent = []
        orig = api._webpush_send_all
        api._webpush_send_all = lambda *a, **k: sent.append(a) or 1
        try:
            api._maybe_webpush('device_offline', {'name': 'web'})   # critical
            api._maybe_webpush('command_queued', {'name': 'web'})   # no severity
            self.assertEqual(len(sent), 1)
        finally:
            api._webpush_send_all = orig

    def test_disabled_send_is_noop(self):
        api.save(api.CONFIG_FILE, {})           # webpush disabled
        self.assertEqual(api._webpush_send_all('t', 'b'), 0)

    def test_vapid_key_never_leaked(self):
        api.save(api.CONFIG_FILE, {'webpush_enabled': True,
                                   'vapid_private_key': '-----BEGIN PRIVATE KEY-----x'})
        api.method = lambda: 'GET'
        got = self.call(api.handle_config_get)
        self.assertTrue(got['vapid_keyed'])
        self.assertNotIn('vapid_private_key', got)


class TestTenancyP2(_HandlerBase):
    """v3.14.0 (#24 P2) — tenant isolation. The load-bearing property: with
    enforcement ON, a tenant admin sees ONLY their tenant's devices, a superadmin
    sees all, and it's fully inert when OFF."""

    def setUp(self):
        super().setUp()
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'builtin': True},
                                    'acme': {'name': 'Acme', 'status': 'active'}})
        api.save(api.USERS_FILE, {
            'super':     {'role': 'admin', 'tenant_id': 'default'},
            'acmeadmin': {'role': 'admin', 'tenant_id': 'acme'},
        })
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'def-host', 'tenant': 'default'},
            'd2': {'name': 'acme-host', 'tenant': 'acme'},
        })
        self._orig_pathinfo = api.path_info
        self.addCleanup(setattr, api, 'path_info', self._orig_pathinfo)

    def _as(self, user, role='admin'):
        api.verify_token = lambda t: (user, role)

    def _enforce(self, on=True):
        api.save(api.CONFIG_FILE, {'tenancy_enforced': on})

    # ── the core isolation invariants ────────────────────────────────────────
    def test_inert_when_disabled(self):
        self._as('acmeadmin')                       # enforcement OFF (no config)
        out = api._scope_filter_devices(api.load(api.DEVICES_FILE))
        self.assertEqual(set(out), {'d1', 'd2'})    # sees everything, as P1

    def test_tenant_admin_is_confined(self):
        self._enforce(); self._as('acmeadmin')
        out = api._scope_filter_devices(api.load(api.DEVICES_FILE))
        self.assertEqual(set(out), {'d2'})          # ONLY Acme's device

    def test_superadmin_sees_all_tenants(self):
        self._enforce(); self._as('super')
        out = api._scope_filter_devices(api.load(api.DEVICES_FILE))
        self.assertEqual(set(out), {'d1', 'd2'})

    def test_device_list_endpoint_isolates(self):
        self._enforce(); self._as('acmeadmin')
        api.method = lambda: 'GET'
        os.environ['QUERY_STRING'] = ''
        self.addCleanup(os.environ.pop, 'QUERY_STRING', None)
        rows = self.call(api.handle_devices_list)
        self.assertEqual({d['id'] for d in rows}, {'d2'})

    def test_cross_tenant_single_device_blocked(self):
        self._enforce(); self._as('acmeadmin')
        self.call(api._scope_block_device, 'd1')    # default-tenant device
        self.assertEqual(self.cap.get('s'), 403)

    def test_own_tenant_device_not_blocked(self):
        self._enforce(); self._as('acmeadmin')
        self.cap.clear()
        self.call(api._scope_block_device, 'd2')    # own tenant
        self.assertIsNone(self.cap.get('s'))

    def test_enforce_device_scope_blocks_path(self):
        self._enforce(); self._as('acmeadmin')
        api.path_info = lambda: '/api/devices/d1/reboot'
        self.call(api._enforce_device_scope)
        self.assertEqual(self.cap.get('s'), 403)

    # ── tenant assignment is superadmin-only ─────────────────────────────────
    def test_tenant_reassign_requires_superadmin(self):
        self._enforce()
        api.method = lambda: 'POST'
        self._as('acmeadmin')                       # tenant admin: must NOT move it
        api.get_json_body = lambda: {'tenant': 'default'}
        self.call(api.handle_device_save_bulk, 'd2')
        self.assertEqual(api.load(api.DEVICES_FILE)['d2'].get('tenant'), 'acme')
        self._as('super')                           # superadmin: may
        api.get_json_body = lambda: {'tenant': 'acme'}
        self.call(api.handle_device_save_bulk, 'd1')
        self.assertEqual(api.load(api.DEVICES_FILE)['d1']['tenant'], 'acme')

    def test_config_flag_roundtrip(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'tenancy_enforced': True}
        self.call(api.handle_config_save)
        self.assertTrue(api.load(api.CONFIG_FILE)['tenancy_enforced'])
        api.method = lambda: 'GET'
        self.assertTrue(self.call(api.handle_config_get)['tenancy_enforced'])


class TestProxmoxLifecycle(_HandlerBase):
    """v3.14.0 #33 — Proxmox VM/CT lifecycle (destructive, gated)."""

    @classmethod
    def setUpClass(cls):
        import importlib
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        cls.pc = importlib.import_module("proxmox_client")

    def test_client_builds_correct_paths(self):
        pc, calls = self.pc, []
        orig = pc._request
        pc._request = lambda c, path, method='GET', data=None: (
            calls.append((path, method, data)) or 'UPID:x')
        try:
            n = {'node': 'pve'}
            pc.lifecycle(n, 'qemu', 100, 'reboot')
            pc.lifecycle(n, 'lxc', 200, 'snapshot', {'snapname': 'preupd'})
            pc.lifecycle(n, 'qemu', 100, 'snapshot_delete', {'snapname': 'preupd'})
            pc.lifecycle(n, 'qemu', 100, 'clone', {'newid': 999})
            pc.lifecycle(n, 'qemu', 100, 'migrate', {'target': 'pve2', 'online': True})
        finally:
            pc._request = orig
        bym = {c[0]: c[1] for c in calls}
        self.assertEqual(bym['/nodes/pve/qemu/100/status/reboot'], 'POST')
        self.assertIn('/nodes/pve/lxc/200/snapshot', bym)
        self.assertEqual(bym['/nodes/pve/qemu/100/snapshot/preupd'], 'DELETE')
        self.assertIn('/nodes/pve/qemu/100/clone', bym)
        self.assertIn('/nodes/pve/qemu/100/migrate', bym)

    def test_client_rejects_bad_input(self):
        E = self.pc.ProxmoxError
        with self.assertRaises(E):
            self.pc.lifecycle({'node': 'pve'}, 'qemu', 1, 'snapshot', {'snapname': '1bad'})
        with self.assertRaises(E):
            self.pc.lifecycle({'node': 'pve'}, 'bogus', 1, 'reboot')
        with self.assertRaises(E):
            self.pc.lifecycle({'node': 'pve'}, 'qemu', 1, 'migrate', {'target': 'bad!'})

    def test_handler_requires_optin(self):
        api.save(api.CONFIG_FILE, {'proxmox_enabled': True})   # lifecycle OFF
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'guest_type': 'qemu', 'vmid': 100, 'action': 'reboot'}
        self.call(api.handle_proxmox_lifecycle)
        self.assertEqual(self.cap['s'], 403)

    def test_handler_dry_run_does_not_execute(self):
        api.save(api.CONFIG_FILE, {'proxmox_enabled': True, 'proxmox_lifecycle_enabled': True})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'guest_type': 'qemu', 'vmid': 100,
                                     'action': 'reboot', 'dry': True}
        r = self.call(api.handle_proxmox_lifecycle)
        self.assertTrue(r['dry'])
        self.assertIn('reboot', r['planned'])

    def test_handler_parks_for_4eyes(self):
        api.save(api.CONFIG_FILE, {'proxmox_enabled': True, 'proxmox_lifecycle_enabled': True,
                                   'change_approval_enabled': True})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'guest_type': 'qemu', 'vmid': 100, 'action': 'stop'}
        self.call(api.handle_proxmox_lifecycle)
        self.assertEqual(self.cap['s'], 202)
        self.assertTrue(self.cap['b'].get('approval_required'))


_EC2_SAMPLE_XML = """<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
 <reservationSet><item><instancesSet><item>
   <instanceId>i-0abc123</instanceId><instanceType>t3.micro</instanceType>
   <privateIpAddress>10.0.0.5</privateIpAddress><ipAddress>1.2.3.4</ipAddress>
   <instanceState><name>running</name></instanceState>
   <placement><availabilityZone>eu-west-1a</availabilityZone></placement>
   <tagSet><item><key>Name</key><value>web-1</value></item></tagSet>
 </item></instancesSet></item></reservationSet>
</DescribeInstancesResponse>"""


class TestCloudImport(_HandlerBase):
    """v3.14.0 #32 — AWS EC2 inventory import (SigV4 + parse + device mapping)."""

    @classmethod
    def setUpClass(cls):
        import importlib
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        cls.ci = importlib.import_module("cloud_import")

    def test_sigv4_get_vanilla_vector(self):
        auth, _sh, _ph = self.ci.sigv4_authorization(
            'GET', 'example.amazonaws.com', 'us-east-1', 'service', '/', '', b'',
            'AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            '20150830T123600Z', '20150830')
        self.assertEqual(auth.split('Signature=')[1],
                         '5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31')

    def test_parse_and_map(self):
        insts = self.ci.parse_ec2_instances(_EC2_SAMPLE_XML)
        self.assertEqual(len(insts), 1)
        i = insts[0]
        self.assertEqual((i['instance_id'], i['name'], i['state']), ('i-0abc123', 'web-1', 'running'))
        did, frag = self.ci.instance_to_device('aws', 'eu-west-1', i)
        self.assertEqual(did, 'aws-i-0abc123')
        self.assertTrue(frag['agentless'])
        self.assertEqual(frag['ip'], '10.0.0.5')
        self.assertIn('cloud', frag['tags'])

    def test_import_aws_uses_mock_opener(self):
        import io
        class _Resp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): self.close()
        insts = self.ci.import_aws('eu-west-1', 'AKIA', 'sk',
                                   _opener=lambda req, timeout=15: _Resp(_EC2_SAMPLE_XML.encode()))
        self.assertEqual(insts[0]['instance_id'], 'i-0abc123')

    def test_config_secret_preserved_and_redacted(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'cloud_accounts': [
            {'provider': 'aws', 'region': 'eu-west-1', 'access_key_id': 'AKIA', 'secret_key': 'sk1'}]}
        self.call(api.handle_config_save)
        # save again WITHOUT the secret → preserved
        api.get_json_body = lambda: {'cloud_accounts': [
            {'provider': 'aws', 'region': 'eu-west-1', 'access_key_id': 'AKIA'}]}
        self.call(api.handle_config_save)
        self.assertEqual((api.load(api.CONFIG_FILE))['cloud_accounts'][0]['secret_key'], 'sk1')
        # GET redacts the secret to a flag
        api.method = lambda: 'GET'
        got = self.call(api.handle_config_get)
        acc = got['cloud_accounts'][0]
        self.assertTrue(acc['secret_key_set'])
        self.assertNotIn('secret_key', acc)

    def test_import_handler_creates_agentless_devices(self):
        api.save(api.CONFIG_FILE, {'cloud_accounts': [
            {'provider': 'aws', 'region': 'eu-west-1', 'access_key_id': 'AKIA', 'secret_key': 'sk'}]})
        orig = self.ci.import_aws
        self.ci.import_aws = lambda region, ak, sk: self.ci.parse_ec2_instances(_EC2_SAMPLE_XML)
        try:
            api.method = lambda: 'POST'
            api.get_json_body = lambda: {}
            r = self.call(api.handle_cloud_import)
        finally:
            self.ci.import_aws = orig
        self.assertEqual(r['imported'], 1)
        dev = (api.load(api.DEVICES_FILE))['aws-i-0abc123']
        self.assertTrue(dev['agentless'])
        self.assertEqual(dev['cloud']['region'], 'eu-west-1')

    def test_import_handler_no_account(self):
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {}
        self.call(api.handle_cloud_import)
        self.assertEqual(self.cap['s'], 400)


class TestSshAgent(_HandlerBase):
    """v3.14.0 #48 — agentless SSH (argv build, sysinfo parse, gated handlers)."""

    @classmethod
    def setUpClass(cls):
        import importlib
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        cls.sa = importlib.import_module("ssh_agent")

    def test_argv_is_batchmode_keyonly(self):
        argv = self.sa.build_ssh_argv('h1', 'root', 2222, '/tmp/k', 'uptime')
        self.assertEqual(argv[0], 'ssh')
        self.assertIn('BatchMode=yes', argv)
        self.assertIn('StrictHostKeyChecking=accept-new', argv)
        self.assertIn('2222', argv)
        self.assertIn('root@h1', argv)
        self.assertEqual(argv[-1], 'uptime')

    def test_run_with_injected_runner_and_parse(self):
        class _R:
            returncode = 0
            stdout = ('motd banner\n{"os":"Linux 6.1","hostname":"h1",'
                      '"uptime":"3 days","mem_percent":"42","disk_percent":"70",'
                      '"loadavg_1m":"0.5"}\n')
            stderr = ''
        res = self.sa.run('h', 'u', 'x', 'KEYDATA', runner=lambda a, timeout=30: _R())
        self.assertTrue(res['ok'])
        info = self.sa.parse_sysinfo(res['output'])
        self.assertEqual(info['platform'], 'Linux 6.1')
        self.assertEqual(info['mem_percent'], 42.0)
        self.assertEqual(info['disk_percent'], 70.0)

    def test_exec_handler_gated_on_optin(self):
        api.save(api.CONFIG_FILE, {})       # agentless SSH disabled
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h', 'ip': '10.0.0.9',
                                           'ssh_user': 'root', 'agentless': True}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'command': 'uptime'}
        self.call(api.handle_device_ssh_exec, 'd1')
        self.assertEqual(self.cap['s'], 403)

    def test_exec_handler_runs_with_mock(self):
        api.save(api.CONFIG_FILE, {'agentless_ssh_enabled': True,
                                   'agentless_ssh_key': 'KEY'})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h', 'ip': '10.0.0.9',
                                           'ssh_user': 'root', 'agentless': True}})
        orig = self.sa.run
        self.sa.run = lambda *a, **k: {'ok': True, 'rc': 0, 'output': 'hi'}
        try:
            api.method = lambda: 'POST'
            api.get_json_body = lambda: {'command': 'uptime'}
            r = self.call(api.handle_device_ssh_exec, 'd1')
        finally:
            self.sa.run = orig
        self.assertTrue(r['ok'])
        self.assertEqual(r['output'], 'hi')

    def test_poll_handler_updates_sysinfo(self):
        api.save(api.CONFIG_FILE, {'agentless_ssh_enabled': True, 'agentless_ssh_key': 'KEY'})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h', 'ip': '10.0.0.9',
                                           'ssh_user': 'root', 'agentless': True}})
        orig = self.sa.run
        self.sa.run = lambda *a, **k: {'ok': True, 'rc': 0,
                                       'output': '{"os":"Linux 6.1","disk_percent":"55"}'}
        try:
            api.method = lambda: 'POST'
            api.get_json_body = lambda: {}
            r = self.call(api.handle_device_ssh_poll, 'd1')
        finally:
            self.sa.run = orig
        self.assertTrue(r['ok'])
        si = (api.load(api.DEVICES_FILE))['d1']['sysinfo']
        self.assertEqual(si['platform'], 'Linux 6.1')
        self.assertEqual(si['disk_percent'], 55.0)

    def test_key_never_leaked(self):
        api.save(api.CONFIG_FILE, {'agentless_ssh_enabled': True,
                                   'agentless_ssh_key': '-----BEGIN OPENSSH PRIVATE KEY-----'})
        api.method = lambda: 'GET'
        got = self.call(api.handle_config_get)
        self.assertTrue(got['agentless_ssh_key_set'])
        self.assertNotIn('agentless_ssh_key', got)


class TestMountRecovery(_HandlerBase):
    """v3.14.0 fix — a mount_issue alert auto-resolves when mount_recovered fires
    for that path (was sticking in the inbox forever)."""

    def test_registry_wired(self):
        self.assertIn('mount_recovered', api.WEBHOOK_EVENT_NAMES)
        self.assertEqual(api._ALERT_RECOVER.get('mount_recovered'), 'mount_issue')
        self.assertEqual(api.EVENT_KIND_MAP.get('mount_recovered'), 'mount')

    def test_recovery_resolves_matching_path_only(self):
        # Two open mount_issue alerts on the same host, different paths.
        now = int(__import__('time').time())
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'a1', 'event': 'mount_issue', 'device_id': 'd1',
             'payload': {'path': '/mnt/a'}, 'ts': now},
            {'id': 'a2', 'event': 'mount_issue', 'device_id': 'd1',
             'payload': {'path': '/mnt/b'}, 'ts': now},
        ]})
        api._auto_resolve_alerts('mount_recovered', {'device_id': 'd1', 'path': '/mnt/a'})
        alerts = {a['id']: a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', [])}
        self.assertTrue(alerts['a1'].get('resolved_at'))      # /mnt/a cleared
        self.assertFalse(alerts['a2'].get('resolved_at'))     # /mnt/b still open


class TestSnmpTrends(_HandlerBase):
    """v3.14.0 fix — SNMP-polled devices record metric samples so they trend."""

    def setUp(self):
        super().setUp()
        self._save = {n: getattr(api, n) for n in
                      ('_record_metrics', '_snmp_cpu_avg_pct',
                       '_snmp_memory_used_pct', '_snmp_storage_mounts')}

    def tearDown(self):
        for n, v in self._save.items():
            setattr(api, n, v)
        super().tearDown()

    def test_records_busiest_disk_to_timeseries(self):
        cap = {}
        api._record_metrics = lambda dev_id, si: cap.update({'dev': dev_id, 'si': si})
        api._snmp_cpu_avg_pct = lambda e: 30.0
        api._snmp_memory_used_pct = lambda e: 50.0
        api._snmp_storage_mounts = lambda e: [{'descr': '/', 'used_pct': 70.0},
                                              {'descr': '/data', 'used_pct': 40.0}]
        api._record_snmp_metrics('d1', {})
        self.assertEqual(cap['dev'], 'd1')
        self.assertEqual(cap['si']['cpu_percent'], 30.0)
        self.assertEqual(cap['si']['mem_percent'], 50.0)
        self.assertEqual(cap['si']['disk_percent'], 70.0)   # busiest mount

    def test_noop_when_nothing_polled(self):
        called = []
        api._record_metrics = lambda *a, **k: called.append(1)
        api._snmp_cpu_avg_pct = lambda e: None
        api._snmp_memory_used_pct = lambda e: None
        api._snmp_storage_mounts = lambda e: []
        api._record_snmp_metrics('d1', {})
        self.assertEqual(called, [])


class TestDeviceComboCoverage(unittest.TestCase):
    """v3.14.0 — every device dropdown is a searchable device-combo (or, for the
    one multi-select, gets the searchable filter). Pins the 5 fixed gaps."""

    HTML = (_ROOT / "server/html/index.html").read_text()
    APP = (_ROOT / "server/html/static/js/app.js").read_text()
    NET = (_ROOT / "server/html/static/js/app-network.js").read_text()
    COMP = (_ROOT / "server/html/static/js/app-compliance.js").read_text()

    def test_al_connected_to_is_combo(self):
        # the "Connected to (upstream)" picker on Add agentless device
        import re
        m = re.search(r'<select id="al-connected-to"[^>]*>', self.HTML)
        self.assertIsNotNone(m)
        self.assertIn('device-combo', m.group(0))

    def test_netmap_link_sel_is_combo(self):
        m = [ln for ln in self.NET.splitlines() if 'netmap-link-sel' in ln and '<select' in ln]
        self.assertTrue(m and 'device-combo' in m[0])
        # save query must be scoped to select.* (combo copies classes to its input)
        self.assertIn("querySelectorAll('select.netmap-link-sel')", self.NET)
        self.assertIn("querySelectorAll('select.netmap-dep-sel')", self.NET)

    def test_multiselect_now_searchable(self):
        # _searchifySelect must no longer bail on <select multiple>
        idx = self.APP.find('function _searchifySelect')
        chunk = self.APP[idx:idx + 400]
        self.assertNotIn('sel.multiple ||', chunk)

    def test_fill_target_select_comboifies(self):
        self.assertIn("el.classList.add('device-combo')", self.COMP)
        self.assertIn('function _comboToggleHidden', self.COMP)
        # the value pickers carry a generic placeholder (they can show group/tag)
        for sid in ('scap-target-value', 'install-target-value', 'oti-target-value'):
            import re
            m = re.search(rf'<select id="{sid}"[^>]*>', self.HTML)
            self.assertIsNotNone(m, sid)
            self.assertIn('data-combo-placeholder', m.group(0), sid)


class TestTrustProxy(_HandlerBase):
    """v3.14.0 — behind a load balancer, the real client IP comes from
    X-Forwarded-For only when trust_proxy is on (else REMOTE_ADDR)."""

    def tearDown(self):
        for k in ('REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR'):
            os.environ.pop(k, None)
        super().tearDown()

    def test_default_uses_remote_addr(self):
        os.environ['REMOTE_ADDR'] = '10.0.0.9'
        os.environ['HTTP_X_FORWARDED_FOR'] = '1.2.3.4'
        api.save(api.CONFIG_FILE, {})                       # trust_proxy off
        self.assertEqual(api._get_client_ip(), '10.0.0.9')   # the (proxy) peer

    def test_trusted_proxy_takes_rightmost_xff(self):
        os.environ['REMOTE_ADDR'] = '10.0.0.9'               # the LB
        # client prepended a spoofed hop; the trusted LB appended the real one
        os.environ['HTTP_X_FORWARDED_FOR'] = '1.1.1.1, 9.9.9.9'
        api.save(api.CONFIG_FILE, {'trust_proxy': True})
        self.assertEqual(api._get_client_ip(), '9.9.9.9')    # rightmost = real client


class TestNoDeprecatedDatetime(unittest.TestCase):
    """v3.14.0 fix — no deprecated naive-UTC datetime calls (they spam stderr →
    nginx error log under Python 3.12+ and are scheduled for removal)."""

    def test_no_utc_naive_calls(self):
        for rel in ('server/cgi-bin/api.py', 'client/remotepower-agent.py',
                    'client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            src = (_ROOT / rel).read_text()
            self.assertNotIn('utcfromtimestamp', src, rel)
            self.assertNotIn('utcnow(', src, rel)


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
