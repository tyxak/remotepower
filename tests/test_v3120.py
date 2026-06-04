#!/usr/bin/env python3
"""
Tests for v3.12.0 — pluggable storage backend (SQLite alongside flat JSON),
strict version-bump pins.

The backend behaviour itself is covered in depth by tests/test_storage_backend.py;
this file holds the strict version-surface pins (loosened to regex on the next
bump) plus a few wiring smoke checks specific to this release.
"""
import os
import tempfile
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_v3120", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

VERSION = "3.12.0"


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
        self.assertNotIn("?v=3.11.0", txt)

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
        self.assertIn("What's new — v3.12.0", html)


class TestStorageBackendWiring(unittest.TestCase):
    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/storage-backend/status'), routes)
        self.assertIn(('POST', '/api/storage-backend/migrate'), routes)

    def test_seam_helpers_exist(self):
        for name in ('backend_exists', 'backend_iter_files', '_storage_backend',
                     '_invalidate_backend_cache'):
            self.assertTrue(hasattr(api, name), name)

    def test_default_backend_is_json(self):
        # With no marker and no env override, the default must be flat JSON so
        # existing installs are unaffected until an operator opts in.
        os.environ.pop('RP_STORAGE_BACKEND', None)
        api._invalidate_backend_cache()
        # A throwaway marker path that doesn't exist -> default json.
        old = api.STORAGE_MARKER_FILE
        api.STORAGE_MARKER_FILE = Path(tempfile.mkdtemp()) / 'storage_backend.json'
        try:
            self.assertEqual(api._storage_backend(), 'json')
        finally:
            api.STORAGE_MARKER_FILE = old
            api._invalidate_backend_cache()

    def test_migrate_storage_module_importable(self):
        import storage
        for fn in ('migrate_run', 'verify_migration', 'migrate_json_to_sqlite',
                   'migrate_sqlite_to_json'):
            self.assertTrue(callable(getattr(storage, fn)), fn)


class TestPortAuditToggle(unittest.TestCase):
    """v3.12.0: a single host-audit toggle (config port_audit_enabled, OFF by
    default) gates new_port_detected, port_exposed_world AND firewall_changed."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('CONFIG_FILE', 'PORT_BASELINE_FILE', 'POSTURE_STATE_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.fired = []
        self._orig_fw = api.fire_webhook
        api.fire_webhook = lambda ev, p: self.fired.append(ev)
        # Seed baselines so the device isn't "first_seen" (which suppresses).
        api.save(api.PORT_BASELINE_FILE, {'dev1': [
            {'proto': 'tcp', 'port': 22, 'process': 'sshd',
             'scope': 'world', 'addr': '0.0.0.0'},
        ]})
        api.save(api.POSTURE_STATE_FILE, {'dev1': {'fw_fp': 'old-fingerprint'}})

    def tearDown(self):
        api.fire_webhook = self._orig_fw
        for attr, val in self._files.items():
            setattr(api, attr, val)

    def _ports(self):
        # A brand-new world-exposed port (docker-proxy on 5696) → fires both
        # new_port_detected and port_exposed_world when the audit is on.
        return [{'proto': 'tcp', 'port': 5696, 'process': 'docker-proxy',
                 'scope': 'world', 'addr': '0.0.0.0'}]

    def _fw_si(self):
        # A drifted firewall fingerprint vs the seeded baseline.
        return {'firewall_fp': {'fp': 'new-fingerprint', 'backend': 'ufw',
                                'rules': 7}}

    def test_audit_on_fires_ports(self):
        api.save(api.CONFIG_FILE, {'port_audit_enabled': True})
        api._audit_listening_ports('dev1', 'host1', self._ports())
        self.assertIn('new_port_detected', self.fired)
        self.assertIn('port_exposed_world', self.fired)

    def test_audit_on_fires_firewall(self):
        api.save(api.CONFIG_FILE, {'port_audit_enabled': True})
        api._ingest_posture_v3110('dev1', 'host1', self._fw_si())
        self.assertIn('firewall_changed', self.fired)

    def test_default_off_when_unset(self):
        api.save(api.CONFIG_FILE, {})
        api._audit_listening_ports('dev1', 'host1', self._ports())
        api._ingest_posture_v3110('dev1', 'host1', self._fw_si())
        self.assertEqual(self.fired, [])

    def test_audit_off_suppresses_all_three(self):
        api.save(api.CONFIG_FILE, {'port_audit_enabled': False})
        api._audit_listening_ports('dev1', 'host1', self._ports())
        api._ingest_posture_v3110('dev1', 'host1', self._fw_si())
        self.assertEqual(self.fired, [])

    def test_off_still_updates_baselines(self):
        # So enabling later doesn't fire a catch-up burst.
        api.save(api.CONFIG_FILE, {'port_audit_enabled': False})
        api._audit_listening_ports('dev1', 'host1', self._ports())
        api._ingest_posture_v3110('dev1', 'host1', self._fw_si())
        base = api.load(api.PORT_BASELINE_FILE)['dev1']
        self.assertTrue(any(p['port'] == 5696 for p in base))
        self.assertEqual(
            api.load(api.POSTURE_STATE_FILE)['dev1']['fw_fp'], 'new-fingerprint')


class _HandlerBase(unittest.TestCase):
    """Drive handlers directly with stubbed auth/request/respond."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'AVATARS_DIR',
                     'ROLES_FILE', 'DEVICES_FILE'):
            self._files[attr] = getattr(api, attr)
            base = Path(getattr(api, attr)).name
            setattr(api, attr, self.d / base)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'verify_token', 'get_token_from_request',
                       'audit_log', 'respond', 'method', 'get_json_body',
                       'get_body', '_check_alert_mutation_perm', '_caller_scope')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api.audit_log = lambda *a, **k: None
        api._caller_scope = lambda: None
        def _resp(s, b=None):
            self.cap['s'] = s; self.cap['b'] = b
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


class TestMyAccount(_HandlerBase):
    def test_me_identity(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin', 'created': 1,
                 'totp_secret': 'X', 'ui_prefs': {'default_ssh_username': 'jmo'}}})
        api.method = lambda: 'GET'
        me = self.call(api.handle_me)
        self.assertEqual(me['username'], 'jakob')
        self.assertTrue(me['admin'] and me['totp_enabled'])
        self.assertEqual(me['default_ssh_username'], 'jmo')
        self.assertFalse(me['has_avatar'])
        self.assertEqual(set(me['permissions']), {'exec', 'reboot', 'upgrade'})

    def test_avatar_upload_validates_and_serves(self):
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin'}})
        png = bytes.fromhex(
            '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489'
            '0000000a49444154789c6360000002000100')
        api.method = lambda: 'POST'
        api.get_body = lambda: png
        r = self.call(api.handle_me_avatar)
        self.assertEqual(r['mime'], 'image/png')
        self.assertTrue(api._avatar_path('jakob').exists())
        # non-image rejected
        api.get_body = lambda: b'definitely not an image'
        self.call(api.handle_me_avatar)
        self.assertEqual(self.cap['s'], 400)

    def test_my_acked_filter(self):
        import os
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'a1', 'acknowledged_by': 'jakob', 'acknowledged_at': 5, 'resolved_at': None, 'device_id': None},
            {'id': 'a2', 'acknowledged_by': 'alice', 'acknowledged_at': 6, 'resolved_at': None, 'device_id': None},
        ]})
        api.method = lambda: 'GET'
        os.environ['QUERY_STRING'] = 'status=ack&mine=1'
        r = self.call(api.handle_alerts_list)
        self.assertEqual([a['id'] for a in r['alerts']], ['a1'])


class TestAckWebhook(_HandlerBase):
    def test_on_ack_fires_full_alert(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'note': 'mine now'}
        api._check_alert_mutation_perm = lambda: 'jakob'
        api.save(api.CONFIG_FILE, {'webhook_urls': [
            {'id': 'wh_t', 'url': 'https://t/x', 'format': 'generic', 'enabled': True,
             'on_ack': True, 'events': ['device_offline']},
            {'id': 'wh_c', 'url': 'https://c/x', 'format': 'discord', 'enabled': True},
        ]})
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'ts': 1000, 'event': 'device_offline', 'severity': 'high',
            'title': 'host1 offline', 'device_id': 'd1', 'device_name': 'host1',
            'payload': {'unit': 'x'}, 'acknowledged_by': None, 'resolved_at': None}]})
        fired = []
        api._dispatch_one_webhook = lambda ev, dest, payload, msg, title, prio: fired.append((dest['id'], ev, payload, dest.get('events')))
        self.call(api.handle_alert_ack, 'a1')
        self.assertEqual([f[0] for f in fired], ['wh_t'])   # only the on_ack dest
        _id, ev, payload, evfilter = fired[0]
        self.assertEqual(ev, 'alert_acked')
        self.assertEqual(payload['alert_id'], 'a1')
        self.assertEqual(payload['acknowledged_by'], 'jakob')
        self.assertEqual(payload['ack_note'], 'mine now')
        self.assertEqual(payload['unit'], 'x')           # original payload merged
        self.assertIsNone(evfilter)                       # filters bypassed (opt-in)


class TestQuickWins(unittest.TestCase):
    """v3.12.0 quick wins: iCal parse, CMDB environment, HTTP body match shape."""

    def test_ics_parse_roundtrip(self):
        ics = ("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Deploy\r\n"
               "DESCRIPTION:a\\nb\r\nDTSTART:20240701T090000Z\r\n"
               "DTEND:20240701T100000Z\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\n"
               "BEGIN:VEVENT\r\nSUMMARY:Holiday\r\nDTSTART;VALUE=DATE:20241225\r\n"
               "DTEND;VALUE=DATE:20241226\r\nEND:VEVENT\r\nEND:VCALENDAR")
        evs = api._parse_ics_events(ics)
        self.assertEqual(len(evs), 2)
        self.assertEqual(evs[0]['title'], 'Deploy')
        self.assertEqual(evs[0]['recur'], 'weekly')
        self.assertIn('a\nb', evs[0]['description'])
        self.assertTrue(evs[1]['all_day'])
        for e in evs:
            _clean, err = api._sanitize_event(e)
            self.assertIsNone(err, (e, err))

    def test_ics_skips_non_ics(self):
        self.assertEqual(api._parse_ics_events('hello not an ics'), [])

    def test_cmdb_environment_default_and_constant(self):
        self.assertIn('environment', api._cmdb_record_default())
        self.assertEqual(api._cmdb_record_default()['environment'], '')
        for e in ('test', 'dev', 'staging', 'prod', ''):
            self.assertIn(e, api.CMDB_ENVIRONMENTS)


class TestQuickWinsHandlers(_HandlerBase):
    def setUp(self):
        super().setUp()
        # APIKEYS_FILE not in the base patch list — patch it here too.
        self._ak = api.APIKEYS_FILE
        api.APIKEYS_FILE = self.d / 'apikeys.json'

    def tearDown(self):
        api.APIKEYS_FILE = self._ak
        super().tearDown()

    def test_apikey_list_includes_expires_at(self):
        api.require_admin_auth = lambda: 'admin'
        exp = int(__import__('time').time()) + 86400
        api.save(api.APIKEYS_FILE, {'k1': {'name': 'ci', 'role': 'admin',
                 'created': 1, 'active': True, 'expires_at': exp, 'key': 'x'}})
        api.method = lambda: 'GET'
        out = self.call(api.handle_apikeys_list)
        self.assertEqual(out[0]['expires_at'], exp)

    def test_monitor_body_match_validated(self):
        import os
        api.require_admin_auth = lambda: 'admin'
        api.require_auth = lambda require_admin=False: 'admin'
        # drive the config-save monitor validation path
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'monitors': [
            {'type': 'http', 'target': 'https://example.com', 'label': 'web',
             'body_match': {'mode': 'contains', 'value': 'Welcome'}},
        ]}
        # handle_config_save respond(200) on success; capture cfg write
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        mons = (api.load(api.CONFIG_FILE) or {}).get('monitors') or []
        self.assertEqual(mons[0]['body_match'], {'mode': 'contains', 'value': 'Welcome'})


class TestCmdbEnrichment(unittest.TestCase):
    def test_trim_sysinfo_surfaces_hw_net(self):
        si = {'cpu_count': 8, 'mem_total_mb': 16384, 'disk_total_gb': 500,
              'network': [{'iface': 'eth0', 'ip': '10.0.0.5', 'mac': 'aa:bb', 'x': 1}],
              'mounts': [{'path': '/', 'percent': 42, 'size_gb': 500, 'j': 1}]}
        t = api._trim_sysinfo(si)
        self.assertEqual(t['cpu_count'], 8)
        self.assertEqual(t['network'][0], {'iface': 'eth0', 'ip': '10.0.0.5', 'mac': 'aa:bb'})
        self.assertEqual(t['mounts'][0], {'path': '/', 'percent': 42, 'size_gb': 500})

    def test_business_list_validation(self):
        clean, err = api._cmdb_clean_list(
            [{'vendor': 'Dell', 'expiry': '2026-01-01'}, {'vendor': '', 'expiry': ''}],
            api._CMDB_LIST_SPECS['contracts'])
        self.assertIsNone(err)
        self.assertEqual(len(clean), 1)
        _, err2 = api._cmdb_clean_list([{'vendor': 'x', 'expiry': 'nope'}],
                                       api._CMDB_LIST_SPECS['contracts'])
        self.assertIn('ISO date', err2 or '')
        lic, _ = api._cmdb_clean_list([{'product': 'W', 'seats': '50'}],
                                      api._CMDB_LIST_SPECS['licenses'])
        self.assertEqual(lic[0]['seats'], 50)

    def test_contract_license_lists_feed_attention(self):
        import datetime
        soon = (datetime.date.today() + datetime.timedelta(days=10)).isoformat()
        rec = api._cmdb_record_default()
        rec['contracts'] = [{'vendor': 'Dell', 'expiry': soon}]
        rec['licenses'] = [{'product': 'Win', 'expiry': soon}]
        kinds = {v['kind'] for v in api._device_contract_status(rec)}
        self.assertIn('support_expiry', kinds)
        self.assertIn('license_expiry', kinds)

    def test_record_default_has_lists(self):
        d = api._cmdb_record_default()
        for k in ('contracts', 'contacts', 'licenses'):
            self.assertEqual(d[k], [])


if __name__ == '__main__':
    unittest.main()
