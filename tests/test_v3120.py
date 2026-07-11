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
import time
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
    # v3.13.0: loosened from the exact 3.12.0 pins (the live strict pin moved to
    # tests/test_v3130.py) so a later bump doesn't fail this file.
    def test_server_version(self):
        self.assertRegex(api.SERVER_VERSION, r'^\d+\.\d+\.\d+$')

    def test_agent_version(self):
        txt = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertRegex(txt, r"\nVERSION\s*=\s*'\d+\.\d+\.\d+'")

    def test_agent_extensionless_matches_py(self):
        a = (_ROOT / "client/remotepower-agent.py").read_bytes()
        b = (_ROOT / "client/remotepower-agent").read_bytes()
        self.assertEqual(a, b, "agent .py and extensionless copy diverged "
                               "(run cp client/remotepower-agent.py client/remotepower-agent)")

    def test_sw_cache_name(self):
        txt = (_ROOT / "server/html/sw.js").read_text()
        self.assertRegex(txt, r"remotepower-shell-v\d+\.\d+\.\d+")

    def test_index_cache_bust(self):
        txt = (_ROOT / "server/html/index.html").read_text()
        self.assertRegex(txt, r"\?v=\d+\.\d+\.\d+")

    def test_readme_badge(self):
        txt = (_ROOT / "README.md").read_text()
        self.assertRegex(txt, r"version-\d+\.\d+\.\d+-blue")

    def test_changelog_top_entry(self):
        txt = (_ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(txt[:2000], r"v\d+\.\d+\.\d+")

    # v4.3.0: docs/v3.12.0.md and the "What's new — v3.12.0" card intentionally
    # aged out of the "keep last 5 versions" window when v4.3.0 shipped, so the
    # original doc-exists / card-present pins were dropped here (the live
    # strict pins live in tests/test_v430.py). The complete v3.12.0 history is
    # preserved in CHANGELOG.md.


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
                      ('require_auth', 'require_admin_auth', 'verify_token',
                       'get_token_from_request', 'audit_log', 'respond', 'method',
                       'get_json_body', 'get_json_obj', 'get_body',
                       '_check_alert_mutation_perm', '_caller_scope')}
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
        # v3.12.0: admin holds the full granular permission set
        self.assertEqual(set(me['permissions']), set(api._RBAC_PERMS))

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


class TestSatellites(_HandlerBase):
    def setUp(self):
        super().setUp()
        self._sf = api.SATELLITES_FILE
        api.SATELLITES_FILE = self.d / 'satellites.json'

    def tearDown(self):
        api.SATELLITES_FILE = self._sf
        super().tearDown()

    def test_create_list_verify_revoke(self):
        import os
        api.require_admin_auth = lambda: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'name': 'dmz'}
        created = self.call(api.handle_satellites_create)
        tok, sid = created['token'], created['id']
        # list has no secrets
        api.method = lambda: 'GET'
        lst = self.call(api.handle_satellites_list)
        self.assertEqual(lst[0]['name'], 'dmz')
        self.assertNotIn('token', lst[0])
        self.assertNotIn('token_hash', lst[0])
        # valid token passes + stamps last_seen
        os.environ['HTTP_X_RP_SATELLITE'] = tok
        api._record_satellite()
        self.assertTrue(api.load(api.SATELLITES_FILE)[sid]['last_seen'])
        # invalid token -> 401
        os.environ['HTTP_X_RP_SATELLITE'] = 'nope'
        with self.assertRaises(api.HTTPError) as cm:
            api._record_satellite()
        self.assertEqual(cm.exception.status, 401)
        os.environ.pop('HTTP_X_RP_SATELLITE', None)
        api._record_satellite()   # no header -> no-op (no raise)
        # revoke
        api.method = lambda: 'DELETE'
        self.call(api.handle_satellites_delete, sid)
        self.assertNotIn(sid, api.load(api.SATELLITES_FILE))

    def test_routes_registered(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route('GET', '/api/satellites')[0], 'handle_satellites_list')
        self.assertEqual(resolve_route('POST', '/api/satellites')[0], 'handle_satellites_create')
        self.assertEqual(resolve_route('DELETE', '/api/satellites/x')[0], 'handle_satellites_delete')


class TestRiskScores(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._saved = {}
        for a in ('DEVICES_FILE', 'CVE_FINDINGS_FILE', 'SOFTWARE_VIOLATIONS_FILE',
                  'CMDB_FILE', 'HARDWARE_FILE'):
            self._saved[a] = getattr(api, a)
            setattr(api, a, self.d / Path(getattr(api, a)).name)

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)

    def test_risk_ordering_and_factors(self):
        import time
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web1', 'monitored': True, 'last_seen': now, 'sysinfo': {
                'packages': {'upgradable': 12},
                'listening_ports': [{'scope': 'world'}, {'scope': 'world'}],
                'mount_issues': [{'path': '/m', 'issue': 'stalled'}], 'reboot_required': True}},
            'd2': {'name': 'db1', 'monitored': True, 'last_seen': now - 99999, 'sysinfo': {}},
            'd3': {'name': 'idle', 'monitored': True, 'last_seen': now, 'sysinfo': {}},
        })
        api.save(api.CVE_FINDINGS_FILE, {'d1': {'findings': [{'severity': 'critical'}, {'severity': 'high'}]}})
        api.save(api.SOFTWARE_VIOLATIONS_FILE, {'d1': {'violations': [{'x': 1}]}})
        risks = {r['device_name']: r for r in api._compute_fleet_risk()}
        self.assertGreater(risks['web1']['score'], risks['db1']['score'])
        self.assertGreater(risks['db1']['score'], risks['idle']['score'])
        self.assertEqual(risks['idle']['score'], 0)
        self.assertEqual(risks['idle']['level'], 'low')
        self.assertEqual(risks['db1']['factors'][0]['kind'], 'offline')
        self.assertLessEqual(risks['web1']['score'], 100)

    def test_risk_route_registered(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route('GET', '/api/risk')[0], 'handle_risk_overview')

    def test_risk_firewall_storage_software_factors(self):
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web1', 'monitored': True, 'last_seen': now, 'sysinfo': {
                'firewall_fp': {'backend': 'none', 'rules': 0},
                'storage_health': [{'name': 'tank', 'state': 'DEGRADED'},
                                   {'name': 'ok', 'state': 'ONLINE'}],
                'failed_units': ['nginx.service', 'redis.service']}},
            'd2': {'name': 'fw-on', 'monitored': True, 'last_seen': now, 'sysinfo': {
                'firewall_fp': {'backend': 'nftables', 'rules': 30}}},
        })
        api.save(api.HARDWARE_FILE, {'d1': {
            'smart': [{'health': 'FAILED'}], 'kernel': {'reboot_for_kernel': True}}})
        risks = {r['device_name']: r for r in api._compute_fleet_risk()}
        kinds = {f['kind'] for f in risks['web1']['factors']}
        self.assertIn('firewall_off', kinds)
        self.assertIn('storage_degraded', kinds)
        self.assertIn('smart_failure', kinds)
        self.assertIn('kernel_outdated', kinds)
        self.assertIn('failed_units', kinds)
        # a host with an active firewall must NOT be flagged firewall_off
        self.assertNotIn('firewall_off',
                         {f['kind'] for f in risks['fw-on']['factors']})

    def test_risk_firewall_summary(self):
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            # richer per-backend summary, none active -> firewall_off
            'off': {'name': 'off', 'monitored': True, 'last_seen': now, 'sysinfo': {
                'firewall': {'active': False, 'backends': [
                    {'name': 'nftables', 'present': True, 'active': False, 'rules': 0},
                    {'name': 'ufw', 'present': True, 'active': False, 'rules': 0}]}}},
            # active with rules -> no firewall_off
            'on': {'name': 'on', 'monitored': True, 'last_seen': now, 'sysinfo': {
                'firewall': {'active': True, 'backends': [
                    {'name': 'nftables', 'present': True, 'active': True, 'rules': 20}]}}},
            # active but iptables defaults to ACCEPT with no rules -> half-weight flag
            'open': {'name': 'open', 'monitored': True, 'last_seen': now, 'sysinfo': {
                'firewall': {'active': True, 'backends': [
                    {'name': 'iptables', 'present': True, 'active': True,
                     'rules': 0, 'policy': 'ACCEPT'}]}}},
        })
        risks = {r['device_name']: r for r in api._compute_fleet_risk()}
        self.assertIn('firewall_off', {f['kind'] for f in risks['off']['factors']})
        self.assertNotIn('firewall_off', {f['kind'] for f in risks['on']['factors']})
        openf = [f for f in risks['open']['factors'] if f['kind'] == 'firewall_off']
        self.assertTrue(openf and openf[0]['points'] < api._RISK_WEIGHTS['firewall_off'])

    def test_risk_firewall_unknown_not_penalised(self):
        # active=None means the agent couldn't read the ruleset (e.g. not root);
        # it must NOT be flagged as no-firewall / raise risk.
        now = int(time.time())
        api.save(api.DEVICES_FILE, {'u': {'name': 'u', 'monitored': True, 'last_seen': now,
            'sysinfo': {'firewall': {'active': None, 'backends': [
                {'name': 'iptables', 'present': True, 'active': None, 'rules': 0}]}}}})
        r = api._compute_fleet_risk()[0]
        self.assertNotIn('firewall_off', {f['kind'] for f in r['factors']})

    def test_risk_firewall_fp_fallback(self):
        # older agent ships only the drift fingerprint
        now = int(time.time())
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h', 'monitored': True,
            'last_seen': now, 'sysinfo': {'firewall_fp': {'backend': 'none', 'rules': 0}}}})
        r = api._compute_fleet_risk()[0]
        self.assertIn('firewall_off', {f['kind'] for f in r['factors']})

    def test_risk_only_one_degraded_counted(self):
        now = int(time.time())
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h', 'monitored': True,
            'last_seen': now, 'sysinfo': {'storage_health': [
                {'name': 'a', 'state': 'ONLINE'}, {'name': 'b', 'state': 'FAULTED'}]}}})
        r = api._compute_fleet_risk()[0]
        sd = [f for f in r['factors'] if f['kind'] == 'storage_degraded'][0]
        self.assertIn('1 degraded', sd['detail'])


class TestConditionalGetEtag(unittest.TestCase):
    """docs/master-improvement-scoping-internal.md #10 — opt-in ETag/304 on
    read-heavy GET endpoints. Calls raise HTTPError directly (not via the
    respond() stub _HandlerBase relies on elsewhere in this file), so these
    tests catch api.HTTPError themselves rather than reusing that harness."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._saved = {}
        for a in ('DEVICES_FILE', 'CVE_FINDINGS_FILE', 'SOFTWARE_VIOLATIONS_FILE',
                  'CMDB_FILE', 'HARDWARE_FILE', 'CONFIG_FILE', 'PACKAGES_FILE',
                  'CVE_IGNORE_FILE', 'FLEET_EVENTS_FILE', 'CMD_OUTPUT_FILE'):
            self._saved[a] = getattr(api, a)
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        self._orig_env = api._env
        self._if_none_match = ''
        api._env = lambda k, d=None: (self._if_none_match if k == 'HTTP_IF_NONE_MATCH' else d)
        self._orig_auth = api.require_auth
        api.require_auth = lambda require_admin=False: 'jakob'
        self._orig_scope = api._caller_scope
        api._caller_scope = lambda: None
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h', 'monitored': True,
                 'last_seen': int(time.time())}})

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        api._env = self._orig_env
        api.require_auth = self._orig_auth
        api._caller_scope = self._orig_scope

    # ── pure _respond_with_etag ──────────────────────────────────────────
    def test_no_if_none_match_sends_200_with_etag(self):
        with self.assertRaises(api.HTTPError) as cm:
            api._respond_with_etag({'x': 1}, 'source-a')
        e = cm.exception
        self.assertEqual(e.status, 200)
        self.assertEqual(e.body, {'x': 1})
        names = dict(e.headers)
        self.assertIn('ETag', names)
        self.assertEqual(names['Cache-Control'], 'no-cache')

    def test_matching_if_none_match_sends_bodyless_304(self):
        with self.assertRaises(api.HTTPError) as cm:
            api._respond_with_etag({'x': 1}, 'source-a')
        etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = etag
        with self.assertRaises(api.HTTPError) as cm2:
            api._respond_with_etag({'x': 1}, 'source-a')
        self.assertEqual(cm2.exception.status, 304)
        self.assertIsNone(cm2.exception.body)

    def test_different_source_never_matches_stale_etag(self):
        with self.assertRaises(api.HTTPError) as cm:
            api._respond_with_etag({'x': 1}, 'source-a')
        stale_etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = stale_etag
        with self.assertRaises(api.HTTPError) as cm2:
            api._respond_with_etag({'x': 2}, 'source-b')   # data AND source changed
        self.assertEqual(cm2.exception.status, 200)
        self.assertEqual(cm2.exception.body, {'x': 2})

    # ── real handler wiring ──────────────────────────────────────────────
    def test_risk_overview_first_call_returns_200(self):
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_risk_overview()
        self.assertEqual(cm.exception.status, 200)
        self.assertIn('devices', cm.exception.body)
        self.assertIn('ETag', dict(cm.exception.headers))

    def test_risk_overview_second_call_same_data_returns_304(self):
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_risk_overview()
        etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = etag
        with self.assertRaises(api.HTTPError) as cm2:
            api.handle_risk_overview()
        self.assertEqual(cm2.exception.status, 304)

    def test_risk_overview_data_change_busts_the_etag(self):
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_risk_overview()
        stale_etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = stale_etag
        # A real fleet change (new device) must invalidate the fleet-risk
        # cache -- and therefore the ETag -- not silently serve a 304.
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'h', 'monitored': True, 'last_seen': int(time.time())},
            'd2': {'name': 'h2', 'monitored': True, 'last_seen': int(time.time())},
        })
        with self.assertRaises(api.HTTPError) as cm2:
            api.handle_risk_overview()
        self.assertEqual(cm2.exception.status, 200)
        self.assertEqual(cm2.exception.body['total'], 2)

    # ── v6.1.1 (#10): the "timeline reads" the tracker note left open ─────
    def _seed_event(self, ts=1):
        api.save(api.FLEET_EVENTS_FILE, {'events': [
            {'ts': ts, 'event': 'device_offline', 'payload': {'device_id': 'd1'}}]})

    def test_fleet_events_first_call_returns_200_with_etag(self):
        self._seed_event()
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_fleet_events()
        self.assertEqual(cm.exception.status, 200)
        self.assertIn('ETag', dict(cm.exception.headers))

    def test_fleet_events_second_call_same_data_returns_304(self):
        self._seed_event()
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_fleet_events()
        etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = etag
        with self.assertRaises(api.HTTPError) as cm2:
            api.handle_fleet_events()
        self.assertEqual(cm2.exception.status, 304)

    def test_fleet_events_new_event_busts_the_etag(self):
        self._seed_event()
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_fleet_events()
        stale_etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = stale_etag
        self._seed_event(ts=2)   # a genuinely new event fires
        with self.assertRaises(api.HTTPError) as cm2:
            api.handle_fleet_events()
        self.assertEqual(cm2.exception.status, 200)

    def test_fleet_events_device_edit_busts_the_etag_without_a_new_event(self):
        # monitored/scope filtering reads live DEVICES_FILE state -- an
        # operator flipping monitored=false can change the response with no
        # new fleet event firing, so DEVICES_FILE must be in the etag key too.
        self._seed_event()
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_fleet_events()
        stale_etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = stale_etag
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h', 'monitored': False,
                 'last_seen': int(time.time())}})
        with self.assertRaises(api.HTTPError) as cm2:
            api.handle_fleet_events()
        self.assertEqual(cm2.exception.status, 200)
        self.assertEqual(cm2.exception.body, [])   # d1 now unmonitored -> filtered out

    def test_device_timeline_conditional_get(self):
        self._seed_event()
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_device_timeline('d1')
        self.assertEqual(cm.exception.status, 200)
        etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = etag
        with self.assertRaises(api.HTTPError) as cm2:
            api.handle_device_timeline('d1')
        self.assertEqual(cm2.exception.status, 304)

    def test_device_timeline_new_command_output_busts_the_etag(self):
        self._seed_event()
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_device_timeline('d1')
        stale_etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = stale_etag
        api.save(api.CMD_OUTPUT_FILE, {'d1': [{'ts': 5, 'cmd': 'uptime', 'rc': 0}]})
        with self.assertRaises(api.HTTPError) as cm2:
            api.handle_device_timeline('d1')
        self.assertEqual(cm2.exception.status, 200)

    def test_fleet_timeline_conditional_get(self):
        self._seed_event()
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_fleet_timeline()
        self.assertEqual(cm.exception.status, 200)
        etag = dict(cm.exception.headers)['ETag']
        self._if_none_match = etag
        with self.assertRaises(api.HTTPError) as cm2:
            api.handle_fleet_timeline()
        self.assertEqual(cm2.exception.status, 304)


class TestMountMonitoring(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._psf = api.POSTURE_STATE_FILE
        api.POSTURE_STATE_FILE = self.d / 'posture_state.json'
        self.fired = []
        self._fw = api.fire_webhook
        api.fire_webhook = lambda ev, p: self.fired.append((ev, p.get('issue'), p.get('path')))

    def tearDown(self):
        api.fire_webhook = self._fw
        api.POSTURE_STATE_FILE = self._psf

    def test_mount_issue_edge_triggered(self):
        api.save(api.POSTURE_STATE_FILE, {'d1': {}})   # seed -> not first_seen
        api._ingest_posture_v3110('d1', 'h', {'mount_issues': [
            {'path': '/mnt/nfs', 'issue': 'stalled', 'fstype': 'nfs'},
            {'path': '/mnt/data', 'issue': 'missing', 'fstype': 'ext4'}]})
        self.assertIn(('mount_issue', 'stalled', '/mnt/nfs'), self.fired)
        self.assertIn(('mount_issue', 'missing', '/mnt/data'), self.fired)
        # same issue for /mnt/nfs -> no re-fire; /mnt/data is gone -> recovered
        # (v3.14.0: a cleared mount now fires mount_recovered so its alert
        # auto-resolves instead of sticking in the inbox).
        self.fired.clear()
        api._ingest_posture_v3110('d1', 'h', {'mount_issues': [
            {'path': '/mnt/nfs', 'issue': 'stalled', 'fstype': 'nfs'}]})
        self.assertEqual(self.fired, [('mount_recovered', None, '/mnt/data')])

    def test_mount_issue_severity_high(self):
        self.assertEqual(api._alert_severity('mount_issue', {'issue': 'stalled'}), 'high')

    def test_mount_issue_in_registries(self):
        self.assertIn('mount_issue', api.WEBHOOK_EVENT_NAMES)

    def test_mount_issue_surfaces_in_attention(self):
        # v3.12.0: mount issues now show on Needs Attention (were invisible)
        saved = api.DEVICES_FILE
        api.DEVICES_FILE = self.d / 'devices.json'
        try:
            api.save(api.DEVICES_FILE, {'d1': {'name': 'nas', 'monitored': True,
                'sysinfo': {'mount_issues': [
                    {'path': '/mnt/nfs', 'issue': 'stalled', 'fstype': 'nfs'},
                    {'path': '/mnt/data', 'issue': 'missing', 'fstype': 'ext4'}]}}})
            items = api._compute_attention()
            mounts = [i for i in items if i['kind'] == 'mount']
            self.assertEqual(len(mounts), 2)
            stalled = [i for i in mounts if 'stalled' in i['summary']][0]
            self.assertEqual(stalled['severity'], 'critical')
            missing = [i for i in mounts if 'not mounted' in i['summary']][0]
            self.assertEqual(missing['severity'], 'warning')
        finally:
            api.DEVICES_FILE = saved


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


class TestRetentionMaintenance(_HandlerBase):
    """v3.12.0: configurable data retention + on-demand DB maintenance."""
    def setUp(self):
        super().setUp()
        for attr in ('HISTORY_FILE', 'FLEET_EVENTS_FILE', 'WEBHOOK_LOG_FILE',
                     'INBOUND_WEBHOOK_LOG_FILE', 'MON_HIST_FILE',
                     'RETENTION_STATE_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.now = int(time.time())
        self.old = self.now - 100 * 86400

    def test_purge_respects_age_and_disabled(self):
        api.save(api.HISTORY_FILE, {'entries': [
            {'ts': self.old, 'command': 'a'}, {'ts': self.now, 'command': 'b'}]})
        api.save(api.FLEET_EVENTS_FILE, {'events': [
            {'ts': self.old}, {'ts': self.now}]})
        # disabled (no config) → nothing purged
        self.assertEqual(api._purge_old_data({}), {})
        self.assertEqual(len(api.load(api.HISTORY_FILE)['entries']), 2)
        # enabled 90d → old entries dropped
        removed = api._purge_old_data({'history_retention_days': 90,
                                       'fleet_events_retention_days': 90})
        self.assertEqual(removed.get('history.json'), 1)
        self.assertEqual(removed.get('fleet_events.json'), 1)
        self.assertEqual([e['command'] for e in
                          api.load(api.HISTORY_FILE)['entries']], ['b'])

    def test_purge_keeps_open_alerts(self):
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'resolved_old', 'resolved_at': self.old},
            {'id': 'open_old', 'resolved_at': None, 'ts': self.old},
            {'id': 'resolved_new', 'resolved_at': self.now}]})
        removed = api._purge_old_data({'alerts_retention_days': 30})
        self.assertEqual(removed.get('alerts.json'), 1)
        ids = {a['id'] for a in api.load(api.ALERTS_FILE)['alerts']}
        self.assertEqual(ids, {'open_old', 'resolved_new'})

    def test_sweep_records_timestamp(self):
        api.save(api.CONFIG_FILE, {'history_retention_days': 90})
        api.save(api.HISTORY_FILE, {'entries': [{'ts': self.old}, {'ts': self.now}]})
        api._retention_sweep_if_due()
        self.assertEqual(len(api.load(api.HISTORY_FILE)['entries']), 1)
        # second call same day → no-op (timestamp recorded)
        self.assertTrue(api.load(api.RETENTION_STATE_FILE).get('last'))

    def test_maintenance_endpoint(self):
        api.method = lambda: 'POST'
        api.save(api.CONFIG_FILE, {'history_retention_days': 90})
        api.save(api.HISTORY_FILE, {'entries': [{'ts': self.old}, {'ts': self.now}]})
        res = self.call(api.handle_maintenance_run)
        self.assertTrue(res['ok'])
        self.assertEqual(res['pruned'].get('history.json'), 1)
        self.assertEqual(res['backend'], api._storage_backend())

    def test_config_save_validates_retention(self):
        # the version-bump/handler harness validates 0..3650 ints; pin the key set
        self.assertEqual(set(api._RETENTION_KEYS), {
            'history_retention_days', 'fleet_events_retention_days',
            'webhook_log_retention_days', 'monitor_history_retention_days',
            'alerts_retention_days', 'audit_log_retention_days',
            'metric_samples_retention_days'})   # v3.14.0

    # ── #21: litigation hold ─────────────────────────────────────────────
    def test_purge_is_a_no_op_while_hold_active(self):
        api.save(api.HISTORY_FILE, {'entries': [{'ts': self.old}, {'ts': self.now}]})
        cfg = {'history_retention_days': 90,
               'litigation_hold': {'enabled': True, 'reason': 'x'}}
        removed = api._purge_old_data(cfg)
        self.assertEqual(removed, {'_litigation_hold': True})
        self.assertEqual(len(api.load(api.HISTORY_FILE)['entries']), 2, 'nothing purged')

    def test_purge_resumes_once_hold_cleared(self):
        api.save(api.HISTORY_FILE, {'entries': [{'ts': self.old}, {'ts': self.now}]})
        api._purge_old_data({'history_retention_days': 90,
                             'litigation_hold': {'enabled': True, 'reason': 'x'}})
        self.assertEqual(len(api.load(api.HISTORY_FILE)['entries']), 2)
        removed = api._purge_old_data({'history_retention_days': 90,
                                       'litigation_hold': {'enabled': False}})
        self.assertEqual(removed.get('history.json'), 1)

    def test_maintenance_endpoint_reports_hold_and_prunes_nothing(self):
        api.method = lambda: 'POST'
        api.save(api.CONFIG_FILE, {'history_retention_days': 90,
                                   'litigation_hold': {'enabled': True, 'reason': 'x'}})
        api.save(api.HISTORY_FILE, {'entries': [{'ts': self.old}, {'ts': self.now}]})
        res = self.call(api.handle_maintenance_run)
        self.assertTrue(res['ok'])
        self.assertTrue(res['litigation_hold'])
        self.assertNotIn('_litigation_hold', res['pruned'])   # marker popped, not leaked
        self.assertEqual(len(api.load(api.HISTORY_FILE)['entries']), 2)

    def test_set_requires_reason_to_enable(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'enabled': True}
        self.call(api.handle_litigation_hold_set)
        self.assertEqual(self.cap['s'], 400)

    def test_set_enable_then_disable_roundtrip(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'enabled': True, 'reason': 'pending case #123'}
        res = self.call(api.handle_litigation_hold_set)
        self.assertTrue(res['ok'])
        api.method = lambda: 'GET'
        got = self.call(api.handle_litigation_hold_get)
        self.assertTrue(got['enabled'])
        self.assertEqual(got['reason'], 'pending case #123')
        self.assertEqual(got['started_by'], 'jakob')
        self.assertIsNotNone(got['started_at'])
        # disable doesn't need a reason
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'enabled': False}
        res = self.call(api.handle_litigation_hold_set)
        self.assertTrue(res['ok'])
        api.method = lambda: 'GET'
        got = self.call(api.handle_litigation_hold_get)
        self.assertFalse(got['enabled'])

    def test_route_registered(self):
        routes = api._build_exact_routes()
        self.assertIs(routes[('GET', '/api/litigation-hold')], api.handle_litigation_hold_get)
        self.assertIs(routes[('POST', '/api/litigation-hold')], api.handle_litigation_hold_set)


class TestLargeFleetUI(unittest.TestCase):
    """v3.12.0: filter boxes on previously-unfiltered pages + a reusable helper."""
    def setUp(self):
        self.app = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.html = (_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_filter_helper_exists(self):
        self.assertIn('function filterRows(', self.app)
        self.assertIn('data-filter-target', self.app)

    def test_pages_have_filter_boxes(self):
        for target in ('#risk-tbody tr', '#storage-tbody tr', '#exposure-tbody tr',
                       '#compose-stacks-tbody tr', '#confirmations-tbody tr',
                       '#swpol-viol-tbody tr', '#rollouts-list > *',
                       '#automation-list > *', '#compliance-body tr',
                       '#containers-lxc-body tr'):
            self.assertIn(f'data-filter-target="{target}"', self.html,
                          f'missing filter box for {target}')

    def test_tablectl_pagination(self):
        # tableCtl paginates every registered table (default 15/page) + pager
        self.assertIn('function goPage(', self.app)
        self.assertIn('function _renderPager(', self.app)
        self.assertIn('opts.pageSize || 15', self.app)
        self.assertIn('function tblPage(', self.app)
        self.assertIn('data-action="tblPage"', self.app)

    def test_command_queue_paging(self):
        self.assertIn('function _renderCommandQueue(', self.app)
        self.assertIn('_cmdqMorePending', self.app)
        self.assertIn('id="cmdqueue-filter"', self.html)

    def test_searchable_selects(self):
        # long <select>s get a type-to-filter input, wired from showPage/openModal
        self.assertIn('function enhanceLongSelects(', self.app)
        self.assertIn('function _searchifySelect(', self.app)
        self.assertIn('enhanceLongSelects(el)', self.app)

    def test_device_combobox(self):
        # device dropdowns become a type-to-search combobox
        self.assertIn('function comboifyDeviceSelect(', self.app)
        self.assertIn('function enhanceDeviceCombos(', self.app)
        self.assertIn('enhanceDeviceCombos(el)', self.app)
        # every confirmed device <select> is tagged for the combobox
        for sid in ('patch-device-filter', 'logs-device-filter', 'timeline-device',
                    'trend-device', 'sched-device', 'compose-create-device',
                    'acme-issue-device', 'backupjob-device', 'iac-device-select',
                    'mailwatch-device', 'oti-device', 'maint-target-device',
                    'log-rule-device', 'inbound-wh-device', 'tasks-device-filter'):
            i = self.html.find(f'id="{sid}"')
            self.assertGreater(i, 0, f'{sid} not found')
            # the class attr on that <select> includes device-combo
            tag = self.html[i:self.html.find('>', i)]
            self.assertIn('device-combo', tag, f'{sid} not tagged device-combo')


class TestExposureHostMute(unittest.TestCase):
    """v3.12.0: mute ALL exposure from one host (device_id-scoped rule)."""
    def test_device_id_rule_matches_only_that_host(self):
        mutes = [{'device_id': 'h1'}]
        # any socket on h1 is muted
        self.assertTrue(api._exposure_muted('sshd', 'tcp', 22, mutes, 'h1'))
        self.assertTrue(api._exposure_muted('nginx', 'tcp', 443, mutes, 'h1'))
        # a different host is not
        self.assertFalse(api._exposure_muted('sshd', 'tcp', 22, mutes, 'h2'))

    def test_combined_device_and_port(self):
        mutes = [{'device_id': 'h1', 'port': 22}]
        self.assertTrue(api._exposure_muted('sshd', 'tcp', 22, mutes, 'h1'))
        self.assertFalse(api._exposure_muted('sshd', 'tcp', 80, mutes, 'h1'))
        self.assertFalse(api._exposure_muted('sshd', 'tcp', 22, mutes, 'h2'))

    def test_empty_rule_still_matches_nothing(self):
        self.assertFalse(api._exposure_muted('x', 'tcp', 1, [{}], 'h1'))


class TestGranularRBAC(unittest.TestCase):
    """v3.12.0: 10 granular action permissions (+ legacy umbrella expansion)
    and a new 'sites' scope type."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._saved = {}
        for a in ('ROLES_FILE', 'DEVICES_FILE'):
            self._saved[a] = getattr(api, a)
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        self._auth = (api.get_token_from_request, api.verify_token, api.respond)
        api.get_token_from_request = lambda: 'tok'

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        api.get_token_from_request, api.verify_token, api.respond = self._auth
        api._LOAD_CACHE.clear()

    def test_perm_set_is_granular(self):
        # v3.12.0 shipped 10 granular perms; v4.2.0 (B5) added 'scan'. Pin the
        # 10 v3.12.0 perms as a subset so this guardrail still catches an
        # accidental removal, without re-pinning the exact count on every add.
        self.assertTrue({
            'command', 'script', 'reboot', 'shutdown', 'patch',
            'packages', 'containers', 'services', 'ssh', 'mitigate'
        }.issubset(set(api._RBAC_PERMS)))
        # 'scan' must NOT be folded into the legacy 'exec' umbrella (it's a
        # distinct, sensitive capability — existing exec roles don't gain it).
        self.assertNotIn('scan', api._expand_perms(['exec']))

    def test_legacy_expansion(self):
        ex = api._expand_perms(['exec'])
        self.assertIn('command', ex)
        self.assertIn('containers', ex)
        self.assertNotIn('patch', ex)        # exec never covered upgrade
        self.assertNotIn('reboot', ex)       # nor power
        self.assertEqual(api._expand_perms(['upgrade']), {'patch'})
        # unknown names dropped
        self.assertEqual(api._expand_perms(['bogus']), set())

    def test_valid_role_perms_accepts_legacy_and_granular(self):
        self.assertTrue({'command', 'exec', 'upgrade'} <= set(api._VALID_ROLE_PERMS))

    def test_site_scope(self):
        api.save(api.DEVICES_FILE, {})
        self.assertTrue(api._device_in_scope({'type': 'sites', 'values': ['hq']},
                                              {'site': 'hq'}))
        self.assertFalse(api._device_in_scope({'type': 'sites', 'values': ['hq']},
                                              {'site': 'dc2'}))
        self.assertIn('sites', api._RBAC_SCOPE_TYPES)

    def test_clean_role_body_site_scope(self):
        clean, err = api._clean_role_body({'name': 'site-ops',
            'permissions': ['containers', 'services'],
            'scope': {'type': 'sites', 'values': ['hq', 'dc2']}})
        self.assertIsNone(err)
        self.assertEqual(clean['scope']['type'], 'sites')
        self.assertEqual(set(clean['permissions']), {'containers', 'services'})

    def test_require_perm_granular(self):
        # go through the storage layer (api.save) so it works on both backends
        api.save(api.ROLES_FILE, {'roles': [
            {'name': 'cops', 'permissions': ['containers'],
             'scope': {'type': 'sites', 'values': ['hq']}}]})
        api.save(api.DEVICES_FILE, {'d1': {'site': 'hq'}, 'd2': {'site': 'dc2'}})
        api.verify_token = lambda t: ('carol', 'cops')
        def _resp(s, b=None):
            raise api.HTTPError(s, b)
        api.respond = _resp
        # has containers, in-scope site
        self.assertEqual(api.require_perm('containers', ['d1']), 'carol')
        # lacks command
        with self.assertRaises(api.HTTPError) as cm:
            api.require_perm('command', ['d1'])
        self.assertEqual(cm.exception.status, 403)
        # containers but out-of-scope site
        with self.assertRaises(api.HTTPError) as cm:
            api.require_perm('containers', ['d2'])
        self.assertEqual(cm.exception.status, 403)

    def test_handlers_regated_to_granular(self):
        src = (Path(api.__file__)).read_text()
        for fn, perm in (('handle_device_container_action', "require_perm('containers'"),
                         ('handle_device_compose_action', "require_perm('containers'"),
                         ('handle_compose_stack_action', "require_perm('containers'"),
                         ('handle_services_config', "require_perm('services'")):
            i = src.find('def ' + fn + '(')
            self.assertGreater(i, 0, fn)
            self.assertIn(perm, src[i:i + 600], f'{fn} should use {perm}')

    def test_apikey_dropdown_has_mcp(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        i = html.find('id="apikey-role"')
        self.assertIn('value="mcp"', html[i:i + 400])


class TestAgentLogRotation(unittest.TestCase):
    """v3.12.0: agent self-rotates its log file (no cron/logrotate needed)."""
    def test_rotating_handler_source(self):
        src = (Path(__file__).resolve().parent.parent /
               'client' / 'remotepower-agent.py').read_text()
        self.assertIn('RotatingFileHandler', src)
        self.assertIn('_agent_file_log_handler', src)
        self.assertIn('maxBytes=5 * 1024 * 1024', src)


class TestAgentFirewallDetail(unittest.TestCase):
    """v3.12.0: agent collects per-backend firewall posture into sysinfo."""
    def setUp(self):
        import importlib.util
        p = Path(__file__).resolve().parent.parent / 'client' / 'remotepower-agent.py'
        spec = importlib.util.spec_from_file_location('rp_agent_fw', p)
        self.ag = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ag)

    def test_collector_contract(self):
        r = self.ag.collect_firewall_detail()
        # None when no backend tools are installed; otherwise a typed summary.
        if r is not None:
            self.assertIn('backends', r)
            self.assertIn('active', r)
            for b in r['backends']:
                self.assertIn(b['name'], ('nftables', 'iptables', 'ufw', 'ebtables'))
                self.assertIsInstance(b['rules'], int)
                # active is True / False / None(=couldn't read the ruleset)
                self.assertIn(b['active'], (True, False, None))

    def test_wired_into_host_health(self):
        src = (Path(__file__).resolve().parent.parent /
               'client' / 'remotepower-agent.py').read_text()
        self.assertIn('def collect_firewall_detail', src)
        self.assertIn("out['firewall'] = _fwd", src)


class TestDevicesListPagination(_HandlerBase):
    """docs/master-improvement-scoping-internal.md #59 -- handle_devices_list
    now slices via the shared _paginate_list() convention instead of a
    hand-rolled limit/offset, so ?meta=1 returns a real `total` count (the
    old bare-slice shape had no way to tell a client how many pages exist)."""
    def setUp(self):
        super().setUp()
        api.method = lambda: 'GET'
        api.save(api.DEVICES_FILE, {
            f'd{i}': {'name': f'host{i:02d}', 'monitored': True,
                      'last_seen': int(time.time())}
            for i in range(5)})

    def tearDown(self):
        os.environ.pop('QUERY_STRING', None)
        super().tearDown()

    def test_no_query_returns_bare_full_list(self):
        os.environ['QUERY_STRING'] = ''
        res = self.call(api.handle_devices_list)
        self.assertIsInstance(res, list)
        self.assertEqual(len(res), 5)

    def test_limit_returns_bare_sliced_list(self):
        os.environ['QUERY_STRING'] = 'limit=2'
        res = self.call(api.handle_devices_list)
        self.assertIsInstance(res, list)
        self.assertEqual(len(res), 2)

    def test_limit_offset_meta_returns_envelope_with_total(self):
        os.environ['QUERY_STRING'] = 'limit=2&offset=2&meta=1'
        res = self.call(api.handle_devices_list)
        self.assertIsInstance(res, dict)
        self.assertEqual(res['total'], 5)
        self.assertEqual(res['limit'], 2)
        self.assertEqual(res['offset'], 2)
        self.assertEqual(len(res['items']), 2)
        self.assertIsNotNone(res['next'])

    def test_last_page_has_no_next(self):
        os.environ['QUERY_STRING'] = 'limit=2&offset=4&meta=1'
        res = self.call(api.handle_devices_list)
        self.assertEqual(len(res['items']), 1)
        self.assertIsNone(res['next'])

    def test_stable_group_name_sort_preserved_under_pagination(self):
        os.environ['QUERY_STRING'] = 'limit=100'
        res = self.call(api.handle_devices_list)
        names = [d['name'] for d in res]
        self.assertEqual(names, sorted(names))


class TestTicketSlaByType(unittest.TestCase):
    """docs/master-improvement-scoping-internal.md #81 -- per-ticket-type SLA
    override. ticket_sla stays the flat priority->hours default; the new
    ticket_sla_by_type config only needs to set the priorities a type wants
    to diverge on."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._config_file = api.CONFIG_FILE
        api.CONFIG_FILE = self.d / 'config.json'
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        api.CONFIG_FILE = self._config_file

    def test_no_override_falls_through_to_flat_policy(self):
        pol = api._ticket_sla_policy('incident')
        self.assertEqual(pol, api.TICKET_SLA_DEFAULT_HOURS)

    def test_unknown_type_ignored(self):
        api.save(api.CONFIG_FILE, {'ticket_sla_by_type': {'incident': {'1': 0.25}}})
        pol = api._ticket_sla_policy('not-a-real-type')
        self.assertEqual(pol, api.TICKET_SLA_DEFAULT_HOURS)

    def test_type_override_wins_for_set_priority(self):
        api.save(api.CONFIG_FILE, {'ticket_sla_by_type': {'incident': {'1': 0.25}}})
        pol = api._ticket_sla_policy('incident')
        self.assertEqual(pol[1], 0.25)
        # priority 2..4 fall through to the (unchanged) default
        for k in (2, 3, 4):
            self.assertEqual(pol[k], api.TICKET_SLA_DEFAULT_HOURS[k])

    def test_other_type_unaffected(self):
        api.save(api.CONFIG_FILE, {'ticket_sla_by_type': {'incident': {'1': 0.25}}})
        pol = api._ticket_sla_policy('request')
        self.assertEqual(pol, api.TICKET_SLA_DEFAULT_HOURS)

    def test_ticket_sla_resolves_by_own_type(self):
        api.save(api.CONFIG_FILE, {'ticket_sla_by_type': {'change': {'2': 1.0}}})
        now = int(time.time())
        t = {'priority': 2, 'created_at': now, 'status': 'ongoing', 'type': 'change'}
        due, _ = api._ticket_sla(t)
        self.assertEqual(due, now + 3600)   # 1 business/wall hour, no calendar configured

    def test_explicit_policy_bypasses_type_merge(self):
        # a caller passing a raw policy dict (e.g. a what-if calc) is honoured
        # as-is -- no implicit type merge grafted on.
        api.save(api.CONFIG_FILE, {'ticket_sla_by_type': {'incident': {'3': 0.1}}})
        now = int(time.time())
        t = {'priority': 3, 'created_at': now, 'status': 'ongoing', 'type': 'incident'}
        due, _ = api._ticket_sla(t, {3: 2})
        self.assertEqual(due, now + 2 * 3600)


class TestTicketAutoRoute(unittest.TestCase):
    """docs/master-improvement-scoping-internal.md #81 -- default group/
    assignee for newly-created tickets, keyed by type."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._config_file = api.CONFIG_FILE
        api.CONFIG_FILE = self.d / 'config.json'
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        api.CONFIG_FILE = self._config_file

    def test_no_rule_returns_empty(self):
        self.assertEqual(api._ticket_auto_route('incident'), ('', ''))

    def test_unknown_type_returns_empty(self):
        api.save(api.CONFIG_FILE, {'ticket_auto_route': {
            'incident': {'group': 'noc', 'assignee': 'oncall'}}})
        self.assertEqual(api._ticket_auto_route('not-a-real-type'), ('', ''))

    def test_matched_rule_returned(self):
        api.save(api.CONFIG_FILE, {'ticket_auto_route': {
            'change': {'group': 'change-board', 'assignee': 'cab-lead'}}})
        self.assertEqual(api._ticket_auto_route('change'), ('change-board', 'cab-lead'))

    def test_partial_rule_ok(self):
        api.save(api.CONFIG_FILE, {'ticket_auto_route': {'request': {'group': 'helpdesk'}}})
        self.assertEqual(api._ticket_auto_route('request'), ('helpdesk', ''))


class TestTicketCreateAutoRoutes(unittest.TestCase):
    """End-to-end: handle_tickets() create path applies auto-route only when
    the operator didn't already specify group/assignee themselves."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        for attr in ('CONFIG_FILE', 'TICKETS_FILE', 'DEVICES_FILE', 'ALERTS_FILE'):
            setattr(self, f'_orig_{attr}', getattr(api, attr))
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        for f in (api.TICKETS_FILE, api.ALERTS_FILE, api.DEVICES_FILE):
            api.save(f, {})
        api.save(api.CONFIG_FILE, {'ticket_auto_route': {
            'incident': {'group': 'noc', 'assignee': 'oncall-bot'}}})
        self.cap = {}
        self._respond = api.respond
        self._auth = api.require_auth
        self._wrole = api.require_write_role
        self._fire = api.fire_webhook

        def _resp(s, b=None):
            self.cap['s'] = s; self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.require_auth = lambda *a, **k: 'tester'
        api.require_write_role = lambda *a, **k: 'tester'
        api.fire_webhook = lambda *a, **k: None

    def tearDown(self):
        api.respond = self._respond
        api.require_auth = self._auth
        api.require_write_role = self._wrole
        api.fire_webhook = self._fire
        for attr in ('CONFIG_FILE', 'TICKETS_FILE', 'DEVICES_FILE', 'ALERTS_FILE'):
            setattr(api, attr, getattr(self, f'_orig_{attr}'))

    def _create(self, body):
        _orig_method, _orig_json = api.method, api.get_json_obj
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: body
        try:
            api.handle_tickets()
        except api.HTTPError:
            pass
        finally:
            api.method = _orig_method
            api.get_json_obj = _orig_json
        return self.cap['b']

    def test_auto_route_fills_unset_fields(self):
        res = self._create({'subject': 'router down', 'type': 'incident'})
        t = next(x for x in api.load(api.TICKETS_FILE)['tickets'] if x['id'] == res['id'])
        self.assertEqual(t['group'], 'noc')
        self.assertEqual(t['assignee'], 'oncall-bot')

    def test_explicit_assignee_wins_over_auto_route(self):
        res = self._create({'subject': 'router down', 'type': 'incident',
                            'assignee': 'jmo', 'group': 'tier2'})
        t = next(x for x in api.load(api.TICKETS_FILE)['tickets'] if x['id'] == res['id'])
        self.assertEqual(t['group'], 'tier2')
        self.assertEqual(t['assignee'], 'jmo')

    def test_type_with_no_rule_falls_back_to_actor(self):
        res = self._create({'subject': 'new laptop', 'type': 'request'})
        t = next(x for x in api.load(api.TICKETS_FILE)['tickets'] if x['id'] == res['id'])
        self.assertEqual(t['group'], '')
        self.assertEqual(t['assignee'], 'tester')   # falls back to the actor, unchanged behavior


class TestStepUpAuth(_HandlerBase):
    """docs/master-improvement-scoping-internal.md #33 -- a shared, reusable
    step-up (fresh re-auth) primitive. require_auth/get_token_from_request
    are stubbed by _HandlerBase (raw token 't', user 'jakob'); this class adds
    TOKENS_FILE isolation and seeds a real session entry so
    _step_up_token_entry()'s real _resolve_token_key lookup has something to
    find (only require_auth/verify_token/get_token_from_request are faked --
    the token-resolution and stamping logic under test is the real code)."""
    def setUp(self):
        super().setUp()
        self._files['TOKENS_FILE'] = api.TOKENS_FILE
        api.TOKENS_FILE = self.d / 'tokens.json'
        self.tkey = api._token_hash('t')
        api.save(api.TOKENS_FILE, {self.tkey: {'user': 'jakob', 'created': int(time.time())}})
        api.save(api.USERS_FILE, {'jakob': {
            'password_hash': api.hash_password('correct horse'), 'role': 'admin'}})

    def _stamp_step_up(self, ago_seconds=0):
        tokens = api.load(api.TOKENS_FILE)
        tokens[self.tkey]['step_up_at'] = int(time.time()) - ago_seconds
        api.save(api.TOKENS_FILE, tokens)

    def test_require_step_up_blocks_without_a_stamp(self):
        with self.assertRaises(api.HTTPError) as cm:
            api.require_step_up()
        self.assertEqual(cm.exception.status, 403)
        self.assertEqual(cm.exception.body.get('code'), 'step_up_required')

    def test_require_step_up_passes_with_a_fresh_stamp(self):
        self._stamp_step_up(ago_seconds=30)
        self.assertEqual(api.require_step_up(), 'jakob')

    def test_require_step_up_blocks_a_stale_stamp(self):
        self._stamp_step_up(ago_seconds=api.STEP_UP_WINDOW_SECONDS + 60)
        with self.assertRaises(api.HTTPError) as cm:
            api.require_step_up()
        self.assertEqual(cm.exception.status, 403)

    def test_require_step_up_degrades_gracefully_for_no_local_credential(self):
        # a pure-SSO admin with no local password and no TOTP has nothing to
        # step up with -- never permanently locked out (see the docstring).
        api.save(api.USERS_FILE, {'jakob': {'role': 'admin'}})
        self.assertEqual(api.require_step_up(), 'jakob')

    def test_verify_correct_password_stamps_session(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'password': 'correct horse'}
        try:
            res = self.call(api.handle_step_up_verify)
        finally:
            del api.method
            del api.get_json_obj
        self.assertTrue(res['ok'])
        tokens = api.load(api.TOKENS_FILE)
        self.assertGreater(tokens[self.tkey].get('step_up_at', 0), 0)

    def test_verify_wrong_password_401s_and_does_not_stamp(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'password': 'wrong'}
        try:
            self.call(api.handle_step_up_verify)
        finally:
            del api.method
            del api.get_json_obj
        self.assertEqual(self.cap['s'], 401)
        tokens = api.load(api.TOKENS_FILE)
        self.assertNotIn('step_up_at', tokens[self.tkey])

    def test_verify_correct_totp_stamps_session(self):
        secret = api._generate_totp_secret()
        api.save(api.USERS_FILE, {'jakob': {
            'password_hash': api.hash_password('correct horse'),
            'role': 'admin', 'totp_secret': secret}})
        code = api._totp(secret)[1]   # current code (window offset 0)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'totp_code': code}
        try:
            res = self.call(api.handle_step_up_verify)
        finally:
            del api.method
            del api.get_json_obj
        self.assertTrue(res['ok'])

    def test_route_registered(self):
        self.assertIs(api._build_exact_routes()[('POST', '/api/auth/step-up')],
                      api.handle_step_up_verify)


class TestThreatModelDoc(unittest.TestCase):
    """docs/master-improvement-scoping-internal.md #22 -- a structured STRIDE
    threat/mitigation matrix, linked from the existing security docs."""

    @classmethod
    def setUpClass(cls):
        cls.doc = (Path(__file__).resolve().parent.parent
                   / 'docs' / 'threat-model.md').read_text()

    def test_covers_every_stride_category(self):
        for cat in ('Spoofing', 'Tampering', 'Repudiation',
                    'Information disclosure', 'Denial of service',
                    'Elevation of privilege'):
            self.assertIn(f'## {cat}', self.doc, f'missing STRIDE category: {cat}')

    def test_cites_this_sessions_real_fixes(self):
        # the doc must reference actual shipped mechanisms, not aspirational
        # ones -- spot-check a few landed this session.
        self.assertIn('step-up', self.doc.lower())
        self.assertIn('litigation_hold', self.doc)
        self.assertIn('_caller_effective_tenant', self.doc)

    def test_linked_from_security_md(self):
        security = (Path(__file__).resolve().parent.parent
                    / 'docs' / 'security.md').read_text()
        self.assertIn('threat-model.md', security)

    def test_linked_from_docs_readme(self):
        readme = (Path(__file__).resolve().parent.parent
                  / 'docs' / 'README.md').read_text()
        self.assertIn('threat-model.md', readme)


if __name__ == '__main__':
    unittest.main()
