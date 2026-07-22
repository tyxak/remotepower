#!/usr/bin/env python3
"""
Tests for v4.2.0 "5ecur1tyM4tter5" — B5 authorized scan orchestration (P1).

P1 scope under test: the `scan` RBAC permission, scope-checked scan-job CRUD
against ENROLLED hosts only, the scanner-satellite claim/results worker path,
server-side target derivation (the cardinal authorization control), and
finding normalisation. The `scan_finding` webhook event + non-enrolled
(domain-verified) targets are P2 and intentionally absent here.
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
sys.path.insert(0, str(Path(__file__).parent))   # routing_harness

_spec = importlib.util.spec_from_file_location("api_v420", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _ScanBase(unittest.TestCase):
    """Drive scan handlers directly with stubbed auth/request/respond."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('DEVICES_FILE', 'ROLES_FILE', 'SATELLITES_FILE',
                     'SCANS_FILE', 'SCAN_TARGETS_FILE', 'SCAN_SCHEDULES_FILE',
                     'MAINT_FILE', 'CONFIG_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('verify_token', 'get_token_from_request', 'audit_log',
                       'respond', 'method', 'get_json_body', '_caller_scope',
                       'require_admin_auth')}
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api.audit_log = lambda *a, **k: None
        api._caller_scope = lambda: None
        api.require_admin_auth = lambda: 'jakob'

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: 'POST'
        os.environ.pop('HTTP_X_RP_SATELLITE', None)

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)
        os.environ.pop('HTTP_X_RP_SATELLITE', None)

    def call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')

    # --- helpers -----------------------------------------------------------
    def _device(self, dev_id='dev1', ip='10.0.0.5', group='prod', name='web1'):
        api.save(api.DEVICES_FILE,
                 {**(api.load(api.DEVICES_FILE) or {}),
                  dev_id: {'name': name, 'ip': ip, 'group': group}})

    def _scanner_satellite(self, scanner=True):
        api.require_admin_auth = lambda: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'name': 'dmz', 'scanner': scanner}
        created = self.call(api.handle_satellites_create)
        return created['token'], created['id']

    def _as_admin(self):
        api.verify_token = lambda t: ('jakob', 'admin')


class TestScanPermission(_ScanBase):
    def test_scan_is_a_granular_perm(self):
        self.assertIn('scan', api._RBAC_PERMS)

    def test_scan_not_in_legacy_exec_umbrella(self):
        # A custom role granted the legacy 'exec' umbrella must NOT silently
        # gain the offensive scan capability.
        self.assertNotIn('scan', api._expand_perms(['exec']))

    def test_admin_has_scan(self):
        self.assertIn('scan', api._resolve_role('admin')['permissions'])

    def test_viewer_denied(self):
        api.verify_token = lambda t: ('v', 'viewer')
        api.method = lambda: 'GET'
        self.call(api.handle_scans_list)
        self.assertEqual(self.cap['s'], 403)


class TestWpscanVhostGate(_ScanBase):
    """wpscan is only useful against a HOSTNAME — WordPress answers on a vhost,
    not the bare IP — so the ownership-verified-vhost gate is the DEFAULT path
    for this tool, not an edge case. It must fail with an actionable message.
    """

    def _queue(self, **over):
        self._device()
        api.verify_token = lambda t: ('jakob', 'admin')
        api.method = lambda: 'POST'
        body = {'device_id': 'dev1', 'tool': 'wpscan', 'profile': 'passive',
                'intensity': 'quick', **over}
        api.get_json_body = lambda: dict(body)
        return self.call(api.handle_scans_create)

    def test_wpscan_is_queueable_in_the_passive_profile(self):
        """It is in SCAN_TOOLS, so no profile juggling should be needed."""
        self.assertIn('wpscan', api.SCAN_TOOLS)
        self.assertIn('wpscan', api.SCAN_ACTIVE_TOOLS)

    def test_unverified_vhost_is_refused_with_the_way_out(self):
        out = self._queue(vhost='example.test')
        self.assertEqual(self.cap['s'], 400)
        err = out['error']
        # Naming the rule is not enough — the operator has to be told where to
        # go and what to do, or the feature is a dead end.
        self.assertIn('not an ownership-verified', err)
        for word in ('External targets', 'Verify'):
            self.assertIn(word, err, f'the error must name {word!r}')

    def test_a_verified_vhost_queues_and_targets_the_hostname(self):
        api.save(api.SCAN_TARGETS_FILE,
                 {'t1': {'id': 't1', 'target': 'example.test',
                         'verified': True, 'kind': 'domain'}})
        out = self._queue(vhost='example.test')
        self.assertTrue(out.get('ok'), out)
        self.assertEqual(out['scan']['status'], 'queued')
        # The scan must hit the vhost, not the device's bare IP.
        self.assertEqual(out['scan']['target'], 'example.test')

    def test_the_vhost_is_matched_case_insensitively(self):
        api.save(api.SCAN_TARGETS_FILE,
                 {'t1': {'id': 't1', 'target': 'example.test',
                         'verified': True, 'kind': 'domain'}})
        out = self._queue(vhost='EXAMPLE.TEST')
        self.assertTrue(out.get('ok'), out)


class TestScanFormGuidesTheOperator(unittest.TestCase):
    """The queue button used to fail server-side for the two most likely
    mistakes. Both are now caught where the fix is visible."""

    @property
    def _js(self):
        return (Path(__file__).resolve().parent.parent / 'server' / 'html'
                / 'static' / 'js' / 'app.js').read_text()

    def test_typing_a_device_name_without_picking_it_says_so(self):
        # The box LOOKS filled — typing clears the selection — so repeating the
        # label ("pick a device") reads as a bug rather than an instruction.
        self.assertIn('typing the name alone does not select it', self._js)

    def test_an_unverified_vhost_is_caught_before_the_round_trip(self):
        self.assertIn('_scanVerifiedVhosts', self._js)
        self.assertIn('is not an ownership-verified target yet', self._js)

    def test_wpscan_without_a_vhost_is_refused_client_side(self):
        self.assertIn('wpscan needs a vhost', self._js)

    def test_verified_targets_are_offered_in_the_vhost_box(self):
        html = (Path(__file__).resolve().parent.parent / 'server' / 'html'
                / 'index.html').read_text()
        self.assertIn('list="scan-vhost-verified"', html)
        self.assertIn('id="scan-vhost-verified"', html)
        self.assertIn('_syncVerifiedVhosts', self._js)


class TestScanLifecycle(_ScanBase):
    def test_create_claim_results_detail(self):
        self._device()
        self._scanner_satellite()
        tok = self._scanner_token = None
        tok, sid_sat = self._scanner_satellite()
        # create (admin)
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        created = self.call(api.handle_scans_create)
        self.assertTrue(created['ok'])
        scan_id = created['id']
        self.assertEqual(created['scan']['status'], 'queued')
        # target is derived server-side from the device, not client input
        self.assertEqual(created['scan']['target'], '10.0.0.5')

        # satellite claims it
        os.environ['HTTP_X_RP_SATELLITE'] = tok
        api.method = lambda: 'POST'
        claimed = self.call(api.handle_scan_claim)
        self.assertEqual(claimed['scan']['id'], scan_id)
        self.assertEqual(claimed['scan']['target'], '10.0.0.5')
        self.assertEqual(api.load(api.SCANS_FILE)[scan_id]['status'], 'running')

        # satellite posts findings
        api.get_json_body = lambda: {'status': 'done', 'findings': [
            {'rule_id': 'tls-version', 'title': 'Old TLS', 'severity': 'high',
             'evidence': 'TLS 1.0', 'reference': 'http://x'},
            {'rule_id': 'hdr', 'title': 'Missing header', 'severity': 'low'},
        ]}
        ok = self.call(api.handle_scan_results, scan_id)
        self.assertTrue(ok['ok'])

        # detail (admin) shows normalised findings + counts
        os.environ.pop('HTTP_X_RP_SATELLITE', None)
        self._as_admin()
        api.method = lambda: 'GET'
        det = self.call(api.handle_scan_detail, scan_id)
        self.assertEqual(det['status'], 'done')
        self.assertEqual(det['finding_count'], 2)
        self.assertEqual(det['severity_counts']['high'], 1)
        self.assertEqual(det['severity_counts']['low'], 1)
        self.assertEqual(len(det['findings']), 2)

    def test_delete_queued(self):
        self._device()
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        scan_id = self.call(api.handle_scans_create)['id']
        api.method = lambda: 'DELETE'
        res = self.call(api.handle_scan_delete, scan_id)
        self.assertTrue(res['removed'])
        self.assertNotIn(scan_id, api.load(api.SCANS_FILE))

    def test_list_newest_first(self):
        self._device('dev1'); self._device('dev2')
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        self.call(api.handle_scans_create)
        time.sleep(1)
        api.get_json_body = lambda: {'device_id': 'dev2'}
        self.call(api.handle_scans_create)
        api.method = lambda: 'GET'
        lst = self.call(api.handle_scans_list)
        self.assertEqual(len(lst['scans']), 2)
        self.assertGreaterEqual(lst['scans'][0]['created'], lst['scans'][1]['created'])
        self.assertIn('nuclei', lst['tools'])
        self.assertIn('passive', lst['profiles'])

    def test_multi_tool_accepted_and_unknown_rejected(self):
        self._device('dev1')
        self._as_admin()
        api.method = lambda: 'POST'
        for tool in ('nuclei', 'nikto', 'nmap'):
            api.get_json_body = lambda t=tool: {'device_id': 'dev1', 'tool': t}
            created = self.call(api.handle_scans_create)
            self.assertEqual(created['scan']['tool'], tool)
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'metasploit'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)


class TestScanAuthorization(_ScanBase):
    """The cardinal control: a target must be an enrolled, in-scope device,
    and its address is derived server-side."""

    def test_unknown_device_404(self):
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'ghost'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 404)

    def test_missing_device_id_400(self):
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)

    def test_blocked_address_refused(self):
        # cloud-metadata / link-local target is refused even for an enrolled host
        self._device('dev1', ip='169.254.169.254')
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)
        self.assertIn('blocked', self.cap['b']['error'])

    def test_client_cannot_inject_target(self):
        # a client-supplied 'target' is ignored — only the device IP is used
        self._device('dev1', ip='10.0.0.9')
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1',
                                     'target': 'evil.example.com'}
        created = self.call(api.handle_scans_create)
        self.assertEqual(created['scan']['target'], '10.0.0.9')

    def test_unsupported_tool_400(self):
        self._device('dev1')
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'metasploit'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)

    def test_scoped_role_cannot_scan_out_of_scope(self):
        self._device('dev1', group='prod')
        self._device('dev2', group='secret')
        api.save(api.ROLES_FILE, {'roles': [
            {'name': 'prodscan', 'permissions': ['scan'],
             'scope': {'type': 'groups', 'values': ['prod']}}]})
        api.verify_token = lambda t: ('op', 'prodscan')
        api.method = lambda: 'POST'
        # in-scope device works
        api.get_json_body = lambda: {'device_id': 'dev1'}
        self.assertTrue(self.call(api.handle_scans_create)['ok'])
        # out-of-scope device is refused by require_perm scope check
        api.get_json_body = lambda: {'device_id': 'dev2'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 403)


class TestScannerSatelliteAuth(_ScanBase):
    def test_claim_requires_satellite_token(self):
        api.method = lambda: 'POST'
        self.call(api.handle_scan_claim)               # no X-RP-Satellite header
        self.assertEqual(self.cap['s'], 401)

    def test_claim_rejects_non_scanner_satellite(self):
        tok, _ = self._scanner_satellite(scanner=False)
        os.environ['HTTP_X_RP_SATELLITE'] = tok
        api.method = lambda: 'POST'
        self.call(api.handle_scan_claim)
        self.assertEqual(self.cap['s'], 403)

    def test_results_from_other_satellite_rejected(self):
        self._device()
        tok_a, _ = self._scanner_satellite()
        tok_b, _ = self._scanner_satellite()
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        scan_id = self.call(api.handle_scans_create)['id']
        # satellite A claims
        os.environ['HTTP_X_RP_SATELLITE'] = tok_a
        self.call(api.handle_scan_claim)
        # satellite B tries to post results -> 403
        os.environ['HTTP_X_RP_SATELLITE'] = tok_b
        api.get_json_body = lambda: {'status': 'done', 'findings': []}
        self.call(api.handle_scan_results, scan_id)
        self.assertEqual(self.cap['s'], 403)
        # scan is untouched (still running)
        self.assertEqual(api.load(api.SCANS_FILE)[scan_id]['status'], 'running')

    def test_results_on_non_running_409(self):
        self._device()
        tok, _ = self._scanner_satellite()
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        scan_id = self.call(api.handle_scans_create)['id']   # still queued
        os.environ['HTTP_X_RP_SATELLITE'] = tok
        api.get_json_body = lambda: {'status': 'done', 'findings': []}
        self.call(api.handle_scan_results, scan_id)
        self.assertEqual(self.cap['s'], 409)


class TestScanFindingNormalisation(_ScanBase):
    def test_bad_severity_becomes_unknown_and_fields_bounded(self):
        f = api._validate_scan_finding(
            {'rule_id': 'x' * 999, 'title': 'T', 'severity': 'apocalyptic',
             'evidence': 'e', 'reference': 'r'})
        self.assertEqual(f['severity'], 'unknown')
        self.assertLessEqual(len(f['rule_id']), 200)

    def test_sev_counts(self):
        c = api._scan_sev_counts(
            [{'severity': 'high'}, {'severity': 'high'}, {'severity': 'weird'}])
        self.assertEqual(c['high'], 2)
        self.assertEqual(c['unknown'], 1)


class TestScanFindingEvent(_ScanBase):
    """v4.2.0 (B5) P2 start: scan_finding fires into the alert/webhook pipeline
    only when a completed scan carries high/critical findings."""

    def _complete_scan(self, findings):
        self._device()
        tok, _ = self._scanner_satellite()
        self._as_admin()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}
        scan_id = self.call(api.handle_scans_create)['id']
        os.environ['HTTP_X_RP_SATELLITE'] = tok
        self.call(api.handle_scan_claim)
        fired = []
        self._orig_fw = api.fire_webhook
        api.fire_webhook = lambda ev, p: fired.append((ev, p))
        try:
            api.get_json_body = lambda: {'status': 'done', 'findings': findings}
            self.call(api.handle_scan_results, scan_id)
        finally:
            api.fire_webhook = self._orig_fw
        return fired

    def test_registries_consistent(self):
        self.assertIn('scan_finding', api.WEBHOOK_EVENT_NAMES)
        self.assertIn('scan_finding', api._ALERT_RULES)
        self.assertEqual(api.EVENT_KIND_MAP.get('scan_finding'), 'scan')

    def test_ondemand_high_does_not_fire(self):
        # v4.2.0 #7: on-demand scans never alert, even on high/critical.
        self.assertEqual(self._complete_scan([{'severity': 'high', 'title': 'x'}]), [])

    def test_scan_finding_severity_is_info(self):
        self.assertEqual(api._alert_severity('scan_finding', {'critical': 5}), 'info')

    def test_silent_on_clean(self):
        self.assertEqual(self._complete_scan([]), [])


class TestScanTargets(_ScanBase):
    """B5 P2: ownership-verified non-enrolled targets (ACME-style)."""

    def test_classify(self):
        self.assertEqual(api._classify_scan_target('example.com'), ('domain', 'example.com'))
        self.assertEqual(api._classify_scan_target('HTTPS://Ex.com/p'), ('domain', 'ex.com'))
        self.assertEqual(api._classify_scan_target('203.0.113.5'), ('ip', '203.0.113.5'))
        self.assertEqual(api._classify_scan_target('10.0.0.1:8443'), ('ip', '10.0.0.1'))
        self.assertEqual(api._classify_scan_target('not valid')[0], None)

    def _create(self, target='example.com'):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': target}
        return self.call(api.handle_scan_targets_create)

    def test_create_returns_proof(self):
        r = self._create('example.com')
        self.assertTrue(r['ok'])
        self.assertTrue(r['token'].startswith('rpscan-'))
        self.assertEqual(r['dns']['name'], '_remotepower-scan-auth.example.com')
        self.assertEqual(r['file']['content'], r['token'])
        # stored unverified
        self.assertFalse(list(api.load(api.SCAN_TARGETS_FILE).values())[0]['verified'])

    def test_create_invalid_400(self):
        self._create('not a domain')
        self.assertEqual(self.cap['s'], 400)

    def test_create_duplicate_409(self):
        self._create('example.com')
        self._create('example.com')
        self.assertEqual(self.cap['s'], 409)

    def test_verify_dns_success(self):
        r = self._create('example.com')
        api._verify_scan_target_dns = lambda t, tok: (True, '')
        api.method = lambda: 'POST'
        res = self.call(api.handle_scan_target_verify, r['id'])
        self.assertTrue(res['verified'])
        self.assertEqual(res['method'], 'dns')
        self.assertTrue(api.load(api.SCAN_TARGETS_FILE)[r['id']]['verified'])

    def test_verify_failure(self):
        r = self._create('example.com')
        api._verify_scan_target_dns = lambda t, tok: (False, 'no TXT')
        api._verify_scan_target_file = lambda t, tok: (False, 'no file')
        api.method = lambda: 'POST'
        res = self.call(api.handle_scan_target_verify, r['id'])
        self.assertFalse(res['verified'])

    def test_scan_unverified_target_rejected(self):
        r = self._create('example.com')
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'scan_target_id': r['id']}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)

    def test_scan_verified_target_ok(self):
        r = self._create('example.com')
        api._verify_scan_target_dns = lambda t, tok: (True, '')
        api.method = lambda: 'POST'
        self.call(api.handle_scan_target_verify, r['id'])
        api.get_json_body = lambda: {'scan_target_id': r['id']}
        created = self.call(api.handle_scans_create)
        self.assertTrue(created['ok'])
        self.assertEqual(created['scan']['target'], 'example.com')
        self.assertEqual(created['scan']['target_device_id'], '')

    def test_scoped_role_cannot_scan_target(self):
        r = self._create('example.com')
        api._verify_scan_target_dns = lambda t, tok: (True, '')
        api.method = lambda: 'POST'
        self.call(api.handle_scan_target_verify, r['id'])
        # a scoped (non-all) caller is refused even for a verified target
        api.verify_token = lambda t: ('op', 'prodscan')
        api.save(api.ROLES_FILE, {'roles': [
            {'name': 'prodscan', 'permissions': ['scan'],
             'scope': {'type': 'groups', 'values': ['prod']}}]})
        api._caller_scope = lambda: {'type': 'groups', 'values': ['prod']}
        api.get_json_body = lambda: {'scan_target_id': r['id']}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 403)

    def test_list_and_delete(self):
        r = self._create('example.com')
        api.method = lambda: 'GET'
        lst = self.call(api.handle_scan_targets_list)
        self.assertEqual(len(lst['targets']), 1)
        self.assertNotIn('token', lst['targets'][0])   # no secret in list
        api.method = lambda: 'DELETE'
        self.call(api.handle_scan_target_delete, r['id'])
        self.assertEqual(api.load(api.SCAN_TARGETS_FILE), {})


class TestActiveScans(_ScanBase):
    """B5 P3: active/intrusive tier — attestation + maintenance-window gating."""

    def _verified_target(self, target='example.com'):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': target}
        r = self.call(api.handle_scan_targets_create)
        api._verify_scan_target_dns = lambda t, tok: (True, '')
        self.call(api.handle_scan_target_verify, r['id'])
        return r['id']

    def test_profiles_and_tools(self):
        self.assertEqual(set(api.SCAN_PROFILES), {'passive', 'active'})
        self.assertEqual(set(api.SCAN_TOOLS), {'nuclei', 'nikto', 'nmap', 'wpscan'})
        self.assertTrue({'zap', 'wapiti'}.issubset(set(api.SCAN_ACTIVE_TOOLS)))

    def test_active_tool_rejected_in_passive(self):
        self._device('dev1')
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'zap', 'profile': 'passive'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)

    def test_active_requires_attestation(self):
        self._device('dev1')
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'nuclei', 'profile': 'active'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 403)
        self.assertIn('attestation', self.cap['b']['error'])

    def test_active_enrolled_needs_window(self):
        self._device('dev1')
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'nuclei',
                                     'profile': 'active', 'attestation': True}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 409)   # no active maintenance window

    def test_active_enrolled_override_window(self):
        self._device('dev1')
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'nuclei',
                                     'profile': 'active', 'attestation': True,
                                     'override_window': True}
        created = self.call(api.handle_scans_create)
        self.assertTrue(created['ok'])
        rec = api.load(api.SCANS_FILE)[created['id']]
        self.assertEqual(rec['profile'], 'active')
        self.assertTrue(rec['attested'])
        self.assertTrue(rec['window_overridden'])
        self.assertEqual(rec['attested_by'], 'jakob')

    def test_active_domain_no_window_needed(self):
        tid = self._verified_target('example.com')
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'scan_target_id': tid, 'tool': 'zap',
                                     'profile': 'active', 'attestation': True}
        created = self.call(api.handle_scans_create)
        self.assertTrue(created['ok'])
        self.assertEqual(created['scan']['tool'], 'zap')
        self.assertTrue(created['scan']['attested'])

    def test_window_active_false_without_windows(self):
        self.assertFalse(api._scan_window_active('dev1', {'group': 'g'}))


class TestHostScans(_ScanBase):
    """B5 P3 (finish): agent-side host-posture scans (lynis), dispatched +
    ingested over the heartbeat channel rather than a satellite."""

    def test_host_tool_sets_agent_runner(self):
        self._device('dev1')
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'lynis'}
        created = self.call(api.handle_scans_create)
        self.assertTrue(created['ok'])
        self.assertEqual(created['scan']['runner'], 'agent')
        self.assertEqual(created['scan']['profile'], 'host')

    def test_host_tool_rejects_domain_target(self):
        # lynis runs on a host; a verified domain target is nonsensical
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': 'example.com'}
        r = self.call(api.handle_scan_targets_create)
        api._verify_scan_target_dns = lambda t, tok: (True, '')
        self.call(api.handle_scan_target_verify, r['id'])
        api.get_json_body = lambda: {'scan_target_id': r['id'], 'tool': 'lynis'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)

    def test_satellite_claim_skips_agent_scans(self):
        self._device('dev1')
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'lynis'}
        self.call(api.handle_scans_create)              # an agent-run scan
        tok, _ = self._scanner_satellite()
        import os
        os.environ['HTTP_X_RP_SATELLITE'] = tok
        claimed = self.call(api.handle_scan_claim)
        self.assertIsNone(claimed['scan'])              # satellite won't take it

    def test_claim_agent_scan_and_apply_results(self):
        self._device('dev1')
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'lynis'}
        sid = self.call(api.handle_scans_create)['id']
        # the heartbeat dispatch helper claims it (queued → running)
        job = api._claim_agent_scan('dev1')
        self.assertEqual(job['id'], sid)
        self.assertEqual(job['tool'], 'lynis')
        self.assertEqual(api.load(api.SCANS_FILE)[sid]['status'], 'running')
        # a DIFFERENT host cannot complete this scan (restrict_device guard)
        ok, code = api._apply_scan_results(sid, 'done', [], '', by='agent:evil',
                                           restrict_device='evil')
        self.assertFalse(ok); self.assertEqual(code, 403)
        # the owning host completes it with findings
        ok, code = api._apply_scan_results(
            sid, 'done', [{'rule_id': 'AUTH-9282', 'title': 'no faillock',
                           'severity': 'medium'}], '', by='agent:dev1',
            restrict_device='dev1')
        self.assertTrue(ok)
        rec = api.load(api.SCANS_FILE)[sid]
        self.assertEqual(rec['status'], 'done')
        self.assertEqual(len(rec['findings']), 1)


class TestScanOptionsAndVhost(_ScanBase):
    """B5 #6 (intensity + run-all-tools) and #1 (vhost)."""

    def test_intensity_stored(self):
        self._device('dev1'); self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'intensity': 'full'}
        created = self.call(api.handle_scans_create)
        self.assertEqual(created['scan']['intensity'], 'full')

    def test_bad_intensity_400(self):
        self._device('dev1'); self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'intensity': 'ludicrous'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)

    def test_all_tools_fans_out(self):
        self._device('dev1'); self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'all', 'profile': 'passive'}
        created = self.call(api.handle_scans_create)
        self.assertEqual(created['count'], len(api.SCAN_TOOLS))
        tools = sorted(v['tool'] for v in api.load(api.SCANS_FILE).values())
        self.assertEqual(tools, sorted(api.SCAN_TOOLS))

    def test_vhost_requires_verified_target(self):
        self._device('dev1'); self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'vhost': 'remote.example.com'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)

    def test_vhost_uses_verified_target(self):
        self._device('dev1')
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': 'remote.example.com'}
        r = self.call(api.handle_scan_targets_create)
        api._verify_scan_target_dns = lambda t, tok: (True, '')
        self.call(api.handle_scan_target_verify, r['id'])
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'vhost': 'remote.example.com'}
        created = self.call(api.handle_scans_create)
        self.assertEqual(created['scan']['target'], 'remote.example.com')
        self.assertEqual(created['scan']['target_device_id'], 'dev1')


class TestScanDeleteClear(_ScanBase):
    """B5: remove a scan record (+findings); clear all finished scans."""

    def _make_scan(self, dev='dev1'):
        self._device(dev)
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': dev}
        return self.call(api.handle_scans_create)['id']

    def test_delete_removes_record(self):
        sid = self._make_scan()
        api.method = lambda: 'DELETE'
        res = self.call(api.handle_scan_delete, sid)
        self.assertTrue(res['removed'])
        self.assertNotIn(sid, api.load(api.SCANS_FILE))

    def test_delete_unknown_404(self):
        self._as_admin(); api.method = lambda: 'DELETE'
        self.call(api.handle_scan_delete, 'ghost')
        self.assertEqual(self.cap['s'], 404)

    def test_clear_finished_only(self):
        done = self._make_scan('dev1')
        queued = self._make_scan('dev2')
        # mark `done` finished, leave `queued` queued
        st = api.load(api.SCANS_FILE); st[done]['status'] = 'done'; api.save(api.SCANS_FILE, st)
        api.method = lambda: 'POST'
        res = self.call(api.handle_scans_clear)
        self.assertEqual(res['removed'], 1)
        scans = api.load(api.SCANS_FILE)
        self.assertNotIn(done, scans)        # finished → cleared
        self.assertIn(queued, scans)         # still queued → kept


class TestSatelliteTargeting(_ScanBase):
    """B5: route a network scan to a SPECIFIC scanner satellite (e.g. the one on
    the target's network segment), or leave it to any scanner satellite."""

    def test_list_includes_scanner_satellites(self):
        tok, sid = self._scanner_satellite()
        self._as_admin(); api.method = lambda: 'GET'
        lst = self.call(api.handle_scans_list)
        self.assertTrue(any(s['id'] == sid for s in lst['satellites']))

    def test_unknown_satellite_rejected(self):
        self._device('dev1')
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'satellite_id': 'nope'}
        self.call(api.handle_scans_create)
        self.assertEqual(self.cap['s'], 400)

    def test_targeted_scan_only_claimed_by_its_satellite(self):
        self._device('dev1')
        tok_a, id_a = self._scanner_satellite()
        tok_b, id_b = self._scanner_satellite()
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'satellite_id': id_a}
        sid = self.call(api.handle_scans_create)['id']
        self.assertEqual(api.load(api.SCANS_FILE)[sid]['satellite_id'], id_a)
        import os
        os.environ['HTTP_X_RP_SATELLITE'] = tok_b           # wrong satellite
        self.assertIsNone(self.call(api.handle_scan_claim)['scan'])
        os.environ['HTTP_X_RP_SATELLITE'] = tok_a           # the assigned one
        self.assertEqual(self.call(api.handle_scan_claim)['scan']['id'], sid)

    def test_unassigned_scan_claimed_by_any(self):
        self._device('dev1')
        tok, _ = self._scanner_satellite()
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1'}   # no satellite_id
        sid = self.call(api.handle_scans_create)['id']
        import os
        os.environ['HTTP_X_RP_SATELLITE'] = tok
        self.assertEqual(self.call(api.handle_scan_claim)['scan']['id'], sid)

    def test_host_scan_ignores_satellite(self):
        self._device('dev1')
        self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'lynis',
                                     'satellite_id': 'whatever'}
        created = self.call(api.handle_scans_create)
        self.assertTrue(created['ok'])                       # not rejected
        self.assertEqual(api.load(api.SCANS_FILE)[created['id']]['satellite_id'], '')


class TestScanSchedules(_ScanBase):
    """B5 #4: recurring scheduled scans (cron) + due-firing."""

    def test_create_list_delete(self):
        self._device('dev1'); self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'nuclei', 'cron': '0 3 * * *'}
        created = self.call(api.handle_scan_schedules_create)
        self.assertTrue(created['ok']); sid = created['id']
        self.assertGreater(created['schedule']['next_run'], 0)
        api.method = lambda: 'GET'
        lst = self.call(api.handle_scan_schedules_list)
        self.assertTrue(any(s['id'] == sid for s in lst['schedules']))
        api.method = lambda: 'DELETE'
        self.call(api.handle_scan_schedule_delete, sid)
        self.assertEqual(api.load(api.SCAN_SCHEDULES_FILE), {})

    def test_run_now_enqueues_scan(self):
        self._device('dev1'); self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'tool': 'nuclei', 'cron': '0 3 * * *'}
        sid = self.call(api.handle_scan_schedules_create)['id']
        api.method = lambda: 'POST'
        self.call(api.handle_scan_schedule_run, sid)
        self.assertEqual(len(api.load(api.SCANS_FILE)), 1)
        self.assertGreater(api.load(api.SCAN_SCHEDULES_FILE)[sid]['last_run'], 0)

    def test_bad_cron_400(self):
        self._device('dev1'); self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'cron': 'not a cron'}
        self.call(api.handle_scan_schedules_create)
        self.assertEqual(self.cap['s'], 400)

    def test_active_schedule_needs_attestation(self):
        self._device('dev1'); self._as_admin(); api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'dev1', 'profile': 'active',
                                     'tool': 'nuclei', 'cron': '0 3 * * *'}
        self.call(api.handle_scan_schedules_create)
        self.assertEqual(self.cap['s'], 403)

    def test_create_scheduled_scan_enqueues(self):
        self._device('dev1')
        api._create_scheduled_scan({'id': 's1', 'device_id': 'dev1', 'tool': 'nuclei',
                                    'profile': 'passive', 'intensity': 'quick', 'satellite_id': ''})
        scans = api.load(api.SCANS_FILE)
        self.assertEqual(len(scans), 1)
        rec = list(scans.values())[0]
        self.assertEqual(rec['tool'], 'nuclei')
        self.assertEqual(rec['status'], 'queued')
        self.assertEqual(rec['target'], '10.0.0.5')

    def test_due_schedule_fires(self):
        self._device('dev1')
        now = int(api.time.time())
        api.save(api.SCAN_SCHEDULES_FILE, {'s1': {
            'id': 's1', 'device_id': 'dev1', 'tool': 'nuclei', 'profile': 'passive',
            'intensity': 'quick', 'satellite_id': '', 'cron': '* * * * *',
            'enabled': True, 'next_run': now - 10, 'last_run': 0}})
        try:
            (api.DATA_DIR / '.scan_sched_check').unlink()   # bypass the 60s gate
        except OSError:
            pass
        api.run_scheduled_scans_if_due()
        self.assertGreaterEqual(len(api.load(api.SCANS_FILE)), 1)
        self.assertGreater(api.load(api.SCAN_SCHEDULES_FILE)['s1']['next_run'], now)


class TestScanFindingInfoOnly(_ScanBase):
    """#7: on-demand scans never alert; scheduled scans fire a quiet INFO notice."""

    def setUp(self):
        super().setUp()
        self._fired = []
        self._orig_fw = api.fire_webhook
        api.fire_webhook = lambda ev, p: self._fired.append((ev, p))

    def tearDown(self):
        api.fire_webhook = self._orig_fw
        super().tearDown()

    def _running(self, actor):
        api.save(api.SCANS_FILE, {'sc1': {
            'id': 'sc1', 'status': 'running', 'target_device_id': 'dev1',
            'target_name': 'web1', 'target': '10.0.0.5', 'actor': actor,
            'claimed_by': 'sat1'}})
        return 'sc1'

    def test_ondemand_does_not_fire(self):
        api._apply_scan_results(self._running('jakob'), 'done',
                                [{'severity': 'critical', 'title': 'x'}], '', by='sat1')
        self.assertEqual(self._fired, [])

    def test_scheduled_fires_info_on_any_findings(self):
        api._apply_scan_results(self._running('schedule:abc'), 'done',
                                [{'severity': 'low', 'title': 'x'}], '', by='sat1')
        self.assertEqual(len(self._fired), 1)
        ev, p = self._fired[0]
        self.assertEqual(ev, 'scan_finding')
        self.assertEqual(api._alert_severity('scan_finding', p), 'info')

    def test_scheduled_clean_does_not_fire(self):
        api._apply_scan_results(self._running('schedule:abc'), 'done', [], '', by='sat1')
        self.assertEqual(self._fired, [])


class TestContainerAlertExclude(_ScanBase):
    """#4: scan containers (rp-scan-*) and operator name-excludes skip alerts."""

    def test_rp_scan_excluded(self):
        self.assertTrue(api._container_alert_excluded('rp-scan-abc123'))

    def test_config_substring_excluded(self):
        api.save(api.CONFIG_FILE, {'container_alert_excludes': ['ephemeral-']})
        self.assertTrue(api._container_alert_excluded('ephemeral-worker-7'))
        self.assertFalse(api._container_alert_excluded('seerr'))


class TestScanRoutes(unittest.TestCase):
    def test_routes_registered(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route('GET', '/api/scans')[0], 'handle_scans_list')
        self.assertEqual(resolve_route('POST', '/api/scans')[0], 'handle_scans_create')
        self.assertEqual(resolve_route('POST', '/api/scans/claim')[0], 'handle_scan_claim')
        self.assertEqual(resolve_route('GET', '/api/scans/abc')[0], 'handle_scan_detail')
        self.assertEqual(resolve_route('DELETE', '/api/scans/abc')[0], 'handle_scan_delete')
        self.assertEqual(resolve_route('POST', '/api/scans/clear')[0], 'handle_scans_clear')
        self.assertEqual(resolve_route('POST', '/api/scans/abc/results')[0], 'handle_scan_results')
        self.assertEqual(resolve_route('PATCH', '/api/satellites/x')[0], 'handle_satellites_update')
        self.assertEqual(resolve_route('GET', '/api/scan-targets')[0], 'handle_scan_targets_list')
        self.assertEqual(resolve_route('POST', '/api/scan-targets')[0], 'handle_scan_targets_create')
        self.assertEqual(resolve_route('POST', '/api/scan-targets/x/verify')[0], 'handle_scan_target_verify')
        self.assertEqual(resolve_route('DELETE', '/api/scan-targets/x')[0], 'handle_scan_target_delete')
        self.assertEqual(resolve_route('GET', '/api/scan-schedules')[0], 'handle_scan_schedules_list')
        self.assertEqual(resolve_route('POST', '/api/scan-schedules')[0], 'handle_scan_schedules_create')
        self.assertEqual(resolve_route('DELETE', '/api/scan-schedules/x')[0], 'handle_scan_schedule_delete')
        self.assertEqual(resolve_route('POST', '/api/scan-schedules/x/run')[0], 'handle_scan_schedule_run')


class TestVersionBumps(unittest.TestCase):
    """v4.2.0 — loosened to regex on the v4.3.0 bump (the live strict pins moved
    to tests/test_v430.py); a later bump must not fail this file."""

    def test_server_version(self):
        self.assertRegex(api.SERVER_VERSION, r'^\d+\.\d+\.\d+$')

    def test_agent_versions(self):
        self.assertRegex((_ROOT / 'client/remotepower-agent.py').read_text(),
                         r"\nVERSION\s*=\s*'\d+\.\d+\.\d+'")
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            self.assertRegex((_ROOT / rel).read_text(),
                             r"VERSION\s*=\s*'\d+\.\d+\.\d+'", rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / 'client/remotepower-agent.py').read_bytes(),
                         (_ROOT / 'client/remotepower-agent').read_bytes())

    def test_sw_and_cachebust(self):
        self.assertRegex((_ROOT / 'server/html/sw.js').read_text(),
                         r'remotepower-shell-v\d+\.\d+\.\d+')
        self.assertRegex((_ROOT / 'server/html/index.html').read_text(),
                         r'\?v=\d+\.\d+\.\d+')

    def test_doc_set_keeps_three_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / 'docs').glob('v[0-9]*.md'))
        self.assertEqual(len(vdocs), 3, f'expected exactly 3 version docs, got {vdocs}')


if __name__ == '__main__':
    unittest.main()
