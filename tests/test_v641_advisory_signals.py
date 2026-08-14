"""v6.4.1: the Security Advisory's dead signals, and the new data layer.

Four advisory inputs were written against keys nothing produced:

  * `sysinfo.ssh_config`  — no agent collected it, `safe_si` never whitelisted
    it, so the ENTIRE identity layer (`id.rootssh`, `id.sshpw`) was unreachable.
  * `sysinfo.tls_certs`   — same; `exp.tls` could not fire. The real data is in
    the TLS monitor's own results, keyed by target rather than device.
  * `sysinfo.brute_force` — the data exists, in its own store, under a different
    shape entirely.
  * the CVE `ignored` flag — a read-time decoration the scanner stamps on a
    COPY. The advisory read the raw store, so an accepted-risk CVE vanished from
    Risk and kept driving the advisory.

`tests/test_advisory.py` passed on all four because it hand-builds device dicts
containing the keys — it validates the pure function's contract, not the ingest
contract. These tests assert the INGEST contract: the fields survive `safe_si`,
and the handler-side gatherers produce what `advisory.build` consumes.
"""
# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api        # noqa: E402
import advisory   # noqa: E402


class TestSshConfigSurvivesIngest(unittest.TestCase):
    """safe_si is a whitelist: a field it drops is a dead feature, however
    correct the collector and the consumer both look. The whitelist is inline
    in handle_heartbeat, so the only honest check is a real heartbeat."""

    def setUp(self):
        self._orig = {k: getattr(api, k)
                      for k in ('respond', 'method', 'get_json_body')}
        api.save(api.DEVICES_FILE,
                 {'hb1': {'id': 'hb1', 'name': 'web01', 'token': 'tok',
                          'poll_interval': 60}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _beat(self, ssh):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'hb1', 'token': 'tok',
                                     'sysinfo': {'ssh_config': ssh}}
        api.respond = lambda status, body: (_ for _ in ()).throw(
            api.HTTPError(status, body))
        try:
            api.handle_heartbeat()
        except (api.HTTPError, SystemExit):
            pass
        api._invalidate_load_cache(api.DEVICES_FILE)
        dev = (api.load(api.DEVICES_FILE) or {}).get('hb1') or {}
        return (dev.get('sysinfo') or {})

    def test_whitelisted(self):
        si = self._beat({'permit_root_login': 'yes',
                         'password_authentication': 'yes',
                         'permit_empty_passwords': 'no',
                         'source': 'sshd -T'})
        self.assertEqual(si.get('ssh_config'), {
            'permit_root_login': 'yes', 'password_authentication': 'yes',
            'permit_empty_passwords': 'no', 'source': 'sshd -T'})

    def test_unknown_keys_and_non_strings_dropped(self):
        si = self._beat({'permit_root_login': 'no', 'listen_address': '0.0.0.0',
                         'port': 22})
        self.assertEqual(si.get('ssh_config'), {'permit_root_login': 'no'})

    def test_empty_and_non_dict_produce_no_key(self):
        for junk in ({}, [], 'yes', None):
            self.assertNotIn('ssh_config', self._beat(junk), junk)

    def test_field_is_delta_eligible_on_both_sides(self):
        # A field the agent may omit but the server doesn't know to merge back
        # would be silently wiped on the first delta beat.
        self.assertIn('ssh_config', api._DELTA_SYSINFO_FIELDS)
        agent = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        block = agent[agent.index('_DELTA_SYSINFO_FIELDS'):]
        self.assertIn('ssh_config', block[:block.index(')')])


class TestAgentCollectsSshConfig(unittest.TestCase):
    """The collector exists, is called from the heartbeat, and is in the
    sysinfo block rather than the earlier payload block (the UnboundLocalError
    class that silently killed four collectors in v6.1.2)."""

    def setUp(self):
        self.src = (ROOT / 'client' / 'remotepower-agent.py').read_text()

    def test_collector_defined_and_called(self):
        self.assertIn('def get_ssh_config(', self.src)
        self.assertIn("sysinfo['ssh_config'] = sc", self.src)

    def test_assigned_after_sysinfo_exists(self):
        store = self.src.index("sysinfo['ssh_config']")
        # the last `sysinfo = {` binding before the store
        self.assertLess(self.src.rindex('sysinfo = {', 0, store), store)

    def test_extensionless_copy_is_in_sync(self):
        self.assertEqual(self.src,
                         (ROOT / 'client' / 'remotepower-agent').read_text())


class TestIdentityLayerFires(unittest.TestCase):
    """With the field now persisted, the layer that never produced a finding
    produces one."""

    def _ids(self, ssh):
        devs = {'d1': {'name': 'web', 'sysinfo': {'ssh_config': ssh}}}
        return {f['id'] for f in advisory.build(devs)['findings']}

    def test_root_login(self):
        self.assertIn('id.rootssh', self._ids({'permit_root_login': 'yes'}))

    def test_password_auth(self):
        self.assertIn('id.sshpw', self._ids({'password_authentication': 'yes'}))

    def test_empty_passwords_is_critical(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {
            'ssh_config': {'permit_empty_passwords': 'yes'}}}}
        f = [g for g in advisory.build(devs)['findings'] if g['id'] == 'id.sshempty']
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['severity'], 'critical')

    def test_hardened_host_produces_nothing(self):
        self.assertEqual(self._ids({'permit_root_login': 'no',
                                    'password_authentication': 'no',
                                    'permit_empty_passwords': 'no'}), set())


class TestBruteForceUsesTheRealStore(unittest.TestCase):
    def test_gatherer_reads_the_store_the_data_is_actually_in(self):
        now = int(api.time.time())
        api.save(api.BRUTE_FORCE_FILE,
                 {'d1': {'sshd': {'10.0.0.9': [now] * 40}}})
        api._invalidate_load_cache(api.BRUTE_FORCE_FILE)
        out = api._advisory_brute_force({'d1'})
        self.assertEqual(len(out.get('d1') or []), 1)
        self.assertEqual(out['d1'][0]['source_ip'], '10.0.0.9')

    def test_below_threshold_is_not_a_finding(self):
        now = int(api.time.time())
        api.save(api.BRUTE_FORCE_FILE, {'d2': {'sshd': {'10.0.0.9': [now] * 2}}})
        api._invalidate_load_cache(api.BRUTE_FORCE_FILE)
        self.assertEqual(api._advisory_brute_force({'d2'}), {})

    def test_finding_is_built_from_the_gathered_shape(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        adv = advisory.build(devs, bf_by_dev={
            'd1': [{'unit': 'sshd', 'source_ip': '10.0.0.9', 'count': 40}]})
        g = [f for f in adv['findings'] if f['id'] == 'id.bruteforce']
        self.assertEqual(len(g), 1)
        self.assertIn('40 failed', g[0]['title'])

    def test_fail2ban_absence_is_stated_rather_than_asked_about(self):
        devs = {'d1': {'name': 'web',
                       'sysinfo': {'fail2ban': {'available': False}}}}
        adv = advisory.build(devs, bf_by_dev={
            'd1': [{'unit': 'sshd', 'source_ip': '10.0.0.9', 'count': 40}]})
        fix = [f for f in adv['findings'] if f['id'] == 'id.bruteforce'][0]['fix']
        self.assertIn('not installed', fix)


class TestCveIgnoreListIsApplied(unittest.TestCase):
    """An accepted-risk CVE disappeared from Risk but kept driving the
    advisory — the two disagreed about the same finding."""

    def test_ignored_finding_does_not_produce_a_finding(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        adv = advisory.build(devs, cve_by_dev={'d1': {'findings': [
            {'vuln_id': 'CVE-1', 'package': 'x', 'severity': 'critical',
             'ignored': True}]}})
        self.assertEqual([f for f in adv['findings'] if f['id'] == 'os.cve'], [])

    def test_handler_applies_the_ignore_list(self):
        # Both decorations now come from the shared extractor — the point of
        # posture_signals is that there is exactly one reading of this store.
        src = (ROOT / 'server' / 'cgi-bin' / 'advisory_handlers.py').read_text()
        self.assertIn('posture_signals.decorated_cve_findings', src)
        self.assertIn('_enrich_cve_findings', src)

    def test_risk_and_the_advisory_read_the_cve_store_the_same_way(self):
        # The divergence that motivated posture_signals: Risk honoured the
        # ignore list and the Advisory did not, so an accepted CVE vanished
        # from one and kept driving the other.
        api_src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        adv_src = (ROOT / 'server' / 'cgi-bin' / 'advisory_handlers.py').read_text()
        for src, who in ((api_src, 'risk'), (adv_src, 'advisory')):
            self.assertIn('posture_signals.decorated_cve_findings', src, who)
        # …and neither may go back to calling the scanner directly.
        risk_fn = api_src[api_src.index('def _compute_fleet_risk'):]
        risk_fn = risk_fn[:risk_fn.index('\ndef ', 10)]
        self.assertNotIn('apply_ignore_list', risk_fn)


class TestKevOutranksSeverity(unittest.TestCase):
    def test_kev_high_is_escalated_to_critical(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        adv = advisory.build(devs, cve_by_dev={'d1': {'findings': [
            {'vuln_id': 'CVE-2', 'package': 'x', 'severity': 'high', 'kev': True}]}})
        g = [f for f in adv['findings'] if f['id'] == 'os.cve'][0]
        self.assertEqual(g['severity'], 'critical')
        self.assertIn('KEV', g['title'])
        self.assertTrue(any('KEV' in e for e in g['evidence']))

    def test_non_kev_high_stays_high(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        adv = advisory.build(devs, cve_by_dev={'d1': {'findings': [
            {'vuln_id': 'CVE-3', 'package': 'x', 'severity': 'high'}]}})
        self.assertEqual([f for f in adv['findings']
                          if f['id'] == 'os.cve'][0]['severity'], 'high')


class TestTlsFindingUsesMonitorResults(unittest.TestCase):
    def test_expiring_target_produces_a_fleet_level_finding(self):
        adv = advisory.build({}, tls_expiring=[{'label': 'a.example', 'days_left': 2}])
        g = [f for f in adv['findings'] if f['id'] == 'exp.tls']
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]['severity'], 'high')
        self.assertEqual(g[0]['device_count'], 0)

    def test_already_expired_is_critical_and_separate(self):
        adv = advisory.build({}, tls_expiring=[{'label': 'a.example', 'days_left': -3}])
        ids = {f['id']: f for f in adv['findings']}
        self.assertEqual(ids['exp.tls.expired']['severity'], 'critical')

    def test_healthy_cert_produces_nothing(self):
        adv = advisory.build({}, tls_expiring=[{'label': 'a.example', 'days_left': 60}])
        self.assertEqual(adv['findings'], [])

    def test_gatherer_skips_errored_and_far_off_probes(self):
        api.save(api.TLS_TARGETS_FILE, {'t1': {'host': 'a.example', 'port': 443},
                                        't2': {'host': 'b.example', 'port': 443}})
        api.save(api.TLS_RESULTS_FILE, {
            't1': {'expires_at': int(api.time.time()) + 3 * 86400},
            't2': {'tls_error': 'handshake failed'},
        })
        for f in (api.TLS_TARGETS_FILE, api.TLS_RESULTS_FILE):
            api._invalidate_load_cache(f)
        out = api._advisory_tls_expiring()
        self.assertEqual([c['label'] for c in out], ['a.example'])


class TestDataLayerNoLongerEmpty(unittest.TestCase):
    """`data` was declared in LAYERS from the start with no builder behind it."""

    def test_layer_is_declared(self):
        self.assertIn('data', advisory.LAYERS)

    def test_secrets_produce_a_finding(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        adv = advisory.build(devs, secrets_by_dev={'d1': [
            {'rule': 'aws-key', 'path': '/srv/app/.env', 'line': 4}]})
        g = [f for f in adv['findings'] if f['id'] == 'data.secrets']
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]['layer'], 'data')
        self.assertIn('/srv/app/.env:4', g[0]['evidence'][0])

    def test_muted_secrets_are_not_findings(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        adv = advisory.build(devs, secrets_by_dev={'d1': [
            {'rule': 'aws-key', 'path': '/srv/app/.env', 'muted': True}]})
        self.assertEqual([f for f in adv['findings'] if f['id'] == 'data.secrets'], [])

    def test_stale_backups_produce_a_finding(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        adv = advisory.build(devs, backups_by_dev={'d1': ['nightly — 96h old']})
        self.assertEqual(len([f for f in adv['findings']
                              if f['id'] == 'data.backup']), 1)

    def test_filevault_off(self):
        devs = {'d1': {'name': 'mac', 'sysinfo': {'mac_posture': {'filevault': False}}}}
        self.assertIn('data.filevault',
                      {f['id'] for f in advisory.build(devs)['findings']})

    def test_bitlocker_unencrypted_volume(self):
        devs = {'d1': {'name': 'win', 'sysinfo': {'win_posture': {
            'bitlocker': [{'mount': 'C:', 'status': 'FullyDecrypted'},
                          {'mount': 'D:', 'status': 'FullyEncrypted'}]}}}}
        g = [f for f in advisory.build(devs)['findings'] if f['id'] == 'data.bitlocker']
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]['device_count'], 1)
        self.assertTrue(any('C:' in e for e in g[0]['evidence']))

    def test_encrypted_host_produces_nothing(self):
        devs = {'d1': {'name': 'win', 'sysinfo': {'win_posture': {
            'bitlocker': [{'mount': 'C:', 'status': 'FullyEncrypted'}]}}}}
        self.assertEqual(advisory.build(devs)['findings'], [])


class TestWindowsPostureReachesIdentity(unittest.TestCase):
    def test_tamper_protection_off_is_high(self):
        devs = {'d1': {'name': 'win', 'sysinfo': {'win_posture': {
            'tamper_protection': False, 'uac_enabled': True}}}}
        g = [f for f in advisory.build(devs)['findings'] if f['id'] == 'id.winposture']
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]['severity'], 'high')

    def test_all_controls_on_produces_nothing(self):
        devs = {'d1': {'name': 'win', 'sysinfo': {'win_posture': {
            'tamper_protection': True, 'uac_enabled': True, 'secure_boot': True}}}}
        self.assertEqual(advisory.build(devs)['findings'], [])

    def test_absent_posture_is_not_a_finding(self):
        # A Linux host has no win_posture — it must not read as "all disabled".
        self.assertEqual(advisory.build({'d1': {'name': 'lin', 'sysinfo': {}}})['findings'], [])


class TestEolTitleNamesTheOs(unittest.TestCase):
    def test_os_string_comes_from_the_device_not_sysinfo(self):
        devs = {'d1': {'name': 'web', 'os': 'Debian 10', 'sysinfo': {}}}
        adv = advisory.build(devs, eol_by_dev={'d1': {'status': 'eol'}})
        self.assertIn('Debian 10',
                      [f for f in adv['findings'] if f['id'] == 'os.eol'][0]['title'])


class TestRedactionStillHolds(unittest.TestCase):
    """The AI brief must never carry evidence — the new layers all add some."""

    def test_new_evidence_does_not_leak_into_the_brief(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        adv = advisory.build(
            devs,
            secrets_by_dev={'d1': [{'rule': 'aws-key', 'path': '/srv/secret.env'}]},
            bf_by_dev={'d1': [{'unit': 'sshd', 'source_ip': '10.0.0.9', 'count': 40}]})
        brief = advisory.summarize_for_ai(adv, 'the whole fleet')
        self.assertNotIn('/srv/secret.env', brief)
        self.assertNotIn('10.0.0.9', brief)


if __name__ == '__main__':
    unittest.main()


class TestScapReachesTheAdvisory(unittest.TestCase):
    """OpenSCAP was a parallel scoring silo with its own page and no route into
    "what should I fix" — each failed rule already carries a severity and an id,
    which is more actionable than most findings in the advisory."""

    def _f(self, scap):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        return {g['id']: g for g in
                advisory.build(devs, scap_by_dev={'d1': scap})['findings']}

    def test_failed_rules_produce_a_finding(self):
        g = self._f({'available': True, 'profile': 'cis_level1', 'score': 71.2,
                     'failed_rules': [{'id': 'xccdf_org_rule_sshd_root', 'severity': 'high'},
                                      {'id': 'xccdf_org_rule_audit', 'severity': 'low'}]})
        self.assertIn('os.scap', g)
        self.assertEqual(g['os.scap']['severity'], 'high')
        self.assertIn('cis_level1', g['os.scap']['title'])
        self.assertIn('71.2', g['os.scap']['title'])

    def test_only_low_severity_rules_are_medium(self):
        g = self._f({'available': True, 'failed_rules': [
            {'id': 'r', 'severity': 'low'}]})
        self.assertEqual(g['os.scap']['severity'], 'medium')

    def test_a_passing_scan_produces_nothing(self):
        self.assertEqual(self._f({'available': True, 'failed_rules': []}), {})

    def test_a_host_that_cannot_scan_produces_nothing(self):
        # `available: false` means OpenSCAP isn't installed — not a finding.
        self.assertEqual(
            self._f({'available': False, 'reason': 'oscap not installed'}), {})

    def test_high_severity_rules_lead_the_evidence(self):
        g = self._f({'available': True, 'failed_rules': (
            [{'id': f'rule_low{i}', 'severity': 'low'} for i in range(6)]
            + [{'id': 'rule_important', 'severity': 'high'}])})
        self.assertEqual(g['os.scap']['evidence'][0], 'important')


class TestAgentTamperReachesTheAdvisory(unittest.TestCase):
    """A hash mismatch previously reached nothing but a badge on the device row
    — for the component that reports everything else about the host."""

    def _f(self, verdict):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        return {g['id']: g for g in
                advisory.build(devs, agent_tamper_by_dev={'d1': verdict})['findings']}

    def test_hash_mismatch_is_critical(self):
        g = self._f('mismatch')
        self.assertEqual(g['int.agenthash']['severity'], 'critical')

    def test_rejected_update_is_high_and_a_different_finding(self):
        g = self._f('update_rejected')
        self.assertNotIn('int.agenthash', g)
        self.assertEqual(g['int.agentupdate']['severity'], 'high')

    def test_verified_agent_produces_nothing(self):
        self.assertEqual(self._f('verified'), {})
        self.assertEqual(self._f(None), {})

    def test_gatherer_prefers_mismatch_over_rejected(self):
        # A host with both is compromised, not merely protected.
        orig = api._agent_integrity_status
        try:
            api._agent_integrity_status = lambda dev, sha, ver: 'mismatch'
            out = api._advisory_agent_tamper(
                {'d1': {'name': 'x', 'agent_update_rejected': 'bad sig'}})
        finally:
            api._agent_integrity_status = orig
        self.assertEqual(out, {'d1': 'mismatch'})

    def test_gatherer_survives_a_broken_integrity_check(self):
        orig = api._agent_integrity_status
        try:
            def _boom(*a, **k):
                raise RuntimeError('no canonical binary on disk')
            api._agent_integrity_status = _boom
            out = api._advisory_agent_tamper({'d1': {'name': 'x'}})
        finally:
            api._agent_integrity_status = orig
        self.assertEqual(out, {})


class TestDriftNamesTheFiles(unittest.TestCase):
    """Risk counts drifted files; the advisory names them, which is the
    actionable half. Deliberately paths only — drift_contents.json holds the
    captured file CONTENT, and a config file's contents are exactly the kind
    of thing that carries a credential."""

    def _f(self, drift_state):
        devs = {'d1': {'name': 'web', 'sysinfo': {}, 'drift_state': drift_state}}
        return {g['id']: g for g in advisory.build(devs)['findings']}

    def test_drifted_files_are_named(self):
        g = self._f({'/etc/nginx/nginx.conf': {'status': 'drifted'},
                     '/etc/ssh/sshd_config': {'status': 'drifted'}})
        self.assertIn('int.drift', g)
        self.assertEqual(sorted(g['int.drift']['evidence']),
                         ['/etc/nginx/nginx.conf', '/etc/ssh/sshd_config'])

    def test_ignored_and_clean_files_do_not_count(self):
        self.assertEqual(self._f({
            '/a': {'status': 'clean'},
            '/b': {'status': 'drifted', 'ignored': True}}), {})

    def test_no_file_contents_reach_the_advisory(self):
        # Check the CODE, not the prose — advisory.py's comment names the store
        # precisely to explain why it is not read.
        import ast
        for rel in ('advisory.py', 'advisory_handlers.py'):
            tree = ast.parse((ROOT / 'server' / 'cgi-bin' / rel).read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) \
                        and ast.get_docstring(node) is not None:
                    node.body = node.body[1:]
            code = ast.unparse(tree)
            self.assertNotIn('drift_contents', code, rel)
            self.assertNotIn('DRIFT_CONTENTS', code, rel)

    def test_evidence_is_the_path_and_nothing_else(self):
        g = self._f({'/etc/ssh/sshd_config': {
            'status': 'drifted',
            'content': 'PermitRootLogin yes\nSuperSecret=hunter2'}})
        self.assertEqual(g['int.drift']['evidence'], ['/etc/ssh/sshd_config'])


class TestWeakSshKeys(unittest.TestCase):
    """"A key was ADDED" is an event and already an alert; the baseline is
    rewritten every heartbeat so a delta read here is always empty. The key's
    ALGORITHM is a durable state, which is what makes this answerable."""

    def test_finding_built_from_the_gathered_shape(self):
        devs = {'d1': {'name': 'web', 'sysinfo': {}}}
        adv = advisory.build(devs, weak_keys_by_dev={'d1': ['root — ssh-dss']})
        g = [f for f in adv['findings'] if f['id'] == 'id.weakkey']
        self.assertEqual(len(g), 1)
        self.assertIn('root — ssh-dss', g[0]['evidence'])

    def test_gatherer_flags_only_deprecated_algorithms(self):
        api.save(api.SSH_KEY_BASELINE_FILE, {'d1': {
            'root': ['ssh-dss AAAAB3Nz... old', 'ssh-ed25519 AAAAC3Nz... good'],
            'deploy': ['ssh-rsa AAAAB3Nz... fine'],
        }})
        api._invalidate_load_cache(api.SSH_KEY_BASELINE_FILE)
        out = api._advisory_weak_ssh_keys({'d1'})
        self.assertEqual(out, {'d1': ['root — ssh-dss']})

    def test_modern_only_host_produces_nothing(self):
        api.save(api.SSH_KEY_BASELINE_FILE,
                 {'d2': {'root': ['ssh-ed25519 AAAAC3Nz... good']}})
        api._invalidate_load_cache(api.SSH_KEY_BASELINE_FILE)
        self.assertEqual(api._advisory_weak_ssh_keys({'d2'}), {})

    def test_other_devices_are_not_included(self):
        api.save(api.SSH_KEY_BASELINE_FILE, {'other': {'root': ['ssh-dss X']}})
        api._invalidate_load_cache(api.SSH_KEY_BASELINE_FILE)
        self.assertEqual(api._advisory_weak_ssh_keys({'d1'}), {})

    def test_junk_baseline_does_not_raise(self):
        api.save(api.SSH_KEY_BASELINE_FILE,
                 {'d1': 'junk', 'd2': {'root': [None, '', 'x']}})
        api._invalidate_load_cache(api.SSH_KEY_BASELINE_FILE)
        self.assertEqual(api._advisory_weak_ssh_keys({'d1', 'd2'}), {})


class TestNoFindingWithoutASourceThatCanSupportIt(unittest.TestCase):
    """Two candidate findings were written and then removed rather than
    shipped, because the store they would read is refreshed on every heartbeat
    — the "new since baseline" delta is therefore always empty at read time,
    and the finding could never fire. Adding a signal that can never fire to
    the release that went hunting for exactly those would be the wrong trade.

    This pins the decision so it is not silently reversed."""

    def setUp(self):
        self.adv = (ROOT / 'server' / 'cgi-bin' / 'advisory.py').read_text()
        self.h = (ROOT / 'server' / 'cgi-bin' / 'advisory_handlers.py').read_text()

    def test_no_new_port_delta_finding(self):
        for src in (self.adv, self.h):
            self.assertNotIn('exp.newport', src)
            self.assertNotIn('PORT_BASELINE_FILE', src)

    def test_no_added_ssh_key_delta_finding(self):
        # The ALGORITHM check is fine (durable state); a "key added" delta is
        # not, and is already covered by the ssh_key_added alert.
        self.assertNotIn('ssh_key_added', self.adv)
        self.assertNotIn('ssh_key_added', self.h)


class TestSshConfigIsVisibleOnTheHost(unittest.TestCase):
    """The Advisory acts on sshd posture, so the device drawer has to show it —
    otherwise the operator is told to fix something whose current value they
    cannot see anywhere in the product."""

    def test_drawer_renders_it(self):
        import clientjs
        js = clientjs.client_js()
        self.assertIn("si.ssh_config", js)
        self.assertIn("'SSH access'", js)

    def test_rendered_from_the_same_keys_the_advisory_reads(self):
        import clientjs
        js = clientjs.client_js()
        adv = (ROOT / 'server' / 'cgi-bin' / 'advisory.py').read_text()
        for key in ('permit_root_login', 'password_authentication',
                    'permit_empty_passwords'):
            self.assertIn(key, js, key)
            self.assertIn(key, adv, key)
