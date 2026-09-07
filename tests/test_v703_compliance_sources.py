#!/usr/bin/env python3
"""Four things RemotePower collects, and the compliance report did not know.

Each has had a page, an alert path or a RAG corpus for several releases:

  OpenSCAP / USG benchmark results  (SCAP_FILE, since v3.4.2)
  the privileged-command trail      (SUDO_LOG_FILE, since W3-40)
  the regulated-data inventory      (PII_FILE, since v6.2.0)
  DMARC / SPF / DKIM posture        (DMARC_RESULTS_FILE)

`_compliance_facts()` read none of them and no control referenced them. Same
shape as the v7.0.0 sshd finding: not a dead signal — read, alerted on and
rendered — it just never reached the surface an auditor reads, which for a
compliance feature is the surface that counts. The benchmark one stings most:
the report had no configuration-baseline control at all while the product was
running the benchmark that IS that control's evidence.

WHAT THIS PINS, and why each one:

* The facts are ASSEMBLED, not just consumed. A control reading a key the
  builder never sets answers NOT_ASSESSED forever and looks like a scope
  decision somebody made on purpose.
* The capable-source rule, per source. An empty offender list on a fleet that
  never ran the scan must be NOT_ASSESSED, never PASS — a green control an
  auditor relies on is the worst thing this report can produce.
* Device-keyed sources are gated on the caller's visible device set. The
  evidence strings carry HOSTNAMES, so an unscoped read is the cross-tenant
  disclosure class the v6.3.1 sweep fixed here. DMARC is fleet-level (a domain
  is not a device) and is not gated, matching the TLS facts beside it.
* The sudo control attests RECORDING, not appropriateness, and a host that ran
  no sudo command is not a finding.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-cs703-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_cs703', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import compliance  # noqa: E402

_STORES = ('SCAP_FILE', 'SUDO_LOG_FILE', 'PII_FILE',
           'DMARC_TARGETS_FILE', 'DMARC_RESULTS_FILE')
_DEV = {'d1': {'name': 'web01', 'sysinfo': {}}}


class _Case(unittest.TestCase):
    """Each store is redirected into a temp dir, taking its BASENAME from the
    attribute it replaces — on SQLite/Postgres the basename picks the table, so
    a made-up `scap_file.json` would not be the SCAP store and every assertion
    below would pass against nothing."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='rp-cs703-')
        tmp = Path(self._tmp.name)
        self._saved = {n: getattr(api, n) for n in _STORES}
        for n in _STORES:
            setattr(api, n, tmp / self._saved[n].name)
            api._invalidate_load_cache(getattr(api, n))
            api.save(getattr(api, n), {})
        self.addCleanup(self._restore)

    def _restore(self):
        for n, v in self._saved.items():
            api._invalidate_load_cache(getattr(api, n))
            setattr(api, n, v)
        self._tmp.cleanup()

    def seed(self, attr, value):
        api.save(getattr(api, attr), value)
        api._invalidate_load_cache(getattr(api, attr))

    def facts(self, devices=None):
        return api._compliance_facts(_DEV if devices is None else devices)


class TestBenchmark(_Case):

    def test_failing_rules_reach_the_facts_and_fail_the_control(self):
        self.seed('SCAP_FILE', {'d1': {'available': True, 'profile': 'cis',
                                       'score': 61, 'pass': 90, 'fail': 12}})
        f = self.facts()
        self.assertEqual(f['scap_scanned_devices'], 1)
        self.assertEqual(len(f['scap_failing']), 1)
        self.assertIn('web01', f['scap_failing'][0])
        self.assertIn('12', f['scap_failing'][0])
        self.assertEqual(compliance._benchmark_control(f)[0], compliance.FAIL)

    def test_a_clean_scan_passes(self):
        self.seed('SCAP_FILE', {'d1': {'available': True, 'profile': 'cis',
                                       'score': 100, 'pass': 102, 'fail': 0}})
        f = self.facts()
        self.assertEqual(f['scap_failing'], [])
        self.assertEqual(compliance._benchmark_control(f)[0], compliance.PASS)

    def test_no_scan_is_not_assessed_not_pass(self):
        """The capable-source rule. A fleet that never ran the benchmark has
        demonstrated nothing, and a green control there is a false assurance."""
        f = self.facts()
        self.assertEqual(f['scap_scanned_devices'], 0)
        st, msg = compliance._benchmark_control(f)
        self.assertEqual(st, compliance.NOT_ASSESSED)
        self.assertIn('not assessed', msg)

    def test_a_host_without_the_toolchain_is_not_counted_as_scanned(self):
        """`available: False` is the agent saying OpenSCAP is not installed.
        Counting it as a scan would let one unequipped host turn the whole
        fleet's verdict from 'not assessed' into a pass."""
        self.seed('SCAP_FILE', {'d1': {'available': False,
                                       'reason': 'oscap not installed'}})
        f = self.facts()
        self.assertEqual(f['scap_scanned_devices'], 0)
        self.assertEqual(compliance._benchmark_control(f)[0],
                         compliance.NOT_ASSESSED)

    def test_a_result_for_an_invisible_device_is_not_read(self):
        self.seed('SCAP_FILE', {'other': {'available': True, 'fail': 5}})
        f = self.facts()
        self.assertEqual(f['scap_failing'], [])
        self.assertEqual(f['scap_scanned_devices'], 0)


class TestPrivilegedCommandTrail(_Case):

    def test_a_reporting_host_passes(self):
        self.seed('SUDO_LOG_FILE', {'d1': [{'ts': 1, 'user': 'alice',
                                            'command': '/usr/bin/systemctl restart nginx'}]})
        f = self.facts()
        self.assertEqual(f['sudo_trail_devices'], 1)
        st, msg = compliance._privileged_command_control(f)
        self.assertEqual(st, compliance.PASS)
        self.assertIn('1 host', msg)

    def test_nothing_reported_is_not_assessed(self):
        f = self.facts()
        self.assertEqual(f['sudo_trail_devices'], 0)
        self.assertEqual(compliance._privileged_command_control(f)[0],
                         compliance.NOT_ASSESSED)

    def test_it_never_fails_on_the_content_of_a_command(self):
        """The control attests that privileged commands are RECORDED. Judging
        whether a given sudo command was appropriate is not something this
        report can do, and a control that pretended to would be worse than
        none."""
        self.seed('SUDO_LOG_FILE', {'d1': [{'ts': 1, 'user': 'root',
                                            'command': 'rm -rf /var/log'}]})
        self.assertEqual(
            compliance._privileged_command_control(self.facts())[0],
            compliance.PASS)

    def test_another_tenants_host_does_not_supply_the_evidence(self):
        self.seed('SUDO_LOG_FILE', {'other': [{'ts': 1, 'command': 'x'}]})
        self.assertEqual(self.facts()['sudo_trail_devices'], 0)


class TestRegulatedData(_Case):

    def test_findings_reach_the_facts_and_fail_the_control(self):
        self.seed('PII_FILE', {'d1': {'ts': 1, 'findings': [
            {'kind': 'credit_card', 'path': '/srv/export.csv', 'count': 40},
            {'kind': 'ssn', 'path': '/srv/hr.txt', 'count': 3}]}})
        f = self.facts()
        self.assertEqual(f['pii_scanned_devices'], 1)
        self.assertEqual(len(f['pii_hosts']), 1)
        self.assertIn('web01', f['pii_hosts'][0])
        self.assertEqual(compliance._regulated_data_control(f)[0], compliance.FAIL)

    def test_the_evidence_never_carries_a_matched_value(self):
        """The scanner stores counts and paths, never the matched text. The
        evidence string must not reintroduce what the store went out of its way
        not to keep."""
        self.seed('PII_FILE', {'d1': {'ts': 1, 'findings': [
            {'kind': 'credit_card', 'path': '/srv/export.csv', 'count': 40}]}})
        _st, msg = compliance._regulated_data_control(self.facts())
        self.assertNotIn('export.csv', msg)
        self.assertIn('web01', msg)

    def test_a_scanned_host_with_no_findings_passes(self):
        self.seed('PII_FILE', {'d1': {'ts': 1, 'findings': []}})
        f = self.facts()
        self.assertEqual(f['pii_scanned_devices'], 1)
        self.assertEqual(f['pii_hosts'], [])
        self.assertEqual(compliance._regulated_data_control(f)[0], compliance.PASS)

    def test_no_scan_is_not_assessed(self):
        f = self.facts()
        self.assertEqual(compliance._regulated_data_control(f)[0],
                         compliance.NOT_ASSESSED)

    def test_an_invisible_device_is_not_read(self):
        self.seed('PII_FILE', {'other': {'ts': 1, 'findings': [
            {'kind': 'ssn', 'path': '/x', 'count': 1}]}})
        f = self.facts()
        self.assertEqual(f['pii_hosts'], [])
        self.assertEqual(f['pii_scanned_devices'], 0)


class TestEmailAuthentication(_Case):

    def _targets(self):
        self.seed('DMARC_TARGETS_FILE', {'dmarc_1': {'domain': 'example.com'}})

    def test_a_spoofable_domain_fails(self):
        self._targets()
        self.seed('DMARC_RESULTS_FILE', {'dmarc_1': {
            'domain': 'example.com', 'status': 'fail',
            'reasons': ['no DMARC record']}})
        f = self.facts()
        self.assertEqual(f['dmarc_failing'], ['example.com'])
        st, msg = compliance._email_auth_control(f)
        self.assertEqual(st, compliance.FAIL)
        self.assertIn('example.com', msg)

    def test_an_enforcing_domain_passes(self):
        self._targets()
        self.seed('DMARC_RESULTS_FILE', {'dmarc_1': {'domain': 'example.com',
                                                     'status': 'ok'}})
        f = self.facts()
        self.assertEqual(f['dmarc_failing'], [])
        self.assertEqual(f['dmarc_weak'], [])
        self.assertEqual(compliance._email_auth_control(f)[0], compliance.PASS)

    def test_weak_is_reported_separately_from_failing(self):
        """'weak' is enforcing with gaps and 'fail' is not enforcing at all.
        They need different work, so folding them together would tell an
        operator with a p=reject policy that their domain is spoofable."""
        self._targets()
        self.seed('DMARC_RESULTS_FILE', {'dmarc_1': {'domain': 'example.com',
                                                     'status': 'weak'}})
        f = self.facts()
        self.assertEqual(f['dmarc_failing'], [])
        self.assertEqual(f['dmarc_weak'], ['example.com'])
        _st, msg = compliance._email_auth_control(f)
        self.assertIn('with gaps', msg)

    def test_no_domains_is_not_assessed(self):
        f = self.facts()
        self.assertEqual(f['dmarc_domains'], 0)
        self.assertEqual(compliance._email_auth_control(f)[0],
                         compliance.NOT_ASSESSED)

    def test_a_configured_but_unchecked_domain_is_not_assessed(self):
        """Adding a domain is not evidence about it. Without this the control
        would PASS the moment somebody typed a domain in, before a single DNS
        lookup had been made."""
        self._targets()
        f = self.facts()
        self.assertEqual(f['dmarc_domains'], 1)
        self.assertEqual(f['dmarc_checked'], 0)
        st, msg = compliance._email_auth_control(f)
        self.assertEqual(st, compliance.NOT_ASSESSED)
        self.assertIn('not assessed', msg)


class TestTheControlsAreMapped(unittest.TestCase):
    """A control function nothing references is evidence assembled and thrown
    away — the shape this whole release is about."""

    _WANT = {
        compliance._benchmark_control: {'pci', 'soc2', 'smb1001'},
        compliance._privileged_command_control: {'pci', 'soc2', 'e8'},
        compliance._regulated_data_control: {'pci', 'soc2', 'smb1001'},
        compliance._email_auth_control: {'pci', 'smb1001'},
    }

    def test_each_control_is_mapped_into_its_frameworks(self):
        for fn, want in self._WANT.items():
            got = {row[0] for row in compliance._CONTROLS if row[3] is fn}
            self.assertEqual(got, want, f'{fn.__name__} maps to {got}, want {want}')

    def test_every_id_is_unique_within_its_framework(self):
        seen = set()
        for fw, cid, _t, _fn, _r in compliance._CONTROLS:
            self.assertNotIn((fw, cid), seen, f'duplicate control id {fw}/{cid}')
            seen.add((fw, cid))

    def test_each_has_a_topic(self):
        for fn in self._WANT:
            self.assertTrue(compliance._TOPICS.get(fn),
                            f'{fn.__name__} has no topic, so the report row '
                            f'cannot deep-link to where you fix it')

    def test_each_has_a_remediation_line(self):
        """A FAIL with no remediation is a report that tells you the bad news
        and not what to do about it."""
        for fw, cid, _t, fn, rem in compliance._CONTROLS:
            if fn in self._WANT:
                self.assertTrue(rem.strip(), f'{fw}/{cid} has no remediation')

    def test_a_report_builds_with_the_new_controls_present(self):
        r = compliance.build_report({'devices': 1})
        ids = {(fw, c['id']) for fw, d in r['frameworks'].items()
               for c in d['controls']}
        for expect in (('pci', '2.2.1'), ('pci', '3.2.1'), ('pci', '5.4.1'),
                       ('pci', '10.2.1.2'), ('soc2', 'CC7.1c'), ('soc2', 'CC6.3'),
                       ('soc2', 'C1.1'), ('e8', 'E8-5c'), ('smb1001', 'S-email'),
                       ('smb1001', 'S-config'), ('smb1001', 'S-data')):
            self.assertIn(expect, ids)

    def test_not_assessed_never_inflates_a_score(self):
        """Eleven new controls that all report NOT_ASSESSED on a bare fleet
        must not move any framework's score — the score is pass/(pass+fail)."""
        bare = {'devices': 1}
        r = compliance.build_report(bare)
        for fw, d in r['frameworks'].items():
            if d['score'] is not None:
                self.assertLessEqual(d['score'], 100.0)
                self.assertEqual(
                    d['pass'] + d['fail'],
                    len([c for c in d['controls']
                         if c['status'] in (compliance.PASS, compliance.FAIL)]))


class TestTheFixLinksResolve(unittest.TestCase):

    def test_every_mapped_topic_points_at_a_real_page(self):
        app = (_ROOT / 'server/html/static/js/app.js').read_text()
        html = (_ROOT / 'server/html/index.html').read_text()
        i = app.index('const _COMPLIANCE_FIX_PAGE')
        region = app[i:app.index('}', i)]
        import re
        pages = set(re.findall(r"[a-z_]+:\s*'([a-z0-9]+)'", region))
        self.assertTrue(pages, 'parsed no pages out of _COMPLIANCE_FIX_PAGE')
        for page in sorted(pages):
            self.assertIn(f'id="page-{page}"', html,
                          f'Fix link targets page "{page}", which does not exist')


if __name__ == '__main__':
    unittest.main()
