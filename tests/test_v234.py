#!/usr/bin/env python3
"""
Tests for v2.3.4 — fleet bugfixes.

  #1 Unmonitored devices excluded from the fleet activity feed.
  #2 CVE severity: the CVSS vector is properly parsed (no more
     substring matching that scored every AC:H vuln as HIGH).
  #5 Drift ignore: a file can be marked ignored → non-critical.
  #7 Services + Logs nav moved to the Main group.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec_cve = importlib.util.spec_from_file_location("cve_v234", _CGI_BIN / "cve_scanner.py")
cve = importlib.util.module_from_spec(_spec_cve)
_spec_cve.loader.exec_module(cve)


# ─── #2 CVE severity ─────────────────────────────────────────────────────


class TestCVSSParser(unittest.TestCase):
    """The core bug: substring matching scored AC:H (Attack Complexity
    High) as if it were C:H (Confidentiality High) → every high-AC
    vuln became HIGH."""

    def test_low_vuln_with_high_attack_complexity(self):
        # AC:H present, but impact is only C:L — this is a LOW vuln.
        # The old code matched 'c:h' inside 'ac:h' and returned 7.5.
        vec = 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'
        score = cve._cvss_base_score(vec)
        self.assertLess(score, 4.0,
                        f'high-attack-complexity low-impact vuln scored {score}, '
                        f'should be < 4.0')

    def test_genuine_high_vuln(self):
        vec = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        score = cve._cvss_base_score(vec)
        self.assertGreaterEqual(score, 9.0)

    def test_scope_changed_critical(self):
        vec = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
        self.assertEqual(cve._cvss_base_score(vec), 10.0)

    def test_numeric_score_passthrough(self):
        self.assertEqual(cve._cvss_base_score('2.9'), 2.9)
        self.assertEqual(cve._cvss_base_score('7.5'), 7.5)

    def test_cvss_below_4_never_high(self):
        # The spec rule: CVSS < 4.0 must never classify as HIGH.
        for vec in ('CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N',
                    'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N'):
            sev, src = cve._severity_from_vuln(
                {'severity': [{'type': 'CVSS_V3', 'score': vec}]})
            self.assertIn(sev, ('low', 'medium'),
                          f'{vec} classified {sev}, must not be high/critical')

    def test_severity_source_is_logged(self):
        # The spec requires logging the classification source.
        sev, src = cve._severity_from_vuln(
            {'severity': [{'type': 'CVSS_V3',
                           'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]})
        self.assertEqual(src, 'cvss_v3')
        # database_specific wins over CVSS and is sourced as such
        sev2, src2 = cve._severity_from_vuln(
            {'database_specific': {'severity': 'low'},
             'severity': [{'type': 'CVSS_V3',
                           'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]})
        self.assertEqual(sev2, 'low')
        self.assertEqual(src2, 'database_specific')

    def test_cvss_roundup(self):
        # CVSS-spec roundup: smallest 1-decimal number >= value
        self.assertEqual(cve._cvss3_roundup(4.0), 4.0)
        self.assertEqual(cve._cvss3_roundup(4.01), 4.1)
        self.assertEqual(cve._cvss3_roundup(3.99), 4.0)


# ─── #1 + #5 server wiring ───────────────────────────────────────────────


class TestFleetAndDrift(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v234", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.api.DATA_DIR = self._tmp
        self.api.DEVICES_FILE = self._tmp / 'devices.json'
        self.api.FLEET_EVENTS_FILE = self._tmp / 'fleet_events.json'
        self.api.DRIFT_STATE_FILE = self._tmp / 'drift_state.json'

    def _capture(self, fn, *a):
        cap = {}
        def fake_respond(status, body):
            cap['status'] = status
            cap['body'] = body
            raise SystemExit(0)
        self.api.respond = fake_respond
        self.api.require_auth = lambda **kw: 'admin'
        self.api.require_admin_auth = lambda **kw: 'admin'
        try:
            fn(*a)
        except SystemExit:
            pass
        return cap

    def test_unmonitored_excluded_from_fleet_events(self):
        # #1 — events for a monitored=false device must not appear.
        self.api.save(self.api.DEVICES_FILE, {
            'mon': {'id': 'mon', 'name': 'monitored-box'},
            'unmon': {'id': 'unmon', 'name': 'quiet-box', 'monitored': False},
        })
        self.api.save(self.api.FLEET_EVENTS_FILE, {'events': [
            {'event': 'device_offline', 'ts': 1, 'payload': {'device_id': 'mon'}},
            {'event': 'device_offline', 'ts': 2, 'payload': {'device_id': 'unmon'}},
            {'event': 'device_offline', 'ts': 3, 'payload': {'device_id': 'mon'}},
        ]})
        cap = self._capture(self.api.handle_fleet_events)
        ids = [(e.get('payload') or {}).get('device_id') for e in cap['body']]
        self.assertIn('mon', ids)
        self.assertNotIn('unmon', ids, 'unmonitored device event leaked into feed')
        self.assertEqual(len(cap['body']), 2)

    def test_drift_ignore_toggle(self):
        # #5 — marking a file ignored, then un-ignoring it.
        self.api.save(self.api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})
        self.api.save(self.api.DRIFT_STATE_FILE, {'d1': {'files': {
            '/etc/pam.d/common-auth': {'exists': False, 'baseline_hash': 'x',
                                       'current_hash': None},
        }}})
        self.api.get_json_body = lambda: {'path': '/etc/pam.d/common-auth',
                                          'ignored': True, 'reason': 'not used here'}
        cap = self._capture(self.api.handle_drift_ignore, 'd1')
        self.assertEqual(cap['status'], 200)
        st = self.api.load(self.api.DRIFT_STATE_FILE)
        f = st['d1']['files']['/etc/pam.d/common-auth']
        self.assertTrue(f['ignored'])
        self.assertEqual(f['ignore_reason'], 'not used here')
        # Un-ignore
        self.api.get_json_body = lambda: {'path': '/etc/pam.d/common-auth',
                                          'ignored': False}
        self._capture(self.api.handle_drift_ignore, 'd1')
        st = self.api.load(self.api.DRIFT_STATE_FILE)
        self.assertNotIn('ignored', st['d1']['files']['/etc/pam.d/common-auth'])

    def test_ignored_file_not_counted_as_drift(self):
        # #5 — an ignored missing file drops out of the overview counts.
        self.api.save(self.api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})
        self.api.save(self.api.DRIFT_STATE_FILE, {'d1': {'files': {
            '/etc/pam.d/common-auth': {'exists': False, 'baseline_hash': 'x',
                                       'current_hash': None, 'ignored': True},
            '/etc/sudoers': {'exists': False, 'baseline_hash': 'y',
                             'current_hash': None},
        }}})
        cap = self._capture(self.api.handle_drift_overview)
        row = cap['body']['devices'][0]
        # The ignored file is NOT in `missing`; the other one is.
        self.assertEqual(row['missing'], 1)
        self.assertEqual(row['ignored'], 1)


# ─── #7 nav move ─────────────────────────────────────────────────────────


class TestNavMove(unittest.TestCase):

    def test_services_logs_in_main(self):
        html = (_ROOT / 'server/html/index.html').read_text()
        sec = html.find('data-group="security"')
        self.assertGreater(sec, 0)
        svc = html.find("showPage('services'")
        log = html.find("showPage('logs'")
        # Both appear before the Security group → they're in Main now
        self.assertGreater(svc, 0)
        self.assertGreater(log, 0)
        self.assertLess(svc, sec, 'Services still inside/after Security group')
        self.assertLess(log, sec, 'Logs still inside/after Security group')
        # Exactly once each — not duplicated
        self.assertEqual(html.count("showPage('services'"), 1)
        self.assertEqual(html.count("showPage('logs'"), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
