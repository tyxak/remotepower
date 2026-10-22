#!/usr/bin/env python3
"""7.4.0: the operator can make one hit on a planted credential or a decoy sign-in a decision.

Until now only the Worker's own ban counted as the honeypot having decided, so a credential the Worker
had planted and someone used waited for `report_min_count` hits unless the Worker also banned the
address. Nobody innocent uses a planted credential, so the setting `edge_planted_decides` (default off)
lets one hit report at once.
"""
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(_ROOT / 'tests'))

import edge_evidence
import ip_intel
import srcpin
import threat_evidence

IP = '93.184.216.34'


def _events(kind, **kw):
    hits = [{'kind': kind, 'ip': IP, 'action': '', 'at': 1_700_000_000}]
    return edge_evidence.trap_events(hits, 1_700_000_100, **kw)[0]


def _qualifies(ev):
    return threat_evidence.qualifies(ev, 10)[0]


class TestPlantedHitsDecide(unittest.TestCase):
    def test_off_by_default_one_hit_waits(self):
        self.assertIs(ip_intel.DEFAULTS['edge_planted_decides'], False)
        for kind in ('canary_use', 'decoy_login'):
            evs = _events(kind)
            self.assertEqual(len(evs), 1, kind)
            self.assertFalse(_qualifies(evs[0]), kind)

    def test_on_one_hit_is_reported_at_once_and_says_who_decided(self):
        for kind in ('canary_use', 'decoy_login'):
            ev = _events(kind, decided_tokens=edge_evidence.PLANTED_TOKENS)[0]
            ok, why = threat_evidence.qualifies(ev, 10)
            self.assertTrue(ok, kind)
            self.assertIn('edge honeypot', why)

    def test_only_the_two_planted_traps_decide(self):
        # A bait path is hit by crawlers and the odd curious visitor; it stays a count.
        for kind in ('bait', 'robots', 'login', 'wpprobe', 'maze'):
            ev = _events(kind, decided_tokens=edge_evidence.PLANTED_TOKENS)[0]
            self.assertFalse(_qualifies(ev), kind)

    def test_the_worker_ban_still_decides_with_the_setting_off(self):
        hits = [{'kind': 'bait', 'ip': IP, 'action': 'banned', 'at': 1_700_000_000}]
        ev = edge_evidence.trap_events(hits, 1_700_000_100)[0][0]
        self.assertTrue(_qualifies(ev))


class TestTheSettingReachesTheRead(unittest.TestCase):
    def test_poll_trap_passes_it(self):
        src = (_ROOT / 'server' / 'cgi-bin' / 'edge_intel_handlers.py').read_text()
        body = srcpin.py_function(src, '_poll_trap')
        self.assertIn("pol.get('edge_planted_decides')", body)
        self.assertIn('PLANTED_TOKENS', body)

    def test_it_is_saved_and_shown(self):
        handlers = (_ROOT / 'server' / 'cgi-bin' / 'ip_intel_handlers.py').read_text()
        self.assertIn("'edge_planted_decides'", handlers)
        models = (_ROOT / 'server' / 'cgi-bin' / 'request_models.py').read_text()
        self.assertIn('edge_planted_decides', models)
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
        self.assertIn("'ipintel-edge-planted', s.edge_planted_decides", js)
        self.assertIn("edge_planted_decides: v('ipintel-edge-planted').checked", js)
        self.assertIn('id="ipintel-edge-planted"', (_ROOT / 'server' / 'html' / 'index.html').read_text())


if __name__ == '__main__':
    unittest.main()
