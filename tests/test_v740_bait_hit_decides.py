"""7.4.0: one request for a bait path is enough to report an address.

A visitor who asks for `.env`, `.git` or a database dump has no innocent reason to. The
honeypot log reader used to count it as one attempt of ten, so 182 of 226 honeypot-only
addresses on one install sat unreported. The setting `edge_bait_decides` (on by default)
makes a bait hit a decision of its own; `login` and the other kinds still count attempts.
"""
import inspect
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
import edge_evidence as ee  # noqa: E402
import edge_intel_handlers as eh  # noqa: E402
import ip_intel  # noqa: E402
import ip_intel_handlers as ih  # noqa: E402
import threat_evidence as te  # noqa: E402


def _hit(kind, ip='45.148.10.201', action='recorded', v=ee.SCRIPT_VERSION):
    # A line from a Worker script that says how the request was made (`v`, version 2). Only such a line can be a decision on one hit: trap_events counts a line without it as one
    # attempt, because nothing in it tells a visitor's own request from one a page caused (8.0.1, 5bf0f40e; test_v740_planted_decides sends the version the same way).
    hit = {'kind': kind, 'ip': ip, 'action': action, 'at': 1_700_000_000}
    if v is not None:
        hit['v'] = v
    return hit


def _qualifies(hits, decided):
    events, _ = ee.trap_events(hits, 1_700_000_100, decided_tokens=decided)
    assert len(events) == 1, events
    return te.qualifies(events[0], 10)


class TestBaitHit(unittest.TestCase):
    def test_on_by_default(self):
        self.assertTrue(ip_intel.DEFAULTS['edge_bait_decides'])

    def test_one_bait_hit_is_reportable_when_the_setting_is_on(self):
        ok, why = _qualifies([_hit('bait')], ee.BAIT_TOKENS)
        self.assertTrue(ok, why)
        self.assertIn('honeypot', why)

    def test_one_bait_hit_waits_when_the_setting_is_off(self):
        ok, why = _qualifies([_hit('bait')], ())
        self.assertFalse(ok)
        self.assertIn('of 10', why)

    def test_a_hit_from_a_script_that_does_not_say_how_the_request_was_made_is_one_attempt(self):
        # no `v` at all (a script from before version 2), and a version below the one that says it: both are one attempt, whatever the kind and the setting
        for v in (None, ee.SCRIPT_VERSION - 1):
            for kind in ee.BAIT_TOKENS:
                with self.subTest(v=v, kind=kind):
                    ok, why = _qualifies([_hit(kind, v=v)], ee.BAIT_TOKENS)
                    self.assertFalse(ok)
                    self.assertIn('of 10', why)
        _events, stats = ee.trap_events([_hit('bait', v=None)], 1_700_000_100, decided_tokens=ee.BAIT_TOKENS)
        self.assertEqual(stats['older'], 1, 'the page is told that a script that does not say how the request was made is still in use')

    def test_a_wordpress_probe_is_decided_too(self):
        for kind in ('wpprobe', 'wpenum', 'decoy', 'gitdump'):
            ok, why = _qualifies([_hit(kind)], ee.BAIT_TOKENS)
            self.assertTrue(ok, kind)

    def test_the_trap_kind_reaches_the_attackers_row(self):
        events, _ = ee.trap_events([_hit('wpprobe')], 1_700_000_100, decided_tokens=ee.BAIT_TOKENS)
        view = ih._evidence_view({'ev': events[0]})
        self.assertEqual(view['kinds'], [{'id': 'wpprobe', 'n': 1}])
        self.assertEqual(view['confirmed'], 'the edge honeypot')
        self.assertEqual(events[0]['tok']['trap'], {'trap:wpprobe': 1})

    def test_a_login_hit_still_counts_as_one_attempt(self):
        ok, _ = _qualifies([_hit('login')], ee.BAIT_TOKENS)
        self.assertFalse(ok)

    def test_ten_login_hits_still_report(self):
        ok, _ = _qualifies([_hit('login') for _ in range(10)], ())
        self.assertTrue(ok)

    def test_the_planted_setting_does_not_widen_to_bait_and_back(self):
        self.assertEqual(set(ee.BAIT_TOKENS) & set(ee.PLANTED_TOKENS), set())

    def test_the_poller_reads_the_setting(self):
        src = inspect.getsource(eh._poll_trap)
        self.assertIn("pol.get('edge_bait_decides')", src)
        self.assertIn('BAIT_TOKENS', src)

    def test_the_setting_is_saved_and_in_the_form(self):
        root = _CGI.parent
        self.assertIn("'edge_bait_decides'", (_CGI / 'ip_intel_handlers.py').read_text())
        self.assertIn('edge_bait_decides', (_CGI / 'request_models.py').read_text())
        self.assertIn('id="ipintel-edge-bait"', (root / 'html' / 'index.html').read_text())
        js = (root / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
        self.assertIn("v('ipintel-edge-bait').checked", js)
        self.assertIn("s.edge_bait_decides", js)


if __name__ == '__main__':
    unittest.main()
