"""What the Alert parameters form does with input it cannot parse.

The page carries 92 numeric thresholds. Until v6.4.3 the save function ended
with:

    payload[key] = Number.isNaN(n) ? dflt : n;

and that single line produced two wrong answers, both under a green toast:

  * A TYPO SAVED THE SHIPPED DEFAULT. "5O" (letter O) parses to NaN, so the
    default went to the server in place of what the operator typed, and the
    response was "Settings saved". They had every reason to believe the
    threshold was 50. The server has ALWAYS rejected an unparseable value with
    a clear 400 — the client simply never let one reach it. A validation layer
    that cannot be reached is indistinguishable from one that does not exist.

  * CLEARING A FIELD DID NOT CLEAR THE OVERRIDE. Blank is the documented way
    back to a default: the threshold loops pop the key. The client sent the
    default as a NUMBER, storing an explicit override that merely equals the
    default *today* — so the install silently pins the old value the next time
    the shipped default moves.

Fixing the client surfaced that the server was not uniform either. Eleven
tunables on the same page grew their own save blocks over the years and never
learned the blank convention: `int('')` raises, so ten of them answered a
cleared field with a 400 — and because respond() aborts the request, the other
91 fields on the form did not persist either. Two more (`scrub_overdue_days`,
`snapshot_stale_days`) swallowed an unparseable value with `except: pass`,
which is the same lie as the client's, three thousand lines away.

Every assertion here drives the REAL handle_config_save.
"""
import unittest

from test_v622_alert_params import _SaveBase, api  # noqa: F401

# The tunables that had a hand-written save block and no blank handling. Ten of
# these 400'd the entire form when their field was cleared.
_LATE_JOINERS = (
    'snmp_failures_before_alert',
    'metric_failures_before_alert',
    'container_stale_ttl',
    'disk_watchdog_pct',
    'ups_critical_battery_pct',
    'ups_critical_runtime_s',
    'scrub_overdue_days',
    'snapshot_stale_days',
    'incident_device_threshold',
    'health_alert_threshold',
)

_SEED = {
    'snmp_failures_before_alert':   6,
    'metric_failures_before_alert': 4,
    'container_stale_ttl':          900,
    'disk_watchdog_pct':            85,
    'ups_critical_battery_pct':     25,
    'ups_critical_runtime_s':       600,
    'scrub_overdue_days':           45,
    'snapshot_stale_days':          14,
    'incident_device_threshold':    5,
    'health_alert_threshold':       70,
}


class TestBlankClearsEveryTunable(_SaveBase):
    def test_each_one_persists_first(self):
        """Positive control. Without it the clearing test below would pass
        against a key that never stored anything."""
        cfg = self._save(dict(_SEED))
        for k, v in _SEED.items():
            self.assertEqual(cfg.get(k), v, f'{k} did not persist at all')

    def test_a_cleared_field_pops_the_override(self):
        self._save(dict(_SEED))
        for k in _LATE_JOINERS:
            cfg = self._save({k: ''})
            self.assertNotIn(k, cfg, f'clearing {k} left the override in place '
                                     '— the shipped default can never apply again')

    def test_clearing_one_field_does_not_abort_the_whole_form(self):
        """The damaging half. respond() raises, so a 400 on ONE key discarded
        the other 91 fields the operator had just edited — and the toast named
        a single field, giving no hint that nothing else saved either."""
        self._save(dict(_SEED))
        cfg = self._save({'disk_watchdog_pct': '', 'health_alert_threshold': 55,
                          'container_stale_ttl': 1200})
        self.assertNotIn('disk_watchdog_pct', cfg)
        self.assertEqual(cfg.get('health_alert_threshold'), 55,
                         'a cleared field aborted the save for every other '
                         'field on the form')
        self.assertEqual(cfg.get('container_stale_ttl'), 1200)

    def test_none_clears_it_too(self):
        """A JSON null from an API client, not just the UI's empty string."""
        self._save(dict(_SEED))
        cfg = self._save({'scrub_overdue_days': None})
        self.assertNotIn('scrub_overdue_days', cfg)


class TestUnparseableIsRefusedNotSwallowed(_SaveBase):
    def test_scrub_overdue_days_rejects_garbage(self):
        """Was `except (TypeError, ValueError): pass` — the value was dropped
        in silence and the response was 200 with a success toast."""
        self._save({'scrub_overdue_days': 'soon'})
        self.assertEqual(self.cap.get('s'), 400,
                         'an unparseable value must be refused, not discarded '
                         'quietly under a "Settings saved" toast')

    def test_snapshot_stale_days_rejects_garbage(self):
        self._save({'snapshot_stale_days': 'never'})
        self.assertEqual(self.cap.get('s'), 400)

    def test_a_valid_value_still_saves(self):
        """The other direction: the new 400 must not reject good input."""
        cfg = self._save({'scrub_overdue_days': 30, 'snapshot_stale_days': 7})
        self.assertEqual(cfg.get('scrub_overdue_days'), 30)
        self.assertEqual(cfg.get('snapshot_stale_days'), 7)

    def test_the_clamps_still_clamp(self):
        cfg = self._save({'scrub_overdue_days': 99999})
        self.assertEqual(cfg.get('scrub_overdue_days'), 3650)


class TestTheClientNoLongerSubstitutesADefault(unittest.TestCase):
    """The client half. A source pin is weak evidence — CLAUDE.md's first
    false-green class — so this asserts the ABSENCE of the specific expression
    that caused the bug, which a grep can establish and a behavioural test
    cannot without a browser. The behaviour above is what proves the server
    honours what the client now sends.
    """

    @classmethod
    def setUpClass(cls):
        import re
        from pathlib import Path
        js = (Path(__file__).resolve().parent.parent / 'server' / 'html'
              / 'static' / 'js' / 'app.js').read_text()
        i = js.index('function saveAlertParams(')
        fn = js[i:js.index('\n}', i)]
        # STRIP THE COMMENTS FIRST. The fix's own comment quotes the expression
        # it replaced, so the assertion below matched the explanation of the
        # bug rather than the bug — it failed against the FIXED code. Assert
        # against what runs, never against what a comment says about it.
        cls.fn = re.sub(r'^\s*//.*$', '', fn, flags=re.M)

    def test_it_does_not_fall_back_to_the_default(self):
        self.assertNotIn('Number.isNaN(n) ? dflt : n', self.fn,
                         'a value the operator typed must never be silently '
                         'replaced by the shipped default')

    def test_a_blank_is_sent_as_a_blank(self):
        self.assertIn("payload[key] = ''", self.fn,
                      'blank must reach the server so it can pop the override')

    def test_it_marks_the_field_and_stops(self):
        self.assertIn("setAttribute('aria-invalid', 'true')", self.fn)
        self.assertIn('nothing was saved', self.fn,
                      'the operator must be told the save did not happen')

    def test_the_invalid_state_is_visible_not_only_announced(self):
        """aria-invalid was being set by three forms with NO css behind it, so
        a sighted operator saw nothing — half of WCAG 2.1 SC 3.3.1."""
        from pathlib import Path
        css = (Path(__file__).resolve().parent.parent / 'server' / 'html'
               / 'static' / 'css' / 'styles.css').read_text()
        self.assertIn('[aria-invalid="true"]', css)


if __name__ == '__main__':
    unittest.main()
