"""v5.8.0 (B3.3): calendar-aware on-call rotation — anchored schedule, dated
overrides, upcoming-handoffs, and back-compat with the legacy modulo."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_oncall', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

DAY = 86400
WEEK = 7 * DAY
ANCHOR = 1_700_000_000   # fixed reference instant


class TestAnchoredSchedule(unittest.TestCase):
    def cfg(self, **kw):
        oc = {'enabled': True, 'contacts': ['alice', 'bob', 'carol'],
              'rotation_days': 7, 'anchor': ANCHOR}
        oc.update(kw)
        return {'oncall': oc}

    def test_first_slot_is_first_contact(self):
        self.assertEqual(api._oncall_at(self.cfg(), ANCHOR), 'alice')
        self.assertEqual(api._oncall_at(self.cfg(), ANCHOR + 3 * DAY), 'alice')

    def test_second_week_is_second_contact(self):
        self.assertEqual(api._oncall_at(self.cfg(), ANCHOR + WEEK), 'bob')
        self.assertEqual(api._oncall_at(self.cfg(), ANCHOR + 2 * WEEK), 'carol')

    def test_wraps_around(self):
        self.assertEqual(api._oncall_at(self.cfg(), ANCHOR + 3 * WEEK), 'alice')

    def test_before_anchor_is_first(self):
        self.assertEqual(api._oncall_at(self.cfg(), ANCHOR - DAY), 'alice')

    def test_disabled_returns_empty(self):
        c = self.cfg(enabled=False)
        self.assertEqual(api._oncall_at(c, ANCHOR + WEEK), '')

    def test_custom_rotation_length(self):
        c = self.cfg(rotation_days=14)
        self.assertEqual(api._oncall_at(c, ANCHOR + WEEK), 'alice')       # still wk1
        self.assertEqual(api._oncall_at(c, ANCHOR + 2 * WEEK), 'bob')     # slot 2


class TestOverrides(unittest.TestCase):
    def cfg(self, overrides):
        return {'oncall': {'enabled': True, 'contacts': ['alice', 'bob'],
                           'rotation_days': 7, 'anchor': ANCHOR,
                           'overrides': overrides}}

    def test_override_wins_in_window(self):
        c = self.cfg([{'contact': 'dave', 'start': ANCHOR, 'end': ANCHOR + DAY}])
        self.assertEqual(api._oncall_at(c, ANCHOR + 3600), 'dave')       # covered
        self.assertEqual(api._oncall_at(c, ANCHOR + 2 * DAY), 'alice')   # after → schedule

    def test_override_outside_window_ignored(self):
        c = self.cfg([{'contact': 'dave', 'start': ANCHOR + 5 * DAY,
                       'end': ANCHOR + 6 * DAY}])
        self.assertEqual(api._oncall_at(c, ANCHOR), 'alice')


class TestUpcoming(unittest.TestCase):
    def test_next_four_handoffs(self):
        cfg = {'oncall': {'enabled': True, 'contacts': ['alice', 'bob'],
                          'rotation_days': 7, 'anchor': ANCHOR}}
        up = api._oncall_upcoming(cfg, ANCHOR + 2 * DAY, count=4)
        self.assertEqual([u['contact'] for u in up], ['alice', 'bob', 'alice', 'bob'])
        self.assertEqual(up[0]['start'], ANCHOR)             # current slot start
        self.assertEqual(up[1]['start'], ANCHOR + WEEK)

    def test_empty_without_anchor(self):
        cfg = {'oncall': {'enabled': True, 'contacts': ['a'], 'rotation_days': 7}}
        self.assertEqual(api._oncall_upcoming(cfg, ANCHOR), [])


class TestLegacyModulo(unittest.TestCase):
    def test_no_anchor_uses_modulo(self):
        # Back-compat: without an anchor the old stateless modulo still works.
        cfg = {'oncall': {'enabled': True, 'contacts': ['a', 'b', 'c'],
                          'rotation_days': 7}}
        got = api._oncall_now(cfg, ANCHOR)
        self.assertIn(got, ('a', 'b', 'c'))
        # deterministic for a fixed clock
        self.assertEqual(got, ['a', 'b', 'c'][(ANCHOR // WEEK) % 3])


class TestWiring(unittest.TestCase):
    def test_config_save_persists_anchor_and_overrides(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("new_oc['anchor'] = anchor", src)
        self.assertIn("new_oc['overrides']", src)

    def test_handler_returns_upcoming(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("'upcoming': _oncall_upcoming(cfg, now, count=4)", src)

    def test_frontend_renders_schedule(self):
        js = (Path(__file__).parent.parent / 'server/html/static/js/app.js').read_text()
        self.assertIn('function _renderOncallSchedule(', js)
        self.assertIn('oncall-anchor', js)


if __name__ == '__main__':
    unittest.main()
