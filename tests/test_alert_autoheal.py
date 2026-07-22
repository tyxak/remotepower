"""Every alert must have a way OUT.

An alert that fires and can never clear is worse than no alert. The inbox stops
being "things that are wrong" and becomes "things that were once wrong", and an
operator who has learned that entries never leave stops reading it — at which
point the whole notification chain is decorative.

So every alertable event in EVENT_REGISTRY must be exactly one of:

  * **auto-healing** — another event `resolves` it. The condition is a STATE, so
    something can observe it clearing.
  * **`lifecycle='point'`** — it records that something HAPPENED. There is no
    condition to watch, so the operator confirms it away.

Anything that is neither is a gap. `_AUTOHEAL_GAPS` lists the known ones so they
are visible and bounded; this file fails if that list grows, or if a new event is
added without deciding which kind it is.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _alertable():
    return {k for k, v in api.EVENT_REGISTRY.items() if 'severity' in v}


def _resolved_by():
    out = {}
    for k, v in api.EVENT_REGISTRY.items():
        for target in (v.get('resolves') or ()):
            out.setdefault(target, []).append(k)
    return out


class TestEveryAlertCanClear(unittest.TestCase):
    def setUp(self):
        self.alertable = _alertable()
        self.resolved_by = _resolved_by()
        self.gaps = set(api._AUTOHEAL_GAPS)

    def test_the_registry_is_actually_being_read(self):
        """A guardrail that matches nothing passes forever."""
        self.assertGreater(len(self.alertable), 50)
        self.assertGreater(len(self.resolved_by), 30)
        self.assertIn('device_offline', self.alertable)

    def test_every_alertable_event_declares_how_it_clears(self):
        undecided = []
        for ev in sorted(self.alertable):
            if ev in self.resolved_by:
                continue                                   # auto-heals
            if api.EVENT_REGISTRY[ev].get('lifecycle') == 'point':
                continue                                   # operator confirms
            if ev in self.gaps:
                continue                                   # known, bounded
            undecided.append(ev)
        self.assertEqual(
            undecided, [],
            "these alerts can fire and never clear. Give the event a recover "
            "event (add it to some event's `resolves`), or mark it "
            "lifecycle='point' if it records something that HAPPENED rather "
            f"than a condition that persists: {undecided}")

    def test_the_gap_list_does_not_grow(self):
        """A ratchet. Shrinking it is the goal; growing it means a new alert was
        added that can never clear."""
        self.assertLessEqual(len(self.gaps), 8, 'a new never-clearing alert was added')

    def test_every_gap_is_really_still_a_gap(self):
        """If one of these gains a resolver, delete it from the list — a stale
        entry hides the fact that the work is done."""
        stale = sorted(g for g in self.gaps if g in self.resolved_by)
        self.assertEqual(stale, [],
                         f'these now auto-heal; remove them from _AUTOHEAL_GAPS: {stale}')

    def test_every_gap_is_a_real_alertable_event(self):
        unknown = sorted(g for g in self.gaps if g not in self.alertable)
        self.assertEqual(unknown, [],
                         f'_AUTOHEAL_GAPS names events that are not alertable: {unknown}')

    def test_point_events_are_not_also_resolved(self):
        """Both would be contradictory — if something observes it clearing, it
        is a state, not a point in time."""
        both = sorted(ev for ev, v in api.EVENT_REGISTRY.items()
                      if v.get('lifecycle') == 'point' and ev in self.resolved_by)
        self.assertEqual(both, [],
                         f'marked point-in-time but something resolves them: {both}')

    def test_a_recover_event_is_not_itself_alertable_without_reason(self):
        """A recover event that lands in the inbox creates a second row for the
        good news, which is how an inbox fills up with noise."""
        noisy = []
        for ev, v in api.EVENT_REGISTRY.items():
            if not v.get('resolves'):
                continue
            if 'severity' in v and v.get('severity') not in (None, 'low', 'info'):
                noisy.append(ev)
        self.assertEqual(noisy, [],
                         f'recover events recorded at a paging severity: {noisy}')


class TestTheResolveMatchKeysAreStored(unittest.TestCase):
    """A recover event finds its open alert by a key from the payload. If that
    key is not in _record_alert's whitelist it was never stored, so the match
    silently never happens and the alert sits open forever — the exact bug
    CLAUDE.md documents for integration_recovered / ip_blacklist_cleared /
    resolver_recovered."""

    KEYS = ('check_id', 'unit', 'pool', 'label', 'target', 'ip', 'image',
            'integration_id', 'dep_edge', 'script_name', 'container')

    def test_every_sub_match_key_is_whitelisted_on_the_alert(self):
        src = (_CGI / 'api.py').read_text()
        i = src.index('def _record_alert')
        blk = src[i:i + 9000]
        wl = blk[blk.index('for key in ('):]
        wl = wl[:wl.index('if key in p')]
        missing = [k for k in self.KEYS if f"'{k}'" not in wl]
        self.assertEqual(missing, [],
                         'recover events match on these keys, but _record_alert '
                         f'never stores them, so they can never resolve: {missing}')


if __name__ == '__main__':
    unittest.main()
