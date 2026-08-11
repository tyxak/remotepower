#!/usr/bin/env python3
"""A cadence sweep with nothing to do must not write.

`main()` runs ~33 maintenance sweeps on EVERY request. `_LockedUpdate` has no
dirty tracking — it saves on every clean exit, unconditionally — so a sweep
that enters the lock before deciding whether anything changed takes a file lock
and rewrites its whole store once per request, to change nothing almost every
time. On Postgres that is a transaction and an advisory lock per request; on
the JSON backend it is an fsync-and-rename of the entire document.

Two sweeps were doing this:

  * run_deadman_check_if_due — for any install with at least one dead-man job.
    Everything it needed to know was already in the cheap read three lines
    above the lock.
  * _maybe_auto_resolve_promoted_incidents — for any install that has ever
    auto-promoted an incident.

This is a sibling of the fingerprint-vs-mtime cache class in CLAUDE.md: work
that is correct, and repeated for no reason, on the hot path.

The test counts REAL writes through the storage layer rather than reading the
source, because the shape that causes it ("is there a `with _LockedUpdate`
before the first `return`") has legitimate instances — a sweep that must hold
the lock to decide is fine. What is never fine is the write.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643sweep-'))

_spec = importlib.util.spec_from_file_location('api_v643_sweep', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class _WriteCounter:
    """Counts writes per storage key.

    Wraps `_save_held`, NOT `save`. A `_LockedUpdate` block does not go through
    `save()` at all — its __exit__ calls `_save_held` directly, because the
    lock is already held. Counting `save` alone shows ZERO for exactly the
    writes this file exists to measure, so both positive controls failed while
    the two "writes nothing" tests passed: a counter that cannot see the write
    reports success no matter what the code does. Both are wrapped now.
    """

    def __init__(self):
        self.counts = {}
        self._orig_save = api.save
        self._orig_held = api._save_held

    def _bump(self, path):
        self.counts[str(path)] = self.counts.get(str(path), 0) + 1

    def __enter__(self):
        def _save(path, data, *a, **k):
            self._bump(path)
            return self._orig_save(path, data, *a, **k)

        def _save_held(path, data, *a, **k):
            self._bump(path)
            return self._orig_held(path, data, *a, **k)
        api.save = _save
        api._save_held = _save_held
        return self

    def __exit__(self, *exc):
        api.save = self._orig_save
        api._save_held = self._orig_held
        return False

    def writes_to(self, path):
        return self.counts.get(str(path), 0)


class TestDeadmanSweep(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        api._invalidate_load_cache(api.DEADMAN_FILE)

    def _seed(self, jobs):
        api.save(api.DEADMAN_FILE, {'jobs': jobs})
        api._invalidate_load_cache(api.DEADMAN_FILE)

    def test_nothing_late_writes_nothing(self):
        self._seed([{'id': 'j1', 'name': 'nightly', 'last_ping': self.now,
                     'period_minutes': 60, 'grace_minutes': 10}])
        with _WriteCounter() as wc:
            for _ in range(5):
                api._invalidate_load_cache(api.DEADMAN_FILE)
                api.run_deadman_check_if_due()
        self.assertEqual(wc.writes_to(api.DEADMAN_FILE), 0,
                         'a sweep with nothing to do rewrote its store — this '
                         'ran once per HTTP request')

    def test_an_already_late_job_writes_nothing_either(self):
        """The edge-triggered case. A job that alerted last week must not
        re-write the store forever after."""
        self._seed([{'id': 'j1', 'name': 'nightly',
                     'last_ping': self.now - 90000, 'period_minutes': 60,
                     'grace_minutes': 10, 'late': True}])
        with _WriteCounter() as wc:
            for _ in range(5):
                api._invalidate_load_cache(api.DEADMAN_FILE)
                api.run_deadman_check_if_due()
        self.assertEqual(wc.writes_to(api.DEADMAN_FILE), 0)

    def test_a_newly_late_job_still_writes_once(self):
        """The positive control, and the whole point of the sweep. Without it a
        sweep that returned immediately would pass both tests above."""
        self._seed([{'id': 'j1', 'name': 'nightly',
                     'last_ping': self.now - 90000, 'period_minutes': 60,
                     'grace_minutes': 10}])
        fired = []
        orig = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None, *a, **k: fired.append(ev)
        try:
            with _WriteCounter() as wc:
                api.run_deadman_check_if_due()
            self.assertEqual(wc.writes_to(api.DEADMAN_FILE), 1,
                             'the sweep must still mark the job late')
        finally:
            api.fire_webhook = orig
        self.assertIn('ping_missed', fired)
        api._invalidate_load_cache(api.DEADMAN_FILE)
        jobs = (api.load(api.DEADMAN_FILE) or {}).get('jobs') or []
        self.assertTrue(jobs[0].get('late'))

    def test_no_jobs_at_all_writes_nothing(self):
        self._seed([])
        with _WriteCounter() as wc:
            api.run_deadman_check_if_due()
        self.assertEqual(wc.writes_to(api.DEADMAN_FILE), 0)


class TestPromotedIncidentSweep(unittest.TestCase):
    def setUp(self):
        api.save(api.ALERTS_FILE, {'alerts': [], 'alert_seq': 0})
        api._invalidate_load_cache(api.ALERTS_FILE)
        api._invalidate_load_cache(api.INCIDENTS_FILE)

    def _seed(self, incidents, alerts=()):
        api.save(api.INCIDENTS_FILE, {'incidents': incidents})
        api.save(api.ALERTS_FILE, {'alerts': list(alerts), 'alert_seq': 0})
        api._invalidate_load_cache(api.INCIDENTS_FILE)
        api._invalidate_load_cache(api.ALERTS_FILE)

    def test_an_open_incident_with_open_alerts_writes_nothing(self):
        self._seed(
            [{'id': 'i1', 'auto_promoted': True, 'status': 'open',
              'alert_ids': [1]}],
            [{'id': 1, 'event': 'device_offline'}])          # not resolved
        with _WriteCounter() as wc:
            for _ in range(5):
                api._invalidate_load_cache(api.INCIDENTS_FILE)
                api._maybe_auto_resolve_promoted_incidents()
        self.assertEqual(wc.writes_to(api.INCIDENTS_FILE), 0,
                         'rewrote the incidents store with nothing resolvable')

    def test_an_already_resolved_incident_writes_nothing(self):
        self._seed(
            [{'id': 'i1', 'auto_promoted': True, 'status': 'resolved',
              'alert_ids': [1]}],
            [{'id': 1, 'event': 'device_offline', 'resolved_at': 123}])
        with _WriteCounter() as wc:
            for _ in range(5):
                api._invalidate_load_cache(api.INCIDENTS_FILE)
                api._maybe_auto_resolve_promoted_incidents()
        self.assertEqual(wc.writes_to(api.INCIDENTS_FILE), 0)

    def test_it_still_resolves_when_every_alert_has_cleared(self):
        """Positive control."""
        self._seed(
            [{'id': 'i1', 'auto_promoted': True, 'status': 'open',
              'alert_ids': [1, 2]}],
            [{'id': 1, 'event': 'device_offline', 'resolved_at': 123},
             {'id': 2, 'event': 'disk_full', 'resolved_at': 124}])
        with _WriteCounter() as wc:
            api._maybe_auto_resolve_promoted_incidents()
        self.assertEqual(wc.writes_to(api.INCIDENTS_FILE), 1)
        api._invalidate_load_cache(api.INCIDENTS_FILE)
        inc = ((api.load(api.INCIDENTS_FILE) or {}).get('incidents') or [])[0]
        self.assertEqual(inc.get('status'), 'resolved')

    def test_a_manually_created_incident_is_left_alone(self):
        """auto_promoted is the gate — a human-opened incident must never be
        closed by a sweep."""
        self._seed(
            [{'id': 'i1', 'status': 'open', 'alert_ids': [1]}],
            [{'id': 1, 'event': 'device_offline', 'resolved_at': 123}])
        with _WriteCounter() as wc:
            api._maybe_auto_resolve_promoted_incidents()
        self.assertEqual(wc.writes_to(api.INCIDENTS_FILE), 0)


if __name__ == '__main__':
    unittest.main()
