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
    """Counts writes per storage key, ON WHICHEVER BACKEND IS ACTIVE.

    Three write paths, and missing any one makes this count zero and report
    success:

      api.save        the ordinary write
      api._save_held  what a _LockedUpdate block calls on the JSON backend,
                      because the flock is already held
      storage.save /  what a _LockedUpdate block calls on SQLite and Postgres:
      storage_pg.save `_DbLockedUpdate.__exit__` delegates to the storage
                      module's own context manager, which never touches either
                      api-level function

    THE THIRD ONE COST A FULL GATE RUN. The first version wrapped only
    `api.save`, so both positive controls failed and I fixed it by adding
    `_save_held` — which is correct for JSON and still blind on a DB backend.
    `make test` went green, I shipped it, and `make test-sqlite` then failed
    the same two positive controls: under SQLite the counter saw ZERO writes
    for everything, so the four "writes nothing" assertions were passing
    VACUOUSLY (0 == 0 regardless of what the code did) on the enterprise
    default backend.

    The positive controls are the only reason any of that was visible. A file
    of purely negative assertions would have reported success on both
    backends while measuring nothing on either — which is the exact failure
    this release is named after, reproduced inside a test written to catch it.
    """

    def __init__(self):
        self.counts = {}
        self._patched = []
        self._depth = 0

    def _bump(self, path):
        self.counts[str(path)] = self.counts.get(str(path), 0) + 1

    def _wrap(self, obj, name):
        orig = getattr(obj, name, None)
        if orig is None:
            return

        def _wrapped(path, data, *a, **k):
            # COUNT THE OUTERMOST CALL ONLY. On a DB backend `api.save`
            # delegates to the storage module's `save`, and both are wrapped —
            # so one logical write registered as two, and every `== 1`
            # assertion failed with 2. The nesting is real; the second entry is
            # not a second write.
            outer = self._depth == 0
            self._depth += 1
            try:
                if outer:
                    self._bump(path)
                return orig(path, data, *a, **k)
            finally:
                self._depth -= 1
        setattr(obj, name, _wrapped)
        self._patched.append((obj, name, orig))

    def __enter__(self):
        self._wrap(api, 'save')
        self._wrap(api, '_save_held')
        mod = api._dbmod()          # None on the JSON backend
        if mod is not None:
            self._wrap(mod, 'save')
        return self

    def __exit__(self, *exc):
        for obj, name, orig in reversed(self._patched):
            setattr(obj, name, orig)
        self._patched = []
        return False

    def writes_to(self, path):
        return self.counts.get(str(path), 0)


class TestTheCounterCanSeeAWrite(unittest.TestCase):
    """Guard the guard, on whatever backend is running.

    Without this, a counter blind to the active backend makes every "writes
    nothing" test below pass by measuring nothing — which is precisely what
    happened under SQLite before this class existed.
    """

    def test_an_ordinary_save_is_counted(self):
        probe = api.DATA_DIR / 'write_counter_probe.json'
        with _WriteCounter() as wc:
            api.save(probe, {'x': 1})
        self.assertEqual(wc.writes_to(probe), 1,
                         'the write counter cannot see api.save on this '
                         'backend — every assertion in this file is vacuous')

    def test_a_locked_update_is_counted(self):
        """The path that actually matters: _LockedUpdate dispatches to a
        DIFFERENT implementation per backend, and only the JSON one goes
        through api._save_held."""
        probe = api.DATA_DIR / 'write_counter_probe2.json'
        api.save(probe, {'x': 1})
        api._invalidate_load_cache(probe)
        with _WriteCounter() as wc:
            with api._LockedUpdate(probe) as doc:
                doc['x'] = 2
        self.assertGreaterEqual(
            wc.writes_to(probe), 1,
            'the counter cannot see a _LockedUpdate write on this backend — '
            'the "writes nothing" tests below would pass against any code')


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
