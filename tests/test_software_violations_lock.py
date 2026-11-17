#!/usr/bin/env python3
"""The violations store is written under its lock, whatever order the pushes of the hosts arrive in.

`handle_packages_submit` took the lock of `packages.json` for the list a host sent, and then called `_eval_software_policy`,
which did a bare `load(SOFTWARE_VIOLATIONS_FILE)` ... `save(SOFTWARE_VIOLATIONS_FILE, store)` with `fire_webhook` (event log,
alert ledger, delivery) between the two. Every host writes that store, so twelve Windows hosts that sent their lists together
(the restart after a patch night) kept three of twelve violation rows. A host whose row was lost read as newly in breach at its
next push, and `software_policy_violation` fired twice for a rule that had been broken once.

These tests drive the real handler with real threads and the real storage. The first makes the interleaving certain instead of
likely: it holds every push at the point where the old code sat between its read and its write. The class (a store a host
writes, read and saved with no lock) is held by tests/test_host_written_store_locks.py.
"""
import importlib.util
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
_TMP = []


def _tmp(prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d


os.environ.setdefault('RP_DATA_DIR', _tmp('rp-violock-'))
_spec = importlib.util.spec_from_file_location('api_violations_lock', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


_local = threading.local()
LIST = [{'name': 'TeamViewer', 'version': '15.49.2'}, {'name': 'Git', 'version': '2.43.0'}]
CLEAN = [{'name': 'Git', 'version': '2.43.0'}]
RULE = {'id': 'no-tv', 'type': 'banned', 'package': 'TeamViewer'}
VIOLATIONS = Path(str(api.SOFTWARE_VIOLATIONS_FILE)).name


def _device(name):
    return {'id': name, 'name': name, 'tenant': 'default', 'os': 'Windows 11 (Build 22631)', 'token': 'tok-' + name,
            'monitored': True, 'group': 'windows', 'tags': ['windows'], 'last_seen': 2_000_000_000}


def _push(dev_id, packages):
    """POST /api/packages as the agent of a Windows host. Returns (status, answer)."""
    _local.body = {'device_id': dev_id, 'token': 'tok-' + dev_id, 'pkg_manager': 'windows', 'packages': packages}
    try:
        api.handle_packages_submit()
    except _Captured as c:
        return c.status, c.body
    raise AssertionError('the handler did not answer')


def _respond(status, data=None, headers=None):
    raise _Captured(status, data)


class _Fleet(unittest.TestCase):
    N = 12

    def setUp(self):
        self.hosts = [f'sviolwin{i}' for i in range(self.N)]
        self.told = []                     # (event, device_id, whether a lock was held at the call)
        self._mutex = threading.Lock()
        real = api.fire_webhook

        def recording(event, payload=None, *a, **k):
            if event in ('software_policy_violation', 'policy_compliant'):
                with self._mutex:
                    self.told.append((event, (payload or {}).get('device_id'), api._locks_held()))
                self.at_event(event)
            return real(event, payload, *a, **k)
        self._patches = [mock.patch.object(api, 'respond', _respond),
                         mock.patch.object(api, 'method', lambda: 'POST'),
                         mock.patch.object(api, 'get_json_obj', lambda: dict(getattr(_local, 'body', {}))),
                         mock.patch.object(api, 'fire_webhook', recording)]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop)
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {h: _device(h) for h in self.hosts})
        api.save(api.PACKAGES_FILE, {})
        api.save(api.SOFTWARE_VIOLATIONS_FILE, {})
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': [RULE]})
        api._LOAD_CACHE.clear()

    def _stop(self):
        for p in reversed(self._patches):
            p.stop()
        for store in (api.DEVICES_FILE, api.PACKAGES_FILE, api.SOFTWARE_VIOLATIONS_FILE, api.SOFTWARE_POLICY_FILE,
                      api.CONFIG_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    def at_event(self, event):
        """A seam for a test to hold a push where it tells the world of a change."""

    def rows(self):
        api._LOAD_CACHE.clear()
        return api.load(api.SOFTWARE_VIOLATIONS_FILE) or {}

    def push_together(self, packages=LIST):
        """Every host pushes at once, released by one barrier. Returns once all have been answered."""
        gate = threading.Barrier(len(self.hosts))
        answers, errors = {}, []

        def run(dev_id):
            try:
                gate.wait(timeout=30)
                answers[dev_id] = _push(dev_id, packages)
            except BaseException as e:          # noqa: BLE001 - a thread has to report, not die quietly
                errors.append((dev_id, repr(e)))
        threads = [threading.Thread(target=run, args=(h,)) for h in self.hosts]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        for dev_id, (status, answer) in answers.items():
            self.assertEqual(status, 200, (dev_id, answer))
        return answers


class TestPushesThatArriveTogether(_Fleet):
    def test_every_host_keeps_its_row_when_the_pushes_meet_between_the_read_and_the_write(self):
        """Certain, not likely. Each push is held when it tells the world of its breach, which is where the old code sat
        between its read of the store and its write: every push then wrote from a snapshot that none of the others was in."""
        gate = threading.Barrier(len(self.hosts))

        def hold(event):
            if event == 'software_policy_violation':
                try:
                    gate.wait(timeout=20)
                except threading.BrokenBarrierError:
                    pass
        self.at_event = hold
        self.push_together()
        rows = self.rows()
        self.assertEqual(sorted(rows), sorted(self.hosts))
        for dev_id, row in rows.items():
            self.assertEqual([v['rule_id'] for v in row['violations']], ['no-tv'], dev_id)
            self.assertEqual(row['manager'], 'windows')

    def test_each_breach_is_told_once_and_a_second_push_of_the_same_lists_tells_nothing(self):
        """What a lost row costs. A host without its row reads as newly in breach at its next push: the repro counted 21
        alerts for 12 hosts that each broke the rule once."""
        self.push_together()
        self.assertEqual(sorted(d for e, d, _ in self.told if e == 'software_policy_violation'), sorted(self.hosts))
        before = len(self.told)
        for host in self.hosts:                                      # the six-hourly resend, one at a time, nothing changed
            self.assertEqual(_push(host, LIST)[0], 200)
        self.assertEqual(len(self.told), before)
        self.assertEqual(sorted(self.rows()), sorted(self.hosts))

    def test_pushes_released_together_keep_every_row_round_after_round(self):
        """The shape of a restart after a patch night, with nothing held: twelve threads, three rounds, the real events."""
        for rnd in range(3):
            api.save(api.SOFTWARE_VIOLATIONS_FILE, {})
            api._LOAD_CACHE.clear()
            self.told.clear()
            self.push_together()
            self.assertEqual(sorted(self.rows()), sorted(self.hosts), f'round {rnd}')
            self.assertEqual(len([1 for e, _, _ in self.told if e == 'software_policy_violation']), len(self.hosts))

    def test_a_host_that_clears_its_breach_loses_its_row_and_only_its_row(self):
        self.push_together()
        self.told.clear()
        self.assertEqual(_push(self.hosts[0], CLEAN)[0], 200)
        self.assertEqual(sorted(self.rows()), sorted(self.hosts[1:]))
        self.assertEqual([(e, d) for e, d, _ in self.told], [('policy_compliant', self.hosts[0])])

    def test_the_events_are_told_after_the_lock_is_released(self):
        """A scope that aborts discards what it queued, so an event told inside the lock can vanish with it: the events are
        collected in the lock and fired after it."""
        self.push_together()
        self.assertEqual(len(self.told), len(self.hosts))
        self.assertEqual([entry for entry in self.told if entry[2]], [])


class TestWithNoRules(_Fleet):
    N = 3

    def test_a_row_an_earlier_ruleset_left_is_dropped_and_the_lock_is_taken_only_for_that(self):
        keep, drop_one, other = self.hosts
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': []})
        api.save(api.SOFTWARE_VIOLATIONS_FILE, {h: {'name': h, 'checked_at': 1, 'violations': [{'rule_id': 'old'}]}
                                                for h in (drop_one, other)})
        api._LOAD_CACHE.clear()
        entered = []
        real = api._LockedUpdate

        def recording(path, non_blocking=False):
            entered.append(Path(str(path)).name)
            return real(path, non_blocking)
        with mock.patch.object(api, '_LockedUpdate', recording):
            self.assertEqual(_push(keep, LIST)[0], 200)
            self.assertNotIn(VIOLATIONS, entered)                 # a host with no row: nothing to drop, no lock
            self.assertEqual(_push(drop_one, LIST)[0], 200)
        self.assertEqual(entered.count(VIOLATIONS), 1)            # the control: a host with a row takes it
        self.assertEqual(sorted(self.rows()), [other])            # the one that pushed is gone, the other is untouched


if __name__ == '__main__':
    unittest.main()
