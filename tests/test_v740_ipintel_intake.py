"""Threat intel's intake has a document of its own (7.4.0).

The queue of addresses waiting for a sweep, each host's sensor record and the edge
feeds' places in their logs are written whenever a heartbeat or a poll has
something to say. They used to share a document with the table of addresses,
which every write rewrites whole: with 5,000 addresses recorded that was 57 to
125 ms on SQLite and 132 to 334 ms on the JSON backend, per heartbeat, under the
lock the sweep and every other writer wait on. The intake is a few hundred
kilobytes at most.

What these tests hold:
  * a heartbeat-side write touches the intake and never the table;
  * no operation holds both locks at once (the SQL backends share one connection
    and cannot, and the JSON backend would let a mistake pass);
  * an install that still has the old shape is adopted, once and in order;
  * the edge feeds' events and cursors go in together or not at all.
"""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v740-intake-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import ipintel_store  # noqa: E402

import threat_evidence as te  # noqa: E402
from test_ip_intel import ATTACKER, _Case  # noqa: E402
from test_v720_threat_intake import raw_event  # noqa: E402
from test_v730_edge_intel import SECOND, THIRD, T, _Edge  # noqa: E402

OTHER = '185.220.101.9'


def sensor_event(ip=ATTACKER):
    return te.normalize_event(raw_event(ip))


def table(n=50):
    """A table of addresses with enough in it to notice a rewrite of it."""
    return {f'45.7.{i // 250}.{i % 250 + 1}': {'first_seen': 1, 'last_seen': 2, 'devices': {'d1': {'count': 3}}}
            for i in range(n)}


class _Held:
    """Stands in for api._LockedUpdate and records which documents are locked, and
    how many at the same time."""

    def __init__(self, api):
        self.real = api._LockedUpdate
        self.api = api
        self.open = []
        self.deepest = 0
        self.taken = {}
        self.lock = threading.Lock()

    def __call__(self, path, *a, **k):
        inner = self.real(path, *a, **k)
        held = self

        class _Scope:
            def __enter__(scope):
                data = inner.__enter__()
                with held.lock:
                    held.open.append(path)
                    held.deepest = max(held.deepest, len(held.open))
                    held.taken[path] = held.taken.get(path, 0) + 1
                return data

            def __exit__(scope, *exc):
                with held.lock:
                    held.open.remove(path)
                return inner.__exit__(*exc)
        return _Scope()

    def named(self, path):
        return self.taken.get(path, 0)


class TestAHeartbeatNeverWritesTheTable(_Case):
    def setUp(self):
        super().setUp()
        self.policy(sensor_enabled=True)
        ipintel_store.update(self.api, attackers=table())
        self.before = self.api.load(self.api.IPINTEL_FILE)
        self.held = _Held(self.api)

    def test_the_brute_force_hook_locks_the_intake_only(self):
        api = self.api
        with mock.patch.object(api, '_LockedUpdate', self.held):
            api.ip_intel_note_attacks('d1', 'sshd.service', [(ATTACKER, 30), (OTHER, 30)], 600)
        self.assertEqual((self.held.named(api.IPINTEL_INTAKE_FILE), self.held.named(api.IPINTEL_FILE)), (1, 0))
        self.assertEqual([q['ip'] for q in ipintel_store.read(api)['queue']], [ATTACKER, OTHER])

    def test_the_sensor_hook_locks_the_intake_only(self):
        api = self.api
        with mock.patch.object(api, '_LockedUpdate', self.held):
            res = api.ip_intel_note_evidence('d1', [sensor_event()], {'sources': [], 'dropped': 0})
        self.assertEqual(res['queued'], 1)
        self.assertEqual((self.held.named(api.IPINTEL_INTAKE_FILE), self.held.named(api.IPINTEL_FILE)), (1, 0))
        self.assertIn('d1', ipintel_store.read(api)['sensors'])

    def test_the_table_is_exactly_as_it_was_after_both_hooks(self):
        api = self.api
        api.ip_intel_note_attacks('d1', 'sshd.service', [(ATTACKER, 30)], 600)
        api.ip_intel_note_evidence('d1', [sensor_event(OTHER)], {'sources': []})
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.IPINTEL_FILE), self.before)

    def test_control_the_counter_does_see_the_table_being_locked(self):
        """A count of zero proves nothing unless the same instrument reads more
        than zero when the table is written. The sweep does write it."""
        api = self.api
        api.ip_intel_note_attacks('d1', 'sshd.service', [(ATTACKER, 30)], 600)
        st = ipintel_store.read(api)
        st['last_sweep'] = 0
        ipintel_store.write(api, st)
        with mock.patch.object(api, '_LockedUpdate', self.held):
            api.run_ip_intel_if_due()
        self.assertGreaterEqual(self.held.named(api.IPINTEL_FILE), 1)
        self.assertGreaterEqual(self.held.named(api.IPINTEL_INTAKE_FILE), 1)


class TestNoOperationHoldsBothLocks(_Edge):
    """The SQL backends share one connection per data directory, so a second
    lock taken inside the first is a nested BEGIN and fails. The JSON backend lets
    it through, which is how a mistake would reach a Postgres install unseen."""

    def run_held(self, fn):
        held = _Held(self.api)
        with mock.patch.object(self.api, '_LockedUpdate', held):
            fn()
        self.assertGreaterEqual(sum(held.taken.values()), 1, 'control: nothing was locked at all')
        self.assertEqual(held.deepest, 1, 'two documents were locked at once')
        return held

    def test_the_hooks(self):
        api = self.api
        self.policy(sensor_enabled=True)
        self.run_held(lambda: api.ip_intel_note_attacks('d1', 'sshd.service', [(ATTACKER, 30)], 600))
        self.run_held(lambda: api.ip_intel_note_evidence('d1', [sensor_event(OTHER)], {'sources': []}))

    def test_the_sweep(self):
        api = self.api
        self.policy(block_enabled=True, block_min_score=1)
        api.ip_intel_note_attacks('d1', 'sshd.service', [(ATTACKER, 30)], 600)
        ipintel_store.update(api, last_sweep=0, blocks={'d1': {OTHER: {
            'at': 1, 'until': 2, 'score': 99, 'by': 'auto', 'kind': 'ssh'}}})
        held = self.run_held(api.run_ip_intel_if_due)
        self.assertGreaterEqual(held.named(api.IPINTEL_INTAKE_FILE), 1)
        self.assertGreaterEqual(held.named(api.IPINTEL_FILE), 1)

    def test_the_edge_poll(self):
        held = self.run_held(self.poll)
        self.assertGreaterEqual(held.named(self.api.IPINTEL_INTAKE_FILE), 1)

    def test_the_clear(self):
        api = self.api
        api.ip_intel_note_attacks('d1', 'sshd.service', [(ATTACKER, 30)], 600)
        self.run_held(lambda: self.call(api.handle_ip_intel_clear, body={}))


class TestAnOldInstallIsAdoptedOnce(_Case):
    """Before 7.4.0 the queue, `sensors` and the feeds' places (`edge.cf_to`,
    `edge.trap_to`) were keys of the one document."""

    def old_shape(self):
        api = self.api
        api.save(api.IPINTEL_FILE, {
            'attackers': table(5),
            'queue': [{'ip': ATTACKER, 'device_id': 'd1', 'unit': 'sshd.service', 'count': 30,
                       'window_s': 600, 'at': 100}],
            'sensors': {'d1': {'at': 100, 'sources': [], 'events': 2, 'throttled': 0, 'dropped': 0,
                               'ignored': {}, 'hour': {'h': 1, 'n': 2}}},
            'edge': {'polled': 5, 'cf_to': 111, 'trap_to': 222},
            'last_sweep': 0})
        api._LOAD_CACHE.clear()
        self.assertFalse(api.backend_exists(api.IPINTEL_INTAKE_FILE), 'control: there is no intake yet')

    def setUp(self):
        super().setUp()
        self.policy(sensor_enabled=True)
        self.old_shape()

    def test_until_the_first_write_the_old_queue_is_what_is_read(self):
        api = self.api
        intake = api._intake_ro()
        self.assertEqual([q['ip'] for q in intake['queue']], [ATTACKER])
        self.assertEqual(intake['cursors'], {'cf': 111, 'trap': 222})
        self.assertIn('d1', intake['sensors'])
        view = self.call(api.handle_ip_intel)[1]
        self.assertEqual(view['queued'], 1)
        self.assertEqual([r['device_id'] for r in view['sensors']], ['d1'])

    def call(self, fn, method='GET'):
        api = self.api
        api.verify_token = lambda _t=None: ('alice', 'admin')
        api.method = lambda: method
        api.get_json_obj = lambda: {}
        self.cap.clear()
        try:
            fn()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def test_the_first_write_takes_the_old_entries_first(self):
        api = self.api
        api.ip_intel_note_attacks('d1', 'sshd.service', [(OTHER, 30)], 600)
        api._LOAD_CACHE.clear()
        intake = ipintel_store.read_intake(api)
        self.assertEqual([q['ip'] for q in intake['queue']], [ATTACKER, OTHER])
        self.assertEqual(intake['cursors'], {'cf': 111, 'trap': 222})
        self.assertEqual(list(intake['sensors']), ['d1'])
        self.assertTrue(intake['adopted'])

    def test_it_happens_once(self):
        api = self.api
        api.ip_intel_note_attacks('d1', 'sshd.service', [(OTHER, 30)], 600)
        st = api.load(api.IPINTEL_FILE)
        st['queue'] = [{'ip': '8.8.8.8', 'device_id': 'd1', 'unit': 'sshd.service', 'count': 30,
                        'window_s': 600, 'at': 200}]
        api.save(api.IPINTEL_FILE, st)
        api._LOAD_CACHE.clear()
        api.ip_intel_note_attacks('d1', 'sshd.service', [(SECOND, 30)], 600)
        api._LOAD_CACHE.clear()
        self.assertEqual([q['ip'] for q in ipintel_store.read_intake(api)['queue']], [ATTACKER, OTHER, SECOND])

    def test_the_sweep_drops_the_old_copies_from_the_table(self):
        api = self.api
        api.run_ip_intel_if_due()
        api._LOAD_CACHE.clear()
        st = api.load(api.IPINTEL_FILE)
        for stale in ('queue', 'sensors'):
            self.assertNotIn(stale, st)
        self.assertEqual(st['edge'], {'polled': 5}, 'only the feeds\' places go; the rest of edge stays')
        intake = ipintel_store.read_intake(api)
        self.assertEqual(intake['cursors'], {'cf': 111, 'trap': 222})
        self.assertEqual(intake['queue'], [], 'the sweep took the entry it was given')
        self.assertIn(ATTACKER, st['attackers'])

    def test_a_clear_after_the_move_empties_the_queue_where_it_is(self):
        api = self.api
        api.ip_intel_note_attacks('d1', 'sshd.service', [(OTHER, 30)], 600)
        st, data = self.call(api.handle_ip_intel_clear, 'POST')
        self.assertEqual((st, data['queue']), (200, 2))
        self.assertEqual(ipintel_store.read_intake(api)['queue'], [])


class TestTheEdgeFeedsAreAllOrNothing(_Edge):
    def test_events_and_places_are_in_the_intake_and_not_in_the_table(self):
        api = self.api
        self.poll()
        intake = ipintel_store.read_intake(api)
        self.assertEqual(intake['cursors']['cf'], T - 90)
        self.assertIn((ATTACKER, 'edge:cloudflare'), {(q['ip'], q['device_id']) for q in intake['queue']})
        edge = api.load(api.IPINTEL_FILE).get('edge') or {}
        self.assertNotIn('cf_to', edge)
        self.assertNotIn('trap_to', edge)
        self.assertEqual(edge['cf']['state'], 'ok', 'control: the table still holds what the page shows')

    def test_a_write_that_fails_halfway_queues_nothing_and_moves_no_place(self):
        """The first feed's events are in the transaction when the second feed's
        fail. Both feeds' events and both places must be as they were, or the next
        read would count the first feed's window twice."""
        api = self.api
        real = api._note_evidence_into
        calls = []

        def second_one_fails(intake, dev, events, status=None, now=None):
            calls.append(dev)
            if len(calls) == 2:
                raise RuntimeError('the write failed')
            return real(intake, dev, events, status, now)
        with mock.patch.object(api, '_note_evidence_into', second_one_fails):
            with self.assertRaises(RuntimeError):
                self.poll()
        self.assertEqual(len(calls), 2, 'control: the first feed was written before the second failed')
        intake = ipintel_store.read_intake(api)
        self.assertEqual((intake.get('queue') or [], intake.get('cursors') or {}), ([], {}))

        # and the next read counts each window once
        self.poll()
        queue = ipintel_store.read_intake(api)['queue']
        keys = [(q['ip'], q['device_id']) for q in queue]
        self.assertEqual(len(keys), len(set(keys)), 'an address was queued twice for one window')
        self.assertIn((ATTACKER, 'edge:cloudflare'), keys)
        self.assertEqual(ipintel_store.read_intake(api)['cursors']['cf'], T - 90)


class TestTheQueueStillHasItsRules(_Case):
    def test_a_full_queue_keeps_what_a_ban_engine_decided_on(self):
        """Moving the queue must not move its trimming rule with it: the most
        urgent entries stay when it is full (the same rule, in the new place)."""
        api = self.api
        self.policy(sensor_enabled=True)
        confirmed = te.normalize_event({'ip': SECOND, 'first': 1, 'last': 2, 'src': {'f2b': 3},
                                        'tok': {'f2b': {'jail:sshd': 3}}, 'ban': ['sshd']}, families=te.AGENT_SOURCES)
        api.ip_intel_note_evidence('d1', [confirmed], {'sources': []})
        for i in range(0, 600, 20):
            api.ip_intel_note_attacks('d1', 'sshd.service',
                                      [('45.9.%d.%d' % (j // 250, j % 250 + 1), 1) for j in range(i, i + 20)], 600)
        queue = ipintel_store.read_intake(api)['queue']
        self.assertEqual(len(queue), 500)
        self.assertIn(SECOND, [q['ip'] for q in queue])


if __name__ == '__main__':
    unittest.main()
