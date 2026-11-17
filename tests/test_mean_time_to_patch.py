#!/usr/bin/env python3
"""Mean time to patch: the time from the first sweep that saw an update waiting on a host to the first sweep that saw none.

The aging store (patch_age.json) kept when each class of update was first seen on a host and dropped the stamp when the host had none left, so nothing recorded how
long a patch took. The sweep now files the pair (first seen, cleared, kind) in the host's own entry, in the same locked write, and the Patches page reads the figures from
`GET /api/patch-report` (`mttp`).

Driven through the real sweep (`run_patch_sla_if_due`), the real handler and the real dispatcher, with the statistics held to numbers worked out by hand:

  * the pair is filed when the host reports none left, for both classes, with or without a patch SLA rule, and never when the count is unknown;
  * the ring: at most 200 pairs a host and none older than 400 days, no pair twice for one stamp, nothing for a stamp that is not a number or lies ahead of the clock;
  * the read-only evaluators (the SLA page, the reports, the risk score, the Patches page) never file a pair and never copy the pairs;
  * mean, median and 90th percentile (nearest rank) in hours, the count n, nothing shown below five pairs, nothing for a host with no pair;
  * the window (30 or 90 days, anything else is 30), hostile values of it, a store from before this change, a store with damaged rows;
  * one organisation reads its own hosts' pairs and no other's, a scoped role likewise, and only the operator of the installation gets the split per tenant.
"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-mttp-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

HOUR, DAY = 3600, 86400
T0 = 1_800_000_000          # a fixed clock for the sweeps


def host(name, upgradable=0, security=0, **extra):
    pk = {}
    if upgradable is not None:
        pk['upgradable'] = upgradable
    if security is not None:
        pk['security_updates'] = security
    rec = {'name': name, 'monitored': True, 'last_seen': int(time.time()), 'sysinfo': {'packages': pk} if pk else {}}
    rec.update(extra)
    return rec


class _Base(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self.addCleanup(shutil.rmtree, str(self.api.DATA_DIR), True)       # the data directory of each test is on tmpfs
        self.api.verify_token = lambda token: {'k': ('admin', 'admin'), 'v': ('vera', 'viewer')}.get(token, (None, None))
        self.api.audit_log = lambda *a, **k: None
        self.fired = []
        self.api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))
        real = self.api.time.time
        self.addCleanup(setattr, self.api.time, 'time', real)

    def put(self, devices, **cfg):
        # through the storage layer: under SQLite and Postgres a store is a table, and a file written beside it is not what the server reads
        self.api.save(self.api.DEVICES_FILE, devices)
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def plant_age(self, age):
        self.api.save(self.api.PATCH_AGE_FILE, age)
        self.api._LOAD_CACHE.clear()

    def age(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.PATCH_AGE_FILE)

    def sweep(self, at):
        """One run of the sweep at a fixed time, as a request of its own."""
        self.api.time.time = lambda: at
        self.api._LOAD_CACHE.clear()
        self.api.run_patch_sla_if_due()
        self.api._LOAD_CACHE.clear()

    def call(self, fn, *args, query='', token='k'):
        return _run(self.api, lambda: fn(*args), None, method='GET', env={'HTTP_AUTHORIZATION': 'Bearer ' + token, 'QUERY_STRING': query})

    def request(self, path, token='k', query=''):
        """A request through main(): the dispatcher, with the gates that run before a handler does."""
        names = ('REQUEST_METHOD', 'PATH_INFO', 'REMOTE_ADDR', 'CONTENT_LENGTH', 'QUERY_STRING', 'HTTP_AUTHORIZATION', 'HTTP_X_TOKEN')
        saved = {n: os.environ.get(n) for n in names}

        def go():
            os.environ.update(PATH_INFO=path)
            self.api.main()
        try:
            return _run(self.api, go, None, method='GET', env={'HTTP_AUTHORIZATION': 'Bearer ' + token, 'QUERY_STRING': query})
        finally:
            for n, v in saved.items():
                if v is None:
                    os.environ.pop(n, None)
                else:
                    os.environ[n] = v


class TestTheStatistics(unittest.TestCase):
    """The figures, from a list of durations in hours, against numbers worked out by hand."""

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def stats(self, hours, hosts=None):
        return self.api._mttp_stats(hours, hosts)

    def test_an_empty_list_is_no_figure_and_none_is_not_zero(self):
        got = self.stats([])
        self.assertEqual(got, {'n': 0, 'hidden': True, 'mean_h': None, 'median_h': None, 'p90_h': None})

    def test_below_five_pairs_the_numbers_are_withheld_and_n_is_not(self):
        for n in range(1, 5):
            got = self.stats([float(i + 1) for i in range(n)])
            self.assertEqual((got['n'], got['hidden'], got['mean_h'], got['median_h'], got['p90_h']), (n, True, None, None, None), n)

    def test_five_pairs_is_the_first_figure(self):
        # 2, 4, 6, 8, 100: the mean is 120 / 5, the median is the middle one, the 90th percentile is the fifth of five (ceil(4.5))
        got = self.stats([100, 2, 8, 4, 6])
        self.assertEqual(got, {'n': 5, 'hidden': False, 'mean_h': 24.0, 'median_h': 6.0, 'p90_h': 100.0})

    def test_an_even_count_takes_the_mean_of_the_two_in_the_middle_and_the_nearest_rank_for_the_90th(self):
        got = self.stats([float(i) for i in range(1, 11)])          # 1..10
        self.assertEqual((got['mean_h'], got['median_h'], got['p90_h']), (5.5, 5.5, 9.0))        # rank ceil(9.0) = 9

    def test_eleven_pairs_the_rank_rounds_up(self):
        got = self.stats([float(i) for i in range(1, 12)])          # 1..11
        self.assertEqual((got['mean_h'], got['median_h'], got['p90_h']), (6.0, 6.0, 10.0))       # rank ceil(9.9) = 10

    def test_the_figures_are_rounded_to_two_places(self):
        got = self.stats([1, 1, 1, 1, 2])                           # mean 6 / 5 = 1.2
        self.assertEqual(got['mean_h'], 1.2)
        got = self.stats([1, 2, 2, 2, 2, 2])                        # mean 11 / 6 = 1.8333...
        self.assertEqual(got['mean_h'], 1.83)

    def test_the_host_count_is_carried_when_it_is_given(self):
        self.assertEqual(self.stats([1.0] * 5, 3)['hosts'], 3)
        self.assertNotIn('hosts', self.stats([1.0] * 5))

    def test_the_hours_of_a_pair_come_from_seconds(self):
        entry = {'done': [[T0, T0 + 5400, 'all'], [T0, T0 + 7200, 'sec']]}
        self.assertEqual(self.api._patch_done_hours(entry, 'all', 0), [1.5])
        self.assertEqual(self.api._patch_done_hours(entry, 'sec', 0), [2.0])
        self.assertEqual(self.api._patch_done_hours(entry, 'all', T0 + 5400), [1.5], 'cleared at the cutoff is in the window')
        self.assertEqual(self.api._patch_done_hours(entry, 'all', T0 + 5401), [], 'cleared before the cutoff is out of it')

    def test_a_row_the_sweep_cannot_have_filed_is_left_out(self):
        entry = {'done': [[T0, T0 - 60, 'all'], [T0, T0 + 3600, 'all'], [T0, T0 + 9 * DAY, 'all']]}
        self.assertEqual(self.api._patch_done_hours(entry, 'all', 0), [1.0, 216.0], 'cleared before it was first seen is dropped, not counted as no time')
        self.assertEqual(self.api._patch_done_hours(entry, 'all', 0, T0 + DAY), [1.0], 'and one cleared in the future is dropped when the clock is given')


class TestFilingThePair(_Base):

    def two(self, up, sec, **extra):
        self.put({'d1': host('one', up, sec, **extra)})

    def test_both_classes_are_filed_when_the_host_reports_none_left(self):
        self.two(4, 2)
        self.sweep(T0)
        self.assertEqual((self.age()['d1'].get('all_first'), self.age()['d1'].get('sec_first')), (T0, T0))
        self.assertNotIn('done', self.age()['d1'], 'nothing is filed while the update is waiting')
        self.sweep(T0 + 2 * HOUR)                                   # still waiting
        self.two(0, 0)
        self.sweep(T0 + 6 * HOUR)
        d = self.age()['d1']
        self.assertEqual(d['done'], [[T0, T0 + 6 * HOUR, 'all'], [T0, T0 + 6 * HOUR, 'sec']])
        self.assertNotIn('all_first', d)
        self.assertNotIn('sec_first', d)

    def test_the_security_pair_closes_before_the_other_when_the_security_updates_go_first(self):
        self.two(4, 2)
        self.sweep(T0)
        self.two(3, 0)
        self.sweep(T0 + 3 * HOUR)
        d = self.age()['d1']
        self.assertEqual(d['done'], [[T0, T0 + 3 * HOUR, 'sec']])
        self.assertEqual(d['all_first'], T0, 'the other updates are still waiting, and their clock has not stopped')
        self.two(0, 0)
        self.sweep(T0 + 8 * HOUR)
        self.assertEqual(self.age()['d1']['done'], [[T0, T0 + 3 * HOUR, 'sec'], [T0, T0 + 8 * HOUR, 'all']])

    def test_it_does_not_need_a_patch_sla_rule_and_a_rule_does_not_change_what_is_filed(self):
        for cfg in ({}, {'patch_sla': [{'match_type': 'all', 'sec_days': 7, 'all_days': 30}]}):
            self.api.save(self.api.PATCH_AGE_FILE, {})
            self.put({'d1': host('one', 4, 2)}, **cfg)
            self.sweep(T0)
            self.put({'d1': host('one', 0, 0)}, **cfg)
            self.sweep(T0 + 5 * HOUR)
            self.assertEqual(self.age()['d1']['done'], [[T0, T0 + 5 * HOUR, 'all'], [T0, T0 + 5 * HOUR, 'sec']], cfg)

    def test_without_a_rule_nothing_is_in_breach_and_nothing_is_fired(self):
        self.two(4, 2)
        self.sweep(T0)
        self.sweep(T0 + 400 * DAY)                                  # a year later, still waiting
        self.assertEqual(self.fired, [])
        self.assertEqual(self.age()['_breaching'], [])

    def test_a_rule_still_fires_its_edge(self):
        self.put({'d1': host('one', 4, 2)}, patch_sla=[{'match_type': 'all', 'sec_days': 1}])
        self.sweep(T0)
        self.sweep(T0 + 3 * DAY)
        self.assertEqual([e for e, _ in self.fired], ['patch_sla_violation'])
        self.put({'d1': host('one', 0, 0)}, patch_sla=[{'match_type': 'all', 'sec_days': 1}])
        self.sweep(T0 + 4 * DAY)
        self.assertEqual([e for e, _ in self.fired], ['patch_sla_violation', 'patch_sla_ok'])

    def test_an_unknown_count_clears_the_stamp_and_files_nothing(self):
        self.two(4, 2)
        self.sweep(T0)
        self.put({'d1': host('one', None, None)})                  # the agent stopped reporting packages
        self.sweep(T0 + 2 * HOUR)
        d = self.age()['d1']
        self.assertNotIn('done', d, 'an unknown count is not "none left"')
        self.assertNotIn('all_first', d)

    def test_a_host_that_does_not_count_security_apart_closes_both_when_none_is_left(self):
        self.two(4, None)
        self.sweep(T0)
        self.api.save(self.api.PATCH_AGE_FILE, dict(self.age(), d1={'all_first': T0, 'sec_first': T0}))
        self.two(0, None)
        self.sweep(T0 + 2 * HOUR)
        self.assertEqual(self.age()['d1']['done'], [[T0, T0 + 2 * HOUR, 'all'], [T0, T0 + 2 * HOUR, 'sec']])

    def test_unmonitored_and_agentless_hosts_are_not_swept(self):
        self.put({'u': host('u', 4, 2, monitored=False), 'a': host('a', 4, 2, agentless=True)})
        self.sweep(T0)
        self.put({'u': host('u', 0, 0, monitored=False), 'a': host('a', 0, 0, agentless=True)})
        self.sweep(T0 + 2 * HOUR)
        age = self.age()
        self.assertEqual([k for k in age if not k.startswith('_')], [])

    def test_a_host_that_is_gone_takes_its_pairs_with_it(self):
        self.two(4, 2)
        self.sweep(T0)
        self.two(0, 0)
        self.sweep(T0 + 2 * HOUR)
        self.assertIn('done', self.age()['d1'])
        self.put({})
        self.sweep(T0 + 4 * HOUR)
        self.assertNotIn('d1', self.age())

    def test_the_sweep_runs_once_an_hour_and_not_twice_for_one_stamp(self):
        self.two(4, 2)
        self.sweep(T0)
        self.two(0, 0)
        self.sweep(T0 + 10)                                         # inside the hour: not due
        self.assertNotIn('done', self.age()['d1'])
        self.sweep(T0 + HOUR)
        self.sweep(T0 + HOUR + 10)                                  # the same hour again
        self.assertEqual(len(self.age()['d1']['done']), 2)

    def test_the_sweep_takes_the_lock_of_the_store(self):
        self.two(4, 2)
        calls = []
        real = self.api._LockedUpdate
        self.api._LockedUpdate = lambda path, non_blocking=False: (calls.append(Path(path).name), real(path, non_blocking))[1]
        self.addCleanup(setattr, self.api, '_LockedUpdate', real)
        self.sweep(T0)
        self.assertEqual(calls, ['patch_age.json'], 'one locked read-modify-write, of the aging store')

    def test_a_worker_that_finds_the_sweep_due_after_another_has_run_it_files_nothing_more(self):
        """The due check outside the lock reads a view that is a moment old. Inside the lock the clock is read again, so two workers that
        both thought the sweep was due do not both file the pair."""
        self.two(4, 2)
        self.sweep(T0)
        self.two(0, 0)
        self.sweep(T0 + 5 * HOUR)
        self.assertEqual(len(self.age()['d1']['done']), 2)
        # a second worker's view from before the first one ran: stamps present and the old clock
        self.api.save(self.api.PATCH_AGE_FILE, dict(self.age(), d1={'all_first': T0, 'sec_first': T0, 'done': self.age()['d1']['done']}))
        real_ro = self.api._load_ro
        stale = {'_last_run': T0}
        self.api._load_ro = lambda path: stale if Path(path).name == 'patch_age.json' else real_ro(path)
        self.addCleanup(setattr, self.api, '_load_ro', real_ro)
        self.api.time.time = lambda: T0 + 5 * HOUR + 30             # the store says it ran 30 seconds ago
        self.api.run_patch_sla_if_due()
        self.api._load_ro = real_ro
        self.assertEqual(len(self.age()['d1']['done']), 2, 'the second worker must not file the pair again')
        self.assertEqual(self.age()['d1']['all_first'], T0, 'and must not touch the stamps')


class TestTheRing(_Base):

    def test_at_most_two_hundred_pairs_a_host_and_the_oldest_go_first(self):
        st = {}
        for i in range(205):
            self.api._patch_done_add(st, T0 + i * HOUR, T0 + i * HOUR + 600, 'all')
        self.assertEqual(len(st['done']), 200)
        self.assertEqual(st['done'][0][0], T0 + 5 * HOUR)
        self.assertEqual(st['done'][-1][0], T0 + 204 * HOUR)

    def test_a_pair_older_than_four_hundred_days_is_dropped_when_the_next_is_filed(self):
        st = {'done': [[T0 - 500 * DAY, T0 - 499 * DAY, 'all'], [T0 - 399 * DAY, T0 - 398 * DAY, 'all']]}
        self.api._patch_done_add(st, T0 - HOUR, T0, 'all')
        self.assertEqual([r[0] for r in st['done']], [T0 - 399 * DAY, T0 - HOUR])

    def test_one_stamp_is_one_pair(self):
        st = {}
        self.api._patch_done_add(st, T0, T0 + HOUR, 'all')
        self.api._patch_done_add(st, T0, T0 + HOUR, 'all')
        self.assertEqual(len(st['done']), 1)
        self.api._patch_done_add(st, T0, T0 + HOUR, 'sec')          # the other class is a pair of its own
        self.assertEqual(len(st['done']), 2)

    def test_a_stamp_that_is_not_a_number_or_lies_ahead_of_the_clock_files_nothing(self):
        for bad in (None, 'x', True, float('nan'), float('inf'), [1], {'a': 1}, T0 + 1):
            st = {}
            self.api._patch_done_add(st, bad, T0, 'all')
            self.assertNotIn('done', st, repr(bad))

    def test_a_done_field_that_is_not_a_list_is_replaced(self):
        st = {'done': 'junk'}
        self.api._patch_done_add(st, T0, T0 + HOUR, 'all')
        self.assertEqual(st['done'], [[T0, T0 + HOUR, 'all']])

    def test_the_ring_is_kept_through_the_sweep(self):
        done = [[T0 - (300 - i) * HOUR, T0 - (300 - i) * HOUR + 600, 'all'] for i in range(200)]
        self.put({'d1': host('one', 4, 2)})
        self.plant_age({'d1': {'all_first': T0, 'done': list(done)}, '_last_run': 0})
        self.put({'d1': host('one', 0, 0)})
        self.sweep(T0 + 2 * HOUR)
        got = self.age()['d1']['done']
        self.assertEqual(len(got), 200)
        self.assertEqual((got[-1], got[-2]), ([T0, T0 + 2 * HOUR, 'all'], done[-1]), 'the new pair is last')
        self.assertEqual(got[0], done[1], 'and the oldest one made room')


class TestWhatOnlyReadsNeverFiles(_Base):

    def setUp(self):
        super().setUp()
        self.put({'d1': host('one', 0, 0)})
        self.plant_age({'d1': {'all_first': T0 - 5 * HOUR, 'sec_first': T0 - 5 * HOUR, 'done': [[T0 - 99 * HOUR, T0 - 90 * HOUR, 'all']]}, '_last_run': int(time.time())})

    def raw(self):
        return json.dumps(self.age(), sort_keys=True)

    def test_the_evaluator_files_only_when_it_is_asked_to(self):
        age = {'d1': {'all_first': T0 - 5 * HOUR, 'sec_first': T0 - 5 * HOUR}}
        devices = {'d1': host('one', 0, 0)}
        self.api._eval_patch_sla(devices, {}, age, T0)
        self.assertNotIn('done', age['d1'], 'the default is read-only')
        age2 = {'d1': {'all_first': T0 - 5 * HOUR}}
        self.api._eval_patch_sla(devices, {}, age2, T0, record=True)
        self.assertEqual(age2['d1']['done'], [[T0 - 5 * HOUR, T0, 'all']])

    def test_the_patch_sla_page_leaves_the_store_as_it_was(self):
        before = self.raw()
        st, got = self.call(self.api.handle_patch_sla)
        self.assertEqual(st, 200, got)
        self.assertEqual(self.raw(), before)

    def test_the_patches_page_leaves_the_store_as_it_was(self):
        before = self.raw()
        st, got = self.call(self.api.handle_patch_report)
        self.assertEqual(st, 200, got)
        self.assertEqual(self.raw(), before)

    def test_the_stamps_copy_has_no_pairs_and_changing_it_changes_nothing(self):
        copy = self.api._patch_age_stamps()
        self.assertEqual(copy['d1'], {'all_first': T0 - 5 * HOUR, 'sec_first': T0 - 5 * HOUR})
        self.assertIn('_last_run', copy)
        copy['d1']['all_first'] = 1
        copy['d1']['x'] = 2
        self.assertEqual(self.api._patch_age_stamps()['d1'], {'all_first': T0 - 5 * HOUR, 'sec_first': T0 - 5 * HOUR})
        self.assertEqual(self.age()['d1']['done'], [[T0 - 99 * HOUR, T0 - 90 * HOUR, 'all']])


def pairs(*hours_ago_and_len, kind='all', now=None):
    """Rows cleared `ago` hours back that took `hours` hours: pairs((24, 2), (48, 4))."""
    now = int(time.time()) if now is None else now
    return [[now - int(a * HOUR) - int(h * HOUR), now - int(a * HOUR), kind] for a, h in hours_ago_and_len]


class _Route(_Base):

    def plant(self, entries, devices=None, **cfg):
        self.put(devices or {k: host(k) for k in entries}, **cfg)
        self.plant_age(dict(entries, _last_run=int(time.time()), _breaching=[]))

    def mttp(self, token='k', query='', path='/api/patch-report'):
        st, out = self.request(path, token=token, query=query)
        self.assertEqual(st, 200, out)
        self.assertIn('mttp', out)
        return out['mttp']


class TestTheFigures(_Route):

    def setUp(self):
        super().setUp()
        self.plant({
            'web01': {'done': pairs((24, 2), (48, 4)) + pairs((24, 1), (60, 3), kind='sec')},
            'web02': {'done': pairs((30, 6))},
            'web03': {'done': pairs((20, 8))},
            'web04': {'done': pairs((10, 100))},
            'web05': {},
        })

    def test_the_fleet_figure_is_the_hand_computed_one(self):
        m = self.mttp()
        self.assertEqual((m['window_days'], m['min_n']), (30, 5))
        self.assertEqual(m['fleet']['all'], {'n': 5, 'hidden': False, 'mean_h': 24.0, 'median_h': 6.0, 'p90_h': 100.0, 'hosts': 4})

    def test_the_security_class_has_its_own_count_and_is_withheld_below_five(self):
        sec = self.mttp()['fleet']['sec']
        self.assertEqual((sec['n'], sec['hidden'], sec['mean_h'], sec['median_h'], sec['p90_h'], sec['hosts']), (2, True, None, None, None, 1))

    def test_a_host_has_its_own_count_and_the_numbers_only_from_five(self):
        hosts = self.mttp()['hosts']
        self.assertEqual(sorted(hosts), ['web01', 'web02', 'web03', 'web04'], 'a host with no pair is not listed: nothing recorded is not zero')
        self.assertEqual((hosts['web01']['all']['n'], hosts['web01']['all']['hidden'], hosts['web01']['all']['mean_h']), (2, True, None))
        self.assertEqual(hosts['web01']['sec']['n'], 2)
        self.assertEqual(sorted(hosts['web02']), ['all'], 'a class with no pair is not listed either')

    def test_a_host_with_five_pairs_in_the_window_has_its_figure(self):
        self.plant({'web01': {'done': pairs((24, 2), (48, 4), (72, 6), (96, 8), (120, 100))}})
        got = self.mttp()['hosts']['web01']['all']
        self.assertEqual(got, {'n': 5, 'hidden': False, 'mean_h': 24.0, 'median_h': 6.0, 'p90_h': 100.0})

    def test_the_window_is_the_time_the_pair_was_cleared_and_ninety_days_reaches_further(self):
        self.plant({'web01': {'done': pairs((24, 2), (48, 4))},
                    'web02': {'done': pairs((30, 6), (40 * 24, 50))},
                    'web03': {'done': pairs((20, 8))},
                    'web04': {'done': pairs((10, 100))}})
        self.assertEqual(self.mttp(query='mttp_days=30')['fleet']['all']['n'], 5)
        wide = self.mttp(query='mttp_days=90')
        self.assertEqual(wide['window_days'], 90)
        # 2, 4, 6, 50, 8, 100: sorted 2 4 6 8 50 100, mean 170 / 6, the middle two are 6 and 8, rank ceil(5.4) = 6
        self.assertEqual(wide['fleet']['all'], {'n': 6, 'hidden': False, 'mean_h': 28.33, 'median_h': 7.0, 'p90_h': 100.0, 'hosts': 4})

    def test_the_window_asked_for_is_one_of_two_and_anything_else_is_the_first(self):
        for q in ('', 'mttp_days=7', 'mttp_days=0', 'mttp_days=-30', 'mttp_days=abc', 'mttp_days=1e9', 'mttp_days=30.5', 'mttp_days=' + '9' * 5000,
                  'mttp_days=%00', 'mttp_days=30;drop', 'mttp_days=999999999999999999999999', 'mttp_days=365', 'mttp_days=30&mttp_days=90'):
            self.assertEqual(self.mttp(query=q)['window_days'], 30, q)
        self.assertEqual(self.mttp(query='mttp_days=%2090')['window_days'], 90, 'surrounding space is read as the number')
        self.assertEqual(self.mttp(query='mttp_days=90')['window_days'], 90)

    def test_below_five_pairs_in_all_the_fleet_figure_is_withheld_through_the_route(self):
        self.plant({'web01': {'done': pairs((24, 2), (48, 4))}, 'web02': {'done': pairs((30, 6))}, 'web03': {'done': pairs((20, 8))}})
        got = self.mttp()['fleet']['all']
        self.assertEqual((got['n'], got['hidden'], got['mean_h'], got['median_h'], got['p90_h']), (4, True, None, None, None))

    def test_an_empty_store_says_no_pair_at_all(self):
        self.api.save(self.api.PATCH_AGE_FILE, {})
        self.api._LOAD_CACHE.clear()
        m = self.mttp()
        self.assertEqual(m['hosts'], {})
        for k in ('all', 'sec'):
            self.assertEqual((m['fleet'][k]['n'], m['fleet'][k]['hidden'], m['fleet'][k]['mean_h']), (0, True, None))
        self.assertNotIn('tenants', m)

    def test_a_store_from_before_this_change_still_loads_and_the_sweep_adds_the_pairs_to_it(self):
        old = {'web01': {'all_first': T0 - 5 * HOUR, 'sec_first': T0 - 5 * HOUR}, 'web02': {}, '_last_run': 0, '_breaching': ['web01']}
        self.put({'web01': host('web01', 3, 1), 'web02': host('web02')})
        self.plant_age(old)
        m = self.mttp()
        self.assertEqual((m['fleet']['all']['n'], m['hosts']), (0, {}))
        self.put({'web01': host('web01', 0, 0), 'web02': host('web02')})
        self.plant_age(old)
        self.sweep(T0)
        d = self.age()['web01']
        self.assertEqual(d['done'], [[T0 - 5 * HOUR, T0, 'all'], [T0 - 5 * HOUR, T0, 'sec']])
        self.assertEqual(self.age()['_breaching'], [])

    def test_damaged_rows_are_skipped_and_the_good_ones_still_count(self):
        good = pairs((24, 2))
        junk = [['junk'], [1, 2], [1, 2, 'zzz'], 'str', None, [True, 5, 'all'], {'f': 1}, [None, 5, 'all'], ['a', 'b', 'all'], [1e308, 1e308, 'all'], [200, 100, 'all']]
        self.plant({'web01': {'done': junk + good + junk}})
        got = self.mttp()['hosts']['web01']['all']
        self.assertEqual(got['n'], 1)

    def test_a_done_field_that_is_not_a_list_is_read_as_no_pairs(self):
        self.plant({'web01': {'done': 'junk'}, 'web02': {'done': {'a': 1}}, 'web03': 'junk', 'web04': {'done': pairs((24, 2))}},
                   devices={k: host(k) for k in ('web01', 'web02', 'web03', 'web04')})
        m = self.mttp()
        self.assertEqual(sorted(m['hosts']), ['web04'])


class TestWhoReadsWhat(_Route):
    """Two organisations on one installation, and a role scoped to a group."""

    def setUp(self):
        super().setUp()
        self.api.verify_token = lambda token: {'ta': ('alice', 'admin'), 'tb': ('bob', 'admin'), 'op': ('root', 'admin'), 'tv': ('vic', 'viewer'),
                                               'ro': ('rita', 'ro-prod')}.get(token, (None, None))
        self.api._caller_effective_tenant = lambda user: {'alice': 'acme', 'bob': 'globex', 'root': 'default', 'vic': 'acme', 'rita': 'default'}[user]
        self.entries = {
            'a1': {'done': pairs((24, 2), (48, 4))},
            'a2': {'done': pairs((30, 6))},
            'a3': {'done': pairs((20, 8))},
            'a4': {'done': pairs((10, 100))},
            'g1': {'done': pairs((24, 10), (48, 20))},
            'd1': {'done': pairs((12, 30))},
        }
        self.devs = {'a1': host('a1', tenant='acme', group='prod'), 'a2': host('a2', tenant='acme', group='prod'),
                     'a3': host('a3', tenant='acme', group='dev'), 'a4': host('a4', tenant='acme', group='dev'),
                     'g1': host('g1', tenant='globex', group='prod'), 'd1': host('d1', group='prod')}

    def enforce(self, on=True):
        self.plant(self.entries, devices=self.devs, tenancy_enforced=on)
        self.api.save(self.api.ROLES_FILE, {'roles': [{'name': 'ro-prod', 'permissions': [], 'scope': {'type': 'groups', 'values': ['prod']}}]})
        self.api._LOAD_CACHE.clear()

    def test_a_tenant_administrator_reads_its_own_hosts_and_no_others(self):
        self.enforce()
        m = self.mttp('ta')
        self.assertEqual(sorted(m['hosts']), ['a1', 'a2', 'a3', 'a4'])
        self.assertEqual(m['fleet']['all'], {'n': 5, 'hidden': False, 'mean_h': 24.0, 'median_h': 6.0, 'p90_h': 100.0, 'hosts': 4})
        self.assertNotIn('tenants', m, 'the split per tenant is for the operator')
        text = json.dumps(m)
        for other in ('g1', 'd1', 'globex'):
            self.assertNotIn(other, text)
        m = self.mttp('tb')
        self.assertEqual(sorted(m['hosts']), ['g1'])
        self.assertEqual((m['fleet']['all']['n'], m['fleet']['all']['hidden']), (2, True))
        self.assertNotIn('a1', json.dumps(m))

    def test_a_read_only_user_of_a_tenant_reads_that_tenant(self):
        self.enforce()
        m = self.mttp('tv')
        self.assertEqual(sorted(m['hosts']), ['a1', 'a2', 'a3', 'a4'])
        self.assertNotIn('tenants', m)

    def test_the_operator_reads_every_host_and_the_figure_per_tenant(self):
        self.enforce()
        m = self.mttp('op')
        self.assertEqual(sorted(m['hosts']), ['a1', 'a2', 'a3', 'a4', 'd1', 'g1'])
        # 2 4 6 8 10 20 30 100: mean 180 / 8, the middle two are 8 and 10, rank ceil(7.2) = 8
        self.assertEqual(m['fleet']['all'], {'n': 8, 'hidden': False, 'mean_h': 22.5, 'median_h': 9.0, 'p90_h': 100.0, 'hosts': 6})
        self.assertEqual(sorted(m['tenants']), ['acme', 'default', 'globex'])
        self.assertEqual(m['tenants']['acme']['all'], {'n': 5, 'hidden': False, 'mean_h': 24.0, 'median_h': 6.0, 'p90_h': 100.0, 'hosts': 4})
        self.assertEqual((m['tenants']['globex']['all']['n'], m['tenants']['globex']['all']['hidden']), (2, True))
        self.assertEqual((m['tenants']['default']['all']['n'], m['tenants']['default']['all']['hidden']), (1, True))

    def test_without_isolation_nobody_gets_a_split_and_everyone_reads_the_fleet(self):
        self.enforce(on=False)
        m = self.mttp('op')
        self.assertNotIn('tenants', m)
        self.assertEqual(len(m['hosts']), 6)

    def test_a_scoped_role_reads_only_the_hosts_in_its_scope(self):
        self.enforce(on=False)
        m = self.mttp('ro')
        self.assertEqual(sorted(m['hosts']), ['a1', 'a2', 'd1', 'g1'], 'the prod group: a1, a2, g1 and d1')
        self.assertEqual(m['fleet']['all']['n'], 2 + 1 + 2 + 1)
        self.assertNotIn('a3', json.dumps(m))
        self.assertNotIn('a4', json.dumps(m))
        self.assertNotIn('tenants', m)

    def test_a_scoped_role_in_an_isolated_install_reads_the_overlap_of_both(self):
        self.enforce()
        m = self.mttp('ro')
        self.assertEqual(sorted(m['hosts']), ['d1'], 'the default tenant and the prod group: only d1')

    def test_a_caller_with_no_token_reads_nothing(self):
        self.enforce()
        st, out = self.request('/api/patch-report', token='nobody')
        self.assertEqual(st, 401, out)
        self.assertNotIn('mttp', out or {})


if __name__ == '__main__':
    unittest.main()
