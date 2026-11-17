#!/usr/bin/env python3
"""The aging store is read on every request, so it must not carry the history; and a failed read of the device store is not an empty fleet.

The completed pairs of the mean time to patch were first filed in the aging store (patch_age.json) beside the first-seen stamps. The sweep runs from `main()` on every request
and reads that store to see whether it is due, and a request starts with a cold cache, so every request, the Patch SLA page, the compliance report, the risk score and the fleet
report parsed up to 200 pairs for every host: 28 ms against 3 ms on 300 hosts with 60 pairs each, 292 ms against 9 ms on 1,000 hosts with 200. The pairs have a store of their own
now (patch_done.json), which only the sweep that files a pair and the Patches page read. Held here:

  * a request through `main()` never reads the pairs store, and the Patches page does (the control that shows the instrument can see it);
  * each of the four read-only evaluators of the SLA (the SLA page, the compliance facts, the fleet risk and the fleet report) reaches the evaluation, is handed an aging store
    with no pair in it, and never reads the pairs store: a copy of the whole history for a figure that does not use it is what the review measured;
  * the aging store stays the size of its stamps however many pairs are filed, which also catches the two stores being put back into one file;
  * the not-due path reads the aging store and nothing else, takes no lock and writes nothing;
  * a read of devices.json that fails answers an empty dict, the same as an installation with no hosts. A sweep that took it for the second one pruned the stamps and announced
    every host in breach as back in line, and (with the pairs in the pruned store) deleted up to 400 days of history. The sweep leaves everything as it was, moves only its due stamp,
    and an empty fleet with nothing stored is still swept;
  * the registry knows the new store: a row that is not a map, a `done` that is not a list and a pair that is not a list are repaired the way the other stores are.
"""
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-agesplit-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import store_shapes  # noqa: E402
from test_mean_time_to_patch import DAY, HOUR, T0, _Base, host  # noqa: E402

JSON_BACKEND = (os.environ.get('RP_STORAGE_BACKEND') or 'json') == 'json'
HISTORY = 200                       # pairs a host: the most the ring holds


def history(now, n=HISTORY):
    """n completed pairs for one host, the latest cleared a day before `now`."""
    return [[now - DAY - (n - k) * 7200 - 3600, now - DAY - (n - k) * 7200, 'all' if k % 2 else 'sec'] for k in range(n)]


class _Fleet(_Base):
    """Forty hosts with updates waiting, a patch SLA rule so every evaluator reaches the evaluation, a due stamp from a moment ago and a long history for each host."""

    N = 40

    def setUp(self):
        super().setUp()
        now = int(time.time())
        self.names = [f'h{i:03d}' for i in range(self.N)]
        self.put({n: host(n, 3, 1, group='prod') for n in self.names}, patch_sla=[{'match_type': 'all', 'sec_days': 7, 'all_days': 30}])
        self.plant_age({**{n: {'all_first': now - 2 * DAY, 'sec_first': now - 2 * DAY} for n in self.names}, '_last_run': now, '_breaching': []})
        self.plant_done({n: {'done': history(now)} for n in self.names})

    def watch(self):
        """Every store `_load_uncached` reads from now on, by file name: the one place any read of a store goes through (JSON, SQLite and Postgres)."""
        seen = []
        real = self.api._load_uncached

        def spy(path):
            seen.append(Path(path).name)
            return real(path)
        self.api._load_uncached = spy
        self.addCleanup(setattr, self.api, '_load_uncached', real)
        return seen


class TestARequestNeverReadsTheHistory(_Fleet):

    def test_an_ordinary_request_through_main_reads_the_aging_store_and_not_the_pairs(self):
        seen = self.watch()
        st, out = self.request('/api/me')
        self.assertEqual(st, 200, out)
        self.assertIn('patch_age.json', seen, 'control: the due check of the sweep read the aging store, so the instrument sees what a request reads')
        self.assertNotIn('patch_done.json', seen)

    def test_the_patches_page_does_read_them(self):
        """The control of the test above: the same instrument reports the pairs store when something does read it."""
        seen = self.watch()
        st, out = self.request('/api/patch-report')
        self.assertEqual(st, 200, out)
        self.assertIn('patch_done.json', seen)
        self.assertGreater(out['mttp']['fleet']['all']['n'], 0, 'and it computed from them')

    def test_the_aging_store_is_the_size_of_its_stamps_and_the_pairs_are_the_size_of_the_history(self):
        sizes = {p: len(json.dumps(self.api.load(f), sort_keys=True)) for p, f in (('age', self.api.PATCH_AGE_FILE), ('done', self.api.PATCH_DONE_FILE))}
        self.assertLess(sizes['age'] * 20, sizes['done'], sizes)


class TestTheReadOnlyEvaluatorsNeverReadTheHistory(_Fleet):

    def evaluators(self):
        api = self.api
        return {
            'the Patch SLA page': lambda: self.call(api.handle_patch_sla),
            'the compliance facts': lambda: api._compliance_facts(api.load(api.DEVICES_FILE)),
            'the fleet risk': lambda: api._compute_fleet_risk(),
            'the fleet report': lambda: api._build_fleet_report(),
        }

    def test_each_one_is_given_the_aging_store_without_a_pair_and_reads_no_pair(self):
        api = self.api
        runs = self.evaluators()
        self.assertEqual(len(runs), 4, 'the four callers of _eval_patch_sla that only read')
        real_eval = api._eval_patch_sla
        handed = []

        def spy(devices, cfg, age, now, *a, **k):
            handed.append(json.loads(json.dumps(age, default=str)))
            return real_eval(devices, cfg, age, now, *a, **k)
        api._eval_patch_sla = spy
        self.addCleanup(setattr, api, '_eval_patch_sla', real_eval)
        for name, run in runs.items():
            with self.subTest(name):
                api._LOAD_CACHE.clear()
                seen = self.watch()
                del handed[:]
                run()
                self.assertTrue(handed, f'{name} never reached the evaluation, so this proves nothing about it')
                self.assertNotIn('patch_done.json', seen, f'{name} read the completed pairs: a cold parse of the whole history for a figure that does not use it')
                self.assertIn('patch_age.json', seen, f'control: {name} read the aging store')
                for age in handed:
                    stamps = {k: v for k, v in age.items() if not k.startswith('_')}
                    self.assertEqual(len(stamps), self.N, 'control: the evaluator was handed the stamps of every host')
                    self.assertEqual([k for k, v in stamps.items() if 'done' in v], [], f'{name} was handed pairs')

    def test_the_evaluators_leave_both_stores_as_they_were(self):
        before = json.dumps([self.age(), self.done()], sort_keys=True)
        for name, run in self.evaluators().items():
            with self.subTest(name):
                run()
        self.assertEqual(json.dumps([self.age(), self.done()], sort_keys=True), before)


class TestTheDueCheck(_Fleet):

    def test_not_due_reads_the_aging_store_and_nothing_else_and_writes_nothing(self):
        api = self.api
        now = int(time.time())
        api.time.time = lambda: now                                  # restored by the base class
        api._LOAD_CACHE.clear()
        seen = self.watch()
        locks, saves = [], []
        real_lock, real_save = api._LockedUpdate, api.save
        api._LockedUpdate = lambda path, non_blocking=False: (locks.append(Path(path).name), real_lock(path, non_blocking))[1]
        api.save = lambda path, *a, **k: (saves.append(Path(path).name), real_save(path, *a, **k))[1]
        self.addCleanup(setattr, api, '_LockedUpdate', real_lock)
        self.addCleanup(setattr, api, 'save', real_save)
        api.run_patch_sla_if_due()
        self.assertEqual(seen, ['patch_age.json'], 'the due check is one read of the one small store')
        self.assertEqual((locks, saves), ([], []))

    def test_a_sweep_that_is_due_and_clears_nothing_does_not_touch_the_pairs(self):
        api = self.api
        seen = self.watch()
        locks = []
        real_lock = api._LockedUpdate
        api._LockedUpdate = lambda path, non_blocking=False: (locks.append(Path(path).name), real_lock(path, non_blocking))[1]
        self.addCleanup(setattr, api, '_LockedUpdate', real_lock)
        self.sweep(int(time.time()) + 2 * HOUR)                      # the hosts still have updates waiting
        self.assertEqual(locks, ['patch_age.json'])
        self.assertNotIn('patch_done.json', seen)


class TestTheStampsStayTheSizeOfTheStamps(_Fleet):

    N = 6

    def test_a_year_of_sweeps_files_pairs_and_the_aging_store_gains_nothing(self):
        self.plant_age({'_last_run': 0, '_breaching': []})
        self.plant_done({})
        cycles = 60
        sizes = []
        for c in range(cycles):
            self.put({n: host(n, 4, 2, group='prod') for n in self.names})
            self.sweep(T0 + (2 * c) * 6 * HOUR)
            self.put({n: host(n, 0, 0, group='prod') for n in self.names})
            self.sweep(T0 + (2 * c + 1) * 6 * HOUR)
            sizes.append(len(json.dumps(self.api.load(self.api.PATCH_AGE_FILE), sort_keys=True)))
        filed = sum(len((e or {}).get('done') or []) for e in self.done().values())
        self.assertEqual(filed, cycles * self.N * 2, 'control: every cycle filed an all and a sec pair for every host, so the history really grew')
        self.assertEqual(sizes[-1], sizes[0], 'the aging store is no bigger after %d cycles than after the first' % cycles)
        keys = {k for v in self.age().values() if isinstance(v, dict) for k in v}
        self.assertLessEqual(keys, {'all_first', 'sec_first'}, 'a host entry of the aging store holds the two stamps and nothing else')


class TestAFailedReadOfTheDeviceStoreIsNotAnEmptyFleet(_Base):

    N = 5

    def setUp(self):
        super().setUp()
        self.names = [f'h{i}' for i in range(self.N)]
        self.put({n: host(n, 0, 0) for n in self.names}, patch_sla=[{'match_type': 'all', 'sec_days': 1}])
        self.plant_age({**{n: ({'all_first': T0 - 5 * HOUR} if n == 'h2' else {}) for n in self.names}, '_last_run': T0 - 2 * HOUR, '_breaching': ['h1']})
        self.plant_done({n: {'done': history(T0 - 30 * DAY, 40)} for n in self.names})
        self.before = json.dumps([self.age(), self.done()], sort_keys=True)

    def pairs_per_host(self):
        return {n: len((e or {}).get('done') or []) for n, e in self.done().items()}

    def assert_left_alone(self):
        age = self.age()
        self.assertEqual(sorted(k for k in age if not k.startswith('_')), sorted(self.names), 'the stamps of every host are still there')
        self.assertEqual(age['h2'], {'all_first': T0 - 5 * HOUR})
        self.assertEqual(age['_breaching'], ['h1'], 'nobody was announced back in line')
        self.assertEqual(self.pairs_per_host(), dict.fromkeys(self.names, 40), 'and the history is whole')
        self.assertEqual(self.fired, [])
        self.assertEqual(age['_last_run'], T0, 'only the due stamp moved: the next try is an hour away, not on the next request')

    def test_control_with_a_readable_device_store_the_sweep_works(self):
        self.sweep(T0)
        age = self.age()
        self.assertEqual(age['_breaching'], [], 'h1 is clean now')
        self.assertEqual([e for e, _ in self.fired], ['patch_sla_ok'], 'and was announced as back in line: the instrument sees an announcement when there is one')
        self.assertNotIn('all_first', age['h2'], 'h2 has nothing waiting, so its stamp went and its pair was filed')
        self.assertEqual(self.pairs_per_host()['h2'], 40 + 1)

    def test_an_empty_read_changes_nothing(self):
        real = self.api._load_uncached
        self.api._load_uncached = lambda path: ({} if Path(path).name == 'devices.json' else real(path))      # what load() answers when a read fails
        self.addCleanup(setattr, self.api, '_load_uncached', real)
        self.sweep(T0)
        self.assert_left_alone()

    @unittest.skipUnless(JSON_BACKEND, 'a file that cannot be parsed is the JSON backend\'s')
    def test_a_device_file_that_cannot_be_parsed_and_has_no_backup_changes_nothing(self):
        dev = self.api.DEVICES_FILE
        dev.write_text('{ this is not json')
        bak = self.api._backup_path(dev)
        if bak.exists():
            bak.unlink()
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.api.load(dev), {}, 'control: that file reads as an empty dict')
        self.sweep(T0)
        self.assert_left_alone()

    @unittest.skipUnless(JSON_BACKEND, 'a read error of the file is the JSON backend\'s')
    def test_one_failed_read_of_an_intact_file_changes_nothing(self):
        real_read = pathlib.Path.read_text

        def flaky(path, *a, **k):
            if path.name == 'devices.json':
                raise OSError(24, 'Too many open files')
            return real_read(path, *a, **k)
        pathlib.Path.read_text = flaky
        try:
            self.api._LOAD_CACHE.clear()
            self.assertEqual(self.api.load(self.api.DEVICES_FILE), {}, 'control: one failed read answers an empty dict, with a good file and a good backup beside it')
            self.sweep(T0)
        finally:
            pathlib.Path.read_text = real_read
        self.assert_left_alone()

    def test_an_installation_with_no_hosts_and_nothing_stored_is_still_swept(self):
        self.put({})
        self.plant_age({'_last_run': 0, '_breaching': []})
        self.plant_done({})
        self.sweep(T0)
        self.assertEqual(self.age(), {'_last_run': T0, '_breaching': []})

    def test_a_fleet_that_is_there_but_lost_a_host_has_the_stamps_of_that_host_dropped(self):
        self.put({n: host(n, 0, 0) for n in self.names if n != 'h3'}, patch_sla=[{'match_type': 'all', 'sec_days': 1}])
        self.sweep(T0)
        self.assertNotIn('h3', self.age(), 'the housekeeping still happens when the read was good')
        self.assertEqual(self.pairs_per_host()['h3'], 40, 'and the sweep never touches a host\'s history')

    def test_what_names_a_host_in_the_aging_store(self):
        f = self.api._patch_age_lists_hosts
        self.assertFalse(f({}))
        self.assertFalse(f({'_last_run': 5, '_breaching': []}))
        self.assertTrue(f({'_last_run': 5, 'h1': {}}))
        self.assertTrue(f({'_last_run': 5, '_breaching': ['h1']}))
        self.assertTrue(f({'h1': {'all_first': 1}}))


class TestThePairsStoreHasItsShape(unittest.TestCase):

    def norm(self, data):
        return store_shapes.normalize('patch_done.json', data)

    def test_the_registry_has_it_and_the_aging_store_no_longer_lists_the_pairs(self):
        self.assertIn('patch_done.json', store_shapes.SHAPES)
        entry = store_shapes.normalize('patch_age.json', {'h1': {'all_first': 5, 'done': 'whatever'}})
        self.assertEqual(entry['h1']['all_first'], 5)

    def test_a_good_store_is_returned_as_it_is(self):
        good = {'h1': {'done': [[1, 2, 'all'], [3, 4, 'sec']]}, 'h2': {}}
        self.assertEqual(self.norm(json.loads(json.dumps(good))), good)

    def test_a_row_that_is_not_a_map_is_left_out_and_a_done_that_is_not_a_list_is_removed(self):
        got = self.norm({'h1': 'junk', 'h2': {'done': 'junk'}, 'h3': {'done': {'a': 1}}, 'h4': 7, 'h5': {'done': [[1, 2, 'all']]}})
        self.assertEqual(sorted(got), ['h2', 'h3', 'h5'])
        self.assertEqual(got['h5'], {'done': [[1, 2, 'all']]})
        self.assertEqual((got['h2'], got['h3']), ({'done': []}, {'done': []}), 'a container of the wrong kind is an empty one of the right kind')

    def test_a_pair_that_is_not_a_list_is_left_out(self):
        got = self.norm({'h1': {'done': [[1, 2, 'all'], 'junk', None, 5, {'a': 1}, [3, 4, 'sec']]}})
        self.assertEqual(got['h1']['done'], [[1, 2, 'all'], [3, 4, 'sec']])


if __name__ == '__main__':
    unittest.main()
