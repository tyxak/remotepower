#!/usr/bin/env python3
"""A failed read of the host store is not an empty fleet: the sweeps that drop what they hold for hosts the host store does not list.

`load()` answers an empty dict when devices.json cannot be read (a file that does not parse and has no usable backup, a read error such as EMFILE or EIO, a dropped
connection to the database), and that is also what an installation with no hosts reads as. Four sweeps keep a store with an entry per host and drop the entries of hosts that
are not in the host store they just read, so one failed read, at the moment one of them ran, took the history of the whole fleet:

  * the health history (a daily score for each host, 180 days),
  * the metric roll-ups (hourly and daily aggregates, kept about two years),
  * the thermal roll-ups (the same for the hottest temperature and the sensors),
  * the dependency edges (what was observed on each declared edge, which the alert for a silent edge reads).

The patch aging sweep had the same defect (tests/test_patch_age_split.py). All five leave what they hold for the next pass when the host store reads as empty while their
own store names hosts (`_fleet_read_failed`), and still drop the entry of a host that is gone when the read was good. Held here, for each of the four, by driving the real sweep:

  * with a good read, the entry of a host that is not in the host store is dropped and the others stay (the control that shows the prune still works);
  * with an empty read, nothing is dropped, and the sweep still moves its own due stamp;
  * an installation with no hosts and a store that names none is swept as before;
  * the helper itself, and the host purge rule for the metric roll-ups (until now only the sweep's prune removed them, which the guard would have left in place for the last host);
  * the population: every function of the server that reads the host store, tests membership in it and removes entries, other than a request handler, is guarded or is listed
    with the reason it need not be. A new sweep of that shape fails here until it is one or the other.
"""
import ast
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-readfailed-'))
_TESTS = Path(__file__).resolve().parent
_CGI = _TESTS.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_CGI))

from test_mean_time_to_patch import T0, _Base, host  # noqa: E402

HOSTS = ['h0', 'h1', 'h2', 'h3']


class _Fleet(_Base):
    """Four hosts in the host store, and a store of the sweep under test that has an entry for each of them."""

    def setUp(self):
        super().setUp()
        self.put({n: host(n, 0, 0, group='prod') for n in HOSTS})
        self.api.time.time = lambda: T0

    def empty_read(self):
        """What load() answers when devices.json cannot be read: an empty dict, for every reader of the store (the shared one and the copying one)."""
        real = self.api._load_uncached
        self.api._load_uncached = lambda path: ({} if Path(path).name == 'devices.json' else real(path))
        self.addCleanup(setattr, self.api, '_load_uncached', real)
        self._real_load = real
        self.api._LOAD_CACHE.clear()

    def good_read(self):
        """The read works again."""
        self.api._load_uncached = self._real_load
        self.api._LOAD_CACHE.clear()

    def without_a_host(self, gone='h3'):
        """A good read of a host store that no longer lists one host."""
        self.put({n: host(n, 0, 0, group='prod') for n in HOSTS if n != gone})

    def stored(self, path):
        self.api._LOAD_CACHE.clear()
        return self.api.load(path)

    def names(self, path, inner=None):
        store = self.stored(path)
        store = store.get(inner) or {} if inner else store
        return sorted(k for k in store if not k.startswith('_'))


class TestTheHealthHistory(_Fleet):

    def setUp(self):
        super().setUp()
        series = [{'date': '2026-01-01', 'ts': 1, 'score': 90}]
        self.api.save(self.api.HEALTH_HIST_FILE, {'fleet': [{'date': '2026-01-01', 'ts': 1, 'score': 90, 'grade': 'A'}], 'devices': {n: list(series) for n in HOSTS}})
        self.api._LOAD_CACHE.clear()

    def sweep(self):
        self.api._LOAD_CACHE.clear()
        self.api._maybe_sample_health(now=T0)

    def test_a_good_read_drops_the_series_of_a_host_that_is_gone(self):
        self.without_a_host('h3')
        self.sweep()
        self.assertEqual(self.names(self.api.HEALTH_HIST_FILE, 'devices'), ['h0', 'h1', 'h2'], 'control: the prune still works')

    def test_an_empty_read_drops_nothing_records_no_day_and_the_next_good_read_records_it(self):
        """An empty fleet scores 100: the day would have gone into the series as a perfect one, and the daily gate would have closed on it."""
        self.empty_read()
        self.sweep()
        got = self.stored(self.api.HEALTH_HIST_FILE)
        self.assertEqual(sorted(got['devices']), HOSTS, 'the history of every host is still there')
        self.assertTrue(all(len(s) == 1 for s in got['devices'].values()), 'and no point was added to it')
        self.assertEqual([f['date'] for f in got['fleet']], ['2026-01-01'], 'no perfect score was recorded for a fleet nobody could read')
        self.good_read()
        self.sweep()
        got = self.stored(self.api.HEALTH_HIST_FILE)
        self.assertEqual(len(got['fleet']), 2, 'the day was not given up: the next request that reads the hosts records it')
        self.assertEqual(sorted(got['devices']), HOSTS)
        self.assertTrue(all(len(s) == 2 for s in got['devices'].values()))

    def test_an_installation_with_no_hosts_and_no_history_is_sampled_as_before(self):
        self.put({})
        self.api.save(self.api.HEALTH_HIST_FILE, {})
        self.sweep()
        self.assertEqual(self.names(self.api.HEALTH_HIST_FILE, 'devices'), [])
        self.assertEqual(len(self.stored(self.api.HEALTH_HIST_FILE)['fleet']), 1)


class TestTheMetricRollups(_Fleet):

    def setUp(self):
        super().setUp()
        row = {'last_ts': 5, 'fivemin': [], 'hourly': [], 'daily': []}
        self.api.save(self.api.METRICS_ROLLUP_FILE, dict({n: dict(row) for n in HOSTS}, _meta={'last_run': 0}))
        self.api._LOAD_CACHE.clear()

    def sweep(self):
        self.api._LOAD_CACHE.clear()
        self.api.run_metric_rollup_if_due()

    def test_a_good_read_drops_the_rollups_of_a_host_that_is_gone(self):
        self.without_a_host('h3')
        self.sweep()
        self.assertEqual(self.names(self.api.METRICS_ROLLUP_FILE), ['h0', 'h1', 'h2'], 'control: the prune still works')

    def test_an_empty_read_drops_nothing_and_moves_the_due_stamp(self):
        self.empty_read()
        self.sweep()
        self.assertEqual(self.names(self.api.METRICS_ROLLUP_FILE), HOSTS)
        self.assertEqual(self.stored(self.api.METRICS_ROLLUP_FILE)['_meta'], {'last_run': T0}, 'the next try is an interval away, not on the next request')

    def test_an_installation_with_no_hosts_and_no_rollups_is_swept_as_before(self):
        self.put({})
        self.api.save(self.api.METRICS_ROLLUP_FILE, {'_meta': {'last_run': 0}})
        self.sweep()
        self.assertEqual(self.stored(self.api.METRICS_ROLLUP_FILE), {'_meta': {'last_run': T0}})


class TestTheThermalRollups(_Fleet):

    def setUp(self):
        super().setUp()
        row = {'last_ts': 5, 'fivemin': [], 'hourly': [], 'daily': []}
        self.api.save(self.api.THERMAL_ROLLUP_FILE, dict({n: dict(row) for n in HOSTS}, _meta={'last_run': 0}))
        self.api._LOAD_CACHE.clear()

    def sweep(self):
        self.api._LOAD_CACHE.clear()
        self.api.run_thermal_rollup_if_due()

    def test_a_good_read_drops_the_rollups_of_a_host_that_is_gone(self):
        self.without_a_host('h3')
        self.sweep()
        self.assertEqual(self.names(self.api.THERMAL_ROLLUP_FILE), ['h0', 'h1', 'h2'], 'control: the prune still works')

    def test_an_empty_read_drops_nothing_and_moves_the_due_stamp(self):
        self.empty_read()
        self.sweep()
        self.assertEqual(self.names(self.api.THERMAL_ROLLUP_FILE), HOSTS)
        self.assertEqual(self.stored(self.api.THERMAL_ROLLUP_FILE)['_meta'], {'last_run': T0})

    def test_an_installation_with_no_hosts_and_no_rollups_is_swept_as_before(self):
        self.put({})
        self.api.save(self.api.THERMAL_ROLLUP_FILE, {'_meta': {'last_run': 0}})
        self.sweep()
        self.assertEqual(self.stored(self.api.THERMAL_ROLLUP_FILE), {'_meta': {'last_run': T0}})


class TestTheDependencyEdges(_Fleet):

    EDGES = {'h0:h1': {'ever_observed': True, 'last_observed': 5, 'alerted': True}, 'h2:h3': {'ever_observed': True, 'last_observed': 5, 'alerted': False}}

    def setUp(self):
        super().setUp()
        devices = {n: host(n, 0, 0, group='prod') for n in HOSTS}
        devices['h0']['depends_on'] = ['h1']              # h0 -> h1 is declared; h2 -> h3 is not (any more)
        self.api.save(self.api.DEVICES_FILE, devices)
        self.api.save(self.api.FLOW_DEPS_FILE, {'last_run': 0, 'edges': json.loads(json.dumps(self.EDGES))})
        self.api._LOAD_CACHE.clear()

    def sweep(self):
        self.api._LOAD_CACHE.clear()
        self.api.run_flow_dep_check_if_due()

    def edges(self):
        return sorted(self.stored(self.api.FLOW_DEPS_FILE).get('edges') or {})

    def test_a_good_read_drops_the_state_of_an_edge_that_is_not_declared(self):
        self.sweep()
        self.assertEqual(self.edges(), ['h0:h1'], 'control: the prune still works')

    def test_an_empty_read_drops_nothing_and_moves_the_due_stamp(self):
        self.empty_read()
        self.sweep()
        self.assertEqual(self.edges(), ['h0:h1', 'h2:h3'])
        self.assertTrue(self.stored(self.api.FLOW_DEPS_FILE)['edges']['h0:h1']['alerted'], 'and the alert that was open on the edge is still marked open')
        self.assertEqual(self.stored(self.api.FLOW_DEPS_FILE)['last_run'], T0)

    def test_an_installation_with_no_hosts_and_no_edges_is_swept_as_before(self):
        self.put({})
        self.api.save(self.api.FLOW_DEPS_FILE, {'last_run': 0, 'edges': {}})
        self.sweep()
        self.assertEqual(self.stored(self.api.FLOW_DEPS_FILE)['last_run'], T0)


class TestTheHelper(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from test_ip_intel import _fresh_api
        cls.api = _fresh_api()

    def failed(self, devices, stored):
        return self.api._fleet_read_failed(devices, stored, 'the test store')

    def test_empty_devices_and_a_store_that_names_hosts_is_a_failed_read(self):
        self.assertTrue(self.failed({}, {'h1': {}}))
        self.assertTrue(self.failed({}, {'_meta': {'last_run': 1}, 'h1': []}))
        self.assertTrue(self.failed(set(), {'h1:h2': {}}))

    def test_anything_else_is_not(self):
        self.assertFalse(self.failed({'h1': {}}, {'h1': {}}), 'a fleet that reads back')
        self.assertFalse(self.failed({'h1': {}}, {'h9': {}}), 'a good read that lacks the host the store names is the case the prune is for')
        self.assertFalse(self.failed({}, {}), 'no hosts and nothing stored')
        self.assertFalse(self.failed({}, None))
        self.assertFalse(self.failed({}, {'_meta': {'last_run': 1}, '_x': 1}), 'meta keys are not hosts')

    def test_it_says_so_in_the_server_log_and_only_then(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.failed({}, {'h1': {}})
            quiet = buf.getvalue()
            buf.truncate(0)
            buf.seek(0)
            self.failed({'h1': {}}, {'h1': {}})
        self.assertIn('devices.json reads as empty yet entries for hosts exist in the test store', quiet)
        self.assertEqual(buf.getvalue(), '')


class TestDeletingAHostTakesItsMetricRollups(_Fleet):

    def test_the_purge_pops_the_row_of_the_host_and_no_other(self):
        row = {'last_ts': 5, 'fivemin': [], 'hourly': [], 'daily': []}
        self.api.save(self.api.METRICS_ROLLUP_FILE, dict({n: dict(row) for n in HOSTS}, _meta={'last_run': T0}))
        self.api._LOAD_CACHE.clear()
        self.assertTrue(self.api._purge_device('h1'))
        self.assertEqual(self.names(self.api.METRICS_ROLLUP_FILE), ['h0', 'h2', 'h3'])
        self.assertEqual(self.stored(self.api.METRICS_ROLLUP_FILE)['_meta'], {'last_run': T0}, 'and the due stamp is left')


# --- the population ---------------------------------------------------------------------------------------------------------------------------------------------

def _loads_devices(node):
    """A call that reads the host store by its constant: load(DEVICES_FILE), _load_ro(DEVICES_FILE), A.load(A.DEVICES_FILE), also inside set(...) or `or {}`."""
    for c in ast.walk(node):
        if isinstance(c, ast.Call) and c.args:
            f = c.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else '')
            a = c.args[0]
            if name in ('load', '_load_ro') and ((isinstance(a, ast.Name) and a.id == 'DEVICES_FILE') or (isinstance(a, ast.Attribute) and a.attr == 'DEVICES_FILE')):
                return True
    return False


def prune_sites(src):
    """Names of the functions that are not request handlers and that read the host store into a name, test membership in that name and remove an entry of some store
    under a lock or a save: the shape of a sweep that drops what it holds for hosts the host store does not list."""
    found = []
    for fn in ast.walk(ast.parse(src)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name.startswith('handle_'):
            continue
        names = {t.id for n in ast.walk(fn) if isinstance(n, ast.Assign) and _loads_devices(n.value) for t in n.targets if isinstance(t, ast.Name)}
        if not names:
            continue
        tests = [n for n in ast.walk(fn) if isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], (ast.In, ast.NotIn))
                 and isinstance(n.comparators[0], ast.Name) and n.comparators[0].id in names]
        removes = any((isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ('pop', 'clear')) or isinstance(n, ast.Delete) for n in ast.walk(fn))
        text = ast.get_source_segment(src, fn) or ''
        if tests and removes and ('_LockedUpdate(' in text or 'save(' in text):
            found.append((fn.name, '_fleet_read_failed(' in text))
    return found


# A function of that shape that need not be guarded, and why. None is listed today: the four sweeps are the whole population. Anything not listed must call `_fleet_read_failed`.
NOT_A_PRUNE_BY_THE_FLEET: dict = {}


class TestEverySweepOfThatShapeIsGuarded(unittest.TestCase):

    def sites(self):
        out = {}
        for path in [_CGI / 'api.py'] + sorted(_CGI.glob('*_handlers.py')):
            for name, guarded in prune_sites(path.read_text(encoding='utf-8')):
                out[name] = (path.name, guarded)
        return out

    def test_the_scan_sees_a_site_of_that_shape_and_not_one_of_another(self):
        """The control of the test below: the same scan, over two small functions, finds the one that prunes and not the one that only looks a host up."""
        src = ('def sweep():\n    devices = load(DEVICES_FILE) or {}\n    with _LockedUpdate(STORE) as s:\n        for k in [k for k in s if k not in devices]:\n            del s[k]\n'
               'def lookup(dev_id):\n    devices = load(DEVICES_FILE) or {}\n    if dev_id not in devices:\n        return None\n    save(OTHER, {})\n'
               'def handle_x():\n    devices = load(DEVICES_FILE)\n    with _LockedUpdate(S) as s:\n        s.pop(1) if 1 in devices else 0\n')
        self.assertEqual(prune_sites(src), [('sweep', False)])

    def test_the_known_sweeps_are_in_the_population(self):
        found = self.sites()
        for name in ('_maybe_sample_health', 'run_metric_rollup_if_due', 'run_thermal_rollup_if_due', 'run_flow_dep_check_if_due'):
            self.assertIn(name, found, f'{name} is a sweep of that shape: the scan has gone blind to it')

    def test_each_one_is_guarded_or_listed_with_a_reason(self):
        found = self.sites()
        for name, (where, guarded) in sorted(found.items()):
            if name in NOT_A_PRUNE_BY_THE_FLEET:
                continue
            self.assertTrue(guarded, f'{where}: {name} drops entries of hosts the host store does not list, and does not ask whether an empty read is a failed one '
                                     f'(api._fleet_read_failed), or it is not that and belongs in NOT_A_PRUNE_BY_THE_FLEET with the reason')

    def test_every_listed_exception_still_has_the_shape_and_a_reason(self):
        found = self.sites()
        self.assertEqual(sorted(set(NOT_A_PRUNE_BY_THE_FLEET) - set(found)), [], 'listed, and no longer of that shape: take it off the list')
        for name, why in NOT_A_PRUNE_BY_THE_FLEET.items():
            self.assertGreater(len(why), 30, name)


if __name__ == '__main__':
    unittest.main()
