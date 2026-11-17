#!/usr/bin/env python3
"""No store a host writes is read and saved with no lock held across the pair.

The violations store of the software policy was written bare by a function that a locked handler called (tests/
test_software_violations_lock.py), and the rule it broke is one the code applies in most places: a function that reads a store
every host writes, changes one host's part of it and saves the whole document loses a write whenever two hosts reach it
together. The window of the brute-force detector was the second case of the class on a host's path.

Two halves:

  * the brute-force detector, driven from threads with the real storage: every host keeps its window and each crossing of the
    threshold is told once;
  * a ratchet over the class. A host-authenticated handler is found from the code (it calls `_device_token_ok`), the functions it
    reaches are found by name, and any of them that reads and saves a store without holding its lock fails the build unless it
    is listed below with the reason. The list holds what is left of the class today and can only shrink.
"""
import ast
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


os.environ.setdefault('RP_DATA_DIR', _tmp('rp-hostlock-'))
_spec = importlib.util.spec_from_file_location('api_host_written_locks', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


# ── the brute-force detector under concurrent hosts ──────────────────────────────────────────────────────────────────────
def _lines(attacker, n=5):
    return [f'Failed password for root from {attacker} port 4{i} ssh2' for i in range(n)]


class TestBruteForceWindows(unittest.TestCase):
    N = 12

    def setUp(self):
        self.hosts = [f'sbfhost{i}' for i in range(self.N)]
        self.attacker = {h: f'185.220.101.{i + 1}' for i, h in enumerate(self.hosts)}
        self.told = []             # (device_id, source, whether a lock was held at the call)
        self.intel = []            # whether a lock was held when the Threat Intel queue was written
        self._mutex = threading.Lock()
        real_fire = api.fire_webhook

        def recording(event, payload=None, *a, **k):
            if event == 'brute_force_detected':
                with self._mutex:
                    self.told.append((payload['device_id'], payload['source_ip'], api._locks_held()))
                self.at_event()
            return real_fire(event, payload, *a, **k)

        def intel(dev_id, unit, sources, window):
            with self._mutex:
                self.intel.append(api._locks_held())
        self._patches = [mock.patch.object(api, 'fire_webhook', recording),
                         mock.patch.object(api, 'ip_intel_note_attacks', intel),
                         mock.patch.object(api, '_brute_config', lambda: (True, 3, 600))]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop)
        api.save(api.BRUTE_FORCE_FILE, {})
        api._LOAD_CACHE.clear()

    def _stop(self):
        for p in reversed(self._patches):
            p.stop()
        api.save(api.BRUTE_FORCE_FILE, {})
        api._LOAD_CACHE.clear()

    def at_event(self):
        """A seam for a test to hold a detection where it tells the world of a crossing."""

    def window(self):
        api._LOAD_CACHE.clear()
        return api.load(api.BRUTE_FORCE_FILE) or {}

    def detect_together(self, lines_of=None):
        gate = threading.Barrier(len(self.hosts))
        errors = []

        def run(host):
            try:
                gate.wait(timeout=30)
                api._detect_brute_force(host, host, 'sshd.service', (lines_of or (lambda h: _lines(self.attacker[h])))(host))
            except BaseException as e:      # noqa: BLE001 - a thread has to report, not die quietly
                errors.append((host, repr(e)))
        threads = [threading.Thread(target=run, args=(h,)) for h in self.hosts]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_every_host_keeps_its_window_when_the_detections_meet_between_the_read_and_the_write(self):
        """Certain, not likely: each detection is held where it tells the world of the crossing, which is where the old code
        sat between its read of the store and its write."""
        gate = threading.Barrier(len(self.hosts))

        def hold():
            try:
                gate.wait(timeout=20)
            except threading.BrokenBarrierError:
                pass
        self.at_event = hold
        self.detect_together()
        store = self.window()
        self.assertEqual(sorted(store), sorted(self.hosts))
        for host in self.hosts:
            sources = store[host]['sshd.service']
            self.assertEqual(list(sources), [self.attacker[host]], host)
            self.assertEqual(len(sources[self.attacker[host]]), 5, host)

    def test_a_crossing_of_the_threshold_is_told_once_per_host(self):
        self.detect_together()
        self.assertEqual(sorted((d, s) for d, s, _ in self.told), sorted(self.attacker.items()))
        before = len(self.told)
        self.detect_together(lambda h: _lines(self.attacker[h], 2))    # the window goes on counting: no second crossing
        self.assertEqual(len(self.told), before)
        for host in self.hosts:
            self.assertEqual(len(self.window()[host]['sshd.service'][self.attacker[host]]), 7)

    def test_the_events_and_the_threat_intel_queue_are_written_after_the_lock_is_released(self):
        """The queue of Threat Intel has a lock of its own, and a lock taken inside another one is an error on SQLite that the
        queue swallows: the sources would be lost without a word."""
        self.detect_together()
        self.assertEqual(len(self.told), len(self.hosts))
        self.assertEqual([entry for entry in self.told if entry[2]], [])
        self.assertEqual(self.intel, [False] * len(self.hosts))

    def test_lines_that_hold_no_source_leave_the_store_as_it_was(self):
        """The control of the one above and of the rule that nothing is written for nothing: a match with no usable source
        address is not a window."""
        api.save(api.BRUTE_FORCE_FILE, {})
        api._detect_brute_force('sbfhost0', 'sbfhost0', 'sshd.service',
                                ['Failed password for root from ---- port 22 ssh2'])
        self.assertEqual(self.window(), {})
        api._detect_brute_force('sbfhost0', 'sbfhost0', 'sshd.service', _lines('185.220.101.1', 1))
        self.assertEqual(list(self.window()['sbfhost0']['sshd.service']), ['185.220.101.1'])

    def test_a_window_that_cannot_be_saved_does_not_raise_and_the_crossing_is_still_told(self):
        """As it was: the save was the last thing the function did and a failure of it was swallowed, and the events had gone
        out before it. The syslog path of an appliance calls the detector with no try around it."""
        real = api._LockedUpdate
        name = Path(str(api.BRUTE_FORCE_FILE)).name

        class _SaveFails:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                return self.inner.__enter__()

            def __exit__(self, *exc):
                self.inner.__exit__(OSError, OSError('disk full'), None)       # the write is given up and the lock released
                raise OSError('disk full')

        def refusing(path, non_blocking=False):
            inner = real(path, non_blocking)
            return _SaveFails(inner) if Path(str(path)).name == name else inner
        with mock.patch.object(api, '_LockedUpdate', refusing):
            api._detect_brute_force('sbfhost0', 'sbfhost0', 'sshd.service', _lines('185.220.101.1'))
        self.assertEqual([(d, s) for d, s, _ in self.told], [('sbfhost0', '185.220.101.1')])
        self.assertEqual(self.intel, [False])
        self.assertEqual(self.window(), {})                      # nothing was kept: the write failed


# ── the class: a store a host writes, read and saved with no lock ───────────────────────────────────────────────────────
# A function that is reached from a host-authenticated handler and does a bare `load(X)` ... `save(X, ...)` of a store X
# loses a write whenever two hosts reach it together. Reachability is by name, over every module of server/cgi-bin, so it
# reads wide. These are the names it stops at, each with the reason; a stop that is not a function any more fails.
STOP_AT = {
    'fire_webhook': 'a recorder: it defers itself while a lock is held and runs after the outermost lock releases; its '
                    'logs (the webhook log, the delivery ledger) are append-only records and not state a host owns',
    'audit_log': 'a recorder like fire_webhook: it defers while a lock is held and only appends to the audit trail',
    'log_command': 'a recorder like fire_webhook: it defers while a lock is held and only appends to the command history',
    'verify_token': 'the lookup of a SESSION token: the write in it refreshes the token of the caller, and the request of a '
                    'host has no session (the helpers that reach it by name read the caller of a page)',
}

# What is left, by (function, store): each is a bare read and save of a store a host reaches, kept on purpose.
EXEMPT = {
    ('_resolve_longpoll', 'LONGPOLL_FILE'):
        'one slot per host, written by the host that answers and read by the one request that waits for it; the same '
        'file is read and saved bare by six more functions of the long-poll protocol, so the file is converted as '
        'a whole or not at all, and a lost slot reads as "no answer from the host within the timeout"',
    ('_record_metrics', 'METRICS_FILE'):
        'the branch of the JSON backend only; the SQL backends, which are the default, append one row to a table. A lost '
        'update there is one point of a chart, and the JSON store keeps the last window of every host in one blob',
    ('_persist_monitor_results', 'MON_HIST_FILE'):
        'the branch of the JSON backend only (the SQL backends write the rows that ran); a lost update is one entry of a '
        'monitor history, and the state that decides an alert is kept in the settings document',
}

LOCK_CALLS = ('_LockedUpdate', '_locked_update')
SAVE_CALLS = ('save',)
LOAD_CALLS = ('load', '_load_ro')
HOST_AUTH = '_device_token_ok'


def _callee(node):
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _store(node):
    """The constant a call names as its first argument: X_FILE, or A.X_FILE in a bound module."""
    if isinstance(node, ast.Name) and node.id.endswith('_FILE'):
        return node.id
    if isinstance(node, ast.Attribute) and node.attr.endswith('_FILE'):
        return node.attr
    return None


def _facts(fn):
    """(called names, stores locked, stores saved, stores loaded) of one function, nested functions included."""
    called, locked, saved, loaded = set(), set(), set(), set()
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        name = _callee(n)
        if name:
            called.add(name)
        store = _store(n.args[0]) if n.args else None
        if not store:
            continue
        if name in LOCK_CALLS:
            locked.add(store)
        elif name in SAVE_CALLS:
            saved.add(store)
        elif name in LOAD_CALLS:
            loaded.add(store)
    return called, locked, saved, loaded


def parse_functions(sources):
    """{function name: [(file, facts), ...]} over {file name: source text}."""
    out = {}
    for fname, text in sources.items():
        for fn in ast.walk(ast.parse(text)):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.setdefault(fn.name, []).append((fname, _facts(fn)))
    return out


def host_written(funcs, stop=STOP_AT):
    """(entry names, reached names, bare pairs {(function, store)}, locked sites {(function, store)})."""
    entries = {name for name, defs in funcs.items() if name != HOST_AUTH
               and any(HOST_AUTH in called for _, (called, _l, _s, _r) in defs)}
    reached, queue = set(entries), sorted(entries)
    while queue:
        cur = queue.pop()
        for _fname, (called, _l, _s, _r) in funcs.get(cur, []):
            for nxt in called:
                if nxt in funcs and nxt not in reached and nxt not in stop:
                    reached.add(nxt)
                    queue.append(nxt)
    bare, locked = set(), set()
    for name in reached:
        for _fname, (_called, lk, sv, ld) in funcs[name]:
            for store in lk:
                locked.add((name, store))
            for store in (sv - lk) & ld:
                bare.add((name, store))
    return entries, reached, bare, locked


def _real_sources():
    return {p.name: p.read_text(encoding='utf-8') for p in sorted(_CGI.glob('*.py'))}


class TestNoBareReadModifyWriteOnAStoreAHostWrites(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.funcs = parse_functions(_real_sources())
        cls.entries, cls.reached, cls.bare, cls.locked = host_written(cls.funcs)

    def test_the_scan_can_see_what_it_looks_for(self):
        """The control. 'nothing was found' is what a broken walk reports too."""
        text = ('def handle_in(body):\n'
                '    if not _device_token_ok(dev, tok):\n'
                '        return\n'
                '    helper(body)\n'
                'def helper(body):\n'
                '    store = load(THING_FILE)\n'
                '    store["x"] = 1\n'
                '    save(THING_FILE, store)\n'
                'def other():\n'
                '    store = load(OTHER_FILE)\n'
                '    save(OTHER_FILE, store)\n')
        entries, reached, bare, locked = host_written(parse_functions({'m.py': text}))
        self.assertEqual(entries, {'handle_in'})
        self.assertEqual(bare, {('helper', 'THING_FILE')}, 'a bare pair behind a host handler must be seen')
        self.assertNotIn('other', reached, 'a function no host handler reaches is not in the population')
        fixed = text.replace('    store = load(THING_FILE)\n    store["x"] = 1\n    save(THING_FILE, store)\n',
                             '    with _LockedUpdate(THING_FILE) as store:\n        store["x"] = 1\n')
        self.assertNotEqual(fixed, text)
        entries, reached, bare, locked = host_written(parse_functions({'m.py': fixed}))
        self.assertEqual((bare, locked), (set(), {('helper', 'THING_FILE')}), 'the locked form is not a finding')
        stopped = host_written(parse_functions({'m.py': text}), stop={'helper': 'x'})
        self.assertEqual(stopped[2], set(), 'a function the walk stops at is not entered')
        bound = text.replace('load(THING_FILE)', 'A.load(A.THING_FILE)').replace('save(THING_FILE,', 'A.save(A.THING_FILE,')
        self.assertEqual(host_written(parse_functions({'m.py': bound}))[2], {('helper', 'THING_FILE')},
                         'the A. prefix of a bound module is read too')

    def test_the_population_is_the_host_handlers_the_code_has(self):
        """The derivation is measured, not assumed: it must hold the handlers a host reaches the server by, and be wide."""
        for name in ('handle_heartbeat', 'handle_packages_submit', 'handle_log_submit', 'handle_scap_report',
                     'handle_threat_events', 'handle_enroll_register'):
            self.assertIn(name, self.entries)
        self.assertGreaterEqual(len(self.entries), 8)
        self.assertGreater(len(self.reached), 300, 'the reach from the host handlers is far smaller than it was')
        for name in ('_eval_software_policy', '_detect_brute_force', '_record_metrics'):
            self.assertIn(name, self.reached, name)

    def test_the_lock_is_the_rule_where_hosts_write(self):
        """The ratio the class is read by: how many (function, store) writes of this population hold the lock, against how
        many are read and saved bare. A rule applied in most places and missed in one or two."""
        self.assertGreater(len(self.locked), 30, 'almost no locked write is reached from a host handler')

    def test_no_function_a_host_reaches_reads_and_saves_a_store_without_its_lock(self):
        unexplained = sorted(self.bare - set(EXEMPT))
        self.assertEqual(
            unexplained, [],
            'These are reached from a host-authenticated handler and do a bare load(X) ... save(X, ...) of a store that every\n'
            'host writes, so two hosts that arrive together lose one write. Take the lock across the read-modify-write\n'
            '(`with _LockedUpdate(X) as store:`), judge outside it, and tell the events after it.\n'
            f'ratio of this population: {len(self.locked)} locked writes, {len(self.bare)} bare pairs, '
            f'{len(set(EXEMPT) & self.bare)} of them listed with a reason.\n'
            + '\n'.join(f'  {fn}: {store}' for fn, store in unexplained))

    def test_a_listed_exemption_is_still_a_bare_pair_and_says_why(self):
        for pair, why in EXEMPT.items():
            self.assertIn(pair, self.bare, f'{pair} is listed but is no longer a bare pair a host reaches: delete the entry')
            self.assertGreater(len(why), 60, f'{pair} is exempt without a reason')
        for name, why in STOP_AT.items():
            self.assertIn(name, self.funcs, f'{name} is not a function any more: delete the stop')
            self.assertGreater(len(why), 60, f'{name} is a stop without a reason')

    def test_the_two_stores_this_class_was_found_in_are_locked(self):
        for pair in (('_eval_software_policy', 'SOFTWARE_VIOLATIONS_FILE'), ('_detect_brute_force', 'BRUTE_FORCE_FILE'),
                     ('handle_packages_submit', 'PACKAGES_FILE')):
            self.assertIn(pair, self.locked)
            self.assertNotIn(pair, self.bare)


if __name__ == '__main__':
    unittest.main()
