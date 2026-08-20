#!/usr/bin/env python3
"""Log ingest read and rewrote the whole fleet's log buffer, holding no lock.

`handle_log_submit` did `load(LOG_WATCH_FILE)` … mutate one device's row …
`save(LOG_WATCH_FILE, whole_store)`. Two faults in one shape.

Correctness: no lock across the pair, so two agents posting logs at the same
time lost one submission outright — the second writer's snapshot predates the
first writer's save. Unlike the heartbeat blobs, log lines are submitted once
and never re-sent, so the lines and every alert derived from them are gone.

Cost: log_watch.json is the largest blob in the product — a 6-hour ring of raw
log lines for every unit on every device, with the per-unit byte cap defaulting
to off. Measured on 150 devices x 12 units x 300 lines (54 MB): 1.39 s to load
and 0.73 s to save, per POST, per device.

log_watch.json is now an ENTITY store (schema v11), so the DB backends read and
write one row: 2029 ms -> 5 ms end to end. The JSON backend has no per-row
store; it takes the lock once and reads through it, which is one parse and one
save — the same as before, now with the lock. Reading the row first and locking
afterwards was the obvious shape and is 31% SLOWER, because _JsonLockedUpdate
re-reads inside the critical section by design (v6.4.2) and the blob is parsed
twice.
"""
import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-lsub-'))
_spec = importlib.util.spec_from_file_location('api_log_submit_rmw', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

sys.path.insert(0, str(_ROOT / 'tests'))
import srcpin                                                    # noqa: E402
import storage                                                   # noqa: E402


class TestTheStoreIsRowAddressable(unittest.TestCase):

    def test_log_watch_is_an_entity_file(self):
        self.assertIn('log_watch.json', storage.ENTITY_FILES)
        self.assertEqual('entity',
                         storage._classify(Path('/x/log_watch.json')))

    def test_existing_databases_migrate_rather_than_reclassify(self):
        """Every install that has ever watched a log has data in the cold kv
        row. Reclassifying without moving it makes that data unreadable —
        load() would start looking in the entity table and find nothing."""
        self.assertIn('log_watch.json', storage._COLD_TO_ENTITY_V9)
        src = (_CGI / 'storage.py').read_text()
        self.assertIn('_migrate_cold_to_entity(conn, _COLD_TO_ENTITY_V9)', src)

    def test_the_schema_version_advanced_past_the_new_gate(self):
        """A wave gated at `db_ver < 11` never runs if SCHEMA_VERSION stays 10:
        a fresh DB is stamped 10, so the migration is skipped forever. This is
        the mistake _COLD_TO_ENTITY_V6's comment records for commands.json."""
        self.assertGreaterEqual(storage.SCHEMA_VERSION, 11)
        src = (_CGI / 'storage.py').read_text()
        self.assertIn('db_ver < 11', src)


class TestTheHandlerTouchesOneRow(unittest.TestCase):

    def setUp(self):
        self.body = srcpin.py_function((_CGI / 'api.py').read_text(),
                                       'handle_log_submit')
        self.code = '\n'.join(l for l in self.body.splitlines()
                              if not l.lstrip().startswith('#'))

    def test_it_no_longer_loads_or_saves_the_whole_store(self):
        for bad in ('load(LOG_WATCH_FILE)', 'save(LOG_WATCH_FILE'):
            self.assertNotIn(bad, self.code,
                             f'{bad} is back — every log POST pays for the '
                             'whole fleet again')

    def test_the_json_path_reads_through_the_lock(self):
        """Not before it. A pre-read plus a lock parses the blob twice."""
        self.assertIn('with _LockedUpdate(LOG_WATCH_FILE) as _store:', self.code)
        i_lock = self.code.index('_LockedUpdate(LOG_WATCH_FILE)')
        i_read = self.code.index('_store.get(dev_id)')
        self.assertLess(i_lock, i_read)

    def test_the_row_write_blocks(self):
        """_entity_write_one defaults to non_blocking — right for a heartbeat
        blob that is re-reported next beat, wrong for log lines that are not."""
        self.assertIn('non_blocking=False', self.code)

    def test_brute_force_detection_moved_outside_the_lock(self):
        """It takes its own lock. Called inside the JSON branch's lock it
        nests, which on the DB backends is an OperationalError and historically
        was swallowed."""
        i_ctx = self.code.index('_device_log_buffer()')
        i_bf = self.code.index('_detect_brute_force(')
        self.assertGreater(i_bf, i_ctx)
        # ...and it is genuinely outside the with-block, not merely later in it.
        line = next(l for l in self.body.splitlines()
                    if '_detect_brute_force(' in l and 'def ' not in l)
        self.assertLessEqual(len(line) - len(line.lstrip()), 12, line)


class TestItStillIngestsCorrectly(unittest.TestCase):
    """The behavioural half, driven through the real handler. Source checks
    above prove the shape; only this proves the lines still arrive."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-lsub-run-'))
        self._saved = api.DATA_DIR
        api.DATA_DIR = self.dir
        self._files = {n: getattr(api, n) for n in
                       ('DEVICES_FILE', 'LOG_WATCH_FILE', 'CONFIG_FILE',
                        'LOG_RULES_GLOBAL_FILE')}
        for n, v in self._files.items():
            setattr(api, n, self.dir / Path(v).name)
        self._tok = api._device_token_ok
        self._bf = api._detect_brute_force
        self._fw = api.fire_webhook
        self._rv = api._read_valid
        api._device_token_ok = lambda dev, t: t == 'tok'
        self.fired = []
        api.fire_webhook = lambda ev, pl=None, *a, **k: self.fired.append(ev)
        self.bf = []
        api._detect_brute_force = lambda *a: self.bf.append(a[2])
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            'd7': {'name': 'h7', 'token': 'tok', 'last_seen': now,
                   'log_watch': [{'unit': 'u0.service', 'pattern': 'FATAL',
                                  'severity': 'high'}]},
            'd8': {'name': 'h8', 'token': 'tok', 'last_seen': now,
                   'log_watch': []}})
        api.save(api.LOG_WATCH_FILE, {
            'd7': {'updated_at': now,
                   'units': {'u0.service': [{'ts': now, 'line': 'old d7',
                                             'sig': 'x7'}]}},
            'd8': {'updated_at': now,
                   'units': {'u0.service': [{'ts': now, 'line': 'old d8',
                                             'sig': 'x8'}]}}})

    def tearDown(self):
        api.DATA_DIR = self._saved
        for n, v in self._files.items():
            setattr(api, n, v)
        api._device_token_ok, api._detect_brute_force = self._tok, self._bf
        api.fire_webhook, api._read_valid = self._fw, self._rv

    def _post(self, dev, lines, unit='u0.service'):
        api._read_valid = lambda m: {
            'device_id': dev, 'token': 'tok',
            'units': {unit: [{'message': l} for l in lines]}}
        api._RCTX.environ = {'REQUEST_METHOD': 'POST', 'PATH_INFO': '/api/logs',
                             'QUERY_STRING': ''}
        for f in self._files.values():
            try:
                api._invalidate_load_cache(self.dir / Path(f).name)
            except Exception:
                pass
        try:
            api.handle_log_submit()
        except api.HTTPError as e:
            return e.status
        except SystemExit:
            return 'exit'

    def _lines(self, dev, unit='u0.service'):
        api._invalidate_load_cache(api.LOG_WATCH_FILE)
        st = api.load(api.LOG_WATCH_FILE) or {}
        return [e['line'] for e in
                ((st.get(dev) or {}).get('units') or {}).get(unit) or []]

    def test_new_lines_are_appended_and_old_ones_kept(self):
        self.assertEqual(200, self._post('d7', ['hello', 'FATAL disk gone']))
        got = self._lines('d7')
        self.assertIn('hello', got)
        self.assertIn('FATAL disk gone', got)
        self.assertIn('old d7', got)

    def test_one_device_submission_does_not_clobber_another(self):
        """The lost-update case, in the single-threaded form the shape allows:
        two sequential posts, each of which used to write back a whole-store
        snapshot."""
        self._post('d7', ['from d7'])
        self._post('d8', ['from d8'])
        self.assertIn('from d7', self._lines('d7'))
        self.assertIn('old d7', self._lines('d7'))
        self.assertIn('from d8', self._lines('d8'))
        self.assertIn('old d8', self._lines('d8'))

    def test_a_matching_rule_still_fires(self):
        """Positive control on the alert path. The webhook is raised from
        inside the lock scope, where fire_webhook auto-defers — if that ever
        stopped working the alert would vanish while ingest looked fine."""
        self._post('d7', ['FATAL disk gone'])
        self.assertIn('log_alert', self.fired)

    def test_a_non_matching_line_fires_nothing(self):
        """The negative half. Without it, a handler that fired on everything
        would satisfy the test above."""
        self._post('d8', ['perfectly ordinary line'])
        self.assertEqual([], self.fired)

    def test_brute_force_detection_still_runs_for_ssh_units(self):
        unit = sorted(api._SSH_UNITS)[0]
        self._post('d8', ['Failed password for root from 10.0.0.9'], unit=unit)
        self.assertIn(unit, self.bf,
                      'moving this out of the lock dropped it entirely')


if __name__ == '__main__':
    unittest.main()
