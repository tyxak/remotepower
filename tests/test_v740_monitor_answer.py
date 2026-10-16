"""GET /api/monitor answers from the newest run instead of probing on every open.

Opening the Monitor page ran every monitor inside the request and waited for the
slowest one: 4.0 s on every open of the demo fleet, the timeout of a ping that
gets no reply, and 35-50 s on a fleet with a few hundred dead targets. The
periodic sweep had already probed the same set minutes earlier.

Now the rows of each run are kept (monitor_last.json) and the GET answers from
them while they fit: the same configured set (a fingerprint), the newest run on
record (config's last_monitor_run), and under two sweep intervals old. The page's
Check now button sends ?run=1 and probes. Drives the real handler and the real
sweep; only the probe itself is replaced, and counted.
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v740-mon-'))
_ROOT = Path(__file__).resolve().parent.parent
CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))

MONITORS = [{'label': 'web', 'type': 'http', 'target': 'https://web.example/'},
            {'label': 'gw', 'type': 'ping', 'target': '10.0.0.1'}]


class _Base(unittest.TestCase):

    def setUp(self):
        self._prev = {k: os.environ.get(k) for k in ('RP_DATA_DIR', 'QUERY_STRING')}
        os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v740-mon-')
        spec = importlib.util.spec_from_file_location('api_v740_mon', CGI / 'api.py')
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        self.api = api
        api.save(api.CONFIG_FILE, {'monitors': json.loads(json.dumps(MONITORS)), 'monitor_interval': 300})
        api._LOAD_CACHE.clear()
        api.verify_token = lambda tok=None: ('alice', 'admin')
        api.get_token_from_request = lambda: 'x'
        api.audit_log = lambda *a, **k: None
        self.runs = 0

        def probe(monitors):
            self.runs += 1
            return [{'label': m['label'], 'type': m['type'], 'target': m['target'], 'ok': True,
                     'detail': 'up (run %d)' % self.runs, 'checked': int(time.time())}
                    for m in monitors if not m.get('paused')]
        api._execute_monitor_checks = probe

        def _respond(status, data=None, headers=None):
            raise api.HTTPError(status, data)
        api.respond = _respond

    def tearDown(self):
        for k, v in self._prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def get(self, query=''):
        os.environ['QUERY_STRING'] = query
        self.api.method = lambda: 'GET'
        self.api._LOAD_CACHE.clear()
        try:
            self.api.handle_monitor_run()
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200, e.body)
            return e.body
        self.fail('no response')

    def config(self, **changes):
        with self.api._LockedUpdate(self.api.CONFIG_FILE) as cfg:
            cfg.update(changes)
        self.api._LOAD_CACHE.clear()


class TestTheGetAnswersFromTheNewestRun(_Base):

    def test_the_first_open_probes_and_the_next_answers_from_it(self):
        first = self.get()
        self.assertEqual((self.runs, first['from_last_run']), (1, False))
        second = self.get()
        self.assertEqual(self.runs, 1, 'the second open did not probe')
        self.assertTrue(second['from_last_run'])
        self.assertEqual([(r['label'], r['detail']) for r in second['monitors']],
                         [(r['label'], r['detail']) for r in first['monitors']])

    def test_check_now_probes(self):
        self.get()
        out = self.get('run=1')
        self.assertEqual((self.runs, out['from_last_run']), (2, False))
        self.assertEqual(out['monitors'][0]['detail'], 'up (run 2)')

    def test_a_changed_monitor_set_probes(self):
        self.get()
        self.config(monitors=MONITORS + [{'label': 'dns', 'type': 'dns', 'target': 'example.com'}])
        out = self.get()
        self.assertEqual(self.runs, 2)
        self.assertIn('dns', [r['label'] for r in out['monitors']])

    def test_pausing_one_probes_and_keeps_its_display_row(self):
        self.get()
        paused = json.loads(json.dumps(MONITORS))
        paused[1]['paused'] = True
        self.config(monitors=paused)
        out = self.get()
        self.assertEqual(self.runs, 2)
        self.get()
        self.assertEqual(self.runs, 2, 'the paused set is answered from its own run')
        rows = {r['label']: r for r in self.get()['monitors']}
        self.assertTrue(rows['gw'].get('paused'), 'the paused row is still shown')
        self.assertEqual(len(out['monitors']), 2)

    def test_a_sweep_newer_than_the_rows_probes(self):
        self.get()
        cfg = self.api.load(self.api.CONFIG_FILE)
        self.config(last_monitor_run=int(cfg['last_monitor_run']) + 5)
        self.get()
        self.assertEqual(self.runs, 2)

    def test_rows_older_than_two_intervals_probe(self):
        self.get()
        old = int(time.time()) - 2 * 300 - 5
        last = self.api.load(self.api.MONITOR_LAST_FILE)
        last['ts'] = old
        self.api.save(self.api.MONITOR_LAST_FILE, last)
        self.config(last_monitor_run=old)
        self.get()
        self.assertEqual(self.runs, 2)


class TestThePeriodicSweepFeedsThePage(_Base):

    def test_the_page_answers_from_the_sweep(self):
        self.config(last_monitor_run=0)
        self.api.run_monitors_if_due()
        self.assertEqual(self.runs, 1, 'control: the sweep ran')
        out = self.get()
        self.assertEqual(self.runs, 1, 'the page answered from the sweep without probing')
        self.assertTrue(out['from_last_run'])


class TestTheButtonForcesARun(unittest.TestCase):

    def test_check_now_sends_run_and_the_page_open_does_not(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('data-action="runMonitor" data-arg="1"', html)
        app = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("api('GET', force ? '/monitor?run=1' : '/monitor')", app)
        self.assertIn("if (name === 'monitor')  { runMonitor();", app)


if __name__ == '__main__':
    unittest.main()
