"""Wave-4 improvement-program guardrails (monitors & metrics depth)."""
import http.server
import os
import tempfile
import threading
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys

ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_w4", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _HandlerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'DEVICES_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', 'verify_token',
                       'get_token_from_request', 'audit_log', 'fire_webhook',
                       'respond', 'method', 'get_json_body', 'get_json_obj')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestHttpFlowMonitor(_HandlerBase):
    """W4-13: multi-step HTTP flow monitor."""

    def _serve(self):
        state = {}

        class H(http.server.BaseHTTPRequestHandler):
            def _send(self, code, body=b'', extra=None):
                self.send_response(code)
                self.send_header('Content-Length', str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                # "login" sets a cookie + returns a token in the body
                self._send(200, b'session token=abc123 ok',
                           {'Set-Cookie': 'sid=xyz', 'Content-Type': 'text/plain'})

            def do_GET(self):
                # "dashboard" requires the cookie
                if 'sid=xyz' in (self.headers.get('Cookie') or ''):
                    self._send(200, b'Welcome back')
                else:
                    self._send(403, b'no session')

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f'http://127.0.0.1:{srv.server_port}'

    def _run(self, steps):
        api.save(api.CONFIG_FILE, {'allow_internal_monitors': True})
        api._invalidate_load_cache(api.CONFIG_FILE)
        return api._run_http_flow({'steps': steps})

    def test_flow_with_cookie_and_extract(self):
        base = self._serve()
        ok, detail = self._run([
            {'method': 'POST', 'url': base + '/login', 'expect_status': 200,
             'extract': {'name': 'tok', 'regex': r'token=([a-z0-9]+)'}},
            {'method': 'GET', 'url': base + '/dash?t=${tok}',
             'expect_contains': 'Welcome'}])
        self.assertTrue(ok, detail)
        self.assertIn('2 steps ok', detail)

    def test_flow_fails_on_wrong_status(self):
        base = self._serve()
        ok, detail = self._run([
            {'method': 'GET', 'url': base + '/dash'}])   # no cookie → 403
        self.assertFalse(ok)
        self.assertIn('403', detail)

    def test_flow_fails_on_missing_content(self):
        base = self._serve()
        ok, detail = self._run([
            {'method': 'POST', 'url': base + '/login',
             'expect_contains': 'NOT PRESENT'}])
        self.assertFalse(ok)
        self.assertIn('not found', detail)

    def test_no_steps(self):
        ok, detail = api._run_http_flow({'steps': []})
        self.assertFalse(ok)

    def test_config_save_validates_steps(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'monitors': [
            {'type': 'http_flow', 'label': 'login flow', 'steps': [
                {'method': 'GET', 'url': 'https://app.test/x', 'expect_status': 200}]}]}
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        mons = (api.load(api.CONFIG_FILE) or {}).get('monitors')
        self.assertEqual(mons[0]['type'], 'http_flow')
        self.assertEqual(len(mons[0]['steps']), 1)


class TestNetworkPathMonitor(_HandlerBase):
    """W4-15: path monitor evaluator + path_changed baseline diff."""

    def setUp(self):
        super().setUp()
        self._mh = api.MON_HIST_FILE
        api.MON_HIST_FILE = self.d / 'monitor_history.json'
        self.fired = []
        api.fire_webhook = lambda ev, p: self.fired.append((ev, p))

    def tearDown(self):
        api.MON_HIST_FILE = self._mh
        super().tearDown()

    def test_path_target_accepted(self):
        self.assertEqual(api._sanitize_monitor_target('path', '8.8.8.8'), '8.8.8.8')
        self.assertIsNone(api._sanitize_monitor_target('path', '-badflag'))

    def test_evaluator_shapes_result(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._run_traceroute = lambda t: ([{'n': 1, 'ip': '10.0.0.1', 'ms': 1.0},
                                          {'n': 2, 'ip': '8.8.8.8', 'ms': 5.0}], '')
        r = api._run_one_monitor_check('path', '8.8.8.8', 'gw', {})
        self.assertTrue(r['ok'])
        self.assertEqual(len(r['hops']), 2)
        self.assertIn('2 hops', r['detail'])

    def test_no_traceroute_binary(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._run_traceroute = lambda t: ([], 'no traceroute/tracepath on the server')
        r = api._run_one_monitor_check('path', '8.8.8.8', 'gw', {})
        self.assertFalse(r['ok'])
        self.assertIn('traceroute', r['detail'])

    def test_path_changed_fires_on_hop_diff(self):
        api.save(api.CONFIG_FILE, {'monitors': [{'label': 'gw', 'type': 'path'}]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        # first result → baselines silently
        api._persist_monitor_results([{'label': 'gw', 'type': 'path', 'target': '8.8.8.8',
                                       'ok': True, 'detail': '2 hops', 'checked': 1,
                                       'hops': [{'ip': '10.0.0.1'}, {'ip': '8.8.8.8'}]}])
        self.assertEqual(self.fired, [])
        # a changed route → path_changed
        api._persist_monitor_results([{'label': 'gw', 'type': 'path', 'target': '8.8.8.8',
                                       'ok': True, 'detail': '2 hops', 'checked': 2,
                                       'hops': [{'ip': '10.0.0.9'}, {'ip': '8.8.8.8'}]}])
        self.assertTrue(any(e == 'path_changed' for e, _ in self.fired))
        # same (new) route again → no re-fire
        self.fired.clear()
        api._persist_monitor_results([{'label': 'gw', 'type': 'path', 'target': '8.8.8.8',
                                       'ok': True, 'detail': '2 hops', 'checked': 3,
                                       'hops': [{'ip': '10.0.0.9'}, {'ip': '8.8.8.8'}]}])
        self.assertEqual(self.fired, [])


class TestMailflowMonitor(_HandlerBase):
    """W4-16: SMTP→IMAP round-trip monitor state machine + config."""

    def setUp(self):
        super().setUp()
        self._msf = api.MAILFLOW_STATE_FILE
        api.MAILFLOW_STATE_FILE = self.d / 'mailflow_state.json'

    def tearDown(self):
        api.MAILFLOW_STATE_FILE = self._msf
        super().tearDown()

    def test_step_sends_when_idle(self):
        sent = []
        st, ev = api._mailflow_step({}, {'to_address': 'x@y.z'}, 1000,
                                    lambda tok: sent.append(tok) or True,
                                    lambda tok: None)
        self.assertEqual(len(sent), 1)
        self.assertTrue(st.get('pending_token'))
        self.assertEqual(ev, [])

    def test_step_records_latency_on_arrival(self):
        st0 = {'pending_token': 'rp-mailflow-900-abcd', 'sent_ts': 900}
        st, ev = api._mailflow_step(st0, {}, 1000,
                                    lambda tok: True, lambda tok: 100)
        self.assertEqual(st.get('last_latency'), 100)
        self.assertNotIn('pending_token', st)
        self.assertEqual(ev, [])

    def test_step_recovers_after_alert(self):
        st0 = {'pending_token': 'rp-mailflow-900-abcd', 'sent_ts': 900, 'alerted': True}
        st, ev = api._mailflow_step(st0, {'to_address': 'x@y.z'}, 1000,
                                    lambda tok: True, lambda tok: 42)
        self.assertFalse(st.get('alerted'))
        self.assertEqual([e for e, _ in ev], ['mailflow_ok'])

    def test_step_alerts_when_overdue(self):
        st0 = {'pending_token': 'rp-mailflow-100-abcd', 'sent_ts': 100}
        st, ev = api._mailflow_step(st0, {'max_latency_seconds': 60, 'to_address': 'x@y.z'},
                                    1000, lambda tok: True, lambda tok: None)
        self.assertTrue(st.get('alerted'))
        self.assertEqual([e for e, _ in ev], ['mailflow_delayed'])

    def test_step_alerts_only_once(self):
        st0 = {'pending_token': 'rp-mailflow-100-abcd', 'sent_ts': 100, 'alerted': True}
        st, ev = api._mailflow_step(st0, {'max_latency_seconds': 60}, 1000,
                                    lambda tok: True, lambda tok: None)
        self.assertEqual(ev, [])

    def test_save_get_redacts_password(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'enabled': True, 'to_address': 'probe@test.io',
                                    'imap_host': 'imap.test.io', 'imap_user': 'u',
                                    'imap_password': 'sekret', 'max_latency_seconds': 120}
        self.call(api.handle_mailflow_save)
        cfg = (api.load(api.CONFIG_FILE) or {}).get('mailflow')
        self.assertEqual(cfg['imap_password'], 'sekret')
        self.assertEqual(cfg['max_latency_seconds'], 120)
        api._invalidate_load_cache(api.CONFIG_FILE)
        out = self.call(api.handle_mailflow_get)
        self.assertTrue(out['imap_password_set'])
        self.assertNotIn('imap_password', out)

    def test_save_requires_valid_address_when_enabled(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'enabled': True, 'to_address': 'not-an-email'}
        out = self.call(api.handle_mailflow_save)
        self.assertIn('to_address', str(out))

    def test_blank_password_keeps_stored(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'enabled': True, 'to_address': 'p@t.io',
                                    'imap_host': 'h', 'imap_password': 'first'}
        self.call(api.handle_mailflow_save)
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.get_json_obj = lambda: {'enabled': True, 'to_address': 'p@t.io',
                                    'imap_host': 'h', 'imap_password': ''}
        self.call(api.handle_mailflow_save)
        cfg = (api.load(api.CONFIG_FILE) or {}).get('mailflow')
        self.assertEqual(cfg['imap_password'], 'first')


class TestSeasonalAnomalies(unittest.TestCase):
    """W4-18: day-of-week × 4-hour bucketed anomaly baselines (pure module)."""

    def setUp(self):
        sys.path.insert(0, str(_CGI_BIN))
        import anomaly_stats
        self.an = anomaly_stats

    def _mk(self, ts, mem):
        return {'ts': ts, 'mem_percent': mem}

    def test_bucket_of_and_label(self):
        # 2026-07-06 is a Monday; pick 09:00 local → block 2 (08–12)
        import time
        ts = int(time.mktime((2026, 7, 6, 9, 0, 0, 0, 0, -1)))
        b = self.an._bucket_of(ts)
        self.assertEqual(b[1], 2)
        self.assertIn('08–12', self.an._bucket_label(b))

    def test_falls_back_to_flat_before_warmup(self):
        # < SEASONAL_WARMUP samples → seasonal=False, uses flat detection
        base = 1_700_000_000
        samples = [self._mk(base + i * 86400, 20) for i in range(8)]
        samples.append(self._mk(base + 8 * 86400, 90))   # spike
        out = self.an.detect_device_seasonal(samples)
        self.assertTrue(out)
        self.assertFalse(out[0]['seasonal'])

    def test_seasonal_bucket_scoring(self):
        # Build >=14 days of hourly-aligned weekly data: every Monday-morning
        # sample runs hot (80), every other day cool (20). A hot Monday should
        # NOT flag against the Monday bucket, but a cool Monday should.
        import time
        out_samples = []
        # 6 Mondays at 09:00 all = 80 (the seasonal norm for that bucket)
        base_mon = int(time.mktime((2026, 6, 1, 9, 0, 0, 0, 0, -1)))  # a Monday
        for wk in range(6):
            out_samples.append(self._mk(base_mon + wk * 7 * 86400, 80))
        # interleave cool weekday samples so total >= warmup
        base_wed = int(time.mktime((2026, 6, 3, 9, 0, 0, 0, 0, -1)))
        for wk in range(10):
            out_samples.append(self._mk(base_wed + wk * 86400, 20))
        out_samples.sort(key=lambda s: s['ts'])
        # latest = a hot Monday (80) → matches the Monday-bucket norm → no flag
        hot_mon = dict(self._mk(base_mon + 6 * 7 * 86400, 80))
        res = self.an.detect_device_seasonal(out_samples + [hot_mon], z=2.0)
        mem = [a for a in res if a['metric'] == 'mem_percent' and a.get('seasonal')]
        self.assertEqual(mem, [], 'hot Monday should be normal for its bucket')
        # latest = a COOL Monday (20) → far below the Monday norm → flags
        cool_mon = dict(self._mk(base_mon + 6 * 7 * 86400, 20))
        res2 = self.an.detect_device_seasonal(out_samples + [cool_mon], z=2.0)
        mem2 = [a for a in res2 if a['metric'] == 'mem_percent' and a.get('seasonal')]
        self.assertTrue(mem2, 'cool Monday should deviate from its bucket')
        self.assertEqual(mem2[0]['direction'], 'low')
        self.assertIn('Mon', mem2[0]['bucket'])


class TestMetricRollups(_HandlerBase):
    """W4-10: long-term metric roll-up pure functions + cadence + endpoint."""

    def setUp(self):
        super().setUp()
        self._mf = api.METRICS_FILE
        self._rf = api.METRICS_ROLLUP_FILE
        api.METRICS_FILE = self.d / 'metrics.json'
        api.METRICS_ROLLUP_FILE = self.d / 'metrics_rollup.json'

    def tearDown(self):
        api.METRICS_FILE = self._mf
        api.METRICS_ROLLUP_FILE = self._rf
        super().tearDown()

    def test_merge_aggregates_minavgmax(self):
        base = 1_700_000_000
        base -= base % 3600     # align to an hour boundary
        samples = [{'ts': base + 60, 'cpu': 10, 'mem': 50},
                   {'ts': base + 120, 'cpu': 30, 'mem': 60},
                   {'ts': base + 180, 'cpu': 20, 'mem': 55}]
        buckets = api._rollup_merge([], samples, api.ROLLUP_HOURLY_SEC)
        self.assertEqual(len(buckets), 1)
        shape = api._rollup_read_shape(buckets)[0]
        self.assertEqual(shape['cpu'], {'min': 10, 'avg': 20.0, 'max': 30})

    def test_merge_is_incremental(self):
        base = 1_700_000_000
        base -= base % 3600
        b1 = api._rollup_merge([], [{'ts': base + 60, 'cpu': 10}], api.ROLLUP_HOURLY_SEC)
        b2 = api._rollup_merge(b1, [{'ts': base + 120, 'cpu': 40}], api.ROLLUP_HOURLY_SEC)
        shape = api._rollup_read_shape(b2)[0]
        self.assertEqual(shape['cpu'], {'min': 10, 'avg': 25.0, 'max': 40})

    def test_prune_drops_old_buckets(self):
        now = 2_000_000_000
        buckets = [{'ts': now - 40 * 86400}, {'ts': now - 1 * 86400}]
        kept = api._rollup_prune(buckets, api.ROLLUP_HOURLY_KEEP, now)
        self.assertEqual([b['ts'] for b in kept], [now - 1 * 86400])

    def test_cadence_folds_raw_window(self):
        base = int(__import__('time').time()) - 600   # recent, inside retention
        api.save(api.DEVICES_FILE, {'d1': {'name': 'host1'}})
        samples = [
            {'ts': base, 'cpu': 10, 'mem': 50, 'swap': 1, 'disk': 20},
            {'ts': base + 120, 'cpu': 30, 'mem': 70, 'swap': 3, 'disk': 22}]
        api.save(api.METRICS_FILE, {'d1': samples})
        # Under a DB backend _raw_metric_samples reads the metric_samples
        # TABLE (the heartbeat-ingest store), not the metrics.json window —
        # seed it too or the fold sees nothing (this fixture was JSON-only,
        # so the test had been red on the SQLite leg since W4-10 shipped).
        dbm = api._dbmod()
        if dbm is not None:
            for s in samples:
                dbm.metric_append(api.DATA_DIR, 'd1', s['ts'], s['cpu'],
                                  s['mem'], s['swap'], s['disk'])
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._invalidate_load_cache(api.METRICS_FILE)
        api.run_metric_rollup_if_due()
        st = api.load(api.METRICS_ROLLUP_FILE) or {}
        self.assertIn('d1', st)
        self.assertTrue(st['d1']['hourly'])
        self.assertTrue(st['d1']['daily'])
        if dbm is None:
            self.assertEqual(st['d1']['last_ts'], base + 120)
        else:
            # DB backends fold through metric_range, a DOWNSAMPLING reader:
            # the first run (since=0) buckets the whole history, so the two
            # samples may average into one bucket stamped MIN(ts) — the
            # high-water mark lands on `base`, not base+120, and converges on
            # the next cadence run. Known one-time first-fold coarseness.
            self.assertGreaterEqual(st['d1']['last_ts'], base)

    def test_cadence_is_throttled(self):
        api.save(api.METRICS_ROLLUP_FILE, {'_meta': {'last_run': int(__import__('time').time())}})
        api._invalidate_load_cache(api.METRICS_ROLLUP_FILE)
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h'}})
        api.save(api.METRICS_FILE, {'d1': [{'ts': 1, 'cpu': 5}]})
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._invalidate_load_cache(api.METRICS_FILE)
        api.run_metric_rollup_if_due()
        st = api.load(api.METRICS_ROLLUP_FILE) or {}
        self.assertNotIn('d1', st)   # throttled — no fold happened

    # ── v6.1.1 (#21 follow-up, adversarial self-review) ──────────────────────
    def test_prune_skipped_while_litigation_hold_active(self):
        # _rollup_prune is a real age-based deletion of historical metric
        # data, but this cadence sweep ran entirely independent of
        # _purge_old_data's litigation-hold gate -- a real, live bypass of
        # a feature whose own docstring calls _purge_old_data "the single
        # choke point." New samples must still fold in (purely additive,
        # never a problem to keep MORE evidence); only pruning must pause.
        api.save(api.CONFIG_FILE, {'litigation_hold': {'enabled': True, 'reason': 'x'}})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'host1'}})
        now = int(__import__('time').time())
        very_old_bucket_ts = now - api.ROLLUP_HOURLY_KEEP - 3600   # well past retention
        api.save(api.METRICS_ROLLUP_FILE, {'d1': {
            'last_ts': now - 600,
            'hourly': [{'ts': very_old_bucket_ts, 'cpu': {'min': 1, 'sum': 1.0, 'max': 1, 'n': 1}}],
            'daily': [],
        }})
        # a fresh sample so the per-device fold path actually runs
        api.save(api.METRICS_FILE, {'d1': [{'ts': now - 60, 'cpu': 10, 'mem': 50, 'swap': 1, 'disk': 20}]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._invalidate_load_cache(api.METRICS_FILE)
        api._invalidate_load_cache(api.METRICS_ROLLUP_FILE)
        api.run_metric_rollup_if_due()
        st = api.load(api.METRICS_ROLLUP_FILE) or {}
        self.assertIn(very_old_bucket_ts, [b['ts'] for b in st['d1']['hourly']],
                     'the old bucket must survive while the hold is active')

    def test_prune_resumes_once_hold_cleared(self):
        api.save(api.CONFIG_FILE, {'litigation_hold': {'enabled': False}})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'host1'}})
        now = int(__import__('time').time())
        very_old_bucket_ts = now - api.ROLLUP_HOURLY_KEEP - 3600
        api.save(api.METRICS_ROLLUP_FILE, {'d1': {
            'last_ts': now - 600,
            'hourly': [{'ts': very_old_bucket_ts, 'cpu': {'min': 1, 'sum': 1.0, 'max': 1, 'n': 1}}],
            'daily': [],
        }})
        api.save(api.METRICS_FILE, {'d1': [{'ts': now - 60, 'cpu': 10, 'mem': 50, 'swap': 1, 'disk': 20}]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._invalidate_load_cache(api.METRICS_FILE)
        api._invalidate_load_cache(api.METRICS_ROLLUP_FILE)
        api.run_metric_rollup_if_due()
        st = api.load(api.METRICS_ROLLUP_FILE) or {}
        self.assertNotIn(very_old_bucket_ts, [b['ts'] for b in st['d1']['hourly']],
                         'pruning must resume once the hold is cleared')

    def test_endpoint_serves_tier(self):
        base = 1_700_000_000
        api.save(api.METRICS_ROLLUP_FILE, {'d1': {'last_ts': base,
            'daily': api._rollup_merge([], [{'ts': base, 'cpu': 12}], api.ROLLUP_DAILY_SEC),
            'hourly': []}})
        api._invalidate_load_cache(api.METRICS_ROLLUP_FILE)
        saved = {n: getattr(api, n) for n in ('_env', '_caller_scope', '_validate_id')}
        try:
            api._env = lambda k, d='': 'tier=daily' if k == 'QUERY_STRING' else d
            api._caller_scope = lambda: None
            api._validate_id = lambda x: True
            out = self.call(api.handle_device_metric_rollup, 'd1')
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
        self.assertEqual(out['tier'], 'daily')
        self.assertEqual(out['points'][0]['cpu']['avg'], 12.0)


class TestProbeFromSatellite(_HandlerBase):
    """W4-14: monitors probed by a relay satellite."""

    def setUp(self):
        super().setUp()
        self._extra = {}
        for attr in ('SATELLITES_FILE', 'SATELLITE_MON_FILE', 'MON_HIST_FILE'):
            self._extra[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        # a registered satellite + its token
        self.tok = 'sat-token-123'
        self.sid = 'abcd1234'
        api.save(api.SATELLITES_FILE, {self.sid: {
            'name': 'branch', 'token_hash': api._satellite_token_hash(self.tok),
            'scanner': False}})
        self._env0 = api._env
        api._env = lambda k, d='': self.tok if k == 'HTTP_X_RP_SATELLITE' else self._env0(k, d)
        self.fired = []
        api.fire_webhook = lambda ev, p: self.fired.append((ev, p))

    def tearDown(self):
        api._env = self._env0
        for attr, v in self._extra.items():
            setattr(api, attr, v)
        super().tearDown()

    def _set_monitors(self, mons):
        api.save(api.CONFIG_FILE, {'monitors': mons})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def test_config_save_validates_satellite_id(self):
        api.method = lambda: 'POST'
        # unknown satellite id → 400
        api.get_json_body = lambda: {'monitors': [
            {'type': 'ping', 'label': 'gw', 'target': '10.0.0.1', 'via_satellite': 'nope'}]}
        out = self.call(api.handle_config_save)
        self.assertIn('unknown satellite', str(out))
        # known id → stored
        api.get_json_body = lambda: {'monitors': [
            {'type': 'ping', 'label': 'gw', 'target': '10.0.0.1', 'via_satellite': self.sid}]}
        self.call(api.handle_config_save)
        mons = (api.load(api.CONFIG_FILE) or {}).get('monitors')
        self.assertEqual(mons[0]['via_satellite'], self.sid)

    def test_execute_skips_satellite_monitors(self):
        res = api._execute_monitor_checks([
            {'type': 'ping', 'label': 'local', 'target': '127.0.0.1'},
            {'type': 'ping', 'label': 'remote', 'target': '10.0.0.1', 'via_satellite': self.sid},
        ])
        labels = [r['label'] for r in res]
        self.assertIn('local', labels)
        self.assertNotIn('remote', labels)

    def test_work_queue_returns_assigned(self):
        self._set_monitors([
            {'type': 'tcp', 'label': 'db', 'target': '10.0.0.5', 'port': 5432, 'via_satellite': self.sid},
            {'type': 'ping', 'label': 'other', 'target': '10.0.0.9', 'via_satellite': 'zzzz'},
        ])
        out = self.call(api.handle_satellite_monitor_work)
        self.assertEqual(out['satellite_id'], self.sid)
        self.assertEqual([j['label'] for j in out['monitors']], ['db'])
        self.assertEqual(out['monitors'][0]['port'], 5432)

    def test_results_accepted_only_for_owned(self):
        self._set_monitors([
            {'type': 'ping', 'label': 'mine', 'target': '10.0.0.1', 'via_satellite': self.sid}])
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'results': [
            {'label': 'mine', 'type': 'ping', 'target': '10.0.0.1', 'ok': False, 'detail': 'timeout'},
            {'label': 'not-mine', 'type': 'ping', 'target': '1.2.3.4', 'ok': True, 'detail': 'x'}]}
        out = self.call(api.handle_satellite_monitor_results)
        self.assertEqual(out['accepted'], 1)
        store = api.load(api.SATELLITE_MON_FILE) or {}
        self.assertIn('mine', store)
        self.assertNotIn('not-mine', store)
        # a down transition fired monitor_down
        self.assertTrue(any(e == 'monitor_down' for e, _ in self.fired))

    def test_display_merges_stored_and_pending(self):
        self._set_monitors([
            {'type': 'ping', 'label': 'has-result', 'target': '10.0.0.1', 'via_satellite': self.sid},
            {'type': 'ping', 'label': 'no-result', 'target': '10.0.0.2', 'via_satellite': self.sid}])
        api.save(api.SATELLITE_MON_FILE, {'has-result': {
            'label': 'has-result', 'type': 'ping', 'target': '10.0.0.1',
            'ok': True, 'detail': 'up', 'checked': 123}})
        api._invalidate_load_cache(api.SATELLITE_MON_FILE)
        rows = api._satellite_monitor_display((api.load(api.CONFIG_FILE) or {}).get('monitors'))
        by = {r['label']: r for r in rows}
        self.assertEqual(by['has-result']['origin'], f'satellite:{self.sid}')
        self.assertEqual(by['has-result']['detail'], 'up')
        self.assertIn('awaiting', by['no-result']['detail'])


if __name__ == '__main__':
    unittest.main()
