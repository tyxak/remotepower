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
                       'respond', 'method', 'get_json_body')}
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


if __name__ == '__main__':
    unittest.main()
