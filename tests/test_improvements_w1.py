"""Wave-1 improvement-program guardrails (internal plan: improvement-program).

One test class per shipped wave-1 item. Each class is self-contained so
items can land (and be reviewed) one commit at a time.
"""
import http.server
import json
import os
import re
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

_spec = importlib.util.spec_from_file_location("api_w1", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _HandlerBase(unittest.TestCase):
    """Drive handlers directly with stubbed auth/request/respond
    (same shape as tests/test_v3120.py)."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'AVATARS_DIR',
                     'ROLES_FILE', 'DEVICES_FILE'):
            self._files[attr] = getattr(api, attr)
            base = Path(getattr(api, attr)).name
            setattr(api, attr, self.d / base)
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


class TestGrafanaDashboard(unittest.TestCase):
    """W1-46: contrib/grafana dashboard stays valid + in sync with the
    /api/metrics exposition (prometheus_export.py)."""

    DASH = ROOT / 'contrib' / 'grafana' / 'remotepower-fleet.json'
    EXPORT = ROOT / 'server' / 'cgi-bin' / 'prometheus_export.py'

    def _dashboard(self):
        return json.loads(self.DASH.read_text())

    def test_dashboard_parses_and_has_panels(self):
        d = self._dashboard()
        self.assertEqual(d['uid'], 'remotepower-fleet')
        panels = [p for p in d['panels'] if p.get('type') != 'row']
        self.assertGreaterEqual(len(panels), 15)
        # importable: datasource is the __inputs template var, not a baked uid
        self.assertEqual(d['__inputs'][0]['name'], 'DS_PROMETHEUS')

    def test_every_dashboard_metric_exists_in_exposition(self):
        exported = set(re.findall(r'remotepower_[a-z0-9_]+',
                                  self.EXPORT.read_text()))
        used = set(re.findall(r'remotepower_[a-z0-9_]+',
                              self.DASH.read_text()))
        self.assertTrue(used, 'dashboard references no metrics?')
        missing = used - exported
        self.assertFalse(
            missing,
            f'dashboard queries metrics the exposition never emits: {missing}')

    def test_panels_have_datasource_and_targets(self):
        d = self._dashboard()
        for p in d['panels']:
            if p.get('type') == 'row':
                continue
            self.assertTrue(p.get('targets'), f'panel {p["title"]}: no targets')
            for t in p['targets']:
                self.assertEqual(t['datasource']['uid'], '${DS_PROMETHEUS}',
                                 f'panel {p["title"]}: hard-wired datasource')

    def test_docs_link_the_dashboard(self):
        self.assertIn('contrib/grafana', (ROOT / 'docs' / 'README.md').read_text())
        self.assertIn('contrib/grafana',
                      (ROOT / 'server' / 'html' / 'index.html').read_text())


class TestHttpMonitorAssertions(_HandlerBase):
    """W1-12: HTTP monitor regex body match + JSON dot-path assertions."""

    # -- pure helper -------------------------------------------------------
    def test_json_path_walk(self):
        doc = {'status': {'healthy': True, 'n': 0},
               'items': [{'state': 'ok'}, {'state': 'bad'}]}
        self.assertEqual(api._monitor_json_path(doc, 'status.healthy'),
                         (True, True))
        self.assertEqual(api._monitor_json_path(doc, 'items.1.state'),
                         (True, 'bad'))
        # "found but null/zero" is distinct from "missing"
        self.assertEqual(api._monitor_json_path(doc, 'status.n'), (True, 0))
        self.assertEqual(api._monitor_json_path(doc, 'status.nope'),
                         (False, None))
        self.assertEqual(api._monitor_json_path(doc, 'items.9.state'),
                         (False, None))
        self.assertEqual(api._monitor_json_path([], '0'), (False, None))

    # -- save-side validation ---------------------------------------------
    def _save_monitors(self, monitors):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'monitors': monitors}
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        return (api.load(api.CONFIG_FILE) or {}).get('monitors') or []

    def test_regex_mode_stored(self):
        mons = self._save_monitors([
            {'type': 'http', 'target': 'https://example.com', 'label': 'web',
             'body_match': {'mode': 'regex', 'value': r'build [0-9]+'}}])
        self.assertEqual(mons[0]['body_match'],
                         {'mode': 'regex', 'value': r'build [0-9]+'})

    def test_invalid_regex_rejected_at_save(self):
        self._save_monitors([
            {'type': 'http', 'target': 'https://example.com', 'label': 'web',
             'body_match': {'mode': 'regex', 'value': '(unclosed'}}])
        self.assertEqual(self.cap['s'], 400)

    def test_expect_json_sanitized_and_stored(self):
        mons = self._save_monitors([
            {'type': 'http', 'target': 'https://example.com', 'label': 'web',
             'expect_json': {'path': ' status.healthy!$() ',
                             'value': 'true'}}])
        self.assertEqual(mons[0]['expect_json'],
                         {'path': 'status.healthy', 'value': 'true'})
        # value omitted → existence-only assertion, no value key stored
        mons = self._save_monitors([
            {'type': 'http', 'target': 'https://example.com', 'label': 'web',
             'expect_json': {'path': 'status'}}])
        self.assertEqual(mons[0]['expect_json'], {'path': 'status'})

    # -- evaluator end-to-end against a local HTTP server ------------------
    def _serve(self, payload):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = payload.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_HEAD = do_GET

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f'http://127.0.0.1:{srv.server_port}/'

    def _probe(self, url, m):
        api.save(api.CONFIG_FILE, {'allow_internal_monitors': True})
        api._invalidate_load_cache(api.CONFIG_FILE)
        return api._run_one_monitor_check('http', url, m.get('label', 't'), m)

    def test_probe_regex_and_json(self):
        url = self._serve('{"status": {"healthy": true}, "build": "build 42"}')
        r = self._probe(url, {'body_match': {'mode': 'regex',
                                             'value': r'build [0-9]+'}})
        self.assertTrue(r['ok'], r)
        r = self._probe(url, {'body_match': {'mode': 'regex',
                                             'value': r'build [a-f]+x'}})
        self.assertFalse(r['ok'], r)
        r = self._probe(url, {'expect_json': {'path': 'status.healthy',
                                              'value': 'true'}})
        self.assertTrue(r['ok'], r)
        r = self._probe(url, {'expect_json': {'path': 'status.healthy',
                                              'value': 'false'}})
        self.assertFalse(r['ok'], r)
        r = self._probe(url, {'expect_json': {'path': 'status.missing'}})
        self.assertFalse(r['ok'], r)
        self.assertIn('missing', r['detail'])
        r = self._probe(url, {'expect_json': {'path': 'status'}})
        self.assertTrue(r['ok'], r)  # existence-only

    def test_probe_non_json_body(self):
        url = self._serve('<html>hello</html>')
        r = self._probe(url, {'expect_json': {'path': 'status'}})
        self.assertFalse(r['ok'], r)
        self.assertIn('not JSON', r['detail'])


class TestCannedTicketReplies(_HandlerBase):
    """W1-26: GET/POST /api/tickets/templates (canned replies)."""

    def _post(self, templates):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'templates': templates}
        return self.call(api.handle_ticket_templates)

    def _get(self):
        api.method = lambda: 'GET'
        return self.call(api.handle_ticket_templates)

    def test_disabled_404(self):
        api.save(api.CONFIG_FILE, {'tickets_enabled': False})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self._get()
        self.assertEqual(self.cap['s'], 404)

    def test_roundtrip_sanitize_and_cap(self):
        api.save(api.CONFIG_FILE, {'tickets_enabled': True})
        api._invalidate_load_cache(api.CONFIG_FILE)
        r = self._post([
            {'name': '  Resolved — confirm  ', 'body': 'Hi,\n\nwe believe {ticket_id} is resolved.'},
            {'name': '', 'body': 'nameless is dropped'},
            {'name': 'empty body dropped', 'body': '   '},
            'not-a-dict-is-dropped',
        ])
        self.assertEqual(self.cap['s'], 200)
        self.assertEqual(len(r['templates']), 1)
        self.assertEqual(r['templates'][0]['name'], 'Resolved — confirm')
        self.assertIn('{ticket_id}', r['templates'][0]['body'])
        # newlines survive in the body (multi-line snippets)
        self.assertIn('\n', r['templates'][0]['body'])
        api._invalidate_load_cache(api.CONFIG_FILE)
        g = self._get()
        self.assertEqual(g['templates'], r['templates'])

    def test_list_required_and_size_caps(self):
        api.save(api.CONFIG_FILE, {'tickets_enabled': True})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self._post('nope')
        self.assertEqual(self.cap['s'], 400)
        r = self._post([{'name': f'n{i}', 'body': 'b'} for i in range(80)])
        self.assertEqual(len(r['templates']), 50)   # hard cap
        r = self._post([{'name': 'x' * 500, 'body': 'y' * 9000}])
        self.assertLessEqual(len(r['templates'][0]['name']), 80)
        self.assertLessEqual(len(r['templates'][0]['body']), 4000)

    def test_route_registered(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route('GET', '/api/tickets/templates')[0],
                         'handle_ticket_templates')
        self.assertEqual(resolve_route('POST', '/api/tickets/templates')[0],
                         'handle_ticket_templates')


class TestCtWatch(_HandlerBase):
    """W1-17: certificate-transparency watch (crt.sh poller + event)."""

    def setUp(self):
        super().setUp()
        self._ctf = api.CT_WATCH_FILE
        api.CT_WATCH_FILE = self.d / 'ct_watch.json'
        self._fetch = api._ct_fetch_domain
        self.fired = []
        api.fire_webhook = lambda ev, p: self.fired.append((ev, p))

    def tearDown(self):
        api.CT_WATCH_FILE = self._ctf
        api._ct_fetch_domain = self._fetch
        super().tearDown()

    def _set_domains(self, domains):
        api.save(api.CONFIG_FILE, {'ct_watch_domains': domains})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _age_state(self):
        """Make every domain due again (cadence gate is 6h)."""
        st = api.load(api.CT_WATCH_FILE) or {}
        for d in st:
            st[d]['last_check'] = 0
        api.save(api.CT_WATCH_FILE, st)
        api._invalidate_load_cache(api.CT_WATCH_FILE)

    def test_baseline_then_alert_on_new_cert(self):
        self._set_domains(['example.com'])
        certs = [{'id': '1', 'serial': 'aa', 'issuer': "C=US, O=Let's Encrypt",
                  'cn': 'example.com', 'not_before': '2026-01-01'}]
        api._ct_fetch_domain = lambda d: list(certs)
        api.run_ct_watch_if_due()
        self.assertEqual(self.fired, [])          # first poll baselines silently
        st = api.load(api.CT_WATCH_FILE)['example.com']
        self.assertTrue(st['baselined'])
        self.assertIn('1', st['seen'])
        # second poll: same cert (no event) + one NEW cert (event)
        certs.append({'id': '2', 'serial': 'bb', 'issuer': 'C=XX, O=EvilCA',
                      'cn': 'example.com', 'not_before': '2026-07-01'})
        self._age_state()
        api.run_ct_watch_if_due()
        self.assertEqual(len(self.fired), 1)
        ev, p = self.fired[0]
        self.assertEqual(ev, 'ct_new_certificate')
        self.assertEqual(p['domain'], 'example.com')
        self.assertEqual(p['issuer'], 'C=XX, O=EvilCA')
        # third poll: nothing new → nothing fired
        self.fired.clear()
        self._age_state()
        api.run_ct_watch_if_due()
        self.assertEqual(self.fired, [])

    def test_circuit_breaker_backs_off(self):
        self._set_domains(['down.example'])

        def boom(d):
            raise OSError('crt.sh timeout')
        api._ct_fetch_domain = boom
        for _ in range(api.CT_FAIL_BACKOFF):
            self._age_state()
            api.run_ct_watch_if_due()
        st = api.load(api.CT_WATCH_FILE)['down.example']
        self.assertEqual(st['fail_streak'], api.CT_FAIL_BACKOFF)
        # circuit open: last_check is recent → skipped entirely (fetch not called)
        calls = []
        api._ct_fetch_domain = lambda d: calls.append(d) or []
        st['last_check'] = int(__import__('time').time()) - api.CT_SCAN_INTERVAL - 1
        api.save(api.CT_WATCH_FILE, {'down.example': st})
        api._invalidate_load_cache(api.CT_WATCH_FILE)
        api.run_ct_watch_if_due()
        self.assertEqual(calls, [])

    def test_event_storm_capped(self):
        self._set_domains(['big.example'])
        api._ct_fetch_domain = lambda d: [
            {'id': str(i), 'serial': f's{i}', 'issuer': 'X', 'cn': 'big.example',
             'not_before': ''} for i in range(1)]
        api.run_ct_watch_if_due()          # baseline
        api._ct_fetch_domain = lambda d: [
            {'id': str(i), 'serial': f's{i}', 'issuer': 'X', 'cn': 'big.example',
             'not_before': ''} for i in range(200)]
        self._age_state()
        api.run_ct_watch_if_due()
        self.assertEqual(len(self.fired), api.CT_MAX_EVENTS_PER_RUN)
        # everything is still marked seen — capping events must not re-alert later
        self.fired.clear()
        self._age_state()
        api.run_ct_watch_if_due()
        self.assertEqual(self.fired, [])

    def test_config_save_sanitizes_domains(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'ct_watch_domains': [
            ' Example.COM ', 'bad host!.com', 'no-dot', 'example.com', 'ok.example.org']}
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        api._invalidate_load_cache(api.CONFIG_FILE)
        doms = (api.load(api.CONFIG_FILE) or {}).get('ct_watch_domains')
        self.assertEqual(doms, ['example.com', 'badhost.com', 'ok.example.org'])

    def test_registry_entry_and_frontend_wiring(self):
        self.assertIn('ct_new_certificate', api.EVENT_REGISTRY)
        appjs = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("'ct_new_certificate'", appjs)
        self.assertIn("case 'ct_new_certificate'", appjs)


class TestEnrolPlacementRules(_HandlerBase):
    """W1-9: _apply_enrol_rules + config-save validation."""

    def _rules(self, rules):
        api.save(api.CONFIG_FILE, {'enrol_rules': rules})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def test_no_rules_is_noop(self):
        self._rules([])
        self.assertEqual(api._apply_enrol_rules('web-1', '10.0.0.5', '', []),
                         ('', [], ''))

    def test_hostname_regex_match(self):
        self._rules([{'match_type': 'hostname', 'pattern': '^web-',
                      'group': 'frontend', 'site': 'dc1', 'tags': ['nginx']}])
        g, t, s = api._apply_enrol_rules('web-01', '', '', [])
        self.assertEqual((g, s), ('frontend', 'dc1'))
        self.assertEqual(t, ['nginx'])
        # non-match leaves inputs untouched
        self.assertEqual(api._apply_enrol_rules('db-01', '', '', []), ('', [], ''))

    def test_cidr_match(self):
        self._rules([{'match_type': 'cidr', 'pattern': '10.20.0.0/16',
                      'group': 'branch'}])
        g, t, s = api._apply_enrol_rules('anything', '10.20.5.9', '', [])
        self.assertEqual(g, 'branch')
        self.assertEqual(api._apply_enrol_rules('x', '192.168.1.1', '', [])[0], '')

    def test_token_defaults_win(self):
        self._rules([{'match_type': 'hostname', 'pattern': '.', 'group': 'ruleg',
                      'tags': ['ruletag']}])
        # token already set group=tokeng, tags=[tokentag]: rule must NOT override
        # the group, but DOES merge its tag
        g, t, s = api._apply_enrol_rules('h', '', 'tokeng', ['tokentag'])
        self.assertEqual(g, 'tokeng')
        self.assertEqual(sorted(t), ['ruletag', 'tokentag'])

    def test_first_match_wins(self):
        self._rules([
            {'match_type': 'hostname', 'pattern': 'prod', 'group': 'first'},
            {'match_type': 'hostname', 'pattern': 'prod', 'group': 'second'}])
        self.assertEqual(api._apply_enrol_rules('prod-1', '', '', [])[0], 'first')

    def test_malformed_rule_skipped_not_raised(self):
        # a bad stored regex must never break enrolment
        api.save(api.CONFIG_FILE, {'enrol_rules': [
            {'match_type': 'hostname', 'pattern': '(unclosed', 'group': 'g'},
            {'match_type': 'hostname', 'pattern': 'ok', 'group': 'good'}]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(api._apply_enrol_rules('ok-host', '', '', [])[0], 'good')

    def test_config_save_validates_regex_and_cidr(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'enrol_rules': [
            {'match_type': 'hostname', 'pattern': '(bad'}]}
        self.call(api.handle_config_save)
        self.assertEqual(self.cap['s'], 400)
        api.get_json_body = lambda: {'enrol_rules': [
            {'match_type': 'cidr', 'pattern': 'not-a-cidr'}]}
        self.call(api.handle_config_save)
        self.assertEqual(self.cap['s'], 400)

    def test_config_save_keeps_valid_rules(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'enrol_rules': [
            {'match_type': 'hostname', 'pattern': '^web', 'group': 'g', 'tags': ['a', 'b']},
            {'match_type': 'cidr', 'pattern': '10.0.0.0/8', 'site': 's'},
            'garbage-dropped',
            {'match_type': 'bogus', 'pattern': 'x'}]}
        self.call(api.handle_config_save)
        rules = (api.load(api.CONFIG_FILE) or {}).get('enrol_rules')
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]['tags'], ['a', 'b'])


class TestAlertKbRunbookLink(_HandlerBase):
    """W1-23: _annotate_alert_kb + config-save validation."""

    def setUp(self):
        super().setUp()
        self._kbf = api.KB_FILE
        api.KB_FILE = self.d / 'kb.json'
        api.save(api.KB_FILE, {'articles': [
            {'id': 'kb_a', 'title': 'Disk full runbook'},
            {'id': 'kb_b', 'title': 'Service down runbook'}]})

    def tearDown(self):
        api.KB_FILE = self._kbf
        super().tearDown()

    def _cfg(self, mapping, kb_on=True):
        api.save(api.CONFIG_FILE, {'kb_enabled': kb_on, 'alert_runbooks': mapping})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def test_maps_event_to_article(self):
        self._cfg({'metric_critical': 'kb_a'})
        alerts = [{'id': '1', 'event': 'metric_critical', 'payload': {}}]
        api._annotate_alert_kb(alerts)
        self.assertEqual(alerts[0]['kb_link'], {'id': 'kb_a', 'title': 'Disk full runbook'})

    def test_maps_custom_check_by_id(self):
        self._cfg({'check:cid9': 'kb_b'})
        alerts = [{'id': '1', 'event': 'custom_check_failed',
                   'payload': {'check_id': 'cid9'}}]
        api._annotate_alert_kb(alerts)
        self.assertEqual(alerts[0]['kb_link']['id'], 'kb_b')

    def test_no_map_no_link(self):
        self._cfg({})
        alerts = [{'id': '1', 'event': 'metric_critical', 'payload': {}}]
        api._annotate_alert_kb(alerts)
        self.assertNotIn('kb_link', alerts[0])

    def test_disabled_kb_no_link(self):
        self._cfg({'metric_critical': 'kb_a'}, kb_on=False)
        alerts = [{'id': '1', 'event': 'metric_critical', 'payload': {}}]
        api._annotate_alert_kb(alerts)
        self.assertNotIn('kb_link', alerts[0])

    def test_stale_article_id_ignored(self):
        self._cfg({'metric_critical': 'kb_gone'})
        alerts = [{'id': '1', 'event': 'metric_critical', 'payload': {}}]
        api._annotate_alert_kb(alerts)
        self.assertNotIn('kb_link', alerts[0])

    def test_config_save_validates_and_cleans(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'alert_runbooks': 'nope'}
        self.call(api.handle_config_save)
        self.assertEqual(self.cap['s'], 400)
        api.get_json_body = lambda: {'alert_runbooks': {
            'metric_critical': 'kb_a', 'blank': '', '': 'kb_b'}}
        self.call(api.handle_config_save)
        saved = (api.load(api.CONFIG_FILE) or {}).get('alert_runbooks')
        self.assertEqual(saved, {'metric_critical': 'kb_a'})


if __name__ == '__main__':
    unittest.main()
