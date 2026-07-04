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


class TestRecurringTickets(_HandlerBase):
    """W1-27: ticket schedules handler + cadence sweep."""

    def setUp(self):
        super().setUp()
        self._tf = api.TICKETS_FILE
        self._sf = api.TICKET_SCHED_STATE_FILE
        api.TICKETS_FILE = self.d / 'tickets.json'
        api.TICKET_SCHED_STATE_FILE = self.d / 'ticket_sched_state.json'
        api.save(api.CONFIG_FILE, {'tickets_enabled': True})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def tearDown(self):
        api.TICKETS_FILE = self._tf
        api.TICKET_SCHED_STATE_FILE = self._sf
        super().tearDown()

    def _save_scheds(self, scheds):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'schedules': scheds}
        self.call(api.handle_ticket_schedules)
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _tickets(self):
        return (api.load(api.TICKETS_FILE) or {}).get('tickets') or []

    def test_save_validates_cron(self):
        self._save_scheds([{'subject': 'x', 'cron': 'not a cron'}])
        self.assertEqual(self.cap['s'], 400)

    def test_save_and_list(self):
        self._save_scheds([{'subject': 'Restore drill', 'cron': '0 9 1 * *',
                            'priority': 3, 'body': 'do it'}])
        api.method = lambda: 'GET'
        r = self.call(api.handle_ticket_schedules)
        self.assertEqual(len(r['schedules']), 1)
        self.assertEqual(r['schedules'][0]['subject'], 'Restore drill')
        self.assertTrue(r['schedules'][0]['id'])

    def test_sweep_creates_and_dedups(self):
        # a cron that matches "every minute" so it fires on any timestamp
        self._save_scheds([{'subject': 'Chore', 'cron': '* * * * *',
                            'priority': 4}])
        _real = api.time.time
        api.time.time = lambda: 1_800_000_000  # fixed minute
        try:
            api.run_ticket_schedules_if_due()
            self.assertEqual(len(self._tickets()), 1)
            t = self._tickets()[0]
            self.assertEqual(t['subject'], 'Chore')
            self.assertEqual(t['created_by'], 'schedule')
            # same minute again → no duplicate
            api.run_ticket_schedules_if_due()
            self.assertEqual(len(self._tickets()), 1)
            # next minute → fires again
            api.time.time = lambda: 1_800_000_060
            api.run_ticket_schedules_if_due()
            self.assertEqual(len(self._tickets()), 2)
        finally:
            api.time.time = _real

    def test_disabled_schedule_skipped(self):
        self._save_scheds([{'subject': 'Off', 'cron': '* * * * *',
                            'enabled': False}])
        _real = api.time.time
        api.time.time = lambda: 1_800_000_000
        try:
            api.run_ticket_schedules_if_due()
            self.assertEqual(self._tickets(), [])
        finally:
            api.time.time = _real

    def test_body_becomes_first_note(self):
        self._save_scheds([{'subject': 'C', 'cron': '* * * * *', 'body': 'checklist'}])
        _real = api.time.time
        api.time.time = lambda: 1_800_000_000
        try:
            api.run_ticket_schedules_if_due()
            msgs = self._tickets()[0]['messages']
            self.assertEqual(msgs[0]['body'], 'checklist')
        finally:
            api.time.time = _real


class TestInvoiceEmail(_HandlerBase):
    """W1-30: invoice send handler + overdue reminder sweep."""

    def setUp(self):
        super().setUp()
        self._inv = api.INVOICES_FILE
        self._bill = api.BILLING_FILE
        self._sites = api.SITES_FILE
        self._remstate = api.INVOICE_REMINDER_STATE_FILE
        api.INVOICES_FILE = self.d / 'invoices.json'
        api.BILLING_FILE = self.d / 'billing.json'
        api.SITES_FILE = self.d / 'sites.json'
        api.INVOICE_REMINDER_STATE_FILE = self.d / 'inv_rem.json'
        api.save(api.CONFIG_FILE, {'billing_enabled': True, 'smtp_host': 'smtp.test'})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.save(api.SITES_FILE, {'site1': {'name': 'ACME Inc'}})
        api.save(api.BILLING_FILE, {'sites': {'site1': {
            'billing_contact': 'ap@acme.example'}}})
        api.save(api.INVOICES_FILE, {'invoices': [{
            'id': 'inv_1', 'number': 'INV-00001', 'site_id': 'site1',
            'status': 'draft', 'currency': 'USD', 'vat_rate': 0,
            'subtotal': 100, 'vat_amount': 0, 'total': 100,
            'line_items': [{'label': 'Consulting', 'amount': 100}],
            'period': {'from': '2026-06-01', 'to': '2026-06-30'}}]})
        # capture sends
        self.sent = []
        self._real_send = api.smtp_notifier.send_email
        api.smtp_notifier.send_email = lambda cfg, rcpts, subj, body, **kw: (
            self.sent.append({'to': rcpts, 'subject': subj, 'body': body}) or {'ok': True})

    def tearDown(self):
        api.smtp_notifier.send_email = self._real_send
        api.INVOICES_FILE = self._inv
        api.BILLING_FILE = self._bill
        api.SITES_FILE = self._sites
        api.INVOICE_REMINDER_STATE_FILE = self._remstate
        super().tearDown()

    def _invoice(self):
        return (api.load(api.INVOICES_FILE) or {}).get('invoices')[0]

    def test_send_emails_contact_and_marks_sent(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {}
        self.call(api.handle_invoice_send, 'inv_1')
        self.assertEqual(self.cap['s'] if 's' in self.cap else 200, 200)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]['to'], ['ap@acme.example'])
        self.assertIn('INV-00001', self.sent[0]['subject'])
        self.assertEqual(self._invoice()['status'], 'sent')
        self.assertTrue(self._invoice().get('last_emailed_at'))

    def test_send_no_contact_400(self):
        api.save(api.BILLING_FILE, {'sites': {'site1': {}}})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {}
        self.call(api.handle_invoice_send, 'inv_1')
        self.assertEqual(self.cap['s'], 400)
        self.assertEqual(self.sent, [])

    def test_reminder_sweep_opt_in_and_bounded(self):
        # reminders off → nothing
        now = int(__import__('time').time())
        api.save(api.INVOICES_FILE, {'invoices': [{
            'id': 'inv_1', 'number': 'INV-1', 'site_id': 'site1', 'status': 'sent',
            'currency': 'USD', 'subtotal': 10, 'total': 10, 'line_items': [],
            'last_emailed_at': now - 40 * 86400}]})
        api.save(api.BILLING_FILE, {'sites': {'site1': {'billing_contact': 'ap@acme.example'}},
                                    'reminders_enabled': False})
        api.run_invoice_reminders_if_due()
        self.assertEqual(self.sent, [])
        # turn on → one reminder, and it doesn't re-send next sweep
        api.save(api.BILLING_FILE, {'sites': {'site1': {'billing_contact': 'ap@acme.example'}},
                                    'reminders_enabled': True, 'reminder_days': 14})
        api.save(api.INVOICE_REMINDER_STATE_FILE, {'last_run': 0})
        api.run_invoice_reminders_if_due()
        self.assertEqual(len(self.sent), 1)
        self.assertIn('Reminder', self.sent[0]['subject'])
        self.assertTrue(self._invoice().get('reminder_sent'))
        # sweep again immediately — cadence gate blocks, still 1
        api.run_invoice_reminders_if_due()
        self.assertEqual(len(self.sent), 1)

    def test_reminder_skips_paid_and_recent(self):
        now = int(__import__('time').time())
        api.save(api.INVOICES_FILE, {'invoices': [
            {'id': 'p', 'site_id': 'site1', 'status': 'paid', 'total': 5,
             'line_items': [], 'last_emailed_at': now - 90 * 86400},
            {'id': 'r', 'site_id': 'site1', 'status': 'sent', 'total': 5,
             'line_items': [], 'last_emailed_at': now - 2 * 86400}]})
        api.save(api.BILLING_FILE, {'sites': {'site1': {'billing_contact': 'ap@acme.example'}},
                                    'reminders_enabled': True, 'reminder_days': 14})
        api.save(api.INVOICE_REMINDER_STATE_FILE, {'last_run': 0})
        api.run_invoice_reminders_if_due()
        self.assertEqual(self.sent, [])   # paid excluded, recent not yet due


class TestTicketCsat(_HandlerBase):
    """W1-31: CSAT survey signing, public rating endpoint, resolve dispatch."""

    def setUp(self):
        super().setUp()
        self._tf = api.TICKETS_FILE
        api.TICKETS_FILE = self.d / 'tickets.json'
        api.save(api.CONFIG_FILE, {'tickets_enabled': True, 'ticket_csat_enabled': True,
                                   'smtp_host': 'smtp.test'})
        api._invalidate_load_cache(api.CONFIG_FILE)
        # capture the rendered CSAT page instead of exiting the process
        self.pages = []
        self._real_page = api.tickets_handlers_mod._csat_page
        self._real_send = api.smtp_notifier.send_email
        self._real_base = api._request_base_url
        self._real_wr = api.require_write_role

        def _fake_page(title, msg):
            self.pages.append((title, msg))
            raise api.HTTPError(200, None)   # unwind like respond() does
        api.tickets_handlers_mod._csat_page = _fake_page

    def tearDown(self):
        api.tickets_handlers_mod._csat_page = self._real_page
        api.smtp_notifier.send_email = self._real_send
        api._request_base_url = self._real_base
        api.require_write_role = self._real_wr
        api.TICKETS_FILE = self._tf
        super().tearDown()

    def _ticket(self, **extra):
        t = {'id': 'tk_1', 'number': 900001, 'subject': 'S', 'status': 'ongoing',
             'to_email': 'user@example.com', 'messages': []}
        t.update(extra)
        api.save(api.TICKETS_FILE, {'tickets': [t]})

    def test_sig_binds_ticket_and_rating(self):
        s_good = api._csat_sig('tk_1', 'good')
        s_bad = api._csat_sig('tk_1', 'bad')
        self.assertNotEqual(s_good, s_bad)
        self.assertEqual(s_good, api._csat_sig('tk_1', 'good'))     # deterministic
        self.assertNotEqual(s_good, api._csat_sig('tk_2', 'good'))  # per-ticket

    def _hit_csat(self, tid, rating, sig):
        import os as _os
        _os.environ['QUERY_STRING'] = f't={tid}&r={rating}&s={sig}'
        api.method = lambda: 'GET'
        self.call(api.handle_ticket_csat)

    def test_valid_click_stores_rating_once(self):
        self._ticket()
        self._hit_csat('tk_1', 'good', api._csat_sig('tk_1', 'good'))
        t = (api.load(api.TICKETS_FILE) or {}).get('tickets')[0]
        self.assertEqual(t['csat']['rating'], 'good')
        self.assertEqual(t['csat']['score'], 5)
        self.assertIn('Thank you', self.pages[-1][0])
        # second click → already recorded, rating unchanged
        self._hit_csat('tk_1', 'bad', api._csat_sig('tk_1', 'bad'))
        t = (api.load(api.TICKETS_FILE) or {}).get('tickets')[0]
        self.assertEqual(t['csat']['rating'], 'good')
        self.assertIn('Already', self.pages[-1][0])

    def test_bad_signature_rejected(self):
        self._ticket()
        self._hit_csat('tk_1', 'good', 'deadbeef')
        t = (api.load(api.TICKETS_FILE) or {}).get('tickets')[0]
        self.assertNotIn('csat', t)
        self.assertIn('Invalid', self.pages[-1][0])

    def test_resolve_sends_survey_once(self):
        self._ticket()
        sent = []
        api.smtp_notifier.send_email = lambda cfg, r, s, b, **k: sent.append((r, s, b))
        api._request_base_url = lambda env: 'https://rp.test'
        api.require_write_role = lambda *a, **k: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'status': 'resolved'}
        try:
            self.call(api.handle_ticket_update, 'tk_1')
        except Exception:
            pass
        self.assertEqual(len(sent), 1)
        # the email carries the three signed rating links
        body = sent[0][2]
        self.assertIn('r=good', body)
        self.assertIn('r=bad', body)
        self.assertIn(api._csat_sig('tk_1', 'good'), body)
        t = (api.load(api.TICKETS_FILE) or {}).get('tickets')[0]
        self.assertTrue(t.get('csat_sent'))

    def test_csat_exempt_from_ip_allowlist(self):
        self.assertIn('/api/tickets/csat', api._IP_ALLOWLIST_EXEMPT_PATHS)


class TestAlertEmailAckLinks(_HandlerBase):
    """W1-21: signed one-click alert ack/resolve email links + public endpoint."""

    def setUp(self):
        super().setUp()
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'a-1', 'event': 'metric_critical', 'device_id': 'd1',
             'payload': {'device_id': 'd1', 'metric': 'disk'}}]})
        self.pages = []
        self._real_page = api._public_action_page

        def _fake(title, msg):
            self.pages.append((title, msg))
            raise api.HTTPError(200, None)
        api._public_action_page = _fake

    def tearDown(self):
        api._public_action_page = self._real_page
        super().tearDown()

    def _alert(self):
        return (api.load(api.ALERTS_FILE) or {}).get('alerts')[0]

    def _hit(self, a, op, sig):
        import os as _os
        _os.environ['QUERY_STRING'] = f'a={a}&op={op}&s={sig}'
        api.method = lambda: 'GET'
        self.call(api.handle_alert_act)

    def test_sig_binds_id_and_op(self):
        s_ack = api._alert_act_sig('a-1', 'ack')
        self.assertNotEqual(s_ack, api._alert_act_sig('a-1', 'resolve'))
        self.assertNotEqual(s_ack, api._alert_act_sig('a-2', 'ack'))
        self.assertEqual(s_ack, api._alert_act_sig('a-1', 'ack'))

    def test_ack_via_link(self):
        self._hit('a-1', 'ack', api._alert_act_sig('a-1', 'ack'))
        self.assertEqual(self._alert()['acknowledged_by'], 'email-link')
        self.assertIn('acknowledged', self.pages[-1][1].lower())

    def test_resolve_via_link_implies_ack(self):
        self._hit('a-1', 'resolve', api._alert_act_sig('a-1', 'resolve'))
        a = self._alert()
        self.assertTrue(a['resolved_at'])
        self.assertTrue(a['acknowledged_at'])   # resolve implies ack

    def test_bad_sig_rejected(self):
        self._hit('a-1', 'ack', 'deadbeef')
        self.assertIsNone(self._alert().get('acknowledged_at'))
        self.assertIn('Invalid', self.pages[-1][0])

    def test_bad_op_rejected(self):
        self._hit('a-1', 'delete', api._alert_act_sig('a-1', 'delete'))
        self.assertIn('Invalid', self.pages[-1][0])

    def test_ack_block_appended_only_when_enabled(self):
        import os as _os
        _os.environ['HTTP_HOST'] = 'rp.example.com'
        # disabled → no block
        self.assertEqual(api._alert_email_ack_block(
            'metric_critical', {'device_id': 'd1', 'metric': 'disk'},
            {'alert_email_ack_links': False}), '')
        # enabled → finds the open alert + emits both links
        block = api._alert_email_ack_block(
            'metric_critical', {'device_id': 'd1', 'metric': 'disk'},
            {'alert_email_ack_links': True})
        self.assertIn('op=ack', block)
        self.assertIn('op=resolve', block)
        self.assertIn(api._alert_act_sig('a-1', 'ack'), block)

    def test_exempt_from_ip_allowlist(self):
        self.assertIn('/api/alerts/act', api._IP_ALLOWLIST_EXEMPT_PATHS)


class TestPatchSla(_HandlerBase):
    """W1-33: patch-compliance SLA eval + sweep + config validation."""

    def setUp(self):
        super().setUp()
        self._paf = api.PATCH_AGE_FILE
        api.PATCH_AGE_FILE = self.d / 'patch_age.json'
        self.fired = []
        api.fire_webhook = lambda ev, p: self.fired.append((ev, p))

    def tearDown(self):
        api.PATCH_AGE_FILE = self._paf
        super().tearDown()

    def _dev(self, upgradable=0, security=0, group='', tags=None):
        return {'name': 'h', 'group': group, 'tags': tags or [], 'monitored': True,
                'sysinfo': {'packages': {'upgradable': upgradable,
                                         'security_updates': security}}}

    def test_first_seen_stamped_and_cleared(self):
        devices = {'d1': self._dev(upgradable=5)}
        cfg = {'patch_sla': [{'match_type': 'all', 'all_days': 30}]}
        age = {}
        api._eval_patch_sla(devices, cfg, age, 1000)
        self.assertEqual(age['d1']['all_first'], 1000)
        # later, still pending → first_seen unchanged
        api._eval_patch_sla(devices, cfg, age, 5000)
        self.assertEqual(age['d1']['all_first'], 1000)
        # dropped to 0 → cleared
        devices['d1'] = self._dev(upgradable=0)
        api._eval_patch_sla(devices, cfg, age, 6000)
        self.assertNotIn('all_first', age['d1'])

    def test_breach_after_deadline(self):
        devices = {'d1': self._dev(security=2)}
        cfg = {'patch_sla': [{'match_type': 'all', 'sec_days': 7}]}
        age = {}
        now = 1_000_000
        rows, viol = api._eval_patch_sla(devices, cfg, age, now)
        self.assertEqual(viol, set())          # just seen, not overdue
        # 8 days later
        rows, viol = api._eval_patch_sla(devices, cfg, age, now + 8 * 86400)
        self.assertEqual(viol, {'d1'})
        self.assertTrue(rows[0]['breached'])
        self.assertIn('security', rows[0]['detail'])

    def test_group_and_tag_scoping(self):
        devices = {'d1': self._dev(upgradable=3, group='prod'),
                   'd2': self._dev(upgradable=3, group='dev')}
        cfg = {'patch_sla': [{'match_type': 'group', 'pattern': 'prod', 'all_days': 1}]}
        age = {'d1': {'all_first': 1}, 'd2': {'all_first': 1}}
        rows, viol = api._eval_patch_sla(devices, cfg, age, 10 * 86400)
        self.assertEqual(viol, {'d1'})         # only prod is in scope

    def test_sweep_edge_fires(self):
        api.save(api.DEVICES_FILE, {'d1': self._dev(security=1)})
        api.save(api.CONFIG_FILE, {'patch_sla': [{'match_type': 'all', 'sec_days': 1}]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        # seed an old first-seen so it's already overdue
        api.save(api.PATCH_AGE_FILE, {'d1': {'sec_first': 1}, '_last_run': 0})
        _real = api.time.time
        api.time.time = lambda: 10 * 86400
        try:
            api.run_patch_sla_if_due()
            self.assertTrue(any(e == 'patch_sla_violation' for e, _ in self.fired))
            # back in compliance → recover fires
            self.fired.clear()
            api.save(api.DEVICES_FILE, {'d1': self._dev(security=0)})
            api.save(api.PATCH_AGE_FILE, {'d1': {}, '_breaching': ['d1'], '_last_run': 0})
            api.run_patch_sla_if_due()
            self.assertTrue(any(e == 'patch_sla_ok' for e, _ in self.fired))
        finally:
            api.time.time = _real

    def test_config_validation(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'patch_sla': 'nope'}
        self.call(api.handle_config_save)
        self.assertEqual(self.cap['s'], 400)
        api.get_json_body = lambda: {'patch_sla': [
            {'match_type': 'all', 'sec_days': 7, 'all_days': 30},
            {'match_type': 'group', 'pattern': 'p', 'all_days': 5},
            {'match_type': 'all'},          # no days → dropped
            {'match_type': 'bogus', 'sec_days': 1}]}  # bad type → dropped
        self.call(api.handle_config_save)
        saved = (api.load(api.CONFIG_FILE) or {}).get('patch_sla')
        self.assertEqual(len(saved), 2)


class TestStatusIncidents(_HandlerBase):
    """W2-25: operator-posted status-page incidents."""

    def setUp(self):
        super().setUp()
        self._if = api.INCIDENTS_FILE
        api.INCIDENTS_FILE = self.d / 'incidents.json'

    def tearDown(self):
        api.INCIDENTS_FILE = self._if
        super().tearDown()

    def _post(self, **body):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: body
        return self.call(api.handle_incidents)

    def _seed(self):
        r = self._post(title='API latency', impact='major', status='investigating',
                       body='looking into it')
        return r['id']

    def test_create_and_list(self):
        self._seed()
        api.method = lambda: 'GET'
        lst = self.call(api.handle_incidents)
        self.assertEqual(len(lst['incidents']), 1)
        self.assertEqual(lst['incidents'][0]['title'], 'API latency')
        self.assertEqual(lst['incidents'][0]['updates'][0]['body'], 'looking into it')

    def test_title_required(self):
        self._post(title='   ')
        self.assertEqual(self.cap['s'], 400)

    def test_update_and_status_change(self):
        iid = self._seed()
        api.method = lambda: 'PATCH'
        api.get_json_body = lambda: {'status': 'resolved', 'body': 'fixed'}
        self.call(api.handle_incident_update, iid)
        inc = (api.load(api.INCIDENTS_FILE) or {}).get('incidents')[0]
        self.assertEqual(inc['status'], 'resolved')
        self.assertEqual(inc['updates'][-1]['body'], 'fixed')

    def test_invalid_status_rejected(self):
        iid = self._seed()
        api.method = lambda: 'PATCH'
        api.get_json_body = lambda: {'status': 'bogus'}
        self.call(api.handle_incident_update, iid)
        self.assertEqual(self.cap['s'], 400)

    def test_delete(self):
        iid = self._seed()
        api.method = lambda: 'DELETE'
        self.call(api.handle_incident_update, iid)
        self.assertEqual((api.load(api.INCIDENTS_FILE) or {}).get('incidents'), [])

    def test_public_projection_includes_open_incident(self):
        self._post(title='Down', impact='major', status='investigating', body='x')
        cfg = {'status_page': {'enabled': True, 'components': [], 'incident_days': 30}}
        now = int(__import__('time').time())
        proj = api._status_page_projection(cfg, {}, now, 60)
        self.assertTrue(proj)
        self.assertEqual(len(proj['posted_incidents']), 1)
        # an open major incident darkens the overall banner
        self.assertEqual(proj['overall'], 'major_outage')

    def test_public_projection_hides_old_resolved(self):
        now = int(__import__('time').time())
        api.save(api.INCIDENTS_FILE, {'incidents': [{
            'id': 'inc_x', 'title': 'old', 'impact': 'minor', 'status': 'resolved',
            'created_at': now - 90 * 86400, 'updated_at': now - 90 * 86400,
            'updates': []}]})
        cfg = {'status_page': {'enabled': True, 'components': [], 'incident_days': 30}}
        proj = api._status_page_projection(cfg, {}, now, 60)
        self.assertEqual(proj['posted_incidents'], [])

    def test_subscriber_notify_on_create(self):
        sent = []
        _real = api.smtp_notifier.send_email
        api.smtp_notifier.send_email = lambda cfg, r, s, b, **k: sent.append((r, s))
        try:
            api.save(api.CONFIG_FILE, {'smtp_host': 'smtp.test',
                                       'status_incident_recipients': 'a@b.co, c@d.co'})
            api._invalidate_load_cache(api.CONFIG_FILE)
            self._post(title='Boom', status='investigating', body='y')
            self.assertEqual(len(sent), 1)
            self.assertEqual(sorted(sent[0][0]), ['a@b.co', 'c@d.co'])
        finally:
            api.smtp_notifier.send_email = _real


class TestNotificationDigest(_HandlerBase):
    """W2-22: per-destination digest window queue + flush."""

    def setUp(self):
        super().setUp()
        self._df = api.WEBHOOK_DIGEST_FILE
        api.WEBHOOK_DIGEST_FILE = self.d / 'webhook_digest.json'
        self.sent = []
        self._real_dispatch = api._dispatch_one_webhook
        # record only the actual (flush) sends — non-digest path
        def _wrap(event, dest, payload, message, title, priority, allow_digest=True):
            if not allow_digest:
                self.sent.append({'event': event, 'title': title, 'message': message})
            else:
                return self._real_dispatch(event, dest, payload, message, title,
                                           priority, allow_digest=allow_digest)
        api._dispatch_one_webhook = _wrap

    def tearDown(self):
        api._dispatch_one_webhook = self._real_dispatch
        api.WEBHOOK_DIGEST_FILE = self._df
        super().tearDown()

    def _queue(self):
        return api.load(api.WEBHOOK_DIGEST_FILE) or {}

    def test_noncritical_queues_not_sends(self):
        dest = {'id': 'wh1', 'url': 'https://x.test', 'format': 'generic',
                'digest_minutes': 30}
        # priority 3 (non-critical) → queued
        api._dispatch_one_webhook('device_online', dest, {}, 'is up', 'Up', 3)
        self.assertEqual(self.sent, [])
        q = self._queue()
        self.assertEqual(len(q['wh1']['items']), 1)

    def test_critical_bypasses_digest(self):
        dest = {'id': 'wh1', 'url': 'https://x.test', 'format': 'generic',
                'digest_minutes': 30}
        # priority 5 (>= bypass) must NOT queue — goes through the real path
        # (which will try to send; we don't assert delivery, only that it wasn't queued)
        try:
            self._real_dispatch('device_offline', dest, {}, 'down', 'Down', 5)
        except Exception:
            pass
        self.assertNotIn('wh1', self._queue())

    def test_flush_when_window_elapsed(self):
        api.save(api.CONFIG_FILE, {'webhook_urls': [
            {'id': 'wh1', 'url': 'https://x.test', 'format': 'generic',
             'enabled': True, 'digest_minutes': 30}]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        # seed a queue whose first_ts is 31 min old
        now = int(__import__('time').time())
        api.save(api.WEBHOOK_DIGEST_FILE, {'wh1': {
            'first_ts': now - 31 * 60,
            'items': [{'event': 'device_online', 'title': 'A up', 'message': 'x', 'priority': 3},
                      {'event': 'monitor_up', 'title': 'B up', 'message': 'y', 'priority': 3}]}})
        api.run_webhook_digests_if_due()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]['event'], 'notification_digest')
        self.assertIn('2 notifications', self.sent[0]['title'])
        self.assertIn('A up', self.sent[0]['message'])
        self.assertEqual(self._queue(), {})   # flushed

    def test_flush_holds_when_not_due(self):
        api.save(api.CONFIG_FILE, {'webhook_urls': [
            {'id': 'wh1', 'url': 'https://x.test', 'format': 'generic',
             'enabled': True, 'digest_minutes': 30}]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        now = int(__import__('time').time())
        api.save(api.WEBHOOK_DIGEST_FILE, {'wh1': {
            'first_ts': now - 60, 'items': [{'event': 'x', 'title': 't', 'message': '', 'priority': 3}]}})
        api.run_webhook_digests_if_due()
        self.assertEqual(self.sent, [])
        self.assertIn('wh1', self._queue())   # still held

    def test_config_save_validates_digest_minutes(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'webhook_urls': [
            {'url': 'https://x.test', 'format': 'generic', 'digest_minutes': 60},
            {'url': 'https://y.test', 'format': 'generic', 'digest_minutes': 0}]}
        self.call(api.handle_config_save)
        urls = (api.load(api.CONFIG_FILE) or {}).get('webhook_urls')
        self.assertEqual(urls[0]['digest_minutes'], 60)
        self.assertNotIn('digest_minutes', urls[1])   # 0 = off, not stored


class TestBusinessHoursSla(_HandlerBase):
    """W2-29: business-hours SLA deadline computation."""

    # Mon–Fri 09:00–17:00 (540..1020 min), UTC.
    SPEC = {'enabled': True, 'tz_offset_min': 0,
            'weekly': {str(d): [[540, 1020]] for d in range(5)},
            'holidays': []}

    def _dt(self, s):
        from datetime import datetime, timezone
        return int(datetime.strptime(s, '%Y-%m-%d %H:%M').replace(
            tzinfo=timezone.utc).timestamp())

    def _iso(self, ts):
        from datetime import datetime, timezone
        return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M')

    def test_within_same_day(self):
        # Wed 2026-07-01 10:00 + 2 business hours = 12:00 same day
        start = self._dt('2026-07-01 10:00')
        due = api._business_deadline(start, 2 * 3600, self.SPEC)
        self.assertEqual(self._iso(due), '2026-07-01 12:00')

    def test_rolls_to_next_day(self):
        # Wed 16:00 + 2h: 1h today (→17:00) then 1h next morning → Thu 10:00
        start = self._dt('2026-07-01 16:00')
        due = api._business_deadline(start, 2 * 3600, self.SPEC)
        self.assertEqual(self._iso(due), '2026-07-02 10:00')

    def test_pauses_over_weekend(self):
        # Fri 2026-07-03 16:00 + 2h: 1h Fri (→17:00) then Mon 09:00–10:00
        start = self._dt('2026-07-03 16:00')
        due = api._business_deadline(start, 2 * 3600, self.SPEC)
        self.assertEqual(self._iso(due), '2026-07-06 10:00')

    def test_skips_holiday(self):
        spec = dict(self.SPEC, holidays=['2026-07-02'])
        # Wed 16:00 + 2h: 1h Wed, Thu is a holiday → Fri 09:00–10:00
        start = self._dt('2026-07-01 16:00')
        due = api._business_deadline(start, 2 * 3600, spec)
        self.assertEqual(self._iso(due), '2026-07-03 10:00')

    def test_start_before_open_waits_for_open(self):
        # Wed 07:00 (before 09:00) + 1h → opens 09:00, due 10:00
        start = self._dt('2026-07-01 07:00')
        due = api._business_deadline(start, 3600, self.SPEC)
        self.assertEqual(self._iso(due), '2026-07-01 10:00')

    def test_ticket_sla_uses_business_hours_when_enabled(self):
        api.save(api.CONFIG_FILE, {'ticket_business_hours': self.SPEC})
        api._invalidate_load_cache(api.CONFIG_FILE)
        t = {'priority': 3, 'created_at': self._dt('2026-07-03 16:00'), 'status': 'ongoing'}
        # P3 default is 24h in the SLA policy; with business hours it lands
        # well past a naive +24h wall-clock (which would be Sat)
        due, _ = api._ticket_sla(t, {3: 2})   # 2 business hours
        self.assertEqual(self._iso(due), '2026-07-06 10:00')

    def test_disabled_is_wall_clock(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        t = {'priority': 3, 'created_at': 1_000_000, 'status': 'ongoing'}
        due, _ = api._ticket_sla(t, {3: 5})
        self.assertEqual(due, 1_000_000 + 5 * 3600)


class TestCveCampaigns(_HandlerBase):
    """W2-35: CVE remediation campaigns + burn-down sweep."""

    def setUp(self):
        super().setUp()
        self._cf = api.CVE_CAMPAIGNS_FILE
        self._ff = api.CVE_FINDINGS_FILE
        self._if2 = api.CVE_IGNORE_FILE
        api.CVE_CAMPAIGNS_FILE = self.d / 'cve_campaigns.json'
        api.CVE_FINDINGS_FILE = self.d / 'cve_findings.json'
        api.CVE_IGNORE_FILE = self.d / 'cve_ignore.json'
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h1'}, 'd2': {'name': 'h2'}})
        api.save(api.CVE_FINDINGS_FILE, {
            'd1': {'findings': [{'cve_id': 'CVE-2026-1', 'severity': 'critical'},
                                {'cve_id': 'CVE-2026-2', 'severity': 'high'}]},
            'd2': {'findings': [{'cve_id': 'CVE-2026-9', 'severity': 'low'}]}})
        self.fired = []
        api.fire_webhook = lambda ev, p: self.fired.append((ev, p))

    def tearDown(self):
        api.CVE_CAMPAIGNS_FILE = self._cf
        api.CVE_FINDINGS_FILE = self._ff
        api.CVE_IGNORE_FILE = self._if2
        super().tearDown()

    def _create(self, **body):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: body
        return self.call(api.handle_cve_campaigns)

    def _list(self):
        api.method = lambda: 'GET'
        return self.call(api.handle_cve_campaigns)

    def test_severity_scoped_affected_count(self):
        self._create(name='crit cleanup', severities=['critical'])
        rows = self._list()['campaigns']
        self.assertEqual(len(rows), 1)
        # only d1 has a critical finding
        self.assertEqual(rows[0]['affected_hosts'], 1)
        self.assertEqual(rows[0]['finding_count'], 1)

    def test_explicit_cve_ids_override(self):
        self._create(name='two', cve_ids=['CVE-2026-2', 'CVE-2026-9'])
        rows = self._list()['campaigns']
        self.assertEqual(rows[0]['affected_hosts'], 2)   # d1 (high) + d2 (low)

    def test_name_required(self):
        self._create(name='')
        self.assertEqual(self.cap['s'], 400)

    def test_delete(self):
        self._create(name='x', severities=['critical'])
        cid = (api.load(api.CVE_CAMPAIGNS_FILE) or {}).get('campaigns')[0]['id']
        api.method = lambda: 'DELETE'
        self.call(api.handle_cve_campaign, cid)
        self.assertEqual((api.load(api.CVE_CAMPAIGNS_FILE) or {}).get('campaigns'), [])

    def test_sweep_samples_and_completes(self):
        self._create(name='crit', severities=['critical'])
        _real = api.time.time
        api.time.time = lambda: 1_000_000
        try:
            api.run_cve_campaign_sample_if_due()
            camp = (api.load(api.CVE_CAMPAIGNS_FILE) or {}).get('campaigns')[0]
            self.assertEqual(camp['samples'][-1]['affected'], 1)
            self.assertIsNone(camp['completed_at'])
            # remediate d1's critical → next daily sample completes it
            api.save(api.CVE_FINDINGS_FILE, {
                'd1': {'findings': [{'cve_id': 'CVE-2026-2', 'severity': 'high'}]},
                'd2': {'findings': []}})
            api.time.time = lambda: 1_000_000 + 25 * 3600
            api.run_cve_campaign_sample_if_due()
            camp = (api.load(api.CVE_CAMPAIGNS_FILE) or {}).get('campaigns')[0]
            self.assertTrue(camp['completed_at'])
            self.assertTrue(any(e == 'campaign_completed' for e, _ in self.fired))
        finally:
            api.time.time = _real

    def test_sweep_cadence_gate(self):
        self._create(name='crit', severities=['critical'])
        api.save(api.CVE_CAMPAIGNS_FILE, dict(
            api.load(api.CVE_CAMPAIGNS_FILE), _last_sample=10 ** 12))
        _real = api.time.time
        api.time.time = lambda: 10 ** 12 + 60   # < 24h since last
        try:
            api.run_cve_campaign_sample_if_due()
            camp = (api.load(api.CVE_CAMPAIGNS_FILE) or {}).get('campaigns')[0]
            self.assertEqual(camp.get('samples', []), [])   # not due → no sample
        finally:
            api.time.time = _real


if __name__ == '__main__':
    unittest.main()
