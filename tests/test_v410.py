#!/usr/bin/env python3
"""
Tests for v4.1.0 — "bind it together / perf / UX" accumulator.

This file holds feature/wiring tests for the v4.1.0 batch. The strict
version-surface pins (SERVER_VERSION == '4.1.0', ?v=, sw cache name, README
badge, docs/v4.1.0.md, "What's new" card) are added when the release is
actually cut; until then this file only covers behaviour.

Coverage so far:
  #54 — stable, monotonic, operator-facing alert id ('alertid_00001'),
        forwarded in the on_ack webhook payload.
"""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_v410", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import rag_index   # pure retrieval engine — corpus builders are unit-tested here


class _HandlerBase(unittest.TestCase):
    """Drive handlers directly with stubbed auth/request/respond."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'DEVICES_FILE',
                     'SECRETS_FILE', 'AUDIT_LOG_FILE', 'HISTORY_FILE', 'METRICS_FILE',
                     'CONTAINERS_FILE', 'HARDWARE_FILE', 'BRUTE_FORCE_FILE'):
            self._files[attr] = getattr(api, attr)
            base = Path(getattr(api, attr)).name
            setattr(api, attr, self.d / base)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', 'verify_token',
                       'get_token_from_request', 'audit_log', 'respond', 'method',
                       'get_json_body', '_check_alert_mutation_perm',
                       '_caller_scope', '_dispatch_one_webhook',
                       '_scope_filter_devices')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api.audit_log = lambda *a, **k: None
        api._caller_scope = lambda: None
        api._scope_filter_devices = lambda d: d
        api._check_alert_mutation_perm = lambda: 'jakob'

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


class TestStableAlertId(_HandlerBase):
    """#54: every alert gets a stable, monotonic, zero-padded `alertid`."""

    def test_record_alert_assigns_monotonic_alertid(self):
        a1 = api._record_alert('device_offline', {})
        a2 = api._record_alert('device_offline', {})
        self.assertIsNotNone(a1, "device_offline should produce an alert")
        self.assertIsNotNone(a2)
        self.assertEqual(a1['alertid'], 'alertid_00001')
        self.assertEqual(a2['alertid'], 'alertid_00002')
        # The random internal id stays the lookup key and is distinct.
        self.assertTrue(a1['id'].startswith('a-'))
        self.assertNotEqual(a1['id'], a1['alertid'])

    def test_alertid_zero_padded_five_digits(self):
        a = api._record_alert('device_offline', {})
        self.assertRegex(a['alertid'], r'^alertid_\d{5,}$')

    def test_counter_persisted_and_not_reused_after_trim(self):
        # Counter lives in the store and only ever grows, so ids survive the
        # MAX_ALERTS trim and are never reused.
        api._record_alert('device_offline', {})
        api._record_alert('device_offline', {})
        store = api.load(api.ALERTS_FILE)
        self.assertEqual(store.get('alert_seq'), 2)
        # Simulate a trimmed ledger: drop the rows but keep the counter.
        store['alerts'] = []
        api.save(api.ALERTS_FILE, store)
        a3 = api._record_alert('device_offline', {})
        self.assertEqual(a3['alertid'], 'alertid_00003')

    def test_ack_webhook_forwards_alertid(self):
        api.save(api.CONFIG_FILE, {'webhook_urls': [
            {'id': 'wh_t', 'url': 'https://t/x', 'format': 'generic',
             'enabled': True, 'on_ack': True, 'events': ['device_offline']},
        ]})
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'alertid': 'alertid_00042', 'ts': 1000,
            'event': 'device_offline', 'severity': 'high', 'title': 'host1 offline',
            'device_id': 'd1', 'device_name': 'host1', 'payload': {'unit': 'x'},
            'acknowledged_by': None, 'resolved_at': None}]})
        fired = []
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {}
        api._dispatch_one_webhook = (
            lambda ev, dest, payload, msg, title, prio: fired.append(payload))
        self.call(api.handle_alert_ack, 'a1')
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0]['alertid'], 'alertid_00042')
        # Backward-compatible internal id is still present.
        self.assertEqual(fired[0]['alert_id'], 'a1')


class TestBulkAck(_HandlerBase):
    """#53: acknowledge several alerts in one call."""

    def _seed(self):
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'a1', 'event': 'device_offline', 'severity': 'high',
             'acknowledged_at': None, 'resolved_at': None, 'device_id': None,
             'payload': {}},
            {'id': 'a2', 'event': 'device_offline', 'severity': 'low',
             'acknowledged_at': None, 'resolved_at': None, 'device_id': None,
             'payload': {}},
            {'id': 'a3', 'event': 'device_offline', 'severity': 'low',
             'acknowledged_at': 5, 'acknowledged_by': 'x', 'resolved_at': None,
             'device_id': None, 'payload': {}},
            {'id': 'a4', 'event': 'device_offline', 'severity': 'low',
             'acknowledged_at': None, 'resolved_at': 99, 'device_id': None,
             'payload': {}},
        ]})

    def test_bulk_ack_only_open_rows(self):
        self._seed()
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'ids': ['a1', 'a2', 'a3', 'a4'], 'note': 'sweep'}
        r = self.call(api.handle_alerts_bulk_ack)
        self.assertEqual(r['acked'], 2)   # a1, a2 only (a3 already acked, a4 resolved)
        store = api.load(api.ALERTS_FILE)
        by = {a['id']: a for a in store['alerts']}
        self.assertEqual(by['a1']['acknowledged_by'], 'jakob')
        self.assertEqual(by['a1']['ack_note'], 'sweep')
        self.assertEqual(by['a2']['acknowledged_by'], 'jakob')
        self.assertEqual(by['a3']['acknowledged_by'], 'x')   # untouched

    def test_bulk_ack_fires_webhook_per_alert(self):
        self._seed()
        api.save(api.CONFIG_FILE, {'webhook_urls': [
            {'id': 'wh', 'url': 'https://t/x', 'format': 'generic',
             'enabled': True, 'on_ack': True}]})
        fired = []
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'ids': ['a1', 'a2']}
        api._dispatch_one_webhook = (
            lambda ev, dest, payload, msg, title, prio: fired.append(payload['alert_id']))
        self.call(api.handle_alerts_bulk_ack)
        self.assertEqual(sorted(fired), ['a1', 'a2'])

    def test_bulk_ack_requires_ids(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {}
        self.call(api.handle_alerts_bulk_ack)
        self.assertEqual(self.cap['s'], 400)

    def test_route_registered(self):
        self.assertIn(('POST', '/api/alerts/bulk-ack'), api._build_exact_routes())


class TestAckCommentSetting(_HandlerBase):
    """#56: alerts list exposes whether to prompt for a comment."""

    def test_default_enabled(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api.method = lambda: 'GET'
        os.environ['QUERY_STRING'] = 'status=all'
        r = self.call(api.handle_alerts_list)
        self.assertTrue(r['ack_comment_enabled'])

    def test_can_be_turned_off(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api.save(api.CONFIG_FILE, {'ack_comment_enabled': False})
        api.method = lambda: 'GET'
        os.environ['QUERY_STRING'] = 'status=all'
        r = self.call(api.handle_alerts_list)
        self.assertFalse(r['ack_comment_enabled'])


class TestSecretsHostMute(_HandlerBase):
    """#55: mute an entire host under Exposed secrets on disk."""

    def test_host_mute_adds_and_removes(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1'}
        r = self.call(api.handle_secrets_host_mute)
        self.assertTrue(r['muted'])
        self.assertIn('d1', api.load(api.CONFIG_FILE)['secrets_host_mutes'])
        api.get_json_body = lambda: {'device_id': 'd1', 'unmute': True}
        r = self.call(api.handle_secrets_host_mute)
        self.assertFalse(r['muted'])
        self.assertNotIn('d1', api.load(api.CONFIG_FILE).get('secrets_host_mutes', []))

    def test_host_mute_resolves_open_secret_alerts_for_that_host(self):
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 's1', 'event': 'secret_exposed', 'device_id': 'd1', 'resolved_at': None},
            {'id': 's2', 'event': 'secret_exposed', 'device_id': 'd2', 'resolved_at': None},
        ]})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1'}
        self.call(api.handle_secrets_host_mute)
        by = {a['id']: a for a in api.load(api.ALERTS_FILE)['alerts']}
        self.assertEqual(by['s1']['resolved_by'], 'secrets-host-mute')
        self.assertIsNone(by['s2']['resolved_at'])   # other host untouched

    def test_ingest_suppresses_alert_for_muted_host(self):
        api.save(api.CONFIG_FILE, {'secrets_host_mutes': ['d1']})
        fired = []
        orig = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None: fired.append(ev)
        try:
            api._ingest_secret_findings('d1', 'host1', [
                {'fingerprint': 'fp1', 'rule': 'aws', 'path': '/x', 'preview': '••'}])
        finally:
            api.fire_webhook = orig
        self.assertEqual(fired, [])   # muted host → no secret_exposed event
        # Finding is still stored.
        self.assertTrue(api.load(api.SECRETS_FILE)['d1']['findings'])

    def test_fleet_secrets_marks_host_muted_zero_active(self):
        api.save(api.CONFIG_FILE, {'secrets_host_mutes': ['d1'], 'secrets_scan_enabled': True})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'host1'}})
        api.save(api.SECRETS_FILE, {'d1': {'ts': 1, 'findings': [
            {'fingerprint': 'fp1', 'rule': 'aws', 'path': '/x', 'preview': '••'}]}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_fleet_secrets)
        self.assertEqual(r['total_active'], 0)
        dev = r['devices'][0]
        self.assertTrue(dev['host_muted'])
        self.assertTrue(dev['findings'][0]['muted'])


class TestSortWiringGuard(unittest.TestCase):
    """#40: every table wired for sorting must mark its sortable columns.

    CLAUDE.md: 'every sortable <th> MUST carry a data-col'. Sort regressions
    shipped repeatedly (Custom Scripts, Log Alert rules, Processes). This is a
    conservative guard: for each thead id passed to wireSortOnly() that is
    defined statically in index.html, that <thead> must contain at least one
    <th ... data-col="...">. Dynamically-built theads are out of scope here."""

    def test_wired_theads_have_data_col(self):
        import re
        sys.path.insert(0, str(Path(__file__).parent))
        from clientjs import client_js
        js = client_js()
        html = (_ROOT / 'server/html/index.html').read_text()
        wired = set(re.findall(r"wireSortOnly\(\s*['\"]([A-Za-z0-9_\-]+)['\"]", js))
        self.assertTrue(wired, 'expected to find wireSortOnly() calls')
        missing = []
        for thead_id in sorted(wired):
            m = re.search(
                r'<thead[^>]*\bid="' + re.escape(thead_id) + r'"[^>]*>(.*?)</thead>',
                html, re.S)
            if not m:
                continue   # built in JS — not statically checkable here
            if 'data-col=' not in m.group(1):
                missing.append(thead_id)
        self.assertEqual(missing, [],
                         f'wired sortable theads with no data-col columns: {missing}')


class TestWebhookRegistryConsistency(unittest.TestCase):
    """#13: whole-set self-checks over the webhook/alert registries, so adding a
    new event and forgetting one of the *silent* registries (CLAUDE.md: 'touch
    EVERY registry' — 2/3/4 fail silently) trips a test instead of half-working
    in production. Complements the per-release specific checks (test_v3110,
    test_v3140, test_api) with global invariants.

    Note: WEBHOOK_EVENTS is a tuple of (name, description, default) tuples."""

    def setUp(self):
        self.events = {e[0] for e in api.WEBHOOK_EVENTS}
        self.recover = (set(api._ALERT_RECOVER)
                        | {e for evs in api._ALERT_RECOVER_EXTRA.values() for e in evs})

    def test_every_event_routed_to_a_kind(self):
        # #3: an event missing from CHANNEL_KINDS gets no routing-matrix row and
        # EVENT_KIND_MAP can't resolve it.
        missing = sorted(self.events - set(api.EVENT_KIND_MAP))
        self.assertEqual(missing, [],
                         f'webhook events not mapped to a channel kind: {missing}')

    def test_no_dead_alert_rules(self):
        dead = sorted(set(api._ALERT_RULES) - self.events)
        self.assertEqual(dead, [],
                         f'_ALERT_RULES keys that are not webhook events: {dead}')

    def test_alertable_events_have_an_alert_rule(self):
        # #2 (the silent one): an alertable event missing from _ALERT_RULES fires
        # a webhook but never lands in the Alerts inbox. Recover/up events and the
        # two command-bookkeeping events intentionally do NOT create alerts.
        non_alerting = self.recover | {'command_queued', 'command_executed', 'service_up'}
        missing = sorted((self.events - non_alerting) - set(api._ALERT_RULES))
        self.assertEqual(missing, [],
            f'alertable events missing from _ALERT_RULES (silent inbox drop): {missing}')


class TestHeartbeatLockHygiene(unittest.TestCase):
    """#16: keep expensive file I/O OUT of the DEVICES_FILE lock in
    handle_heartbeat. Source-level guards so the two wins can't silently
    regress: (a) drift is ingested exactly once (the in-lock duplicate stays
    gone), (b) _record_metrics runs only after the lock is released."""

    def setUp(self):
        src = (_CGI_BIN / 'api.py').read_text().splitlines()
        start = next(i for i, l in enumerate(src)
                     if l.startswith('def handle_heartbeat'))
        end = next((i for i in range(start + 1, len(src))
                    if src[i].startswith('def ')), len(src))
        self.body = '\n'.join(src[start:end])

    def test_drift_ingested_once(self):
        n = self.body.count('_ingest_drift_report(dev_id')
        self.assertEqual(n, 1,
            f'expected exactly one _ingest_drift_report call in handle_heartbeat, '
            f'found {n} (the in-lock duplicate must stay removed)')

    def test_record_metrics_is_post_lock(self):
        marker = self.body.find('OUT OF THE LOCK')
        call = self.body.find('_record_metrics(dev_id')
        self.assertNotEqual(marker, -1, 'OUT OF THE LOCK marker missing')
        self.assertNotEqual(call, -1, '_record_metrics call missing')
        self.assertGreater(call, marker,
            '_record_metrics must run AFTER the DEVICES lock is released '
            '(it writes METRICS_FILE under its own flock)')


class TestSortAccessibility(unittest.TestCase):
    """#36: sortable column headers expose state via aria-sort, and the
    decorative sort glyphs are hidden from the accessibility tree."""

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).parent))
        from clientjs import client_js
        self.js = client_js()

    def test_sets_aria_sort(self):
        for state in ("'none'", "'ascending'", "'descending'"):
            self.assertIn(state, self.js,
                          f'sort renderer should set aria-sort {state}')
        self.assertIn("setAttribute('aria-sort'", self.js)

    def test_decorative_arrows_hidden(self):
        # The ↕/▲/▼ glyph spans must carry aria-hidden so screen readers don't
        # read them; aria-sort conveys the state instead.
        self.assertIn('aria-hidden="true"', self.js)

    def test_keyboard_operable(self):
        # #35: sortable headers are focusable and activate on Enter/Space,
        # reusing the same handler as click.
        self.assertIn("setAttribute('tabindex', '0')", self.js)
        self.assertIn('const doSort', self.js)
        self.assertIn("ev.key === 'Enter'", self.js)


class TestListPagination(_HandlerBase):
    """#23: opt-in, backward-compatible limit/offset on the unbounded list
    endpoints (audit log, command history)."""

    def test_helper_no_limit_returns_all(self):
        os.environ['QUERY_STRING'] = ''
        self.assertEqual(api._paginate_list([1, 2, 3]), [1, 2, 3])

    def test_helper_limit(self):
        os.environ['QUERY_STRING'] = 'limit=2'
        self.assertEqual(api._paginate_list([1, 2, 3, 4]), [1, 2])

    def test_helper_limit_offset(self):
        os.environ['QUERY_STRING'] = 'limit=2&offset=1'
        self.assertEqual(api._paginate_list([1, 2, 3, 4]), [2, 3])

    def test_helper_bad_limit_returns_all(self):
        os.environ['QUERY_STRING'] = 'limit=abc'
        self.assertEqual(api._paginate_list([1, 2, 3]), [1, 2, 3])

    def test_audit_log_backward_compatible(self):
        api.save(api.AUDIT_LOG_FILE, {'entries': [{'a': 1}, {'a': 2}, {'a': 3}]})
        api.method = lambda: 'GET'
        os.environ['QUERY_STRING'] = ''
        r = self.call(api.handle_audit_log)
        self.assertEqual([e['a'] for e in r], [3, 2, 1])   # newest-first, all

    def test_audit_log_paginated(self):
        api.save(api.AUDIT_LOG_FILE, {'entries': [{'a': 1}, {'a': 2}, {'a': 3}]})
        api.method = lambda: 'GET'
        os.environ['QUERY_STRING'] = 'limit=2'
        r = self.call(api.handle_audit_log)
        self.assertEqual([e['a'] for e in r], [3, 2])      # newest 2

    def test_history_paginated(self):
        api.save(api.HISTORY_FILE, {'entries': [{'h': 1}, {'h': 2}, {'h': 3}]})
        api.method = lambda: 'GET'
        os.environ['QUERY_STRING'] = 'limit=1&offset=1'
        r = self.call(api.handle_history)
        self.assertEqual([e['h'] for e in r], [2])


class TestModalManager(unittest.TestCase):
    """#4/#34: openModal/closeModal provide a focus trap, Escape-to-close, and
    focus restore via a modal stack."""

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).parent))
        from clientjs import client_js
        self.js = client_js()

    def test_escape_and_tab_handled(self):
        self.assertIn('_modalStack', self.js)
        self.assertIn("e.key === 'Escape'", self.js)
        self.assertIn("e.key !== 'Escape' && e.key !== 'Tab'", self.js)

    def test_focus_restore_tracked(self):
        # openModal must remember the prior focus and closeModal restore it.
        self.assertIn('_modalReturnFocus', self.js)
        self.assertIn('document.activeElement', self.js)


class TestRagNewSources(unittest.TestCase):
    """Feed the RAG more data: drift + compliance corpus builders (pure)."""

    def test_drift_corpus(self):
        devices = [
            {'id': 'd1', 'name': 'web01', 'drift_state': {
                '/etc/ssh/sshd_config': {'status': 'drifted'},
                '/etc/hosts': {'status': 'ok'},
                '/etc/fstab': {'status': 'drifted', 'ignored': True}}},
            {'id': 'd2', 'name': 'db01', 'drift_state': {}},
        ]
        docs = rag_index.build_drift_corpus(devices, now=100)
        ids = {d['id'] for d in docs}
        self.assertIn('drift/d1', ids)
        self.assertIn('drift/_fleet', ids)
        self.assertNotIn('drift/d2', ids)            # no drift → no chunk
        d1 = next(d for d in docs if d['id'] == 'drift/d1')
        self.assertIn('sshd_config', d1['text'])
        self.assertNotIn('/etc/hosts', d1['text'])   # not drifted
        self.assertNotIn('/etc/fstab', d1['text'])   # ignored

    def test_compliance_corpus(self):
        report = {'frameworks': {'pci': {
            'label': 'PCI DSS', 'pass': 3, 'fail': 1, 'na': 0, 'score': 75.0,
            'controls': [
                {'id': 'pci-1', 'title': 'MFA', 'status': 'fail',
                 'evidence': 'no TOTP users', 'remediation': 'enable 2FA'},
                {'id': 'pci-2', 'title': 'Patching', 'status': 'pass',
                 'evidence': 'ok'}]}},
            'summary': {'pass': 3, 'fail': 1, 'na': 0, 'total': 4}}
        docs = rag_index.build_compliance_corpus(report, now=100)
        ids = {d['id'] for d in docs}
        self.assertIn('compliance/pci', ids)
        self.assertIn('compliance/_summary', ids)
        pci = next(d for d in docs if d['id'] == 'compliance/pci')
        self.assertIn('PCI DSS', pci['text'])
        self.assertIn('pci-1', pci['text'])          # failing control surfaced
        self.assertIn('enable 2FA', pci['text'])     # remediation surfaced
        self.assertNotIn('pci-2', pci['text'])       # passing control omitted

    def test_metrics_corpus(self):
        docs = rag_index.build_metrics_corpus(
            [{'device': 'd1', 'name': 'web01', 'text': 'web01 CPU avg 80%'}], now=5)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['id'], 'metrics/d1')
        self.assertEqual(docs[0]['source'], 'metrics')

    def test_summarise_metric_samples(self):
        samples = [{'cpu': 50, 'mem': 40}, {'cpu': 90, 'mem': 60}]
        txt = api._summarise_metric_samples('web01', samples, 7)
        self.assertIn('CPU: avg 70%, peak 90%', txt)
        self.assertIn('memory: avg 50%, peak 60%', txt)
        # No samples → empty.
        self.assertEqual(api._summarise_metric_samples('x', [], 7), '')

    def test_default_sources_include_new(self):
        src = api._AI_DEFAULTS['rag']['sources']
        self.assertTrue(src['drift'])
        self.assertTrue(src['compliance'])
        self.assertIn('metrics', src)   # present (opt-in / default off)

    def test_dedup_id_helper(self):
        seen = set()
        self.assertEqual(rag_index._dedup_id('a', seen), 'a')
        self.assertEqual(rag_index._dedup_id('a', seen), 'a~2')
        self.assertEqual(rag_index._dedup_id('a', seen), 'a~3')
        self.assertEqual(rag_index._dedup_id('b', seen), 'b')

    def test_docs_corpus_ids_unique_on_split(self):
        # One heading with enough paragraphs to split into multiple chunks —
        # previously all shared docs/README#intro and overwrote each other.
        body = '# Intro\n\n' + '\n\n'.join('para ' + 'x' * 300 for _ in range(10))
        docs = rag_index.build_docs_corpus([('README', body)])
        self.assertGreater(len(docs), 1)                       # actually split
        ids = [d['id'] for d in docs]
        self.assertEqual(len(ids), len(set(ids)))              # all unique now
        self.assertTrue(any('~' in i for i in ids))            # suffix applied


class TestRagMetricSummaries(_HandlerBase):
    """B1: _rag_metric_summaries reads the time-series (JSON window here)."""

    def test_json_window_summaries(self):
        now = int(api.time.time())
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web01', 'monitored': True}})
        api.save(api.METRICS_FILE, {'d1': [
            {'ts': now - 100, 'cpu': 40, 'mem': 30, 'disk': 50, 'swap': 0},
            {'ts': now - 50,  'cpu': 80, 'mem': 50, 'disk': 55, 'swap': 0},
        ]})
        out = api._rag_metric_summaries()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['device'], 'd1')
        self.assertIn('CPU: avg 60%, peak 80%', out[0]['text'])

    def test_skips_agentless_and_unmonitored(self):
        now = int(api.time.time())
        api.save(api.DEVICES_FILE, {
            'a': {'name': 'a', 'agentless': True},
            'u': {'name': 'u', 'monitored': False}})
        api.save(api.METRICS_FILE, {'a': [{'ts': now, 'cpu': 9}],
                                    'u': [{'ts': now, 'cpu': 9}]})
        self.assertEqual(api._rag_metric_summaries(), [])


class TestRagPgVector(unittest.TestCase):
    """B2: pgvector index backend + live switch. The actual SQL needs a live
    Postgres (verified in the test deploy); here we verify the dispatch,
    row-building, reindex/retrieve orchestration, and migrate flow against a
    mocked storage_pg layer."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._orig = {n: getattr(api, n) for n in
                      ('_storage_backend', '_dbmod', '_rag_build_corpus',
                       '_rag_embeddings_active', '_rag_reindex', 'CONFIG_FILE',
                       'RAG_INDEX_FILE', 'RAG_MIGRATE_STATUS_FILE',
                       'require_admin_auth', 'respond', 'method', 'get_json_body',
                       'audit_log', '_rag_newest_mtime', 'DATA_DIR')}
        api.CONFIG_FILE = self.d / 'config.json'
        api.RAG_INDEX_FILE = self.d / 'rag_index.json'
        api.RAG_MIGRATE_STATUS_FILE = self.d / 'rag_migrate_status.json'
        api.DATA_DIR = self.d
        # RAG dispatch sees 'postgres' (mocked per test), but file I/O for the
        # config/json-index must use local JSON, not a real PG connection.
        api._dbmod = lambda: None
        api._rag_embeddings_active = lambda cfg: False
        api._rag_newest_mtime = lambda sources: 0
        api.audit_log = lambda *a, **k: None
        # Mock the PG vector store.
        self.pg = {'replaced': None, 'init': 0, 'count': 0, 'built_at': 0,
                   'cleared': 0, 'search': []}
        self._pg_orig = {n: getattr(api.storage_pg, n) for n in
                         ('rag_init_schema', 'rag_replace_all', 'rag_search',
                          'rag_count', 'rag_built_at', 'rag_clear')}

        def _replace(dd, rows, built_at=0):
            self.pg['replaced'] = list(rows); self.pg['count'] = len(rows)
            return len(rows)
        api.storage_pg.rag_init_schema = lambda dd: self.pg.__setitem__('init', self.pg['init'] + 1)
        api.storage_pg.rag_replace_all = _replace
        api.storage_pg.rag_search = lambda dd, q, v, k=6: list(self.pg['search'])[:k]
        api.storage_pg.rag_count = lambda dd: self.pg['count']
        api.storage_pg.rag_built_at = lambda dd: self.pg['built_at']
        api.storage_pg.rag_clear = lambda dd: self.pg.__setitem__('cleared', self.pg['cleared'] + 1)

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for n, v in self._pg_orig.items():
            setattr(api.storage_pg, n, v)

    def _corpus(self):
        return [rag_index.make_doc('live/web01#cves', 'live_state', 'device_cves',
                                   'web01 has 2 critical CVEs', device='web01', ts=1),
                rag_index.make_doc('docs/x#a', 'docs', 'doc_md', 'how to patch', ts=1)]

    def test_index_backend_selection(self):
        api._storage_backend = lambda: 'json'
        self.assertEqual(api._rag_index_backend({'rag': {'index_backend': 'postgres'}}), 'json')
        api._storage_backend = lambda: 'postgres'
        self.assertEqual(api._rag_index_backend({'rag': {'index_backend': 'postgres'}}), 'postgres')
        self.assertEqual(api._rag_index_backend({'rag': {'index_backend': 'json'}}), 'json')
        self.assertEqual(api._rag_index_backend({'rag': {}}), 'json')

    def test_pg_rows_pairs_embeddings(self):
        idx = rag_index.InfraIndex()
        idx.build(self._corpus(), built_at=1)
        idx.emb_cache = {idx.docs[0]['hash']: [0.1, 0.2]}
        rows = api._rag_pg_rows(idx)
        self.assertEqual(len(rows), 2)
        byid = {r['id']: r for r in rows}
        self.assertEqual(byid['live/web01#cves']['embedding'], [0.1, 0.2])
        self.assertIsNone(byid['docs/x#a']['embedding'])
        self.assertEqual(byid['live/web01#cves']['dtype'], 'device_cves')

    def test_reindex_writes_to_pg(self):
        api._storage_backend = lambda: 'postgres'
        api._rag_build_corpus = lambda cfg: self._corpus()
        cfg = {'rag': {'enabled': True, 'index_backend': 'postgres', 'sources': {}}}
        stats = api._rag_reindex(cfg)
        self.assertEqual(stats['index_backend'], 'postgres')
        self.assertEqual(self.pg['init'], 1)
        self.assertEqual(len(self.pg['replaced']), 2)
        self.assertFalse(api.RAG_INDEX_FILE.exists())   # PG path doesn't write JSON

    def test_reindex_pg_failure_falls_back_to_json(self):
        api._storage_backend = lambda: 'postgres'
        api._rag_build_corpus = lambda cfg: self._corpus()
        def _boom(dd, rows, built_at=0):
            raise RuntimeError('no pgvector')
        api.storage_pg.rag_replace_all = _boom
        cfg = {'rag': {'enabled': True, 'index_backend': 'postgres', 'sources': {}}}
        stats = api._rag_reindex(cfg)
        self.assertEqual(stats['index_backend'], 'json')
        self.assertIn('pg_error', stats)
        self.assertTrue(api.RAG_INDEX_FILE.exists())     # fell back to JSON

    def test_retrieve_pg_budget_trim(self):
        api._storage_backend = lambda: 'postgres'
        self.pg['count'] = 3
        self.pg['built_at'] = int(api.time.time())
        self.pg['search'] = [{'text': 'a' * 3000, 'id': '1'},
                             {'text': 'b' * 3000, 'id': '2'},
                             {'text': 'c' * 3000, 'id': '3'}]
        cfg = {'rag': {'enabled': True, 'index_backend': 'postgres',
                       'max_chunks': 6, 'max_chars': 4000, 'sources': {}}}
        out = api._rag_retrieve(cfg, 'cve')
        self.assertEqual([c['id'] for c in out], ['1'])  # 2nd would blow the 4000 budget

    def test_migrate_requires_pg_storage(self):
        cap = {}
        api.require_admin_auth = lambda: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': 'postgres'}
        api._storage_backend = lambda: 'sqlite'   # not postgres

        def _resp(s, b=None):
            cap['s'] = s; cap['b'] = b; raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.CONFIG_FILE, {'ai': {'rag': {'enabled': True}}})
        try:
            api.handle_ai_rag_index_migrate()
        except api.HTTPError:
            pass
        self.assertEqual(cap['s'], 400)
        self.assertIn('Postgres first', cap['b']['error'])

    def test_migrate_flips_config_and_reindexes(self):
        cap = {}
        api.require_admin_auth = lambda: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': 'postgres'}
        api._storage_backend = lambda: 'postgres'
        api._rag_build_corpus = lambda cfg: self._corpus()

        def _resp(s, b=None):
            cap['s'] = s; cap['b'] = b; raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.CONFIG_FILE, {'ai': {'rag': {'enabled': True}}})
        try:
            api.handle_ai_rag_index_migrate()
        except api.HTTPError:
            pass
        self.assertEqual(cap['s'], 200)
        self.assertEqual(cap['b']['target'], 'postgres')
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual(cfg['ai']['rag']['index_backend'], 'postgres')
        self.assertGreaterEqual(self.pg['init'], 1)

    def test_migrate_records_then_clears_status(self):
        cap = {}
        api.require_admin_auth = lambda: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': 'postgres'}
        api._storage_backend = lambda: 'postgres'
        api._rag_build_corpus = lambda cfg: self._corpus()

        def _resp(s, b=None):
            cap['s'] = s; cap['b'] = b; raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.CONFIG_FILE, {'ai': {'rag': {'enabled': True}}})
        try:
            api.handle_ai_rag_index_migrate()
        except api.HTTPError:
            pass
        self.assertEqual(cap['s'], 200)
        # status file is back to idle after a successful migrate
        self.assertEqual(api._rag_migration_status().get('state'), 'idle')

    def test_concurrent_migration_rejected(self):
        cap = {}
        api.require_admin_auth = lambda: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': 'postgres'}
        api._storage_backend = lambda: 'postgres'

        def _resp(s, b=None):
            cap['s'] = s; cap['b'] = b; raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.CONFIG_FILE, {'ai': {'rag': {'enabled': True}}})
        # A migration is already running.
        api.save(api.RAG_MIGRATE_STATUS_FILE,
                 {'state': 'running', 'target': 'postgres',
                  'started': int(api.time.time())})
        try:
            api.handle_ai_rag_index_migrate()
        except api.HTTPError:
            pass
        self.assertEqual(cap['s'], 409)
        self.assertIn('already running', cap['b']['error'])

    def test_stale_running_status_ignored(self):
        api.save(api.RAG_MIGRATE_STATUS_FILE,
                 {'state': 'running', 'target': 'postgres',
                  'started': int(api.time.time()) - 7200})   # 2h ago → stale
        self.assertEqual(api._rag_migration_status(), {})

    def test_migrate_pgvector_unavailable_returns_400(self):
        cap = {}
        api.require_admin_auth = lambda: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': 'postgres'}
        api._storage_backend = lambda: 'postgres'

        def _boom(dd):
            raise RuntimeError("the pgvector 'vector' extension is not installed "
                               "... Ask a DBA to run once: CREATE EXTENSION vector;")
        api.storage_pg.rag_init_schema = _boom

        def _resp(s, b=None):
            cap['s'] = s; cap['b'] = b; raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.CONFIG_FILE, {'ai': {'rag': {'enabled': True}}})
        try:
            api.handle_ai_rag_index_migrate()
        except api.HTTPError:
            pass
        self.assertEqual(cap['s'], 400)
        self.assertIn('CREATE EXTENSION vector', cap['b']['error'])
        # config must NOT have been flipped to postgres on failure
        cfg = api.load(api.CONFIG_FILE)
        self.assertNotEqual(cfg.get('ai', {}).get('rag', {}).get('index_backend'),
                            'postgres')

    def test_migrate_pg_write_fallback_reports_failure(self):
        # If the PG write fails, _rag_reindex falls back to JSON. The handler
        # must report ok:False, leave config on 'json' (not a broken 'postgres'),
        # and clean up the PG store.
        cap = {}
        api.require_admin_auth = lambda: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'target': 'postgres'}
        api._storage_backend = lambda: 'postgres'
        api._rag_reindex = lambda cfg: {'docs': 5, 'index_backend': 'json',
                                        'pg_error': 'duplicate key ...'}

        def _resp(s, b=None):
            cap['s'] = s; cap['b'] = b; raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.CONFIG_FILE, {'ai': {'rag': {'enabled': True}}})
        try:
            api.handle_ai_rag_index_migrate()
        except api.HTTPError:
            pass
        self.assertEqual(cap['s'], 200)
        self.assertFalse(cap['b']['ok'])
        self.assertIn('kept on JSON', cap['b']['error'])
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual(cfg['ai']['rag']['index_backend'], 'json')  # not left on pg
        self.assertGreaterEqual(self.pg['cleared'], 1)               # PG store dropped

    def test_route_registered(self):
        self.assertIn(('POST', '/api/ai/rag/index-backend/migrate'),
                      api._build_exact_routes())


class TestFleetQueryFilters(_HandlerBase):
    """More Fleet Query options: cpu/swap/load thresholds, kernel/platform
    substrings, and drift / mount-issue / world-port / storage-degraded flags."""

    def setUp(self):
        super().setUp()
        self._gt = getattr(api, 'get_online_ttl')
        api.get_online_ttl = lambda: 300
        now = int(api.time.time())
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'hot', 'last_seen': now, 'monitored': True,
                   'drift_state': {'/etc/hosts': {'status': 'drifted'}},
                   'sysinfo': {
                       'cpu_percent': 95, 'mem_percent': 40, 'swap_percent': 80,
                       'loadavg_1m': 8.0, 'kernel': '6.1.0-amd64',
                       'platform': 'Debian 12 x86_64', 'cpu_count': 2,
                       'last_boot': now - 100 * 86400,   # ~100 days uptime
                       'timers': [{'unit': 'backup.timer', 'failed': True}],
                       'mount_issues': [{'path': '/mnt', 'issue': 'stalled'}],
                       'listening_ports': [{'port': 22, 'scope': 'world'}],
                       'storage_health': [{'name': 'tank', 'state': 'DEGRADED'}]}},
            'd2': {'name': 'calm', 'last_seen': now, 'monitored': True,
                   'sysinfo': {
                       'cpu_percent': 5, 'mem_percent': 10, 'swap_percent': 0,
                       'loadavg_1m': 0.1, 'kernel': '5.15.0-arm64',
                       'platform': 'Ubuntu 22.04 aarch64', 'cpu_count': 16,
                       'last_boot': now - 1 * 86400,      # ~1 day uptime
                       'timers': [{'unit': 'ok.timer', 'failed': False}],
                       'listening_ports': [{'port': 22, 'scope': 'local'}],
                       'storage_health': [{'name': 'p', 'state': 'ONLINE'}]}},
        })
        # d1 has a stopped + a restarting container; d2 has none.
        api.save(api.CONTAINERS_FILE, {'d1': {'items': [
            {'name': 'web', 'status': 'exited (1)', 'runtime': 'docker'},
            {'name': 'flap', 'status': 'running', 'restart_count': 9, 'runtime': 'docker'},
        ]}})
        # d1: failed SMART disk + UPS on battery; d2: healthy.
        api.save(api.HARDWARE_FILE, {
            'd1': {'_smart_failed': True, '_ups_on_battery': True},
            'd2': {'_smart_failed': False, '_ups_on_battery': False}})
        # d1: active brute-force (lots of recent attempts from one IP).
        api.save(api.BRUTE_FORCE_FILE, {
            'd1': {'sshd': {'10.0.0.9': [now - i for i in range(200)]}}})

    def tearDown(self):
        api.get_online_ttl = self._gt
        super().tearDown()

    def _run(self, qs):
        import os as _os
        _os.environ['QUERY_STRING'] = qs
        return self.call(api.handle_fleet_query)

    def _names(self, qs):
        return sorted(d['name'] for d in (self._run(qs).get('devices') or []))

    def test_cpu_gt(self):
        self.assertEqual(self._names('cpu_gt=50'), ['hot'])

    def test_swap_gt(self):
        self.assertEqual(self._names('swap_gt=50'), ['hot'])

    def test_load_gt_float(self):
        self.assertEqual(self._names('load_gt=1.5'), ['hot'])

    def test_kernel_and_platform_substr(self):
        self.assertEqual(self._names('kernel=arm64'), ['calm'])
        self.assertEqual(self._names('platform=debian'), ['hot'])

    def test_posture_flags(self):
        self.assertEqual(self._names('drift=1'), ['hot'])
        self.assertEqual(self._names('mount_issue=1'), ['hot'])
        self.assertEqual(self._names('port_world=1'), ['hot'])
        self.assertEqual(self._names('storage_degraded=1'), ['hot'])

    def test_rows_surface_cpu_mem(self):
        by = {d['name']: d for d in self._run('').get('devices')}
        self.assertEqual(by['hot']['cpu'], 95)
        self.assertEqual(by['hot']['mem'], 40)

    def test_anded_no_match(self):
        # cpu high AND arm64 kernel matches neither host
        self.assertEqual(self._names('cpu_gt=50&kernel=arm64'), [])

    def test_uptime(self):
        self.assertEqual(self._names('uptime_gt=30'), ['hot'])    # ~100d up
        self.assertEqual(self._names('uptime_lt=7'), ['calm'])    # ~1d up

    def test_cores(self):
        self.assertEqual(self._names('cores_gt=8'), ['calm'])     # 16 cores
        self.assertEqual(self._names('cores_lt=4'), ['hot'])      # 2 cores

    def test_container_state(self):
        self.assertEqual(self._names('container_stopped=1'), ['hot'])
        self.assertEqual(self._names('container_restarting=1'), ['hot'])

    def test_timer_failed(self):
        self.assertEqual(self._names('timer_failed=1'), ['hot'])

    def test_security_hardware_flags(self):
        self.assertEqual(self._names('brute_force=1'), ['hot'])
        self.assertEqual(self._names('smart_failure=1'), ['hot'])
        self.assertEqual(self._names('ups_on_battery=1'), ['hot'])

    def test_export_csv_bytes(self):
        rows = self._run('').get('devices')
        data, ctype, fname = api._fleet_query_bytes(rows, 'csv')
        self.assertEqual(ctype, 'text/csv')
        self.assertTrue(fname.endswith('.csv'))
        text = data.decode()
        self.assertIn('Device,Group,OS', text)   # header
        self.assertIn('hot', text)
        self.assertIn('calm', text)

    def test_export_xml_bytes(self):
        rows = self._run('').get('devices')
        data, ctype, fname = api._fleet_query_bytes(rows, 'xml')
        self.assertEqual(ctype, 'application/xml')
        text = data.decode()
        self.assertIn('<FleetQuery', text)
        self.assertIn('<Name>hot</Name>', text)

    def test_rag_fleet_rollups(self):
        # The cross-store rollups (mirroring the query) cover d1 ('hot') across
        # many dimensions, so the AI can answer "which hosts ..." in plain English.
        rolls = {r['label']: r['hosts'] for r in api._rag_fleet_rollups()}
        self.assertTrue(any('CPU' in k for k in rolls))
        self.assertIn('UPS on battery', rolls)
        self.assertTrue(any('SMART' in k for k in rolls))
        self.assertTrue(any('brute' in k.lower() for k in rolls))
        self.assertTrue(any('drift' in k for k in rolls))
        flat = ' '.join(' '.join(v) for v in rolls.values())
        self.assertIn('hot', flat)
        self.assertNotIn('calm', flat)   # healthy host isn't flagged

    def test_rag_fleet_rollups_corpus(self):
        docs = rag_index.build_fleet_rollups_corpus(
            [{'label': 'high CPU (>=85%)', 'hosts': ['web01 (95%)']},
             {'label': 'empty', 'hosts': []}])    # empty dim skipped
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['type'], 'fleet_rollup')
        self.assertEqual(docs[0]['source'], 'live_state')
        self.assertIn('web01', docs[0]['text'])

    def test_csv_formula_injection_neutralised(self):
        # A device name starting with '=' must be quoted in CSV output.
        api.save(api.DEVICES_FILE, {'x': {'name': '=cmd()', 'last_seen': int(api.time.time()),
                                          'monitored': True, 'sysinfo': {}}})
        rows = self._run('').get('devices')
        data, _c, _f = api._fleet_query_bytes(rows, 'csv')
        self.assertIn("'=cmd()", data.decode())


if __name__ == '__main__':
    unittest.main()
