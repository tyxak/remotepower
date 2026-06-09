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
        # Space the two samples > one downsample bucket apart (7d/400 ≈ 1512s)
        # so the DB backend's metric_range keeps both (peak stays 80, not the avg).
        samples = [
            {'ts': now - 180000, 'cpu': 40, 'mem': 30, 'disk': 50, 'swap': 0},
            {'ts': now - 50,     'cpu': 80, 'mem': 50, 'disk': 55, 'swap': 0},
        ]
        # Seed via the active backend: JSON blob for json, metric_append for DB.
        dbm = api._dbmod()
        if dbm is not None:
            for s in samples:
                dbm.metric_append(api.DATA_DIR, 'd1', s['ts'],
                                  s['cpu'], s['mem'], s['swap'], s['disk'])
        else:
            api.save(api.METRICS_FILE, {'d1': samples})
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


class TestThresholdMonitors(unittest.TestCase):
    """Batch 1 monitors (inode / file-descriptors / conntrack) reuse the existing
    metric_warning/critical pipeline — no new event types."""

    def test_resolver_defaults(self):
        self.assertEqual(api._resolve_metric_thresholds({}, 'inode'), (85.0, 95.0))
        self.assertEqual(api._resolve_metric_thresholds({}, 'fd'), (80.0, 95.0))
        self.assertEqual(api._resolve_metric_thresholds({}, 'conntrack'), (80.0, 95.0))

    def test_resolver_overrides(self):
        dev = {'metric_thresholds': {'inode_warn_percent': 50, 'inode_crit_percent': 60}}
        self.assertEqual(api._resolve_metric_thresholds(dev, 'inode'), (50.0, 60.0))

    def test_threshold_transitions(self):
        fired = []
        orig = api._fire_metric_webhook
        api._fire_metric_webhook = lambda ev, *a, **k: fired.append((ev, a[2]))  # (event, kind)
        try:
            dev = {}
            safe_si = {'fd_percent': 99, 'conntrack_percent': 99,
                       'mounts': [{'path': '/', 'percent': 10, 'inode_percent': 99}]}
            api.process_metric_thresholds('d1', dev, safe_si)
        finally:
            api._fire_metric_webhook = orig
        st = dev.get('metric_state') or {}
        self.assertEqual(st.get('fd:'), 'critical')
        self.assertEqual(st.get('conntrack:'), 'critical')
        self.assertEqual(st.get('inode:/'), 'critical')
        self.assertIn(('metric_critical', 'fd'), fired)


class TestMonitorChecks(unittest.TestCase):
    """v4.1.0 remote/active checks: DNS, ICMP latency+loss, HTTP assertions,
    and tag/group target expansion in the monitor runner."""

    def test_dns_check_resolves(self):
        # localhost always resolves; no expect → up.
        r = api._run_one_monitor_check('dns', 'localhost', 'L', {})
        self.assertEqual(r['type'], 'dns')
        self.assertTrue(r['ok'])

    def test_dns_check_expect_mismatch(self):
        r = api._run_one_monitor_check('dns', 'localhost', 'L',
                                       {'expect': '203.0.113.99'})
        self.assertFalse(r['ok'])
        self.assertIn('expected', r['detail'])

    def test_dns_check_nxdomain(self):
        r = api._run_one_monitor_check(
            'dns', 'no-such-host.invalid.example', 'L', {})
        self.assertFalse(r['ok'])

    def test_icmp_loss_threshold_fields(self):
        # Drive the parser with a fake ping subprocess (high loss → down).
        import subprocess as _sp
        orig = api.subprocess.run
        class _R:  # noqa
            returncode = 1
            stdout = '5 packets transmitted, 0 received, 100% packet loss\n'
            stderr = ''
        api.subprocess.run = lambda *a, **k: _R()
        try:
            r = api._run_one_monitor_check('icmp', '192.0.2.1', 'L',
                                           {'max_loss_pct': 50})
            self.assertFalse(r['ok'])
            self.assertIn('loss', r['detail'])
        finally:
            api.subprocess.run = orig

    def test_icmp_latency_sla(self):
        orig = api.subprocess.run
        class _R:  # noqa
            returncode = 0
            stdout = ('5 packets transmitted, 5 received, 0% packet loss\n'
                      'rtt min/avg/max/mdev = 1.0/900.0/1500.0/1.0 ms\n')
            stderr = ''
        api.subprocess.run = lambda *a, **k: _R()
        try:
            ok = api._run_one_monitor_check('icmp', '192.0.2.1', 'L',
                                            {'max_latency_ms': 100})
            self.assertFalse(ok['ok'])           # 900ms avg > 100ms SLA
            relaxed = api._run_one_monitor_check('icmp', '192.0.2.1', 'L',
                                                 {'max_latency_ms': 2000})
            self.assertTrue(relaxed['ok'])
        finally:
            api.subprocess.run = orig

    def test_tag_group_expansion(self):
        # Two devices tagged 'web' → two ping results; runner uses load(DEVICES_FILE).
        devs = {
            'd1': {'name': 'a', 'ip': '10.0.0.1', 'tags': ['web']},
            'd2': {'name': 'b', 'ip': '10.0.0.2', 'tags': ['web']},
            'd3': {'name': 'c', 'ip': '10.0.0.3', 'tags': ['db']},
        }
        orig_load = api.load
        orig_run = api._run_one_monitor_check
        api.load = lambda f, *a, **k: devs if f == api.DEVICES_FILE else orig_load(f, *a, **k)
        api._run_one_monitor_check = lambda mt, t, lbl, m: {
            'label': lbl, 'type': mt, 'target': t, 'ok': True, 'detail': 'up',
            'checked': 0}
        try:
            res = api._execute_monitor_checks(
                [{'type': 'ping', 'target': 'web', 'target_kind': 'tag',
                  'label': 'web hosts'}])
        finally:
            api.load = orig_load
            api._run_one_monitor_check = orig_run
        self.assertEqual(len(res), 2)
        self.assertTrue(all('web hosts ·' in r['label'] for r in res))

    def _fake_db_socket(self, recv_bytes, peer='198.51.100.7'):
        """A minimal stand-in for socket.create_connection's return value."""
        captured = {'sent': b''}
        test = self
        class _S:  # noqa
            def __enter__(self_): return self_
            def __exit__(self_, *a): return False
            def getpeername(self_): return (peer, 5432)
            def settimeout(self_, t): pass
            def sendall(self_, b): captured['sent'] += b
            def recv(self_, n): return recv_bytes
        return _S(), captured

    def test_db_postgres_alive(self):
        sock, cap = self._fake_db_socket(b'S')
        orig = api.socket.create_connection
        api.socket.create_connection = lambda *a, **k: sock
        try:
            r = api._run_one_monitor_check('db', 'pg.example:5432', 'PG',
                                           {'db_kind': 'postgres'})
        finally:
            api.socket.create_connection = orig
        self.assertTrue(r['ok'])
        self.assertIn('postgres up', r['detail'])
        self.assertEqual(cap['sent'], b'\x00\x00\x00\x08\x04\xd2\x16\x2f')

    def test_db_mysql_handshake(self):
        sock, _ = self._fake_db_socket(b'\x4a\x00\x00\x00\x0a')  # len + proto 10
        orig = api.socket.create_connection
        api.socket.create_connection = lambda *a, **k: sock
        try:
            r = api._run_one_monitor_check('db', 'my.example:3306', 'MY',
                                           {'db_kind': 'mysql'})
        finally:
            api.socket.create_connection = orig
        self.assertTrue(r['ok'])
        self.assertIn('proto 10', r['detail'])

    def test_db_redis_pong(self):
        sock, cap = self._fake_db_socket(b'+PONG\r\n')
        orig = api.socket.create_connection
        api.socket.create_connection = lambda *a, **k: sock
        try:
            r = api._run_one_monitor_check('db', 'r.example:6379', 'R',
                                           {'db_kind': 'redis'})
        finally:
            api.socket.create_connection = orig
        self.assertTrue(r['ok'])
        self.assertEqual(cap['sent'], b'PING\r\n')

    def test_db_redis_noauth_still_up(self):
        sock, _ = self._fake_db_socket(b'-NOAUTH Authentication required.\r\n')
        orig = api.socket.create_connection
        api.socket.create_connection = lambda *a, **k: sock
        try:
            r = api._run_one_monitor_check('db', 'r.example:6379', 'R',
                                           {'db_kind': 'redis'})
        finally:
            api.socket.create_connection = orig
        self.assertTrue(r['ok'])

    def test_db_wrong_protocol_down(self):
        sock, _ = self._fake_db_socket(b'garbage')
        orig = api.socket.create_connection
        api.socket.create_connection = lambda *a, **k: sock
        try:
            r = api._run_one_monitor_check('db', 'x.example:5432', 'X',
                                           {'db_kind': 'postgres'})
        finally:
            api.socket.create_connection = orig
        self.assertFalse(r['ok'])

    def test_db_blocked_peer(self):
        # A loopback peer with allow_internal off → blocked, not probed.
        sock, _ = self._fake_db_socket(b'S', peer='127.0.0.1')
        orig = api.socket.create_connection
        api.socket.create_connection = lambda *a, **k: sock
        try:
            r = api._run_one_monitor_check('db', 'localhost:5432', 'L',
                                           {'db_kind': 'postgres'})
        finally:
            api.socket.create_connection = orig
        self.assertFalse(r['ok'])
        self.assertEqual(r['detail'], 'blocked')

    def test_tag_no_devices_fallback(self):
        orig_load = api.load
        api.load = lambda f, *a, **k: {} if f == api.DEVICES_FILE else orig_load(f, *a, **k)
        try:
            res = api._execute_monitor_checks(
                [{'type': 'ping', 'target': 'ghost', 'target_kind': 'group',
                  'label': 'ghosts'}])
        finally:
            api.load = orig_load
        self.assertEqual(len(res), 1)
        self.assertTrue(res[0]['ok'])
        self.assertIn('no devices', res[0]['detail'])


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
                       'mounts': [{'path': '/', 'percent': 50, 'inode_percent': 97}],
                       'fd_percent': 92, 'conntrack_percent': 88,
                       'clock': {'synced': False, 'skewed': True},
                       'gateway': {'ip': '10.0.0.1', 'reachable': False},
                       'last_oom_ts': now - 600,   # OOM 10 min ago
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
            'd1': {'_smart_failed': True, '_ups_on_battery': True, '_temp_high': True},
            'd2': {'_smart_failed': False, '_ups_on_battery': False, '_temp_high': False}})
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
        self.assertEqual(self._names('temp_high=1'), ['hot'])

    def test_capacity_exhaustion_filters(self):
        self.assertEqual(self._names('inode_gt=90'), ['hot'])      # 97%
        self.assertEqual(self._names('fd_gt=90'), ['hot'])         # 92%
        self.assertEqual(self._names('conntrack_gt=80'), ['hot'])  # 88%

    def test_clock_skew_filter(self):
        self.assertEqual(self._names('clock_skew=1'), ['hot'])

    def test_gateway_and_oom_filters(self):
        self.assertEqual(self._names('gateway_unreachable=1'), ['hot'])
        self.assertEqual(self._names('oom_recent=1'), ['hot'])

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
        self.assertTrue(any('temperature' in k for k in rolls))
        self.assertTrue(any('clock' in k for k in rolls))
        self.assertTrue(any('gateway' in k for k in rolls))
        self.assertTrue(any('OOM' in k for k in rolls))
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


class TestHostChecks(_HandlerBase):
    """CheckMK-style per-host checks model: aggregator, summary, enable/disable,
    endpoints."""

    def setUp(self):
        super().setUp()
        self._gt = api.get_online_ttl
        api.get_online_ttl = lambda: 180

    def tearDown(self):
        api.get_online_ttl = self._gt
        super().tearDown()

    def _dev(self):
        now = int(api.time.time())
        return now, {
            'name': 'web01', 'last_seen': now, 'group': 'prod',
            'metric_state': {'memory:': 'critical', 'disk:/': 'warning'},
            'drift_state': {'/etc/hosts': {'status': 'drifted'}},
            'sysinfo': {
                'loadavg_1m': 2.0, 'cpu_count': 4, 'mem_percent': 96,
                'swap_percent': 10, 'fd_percent': 30, 'conntrack_percent': 20,
                'mounts': [{'path': '/', 'percent': 85, 'inode_percent': 40}],
                'failed_units': ['nginx.service'],
                'listening_ports': [{'port': 22, 'scope': 'world'}],
                'reboot_required': True, 'packages': {'upgradable': 12},
                'clock': {'synced': True, 'skewed': False},
                'gateway': {'ip': '10.0.0.1', 'reachable': True},
                'storage_health': [{'name': 'tank', 'state': 'ONLINE'}]}}

    def test_aggregator_status(self):
        now, dev = self._dev()
        hw = {'_smart_failed': True, '_ups_on_battery': False, '_temp_high': False}
        chk = {c['key']: c for c in api._host_checks('d1', dev, hw, [], now, 180, cve_high=3)}
        self.assertEqual(chk['reachability']['status'], 'ok')
        self.assertEqual(chk['memory']['status'], 'critical')
        self.assertEqual(chk['disk:/']['status'], 'warning')
        self.assertEqual(chk['services']['status'], 'critical')
        self.assertEqual(chk['drift']['status'], 'warning')
        self.assertEqual(chk['exposure']['status'], 'warning')
        self.assertEqual(chk['reboot']['status'], 'warning')
        self.assertEqual(chk['patches']['status'], 'warning')
        self.assertEqual(chk['smart']['status'], 'critical')
        self.assertEqual(chk['cve']['status'], 'critical')
        self.assertEqual(chk['cpu']['status'], 'ok')           # no metric_state entry
        self.assertEqual(chk['storage']['status'], 'ok')       # ONLINE pool

    def test_offline_is_critical(self):
        now, dev = self._dev()
        dev['last_seen'] = now - 99999
        chk = {c['key']: c for c in api._host_checks('d1', dev, {}, [], now, 180)}
        self.assertEqual(chk['reachability']['status'], 'critical')

    def test_mailq_check_thresholds(self):
        now, dev = self._dev()
        # absent on non-MTA hosts
        chk = {c['key']: c for c in api._host_checks('d1', dev, {}, [], now, 180)}
        self.assertNotIn('mailq', chk)
        # ok / warning / critical against defaults (50 / 500)
        for depth, want in ((3, 'ok'), (80, 'warning'), (900, 'critical')):
            dev['sysinfo']['mailq'] = depth
            chk = {c['key']: c for c in api._host_checks('d1', dev, {}, [], now, 180)}
            self.assertEqual(chk['mailq']['status'], want, depth)
        # per-host override
        dev['sysinfo']['mailq'] = 12
        dev['mailq_thresholds'] = {'warn': 10, 'crit': 20}
        chk = {c['key']: c for c in api._host_checks('d1', dev, {}, [], now, 180)}
        self.assertEqual(chk['mailq']['status'], 'warning')

    def test_readonly_fs_check(self):
        now, dev = self._dev()
        # No 'ro' key on any mount → check omitted entirely.
        chk = {c['key']: c for c in api._host_checks('d1', dev, {}, [], now, 180)}
        self.assertNotIn('readonly_fs', chk)
        # All rw → ok; one ro → warning naming the path.
        dev['sysinfo']['mounts'][0]['ro'] = False
        chk = {c['key']: c for c in api._host_checks('d1', dev, {}, [], now, 180)}
        self.assertEqual(chk['readonly_fs']['status'], 'ok')
        dev['sysinfo']['mounts'].append({'path': '/data', 'percent': 10, 'ro': True})
        chk = {c['key']: c for c in api._host_checks('d1', dev, {}, [], now, 180)}
        self.assertEqual(chk['readonly_fs']['status'], 'warning')
        self.assertIn('/data', chk['readonly_fs']['output'])

    def test_disk_eta_check(self):
        now, dev = self._dev()
        # No eta passed → omitted.
        chk = {c['key']: c for c in api._host_checks('d1', dev, {}, [], now, 180)}
        self.assertNotIn('disk_eta', chk)
        for days, want in ((30, 'ok'), (5, 'warning'), (1, 'critical')):
            chk = {c['key']: c for c in
                   api._host_checks('d1', dev, {}, [], now, 180, disk_eta=days)}
            self.assertEqual(chk['disk_eta']['status'], want, days)

    def test_disk_fill_eta_helper(self):
        now = int(api.time.time())
        # Rising disk%: 80→95 over ~10 days → fills soon (warn/crit band).
        samples = [{'ts': now - 10 * 86400, 'cpu': 1, 'mem': 1, 'swap': 0, 'disk': 80},
                   {'ts': now - 7 * 86400,  'cpu': 1, 'mem': 1, 'swap': 0, 'disk': 86},
                   {'ts': now - 3 * 86400,  'cpu': 1, 'mem': 1, 'swap': 0, 'disk': 92},
                   {'ts': now - 3600,       'cpu': 1, 'mem': 1, 'swap': 0, 'disk': 95}]
        # Unique device id: under SQLite the metric_samples table is keyed by
        # DATA_DIR (not reset per test), so a shared id would pollute siblings.
        did = 'etahost'
        dbm = api._dbmod()
        if dbm is not None:
            for s in samples:
                dbm.metric_append(api.DATA_DIR, did, s['ts'], s['cpu'], s['mem'],
                                  s['swap'], s['disk'])
        else:
            api.save(api.METRICS_FILE, {did: samples})
        devs = {did: {'name': 'web01', 'sysinfo': {'mounts': [{'path': '/', 'percent': 95}]}}}
        eta = api._disk_fill_eta(devs)
        self.assertIn(did, eta)
        self.assertGreater(eta[did], 0)
        # Below the min_percent gate → never queried/predicted.
        low = {'lowhost': {'name': 'x', 'sysinfo': {'mounts': [{'path': '/', 'percent': 20}]}}}
        self.assertNotIn('lowhost', api._disk_fill_eta(low))

    def test_disabled_flag(self):
        now, dev = self._dev()
        chk = {c['key']: c for c in api._host_checks('d1', dev, {}, ['memory'], now, 180)}
        self.assertFalse(chk['memory']['enabled'])
        self.assertTrue(chk['cpu']['enabled'])

    def test_summary_worst_and_excludes_disabled(self):
        now, dev = self._dev()
        hw = {'_smart_failed': True}
        full = api._host_check_summary(api._host_checks('d1', dev, hw, [], now, 180, cve_high=2))
        self.assertEqual(full['worst'], 'critical')
        # disable every critical → worst drops below critical
        crit_keys = [c['key'] for c in api._host_checks('d1', dev, hw, [], now, 180, cve_high=2)
                     if c['status'] == 'critical']
        less = api._host_check_summary(
            api._host_checks('d1', dev, hw, crit_keys, now, 180, cve_high=2))
        self.assertNotEqual(less['worst'], 'critical')

    def test_device_checks_endpoint(self):
        now, dev = self._dev()
        api.save(api.DEVICES_FILE, {'d1': dev})
        api.method = lambda: 'GET'
        r = self.call(api.handle_device_checks, 'd1')
        self.assertEqual(r['device_id'], 'd1')
        self.assertIn('summary', r)
        self.assertTrue(any(c['key'] == 'memory' for c in r['checks']))

    def test_toggle_persists_and_clears(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1', 'check': 'cpu', 'enabled': False}
        r = self.call(api.handle_checks_toggle)
        self.assertTrue(r['ok'])
        self.assertIn('cpu', api.load(api.CONFIG_FILE)['host_checks_disabled']['d1'])
        api.get_json_body = lambda: {'device_id': 'd1', 'check': 'cpu', 'enabled': True}
        self.call(api.handle_checks_toggle)
        self.assertNotIn('d1', api.load(api.CONFIG_FILE).get('host_checks_disabled', {}))

    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/checks'), routes)
        self.assertIn(('POST', '/api/checks/toggle'), routes)


class TestChecksView(unittest.TestCase):
    """Phase 2: the CheckMK-style Checks page exists and is wired."""

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).parent))
        from clientjs import client_js
        self.js = client_js()
        self.html = (_CGI_BIN.parent / 'html' / 'index.html').read_text()

    def test_page_and_nav_present(self):
        self.assertIn('id="page-checks"', self.html)
        self.assertIn('data-page="checks"', self.html)
        self.assertIn('id="checks-thead"', self.html)

    def test_loader_and_dispatch_wired(self):
        self.assertIn("if (name === 'checks')   loadChecks()", self.js)
        self.assertIn('async function loadChecks', self.js)
        self.assertIn('function renderChecks', self.js)
        self.assertIn('async function toggleHostCheck', self.js)
        # sortable + status pills
        self.assertIn("wireSortOnly('checks-thead'", self.js)
        self.assertIn('chk-pill chk-', self.js)

    def test_custom_checks_ui_wired(self):
        self.assertIn('id="custom-checks-modal"', self.html)
        self.assertIn('data-action="openCustomChecks"', self.html)
        for fn in ('async function openCustomChecks', 'async function saveCustomCheck',
                   'async function deleteCustomCheck', 'function ccKindChanged'):
            self.assertIn(fn, self.js)


class TestCustomChecks(_HandlerBase):
    """Phase 4: operator-defined custom checks, evaluated server-side and
    assignable to host / tag / group / fleet."""

    def _dev(self, **kw):
        d = {'name': 'web01', 'group': 'prod', 'tags': ['web'],
             'sysinfo': {'proc_names': ['nginx', 'sshd', 'systemd'],
                         'listening_ports': [{'port': 443, 'scope': 'world'},
                                             {'port': 22, 'scope': 'lan'}]}}
        d.update(kw)
        return d

    def test_applies_targeting(self):
        dev = self._dev()
        ap = api._custom_check_applies
        self.assertTrue(ap({'target_kind': 'all'}, 'd1', dev))
        self.assertTrue(ap({'target_kind': 'host', 'target': 'd1'}, 'd1', dev))
        self.assertFalse(ap({'target_kind': 'host', 'target': 'd2'}, 'd1', dev))
        self.assertTrue(ap({'target_kind': 'tag', 'target': 'web'}, 'd1', dev))
        self.assertFalse(ap({'target_kind': 'tag', 'target': 'db'}, 'd1', dev))
        self.assertTrue(ap({'target_kind': 'group', 'target': 'prod'}, 'd1', dev))

    def test_eval_process(self):
        dev = self._dev()
        self.assertEqual(api._eval_custom_check({'type': 'process', 'param': 'nginx'}, dev)[0], 'ok')
        self.assertEqual(api._eval_custom_check({'type': 'process', 'param': 'mysqld'}, dev)[0], 'critical')
        # no proc data → unknown
        self.assertEqual(api._eval_custom_check(
            {'type': 'process', 'param': 'x'}, {'sysinfo': {}})[0], 'unknown')

    def test_eval_ports(self):
        dev = self._dev()
        self.assertEqual(api._eval_custom_check({'type': 'port_open', 'param': '443'}, dev)[0], 'ok')
        self.assertEqual(api._eval_custom_check({'type': 'port_open', 'param': '8080'}, dev)[0], 'critical')
        self.assertEqual(api._eval_custom_check({'type': 'port_closed', 'param': '8080'}, dev)[0], 'ok')
        self.assertEqual(api._eval_custom_check({'type': 'port_closed', 'param': '22'}, dev)[0], 'critical')

    def test_save_validates_and_autoids(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'type': 'bogus', 'param': 'x'}
        self.assertEqual(self.call(api.handle_custom_checks_save) and self.cap['s'], 400)
        api.get_json_body = lambda: {'type': 'process', 'param': 'nginx', 'name': 'web'}
        out = self.call(api.handle_custom_checks_save)
        self.assertTrue(out['ok'])
        self.assertEqual(out['check']['id'], 'ck_00001')
        saved = api.load(api.CONFIG_FILE)['custom_checks']
        self.assertEqual(len(saved), 1)
        # tag target requires a value
        api.get_json_body = lambda: {'type': 'process', 'param': 'x', 'target_kind': 'tag'}
        self.assertEqual(self.call(api.handle_custom_checks_save) and self.cap['s'], 400)

    def test_save_update_then_delete(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'type': 'port_open', 'param': '443', 'name': 'https'}
        cid = self.call(api.handle_custom_checks_save)['check']['id']
        api.get_json_body = lambda: {'id': cid, 'type': 'port_open', 'param': '8443', 'name': 'https-alt'}
        self.call(api.handle_custom_checks_save)
        saved = api.load(api.CONFIG_FILE)['custom_checks']
        self.assertEqual(len(saved), 1)               # updated in place
        self.assertEqual(saved[0]['param'], '8443')
        api.get_json_body = lambda: {'id': cid}
        self.call(api.handle_custom_checks_delete)
        self.assertEqual(api.load(api.CONFIG_FILE).get('custom_checks'), [])

    def test_merged_into_host_checks(self):
        dev = self._dev()
        defs = [{'id': 'ck_1', 'name': 'nginx', 'type': 'process', 'param': 'nginx',
                 'target_kind': 'all'},
                {'id': 'ck_2', 'name': 'no-telnet', 'type': 'port_closed', 'param': '23',
                 'target_kind': 'group', 'target': 'prod'},
                {'id': 'ck_3', 'name': 'other', 'type': 'process', 'param': 'x',
                 'target_kind': 'host', 'target': 'OTHER'}]
        chk = {c['key']: c for c in api._host_checks(
            'd1', dev, {}, [], int(api.time.time()), 180, custom_defs=defs)}
        self.assertEqual(chk['custom:ck_1']['status'], 'ok')
        self.assertEqual(chk['custom:ck_2']['status'], 'ok')   # 23 not open
        self.assertNotIn('custom:ck_3', chk)                   # targets another host

    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/checks/custom'), routes)
        self.assertIn(('POST', '/api/checks/custom'), routes)
        self.assertIn(('POST', '/api/checks/custom/delete'), routes)

    def test_agent_type_eval_reads_reported(self):
        # Agent-side types are not evaluated server-side; the agent's reported
        # result in sysinfo.custom_check_results is surfaced verbatim.
        dev = {'sysinfo': {'custom_check_results': {
            'ck_1': {'status': 'critical', 'output': 'missing'}}}}
        self.assertEqual(api._eval_custom_check(
            {'id': 'ck_1', 'type': 'file_present', 'param': '/x'}, dev),
            ('critical', 'missing'))
        # Not yet reported → unknown.
        self.assertEqual(api._eval_custom_check(
            {'id': 'ck_2', 'type': 'job_fresh', 'param': '/x'}, dev)[0], 'unknown')

    def test_agent_type_save_validation_and_extras(self):
        api.method = lambda: 'POST'
        # file/job require an absolute path
        api.get_json_body = lambda: {'type': 'file_present', 'param': 'relative'}
        self.assertEqual(self.call(api.handle_custom_checks_save) and self.cap['s'], 400)
        # log_errors stores window/warn/crit (crit floored to warn)
        api.get_json_body = lambda: {'type': 'log_errors', 'param': 'oops',
                                     'window_min': 30, 'warn': 5, 'crit': 2, 'unit': 'nginx.service'}
        out = self.call(api.handle_custom_checks_save)['check']
        self.assertEqual(out['window_min'], 30)
        self.assertEqual(out['warn'], 5)
        self.assertEqual(out['crit'], 5)            # crit clamped up to warn
        self.assertEqual(out['unit'], 'nginx.service')
        # job_fresh stores max_age_hours
        api.get_json_body = lambda: {'type': 'job_fresh', 'param': '/var/run/x.stamp',
                                     'max_age_hours': 6}
        out = self.call(api.handle_custom_checks_save)['check']
        self.assertEqual(out['max_age_hours'], 6)

    def test_heartbeat_push_wiring_present(self):
        src = (_CGI_BIN / 'api.py').read_text()
        self.assertIn("common_resp['agent_checks']", src)
        self.assertIn("c.get('type') in AGENT_CHECK_TYPES", src)
        self.assertIn('_custom_check_applies(c, dev_id, saved_dev)', src)


class TestAgentSideChecks(unittest.TestCase):
    """The agent evaluates server-pushed file/job/log checks on-host."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'rp_agent_cc', _CGI_BIN.parent.parent / 'client' / 'remotepower-agent.py')
        cls.agent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.agent)

    def test_file_present_absent(self):
        import tempfile, os
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        self.addCleanup(os.unlink, f.name)
        self.assertEqual(self.agent._eval_one_agent_check(
            {'type': 'file_present', 'param': f.name})[0], 'ok')
        self.assertEqual(self.agent._eval_one_agent_check(
            {'type': 'file_present', 'param': '/no/such/path'})[0], 'critical')
        self.assertEqual(self.agent._eval_one_agent_check(
            {'type': 'file_absent', 'param': f.name})[0], 'critical')
        self.assertEqual(self.agent._eval_one_agent_check(
            {'type': 'file_absent', 'param': '/no/such/path'})[0], 'ok')

    def test_job_fresh(self):
        import tempfile, os
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        self.addCleanup(os.unlink, f.name)
        # fresh file → ok
        self.assertEqual(self.agent._eval_one_agent_check(
            {'type': 'job_fresh', 'param': f.name, 'max_age_hours': 24})[0], 'ok')
        # backdate the mtime well past the window → critical
        old = self.agent.time.time() - 100 * 3600
        os.utime(f.name, (old, old))
        self.assertEqual(self.agent._eval_one_agent_check(
            {'type': 'job_fresh', 'param': f.name, 'max_age_hours': 1})[0], 'critical')
        self.assertEqual(self.agent._eval_one_agent_check(
            {'type': 'job_fresh', 'param': '/no/such/file', 'max_age_hours': 1})[0], 'critical')

    def test_eval_agent_checks_keys_by_id(self):
        out = self.agent.eval_agent_checks([
            {'id': 'a', 'type': 'file_present', 'param': '/no/such'},
            {'type': 'file_present', 'param': '/x'},   # no id → skipped
        ])
        self.assertIn('a', out)
        self.assertEqual(out['a']['status'], 'critical')
        self.assertEqual(len(out), 1)


class TestAlertCorrelation(unittest.TestCase):
    """v4.1.0: host-level root-cause folding — a host's symptom alerts link to
    its open device_offline alert so the grouped inbox reads as one incident."""

    def _alerts(self):
        return [
            {'id': 'o1', 'event': 'device_offline', 'device_id': 'd1'},
            {'id': 's1', 'event': 'service_down', 'device_id': 'd1'},
            {'id': 's2', 'event': 'metric_critical', 'device_id': 'd1'},
            {'id': 'x1', 'event': 'cve_found', 'device_id': 'd1'},     # not a symptom type
            {'id': 'o2', 'event': 'service_down', 'device_id': 'd2'},  # d2 has no offline
        ]

    def test_root_and_symptoms_tagged(self):
        out = {a['id']: a for a in api._annotate_alert_correlation(self._alerts())}
        self.assertTrue(out['o1'].get('_root_cause'))
        self.assertEqual(out['s1'].get('_symptom_of'), 'o1')
        self.assertEqual(out['s2'].get('_symptom_of'), 'o1')
        self.assertIsNone(out['x1'].get('_symptom_of'))      # cve isn't a symptom
        self.assertIsNone(out['o2'].get('_symptom_of'))      # d2 has no root

    def test_acked_offline_is_not_root(self):
        al = self._alerts()
        al[0]['acknowledged_at'] = 123          # offline already acked → not open
        out = {a['id']: a for a in api._annotate_alert_correlation(al)}
        self.assertFalse(out['o1'].get('_root_cause'))
        self.assertIsNone(out['s1'].get('_symptom_of'))

    def test_symptom_set_membership(self):
        self.assertIn('service_down', api.ALERT_SYMPTOM_EVENTS)
        self.assertIn('monitor_down', api.ALERT_SYMPTOM_EVENTS)
        self.assertNotIn('device_offline', api.ALERT_SYMPTOM_EVENTS)
        self.assertNotIn('cve_found', api.ALERT_SYMPTOM_EVENTS)

    def test_ui_wired(self):
        sys.path.insert(0, str(Path(__file__).parent))
        from clientjs import client_js
        js = client_js()
        html = (_CGI_BIN.parent / 'html' / 'index.html').read_text()
        self.assertIn('id="alerts-group-host"', html)
        for fn in ('function _renderAlertsGrouped', 'function toggleAlertGroup',
                   'async function ackGroup', 'async function resolveGroup',
                   'function _alertHostKey'):
            self.assertIn(fn, js)


class TestDashboardCards(_HandlerBase):
    """v4.1.0 dashboard cards: upcoming calendar/scheduler events + tickets
    (open quick-ack list + recently acknowledged)."""

    def setUp(self):
        super().setUp()
        for attr in ('CALENDAR_FILE', 'SCHEDULE_FILE', 'MAINT_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)

    def test_tickets_open_and_acked(self):
        now = int(api.time.time())
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'a1', 'event': 'service_down', 'severity': 'high',
             'title': 'svc', 'device_name': 'web', 'ts': now - 10},
            {'id': 'a2', 'event': 'metric_critical', 'severity': 'critical',
             'title': 'cpu', 'ts': now - 5},
            {'id': 'a3', 'event': 'x', 'severity': 'low', 'title': 'old',
             'ts': now - 100, 'acknowledged_at': now - 50, 'acknowledged_by': 'jakob'},
            {'id': 'a4', 'event': 'y', 'severity': 'medium', 'title': 'done',
             'ts': now - 200, 'acknowledged_at': now - 20, 'acknowledged_by': 'sam',
             'resolved_at': now - 10, 'resolved_by': 'sam'},
        ]})
        t = api._dashboard_tickets()
        self.assertEqual(t['open_total'], 2)
        self.assertEqual([a['id'] for a in t['open']], ['a2', 'a1'])  # critical first
        self.assertEqual([a['id'] for a in t['acked']], ['a4', 'a3'])  # newest ack first
        self.assertTrue(t['acked'][0]['resolved'])
        self.assertFalse(t['acked'][1]['resolved'])
        self.assertEqual(t['acked'][1]['acknowledged_by'], 'jakob')

    def test_upcoming_merges_and_orders(self):
        import datetime as dt
        now = int(api.time.time())
        iso = lambda ts: dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()
        api.save(api.CALENDAR_FILE, {'events': [
            {'title': 'past', 'start': iso(now - 7200), 'end': iso(now - 3600)},
            {'title': 'ongoing', 'start': iso(now - 600), 'end': iso(now + 600)},
            {'title': 'future', 'start': iso(now + 3600), 'end': iso(now + 7200)},
        ]})
        api.save(api.SCHEDULE_FILE, [
            {'id': 's1', 'command': 'reboot', 'device_name': 'db', 'run_at': now + 1800},
        ])
        api.save(api.MAINT_FILE, {'windows': []})
        items = api._dashboard_upcoming(limit=5)
        titles = [i['title'] for i in items]
        self.assertNotIn('past', titles)               # finished events drop off
        self.assertEqual(items[0]['title'], 'ongoing')  # ongoing sorts first
        self.assertTrue(items[0]['ongoing'])
        self.assertIn('future', titles)
        self.assertTrue(any('reboot' in t for t in titles))

    def test_upcoming_limit(self):
        import datetime as dt
        now = int(api.time.time())
        iso = lambda ts: dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()
        api.save(api.CALENDAR_FILE, {'events': [
            {'title': f'e{i}', 'start': iso(now + i * 3600)} for i in range(1, 8)]})
        api.save(api.SCHEDULE_FILE, [])
        api.save(api.MAINT_FILE, {'windows': []})
        self.assertEqual(len(api._dashboard_upcoming(limit=3)), 3)


class TestDashboardCardsUI(unittest.TestCase):
    """The two new cards are wired, and Ask-AI + Customize moved to the footer."""

    def test_wiring(self):
        sys.path.insert(0, str(Path(__file__).parent))
        from clientjs import client_js
        js = client_js()
        html = (_CGI_BIN.parent / 'html' / 'index.html').read_text()
        self.assertIn('data-widget="upcoming"', html)
        self.assertIn('data-widget="tickets"', html)
        self.assertIn('id="home-footer-controls"', html)
        # Ask-AI + Customize now live inside the footer (moved to the bottom).
        fi = html.index('id="home-footer-controls"')
        self.assertGreater(html.index('home-ai-q'), fi)
        self.assertGreater(html.index('data-action="toggleDashEdit"'), fi)
        for fn in ('function _renderHomeUpcoming', 'function _renderHomeTickets',
                   'async function quickAckAlert'):
            self.assertIn(fn, js)
        self.assertIn('home.appendChild(footer)', js)   # footer pinned last
        self.assertIn('out.unshift(', js)               # new widgets surface on top


class TestDashboardWidgetGrid(unittest.TestCase):
    """v4.1.0 dashboard builder: per-widget size persistence, the 10 add-on
    widgets, and the reset/align/share + add-catalog UI."""

    def test_size_persisted_and_validated(self):
        clean = api._sanitise_ui_prefs({'dashboard': [
            {'key': 'health', 'on': True, 'size': 'lg'},
            {'key': 'offline', 'on': True, 'size': 'sm'},
            {'key': 'cves', 'on': False, 'size': 'bogus'},   # bad size → md
            {'key': 'not_a_widget', 'on': True, 'size': 'sm'},  # dropped
        ]})
        dash = {e['key']: e for e in clean['dashboard']}
        self.assertEqual(dash['health']['size'], 'lg')
        self.assertEqual(dash['offline']['size'], 'sm')
        self.assertEqual(dash['cves']['size'], 'md')      # invalid coerced
        self.assertNotIn('not_a_widget', dash)            # unknown dropped

    _EXPANDED = ('offline', 'updates', 'cves', 'drift', 'capacity', 'groups',
                 'monitored', 'stale', 'mailwatch', 'oncall', 'os', 'agentver',
                 'devtypes', 'tags', 'ungrouped', 'activity', 'attseverity',
                 'atttop', 'healthscore', 'fleettotal', 'crittotal', 'updatestotal',
                 'drifttotal', 'recentonline', 'alertsev', 'maintenance',
                 'monitors', 'containers', 'diskfill',
                 'subnet', 'patchpct', 'agentless', 'neverseen', 'worsthealth',
                 'gradedist', 'versionskew', 'offlinegroups')

    def test_widget_registry_has_addons(self):
        for k in self._EXPANDED:
            self.assertIn(k, api.DASHBOARD_WIDGETS)
        self.assertEqual(api.DASHBOARD_WIDGET_SIZES, ('sm', 'md', 'lg'))
        # ≥30 widgets total now (7 core + 29 add-on).
        self.assertGreaterEqual(len(api.DASHBOARD_WIDGETS), 30)

    def test_extra_widgets_payload(self):
        # _dashboard_extra_widgets is best-effort and always returns the keys.
        w = api._dashboard_extra_widgets({}, {}, int(api.time.time()))
        for k in ('alertsev', 'maintenance', 'monitors', 'containers', 'diskfill'):
            self.assertIn(k, w)

    def test_home_includes_oncall(self):
        # handle_home embeds the on-call widget datum (cheap, cfg-derived).
        src = (_CGI_BIN / 'api.py').read_text()
        self.assertIn("'oncall':", src)
        self.assertIn('_oncall_now(cfg', src)

    def test_ui_wired(self):
        sys.path.insert(0, str(Path(__file__).parent))
        from clientjs import client_js
        js = client_js()
        html = (_CGI_BIN.parent / 'html' / 'index.html').read_text()
        self.assertIn('id="dash-grid"', html)
        for k in self._EXPANDED:
            self.assertIn(f'data-widget="{k}"', html)
        for fn in ('function dashSize', 'function dashReset', 'function dashAlign',
                   'function dashShareExport', 'function dashShareImport',
                   'function _renderHomeWidgets'):
            self.assertIn(fn, js)
        # size span classes applied by the layout engine
        self.assertIn("'dash-w-'", js)
        self.assertIn('dash-w-sm', (_CGI_BIN.parent / 'html' / 'static' / 'css' / 'styles.css').read_text())


if __name__ == '__main__':
    unittest.main()
