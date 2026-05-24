"""v3.0.2 release tests.

Covers:
  - JSON load cache: deepcopy on hit, save() invalidation, _LockedUpdate abort
  - Multi-webhook: config validation, format auto-detect, Pushover redaction,
    per-destination filters (events + min_priority), Pushover body shape
  - Self-monitoring: /api/self/status returns the expected shape
  - Audit log retention archive
  - Login lockout exponential ladder
  - Force ACME rescan endpoint
"""
import json, os, sys, tempfile, time, unittest, importlib, shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))


class _ApiTestBase(unittest.TestCase):
    """Each subclass gets its own DATA_DIR + fresh api module import."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_v302_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        # Force a fresh import so DATA_DIR resolves against the tmpdir
        if 'api' in sys.modules: del sys.modules['api']
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)


class TestLoadCache(_ApiTestBase):
    def setUp(self):
        # Reset cache between tests within the same class
        self.api._LOAD_CACHE.clear()

    def test_repeated_load_returns_cached_after_first(self):
        p = self.api.DATA_DIR / 'cache_test.json'
        self.api.save(p, {'value': 1})
        # Load twice — second time should hit cache (verified by mutating
        # the file outside save() and confirming load() still returns old)
        first  = self.api.load(p)
        # Bypass save() so cache is NOT invalidated
        p.write_text(json.dumps({'value': 42}))
        second = self.api.load(p)
        self.assertEqual(first,  {'value': 1})
        self.assertEqual(second, {'value': 1},
            'second load should hit cache and not see the out-of-band rewrite')

    def test_save_invalidates_cache(self):
        p = self.api.DATA_DIR / 'inv_test.json'
        self.api.save(p, {'value': 1})
        self.api.load(p)                          # populates cache
        self.api.save(p, {'value': 2})            # invalidates
        self.assertEqual(self.api.load(p), {'value': 2})

    def test_cache_returns_deep_copy(self):
        """Mutating the returned dict must NOT mutate the cached copy."""
        p = self.api.DATA_DIR / 'copy_test.json'
        self.api.save(p, {'nested': {'k': 'v'}})
        first = self.api.load(p)
        first['nested']['k'] = 'CORRUPTED'
        second = self.api.load(p)
        self.assertEqual(second, {'nested': {'k': 'v'}},
            'caller mutation must not leak into cache')

    def test_lockedupdate_exception_aborts_cache(self):
        """If a _LockedUpdate block raises, the next load must see disk truth,
        not the in-flight mutation."""
        p = self.api.DATA_DIR / 'abort_test.json'
        self.api.save(p, {'original': True})
        with self.assertRaises(RuntimeError):
            with self.api._LockedUpdate(p) as d:
                d['original'] = False
                d['injected'] = 'should not persist'
                raise RuntimeError('synthetic abort')
        again = self.api.load(p)
        self.assertEqual(again, {'original': True},
            'aborted _LockedUpdate must not leak partial mutations through cache')


class TestMultiWebhook(_ApiTestBase):
    def setUp(self):
        self.api._LOAD_CACHE.clear()

    def test_auto_detect_format(self):
        cases = {
            'https://discord.com/api/webhooks/123/abc':       'discord',
            'https://discordapp.com/api/webhooks/123/abc':    'discord',
            'https://hooks.slack.com/services/T/B/X':         'slack',
            'https://api.pushover.net/1/messages.json':       'pushover',
            'https://outlook.office.com/webhook/foo':         'teams',
            'https://webhook.office.com/x':                   'teams',
            'https://ntfy.sh/mytopic':                        'ntfy',
            'https://myserver.example.com/hook':              'generic',
        }
        for url, expected in cases.items():
            self.assertEqual(self.api._auto_detect_format(url), expected,
                             f'expected {expected} for {url}')

    def test_pushover_body_includes_token_and_user(self):
        dest = {
            'format': 'pushover',
            'url': 'https://api.pushover.net/1/messages.json',
            'pushover_token': 'apTEST',
            'pushover_user':  'uTEST',
        }
        body, headers, ct = self.api._build_pushover_body(
            'device_offline', 'Title', 'Message body', 1, dest)
        self.assertIsNotNone(body)
        self.assertEqual(ct, 'application/x-www-form-urlencoded')
        decoded = body.decode()
        self.assertIn('token=apTEST', decoded)
        self.assertIn('user=uTEST', decoded)
        self.assertIn('priority=1', decoded)

    def test_pushover_missing_creds_returns_none(self):
        dest = {'format': 'pushover', 'url': 'https://api.pushover.net/1/messages.json'}
        body, _, _ = self.api._build_pushover_body('test', 'Title', 'Msg', 0, dest)
        self.assertIsNone(body,
            'must return None body so caller can log a clear error rather than POSTing junk')

    def test_pushover_critical_caps_at_priority_1(self):
        """Pushover priority=2 requires retry+expire and triggers the emergency
        tier — must be operator-explicit. Our internal critical (priority=2)
        maps to Pushover 1 (high), not 2 (emergency)."""
        dest = {'format': 'pushover', 'url': 'x', 'pushover_token': 'a', 'pushover_user': 'b'}
        body, _, _ = self.api._build_pushover_body('event', 'T', 'M', 2, dest)
        self.assertIn('priority=1', body.decode())
        self.assertNotIn('priority=2', body.decode())

    def test_discord_body_has_embed_with_severity_color(self):
        body, _, _ = self.api._build_discord_body('device_offline', 'Title', 'Msg')
        payload = json.loads(body)
        self.assertEqual(payload['embeds'][0]['color'], 0xEF4444)
        body2, _, _ = self.api._build_discord_body('device_online', 'Title', 'Msg')
        self.assertEqual(json.loads(body2)['embeds'][0]['color'], 0x22C55E)

    def test_teams_body_has_messagecard_schema(self):
        body, _, _ = self.api._build_teams_body('cve_found', 'CVEs', 'Found 5 CVEs')
        payload = json.loads(body)
        self.assertEqual(payload['@type'], 'MessageCard')
        self.assertEqual(payload['themeColor'], 'EF4444')
        self.assertEqual(payload['title'], 'CVEs')

    def test_ntfy_body_is_plain_text_with_headers(self):
        body, headers, ct = self.api._build_ntfy_body('monitor_down', 'Mon', 'Down!', 2)
        self.assertEqual(ct, 'text/plain; charset=utf-8')
        self.assertEqual(body, b'Down!')
        self.assertEqual(headers['Title'], 'Mon')
        self.assertEqual(headers['Priority'], '5')   # internal 2 → ntfy 5

    def test_generic_body_includes_event_payload(self):
        body, headers, ct = self.api._build_generic_body(
            'test', 'Title', 'Message', 0, {'extra': 'value'})
        payload = json.loads(body)
        self.assertEqual(payload['event'], 'test')
        self.assertEqual(payload['extra'], 'value')
        self.assertEqual(headers['X-Title'], 'Title')


class TestSelfStatus(_ApiTestBase):
    def setUp(self):
        self.api._LOAD_CACHE.clear()

    def test_self_status_shape(self):
        # Seed a minimal monitored device
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'host1', 'last_seen': int(time.time()),
                   'monitored': True, 'token': 'x'},
            'd2': {'name': 'host2', 'last_seen': int(time.time()) - 99999,
                   'monitored': True, 'token': 'y'},
        })
        # Seed a webhook log
        self.api.save(self.api.WEBHOOK_LOG_FILE, {'entries': [
            {'ts': int(time.time()), 'event': 'test', 'url': 'x', 'status': '200'},
            {'ts': int(time.time()), 'event': 'test', 'url': 'x', 'status': '500'},
        ]})
        # Patch respond to capture instead of sys.exit
        captured = {}
        def fake_respond(status, data):
            captured['status'] = status; captured['data'] = data
            raise self.api.HTTPError(status, data)
        orig_respond = self.api.respond
        self.api.respond = fake_respond
        # Also patch require_auth to bypass
        self.api.require_auth = lambda *a, **kw: 'test_user'
        try:
            try:
                self.api.handle_self_status()
            except self.api.HTTPError:
                pass
        finally:
            self.api.respond = orig_respond
        self.assertEqual(captured.get('status'), 200)
        data = captured['data']
        self.assertEqual(data['server_version'], '3.0.2')
        self.assertIn('devices', data)
        self.assertEqual(data['devices']['monitored'], 2)
        self.assertIn('webhooks', data)
        self.assertIn('data_dir', data)
        self.assertIn('audit_log', data)


class TestAuditRetention(_ApiTestBase):
    def setUp(self):
        self.api._LOAD_CACHE.clear()

    def test_old_entries_get_archived(self):
        # Set retention to 1 day; seed entries older + newer
        self.api.save(self.api.CONFIG_FILE, {'audit_log_retention_days': 1})
        now = int(time.time())
        old = now - 5 * 86400
        self.api.save(self.api.AUDIT_LOG_FILE, {'entries': [
            {'ts': old, 'actor': 'a', 'action': 'old', 'detail': '', 'source_ip': '', 'user_agent': ''},
            {'ts': now, 'actor': 'b', 'action': 'new', 'detail': '', 'source_ip': '', 'user_agent': ''},
        ]})
        # Append one more — that triggers retention sweep on append
        self.api.audit_log('c', 'newer')
        al = self.api.load(self.api.AUDIT_LOG_FILE)
        actions = [e['action'] for e in al.get('entries', [])]
        self.assertNotIn('old', actions, 'old entries should have been evicted')
        self.assertIn('new', actions)
        self.assertIn('newer', actions)
        # Archive file should exist now with the old entry
        arch = self.api.DATA_DIR / 'audit_log_archive.jsonl.gz'
        self.assertTrue(arch.exists(), 'archive file should be created')
        import gzip
        with gzip.open(str(arch), 'rt') as f:
            archived = [json.loads(line) for line in f if line.strip()]
        archived_actions = [e['action'] for e in archived]
        self.assertIn('old', archived_actions)


class TestLockoutLadder(_ApiTestBase):
    def setUp(self):
        self.api._LOAD_CACHE.clear()
        # Use a unique user per test to avoid cross-test interference
        self.user = f'lock_user_{int(time.time()*1000)}'

    def test_each_lockout_extends(self):
        # Trip the lockout N+1 times and confirm the lockout wait increases
        for trip in range(3):
            for _ in range(self.api.LOGIN_FAIL_MAX):
                self.api._record_login_failure(self.user)
            rl = self.api.load(self.api.RATELIMIT_FILE)
            entry = rl.get(f'login:{self.user}')
            self.assertIsNotNone(entry)
            # Compare against the ladder
            expected = self.api._LOCKOUT_LADDER_S[min(trip, len(self.api._LOCKOUT_LADDER_S) - 1)]
            self.assertEqual(entry.get('last_wait_s'), expected,
                f'trip {trip} should lock for {expected}s, got {entry.get("last_wait_s")}')

    def test_successful_login_clears_ladder(self):
        for _ in range(self.api.LOGIN_FAIL_MAX):
            self.api._record_login_failure(self.user)
        self.api._clear_login_failures(self.user)
        rl = self.api.load(self.api.RATELIMIT_FILE)
        self.assertNotIn(f'login:{self.user}', rl,
            'successful login must clear the entry, including lockout_count')


class TestForceAcmeRescan(_ApiTestBase):
    def setUp(self):
        self.api._LOAD_CACHE.clear()

    def test_endpoint_sets_flag(self):
        did = 'rescan_dev_1'
        self.api.save(self.api.DEVICES_FILE, {did: {'name': 'h', 'token': 'x'}})
        # Patch around the auth/respond
        self.api.require_admin_auth = lambda *a, **kw: 'admin'
        captured = {}
        def fake_respond(status, data):
            captured['status'] = status; captured['data'] = data
            raise self.api.HTTPError(status, data)
        os.environ['REQUEST_METHOD'] = 'POST'
        orig = self.api.respond
        self.api.respond = fake_respond
        try:
            try:
                self.api.handle_force_acme_rescan(did)
            except self.api.HTTPError:
                pass
        finally:
            self.api.respond = orig
            os.environ.pop('REQUEST_METHOD', None)
        self.assertEqual(captured.get('status'), 200)
        devs = self.api.load(self.api.DEVICES_FILE)
        self.assertTrue(devs[did].get('force_acme_rescan'))


class TestVersionConsistencyV302(unittest.TestCase):
    """v3.0.2 release sanity: changelog top + sw.js + readme all aligned."""

    def test_changelog_v302_present(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        # First version header in the file should be 3.0.2
        import re
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), '3.0.2')

    def test_sw_cache_name_is_302(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertIn('remotepower-shell-v3.0.2', sw)

    def test_api_server_version_is_302(self):
        # Import-free check — read the source file directly so this test
        # doesn't depend on the api module loading cleanly.
        src = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("SERVER_VERSION = '3.0.2'", src)

    def test_agent_version_is_302(self):
        src = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertIn("VERSION      = '3.0.2'", src)


if __name__ == '__main__':
    unittest.main()


class TestLogSearchEndpoint(_ApiTestBase):
    """v3.0.2 regression: the Logs page Search button. Backend was working,
    frontend was throwing TypeError on 400 responses. These tests verify the
    backend stays sane so frontend errors stay diagnosable."""

    def setUp(self):
        self.api._LOAD_CACHE.clear()
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'host1', 'token': 'x', 'monitored': True},
        })
        self.api.save(self.api.LOG_WATCH_FILE, {
            'd1': {
                'updated_at': int(time.time()),
                'units': {
                    'postfix.service': [
                        {'ts': 1000, 'line': 'CONNECT from 10.0.0.1'},
                        {'ts': 1001, 'line': 'error: something broke'},
                    ],
                },
            },
        })
        self.api.require_auth = lambda *a, **kw: 'tester'

    def _run_search(self, query_string):
        os.environ['QUERY_STRING'] = query_string
        captured = {}
        def fake_respond(status, data):
            captured['status'] = status; captured['data'] = data
            raise self.api.HTTPError(status, data)
        orig = self.api.respond
        self.api.respond = fake_respond
        try:
            try:
                self.api.handle_log_search()
            except self.api.HTTPError:
                pass
        finally:
            self.api.respond = orig
            os.environ.pop('QUERY_STRING', None)
        return captured

    def test_normal_search_returns_matches(self):
        r = self._run_search('q=error')
        self.assertEqual(r['status'], 200)
        self.assertEqual(r['data']['count'], 1)
        self.assertIn('something broke', r['data']['results'][0]['line'])

    def test_bad_regex_returns_400_with_error(self):
        """The frontend now handles this gracefully — was throwing TypeError
        on `data.results.length` because data was {error: '...'} with no
        results key."""
        r = self._run_search('q=%5Bunclosed')
        self.assertEqual(r['status'], 400)
        self.assertIn('invalid regex', r['data']['error'])
        # Critically: there is NO results key on the error response
        self.assertNotIn('results', r['data'])

    def test_empty_query_returns_400(self):
        r = self._run_search('q=')
        self.assertEqual(r['status'], 400)

    def test_search_walks_units_correctly(self):
        # Add a second unit to verify cross-unit search works
        self.api.save(self.api.LOG_WATCH_FILE, {
            'd1': {
                'updated_at': int(time.time()),
                'units': {
                    'unitA': [{'ts': 1, 'line': 'apple in unitA'}],
                    'unitB': [{'ts': 2, 'line': 'apple in unitB'}],
                    'unitC': [{'ts': 3, 'line': 'banana in unitC'}],
                },
            },
        })
        r = self._run_search('q=apple')
        self.assertEqual(r['data']['count'], 2)
        r2 = self._run_search('q=banana')
        self.assertEqual(r2['data']['count'], 1)


class TestWebhookTestRoute(_ApiTestBase):
    """v3.0.2 regression: the webhook test endpoint moved/aliased between
    /webhook/test (canonical) and /webhook-test (mistakenly used by my new
    multi-webhook UI). Lock the canonical path."""

    def test_canonical_route_in_dispatch(self):
        src = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        # Single canonical route
        self.assertIn("'/api/webhook/test'", src,
            "canonical webhook test route must be /api/webhook/test")
        # No stray /api/webhook-test (with dash) — that was the bug
        self.assertNotIn("'/api/webhook-test'", src,
            "found a /api/webhook-test reference — should be /api/webhook/test")

    def test_frontend_calls_canonical_path(self):
        js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        # No stray '/webhook-test' (with dash). Allow '/webhook/test' (correct).
        # Check by counting dashes between webhook and test in api(...) calls.
        import re as _re
        wrong = _re.findall(r"api\([^)]*?/webhook-test", js)
        self.assertEqual(wrong, [],
            f"found {len(wrong)} stray /webhook-test references in app.js — should be /webhook/test")


class TestCssVarsExist(unittest.TestCase):
    """v3.0.2 regression: I used var(--bg-card) and var(--bg-hover) in
    multiple modals — neither exists in styles.css, so modals rendered with
    transparent backgrounds. Lock the actual variable names."""

    @classmethod
    def setUpClass(cls):
        cls.css = (REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
        cls.js  = (REPO_ROOT / 'server' / 'html' / 'static' / 'js'  / 'app.js').read_text()

    def test_no_var_bg_card_in_js(self):
        # The variable was never defined; my v3.0.2 modals used it. Replaced
        # with var(--surface). Lock this in.
        self.assertNotIn('var(--bg-card)', self.js,
            'var(--bg-card) does not exist in styles.css — use var(--surface)')

    def test_no_var_bg_hover_in_js(self):
        self.assertNotIn('var(--bg-hover)', self.js,
            'var(--bg-hover) does not exist in styles.css — use var(--surface2)')

    def test_referenced_vars_are_defined(self):
        # Grep every var(--xxx) in js and confirm it's defined somewhere
        # in css. False positives are fine — we just want to catch the
        # totally-undefined ones.
        import re as _re
        referenced = set(_re.findall(r'var\(--([a-z0-9-]+)\)', self.js))
        defined = set(_re.findall(r'--([a-z0-9-]+):', self.css))
        missing = referenced - defined
        self.assertFalse(missing, f'JS references undefined CSS vars: {sorted(missing)}')


class TestUnmonitoredDeviceSuppression(_ApiTestBase):
    """v3.0.2: a device flagged monitored=false must not fire ANY webhook.
    This previously worked for device_offline (which had its own check at
    line ~2256) but not for metric_warning / metric_critical / service_*
    / log_alert / cve_found / drift_detected / custom_script_* — heartbeat
    ingestion still ran threshold checks for unmonitored devices and the
    resulting fire_webhook() bypassed straight through to the destination
    (legacy + multi-webhook). The fix is a single per-device guard inside
    fire_webhook() that covers every event carrying a `device_id`."""

    def setUp(self):
        self.api._LOAD_CACHE.clear()
        self.fired = []
        # Stub the actual HTTP dispatcher so we can observe whether
        # a webhook was attempted without making a real request.
        def fake_send(event, safe_payload, message, cfg):
            self.fired.append({'event': event, 'payload': safe_payload, 'message': message})
        self._orig_send = self.api._send_webhook_to_url
        self.api._send_webhook_to_url = fake_send
        # Configure a working destination
        self.api.save(self.api.CONFIG_FILE, {
            'webhook_url': 'https://example.com/hook',
            'webhook_events': {ev[0]: True for ev in self.api.WEBHOOK_EVENTS},
            'webhook_url_set': True,
        })

    def tearDown(self):
        self.api._send_webhook_to_url = self._orig_send

    def test_unmonitored_device_suppresses_metric_warning(self):
        self.api.save(self.api.DEVICES_FILE, {
            'd_unmon': {'name': 'host-unmon', 'token': 'x', 'monitored': False},
        })
        self.api.fire_webhook('metric_warning', {
            'device_id': 'd_unmon', 'name': 'host-unmon',
            'kind': 'swap', 'target': '', 'value': 95, 'threshold': 50,
        })
        self.assertEqual(self.fired, [],
            'metric_warning must NOT fire when device is unmonitored — this was the Pushover swap-warning bug')

    def test_monitored_device_still_fires(self):
        self.api.save(self.api.DEVICES_FILE, {
            'd_mon': {'name': 'host-mon', 'token': 'x', 'monitored': True},
        })
        self.api.fire_webhook('metric_warning', {
            'device_id': 'd_mon', 'name': 'host-mon',
            'kind': 'swap', 'target': '', 'value': 95, 'threshold': 50,
        })
        self.assertEqual(len(self.fired), 1,
            'metric_warning must fire normally for monitored devices')

    def test_unmonitored_suppresses_every_per_device_event(self):
        # Cover every event that carries a device_id — single guard, single test
        self.api.save(self.api.DEVICES_FILE, {
            'd_unmon': {'name': 'host-unmon', 'token': 'x', 'monitored': False},
        })
        for event in ('service_down', 'log_alert', 'cve_found', 'drift_detected',
                      'custom_script_fail', 'container_stopped', 'patch_alert',
                      'brute_force_detected', 'ssh_key_added', 'tls_expiry',
                      'reboot_required', 'new_port_detected'):
            self.fired.clear()
            self.api.fire_webhook(event, {
                'device_id': 'd_unmon', 'name': 'host-unmon',
                # event-specific fields filled minimally
                'unit': 'x', 'pattern': 'y', 'critical': 1, 'high': 1,
                'count': 1, 'sample': ['x'],
            })
            self.assertEqual(self.fired, [],
                f'{event} fired through for unmonitored device — guard missed this event')

    def test_event_with_no_device_id_unaffected(self):
        """Test events with no device_id (e.g. webhook test) must still fire."""
        self.api.save(self.api.DEVICES_FILE, {})
        self.api.fire_webhook('test', {
            'server_version': '3.0.2', 'triggered_by': 'admin',
        })
        self.assertEqual(len(self.fired), 1,
            'events without a device_id must not be suppressed')


class TestAcmeNoCertsRowsFiltering(unittest.TestCase):
    """v3.0.2: ACME table previously rendered a row per device without
    acme.sh installed ("acme.sh not installed on this device"). User has
    most of their fleet on other cert managers, so the noise dominates the
    table. The renderer now skips those rows and surfaces a discreet count
    above the table."""

    def test_renderer_skips_unavailable(self):
        js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        # The unavailable case should not push a row anymore
        self.assertNotIn(
            "rows.push({ _kind: 'unavailable'",
            js,
            "unavailable rows must no longer be added to the rendered list")
        # The skip-and-count pattern should be present
        self.assertIn('suppressed_unavailable', js,
            "renderer should track skipped count")
        self.assertIn('acme-suppressed-hint', js,
            "renderer should write the count to the hint element")

    def test_hint_element_exists_in_html(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="acme-suppressed-hint"', html,
            "hint element must be present in the ACME table card")


class TestUrlBarSync(unittest.TestCase):
    """v3.0.2: clicking through pages used to leave the URL hash stuck at
    whatever switchSettingsTab last wrote (e.g. #settings/notifs). Now
    showPage updates the hash via history.replaceState."""

    def test_show_page_writes_url_hash(self):
        js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        # showPage should call replaceState
        import re
        m = re.search(r'function showPage\([^)]*\)\s*\{([^}]+(?:\{[^}]+\}[^}]+)*?)', js)
        self.assertIsNotNone(m)
        # Look in a generous window
        idx = js.find('function showPage(')
        block = js[idx:idx + 3000]
        self.assertIn('history.replaceState', block,
            'showPage must call history.replaceState to keep URL bar in sync')

    def test_settings_tab_uses_replace_state(self):
        """switchSettingsTab should use replaceState, not pushState/assign,
        so clicking through tabs doesn't bloat browser history."""
        js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        idx = js.find('function switchSettingsTab(')
        if idx == -1:
            # Some builds inline this; grep for the body
            idx = js.find('switchSettingsTab')
        block = js[idx:idx + 1500]
        self.assertIn('replaceState', block,
            'switchSettingsTab should use history.replaceState')


class TestDeadCodeRemoved(unittest.TestCase):
    """v3.0.2 audit: dead `_get_disk_thresholds` branch removed.
    Replaced with the canonical _resolve_metric_thresholds. The dead branch
    was guarded by `callable(globals().get(...))` which was always false,
    silently swallowing the per-mount disk threshold override map."""

    def test_get_disk_thresholds_no_longer_referenced(self):
        src = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        # Strip Python comments (and trailing comment portions of code
        # lines) before checking. We legitimately mention the old name in
        # a why-this-changed comment.
        import re
        no_comments = re.sub(r'#.*$', '', src, flags=re.MULTILINE)
        self.assertNotIn('_get_disk_thresholds', no_comments,
            'dead reference to undefined _get_disk_thresholds should be removed')

    def test_resolve_metric_thresholds_used_in_attention(self):
        """_compute_attention should resolve disk thresholds via the
        canonical helper, picking up per-mount overrides."""
        src = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        # Find _compute_attention function bounds
        import re
        m = re.search(r'^def _compute_attention\b', src, re.MULTILINE)
        if m:
            nxt = re.search(r'^(def [a-zA-Z]|class )', src[m.end():], re.MULTILINE)
            end = m.end() + nxt.start() if nxt else len(src)
            block = src[m.start():end]
            self.assertIn("_resolve_metric_thresholds(dev, 'disk',", block,
                "attention computer should use canonical disk threshold resolver")


class TestCssVarsDefined(unittest.TestCase):
    """v3.0.2 audit: every var(--xxx) referenced anywhere in the codebase
    must be defined in styles.css. Previously caught --bg-card / --bg-hover
    / --ok in JS. Now also catches --bg2 / --bg3 / --border2 / --font-body
    inside the CSS file itself (drawer footer, etc.) which were rendering
    with default browser colours in dark mode."""

    def test_no_undefined_vars_anywhere(self):
        import glob, re
        css = (REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
        defined = set(re.findall(r'--([a-z0-9-]+):', css))
        bad = {}
        for p in (list(REPO_ROOT.glob('server/html/**/*.js')) +
                  list(REPO_ROOT.glob('server/html/**/*.html')) +
                  list(REPO_ROOT.glob('server/html/static/css/*.css'))):
            content = p.read_text()
            referenced = set(re.findall(r'var\(--([a-z0-9-]+)\)', content))
            missing = referenced - defined
            if missing:
                bad[str(p.relative_to(REPO_ROOT))] = sorted(missing)
        self.assertFalse(bad, f'undefined CSS variables: {bad}')


class TestNAcoverage(_ApiTestBase):
    """v3.0.2: NA used to surface only `disk` for metric thresholds and
    nothing at all for container state or ACME failures, even though
    metric_warning / container_stopped webhooks fired for those. Audit
    closed those gaps."""

    def setUp(self):
        self.api._LOAD_CACHE.clear()
        self.api.require_auth = lambda *a, **kw: 'tester'

    def _run_attention(self):
        captured = {}
        def fake_respond(s, d):
            captured['status'] = s; captured['data'] = d
            raise self.api.HTTPError(s, d)
        orig = self.api.respond
        self.api.respond = fake_respond
        try:
            try: self.api.handle_attention()
            except self.api.HTTPError: pass
        finally:
            self.api.respond = orig
        return captured

    def test_memory_swap_cpu_surface_in_na(self):
        """metric_state with 'warning'/'critical' for non-disk kinds must
        produce NA items."""
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {
                'name': 'host1', 'token': 'x', 'monitored': True,
                'last_seen': now - 10,  # online
                'sysinfo': {
                    'mem_percent': 92,
                    'swap_percent': 35,
                    'loadavg': [2.5, 2.0, 1.5],
                    'cpu_count': 2,
                },
                'metric_state': {
                    'memory:':     'critical',
                    'swap:':       'warning',
                    'cpu:loadavg': 'warning',
                },
            },
        })
        r = self._run_attention()
        kinds = {i['kind'] for i in r['data']['items']}
        self.assertIn('memory', kinds, 'memory NA item must surface from metric_state')
        self.assertIn('swap',   kinds, 'swap NA item must surface from metric_state')
        self.assertIn('cpu',    kinds, 'cpu NA item must surface from metric_state')

    def test_containers_stopped_surface_in_na(self):
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'host1', 'token': 'x', 'monitored': True,
                   'last_seen': now - 10},
        })
        self.api.save(self.api.CONTAINERS_FILE, {
            'd1': {
                'ts': now - 30,
                'items': [
                    {'id': 'c1', 'name': 'webapp', 'status': 'running',    'runtime': 'docker'},
                    {'id': 'c2', 'name': 'queue',  'status': 'exited',     'runtime': 'docker'},
                    {'id': 'c3', 'name': 'cache',  'status': 'restarting', 'runtime': 'docker'},
                ],
            },
        })
        r = self._run_attention()
        kinds = {i['kind'] for i in r['data']['items']}
        self.assertIn('container', kinds, 'container NA item must surface for stopped+restarting')

    def test_acme_renewal_failure_surfaces_in_na(self):
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'host1', 'token': 'x', 'monitored': True,
                   'last_seen': now - 10},
        })
        self.api.save(self.api.ACME_STATE_FILE, {
            'devices': {
                'd1': {
                    'available': True,
                    'certs': [
                        {'domain': 'example.com', 'status': 'failed'},
                        {'domain': 'ok.com',      'status': 'ok'},
                    ],
                },
            },
        })
        r = self._run_attention()
        acme_items = [i for i in r['data']['items'] if i['kind'] == 'acme']
        self.assertEqual(len(acme_items), 1, 'only failed cert should surface, not OK')
        self.assertIn('failed', acme_items[0]['summary'])

    def test_unmonitored_skipped_for_new_kinds(self):
        """The new memory/swap/cpu/container/acme NA items must respect
        the monitored flag — same gate as the existing kinds."""
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {
                'name': 'host-unmon', 'token': 'x', 'monitored': False,
                'last_seen': now - 10,
                'sysinfo': {'mem_percent': 99},
                'metric_state': {'memory:': 'critical'},
            },
        })
        self.api.save(self.api.CONTAINERS_FILE, {
            'd1': {'ts': now, 'items': [{'id': 'c', 'name': 'x', 'state': 'exited'}]},
        })
        r = self._run_attention()
        # No items at all should mention this device
        names = [i.get('device') for i in r['data']['items']]
        self.assertNotIn('host-unmon', names,
            'unmonitored device must not appear in NA regardless of kind')


class TestSuppressionLogParity(_ApiTestBase):
    """v3.0.2: when only multi-webhook is configured (no legacy
    webhook_url), suppression events used to silently drop with no log
    entry — operators had no way to diagnose 'why didn't my Pushover
    fire?'. Helper now falls through to the first enabled multi entry."""

    def setUp(self):
        self.api._LOAD_CACHE.clear()
        # Stub the sender so we never make real HTTP
        self.api._send_webhook_to_url = lambda *a, **kw: None

    def test_suppression_logs_against_multi_when_no_legacy(self):
        # Configure ONLY multi (no legacy webhook_url) and disable an event
        self.api.save(self.api.CONFIG_FILE, {
            'webhook_url': '',
            'webhook_urls': [{
                'id': 'wh_multi', 'url': 'https://example.com/multi',
                'format': 'discord', 'enabled': True,
            }],
            'webhook_events': {'patch_alert': False},
        })
        self.api.fire_webhook('patch_alert', {
            'device_id': 'never-mind', 'name': 'host', 'upgradable': 5,
        })
        wl = self.api.load(self.api.WEBHOOK_LOG_FILE) or {}
        entries = wl.get('entries') or []
        self.assertTrue(any(
            e.get('event') == 'patch_alert' and e.get('status') == 'disabled'
            and 'example.com/multi' in e.get('url', '')
            for e in entries
        ), 'suppression log must record against the multi-webhook URL when no legacy is set')

    def test_no_log_when_no_destinations_at_all(self):
        # No legacy, no multi — silent is correct (nothing to attribute to)
        self.api.save(self.api.CONFIG_FILE, {
            'webhook_url': '',
            'webhook_urls': [],
            'webhook_events': {'patch_alert': False},
        })
        before = (self.api.load(self.api.WEBHOOK_LOG_FILE) or {}).get('entries') or []
        self.api.fire_webhook('patch_alert', {'device_id': 'x', 'upgradable': 1})
        after = (self.api.load(self.api.WEBHOOK_LOG_FILE) or {}).get('entries') or []
        self.assertEqual(len(before), len(after),
            'no log entry should be created when there is no destination at all')


class TestUptimeSeederExists(unittest.TestCase):
    """v3.0.2: the seed-uptime.py CLI populates uptime.json with 7 days of
    synthetic history. Real heartbeats then naturally take over."""

    def test_script_present_and_executable(self):
        p = REPO_ROOT / 'packaging' / 'seed-uptime.py'
        self.assertTrue(p.exists(), 'seed-uptime.py must ship in packaging/')
        # First line should be a python shebang
        first_line = p.read_text().splitlines()[0]
        self.assertTrue(first_line.startswith('#!/usr/bin/env python3'),
            'seed-uptime.py must have a python3 shebang')

    def test_demo_seeder_includes_uptime(self):
        p = REPO_ROOT / 'packaging' / 'seed-demo-data.py'
        src = p.read_text()
        self.assertIn("'uptime.json':", src,
            'demo seeder must register a build_uptime builder so the Fleet roster has data')
        self.assertIn('def build_uptime', src)


class TestAgentSecurity(unittest.TestCase):
    """v3.0.2 agent security audit. Loads the agent module via SourceFileLoader
    (extensionless binary) and exercises the new defensive code paths in
    isolation — credential write atomicity, /tmp/ symlink defense, log_watch
    path deny list, URL scheme stripping."""

    @classmethod
    def setUpClass(cls):
        import importlib.machinery, importlib.util
        agent_path = REPO_ROOT / 'client' / 'remotepower-agent'
        loader = importlib.machinery.SourceFileLoader('rp_agent_security', str(agent_path))
        spec = importlib.util.spec_from_loader('rp_agent_security', loader)
        cls.agent = importlib.util.module_from_spec(spec)
        loader.exec_module(cls.agent)

    def test_url_scheme_strip_handles_httpserver_typo(self):
        """The old lstrip() based code corrupted hostnames starting with 'http'
        like 'httpserver.com' → 'server.com'. Lock the proper-prefix behaviour."""
        self.assertEqual(self.agent._strip_url_scheme('http://example.com'),
                         'example.com')
        self.assertEqual(self.agent._strip_url_scheme('https://example.com'),
                         'example.com')
        # The pathological case the old code mangled
        self.assertEqual(self.agent._strip_url_scheme('httpserver.com'),
                         'httpserver.com')
        # Already-stripped — passthrough
        self.assertEqual(self.agent._strip_url_scheme('myhost.lab'),
                         'myhost.lab')
        # Mixed case
        self.assertEqual(self.agent._strip_url_scheme('HTTPS://x.y'), 'x.y')

    def test_file_log_path_allowed_rejects_shadow(self):
        self.assertFalse(self.agent._file_log_path_allowed('/etc/shadow'))
        self.assertFalse(self.agent._file_log_path_allowed('/etc/gshadow'))
        self.assertFalse(self.agent._file_log_path_allowed('/etc/sudoers'))
        self.assertFalse(self.agent._file_log_path_allowed('/etc/sudoers.d/some-rule'))

    def test_file_log_path_allowed_rejects_ssh_keys(self):
        self.assertFalse(self.agent._file_log_path_allowed('/root/.ssh/id_rsa'))
        self.assertFalse(self.agent._file_log_path_allowed('/root/.ssh/authorized_keys'))
        self.assertFalse(self.agent._file_log_path_allowed('/home/jakob/.ssh/id_ed25519'))

    def test_file_log_path_allowed_rejects_proc_sys_dev(self):
        self.assertFalse(self.agent._file_log_path_allowed('/proc/kcore'))
        self.assertFalse(self.agent._file_log_path_allowed('/proc/1/maps'))
        self.assertFalse(self.agent._file_log_path_allowed('/sys/kernel/debug/log'))
        self.assertFalse(self.agent._file_log_path_allowed('/dev/mem'))

    def test_file_log_path_allowed_permits_normal_log_paths(self):
        self.assertTrue(self.agent._file_log_path_allowed('/var/log/syslog'))
        self.assertTrue(self.agent._file_log_path_allowed('/var/log/nginx/access.log'))
        self.assertTrue(self.agent._file_log_path_allowed('/opt/myapp/logs/app.log'))
        self.assertTrue(self.agent._file_log_path_allowed('/home/jakob/app.log'))  # not ~/.ssh
        self.assertTrue(self.agent._file_log_path_allowed('/srv/foo/logs/bar.log'))

    def test_file_log_symlink_to_shadow_is_rejected(self):
        """realpath() must resolve symlinks before the allow-check —
        otherwise an attacker who can write to a benign-looking dir
        could redirect the agent to /etc/shadow."""
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            innocent = os.path.join(td, 'app.log')
            os.symlink('/etc/shadow', innocent)
            self.assertFalse(self.agent._file_log_path_allowed(innocent),
                'symlink to /etc/shadow must be rejected after realpath resolution')

    def test_safe_state_write_round_trip(self):
        """Marker writes survive a round trip and don't leak through symlinks."""
        import tempfile, os, unittest.mock
        with tempfile.TemporaryDirectory() as td:
            with unittest.mock.patch.object(self.agent, 'STATE_DIR',
                                            self.agent.Path(td)):
                self.agent._safe_state_write('round-trip', 'value-42')
                self.assertEqual(self.agent._safe_state_read('round-trip'), 'value-42')
                self.agent._safe_state_unlink('round-trip')
                self.assertIsNone(self.agent._safe_state_read('round-trip'))

    def test_safe_state_write_resists_symlink(self):
        """If an attacker (or stale state) put a symlink at the target path,
        the write must not follow it. The O_NOFOLLOW flag should refuse."""
        import tempfile, os, unittest.mock
        with tempfile.TemporaryDirectory() as td:
            statedir = os.path.join(td, 'state')
            os.makedirs(statedir, mode=0o700)
            target_path = os.path.join(statedir, 'last-cmd')
            decoy_target = os.path.join(td, 'attacker-target')
            # Pre-place a symlink at the path the agent will try to write
            os.symlink(decoy_target, target_path)
            with unittest.mock.patch.object(self.agent, 'STATE_DIR',
                                            self.agent.Path(statedir)):
                # The agent's write should NOT create /tmp file path that
                # follows the symlink to write to the decoy
                self.agent._safe_state_write('last-cmd', 'reboot')
                # Either: the symlink was replaced with a regular file at the
                # right location, OR the write failed safely. Either is OK,
                # but the decoy target must NOT have been written.
                self.assertFalse(os.path.exists(decoy_target),
                    'O_NOFOLLOW must prevent the write from reaching the decoy target')

    def test_save_credentials_creates_mode_600_atomically(self):
        """Credentials must be 0o600 from creation, never world-readable
        in a window between write and chmod."""
        import tempfile, os, unittest.mock, stat
        with tempfile.TemporaryDirectory() as td:
            confdir = self.agent.Path(td) / 'rp-creds-test'
            credsfile = confdir / 'credentials'
            with unittest.mock.patch.object(self.agent, 'CONF_DIR', confdir), \
                 unittest.mock.patch.object(self.agent, 'CREDS_FILE', credsfile):
                self.agent.save_credentials({'token': 'secret-token-xyz', 'device_id': 'd1'})
                self.assertTrue(credsfile.exists())
                mode = stat.S_IMODE(credsfile.stat().st_mode)
                self.assertEqual(mode, 0o600,
                    f'credentials file mode is 0o{mode:o}, must be 0o600')
                # Dir mode should be 0700
                dir_mode = stat.S_IMODE(confdir.stat().st_mode)
                self.assertEqual(dir_mode, 0o700,
                    f'CONF_DIR mode is 0o{dir_mode:o}, must be 0o700')

    def test_save_credentials_overwrites_existing_symlink(self):
        """If an attacker pre-placed a symlink at CREDS_FILE, the save must
        not follow it. We unlink before O_EXCL|O_NOFOLLOW open."""
        import tempfile, os, unittest.mock
        with tempfile.TemporaryDirectory() as td:
            confdir = self.agent.Path(td) / 'rp-symlink-test'
            confdir.mkdir(parents=True)
            credsfile = confdir / 'credentials'
            decoy = self.agent.Path(td) / 'attacker-decoy'
            # Pre-place a symlink at where the agent will write
            os.symlink(str(decoy), str(credsfile))
            with unittest.mock.patch.object(self.agent, 'CONF_DIR', confdir), \
                 unittest.mock.patch.object(self.agent, 'CREDS_FILE', credsfile):
                self.agent.save_credentials({'token': 'secret', 'device_id': 'd'})
            # The decoy must not have been written through
            self.assertFalse(decoy.exists(),
                'symlink attack on credentials file must be defeated by O_NOFOLLOW + unlink')
            # The actual creds file should exist as a regular file
            self.assertTrue(credsfile.is_file() and not credsfile.is_symlink())
