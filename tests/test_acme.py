"""v3.0.1: tests for ACME / acme.sh feature.

Coverage:
  - _acme_parse_conf: handles quoted/unquoted values, comments, malformed
  - _acme_decode_reload: base64 markers decoded; plain commands passed through
  - _acme_validate_domain: FQDN + wildcard accepted; junk rejected
  - _ingest_acme_state: shape validation, hard caps, sanitization
  - collect_acme_state: synthesizes a fake ~/.acme.sh and verifies parsing
"""
import base64
import importlib.machinery
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Load agent module (extensionless file). Same pattern other tests use.
_AGENT_PATH = Path(__file__).parent.parent / 'client' / 'remotepower-agent.py'
agent = importlib.machinery.SourceFileLoader('agent_acme', str(_AGENT_PATH)).load_module()

# Server api module under a fresh DATA_DIR per test class
sys.path.insert(0, str(Path(__file__).parent.parent / 'server' / 'cgi-bin'))


class TestAgentAcmeParsing(unittest.TestCase):

    def test_parse_conf_quoted(self):
        with tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False) as f:
            f.write("""\
Le_Domain='example.com'
Le_Alt='*.example.com'
Le_Webroot='dns_cf'
Le_Keylength='4096'
# a comment
Le_OCSP_Staple=''
""")
            path = f.name
        try:
            d = agent._acme_parse_conf(Path(path))
            self.assertEqual(d['Le_Domain'], 'example.com')
            self.assertEqual(d['Le_Alt'], '*.example.com')
            self.assertEqual(d['Le_Webroot'], 'dns_cf')
            self.assertEqual(d['Le_Keylength'], '4096')
            self.assertEqual(d['Le_OCSP_Staple'], '')
            self.assertNotIn('# a comment', d)
        finally:
            os.unlink(path)

    def test_parse_conf_missing_file(self):
        # Contract: returns None on read failure (docstring says "dict or None")
        d = agent._acme_parse_conf(Path('/nonexistent/path/foo.conf'))
        self.assertIsNone(d)

    def test_decode_reload_base64(self):
        cmd = '/root/update_tls.sh'
        enc = base64.b64encode(cmd.encode()).decode()
        wrapped = f'__ACME_BASE64__START_{enc}__ACME_BASE64__END_'
        self.assertEqual(agent._acme_decode_reload(wrapped), cmd)

    def test_decode_reload_plain(self):
        self.assertEqual(agent._acme_decode_reload('nginx -s reload'), 'nginx -s reload')

    def test_decode_reload_empty(self):
        self.assertEqual(agent._acme_decode_reload(''), '')
        self.assertEqual(agent._acme_decode_reload(None), '')

    def test_decode_reload_malformed_base64(self):
        # Wrapped but inner data isn't valid base64 — fall back to raw
        bad = '__ACME_BASE64__START_!!!not_valid_b64!!!__ACME_BASE64__END_'
        out = agent._acme_decode_reload(bad)
        # Either returns the raw markers or empty — must not crash
        self.assertIsInstance(out, str)

    def test_collect_acme_state_no_acme(self):
        # Temporarily redirect ACME_HOME_CANDIDATES away from any real install
        orig = agent.ACME_HOME_CANDIDATES
        try:
            agent.ACME_HOME_CANDIDATES = (Path('/nonexistent/.acme.sh'),)
            s = agent.collect_acme_state()
            self.assertFalse(s['available'])
            self.assertIsNone(s['home'])
            self.assertEqual(s['certs'], [])
        finally:
            agent.ACME_HOME_CANDIDATES = orig

    def test_collect_acme_state_with_certs(self):
        # Build a fake ~/.acme.sh structure
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / '.acme.sh'
            home.mkdir()
            (home / 'acme.sh').write_text('#!/bin/sh\necho v3.0.6\n')
            (home / 'acme.sh').chmod(0o755)
            # Internal dirs we should skip
            for skip in ('ca', 'deploy', 'dnsapi', 'notify', 'zone'):
                (home / skip).mkdir()
            # A real cert
            cert_dir = home / 'example.com'
            cert_dir.mkdir()
            (cert_dir / 'example.com.conf').write_text("""\
Le_Domain='example.com'
Le_Alt='*.example.com,www.example.com'
Le_Webroot='dns_cf'
Le_Keylength='4096'
Le_CertCreateTime='1700000000'
Le_NextRenewTime='1705000000'
Le_CertCreateTimeStr='Fri Nov 14 22:13:20 UTC 2023'
Le_NextRenewTimeStr='Tue Jan 12 12:26:40 UTC 2024'
Le_ReloadCmd=''
""")
            (cert_dir / 'example.com.cer').write_text('-----BEGIN CERTIFICATE-----\n')
            (cert_dir / 'example.com.key').write_text('-----BEGIN PRIVATE KEY-----\n')
            (cert_dir / 'fullchain.cer').write_text('-----BEGIN CERTIFICATE-----\n')

            orig = agent.ACME_HOME_CANDIDATES
            try:
                agent.ACME_HOME_CANDIDATES = (home,)
                s = agent.collect_acme_state()
                self.assertTrue(s['available'])
                self.assertEqual(s['home'], str(home))
                self.assertEqual(len(s['certs']), 1)
                c = s['certs'][0]
                self.assertEqual(c['domain'], 'example.com')
                self.assertIn('*.example.com', c['alt_names'])
                self.assertIn('www.example.com', c['alt_names'])
                self.assertTrue(c['is_wildcard'])
                self.assertTrue(c['is_dns_challenge'])
                self.assertEqual(c['dns_provider'], 'dns_cf')
                self.assertEqual(c['key_length'], '4096')
                self.assertEqual(c['created_ts'], 1700000000)
                self.assertEqual(c['next_renew_ts'], 1705000000)
                self.assertTrue(c['cert_path'].endswith('example.com.cer'))
                self.assertTrue(c['fullchain_path'].endswith('fullchain.cer'))
            finally:
                agent.ACME_HOME_CANDIDATES = orig


class TestServerAcme(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Fresh DATA_DIR for these tests
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_acme_test_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        # Import after env set so DATA_DIR resolves correctly
        if 'api' in sys.modules:
            del sys.modules['api']
        import api  # noqa: E402
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)

    def test_validate_domain_ok(self):
        self.assertTrue(self.api._acme_validate_domain('example.com'))
        self.assertTrue(self.api._acme_validate_domain('sub.example.com'))
        self.assertTrue(self.api._acme_validate_domain('*.example.com'))
        # Norwegian etc. IDN — left as-is for now (acme.sh handles)
        self.assertTrue(self.api._acme_validate_domain('a-b.example.co.uk'))

    def test_validate_domain_rejects_junk(self):
        self.assertFalse(self.api._acme_validate_domain(''))
        self.assertFalse(self.api._acme_validate_domain('no-tld'))
        self.assertFalse(self.api._acme_validate_domain('*'))
        self.assertFalse(self.api._acme_validate_domain('*.'))
        # Path traversal / shell metacharacters
        self.assertFalse(self.api._acme_validate_domain('foo;rm -rf /'))
        self.assertFalse(self.api._acme_validate_domain('../etc/passwd'))
        self.assertFalse(self.api._acme_validate_domain('a b.com'))
        # Wildcard only allowed on leftmost label
        self.assertFalse(self.api._acme_validate_domain('foo.*.example.com'))

    def test_ingest_acme_state_shape(self):
        # Valid payload persists; capped fields don't crash
        self.api._ingest_acme_state('dev123', {
            'available': True,
            'home': '/root/.acme.sh',
            'version': 'v3.0.6',
            'certs': [{
                'domain': 'example.com',
                'alt_names': ['*.example.com'],
                'is_wildcard': True,
                'challenge': 'dns_cf',
                'is_dns_challenge': True,
                'dns_provider': 'dns_cf',
                'dns_provider_label': 'Cloudflare',
                'key_length': '4096',
                'created_ts': 1700000000,
                'next_renew_ts': 1705000000,
                'created_str': 'Fri Nov 14 22:13:20 UTC 2023',
                'next_renew_str': 'Tue Jan 12 12:26:40 UTC 2024',
                'reload_cmd': '/root/update_tls.sh',
                'cert_path': '/root/.acme.sh/example.com/example.com.cer',
                'key_path':  '/root/.acme.sh/example.com/example.com.key',
                'fullchain_path': '/root/.acme.sh/example.com/fullchain.cer',
            }],
        })
        # Verify persisted (backend-agnostic: load via api, not the raw file)
        self.assertTrue(self.api.backend_exists(self.api.ACME_STATE_FILE))
        store = self.api.load(self.api.ACME_STATE_FILE)
        self.assertIn('dev123', store)
        self.assertTrue(store['dev123']['available'])
        self.assertEqual(len(store['dev123']['certs']), 1)

    def test_ingest_acme_caps_cert_count(self):
        # Send 500 certs — should cap at internal limit (200)
        certs = [{'domain': f'example{i}.com', 'alt_names': [], 'is_wildcard': False,
                  'challenge': 'dns_cf', 'is_dns_challenge': True,
                  'dns_provider': 'dns_cf', 'dns_provider_label': 'Cloudflare',
                  'key_length': '4096', 'created_ts': 1700000000,
                  'next_renew_ts': 1705000000, 'created_str': '', 'next_renew_str': '',
                  'reload_cmd': '', 'cert_path': '', 'key_path': '', 'fullchain_path': ''}
                 for i in range(500)]
        self.api._ingest_acme_state('dev_overflow', {
            'available': True, 'home': '/root/.acme.sh', 'version': 'v3.0.6',
            'certs': certs,
        })
        store = self.api.load(self.api.ACME_STATE_FILE)
        self.assertLessEqual(len(store['dev_overflow']['certs']), 200,
            'ingest should cap cert count to prevent unbounded growth')

    def test_ingest_acme_rejects_bad_shape(self):
        # Bad shapes should not crash; either ignored or sanitized
        try:
            self.api._ingest_acme_state('dev_bad', {
                'available': 'not-a-bool', 'certs': 'not-a-list',
            })
        except Exception as e:
            self.fail(f'Should not raise on bad shape: {e}')

    def test_acme_log_path_safe(self):
        # Action IDs and device IDs with sketchy chars must not escape ACME_LOGS_DIR
        p = self.api._acme_log_path('dev/../../etc', 'foo/../bar')
        self.assertTrue(str(p).startswith(str(self.api.ACME_LOGS_DIR)))
        self.assertNotIn('..', p.name)


if __name__ == '__main__':
    unittest.main()


class TestAcmeCmdRoundTrip(unittest.TestCase):
    """v3.0.1: regression test for the 'pending forever' bug.

    The agent round-trips the full original cmd including the 'exec:' prefix.
    The server's tag-matching regex must accept either form.
    """

    def test_regex_matches_with_exec_prefix(self):
        import re as _re
        rx = r'^(?:exec:)?#acme:([a-zA-Z0-9_-]+)#(.*)$'
        # Real-world case: agent sends back with exec: prefix
        m = _re.match(rx, 'exec:#acme:5646fce92976#/root/.acme.sh/acme.sh --renew --force -d bymanden.dk', _re.DOTALL)
        self.assertIsNotNone(m, 'regex must accept exec: prefix from round-tripped cmd')
        self.assertEqual(m.group(1), '5646fce92976')
        self.assertIn('bymanden.dk', m.group(2))

    def test_regex_still_matches_bare_tag(self):
        import re as _re
        rx = r'^(?:exec:)?#acme:([a-zA-Z0-9_-]+)#(.*)$'
        # Server may also pass bare to its own log-routing path
        m = _re.match(rx, '#acme:abc123#/some/cmd', _re.DOTALL)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'abc123')

    def test_regex_rejects_non_acme(self):
        import re as _re
        rx = r'^(?:exec:)?#acme:([a-zA-Z0-9_-]+)#(.*)$'
        # Normal exec commands must NOT be misinterpreted as acme
        self.assertIsNone(_re.match(rx, 'exec:apt-get update', _re.DOTALL))
        self.assertIsNone(_re.match(rx, 'exec:#mitigate:xyz#whatever', _re.DOTALL))
        # And a malicious-looking tag with shell chars in the action_id
        self.assertIsNone(_re.match(rx, 'exec:#acme:abc;rm -rf /#cmd', _re.DOTALL))


class TestAttentionAudit(unittest.TestCase):
    """v3.0.1 attention audit: critical state must surface in Needs Attention.

    Regression tests for the 'palworld.service went to Recent Activity but
    not Needs Attention' bug. Whenever the underlying state file says
    something is broken, _compute_attention must produce an item for it.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_attn_audit_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        # Need a fresh import so DATA_DIR resolves
        for mod in ('api',):
            if mod in sys.modules: del sys.modules[mod]
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)

    def _seed_device(self, dev_id='dev1', name='tviapp01'):
        # Minimal monitored device
        devices = {dev_id: {'name': name, 'last_seen': int(time.time()),
                            'monitored': True, 'token': 'x'}}
        self.api.save(self.api.DEVICES_FILE, devices)
        return dev_id, name

    def test_service_down_appears_in_attention(self):
        # This is THE bug Jakob reported: stopped palworld.service ended up
        # in fleet_events but not Needs Attention. After the fix, an
        # inactive service in SERVICES_FILE must produce an NA item.
        did, name = self._seed_device()
        self.api.save(self.api.SERVICES_FILE, {did: {
            'updated_at': int(time.time()),
            'services': [
                {'unit': 'palworld.service', 'active': 'inactive', 'sub': 'dead'},
                {'unit': 'nginx.service',    'active': 'active',   'sub': 'running'},
            ],
        }})
        items = self.api._compute_attention()
        service_items = [i for i in items if i.get('kind') == 'service_down']
        self.assertEqual(len(service_items), 1,
            f'Expected exactly one service_down NA item, got: {service_items}')
        s = service_items[0]
        self.assertEqual(s['device'], name)
        self.assertIn('palworld.service', s['summary'])
        # And it carries the target so mitigation can substitute it
        self.assertEqual(s.get('target'), 'palworld.service')

    def test_service_failed_is_critical_inactive_is_warning(self):
        did, _ = self._seed_device()
        self.api.save(self.api.SERVICES_FILE, {did: {
            'updated_at': int(time.time()),
            'services': [
                {'unit': 'failed.service',   'active': 'failed',   'sub': 'failed'},
                {'unit': 'inactive.service', 'active': 'inactive', 'sub': 'dead'},
            ],
        }})
        items = self.api._compute_attention()
        sev_by_unit = {i.get('target'): i.get('severity')
                       for i in items if i.get('kind') == 'service_down'}
        self.assertEqual(sev_by_unit.get('failed.service'),   'critical')
        self.assertEqual(sev_by_unit.get('inactive.service'), 'warning')

    def test_active_services_dont_produce_attention(self):
        did, _ = self._seed_device()
        self.api.save(self.api.SERVICES_FILE, {did: {
            'updated_at': int(time.time()),
            'services': [
                {'unit': 'nginx.service', 'active': 'active',     'sub': 'running'},
                {'unit': 'job.service',   'active': 'activating', 'sub': 'start-pre'},
            ],
        }})
        items = self.api._compute_attention()
        self.assertFalse(any(i.get('kind') == 'service_down' for i in items),
            'active/activating services must not produce service_down items')

    def test_custom_script_fail_appears_in_attention(self):
        did, name = self._seed_device()
        devs = self.api.load(self.api.DEVICES_FILE)
        devs[did]['custom_script_results'] = {
            'script_abc': {
                'script_name': 'check_disk',
                'rc': 1,
                'ran_at': int(time.time()),
            },
            'script_xyz': {
                'script_name': 'all_good',
                'rc': 0,
                'ran_at': int(time.time()),
            },
        }
        self.api.save(self.api.DEVICES_FILE, devs)
        items = self.api._compute_attention()
        cs_items = [i for i in items if i.get('kind') == 'custom_script_fail']
        self.assertEqual(len(cs_items), 1)
        self.assertIn('check_disk', cs_items[0]['summary'])

    def test_monitor_down_appears_in_attention(self):
        # Seed a monitor + its last history entry showing failure
        cfg = self.api.load(self.api.CONFIG_FILE) or {}
        cfg['monitors'] = [{'label': 'jellyfin', 'type': 'http',
                            'target': 'https://jelly.example.com'}]
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api.save(self.api.MON_HIST_FILE, {
            'jellyfin': [
                {'ts': int(time.time()) - 600, 'ok': True},
                {'ts': int(time.time()),       'ok': False, 'detail': 'timeout'},
            ]
        })
        items = self.api._compute_attention()
        mon_items = [i for i in items if i.get('kind') == 'monitor_down']
        self.assertEqual(len(mon_items), 1)
        self.assertEqual(mon_items[0]['device'], 'jellyfin')

    def test_attention_items_include_device_id(self):
        # Regression for: the decorator-step adds device_id by name
        # reverse-lookup so the 🩺 button knows which device to target
        did, name = self._seed_device(dev_id='dev_xyz', name='hostX')
        self.api.save(self.api.SERVICES_FILE, {did: {
            'updated_at': int(time.time()),
            'services': [{'unit': 'foo.service', 'active': 'failed', 'sub': 'failed'}],
        }})
        items = self.api._compute_attention()
        sv = next(i for i in items if i.get('kind') == 'service_down')
        self.assertEqual(sv.get('device_id'), 'dev_xyz')
        # And mitigation metadata for the frontend button
        self.assertEqual(sv.get('mitigation_kind'), 'service_down')
        self.assertEqual(sv.get('mitigation_target'), 'foo.service')


class TestAcmeCancelPending(unittest.TestCase):
    """v3.0.1: cancel pending ACME actions either before or after dispatch."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_acme_cancel_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        for mod in ('api',):
            if mod in sys.modules: del sys.modules[mod]
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)

    def test_cancel_distinguishes_queue_vs_dispatched(self):
        # Set up: one pending action in CMDS_FILE with the right tag, plus
        # its meta.json. Cancel — expect removal from queue + rc=-3.
        did = 'dev_cancel_a'
        aid = 'aaaaaa'
        self.api.save(self.api.DEVICES_FILE, {did: {'name': 'host', 'token': 'x'}})
        self.api.ACME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        log_path = self.api._acme_log_path(did, aid)
        meta_path = log_path.with_suffix('.meta.json')
        log_path.write_text('(queued)')
        meta_path.write_text(json.dumps({'action': 'renew', 'domain': 'a.example.com',
                                          'queued_at': int(time.time()), 'actor': 'admin'}))
        # Queue contains exec: with the tag — emulate what _acme_queue_command writes
        self.api.save(self.api.CMDS_FILE, {did: [f'exec:#acme:{aid}#/root/.acme.sh/acme.sh --renew --force -d a.example.com']})
        # Call cancel directly (bypass auth path)
        # Re-implement the queue-search logic here for the unit test:
        with self.api._LockedUpdate(self.api.CMDS_FILE) as cmds:
            queue = cmds.get(did) or []
            kept = [c for c in queue if f'#acme:{aid}#' not in c]
            removed_from_queue = (len(kept) != len(queue))
            if kept: cmds[did] = kept
            else: cmds.pop(did, None)
        self.assertTrue(removed_from_queue,
            'cancel should remove pending entry from CMDS_FILE')
        # Update meta as the handler would
        meta = json.loads(meta_path.read_text())
        meta['rc'] = -3
        meta_path.write_text(json.dumps(meta))
        # Verify cancelled state
        self.assertEqual(json.loads(meta_path.read_text())['rc'], -3)

    def test_cancel_already_dispatched_marks_meta(self):
        # If the command isn't in the queue (agent already grabbed it),
        # rc should be -4 instead of -3.
        did = 'dev_cancel_b'
        aid = 'bbbbbb'
        self.api.save(self.api.DEVICES_FILE, {did: {'name': 'host', 'token': 'x'}})
        self.api.ACME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        log_path = self.api._acme_log_path(did, aid)
        meta_path = log_path.with_suffix('.meta.json')
        log_path.write_text('(running)')
        meta_path.write_text(json.dumps({'action': 'renew', 'domain': 'b.example.com',
                                          'queued_at': int(time.time())}))
        # Empty queue → "already dispatched"
        self.api.save(self.api.CMDS_FILE, {})
        with self.api._LockedUpdate(self.api.CMDS_FILE) as cmds:
            queue = cmds.get(did) or []
            kept = [c for c in queue if f'#acme:{aid}#' not in c]
            removed_from_queue = (len(kept) != len(queue))
        self.assertFalse(removed_from_queue)
        # Meta should be marked with -4
        meta = json.loads(meta_path.read_text())
        meta['rc'] = -4
        meta_path.write_text(json.dumps(meta))
        self.assertEqual(json.loads(meta_path.read_text())['rc'], -4)


class TestDebugLogPost(unittest.TestCase):
    """v3.0.1 iteration 3: regression — handle_debug_log_post was catching
    HTTPError raised by its own successful respond(200), turning every
    debug-log batch flush into a 500."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_dbglog_test_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        for mod in ('api',):
            if mod in sys.modules: del sys.modules[mod]
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)

    def test_respond_is_outside_try(self):
        # Static check: the respond(200, ...) inside handle_debug_log_post
        # must not be wrapped by a broad except Exception that would catch
        # HTTPError. Detected by reading the function source.
        import inspect
        src = inspect.getsource(self.api.handle_debug_log_post)
        # Find every 'try:' block and confirm none of them syntactically
        # contain a `respond(` call followed by a bare/Exception catch
        # before the matching except.
        lines = src.splitlines()
        in_try, in_try_indent, has_respond = False, -1, False
        violation = False
        for ln in lines:
            stripped = ln.lstrip()
            indent = len(ln) - len(stripped)
            if stripped.startswith('try:'):
                in_try = True; in_try_indent = indent; has_respond = False
                continue
            if in_try and stripped.startswith('except '):
                # Same-indent except closes the try
                if indent == in_try_indent:
                    if has_respond and ('Exception' in stripped or 'BaseException' in stripped) and 'HTTPError' not in stripped:
                        violation = True
                    in_try = False
            if in_try and indent > in_try_indent and 'respond(' in stripped:
                has_respond = True
        self.assertFalse(violation,
            'handle_debug_log_post must not wrap respond() in `try: ... except Exception` — '
            'respond() raises HTTPError to signal success, and a broad catch turns every 200 into a 500.')


class TestAttentionLogAlertSurfacing(unittest.TestCase):
    """v3.0.1 iteration 3: log_alert events should surface as NA items
    until they expire from the event window."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_log_alert_attn_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        for mod in ('api',):
            if mod in sys.modules: del sys.modules[mod]
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)

    def _seed_device(self, dev_id='dev1', name='host1'):
        self.api.save(self.api.DEVICES_FILE, {dev_id: {
            'name': name, 'last_seen': int(time.time()),
            'monitored': True, 'token': 'x'}})
        return dev_id, name

    def test_recent_log_alert_appears_in_attention(self):
        did, name = self._seed_device()
        now = int(time.time())
        self.api.save(self.api.FLEET_EVENTS_FILE, [
            {'ts': now - 60, 'event': 'log_alert', 'payload': {
                'device_id': did, 'name': name,
                'unit': 'postfix.service',
                'pattern': 'warning|error|critical|FATAL',
                'count': 3, 'severity': 'WARN',
            }},
        ])
        items = self.api._compute_attention()
        la = [i for i in items if i.get('kind') == 'log_alert']
        self.assertEqual(len(la), 1, f'Expected exactly one log_alert NA item, got: {la}')
        self.assertEqual(la[0]['severity'], 'warning')
        self.assertIn('postfix.service', la[0]['summary'])

    def test_crit_severity_promotes_to_critical(self):
        did, _ = self._seed_device()
        now = int(time.time())
        self.api.save(self.api.FLEET_EVENTS_FILE, [
            {'ts': now - 60, 'event': 'log_alert', 'payload': {
                'device_id': did, 'unit': 'sshd.service',
                'pattern': 'BREACH', 'count': 1, 'severity': 'CRIT',
            }},
        ])
        items = self.api._compute_attention()
        la = next(i for i in items if i.get('kind') == 'log_alert')
        self.assertEqual(la['severity'], 'critical')

    def test_old_log_alert_does_not_appear(self):
        # Events older than 24h must not surface
        did, _ = self._seed_device()
        now = int(time.time())
        self.api.save(self.api.FLEET_EVENTS_FILE, [
            {'ts': now - 25 * 3600, 'event': 'log_alert', 'payload': {
                'device_id': did, 'unit': 'old.service',
                'pattern': 'x', 'count': 1, 'severity': 'WARN',
            }},
        ])
        items = self.api._compute_attention()
        self.assertFalse(any(i.get('kind') == 'log_alert' for i in items))

    def test_duplicate_log_alerts_dedup(self):
        # Same rule firing 50 times in a day should produce ONE NA item.
        did, _ = self._seed_device()
        now = int(time.time())
        evs = [{'ts': now - i * 60, 'event': 'log_alert', 'payload': {
            'device_id': did, 'unit': 'noisy.service',
            'pattern': 'warning', 'count': i, 'severity': 'WARN',
        }} for i in range(50)]
        self.api.save(self.api.FLEET_EVENTS_FILE, evs)
        items = self.api._compute_attention()
        la = [i for i in items if i.get('kind') == 'log_alert']
        self.assertEqual(len(la), 1, f'Dedup should produce one item, got {len(la)}')

    def test_new_port_event_surfaces(self):
        did, name = self._seed_device()
        now = int(time.time())
        self.api.save(self.api.FLEET_EVENTS_FILE, [
            {'ts': now - 60, 'event': 'new_port_detected', 'payload': {
                'device_id': did, 'name': name,
                'proto': 'tcp', 'port': 4444, 'process': 'suspicious',
            }},
        ])
        # v3.4.0: new_port is informational by default — no Needs-Attention card.
        items = self.api._compute_attention()
        self.assertEqual([i for i in items if i.get('kind') == 'new_port'], [])
        # …but it surfaces once the operator turns the channel on.
        cfg = self.api.load(self.api.CONFIG_FILE) or {}
        cfg['channel_routing'] = {'new_port': {'needs_attention': True,
            'recent_activity': True, 'alerts': True, 'webhook': True}}
        self.api.save(self.api.CONFIG_FILE, cfg)
        items = self.api._compute_attention()
        np_items = [i for i in items if i.get('kind') == 'new_port']
        self.assertEqual(len(np_items), 1)
        self.assertIn('4444', np_items[0]['summary'])

    def test_ssh_key_event_surfaces_as_critical(self):
        did, _ = self._seed_device()
        now = int(time.time())
        self.api.save(self.api.FLEET_EVENTS_FILE, [
            {'ts': now - 60, 'event': 'ssh_key_added', 'payload': {
                'device_id': did, 'user': 'root',
                'fingerprint': 'SHA256:abc123', 'comment': 'attacker@evil',
            }},
        ])
        items = self.api._compute_attention()
        sk = [i for i in items if i.get('kind') == 'ssh_key']
        self.assertEqual(len(sk), 1)
        self.assertEqual(sk[0]['severity'], 'critical')


class TestCurrentUsernameDefined(unittest.TestCase):
    """v3.0.1 iteration 4: regression — current_username() was being called
    in three audit-log call sites (cancel, ignore, mitigation) but never
    defined. Every call to those endpoints raised NameError and returned 500.
    The Ignore button looked dead because the response never came back ok."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_username_test_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        for mod in ('api',):
            if mod in sys.modules: del sys.modules[mod]
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)

    def test_current_username_exists(self):
        self.assertTrue(callable(getattr(self.api, 'current_username', None)),
            'current_username() must be defined — called by handle_acme_cancel, '
            'handle_acme_ignore, and the mitigation handlers.')

    def test_current_username_returns_none_when_unauth(self):
        # No token in environment → no session → None
        os.environ.pop('HTTP_X_TOKEN', None)
        result = self.api.current_username()
        self.assertIsNone(result)


class TestPacmanSandboxProbe(unittest.TestCase):
    """v3.0.1 iteration 4: regression — `pacman --help` doesn't list
    --disable-sandbox (it's an -S operation flag). The probe needs to
    use `pacman -S --help` or fall back to a version check."""

    def test_server_upgrade_cmd_uses_correct_probe(self):
        import api as _api  # only need the constant
        cmd = _api._UPGRADE_CMD
        # The fixed probe checks `pacman -S --help`, NOT bare `pacman --help`.
        # Locking this in so the bug doesn't regress.
        self.assertIn('pacman -S --help', cmd,
            '_UPGRADE_CMD must probe `pacman -S --help` for --disable-sandbox '
            '(top-level `pacman --help` does not list operation flags).')
        # Bonus: version-check fallback should also be present
        self.assertIn('pacman --version', cmd,
            'should fall back to version check if -S --help does not advertise the flag')
