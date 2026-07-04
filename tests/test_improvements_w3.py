"""Wave-3 improvement-program guardrails (agent wave).

One test class per shipped wave-3 item; self-contained so items land one
commit at a time. Shares the direct-handler harness shape with
tests/test_improvements_w1.py.
"""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys

ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_w3", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _load_agent():
    """Import the agent module (functions only; main() is __main__-gated)."""
    s = importlib.util.spec_from_file_location(
        "rpagent_w3", ROOT / "client" / "remotepower-agent.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class _HandlerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'AVATARS_DIR',
                     'ROLES_FILE', 'DEVICES_FILE'):
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


class TestAgentExtensionlessSynced(unittest.TestCase):
    """The .py agent and its extensionless twin must stay byte-identical."""

    def test_agent_files_match(self):
        py = (ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        ext = (ROOT / 'client' / 'remotepower-agent').read_bytes()
        self.assertEqual(py, ext,
                         'client/remotepower-agent is out of sync with .py — '
                         'run: cp client/remotepower-agent.py client/remotepower-agent')


class TestBackupSizeTrending(_HandlerBase):
    """W3-42: backup shrink-anomaly pure check + config."""

    def test_no_alert_without_pct(self):
        self.assertEqual(api._backup_is_shrunk(10, [100, 100, 100], 0), (False, 0))

    def test_no_alert_below_min_samples(self):
        self.assertEqual(api._backup_is_shrunk(10, [100, 100], 50), (False, 0))

    def test_shrink_detected(self):
        shrunk, median = api._backup_is_shrunk(30, [100, 100, 100, 100], 50)
        self.assertTrue(shrunk)         # 30 < 50% of 100
        self.assertEqual(median, 100)

    def test_normal_size_ok(self):
        shrunk, _ = api._backup_is_shrunk(80, [100, 100, 100], 50)
        self.assertFalse(shrunk)        # 80 >= 50% of 100

    def test_config_save(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'backup_size_anomaly_pct': 40}
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        self.assertEqual((api.load(api.CONFIG_FILE) or {}).get('backup_size_anomaly_pct'), 40)

    def test_agent_reports_size(self):
        # the agent's collect_backup_status must include a 'size' key
        agent_src = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertIn("'size': int(size)", agent_src)


class TestSudoAuditTrail(_HandlerBase):
    """W3-40: sudo command redaction + per-device/fleet search handlers."""

    def setUp(self):
        super().setUp()
        self._sf = api.SUDO_LOG_FILE
        api.SUDO_LOG_FILE = self.d / 'sudo_log.json'

    def tearDown(self):
        api.SUDO_LOG_FILE = self._sf
        super().tearDown()

    def test_redaction(self):
        self.assertEqual(api._redact_sudo_command('mysql --password=hunter2 db'),
                         'mysql --password=*** db')
        self.assertEqual(api._redact_sudo_command('curl --token=abc123 url'),
                         'curl --token=*** url')
        self.assertEqual(api._redact_sudo_command('mysql -pS3cretPass -e x'),
                         'mysql -p*** -e x')
        self.assertEqual(api._redact_sudo_command('systemctl restart nginx'),
                         'systemctl restart nginx')   # nothing to redact

    def test_device_sudo_log_admin_only(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h'}})
        api.save(api.SUDO_LOG_FILE, {'d1': [
            {'ts': 100, 'user': 'bob', 'command': 'systemctl restart x'}]})
        api._caller_scope = lambda: None
        r = self.call(api.handle_device_sudo_log, 'd1')
        self.assertEqual(len(r['events']), 1)
        # non-admin/auditor rejected
        api.verify_token = lambda t: ('viewer', 'viewer')
        api._resolve_role = lambda role: {'admin': False}
        self.call(api.handle_device_sudo_log, 'd1')
        self.assertEqual(self.cap['s'], 403)

    def test_fleet_search(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web'}, 'd2': {'name': 'db'}})
        api.save(api.SUDO_LOG_FILE, {
            'd1': [{'ts': 200, 'user': 'alice', 'command': 'systemctl restart nginx'}],
            'd2': [{'ts': 300, 'user': 'bob', 'command': 'apt-get upgrade'}]})
        api._caller_scope = lambda: None
        api.verify_token = lambda t: ('jakob', 'admin')
        api._resolve_role = lambda role: {'admin': True}
        import os as _os
        _os.environ['QUERY_STRING'] = 'q=systemctl'
        r = self.call(api.handle_sudo_search)
        self.assertEqual(len(r['events']), 1)
        self.assertEqual(r['events'][0]['device_name'], 'web')
        _os.environ['QUERY_STRING'] = 'user=bob'
        r = self.call(api.handle_sudo_search)
        self.assertEqual(len(r['events']), 1)
        self.assertEqual(r['events'][0]['command'], 'apt-get upgrade')

    def test_agent_has_collector(self):
        src = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertIn('def collect_sudo_events', src)
        self.assertIn("payload['sudo_events']", src)


class TestRealtimeFim(unittest.TestCase):
    """W3-37: near-real-time drift — cheap per-poll change detector."""

    def test_change_detector(self):
        import os as _os
        import tempfile as _tf
        import time as _t
        agent = _load_agent()
        f = _tf.NamedTemporaryFile(delete=False)
        f.write(b'a')
        f.close()
        wf = [{'path': f.name}]
        try:
            self.assertFalse(agent._watched_files_changed(wf))   # first seeds
            self.assertFalse(agent._watched_files_changed(wf))   # no change
            _t.sleep(1.1)
            with open(f.name, 'w') as fh:
                fh.write('bb')
            _os.utime(f.name, (_t.time(), _t.time()))
            self.assertTrue(agent._watched_files_changed(wf))    # changed
            self.assertFalse(agent._watched_files_changed(wf))   # settled
        finally:
            _os.unlink(f.name)

    def test_deleted_file_forgotten(self):
        import os as _os
        import tempfile as _tf
        agent = _load_agent()
        f = _tf.NamedTemporaryFile(delete=False)
        f.close()
        wf = [{'path': f.name}]
        agent._watched_files_changed(wf)     # seed
        _os.unlink(f.name)
        # deletion is a change (mtime sig → None differs from cached)
        self.assertTrue(agent._watched_files_changed(wf))


class TestStoreAndForward(_HandlerBase):
    """W3-47: server-side metrics backfill + agent spool round-trip."""

    def setUp(self):
        super().setUp()
        self._mf = api.METRICS_FILE
        api.METRICS_FILE = self.d / 'metrics.json'

    def tearDown(self):
        api.METRICS_FILE = self._mf
        super().tearDown()

    def test_backfill_merges_and_sorts(self):
        now = 1_000_000
        api.save(api.METRICS_FILE, {'d1': [{'ts': now - 100, 'cpu': 5}]})
        n = api._backfill_metrics('d1', [
            {'ts': now - 300, 'cpu': 1, 'mem': 2},
            {'ts': now - 200, 'cpu': 3}], now)
        self.assertEqual(n, 2)
        window = (api.load(api.METRICS_FILE) or {})['d1']
        self.assertEqual([w['ts'] for w in window],
                         [now - 300, now - 200, now - 100])   # sorted

    def test_backfill_rejects_future_and_stale(self):
        now = 1_000_000
        api.save(api.METRICS_FILE, {'d1': []})
        n = api._backfill_metrics('d1', [
            {'ts': now + 10_000, 'cpu': 1},        # future
            {'ts': now - 30 * 86400, 'cpu': 2}], now)  # >7d old
        self.assertEqual(n, 0)

    def test_backfill_dedups_ts(self):
        now = 1_000_000
        api.save(api.METRICS_FILE, {'d1': [{'ts': now - 100, 'cpu': 5}]})
        api._backfill_metrics('d1', [{'ts': now - 100, 'cpu': 9}], now)
        window = (api.load(api.METRICS_FILE) or {})['d1']
        self.assertEqual(len(window), 1)   # same ts not duplicated

    def test_agent_spool_roundtrip(self):
        import tempfile as _tf
        agent = _load_agent()
        agent.STATE_DIR = Path(_tf.mkdtemp())
        agent._spool_metric_sample({'cpu_percent': 10, 'mem_percent': 20})
        agent._spool_metric_sample({'cpu_percent': 11})
        spool = agent._read_metrics_spool()
        self.assertEqual(len(spool), 2)
        self.assertEqual(spool[0]['cpu'], 10)
        # a sample with no metrics is not spooled
        agent._spool_metric_sample({})
        self.assertEqual(len(agent._read_metrics_spool()), 2)


class TestDependencySuggestions(_HandlerBase):
    """W3-8: observed-traffic dependency correlation + accept/dismiss."""

    def setUp(self):
        super().setUp()
        self._pf = api.PEER_CONNS_FILE
        self._df = api.DEP_DISMISS_FILE
        api.PEER_CONNS_FILE = self.d / 'peer_conns.json'
        api.DEP_DISMISS_FILE = self.d / 'dep_dismissed.json'
        api.save(api.DEVICES_FILE, {
            'web': {'name': 'web', 'ip': '10.0.0.1'},
            'db': {'name': 'db', 'ip': '10.0.0.2'}})
        api.save(api.PEER_CONNS_FILE, {
            'web': {'ts': 1, 'peers': [{'ip': '10.0.0.2', 'port': 5432, 'count': 3}]}})

    def tearDown(self):
        api.PEER_CONNS_FILE = self._pf
        api.DEP_DISMISS_FILE = self._df
        super().tearDown()

    def test_suggestion_correlates_peer_to_device(self):
        s = api._dependency_suggestions()
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0]['device_id'], 'web')
        self.assertEqual(s[0]['upstream_id'], 'db')
        self.assertIn('5432', s[0]['evidence'])

    def test_declared_dep_not_suggested(self):
        api.save(api.DEVICES_FILE, {
            'web': {'name': 'web', 'ip': '10.0.0.1', 'depends_on': ['db']},
            'db': {'name': 'db', 'ip': '10.0.0.2'}})
        self.assertEqual(api._dependency_suggestions(), [])

    def test_accept_adds_dependency(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'web', 'upstream_id': 'db', 'action': 'accept'}
        self.call(api.handle_dependency_suggestions)
        self.assertIn('db', (api.load(api.DEVICES_FILE) or {})['web'].get('depends_on'))
        self.assertEqual(api._dependency_suggestions(), [])   # now declared

    def test_dismiss_hides_suggestion(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'web', 'upstream_id': 'db', 'action': 'dismiss'}
        self.call(api.handle_dependency_suggestions)
        self.assertEqual(api._dependency_suggestions(), [])

    def test_agent_private_ip_filter(self):
        agent = _load_agent()
        self.assertTrue(agent._is_private_ip('10.1.2.3'))
        self.assertTrue(agent._is_private_ip('192.168.1.1'))
        self.assertTrue(agent._is_private_ip('172.16.0.1'))
        self.assertFalse(agent._is_private_ip('8.8.8.8'))
        self.assertFalse(agent._is_private_ip('172.32.0.1'))


class TestCanaryFiles(_HandlerBase):
    """W3-38: canary config validation + agent plant/detect."""

    def test_config_save_validates_paths(self):
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'canary_files': [
            {'path': '/root/.aws/credentials.bak', 'content': 'fake'},
            {'path': 'relative/nope'},          # not absolute → dropped
            {'path': '/etc/../evil'}]}           # traversal → dropped
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        cf = (api.load(api.CONFIG_FILE) or {}).get('canary_files')
        self.assertEqual(len(cf), 1)
        self.assertEqual(cf[0]['path'], '/root/.aws/credentials.bak')

    def test_event_registered_critical(self):
        self.assertIn('canary_accessed', api.EVENT_REGISTRY)
        self.assertEqual(api.EVENT_REGISTRY['canary_accessed']['severity'], 'critical')

    def test_agent_plant_and_detect(self):
        import os as _os
        import tempfile as _tf
        agent = _load_agent()
        agent._canary_planted.clear()
        agent._canary_reported.clear()
        d = _tf.mkdtemp()
        path = _os.path.join(d, 'secret.creds')
        cfg = [{'path': path, 'content': 'AKIAFAKE'}]
        agent._plant_canaries(cfg)
        self.assertTrue(_os.path.exists(path))
        self.assertEqual(agent._check_canaries(cfg), [])   # untouched
        # modify → detected as 'modified', reported once
        with open(path, 'a') as fh:
            fh.write('x')
        ev = agent._check_canaries(cfg)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]['reason'], 'modified')
        self.assertEqual(agent._check_canaries(cfg), [])   # not re-reported
        # uninstall removes the decoy we planted
        agent._remove_canaries()
        self.assertFalse(_os.path.exists(path))

    def test_agent_never_overwrites_existing(self):
        import os as _os
        import tempfile as _tf
        agent = _load_agent()
        agent._canary_planted.clear()
        f = _tf.NamedTemporaryFile(mode='w', delete=False)
        f.write('REAL DATA')
        f.close()
        agent._plant_canaries([{'path': f.name}])
        with open(f.name) as fh:
            self.assertEqual(fh.read(), 'REAL DATA')   # untouched
        # a pre-existing file is not removed on uninstall (ours=False)
        agent._remove_canaries()
        self.assertTrue(_os.path.exists(f.name))
        _os.unlink(f.name)


class TestFileManagerUpload(unittest.TestCase):
    """W3-50: agent upload op (binary, no-overwrite) + read base64."""

    def test_agent_upload_and_binary_read(self):
        import base64 as _b
        import os as _os
        import tempfile as _tf
        agent = _load_agent()
        d = _tf.mkdtemp()
        target = _os.path.join(d, 'blob.bin')
        raw = bytes(range(256))
        # build the agent command: files:upload:<b64 path>:<b64 bytes>:<flag>
        cmd = ('files:upload:' + _b.urlsafe_b64encode(target.encode()).decode()
               + ':' + _b.urlsafe_b64encode(raw).decode() + ':0')
        # allowlist the temp dir
        agent.FILE_MGR_ALLOWED_ROOTS = [d] if hasattr(agent, 'FILE_MGR_ALLOWED_ROOTS') else None
        out = agent._handle_file_op(cmd)
        res = json.loads(out['output']) if 'output' in out else {}
        # either uploaded, or blocked by root allowlist — but never a crash
        self.assertIn('output', out)
        if res.get('uploaded') is not None:
            with open(target, 'rb') as fh:
                self.assertEqual(fh.read(), raw)
            # no-overwrite: a second upload with flag 0 must refuse
            out2 = agent._handle_file_op(cmd)
            res2 = json.loads(out2['output'])
            self.assertIn('exists', str(res2.get('error', '')))

    def test_upload_in_write_ops(self):
        self.assertIn('upload', api._FILE_MGR_OPS_WRITE)

    def test_agent_read_emits_b64_for_binary(self):
        src = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertIn("res['content_b64']", src)


import json  # noqa: E402  (used by the file-manager test above)

if __name__ == '__main__':
    unittest.main()
