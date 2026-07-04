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


if __name__ == '__main__':
    unittest.main()
