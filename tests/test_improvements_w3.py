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


if __name__ == '__main__':
    unittest.main()
