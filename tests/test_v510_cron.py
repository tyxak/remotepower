"""v5.1.0 — host cron + systemd-timer management.

Crontab content is arbitrary shell, so the security guarantee is that it rides
base64 to the agent and is installed via a temp file (`crontab -u <user> <file>`,
argv — never a shell), while the user / timer-unit tokens are regex-pinned.
"""
import base64
import importlib.util
import json
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_AGENT_PY = _ROOT / 'client' / 'remotepower-agent.py'

_spec = importlib.util.spec_from_file_location('api_cron', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _load_agent():
    spec = importlib.util.spec_from_file_location('rpa_cron', _AGENT_PY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class _FakeProc:
    def __init__(self, rc=0, stderr=''):
        self.returncode = rc
        self.stdout = ''
        self.stderr = stderr


class TestServerValidators(unittest.TestCase):
    def test_user_regex(self):
        self.assertTrue(api._CRON_USER_RE.match('root'))
        self.assertTrue(api._CRON_USER_RE.match('www-data'))
        self.assertFalse(api._CRON_USER_RE.match('root; rm -rf /'))
        self.assertFalse(api._CRON_USER_RE.match('-bad'))
        self.assertFalse(api._CRON_USER_RE.match(''))

    def test_timer_regex(self):
        self.assertTrue(api._TIMER_UNIT_RE.match('logrotate.timer'))
        self.assertTrue(api._TIMER_UNIT_RE.match('backup@daily.timer'))
        self.assertFalse(api._TIMER_UNIT_RE.match('logrotate.service'))
        self.assertFalse(api._TIMER_UNIT_RE.match('a.timer; reboot'))


class TestApiWiring(unittest.TestCase):
    def test_handlers_and_routes(self):
        self.assertTrue(hasattr(api, 'handle_cron_overview'))
        self.assertTrue(hasattr(api, 'handle_device_cron_action'))
        src = (_CGI / 'api.py').read_text()
        self.assertIn("('GET', '/api/cron'): handle_cron_overview", src)
        self.assertIn("pi.endswith('/cron-action') and m == 'POST'", src)
        h = src[src.index('def handle_device_cron_action'):
                src.index('def handle_device_cron_action') + 2200]
        self.assertIn("require_perm('command'", h)
        self.assertIn("audit_log(actor, 'host_cron'", h)
        self.assertIn("_queue_command(dev_id, command, actor)", h)


class TestAgentCronOps(unittest.TestCase):
    def setUp(self):
        self.m = _load_agent()
        self.calls = []

    def _patch_run(self, rc=0, capture_file=False):
        store = {}

        def fake(argv, **kw):
            self.calls.append(argv)
            if capture_file and len(argv) >= 4 and argv[0] == 'crontab':
                store['content'] = Path(argv[3]).read_text()
            return _FakeProc(rc)
        self.m.subprocess.run = fake
        return store

    def _cmd(self, op, arg, content=None):
        parts = ['cron', op, base64.urlsafe_b64encode(arg.encode()).decode()]
        if content is not None:
            parts.append(base64.urlsafe_b64encode(content.encode()).decode())
        return ':'.join(parts)

    def test_set_writes_via_tempfile_argv(self):
        store = self._patch_run(capture_file=True)
        # A cron line full of shell metacharacters must survive verbatim — proving
        # it never went through a shell.
        line = '0 3 * * * /bin/sh -c "backup && echo done | tee /var/log/b.log; date"'
        r = self.m._handle_file_op  # sanity: file op exists too
        out = self.m._handle_cron_op(self._cmd('set', 'root', line + '\n'))
        self.assertEqual(out['rc'], 0)
        self.assertEqual(self.calls[0][:3], ['crontab', '-u', 'root'])
        self.assertIn(line, store['content'])

    def test_invalid_user_rejected(self):
        self._patch_run()
        out = self.m._handle_cron_op(self._cmd('set', 'root; reboot', 'x\n'))
        self.assertEqual(out['rc'], 1)
        self.assertEqual(self.calls, [])  # never shelled out

    def test_del(self):
        self._patch_run()
        out = self.m._handle_cron_op(self._cmd('del', 'www-data'))
        self.assertEqual(out['rc'], 0)
        self.assertEqual(self.calls[0], ['crontab', '-u', 'www-data', '-r'])

    def test_timer_enable_argv(self):
        self._patch_run()
        out = self.m._handle_cron_op(self._cmd('timer_enable', 'logrotate.timer'))
        self.assertEqual(out['rc'], 0)
        self.assertEqual(self.calls[0], ['systemctl', 'enable', '--', 'logrotate.timer'])

    def test_timer_bad_unit_rejected(self):
        self._patch_run()
        out = self.m._handle_cron_op(self._cmd('timer_start', 'evil; reboot'))
        self.assertEqual(out['rc'], 1)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
