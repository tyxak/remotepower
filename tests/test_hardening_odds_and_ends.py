"""Three smaller fixes from the project-wide security pass.

  * the heartbeat's debug line wrote a device id and version straight from an
    unauthenticated body, so a newline forged whole log lines;
  * any signed-in role could run every monitor again with no limit;
  * the installers wrote their logs and the fetched CA to fixed or guessable names
    in /tmp as root.
"""
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-odds-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class _Captured(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


def _fresh():
    d = tempfile.mkdtemp(prefix='rp-odds-')
    os.environ['RP_DATA_DIR'] = d
    for name in ('USERS_FILE', 'TOKENS_FILE', 'DEVICES_FILE', 'AUDIT_LOG_FILE', 'CONFIG_FILE',
                 'RATELIMIT_FILE', 'DEBUG_LOG_FILE'):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    api._begin_request()
    api.ensure_default_user()


def _call(fn, method='POST', body=None, token=None):
    api._begin_request()
    os.environ['REQUEST_METHOD'] = method
    os.environ['PATH_INFO'] = '/api/x'
    os.environ['REMOTE_ADDR'] = '203.0.113.50'
    raw = b'' if body is None else json.dumps(body).encode()
    os.environ['CONTENT_LENGTH'] = str(len(raw))
    api.sys.stdin = _Stdin(raw)
    if token:
        os.environ['HTTP_X_TOKEN'] = token
    else:
        os.environ.pop('HTTP_X_TOKEN', None)

    def fake(status, data=None, *a, **k):
        raise _Captured(status, data)
    orig = api.respond
    api.respond = fake
    try:
        fn()
        return None
    except _Captured as c:
        return c.status
    finally:
        api.respond = orig
        os.environ.pop('HTTP_X_TOKEN', None)


class TestHeartbeatDebugLine(unittest.TestCase):
    def setUp(self):
        _fresh()

    def test_log_field_keeps_one_harmless_token(self):
        self.assertEqual(api._log_field('abc-123_x', 64), 'abc-123_x')
        out = api._log_field('x\n[2026-01-01T00:00:00] heartbeat dev=forged ver=9', 64)
        self.assertNotIn('\n', out)
        self.assertNotIn(' ', out)
        self.assertLessEqual(len(api._log_field('a' * 500, 64)), 64)

    def test_a_newline_in_the_device_id_or_version_cannot_forge_a_line(self):
        api.save(api.CONFIG_FILE, {'debug_logging': True})
        api._invalidate_load_cache(api.CONFIG_FILE)
        status = _call(api.handle_heartbeat,
                       body={'device_id': 'dev1\n[2026-01-01T00:00:00] heartbeat dev=forged ver=9',
                             'token': 'x', 'version': '7.3.0\n[2026-01-01T00:00:00] ADMIN LOGIN'})
        self.assertEqual(status, 403)
        lines = Path(api.DEBUG_LOG_FILE).read_text().splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertNotIn('forged', lines[0].split('heartbeat dev=', 1)[0])


class TestMonitorRunIsThrottled(unittest.TestCase):
    def setUp(self):
        _fresh()
        users = api.load(api.USERS_FILE)
        users['viewer1'] = {'password_hash': 'x', 'role': 'viewer', 'created': int(time.time())}
        api.save(api.USERS_FILE, users)
        api._begin_request()
        self.token = api._mint_session('viewer1')
        api._begin_request()
        self.runs = 0
        self._orig = api._execute_monitor_checks

        def counting(monitors):
            self.runs += 1
            return []
        api._execute_monitor_checks = counting

    def tearDown(self):
        api._execute_monitor_checks = self._orig

    def test_a_loop_from_one_account_is_cut_off_and_runs_stop(self):
        seen = [_call(api.handle_monitor_run, method='GET', token=self.token) for _ in range(40)]
        self.assertIn(429, seen, seen)
        self.assertLessEqual(self.runs, 30)               # the monitors really were not run again

    def test_normal_use_is_untouched(self):
        for _ in range(5):
            self.assertNotEqual(_call(api.handle_monitor_run, method='GET', token=self.token), 429)


class TestInstallersDoNotUseGuessableTempNames(unittest.TestCase):
    def _text(self, rel):
        return (_ROOT / rel).read_text()

    def test_install_sh_uses_mktemp_for_the_cert_log(self):
        s = self._text('install.sh')
        self.assertNotIn('/tmp/rp-genca.$$', s)
        self.assertRegex(s, r'genlog="\$\(mktemp ')

    def test_the_container_entrypoint_uses_mktemp_for_the_cert_log(self):
        s = self._text('docker/entrypoint.sh')
        self.assertNotIn('/tmp/genca.log', s)
        self.assertIn('GENCA_LOG="$(mktemp)"', s)

    def test_the_agent_entrypoint_checks_and_installs_the_same_private_file(self):
        s = self._text('docker/agent-entrypoint.sh')
        self.assertNotIn('/tmp/ca.crt', s)
        self.assertIn('ca_tmp=$(mktemp)', s)
        # the file the fingerprint was checked on is the one that is installed
        self.assertRegex(s, r'openssl x509 -in "\$ca_tmp"')
        self.assertRegex(s, r'mv "\$ca_tmp" /etc/remotepower/ca\.crt')


if __name__ == '__main__':
    unittest.main()
