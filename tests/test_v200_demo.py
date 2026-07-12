#!/usr/bin/env python3
"""
Tests for v2.0 demo / read-only mode.

Covers:
  - _is_demo_read_only() reads RP_READ_ONLY from env correctly
  - _enforce_read_only() blocks mutations and returns 403 + demo flag
  - GET requests pass through unchanged
  - Whitelisted endpoints (login, logout, totp/verify) pass through
  - public-info exposes the read_only flag

Pattern follows tests/test_v200_docs.py — bootstrap a tmp data dir,
import api, then poke the helpers directly with respond capture.
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v200_demo", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


def _capture_respond():
    def fake(status, data):
        raise _Captured(status, data)
    api.respond = fake


def _set_env(method='GET', path='/api/devices', read_only=None):
    os.environ['REQUEST_METHOD'] = method
    os.environ['PATH_INFO'] = path
    # Only touch RP_READ_ONLY if the caller explicitly passes a value.
    # Tests typically set it once at the top of a test method then call
    # _set_env multiple times; clobbering it on every call would undo
    # the setup.
    if read_only is not None:
        if read_only == '':
            os.environ.pop('RP_READ_ONLY', None)
        else:
            os.environ['RP_READ_ONLY'] = read_only


# ─── Env-var parsing ──────────────────────────────────────────────────────────


class TestIsDemoReadOnly(unittest.TestCase):

    def tearDown(self):
        os.environ.pop('RP_READ_ONLY', None)

    def test_unset_is_false(self):
        os.environ.pop('RP_READ_ONLY', None)
        self.assertFalse(api._is_demo_read_only())

    def test_empty_is_false(self):
        os.environ['RP_READ_ONLY'] = ''
        self.assertFalse(api._is_demo_read_only())

    def test_zero_is_false(self):
        os.environ['RP_READ_ONLY'] = '0'
        self.assertFalse(api._is_demo_read_only())

    def test_false_is_false(self):
        os.environ['RP_READ_ONLY'] = 'false'
        self.assertFalse(api._is_demo_read_only())
        os.environ['RP_READ_ONLY'] = 'FALSE'
        self.assertFalse(api._is_demo_read_only())
        os.environ['RP_READ_ONLY'] = 'no'
        self.assertFalse(api._is_demo_read_only())
        os.environ['RP_READ_ONLY'] = 'off'
        self.assertFalse(api._is_demo_read_only())

    def test_one_is_true(self):
        os.environ['RP_READ_ONLY'] = '1'
        self.assertTrue(api._is_demo_read_only())

    def test_true_is_true(self):
        os.environ['RP_READ_ONLY'] = 'true'
        self.assertTrue(api._is_demo_read_only())
        os.environ['RP_READ_ONLY'] = 'yes'
        self.assertTrue(api._is_demo_read_only())

    def test_anything_truthy_is_true(self):
        # Liberal interpretation — anything that isn't a known false-y
        # value is treated as enabled. Covers 'enabled', 'demo', etc.
        os.environ['RP_READ_ONLY'] = 'demo'
        self.assertTrue(api._is_demo_read_only())


# ─── _enforce_read_only ───────────────────────────────────────────────────────


class TestEnforceReadOnly(unittest.TestCase):

    def setUp(self):
        _capture_respond()

    def tearDown(self):
        os.environ.pop('RP_READ_ONLY', None)

    def _expect_blocked(self):
        try:
            api._enforce_read_only()
        except _Captured as c:
            return c
        self.fail('_enforce_read_only() should have called respond()')

    def _expect_allowed(self):
        # No exception thrown == handler returned normally
        api._enforce_read_only()

    def test_normal_mode_passes_everything(self):
        # No env var → enforce() is a no-op for any method/path
        os.environ.pop('RP_READ_ONLY', None)
        for method in ('GET', 'POST', 'PUT', 'DELETE'):
            for path in ('/api/devices', '/api/devices/abc', '/api/login'):
                _set_env(method=method, path=path)
                self._expect_allowed()

    def test_get_always_allowed_in_demo(self):
        os.environ['RP_READ_ONLY'] = '1'
        for path in ('/api/devices', '/api/cmdb/foo', '/api/audit-log',
                     '/api/anything', '/api/devices/xyz/metrics'):
            _set_env(method='GET', path=path)
            self._expect_allowed()

    def test_post_blocked_in_demo(self):
        os.environ['RP_READ_ONLY'] = '1'
        _set_env(method='POST', path='/api/devices/abc/cve-scan')
        c = self._expect_blocked()
        self.assertEqual(c.status, 403)
        self.assertTrue(c.body['demo'])
        self.assertIn('read-only', c.body['error'].lower())

    def test_put_blocked_in_demo(self):
        os.environ['RP_READ_ONLY'] = '1'
        _set_env(method='PUT', path='/api/cmdb/abc')
        c = self._expect_blocked()
        self.assertEqual(c.status, 403)

    def test_delete_blocked_in_demo(self):
        os.environ['RP_READ_ONLY'] = '1'
        _set_env(method='DELETE', path='/api/devices/abc')
        c = self._expect_blocked()
        self.assertEqual(c.status, 403)

    def test_login_allowed_in_demo(self):
        # Visitors must be able to log in to the demo user, even when
        # the rest of the API is locked down. Login is POST.
        os.environ['RP_READ_ONLY'] = '1'
        _set_env(method='POST', path='/api/login')
        self._expect_allowed()

    def test_logout_allowed_in_demo(self):
        os.environ['RP_READ_ONLY'] = '1'
        _set_env(method='POST', path='/api/logout')
        self._expect_allowed()

    def test_totp_verify_allowed_in_demo(self):
        os.environ['RP_READ_ONLY'] = '1'
        _set_env(method='POST', path='/api/totp/verify')
        self._expect_allowed()

    def test_heartbeat_blocked_in_demo(self):
        # Heartbeat is POST — and a demo server has no real agents, so
        # blocking is correct. If somebody points an agent at the demo,
        # they should learn about it via 403 rather than silently
        # populating fake state.
        os.environ['RP_READ_ONLY'] = '1'
        _set_env(method='POST', path='/api/heartbeat')
        c = self._expect_blocked()
        self.assertEqual(c.status, 403)

    def test_demo_payload_includes_helpful_url(self):
        os.environ['RP_READ_ONLY'] = '1'
        _set_env(method='POST', path='/api/devices/x/exec')
        c = self._expect_blocked()
        # The error body should point users at the project; test that
        # specific text since it's part of the API contract.
        self.assertIn('github.com/tyxak/remotepower', c.body.get('detail', ''))


class TestVersionCheckReadOnly(unittest.TestCase):
    """A public read-only demo must never show the 'vX is available — run
    git pull && install-server.sh' update banner: the viewer can't upgrade it
    and it makes the demo look neglected. handle_version_check reports
    up-to-date (and skips the outbound GitHub call) when RP_READ_ONLY is set."""

    def setUp(self):
        _capture_respond()
        self._ra = api.require_auth
        api.require_auth = lambda *a, **k: ('demo', 'viewer')

    def tearDown(self):
        api.require_auth = self._ra
        os.environ.pop('RP_READ_ONLY', None)

    def test_readonly_demo_never_advertises_update(self):
        os.environ['RP_READ_ONLY'] = '1'
        # Seed a cached "latest" far ahead of local — the read-only short-circuit
        # must win over it (and must NOT hit the network).
        api.save(api.CONFIG_FILE, {'_github_latest_version': '999.0.0',
                                   '_github_latest_ts': int(__import__('time').time())})
        with self.assertRaises(_Captured) as cm:
            api.handle_version_check()
        body = cm.exception.body
        self.assertEqual(cm.exception.status, 200)
        self.assertFalse(body['update_available'])
        self.assertEqual(body['current'], body['latest'])
        self.assertEqual(body['latest'], api.SERVER_VERSION)

    def test_non_demo_still_reports_update_from_cache(self):
        os.environ.pop('RP_READ_ONLY', None)
        api.save(api.CONFIG_FILE, {'_github_latest_version': '999.0.0',
                                   '_github_latest_ts': int(__import__('time').time())})
        with self.assertRaises(_Captured) as cm:
            api.handle_version_check()
        body = cm.exception.body
        self.assertTrue(body['update_available'])
        self.assertEqual(body['latest'], '999.0.0')


if __name__ == '__main__':
    unittest.main()
