"""Behavioural authorization smoke test.

Several tests asserted admin-only protection by grepping the handler source for
`require_admin_auth()`. That checks a string exists, not that a viewer is
actually refused — a handler could grep-match yet still leak (wrong gate, early
return, refactor). This drives the real handlers with a *viewer* token and
asserts a 403, which is the guarantee that actually matters for these
destructive / sensitive endpoints.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


class _Captured(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body


class _StdinShim:
    def __init__(self, raw): self._raw = raw
    def read(self, *a): return self._raw


def _set_request(method, path, body=None, token=None):
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = path
    raw = b"" if body is None else json.dumps(body).encode()
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _StdinShim(raw)
    if token:
        os.environ["HTTP_X_TOKEN"] = token
    else:
        os.environ.pop("HTTP_X_TOKEN", None)


def _status_of(fn):
    """Run a handler thunk and return the HTTP status it responds with."""
    def fake(status, data):
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


def _seed_viewer():
    d = tempfile.mkdtemp()
    os.environ["RP_DATA_DIR"] = d
    for name in ("USERS_FILE", "TOKENS_FILE", "DEVICES_FILE",
                 "AUDIT_LOG_FILE", "CONFIG_FILE"):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    api.ensure_default_user()
    users = api.load(api.USERS_FILE)
    users["viewer1"] = {"password_hash": "x", "created": int(time.time()),
                        "role": "viewer"}
    api.save(api.USERS_FILE, users)
    token = api.make_token()
    api.save(api.TOKENS_FILE, {token: {
        "user": "viewer1", "created": int(time.time()),
        "ttl": 3600, "admin": False, "remember": False}})
    return token


class TestAdminOnlyEndpointsRejectViewer(unittest.TestCase):
    # (handler, call-args, method, path) — each is admin-only and must 403 a
    # viewer. require_admin_auth() runs first, so the dummy args never matter.
    ENDPOINTS = [
        (lambda: api.handle_security_diag(), 'GET', '/api/security/diag'),
        (lambda: api.handle_proxmox_lxc_create(), 'POST', '/api/proxmox/lxc/create'),
        (lambda: api.handle_proxmox_lxc_delete('123'), 'DELETE', '/api/proxmox/lxc/123'),
        (lambda: api.handle_device_speedtest('dev1'), 'POST', '/api/devices/dev1/speedtest'),
        (lambda: api.handle_device_host_config_put('dev1'), 'PUT', '/api/devices/dev1/host-config'),
    ]

    def setUp(self):
        self.token = _seed_viewer()

    def test_viewer_gets_403(self):
        for fn, method, path in self.ENDPOINTS:
            _set_request(method, path, body={}, token=self.token)
            status = _status_of(fn)
            self.assertEqual(status, 403, f"{method} {path} must 403 a viewer (got {status})")

    def test_no_token_gets_401(self):
        _set_request('GET', '/api/security/diag', token=None)
        status = _status_of(api.handle_security_diag)
        self.assertEqual(status, 401)


if __name__ == '__main__':
    unittest.main()
