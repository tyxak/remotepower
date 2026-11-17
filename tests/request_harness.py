#!/usr/bin/env python3
"""A request through the real dispatcher, for tests of who sees what.

`RequestCase` gives a test a fresh `api.py` over a data directory of its own, tokens for each kind of caller (the stub stands in for the
session store only: `require_auth`, `require_perm`, the tenant gate and the scope filter are the real ones), a way to store hosts through
the storage layer so the SQL backends see them, and `request()`, which runs `main()` with the gates that run before any handler:

    token  caller
    k      admin of the default tenant (the operator of the installation)
    v      a viewer, mc an mcp key, au an auditor, fi a finance user (all of the default tenant)
    ops    a custom role with action permissions, rw a custom role with none
    ro     a custom role without action permissions, scoped to the group prod
    ta     an administrator of the tenant acme, tb of the tenant globex, tv a viewer of acme

The tenants are only in force when a test stores `tenancy_enforced`.
"""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-harness-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

TOKENS = {
    'k': ('admin', 'admin'), 'v': ('vera', 'viewer'), 'mc': ('mcp-bot', 'mcp'), 'au': ('audie', 'auditor'), 'fi': ('finn', 'finance'),
    'ops': ('olga', 'ops'), 'rw': ('rhea', 'ro-all'), 'ro': ('rita', 'ro-prod'),
    'ta': ('alice', 'admin'), 'tb': ('bob', 'admin'), 'tv': ('vic', 'viewer'),
}
TENANT = {'admin': 'default', 'vera': 'default', 'mcp-bot': 'default', 'audie': 'default', 'finn': 'default', 'olga': 'default', 'rhea': 'default',
          'rita': 'default', 'alice': 'acme', 'bob': 'globex', 'vic': 'acme'}
ROLES = {'roles': [
    {'name': 'ops', 'permissions': ['patch', 'command'], 'scope': {'type': 'all'}},
    {'name': 'ro-all', 'permissions': [], 'scope': {'type': 'all'}},
    {'name': 'ro-prod', 'permissions': [], 'scope': {'type': 'groups', 'values': ['prod']}},
]}


class RequestCase(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self.addCleanup(shutil.rmtree, str(self.api.DATA_DIR), True)       # the data directory of each test is on tmpfs
        self.api.verify_token = lambda token: TOKENS.get(token, (None, None))
        self.api._caller_effective_tenant = lambda user: TENANT.get(user, 'default')
        self.api.audit_log = lambda *a, **k: None
        self.fired = []
        self.api.fire_webhook = lambda ev, payload=None, *a, **k: self.fired.append((ev, payload))
        self.api.save(self.api.ROLES_FILE, ROLES)
        self.api._LOAD_CACHE.clear()

    def put(self, devices=None, **cfg):
        """Store hosts and settings through the storage layer: under SQLite and Postgres a store is a table, and a file written beside it is not what the server reads."""
        if devices is not None:
            self.api.save(self.api.DEVICES_FILE, devices)
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def request(self, path, method='GET', token='k', body=None, query=''):
        """A request through main(): the dispatcher, with the gates that run before a handler does. Returns (status, body)."""
        names = ('REQUEST_METHOD', 'PATH_INFO', 'REMOTE_ADDR', 'CONTENT_LENGTH', 'QUERY_STRING', 'HTTP_AUTHORIZATION', 'HTTP_X_TOKEN')
        saved = {n: os.environ.get(n) for n in names}

        def go():
            os.environ.update(PATH_INFO=path)
            self.api.main()
        try:
            return _run(self.api, go, body, method=method, env={'HTTP_AUTHORIZATION': 'Bearer ' + token, 'QUERY_STRING': query})
        finally:
            for n, v in saved.items():
                if v is None:
                    os.environ.pop(n, None)
                else:
                    os.environ[n] = v

    def call(self, fn, *args, body=None, method='GET', token='k', query=''):
        """A handler run as a request, without the dispatcher: (status, body)."""
        return _run(self.api, lambda: fn(*args), body, method=method, env={'HTTP_AUTHORIZATION': 'Bearer ' + token, 'QUERY_STRING': query})
