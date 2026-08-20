#!/usr/bin/env python3
"""A tenant admin saw other tenants' credential metadata on their own device.

`handle_device_inherited_credentials` tenant-gates the DEVICE — v6.3.0 added
`_scope_block_device` for exactly that — and then listed every scoped credential
whose scope matched, with no tenant filter.

`_caller_scope_covers_credential` is an RBAC-SCOPE check, and a tenant admin
resolves to `_caller_scope() is None`, so it returns True for everything. The
result: a tenant admin looking at a device they legitimately own saw the label,
username and note of any other tenant's credential whose scope value happened to
match. Scope values are site / group / tag names, and those collide across
tenants as a matter of course — "web", "prod", "dc1".

Half-applied rule. `handle_scoped_credentials_list` and `_reveal` have applied
`_scoped_cred_visible` since v6.4.3; this third reader was left out. Two of four
consumers filtered, so the file read as though the rule was enforced.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(_ROOT / 'tests'))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-icred-'))
_spec = importlib.util.spec_from_file_location('api_icred', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import srcpin                                                    # noqa: E402

# cmdb_handlers is a BOUND module: its `A.` proxy is wired when api.py execs it,
# so importing it standalone leaves A unbound and every call raises
# AttributeError on None. Reach the handler through api, which is where the name
# is re-imported and where the dispatcher resolves it.


class TestTheRatio(unittest.TestCase):
    """The population, not the one handler — that is what was wrong."""

    def test_every_reader_of_the_credential_store_filters_by_tenant(self):
        import re
        unfiltered = []
        for rel in ('server/cgi-bin/cmdb_handlers.py', 'server/cgi-bin/api.py'):
            src = (_ROOT / rel).read_text()
            for m in re.finditer(r'_scoped_creds_load\(\)', src):
                fn = re.findall(r'^def (\w+)', src[:m.start()], re.M)[-1]
                body = srcpin.py_function(src, fn)
                if not any(g in body for g in ('_scoped_cred_visible',
                                               '_tenant_visible')):
                    unfiltered.append(fn)
        self.assertEqual([], unfiltered,
                         f'read the scoped-credential store with no tenant '
                         f'filter: {unfiltered}')

    def test_the_enumeration_found_the_readers(self):
        """Positive control: a regex that matched nothing makes the ratio
        above trivially perfect."""
        import re
        n = sum(len(re.findall(r'_scoped_creds_load\(\)', (_ROOT / rel).read_text()))
                for rel in ('server/cgi-bin/cmdb_handlers.py',
                            'server/cgi-bin/api.py'))
        self.assertGreaterEqual(n, 4)


class TestTheHandler(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-icred-run-'))
        self._files = {n: getattr(api, n) for n in
                       ('DATA_DIR', 'DEVICES_FILE', 'SCOPED_VAULT_FILE')}
        api.DATA_DIR = self.dir
        for n in ('DEVICES_FILE', 'SCOPED_VAULT_FILE'):
            setattr(api, n, self.dir / Path(self._files[n]).name)
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', '_tenant_gate', '_scope_block_device')}
        api.require_auth = lambda *a, **k: 'admin@acme'
        api._scope_block_device = lambda d: None      # device gate proven elsewhere
        # Both tenants tag a host "web" — the whole point.
        api.save(api.DEVICES_FILE, {
            'acme1': {'name': 'acme-web', 'tenant': 'acme', 'tags': ['web']},
        })
        api.save(api.SCOPED_VAULT_FILE, {'creds': [
            {'id': 'c-acme', 'scope_type': 'tag', 'scope_value': 'web',
             'label': 'acme switch', 'username': 'acmeadmin', 'note': 'ours',
             'nonce': 'n', 'ct': 'x', 'tenant': 'acme'},
            {'id': 'c-globex', 'scope_type': 'tag', 'scope_value': 'web',
             'label': 'globex core switch', 'username': 'gxroot',
             'note': 'globex only', 'nonce': 'n', 'ct': 'y', 'tenant': 'globex'},
        ]})
        self.cap = {}
        self._resp = api.respond

        def _r(s, b=None):
            self.cap['s'], self.cap['b'] = s, b
            raise api.HTTPError(s, b)
        api.respond = _r

    def tearDown(self):
        for n, v in self._files.items():
            setattr(api, n, v)
        for n, v in self._orig.items():
            setattr(api, n, v)
        api.respond = self._resp

    def _get(self, tenant):
        api._tenant_gate = lambda: tenant
        api._RCTX.environ = {'REQUEST_METHOD': 'GET',
                             'PATH_INFO': '/api/cmdb/acme1/inherited-credentials',
                             'QUERY_STRING': ''}
        self.cap.clear()
        try:
            api.handle_device_inherited_credentials('acme1')
        except (api.HTTPError, SystemExit):
            pass
        return self.cap.get('b') or {}

    def test_the_other_tenants_credential_is_not_listed(self):
        got = self._get('acme')
        ids = {c.get('id') for c in got.get('credentials', [])}
        self.assertNotIn('c-globex', ids,
                         "another tenant's credential metadata is on this "
                         "device's inherited list")

    def test_your_own_credential_still_is(self):
        """Positive control. A filter that dropped everything would satisfy the
        assertion above and break the feature."""
        got = self._get('acme')
        ids = {c.get('id') for c in got.get('credentials', [])}
        self.assertIn('c-acme', ids)

    def test_no_label_username_or_note_from_the_other_tenant_leaks(self):
        """Checking ids alone would miss a projection that merged fields."""
        blob = str(self._get('acme'))
        for secret in ('globex core switch', 'gxroot', 'globex only'):
            self.assertNotIn(secret, blob)

    def test_a_superadmin_sees_both(self):
        got = self._get(None)
        self.assertEqual({'c-acme', 'c-globex'},
                         {c.get('id') for c in got.get('credentials', [])})

    def test_a_credential_with_no_tenant_belongs_to_the_default_tenant(self):
        """Pre-v6.4.3 credentials carry no tenant. They must resolve the same
        way the list handler already resolves them, or upgrading hides them."""
        api.save(api.SCOPED_VAULT_FILE, {'creds': [
            {'id': 'c-legacy', 'scope_type': 'tag', 'scope_value': 'web',
             'label': 'legacy', 'username': 'u', 'nonce': 'n', 'ct': 'z'},
        ]})
        self.assertNotIn('c-legacy',
                         {c.get('id') for c in
                          self._get('acme').get('credentials', [])})
        self.assertIn('c-legacy',
                      {c.get('id') for c in
                       self._get(api.DEFAULT_TENANT).get('credentials', [])})


if __name__ == '__main__':
    unittest.main()
