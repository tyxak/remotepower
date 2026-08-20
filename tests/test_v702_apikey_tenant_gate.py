#!/usr/bin/env python3
"""A tenant admin could delete, edit and rotate another tenant's API keys.

`handle_apikeys_list` has filtered its roster by tenant since v6.1.1. Delete,
update and rotate never checked at all — so a tenant admin who could not SEE
another tenant's key could still remove it, rename it, change its role and
device scope, or rotate it out from under them, by id.

`require_admin_auth` does not help. A tenant admin IS an admin, and
`_caller_scope()` is None for an admin role, so every gate shaped
`if scope is not None:` passes them. That one fact is the recurring source of
cross-tenant findings in this codebase.

Half-applied rule, and the ratio is the tell: 1 of 5 handlers gated. The
correct one made the file read as though the rule was enforced.

The gate is 404, not 403 — a 403 confirms the id exists and turns the endpoint
into an enumeration oracle, which is how the device handlers already answer.
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-akt-'))
_spec = importlib.util.spec_from_file_location('api_apikey_tenant', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import srcpin                                                    # noqa: E402


class TestTheRatio(unittest.TestCase):
    """Measure the population, not one handler. This is what was wrong: the
    rule existed and was applied in one place out of five."""

    _HANDLERS = ('handle_apikeys_list', 'handle_apikeys_create',
                 'handle_apikeys_delete', 'handle_apikeys_update',
                 'handle_apikeys_rotate')

    def test_every_apikey_handler_considers_the_tenant(self):
        src = (_CGI / 'api.py').read_text()
        ungated = []
        for fn in self._HANDLERS:
            body = srcpin.py_function(src, fn)
            if not any(g in body for g in ('_tenant_gate', '_apikey_tenant_block',
                                           '_caller_effective_tenant')):
                ungated.append(fn)
        self.assertEqual([], ungated,
                         f'{len(ungated)} of {len(self._HANDLERS)} API-key '
                         f'handlers ignore the tenant: {ungated}')

    def test_the_enumeration_reads_real_handlers(self):
        """Positive control: a typo'd name would make the loop above inspect
        nothing and pass."""
        src = (_CGI / 'api.py').read_text()
        for fn in self._HANDLERS:
            self.assertGreater(len(srcpin.py_function(src, fn).splitlines()), 4, fn)


class TestTheGateBehaves(unittest.TestCase):
    """Driven through the real handlers. Only verify_token is stubbed — stubbing
    require_admin_auth would pass a handler with no gate at all."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-akt-run-'))
        self._saved = {n: getattr(api, n) for n in ('DATA_DIR', 'APIKEYS_FILE')}
        api.DATA_DIR = self.dir
        api.APIKEYS_FILE = self.dir / 'apikeys.json'
        api.save(api.APIKEYS_FILE, {
            'aaaaaa': {'name': 'acme key', 'key_hash': 'x', 'user': 'a@acme',
                       'role': 'admin', 'active': True, 'tenant_id': 'acme'},
            'bbbbbb': {'name': 'globex key', 'key_hash': 'y', 'user': 'b@globex',
                       'role': 'admin', 'active': True, 'tenant_id': 'globex'},
            'cccccc': {'name': 'legacy key', 'key_hash': 'z', 'user': 'c',
                       'role': 'admin', 'active': True},   # pre-v6.1.1, no tenant
        })
        self._ra = api.require_admin_auth
        self._tg = api._tenant_gate
        api.require_admin_auth = lambda *a, **k: 'admin@acme'

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api.require_admin_auth = self._ra
        api._tenant_gate = self._tg

    def _as(self, tenant):
        api._tenant_gate = lambda: tenant

    def _call(self, fn, *a, **k):
        api._RCTX.environ = {'REQUEST_METHOD': k.pop('m', 'DELETE'),
                             'PATH_INFO': '/api/apikeys', 'QUERY_STRING': ''}
        try:
            fn(*a)
        except api.HTTPError as e:
            return e.status, e.body
        except SystemExit:
            return 'exit', None
        return None, None

    def _keys(self):
        api._invalidate_load_cache(api.APIKEYS_FILE)
        return set(api.load(api.APIKEYS_FILE) or {})

    def test_a_tenant_admin_cannot_delete_another_tenants_key(self):
        self._as('acme')
        status, _ = self._call(api.handle_apikeys_delete, 'bbbbbb')
        self.assertEqual(404, status)
        self.assertIn('bbbbbb', self._keys(), 'the key was deleted anyway')

    def test_the_refusal_is_404_not_403(self):
        """403 confirms the id exists. The device handlers answer 404 for the
        same reason and these must match, or the endpoint enumerates ids."""
        self._as('acme')
        status, body = self._call(api.handle_apikeys_delete, 'bbbbbb')
        self.assertEqual(404, status)
        self.assertNotIn('tenant', str(body).lower(),
                         'the error names the reason and so confirms the id')

    def test_a_tenant_admin_can_still_delete_its_own_key(self):
        """The positive control. A gate that refused everything would satisfy
        every assertion above."""
        self._as('acme')
        status, _ = self._call(api.handle_apikeys_delete, 'aaaaaa')
        self.assertEqual(200, status)
        self.assertNotIn('aaaaaa', self._keys())

    def test_a_superadmin_can_delete_any_tenants_key(self):
        self._as(None)
        status, _ = self._call(api.handle_apikeys_delete, 'bbbbbb')
        self.assertEqual(200, status)
        self.assertNotIn('bbbbbb', self._keys())

    def test_a_pre_tenancy_key_belongs_to_the_default_tenant(self):
        """A key with no stored tenant_id predates v6.1.1. It must resolve the
        same way the list filter and _user_tenant already resolve it, or
        upgrading an install makes existing keys unmanageable."""
        self._as('acme')
        status, _ = self._call(api.handle_apikeys_delete, 'cccccc')
        self.assertEqual(404, status, 'a legacy key leaked to tenant "acme"')
        self._as(api.DEFAULT_TENANT)
        status, _ = self._call(api.handle_apikeys_delete, 'cccccc')
        self.assertEqual(200, status,
                         'the default tenant cannot manage its own legacy key')

    def test_update_is_gated_too(self):
        self._as('acme')
        api._read_valid = lambda m: {'name': 'stolen'}
        try:
            status, _ = self._call(api.handle_apikeys_update, 'bbbbbb', m='PATCH')
        finally:
            del api._read_valid
        self.assertEqual(404, status)
        api._invalidate_load_cache(api.APIKEYS_FILE)
        self.assertEqual('globex key',
                         api.load(api.APIKEYS_FILE)['bbbbbb']['name'])

    def test_delete_holds_a_lock_across_the_read_and_the_write(self):
        """It was a bare load/mutate/save. On this store a lost update means a
        key the operator just minted disappears, or a deleted one comes back."""
        src = srcpin.py_function((_CGI / 'api.py').read_text(),
                                 'handle_apikeys_delete')
        self.assertIn('_LockedUpdate(APIKEYS_FILE)', src)
        self.assertNotIn('save(APIKEYS_FILE', src)


if __name__ == '__main__':
    unittest.main()
