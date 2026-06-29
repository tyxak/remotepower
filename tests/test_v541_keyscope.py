"""D6 — per-key device scope (scoped service-account API keys).

A key may carry an optional device scope (groups/tags/sites) that confines its
visibility + actions to a subset of the fleet, intersected with its role scope and
binding even an admin-role key. Opt-in: a key with no scope behaves exactly as
before (the key feature — existing keys are unaffected).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-keyscope-test-"))

import api  # noqa: E402


class TestDeviceInScopeComposite(unittest.TestCase):
    def test_all_of_requires_every_subscope(self):
        dev = {'group': 'prod', 'tags': ['db'], 'site': 's1'}
        s = {'type': 'all_of', 'scopes': [
            {'type': 'groups', 'values': ['prod']},
            {'type': 'tags', 'values': ['db']}]}
        self.assertTrue(api._device_in_scope(s, dev))
        s2 = {'type': 'all_of', 'scopes': [
            {'type': 'groups', 'values': ['prod']},
            {'type': 'tags', 'values': ['web']}]}     # tag doesn't match
        self.assertFalse(api._device_in_scope(s2, dev))

    def test_all_and_empty(self):
        self.assertTrue(api._device_in_scope({'type': 'all'}, {'group': 'x'}))
        self.assertTrue(api._device_in_scope(None, {'group': 'x'}))


class TestValidateKeyScope(unittest.TestCase):
    def test_none_and_all_are_no_scope(self):
        self.assertIsNone(api._validate_key_scope(None))
        self.assertIsNone(api._validate_key_scope({'type': 'all'}))

    def test_valid_scope_cleaned(self):
        s = api._validate_key_scope({'type': 'groups', 'values': ['prod', ' staging ', '']})
        self.assertEqual(s, {'type': 'groups', 'values': ['prod', 'staging']})

    def test_bad_shapes_400(self):
        for bad in ({'type': 'bogus', 'values': ['x']},
                    {'type': 'groups', 'values': []},
                    {'type': 'groups'},
                    'not-a-dict'):
            with self.assertRaises(api.HTTPError) as cm:
                api._validate_key_scope(bad)
            self.assertEqual(cm.exception.status, 400)


class TestCallerScopeIntersection(unittest.TestCase):
    """_caller_scope() combines role scope + the auth key's scope."""

    def setUp(self):
        self._saved = api._CALLER_KEY_SCOPE
        # neutralise token plumbing: pretend an admin key authed.
        self._gt = api.get_token_from_request
        self._vt = api.verify_token
        api.get_token_from_request = lambda: 'x'
        api.verify_token = lambda t: ('api', 'admin')   # NB: does NOT set the global

    def tearDown(self):
        api._CALLER_KEY_SCOPE = self._saved
        api.get_token_from_request = self._gt
        api.verify_token = self._vt

    def test_admin_key_with_no_scope_sees_all(self):
        api._CALLER_KEY_SCOPE = None
        self.assertIsNone(api._caller_scope())

    def test_admin_key_with_scope_is_confined(self):
        api._CALLER_KEY_SCOPE = {'type': 'tags', 'values': ['edge']}
        self.assertEqual(api._caller_scope(), {'type': 'tags', 'values': ['edge']})

    def test_role_and_key_scope_compose_to_all_of(self):
        # a non-admin role with its own scope + a scoped key → all_of
        api.verify_token = lambda t: ('u', 'fieldtech')
        orig = api._resolve_role
        api._resolve_role = lambda r: ({'permissions': set(), 'admin': False,
                                        'scope': {'type': 'groups', 'values': ['prod']}}
                                       if r == 'fieldtech' else orig(r))
        try:
            api._CALLER_KEY_SCOPE = {'type': 'sites', 'values': ['dc1']}
            sc = api._caller_scope()
            self.assertEqual(sc['type'], 'all_of')
            self.assertIn({'type': 'groups', 'values': ['prod']}, sc['scopes'])
            self.assertIn({'type': 'sites', 'values': ['dc1']}, sc['scopes'])
            # a device must satisfy BOTH
            self.assertTrue(api._device_in_scope(sc, {'group': 'prod', 'site': 'dc1'}))
            self.assertFalse(api._device_in_scope(sc, {'group': 'prod', 'site': 'dc2'}))
        finally:
            api._resolve_role = orig


class TestVerifyTokenSetsKeyScope(unittest.TestCase):
    """An API key with a scope sets _CALLER_KEY_SCOPE on auth; one without clears it."""

    def setUp(self):
        self._orig = api.APIKEYS_FILE
        self._d = tempfile.mkdtemp()
        api.APIKEYS_FILE = api.Path(self._d) / 'apikeys.json'

    def tearDown(self):
        api.APIKEYS_FILE = self._orig
        api._CALLER_KEY_SCOPE = None

    def test_scoped_key_sets_global_unscoped_clears(self):
        import secrets
        scoped = secrets.token_urlsafe(40)
        plain = secrets.token_urlsafe(40)
        api.save(api.APIKEYS_FILE, {
            'k1': {'name': 's', 'key_hash': api._apikey_hash(scoped), 'user': 'api',
                   'role': 'admin', 'active': True, 'scope': {'type': 'tags', 'values': ['edge']}},
            'k2': {'name': 'p', 'key_hash': api._apikey_hash(plain), 'user': 'api',
                   'role': 'admin', 'active': True},
        })
        u, r = api.verify_token(scoped)
        self.assertEqual((u, r), ('api', 'admin'))
        self.assertEqual(api._CALLER_KEY_SCOPE, {'type': 'tags', 'values': ['edge']})
        # a different (unscoped) key must CLEAR the scope, not inherit the prior one
        api.verify_token(plain)
        self.assertIsNone(api._CALLER_KEY_SCOPE)


class TestSourceWiring(unittest.TestCase):
    def test_create_update_list_carry_scope(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("key_scope = _validate_key_scope(body.get('scope'))", src)  # create
        self.assertIn("if 'scope' in body:", src)                                  # update
        self.assertIn("'scope': v.get('scope'),", src)                             # list


if __name__ == '__main__':
    unittest.main()
