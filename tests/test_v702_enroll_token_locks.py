#!/usr/bin/env python3
"""Revoking a leaked enrollment token could silently fail.

`handle_enroll_token_create`, `_list` and `_revoke` each did
`load(ENROLL_TOKENS_FILE)` … mutate … `save(...)` with no lock across the pair.

On this store that is not a lost edit, it is a revoked credential coming back:
a create running alongside a revoke writes back a snapshot taken before the
delete, and the token an admin just killed is live again. An enrollment token
lets a machine join the fleet.

`_list` is the same shape wearing a GET — it prunes expired tokens as a side
effect, so merely listing while another admin created or revoked one could undo
them. The prune is opportunistic, so it takes the lock non-blocking and lists
what it read if the store is busy; a token that outlives its expiry by one
request is filtered out of the response regardless.

This is the class issue #8 moved ~24 device handlers onto the lock for, showing
up on a store that is not devices.json.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(_ROOT / 'tests'))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-etl-'))
_spec = importlib.util.spec_from_file_location('api_enroll_locks', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import srcpin                                                    # noqa: E402


class TestNoneOfThemDoesABareReadModifyWrite(unittest.TestCase):
    """Source-level, over the whole population — mirrors
    tests/test_device_write_locks.py's shape for DEVICES_FILE."""

    _HANDLERS = ('handle_enroll_token_create', 'handle_enroll_token_list',
                 'handle_enroll_token_revoke')

    def setUp(self):
        self.src = (_CGI / 'api.py').read_text()

    def test_the_handlers_are_still_there(self):
        """Positive control: a typo'd name inspects nothing and passes."""
        for h in self._HANDLERS:
            self.assertGreater(len(srcpin.py_function(self.src, h).splitlines()), 5, h)

    def test_no_bare_save_of_the_token_store(self):
        offenders = []
        for h in self._HANDLERS:
            body = srcpin.py_function(self.src, h)
            code = '\n'.join(l for l in body.splitlines()
                             if not l.lstrip().startswith('#'))
            if 'save(ENROLL_TOKENS_FILE' in code:
                offenders.append(h)
        self.assertEqual([], offenders,
                         f'these write the token store without holding the '
                         f'lock across the read: {offenders}')

    def test_the_mutating_ones_hold_the_lock(self):
        for h in ('handle_enroll_token_create', 'handle_enroll_token_revoke'):
            with self.subTest(handler=h):
                body = srcpin.py_function(self.src, h)
                self.assertIn('_LockedUpdate(ENROLL_TOKENS_FILE)', body)

    def test_audit_log_stays_outside_the_lock(self):
        """audit_log is self-locking. Inside another lock it nests, which on the
        DB backends is an OperationalError — the recorders auto-defer now, but
        the collect-then-fire ordering is still the documented shape."""
        body = srcpin.py_function(self.src, 'handle_enroll_token_revoke')
        self.assertLess(body.index('del tokens[full]'), body.index('audit_log'))


class TestARevokedTokenStaysRevoked(unittest.TestCase):
    """Driven through the real handlers, because the source check above proves
    the shape and only this proves the outcome."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-etl-run-'))
        self._saved = {n: getattr(api, n) for n in ('DATA_DIR', 'ENROLL_TOKENS_FILE')}
        api.DATA_DIR = self.dir
        api.ENROLL_TOKENS_FILE = self.dir / 'enrollment_tokens.json'
        self._orig = {n: getattr(api, n) for n in
                      ('require_admin_auth', 'audit_log', 'respond', 'method')}
        api.require_admin_auth = lambda *a, **k: 'admin'
        api.audit_log = lambda *a, **k: None
        self.cap = {}

        def _r(s, b=None):
            self.cap['s'], self.cap['b'] = s, b
            raise api.HTTPError(s, b)
        api.respond = _r
        now = int(time.time())
        api.save(api.ENROLL_TOKENS_FILE, {
            'h1': {'prefix': 'aaaaaaaa', 'created': now, 'expires': now + 3600,
                   'actor': 'admin', 'label': 'keep'},
            'h2': {'prefix': 'bbbbbbbb', 'created': now, 'expires': now + 3600,
                   'actor': 'admin', 'label': 'LEAKED'}})

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        for n, v in self._orig.items():
            setattr(api, n, v)

    def _call(self, fn, *a, m='GET', body=None):
        api.method = lambda: m
        api.get_json_obj = lambda: (body or {})
        api._read_valid = lambda mm: (body or {})
        api._RCTX.environ = {'REQUEST_METHOD': m, 'QUERY_STRING': '',
                             'PATH_INFO': '/api/enrollment-tokens'}
        api._invalidate_load_cache(api.ENROLL_TOKENS_FILE)
        self.cap.clear()
        try:
            fn(*a)
        except (api.HTTPError, SystemExit):
            pass
        return self.cap.get('s'), self.cap.get('b')

    def _labels(self):
        api._invalidate_load_cache(api.ENROLL_TOKENS_FILE)
        return sorted((v.get('label') or k)
                      for k, v in (api.load(api.ENROLL_TOKENS_FILE) or {}).items())

    def test_revoke_then_create_does_not_resurrect_it(self):
        self.assertEqual(200, self._call(api.handle_enroll_token_revoke,
                                         'bbbbbbbb', m='DELETE')[0])
        self.assertNotIn('LEAKED', self._labels())
        self.assertIn(self._call(api.handle_enroll_token_create, m='POST',
                                 body={'label': 'new', 'expires_in': 3600})[0],
                      (200, 201))
        self.assertNotIn('LEAKED', self._labels(),
                         'the revoked token came back after a create')

    def test_create_then_revoke_keeps_the_new_one(self):
        """The other order. A fix that simply dropped writes would pass the
        test above."""
        self._call(api.handle_enroll_token_create, m='POST',
                   body={'label': 'new', 'expires_in': 3600})
        self._call(api.handle_enroll_token_revoke, 'bbbbbbbb', m='DELETE')
        labels = self._labels()
        self.assertIn('new', labels)
        self.assertIn('keep', labels)
        self.assertNotIn('LEAKED', labels)

    def test_listing_does_not_undo_a_revoke(self):
        self._call(api.handle_enroll_token_revoke, 'bbbbbbbb', m='DELETE')
        self._call(api.handle_enroll_token_list)
        self.assertNotIn('LEAKED', self._labels())

    def test_the_list_never_returns_a_token_value(self):
        """The listing exists to avoid the leak-active-tokens footgun."""
        _, body = self._call(api.handle_enroll_token_list)
        blob = str(body)
        self.assertNotIn('h1', blob)
        self.assertNotIn('h2', blob)
        self.assertIn('aaaaaaaa', blob)      # the display prefix, not the key

    def test_the_list_drops_expired_tokens(self):
        now = int(time.time())
        api.save(api.ENROLL_TOKENS_FILE, {
            'h3': {'prefix': 'cccccccc', 'created': now - 7200,
                   'expires': now - 60, 'actor': 'admin', 'label': 'old'}})
        _, body = self._call(api.handle_enroll_token_list)
        self.assertEqual([], body or [])


if __name__ == '__main__':
    unittest.main()
