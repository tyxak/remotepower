#!/usr/bin/env python3
"""A read-only role could publish a shared query template.

`handle_query_template_create` gated on `require_auth()`, which admits every
read-only role — viewer, mcp, auditor, finance. A PRIVATE template is that
caller's own saved filter and require_auth is correct for it: a viewer saving a
query for themselves is reading, with a bookmark. A SHARED one is written into a
list every user of the instance sees, and shared state is what
`require_write_role` exists to protect.

Low severity — a saved filter discloses nothing the caller could not already
read. It is here because it is the documented read-only-role WRITE-gate class,
which recurs as an incomplete migration, and because a shared list any account
can write is a place to put misleading text in front of other operators.

The gate lives in `_qt_visibility()` with the decision it guards, rather than
three lines above it, which is the arrangement where a later edit moves one and
not the other.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702qt-'))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('api_v702qt', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        self._saved = {n: getattr(api, n) for n in
                       ('respond', 'require_auth', 'verify_token',
                        'get_token_from_request', '_resolve_role')}
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.require_auth = lambda *a, **k: 'someone'
        api.get_token_from_request = lambda: 'tok'

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)

    def _as(self, role, admin=False, perms=None):
        api.verify_token = lambda _t=None: ('someone', role)
        api._resolve_role = lambda _r: {'admin': admin,
                                        'permissions': perms or []}

    def _visibility(self, body):
        self.cap.clear()
        try:
            return api._qt_visibility(body)
        except api.HTTPError:
            return f"REFUSED {self.cap.get('status')}"


class TestReadOnlyRolesCannotPublish(_Base):

    def test_a_viewer_is_refused_the_shared_option(self):
        self._as('viewer')
        self.assertTrue(str(self._visibility({'shared': True})).startswith('REFUSED'))

    def test_every_read_only_role_is_refused(self):
        for role in ('viewer', 'mcp', 'auditor', 'finance'):
            self._as(role)
            self.assertTrue(
                str(self._visibility({'shared': True})).startswith('REFUSED'), role)

    def test_a_viewer_can_still_save_a_private_one(self):
        """The control that matters — this is a feature read-only roles are
        meant to have, and a blanket gate would take it away."""
        self._as('viewer')
        self.assertEqual(self._visibility({}), 'private')
        self.assertEqual(self._visibility({'shared': False}), 'private')

    def test_an_admin_can_publish(self):
        self._as('admin', admin=True)
        self.assertEqual(self._visibility({'shared': True}), 'shared')

    def test_a_scoped_operator_can_publish(self):
        """require_write_role is permission-based, not a role-name denylist —
        the recurring denylist-role bug class. A custom role holding any action
        permission is an operator."""
        self._as('deployer', admin=False, perms=['command'])
        self.assertEqual(self._visibility({'shared': True}), 'shared')


class TestTheHandlerUsesIt(unittest.TestCase):

    def test_the_visibility_decision_goes_through_the_gate(self):
        sys.path.insert(0, str(Path(__file__).parent))
        import srcpin
        body = srcpin.py_function((_CGI / 'api.py').read_text(),
                                  'handle_query_template_create')
        self.assertIn('_qt_visibility(body)', body)
        self.assertNotIn("'shared' if body.get('shared') else 'private'", body,
                         'the inline ternary is back and the gate is bypassed')


if __name__ == '__main__':
    unittest.main()
