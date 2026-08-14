"""v4.10.0: site / group / tag-scoped credentials.

A credential defined once at a site/group/tag level, inherited by every member
device, encrypted with the same CMDB vault. Admin-only; reveal is audit-logged.
"""

# v6.4.1: pin RP_DATA_DIR at module scope BEFORE api.py is exec'd — its
# import-time ensure_default_user() writes to DATA_DIR, so without this the
# module targets the REAL /var/lib/remotepower and, on a box where that is
# writable, would overwrite a live install's admin user. These files only
# passed because `unittest discover` happened to import a guarded module
# first; run on their own they raised PermissionError (or worse, succeeded).
# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import os as _rp_os, tempfile as _rp_tempfile
_rp_os.environ.setdefault("RP_DATA_DIR", _rp_tempfile.mkdtemp())
import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_scoped", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestScopedCredResolution(unittest.TestCase):
    DEV = {'site': 's1', 'group': 'web', 'tags': ['prod', 'eu']}

    def test_applies_by_site(self):
        self.assertTrue(api._scoped_cred_applies({'scope_type': 'site', 'scope_value': 's1'}, self.DEV))
        self.assertFalse(api._scoped_cred_applies({'scope_type': 'site', 'scope_value': 's2'}, self.DEV))

    def test_applies_by_group_and_tag(self):
        self.assertTrue(api._scoped_cred_applies({'scope_type': 'group', 'scope_value': 'web'}, self.DEV))
        self.assertTrue(api._scoped_cred_applies({'scope_type': 'tag', 'scope_value': 'prod'}, self.DEV))
        self.assertFalse(api._scoped_cred_applies({'scope_type': 'tag', 'scope_value': 'staging'}, self.DEV))

    def test_unknown_scope_never_applies(self):
        self.assertFalse(api._scoped_cred_applies({'scope_type': 'bogus', 'scope_value': 's1'}, self.DEV))

    def test_meta_strips_ciphertext(self):
        c = {'id': 'scred_1', 'scope_type': 'site', 'scope_value': 's1', 'label': 'L',
             'username': 'u', 'note': 'n', 'nonce': 'NONCE', 'ct': 'CIPHER',
             'created_by': 'a', 'created_at': 1}
        m = api._scoped_cred_meta(c)
        self.assertNotIn('nonce', m)
        self.assertNotIn('ct', m)
        self.assertEqual(m['scope_value'], 's1')

    def test_scopes_constant(self):
        self.assertEqual(api._SCOPED_CRED_SCOPES, ('site', 'group', 'tag'))


class TestScopedCredRouting(unittest.TestCase):
    def test_routes_registered(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route('GET', '/api/scoped-credentials')[0],
                         'handle_scoped_credentials_list')
        self.assertEqual(resolve_route('POST', '/api/scoped-credentials')[0],
                         'handle_scoped_credentials_add')
        self.assertEqual(resolve_route('POST', '/api/scoped-credentials/scred_x/reveal')[0],
                         'handle_scoped_credentials_reveal')
        self.assertEqual(resolve_route('DELETE', '/api/scoped-credentials/scred_x')[0],
                         'handle_scoped_credentials_delete')
        self.assertEqual(resolve_route('GET', '/api/cmdb/dev1/inherited-credentials')[0],
                         'handle_device_inherited_credentials')


class TestScopedCredUi(unittest.TestCase):
    def test_management_card(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="scoped-creds-tbody"', html)
        self.assertIn('data-action="scopedCredAdd"', html)

    def test_js_reuses_vault(self):
        app = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-cmdb.js').read_text()
        self.assertIn('async function loadScopedCreds', app)
        self.assertIn("cmdbApi('POST', '/scoped-credentials'", app)
        # reveal must send the vault key (4th arg true)
        self.assertIn("/reveal', {}, true)", app)


if __name__ == '__main__':
    unittest.main()
