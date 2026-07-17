"""v5.1.0 — app catalog (one-click compose deploy).

The catalog is a curated static registry whose templates feed the existing,
audited compose-stack deploy path. These tests pin the registry's integrity and
the API wiring; the deploy itself reuses proven compose_deploy plumbing.
"""
import importlib.util
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_cat', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestCatalogRegistry(unittest.TestCase):
    def test_nonempty_and_unique_ids(self):
        ids = [a['id'] for a in api.APP_CATALOG]
        self.assertTrue(ids)
        self.assertEqual(len(ids), len(set(ids)), 'duplicate app ids')

    def test_each_template_is_valid(self):
        for a in api.APP_CATALOG:
            for k in ('id', 'name', 'category', 'description', 'yaml'):
                self.assertIn(k, a, f'{a.get("id")} missing {k}')
            # the compose-stack create validator requires a 'services:' key
            self.assertIn('services:', a['yaml'], f'{a["id"]} yaml has no services:')
            self.assertLessEqual(len(a['yaml']), api.COMPOSE_YAML_MAX)
            # id must satisfy the stack-name rule (it is reused as the stack name)
            self.assertRegex(a['id'], r'^[a-z0-9_-]{1,64}$')
            self.assertTrue(api._STACK_NAME_RE.match(a['id']))

    def test_by_id_index(self):
        self.assertEqual(set(api._APP_CATALOG_BY_ID), {a['id'] for a in api.APP_CATALOG})


class TestApiWiring(unittest.TestCase):
    def test_handlers_and_routes(self):
        self.assertTrue(hasattr(api, 'handle_app_catalog'))
        self.assertTrue(hasattr(api, 'handle_app_catalog_deploy'))
        src = (_CGI / 'api.py').read_text()   # route table stays in api.py
        self.assertIn("('GET', '/api/app-catalog'): handle_app_catalog", src)
        self.assertIn("('POST', '/api/app-catalog/deploy'): handle_app_catalog_deploy", src)
        # handle_app_catalog_deploy moved to apps_compose_handlers.py — read the
        # combined source and extract the whole handler (growth-proof, srcpin).
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).resolve().parent))
        from apisrc import api_source
        from srcpin import py_function
        h = py_function(api_source(), 'handle_app_catalog_deploy')
        self.assertIn("require_perm('containers')", h)
        self.assertIn("compose deploys are disabled", h)       # compose_enabled gate
        self.assertIn("audit_log(actor, 'app_catalog_deploy'", h)
        self.assertIn("compose_deploy:", h)                    # reuses the proven path


class TestCustomApps(unittest.TestCase):
    """v5.1.0: admin-added custom catalog entries, merged with the curated list."""

    def setUp(self):
        # start from an empty custom store for each test
        api.save(api.APP_CATALOG_CUSTOM_FILE, {})

    def test_custom_add_route_and_admin_gate(self):
        src = (_CGI / 'api.py').read_text()   # route table stays in api.py
        self.assertIn("('POST', '/api/app-catalog/custom'): handle_app_catalog_custom_add", src)
        self.assertIn("('POST', '/api/app-catalog/custom/delete'): handle_app_catalog_custom_delete", src)
        # handlers moved to apps_compose_handlers.py — read the combined source
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).resolve().parent))
        from apisrc import api_source
        from srcpin import py_function
        for fn in ('handle_app_catalog_custom_add', 'handle_app_catalog_custom_delete'):
            seg = py_function(api_source(), fn)
            self.assertIn('require_admin_auth()', seg, f'{fn} not admin-gated')
            self.assertIn('audit_log(', seg, f'{fn} not audited')

    def test_merge_flags_custom_and_lookup(self):
        with api._LockedUpdate(api.APP_CATALOG_CUSTOM_FILE) as apps:
            apps['my-app'] = {'id': 'my-app', 'name': 'My App', 'category': 'Custom',
                              'description': 'd', 'port': 8080,
                              'yaml': 'services:\n  x:\n    image: y\n'}
        allapps = api._app_catalog_all()
        ids = [a['id'] for a in allapps]
        self.assertIn('my-app', ids)
        # curated stay un-flagged, custom flagged
        cur = next(a for a in allapps if a['id'] == 'uptime-kuma')
        cust = next(a for a in allapps if a['id'] == 'my-app')
        self.assertFalse(cur.get('custom'))
        self.assertTrue(cust.get('custom'))
        # lookup resolves both curated and custom
        self.assertEqual(api._app_by_id('dozzle')['name'], 'Dozzle')
        self.assertEqual(api._app_by_id('my-app')['name'], 'My App')
        self.assertIsNone(api._app_by_id('does-not-exist'))

    def test_custom_id_is_valid_stack_name(self):
        # the derived id is reused as the compose stack name → must match the rule
        with api._LockedUpdate(api.APP_CATALOG_CUSTOM_FILE) as apps:
            apps['custom-uptime-kuma'] = {'id': 'custom-uptime-kuma', 'name': 'x',
                                          'yaml': 'services:\n  a:\n    image: b\n'}
        for a in api._custom_apps():
            self.assertTrue(api._STACK_NAME_RE.match(a['id']), a['id'])


if __name__ == '__main__':
    unittest.main()
