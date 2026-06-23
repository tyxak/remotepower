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
        src = (_CGI / 'api.py').read_text()
        self.assertIn("('GET', '/api/app-catalog'): handle_app_catalog", src)
        self.assertIn("('POST', '/api/app-catalog/deploy'): handle_app_catalog_deploy", src)
        h = src[src.index('def handle_app_catalog_deploy'):
                src.index('def handle_app_catalog_deploy') + 2200]
        self.assertIn("require_perm('containers')", h)
        self.assertIn("compose deploys are disabled", h)       # compose_enabled gate
        self.assertIn("audit_log(actor, 'app_catalog_deploy'", h)
        self.assertIn("compose_deploy:", h)                    # reuses the proven path


if __name__ == '__main__':
    unittest.main()
