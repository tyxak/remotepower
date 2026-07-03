"""v5.8.0 (B3.5): declarative config export — a versioned, secret-redacted
document of operator-authored resources (read-only in this cut)."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_decl', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestExport(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {
            'monitors': [{'id': 'm1', 'type': 'ping', 'target': '1.1.1.1'}],
            'custom_checks': [{'id': 'c1', 'type': 'port_open', 'port': 22}],
            'integrations': [{'id': 'i1', 'type': 'pihole',
                              'secret': 'topsecret', 'url': 'http://pi.hole'}],
            'webhook_urls': [{'label': 'slack', 'enabled': True,
                              'url': 'https://hooks.slack.com/services/T/B/XYZ'}],
            'service_baselines': [{'unit': 'sshd.service', 'scope': 'all'}],
        })
        api.save(api.RULES_FILE, {'rules': [{'id': 'r1', 'event': 'device_offline'}]})
        api.save(api.MAINT_FILE, {'windows': [{'id': 'w1', 'scope': 'global'}]})
        api.save(api.TLS_TARGETS_FILE, {'tls_a': {'host': 'example.com', 'port': 443}})

    def test_schema_and_metadata(self):
        doc = api._build_declarative_config()
        self.assertEqual(doc['schema'], api.DECLARATIVE_SCHEMA)
        self.assertEqual(doc['server_version'], api.SERVER_VERSION)
        self.assertIn('exported_at', doc)
        self.assertIn('resources', doc)

    def test_collections_present(self):
        r = api._build_declarative_config()['resources']
        for name in ('monitors', 'custom_checks', 'integrations',
                     'webhook_destinations', 'automation_rules',
                     'maintenance_windows', 'tls_targets'):
            self.assertIn(name, r, name)

    def test_operator_data_round_trips(self):
        r = api._build_declarative_config()['resources']
        self.assertEqual(r['monitors'], [{'id': 'm1', 'type': 'ping', 'target': '1.1.1.1'}])
        self.assertEqual(r['automation_rules'], [{'id': 'r1', 'event': 'device_offline'}])
        self.assertEqual(r['tls_targets'], {'tls_a': {'host': 'example.com', 'port': 443}})

    def test_named_secret_redacted(self):
        r = api._build_declarative_config()['resources']
        self.assertEqual(r['integrations'][0]['secret'], '(redacted)')
        # non-secret fields survive
        self.assertEqual(r['integrations'][0]['url'], 'http://pi.hole')

    def test_webhook_url_token_stripped(self):
        r = api._build_declarative_config()['resources']
        self.assertEqual(r['webhook_destinations'][0]['url'], 'https://hooks.slack.com')

    def test_export_is_deepcopy_not_live_config(self):
        # mutating the export must not touch the stored config
        doc = api._build_declarative_config()
        doc['resources']['monitors'][0]['target'] = 'MUTATED'
        again = api._build_declarative_config()
        self.assertEqual(again['resources']['monitors'][0]['target'], '1.1.1.1')


class TestWiring(unittest.TestCase):
    def test_route_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/config/declarative'), routes)

    def test_handler_is_admin_only(self):
        src = (_CGI / 'api.py').read_text()
        # the handler must require admin + audit
        i = src.index('def handle_config_declarative')
        body = src[i:i + 600]
        self.assertIn('require_admin_auth()', body)
        self.assertIn('config_declarative_export', body)


if __name__ == '__main__':
    unittest.main()
