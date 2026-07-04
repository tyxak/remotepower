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


class TestImport(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {
            'monitors': [{'id': 'm1', 'type': 'ping', 'target': '1.1.1.1'}],
            'integrations': [{'id': 'i1', 'type': 'pihole',
                              'secret': 'REALSECRET', 'url': 'http://p'}],
            'webhook_urls': [{'label': 'slack', 'url': 'https://hooks.slack.com/services/T/B/XYZ'}],
        })
        api.save(api.RULES_FILE, {'rules': [{'id': 'r1', 'event': 'device_offline'}]})
        api.save(api.TLS_TARGETS_FILE, {'tls_a': {'host': 'example.com', 'port': 443}})

    def test_round_trip_is_lossless(self):
        import copy
        doc = api._build_declarative_config()
        res = api._declarative_apply(copy.deepcopy(doc), 'tester', dry_run=True)
        self.assertTrue(res['ok'])
        for name in ('monitors', 'integrations', 'automation_rules', 'tls_targets'):
            d = res['report'][name]
            self.assertEqual((d.get('added', 0), d.get('changed', 0), d.get('removed', 0)),
                             (0, 0, 0), f'{name} should be a no-op round-trip: {d}')

    def test_dry_run_does_not_write(self):
        doc = api._build_declarative_config()
        doc['resources']['monitors'] = [{'id': 'm1', 'type': 'ping', 'target': 'CHANGED'}]
        api._declarative_apply(doc, 'tester', dry_run=True)
        self.assertEqual(api.load(api.CONFIG_FILE)['monitors'][0]['target'], '1.1.1.1')

    def test_apply_writes_and_rehydrates_secret(self):
        import copy
        doc = api._build_declarative_config()   # integration secret == '(redacted)'
        self.assertEqual(doc['resources']['integrations'][0]['secret'], '(redacted)')
        api._declarative_apply(copy.deepcopy(doc), 'tester', dry_run=False)
        cfg = api.load(api.CONFIG_FILE)
        # secret rehydrated from the store, NOT written as '(redacted)'
        self.assertEqual(cfg['integrations'][0]['secret'], 'REALSECRET')

    def test_apply_add_change_remove(self):
        doc = {'schema': api.DECLARATIVE_SCHEMA, 'resources': {
            'monitors': [
                {'id': 'm1', 'type': 'ping', 'target': 'NEWTARGET'},   # changed
                {'id': 'm2', 'type': 'tcp', 'target': 'host:22'},      # added
            ]}}
        res = api._declarative_apply(doc, 'tester', dry_run=True)
        d = res['report']['monitors']
        self.assertEqual((d['added'], d['changed'], d['removed']), (1, 1, 0))
        api._declarative_apply(doc, 'tester', dry_run=False)
        mons = api.load(api.CONFIG_FILE)['monitors']
        self.assertEqual(len(mons), 2)
        self.assertEqual(next(m for m in mons if m['id'] == 'm1')['target'], 'NEWTARGET')

    def test_lossy_collection_skipped(self):
        doc = {'schema': api.DECLARATIVE_SCHEMA, 'resources': {
            'webhook_destinations': [{'label': 'x', 'url': 'https://host'}]}}
        res = api._declarative_apply(doc, 'tester', dry_run=False)
        self.assertIn('skipped', res['report']['webhook_destinations'])
        # the real webhook_urls store is untouched
        self.assertEqual(api.load(api.CONFIG_FILE)['webhook_urls'][0]['url'],
                         'https://hooks.slack.com/services/T/B/XYZ')

    def test_bad_schema_rejected(self):
        res = api._declarative_apply({'schema': 'wrong', 'resources': {}}, 'tester')
        self.assertFalse(res['ok'])

    def test_absent_collection_untouched(self):
        # a doc with only monitors must not wipe automation_rules
        doc = {'schema': api.DECLARATIVE_SCHEMA, 'resources': {'monitors': []}}
        api._declarative_apply(doc, 'tester', dry_run=False)
        self.assertEqual((api.load(api.RULES_FILE) or {}).get('rules'),
                         [{'id': 'r1', 'event': 'device_offline'}])

    def test_file_list_collection_applies(self):
        doc = {'schema': api.DECLARATIVE_SCHEMA, 'resources': {
            'automation_rules': [{'id': 'r1', 'event': 'device_offline'},
                                 {'id': 'r2', 'event': 'cve_found'}]}}
        api._declarative_apply(doc, 'tester', dry_run=False)
        self.assertEqual(len((api.load(api.RULES_FILE) or {}).get('rules')), 2)


class TestDiffDetail(unittest.TestCase):
    """v5.8.0: the dry-run diff names which ids move and which fields change."""
    def test_list_diff_names_ids_and_fields(self):
        cur = [{'id': 'm1', 'target': 'a'}, {'id': 'm2', 'target': 'b'}]
        inc = [{'id': 'm1', 'target': 'A'}, {'id': 'm3', 'target': 'c'}]
        d = api._declarative_diff(cur, inc, 'id')
        self.assertEqual((d['added'], d['changed'], d['removed']), (1, 1, 1))
        self.assertEqual(d['detail']['added'], ['m3'])
        self.assertEqual(d['detail']['removed'], ['m2'])
        self.assertEqual(d['detail']['changed'], [{'id': 'm1', 'fields': ['target']}])

    def test_dict_diff_names_keys(self):
        cur = {'a': {'x': 1}, 'b': {'y': 2}}
        inc = {'a': {'x': 9}, 'c': {'z': 3}}
        d = api._declarative_diff(cur, inc, None)
        self.assertEqual(d['detail']['added'], ['c'])
        self.assertEqual(d['detail']['removed'], ['b'])
        self.assertEqual(d['detail']['changed'], [{'id': 'a', 'fields': ['x']}])

    def test_replace_note_when_no_stable_id(self):
        d = api._declarative_diff([1, 2], [1, 2, 3], None)
        self.assertTrue(d.get('replace'))
        self.assertIn('note', d['detail'])

    def test_no_change_has_empty_detail(self):
        d = api._declarative_diff([{'id': 'm1'}], [{'id': 'm1'}], 'id')
        self.assertEqual((d['added'], d['changed'], d['removed']), (0, 0, 0))
        self.assertEqual(d['detail'], {'added': [], 'removed': [], 'changed': []})


class TestWebhookEncryptedRoundTrip(unittest.TestCase):
    """v5.8.0: with a config master key armed, webhook_destinations exports as an
    enc:v… ciphertext (git-safe) and round-trips losslessly on import — the URL is
    restored by the name-agnostic config-secret decrypt on the next load."""
    def setUp(self):
        self._had = os.environ.get('RP_CONFIG_KEY')
        os.environ['RP_CONFIG_KEY'] = 'unit-test-master-key-8f2b1c9de4a6'
        api._CFG_DK_CACHE.clear()
        api.save(api.CONFIG_FILE, {'webhook_urls': [
            {'label': 'slack', 'url': 'https://hooks.slack.com/services/T/B/XYZ'}]})

    def tearDown(self):
        if self._had is None:
            os.environ.pop('RP_CONFIG_KEY', None)
        else:
            os.environ['RP_CONFIG_KEY'] = self._had
        api._CFG_DK_CACHE.clear()

    def test_export_encrypts_and_is_importable(self):
        if not api.backup_crypto.available():
            self.skipTest('cryptography lib not available')
        r = api._build_declarative_config()['resources']
        url = r['webhook_destinations'][0]['url']
        self.assertTrue(url.startswith(('enc:v1:', 'enc:v2:')), url)
        self.assertNotIn('slack.com', url)  # no plaintext host leaks
        self.assertTrue(api._declarative_meta()['webhook_destinations'].get('importable'))

    def test_import_restores_plaintext_url(self):
        if not api.backup_crypto.available():
            self.skipTest('cryptography lib not available')
        import copy
        doc = api._build_declarative_config()
        api.save(api.CONFIG_FILE, {'webhook_urls': []})   # wipe, then re-import
        res = api._declarative_apply(copy.deepcopy(doc), 'tester', dry_run=False)
        self.assertNotIn('skipped', res['report']['webhook_destinations'])
        cfg = api.load(api.CONFIG_FILE)   # inbound decrypt runs on load
        self.assertEqual(cfg['webhook_urls'][0]['url'],
                         'https://hooks.slack.com/services/T/B/XYZ')

    def test_without_key_stays_lossy(self):
        os.environ.pop('RP_CONFIG_KEY', None)
        api._CFG_DK_CACHE.clear()
        r = api._build_declarative_config()['resources']
        self.assertEqual(r['webhook_destinations'][0]['url'], 'https://hooks.slack.com')
        self.assertFalse(api._declarative_meta()['webhook_destinations'].get('importable'))


class TestWiring(unittest.TestCase):
    def test_route_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/config/declarative'), routes)
        self.assertIn(('POST', '/api/config/declarative'), routes)

    def test_handler_is_admin_only(self):
        src = (_CGI / 'api.py').read_text()
        # the handler must require admin + audit
        i = src.index('def handle_config_declarative')
        body = src[i:i + 600]
        self.assertIn('require_admin_auth()', body)
        self.assertIn('config_declarative_export', body)


if __name__ == '__main__':
    unittest.main()
