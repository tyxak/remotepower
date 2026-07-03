#!/usr/bin/env python3
"""v5.6.x: config-secret encryption extended to the WHOLE config tree.

The v5.4.1 C2 feature (opt-in via RP_CONFIG_KEY, transparent at load/save,
fail-graceful) covered five flat scalar fields. It now covers every
secret-NAMED string leaf at any depth — acme_dns_credentials.<provider>.*,
webhook destination tokens, ai.api_key, integration `secret`s, the legacy
token-bearing webhook_url scalar — which is what the original C2 plan
specified. New writes use the v2 format (per-install salt file + per-process
cached fast KDF — v1's per-VALUE 200k-iter PBKDF2 was ruinous at ~30 fields
under fork-per-request CGI); v1 blobs stay readable and migrate on save.

Runs under both backends via make test-both.
"""
import base64
import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')

import backup_crypto  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_cst', _CGI_BIN / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

CRYPTO = backup_crypto.available()

CFG = {
    'server_name': 'rp-test',
    'password_min_length': 12,                      # skip-suffix: stays plaintext
    'proxmox_token_id': 'user@pam!mytok',           # *_id: stays plaintext
    'secrets_scan_paths': ['/etc', '/opt'],         # list items: stay plaintext
    'webhook_url': 'https://hooks.slack.com/services/T00/B00/SECRETPART',
    'smtp_password': 'flat-legacy-field',
    'ai': {'provider': 'openai', 'api_key': 'unit-fake-ai-credential-1'},
    'acme_dns_credentials': {'dns_cf': {'CF_Token': 'cf-secret-xyz'}},
    'webhook_destinations': [
        {'name': 'pd', 'format': 'pagerduty', 'routing_key': 'rk',
         'token': 'dest-token-1', 'url': 'https://events.pagerduty.com/v2/enqueue'},
    ],
    'integrations': [{'type': 'pihole', 'url': 'http://10.0.0.2/admin',
                      'secret': 'pihole-api-key'}],
}
SECRET_VALUES = ('SECRETPART', 'flat-legacy-field', 'unit-fake-ai-credential-1',
                 'cf-secret-xyz', 'dest-token-1', 'pihole-api-key')


class _Base(unittest.TestCase):
    def setUp(self):
        self._k = os.environ.pop('RP_CONFIG_KEY', None)
        self._orig = api.CONFIG_FILE
        api.CONFIG_FILE = api.DATA_DIR / 'config_tree_test.json'
        api._LOAD_CACHE.clear()
        api._CFG_DK_CACHE.clear()

    def tearDown(self):
        try:
            api.backend_exists(api.CONFIG_FILE) and api.save(api.CONFIG_FILE, {})
        except Exception:
            pass
        api.CONFIG_FILE = self._orig
        api._LOAD_CACHE.clear()
        if self._k is None:
            os.environ.pop('RP_CONFIG_KEY', None)
        else:
            os.environ['RP_CONFIG_KEY'] = self._k

    def _at_rest(self):
        m = api._dbmod()
        if m is not None:
            return m.load(api.CONFIG_FILE)
        import json
        return json.loads(api.CONFIG_FILE.read_text())


class TestTreeCoverage(_Base):
    @unittest.skipUnless(CRYPTO, 'cryptography not installed')
    def test_nested_secrets_encrypted_at_rest(self):
        os.environ['RP_CONFIG_KEY'] = 'unit-master-key'
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, dict(CFG))
        import json
        raw = json.dumps(self._at_rest())
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, raw,
                             f'{secret!r} stored in cleartext')
        d = self._at_rest()
        self.assertTrue(d['ai']['api_key'].startswith('enc:v2:'))
        self.assertTrue(d['acme_dns_credentials']['dns_cf']['CF_Token']
                        .startswith('enc:v2:'))
        self.assertTrue(d['webhook_destinations'][0]['token'].startswith('enc:v2:'))
        self.assertTrue(d['webhook_url'].startswith('enc:v2:'))

    @unittest.skipUnless(CRYPTO, 'cryptography not installed')
    def test_non_secrets_stay_plaintext(self):
        os.environ['RP_CONFIG_KEY'] = 'unit-master-key'
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, dict(CFG))
        d = self._at_rest()
        self.assertEqual(d['server_name'], 'rp-test')
        self.assertEqual(d['password_min_length'], 12)
        self.assertEqual(d['proxmox_token_id'], 'user@pam!mytok')
        self.assertEqual(d['secrets_scan_paths'], ['/etc', '/opt'])
        # non-secret-named URL fields (integration/dest url) stay readable
        self.assertEqual(d['integrations'][0]['url'], 'http://10.0.0.2/admin')

    @unittest.skipUnless(CRYPTO, 'cryptography not installed')
    def test_transparent_roundtrip(self):
        os.environ['RP_CONFIG_KEY'] = 'unit-master-key'
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, dict(CFG))
        api._LOAD_CACHE.clear()
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual(cfg['ai']['api_key'], 'unit-fake-ai-credential-1')
        self.assertEqual(cfg['acme_dns_credentials']['dns_cf']['CF_Token'],
                         'cf-secret-xyz')
        self.assertEqual(cfg['webhook_destinations'][0]['token'], 'dest-token-1')
        self.assertEqual(cfg['webhook_url'],
                         'https://hooks.slack.com/services/T00/B00/SECRETPART')

    def test_no_key_is_full_noop(self):
        os.environ.pop('RP_CONFIG_KEY', None)
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, dict(CFG))
        d = self._at_rest()
        self.assertEqual(d['ai']['api_key'], 'unit-fake-ai-credential-1')   # byte-identical


class TestV1Compat(_Base):
    @unittest.skipUnless(CRYPTO, 'cryptography not installed')
    def test_legacy_v1_blob_still_decrypts_and_migrates(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        os.environ['RP_CONFIG_KEY'] = 'unit-master-key'
        # craft a v1 blob exactly as the v5.4.1 code wrote it
        salt, nonce = os.urandom(16), os.urandom(12)
        dk = hashlib.pbkdf2_hmac('sha256', b'unit-master-key', salt, 200000)
        ct = AESGCM(dk).encrypt(nonce, b'legacy-secret', None)
        v1 = 'enc:v1:' + base64.b64encode(salt + nonce + ct).decode()
        api._LOAD_CACHE.clear()
        # write it at rest bypassing the encrypt hook (simulates an upgraded store)
        os.environ.pop('RP_CONFIG_KEY')
        api.save(api.CONFIG_FILE, {'smtp_password': v1})
        os.environ['RP_CONFIG_KEY'] = 'unit-master-key'
        api._LOAD_CACHE.clear()
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual(cfg['smtp_password'], 'legacy-secret')
        # a save migrates it to v2
        api.save(api.CONFIG_FILE, cfg)
        self.assertTrue(self._at_rest()['smtp_password'].startswith('enc:v2:'))

    @unittest.skipUnless(CRYPTO, 'cryptography not installed')
    def test_kdf_cached_per_process(self):
        os.environ['RP_CONFIG_KEY'] = 'unit-master-key'
        api._CFG_DK_CACHE.clear()
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, dict(CFG))
        api._LOAD_CACHE.clear()
        api.load(api.CONFIG_FILE)
        # every v2 value shares ONE derivation (master, install-salt)
        v2_keys = [k for k in api._CFG_DK_CACHE if k[0] != 'v1']
        self.assertEqual(len(v2_keys), 1)


if __name__ == '__main__':
    unittest.main()
