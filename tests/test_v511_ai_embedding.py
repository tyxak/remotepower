"""Regression tests for the two community issues fixed on the v5.1.1 test line:

  * #10 (loryanstrant) — the API-key field was *disabled* for LocalAI, even
    though LocalAI now supports API keys (the backend already forwards a key for
    local providers). The fix is frontend-only: the field must no longer be
    disabled for local providers.

  * #11 (loryanstrant) — embeddings could only ever run on the same service as
    chat. Operators who want to point embeddings at a *different* service (a
    dedicated, less-contested GPU box) can now set rag.embedding_{provider,
    base_url,api_key}; ai_provider.embedding_cfg() resolves the effective
    embedding config and embed()/embedding_fingerprint()/supports_embeddings()
    honour it.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

try:
    from clientjs import client_js
except ImportError:  # running this file directly from repo root
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from clientjs import client_js


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _CGI / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ai_provider = _load('ai_provider_v511', 'ai_provider.py')


# ───────────────────────── #10: LocalAI API key ─────────────────────────────

class TestLocalAIApiKeyAllowed(unittest.TestCase):
    def test_frontend_does_not_disable_key_for_local(self):
        js = client_js()
        # The old code set `ai-api-key`.disabled = local (true for ollama/localai).
        # That exact pattern must be gone.
        self.assertNotRegex(
            js, r"getElementById\('ai-api-key'\)\.disabled\s*=\s*local",
            "API-key field must not be disabled for local providers (#10)")
        # And it must be explicitly (re-)enabled.
        self.assertIn("getElementById('ai-api-key').disabled = false", js)

    def test_hint_text_no_longer_claims_key_unused(self):
        html = (Path(__file__).resolve().parent.parent
                / 'server' / 'html' / 'index.html').read_text()
        self.assertNotIn('Not used for Ollama or LocalAI', html)

    def test_backend_validate_accepts_localai_with_key(self):
        cfg = {'enabled': True, 'provider': 'localai', 'api_key': 'sk-local-123'}
        ok, err = ai_provider.validate_config(cfg)
        self.assertTrue(ok, err)

    def test_backend_validate_still_allows_localai_without_key(self):
        ok, err = ai_provider.validate_config(
            {'enabled': True, 'provider': 'localai'})
        self.assertTrue(ok, err)

    def test_localai_key_is_sent_as_bearer(self):
        # embed() must attach the key as a Bearer header for LocalAI.
        captured = {}

        def fake_post(url, headers, body, timeout=None, insecure_ssl=False):
            captured['url'] = url
            captured['headers'] = headers
            return 200, {'data': [{'index': 0, 'embedding': [0.1, 0.2]}],
                         'model': body['model']}

        orig = ai_provider._http_post_json
        ai_provider._http_post_json = fake_post
        try:
            cfg = {'provider': 'localai', 'api_key': 'sk-local-xyz',
                   'base_url': 'http://localai.lan:8080/v1', 'rag': {}}
            res = ai_provider.embed(cfg, ['hello'])
        finally:
            ai_provider._http_post_json = orig
        self.assertTrue(res['ok'], res)
        self.assertEqual(captured['headers'].get('Authorization'),
                         'Bearer sk-local-xyz')


# ──────────────────── #11: separate embedding service ───────────────────────

class TestEmbeddingCfgResolution(unittest.TestCase):
    def test_no_overrides_returns_cfg_verbatim(self):
        cfg = {'provider': 'localai', 'base_url': 'http://a/v1', 'api_key': 'k',
               'rag': {'embedding_model': 'm'}}
        self.assertIs(ai_provider.embedding_cfg(cfg), cfg)

    def test_separate_base_url_and_key(self):
        cfg = {'provider': 'localai', 'base_url': 'http://chat:8080/v1',
               'api_key': 'chatkey',
               'rag': {'embedding_model': 'emb-model',
                       'embedding_base_url': 'http://gpubox:9090/v1',
                       'embedding_api_key': 'embkey'}}
        e = ai_provider.embedding_cfg(cfg)
        self.assertEqual(e['provider'], 'localai')
        self.assertEqual(e['base_url'], 'http://gpubox:9090/v1')
        self.assertEqual(e['api_key'], 'embkey')
        self.assertEqual(e['rag']['embedding_model'], 'emb-model')

    def test_different_provider_does_not_replay_chat_key(self):
        # chat=anthropic (no key needed here), embeddings=localai with own key.
        cfg = {'provider': 'anthropic', 'api_key': 'sk-anthropic',
               'rag': {'embedding_provider': 'localai',
                       'embedding_base_url': 'http://emb:8080/v1'}}
        e = ai_provider.embedding_cfg(cfg)
        self.assertEqual(e['provider'], 'localai')
        # Must NOT inherit the anthropic key onto a different endpoint.
        self.assertNotEqual(e.get('api_key'), 'sk-anthropic')

    def test_same_provider_no_overrides_inherits(self):
        cfg = {'provider': 'openai', 'base_url': 'http://oai/v1',
               'api_key': 'oaikey',
               'rag': {'embedding_provider': 'openai'}}
        e = ai_provider.embedding_cfg(cfg)
        self.assertEqual(e['base_url'], 'http://oai/v1')
        self.assertEqual(e['api_key'], 'oaikey')


class TestEmbeddingProviderEnablesSupport(unittest.TestCase):
    def test_anthropic_chat_localai_embeddings_supports(self):
        # Anthropic alone can't embed; with a LocalAI embedding provider it can.
        self.assertFalse(ai_provider.supports_embeddings({'provider': 'anthropic'}))
        self.assertTrue(ai_provider.supports_embeddings(
            {'provider': 'anthropic',
             'rag': {'embedding_provider': 'localai'}}))


class TestEmbeddingFingerprintTracksOverride(unittest.TestCase):
    def test_changing_embedding_base_url_changes_fingerprint(self):
        a = {'provider': 'localai', 'base_url': 'http://chat/v1',
             'rag': {'embedding_model': 'm'}}
        b = {'provider': 'localai', 'base_url': 'http://chat/v1',
             'rag': {'embedding_model': 'm',
                     'embedding_base_url': 'http://gpubox/v1'}}
        self.assertNotEqual(ai_provider.embedding_fingerprint(a),
                            ai_provider.embedding_fingerprint(b))

    def test_changing_embedding_provider_changes_fingerprint(self):
        a = {'provider': 'anthropic', 'rag': {'embedding_provider': 'openai',
                                              'embedding_model': 'm'}}
        b = {'provider': 'anthropic', 'rag': {'embedding_provider': 'localai',
                                              'embedding_model': 'm'}}
        self.assertNotEqual(ai_provider.embedding_fingerprint(a),
                            ai_provider.embedding_fingerprint(b))


class TestEmbedUsesOverrideEndpoint(unittest.TestCase):
    def test_embed_posts_to_override_endpoint_with_override_key(self):
        captured = {}

        def fake_post(url, headers, body, timeout=None, insecure_ssl=False):
            captured['url'] = url
            captured['headers'] = headers
            return 200, {'data': [{'index': 0, 'embedding': [1.0, 2.0, 3.0]}],
                         'model': body['model']}

        orig = ai_provider._http_post_json
        ai_provider._http_post_json = fake_post
        try:
            cfg = {'provider': 'anthropic', 'api_key': 'sk-anthropic',
                   'rag': {'embedding_provider': 'localai',
                           'embedding_base_url': 'http://gpubox:9090/v1',
                           'embedding_api_key': 'embkey',
                           'embedding_model': 'my-embed'}}
            res = ai_provider.embed(cfg, ['hello'])
        finally:
            ai_provider._http_post_json = orig
        self.assertTrue(res['ok'], res)
        self.assertEqual(captured['url'], 'http://gpubox:9090/v1/embeddings')
        self.assertEqual(captured['headers'].get('Authorization'), 'Bearer embkey')


class TestFrontendEmbeddingFields(unittest.TestCase):
    def test_index_has_embedding_service_fields(self):
        html = (Path(__file__).resolve().parent.parent
                / 'server' / 'html' / 'index.html').read_text()
        for fid in ('ai-rag-embed-provider', 'ai-rag-embed-base-url',
                    'ai-rag-embed-api-key'):
            self.assertIn(fid, html, f'missing {fid} in Settings UI (#11)')

    def test_frontend_saves_and_loads_embedding_overrides(self):
        js = client_js()
        self.assertIn('embedding_provider:', js)
        self.assertIn('embedding_base_url:', js)
        self.assertIn('embedding_api_key', js)


if __name__ == '__main__':
    unittest.main()
