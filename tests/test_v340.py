"""v3.4.0 release tests.

Strict version pins for v3.4.0. The v3.3.4 strict pins loosen to regex
when this file ships, following the same convention every prior
release-bump test followed.

v3.4.0's headline feature is "RAG over your infrastructure": a pure-stdlib
retrieval layer (rag_index.py) that indexes device state, docs, CMDB, and
history, with lexical BM25 always available and an optional embeddings
rerank when the provider supports it. The behavioural regression tests for
retrieval live in tests/test_rag.py; this file pins the version bump + that
the feature is wired and shipped end to end.
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """v3.4.0 takes the strict version pin (following prior convention)."""
    EXPECTED = '3.4.0'

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertIn(f"'remotepower-shell-v{self.EXPECTED}'", sw,
            f'sw.js CACHE_NAME must be bumped to remotepower-shell-v{self.EXPECTED}')

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn(f'?v={self.EXPECTED}', html,
            f'index.html cache-bust ?v= must be {self.EXPECTED}')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertIn(f'version-{self.EXPECTED}-blue.svg', text,
            'README.md version badge not bumped')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v<x.y.z> header')
        self.assertEqual(m.group(1), self.EXPECTED,
            f'CHANGELOG.md top entry is v{m.group(1)}, expected v{self.EXPECTED}')

    def test_release_notes_doc_present(self):
        path = REPO_ROOT / 'docs' / f'v{self.EXPECTED}.md'
        self.assertTrue(path.exists(), f'docs/v{self.EXPECTED}.md is missing')
        self.assertIn(self.EXPECTED, path.read_text())


class TestRagShipped(unittest.TestCase):
    """The RAG feature must be wired end to end, not just present in a module."""

    CGI = REPO_ROOT / 'server' / 'cgi-bin'

    def test_rag_index_module_present(self):
        mod = self.CGI / 'rag_index.py'
        self.assertTrue(mod.exists(), 'rag_index.py is missing')
        text = mod.read_text()
        for sym in ('def tokenize', 'def chunk_markdown', 'class InfraIndex',
                    'def build_live_state_corpus', 'def build_cmdb_corpus',
                    'def rrf_fuse', 'def cosine'):
            self.assertIn(sym, text, f'rag_index.py missing {sym!r}')

    def test_provider_embed_present(self):
        text = (self.CGI / 'ai_provider.py').read_text()
        self.assertIn('def embed(', text)
        self.assertIn('EMBEDDING_PROVIDERS', text)
        self.assertIn('def supports_embeddings', text)

    def test_ai_context_retrieved_block(self):
        text = (self.CGI / 'ai_context.py').read_text()
        self.assertIn('def build_retrieved_context', text)
        self.assertIn('<retrieved_context>', text)

    def test_api_endpoints_routed(self):
        text = (self.CGI / 'api.py').read_text()
        for route in ('/api/ai/rag/status', '/api/ai/rag/reindex',
                      '/api/ai/rag/search'):
            self.assertIn(route, text, f'route {route} not wired in api.py')
        for fn in ('def handle_ai_rag_status', 'def handle_ai_rag_reindex',
                   'def handle_ai_rag_search', 'def _rag_retrieve',
                   'def _rag_build_corpus'):
            self.assertIn(fn, text, f'{fn} missing from api.py')
        # chat injection: retrieved context is passed into the prompt builder
        self.assertIn('retrieved=retrieved', text)
        self.assertIn('import rag_index', text)

    def test_rag_config_defaults(self):
        text = (self.CGI / 'api.py').read_text()
        self.assertIn("'rag': {", text)
        self.assertIn("'embeddings_enabled'", text)
        self.assertIn("'include_rag'", text)

    def test_ui_controls_present(self):
        app = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        for fn in ('function aiRagReindex', 'function aiRagTestSearch',
                   'function loadRAGStatus', 'function _ragRenderSearch'):
            self.assertIn(fn, app, f'{fn} missing from app.js')
        # the results table must wire the sort control off data-col
        self.assertIn("wireSortOnly('ai-rag-results-thead'", app)
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('ai-rag-enabled', html)
        self.assertIn('aiRagReindex', html)

    def test_docs_deployed_for_rag(self):
        # both installers must place product docs where the indexer reads them
        for script in ('deploy-server.sh', 'install-server.sh'):
            text = (REPO_ROOT / script).read_text()
            self.assertIn('/docs', text)
            self.assertRegex(text, r'docs/\*\.md')

    def test_rag_reference_doc_present(self):
        path = REPO_ROOT / 'docs' / 'rag.md'
        self.assertTrue(path.exists(), 'docs/rag.md is missing')


if __name__ == '__main__':
    unittest.main()
