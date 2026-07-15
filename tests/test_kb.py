"""v5.6.0 — Knowledge base (structured IT documentation).

Operator-authored markdown articles in a category folder-tree, searchable,
admin-authored / all-roles-read, opt-in behind `kb_enabled`, and wired as a
fifth-place RAG source so the AI can answer from the operator's own docs.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-kb-test-"))

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_kb', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
_SRC = (_CGI / 'api.py').read_text()

_rspec = importlib.util.spec_from_file_location('rag_kb', _CGI / 'rag_index.py')
rag = importlib.util.module_from_spec(_rspec)
_rspec.loader.exec_module(rag)


class TestHelpers(unittest.TestCase):
    def test_clean_category_normalises_and_blocks_traversal(self):
        self.assertEqual(api._kb_clean_category('network/vpn'), 'network/vpn')
        self.assertEqual(api._kb_clean_category('/a//b/'), 'a/b')
        self.assertEqual(api._kb_clean_category('a/../../b'), 'a/b')
        self.assertEqual(api._kb_clean_category('.'), '')
        self.assertEqual(api._kb_clean_category(''), '')

    def test_clean_tags_dedupes_and_caps(self):
        out = api._kb_clean_tags(['vpn', 'vpn', ' wg ', '', 123, 'x' * 99])
        self.assertEqual(out[:3], ['vpn', 'wg', '123'])
        self.assertTrue(all(len(t) <= 40 for t in out))
        self.assertLessEqual(len(api._kb_clean_tags(['t%d' % i for i in range(100)])), 24)

    def test_public_shape_omits_body_in_list(self):
        a = {'id': 'kb_1', 'title': 'T', 'category': 'c', 'tags': ['x'],
             'body': 'secret-ish-body', 'pinned': True, 'author': 'admin'}
        full = api._kb_public(a, full=True)
        lite = api._kb_public(a, full=False)
        self.assertIn('body', full)
        self.assertNotIn('body', lite)
        self.assertTrue(full['pinned'])


class TestApiWiring(unittest.TestCase):
    def test_handlers_exist(self):
        for fn in ('handle_kb', 'handle_kb_article', '_kb_enabled',
                   '_kb_public', '_kb_clean_category', '_kb_clean_tags'):
            self.assertTrue(hasattr(api, fn), f'missing {fn}')

    def test_routes_registered(self):
        self.assertIn("('GET', '/api/kb'): handle_kb", _SRC)
        self.assertIn("('POST', '/api/kb'): handle_kb", _SRC)
        self.assertIn("pi.startswith('/api/kb/')", _SRC)

    def test_mutations_admin_gated_audited_and_kill_switched(self):
        for fn in ('handle_kb', 'handle_kb_article'):
            seg = _SRC[_SRC.index('def ' + fn): _SRC.index('def ' + fn) + 3200]
            self.assertIn('_kb_enabled()', seg, f'{fn} missing kill-switch')
            self.assertIn('require_admin_auth()', seg, f'{fn} not admin-gated')
            self.assertIn('audit_log(', seg, f'{fn} not audited')
            self.assertIn('require_auth()', seg, f'{fn} read not auth-gated')

    def test_config_flag_emitted_and_saved(self):
        self.assertIn("safe.setdefault('kb_enabled',", _SRC)
        self.assertIn("cfg['kb_enabled'] = bool(body['kb_enabled'])", _SRC)


class TestRagWiring(unittest.TestCase):
    """A new RAG source must touch all five places (CLAUDE.md)."""
    def test_default_on(self):
        self.assertIn('kb', api._AI_DEFAULTS['rag']['sources'])

    def test_source_files_and_corpus_and_whitelist(self):
        self.assertIn("if sources.get('kb'):", _SRC)
        self.assertIn('build_kb_corpus', _SRC)
        # save whitelist tuple includes 'kb'
        self.assertIn("'posture', 'vpn', 'tickets', 'kb'", _SRC)

    def test_builder_emits_docs(self):
        store = {'articles': [
            {'id': 'kb_1', 'title': 'Rotate VPN keys', 'category': 'network/vpn',
             'tags': ['vpn'], 'body': 'Step 1: ...', 'updated_at': 1},
        ]}
        docs = rag.build_kb_corpus(store, now=100)
        self.assertEqual(len(docs), 2)             # one article + the index doc
        self.assertTrue(all(d['source'] == 'kb' for d in docs))
        self.assertTrue(any('Rotate VPN keys' in d.get('text', '') for d in docs))

    def test_builder_defensive_on_bad_shape(self):
        self.assertEqual(rag.build_kb_corpus({}, now=1), [])
        self.assertEqual(rag.build_kb_corpus({'articles': 'nope'}, now=1), [])


class TestFrontendWiring(unittest.TestCase):
    def test_nav_page_and_module(self):
        index = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="nav-kb"', index)
        self.assertIn('id="page-kb"', index)
        self.assertIn('id="kb-edit-modal"', index)
        # v6.2.2: app-kb.js is a LAZY page module — wired through app.js's
        # _LAZY_PAGE_MODULES map, not a boot <script> tag.
        _appjs_core = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("'app-kb.js'", _appjs_core)
        # v6.0.0: KB is an always-on module — the opt-in checkbox is GONE
        self.assertNotIn('cfg-kb-enabled', index)
        self.assertIn('<button class="nav-btn" id="nav-kb"', index)
        appjs = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-kb.js').read_text()
        for fn in ('function loadKb', 'function saveKbArticle',
                   'function openKbArticle', 'function deleteKbArticle'):
            self.assertIn(fn, appjs)


if __name__ == '__main__':
    unittest.main()
