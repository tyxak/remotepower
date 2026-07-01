"""v5.6.0 — AI "what was sent?" debug mode.

Operators reported AI advisors answering "I need to see the actual drift data"
— i.e. the RAG/fleet context wasn't reaching the model (RAG is off by default).
`POST /api/ai/chat` with `debug:true` now returns EXACTLY what would be sent (the
assembled system prompt + what RAG retrieved) WITHOUT calling the provider, and
the UI exposes it per insight card and on every AI result modal.
"""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-aidbg-'))
_ROOT = Path(__file__).parent.parent
_API = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
_AIJS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ai.js').read_text()


class TestBackendDebugBranch(unittest.TestCase):
    def test_debug_short_circuits_before_model_call(self):
        seg = _API[_API.index('def handle_ai_chat'):
                   _API.index('def handle_ai_chat') + 9000]
        self.assertIn("if body.get('debug'):", seg)
        # returns the assembled prompt + retrieval facts
        for key in ("'system_prompt'", "'retrieved_count'", "'rag_enabled'",
                    "'rag_query'", "'caller_full_access'", "'note'"):
            self.assertIn(key, seg, f'{key} missing from debug response')
        # the debug branch must precede the actual provider call
        self.assertLess(seg.index("if body.get('debug'):"),
                        seg.index('ai_provider.chat('),
                        'debug branch must short-circuit before the model call')

    def test_rag_query_initialised_for_debug(self):
        seg = _API[_API.index('def handle_ai_chat'):
                   _API.index('def handle_ai_chat') + 9000]
        self.assertIn('rag_query = None', seg,
                      'rag_query must be defined even when RAG is skipped')


class TestFrontendDebugWiring(unittest.TestCase):
    def test_functions_exist(self):
        for fn in ('function aiInsightDebug', 'async function _aiRunDebug',
                   'function aiModalDebug'):
            self.assertIn(fn, _AIJS, f'{fn} missing')

    def test_debug_sends_debug_flag(self):
        self.assertIn('debug: true', _AIJS)

    def test_per_card_debug_button(self):
        self.assertIn('data-action="aiInsightDebug"', _AIJS)
        self.assertIn('ai-insight-wrap', _AIJS)

    def test_result_modal_debug_button(self):
        self.assertIn('id="ai-modal-debug"', _AIJS)
        self.assertIn('data-action="aiModalDebug"', _AIJS)
        self.assertIn('window._aiModalLast', _AIJS)


if __name__ == '__main__':
    unittest.main()
