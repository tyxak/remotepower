"""v5.8.0: opencode (REST) + openclaw (WebSocket-RPC) AI providers."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_spec = importlib.util.spec_from_file_location("ai_provider_x", _CGI / "ai_provider.py")
ai = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ai)


class TestRegistry(unittest.TestCase):
    def test_providers_registered(self):
        self.assertIn('opencode', ai.VALID_PROVIDERS)
        self.assertIn('openclaw', ai.VALID_PROVIDERS)
        self.assertIn('opencode', ai.DEFAULT_BASE_URLS)
        self.assertEqual(ai.DEFAULT_BASE_URLS['openclaw'], 'ws://localhost:18789')

    def test_local_providers_need_no_api_key(self):
        for p in ('opencode', 'openclaw'):
            ok, err = ai.validate_config({'enabled': True, 'provider': p})
            self.assertTrue(ok, err)


class TestHelpers(unittest.TestCase):
    def test_flatten_prompt(self):
        out = ai._flatten_prompt([{'role': 'user', 'content': 'hi'}], 'be terse')
        self.assertIn('be terse', out)
        self.assertIn('hi', out)

    def test_extract_text_shapes(self):
        self.assertEqual(ai._extract_text({'text': 'A'}), 'A')
        self.assertEqual(ai._extract_text({'parts': [{'type': 'text', 'text': 'B'}]}), 'B')
        self.assertEqual(ai._extract_text({'message': {'content': 'C'}}), 'C')
        self.assertEqual(ai._extract_text([{'x': 1}, {'text': 'D'}]), 'D')
        self.assertEqual(ai._extract_text({'nope': 1}), '')


class TestOpencode(unittest.TestCase):
    def test_happy_path(self):
        calls = []

        def fake_post(url, headers, body, timeout=None, insecure_ssl=False):
            calls.append((url, body, headers))
            if url.endswith('/session'):
                return 200, {'id': 'ses_1'}
            return 200, {'parts': [{'type': 'text', 'text': 'the answer'}]}
        orig = ai._http_post_json
        ai._http_post_json = fake_post
        try:
            r = ai.chat_opencode({'provider': 'opencode', 'model': 'anthropic/claude'},
                                 [{'role': 'user', 'content': 'q'}], 'sys', 100)
        finally:
            ai._http_post_json = orig
        self.assertTrue(r['ok'])
        self.assertEqual(r['text'], 'the answer')
        # session created first, then message posted with a split provider/model
        self.assertTrue(calls[0][0].endswith('/session'))
        self.assertEqual(calls[1][1].get('providerID'), 'anthropic')
        self.assertEqual(calls[1][1].get('modelID'), 'claude')

    def test_basic_auth_header(self):
        seen = {}

        def fake_post(url, headers, body, timeout=None, insecure_ssl=False):
            seen.update(headers)
            return (200, {'id': 's'}) if url.endswith('/session') else (200, {'text': 'x'})
        orig = ai._http_post_json
        ai._http_post_json = fake_post
        try:
            ai.chat_opencode({'provider': 'opencode', 'api_key': 'secret', 'username': 'me'},
                             [{'role': 'user', 'content': 'q'}], '', 100)
        finally:
            ai._http_post_json = orig
        self.assertIn('Authorization', seen)
        self.assertTrue(seen['Authorization'].startswith('Basic '))

    def test_session_failure(self):
        orig = ai._http_post_json
        ai._http_post_json = lambda *a, **k: (500, {'error': 'boom'})
        try:
            r = ai.chat_opencode({'provider': 'opencode'}, [{'role': 'user', 'content': 'q'}], '', 100)
        finally:
            ai._http_post_json = orig
        self.assertFalse(r['ok'])


class TestOpenclaw(unittest.TestCase):
    def test_happy_path(self):
        sent = []

        def fake_ws(url, messages, timeout=30, insecure_ssl=False, max_frames=200):
            sent.extend(messages)
            return [{'id': 2, 'result': {'runId': 'r1', 'status': 'started'}},
                    {'method': 'chat.event', 'params': {'message': {'content': 'hello from openclaw'}}}]
        orig = ai._ws_rpc
        ai._ws_rpc = fake_ws
        try:
            r = ai.chat_openclaw({'provider': 'openclaw', 'api_key': 'tok'},
                                 [{'role': 'user', 'content': 'q'}], 'sys', 100)
        finally:
            ai._ws_rpc = orig
        self.assertTrue(r['ok'])
        self.assertEqual(r['text'], 'hello from openclaw')
        # auth token forwarded on the connect frame; chat.send carries the prompt
        self.assertEqual(sent[0]['method'], 'connect')
        self.assertEqual(sent[0]['params']['auth']['token'], 'tok')
        self.assertEqual(sent[1]['method'], 'chat.send')

    def test_no_text_fails(self):
        orig = ai._ws_rpc
        ai._ws_rpc = lambda *a, **k: [{'result': {'status': 'started'}}]
        try:
            r = ai.chat_openclaw({'provider': 'openclaw'}, [{'role': 'user', 'content': 'q'}], '', 100)
        finally:
            ai._ws_rpc = orig
        self.assertFalse(r['ok'])

    def test_ws_error_is_caught(self):
        orig = ai._ws_rpc
        def boom(*a, **k):
            raise RuntimeError('refused')
        ai._ws_rpc = boom
        try:
            r = ai.chat_openclaw({'provider': 'openclaw'}, [{'role': 'user', 'content': 'q'}], '', 100)
        finally:
            ai._ws_rpc = orig
        self.assertFalse(r['ok'])
        self.assertIn('openclaw', r['error'])


class TestDispatch(unittest.TestCase):
    def test_chat_routes_to_new_providers(self):
        orig_oc, orig_ocl = ai.chat_opencode, ai.chat_openclaw
        ai.chat_opencode = lambda *a, **k: {'ok': True, 'text': 'OC'}
        ai.chat_openclaw = lambda *a, **k: {'ok': True, 'text': 'OCL'}
        try:
            r1 = ai.chat({'enabled': True, 'provider': 'opencode'}, [{'role': 'user', 'content': 'q'}])
            r2 = ai.chat({'enabled': True, 'provider': 'openclaw'}, [{'role': 'user', 'content': 'q'}])
        finally:
            ai.chat_opencode, ai.chat_openclaw = orig_oc, orig_ocl
        self.assertEqual(r1['text'], 'OC')
        self.assertEqual(r2['text'], 'OCL')


if __name__ == '__main__':
    unittest.main()
