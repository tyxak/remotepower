#!/usr/bin/env python3
"""
Tests for v2.1.3 — AI provider integration.

Covers:
  - ai_provider.validate_config  / validate_messages
  - ai_provider.redact + redact_messages (always-on safety,
    privacy-toggled IPv4 / FQDN / IPv6)
  - About-page version logic: latest is clamped to >= local
  - handle_ai_config_get returns masked api_key
  - handle_ai_config_set persists, validates, supports __clear__
  - handle_ai_chat validates messages, dispatches, audit-logs
  - Rate limit applies per user-day

We don't actually make HTTP calls against real providers — the chat()
adapter is monkey-patched.
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v213", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import ai_provider


# ─── Test scaffolding (same pattern as other test files) ─────────────────


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


def _capture_respond():
    def fake_respond(status, data):
        raise _Captured(status, data)
    api.respond = fake_respond


class _StdinShim:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def _set_request(method='POST', body=None):
    os.environ['REQUEST_METHOD'] = method
    if body is not None:
        body_bytes = json.dumps(body).encode('utf-8')
        os.environ['CONTENT_LENGTH'] = str(len(body_bytes))
        api.sys.stdin = _StdinShim(body_bytes)
    else:
        os.environ['CONTENT_LENGTH'] = '0'
        api.sys.stdin = _StdinShim(b'')


def _stub_auth(username='admin'):
    api.require_auth = lambda **kw: username
    api.require_admin_auth = lambda: username


class _Base(unittest.TestCase):
    def setUp(self):
        self._data_dir = Path(tempfile.mkdtemp())
        api.DATA_DIR        = self._data_dir
        api.CONFIG_FILE     = self._data_dir / 'config.json'
        api.AI_USAGE_FILE   = self._data_dir / 'ai_usage.json'
        api.AUDIT_LOG_FILE  = self._data_dir / 'audit_log.json'
        _capture_respond()
        _stub_auth('admin')


# ─── Redaction ──────────────────────────────────────────────────────────────


class TestRedact(unittest.TestCase):

    def test_always_strips_bearer_tokens(self):
        # Even with "send everything" privacy, bearer tokens get redacted
        out = ai_provider.redact(
            'Authorization: Bearer abcdef1234567890abcdef1234567890',
            {'send_ips': True, 'send_hostnames': True})
        self.assertIn('<REDACTED>', out)
        self.assertNotIn('abcdef', out)

    def test_always_strips_aws_keys(self):
        out = ai_provider.redact('key=AKIAIOSFODNN7EXAMPLE',
                                 {'send_ips': True, 'send_hostnames': True})
        self.assertIn('<REDACTED-AWS>', out)
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', out)

    def test_always_strips_long_hex(self):
        out = ai_provider.redact(
            'token a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8',
            {'send_ips': True, 'send_hostnames': True})
        self.assertIn('<REDACTED-HEX>', out)

    def test_redacts_ipv4_by_default(self):
        out = ai_provider.redact('connect to 192.168.1.10', {})
        self.assertNotIn('192.168.1.10', out)
        self.assertIn('<IP>', out)

    def test_keeps_ipv4_when_toggled_on(self):
        out = ai_provider.redact('connect to 192.168.1.10',
                                 {'send_ips': True})
        self.assertIn('192.168.1.10', out)

    def test_redacts_fqdn_by_default(self):
        out = ai_provider.redact('curl https://pmg01.example.com/health', {})
        self.assertNotIn('pmg01.example.com', out)
        self.assertIn('<HOST>', out)

    def test_keeps_fqdn_when_toggled_on(self):
        out = ai_provider.redact('curl https://pmg01.example.com/health',
                                 {'send_hostnames': True})
        self.assertIn('pmg01.example.com', out)

    def test_handles_non_string_gracefully(self):
        self.assertEqual(ai_provider.redact(None, {}), None)
        self.assertEqual(ai_provider.redact(42, {}), 42)

    def test_redact_messages_iterates(self):
        msgs = [
            {'role': 'user', 'content': 'IP is 10.0.0.5'},
            {'role': 'assistant', 'content': 'OK'},
        ]
        out = ai_provider.redact_messages(msgs, {})
        self.assertEqual(out[0]['content'], 'IP is <IP>')
        self.assertEqual(out[1]['content'], 'OK')
        # Original untouched
        self.assertEqual(msgs[0]['content'], 'IP is 10.0.0.5')


# ─── Validation ────────────────────────────────────────────────────────────


class TestValidateConfig(unittest.TestCase):

    def test_disabled_is_valid(self):
        ok, err = ai_provider.validate_config({'enabled': False})
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_anthropic_requires_key(self):
        ok, err = ai_provider.validate_config({
            'enabled': True, 'provider': 'anthropic'})
        self.assertFalse(ok)
        self.assertIn('api_key', err)

    def test_anthropic_with_key_ok(self):
        ok, _ = ai_provider.validate_config({
            'enabled': True, 'provider': 'anthropic', 'api_key': 'sk-...'})
        self.assertTrue(ok)

    def test_ollama_no_key_ok(self):
        # Local providers don't require an API key
        ok, _ = ai_provider.validate_config({
            'enabled': True, 'provider': 'ollama'})
        self.assertTrue(ok)

    def test_unknown_provider_rejected(self):
        ok, err = ai_provider.validate_config({
            'enabled': True, 'provider': 'gptmagic'})
        self.assertFalse(ok)
        self.assertIn('provider must be', err)


class TestValidateMessages(unittest.TestCase):

    def test_empty_list_rejected(self):
        ok, _ = ai_provider.validate_messages([])
        self.assertFalse(ok)

    def test_normal_chat_ok(self):
        ok, _ = ai_provider.validate_messages(
            [{'role': 'user', 'content': 'hi'}])
        self.assertTrue(ok)

    def test_unknown_role_rejected(self):
        ok, _ = ai_provider.validate_messages(
            [{'role': 'bot', 'content': 'hi'}])
        self.assertFalse(ok)

    def test_oversize_message_rejected(self):
        big = 'x' * (ai_provider.MAX_MESSAGE_BYTES + 100)
        ok, err = ai_provider.validate_messages(
            [{'role': 'user', 'content': big}])
        self.assertFalse(ok)
        self.assertIn('too large', err)

    def test_oversize_total_rejected(self):
        msg = 'x' * (ai_provider.MAX_MESSAGE_BYTES - 100)
        # Many messages just under per-message cap, blowing total
        msgs = [{'role': 'user', 'content': msg}
                for _ in range(ai_provider.MAX_TOTAL_BYTES // len(msg) + 2)]
        ok, _ = ai_provider.validate_messages(msgs)
        self.assertFalse(ok)


# ─── About-page version logic (v2.1.3 fix) ──────────────────────────────────


class TestVersionCheck(_Base):

    def _check(self):
        _set_request('GET')
        try:
            api.handle_version_check()
        except _Captured as c:
            return c
        self.fail("respond not called")

    def test_running_ahead_of_github_release(self):
        """If GitHub's latest tag is OLDER than SERVER_VERSION (i.e. running
        a dev build before tagging), 'latest' should clamp up to local
        and update_available is False."""
        api.SERVER_VERSION = '2.1.3'
        api.save(api.CONFIG_FILE, {
            '_github_latest_version': '2.0.0',
            '_github_latest_ts': int(time.time()),  # fresh cache → no GH call
        })
        r = self._check()
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body['current'], '2.1.3')
        self.assertEqual(r.body['latest'], '2.1.3')   # clamped up
        self.assertFalse(r.body['update_available'])

    def test_github_ahead_of_local(self):
        """Real upgrade-available case."""
        api.SERVER_VERSION = '2.0.0'
        api.save(api.CONFIG_FILE, {
            '_github_latest_version': '2.1.3',
            '_github_latest_ts': int(time.time()),
        })
        r = self._check()
        self.assertEqual(r.body['current'], '2.0.0')
        self.assertEqual(r.body['latest'], '2.1.3')
        self.assertTrue(r.body['update_available'])

    def test_uses_server_version_not_stale_config(self):
        """The old code read 'server_version' from CONFIG_FILE — which was
        often stale. Confirm the fix uses the module constant instead."""
        api.SERVER_VERSION = '2.1.3'
        api.save(api.CONFIG_FILE, {
            'server_version': '2.0.0',                # stale!
            '_github_latest_version': '2.1.3',
            '_github_latest_ts': int(time.time()),
        })
        r = self._check()
        self.assertEqual(r.body['current'], '2.1.3')  # not 2.0.0


# ─── AI config CRUD ────────────────────────────────────────────────────────


class TestAIConfigEndpoints(_Base):

    def test_get_returns_defaults_when_unset(self):
        _set_request('GET')
        try:
            api.handle_ai_config_get()
        except _Captured as c:
            r = c
        self.assertEqual(r.status, 200)
        self.assertFalse(r.body['enabled'])
        self.assertEqual(r.body['provider'], 'anthropic')   # default
        self.assertIn('_providers', r.body)
        self.assertIn('_defaults', r.body)

    def test_get_masks_api_key(self):
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic',
            'api_key': 'sk-ant-1234567890abcdef',
        }})
        _set_request('GET')
        try:
            api.handle_ai_config_get()
        except _Captured as c:
            r = c
        self.assertEqual(r.status, 200)
        self.assertIn('••••', r.body['api_key'])
        self.assertNotIn('1234567890', r.body['api_key'])
        # Trailing chars present so the operator can spot which key it is
        self.assertTrue(r.body['api_key'].endswith('cdef'))

    def test_set_persists(self):
        _set_request('POST', {
            'enabled': True, 'provider': 'openai',
            'api_key': 'sk-test', 'model': 'gpt-4o-mini',
        })
        try:
            api.handle_ai_config_set()
        except _Captured as c:
            r = c
        self.assertEqual(r.status, 200)
        cfg = api.load(api.CONFIG_FILE)['ai']
        self.assertEqual(cfg['provider'], 'openai')
        self.assertEqual(cfg['api_key'], 'sk-test')

    def test_set_empty_api_key_preserves_existing(self):
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic',
            'api_key': 'sk-original',
        }})
        _set_request('POST', {
            'enabled': True, 'provider': 'anthropic',
            'api_key': '',   # blank — should not overwrite
        })
        try:
            api.handle_ai_config_set()
        except _Captured:
            pass
        cfg = api.load(api.CONFIG_FILE)['ai']
        self.assertEqual(cfg['api_key'], 'sk-original')

    def test_set_clear_marker_wipes(self):
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic',
            'api_key': 'sk-original',
        }})
        # Clearing the key while still in "enabled anthropic" mode would
        # leave the config in an invalid state — validator correctly
        # rejects it. Operator must disable first, OR switch to a local
        # provider that doesn't need a key. Test the disable-first flow.
        _set_request('POST', {'enabled': False, 'api_key': '__clear__'})
        try:
            api.handle_ai_config_set()
        except _Captured:
            pass
        cfg = api.load(api.CONFIG_FILE)['ai']
        self.assertEqual(cfg['api_key'], '')

    def test_set_clear_rejected_when_still_enabled(self):
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic',
            'api_key': 'sk-original',
        }})
        _set_request('POST', {'api_key': '__clear__'})   # still enabled
        try:
            api.handle_ai_config_set()
        except _Captured as c:
            self.assertEqual(c.status, 400)
            # Key not actually wiped because validator rejected
            cfg = api.load(api.CONFIG_FILE)['ai']
            self.assertEqual(cfg['api_key'], 'sk-original')

    def test_set_validates_provider(self):
        _set_request('POST', {'enabled': True, 'provider': 'bogus'})
        try:
            api.handle_ai_config_set()
        except _Captured as c:
            self.assertEqual(c.status, 400)
            return
        self.fail("expected 400")

    def test_set_validates_anthropic_needs_key(self):
        _set_request('POST', {'enabled': True, 'provider': 'anthropic'})
        try:
            api.handle_ai_config_set()
        except _Captured as c:
            self.assertEqual(c.status, 400)
            self.assertIn('api_key', c.body['error'])


# ─── AI chat endpoint ──────────────────────────────────────────────────────


class TestAIChatEndpoint(_Base):

    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic', 'api_key': 'k',
            'limits': {'max_tokens_per_response': 1000,
                       'max_requests_per_user_day': 5},
        }})
        # Stub out the actual HTTP call
        self._chat_calls = []
        def fake_chat(cfg, messages, system=None, max_tokens=None, model=None):
            self._chat_calls.append({'cfg': cfg, 'messages': messages,
                                     'system': system, 'max_tokens': max_tokens,
                                     'model': model})
            return {'ok': True, 'text': 'mocked response',
                    'model': model or 'mock-1', 'tokens_in': 10, 'tokens_out': 5}
        ai_provider.chat = fake_chat

    def _chat(self, body):
        _set_request('POST', body)
        try:
            api.handle_ai_chat()
        except _Captured as c:
            return c
        self.fail("respond not called")

    def test_basic_chat(self):
        r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}],
                        'system': 'explain_output'})
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body['text'], 'mocked response')
        self.assertEqual(self._chat_calls[0]['system'],
                         ai_provider.SYSTEM_PROMPTS['explain_output'])

    def test_literal_system_passes_through(self):
        r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}],
                        'system': 'be terse'})
        self.assertEqual(r.status, 200)
        self.assertEqual(self._chat_calls[0]['system'], 'be terse')

    def test_disabled_400(self):
        api.save(api.CONFIG_FILE, {'ai': {'enabled': False}})
        r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}]})
        self.assertEqual(r.status, 400)

    def test_invalid_messages_400(self):
        r = self._chat({'messages': []})
        self.assertEqual(r.status, 400)

    def test_audit_logged(self):
        self._chat({'messages': [{'role': 'user', 'content': 'hi'}],
                    'context': 'device:abc'})
        log = api.load(api.AUDIT_LOG_FILE)
        # audit log shape varies but should contain ai_chat somewhere
        self.assertIn('ai_chat', json.dumps(log))

    def test_rate_limit_enforced(self):
        # cap is 5
        for _ in range(5):
            r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}]})
            self.assertEqual(r.status, 200)
        # 6th hits the cap
        r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}]})
        self.assertEqual(r.status, 429)
        self.assertIn('cap reached', r.body['error'])

    def test_rate_limit_zero_means_unlimited(self):
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic', 'api_key': 'k',
            'limits': {'max_requests_per_user_day': 0},
        }})
        for _ in range(20):
            r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}]})
            self.assertEqual(r.status, 200)

    def test_per_user_isolation(self):
        # admin uses 5/5, second user should still have full budget
        for _ in range(5):
            self._chat({'messages': [{'role': 'user', 'content': 'hi'}]})
        api.require_auth = lambda **kw: 'bob'
        api.require_admin_auth = lambda: 'bob'
        r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}]})
        self.assertEqual(r.status, 200)

    def test_model_override_passed_through(self):
        """AI page picker sends `model` per-request; chat() should honour it."""
        r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}],
                        'model': 'llama3.1:70b'})
        self.assertEqual(r.status, 200)
        self.assertEqual(self._chat_calls[0]['model'], 'llama3.1:70b')
        self.assertEqual(r.body['model'], 'llama3.1:70b')

    def test_model_override_ignored_if_too_long(self):
        """Defence against a client sending a 50KB string as `model`."""
        long_model = 'x' * 500
        r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}],
                        'model': long_model})
        self.assertEqual(r.status, 200)
        self.assertIsNone(self._chat_calls[0]['model'])

    def test_max_tokens_capped_to_config(self):
        """Client can request fewer tokens but not more than the server cap."""
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic', 'api_key': 'k',
            'limits': {'max_tokens_per_response': 500},
        }})
        r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}],
                        'max_tokens': 10000})
        self.assertEqual(r.status, 200)
        # Caller asked for 10000 but cap is 500 → 500 should be passed
        self.assertEqual(self._chat_calls[0]['max_tokens'], 500)

    def test_max_tokens_smaller_request_honoured(self):
        r = self._chat({'messages': [{'role': 'user', 'content': 'hi'}],
                        'max_tokens': 200})
        self.assertEqual(self._chat_calls[0]['max_tokens'], 200)


# ─── /api/ai/models + /api/ai/stats ────────────────────────────────────────


class TestAIIntrospection(_Base):

    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'ollama',
            'base_url': 'http://localhost:11434/v1',
        }})

    def test_models_endpoint_returns_list(self):
        ai_provider.list_models = lambda cfg: {'ok': True, 'models': [
            {'name': 'llama3.1:8b', 'size_bytes': 4000000000},
            {'name': 'smallthinker:latest', 'size_bytes': 2000000000},
        ]}
        _set_request('GET')
        try:
            api.handle_ai_models()
        except _Captured as c:
            r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(len(r.body['models']), 2)

    def test_models_endpoint_disabled_400(self):
        api.save(api.CONFIG_FILE, {'ai': {'enabled': False}})
        _set_request('GET')
        try:
            api.handle_ai_models()
        except _Captured as c:
            self.assertEqual(c.status, 400)

    def test_stats_endpoint_returns_provider_info(self):
        ai_provider.provider_stats = lambda cfg: {
            'ok': True, 'provider': 'ollama',
            'version': '0.1.32', 'reachable': True,
            'loaded_models': [{'name': 'smallthinker:latest', 'vram_mb': 1500}],
        }
        _set_request('GET')
        try:
            api.handle_ai_stats()
        except _Captured as c:
            r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body['version'], '0.1.32')
        self.assertTrue(r.body['reachable'])


# ─── Ollama URL handling ────────────────────────────────────────────────────


class TestOllamaURLHandling(unittest.TestCase):

    def test_strips_v1_suffix_for_introspection(self):
        """Operators paste either form: http://host:11434 or
        http://host:11434/v1. Either should work."""
        cfg_with_v1 = {'provider': 'ollama', 'base_url': 'http://localhost:11434/v1'}
        cfg_root    = {'provider': 'ollama', 'base_url': 'http://localhost:11434'}
        self.assertEqual(ai_provider._ollama_root(cfg_with_v1),
                         'http://localhost:11434')
        self.assertEqual(ai_provider._ollama_root(cfg_root),
                         'http://localhost:11434')


# ─── System prompts ────────────────────────────────────────────────────────


class TestSystemPrompts(unittest.TestCase):
    def test_all_inline_button_keys_present(self):
        """The 6 inline buttons + script generation refer to these keys.
        If any is renamed, the button breaks silently — this test catches it."""
        required = {'explain_output', 'find_problem', 'explain_script',
                    'audit_script', 'generate_script', 'triage_cve',
                    'investigate_device', 'explain_alert'}
        self.assertTrue(required.issubset(ai_provider.SYSTEM_PROMPTS.keys()),
                        f"missing keys: {required - ai_provider.SYSTEM_PROMPTS.keys()}")

    def test_prompts_are_non_empty(self):
        for k, v in ai_provider.SYSTEM_PROMPTS.items():
            self.assertTrue(v.strip(), f'empty prompt for {k}')
            self.assertGreater(len(v), 40, f'prompt for {k} suspiciously short')


if __name__ == '__main__':
    unittest.main(verbosity=2)
