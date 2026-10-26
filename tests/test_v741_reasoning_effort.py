#!/usr/bin/env python3
"""7.4.1, issue #40: a reasoning-effort setting for the OpenAI-compatible AI providers.

With Ollama and a thinking model every request thought as long as it liked. On a real alert the model
spent the whole token allowance reasoning, Mitigate showed "Done in 115s, but the response was empty",
and nothing in RemotePower could stop it: Ollama's /v1 endpoint only turns thinking off when the
request carries a top-level `reasoning_effort: "none"`, and RemotePower never sent that field.

What is held here, each against the real code:

  * The adapter puts the field on the wire, read from a local server that records the request body:
    sent for none / low / medium / high, not sent when blank, a per-call value beats the setting,
    junk in a hand-edited config is dropped, and the Anthropic adapter never carries it.
  * The two settings round-trip through the real handlers: Settings -> AI assistant (global) and a
    prompt's Fine-tuning (per prompt), with a blank clearing and a bad level refused.
  * Every route into the provider honours them. The reporter's route, Mitigate, goes through
    `_call_ai_with_prompts`, which read the per-prompt overrides from `cfg['ai']` while they are saved
    at the top of the config, so a Fine-tuning row (max tokens, temperature, ...) never reached it,
    nor the alert triage, log sweep or AI exec prompts that share it. Both are driven to the wire.
  * An empty reply that stopped at the token limit now says why instead of being a blank success.
"""
import ast
import functools
import http.server
import importlib.util
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
ROOT = _HERE.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v741-re-"))
_spec = importlib.util.spec_from_file_location("api_v741_re", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import ai_provider  # noqa: E402
import request_models  # noqa: E402

LANGS = ("zh", "hi", "es", "ar", "de", "fr")
I18N = (ROOT / "server/html/static/js/i18n.js").read_text()
HTML = (ROOT / "server/html/index.html").read_text()
APP_AI = (ROOT / "server/html/static/js/app-ai.js").read_text()


class _Endpoint:
    """A local OpenAI-compatible server. It records the JSON body of every request."""

    def __init__(self):
        outer = self
        self.seen = []
        self.reply = {'choices': [{'message': {'content': 'OK'}, 'finish_reason': 'stop'}],
                      'usage': {'prompt_tokens': 3, 'completion_tokens': 1}}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get('Content-Length') or 0)
                outer.seen.append((self.path, json.loads(self.rfile.read(n))))
                data = json.dumps(outer.reply).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.srv = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = 'http://127.0.0.1:%d/v1' % self.srv.server_address[1]

    def reset(self):
        self.seen.clear()
        self.reply.pop('content', None)
        self.reply['choices'][0] = {'message': {'content': 'OK'}, 'finish_reason': 'stop'}

    def body_last(self):
        """The JSON body of the most recent request. Fails if there was none."""
        if not self.seen:
            raise AssertionError('no request reached the endpoint')
        return self.seen[-1][1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


_EP = {}


def setUpModule():
    _EP['ep'] = _Endpoint()


def tearDownModule():
    _EP['ep'].close()


def _cfg(ep, provider='ollama', **extra):
    cfg = {'enabled': True, 'provider': provider, 'base_url': ep.base, 'model': 'qwen3.5:9b',
           'insecure_ssl': True}      # insecure_ssl is what allows the loopback peer
    cfg.update(extra)
    return cfg


class TestTheRequestBody(unittest.TestCase):
    """What goes over the wire, read from the server's side."""

    def setUp(self):
        self.ep = _EP['ep']
        self.ep.reset()

    def call(self, provider='ollama', cfg=None, **kw):
        res = ai_provider.chat(_cfg(self.ep, provider, **(cfg or {})),
                               [{'role': 'user', 'content': 'hi'}], **kw)
        self.assertTrue(self.ep.seen, 'no request reached the endpoint: %s' % res)
        return res, self.ep.seen[-1][1]

    def test_nothing_is_sent_by_default(self):
        _, body = self.call()
        self.assertNotIn('reasoning_effort', body)
        # and the rest of the request is what it was
        self.assertEqual(body['model'], 'qwen3.5:9b')
        self.assertEqual(body['options'], {'num_ctx': 16384})
        self.assertIs(body['stream'], False)

    def test_none_is_sent_as_the_string_none(self):
        """The case the report is about. Python's None is not "none": it must be the four-letter string."""
        _, body = self.call(cfg={'reasoning_effort': 'none'})
        self.assertEqual(body['reasoning_effort'], 'none')
        self.assertIsInstance(body['reasoning_effort'], str)

    def test_each_level_is_sent_as_written(self):
        for level in ('none', 'low', 'medium', 'high'):
            with self.subTest(level=level):
                _, body = self.call(cfg={'reasoning_effort': level})
                self.assertEqual(body['reasoning_effort'], level)

    def test_every_openai_compatible_provider_gets_it(self):
        for provider in ('openai', 'deepseek', 'ollama', 'localai'):
            with self.subTest(provider=provider):
                _, body = self.call(provider, cfg={'reasoning_effort': 'none'})
                self.assertEqual(body['reasoning_effort'], 'none')

    def test_a_per_call_value_beats_the_setting(self):
        _, body = self.call(cfg={'reasoning_effort': 'none'}, reasoning_effort='high')
        self.assertEqual(body['reasoning_effort'], 'high')
        _, body = self.call(reasoning_effort='low')
        self.assertEqual(body['reasoning_effort'], 'low')

    def test_blank_values_send_nothing(self):
        for value in ('', '  ', None):
            with self.subTest(value=value):
                _, body = self.call(cfg={'reasoning_effort': value})
                self.assertNotIn('reasoning_effort', body)

    def test_junk_in_a_hand_edited_config_is_not_sent(self):
        for value in ('bogus', 'xhigh', 7, ['none'], {'a': 1}):
            with self.subTest(value=value):
                _, body = self.call(cfg={'reasoning_effort': value})
                self.assertNotIn('reasoning_effort', body)

    def test_case_and_spaces_in_a_hand_edited_config_are_forgiven(self):
        _, body = self.call(cfg={'reasoning_effort': ' NONE '})
        self.assertEqual(body['reasoning_effort'], 'none')

    def test_anthropic_never_carries_it(self):
        self.ep.reply['content'] = [{'type': 'text', 'text': 'OK'}]
        _, body = self.call('anthropic', cfg={'reasoning_effort': 'none', 'api_key': 'k'},
                            reasoning_effort='high')
        self.assertNotIn('reasoning_effort', body)

    def test_opencode_and_openclaw_adapters_are_not_handed_it(self):
        """Their adapters have no such parameter: handing it over would be a TypeError on every call."""
        seen = {}
        saved = {n: getattr(ai_provider, n) for n in ('chat_opencode', 'chat_openclaw')}
        try:
            for name in saved:
                setattr(ai_provider, name, lambda *a, _n=name, **k: seen.setdefault(_n, (a, k)) and {'ok': True})
            for provider in ('opencode', 'openclaw'):
                ai_provider.chat(_cfg(self.ep, provider, reasoning_effort='none'),
                                 [{'role': 'user', 'content': 'hi'}], reasoning_effort='high')
        finally:
            for name, fn in saved.items():
                setattr(ai_provider, name, fn)
        self.assertEqual(sorted(seen), ['chat_openclaw', 'chat_opencode'])
        for name, (args, kwargs) in seen.items():
            self.assertEqual(kwargs, {}, name)
            self.assertEqual(len(args), 4, name)


class TestAnEmptyReplyIsExplained(unittest.TestCase):

    def setUp(self):
        self.ep = _EP['ep']
        self.ep.reset()

    def call(self, choice):
        self.ep.reply['choices'][0] = choice
        return ai_provider.chat(_cfg(self.ep), [{'role': 'user', 'content': 'hi'}])

    def test_empty_at_the_token_limit_is_an_error_that_names_the_setting(self):
        res = self.call({'message': {'content': '', 'reasoning': 'let me think about it'},
                         'finish_reason': 'length'})
        self.assertFalse(res['ok'])
        self.assertIn('token limit', res['error'])
        self.assertIn('Reasoning effort', res['error'])
        self.assertIn('none', res['error'])

    def test_a_missing_content_field_at_the_limit_is_the_same_error(self):
        res = self.call({'message': {'content': None}, 'finish_reason': 'length'})
        self.assertFalse(res['ok'])
        self.assertIn('Reasoning effort', res['error'])

    def test_a_partial_answer_at_the_limit_is_still_an_answer(self):
        res = self.call({'message': {'content': 'half of the'}, 'finish_reason': 'length'})
        self.assertTrue(res['ok'])
        self.assertEqual(res['text'], 'half of the')

    def test_an_empty_reply_that_ended_normally_is_left_alone(self):
        res = self.call({'message': {'content': ''}, 'finish_reason': 'stop'})
        self.assertTrue(res['ok'])
        self.assertEqual(res['text'], '')


class _Base(unittest.TestCase):
    """The real handlers, with auth and the response channel stubbed and the stores in a temp dir."""

    FILES = ('USERS_FILE', 'CONFIG_FILE', 'ROLES_FILE', 'AI_USAGE_FILE', 'DEVICES_FILE')
    STUBS = ('require_auth', 'require_admin_auth', 'require_instance_admin_auth', 'verify_token',
             'audit_log', 'fire_webhook', 'respond', 'method', 'get_json_obj', '_caller_scope')

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {a: getattr(api, a) for a in self.FILES}
        for attr, old in self._files.items():
            setattr(api, attr, self.d / Path(old).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in self.STUBS}
        api.require_auth = lambda **k: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
        api.require_instance_admin_auth = lambda what='x': 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.method = lambda: 'POST'
        api._caller_scope = lambda: None

        def _resp(s, b=None):
            self.cap['s'], self.cap['b'] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        self.ep = _EP['ep']
        self.ep.reset()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def store(self, cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)

    def stored(self):
        api._invalidate_load_cache(api.CONFIG_FILE)
        return api.load(api.CONFIG_FILE) or {}

    def post(self, handler, body):
        self.cap.clear()
        api.get_json_obj = lambda: body
        try:
            handler()
        except api.HTTPError:
            pass
        return self.cap.get('s'), self.cap.get('b')

    def ai_on(self, **extra):
        ai = {'enabled': True, 'provider': 'ollama', 'base_url': self.ep.base, 'model': 'qwen3.5:9b',
              'insecure_ssl': True,
              'context': {'include_project_context': False, 'include_fleet_context': False,
                          'include_rag': False},
              'limits': {'max_tokens_per_response': 1000, 'max_requests_per_user_day': 0}}
        ai.update(extra)
        return ai


class TestTheGlobalSetting(_Base):

    def save(self, body):
        status, _ = self.post(api.handle_ai_config_set, body)
        return status, self.stored().get('ai') or {}

    def test_it_persists_and_comes_back_on_get(self):
        status, ai = self.save({'enabled': False, 'reasoning_effort': 'none'})
        self.assertEqual((status, ai.get('reasoning_effort')), (200, 'none'))
        status, body = self.post(api.handle_ai_config_get, {})
        self.assertEqual((status, body.get('reasoning_effort')), (200, 'none'))

    def test_the_default_is_blank_and_is_offered_by_get(self):
        status, body = self.post(api.handle_ai_config_get, {})
        self.assertEqual((status, body.get('reasoning_effort')), (200, ''))

    def test_the_reader_keeps_it(self):
        """_ai_cfg() copies only the keys in _AI_DEFAULTS. A key missing there saves fine, shows on
        nothing and is never sent."""
        self.save({'enabled': False, 'reasoning_effort': 'low'})
        self.assertEqual(api._ai_cfg().get('reasoning_effort'), 'low')
        self.assertIn('reasoning_effort', api._AI_DEFAULTS)

    def test_blank_clears_it(self):
        self.save({'enabled': False, 'reasoning_effort': 'high'})
        status, ai = self.save({'enabled': False, 'reasoning_effort': ''})
        self.assertEqual((status, ai.get('reasoning_effort')), (200, ''))

    def test_a_save_that_does_not_mention_it_leaves_it_alone(self):
        """An API client that updates only the model must not wipe the level."""
        self.save({'enabled': False, 'reasoning_effort': 'none'})
        status, ai = self.save({'enabled': False, 'model': 'other:7b'})
        self.assertEqual((status, ai.get('reasoning_effort'), ai.get('model')), (200, 'none', 'other:7b'))

    def test_case_and_spaces_are_normalised_on_the_way_in(self):
        status, ai = self.save({'enabled': False, 'reasoning_effort': ' None '})
        self.assertEqual((status, ai.get('reasoning_effort')), (200, 'none'))

    def test_an_unknown_level_is_refused_and_nothing_is_saved(self):
        self.save({'enabled': False, 'reasoning_effort': 'low'})
        for bad in ('extreme', 'xhigh', '7', ['none']):
            with self.subTest(bad=bad):
                status, ai = self.save({'enabled': False, 'reasoning_effort': bad})
                self.assertEqual(status, 400)
                self.assertEqual(ai.get('reasoning_effort'), 'low')

    def test_a_bad_level_is_refused_while_the_assistant_is_off_too(self):
        status, _ = self.save({'enabled': False, 'reasoning_effort': 'extreme'})
        self.assertEqual(status, 400)

    def test_a_hand_edited_level_does_not_block_an_unrelated_save(self):
        """validate_config runs over the stored values, not just the new ones."""
        self.store({'ai': {'enabled': False, 'reasoning_effort': 'HIGH'}})
        status, ai = self.save({'enabled': False, 'model': 'm'})
        self.assertEqual(status, 200)
        self.assertEqual(ai.get('model'), 'm')

    def test_the_request_model_accepts_it(self):
        ok, err = request_models.validate(request_models.AiConfigSetRequest, {'reasoning_effort': 'none'})
        self.assertTrue(ok, err)
        ok, err = request_models.validate(request_models.AiConfigSetRequest, {'reasoning_effort': None})
        self.assertTrue(ok, err)

    def test_the_setting_reaches_the_wire_through_the_real_chat_handler(self):
        self.store({'ai': self.ai_on(reasoning_effort='none')})
        status, _ = self.post(api.handle_ai_chat, {'messages': [{'role': 'user', 'content': 'hi'}],
                                                    'system': 'explain_output'})
        self.assertEqual(status, 200)
        self.assertEqual(self.ep.body_last()['reasoning_effort'], 'none')

    def test_the_test_button_uses_it_and_so_proves_it(self):
        self.store({'ai': self.ai_on(reasoning_effort='none')})
        status, _ = self.post(api.handle_ai_test, {})
        self.assertEqual(status, 200)
        body = self.ep.body_last()
        self.assertEqual(body['reasoning_effort'], 'none')
        self.assertEqual(body['max_tokens'], 8)

    def test_the_insight_helper_follows_the_global_setting(self):
        self.store({'ai': self.ai_on(reasoning_effort='low')})
        try:
            api._ai_run('jakob', 'sys', [{'role': 'user', 'content': 'hi'}], 'anomaly')
        except api.HTTPError:
            pass
        self.assertEqual(self.ep.body_last()['reasoning_effort'], 'low')


class TestFineTuning(_Base):
    """A prompt's own value, stored at the top of the config under ai_param_overrides."""

    def save(self, body):
        return self.post(api.handle_ai_params_save, body)

    def overrides(self):
        return self.stored().get('ai_param_overrides') or {}

    def test_it_persists_for_one_prompt_and_nothing_else(self):
        status, _ = self.save({'key': 'alert_triage', 'reasoning_effort': 'none'})
        self.assertEqual(status, 200)
        self.assertEqual(self.overrides()['alert_triage'], {'reasoning_effort': 'none'})
        self.assertEqual(api._resolve_ai_params('alert_triage')['reasoning_effort'], 'none')
        self.assertIsNone(api._resolve_ai_params('mitigate_service')['reasoning_effort'])

    def test_it_sits_beside_the_other_four(self):
        self.save({'key': 'alert_triage', 'reasoning_effort': 'low', 'temperature': 0.2, 'top_p': 0.9,
                   'max_tokens': 900, 'num_ctx': 8192})
        self.assertEqual(self.overrides()['alert_triage'],
                         {'temperature': 0.2, 'top_p': 0.9, 'max_tokens': 900, 'num_ctx': 8192,
                          'reasoning_effort': 'low'})

    def test_blank_or_null_follows_the_global_setting_again(self):
        self.save({'key': 'alert_triage', 'reasoning_effort': 'high', 'temperature': 0.5})
        for blank in ('', None):
            with self.subTest(blank=blank):
                self.save({'key': 'alert_triage', 'reasoning_effort': blank, 'temperature': 0.5})
                self.assertNotIn('reasoning_effort', self.overrides()['alert_triage'])
                self.assertIsNone(api._resolve_ai_params('alert_triage')['reasoning_effort'])

    def test_an_unknown_level_is_refused(self):
        status, body = self.save({'key': 'alert_triage', 'reasoning_effort': 'extreme'})
        self.assertEqual(status, 400)
        self.assertEqual(body['error'], 'reasoning_effort must be none, low, medium or high')
        self.assertNotIn('alert_triage', self.overrides())

    def test_get_lists_it_for_every_prompt(self):
        self.save({'key': 'alert_triage', 'reasoning_effort': 'none'})
        status, body = self.post(api.handle_ai_params_get, {})
        self.assertEqual(status, 200)
        rows = {r['key']: r for r in body['params']}
        self.assertEqual(rows['alert_triage']['reasoning_effort'], 'none')
        self.assertIsNone(rows['generate_runbook']['reasoning_effort'])
        self.assertGreater(len(rows), 60)

    def test_the_reader_drops_a_hand_edited_junk_level(self):
        self.store({'ai_param_overrides': {'alert_triage': {'reasoning_effort': 'bogus'}}})
        self.assertIsNone(api._resolve_ai_params('alert_triage')['reasoning_effort'])
        self.store({'ai_param_overrides': {'alert_triage': {'reasoning_effort': ' Low '}}})
        self.assertEqual(api._resolve_ai_params('alert_triage')['reasoning_effort'], 'low')

    def test_the_request_model_accepts_it(self):
        ok, err = request_models.validate(request_models.AiParamsSaveRequest,
                                          {'key': 'x', 'reasoning_effort': None})
        self.assertTrue(ok, err)

    def test_a_prompt_value_beats_the_global_one_on_the_wire(self):
        self.store({'ai': self.ai_on(reasoning_effort='none'),
                    'ai_param_overrides': {'explain_output': {'reasoning_effort': 'high'}}})
        self.post(api.handle_ai_chat, {'messages': [{'role': 'user', 'content': 'hi'}],
                                       'system': 'explain_output'})
        self.assertEqual(self.ep.body_last()['reasoning_effort'], 'high')

    def test_the_chat_route_forwards_a_prompt_value_and_its_other_tuning(self):
        self.store({'ai': self.ai_on(),
                    'ai_param_overrides': {'explain_output': {'reasoning_effort': 'none', 'max_tokens': 77,
                                                              'temperature': 0.3, 'num_ctx': 4096}}})
        self.post(api.handle_ai_chat, {'messages': [{'role': 'user', 'content': 'hi'}],
                                       'system': 'explain_output'})
        body = self.ep.body_last()
        self.assertEqual((body['reasoning_effort'], body['max_tokens'], body['temperature']),
                         ('none', 77, 0.3))
        self.assertEqual(body['options'], {'num_ctx': 4096})


class TestTheRouteTheReporterHit(_Base):
    """Mitigate, alert triage, the log sweep and the AI exec proposal all go through
    _call_ai_with_prompts. It read ai_param_overrides from cfg['ai'], and handle_ai_params_save
    writes it at the top of the config, so none of the five Fine-tuning fields ever reached them.
    This test uses only the four that existed before 7.4.1, so it fails on the old code by assertion."""

    def test_a_fine_tuning_row_reaches_the_request(self):
        self.store({'ai': self.ai_on(),
                    'ai_param_overrides': {'alert_triage': {'max_tokens': 321, 'temperature': 0.1,
                                                            'top_p': 0.5, 'num_ctx': 2048}}})
        res = api._call_ai_with_prompts('system text', 'user text', 'alert_triage')
        self.assertTrue(res['ok'], res)
        body = self.ep.body_last()
        self.assertEqual(body['max_tokens'], 321, 'the Fine-tuning max_tokens was ignored')
        self.assertEqual(body['temperature'], 0.1)
        self.assertEqual(body['top_p'], 0.5)
        self.assertEqual(body['options'], {'num_ctx': 2048})

    def test_without_a_row_the_old_defaults_stand(self):
        self.store({'ai': self.ai_on()})
        api._call_ai_with_prompts('system text', 'user text', 'alert_triage')
        body = self.ep.body_last()
        self.assertEqual(body['max_tokens'], 4000)
        self.assertNotIn('temperature', body)
        self.assertEqual(body['options'], {'num_ctx': 16384})

    def test_every_prompt_that_uses_it_follows_the_rows(self):
        """The four keys the callers pass, as the handlers choose them (mitigate keys come from the
        playbook table)."""
        keys = ['alert_triage', 'log_sweep_rca'] + sorted(
            {pb.get('ai_prompt_key') for pb in api._MITIGATE_PLAYBOOKS.values() if pb.get('ai_prompt_key')})
        self.assertGreater(len(keys), 10, keys)
        for key in keys:
            with self.subTest(prompt=key):
                self.store({'ai': self.ai_on(), 'ai_param_overrides': {key: {'max_tokens': 222}}})
                api._call_ai_with_prompts('s', 'u', key)
                self.assertEqual(self.ep.body_last()['max_tokens'], 222)

    def test_the_level_reaches_the_wire_for_the_reporters_prompt(self):
        """The report: Ollama, a thinking model, a real alert. One prompt's row set to none ends it."""
        self.store({'ai': self.ai_on(),
                    'ai_param_overrides': {'alert_triage': {'reasoning_effort': 'none'}}})
        api._call_ai_with_prompts('system text', 'user text', 'alert_triage')
        self.assertEqual(self.ep.body_last()['reasoning_effort'], 'none')
        api._call_ai_with_prompts('system text', 'user text', 'mitigate_service')
        self.assertNotIn('reasoning_effort', self.ep.body_last())

    def test_the_global_level_reaches_it_too(self):
        self.store({'ai': self.ai_on(reasoning_effort='none')})
        api._call_ai_with_prompts('system text', 'user text', 'mitigate_service')
        self.assertEqual(self.ep.body_last()['reasoning_effort'], 'none')

    def test_the_anthropic_branch_takes_the_rows_and_no_level(self):
        seen = {}
        saved = ai_provider.chat_anthropic

        def fake(cfg, messages, system, max_tokens, temperature=None, top_p=None):
            seen.update(max_tokens=max_tokens, temperature=temperature, top_p=top_p)
            return {'ok': True, 'text': 'x'}
        ai_provider.chat_anthropic = fake
        try:
            self.store({'ai': self.ai_on(provider='anthropic', api_key='k', reasoning_effort='none'),
                        'ai_param_overrides': {'alert_triage': {'max_tokens': 500, 'temperature': 0.4,
                                                                'reasoning_effort': 'high'}}})
            api._call_ai_with_prompts('s', 'u', 'alert_triage')
        finally:
            ai_provider.chat_anthropic = saved
        self.assertEqual(seen, {'max_tokens': 500, 'temperature': 0.4, 'top_p': None})


@functools.lru_cache(maxsize=None)
def _functions():
    """{function name: [(file, source)]} for every def in server/cgi-bin, parsed once."""
    out = {}
    for path in sorted(_CGI.glob('*.py')):
        text = path.read_text()
        lines = text.splitlines()
        for n in ast.walk(ast.parse(text)):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.setdefault(n.name, []).append((path.name, '\n'.join(lines[n.lineno - 1:n.end_lineno])))
    return out


@functools.lru_cache(maxsize=None)
def _provider_callers():
    """{function name: files} for every function that calls an adapter of ai_provider."""
    out = {}

    class V(ast.NodeVisitor):
        def __init__(self, fname):
            self.fname, self.stack = fname, []

        def visit_FunctionDef(self, n):
            self.stack.append(n.name)
            self.generic_visit(n)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, n):
            f = n.func
            if (isinstance(f, ast.Attribute) and f.attr in ('chat', 'chat_openai_compatible', 'chat_anthropic')
                    and ast.unparse(f.value).endswith('ai_provider') and self.stack):
                out.setdefault(self.stack[-1], set()).add(self.fname)
            self.generic_visit(n)

    for path in sorted(_CGI.glob('*.py')):
        V(path.name).visit(ast.parse(path.read_text()))
    return {k: frozenset(v) for k, v in out.items()}


class TestEveryRouteIntoTheProvider(unittest.TestCase):
    """A rule written down and applied in most places: count the places. Every function that calls an
    adapter is either one that forwards the per-prompt overrides, the shared wrapper that reads them
    itself, or one that follows the global setting only, and is listed with the reason."""

    FORWARDS = {'handle_ai_chat', 'handle_runbook_generate', 'handle_iac_generate', '_build_report_summary'}
    WRAPPER = {'_call_ai_with_prompts'}
    GLOBAL_ONLY = {
        '_ai_run': "Runs the four on-demand insight features (runbook text, doc draft, cron builder, "
                   "anomaly). None of them is a prompt key on the Fine-tuning list.",
        'handle_ai_test': "The Test connection button: one fixed eight-token request that has no prompt "
                          "of its own, and so shows what the global setting does.",
    }

    @staticmethod
    def source_of(_unused, func):
        defs = _functions().get(func)
        if not defs:
            raise AssertionError('no function named %s' % func)
        return '\n'.join(src for _, src in defs)

    def test_the_population_is_the_listed_one(self):
        found = _provider_callers()
        expected = self.FORWARDS | self.WRAPPER | set(self.GLOBAL_ONLY)
        self.assertEqual(set(found), expected,
                         'a function now calls the AI provider that is not in this census (or one left): '
                         'decide whether it forwards the per-prompt overrides or follows the global '
                         'setting only, and list it. %d routes: %s' % (len(found), sorted(found)))
        self.assertGreaterEqual(len(found), 7)

    def test_each_forwarder_loops_over_the_one_shared_tuple(self):
        for name in sorted(self.FORWARDS):
            with self.subTest(route=name):
                src = self.source_of(None, name)
                self.assertIn('_AI_FORWARDED_PARAMS', src)
                self.assertIn('_resolve_ai_params', src)
                self.assertNotRegex(src, r"for _p in \('temperature'",
                                    'a private copy of the list of forwarded fields: the next field '
                                    'added to the tuple would miss this route')

    def test_the_wrapper_reads_the_overrides_the_way_they_are_saved(self):
        src = self.source_of(None, '_call_ai_with_prompts')
        self.assertIn('_resolve_ai_params(prompt_key)', src)
        self.assertIn('reasoning_effort', src)
        self.assertNotIn("ai_cfg.get('ai_param_overrides')", src)

    def test_the_global_only_routes_do_not_read_the_per_prompt_rows(self):
        for name in sorted(self.GLOBAL_ONLY):
            with self.subTest(route=name):
                self.assertNotIn('_resolve_ai_params', self.source_of(None, name),
                                 '%s now reads per-prompt rows: move it out of GLOBAL_ONLY' % name)

    def test_the_overrides_are_read_in_one_place_only(self):
        """The wrapper's bug was a second reader that looked in the wrong dict."""
        homes = {name: files for name, files in
                 ((n, [f for f, src in defs if re.search(r"""['"]ai_param_overrides['"]""", src)])
                  for n, defs in _functions().items()) if files}
        self.assertEqual(sorted(homes), ['_resolve_ai_params', 'handle_ai_params_get', 'handle_ai_params_save'],
                         homes)

    def test_the_forwarded_fields_are_the_fields_the_reader_returns(self):
        reader = set(api._resolve_ai_params('no_such_prompt'))
        self.assertEqual(set(api._AI_FORWARDED_PARAMS) | {'max_tokens'}, reader,
                         'a field the reader returns that no route forwards (or the reverse)')


class TestTheScreens(unittest.TestCase):

    def test_the_setting_is_in_settings_and_hidden_for_the_other_providers(self):
        self.assertEqual(HTML.count('id="ai-reasoning-effort"'), 1)
        m = re.search(r'<select id="ai-reasoning-effort"[^>]*>(.*?)</select>', HTML, re.S)
        values = re.findall(r'<option value="([^"]*)"', m.group(1))
        self.assertEqual(values, ['', 'none', 'low', 'medium', 'high'])
        self.assertEqual(tuple(v for v in values if v), ai_provider.REASONING_EFFORTS)
        self.assertRegex(HTML, r'<div id="ai-reasoning-row" class="d-none">')
        self.assertRegex(APP_AI, r"\['openai', 'deepseek', 'ollama', 'localai'\]\.includes\(provider\)")

    def test_the_settings_page_reads_and_writes_it(self):
        self.assertIn("document.getElementById('ai-reasoning-effort').value = cfg.reasoning_effort || ''", APP_AI)
        self.assertIn("reasoning_effort: document.getElementById('ai-reasoning-effort').value", APP_AI)

    def test_a_prompts_fine_tuning_has_the_select_and_sends_null_for_blank(self):
        self.assertIn('data-field="reasoning-effort"', APP_AI)
        self.assertIn("reasoning_effort: _v('[data-field=\"reasoning-effort\"]')", APP_AI)
        self.assertIn('|| !!params.reasoning_effort', APP_AI)       # a set value opens the Fine-tuning box
        m = re.search(r'data-field="reasoning-effort">(.*?)</select>', APP_AI, re.S)
        self.assertEqual(re.findall(r'<option value="([^"]*)"', m.group(1)), ['', 'none', 'low', 'medium', 'high'])

    def test_every_new_label_is_translated_into_all_six_languages(self):
        keys = ['Reasoning effort', 'Provider default (nothing is sent)', 'None (turn thinking off)',
                'Reasoning effort (OpenAI-compatible)', 'Use the global setting',
                'Fine-tuning (temperature, top_p, tokens, context, reasoning)',
                'reasoning_effort must be none, low, medium or high']
        hint = re.search(r'<div class="meta-sm">(Sent as reasoning_effort[^<]*)</div>', HTML)
        self.assertTrue(hint, 'the hint is missing from the Settings page')
        keys.append(hint.group(1))
        for key in keys:
            with self.subTest(key=key[:40]):
                i = I18N.find('"%s"' % key)
                self.assertGreater(i, 0, 'no dictionary entry')
                entry = I18N[i:I18N.index('},', i)]
                for lang in LANGS:
                    self.assertRegex(entry, r'"%s"\s*:' % lang, '%s missing %s' % (key[:24], lang))

    def test_the_old_summary_text_is_gone_from_both_places(self):
        self.assertNotIn('Fine-tuning (temperature, top_p, tokens, context)', APP_AI)
        self.assertNotIn('"Fine-tuning (temperature, top_p, tokens, context)"', I18N)

    def test_the_docs_say_how(self):
        doc = (ROOT / 'docs/ai.md').read_text()
        self.assertIn('Reasoning effort', doc)
        self.assertIn('reasoning_effort: "none"', doc)
        self.assertIn('/no_think', doc)


if __name__ == '__main__':
    unittest.main()
