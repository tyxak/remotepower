"""v3.0.4 release tests — strict version pins live here.

v3.0.4 is a bug-fix release. Five real production bugs:

  1. AI chat 500 — `cfg.get('insecure_ssl')` referenced an unbound
     name inside `_http_post_json`. Latent in v3.0.2; only triggers
     the first time the OpenAI-compat chat path runs.

  2. Monitor page row showed "OK" while /api/attention surfaced a
     swap warning on the same host. `handle_devices_list` curated
     fields and dropped `metric_state`; the JS row aggregator
     iterated an empty dict.

  3. The 🩺 Investigate button was missing on memory/swap/cpu
     alerts. The AI prompt keys existed since v3.0.1, but the
     `_MITIGATE_PLAYBOOKS` dict only carried patches/disk/drift/
     service_down/reboot/brute_force.

  4. The device-drawer "Save settings" button posted the bundle to
     `POST /api/devices/<id>` which had no server-side handler;
     fell through to a 404. New `handle_device_save_bulk` fixes it
     atomically.

  5. `_call_ai_with_prompts` passed arguments to
     chat_openai_compatible in the wrong order — `messages` was a
     string, payload_messages.extend(messages) iterated character
     by character, the provider rejected the array, and the AI
     mitigation re-run returned 200 OK with every field blank.

Plus the v3.1.0 Stage 1 scaffolding (role constants + audit shape
+ per-device require_confirmation + bulk-save dispatcher) lands as
silent infra — not exercised yet. Stage 1 tests are in
test_v310.py and pin to no specific version.
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))


def _clear_env(*names):
    for n in names:
        os.environ.pop(n, None)


class _ApiTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_v304_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        for mod in ('api',):
            if mod in sys.modules:
                del sys.modules[mod]
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        _clear_env('RP_DATA_DIR')

    def _seed_admin_session(self, username='admin'):
        users = self.api.load(self.api.USERS_FILE)
        users[username] = {
            'password_hash': self.api.hash_password('x'),
            'role': 'admin',
        }
        self.api.save(self.api.USERS_FILE, users)
        token = 'admin-tok-' + os.urandom(8).hex()
        tokens = self.api.load(self.api.TOKENS_FILE)
        tokens[token] = {'user': username, 'created': int(time.time()),
                          'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, tokens)
        os.environ['HTTP_X_TOKEN'] = token
        return token


# ─── Version pins (strict — this is the live v3.0.4 release) ────────────────

class TestVersionBumps(unittest.TestCase):
    EXPECTED = '3.0.4'

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
        text = path.read_text()
        self.assertIn(self.EXPECTED, text)


class TestCallAiWithPromptsArgumentShape(unittest.TestCase):
    """v3.0.4 regression: _call_ai_with_prompts in api.py was calling
    chat_openai_compatible with the wrong argument order. Result: messages
    was a string (not a list of {role, content} dicts), the provider's
    payload_messages.extend(messages) iterated the string char-by-char,
    Ollama rejected the malformed array, and the function returned 200 OK
    with every field blank.

    This test intercepts the provider call and asserts the arguments
    arrive in the right shape: messages must be a list of dicts, system
    must be a string, max_tokens must be numeric.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_v304_ai_args_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        for mod in ('api', 'ai_provider'):
            if mod in sys.modules:
                del sys.modules[mod]
        import api, ai_provider
        cls.api = api
        cls.ai_provider = ai_provider

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        _clear_env('RP_DATA_DIR')

    def setUp(self):
        # Seed an Ollama-shaped config so the OpenAI-compat path is taken
        self.api.save(self.api.CONFIG_FILE, {
            'ai': {
                'enabled': True,
                'provider': 'ollama',
                'base_url': 'http://test/v1',
                'model': 'devstral:24b',
                'api_key': '',
            }
        })

    def test_openai_compatible_receives_proper_messages_list(self):
        captured = {}

        def fake_openai_compat(cfg, messages, system, max_tokens, **kwargs):
            captured['cfg']        = cfg
            captured['messages']   = messages
            captured['system']     = system
            captured['max_tokens'] = max_tokens
            captured['kwargs']     = kwargs
            return {'ok': True, 'text': 'fake response', 'model': 'x',
                     'tokens_in': 0, 'tokens_out': 0}

        original = self.ai_provider.chat_openai_compatible
        self.ai_provider.chat_openai_compatible = fake_openai_compat
        try:
            result = self.api._call_ai_with_prompts(
                system_prompt='SYSTEM: be helpful',
                user_prompt='diagnose: swap is full',
                prompt_key='mitigate_memory',
            )
        finally:
            self.ai_provider.chat_openai_compatible = original

        # The bug: messages used to be the system_prompt STRING.
        # Correct: a list with a single user-role dict.
        self.assertIsInstance(captured['messages'], list,
            f"messages must be a list (got {type(captured['messages']).__name__}). "
            f"Without this, ai_provider.payload_messages.extend(messages) "
            f"iterates char-by-char and the AI returns nothing.")
        self.assertEqual(len(captured['messages']), 1)
        self.assertEqual(captured['messages'][0]['role'], 'user')
        self.assertEqual(captured['messages'][0]['content'], 'diagnose: swap is full')

        # The bug: system used to be the user_prompt
        self.assertEqual(captured['system'], 'SYSTEM: be helpful')

        # The bug: max_tokens used to be the overrides DICT
        self.assertIsInstance(captured['max_tokens'], (int, float),
            f"max_tokens must be numeric (got {type(captured['max_tokens']).__name__}). "
            f"Previously the overrides dict landed here.")

        # And the helper must propagate the ok/text result, not swallow it
        self.assertTrue(result.get('ok'))
        self.assertEqual(result.get('text'), 'fake response')

    def test_provider_failure_surfaces_to_caller(self):
        """When the provider returns {ok: False, error: ...} the helper must
        propagate that — handle_mitigate_ai checks ok and 502s the operator
        rather than 200-with-empty-fields."""
        def fake_openai_compat(cfg, messages, system, max_tokens, **kwargs):
            return {'ok': False, 'error': 'simulated provider failure'}

        original = self.ai_provider.chat_openai_compatible
        self.ai_provider.chat_openai_compatible = fake_openai_compat
        try:
            result = self.api._call_ai_with_prompts(
                'sys', 'usr', 'mitigate_memory')
        finally:
            self.ai_provider.chat_openai_compatible = original

        self.assertFalse(result.get('ok'))
        self.assertIn('simulated', result.get('error', ''))





# ──────────────────────────────────────────────────────────────────────────

class TestAiProviderHttpPostJson(unittest.TestCase):
    """Regression: v3.0.2 introduced `if cfg.get('insecure_ssl'):` inside
    _http_post_json which had no `cfg` parameter. The reference resolved
    against the module-global `cfg` (none such → NameError) on every
    invocation, returning a 500 on the first real /api/ai/chat call.
    Fix: pass insecure_ssl explicitly. This test guards the signature."""

    def setUp(self):
        # Ensure a clean import so the module's current source is loaded
        if 'ai_provider' in sys.modules:
            del sys.modules['ai_provider']
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        import ai_provider
        self.ai_provider = ai_provider

    def test_http_post_json_accepts_insecure_ssl_param(self):
        """Signature must accept insecure_ssl — covers both the explicit
        kwarg and the default-False semantics."""
        import inspect
        sig = inspect.signature(self.ai_provider._http_post_json)
        self.assertIn('insecure_ssl', sig.parameters,
            '_http_post_json must accept insecure_ssl after the v3.0.2 bug')
        self.assertEqual(sig.parameters['insecure_ssl'].default, False,
            'insecure_ssl must default to False (strict) — opt-in only')

    def test_http_post_json_no_unbound_cfg_reference(self):
        """The function body must not reference a bare `cfg` name. AST-level
        check catches the regression without needing to actually make an
        HTTP call."""
        import ast
        src = (REPO_ROOT / 'server' / 'cgi-bin' / 'ai_provider.py').read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == '_http_post_json':
                params = {a.arg for a in node.args.args} | {
                    kw.arg for kw in node.args.kwonlyargs}
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Name) and inner.id == 'cfg':
                        if 'cfg' not in params:
                            self.fail(
                                f'_http_post_json references unbound `cfg` at '
                                f'line {inner.lineno}. The v3.0.2 NameError bug '
                                f'is back — pass insecure_ssl as an explicit '
                                f'parameter instead.')
                return
        self.fail('_http_post_json not found in ai_provider.py')

    def test_chat_openai_compatible_passes_insecure_ssl(self):
        """The caller chat_openai_compatible() must forward cfg['insecure_ssl']
        explicitly. This test inspects the source to verify the
        forwarding survives a future refactor."""
        src = (REPO_ROOT / 'server' / 'cgi-bin' / 'ai_provider.py').read_text()
        # Find the body of chat_openai_compatible and check that any
        # _http_post_json call inside it passes insecure_ssl.
        import ast
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == 'chat_openai_compatible'):
                for inner in ast.walk(node):
                    if (isinstance(inner, ast.Call)
                            and isinstance(inner.func, ast.Name)
                            and inner.func.id == '_http_post_json'):
                        kwarg_names = {kw.arg for kw in inner.keywords}
                        self.assertIn(
                            'insecure_ssl', kwarg_names,
                            'chat_openai_compatible must forward '
                            'cfg["insecure_ssl"] to _http_post_json')
                        return
        self.fail('chat_openai_compatible or its _http_post_json call not found')





# ──────────────────────────────────────────────────────────────────────────

class TestDevicesListIncludesMetricState(_ApiTestBase):
    """v3.0.4 fix: /api/devices must include metric_state per device.

    Without this, the Monitor page row aggregator iterates an empty dict
    for every device and shows "OK" even when /api/attention is correctly
    surfacing a swap/memory/cpu warning on the same host. The dashboard
    contradicting itself was the user-visible symptom.
    """

    def setUp(self):
        self._seed_admin_session('admin')
        self.api.save(self.api.DEVICES_FILE, {
            'd-warn': {
                'name': 'pmg01.tvipper.com',
                'monitored': True,
                'last_seen': int(time.time()),
                'token': 'devtok',
                'metric_state': {'swap:': 'warning'},
            },
            'd-ok': {
                'name': 'clean-box',
                'monitored': True,
                'last_seen': int(time.time()),
                'token': 'devtok2',
                'metric_state': {},
            },
        })

    def tearDown(self):
        _clear_env('HTTP_X_TOKEN', 'REQUEST_METHOD')

    def test_metric_state_present_for_each_device(self):
        os.environ['REQUEST_METHOD'] = 'GET'
        try:
            self.api.handle_devices_list()
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
            for d in e.body:
                self.assertIn('metric_state', d,
                    f'/api/devices must include metric_state '
                    f'(missing on device {d.get("name")!r}). '
                    f'Without it the Monitor page row aggregator '
                    f'always shows "OK".')

    def test_swap_warning_round_trips_to_response(self):
        os.environ['REQUEST_METHOD'] = 'GET'
        try:
            self.api.handle_devices_list()
        except self.api.HTTPError as e:
            warn_dev = next(d for d in e.body if d['name'] == 'pmg01.tvipper.com')
            self.assertEqual(warn_dev['metric_state'], {'swap:': 'warning'},
                'metric_state with a swap warning must arrive at the client '
                'verbatim — the row aggregator depends on it')





# ──────────────────────────────────────────────────────────────────────────

class TestMitigationPlaybooksCoverage(unittest.TestCase):
    """v3.0.4 fix: the metric playbooks (memory/swap/cpu) were missing.
    The prompt keys (mitigate_memory, mitigate_cpu) existed in
    ai_provider.SYSTEM_PROMPTS since v3.0.1, but _MITIGATE_PLAYBOOKS
    only carried patches/disk/drift/service_down/reboot/brute_force.
    Result: the alert fired, Needs Attention showed the entry, but no
    🩺 Investigate button rendered because the kind wasn't in the
    playbook set.
    """

    @classmethod
    def setUpClass(cls):
        # Need a real api import; reuse the same tmpdir mechanism
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_v310_mit_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        for mod in ('api',):
            if mod in sys.modules:
                del sys.modules[mod]
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        _clear_env('RP_DATA_DIR')

    def test_memory_swap_cpu_playbooks_registered(self):
        for kind in ('memory', 'swap', 'cpu'):
            self.assertIn(kind, self.api._MITIGATE_PLAYBOOKS,
                f"v3.0.4: '{kind}' alert needs a playbook so the 🩺 "
                f"Investigate button renders in Needs Attention. Without "
                f"it the operator gets a metric warning with no mitigation "
                f"path.")

    def test_playbook_prompt_keys_exist(self):
        """Each playbook's ai_prompt_key must reference a real prompt in
        ai_provider.SYSTEM_PROMPTS — otherwise the AI step silently uses
        the empty fallback."""
        import ai_provider
        for kind, playbook in self.api._MITIGATE_PLAYBOOKS.items():
            key = playbook.get('ai_prompt_key')
            if key is None:
                continue
            self.assertIn(key, ai_provider.SYSTEM_PROMPTS,
                f"playbook '{kind}' references prompt key '{key}' but "
                f"that key doesn't exist in ai_provider.SYSTEM_PROMPTS")

    def test_playbook_diagnostics_are_non_destructive(self):
        """Memory/swap/cpu diagnostics must be read-only (no rm, kill,
        systemctl mutations etc.). Mitigation runners need operator
        sign-off before destructive steps; the diagnostic itself runs
        immediately and must never alter state."""
        forbidden = (' rm ', 'kill ', 'systemctl restart', 'systemctl stop',
                     'systemctl start', 'shutdown', 'reboot', '>/dev/sda',
                     'mkfs', 'dd if=', 'iptables -A', 'iptables -F')
        for kind in ('memory', 'swap', 'cpu'):
            diag = self.api._MITIGATE_PLAYBOOKS[kind].get('diagnostic', '')
            self.assertEqual(self.api._MITIGATE_PLAYBOOKS[kind].get('destructive'),
                              False,
                              f"playbook '{kind}' must be marked non-destructive")
            for bad in forbidden:
                self.assertNotIn(bad, diag,
                    f"playbook '{kind}' diagnostic contains potentially "
                    f"destructive token {bad!r}")

    def test_js_and_python_mitigation_kinds_agree(self):
        """The client's MITIGATE_KINDS set and the server's _MITIGATE_PLAYBOOKS
        keys are two sources of truth for the same fact. When they drift,
        the symptom is what Jakob hit: the server adds a playbook, the
        🩺 button renders, the click handler refuses with "No mitigation
        playbook for <kind> yet" because the client list never grew.

        Until we refactor to a single source (a /api/mitigate/kinds
        endpoint the client fetches on startup), this static check is
        the cheapest way to catch the drift at build time."""
        import re
        js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
              ).read_text()
        m = re.search(
            r'const MITIGATE_KINDS\s*=\s*new Set\(\[(.*?)\]\)',
            js, re.DOTALL)
        self.assertIsNotNone(m,
            'MITIGATE_KINDS constant missing or restructured in app.js — '
            'this regression check needs updating')
        js_kinds = set(re.findall(r"'([a-z_]+)'", m.group(1)))
        py_kinds = set(self.api._MITIGATE_PLAYBOOKS.keys())
        missing_in_js  = py_kinds - js_kinds
        missing_in_py  = js_kinds - py_kinds
        self.assertEqual(missing_in_js, set(),
            f"server has playbooks the client doesn't know about: "
            f"{sorted(missing_in_js)}. The 🩺 button renders but the "
            f"click handler will toast 'No mitigation playbook for ...' "
            f"and refuse. Add these to MITIGATE_KINDS + "
            f"_MITIGATE_KIND_LABELS in app.js.")
        self.assertEqual(missing_in_py, set(),
            f"client claims playbooks the server doesn't have: "
            f"{sorted(missing_in_py)}. The 🩺 button works in the UI "
            f"but the server-side investigate handler will fail.")

    def test_each_js_kind_has_a_label(self):
        """MITIGATE_KINDS and _MITIGATE_KIND_LABELS in app.js are two
        separate lists that must agree. Without a label the modal title
        renders as the raw kind string ("Investigate: swap")."""
        import re
        js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
              ).read_text()
        m_set = re.search(
            r'const MITIGATE_KINDS\s*=\s*new Set\(\[(.*?)\]\)',
            js, re.DOTALL)
        m_lbl = re.search(
            r'const _MITIGATE_KIND_LABELS\s*=\s*\{(.*?)\};',
            js, re.DOTALL)
        self.assertIsNotNone(m_set)
        self.assertIsNotNone(m_lbl)
        kinds = set(re.findall(r"'([a-z_]+)'", m_set.group(1)))
        labels = set(re.findall(
            r"^\s*([a-z_]+)\s*:", m_lbl.group(1), re.MULTILINE))
        self.assertEqual(kinds, labels,
            f"MITIGATE_KINDS and _MITIGATE_KIND_LABELS in app.js have "
            f"drifted. Symmetric difference: "
            f"{sorted(kinds.symmetric_difference(labels))}")





# ──────────────────────────────────────────────────────────────────────────

class TestDeviceSaveBulk(_ApiTestBase):
    """v3.0.4: POST /api/devices/<id> with a settings bundle from the
    drawer's Save button. Before this handler existed, the route fell
    through to the catch-all 404. Per-field PATCH endpoints continue
    to exist and work; this is purely additive.
    """

    def setUp(self):
        self._seed_admin_session('admin')
        self.api.save(self.api.DEVICES_FILE, {
            'd-1': {
                'name': 'web-01',
                'monitored': True,
                'group': 'web',
                'last_seen': int(time.time()),
                'token': 'devtok',
            },
        })

    def tearDown(self):
        _clear_env('HTTP_X_TOKEN', 'REQUEST_METHOD', 'CONTENT_LENGTH')

    def _post(self, dev_id, body_dict):
        os.environ['REQUEST_METHOD'] = 'POST'
        body = json.dumps(body_dict).encode()
        os.environ['CONTENT_LENGTH'] = str(len(body))

        class _StdinShim:
            buffer = io.BytesIO(body)

        old_stdin = sys.stdin
        sys.stdin = _StdinShim()
        try:
            self.api.handle_device_save_bulk(dev_id)
        finally:
            sys.stdin = old_stdin

    def test_full_bundle_saves(self):
        """The exact payload shape the drawer sends."""
        try:
            self._post('d-1', {
                'group': 'apt',
                'tags': ['workstations'],
                'icon': '',
                'monitored': True,
                'poll_interval': 60,
                'watched_services': [],
                'log_watch': [],
                'watched_files': [],
                'cmd_allowlist': [],
            })
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200,
                f'expected 200, got {e.status}: {e.body}')
            self.assertTrue(e.body['ok'])
            # `updated` lists exactly the fields the handler touched
            self.assertIn('group', e.body['updated'])

        d = self.api.load(self.api.DEVICES_FILE)['d-1']
        self.assertEqual(d['group'], 'apt')
        self.assertEqual(d['tags'], ['workstations'])
        self.assertEqual(d['poll_interval'], 60)

    def test_unknown_field_ignored(self):
        """Body may contain extra keys (e.g. from a newer client); the
        handler silently ignores anything it doesn't recognise rather
        than 400-ing — keeps the client/server upgrade order flexible."""
        try:
            self._post('d-1', {
                'group': 'newgroup',
                'wat_is_dit': 'mystery',     # not in the field set
            })
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
        d = self.api.load(self.api.DEVICES_FILE)['d-1']
        self.assertEqual(d['group'], 'newgroup')
        self.assertNotIn('wat_is_dit', d)

    def test_empty_body_returns_400(self):
        """No recognised fields is a client error — saves nothing,
        emits a clear error rather than silently doing nothing."""
        try:
            self._post('d-1', {})
            self.fail('expected 400 on empty body')
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 400)
            self.assertIn('no recognised', e.body['error'].lower())

    def test_unknown_device_returns_404(self):
        try:
            self._post('does-not-exist', {'group': 'x'})
            self.fail('expected 404')
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 404)

    def test_cmd_allowlist_writes_canonical_field(self):
        """Client sends `cmd_allowlist`, but the enforcement code reads
        `allowed_commands`. The bulk handler must write the canonical
        name; otherwise the operator saves an allowlist that the
        executor never consults."""
        try:
            self._post('d-1', {'cmd_allowlist': ['systemctl status nginx', 'uptime']})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
        d = self.api.load(self.api.DEVICES_FILE)['d-1']
        self.assertEqual(d['allowed_commands'],
                          ['systemctl status nginx', 'uptime'],
            'cmd_allowlist (client) must land in allowed_commands (server) '
            'since that is the field _check_exec_allowlist() reads')

    def test_watched_services_writes_canonical_field(self):
        """services_watched is the storage name; watched_services is the
        client-side name. Mirror it on save."""
        try:
            self._post('d-1', {'watched_services': ['nginx', 'sshd']})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
        d = self.api.load(self.api.DEVICES_FILE)['d-1']
        self.assertEqual(d['services_watched'], ['nginx', 'sshd'])

    def test_log_watch_filters_invalid_entries(self):
        try:
            self._post('d-1', {'log_watch': [
                {'unit': 'sshd', 'pattern': 'Failed password'},
                {'unit': '', 'pattern': 'x'},      # empty unit dropped
                {'unit': 'good', 'pattern': ''},   # empty pattern dropped
                'not a dict',                       # non-dict dropped
            ]})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
        d = self.api.load(self.api.DEVICES_FILE)['d-1']
        self.assertEqual(d['log_watch'],
                          [{'unit': 'sshd', 'pattern': 'Failed password'}])

    def test_watched_files_requires_absolute_paths(self):
        try:
            self._post('d-1', {'watched_files': [
                '/etc/hosts',
                'relative/path',    # dropped — not absolute
                '/etc/nginx/conf.d/site.conf',
            ]})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
        d = self.api.load(self.api.DEVICES_FILE)['d-1']
        self.assertEqual(d['watched_files'],
                          ['/etc/hosts', '/etc/nginx/conf.d/site.conf'])

    def test_poll_interval_floor_enforced(self):
        try:
            self._post('d-1', {'poll_interval': 5})  # below 30
            self.fail('expected 400')
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 400)
            self.assertIn('30', e.body['error'])

    def test_poll_interval_ceiling_enforced(self):
        try:
            self._post('d-1', {'poll_interval': 99999})
            self.fail('expected 400')
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 400)

    def test_monitoring_off_clears_offline_notified(self):
        """Mirrors the per-field /monitored handler's side effect: turning
        monitoring off must clear any pending offline notification so we
        don't ping about a host the operator just told us to ignore."""
        # Pre-seed an offline notification
        self.api.save(self.api.CONFIG_FILE,
                       {'offline_notified': {'d-1': int(time.time())}})
        try:
            self._post('d-1', {'monitored': False})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
        cfg = self.api.load(self.api.CONFIG_FILE)
        self.assertNotIn('d-1', cfg.get('offline_notified', {}))

    def test_audit_log_records_bulk_save(self):
        before = len(self.api.load(self.api.AUDIT_LOG_FILE).get('entries', []))
        try:
            self._post('d-1', {'group': 'auditme', 'monitored': False})
        except self.api.HTTPError:
            pass
        entries = self.api.load(self.api.AUDIT_LOG_FILE)['entries']
        self.assertEqual(len(entries), before + 1)
        e = entries[-1]
        self.assertEqual(e['action'], 'device_save_bulk')
        self.assertEqual(e['actor'], 'admin',
            'audit actor must be the username, not require_admin_auth.__name__')
        # Field list in detail (sorted, comma-separated)
        self.assertIn('group', e['detail'])
        self.assertIn('monitored', e['detail'])

    def test_viewer_cannot_save(self):
        apikeys = self.api.load(self.api.APIKEYS_FILE)
        apikeys['v'] = {'name': 'v', 'key': 'rpk_v', 'user': 'v',
                         'role': 'viewer', 'created': int(time.time()),
                         'active': True, 'expires_at': None}
        self.api.save(self.api.APIKEYS_FILE, apikeys)
        os.environ['HTTP_X_TOKEN'] = 'rpk_v'
        try:
            self._post('d-1', {'group': 'x'})
            self.fail('viewer should not be allowed')
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 403)





# ──────────────────────────────────────────────────────────────────────────

class TestDeviceSaveBulkDispatch(_ApiTestBase):
    """Static check: the dispatcher's route for the bulk handler must
    handle exactly `/api/devices/<id>` and not collide with any
    `/api/devices/<id>/<suffix>` POST route. Catches the case where a
    future suffix POST forgets to live BELOW (more specific) this
    bulk route in the dispatcher chain."""

    def test_route_pattern_excludes_suffixed_paths(self):
        src = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        # The route line must exist
        self.assertIn(
            "handle_device_save_bulk(pi[len('/api/devices/'):])", src,
            'bulk-save dispatcher route missing')
        # The check that rejects suffixed paths must also be present —
        # without it, POST /api/devices/<id>/compose/action would be
        # intercepted by the bulk handler instead of the compose route.
        self.assertIn(
            "'/' not in pi[len('/api/devices/'):]", src,
            'bulk-save route must guard against suffixed paths '
            '(no slash after the dev_id portion)')


class TestMetricThresholdRecomputeAfterChange(_ApiTestBase):
    """v3.0.4: prove the threshold-change → next-heartbeat → metric_state
    recompute flow works end-to-end on the server side.

    Jakob's bug report: edited memory thresholds to W:40 C:50, host
    reports mem 59.1%, but the Monitor page row still shows "OK". If
    THIS test passes, the server-side logic is correct and the issue
    is environmental (browser caching, agent not reporting mem_percent
    on the host that was edited, etc.). If it fails, we've found the
    bug — fix here.
    """

    def setUp(self):
        # Seed pmg01 with no metric_state (mimicking post-threshold-PATCH)
        # and the new W:40 C:50 mem thresholds. Mem 59.1% is between W
        # and C, so the expected outcome is metric_state['memory:'] =
        # 'critical' (since 59.1 >= 50).
        self.api.save(self.api.DEVICES_FILE, {
            'pmg01': {
                'name': 'pmg01.tvipper.com',
                'monitored': True,
                'last_seen': int(time.time()),
                'metric_thresholds': {
                    'mem_warn_percent': 40.0,
                    'mem_crit_percent': 50.0,
                },
                # NOTE: metric_state intentionally absent — matches the
                # state right after handle_device_metric_thresholds() pops
                # it on a threshold change.
                'sysinfo': {'mem_percent': 59.1},
            },
        })

    def test_critical_lands_after_recompute(self):
        """Simulate a heartbeat: call process_metric_thresholds directly
        with a safe_si carrying the offending mem_percent. After the
        call, dev['metric_state']['memory:'] must be 'critical'."""
        devices = self.api.load(self.api.DEVICES_FILE)
        dev = devices['pmg01']
        safe_si = {'mem_percent': 59.1}
        self.api.process_metric_thresholds('pmg01', dev, safe_si)
        self.assertIn('metric_state', dev,
            'process_metric_thresholds must write back metric_state')
        ms = dev['metric_state']
        self.assertIn('memory:', ms,
            f'memory threshold check must populate metric_state[\"memory:\"] '
            f'(state after recompute: {ms!r})')
        self.assertEqual(ms['memory:'], 'critical',
            f'mem 59.1% with W:40 C:50 must classify as critical, '
            f'got {ms.get("memory:")!r}')

    def test_warning_lands_at_threshold(self):
        """mem 45% with W:40 C:50 must classify as warning."""
        devices = self.api.load(self.api.DEVICES_FILE)
        dev = devices['pmg01']
        self.api.process_metric_thresholds('pmg01', dev, {'mem_percent': 45.0})
        self.assertEqual(dev['metric_state'].get('memory:'), 'warning')

    def test_ok_below_warning_threshold(self):
        """mem 30% with W:40 C:50 must classify as ok (absent from state)."""
        devices = self.api.load(self.api.DEVICES_FILE)
        dev = devices['pmg01']
        self.api.process_metric_thresholds('pmg01', dev, {'mem_percent': 30.0})
        # 'ok' state is the absence of an entry — _check returns early
        # when new_level == prev_level == 'ok' without setting the key.
        # Either case is fine: missing key OR explicit 'ok' value.
        ms_mem = dev.get('metric_state', {}).get('memory:')
        self.assertIn(ms_mem, (None, 'ok'),
            f'mem 30% with W:40 must NOT classify as warning/critical, got {ms_mem!r}')

    def test_resolve_thresholds_returns_overridden_values(self):
        """Sanity-check the resolver — the bug could hide here if the
        override merge logic was broken."""
        dev = self.api.load(self.api.DEVICES_FILE)['pmg01']
        warn, crit = self.api._resolve_metric_thresholds(dev, 'memory', '')
        self.assertEqual(warn, 40.0,
            f'expected mem_warn_percent=40 from device overrides, got {warn}')
        self.assertEqual(crit, 50.0,
            f'expected mem_crit_percent=50 from device overrides, got {crit}')

    def test_threshold_patch_pops_metric_state(self):
        """handle_device_metric_thresholds PATCH must clear metric_state
        so the next heartbeat re-evaluates from scratch. Without the pop,
        a device stuck in 'warning' under old thresholds would stay
        'warning' even after the operator raised the threshold above
        the current value."""
        # Pre-seed with an existing state that contradicts the new threshold
        self.api.save(self.api.DEVICES_FILE, {
            'pmg01': {
                'name': 'pmg01',
                'monitored': True,
                'metric_state': {'memory:': 'warning'},
                'metric_thresholds': {'mem_warn_percent': 80, 'mem_crit_percent': 90},
            },
        })
        self._seed_admin_session('admin')
        os.environ['REQUEST_METHOD'] = 'PATCH'
        body = json.dumps({'mem_warn_percent': 40, 'mem_crit_percent': 50}).encode()
        os.environ['CONTENT_LENGTH'] = str(len(body))

        class _StdinShim:
            buffer = io.BytesIO(body)

        old_stdin = sys.stdin
        sys.stdin = _StdinShim()
        try:
            try:
                self.api.handle_device_metric_thresholds('pmg01')
            except self.api.HTTPError as e:
                self.assertEqual(e.status, 200)
        finally:
            sys.stdin = old_stdin
            _clear_env('REQUEST_METHOD', 'CONTENT_LENGTH', 'HTTP_X_TOKEN')

        dev = self.api.load(self.api.DEVICES_FILE)['pmg01']
        self.assertNotIn('metric_state', dev,
            'metric_state must be popped after a thresholds PATCH so the '
            'next heartbeat re-evaluates the device cleanly')


class TestMobileNavCloseHandler(unittest.TestCase):
    """v3.0.4: mobile sidebar collapse was silently broken — only the
    nav-button-click path closed the drawer. Tap-outside-to-close
    required `e.target === document.body`, but with the scrim catching
    pointer events the actual target on mobile Chrome / PWA tended to
    be `<div id="app">` or `.app-content`. Burger-to-close also broken
    because the burger sits behind the scrim once the drawer is open.

    New handler logic: when drawer is open, ANY click outside the
    sidebar and outside the burger button closes the drawer. This test
    asserts the four required paths are all present in app.js so the
    code can't silently regress to the `e.target === document.body`
    pattern again.
    """

    APP_JS = REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'

    def test_handler_no_longer_uses_strict_body_target(self):
        """The strict `e.target === document.body` check was the cause
        of the breakage on real browsers. Make sure it doesn't sneak
        back in — the comment can mention it, but no live check.
        Heuristic: find every line that ISN'T a comment, then assert
        the brittle pattern is absent from those."""
        js = self.APP_JS.read_text()
        live_code = '\n'.join(
            line for line in js.splitlines()
            if not line.lstrip().startswith(('//', '*', '/*'))
        )
        self.assertNotIn(
            'e.target === document.body', live_code,
            "The strict body-target check is back. Use "
            "e.target.closest('.sidebar') / .mobile-burger / .nav-btn "
            "guards instead — see v3.0.4 close-handler rewrite.")

    def test_handler_has_sidebar_guard(self):
        """A click inside the sidebar (but not on a nav-btn) must NOT
        close the drawer. The guard `e.target.closest('.sidebar')` is
        the only way to allow taps on sidebar headers, scroll bars,
        and other interactive bits without dismissing the menu."""
        js = self.APP_JS.read_text()
        self.assertIn(
            "e.target.closest('.sidebar')", js,
            "close handler must protect taps INSIDE the sidebar from "
            "dismissing the drawer")

    def test_handler_has_burger_guard(self):
        """Without a burger guard, the open-via-burger flow toggles
        the class on, then the same click bubbles to document and the
        handler closes it — drawer never appears."""
        js = self.APP_JS.read_text()
        self.assertIn(
            "e.target.closest('.mobile-burger')", js,
            "close handler must skip when the click was on the burger "
            "itself — otherwise opening via the burger immediately "
            "closes (the toggleMobileNav onclick adds the class, then "
            "the close handler removes it on the same bubbled event)")

    def test_handler_closes_on_outside_tap(self):
        """The actual close path: drawer is open, user taps outside.
        Must call body.classList.remove('mobile-nav-open') for the
        catch-all case."""
        js = self.APP_JS.read_text()
        # Find the close handler block (between the addEventListener
        # and its closing brace) and confirm it removes the class
        # outside any of the early-return guards.
        import re
        m = re.search(
            r"document\.addEventListener\('click',\s*e\s*=>\s*\{(.+?)\}\s*\);",
            js, re.DOTALL)
        self.assertIsNotNone(m, 'click handler not found in app.js')
        body = m.group(1)
        self.assertIn(
            "innerWidth <= 720", body,
            "close handler must gate on mobile viewport width — "
            "desktop sidebar is permanent, not a drawer")
        self.assertIn(
            "document.body.classList.remove('mobile-nav-open')", body)


class TestAiPrioritiseAutoQueuesListing(unittest.TestCase):
    """v3.0.4 iter 2: when patch_history has no upgrade listing yet,
    the ✨ button used to direct the operator to 'Force re-scan packages'
    — but Force re-scan only refreshes the upgradable COUNT, not the
    listing (agent's get_patch_info() discards `out` and only keeps
    len()). Real fix: ✨ now auto-queues the right per-package-manager
    listing command via POST /api/exec.
    """

    APP_JS = REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'

    def test_force_rescan_packages_advice_removed(self):
        """The misleading 'use Force re-scan packages' toast in
        aiPrioritisePatchesForDevice must be gone — it didn't do what
        it claimed."""
        js = self.APP_JS.read_text()
        # Find the function body
        import re
        m = re.search(
            r'async function aiPrioritisePatchesForDevice\([^{]+\{(.+?)\n\}',
            js, re.DOTALL)
        self.assertIsNotNone(m, 'aiPrioritisePatchesForDevice not found')
        body = m.group(1)
        # The string 'Force re-scan' (case-insensitive) MUST NOT appear
        # in the handler body — it was the misleading advice.
        self.assertNotIn(
            'Force re-scan', body,
            "The 'Force re-scan packages' suggestion is misleading: "
            "force_package_scan only refreshes the upgradable count, "
            "not the listing. ✨ now auto-queues the right exec command.")

    def test_handler_has_pacman_listing_command(self):
        """pacman is one of Jakob's target distros (CachyOS); the
        listing command for pacman is `pacman -Qu`."""
        js = self.APP_JS.read_text()
        # The mapping must exist somewhere in the handler region. Be
        # tolerant of formatting — just look for the key/value pair.
        self.assertRegex(
            js, r"pacman:\s*'pacman -Qu'",
            "Listing command for pacman must be 'pacman -Qu'")

    def test_handler_has_apt_listing_command(self):
        js = self.APP_JS.read_text()
        self.assertRegex(
            js, r"apt:\s*'apt list --upgradable'",
            "Listing command for apt must be 'apt list --upgradable'")

    def test_handler_has_dnf_listing_command(self):
        js = self.APP_JS.read_text()
        self.assertRegex(
            js, r"dnf:\s*'dnf check-update'",
            "Listing command for dnf must be 'dnf check-update'")

    def test_handler_posts_to_exec_endpoint(self):
        """The auto-queue path posts to /exec — same endpoint sendExecCmd
        uses for the Run Command modal. No new endpoint introduced."""
        js = self.APP_JS.read_text()
        import re
        m = re.search(
            r'async function aiPrioritisePatchesForDevice\([^{]+\{(.+?)\n\}',
            js, re.DOTALL)
        body = m.group(1)
        self.assertRegex(
            body, r"api\(\s*'POST'\s*,\s*'/exec'",
            "Handler must POST to /exec to queue the listing command")


class TestMobileSidebarCloseButton(unittest.TestCase):
    """v3.0.4 iter 2: burger-to-close was unreliable on mobile because
    the burger sits at z-index 100 behind the z-index 800 scrim once
    the drawer is open. Standard mobile-drawer fix: an explicit ✕
    button INSIDE the sidebar header. Always discoverable, always
    works, no z-order trickery.
    """

    INDEX_HTML = REPO_ROOT / 'server' / 'html' / 'index.html'
    STYLES_CSS = REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'

    def test_close_button_exists_in_sidebar(self):
        html = self.INDEX_HTML.read_text()
        self.assertIn(
            'sidebar-mobile-close', html,
            'Sidebar must include a mobile-only close button '
            '(class="sidebar-mobile-close")')

    def test_close_button_calls_toggleMobileNav(self):
        html = self.INDEX_HTML.read_text()
        # Find the close button line and check its onclick
        import re
        m = re.search(
            r'<button[^>]*class="sidebar-mobile-close"[^>]*>',
            html)
        self.assertIsNotNone(m, 'sidebar-mobile-close button not found')
        btn = m.group(0)
        self.assertIn(
            'toggleMobileNav()', btn,
            'Close button must call toggleMobileNav() so it uses the '
            'same toggle path as the burger')
        # Accessibility — must have an aria-label
        self.assertIn(
            'aria-label=', btn,
            'Close button must have an aria-label for screen readers')

    def test_close_button_hidden_on_desktop(self):
        css = self.STYLES_CSS.read_text()
        # The default rule (outside any @media block) must hide it
        self.assertRegex(
            css, r'\.sidebar-mobile-close\s*\{\s*display:\s*none',
            'The close button must be hidden on desktop by default '
            '(only the burger-equivalent is needed on mobile)')

    def test_close_button_shown_on_mobile(self):
        """Inside @media (max-width: 720px) there must be a rule that
        sets display: flex (or similar visible value) on the button."""
        css = self.STYLES_CSS.read_text()
        # Find the mobile @media block that contains our selector
        import re
        # Match @media (max-width: 720px) { ... } blocks (non-nested ok
        # since our CSS isn't nested)
        for m in re.finditer(
                r'@media\s*\(\s*max-width:\s*720px\s*\)\s*\{(.+?)\n\}',
                css, re.DOTALL):
            block = m.group(1)
            if '.sidebar-mobile-close' in block and 'display' in block:
                # Confirm it's a visible display value, not 'none'
                rule = re.search(
                    r'\.sidebar-mobile-close\s*\{[^}]*display:\s*(\w+)',
                    block)
                if rule:
                    self.assertNotEqual(
                        rule.group(1), 'none',
                        'On mobile the close button must be visible')
                    return
        self.fail('No mobile rule showing .sidebar-mobile-close found')

    def test_collapse_button_hidden_on_mobile(self):
        """v3.0.4 (iter 3): the desktop Collapse button is meaningless
        in the mobile drawer context (drawer is overlay, not docked).
        Operators reported it as inert/confusing. The ✕ is the sole
        mobile close action; the collapse-btn must be hidden under the
        mobile breakpoint."""
        css = self.STYLES_CSS.read_text()
        import re
        for m in re.finditer(
                r'@media\s*\(\s*max-width:\s*720px\s*\)\s*\{(.+?)\n\}',
                css, re.DOTALL):
            block = m.group(1)
            # Look for `.sidebar-collapse-btn { display: none }` (or
            # equivalent with extra selectors / properties) inside the
            # mobile breakpoint.
            rule = re.search(
                r'\.sidebar-collapse-btn\s*\{[^}]*display:\s*none',
                block)
            if rule:
                return
        self.fail(
            'No mobile rule hiding .sidebar-collapse-btn found. '
            'On mobile the Collapse button is inert and confusing — '
            'the ✕ button replaces it.')


class TestServiceWorkerRegistrationHardening(unittest.TestCase):
    """v3.0.4 iter 2: Chrome throws `InvalidStateError: The document is
    in an invalid state` when serviceWorker.register() runs during a
    transient state (BFCache restore, navigation in progress, etc).
    The previous code waited for `load`, registered once, and bailed
    on .catch. When the new SW failed to register, the old SW kept
    running with its stale cache — operators saw "page looks broken
    after deploy" (unstyled icons, missing new behaviours).
    """

    INDEX_HTML = REPO_ROOT / 'server' / 'html' / 'index.html'

    def test_no_longer_registers_inside_load_event(self):
        """The brittle `window.addEventListener('load', ...)` pattern
        must not be the SW registration trigger. DOMContentLoaded (or
        synchronous registration when DOM is already ready) is more
        reliable."""
        html = self.INDEX_HTML.read_text()
        # Find the SW registration block by anchor
        import re
        m = re.search(
            r"if \('serviceWorker' in navigator\) \{(.+?)\n  \}",
            html, re.DOTALL)
        self.assertIsNotNone(m, 'SW registration block not found')
        block = m.group(1)
        self.assertNotIn(
            "window.addEventListener('load'", block,
            "SW registration must not be gated on the `load` event — that "
            "fires too late on slow networks and during BFCache restore, "
            "causing InvalidStateError. Use DOMContentLoaded or register "
            "synchronously when DOM is ready.")

    def test_retries_on_invalid_state_error(self):
        """One retry on InvalidStateError clears the transient case."""
        html = self.INDEX_HTML.read_text()
        self.assertIn(
            'InvalidStateError', html,
            "SW registration must explicitly handle InvalidStateError")
        # And there must be a retry mechanism (setTimeout somewhere
        # near the InvalidStateError check)
        import re
        m = re.search(
            r"InvalidStateError[^}]+setTimeout",
            html, re.DOTALL)
        self.assertIsNotNone(
            m, 'After detecting InvalidStateError, registration must '
               'retry via setTimeout — one retry typically succeeds.')

    def test_warns_when_stale_sw_blocks_registration(self):
        """When a previous SW is still controlling the page and the new
        registration fails, surface a console hint pointing at the
        DevTools fix. Operators need a discoverable remediation path."""
        html = self.INDEX_HTML.read_text()
        self.assertIn(
            'navigator.serviceWorker.controller', html,
            "On registration failure, code must check "
            "navigator.serviceWorker.controller (the existing SW) and "
            "log a hint about how to clear it")
        self.assertIn(
            'Unregister', html,
            "The remediation hint must mention 'Unregister' so operators "
            "can find the DevTools action")
