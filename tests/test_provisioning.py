"""v5.6.0 — Provisioning blueprints (catalog + render).

A library of parameterized IaC / boot templates organised in a folder tree.
RENDER-ONLY: the server does pure ${var} string substitution and never executes
anything (the strong guarantee these tests pin). Admin-gated, kill-switched
behind `show_provisioning`.
"""
import importlib.util
import unittest
import sys as _as_sys
from pathlib import Path as _as_Path
_as_sys.path.insert(0, str(_as_Path(__file__).resolve().parent))
from apisrc import api_source as _apisrc_combined   # api.py + *_handlers.py bound modules (decomposition-safe pins)
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_prov', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
_SRC = _apisrc_combined()


class TestBlueprintHelpers(unittest.TestCase):
    def test_clean_folder_normalises_and_blocks_traversal(self):
        self.assertEqual(api._bp_clean_folder('aws/dev'), 'aws/dev')
        self.assertEqual(api._bp_clean_folder('/aws//dev/'), 'aws/dev')
        self.assertEqual(api._bp_clean_folder('a/../../b'), 'a/b')
        self.assertEqual(api._bp_clean_folder('.'), '')
        self.assertEqual(api._bp_clean_folder(''), '')

    def test_clean_vars_sanitises(self):
        out = api._bp_clean_vars([
            {'name': 'region', 'label': 'AWS region', 'default': 'eu-west-1'},
            {'name': 'bad name!', 'label': 'x', 'default': 'y', 'secret': True},
            {'no': 'name'},          # dropped — no usable name
            'not a dict',            # dropped
        ])
        self.assertEqual([v['name'] for v in out], ['region', 'badname'])
        self.assertTrue(out[1]['secret'])

    def test_var_regex_matches_braced_identifiers_only(self):
        self.assertEqual(api._BLUEPRINT_VAR_RE.findall('${a} $b ${c_1} ${1bad}'),
                         ['a', 'c_1'])

    def test_public_masks_secret_var_defaults(self):
        bp = {'id': 'x', 'name': 'n', 'kind': 'terraform', 'content': 'c',
              'variables': [{'name': 's', 'default': 'hunter2', 'secret': True},
                            {'name': 'r', 'default': 'eu', 'secret': False}]}
        pub = api._bp_public(bp)
        sec = next(v for v in pub['variables'] if v['name'] == 's')
        self.assertEqual(sec['default'], '')
        self.assertTrue(sec.get('default_set'))
        plain = next(v for v in pub['variables'] if v['name'] == 'r')
        self.assertEqual(plain['default'], 'eu')

    def test_request_base_url(self):
        self.assertEqual(api._request_base_url({'HTTP_HOST': 'rp.example.com'}),
                         'https://rp.example.com')
        self.assertEqual(
            api._request_base_url({'HTTP_HOST': 'h', 'HTTP_X_FORWARDED_PROTO': 'http'}),
            'http://h')


class TestRenderSubstitution(unittest.TestCase):
    """Exercise the exact substitution the render handler performs."""
    def _render(self, content, values):
        missing = []

        def _sub(mo):
            k = mo.group(1)
            if k in values:
                return values[k]
            missing.append(k)
            return mo.group(0)
        return api._BLUEPRINT_VAR_RE.sub(_sub, content), missing

    def test_substitutes_known_leaves_unknown(self):
        out, missing = self._render('region=${region} az=${az}', {'region': 'eu'})
        self.assertEqual(out, 'region=eu az=${az}')
        self.assertEqual(missing, ['az'])

    def test_agent_install_macro_shape(self):
        base = 'https://rp.example.com'
        macro = f'curl -fsSL {base}/install | sudo sh -s -- --token <enrollment-token>'
        out, _ = self._render('# ${rp_agent_install}', {'rp_agent_install': macro})
        self.assertIn('/install', out)
        self.assertIn('--token', out)


class TestApiWiring(unittest.TestCase):
    def test_handlers_exist(self):
        for fn in ('handle_blueprints_list', 'handle_blueprint_create',
                   'handle_blueprint_update', 'handle_blueprint_delete',
                   'handle_blueprint_render'):
            self.assertTrue(hasattr(api, fn), f'missing {fn}')

    def test_routes_registered(self):
        self.assertIn("('GET', '/api/provisioning/blueprints'): handle_blueprints_list", _SRC)
        self.assertIn("('POST', '/api/provisioning/blueprints'): handle_blueprint_create", _SRC)
        self.assertIn("/api/provisioning/blueprints/') and pi.endswith('/render')", _SRC)

    def test_mutations_admin_gated_and_audited(self):
        for fn in ('handle_blueprint_create', 'handle_blueprint_update',
                   'handle_blueprint_delete'):
            seg = _SRC[_SRC.index('def ' + fn): _SRC.index('def ' + fn) + 1800]
            self.assertIn('require_admin_auth()', seg, f'{fn} not admin-gated')
            self.assertIn('audit_log(', seg, f'{fn} not audited')
            self.assertIn('_provisioning_enabled()', seg, f'{fn} missing kill-switch')

    def test_render_is_admin_gated_and_kill_switched(self):
        seg = _SRC[_SRC.index('def handle_blueprint_render'):
                   _SRC.index('def handle_blueprint_render') + 1800]
        self.assertIn('require_admin_auth()', seg)
        self.assertIn('_provisioning_enabled()', seg)

    def test_render_handler_no_execution(self):
        """The RENDER handler must be pure string substitution — no process/exec
        sinks. (Terraform execution lives in the separate run handler, gated and
        tested below.)"""
        start = _SRC.index('def handle_blueprint_render')
        end = _SRC.index('def _terraform_available')   # render ends where exec begins
        block = _SRC[start:end]
        for sink in ('subprocess', 'os.system', 'os.popen', 'eval(', 'exec(',
                     'Popen', 'shell=True'):
            self.assertNotIn(sink, block, f'render handler must not use {sink}')

    def test_config_flag_emitted_and_saved(self):
        self.assertIn("'show_provisioning': bool(cfg.get('show_provisioning'))", _SRC)
        self.assertIn("cfg['show_provisioning'] = bool(body.get('show_provisioning'))", _SRC)


class TestTerraformExecution(unittest.TestCase):
    def test_run_wiring(self):
        self.assertIn("/api/provisioning/blueprints/') and pi.endswith('/run')", _SRC)
        seg = _SRC[_SRC.index('def handle_blueprint_run'):
                   _SRC.index('def handle_blueprint_run') + 3500]
        self.assertIn('require_admin_auth()', seg)
        self.assertIn('_provisioning_enabled()', seg)
        self.assertIn('_iac_execute_enabled()', seg)            # the second gate
        self.assertIn("audit_log(actor, 'blueprint_run'", seg)
        self.assertIn("bp.get('kind') != 'terraform'", seg)     # only terraform executes
        self.assertIn('fcntl.flock', seg)                       # per-blueprint run lock

    def test_list_exposes_exec_flags(self):
        # (?:A.)? — the provisioning handlers access api services via the
        # bound A namespace since the bound-module extraction.
        self.assertRegex(_SRC, r"'execute_enabled': (?:A\.)?_iac_execute_enabled\(\)")
        self.assertRegex(_SRC, r"'terraform_available': (?:A\.)?_terraform_available\(\)")

    def test_config_flag_emitted_and_saved(self):
        self.assertIn("'iac_execute_enabled': bool(cfg.get('iac_execute_enabled'))", _SRC)
        self.assertIn("cfg['iac_execute_enabled'] = bool(body['iac_execute_enabled'])", _SRC)

    def test_var_secret_split(self):
        """Non-secret vars go to the on-disk tfvars; secrets never do (env only).
        Uses a provider-free config so terraform init is fast if installed, and
        falls back gracefully (rc 127) when terraform is absent."""
        import json as _json
        import shutil as _sh
        bp = {'id': 'tftest_split', 'kind': 'terraform',
              'content': 'variable "region" {}\nvariable "token" {}\n',
              'variables': [{'name': 'region', 'secret': False},
                            {'name': 'token', 'secret': True}]}
        wd = api.IAC_RUNS_DIR / 'tftest_split'
        try:
            out, rc = api._terraform_run(bp, 'plan', {'region': 'eu-west-1', 'token': 'SEKRET'})
            tfvars = _json.loads((wd / 'rp.auto.tfvars.json').read_text())
            self.assertEqual(tfvars.get('region'), 'eu-west-1')
            self.assertNotIn('token', tfvars)              # secret stays OFF disk
            self.assertIn('variable "region"', (wd / 'main.tf').read_text())
            self.assertNotIn('SEKRET', (wd / 'rp.auto.tfvars.json').read_text())
            self.assertIsInstance(rc, int)
        finally:
            _sh.rmtree(wd, ignore_errors=True)


class TestFrontendWiring(unittest.TestCase):
    def test_run_button_and_modal(self):
        index = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="blueprint-run-modal"', index)
        prov = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-provisioning.js').read_text()
        self.assertIn('function runBlueprintOp', prov)
        self.assertIn('_blueprintRunBtn', prov)

    def test_page_module_and_nav_present(self):
        index = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="nav-provisioning"', index)
        self.assertIn('id="page-provisioning"', index)
        # v6.2.2: app-provisioning.js is a LAZY page module — wired through
        # app.js's _LAZY_PAGE_MODULES map, not a boot <script> tag.
        _appjs_core = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("'app-provisioning.js'", _appjs_core)
        appjs = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-provisioning.js').read_text()
        for fn in ('function loadProvisioning', 'function saveBlueprint',
                   'function renderBlueprint', 'function deleteBlueprint'):
            self.assertIn(fn, appjs)


if __name__ == '__main__':
    unittest.main()
