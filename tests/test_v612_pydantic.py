"""v6.1.2 — typed request-body validation (pydantic v2), full adoption.

The single pattern is the pre-existing `request_models.validate(Model, body)`
additive pre-check (server/cgi-bin/request_models.py): it validates types as a
SUPERSET of each handler's hand-rolled checks (never narrower — a value the old
code accepted still validates, an out-of-range value the old code CLAMPED is not
turned into a 400), returns (True, None) when pydantic is absent so handlers still
work, and `extra='ignore'` so it can't break existing API clients. This pins the
helper contract, the newly-added models, and that pydantic is wired into every
dependency-declaration surface (installed by default, like flask/gunicorn).
"""
import importlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v612-pyd-')
    spec = importlib.util.spec_from_file_location('api_v612_pyd', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestValidateHelperContract(unittest.TestCase):
    def setUp(self):
        self.rm = importlib.import_module('request_models')

    def test_pydantic_is_actually_available(self):
        self.assertTrue(self.rm.available(),
                        'pydantic must import — it is installed by default '
                        'so request validation actually runs in production')

    def test_valid_body_passes(self):
        ok, err = self.rm.validate(self.rm.TenantCreateRequest, {'name': 'acme'})
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_non_dict_body_is_rejected(self):
        ok, err = self.rm.validate(self.rm.TenantCreateRequest, [1, 2, 3])
        self.assertFalse(ok)
        self.assertIn('object', err)

    def test_bad_type_is_a_message_not_a_crash(self):
        # amount is required + must be float-coercible in BillingPaymentWebhookRequest
        ok, err = self.rm.validate(self.rm.BillingPaymentWebhookRequest,
                                   {'amount': 'not-a-number'})
        self.assertFalse(ok)
        self.assertIsInstance(err, str)

    def test_extra_keys_are_ignored_not_rejected(self):
        """extra='ignore' is deliberate — rejecting unknown keys would break
        existing API clients (a breaking change this repo doesn't ship silently)."""
        ok, err = self.rm.validate(self.rm.TenantCreateRequest,
                                   {'name': 'acme', 'totally_unknown': 1})
        self.assertTrue(ok, 'an unknown key must be ignored, not a 400')

    def test_errors_never_echo_input_values(self):
        """A validation error must not reflect the submitted value back — bodies
        can carry secrets (tokens, passwords)."""
        ok, err = self.rm.validate(self.rm.BillingPaymentWebhookRequest,
                                   {'amount': 'sk_live_SECRET'})
        self.assertFalse(ok)
        self.assertNotIn('sk_live_SECRET', err)


class TestNewModelsAreFaithfulSupersets(unittest.TestCase):
    """The v6.1.2 models must not reject anything the old hand-rolled code accepted."""

    def setUp(self):
        self.rm = importlib.import_module('request_models')

    def test_deadman_coerces_string_minutes(self):
        ok, err = self.rm.validate(self.rm.DeadmanCreateRequest,
                                   {'name': 'NAS', 'period_minutes': '1440'})
        self.assertTrue(ok, err)

    def test_deadman_out_of_range_is_NOT_rejected(self):
        """The old code clamped (max(1,min(43200,...))) — so the model must NOT
        400 an out-of-range value, or it would be narrower than the old contract."""
        ok, err = self.rm.validate(self.rm.DeadmanCreateRequest,
                                   {'name': 'NAS', 'period_minutes': 999999})
        self.assertTrue(ok, 'out-of-range must pass validation (handler clamps it)')

    def test_deadman_non_numeric_minutes_is_rejected(self):
        ok, err = self.rm.validate(self.rm.DeadmanCreateRequest,
                                   {'name': 'NAS', 'period_minutes': 'abc'})
        self.assertFalse(ok)

    def test_docker_prune_empty_body_passes(self):
        ok, err = self.rm.validate(self.rm.DockerPruneRequest, {})
        self.assertTrue(ok, err)

    def test_docker_prune_coerces_non_string_scope(self):
        # str(body.get('scope')) in the handler accepts any scalar; the model must too
        ok, err = self.rm.validate(self.rm.DockerPruneRequest, {'scope': 123})
        self.assertTrue(ok, err)


class TestConvertedHandlersKeepBehaviour(unittest.TestCase):
    """The converted handlers must keep their exact end-to-end behaviour."""

    def setUp(self):
        self.api = _fresh_api()
        self.cap = {}

        def _r(s, d=None):
            self.cap['s'] = s
            self.cap['d'] = d
            raise self.api.HTTPError(s, d)
        self.api.respond = _r
        self.api.require_admin_auth = lambda *a, **k: 'admin'
        self.api.audit_log = lambda *a, **k: None
        self.api._request_base_url = lambda: 'https://x'
        self.api.method = lambda: 'POST'

    def test_deadman_coerces_string_minutes(self):
        self.api.get_json_obj = lambda: {'name': 'NAS', 'period_minutes': '1440'}
        try:
            self.api.handle_deadman_jobs()
        except self.api.HTTPError:
            pass
        job = self.cap['d']['job']
        self.assertEqual(job['period_minutes'], 1440)

    def test_deadman_out_of_range_is_clamped_not_400(self):
        self.api.get_json_obj = lambda: {'name': 'NAS', 'period_minutes': 999999}
        try:
            self.api.handle_deadman_jobs()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['s'], 200)
        self.assertEqual(self.cap['d']['job']['period_minutes'], 43200)

    def test_deadman_non_numeric_minutes_is_400(self):
        self.api.get_json_obj = lambda: {'name': 'NAS', 'period_minutes': 'abc'}
        try:
            self.api.handle_deadman_jobs()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['s'], 400)

    def test_deadman_missing_name_is_400(self):
        self.api.get_json_obj = lambda: {'period_minutes': 60}
        try:
            self.api.handle_deadman_jobs()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['s'], 400)

    def test_docker_prune_defaults_scope_and_reads_confirm(self):
        self.api.require_perm = lambda *a, **k: 'admin'
        self.api._validate_id = lambda x: True
        self.api.save(self.api.DEVICES_FILE, {'d1': {'name': 'n', 'token': 't'}})
        self.api.get_json_obj = lambda: {}   # no scope -> defaults to 'all' (safe)
        try:
            self.api.handle_device_docker_prune('d1')
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['s'], 200)


class TestSweepCoverageAndExclusions(unittest.TestCase):
    """The full-adoption sweep wired request_models.validate() into the body-reading
    handlers, with a SMALL, DELIBERATE exclusion set. These pins stop a future sweep
    from (a) regressing coverage or (b) re-adding an excluded handler and
    reintroducing a real bug."""

    @classmethod
    def setUpClass(cls):
        cls.api_src = (CGI / 'api.py').read_text()

    def test_broad_coverage(self):
        """A floor, not an exact count (new handlers keep landing). The sweep wired
        200+ handlers; if this drops far below, the sweep was reverted."""
        n = self.api_src.count('request_models.validate(')
        self.assertGreater(n, 200, f'only {n} validate() call sites — sweep regressed?')

    def test_non_dict_body_handlers_are_NOT_validated(self):
        """These legitimately accept a bare JSON array/string (or any non-dict) body;
        a dict-expecting model would 400 a request they accept. Must stay unwired."""
        for fn in ('handle_favorites_set', 'handle_drift_policies_set',
                   'handle_syslog_in', 'handle_snmp_trap_in'):
            i = self.api_src.index('def ' + fn + '(')
            nxt = self.api_src.find('\ndef ', i + 1)
            block = self.api_src[i:nxt]
            self.assertNotIn('request_models.validate(', block,
                             f'{fn} accepts a non-dict body — must not be validated')

    def test_heartbeat_is_not_validated(self):
        """The hottest path (every agent, every interval), a 39-field agent-controlled
        body already run through safe_si — validating it pre-auth is cost with ~no
        value. Deliberately unwired."""
        i = self.api_src.index('def handle_heartbeat(')
        nxt = self.api_src.find('\ndef ', i + 1)
        self.assertNotIn('request_models.validate(', self.api_src[i:nxt])


class TestPydanticIsInstalledEverywhere(unittest.TestCase):
    """It is installed by default (request validation depends on it running), so it
    must be declared everywhere the other runtime deps (flask/gunicorn) are — the
    checklist the Flask cutover established and that a CI run missed once already."""

    def test_ci_installs_it(self):
        ci = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text()
        self.assertIn('pydantic', ci)

    def test_the_installers_install_it(self):
        for f in ('install.sh', 'install-server.sh'):
            self.assertIn('pydantic', (ROOT / f).read_text(), f)

    def test_dockerfile_installs_it(self):
        self.assertIn('pydantic', (ROOT / 'Dockerfile').read_text())

    def test_aur_depends_on_it(self):
        pkg = (ROOT / 'packaging' / 'aur' / 'remotepower-server' / 'PKGBUILD').read_text()
        self.assertIn('python-pydantic', pkg)


if __name__ == '__main__':
    unittest.main()
