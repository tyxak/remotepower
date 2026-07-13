"""v6.1.2 — typed request-body validation (pydantic v2), foundation + wave 1.

The `validated(model)` helper replaces the hand-rolled
`body = get_json_obj(); x = int(body.get('x') or default)` dance that is the source
of the silent-whitelist / wrong-type / 500-on-bad-body bug class. This pins the
helper's contract and the first converted handlers, and asserts pydantic is wired
into every dependency-declaration surface (it is now a hard runtime dep, like Flask).
"""
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


class TestValidatedHelper(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.cap = {}

        def _r(s, d=None):
            self.cap['s'] = s
            self.cap['d'] = d
            raise self.api.HTTPError(s, d)
        self.api.respond = _r

    def _model(self):
        class M(self.api.RPStrictModel):
            name: str
            count: int = 0
        return M

    def test_pydantic_is_actually_available(self):
        self.assertTrue(self.api._PYDANTIC_OK,
                        'pydantic must import — it is a hard runtime dependency')

    def test_valid_body_is_coerced_and_returned(self):
        self.api.get_json_obj = lambda: {'name': 'nas', 'count': '5'}
        m = self.api.validated(self._model())
        self.assertEqual(m.name, 'nas')
        self.assertEqual(m.count, 5)             # "5" coerced to int
        self.assertIsInstance(m.count, int)

    def test_a_bad_body_is_a_structured_400(self):
        self.api.get_json_obj = lambda: {'count': 'x'}   # missing name, bad count
        try:
            self.api.validated(self._model())
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['s'], 400)
        self.assertIn('fields', self.cap['d'])
        self.assertIn('name', self.cap['d']['fields'])

    def test_strict_model_rejects_unknown_keys(self):
        self.api.get_json_obj = lambda: {'name': 'x', 'bogus': 1}
        try:
            self.api.validated(self._model())
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['s'], 400)
        self.assertIn('bogus', self.cap['d']['fields'])

    def test_lenient_model_ignores_unknown_keys(self):
        class L(self.api.RPLenientModel):
            name: str
        self.api.get_json_obj = lambda: {'name': 'x', 'extra': 'ignored'}
        m = self.api.validated(L)
        self.assertEqual(m.name, 'x')

    def test_errors_never_echo_input_values(self):
        """A validation error must not reflect the submitted value back — bodies
        can carry secrets (tokens, passwords)."""
        self.api.get_json_obj = lambda: {'name': 123, 'count': 'sk_live_SECRET'}
        try:
            self.api.validated(self._model())
        except self.api.HTTPError:
            pass
        body = str(self.cap['d'])
        self.assertNotIn('sk_live_SECRET', body)


class TestConvertedHandlers(unittest.TestCase):
    """The wave-1 conversions must keep their exact behaviour; each already has
    functional tests elsewhere — these pin the pydantic-specific edges."""

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

    def test_deadman_rejects_out_of_range_minutes(self):
        self.api.get_json_obj = lambda: {'name': 'NAS', 'period_minutes': 999999}
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
        self.api.save(self.api.DEVICES_FILE,
                      {'d1': {'name': 'n', 'token': 't'}})
        # no scope -> defaults to 'all' (safe); reaches the queue path
        self.api.get_json_obj = lambda: {}
        try:
            self.api.handle_device_docker_prune('d1')
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['s'], 200)


class TestPydanticIsAHardDependency(unittest.TestCase):
    """It is now required at runtime (request validation depends on it), so it must
    be declared everywhere the other hard deps (flask/gunicorn) are — the checklist
    that the Flask cutover established and that a CI run missed once already."""

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
