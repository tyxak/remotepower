"""v5.1.0 — declarative plugin: the code-free custom HTTP health probe.

A "plugin" is an integration instance of the new `custom_probe` connector, so it
inherits the entire integrations machinery — SSRF-safe client, poll cadence,
alerts, secret-scrub, and the generic Settings UI. These tests pin the connector
logic + that the declarative spec survives the save path.
"""
import importlib.util
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('integ_plugin', _CGI / 'integrations.py')
integ = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(integ)


class _Resp:
    def __init__(self, status, payload=None, not_json=False):
        self.status = status
        self.ok = 200 <= status < 300
        self._payload = payload
        self._not_json = not_json

    def json(self):
        if self._not_json:
            raise ValueError('not json')
        return self._payload


class _Client:
    def __init__(self, resp):
        self._resp = resp
        self.last_headers = None
        self.last_path = None

    def get(self, path, headers=None, params=None):
        self.last_path = path
        self.last_headers = headers or {}
        return self._resp


class TestRegistration(unittest.TestCase):
    def test_registered_with_declarative_fields(self):
        self.assertIn('custom_probe', integ.CONNECTORS)
        keys = {f['key'] for f in integ.CONNECTORS['custom_probe']['fields']}
        self.assertGreaterEqual(
            keys, {'probe_path', 'probe_expect', 'probe_json_field', 'probe_json_op', 'probe_json_value'})
        # appears in the UI catalog
        self.assertTrue(any(c['type'] == 'custom_probe' for c in integ.list_connectors()))


class TestProbeCompare(unittest.TestCase):
    def test_ops(self):
        self.assertTrue(integ._probe_compare('healthy', 'eq', 'healthy'))
        self.assertFalse(integ._probe_compare('down', 'eq', 'healthy'))
        self.assertTrue(integ._probe_compare('down', 'ne', 'healthy'))
        self.assertTrue(integ._probe_compare(5, 'lt', 10))
        self.assertTrue(integ._probe_compare(20, 'gt', 10))
        self.assertFalse(integ._probe_compare('x', 'lt', 10))      # non-numeric → False
        self.assertTrue(integ._probe_compare('all systems go', 'contains', 'systems'))


class TestCustomProbe(unittest.TestCase):
    def test_2xx_ok(self):
        r = integ._custom_probe({}, _Client(_Resp(204)))
        self.assertEqual(r['status'], integ.OK)

    def test_expected_status_mismatch_crit(self):
        r = integ._custom_probe({'probe_expect': '200'}, _Client(_Resp(503)))
        self.assertEqual(r['status'], integ.CRIT)

    def test_non2xx_without_expect_is_crit(self):
        r = integ._custom_probe({}, _Client(_Resp(500)))
        self.assertEqual(r['status'], integ.CRIT)

    def test_json_field_ok_and_crit(self):
        cli = _Client(_Resp(200, {'data': {'status': 'healthy'}}))
        ok = integ._custom_probe(
            {'probe_json_field': 'data.status', 'probe_json_op': 'eq', 'probe_json_value': 'healthy'}, cli)
        self.assertEqual(ok['status'], integ.OK)
        bad = integ._custom_probe(
            {'probe_json_field': 'data.status', 'probe_json_op': 'eq', 'probe_json_value': 'healthy'},
            _Client(_Resp(200, {'data': {'status': 'degraded'}})))
        self.assertEqual(bad['status'], integ.CRIT)

    def test_json_field_missing_warns(self):
        r = integ._custom_probe(
            {'probe_json_field': 'nope.here'}, _Client(_Resp(200, {'data': {}})))
        self.assertEqual(r['status'], integ.WARN)

    def test_non_json_body_warns_when_field_requested(self):
        r = integ._custom_probe(
            {'probe_json_field': 'x'}, _Client(_Resp(200, not_json=True)))
        self.assertEqual(r['status'], integ.WARN)

    def test_bearer_token_from_secret(self):
        cli = _Client(_Resp(200))
        integ._custom_probe({'secret': 'tok123', 'probe_path': '/h'}, cli)
        self.assertEqual(cli.last_path, '/h')
        self.assertEqual(cli.last_headers.get('Authorization'), 'Bearer tok123')


class TestSavePreservesSpec(unittest.TestCase):
    def test_api_save_whitelists_probe_fields(self):
        src = (_CGI / 'api.py').read_text()
        # the save loop must preserve the declarative spec for custom_probe
        self.assertIn("if typ == 'custom_probe':", src)
        for k in ('probe_path', 'probe_expect', 'probe_json_field', 'probe_json_op', 'probe_json_value'):
            self.assertIn(f"inst['{k}']", src)


if __name__ == '__main__':
    unittest.main()
