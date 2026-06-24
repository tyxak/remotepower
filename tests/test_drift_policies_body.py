"""Regression: PUT /api/drift-policies must accept a bare JSON array body, not
only {"policies": [...]}.

handle_drift_policies_set read the body via get_json_obj(), which coerces a
top-level array to {} -- so a bare-list PUT (the documented forward-compat
shape the handler's own `if isinstance(body, dict) else body` branch is meant
to support) 400'd with "policies must be a list" and the fleet kept its stale
drift policy. Same get_json_obj() sweep regression that was reverted for
handle_favorites_set (commit b7327ea); this handler was missed.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_drift_body', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _set_policies(body_value):
    """Drive handle_drift_policies_set as a stubbed admin PUT carrying
    body_value, and return the captured (status, body)."""
    cap = {}

    def _resp(status, body=None):
        cap['status'] = status
        cap['body'] = body
        raise api.HTTPError(status, body)

    orig = {n: getattr(api, n) for n in
            ('require_admin_auth', 'method', 'get_json_body', 'respond', 'audit_log')}
    api.save(api.CONFIG_FILE, {})
    api.require_admin_auth = lambda: 'admin'
    api.method = lambda: 'PUT'
    api.get_json_body = lambda: body_value
    api.audit_log = lambda *a, **k: None
    api.respond = _resp
    try:
        try:
            api.handle_drift_policies_set()
        except api.HTTPError:
            pass
    finally:
        for n, v in orig.items():
            setattr(api, n, v)
    return cap


class TestDriftPoliciesBody(unittest.TestCase):
    POLICY = {'scope': 'tag', 'value': 'prod', 'mode': 'enforce'}

    def test_accepts_bare_list(self):
        cap = _set_policies([dict(self.POLICY)])
        self.assertEqual(cap.get('status'), 200, cap.get('body'))
        self.assertEqual(cap['body']['policies'], [self.POLICY])

    def test_accepts_wrapped_object(self):
        cap = _set_policies({'policies': [dict(self.POLICY)]})
        self.assertEqual(cap.get('status'), 200, cap.get('body'))
        self.assertEqual(cap['body']['policies'], [self.POLICY])


if __name__ == '__main__':
    unittest.main()
