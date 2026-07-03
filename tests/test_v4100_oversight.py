"""v4.10.0: read-only Auditor role, scope-delegated credential reveal, and the
agent-stopped (host-was-up) distinct signal."""
import importlib.util
import sys
import unittest
import sys as _as_sys
from pathlib import Path as _as_Path
_as_sys.path.insert(0, str(_as_Path(__file__).resolve().parent))
from apisrc import api_source as _apisrc_combined   # api.py + *_handlers.py bound modules (decomposition-safe pins)
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))
_spec = importlib.util.spec_from_file_location("api_oversight", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

API_SRC = _apisrc_combined()
APP = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
AGENT = (_ROOT / "client" / "remotepower-agent.py").read_text()


class TestAuditorRole(unittest.TestCase):
    def test_registered(self):
        self.assertIn('auditor', api.VALID_ROLES)
        self.assertIn('auditor', api.USER_ROLES)

    def test_resolves_read_only(self):
        rd = api._resolve_role('auditor')
        self.assertFalse(rd['admin'])
        self.assertEqual(rd['permissions'], set())   # runs nothing

    def test_gate_exists_and_used(self):
        self.assertTrue(hasattr(api, 'require_admin_or_auditor_auth'))
        # the five oversight read endpoints use the relaxed gate
        for fn in ('def handle_audit_log(', 'def handle_audit_log_verify(',
                   'def handle_audit_log_archive(', 'def handle_evidence_pack(',
                   'def handle_security_posture('):
            i = API_SRC.index(fn)
            self.assertIn('require_admin_or_auditor_auth', API_SRC[i:i + 600], fn)

    def test_ui_option(self):
        self.assertIn('value="auditor"', APP)


class TestScopeDelegatedCreds(unittest.TestCase):
    def _cover(self, scope, st, sv):
        orig = api._caller_scope
        api._caller_scope = lambda: scope
        try:
            return api._caller_scope_covers_credential(st, sv)
        finally:
            api._caller_scope = orig

    def test_admin_covers_all(self):
        self.assertTrue(self._cover(None, 'site', 'anything'))

    def test_sites_scope(self):
        sc = {'type': 'sites', 'values': ['s1', 's2']}
        self.assertTrue(self._cover(sc, 'site', 's1'))
        self.assertFalse(self._cover(sc, 'site', 's9'))
        self.assertFalse(self._cover(sc, 'group', 's1'))   # type mismatch

    def test_handlers_relaxed(self):
        # list/reveal/inherited dropped admin-only; add/delete stayed admin
        for fn in ('def handle_scoped_credentials_list(',
                   'def handle_scoped_credentials_reveal(',
                   'def handle_device_inherited_credentials('):
            i = API_SRC.index(fn)
            block = API_SRC[i:i + 500]
            self.assertNotIn('require_admin_auth()', block, fn)
        for fn in ('def handle_scoped_credentials_add(',
                   'def handle_scoped_credentials_delete('):
            i = API_SRC.index(fn)
            self.assertIn('require_admin_auth()', API_SRC[i:i + 300], fn)


class TestAgentStopped(unittest.TestCase):
    def test_events_registered(self):
        names = {e[0] for e in api.WEBHOOK_EVENTS}
        self.assertIn('agent_stopped', names)
        self.assertIn('agent_started', names)
        self.assertEqual(api._ALERT_RECOVER.get('agent_started'), 'agent_stopped')
        self.assertEqual(api._ALERT_RULES.get('agent_stopped')[0], 'high')

    def test_server_branch(self):
        self.assertIn("body.get('agent_stopping')", API_SRC)
        self.assertIn("fire_webhook('agent_stopped'", API_SRC)
        self.assertIn("fire_webhook('agent_started'", API_SRC)

    def test_agent_sends_notice(self):
        self.assertIn("'agent_stopping': True", AGENT)
        self.assertIn('signal.signal(signal.SIGTERM', AGENT)


if __name__ == '__main__':
    unittest.main()
