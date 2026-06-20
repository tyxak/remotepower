"""v4.10.0: backup integrity verification + per-site (customer) reports."""
import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))
_spec = importlib.util.spec_from_file_location("api_feat2", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

API_SRC = (_CGI_BIN / "api.py").read_text()
AGENT = (_ROOT / "client" / "remotepower-agent.py").read_text()
APP = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()


class TestBackupVerifyAgent(unittest.TestCase):
    def test_tool_detection(self):
        i = AGENT.index('def _detect_backup_tool(')
        self.assertIn('restic', AGENT[i:i + 600])
        self.assertIn('collect_backup_verify', AGENT)
        # wired into the heartbeat payload
        self.assertIn("payload['backup_verify']", AGENT)


class TestBackupVerifyServer(unittest.TestCase):
    def test_events_registered(self):
        names = {e[0] for e in api.WEBHOOK_EVENTS}
        self.assertIn('backup_verify_failed', names)
        self.assertIn('backup_verified', names)
        self.assertEqual(api._ALERT_RECOVER.get('backup_verified'), 'backup_verify_failed')
        self.assertEqual(api._ALERT_RULES.get('backup_verify_failed')[0], 'high')

    def test_config_schema(self):
        # backup_monitors validation accepts the verify fields
        i = API_SRC.index("if 'backup_monitors' in body:")
        block = API_SRC[i:i + 900]
        self.assertIn('verify_enabled', block)
        self.assertIn("'tool'", block)

    def test_heartbeat_ingest(self):
        self.assertIn("body.get('backup_verify')", API_SRC)
        self.assertIn("fire_webhook('backup_verify_failed'", API_SRC)

    def test_endpoint_surfaces_verify(self):
        i = API_SRC.index('def handle_device_backups(')
        self.assertIn('verify_status', API_SRC[i:i + 2000])


class TestPerSiteReport(unittest.TestCase):
    def test_builder_accepts_site_id(self):
        import inspect
        self.assertIn('site_id', inspect.signature(api._build_fleet_report).parameters)

    def test_route_registered(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route('GET', '/api/report/site/abc')[0], 'handle_site_report')

    def test_ui_button_and_fn(self):
        self.assertIn('downloadSiteReport', APP)
        self.assertIn('/api/report/site/', APP)


class TestHealthGatedRollouts(unittest.TestCase):
    HTML = (_ROOT / "server" / "html" / "index.html").read_text()

    def test_event_registered(self):
        self.assertIn('rollout_halted', {e[0] for e in api.WEBHOOK_EVENTS})
        self.assertEqual(api._ALERT_RULES.get('rollout_halted')[0], 'high')

    def test_create_accepts_health_gate(self):
        i = API_SRC.index('def handle_rollouts_create(')
        self.assertIn('health_gate', API_SRC[i:i + 3000])

    def test_advance_has_gate_and_pending(self):
        i = API_SRC.index('def _rollout_advance(')
        block = API_SRC[i:i + 4500]
        self.assertIn("hg.get('enabled')", block)
        self.assertIn("pending.append(('rollout_halted'", block)
        # fire happens AFTER the lock in _rollout_tick (no lock-nesting)
        j = API_SRC.index('def _rollout_tick(')
        tick = API_SRC[j:j + 1500]
        self.assertIn('fire_webhook(_ev, _pl)', tick)

    def test_ui_inputs(self):
        self.assertIn('id="ro-health-gate"', self.HTML)
        self.assertIn('health_gate', APP)
        # no inline style= in the new modal markup (CSP)
        idx = self.HTML.find('id="ro-health-gate"')
        self.assertNotIn('style=', self.HTML[idx - 200:idx + 400])


if __name__ == '__main__':
    unittest.main()
