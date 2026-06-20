"""v4.10.0: agent audit (read-only) mode + the SLA per-device omnisearch.

Audit mode = the agent observes/reports but never modifies the host: every
command is refused, host-config apply is refused, self-update is skipped — all
gated by an operator-owned sentinel the server can't clear. Read-only
assessments + passive collection keep running (they're off the command path).
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT = (ROOT / 'client' / 'remotepower-agent.py').read_text()
AGENT_EXT = (ROOT / 'client' / 'remotepower-agent').read_text()
WIN = (ROOT / 'client' / 'remotepower-agent-win.py').read_text()
MAC = (ROOT / 'client' / 'remotepower-agent-mac.py').read_text()
API = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
APP = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
HTML = (ROOT / 'server' / 'html' / 'index.html').read_text()


class TestAuditModeLinuxAgent(unittest.TestCase):
    def test_sentinel_and_helper(self):
        self.assertIn("AUDIT_MODE_FILE = CONF_DIR / 'audit-mode'", AGENT)
        self.assertIn("def _audit_mode():", AGENT)

    def test_execute_command_refuses(self):
        i = AGENT.index('def execute_command(cmd):')
        head = AGENT[i:i + 500]
        self.assertIn('_audit_mode()', head)
        self.assertIn('audit (read-only) mode', head)

    def test_apply_host_config_refuses(self):
        i = AGENT.index('def apply_host_config(desired):')
        self.assertIn('_audit_mode()', AGENT[i:i + 900])

    def test_self_update_skipped(self):
        i = AGENT.index('def check_for_update(')
        self.assertIn('skipping self-update', AGENT[i:i + 2200])

    def test_sysinfo_reports_flag(self):
        self.assertIn("'audit_mode': _audit_mode()", AGENT)

    def test_extensionless_in_sync(self):
        # The byte-identical guard lives in test_v3120; here just confirm the
        # gate shipped to the copy the server serves.
        self.assertIn("AUDIT_MODE_FILE = CONF_DIR / 'audit-mode'", AGENT_EXT)


class TestAuditModeWinMacParity(unittest.TestCase):
    def test_parity(self):
        for src, name in ((WIN, 'win'), (MAC, 'mac')):
            self.assertIn('def _audit_mode():', src, name)
            self.assertIn("'audit_mode': _audit_mode()", src, name)
            h = src.index('def handle_command(cmd):')
            head = src[h:h + 400]
            self.assertIn('_audit_mode()', head, name)
            self.assertIn('audit (read-only) mode', head, name)


class TestAuditModeServer(unittest.TestCase):
    def test_flag_persisted_through_sanitizer(self):
        self.assertIn("safe_si['audit_mode'] = bool(si['audit_mode'])", API)

    def test_queue_command_refuses_audit_host(self):
        i = API.index('def _queue_command(')
        block = API[i:i + 1400]
        self.assertIn("audit (read-only) mode", block)
        self.assertIn("audit_mode", block)


class TestAuditModeUi(unittest.TestCase):
    def test_device_card_badge(self):
        self.assertIn('audit_mode', APP)
        self.assertIn('AUDIT', APP)

    def test_eye_icon_defined(self):
        self.assertIn('eye:', APP)


class TestSlaOmnisearch(unittest.TestCase):
    def test_search_input_present(self):
        self.assertIn('id="sla-search"', HTML)
        self.assertIn('data-input="_renderReportsSla"', HTML)

    def test_renderer_filters(self):
        self.assertIn("document.getElementById('sla-search')", APP)


if __name__ == '__main__':
    unittest.main()
