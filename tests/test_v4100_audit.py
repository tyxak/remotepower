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
        # v5.1.0: a `files:` op is dispatched BEFORE the blanket guard (it carries
        # its own audit policy — reads allowed, mutations refused), so the blanket
        # _audit_mode() guard moved a few lines down; widen the head window.
        # v6.1.1: files:archive: dispatched even earlier still (its own channel,
        # see _handle_file_archive) pushed the guard further down again.
        head = AGENT[i:i + 1200]
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
        """v6.1.3: DRIVEN, not grepped.

        This used to assert the string "audit (read-only) mode" appeared within
        1400 chars of `def _queue_command(`. When the three command gates were
        factored into the shared `_command_block_reason` predicate — so the
        post-approval executor would stop enforcing only a subset of them — the
        grep broke while the behaviour it guarded got strictly stronger. The grep
        was pinning the gate's ADDRESS, not the gate. So drive the gate.
        """
        import importlib.util
        import os
        import tempfile
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v4100-audit-'))
        spec = importlib.util.spec_from_file_location(
            'api_v4100_audit', ROOT / 'server' / 'cgi-bin' / 'api.py')
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)

        audit_host = {'name': 'web01', 'sysinfo': {'audit_mode': True}}
        blocked = api._command_block_reason(audit_host, 'exec:whoami')
        self.assertIsNotNone(blocked, 'an audit-mode host must refuse commands')
        self.assertEqual(409, blocked[0])
        self.assertIn('audit (read-only) mode', blocked[1])
        # A normal host is not blocked…
        self.assertIsNone(api._command_block_reason({'name': 'web01'}, 'exec:whoami'))
        # …and poll_interval stays exempt even on an audit host (agent-local timer).
        self.assertIsNone(api._command_block_reason(audit_host, 'poll_interval:300'))


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
