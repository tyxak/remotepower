"""v4.10.0: agent audit (read-only) mode + the SLA per-device omnisearch.

Audit mode = the agent observes/reports but never modifies the host: every
command is refused, host-config apply is refused, self-update is skipped — all
gated by an operator-owned sentinel the server can't clear. Read-only
assessments + passive collection keep running (they're off the command path).
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from srcpin import py_function  # noqa: E402  (growth-proof source pins)

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
        # The guard's position inside execute_command keeps moving (files: and
        # files:archive: dispatch ahead of it, each with its own audit policy),
        # which used to mean re-widening a head window every release. Pin the
        # whole def instead.
        body = py_function(AGENT, 'execute_command')
        self.assertIn('_audit_mode()', body)
        self.assertIn('audit (read-only) mode', body)

    def test_apply_host_config_refuses(self):
        self.assertIn('_audit_mode()', py_function(AGENT, 'apply_host_config'))

    def test_self_update_skipped(self):
        self.assertIn('skipping self-update', py_function(AGENT, 'check_for_update'))

    def test_sysinfo_reports_flag(self):
        self.assertIn("'audit_mode': _audit_mode()", AGENT)

    def test_extensionless_in_sync(self):
        # The byte-identical guard lives in test_v3120; here just confirm the
        # gate shipped to the copy the server serves.
        self.assertIn("AUDIT_MODE_FILE = CONF_DIR / 'audit-mode'", AGENT_EXT)


class TestAuditModeWinMacParity(unittest.TestCase):
    def test_parity(self):
        # The Win/Mac agents expose _audit_mode() and report it in sysinfo.
        for src, name in ((WIN, 'win'), (MAC, 'mac')):
            self.assertIn('def _audit_mode():', src, name)
            self.assertIn("'audit_mode': _audit_mode()", src, name)

    def test_handle_command_refuses_in_audit_mode(self):
        """v6.2.0: DRIVEN, not grepped.

        This used to slice handle_command's source [def : def+400] and assert
        '_audit_mode()' appeared inside it. A defensive non-string guard added to
        the Windows handler (with its explanatory comment) pushed the audit check
        past the 400-char window — the behaviour was unchanged, the source WINDOW
        moved. That is the fixed-size-source-window fragility again: drive the
        handler instead of pinning where a string sits.
        """
        import importlib.util
        import os
        import tempfile
        for rel, modname in (('client/remotepower-agent-win.py', 'rp_win_audit'),
                             ('client/remotepower-agent-mac.py', 'rp_mac_audit')):
            os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v4100-agent-audit-')
            spec = importlib.util.spec_from_file_location(modname, ROOT / rel)
            ag = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ag)
            # Stub the marker check (each agent's own suite covers the marker
            # mechanism; the win/mac data-dir conventions differ). The behaviour
            # under test is: audit mode ON → handle_command REFUSES, not runs.
            ag._audit_mode = lambda: True
            r = ag.handle_command('exec:whoami')
            self.assertIsInstance(r, dict, modname)
            self.assertEqual(r.get('rc'), 126, modname)
            self.assertIn('audit', (r.get('output') or '').lower(), modname)


class TestAuditModeServer(unittest.TestCase):
    def test_flag_persisted_through_sanitizer(self):
        self.assertIn("safe_si['audit_mode'] = bool(si['audit_mode'])", API)

    def test_queue_command_refuses_audit_host(self):
        """v6.2.0: DRIVEN, not grepped.

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
