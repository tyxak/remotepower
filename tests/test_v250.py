#!/usr/bin/env python3
"""
Tests for v2.5.0 — Custom Monitoring Scripts.

  1. api.py: constants, CRUD handler stubs, results handler, heartbeat wiring.
  2. agent: SCRIPT_CHECK_EVERY constant, run_custom_scripts function,
     heartbeat loop state variables, custom_scripts in response handling.
  3. Frontend: sidebar nav entry, page-custom-scripts div, modal elements,
     JS functions in app.js.
  4. Docs: custom-scripts.md exists and covers required topics.
  5. Webhook events registered with correct metadata.
  6. Version consistency.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from routing_harness import routes_to

_ROOT = Path(__file__).parent.parent


def _server_version():
    api = (_ROOT / 'server/cgi-bin/api.py').read_text()
    m = re.search(r"SERVER_VERSION\s*=\s*'([^']+)'", api)
    assert m, 'SERVER_VERSION not found'
    return m.group(1)


# ── api.py: constants ─────────────────────────────────────────────────────────

class TestAPIConstants(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = (_ROOT / 'server/cgi-bin/api.py').read_text()

    def test_custom_scripts_file_defined(self):
        self.assertIn('CUSTOM_SCRIPTS_FILE', self.api)

    def test_max_custom_scripts(self):
        self.assertIn('MAX_CUSTOM_SCRIPTS', self.api)

    def test_max_scripts_per_device(self):
        self.assertIn('MAX_CUSTOM_SCRIPTS_PER_DEVICE', self.api)

    def test_max_script_body(self):
        self.assertIn('MAX_CUSTOM_SCRIPT_BODY', self.api)

    def test_max_script_output(self):
        self.assertIn('MAX_SCRIPT_OUTPUT', self.api)

    def test_script_timeout_defined(self):
        self.assertIn('CUSTOM_SCRIPT_TIMEOUT', self.api)


# ── api.py: webhook events ────────────────────────────────────────────────────

class TestWebhookEvents(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = (_ROOT / 'server/cgi-bin/api.py').read_text()

    def test_custom_script_fail_event_registered(self):
        self.assertIn("'custom_script_fail'", self.api)

    def test_custom_script_recover_event_registered(self):
        self.assertIn("'custom_script_recover'", self.api)

    def test_both_events_in_webhook_events_tuple(self):
        # Check they appear in the WEBHOOK_EVENTS tuple (has description strings)
        self.assertIn('custom_script_fail', self.api)
        self.assertIn('custom_script_recover', self.api)

    def test_custom_script_fail_in_priority_mapping(self):
        self.assertIn('custom_script_fail', self.api)

    def test_custom_script_fail_in_tags_mapping(self):
        # Tags mapping uses a dict — search the whole file
        self.assertIn("'custom_script_fail'", self.api)
        self.assertIn("test_tube", self.api)

    def test_webhook_message_handles_fail(self):
        # v3.0.2: anchor on `def _webhook_message` and scan until the next
        # top-level def/class. My v3.0.2 refactor moved the `titles` dict
        # out of `_send_webhook_to_url` AND made `_webhook_message` longer
        # than the original 2500-byte window. Brittle on both counts;
        # AST-style anchor is more robust.
        import re as _re
        m = _re.search(r'^def _webhook_message\b', self.api, _re.MULTILINE)
        self.assertIsNotNone(m, '_webhook_message function not found')
        nxt = _re.search(r'^(def [a-zA-Z]|class )', self.api[m.end():], _re.MULTILINE)
        end = m.end() + nxt.start() if nxt else len(self.api)
        block = self.api[m.start(): end]
        self.assertIn('custom_script_fail', block)
        self.assertIn('custom_script_recover', block)


# ── api.py: handlers ──────────────────────────────────────────────────────────

class TestAPIHandlers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = (_ROOT / 'server/cgi-bin/api.py').read_text()

    def test_list_handler_exists(self):
        self.assertIn('def handle_custom_scripts_list(', self.api)

    def test_get_handler_exists(self):
        self.assertIn('def handle_custom_script_get(', self.api)

    def test_create_handler_exists(self):
        self.assertIn('def handle_custom_script_create(', self.api)

    def test_update_handler_exists(self):
        self.assertIn('def handle_custom_script_update(', self.api)

    def test_delete_handler_exists(self):
        self.assertIn('def handle_custom_script_delete(', self.api)

    def test_results_handler_exists(self):
        self.assertIn('def handle_custom_scripts_results(', self.api)

    def test_ingest_helper_exists(self):
        self.assertIn('def _ingest_custom_script_results(', self.api)

    def test_get_scripts_for_device_helper(self):
        self.assertIn('def _get_custom_scripts_for_device(', self.api)

    def test_create_handler_validates_nul_bytes(self):
        idx = self.api.find('def handle_custom_script_create(')
        block = self.api[idx: idx + 3000]
        self.assertIn('\\x00', block,
                      'create handler must reject NUL bytes in script body')

    def test_create_handler_validates_body_length(self):
        idx = self.api.find('def handle_custom_script_create(')
        block = self.api[idx: idx + 3000]
        self.assertIn('MAX_CUSTOM_SCRIPT_BODY', block)

    def test_ingest_validates_device_ownership(self):
        """Results for scripts not assigned to a device must be rejected."""
        idx = self.api.find('def _ingest_custom_script_results(')
        block = self.api[idx: idx + 2000]
        self.assertIn('assigned_devices', block,
                      'ingest must check script is assigned to this device')

    def test_ingest_edge_triggered_alerts(self):
        idx = self.api.find('def _ingest_custom_script_results(')
        block = self.api[idx: idx + 6000]
        self.assertIn('fire_webhook', block)
        self.assertIn('custom_script_fail', block)
        self.assertIn('custom_script_recover', block)

    def test_ingest_no_alert_on_first_result(self):
        idx = self.api.find('def _ingest_custom_script_results(')
        block = self.api[idx: idx + 2500]
        # prev_ok is None on first run → no alert
        self.assertIn('prev_ok is None', block,
                      'first-run case must be handled to suppress initial alerts')

    def test_delete_clears_device_results(self):
        idx = self.api.find('def handle_custom_script_delete(')
        block = self.api[idx: idx + 1000]
        self.assertIn('custom_script_results', block,
                      'delete must remove stored results from device records')


# ── api.py: routing table ─────────────────────────────────────────────────────

class TestRoutingTable(unittest.TestCase):
    """Behavioural: drive the real dispatcher and assert each custom-scripts
    route reaches the right handler (was: grep the dispatcher source, which
    broke when routes moved into the _EXACT_ROUTES table even though every
    route still resolved correctly)."""

    def test_list_route(self):
        self.assertEqual(routes_to('GET', '/api/custom-scripts'),
                         'handle_custom_scripts_list')

    def test_results_route(self):
        self.assertEqual(routes_to('GET', '/api/custom-scripts/results'),
                         'handle_custom_scripts_results')

    def test_create_route(self):
        self.assertEqual(routes_to('POST', '/api/custom-scripts'),
                         'handle_custom_script_create')

    def test_update_route(self):
        self.assertEqual(routes_to('PUT', '/api/custom-scripts/abc'),
                         'handle_custom_script_update')

    def test_delete_route(self):
        self.assertEqual(routes_to('DELETE', '/api/custom-scripts/abc'),
                         'handle_custom_script_delete')

    def test_results_route_before_id_routes(self):
        """GET /results must reach the results handler, not the :id catch-all."""
        self.assertEqual(routes_to('GET', '/api/custom-scripts/results'),
                         'handle_custom_scripts_results')
        self.assertEqual(routes_to('GET', '/api/custom-scripts/some-id'),
                         'handle_custom_script_get')


# ── api.py: heartbeat wiring ──────────────────────────────────────────────────

class TestHeartbeatWiring(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = (_ROOT / 'server/cgi-bin/api.py').read_text()
        # Find handle_heartbeat
        idx = cls.api.find('def handle_heartbeat(')
        # v3.12.0: widened 50000→60000 — handle_heartbeat grew (single-row
        # device update + mount-issue sanitisation), pushing the strings this
        # test greps for past the old slice boundary.
        cls.hb = cls.api[idx: idx + 68000]   # widened (v4.2.0 host-scan dispatch + scheduled-scan hook)

    def test_custom_script_results_ingested(self):
        self.assertIn('custom_script_results', self.hb)
        self.assertIn('_ingest_custom_script_results', self.hb)

    def test_custom_scripts_in_common_resp(self):
        self.assertIn("'custom_scripts'", self.hb)
        self.assertIn('_get_custom_scripts_for_device', self.hb)


# ── agent ─────────────────────────────────────────────────────────────────────

class TestAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = (_ROOT / 'client/remotepower-agent.py').read_text()

    def test_script_check_every_constant(self):
        self.assertIn('SCRIPT_CHECK_EVERY', self.agent)

    def test_script_check_every_is_5(self):
        m = re.search(r'SCRIPT_CHECK_EVERY\s*=\s*(\d+)', self.agent)
        self.assertIsNotNone(m, 'SCRIPT_CHECK_EVERY not found')
        self.assertEqual(int(m.group(1)), 5,
                         'SCRIPT_CHECK_EVERY must be 5 (5 polls × 60 s = 5 min)')

    def test_run_custom_scripts_function_exists(self):
        self.assertIn('def run_custom_scripts(', self.agent)

    def test_run_custom_scripts_uses_temp_file(self):
        idx = self.agent.find('def run_custom_scripts(')
        block = self.agent[idx: idx + 3000]
        self.assertIn('mkstemp', block, 'must use tempfile.mkstemp for security')

    def test_run_custom_scripts_chmod_700(self):
        idx = self.agent.find('def run_custom_scripts(')
        block = self.agent[idx: idx + 3000]
        self.assertIn('S_IRWXU', block, 'temp file must be chmod 700 (S_IRWXU)')

    def test_run_custom_scripts_deletes_temp_file(self):
        idx = self.agent.find('def run_custom_scripts(')
        block = self.agent[idx: idx + 3000]
        self.assertIn('os.unlink', block, 'temp file must be deleted after execution')

    def test_run_custom_scripts_handles_timeout(self):
        idx = self.agent.find('def run_custom_scripts(')
        block = self.agent[idx: idx + 3000]
        self.assertIn('TimeoutExpired', block)

    def test_run_custom_scripts_caps_output(self):
        idx = self.agent.find('def run_custom_scripts(')
        block = self.agent[idx: idx + 3000]
        self.assertIn('4096', block, 'output must be capped at 4096 bytes')

    def test_custom_scripts_variable_in_heartbeat(self):
        idx = self.agent.find('def heartbeat(')
        block = self.agent[idx: idx + 8000]
        self.assertIn('custom_scripts', block)

    def test_pending_script_results_in_heartbeat(self):
        idx = self.agent.find('def heartbeat(')
        block = self.agent[idx: idx + 8000]
        self.assertIn('pending_script_results', block)

    def test_custom_script_results_in_payload(self):
        idx = self.agent.find('def heartbeat(')
        block = self.agent[idx: idx + 32000]
        self.assertIn("'custom_script_results'", block)

    def test_custom_scripts_updated_from_response(self):
        idx = self.agent.find('def heartbeat(')
        block = self.agent[idx: idx + 32000]
        self.assertIn("'custom_scripts' in resp", block)

    def test_script_runs_every_script_check_every_polls(self):
        idx = self.agent.find('def heartbeat(')
        block = self.agent[idx: idx + 32000]
        self.assertIn('SCRIPT_CHECK_EVERY', block)

    def test_agent_binary_in_sync(self):
        """The extensionless binary must match the .py file."""
        py  = (_ROOT / 'client/remotepower-agent.py').read_bytes()
        bin_ = (_ROOT / 'client/remotepower-agent').read_bytes()
        self.assertEqual(py, bin_,
                         'client/remotepower-agent binary is out of sync with .py')


# ── frontend ──────────────────────────────────────────────────────────────────

class TestFrontend(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = (_ROOT / 'server/html/index.html').read_text()
        cls.js   = client_js()

    def test_sidebar_nav_entry(self):
        # Custom Scripts is embedded in the Monitor page — no separate nav entry.
        # v3.0.4: inline onclick → data-page="monitor". v3.1.0: sidebar uses
        # focused sub-items via data-section-page="monitor" / data-action.
        self.assertRegex(self.html,
            r'data-(section-page|page)="monitor"')

    def test_custom_scripts_section_in_monitor_page(self):
        """Custom Scripts section must be inside page-monitor."""
        monitor_start = self.html.find('id="page-monitor"')
        monitor_end   = self.html.find('id="page-users"', monitor_start)
        monitor_block = self.html[monitor_start:monitor_end]
        self.assertIn('id="cs-results-tbody"', monitor_block,
                      'cs-results-tbody must be inside page-monitor')

    def test_page_div_exists(self):
        # The section is embedded in page-monitor (no standalone page-custom-scripts)
        self.assertIn('id="page-monitor"', self.html)

    def test_stats_bar_elements(self):
        for eid in ('cs-stat-total', 'cs-stat-running', 'cs-stat-fail', 'cs-stat-ok'):
            self.assertIn(f'id="{eid}"', self.html)

    def test_results_table_exists(self):
        self.assertIn('id="cs-results-tbody"', self.html)

    def test_modal_exists(self):
        self.assertIn('id="custom-script-modal"', self.html)

    def test_modal_body_textarea(self):
        self.assertIn('id="cs-modal-body"', self.html)

    def test_modal_device_picker(self):
        self.assertIn('id="cs-device-picker"', self.html)

    def test_modal_ai_row(self):
        self.assertIn('id="cs-ai-prompt"', self.html)
        self.assertIn('csGenerateWithAI', self.html)

    def test_output_modal_exists(self):
        self.assertIn('id="cs-output-modal"', self.html)

    def test_in_app_docs_card(self):
        self.assertIn('custom scripts', self.html.lower())
        self.assertIn('data-keywords', self.html)

    def test_load_function_in_js(self):
        self.assertIn('function loadCustomScripts(', self.js)

    def test_render_function_in_js(self):
        self.assertIn('function renderCustomScriptsPage(', self.js)

    def test_save_function_in_js(self):
        self.assertIn('function saveCustomScript(', self.js)

    def test_delete_function_in_js(self):
        self.assertIn('function deleteCustomScript(', self.js)

    def test_ai_generate_function_in_js(self):
        self.assertIn('function csGenerateWithAI(', self.js)

    def test_showpage_dispatcher_wired(self):
        # loadCustomScripts is triggered by the monitor page, not a standalone route
        self.assertIn('loadCustomScripts', self.js)
        # Should be called alongside loadDeviceMetrics on monitor page load
        monitor_dispatch_idx = self.js.find("'monitor'")
        context = self.js[monitor_dispatch_idx:monitor_dispatch_idx + 100]
        self.assertIn('loadCustomScripts', context)

    def test_ai_strips_markdown_fences(self):
        idx = self.js.find('function csGenerateWithAI(')
        block = self.js[idx: idx + 2000]
        self.assertIn('```', block,
                      'AI generator must strip markdown code fences from output')

    def test_open_cs_output_function(self):
        self.assertIn('function openCsOutput(', self.js)


# ── docs ──────────────────────────────────────────────────────────────────────

class TestDocs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.doc = (_ROOT / 'docs/custom-scripts.md').read_text()

    def test_doc_file_exists(self):
        self.assertTrue((_ROOT / 'docs/custom-scripts.md').exists())

    def test_exit_code_convention_documented(self):
        self.assertIn('Exit code', self.doc)
        self.assertIn('0', self.doc)

    def test_five_minute_cadence_documented(self):
        self.assertIn('5 minute', self.doc.replace('five minutes', '5 minute') \
                                         .replace('5-minute', '5 minute'))

    def test_alert_events_documented(self):
        self.assertIn('custom_script_fail', self.doc)
        self.assertIn('custom_script_recover', self.doc)

    def test_edge_triggered_explained(self):
        self.assertIn('edge-triggered', self.doc.lower())

    def test_security_section_present(self):
        self.assertIn('Security', self.doc)

    def test_api_reference_present(self):
        self.assertIn('/api/custom-scripts', self.doc)

    def test_example_scripts_present(self):
        self.assertIn('#!/bin/bash', self.doc)

    def test_timeout_documented(self):
        self.assertIn('30', self.doc)

    def test_features_md_mentions_custom_scripts(self):
        features = (_ROOT / 'docs/features.md').read_text()
        self.assertIn('Custom', features)
        self.assertIn('custom-scripts.md', features)

    def test_readme_mentions_custom_scripts(self):
        readme = (_ROOT / 'README.md').read_text()
        self.assertIn('Custom', readme)

    def test_changelog_has_v250_entry(self):
        cl = (_ROOT / 'CHANGELOG.md').read_text()
        self.assertIn('v2.5.0', cl)
        self.assertIn('Custom monitoring scripts', cl)


# ── version consistency ───────────────────────────────────────────────────────

class TestVersionConsistency(unittest.TestCase):

    def setUp(self):
        self.ver = _server_version()

    def _agent_ver(self, path):
        text = path.read_text()
        m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m)
        return m.group(1)

    def test_agent_py(self):
        self.assertEqual(self._agent_ver(_ROOT / 'client/remotepower-agent.py'), self.ver)

    def test_agent_binary(self):
        self.assertEqual(self._agent_ver(_ROOT / 'client/remotepower-agent'), self.ver)

    def test_readme_badge(self):
        readme = (_ROOT / 'README.md').read_text()
        m = re.search(r'version-([0-9.]+)-blue', readme)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), self.ver)

    def test_changelog_top_entry(self):
        cl = (_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v([0-9.]+)', cl, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), self.ver)

    def test_cache_busting(self):
        html = (_ROOT / 'server/html/index.html').read_text()
        for asset in ('static/js/app.js', 'static/css/styles.css'):
            m = re.search(re.escape(asset) + r'\?v=([0-9.]+)', html)
            self.assertIsNotNone(m, f'{asset} missing ?v=')
            self.assertEqual(m.group(1), self.ver)

    def test_sw_cache_name(self):
        sw = (_ROOT / 'server/html/sw.js').read_text()
        self.assertIn(self.ver, sw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
