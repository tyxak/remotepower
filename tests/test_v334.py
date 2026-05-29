"""v3.3.4 release tests.

Strict version pins for v3.3.4. The v3.3.3 strict pins loosen to regex
when this file ships, following the same convention every prior
release-bump test followed.

v3.3.4 adds container image-update detection: the agent reports each
container's pulled image digest, and the server checks it against the
registry's current digest for that tag, flagging stale images on the
Containers page and (debounced) in the alert inbox. The behavioural
regression tests for that feature live in tests/test_image_updates.py;
this file only pins the version bump + that the feature is wired/shipped.
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """Loosened to regex — v3.4.0 now holds the strict pin (test_v340.py).
    Version-pin assertions relax to pattern-only; the v3.3.4 feature
    regression tests below stay."""

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertRegex(sw, r"'remotepower-shell-v3\.\d+\.\d+(?:-[a-z0-9]+)?'")

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertRegex(html, r'\?v=3\.\d+\.\d+')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertRegex(text, r'version-3\.\d+\.\d+-blue\.svg')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(3\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v3.x.x header')

    def test_release_notes_doc_present(self):
        # v3.3.4 release notes must stay present forever
        path = REPO_ROOT / 'docs' / 'v3.3.4.md'
        self.assertTrue(path.exists(), 'docs/v3.3.4.md is missing')
        self.assertIn('3.3.4', path.read_text())


class TestImageUpdatesShipped(unittest.TestCase):
    """The image-update detection feature must be present + wired."""

    def test_registry_module_present(self):
        path = REPO_ROOT / 'server' / 'cgi-bin' / 'image_registry.py'
        self.assertTrue(path.exists(), 'image_registry.py is missing')
        body = path.read_text()
        self.assertIn('def parse_image_ref', body)
        self.assertIn('def remote_digest', body)

    def test_scan_wired_into_dispatcher(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('def run_image_scan_if_due', api)
        self.assertIn("_safe(run_image_scan_if_due", api)
        self.assertIn("'/api/image-updates'", api)

    def test_image_update_event_registered(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'image_update_available'", api)
        self.assertIn("'image_updated'", api)

    def test_whats_new_card_mentions_image_updates(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn("What's new — v3.3.4", html)


class TestComposeStacksShipped(unittest.TestCase):
    """The compose-stacks feature (upload + deploy) must be present + wired."""

    def setUp(self):
        self.api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.agent = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.appjs = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()

    def test_server_endpoints_and_gating(self):
        self.assertIn("def handle_compose_stack_action", self.api)
        self.assertIn("def handle_compose_fetch", self.api)
        self.assertIn("def handle_device_compose_enabled", self.api)
        self.assertIn("'/api/compose/stacks'", self.api)
        # the per-device opt-in must guard deploys
        self.assertIn("compose_enabled", self.api)

    def test_agent_deploy_handler(self):
        self.assertIn("def _run_compose_deploy", self.agent)
        self.assertIn("compose_deploy:", self.agent)

    def test_ui_wired(self):
        self.assertIn('id="compose-stacks-tbody"', self.html)
        self.assertIn("function loadComposeStacks", self.appjs)
        self.assertIn("function composeStackAction", self.appjs)


class TestSynologyPollerShipped(unittest.TestCase):
    """The Synology SNMP poller must be present + wired into the sweep."""

    def test_poller_present(self):
        snmp = (REPO_ROOT / 'server' / 'cgi-bin' / 'snmp.py').read_text()
        self.assertIn('def poll_synology', snmp)
        self.assertIn('1.3.6.1.4.1.6574', snmp)

    def test_wired_into_poll_and_deep(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('poll_synology', api)
        self.assertIn("'synology'", api)


class TestAgentlessReachabilityShipped(unittest.TestCase):
    """Agentless ICMP reachability + the per-device mode control."""

    def setUp(self):
        self.api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.appjs = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()

    def test_sweep_and_helper_present(self):
        self.assertIn('def run_agentless_reachability_if_due', self.api)
        self.assertIn('def _agentless_online', self.api)
        self.assertIn('def _ping_host', self.api)
        self.assertIn("_safe(run_agentless_reachability_if_due", self.api)

    def test_ui_reachability_control(self):
        self.assertIn('id="ds-reachability"', self.appjs)
        self.assertIn('function onReachabilityModeChange', self.appjs)


class TestRouterosShipped(unittest.TestCase):
    """MikroTik RouterOS REST client + endpoints + drawer card."""

    def setUp(self):
        self.api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.appjs = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()

    def test_client_module_present(self):
        path = REPO_ROOT / 'server' / 'cgi-bin' / 'routeros.py'
        self.assertTrue(path.exists(), 'routeros.py missing')
        body = path.read_text()
        self.assertIn('def overview', body)
        self.assertIn('def action', body)
        self.assertIn('/rest', body)

    def test_endpoints_and_gating(self):
        self.assertIn('def handle_device_routeros', self.api)
        self.assertIn('def handle_device_routeros_action', self.api)
        self.assertIn("'/routeros'", self.api)
        self.assertIn('_routeros_target', self.api)

    def test_ui_card_present(self):
        self.assertIn('function _renderRouterosCard', self.appjs)
        self.assertIn('function routerosAction', self.appjs)


if __name__ == '__main__':
    unittest.main()
