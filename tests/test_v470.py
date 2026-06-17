#!/usr/bin/env python3
"""Strict version-surface pins for v4.7.0 + a light presence check of the two
headline features (containerized agent, homelab software integrations).

The deep behavioural tests live in tests/test_docker_agent.py and
tests/test_integrations.py; this file pins the release surface and loosens on
the next bump (see tests/test_v461.py for the pattern).
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v470", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_HTML = (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    """v4.7.0 — loosened to regex on the v4.8.0 bump (live strict pins moved to
    tests/test_v480.py). The feature-presence tests below stay version-agnostic."""

    def test_server_version(self):
        self.assertRegex(api.SERVER_VERSION, r'^\d+\.\d+\.\d+$')

    def test_agent_versions(self):
        self.assertRegex((_ROOT / 'client/remotepower-agent.py').read_text(),
                         r"\nVERSION\s*=\s*'\d+\.\d+\.\d+'")
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            self.assertRegex((_ROOT / rel).read_text(),
                             r"VERSION\s*=\s*'\d+\.\d+\.\d+'", rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / 'client/remotepower-agent.py').read_bytes(),
                         (_ROOT / 'client/remotepower-agent').read_bytes())

    def test_sw_and_cachebust(self):
        self.assertRegex((_ROOT / 'server/html/sw.js').read_text(),
                         r'remotepower-shell-v\d+\.\d+\.\d+')
        self.assertRegex(_HTML, r'\?v=\d+\.\d+\.\d+')

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / 'docs').glob('v*.md'))
        self.assertEqual(len(vdocs), 5, f'expected exactly 5 version docs, got {vdocs}')


class TestFeaturePresence(unittest.TestCase):
    """The two v4.7.0 features are wired into the build (deep tests elsewhere)."""

    def test_containerized_agent_artifacts(self):
        self.assertTrue((_ROOT / 'Dockerfile.agent').exists())
        self.assertTrue((_ROOT / 'docker/agent-entrypoint.sh').exists())
        self.assertTrue((_ROOT / 'docker/docker-compose.agent.yml').exists())

    def test_integrations_subsystem_wired(self):
        import integrations as I
        self.assertGreaterEqual(len(I.CONNECTORS), 20)
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/integrations'), routes)
        self.assertIn('integration_down', api.WEBHOOK_EVENT_NAMES)
        self.assertIn('integrations', api.DASHBOARD_WIDGETS)


if __name__ == '__main__':
    unittest.main()
