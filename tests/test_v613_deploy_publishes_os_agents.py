#!/usr/bin/env python3
"""v6.2.0 guardrail: EVERY server-deploy path must publish the Windows + macOS
agents, not just the Linux one.

The server serves the OS agents at /api/agent/{win,mac}/download and bakes the
Windows one-liner (/install.ps1 → handle_win_install) + cross-platform
self-update around them. handle_win_agent_download 404s when
`/var/www/remotepower/agent/remotepower-agent-win.py` is absent, and
/api/agent/win/version returns all-nulls (by design) — so a deploy that ships
only the Linux agent leaves the whole Windows onboarding DEAD end to end while
looking healthy.

This bit the live instance: every deploy path (deploy-server.sh,
install-server.sh, Dockerfile, the AUR PKGBUILD) copied ONLY
client/remotepower-agent. This test fails if any of them regresses to publishing
just the Linux agent. It reads the deploy scripts as text — they are not
executable in CI — which is the correct scope for "does the deploy copy the
file", the exact thing that broke.
"""
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_OS_AGENTS = ("remotepower-agent-win.py", "remotepower-agent-mac.py")

# (path, must-exist): the deploy artefacts that place the served agent files.
_DEPLOY_FILES = (
    "deploy-server.sh",
    "install-server.sh",
    "Dockerfile",
    "packaging/aur/remotepower-server/PKGBUILD",
)


class TestDeployPublishesOsAgents(unittest.TestCase):
    def test_os_agent_source_files_exist(self):
        for name in _OS_AGENTS:
            self.assertTrue((_ROOT / "client" / name).is_file(),
                            f"client/{name} is missing — nothing to publish")

    def test_every_deploy_path_publishes_both_os_agents(self):
        for rel in _DEPLOY_FILES:
            p = _ROOT / rel
            self.assertTrue(p.is_file(), f"{rel} not found")
            src = p.read_text()
            # Sanity: it DOES publish the Linux agent (else the assertion below
            # would be vacuous — this file isn't the one that places agents).
            self.assertIn("agent/remotepower-agent", src,
                          f"{rel} does not look like it publishes any agent")
            for name in _OS_AGENTS:
                self.assertIn(name, src,
                              f"{rel} publishes the Linux agent but NOT {name} "
                              f"— the Windows/macOS install one-liner + self-update "
                              f"will 404 on any server deployed this way")


if __name__ == "__main__":
    unittest.main()
