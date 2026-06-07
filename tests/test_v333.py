"""v3.3.3 release tests.

Strict version pins for v3.3.3. The v3.3.2 strict pins loosen to regex
when this file ships, following the same convention every prior
release-bump test followed.

v3.3.3 adds a per-alert "AI Investigate" button to the Alerts inbox
(MAIN -> Alerts). Each open alert row gets an Investigate button,
aligned with the existing Ack / Resolve actions, that opens the AI
modal with a new `investigate_alert` system prompt — the model reads
the alert's severity / event / device / message and returns what it
means, the likely cause, and concrete next steps.
"""
import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

import sys
sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
import ai_provider


class TestVersionBumps(unittest.TestCase):
    """Loosened to regex — v3.3.4 now holds the strict pin (test_v334.py).
    Version-pin assertions relax to pattern-only; the v3.3.3 feature
    regression tests below stay."""

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'(\d+\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'(\d+\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertRegex(sw, r"'remotepower-shell-v\d+\.\d+\.\d+(?:-[a-z0-9]+)?'")

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertRegex(html, r'\?v=\d+\.\d+\.\d+')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertRegex(text, r'version-\d+\.\d+\.\d+-blue\.svg')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v3.x.x header')

    def test_release_notes_doc_present(self):
        # v3.3.3 release notes must stay present forever
        # notes recorded in CHANGELOG.md; per-version docs pruned to last 5
        self.assertIn('3.3.3', (REPO_ROOT / 'CHANGELOG.md').read_text())


class TestInvestigateAlertPrompt(unittest.TestCase):
    """The new investigate_alert system prompt must exist and be wired."""

    def test_prompt_registered(self):
        self.assertIn('investigate_alert', ai_provider.SYSTEM_PROMPTS,
            'investigate_alert system prompt missing from ai_provider')

    def test_prompt_is_actionable(self):
        p = ai_provider.SYSTEM_PROMPTS['investigate_alert']
        self.assertGreater(len(p), 40, 'investigate_alert prompt suspiciously short')
        # It should ask for next steps / actions, not just a paraphrase.
        self.assertRegex(p.lower(), r'(next step|steps|command|resolve|cause)',
            'investigate_alert prompt should request a likely cause + next steps')

    def test_prompt_label_present(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'investigate_alert':", api,
            'investigate_alert must have a label in _AI_PROMPT_LABELS')


class TestInvestigateAlertButton(unittest.TestCase):
    """The Alerts-inbox row must render an AI Investigate button wired to
    the aiInvestigateAlert handler, alongside Ack / Resolve."""

    def setUp(self):
        self.appjs = client_js()

    def test_handler_exists(self):
        self.assertIn('function aiInvestigateAlert(', self.appjs,
            'aiInvestigateAlert handler missing')

    def test_handler_uses_investigate_alert_system(self):
        m = re.search(r'function aiInvestigateAlert\(.*?\n(?:.*?\n){0,40}',
                      self.appjs, re.DOTALL)
        self.assertIsNotNone(m, 'aiInvestigateAlert body not found')
        self.assertIn("system:", m.group(0))
        self.assertIn("'investigate_alert'", m.group(0),
            'aiInvestigateAlert must call openAIModal with investigate_alert')

    def test_button_in_alert_row(self):
        self.assertIn('data-action="aiInvestigateAlert"', self.appjs,
            'Alert row must wire a button to aiInvestigateAlert')

    def test_button_with_ack_and_resolve(self):
        # The button is added inside the non-resolved branch, before the
        # existing ackAlert / resolveAlert buttons in the same actions cell.
        inv = self.appjs.find('data-action="aiInvestigateAlert"')
        ack = self.appjs.find('data-action="ackAlert"')
        res = self.appjs.find('data-action="resolveAlert"')
        self.assertNotEqual(inv, -1, 'Investigate button missing')
        self.assertNotEqual(ack, -1, 'ackAlert button missing')
        self.assertNotEqual(res, -1, 'resolveAlert button missing')
        self.assertTrue(inv < ack < res,
            'Investigate should render before Ack and Resolve in the alert row')
        self.assertLess(res - inv, 800,
            'Investigate/Ack/Resolve should share one alert-row actions block')


if __name__ == '__main__':
    unittest.main()
