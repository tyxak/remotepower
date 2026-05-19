#!/usr/bin/env python3
"""
Tests for v2.4.14 — Pending Reboot indicator on the Patches page.

  1. handle_patch_report() in api.py includes a boolean
     `reboot_required` field for every device entry.
  2. The field is sourced safely from sysinfo — absent / non-bool
     values coerce to False rather than leaking raw data.
  3. app.js _registerPatchTable() renders the amber ⟳ Reboot badge
     when reboot_required is truthy.
  4. The badge carries an accessible title / tooltip.
  5. docs/features.md contains AI assistant and MCP server sections
     (previously missing).
  6. Cache-busting ?v= strings match SERVER_VERSION.
  7. Version strings are consistent across api.py, agent, agent
     binary, README, and CHANGELOG.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent


# ── helpers ──────────────────────────────────────────────────────────────────

def _server_version():
    api = (_ROOT / 'server/cgi-bin/api.py').read_text()
    m = re.search(r"SERVER_VERSION\s*=\s*'([^']+)'", api)
    assert m, 'SERVER_VERSION not found in api.py'
    return m.group(1)


def _agent_version(path):
    text = path.read_text()
    m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
    assert m, f'VERSION not found in {path.name}'
    return m.group(1)


# ── api.py: patch report includes reboot_required ────────────────────────────

class TestPatchReportAPIField(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = (_ROOT / 'server/cgi-bin/api.py').read_text()

    def _patch_report_block(self):
        """Return the source of handle_patch_report()."""
        idx = self.api.find('def handle_patch_report():')
        self.assertGreater(idx, 0, 'handle_patch_report not found')
        # Grab enough lines to cover the entry dict construction.
        return self.api[idx: idx + 3000]

    def test_reboot_required_in_entry_dict(self):
        block = self._patch_report_block()
        self.assertIn("'reboot_required'", block,
                      "patch report entry missing 'reboot_required' key")

    def test_reboot_required_bool_cast(self):
        """Value must be bool()-cast so non-bool sysinfo values are safe."""
        block = self._patch_report_block()
        self.assertIn("bool(si.get('reboot_required'", block,
                      "reboot_required must be bool()-cast from sysinfo")

    def test_reboot_required_default_false(self):
        """Absent key must default to False, not None / KeyError."""
        block = self._patch_report_block()
        # Expect bool(si.get('reboot_required', False))
        self.assertIn("'reboot_required', False", block,
                      "missing default=False in si.get('reboot_required', ...)")

    def test_handle_patch_report_device_present(self):
        """Single-device endpoint still exists (regression guard)."""
        self.assertIn('def handle_patch_report_device(', self.api)


# ── app.js: reboot badge rendered in patch table row ─────────────────────────

class TestPatchTableRebootBadge(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = (_ROOT / 'server/html/static/js/app.js').read_text()

    def _register_patch_block(self):
        idx = self.js.find('function _registerPatchTable(')
        self.assertGreater(idx, 0, '_registerPatchTable not found')
        end = self.js.find('\nfunction ', idx + 1)
        return self.js[idx:end]

    def test_reboot_required_checked_in_row(self):
        block = self._register_patch_block()
        self.assertIn('reboot_required', block,
                      'reboot_required not referenced in _registerPatchTable row')

    def test_reboot_badge_label(self):
        """Badge must contain the text 'Reboot'."""
        block = self._register_patch_block()
        self.assertIn('Reboot', block,
                      "Reboot label not found in patch table row renderer")

    def test_reboot_badge_has_tooltip(self):
        """Badge must have a title= attribute for accessibility."""
        block = self._register_patch_block()
        self.assertIn('title=', block,
                      'reboot badge missing title= tooltip')

    def test_reboot_badge_amber_colour(self):
        """Badge should use the amber colour token for visual consistency."""
        block = self._register_patch_block()
        self.assertIn('amber', block,
                      'reboot badge missing amber colour reference')

    def test_reboot_badge_only_when_true(self):
        """Badge must be conditional — only rendered when reboot_required."""
        block = self._register_patch_block()
        # The ternary / conditional must reference reboot_required
        # and produce an empty string ('') for the false branch.
        self.assertIn('rebootBadge', block)
        self.assertIn("? `", block)   # ternary true branch (template literal)

    def test_name_cell_contains_badge(self):
        """The badge variable must be interpolated into the name <td>."""
        block = self._register_patch_block()
        # escHtml(d.name) and ${rebootBadge} must appear in the same cell.
        name_td_idx = block.find("escHtml(d.name)")
        self.assertGreater(name_td_idx, 0)
        name_td = block[name_td_idx: name_td_idx + 80]
        self.assertIn('rebootBadge', name_td,
                      '${rebootBadge} not inside the name <td>')


# ── docs/features.md: AI and MCP sections present ────────────────────────────

class TestFeaturesMdCompleteness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.md = (_ROOT / 'docs/features.md').read_text()

    def test_ai_assistant_section_present(self):
        self.assertIn('AI assistant', self.md,
                      'AI assistant section missing from features.md')

    def test_ai_providers_listed(self):
        for provider in ('Ollama', 'LocalAI', 'Anthropic', 'OpenAI', 'DeepSeek'):
            self.assertIn(provider, self.md,
                          f'AI provider {provider} not mentioned in features.md')

    def test_mcp_server_section_present(self):
        self.assertIn('MCP server', self.md,
                      'MCP server section missing from features.md')

    def test_mcp_read_only_policy_documented(self):
        self.assertIn('No write tools', self.md,
                      'MCP no-write-tools policy not documented')

    def test_pending_reboot_indicator_documented(self):
        self.assertIn('Pending Reboot', self.md,
                      'Pending Reboot indicator not documented in features.md')

    def test_ai_link_to_ai_md(self):
        """features.md should cross-link to the full docs/ai.md."""
        self.assertIn('ai.md', self.md,
                      'features.md missing cross-link to ai.md')


# ── version consistency ───────────────────────────────────────────────────────

class TestVersionConsistency(unittest.TestCase):

    def setUp(self):
        self.ver = _server_version()

    def test_agent_py_version_matches(self):
        agent_ver = _agent_version(_ROOT / 'client/remotepower-agent.py')
        self.assertEqual(agent_ver, self.ver,
                         'remotepower-agent.py VERSION mismatch')

    def test_agent_binary_version_matches(self):
        agent_ver = _agent_version(_ROOT / 'client/remotepower-agent')
        self.assertEqual(agent_ver, self.ver,
                         'client/remotepower-agent (binary) VERSION mismatch')

    def test_readme_badge_version_matches(self):
        readme = (_ROOT / 'README.md').read_text()
        m = re.search(r'version-([0-9.]+)-blue', readme)
        self.assertIsNotNone(m, 'version badge missing from README')
        self.assertEqual(m.group(1), self.ver,
                         'README version badge mismatch')

    def test_changelog_top_entry_matches(self):
        cl = (_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v([0-9.]+)', cl, re.MULTILINE)
        self.assertIsNotNone(m, 'No version heading in CHANGELOG')
        self.assertEqual(m.group(1), self.ver,
                         'CHANGELOG top entry does not match SERVER_VERSION')

    def test_cache_bust_strings_match(self):
        html = (_ROOT / 'server/html/index.html').read_text()
        for asset in ('static/js/app.js', 'static/css/styles.css'):
            m = re.search(re.escape(asset) + r'\?v=([0-9.]+)', html)
            self.assertIsNotNone(m, f'{asset} missing ?v= in index.html')
            self.assertEqual(m.group(1), self.ver,
                             f'{asset} ?v= mismatch vs SERVER_VERSION')


if __name__ == '__main__':
    unittest.main(verbosity=2)
