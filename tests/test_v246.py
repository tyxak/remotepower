#!/usr/bin/env python3
"""
Tests for v2.4.6 — documentation audit + update notice with commands.

This release is mostly content (the doc audit and the admin guide).
These tests guard that the documentation actually covers the recent
features, and that the update banner now carries update steps.
"""

import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent


class TestFeaturesDoc(unittest.TestCase):
    """docs/features.md was stale — it predated the 2.2-2.4 work."""

    @classmethod
    def setUpClass(cls):
        cls.text = (_ROOT / 'docs' / 'features.md').read_text().lower()

    def test_covers_recent_features(self):
        # The gap the audit closed: these had zero mentions before.
        for topic in ('proxmox', 'drift', 'mailbox', 'snapshot',
                      'scan packages', 'ssh username', 'mcp'):
            self.assertIn(topic, self.text,
                          f'features.md does not mention {topic!r}')


class TestAdminGuide(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.path = _ROOT / 'docs' / 'admin-guide.md'

    def test_admin_guide_exists(self):
        self.assertTrue(self.path.exists(), 'docs/admin-guide.md missing')

    def test_admin_guide_covers_operations(self):
        text = self.path.read_text().lower()
        for section in ('installing the server', 'installing agents',
                        'hardening', 'backup', 'upgrading',
                        'troubleshooting'):
            self.assertIn(section, text,
                          f'admin guide missing section: {section}')


class TestDocCards(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = (_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_scan_packages_doc_card(self):
        # The one in-app Documentation gap from the audit.
        self.assertIn('Scan packages now', self.html)

    def test_doc_cards_well_formed(self):
        self.assertEqual(self.html.count('<details'),
                         self.html.count('</details>'))


class TestUpdateBanner(unittest.TestCase):
    """The update-available detection already existed; 2.4.6 makes the
    banner show the actual update commands, not just a link."""

    @classmethod
    def setUpClass(cls):
        cls.js  = (_ROOT / 'server/html/static/js/app.js').read_text()
        cls.css = (_ROOT / 'server/html/static/css/styles.css').read_text()

    def test_banner_shows_update_commands(self):
        idx = self.js.find('function checkServerVersion')
        chunk = self.js[idx:idx + 1400]
        self.assertIn('install-server.sh', chunk)
        self.assertIn('update-steps', chunk)

    def test_banner_states_no_self_update(self):
        # The banner must be honest that this is a manual step.
        idx = self.js.find('function checkServerVersion')
        chunk = self.js[idx:idx + 1400]
        self.assertIn('does not update itself', chunk)

    def test_toggle_function_present(self):
        self.assertIn('function toggleUpdateSteps', self.js)

    def test_banner_styling_present(self):
        self.assertIn('update-steps-btn', self.css)

    def test_no_duplicate_version_handler(self):
        # A duplicate handler was created and removed during development —
        # guard that exactly one definition exists.
        api = (_ROOT / 'server/cgi-bin/api.py').read_text()
        self.assertEqual(api.count('def handle_version_check'), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
