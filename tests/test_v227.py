#!/usr/bin/env python3
"""
Tests for v2.2.7 — mobile sidebar hotfix.

The mobile drawer was unusable: below 720px both the 720px drawer
block and a leftover 768px icon-rail block applied, producing a wide
240px drawer with all nav labels hidden and the icons shoved down by
a 72px top padding. This release deletes the icon-rail block and has
the drawer block explicitly restore labels / alignment / padding.
"""

import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent


class TestMobileDrawerFix(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.css = (_ROOT / 'server/html/static/css/styles.css').read_text()

    def test_icon_rail_block_removed(self):
        # The 56px icon-rail that collided with the drawer is gone.
        self.assertNotIn('.sidebar { width: 56px;', self.css,
                          'the conflicting 768px icon-rail must be removed')
        # And the label-hiding rule that came with it
        self.assertNotIn('.sidebar .nav-btn span, .sidebar .sidebar-label { display: none; }',
                         self.css)

    def test_drawer_restores_labels(self):
        # The drawer block explicitly re-shows nav labels + section headers
        self.assertIn('.sidebar .sidebar-label { display: block; }', self.css)
        self.assertIn('.sidebar .nav-btn span', self.css)

    def test_drawer_left_aligns_nav(self):
        # Nav buttons left-aligned again (rail had centred them as icons)
        self.assertIn('justify-content: flex-start;', self.css)

    def test_drawer_sane_top_padding(self):
        # The drawer block overrides the rail's 72px top padding.
        idx = self.css.find('@media (max-width: 720px)')
        block = self.css[idx:idx + 1400]
        self.assertIn('padding: 12px 10px 16px;', block,
                      'drawer should reset the oversized rail padding')
        # The actual rail padding declaration `72px 6px 16px` must not
        # survive as a live rule (mentioning it in a comment is fine).
        self.assertNotIn('padding: 72px', block)

    def test_braces_balanced(self):
        self.assertEqual(self.css.count('{'), self.css.count('}'),
                         'CSS brace mismatch')

    def test_content_margin_reset_on_mobile(self):
        # Content must not keep a left margin for a now-removed rail
        idx = self.css.find('@media (max-width: 720px)')
        block = self.css[idx:idx + 3000]
        self.assertIn('.app-content { margin-left: 0', block)


if __name__ == '__main__':
    unittest.main(verbosity=2)
