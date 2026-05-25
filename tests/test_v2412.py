#!/usr/bin/env python3
"""
Tests for v2.4.12 — three dashboard fixes plus asset cache-busting.

  1. Needs Attention CVE items routed to page 'cves' — no such page
     id (it's 'cve'), so the click landed on a blank page.
  2. The "Devices online" tile counted unmonitored devices.
  3. The Virtualization page had no way to find a VM in a long list.
  4. index.html referenced app.js / styles.css with no version
     query string, so an in-place upgrade left browsers running a
     stale app.js against fresh index.html for up to an hour (the
     nginx `expires 1h` rule). Assets now carry `?v=<version>`.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent


def _server_version():
    api = (_ROOT / 'server/cgi-bin/api.py').read_text()
    m = re.search(r"SERVER_VERSION\s*=\s*'([^']+)'", api)
    assert m, 'SERVER_VERSION not found'
    return m.group(1)


class TestAttentionRouting(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = (_ROOT / 'server/html/static/js/app.js').read_text()

    def test_cve_maps_to_real_page_id(self):
        # The page element is id="page-cve" — the digest must route to
        # 'cve', not 'cves'.
        idx = self.js.find('const PAGE_FOR')
        self.assertGreater(idx, 0)
        block = self.js[idx:idx + 200]
        self.assertIn("cve: 'cve'", block)
        self.assertNotIn("cve: 'cves'", block)

    def test_all_attention_pages_exist(self):
        # Every page a digest item can route to must have a matching
        # page-<name> element in index.html.
        html = (_ROOT / 'server/html/index.html').read_text()
        idx = self.js.find('const PAGE_FOR')
        block = self.js[idx:self.js.find('}', idx)]
        for page in re.findall(r":\s*'(\w+)'", block):
            self.assertIn(f'id="page-{page}"', html,
                          f'PAGE_FOR routes to missing page-{page}')


class TestOnlineTileCount(unittest.TestCase):

    def test_tile_excludes_unmonitored(self):
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        idx = js.find('function _renderHomeTiles')
        block = js[idx:idx + 700]
        # The count must be taken from a monitored-filtered list.
        self.assertIn("monitored !== false", block)
        self.assertIn("counted", block)


class TestVirtualizationSearch(unittest.TestCase):

    def test_search_box_and_filter(self):
        html = (_ROOT / 'server/html/index.html').read_text()
        js   = (_ROOT / 'server/html/static/js/app.js').read_text()
        self.assertIn('id="virt-search"', html)
        self.assertIn('function filterVirtualization', js)
        self.assertIn('_renderVirtualizationList', js)


class TestAssetCacheBusting(unittest.TestCase):
    """The fix for stale-app.js-after-upgrade."""

    @classmethod
    def setUpClass(cls):
        cls.html = (_ROOT / 'server/html/index.html').read_text()
        cls.version = _server_version()

    def test_app_js_versioned(self):
        self.assertIn(f'static/js/app.js?v={self.version}', self.html)

    def test_styles_css_versioned(self):
        self.assertIn(f'static/css/styles.css?v={self.version}', self.html)

    def test_no_unversioned_asset_refs(self):
        # A bare reference (no ?v=) would defeat cache-busting.
        self.assertNotIn('"static/js/app.js"', self.html)
        self.assertNotIn('"static/css/styles.css"', self.html)

    def test_version_query_matches_server_version(self):
        # This is the guard: if a future release bumps SERVER_VERSION
        # but forgets the ?v= in index.html, make dist fails here
        # rather than shipping a stale-cache trap.
        for asset in ('static/js/app.js', 'static/css/styles.css'):
            m = re.search(re.escape(asset) + r'\?v=([0-9.]+)', self.html)
            self.assertIsNotNone(m, f'{asset} missing ?v=')
            self.assertEqual(m.group(1), self.version,
                             f'{asset} ?v= ({m.group(1)}) != SERVER_VERSION '
                             f'({self.version})')


if __name__ == '__main__':
    unittest.main(verbosity=2)
