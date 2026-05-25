#!/usr/bin/env python3
"""
Tests for v2.2.5 — UX polish.

Covers:
  1. Container max-width raised to 1300px.
  2. Tables/grids gain scroll wrap above 20 rows (CSS class +
     tableCtl auto-application).
  3. Home activity items are clickable; the routing helper covers
     every fleet event the server fires.
  4. Favicon stays at the document root; deploy script publishes it;
     no duplicate under /static/.
  5. Hover-action affordances removed (no more revealed buttons on
     row hover).
"""

import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_v225", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _AssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.css    = (_ROOT / 'server/html/static/css/styles.css').read_text()
        cls.js     = (_ROOT / 'server/html/static/js/app.js').read_text()
        cls.html   = (_ROOT / 'server/html/index.html').read_text()
        cls.deploy = (_ROOT / 'deploy-server.sh').read_text()


# ─── Fix 1: container max-width 1300px ───────────────────────────────────


class TestContainerWidth(_AssetTests):

    def test_container_max_width_1300(self):
        # The first .container block (desktop layout)
        idx = self.css.find('.container {')
        self.assertGreater(idx, 0)
        block = self.css[idx:idx + 400]
        self.assertIn('max-width: 1300px', block,
                      "container should be 1300px in v2.2.5")
        self.assertNotIn('max-width: 1100px', block,
                         "old 1100px width should be gone")


# ─── Fix 2: >20 row scroll wrap ─────────────────────────────────────────


class TestScrollWrap(_AssetTests):

    def test_scrollable_table_wrap_css(self):
        # Class exists with the right essentials
        self.assertIn('.scrollable-table-wrap', self.css)
        idx = self.css.find('.scrollable-table-wrap {')
        block = self.css[idx:idx + 500]
        self.assertIn('max-height', block)
        self.assertIn('overflow-y: auto', block)
        # Sticky header for the wrapped table
        self.assertIn('.scrollable-table-wrap thead th', self.css)
        self.assertIn('position: sticky', self.css)

    def test_scrollable_grid_wrap_css(self):
        self.assertIn('.scrollable-grid-wrap', self.css)

    def test_tablectl_applies_scroll_wrap(self):
        # tableCtl.render now toggles .scrollable-table-wrap on the
        # parent .table-card whenever rendered row count > 20.
        self.assertIn('_applyScrollWrap', self.js)
        self.assertIn('SCROLL_THRESHOLD', self.js)
        # The 20 magic number is the threshold
        scroll_block = self.js[self.js.find('function _applyScrollWrap'):]
        scroll_block = scroll_block[:scroll_block.find('}', scroll_block.find('}') + 1)]
        self.assertIn('SCROLL_THRESHOLD', scroll_block)
        # Defined as 20
        const_idx = self.js.find('const SCROLL_THRESHOLD = 20')
        self.assertGreater(const_idx, 0,
                           "SCROLL_THRESHOLD should be 20 in v2.2.5")

    def test_devices_minimal_table_scroll_wrap(self):
        # The minimal devices table render adds the wrap class
        # conditionally on its wrapper div.
        self.assertIn("'devices-minimal-wrap scrollable-table-wrap'", self.js)

    def test_devices_grid_scroll_wrap(self):
        # Card view container gets the .scrollable-grid-wrap class
        self.assertIn("classList.add('scrollable-grid-wrap')", self.js)


# ─── Fix 3: clickable activity items ────────────────────────────────────


class TestActivityClickable(_AssetTests):

    def test_activity_item_onclick(self):
        # CSP L1 (v3.0.4): the inline onclick was replaced with
        # data-action-btn="_homeNavAction" event delegation; the
        # per-event routing helper was renamed _homeActivityAction →
        # _homeActivityAttrs (returns the data-* attribute string).
        idx = self.js.find('function _renderHomeActivity')
        chunk = self.js[idx:idx + 12000]
        self.assertIn('data-action-btn="_homeNavAction"', chunk)
        self.assertIn('_homeActivityAttrs', chunk,
                      "Activity should call routing-attrs helper")

    def test_action_helper_covers_all_fleet_events(self):
        # The router switch in _homeActivityAttrs must have a case for
        # every event in the server's WEBHOOK_EVENTS tuple.
        idx = self.js.find('function _homeActivityAttrs')
        self.assertGreater(idx, 0, "_homeActivityAttrs missing")
        chunk = self.js[idx:idx + 4000]
        for ev in api.WEBHOOK_EVENT_NAMES:
            if ev == 'test':
                continue
            self.assertIn(f"case '{ev}'", chunk,
                          f"no explicit routing case for fleet event {ev!r}")

    def test_activity_item_cursor_pointer(self):
        # CSP L1: cursor:pointer is no longer inline; the class
        # `pointer` (defined in styles.css) is applied instead.
        idx = self.js.find('function _renderHomeActivity')
        chunk = self.js[idx:idx + 12000]
        self.assertIn('"dash-feed-item pointer"', chunk,
                      'activity items should carry the .pointer utility class')


# ─── Fix 4: favicon at root, deploy script publishes it ─────────────────


class TestFavicon(_AssetTests):

    def test_favicon_exists_at_root(self):
        # Real file lives at server/html/favicon.png — not under /static/
        root_path   = _ROOT / 'server/html/favicon.png'
        static_path = _ROOT / 'server/html/static/img/favicon.png'
        self.assertTrue(root_path.is_file(),
                        "favicon.png must exist at server/html/ root")
        self.assertFalse(static_path.is_file(),
                         "favicon.png should NOT have a duplicate under "
                         "static/img/ — the duplicate confuses the source "
                         "of truth")

    def test_index_html_favicon_link_resolves_to_root(self):
        # The <link> tag uses a relative path that resolves to the
        # server root (not /static/).
        self.assertIn('href="favicon.png"', self.html)
        # Make sure no rogue tag points under /static/
        self.assertNotIn('href="static/img/favicon', self.html)
        self.assertNotIn("href='static/img/favicon", self.html)

    def test_deploy_script_publishes_root_favicon(self):
        # Pre-2.2.5 the deploy script's *.html glob meant favicon.png
        # at the root never got published, so /favicon.png returned
        # 404 in the browser. v2.2.5 adds an explicit loop for root
        # non-HTML assets.
        self.assertIn('favicon.', self.deploy,
                      "deploy script must mention favicon")
        self.assertIn('install -m 644', self.deploy)


# ─── Fix 5: hover affordance removed ────────────────────────────────────


class TestHoverActionsRemoved(_AssetTests):

    def test_no_hover_actions_in_minimal_row(self):
        # The minimal devices row no longer emits a <span class="row-actions">
        idx = self.js.find('function _renderDevicesMinimal')
        # The renderRow lives in tableCtl.register up the file —
        # find the dev-row template
        chunk = self.js[self.js.find("class=\"dev-row "):
                        self.js.find("class=\"dev-row ") + 3000]
        self.assertNotIn('class="row-actions"', chunk,
                         "hover-action span should be removed from row template")
        self.assertNotIn('has-hover-actions', chunk,
                         "row should no longer carry the has-hover-actions class")

    def test_hover_action_css_neutered(self):
        # CSS rule still exists for back-compat with any HTML still
        # tagged has-hover-actions, but renders as display:none
        idx = self.css.find('tr.has-hover-actions .row-actions')
        # Find the first one (the v2.2.5 no-op)
        block = self.css[idx:idx + 200]
        self.assertIn('display: none', block,
                      "hover action strip must be invisible in v2.2.5")


if __name__ == '__main__':
    unittest.main(verbosity=2)
