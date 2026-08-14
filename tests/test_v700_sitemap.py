#!/usr/bin/env python3
"""The product map must be DERIVED from the sidebar, never a second list.

89 pages across 12 domains, with the sidebar accordion showing one domain at a
time, left no surface answering "what is in this product and where". The command
palette and the sidebar search both require already knowing what to type.

The map is built from the sidebar DOM at open time. That is the whole design
decision, and it is the one worth protecting: a hand-kept copy of the page list
would be a second registry, and every recurring bug in this project's notes is
two registries drifting apart — FLEET_EVENTS against the server's event set,
DASH_WIDGETS against DASHBOARD_WIDGETS, the scheduler's CADENCE against main().

Deriving it buys three things for free:

* a page added tomorrow appears with no edit to the map code;
* a page hidden by a module gate is absent, because it is hidden in the sidebar;
* the one-line description is the nav button's own `title`, which already exists
  on all 82 of them and is already the text an operator sees on hover.

So this file mostly checks that the derivation is still a derivation.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text(encoding='utf-8')
# v7.0.0: the renderer moved to its own LAZY module — 4,438 bytes that run only
# when the dialog opens, and the eager JS payload has a hard budget it would
# otherwise have blown by 4,221. app.js keeps a loader stub. Both files are
# searched together below, because "is this derived from the sidebar" is a
# property of the feature, not of which file happens to hold it.
_MOD = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-sitemap.js').read_text(encoding='utf-8')
_JS = _APP + '\n' + _MOD
_CSS = (_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text(encoding='utf-8')


class TestTheSourceOfTruthIsTheSidebar(unittest.TestCase):

    def test_every_nav_button_carries_a_description(self):
        """The map's second line IS this attribute. A button without one would
        render a card with a name and nothing to recognise it by, which is what
        the sidebar already offers."""
        btns = re.findall(r'<button[^>]*class="nav-btn[^"]*"[^>]*>', _HTML)
        self.assertGreater(len(btns), 70, f'only {len(btns)} nav buttons found')
        missing = [b[:90] for b in btns if 'title=' not in b]
        self.assertEqual(
            missing, [],
            'these nav buttons have no title, so their card in the map has no '
            'description:\n' + '\n'.join('  ' + m for m in missing))

    def test_the_renderer_reads_the_dom_not_a_list(self):
        fn = _JS[_JS.index('function _sitemapGroups'):]
        fn = fn[:fn.index('\nfunction ')]
        self.assertIn('querySelectorAll', fn)
        self.assertIn(".nav-btn[data-page]", fn)
        self.assertIn("getAttribute('title')", fn)

    def test_there_is_no_second_page_list(self):
        """A literal array of page names next to the renderer would be the
        registry this design exists to avoid."""
        fn = _JS[_JS.index('function _sitemapGroups'):]
        fn = fn[:fn.index('\nfunction renderSitemap')]
        # A page-name array would look like ['home', 'devices', ...]
        self.assertNotRegex(
            fn, r"\[\s*'[a-z-]+'\s*,\s*'[a-z-]+'\s*,\s*'[a-z-]+'",
            'the map appears to carry its own list of pages')

    def test_hidden_pages_are_excluded(self):
        """Module-gated pages are hidden in the sidebar; the map must respect
        that rather than advertising a page whose API answers 404."""
        fn = _JS[_JS.index('function _sitemapGroups'):]
        fn = fn[:fn.index('\nfunction renderSitemap')]
        self.assertIn("classList.contains('hidden')", fn)
        self.assertIn("display", fn)


class TestTheEntryPointsExist(unittest.TestCase):

    def test_the_sidebar_has_a_way_in(self):
        self.assertIn('data-action="openSitemap"', _HTML)

    def test_the_actions_resolve_to_functions(self):
        for name in ('openSitemap', 'sitemapGo', 'renderSitemap',
                     'expandAllSidebarGroups'):
            self.assertRegex(_JS, rf'\b(?:async )?function {name}\s*\(',
                             f'data-action="{name}" resolves to nothing')

    def test_the_modal_is_at_body_level(self):
        """CLAUDE.md: a fixed full-screen overlay nested inside .container has
        its z-index sealed inside a stacking context and cannot rise above the
        sidebar."""
        i = _HTML.index('id="sitemap-modal"')
        self.assertIn('</div><!-- /app -->', _HTML[:i],
                      'the map dialog is inside .container — it will render '
                      'under the sidebar at narrow widths')

    def test_the_filter_input_is_labelled(self):
        i = _HTML.index('id="sitemap-filter"')
        tag = _HTML[i - 200:i + 200]
        self.assertIn('aria-label', tag)


class TestTheSidebarAllowsMoreThanOneOpenGroup(unittest.TestCase):

    def test_the_stored_state_is_a_set(self):
        self.assertIn('_SIDEBAR_OPEN_KEY', _APP)  # sidebar state stays eager
        fn = _APP[_APP.index('function _openGroupSet'):]
        fn = fn[:fn.index('\nfunction ')]
        self.assertIn('new Set', fn)

    def test_the_legacy_single_group_key_is_migrated(self):
        """Someone upgrading has a group open. Discarding the old key would
        close it for no reason they can see."""
        fn = _APP[_APP.index('function _openGroupSet'):]
        fn = fn[:fn.index('\nfunction ')]
        self.assertIn("'sidebar.open_group'", fn)

    def test_navigating_does_not_close_what_you_opened(self):
        """_openSidebarGroup is called on navigation to reveal the active
        page's domain. If it replaced the set rather than adding to it, every
        click would collapse the groups you deliberately left open."""
        fn = _APP[_APP.index('function _openSidebarGroup'):]
        fn = fn[:fn.index('\nfunction ')]
        self.assertIn('set.add', fn)
        self.assertNotIn('new Set([name])', fn)

    def test_expand_all_also_collapses(self):
        fn = _APP[_APP.index('function expandAllSidebarGroups'):]
        fn = fn[:fn.index('\n}') + 2]
        self.assertIn('new Set()', fn,
                      'the control expands but never collapses — an operator '
                      'who wants the tidy rail back has to click 12 times')


class TestTheCardsAreReadable(unittest.TestCase):

    def test_the_description_is_clamped(self):
        """A long title must not make one card twice the height of its
        neighbours and break the grid's rhythm."""
        i = _CSS.index('.sitemap-card-desc')
        self.assertIn('line-clamp', _CSS[i:i + 400])

    def test_the_body_scrolls(self):
        i = _HTML.index('id="sitemap-body"')
        self.assertIn('scroll-cap', _HTML[i:i + 120],
                      '77 cards with no cap is the box-overflow rule broken in '
                      'the one dialog whose whole job is to list everything')


if __name__ == '__main__':
    unittest.main()
