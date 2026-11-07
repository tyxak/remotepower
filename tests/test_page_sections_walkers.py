#!/usr/bin/env python3
"""Every browser test that walks the pages runs with One long page chosen, so a card behind a tab is still in what it measures.

A page with tabs shows one group of cards and hides the rest, and a walk that reads "what is visible" then reads a third of the
page and passes. Threat Intel, My Account, Sites and Reports had that blind spot since 7.4.0; eleven more pages gained tabs with
the page sections change, so every whole-page walker sets `rp_pagetabs` to `stacked` in its browser context before it starts
(My Account > Appearance > Page sections writes the same key). The tests of the tabs themselves are the two exceptions below.

The population is derived, not listed: a test module that loops over pages (a `for` whose body shows a page) and opens a browser.
A new walker that forgets the line fails here. The control is that the derivation finds the walkers there are.

The same choice is made by every other browser test that signs in to the app (they all set `rp_tour_done`): a feature test that
clicks a card on a page whose cards are now behind tabs would otherwise find it hidden, and the next page to gain tabs would break
tests nobody expected. They test features, not layout; the two tests of the tabs themselves are the exceptions.
"""
import ast
import re
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
# modules that test the tabs, and so must see them
EXEMPT = {
    'test_v740_page_tabs_e2e.py': 'tests the strip and its tiles on the four pages that had them in 7.4.0',
    'test_page_sections_e2e.py': 'tests the tabs, the one-long-page switch and the cards a tab hides',
}
# a context or a page opened straight from the browser (a page made from a context inherits the context's init script)
_OPEN = re.compile(r'\.new_context\(|\b[\w.]*browser[\w.]*\.new_page\(\)', re.I)
_SHOWS_A_PAGE = ('showPage', 'data-page', 'nav-btn')


def _walks_pages(src):
    """True when the source has a loop whose body shows a page."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            seg = ast.get_source_segment(src, node) or ''
            if any(tok in seg for tok in _SHOWS_A_PAGE):
                return True
    return False


def walkers(root=_TESTS):
    out = {}
    for p in sorted(root.glob('*.py')):
        src = p.read_text(encoding='utf-8')
        if _OPEN.search(src) and _walks_pages(src):
            out[p.name] = src
    return out


def app_tests(root=_TESTS):
    """Browser tests that sign in to the app: they use playwright and set rp_tour_done so the tour does not cover the page.
    (A source test that only looks for the string in app.js, test_v541, is not one.)"""
    out = {}
    for p in sorted(root.glob('*.py')):
        src = p.read_text(encoding='utf-8')
        if 'rp_tour_done' in src and 'playwright' in src:
            out[p.name] = src
    return out


def short_of_the_line(src):
    """How many browser contexts or pages the source opens beyond the number of times it sets the preference."""
    return max(0, len(_OPEN.findall(src)) - len(re.findall(r"rp_pagetabs", src)))


class TestEveryWalkerSeesEveryCard(unittest.TestCase):
    def test_every_walker_sets_the_preference_for_each_browser_it_opens(self):
        found = walkers()
        bad = {n: short_of_the_line(s) for n, s in found.items() if n not in EXEMPT and short_of_the_line(s)}
        self.assertEqual(bad, {}, 'a walker opens a browser without choosing One long page: add '
                                  "ctx.add_init_script(\"try { localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}\")")

    def test_every_browser_test_of_the_app_chooses_one_long_page(self):
        found = app_tests()
        bad = sorted(n for n, src in found.items() if n not in EXEMPT and 'rp_pagetabs' not in src)
        self.assertEqual(bad, [], "a browser test that signs in opens the app with tabs on: add localStorage.setItem('rp_pagetabs', 'stacked') "
                                  "beside rp_tour_done, or list it in EXEMPT if it tests the tabs")
        self.assertGreaterEqual(len(found), 35, 'control: the derivation found the browser tests there are')

    def test_the_derivation_finds_the_walkers_there_are(self):
        found = walkers()
        self.assertGreaterEqual(len(found) - len(set(found) & set(EXEMPT)), 17, sorted(found))
        for name in ('test_a11y_axe.py', 'test_v630_e2e_page_smokes.py', 'test_v640_e2e_click_sweep.py',
                     'test_sidebar_pages_rendered_e2e.py', 'test_v643_box_overflow_rendered.py', 'test_v643_icon_label_gap.py',
                     'test_v740_narrow_e2e.py', 'test_v740_print_e2e.py'):
            self.assertIn(name, found, name)

    def test_every_exemption_exists_and_gives_a_reason(self):
        for name, why in EXEMPT.items():
            self.assertTrue((_TESTS / name).is_file(), name)
            self.assertGreater(len(why), 20, name)

    def test_the_exempt_modules_do_not_choose_one_long_page(self):
        # they test the tabs: a stray `stacked` init script would hide the thing they look at
        for name in EXEMPT:
            src = (_TESTS / name).read_text(encoding='utf-8')
            self.assertNotIn("add_init_script(\"try { localStorage.setItem('rp_pagetabs', 'stacked')", src, name)

    def test_the_check_sees_a_walker_that_forgot_and_one_that_did_not(self):
        forgot = ("def t(self):\n    ctx = self.browser.new_context()\n    page = ctx.new_page()\n"
                  "    for n in names:\n        page.evaluate('showPage(n)')\n")
        chose = forgot.replace("    page = ", "    ctx.add_init_script(\"localStorage.setItem('rp_pagetabs', 'stacked')\")\n    page = ")
        self.assertTrue(_walks_pages(forgot) and _OPEN.search(forgot))
        self.assertEqual(short_of_the_line(forgot), 1)
        self.assertEqual(short_of_the_line(chose), 0)
        self.assertFalse(_walks_pages("def t(self):\n    page.evaluate('showPage(1)')\n"))      # no loop: not a walker


if __name__ == '__main__':
    unittest.main()
