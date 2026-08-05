"""v6.4.2 — thirty pages stop being sidebar-only destinations.

Cross-page navigation in the SPA was almost entirely one-way. The dashboard
activity feed routed to ~28 pages via `_homeNavAction`, and a handful of
Settings hints linked to drift and exposure. Everything else was reachable only
from its own sidebar button. Thirty pages had ZERO inbound reference from
anywhere else in the app — including the flagship Security Advisory ("what do I
fix first"), Risk, Forecast, Alert Tuning, Command Queue, Predictive health,
Package Snapshots, Data Explorer and the NOC Board.

An operator triaging a critical CVE therefore had no route to that host's risk
score, to the advisory that ranks the CVE against everything else, or to
Package Snapshots to see what changed. They had to remember the page exists,
remember which of the twelve accordion groups it lives in, open that group
(which collapses the one they were in), and lose their filter state on the way.

Not in scope, because it turned out to be a stale premise: the audit noted that
"the Ctrl-K palette's hardcoded page list omits advisory, tuning, billing,
board, calendar, catalog, netmetrics and schedule". `_palettePages()` does not
have a hardcoded list — it enumerates `.nav-btn[data-page]` from the live DOM,
so all eight are already indexed. `test_the_palette_is_dom_derived` pins that,
so the claim cannot quietly become true again.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_HTML = ROOT / "server" / "html" / "index.html"
_JS = ROOT / "server" / "html" / "static" / "js" / "app.js"
_CSS = ROOT / "server" / "html" / "static" / "css" / "styles.css"


def _registry(js):
    """The _PAGE_RELATED literal, parsed into {page: [pages]}."""
    i = js.index("const _PAGE_RELATED = {")
    body = js[i:js.index("\n};", i)]
    out = {}
    # Keys are bare (`cve:`) OR quoted when they contain a hyphen
    # (`'ssh-keys':`), and so are the targets. A `[a-z]+` parser silently
    # skipped every hyphenated page — which is exactly the shape of gap these
    # tests exist to catch, so it must not be in the test either.
    for m in re.finditer(r"^\s*'?([a-z0-9-]+)'?:\s*\[([^\]]*)\]", body, re.M):
        out[m.group(1)] = re.findall(r"'([a-z0-9-]+)'", m.group(2))
    return out


class TestTheRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HTML.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.html = _HTML.read_text()
        cls.js = _JS.read_text()
        cls.rel = _registry(cls.js)
        cls.pages = set(re.findall(r'id="page-([a-z0-9_-]+)"', cls.html))
        cls.nav = set(re.findall(r'data-page="([a-z0-9_-]+)"', cls.html))

    def test_it_parsed(self):
        """A registry test that silently matched nothing would pass forever."""
        self.assertGreater(len(self.rel), 25)

    def test_the_parser_sees_the_hyphenated_pages(self):
        """`ssh-keys`, `disk-health` and `software-policy` are quoted keys with
        hyphens. The first version of this parser matched `[a-z]+` and skipped
        all three — a gate that silently covers less than it claims."""
        for p in ("ssh-keys", "disk-health", "software-policy"):
            with self.subTest(page=p):
                self.assertIn(p, self.rel)
        self.assertIn("disk-health", {t for ts in self.rel.values() for t in ts})

    def test_every_source_page_exists(self):
        bad = sorted(p for p in self.rel if p not in self.pages)
        self.assertEqual(bad, [], f"no such page: {bad}")

    def test_every_target_page_exists(self):
        """A chip pointing at a page that does not exist renders as a dead link
        — and because showPage() just returns, it looks like a broken click
        rather than an error."""
        bad = sorted({t for ts in self.rel.values() for t in ts
                      if t not in self.pages})
        self.assertEqual(bad, [], f"no such page: {bad}")

    def test_every_target_has_a_nav_button(self):
        """The label is read from the nav button at render time. A target with
        no nav button produces an empty label and is silently dropped — so it
        would look wired and do nothing."""
        bad = sorted({t for ts in self.rel.values() for t in ts
                      if t not in self.nav})
        self.assertEqual(bad, [], f"no nav button: {bad}")

    def test_no_page_relates_to_itself(self):
        self.assertEqual([p for p, ts in self.rel.items() if p in ts], [])

    def test_no_duplicates_within_a_row(self):
        for p, ts in self.rel.items():
            with self.subTest(page=p):
                self.assertEqual(len(ts), len(set(ts)))

    def test_the_rows_stay_short(self):
        """These sit inline on the subtitle line next to the Documentation
        link. Past about five they wrap and stop reading as an aside."""
        for p, ts in self.rel.items():
            with self.subTest(page=p):
                self.assertLessEqual(len(ts), 5)

    def test_the_pages_the_finding_named_are_now_reachable(self):
        """Advisory is the product's answer to "what do I fix first" and the
        only way to discover it was scrolling the Security group."""
        inbound = {t for ts in self.rel.values() for t in ts}
        for page in ("advisory", "risk", "forecast", "tuning", "cmdqueue",
                     "patchsnapshots", "board", "dataexplorer"):
            with self.subTest(page=page):
                self.assertIn(page, inbound)

    def test_the_cve_triage_path_the_finding_describes(self):
        """The worked example: from a CVE finding to the score, the ranking and
        what changed."""
        for t in ("risk", "advisory", "patchsnapshots"):
            with self.subTest(target=t):
                self.assertIn(t, self.rel["cve"])


class TestTheRenderer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _JS.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = _JS.read_text()
        cls.body = cls.js[cls.js.index("function _renderPageRelated("):]
        cls.body = cls.body[:cls.body.index("\n}\n")]

    def test_it_runs_on_every_page_entry(self):
        sp = self.js[self.js.index("function showPage(name, btn) {"):]
        sp = sp[:sp.index("\nfunction ", 10)]
        self.assertIn("_renderPageRelated(name)", sp)

    def test_navigation_survives_a_failure_in_it(self):
        sp = self.js[self.js.index("function showPage(name, btn) {"):]
        sp = sp[:sp.index("\nfunction ", 10)]
        i = sp.index("_renderPageRelated(name)")
        self.assertIn("try {", sp[i - 40:i])

    def test_labels_come_from_the_nav_not_a_second_copy(self):
        """A hardcoded label list is a second registry: rename a page and the
        chips keep the old name. This codebase has been bitten by that shape
        repeatedly."""
        self.assertIn("_pageNavLabel(", self.body)
        lbl = self.js[self.js.index("function _pageNavLabel("):]
        lbl = lbl[:lbl.index("\n}\n")]
        self.assertIn('.nav-btn[data-page="', lbl)

    def test_a_gated_off_module_gets_no_chip(self):
        """showPage() refuses a disabled module's route, so a chip pointing at
        one is a button that toasts an error. The nav button carries `d-none`
        when the module is off — that is the signal."""
        lbl = self.js[self.js.index("function _pageNavLabel("):]
        lbl = lbl[:lbl.index("\n}\n")]
        self.assertIn("d-none", lbl)
        self.assertIn("filter(([, label]) => label)", self.body)

    def test_it_rebuilds_rather_than_appending(self):
        """Called on every entry — appending would stack a new row each visit."""
        self.assertIn("const existing = sub.querySelector('.rel-pages')", self.body)
        self.assertIn("row.innerHTML =", self.body)

    def test_an_empty_list_removes_a_stale_row(self):
        self.assertIn("if (existing) existing.remove()", self.body)

    def test_the_chips_are_escaped(self):
        """The label is DOM text from the nav, but it goes into innerHTML."""
        self.assertIn("escHtml(label)", self.body)
        self.assertIn("escAttr(p)", self.body)

    def test_it_uses_the_existing_dispatch_not_an_inline_handler(self):
        self.assertIn('data-action="showPage"', self.body)
        self.assertNotIn("onclick", self.body)
        self.assertNotIn('style="', self.body)

    def test_it_renders_into_the_subtitle_line_not_a_new_row(self):
        """77 of 78 pages already put their Documentation link there — a new
        block would add vertical chrome to every page in the product."""
        self.assertIn(".page-subtitle", self.body)


class TestTheStyling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _CSS.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.css = _CSS.read_text()

    def test_the_classes_exist(self):
        for c in (".rel-pages", ".rel-label", ".rel-chip"):
            with self.subTest(cls=c):
                self.assertIn(c, self.css)

    def test_the_chips_have_a_focus_style(self):
        """Keyboard users get the same affordance as the hover."""
        i = self.css.index(".rel-chip:hover")
        self.assertIn("focus-visible", self.css[i:i + 120])

    def test_they_wrap_rather_than_overflowing(self):
        i = self.css.index(".rel-pages {")
        self.assertIn("flex-wrap: wrap", self.css[i:i + 200])


class TestThePaletteClaimWasStale(unittest.TestCase):
    """The audit said the Ctrl-K palette had a hardcoded page list omitting
    eight pages. It does not — it enumerates the live nav. Pinned so the claim
    cannot quietly become true again."""

    @classmethod
    def setUpClass(cls):
        if not _JS.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = _JS.read_text()
        cls.html = _HTML.read_text()

    def test_the_palette_is_dom_derived(self):
        body = self.js[self.js.index("function _palettePages() {"):]
        body = body[:body.index("\n}\n")]
        self.assertIn(".nav-btn[data-page]", body)

    def test_the_eight_pages_named_all_have_nav_buttons(self):
        for page in ("advisory", "tuning", "billing", "board", "calendar",
                     "catalog", "netmetrics", "schedule"):
            with self.subTest(page=page):
                self.assertRegex(
                    self.html, rf'class="nav-btn"[^>]*data-page="{page}"')


if __name__ == "__main__":
    unittest.main()
