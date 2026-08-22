"""v7.0.2 — every page carries a Documentation pointer, and none of them dangle.

The doc-pointer program is the reason an operator on an unfamiliar page knows
where to read more: a `<a href="docs/<topic>.md" class="c-accent">Documentation</a>`
appended to a section's `<p class="hint">`. Two things rot it.

**A dangling pointer is worse than none.** The in-app doc viewer intercepts
`a[href^="docs/"]`, fetches the file and renders it; a link to a file that was
renamed or never written falls into the viewer's error state, which reads as a
broken product rather than a missing file. `test_v642_doc_links` already holds
that line for `.md` pointers; this file holds it for every doc href in
index.html, `.txt` samples and the `docs/README.md` index included.

**A new page ships without one.** Coverage was 80 of 82 pages when this file was
written, and the two gaps (My Account, About) were both pages added after the
program ran. Prose did not stop that, so the ratio is a grow-only ratchet here.

The comment this file was written against claimed "77 of 78 pages have one".
That was true of a 78-page app; index.html now declares 83 `id="page-*"` and
82 of those are pages — `page-watermark` is a decorative `aria-hidden` div that
`_setPageWatermark` fills, not a route. Deriving the population from
`class="page"` rather than from the id prefix is what keeps that div out of the
count, and `test_the_population_is_derived_not_guessed` fails if the derivation
ever collapses.
"""

import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_HTML = ROOT / "server" / "html" / "index.html"
_DOCS = ROOT / "docs"

# A page shell, not the decorative watermark div: the class is what makes it a
# route. `page-home` carries "page active", so match a class list that STARTS
# with page rather than one that equals it.
_PAGE = re.compile(r'<div id="page-([a-z0-9-]+)"[^>]*class="page[ "]')
# The `#fragment` half is not optional decoration: one pointer deep-links into
# a section (`self-monitoring.md#restoring-from-a-backup`), and a regex without
# it leaves that link out of the POPULATION — not exempt from the on-disk check,
# invisible to it. Captured separately so the existence check can drop it.
_HREF = re.compile(r'href="/?docs/([A-Za-z0-9._/-]+)(#[A-Za-z0-9._-]*)?"')


def _targets(text):
    """Every doc target in `text`, fragments stripped."""
    return [m.group(1) for m in _HREF.finditer(text)]

# Grow-only. Raise these when a page or a pointer is added; never lower them
# without saying which page lost its pointer and why.
MIN_PAGES = 82
MIN_PAGES_WITH_A_POINTER = 82
MIN_POINTERS = 228


def _pages(src):
    """id -> the doc targets inside that page's shell.

    Each shell runs to the start of the next one, which over-counts nothing:
    the page divs are siblings in document order.
    """
    marks = [(m.start(), m.group(1)) for m in _PAGE.finditer(src)]
    out = {}
    for i, (pos, name) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(src)
        out[name] = _targets(src[pos:end])
    return out


class TestDocPointers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HTML.exists():
            raise unittest.SkipTest("index.html excluded from this tree")
        cls.src = _HTML.read_text()
        cls.pages = _pages(cls.src)
        cls.refs = sorted(set(_targets(cls.src)))

    # ---- the derivation itself -------------------------------------------

    def test_the_population_is_derived_not_guessed(self):
        """A broken regex would make every later assertion pass on an empty set.

        This is the control: the shells exist, the decorative watermark div is
        not one of them, and the count has not collapsed.
        """
        self.assertGreaterEqual(
            len(self.pages), MIN_PAGES,
            "the page derivation found %d shells, expected at least %d — fix "
            "the regex before trusting anything else in this file"
            % (len(self.pages), MIN_PAGES))
        self.assertIn("home", self.pages, "page-home carries class='page active'")
        self.assertNotIn(
            "watermark", self.pages,
            "page-watermark is an aria-hidden decoration, not a route")

    def test_the_pointer_scan_finds_something(self):
        self.assertGreaterEqual(
            len(self.refs), 50,
            "the href scan found %d doc targets — the regex is broken"
            % len(self.refs))

    # ---- a dangling pointer is worse than none ---------------------------

    def test_every_referenced_doc_exists_on_disk(self):
        if not _DOCS.exists():
            self.skipTest("docs excluded from this tree")
        dead = [r for r in self.refs if not (_DOCS / r).is_file()]
        self.assertEqual(
            dead, [],
            "these Documentation pointers resolve to nothing: " + ", ".join(dead))

    def test_no_pointer_escapes_the_docs_folder(self):
        """`../` in a doc href would leave the folder the viewer can fetch."""
        bad = [r for r in self.refs if ".." in r or r.startswith("/")]
        self.assertEqual(bad, [], "suspicious doc hrefs: %r" % (bad,))

    # ---- coverage, ratcheted ---------------------------------------------

    def test_every_page_has_a_documentation_pointer(self):
        missing = sorted(n for n, links in self.pages.items() if not links)
        self.assertEqual(
            missing, [],
            "these pages give the operator nowhere to read more: "
            + ", ".join(missing)
            + " — add <a href=\"docs/<topic>.md\" class=\"c-accent\">Documentation</a>"
              " to a <p class=\"hint\"> in the page, and write the doc if it is"
              " missing. Never append it to the .page-subtitle: that line is"
              " keyed in i18n.js HTMLDICT by its normalised innerHTML.")

    def test_the_coverage_ratio_only_grows(self):
        covered = sum(1 for links in self.pages.values() if links)
        self.assertGreaterEqual(
            covered, MIN_PAGES_WITH_A_POINTER,
            "%d of %d pages carry a pointer, was %d — a page lost one"
            % (covered, len(self.pages), MIN_PAGES_WITH_A_POINTER))

    def test_the_pointer_count_only_grows(self):
        total = len(_targets(self.src))
        self.assertGreaterEqual(
            total, MIN_POINTERS,
            "index.html carries %d doc pointers, was %d" % (total, MIN_POINTERS))

    # ---- the two shapes that break silently ------------------------------

    def test_a_subtitle_pointer_has_an_i18n_entry(self):
        """79 pages carry the pointer inside their `.page-subtitle`, which is
        legal and was the program's original idiom — HTMLDICT simply keys that
        line by its normalised innerHTML, so a subtitle and its translation
        move together. What is not legal is a subtitle the dictionary has never
        seen. Anything added to a hint instead is unscanned and always safe,
        which is why the two pages fixed in v7.0.2 went there.
        """
        i18n = ROOT / "server" / "html" / "static" / "js" / "i18n.js"
        if not i18n.is_file():
            self.skipTest("i18n.js excluded from this tree")
        js = i18n.read_text()
        subs = [m.group(1).strip() for m in re.finditer(
            r'<div class="page-subtitle"[^>]*>(.*?)</div>', self.src, re.S)]
        withlink = [t for t in subs if 'href="docs/' in t]
        self.assertGreaterEqual(
            len(withlink), 70,
            "the subtitle scan found %d linked subtitles — regex broken"
            % len(withlink))
        # A spot control rather than all 79: the point is that the dictionary
        # is keyed on this shape at all, so a wholesale reformat is caught.
        head = re.sub(r"\s+", " ", withlink[0])[:40]
        self.assertIn(head.split("<")[0].strip()[:24], js,
                      "a linked page-subtitle has no HTMLDICT entry — editing "
                      "one without editing i18n.js reverts it to English")

    def test_pointers_are_relative_so_the_viewer_can_intercept_them(self):
        """app.js delegates on a[href^="docs/"] — an absolute /docs/ href is
        invisible to it and unloads the SPA instead of opening the viewer."""
        self.assertNotIn('href="/docs/', self.src)


class TestTheDocsIndexKnowsTheNewGuides(unittest.TestCase):
    """A doc nobody links from the index is findable only by guessing."""

    def test_my_account_is_indexed(self):
        idx = _DOCS / "README.md"
        if not idx.is_file():
            self.skipTest("docs excluded from this tree")
        self.assertIn("my-account.md", idx.read_text())


if __name__ == "__main__":
    unittest.main()
