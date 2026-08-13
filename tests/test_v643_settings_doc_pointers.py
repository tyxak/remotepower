"""v6.4.3: every Settings section that needs documentation links to it.

CLAUDE.md has asked for a doc pointer near every non-obvious Settings section
for several releases. Measured, 82 of 129 sections had none — the rule existed
and nothing checked it, so coverage tracked whoever last remembered.

Two things are gated here, and the second is the one that matters:

1. **No dangling pointer.** A link to a doc that does not exist is worse than no
   link: it looks like help and 404s. Version docs are deleted on a keep-three
   policy, so this rots on its own schedule.
2. **Coverage is a RATCHET.** A new Settings section may not push the
   without-a-pointer count up. That is what stops the slow return to 82 — the
   rule is now enforced at the moment a section is added rather than
   rediscovered by counting a year later.

The ceiling is deliberately not zero. Three sections are self-explanatory
("Server identity", "Online TTL", "Test connection") and 24 are threshold groups
in the Alert parameters pane, which carries ONE pane-level pointer instead of 24
identical ones — the whole pane is a single topic and repeating the link per
group would be noise, not help. Lower the ceiling when a section gains a
pointer; never raise it.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = _ROOT / "server" / "html" / "index.html"
_DOCS = _ROOT / "docs"

# Shrink-only. See the module docstring for why it is not zero.
_WITHOUT_POINTER_CEILING = 27


def _settings_html():
    h = _HTML.read_text(encoding="utf-8")
    return h[h.index('id="page-settings"') :]


def _sections():
    """[(title, section_html)] for every Settings section."""
    out = []
    for part in re.split(r'(?=<div class="settings-section")', _settings_html())[1:]:
        t = re.search(r'<div class="section-title">([^<]+)</div>', part)
        if t:
            out.append((t.group(1).strip(), part))
    return out


def _doc_refs(html):
    return set(re.findall(r'href="docs/([a-z0-9._-]+\.md)"', html))


class TestTheExtractionWorks(unittest.TestCase):
    """Positive controls. Both checks below read live markup with regexes; a
    parse miss would make each of them pass over nothing.

    This is not hypothetical here — the first version of this sweep reported
    0 of 129 sections carrying a pointer, seconds after one had been verified
    by hand. The split used a lookahead, so every part began with the marker and
    each body sliced to empty.
    """

    def setUp(self):
        if not _HTML.exists():
            self.skipTest("index.html excluded from this tree")

    def test_sections_are_found(self):
        self.assertGreater(len(_sections()), 100, f"parsed {len(_sections())}")

    def test_pointers_are_found(self):
        with_ptr = [t for t, body in _sections() if _doc_refs(body)]
        self.assertGreater(
            len(with_ptr),
            50,
            "almost no section appears to carry a pointer — the extraction is "
            "broken, not the page",
        )

    def test_a_known_pointer_is_seen(self):
        for title, body in _sections():
            if title == "Disk encryption checks":
                self.assertIn("checks.md", _doc_refs(body))
                return
        self.fail("the 'Disk encryption checks' section has disappeared")


class TestNoPointerDangles(unittest.TestCase):
    def setUp(self):
        if not _HTML.exists() or not _DOCS.is_dir():
            self.skipTest("excluded from this tree")

    def test_every_settings_doc_link_resolves(self):
        missing = sorted(r for r in _doc_refs(_settings_html()) if not (_DOCS / r).exists())
        self.assertEqual(
            [],
            missing,
            "Settings links to documentation that does not exist — a 404 "
            f"dressed as help: {missing}",
        )

    def test_every_doc_link_on_the_whole_page_resolves(self):
        """Not just Settings — the same rot applies to every in-app pointer."""
        html = _HTML.read_text(encoding="utf-8")
        missing = sorted(r for r in _doc_refs(html) if not (_DOCS / r).exists())
        self.assertEqual([], missing, f"dangling in-app doc links: {missing}")


class TestCoverageOnlyImproves(unittest.TestCase):
    def setUp(self):
        if not _HTML.exists():
            self.skipTest("index.html excluded from this tree")
        self.without = [t for t, body in _sections() if not _doc_refs(body)]

    def test_the_count_does_not_grow(self):
        self.assertLessEqual(
            len(self.without),
            _WITHOUT_POINTER_CEILING,
            f"{len(self.without)} Settings sections have no documentation "
            f"pointer, ceiling {_WITHOUT_POINTER_CEILING}. A new section needs "
            "one — or, if it is genuinely self-explanatory, raise the ceiling "
            "here WITH the reason. Currently uncovered:\n  " + "\n  ".join(self.without),
        )

    def test_the_ceiling_is_not_slack(self):
        """A ceiling far above the real count silently permits regressions."""
        self.assertGreaterEqual(
            len(self.without) + 3,
            _WITHOUT_POINTER_CEILING,
            f"only {len(self.without)} sections lack a pointer but the ceiling "
            f"is {_WITHOUT_POINTER_CEILING} — lower it to lock the gain in",
        )


# Shrink-only. The docs' own wayfinding paths, the counterpart of the v6.4.2
# check that does this for hints/toasts inside the app.
_UNRESOLVABLE_DOC_PATHS_CEILING = 37


def _settings_tabs():
    h = _HTML.read_text(encoding="utf-8")
    i = h.index('<div class="settings-tabs"')
    seg = h[i : h.index("\n        </div>", i)]
    return sorted(
        {
            t.strip()
            for t in re.findall(
                r'data-tab="[a-z0-9-]+"[^>]*?tabindex="[^"]*">([^<]*)</button>', seg
            )
        },
        key=len,
        reverse=True,
    )


class TestDocsPointAtRealSettingsTabs(unittest.TestCase):
    """A doc that says "Settings -> X" where X is not a tab sends the reader
    hunting. 62 such paths existed; the unambiguous ones are corrected and the
    rest are frozen so the count cannot grow.

    Proven unrelated to the v6.4.3 sidebar/Settings reordering: the identical
    count (62) appears at the commit before the reorder, at the reorder itself,
    and after. Reordering within a group renames nothing.
    """

    def setUp(self):
        if not _HTML.exists() or not _DOCS.is_dir():
            self.skipTest("excluded from this tree")
        self.tabs = _settings_tabs()

    def _unresolvable(self):
        out = []
        files = sorted(_DOCS.glob("*.md"))
        readme = _ROOT / "README.md"
        if readme.exists():
            files.append(readme)
        for p in files:
            if p.name.startswith("security-review-"):
                continue  # historical records; not navigation
            t = p.read_text(encoding="utf-8")
            for m in re.finditer(r"Settings\s*\u2192\s*", t):
                tail = t[m.end() : m.end() + 40]
                if not any(tail.startswith(x) for x in self.tabs):
                    out.append(f"{p.name}: Settings -> {tail[:34].strip()}")
        return out

    def test_the_tab_list_was_parsed(self):
        """Positive control — an empty tab list would flag every path."""
        self.assertGreaterEqual(len(self.tabs), 10, f"parsed {self.tabs}")
        self.assertIn("Advanced", self.tabs)

    def test_the_count_does_not_grow(self):
        bad = self._unresolvable()
        self.assertLessEqual(
            len(bad),
            _UNRESOLVABLE_DOC_PATHS_CEILING,
            f"{len(bad)} documented Settings paths name no real tab, ceiling "
            f"{_UNRESOLVABLE_DOC_PATHS_CEILING}:\n  " + "\n  ".join(bad[:20]),
        )


if __name__ == "__main__":
    unittest.main()
