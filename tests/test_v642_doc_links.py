"""v6.4.2 — a Documentation link stops unloading the app, and none of them 404.

The doc-pointer program put 126 `<a href="docs/<topic>.md">Documentation</a>`
links across the app — 77 of 78 pages have one — and exactly ONE carried
target="_blank". The other 125 unloaded the SPA and handed the browser a raw
markdown file served as a static asset with no renderer, even though
`renderMarkdown()` already shipped for the KB and the AI chat.

So an operator mid-way through configuring TLS monitoring clicks Documentation
beside the certificate-file hint. The whole app unloads, they get
`# TLS certificate monitoring` in plain source form (or, on a stock nginx where
`.md` has no MIME mapping and the server sends X-Content-Type-Options: nosniff,
a file download), and returning means a full SPA reboot to the dashboard with
the half-filled form gone.

One of those links was also dead: `docs/tls.md` has never existed — the file is
`tls-monitor.md` — so on the Settings → Security pane the click produced a 404.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_HTML = ROOT / "server" / "html" / "index.html"
_JS = ROOT / "server" / "html" / "static" / "js" / "app.js"
_DOCS = ROOT / "docs"

# Deliberately matches an OPTIONAL leading slash so the scan sees absolute doc
# links too. It used to require the relative form, which meant four `/docs/`
# links were invisible to every assertion in this file — including the
# resolves-on-disk one — while ALSO being the only links the in-app doc viewer
# could not intercept (app.js delegates on a[href^="docs/"]). A link the gate
# cannot see and the viewer cannot open is the worst of both.
_HREF = re.compile(r'href="/?docs/([A-Za-z0-9._-]+\.md)"')
_ABS_HREF = re.compile(r'href="/docs/')


class TestEveryDocLinkResolves(unittest.TestCase):
    """The 30-second half of the finding, with the guardrail it deserves."""

    @classmethod
    def setUpClass(cls):
        if not _DOCS.exists():
            raise unittest.SkipTest("docs excluded from this tree")
        cls.on_disk = {p.name for p in _DOCS.glob("*.md")}

    def _dead(self, text):
        return sorted({m.group(1) for m in _HREF.finditer(text)
                       if m.group(1) not in self.on_disk})

    def test_index_html(self):
        dead = self._dead(_HTML.read_text())
        self.assertEqual(dead, [],
                         "these Documentation links 404: " + ", ".join(dead))

    def test_the_page_modules(self):
        js = ROOT / "server" / "html" / "static" / "js"
        dead = []
        for f in sorted(js.glob("*.js")):
            dead += [f"{f.name}: {d}" for d in self._dead(f.read_text())]
        self.assertEqual(dead, [], "\n  ".join(dead))

    def test_tls_md_specifically(self):
        """The one that was dead. Named because a regression here is silent —
        the link renders identically."""
        self.assertNotIn("tls.md", self.on_disk,
                         "if tls.md now exists this pin is moot; drop it")
        self.assertNotIn('href="docs/tls.md"', _HTML.read_text())

    def test_the_scan_actually_finds_links(self):
        """A gate that matches nothing is the false-green shape this codebase
        keeps hitting."""
        self.assertGreater(len(_HREF.findall(_HTML.read_text())), 100)

    def test_no_doc_link_is_absolute(self):
        """Every doc link must be RELATIVE, or the in-app viewer can't open it.

        app.js:1812 delegates on `a[href^="docs/"]`. An `/docs/…` link doesn't
        match, so it leaves the SPA and does a full page load to a raw markdown
        file — reproducing exactly the behaviour the viewer was built to
        replace. Four of them shipped this way, and every one had a relative
        sibling elsewhere in the same file pointing at the same topic, so the
        page was inconsistent with itself rather than with some other component.
        """
        for path in (_HTML, _JS):
            n = len(_ABS_HREF.findall(path.read_text()))
            self.assertEqual(
                n, 0,
                f"{path.name}: {n} doc link(s) use an absolute /docs/ path — "
                f'drop the leading slash so a[href^="docs/"] can intercept it')

    def test_no_doc_card_denies_a_capability_the_ui_actually_has(self):
        """The Documentation page must not tell operators a feature is absent
        while the button for it sits in the same file.

        It said "No in-UI restore — backups are tarballs you extract yourself"
        while `data-action="pickRestoreFile"` was ~2,500 lines above it, and it
        contradicted the very doc it linked to. The harm is not the wrong
        sentence; it is that the manual path it recommends is the one that does
        NOT take a pre-restore safety snapshot.
        """
        html = _HTML.read_text()
        actions = {m.lower() for m in
                   re.findall(r'data-action="([A-Za-z0-9_]+)"', html)}
        problems = []
        for claim in re.findall(r'No in-(?:UI|app) ([a-z]+)', html):
            hits = [a for a in actions if claim.lower() in a]
            if hits:
                problems.append(f'the page claims "No in-UI {claim}" but '
                                f'data-action(s) {sorted(hits)} exist')
        self.assertEqual(problems, [], "\n  ".join(problems))


class TestTheViewerKeepsTheOperatorInTheApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = _JS.read_text()
        cls.html = _HTML.read_text()

    def test_the_viewer_exists(self):
        self.assertRegex(self.js, r"\basync function openDocViewer\s*\(")
        self.assertIn('id="doc-viewer-modal"', self.html)

    def test_it_uses_the_renderer_the_app_already_ships(self):
        body = self.js[self.js.index("async function openDocViewer"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("renderMarkdown(", body,
                      "shipping a second markdown renderer would be the wrong "
                      "fix twice over")

    def test_it_intercepts_by_delegation_not_126_edits(self):
        self.assertIn('closest(\'a[href^="docs/"]\')', self.js)

    def test_a_modified_click_still_opens_a_tab(self):
        """An operator who ctrl-clicks is asking for a tab and should get one."""
        i = self.js.index('closest(\'a[href^="docs/"]\')')
        seg = self.js[i:i + 600]
        for k in ("metaKey", "ctrlKey", "shiftKey", "button !== 0"):
            with self.subTest(modifier=k):
                self.assertIn(k, seg)

    def test_an_explicit_blank_target_is_left_alone(self):
        i = self.js.index('closest(\'a[href^="docs/"]\')')
        self.assertIn("'_blank'", self.js[i:i + 600])

    def test_a_failed_fetch_falls_back_to_the_raw_file(self):
        """Trapping the operator in a broken modal would be worse than the
        behaviour being replaced."""
        body = self.js[self.js.index("async function openDocViewer"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("Open the raw file", body)

    def test_the_modal_offers_the_raw_file_too(self):
        self.assertIn('id="doc-viewer-raw"', self.html)

    def test_the_body_class_exists(self):
        """`kb-article` — the obvious guess — is not a class this app has. The
        one the KB and the AI chat render markdown into is `ai-content`."""
        css = (ROOT / "server" / "html" / "static" / "css" / "styles.css").read_text()
        i = self.html.index('id="doc-viewer-body"')
        cls = re.search(r'class="([^"]+)"', self.html[i:i + 200]).group(1)
        for c in cls.split():
            with self.subTest(cls=c):
                self.assertIn("." + c, css, f"'{c}' is not a real class")

    def test_the_viewer_is_capped_and_scrolls(self):
        i = self.html.index('id="doc-viewer-body"')
        self.assertIn("scroll-cap", self.html[i:i + 200],
                      "a long doc grows the modal unbounded")


class TestTheDocsFilterIsMultiToken(unittest.TestCase):
    def test_it_matches_every_token(self):
        """As one substring, "cve scan" only hit a card containing that exact
        phrase — so the obvious two-word query returned nothing, while the
        sidebar search has always been multi-token."""
        js = _JS.read_text()
        body = js[js.index("function filterDocs("):]
        body = body[:body.index("\n}\n")]
        self.assertIn(".every(", body)
        self.assertNotIn("summary.includes(q) || body.includes(q)", body)


class TestDocsDoNotLinkToEachOtherIntoNothing(unittest.TestCase):
    """v6.4.3: the scan above covers app → docs. Nothing covered docs → docs,
    and `docs/compliance.md` had been pointing at `pii.md` — a file that has
    never existed under that name (it is `pii-scan.md`) — since the PII scanner
    shipped. Same failure the tls.md case above pins, one hop further out.

    README.md and SECURITY.md are included: they are the entry points a reader
    arrives through. CHANGELOG.md is deliberately NOT, because it is the
    complete dated history and its `See docs/vX.Y.Z.md` pointers are expected
    to dangle once retention deletes the version doc — that is stated policy,
    not rot.
    """

    _LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

    def _dead(self, path):
        out = []
        for m in self._LINK.finditer(path.read_text()):
            target = m.group(1).split("#")[0].strip()
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            if not (path.parent / target).exists():
                out.append(f"{path.name} → {target}")
        return out

    def test_every_docs_page(self):
        dead = [d for p in sorted(_DOCS.glob("*.md")) for d in self._dead(p)]
        self.assertEqual(dead, [], "dead relative links between docs: " + str(dead))

    def test_the_readme_and_security_policy(self):
        dead = []
        for name in ("README.md", "SECURITY.md"):
            p = ROOT / name
            if p.exists():
                dead += self._dead(p)
        self.assertEqual(dead, [], "dead relative links: " + str(dead))

    def test_the_scan_finds_links_at_all(self):
        """Without this, deleting every doc would make the two tests above pass."""
        self.assertGreater(
            len(self._LINK.findall((_DOCS / "README.md").read_text())), 20)


if __name__ == "__main__":
    unittest.main()
