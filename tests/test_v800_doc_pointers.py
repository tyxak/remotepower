#!/usr/bin/env python3
"""8.0.0: the surfaces this release added point to the guide that explains them.

A person who opens the discovery list of a host, the Automatic updates card, the layouts manager, the tenant branding dialog or any of the wizards should be one click from
the page that says what it does. Held at the source: each surface carries a link to a guide that exists (and to a heading that exists when the link names one). The wizards
take the guide from their definition (the sidecar wizards name their own) and fall back to docs/wizards.md.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = (ROOT / "server/html/index.html").read_text()
JS = {n: (ROOT / "server/html/static/js" / n).read_text() for n in ("app-wizard.js", "app-wizard-sidecars.js", "app-dashsets.js")}


def _slug(heading):
    s = re.sub(r"[*_`]", "", heading).strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"\s", "-", s)


def _anchors(doc):
    return {_slug(m.group(1)) for m in re.finditer(r"^#{1,6}\s+(.+)$", (ROOT / "docs" / doc).read_text(), re.M)}


def _block(start_marker, length=2500):
    i = HTML.index(start_marker)
    return HTML[i:i + length]


class TestSurfacesPointToTheirGuides(unittest.TestCase):

    SURFACES = (
        ("the apps found on a host (host drawer)", lambda: _block('id="drawer-apps-section"', 700), "app-discovery.md", None),
        ("the Automatic updates card", lambda: _block('id="image-autoupdate-card"', 1200), "containers.md", None),
        ("the tenant branding dialog", lambda: _block('id="tenant-branding-modal"', 1200), "scaling.md", "onboarding-a-tenant-end-to-end"),
        ("the layouts manager", lambda: JS["app-dashsets.js"], "dashboard.md", "layouts"),
    )

    def test_each_surface_links_a_guide_that_exists(self):
        for name, get, doc, anchor in self.SURFACES:
            with self.subTest(surface=name):
                text = get()
                link = "docs/%s%s" % (doc, "#" + anchor if anchor else "")
                self.assertIn('href="%s"' % link, text)
                self.assertTrue((ROOT / "docs" / doc).exists(), doc)
                if anchor:
                    self.assertIn(anchor, _anchors(doc), "the link names a heading that is not there")

    def test_every_wizard_gets_a_documentation_link(self):
        shell = JS["app-wizard.js"]
        self.assertIn("docLink.href = def.doc || 'docs/wizards.md'", shell)
        self.assertIn("'Documentation'", shell)
        self.assertTrue((ROOT / "docs/wizards.md").exists())

    def test_the_sidecar_wizards_name_guides_that_exist(self):
        for doc in re.findall(r"doc: 'docs/([a-z0-9-]+\.md)'", JS["app-wizard-sidecars.js"]):
            self.assertTrue((ROOT / "docs" / doc).exists(), doc)

    def test_the_anchor_check_sees_a_missing_heading(self):
        self.assertNotIn("no-such-heading", _anchors("dashboard.md"))
        self.assertIn("layouts", _anchors("dashboard.md"))


if __name__ == "__main__":
    unittest.main()
