"""v6.4.2 — "Group → Page" wayfinding strings must name real destinations.

Hints, empty states and toasts tell operators where to go in prose: "enable in
Settings → Alerts", "Lift it under Monitoring → Tuning", "Configure it under
Settings → Proxmox". A subset of those named places that do not exist:

  * `Settings → Proxmox`      — the tab has read **Virtualization** since v5.6.0
  * `Monitoring → GPUs`       — GPUs is in the **Hardware** nav group
  * `Admin → CMDB`            — CMDB is in the **Fleet** group
  * `Settings → Alerts`, `Settings → Log rules`, `Settings → Service watch`,
    `Settings → Power` — none of which is a Settings tab label

A new operator reads "Alerting off — enable in Settings → Alerts", opens
Settings, and finds Install / General / Notifications / Alerting / Alert
parameters / Mailbox monitor / Ignored items / Integrations / Virtualization /
AI assistant / Security / Tickets / Backups / Advanced. There is no Alerts tab.
That is the exact dead end the sidebar-search and doc-pointer programs were built
to remove, left unfinished in prose.

This test derives the destination set from the ACTUAL markup — sidebar group
names, nav button labels, Settings tab labels — so it goes stale the moment a
page moves, which a hand-kept list would not.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_HTML = ROOT / "server" / "html"
_JS = _HTML / "static" / "js"

# The nav groups a wayfinding string may name. Anything else on the left is
# prose or a third-party UI's menu path, and is skipped rather than guessed at.
_GROUPS = ("Settings", "Monitoring", "Security", "Fleet", "Hardware", "Admin",
           "Automation", "Scheduling", "Access", "Backups", "Compliance",
           "Patching", "Business")

# Deliberately tight. An earlier, looser version matched 19 strings of which 13
# were prose continuations ("Settings → Data still prunes by age on t…") or a
# case difference. A gate that cries wolf gets switched off — which is the same
# lesson the alerting side of this product already learned.
_ARROW = re.compile(
    r"\b(" + "|".join(_GROUPS) + r")\s*(?:→|-&gt;)\s*"
    r"([A-Z][A-Za-z]*(?:[ /&-][A-Za-z]+){0,2})")

# `device drawer → Health & Hardware → Scan LAN` is a breadcrumb inside a
# dialog, not sidebar navigation; the regex would read its middle segment as a
# nav group.
_NOT_NAV = ("drawer →", "Datacenter →", "Permissions →")


def _destinations(html):
    """Every place a wayfinding string may legitimately point at, derived from
    the ACTUAL markup — sidebar page labels + slugs, Settings tab labels and
    section titles. Derived, not hand-kept, so it goes stale when a page moves."""
    out = set()
    for m in re.finditer(r'id="settings-tab-btn-[a-z]+"[^>]*>([^<]+)</button>',
                         html):
        out.add(m.group(1).strip().lower())
    for m in re.finditer(r'<div class="section-title"[^>]*>([^<]+)</div>', html):
        out.add(m.group(1).strip().lower())
    for m in re.finditer(r'data-page="([a-z0-9_-]+)"[^>]*>(.*?)</button>',
                         html, re.S):
        txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(2))).strip()
        if txt:
            out.add(txt.lower())
        out.add(m.group(1))
    return out


def _strings_in(path):
    """Every `Group → Place` pair in operator-visible text, comments stripped."""
    src = path.read_text()
    if path.suffix == ".js":
        src = re.sub(r"^\s*//.*$", "", src, flags=re.M)
        src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    else:
        src = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    out = []
    for m in _ARROW.finditer(src):
        window = src[max(0, m.start() - 40):m.start()]
        if any(x in window for x in _NOT_NAV):
            continue
        out.append((m.group(2).strip().lower(), m.group(0)))
    return out


class TestWayfindingNamesRealPlaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = _HTML / "index.html"
        if not p.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.html = p.read_text()
        cls.known = _destinations(cls.html)

    def _bad(self, pairs):
        """A destination matches if it IS a known place, or shares a leading
        segment with one — "Settings → AI Assistant apply" points at the AI
        assistant tab, and "Settings → Notifications → Patch alert" at
        Notifications. Prefix matching is what keeps this a defect gate rather
        than a phrasing gate."""
        bad = []
        for right, whole in pairs:
            if any(right == k or right.startswith(k + " ")
                   or k.startswith(right + " ") for k in self.known):
                continue
            bad.append(whole)
        return bad

    def test_the_previously_broken_ones_are_gone(self):
        """The concrete set the audit confirmed as pointing nowhere."""
        everywhere = self.html + "".join(
            (_JS / f).read_text() for f in
            ("app.js", "app-backups.js", "app-proxmox.js", "app-dns.js",
             "app-network.js"))
        for dead in ("Settings → Proxmox", "Monitoring → GPUs", "Admin → CMDB",
                     "Settings → Log rules", "Settings → Service watch",
                     "Settings → Power"):
            with self.subTest(dead=dead):
                self.assertNotIn(dead, everywhere,
                                 f"'{dead}' names a place that does not exist")

    def test_settings_alerts_is_gone(self):
        """`Settings → Alerts` is the sharpest one — Settings has BOTH a
        Notifications and an Alerting tab, so the operator has to guess."""
        everywhere = self.html + (_JS / "app.js").read_text() \
            + (_JS / "app-network.js").read_text()
        self.assertNotRegex(everywhere, r"Settings → Alerts\b")

    def test_the_replacements_are_real_destinations(self):
        for dest in ("virtualization", "alerting", "advanced", "notifications",
                     "integrations", "gpus", "cmdb"):
            with self.subTest(dest=dest):
                self.assertIn(dest, self.known)

    def test_index_html_wayfinding_resolves(self):
        bad = self._bad(_strings_in(_HTML / "index.html"))
        self.assertEqual(bad, [], "wayfinding strings naming nowhere:\n  "
                                  + "\n  ".join(sorted(set(bad))))

    def test_page_module_wayfinding_resolves(self):
        bad = []
        for f in sorted(_JS.glob("app*.js")):
            bad += self._bad(_strings_in(f))
        self.assertEqual(bad, [], "wayfinding strings naming nowhere:\n  "
                                  + "\n  ".join(sorted(set(bad))))

    def test_the_parser_actually_finds_things(self):
        """A test that silently matches nothing is the false-green shape this
        codebase keeps hitting — prove the extractor works."""
        found = _strings_in(_HTML / "index.html")
        self.assertGreater(len(found), 20,
                           "the arrow extractor matched almost nothing — it is "
                           "not testing what it claims to")


class TestElevationTokens(unittest.TestCase):
    """All 11 elevation shadows were hardcoded 30-40% black at 16-40px blur with
    no token and no `body.light` override, so the four light themes (Daylight,
    Paper, Solarized Light, Nord Light) rendered modals, drawers and toasts
    ringed in a grey wash tuned for a near-black background."""

    @classmethod
    def setUpClass(cls):
        p = _HTML / "static" / "css" / "styles.css"
        if not p.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.css = p.read_text()

    def test_the_tokens_exist(self):
        for t in ("--shadow-1", "--shadow-2", "--shadow-3", "--shadow-edge"):
            with self.subTest(token=t):
                self.assertIn(t + ":", self.css)

    @staticmethod
    def _block(css, opener):
        """styles.css has TWO `body.light {` blocks — the palette one and the
        chrome one. Take the block that actually declares --shadow-*, or this
        asserts against the wrong half and fails on working code."""
        i = 0
        while True:
            i = css.index(opener, i)
            end = css.index("\n  }", i)
            block = css[i:end]
            if "--shadow-" in block:
                return block
            i = end

    def test_light_overrides_them(self):
        block = self._block(self.css, "body.light {")
        for t in ("--shadow-1", "--shadow-2", "--shadow-3", "--shadow-edge"):
            with self.subTest(token=t):
                self.assertIn(t, block,
                              "the light themes still get a shadow tuned for a "
                              "near-black background")

    def test_light_alpha_is_lower(self):
        def alphas(block):
            return [float("0." + a) for a in
                    re.findall(r"--shadow-[a-z0-9]+:[^;]*rgba\([^)]*?[,.]\s*\.?(\d+)\)",
                               block)]
        da = alphas(self._block(self.css, "  :root {"))
        la = alphas(self._block(self.css, "body.light {"))
        self.assertTrue(da and la, "could not read the alphas back")
        self.assertLess(max(la), min(da),
                        "every light-theme shadow must be lighter than every "
                        "dark one, or the wash is still there")

    def test_no_heavy_literal_shadows_remain(self):
        """Any new `0 Npx Mpx rgba(0,0,0,.3)` reintroduces the whole class."""
        leftovers = re.findall(
            r"box-shadow:\s*0 \d+px (?:1[6-9]|[2-9]\d)px rgba\(0,\s*0,\s*0",
            self.css)
        self.assertEqual(leftovers, [],
                         "a hardcoded elevation shadow is back — use "
                         "var(--shadow-1/-2/-3) so the light themes get their "
                         "own alpha")

    def test_the_tokens_are_actually_used(self):
        self.assertGreater(self.css.count("var(--shadow-"), 15,
                           "tokens defined and nothing points at them")


if __name__ == "__main__":
    unittest.main()
