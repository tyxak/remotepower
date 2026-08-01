"""v6.4.2 — accent-as-text contrast, and Ctrl+P on a page that is not Reports.

Both halves are computed, not grepped:

* The contrast half parses every theme / accent-preset custom-property block
  out of styles.css, replays the real cascade for all 13 palettes x 6 accents
  x light/dark, converts the resulting colours to WCAG relative luminance and
  asserts the accent-as-ink tokens clear 4.5:1 against the surfaces they are
  actually painted on. Add a 14th palette that regresses and this fails.

* The print half builds the real ancestor chain of `.page.active` out of
  index.html, then runs a small selector matcher + cascade over the
  `@media print` block to answer the only question that matters: with an
  empty `#print-report`, does anything still hide the page you are looking
  at? (It did — `body > *:not(#print-report)` hid `#app`, and that is why
  Ctrl+P produced a blank sheet everywhere except Reports.)
"""

import colorsys
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CSS = ROOT / "server" / "html" / "static" / "css" / "styles.css"
_INDEX = ROOT / "server" / "html" / "index.html"

AA_TEXT = 4.5


# ── colour maths ────────────────────────────────────────────────────────────

def _hex_rgb(value):
    h = value.strip().lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _rgba(value):
    """Parse `#rgb`/`#rrggbb`/`rgba(r,g,b,a)` -> (r, g, b, alpha)."""
    value = value.strip()
    m = re.fullmatch(r"rgba?\(([^)]*)\)", value)
    if m:
        parts = [p.strip() for p in m.group(1).split(",")]
        r, g, b = (int(float(p)) for p in parts[:3])
        a = float(parts[3]) if len(parts) > 3 else 1.0
        return r, g, b, a
    return _hex_rgb(value) + (1.0,)


def _over(top, bottom):
    """Composite `top` (may be translucent) over the opaque `bottom`."""
    tr, tg, tb, ta = _rgba(top)
    br, bg_, bb, _ = _rgba(bottom)
    return "#%02x%02x%02x" % (
        round(ta * tr + (1 - ta) * br),
        round(ta * tg + (1 - ta) * bg_),
        round(ta * tb + (1 - ta) * bb),
    )


def luminance(value):
    def chan(c):
        c /= 255.0
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b, _ = _rgba(value)
    return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)


def contrast(a, b):
    la, lb = luminance(a), luminance(b)
    if la < lb:
        la, lb = lb, la
    return (la + 0.05) / (lb + 0.05)


def _hsl(value):
    r, g, b, _ = _rgba(value)
    return colorsys.rgb_to_hls(r / 255, g / 255, b / 255)  # (h, l, s)


# ── custom-property extraction ──────────────────────────────────────────────

def _blocks(src):
    """[(selector, {prop: value})] for every top-level rule that declares a
    `--custom-property`. Rules nested in @media are skipped: the palettes are
    all declared at the top level."""
    out = []
    depth = 0
    i = 0
    while i < len(src):
        if src.startswith("/*", i):
            i = src.find("*/", i) + 2
            continue
        ch = src[i]
        if ch == "@":
            depth += 0  # at-rules are handled by brace depth below
        if ch == "{":
            if depth == 0:
                sel = src[:i].rsplit("}", 1)[-1].rsplit("{", 1)[-1]
                sel = re.sub(r"/\*.*?\*/", "", sel, flags=re.S).strip()
                end = src.find("}", i)
                body = src[i + 1:end] if end != -1 else ""
                if "--" in body and not sel.startswith("@"):
                    props = dict(re.findall(
                        r"(--[\w-]+)\s*:\s*([^;}]+)", body))
                    out.append((sel, {k: v.strip() for k, v in props.items()}))
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return out


class Palettes:
    """The theme/accent cascade, replayed from the stylesheet itself."""

    def __init__(self, src):
        self.src = src
        self.blocks = _blocks(src)
        self.themes = sorted(set(re.findall(
            r'body\[data-theme="([^"]+)"\]\s*\{', src)))
        self.accents = sorted(set(re.findall(
            r'body\[data-accent="([^"]+)"\]\s*\{', src)))

    def _merge(self, selector):
        merged = {}
        for sel, props in self.blocks:
            if sel == selector:
                merged.update(props)
        return merged

    def resolve(self, theme=None, accent=None, light=None):
        """Resolve one body state. `theme` is a data-theme id (None = the
        built-in dark/light pair). Mirrors the documented source order:
        :root -> body.light -> body[data-theme] -> body[data-accent] ->
        body.light[data-accent]."""
        vals = dict(self._merge(":root"))
        if light is None:
            light = theme is None and False
        if light:
            vals.update(self._merge("body.light"))
        if theme:
            vals.update(self._merge('body[data-theme="%s"]' % theme))
            # A named light theme also carries body.light (applyTheme() in
            # app.js toggles the class for type:'light' themes), but the theme
            # block is declared after it and wins, which the order above
            # already reproduces.
        if accent:
            vals.update(self._merge('body[data-accent="%s"]' % accent))
            if light:
                vals.update(self._merge('body.light[data-accent="%s"]' % accent))
        return vals

    def states(self):
        """Every (label, resolved-vars) pair a user can actually be in."""
        base = [("dark", None, False), ("light", None, True)]
        for t in self.themes:
            probe = self.resolve(theme=t)
            base.append((t, t, luminance(probe["--bg"]) > 0.5))
        for name, theme, light in base:
            for accent in [None] + self.accents:
                label = "%s + %s" % (name, accent or "theme default")
                yield label, self.resolve(theme=theme, accent=accent,
                                          light=light)


def _backgrounds(vals):
    """Every opaque background an accent-ink string is painted on: the three
    surfaces, plus --accent-soft composited over each (the .status-pill /
    .nav-btn.active / .tile-ic chip stack)."""
    surfaces = [vals[k] for k in ("--bg", "--surface", "--surface2")]
    soft = vals.get("--accent-soft")
    out = list(surfaces)
    if soft:
        out += [_over(soft, s) for s in surfaces]
    return out


class TestAccentAsTextContrast(unittest.TestCase):
    def setUp(self):
        self.src = _CSS.read_text()
        self.pal = Palettes(self.src)

    def test_palette_set_is_discovered(self):
        """Guards the guard: if the parser stops finding the palettes the
        contrast test below would pass vacuously."""
        self.assertGreaterEqual(len(self.pal.themes), 11, self.pal.themes)
        self.assertGreaterEqual(len(self.pal.accents), 5, self.pal.accents)
        self.assertIn("amber", self.pal.accents)

    def test_every_state_clears_aa_for_accent_ink(self):
        failures = []
        checked = 0
        for label, vals in self.pal.states():
            for token in ("--accent-ink", "--accent2-ink"):
                ink = vals.get(token)
                self.assertIsNotNone(
                    ink, "%s does not resolve %s" % (label, token))
                for bg in _backgrounds(vals):
                    checked += 1
                    ratio = contrast(ink, bg)
                    if ratio < AA_TEXT:
                        failures.append(
                            "%-34s %s %s on %s = %.2f:1"
                            % (label, token, ink, bg, ratio))
        self.assertGreater(checked, 500, "far too few combinations checked")
        self.assertEqual(
            failures, [],
            "accent-as-text below WCAG AA (4.5:1). Darken the ink for light "
            "palettes / lighten it for dark ones — do NOT touch --accent "
            "itself, it is the fill colour:\n  " + "\n  ".join(failures))

    def test_raw_accent_as_text_really_did_fail(self):
        """The bug this fixes, asserted rather than asserted-about: the raw
        --accent is below AA as text on the shipped defaults (amber, light)."""
        vals = self.pal.resolve(accent="amber", light=True)
        self.assertLess(contrast(vals["--accent"], vals["--surface"]), 3.0)
        self.assertGreaterEqual(
            contrast(vals["--accent-ink"], vals["--surface"]), AA_TEXT)

    def test_ink_keeps_the_accent_hue(self):
        """An ink that clears AA by going grey/black would pass the ratio test
        and destroy the theme. Lightness may move; hue may not."""
        drift = []
        for label, vals in self.pal.states():
            for acc, ink in (("--accent", "--accent-ink"),
                             ("--accent2", "--accent2-ink")):
                ah, _, asat = _hsl(vals[acc])
                ih, _, isat = _hsl(vals[ink])
                if asat < 0.15:
                    continue
                delta = abs(ah - ih) * 360
                delta = min(delta, 360 - delta)
                if delta > 12 or isat < asat * 0.55:
                    drift.append("%s %s->%s hue%+.0f sat %.2f->%.2f"
                                 % (label, vals[acc], vals[ink], delta,
                                    asat, isat))
        self.assertEqual(sorted(set(drift)), [], "\n  ".join(sorted(set(drift))))

    def test_every_palette_declares_its_own_ink(self):
        """A new palette must bring its own ink rather than silently
        inheriting the previous one's."""
        missing = []
        for theme in self.pal.themes:
            props = self.pal._merge('body[data-theme="%s"]' % theme)
            for token in ("--accent-ink", "--accent2-ink"):
                if token not in props:
                    missing.append("body[data-theme=%s] %s" % (theme, token))
        for accent in self.pal.accents:
            if "--accent-ink" not in self.pal._merge(
                    'body[data-accent="%s"]' % accent):
                missing.append("body[data-accent=%s] --accent-ink" % accent)
            if "--accent-ink" not in self.pal._merge(
                    'body.light[data-accent="%s"]' % accent):
                missing.append(
                    "body.light[data-accent=%s] --accent-ink" % accent)
        self.assertEqual(missing, [], "\n  ".join(missing))

    def test_c_accent_and_friends_use_the_ink_token(self):
        """.c-accent is the mandated idiom for every in-app doc link, so the
        token has to reach it — the maths above is worthless otherwise."""
        for rule in (".c-accent", ".c-accent-12", ".c-accent-bold",
                     ".fs-13-accent", ".meta-accent", ".anomaly-link",
                     ".compliance-fix"):
            m = re.search(re.escape(rule) + r"\s*\{([^}]*)\}", self.src)
            self.assertIsNotNone(m, "%s vanished from styles.css" % rule)
            self.assertIn("var(--accent-ink)", m.group(1),
                          "%s still paints text with the fill accent" % rule)

    def test_no_text_rule_still_paints_with_the_fill_accent(self):
        left = re.findall(r"(?<![-a-zA-Z])color: ?var\(--accent2?\)", self.src)
        self.assertEqual(
            left, [],
            "`color: var(--accent)` is the fill colour used as ink — use "
            "var(--accent-ink) / var(--accent2-ink) instead (%d sites)"
            % len(left))

    def test_accent_fills_are_untouched(self):
        """The fix must not have leaked into backgrounds/borders: --accent is
        still what paints a filled button, and its ink stays --accent-contrast."""
        self.assertIn("background: var(--accent); color: var(--accent-contrast, #fff);",
                      self.src)
        self.assertGreater(len(re.findall(r"border-color: ?var\(--accent\)",
                                          self.src)), 10)


# ── a very small selector matcher, for the print cascade ────────────────────

class El:
    def __init__(self, tag, el_id=None, classes=(), parent=None):
        self.tag, self.id, self.classes, self.parent = tag, el_id, set(classes), parent


_COMPOUND = re.compile(
    r"""(?P<tag>^[*\w-]+)|\#(?P<id>[\w-]+)|\.(?P<cls>[\w-]+)
        |\[(?P<attr>[^\]]+)\]|:(?P<pseudo>[\w-]+)(?:\((?P<arg>[^()]*(?:\([^()]*\)[^()]*)*)\))?""",
    re.X)


def _match_compound(sel, el, doc):
    """`sel` is one compound selector (no combinators)."""
    for m in _COMPOUND.finditer(sel):
        if m.group("tag") and m.group("tag") != "*":
            if el.tag != m.group("tag"):
                return False
        elif m.group("id"):
            if el.id != m.group("id"):
                return False
        elif m.group("cls"):
            if m.group("cls") not in el.classes:
                return False
        elif m.group("attr"):
            return False  # no data-* attributes are modelled on these nodes
        elif m.group("pseudo"):
            name, arg = m.group("pseudo"), m.group("arg")
            if name == "not":
                if any(_match(a, el, doc) for a in arg.split(",")):
                    return False
            elif name == "has":
                if not any(_match(arg, other, doc) for other in doc):
                    return False
            elif name == "empty":
                if not getattr(el, "empty", False):
                    return False
            else:
                return False  # unknown pseudo -> treat as non-matching
    return True


def _match(selector, el, doc):
    """Descendant/child combinators only — enough for the print block."""
    parts = re.split(r"\s*(>)\s*|\s+", selector.strip())
    parts = [p for p in parts if p]
    if not parts:
        return False
    if not _match_compound(parts[-1], el, doc):
        return False
    node, i = el.parent, len(parts) - 2
    while i >= 0:
        if parts[i] == ">":
            i -= 1
            if i < 0 or node is None or not _match_compound(parts[i], node, doc):
                return False
            node, i = node.parent, i - 1
            continue
        cur = node
        while cur is not None and not _match_compound(parts[i], cur, doc):
            cur = cur.parent
        if cur is None:
            return False
        node, i = cur.parent, i - 1
    return True


def _specificity(selector):
    ids = len(re.findall(r"#[\w-]+", selector))
    cls = len(re.findall(r"\.[\w-]+|\[[^\]]+\]|:(?!not|has)[\w-]+", selector))
    tags = len(re.findall(r"(?:^|[\s>,])[a-z]+\b", selector))
    return ids, cls, tags


def _print_rules(src):
    """[(selector, {prop: (value, important)}, order)] for the @media print
    blocks, flattened."""
    rules = []
    for m in re.finditer(r"@media print\s*\{", src):
        i = m.end()
        depth = 1
        start = i
        while i < len(src) and depth:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        body = re.sub(r"/\*.*?\*/", "", src[start:i - 1], flags=re.S)
        for rm in re.finditer(r"([^{}]+)\{([^{}]*)\}", body):
            sel, decls = rm.group(1).strip(), rm.group(2)
            if sel.startswith("@"):
                continue
            props = {}
            for d in decls.split(";"):
                if ":" not in d:
                    continue
                k, v = d.split(":", 1)
                props[k.strip()] = (v.replace("!important", "").strip(),
                                    "!important" in v)
            for one in sel.split(","):
                rules.append((one.strip(), props, len(rules)))
    return rules


def _computed(prop, el, doc, rules):
    winner = None
    key = None
    for sel, props, order in rules:
        if prop not in props:
            continue
        if not _match(sel, el, doc):
            continue
        val, imp = props[prop]
        k = (imp, _specificity(sel), order)
        if key is None or k > key:
            key, winner = k, val
    return winner


class TestPrintPrintsWhatYouAreLookingAt(unittest.TestCase):
    """The old rule hid every body child except #print-report, which only the
    Reports page ever fills — so Ctrl+P was a blank sheet on 79 pages."""

    @classmethod
    def setUpClass(cls):
        cls.src = _CSS.read_text()
        cls.rules = _print_rules(cls.src)

    def _doc(self, report_filled=False, modal_open=False, drawer_open=False):
        html = El("html")
        body = El("body", parent=html)
        report = El("div", "print-report", ["print-only"], parent=body)
        report.empty = not report_filled
        app = El("div", "app", parent=body)
        layout = El("div", classes=["app-layout"], parent=app)
        content = El("div", classes=["app-content"], parent=layout)
        main = El("main", "main-content", parent=content)
        container = El("div", classes=["container"], parent=main)
        page = El("div", classes=["page", "active"], parent=container)
        table = El("div", classes=["scrollable-table-wrap", "audit-scroll"],
                   parent=page)
        sidebar = El("nav", classes=["sidebar"], parent=app)
        modal = El("div", "detail-modal",
                   ["modal-overlay"] + (["active"] if modal_open else []),
                   parent=body)
        drawer = El("div", "device-drawer",
                    ["device-drawer"] + (["open"] if drawer_open else []),
                    parent=body)
        doc = [html, body, report, app, layout, content, main, container,
               page, table, sidebar, modal, drawer]
        return doc, dict(body=body, report=report, app=app, main=main,
                         container=container, page=page, table=table,
                         sidebar=sidebar, modal=modal, drawer=drawer)

    def test_index_html_still_has_the_chain_we_model(self):
        html = _INDEX.read_text()
        for needle in ('<div id="app"', 'class="app-layout"',
                       'class="app-content"', '<main id="main-content"',
                       'class="container"', 'id="print-report"'):
            self.assertIn(needle, html,
                          "the modelled print chain drifted from index.html")

    def test_active_page_is_not_hidden_when_the_report_is_empty(self):
        doc, n = self._doc()
        for name in ("app", "main", "container", "page"):
            self.assertNotEqual(
                _computed("display", n[name], doc, self.rules), "none",
                "@media print hides <%s> — Ctrl+P prints a blank sheet on "
                "every page that is not Reports" % name)

    def test_report_takeover_still_works_when_it_is_filled(self):
        doc, n = self._doc(report_filled=True)
        self.assertEqual(_computed("display", n["app"], doc, self.rules),
                         "none", "the Reports print path regressed")
        self.assertEqual(_computed("display", n["report"], doc, self.rules),
                         "block")

    def test_chrome_is_dropped(self):
        doc, n = self._doc()
        self.assertEqual(_computed("display", n["sidebar"], doc, self.rules),
                         "none")

    def test_capped_panels_expand_instead_of_clipping(self):
        doc, n = self._doc()
        self.assertEqual(
            _computed("max-height", n["table"], doc, self.rules), "none",
            "a scroll-capped table would print clipped, silently losing rows")
        self.assertEqual(
            _computed("overflow", n["table"], doc, self.rules), "visible")

    def test_an_open_modal_owns_the_page(self):
        doc, n = self._doc(modal_open=True)
        self.assertEqual(_computed("display", n["main"], doc, self.rules),
                         "none", "the page behind an open modal still prints")
        self.assertNotEqual(_computed("display", n["modal"], doc, self.rules),
                            "none")
        self.assertEqual(_computed("position", n["modal"], doc, self.rules),
                         "static", "a fixed overlay clips at one viewport")

    def test_a_closed_modal_never_prints(self):
        doc, n = self._doc()
        self.assertEqual(_computed("display", n["modal"], doc, self.rules),
                         "none")

    def test_an_open_drawer_owns_the_page(self):
        doc, n = self._doc(drawer_open=True)
        self.assertEqual(_computed("display", n["main"], doc, self.rules),
                         "none")
        self.assertEqual(_computed("display", n["drawer"], doc, self.rules),
                         "block")

    def test_status_board_prints(self):
        """status.html reuses styles.css and has no #print-report at all, so
        the old body-child rule blanked it outright."""
        html = El("html")
        body = El("body", classes=["status-page"], parent=html)
        main = El("main", classes=["status-wrap"], parent=body)
        head = El("header", classes=["status-head"], parent=main)
        doc = [html, body, main, head]
        for el, label in ((main, "main.status-wrap"), (head, "header.status-head")):
            self.assertNotEqual(_computed("display", el, doc, self.rules),
                                "none", "%s does not print" % label)


if __name__ == "__main__":
    unittest.main()
