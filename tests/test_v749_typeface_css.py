#!/usr/bin/env python3
"""7.4.9: the typeface option is a block of the stylesheet that cannot reach the default, and it draws no other change.

The system font stack is what the interface has always used and stays the default. B612 is an option, and the stylesheet's part of it
is one block at the end, between two markers. These promises make it safe to keep:

* **The only rules that match anything start with `body[data-typeface="b612"]`.** A rule that forgot the prefix would change the font
  for everybody, and nothing else would show it, because the default is not looked at by any other gate. The attribute is named
  nowhere outside the block.
* **The two `@font-face` rules are the whole of it.** One family, two files that exist and are the pinned ones, Regular for 400-500
  and Bold for 600-700 (the weights B612 has; nothing is faked), Latin letters only, the same `size-adjust` for both so Bold is
  not drawn larger than Regular, `font-display: swap`, and no `local()` source: a B612 installed on the reader's machine could be
  another version with other metrics, and the size ratio was measured against the vendored file.
* **The block changes the font and nothing else.** It sets `--font`, `--font-ui` and `--font-system`, no size, no palette colour, no
  `!important`. The stack it falls back to is the stack the page has always used, held equal to the one at the top of the sheet.
* **The wordmark beside the logo does not change.** `.logo-text` keeps the system stack under B612, and the block names no other
  logo or brand selector.

The scanner is checked against inputs that break each promise, because a scan over a block it cannot read would pass.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v749_look_css import custom_properties, rules, selectors  # noqa: E402
from test_v749_typeface_font import PINS  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_CSS_PATH = _ROOT / "server" / "html" / "static" / "css" / "styles.css"
_CSS = _CSS_PATH.read_text()
BEGIN = "═══ TYPEFACE (7.4.9) ═══ BEGIN"
END = "═══ TYPEFACE (7.4.9) ═══ END"
PREFIX = 'body[data-typeface="b612"]'
OWN_PROPERTIES = {"--font-system", "--font", "--font-ui"}
LOGO_WORDS = ("logo", ".brand", "brand-", "favicon", "login-page", "#login")
# U+0000-00FF and the usual punctuation: the "latin" subset in the package's unicode.json
LATIN = ("U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,"
         "U+2193,U+2212,U+2215,U+FEFF,U+FFFD")
WEIGHTS = {"b612-latin-400-normal.woff2": "400 500", "b612-latin-700-normal.woff2": "600 700"}


def block(css):
    """The Typeface block, from its begin marker to its end marker."""
    assert css.count(BEGIN) == 1 and css.count(END) == 1, "the Typeface block needs exactly one begin and one end marker"
    start = css.index(BEGIN)
    return css[css.index("*/", start) + 2: css.rindex("/*", 0, css.index(END))]


def font_faces(css):
    """[{descriptor: value}] for every @font-face of the text, comments removed and whitespace folded."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    out = []
    for body in re.findall(r"@font-face\s*\{([^}]*)\}", css):
        out.append({name: " ".join(value.split()) for name, value in re.findall(r"([a-z-]+)\s*:\s*([^;]+);", body)})
    return out


def face_problems(faces):
    """Everything wrong with a list of font-face descriptor sets, as readable lines (empty when it is right)."""
    bad = []
    if len(faces) != 2:
        return [f"{len(faces)} faces, not 2"]
    sizes = {f.get("size-adjust") for f in faces}
    if len(sizes) != 1:
        bad.append(f"the faces use different size-adjust values: {sorted(str(s) for s in sizes)}")
    for f in faces:
        urls = re.findall(r"url\(([^)]*)\)", f.get("src", ""))
        name = urls[0].strip("'\"").rsplit("/", 1)[-1] if len(urls) == 1 else None
        label = name or "?"
        if f.get("font-family", "").strip("'\"") != "B612":
            bad.append(f"{label}: the family is {f.get('font-family')!r}")
        if f.get("font-style") != "normal":
            bad.append(f"{label}: the style is {f.get('font-style')!r}")
        if name not in WEIGHTS:
            bad.append(f"{label}: not one of the vendored files")
        elif f.get("font-weight") != WEIGHTS[name]:
            bad.append(f"{label}: weights {f.get('font-weight')!r}, wanted {WEIGHTS[name]!r}")
        if f.get("font-display") != "swap":
            bad.append(f"{label}: font-display is {f.get('font-display')!r}")
        if "local(" in f.get("src", ""):
            bad.append(f"{label}: a local() source")
        if not re.fullmatch(r"url\([^)]*\) format\('woff2'\)", f.get("src", "")):
            bad.append(f"{label}: src is {f.get('src')!r}")
        if f.get("unicode-range", "").replace(" ", "") != LATIN:
            bad.append(f"{label}: the unicode-range is not the Latin subset")
        m = re.fullmatch(r"(\d+(?:\.\d+)?)%", f.get("size-adjust", ""))
        if not m or not 85 <= float(m.group(1)) <= 100:
            bad.append(f"{label}: size-adjust {f.get('size-adjust')!r} is outside 85%..100%")
    if sorted(WEIGHTS.values()) != sorted(f.get("font-weight", "") for f in faces):
        bad.append("the two faces do not cover 400-500 and 600-700 once each")
    return bad


def root_value(css, prop):
    """The value of a custom property in the first :root rule that sets it, whitespace folded."""
    for sel, body in rules(css):
        if sel.strip() == ":root":
            m = re.search(rf"(?<![\w-]){re.escape(prop)}\s*:\s*([^;]+);", body)
            if m:
                return " ".join(m.group(1).split())
    return None


class TestTheTypefaceBlock(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.block = block(_CSS)
        cls.rules = rules(cls.block)
        cls.sels = selectors(cls.rules)
        cls.faces = font_faces(cls.block)

    def test_the_block_was_read(self):
        # a scan over nothing passes: the block is two font faces and two rules
        self.assertEqual(len(self.faces), 2)
        self.assertEqual(len(self.rules), 2, self.rules)
        self.assertIn(PREFIX, self.sels)
        self.assertIn(PREFIX + " .logo-text", self.sels)

    def test_every_selector_starts_with_the_attribute(self):
        loose = [s for s in self.sels if not s.startswith(PREFIX)]
        self.assertEqual(loose, [], "a rule without the prefix would change the font for everybody")

    def test_the_attribute_is_named_nowhere_else(self):
        outside = _CSS[:_CSS.index(BEGIN)] + _CSS[_CSS.index(END):]
        self.assertNotIn("data-typeface", outside)

    def test_the_stylesheet_declares_no_other_font_face(self):
        # the page ships one extra family and says so; a second @font-face (in the block or outside it) is a decision to make visible
        live = re.sub(r"/\*.*?\*/", "", _CSS, flags=re.S)          # the block's own comment names the rule, which is not a rule
        self.assertEqual(live.count("@font-face"), 2)
        self.assertEqual(re.sub(r"/\*.*?\*/", "", self.block, flags=re.S).count("@font-face"), 2)
        self.assertNotIn("@import", live)

    def test_the_faces_are_the_ones_described(self):
        self.assertEqual(face_problems(self.faces), [])

    def test_the_urls_are_the_vendored_files(self):
        found = set()
        for f in self.faces:
            for url in re.findall(r"url\(([^)]*)\)", f["src"]):
                target = (_CSS_PATH.parent / url.strip("'\"")).resolve()
                self.assertTrue(target.is_file(), f"{url} does not resolve to a file")
                found.add(target.name)
        self.assertEqual(found, set(PINS), "the stylesheet loads files other than the pinned ones")

    def test_the_block_changes_the_font_and_nothing_else(self):
        declared = custom_properties(self.rules)
        self.assertEqual(declared, OWN_PROPERTIES)
        for sel, body in self.rules:
            # every property a rule sets: the three tokens, and font-family on the wordmark; no size, no weight, no colour
            props = set(re.findall(r"(?:^|[;{\s])([a-z-]+)\s*:", body))
            self.assertLessEqual(props - OWN_PROPERTIES, {"font-family"}, (sel, props))
        self.assertNotIn("!important", self.block)

    def test_the_override_puts_b612_first_and_the_system_stack_behind_it(self):
        body = [b for s, b in self.rules if s == PREFIX][0]
        for prop in ("--font", "--font-ui"):
            m = re.search(rf"(?<![\w-]){prop}\s*:\s*([^;]+);", body)
            self.assertIsNotNone(m, prop)
            self.assertEqual(" ".join(m.group(1).split()), "'B612', var(--font-system)", prop)

    def test_the_system_stack_is_the_one_the_page_has_always_used(self):
        body = [b for s, b in self.rules if s == PREFIX][0]
        stack = " ".join(re.search(r"--font-system\s*:\s*([^;]+);", body).group(1).split())
        self.assertTrue(stack.startswith("-apple-system, "), stack)
        self.assertEqual(stack, root_value(_CSS, "--font"), "the fallback drifted from --font")
        self.assertEqual(stack, root_value(_CSS, "--font-ui"), "the fallback drifted from --font-ui")

    def test_the_wordmark_keeps_the_system_stack(self):
        pin = [b for s, b in self.rules if s == PREFIX + " .logo-text"][0]
        self.assertEqual(" ".join(pin.split()), "font-family: var(--font-system);")
        touched = [s for s in self.sels if any(w in s.lower() for w in LOGO_WORDS)]
        self.assertEqual(touched, [PREFIX + " .logo-text"], "only the wordmark is named, and only to keep it as it is")
        # and the words are the real ones: the sheet does name the wordmark outside the block
        self.assertIn(".logo-text", _CSS[:_CSS.index(BEGIN)])

    def test_the_default_font_of_the_page_is_untouched(self):
        outside = _CSS[:_CSS.index(BEGIN)]
        self.assertRegex(outside, r"--font:\s*-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;")
        self.assertNotIn("'B612'", outside)


class TestTheScannerSeesWhatItIsFor(unittest.TestCase):
    """Each promise, broken in a small stylesheet of its own, is reported; a scan that cannot be failed proves nothing."""

    GOOD = [
        {"font-family": "'B612'", "font-style": "normal", "font-weight": "400 500", "font-display": "swap", "size-adjust": "92%",
         "src": "url(../vendor/fonts/files/b612-latin-400-normal.woff2) format('woff2')", "unicode-range": LATIN},
        {"font-family": "'B612'", "font-style": "normal", "font-weight": "600 700", "font-display": "swap", "size-adjust": "92%",
         "src": "url(../vendor/fonts/files/b612-latin-700-normal.woff2) format('woff2')", "unicode-range": LATIN},
    ]

    def changed(self, which, **kw):
        faces = [dict(f) for f in self.GOOD]
        faces[which].update(kw)
        return face_problems(faces)

    def test_the_good_pair_passes(self):
        self.assertEqual(face_problems(self.GOOD), [])

    def test_an_unprefixed_rule_is_found(self):
        css = 'body[data-typeface="b612"] .a { color: red; } body { --font: x; } @media (min-width: 1px) { .c { color: red; } }'
        self.assertEqual([s for s in selectors(rules(css)) if not s.startswith(PREFIX)], ["body", ".c"])

    def test_a_palette_colour_is_found(self):
        css = 'body[data-typeface="b612"] { --font: x; --surface: #fff; --accent: red; }'
        self.assertEqual(custom_properties(rules(css)) - OWN_PROPERTIES, {"--surface", "--accent"})

    def test_a_wrong_weight_range_is_found(self):
        self.assertTrue(any("weights" in p for p in self.changed(1, **{"font-weight": "500 700"})))
        self.assertTrue(any("cover" in p for p in self.changed(1, **{"font-weight": "400 500"})))

    def test_a_different_size_for_one_face_is_found(self):
        self.assertTrue(any("different size-adjust" in p for p in self.changed(1, **{"size-adjust": "100%"})))

    def test_a_size_outside_the_range_is_found(self):
        faces = [dict(f, **{"size-adjust": "70%"}) for f in self.GOOD]
        self.assertTrue(any("outside" in p for p in face_problems(faces)))

    def test_a_local_source_is_found(self):
        src = "local('B612'), url(../vendor/fonts/files/b612-latin-400-normal.woff2) format('woff2')"
        self.assertTrue(any("local()" in p for p in self.changed(0, src=src)))

    def test_another_file_is_found(self):
        src = "url(../vendor/fonts/files/b612-latin-400-italic.woff2) format('woff2')"
        self.assertTrue(any("not one of the vendored files" in p for p in self.changed(0, src=src)))

    def test_another_family_is_found(self):
        self.assertTrue(any("family" in p for p in self.changed(0, **{"font-family": "'Inter'"})))

    def test_a_blocking_display_is_found(self):
        self.assertTrue(any("font-display" in p for p in self.changed(0, **{"font-display": "block"})))

    def test_a_narrower_range_is_found(self):
        self.assertTrue(any("unicode-range" in p for p in self.changed(0, **{"unicode-range": "U+0000-007F"})))

    def test_a_third_face_is_found(self):
        self.assertEqual(face_problems(self.GOOD + [self.GOOD[0]]), ["3 faces, not 2"])

    def test_the_parser_reads_a_real_face(self):
        css = ("@font-face {\n font-family: 'B612';\n font-weight: 400 500;\n src: url(a.woff2) format('woff2');\n"
               " unicode-range: U+0000-00FF,\n   U+0131;\n}\n/* @font-face { font-family: x; } */")
        faces = font_faces(css)
        self.assertEqual(len(faces), 1)
        self.assertEqual(faces[0]["unicode-range"], "U+0000-00FF, U+0131")

    def test_the_logo_words_find_a_wordmark_rule(self):
        css = 'body[data-typeface="b612"] .logo-text { font-family: x; } body[data-typeface="b612"] .sidebar .brand .logo-img { x: y; }'
        touched = [s for s in selectors(rules(css)) if any(w in s.lower() for w in LOGO_WORDS)]
        self.assertEqual(len(touched), 2)

    def test_a_block_without_markers_is_refused(self):
        with self.assertRaises(AssertionError):
            block("body { color: red; }")

    def test_root_value_reads_the_first_root_rule_that_sets_it(self):
        css = ":root { --a: 1; --font: x, y; } :root { --font: z; } body { --font: q; }"
        self.assertEqual(root_value(css, "--font"), "x, y")
        self.assertIsNone(root_value(css, "--missing"))


if __name__ == "__main__":
    unittest.main()
