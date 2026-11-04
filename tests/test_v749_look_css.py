#!/usr/bin/env python3
"""7.4.9: the Pilot look is a block of the stylesheet that cannot reach Classic, and it draws structure, never a palette.

Classic is the stylesheet as it was. The Pilot look is one block at the end of it, and three promises make the switch safe to keep:

* **Every selector in the block starts with `body[data-look="pilot"]`.** A rule that forgot the prefix would restyle Classic for
  everybody, and nothing else would show it: Classic is not the default any more, so no other gate looks at it. `data-look` is
  named nowhere outside the block.
* **The block sets no palette colour.** The neutrals, the status colours and the inks come from the theme in use, so every theme and
  accent keeps working under Pilot. (The old Industrial skin hard-coded its palette after the theme blocks and ignored every theme
  and the accent picker until 5.7.0.) The only custom properties the block declares are its own.
* **Every blurred shadow goes through `--glow-a`**, so "Reduced effects" turns every glow off and a new one cannot be added that
  the switch does not reach. A ring (a spread without a blur) is part of the shape and stays.

The scanner is checked against inputs that break each promise, because a scan over a block it cannot read would pass.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

_ROOT = Path(__file__).resolve().parent.parent
_CSS = (_ROOT / "server" / "html" / "static" / "css" / "styles.css").read_text()
BEGIN = "═══ PILOT LOOK (7.4.9) ═══ BEGIN"
END = "═══ PILOT LOOK (7.4.9) ═══ END"
PREFIX = 'body[data-look="pilot"]'
OWN_PROPERTIES = {"--glow-a", "--tex-a", "--dm-off", "--led", "--c"}


def block(css):
    """The Pilot block, from its begin marker to its end marker."""
    assert css.count(BEGIN) == 1 and css.count(END) == 1, "the Pilot block needs exactly one begin and one end marker"
    start = css.index(BEGIN)
    return css[css.index("*/", start) + 2: css.rindex("/*", 0, css.index(END))]


def rules(css):
    """[(selector, declarations)] for every rule, a rule inside an @media block included."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    out, i, n = [], 0, len(css)
    stack = []
    start = 0
    while i < n:
        c = css[i]
        if c == "{":
            prelude = css[start:i].strip()
            stack.append(prelude)
            start = i + 1
        elif c == "}":
            if stack:
                prelude = stack.pop()
                if not prelude.startswith("@"):
                    out.append((prelude, css[start:i].strip()))
            start = i + 1
        elif c == ";" and not stack:
            start = i + 1
        i += 1
    return out


def selectors(rule_list):
    out = []
    for sel, _body in rule_list:
        out += [s.strip() for s in sel.split(",") if s.strip()]
    return out


def custom_properties(rule_list):
    return {m for _s, body in rule_list for m in re.findall(r"(--[\w-]+)\s*:", body)}


def _balanced_split(value, sep=","):
    parts, depth, cur = [], 0, ""
    for ch in value:
        depth += ch == "("
        depth -= ch == ")"
        if ch == sep and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    return parts + [cur]


def _strip_calls(text):
    """The text with every balanced function call (color-mix, rgba, var) taken out, leaving the lengths."""
    out, depth = "", 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            out += ch
    return out


def unreached_glows(rule_list):
    """Every blurred shadow that does not go through --glow-a, as (selector, shadow)."""
    bad = []
    for sel, body in rule_list:
        for prop, value in re.findall(r"(box-shadow|filter)\s*:\s*([^;]+)", body):
            shadows = []
            if prop == "box-shadow":
                shadows = _balanced_split(value)
            else:
                shadows = [inner for inner in re.findall(r"drop-shadow\((.+)\)", value)]
            for shadow in shadows:
                shadow = shadow.strip()
                if shadow in ("none", "initial", ""):
                    continue
                lengths = re.findall(r"-?\d*\.?\d+(?:px)?", _strip_calls(shadow.replace("inset", "")))
                blur = float(lengths[2].replace("px", "")) if len(lengths) > 2 else 0.0
                if blur > 0 and "--glow-a" not in shadow:
                    bad.append((sel, shadow))
    return bad


class TestThePilotBlock(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.block = block(_CSS)
        cls.rules = rules(cls.block)
        cls.sels = selectors(cls.rules)

    def test_the_block_was_read(self):
        # a scan over nothing passes: the block is long and the count says the parser saw it
        self.assertGreater(len(self.rules), 60, len(self.rules))
        self.assertGreater(len(self.sels), 80, len(self.sels))
        self.assertIn('body[data-look="pilot"][data-fx="reduced"]', self.sels)
        self.assertTrue(any("@media" in line for line in self.block.splitlines()), "no @media block was in the block")

    def test_every_selector_starts_with_the_look(self):
        loose = [s for s in self.sels if not s.startswith(PREFIX)]
        self.assertEqual(loose, [], "a Pilot rule without the prefix would restyle Classic")

    def test_the_look_is_named_nowhere_else(self):
        outside = _CSS[:_CSS.index(BEGIN)] + _CSS[_CSS.index(END):]
        self.assertNotIn("data-look", outside)

    def test_the_block_sets_no_palette_colour(self):
        declared = custom_properties(self.rules)
        self.assertEqual(declared - OWN_PROPERTIES, set(), "the look draws structure; palettes come from the theme")
        self.assertTrue(OWN_PROPERTIES <= declared | {"--c"}, declared)

    def test_the_block_adds_no_important(self):
        self.assertNotIn("!important", self.block)

    def test_every_glow_goes_through_the_effects_setting(self):
        self.assertEqual(unreached_glows(self.rules), [])

    def test_reduced_effects_switch_off_both_strengths(self):
        m = re.search(r'body\[data-look="pilot"\]\[data-fx="reduced"\]\s*\{([^}]*)\}', self.block)
        self.assertIsNotNone(m)
        body = m.group(1) if m else ""
        self.assertRegex(body, r"--glow-a:\s*0%")
        self.assertRegex(body, r"--tex-a:\s*0%")
        # and the normal strengths are not zero, or the switch would have nothing to switch off
        normal = re.search(r'body\[data-look="pilot"\]\s*\{([^}]*)\}', self.block).group(1)
        self.assertRegex(normal, r"--glow-a:\s*[1-9]\d*%")
        self.assertRegex(normal, r"--tex-a:\s*[1-9]\d*%")

    def test_the_hero_texture_follows_the_setting(self):
        hero = [b for s, b in self.rules if s.endswith(".pilot-hero::before")][0]
        self.assertIn("opacity: var(--tex-a)", hero)


class TestTheScannerSeesWhatItIsFor(unittest.TestCase):
    """Each promise, broken in a small stylesheet of its own, is reported; a scan that cannot be failed proves nothing."""

    def parse(self, css):
        return rules(css)

    def test_an_unprefixed_rule_is_found_inside_media_too(self):
        css = 'body[data-look="pilot"] .a { color: red; } .b { color: red; } @media (max-width: 1px) { .c { color: red; } ' \
              'body[data-look="pilot"] .d { color: red; } }'
        loose = [s for s in selectors(self.parse(css)) if not s.startswith(PREFIX)]
        self.assertEqual(loose, [".b", ".c"])

    def test_a_selector_list_is_split(self):
        css = 'body[data-look="pilot"] .a, .b { color: red; }'
        self.assertEqual([s for s in selectors(self.parse(css)) if not s.startswith(PREFIX)], [".b"])

    def test_a_palette_colour_is_found(self):
        css = 'body[data-look="pilot"] { --surface: #fff; --glow-a: 5%; }'
        self.assertEqual(custom_properties(self.parse(css)) - OWN_PROPERTIES, {"--surface"})

    def test_a_glow_that_ignores_the_setting_is_found(self):
        bad = 'body[data-look="pilot"] .x { box-shadow: 0 0 9px color-mix(in srgb, red 50%, transparent); }'
        self.assertEqual(len(unreached_glows(self.parse(bad))), 1)
        also = 'body[data-look="pilot"] .x { filter: drop-shadow(0 0 4px red); }'
        self.assertEqual(len(unreached_glows(self.parse(also))), 1)
        second = 'body[data-look="pilot"] .x { box-shadow: 0 0 0 3px red, 0 0 9px red; }'
        self.assertEqual(len(unreached_glows(self.parse(second))), 1)
        under = 'body[data-look="pilot"] .x { box-shadow: 0 8px 18px -10px red; }'
        self.assertEqual(len(unreached_glows(self.parse(under))), 1)

    def test_a_ring_and_a_governed_glow_are_not(self):
        fine = ('body[data-look="pilot"] .x { box-shadow: 0 0 0 3px color-mix(in srgb, red 16%, transparent), '
                '0 0 9px color-mix(in srgb, red var(--glow-a), transparent); } '
                'body[data-look="pilot"] .y { box-shadow: inset 0 0 0 1.5px var(--muted); filter: none; box-shadow: none; }')
        self.assertEqual(unreached_glows(self.parse(fine)), [])

    def test_a_block_without_markers_is_refused(self):
        with self.assertRaises(AssertionError):
            block("body { color: red; }")


if __name__ == "__main__":
    unittest.main()
