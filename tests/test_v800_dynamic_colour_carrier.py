#!/usr/bin/env python3
"""8.0.0: an element that uses a "dynamic colour" placeholder class carries its colour some other way.

Removing the inline styles (42dca579) turned each style that held a value into a class with no rule: `/* .isl-N — dynamic colour, applied via data-color attribute */`. The colour is meant to
arrive from the element, as a `data-color` attribute that app.js turns into `style.color`, or from another class chosen at render time (`c-red`, `c-amber`, `${vc}`, `is-selected`). The class-parity gate
accepted the placeholders as reviewed without looking at the elements, and four of them had nothing: the Patch Report's Status and Online lines, the audit Metrics tiles and a row of the drift
table were drawn with no colour at all, while the page kept computing the colour into a variable it never read (`statusColor`, `col`, `rowStyle`). tests/test_v800_dropped_styles_e2e.py measures the
four in a browser; this reads every render site.

The rule is read off the sources: the placeholders are the classes whose only trace in styles.css is that comment; for each element in the JS and the HTML that carries one, the start tag must
carry `data-color` (or another `data-*` the colour hooks read), a class interpolation (`${...}` inside the class attribute), or a colour utility class.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = _ROOT / "server" / "html"
_JS = _HTML / "static" / "js"
_CSS = _HTML / "static" / "css" / "styles.css"

_PLACEHOLDER = re.compile(r"^/\* \.(isl-\d+) — dynamic colour", re.M)
_COLOUR_ATTRS = ("data-color", "data-bg", "data-bd", "data-bd-color", "data-bd-style")
_COLOUR_CLASS = re.compile(r"(?<![\w-])(?:c-(?:red|green|amber|muted|accent|text|danger|blue)|text-(?:red|green|amber|muted))(?![\w-])")


def _placeholders():
    return sorted(set(_PLACEHOLDER.findall(_CSS.read_text())))


def _start_tag(text, pos):
    """The start tag that holds position `pos`: from the `<` before it to the `>` that closes it, ignoring any `>` inside a ${...} expression."""
    lt = text.rfind("<", 0, pos)
    if lt < 0:
        return ""
    depth = 0
    i = lt
    while i < len(text):
        c = text[i]
        if c == "$" and text[i + 1:i + 2] == "{":
            depth += 1
            i += 2
            continue
        if c == "}" and depth:
            depth -= 1
        elif c == ">" and depth == 0:
            return text[lt:i + 1]
        i += 1
    return text[lt:]


def _class_attr(tag):
    m = re.search(r'class="([^"]*)"', tag, re.S)
    return m.group(1) if m else ""


def _carries_a_colour(tag):
    if any(a in tag for a in _COLOUR_ATTRS):
        return True
    classes = _class_attr(tag)
    return "${" in classes or bool(_COLOUR_CLASS.search(classes))


def _sites(placeholders):
    out = []
    files = sorted(_JS.glob("*.js")) + [_HTML / "index.html"]
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        for cls in placeholders:
            for m in re.finditer(r"(?<![\w-])" + re.escape(cls) + r"(?![\w-])", text):
                out.append((f.name, text.count("\n", 0, m.start()) + 1, cls, _start_tag(text, m.start())))
    return out


class TestEveryPlaceholderElementCarriesItsColour(unittest.TestCase):
    def test_the_elements_that_use_a_placeholder_class(self):
        placeholders = _placeholders()
        sites = _sites(placeholders)
        # Control: the population must be what it was when this was written, or the rule inspected nothing.
        self.assertGreaterEqual(len(placeholders), 10, f"only {len(placeholders)} placeholder classes found in styles.css: the detector is broken")
        self.assertGreaterEqual(len(sites), 10, f"only {len(sites)} render sites found for them: the detector is broken")
        bare = [f"{f}:{ln} {cls}  {tag[:90]!r}" for f, ln, cls, tag in sites if not _carries_a_colour(tag)]
        self.assertEqual(bare, [], f"{len(bare)} of {len(sites)} elements use a 'dynamic colour' placeholder class and carry no colour: no data-color, no class chosen at render time, no colour class. "
                                   "Give the element `data-color=\"${value}\"` or a c-* class, or give the class a real rule:\n  " + "\n  ".join(bare))

    def test_the_tag_scanner_reads_past_a_greater_than_inside_an_expression(self):
        """A `>` inside ${...} ended the first version of this scan early and read a carrier as missing."""
        text = '<td class="isl-535 ${r.drifted > 0 ? \'fw-600\' : \'\'}" data-color="${driftColor}">${r.drifted}</td>'
        tag = _start_tag(text, text.index("isl-535"))
        self.assertTrue(tag.endswith('data-color="${driftColor}">'), tag)
        self.assertTrue(_carries_a_colour(tag))

    def test_the_rule_tells_a_carrier_from_a_bare_element(self):
        carriers = [
            '<span class="isl-1" data-color="${c}">',
            '<div class="value isl-2 ${cls}">',
            '<div class="value isl-3 c-red">',
            '<div class="isl-4" data-bg="${bg}" data-bd="${bd}">',
        ]
        bare = [
            '<tr class="isl-543">',
            '<div class="value isl-377">',
            '<div class="isl-5 fw-600">',
        ]
        for tag in carriers:
            with self.subTest(carrier=tag):
                self.assertTrue(_carries_a_colour(tag))
        for tag in bare:
            with self.subTest(bare=tag):
                self.assertFalse(_carries_a_colour(tag))


if __name__ == "__main__":
    unittest.main()
