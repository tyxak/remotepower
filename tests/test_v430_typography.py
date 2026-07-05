#!/usr/bin/env python3
"""v4.3.0: typography guardrail — mechanically enforce the CLAUDE.md scale.

The canonical scale is {28,16,14,13,12,11,10}px (page title, section heading,
body, table cells, hints, badges, tiny badges). Off-scale sizes and fractional
px keep creeping in through new cards and get swept in follow-up releases —
this pins the rule so review doesn't have to catch it.

v6.0.0 "ClarityMatters": the chosen design (design/v6-claritymatters/
chosen-design.html) carries half-px stops — 12.5 nav rows, 9.5 mono eyebrows/
kbd (later 13.5 body, 11.5 sub-sub, 19 pane headings). Surfaces adopt them as
they migrate; each newly-used stop is added to CANONICAL here, deliberately,
per surface — anything NOT on the design scale still fails.

Display numerals (big stat digits, the enrollment PIN, icon glyph boxes) are
deliberate exceptions, enumerated below WITH their allowed occurrence count —
adding another use of an exception size fails until it's consciously listed.
"""
import re
import unittest
from collections import Counter
from pathlib import Path

CSS = (Path(__file__).parent.parent / "server" / "html" / "static" / "css"
       / "styles.css").read_text()

# ints = the original scale; halves = v6 Clarity stops adopted so far
# (sidebar: 12.5 nav rows, 9.5 eyebrow labels + count pills;
#  topbar: 11.5 health readout).
CANONICAL = {28, 16, 14, 13, 12.5, 12, 11.5, 11, 10, 9.5}

# Deliberate display-size exceptions: size → max occurrences.
# .status-num 64 / .hh-num 48 (big stat digits), .pin-code 36 (enrollment PIN),
# .isl-286/.isl-326 24 (emoji-glyph pickers), .isl-313 22 (device icon glyph),
# .isl-1 20 (TOTP input).
EXCEPTIONS = {64: 1, 48: 1, 36: 1, 24: 2, 22: 1, 20: 1}


class TestTypographyScale(unittest.TestCase):
    def _sizes(self):
        return [s.strip() for s in re.findall(r'font-size:\s*([^;}]+)', CSS)]

    def test_no_offscale_fraction_or_relative_font_sizes(self):
        # px only; halves allowed ONLY where the v6 design scale has a .5 stop
        # (checked against CANONICAL below) — no other fractions, no em/rem/%.
        bad = [s for s in self._sizes() if not re.fullmatch(r'\d+(?:\.5)?px', s)]
        self.assertEqual(bad, [],
                         f"font-size values must be whole or half px (no other "
                         f"fractions, no em/rem/%%): {bad}")

    def test_sizes_stay_on_the_canonical_scale(self):
        counts = Counter(float(s[:-2]) for s in self._sizes()
                         if re.fullmatch(r'\d+(?:\.5)?px', s))
        offenders = {}
        for size, n in counts.items():
            if size in CANONICAL:
                continue
            if size in EXCEPTIONS and n <= EXCEPTIONS[size]:
                continue
            offenders[f'{size:g}px'] = n
        self.assertEqual(offenders, {},
                         "font sizes off the canonical scale (and not a listed "
                         "display exception): "
                         f"{offenders}. Fold onto the scale, or if genuinely a "
                         "display numeral, add it to EXCEPTIONS with a comment.")

    def test_no_bare_monospace(self):
        # the mono stack lives in var(--font-mono); a bare `font-family:
        # monospace` forks the typography (user-flagged regression class)
        bad = [m for m in re.findall(r'font-family:\s*([^;}]+)', CSS)
               if re.fullmatch(r'monospace', m.strip())]
        self.assertEqual(bad, [], "bare `font-family: monospace` — use var(--font-mono)")


if __name__ == '__main__':
    unittest.main()
