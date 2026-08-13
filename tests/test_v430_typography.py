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

_CSS_DIR = Path(__file__).parent.parent / "server" / "html" / "static" / "css"

# v6.4.3: this read styles.css and nothing else, while five stylesheets ship and
# four of them are linked by live pages (report, fleet-query, status, portal,
# swagger). Two real off-scale sizes were sitting in the unread ones — a 15px
# heading on the public status page, and a 14px body size in the report, 14
# being a stop this scale deliberately RETIRED so it could not creep back. The
# gate could not see either.
#
# swagger.css is vendored, so it is excluded rather than reformatted.
_VENDORED = {"swagger.css"}
_CSS_FILES = sorted(f for f in _CSS_DIR.glob("*.css") if f.name not in _VENDORED)
CSS = "\n".join(f.read_text() for f in _CSS_FILES)

# ints = the original scale; halves = v6 Clarity stops adopted so far
# (sidebar: 12.5 nav rows, 9.5 eyebrows/count pills; topbar: 11.5 health;
#  frame: 13.5 body, 19 page title — 28 stays for display numerals).
# 14 was a legacy stop that predated the v6 scale (whose body anchor is 13.5). It
# lingered on ~9 selectors — device names, the status board, a mono code, a score
# numeral — so 13.5px body text sat next to 14px body text. Folded onto the scale
# (body → 13.5, headings/chrome/numerals → 13) and dropped here so it can't creep back.
CANONICAL = {28, 19, 16, 13.5, 13, 12.5, 12, 11.5, 11, 10, 9.5}

# Deliberate display-size exceptions: size → max occurrences.
# .status-num 64 / .hh-num 48 (big stat digits), .pin-code 36 (enrollment PIN),
# .isl-286/.isl-326 24 (emoji-glyph pickers), .isl-313 22 (device icon glyph),
# .isl-1 20 (TOTP input).
# v6.4.3, when this gate started reading the other stylesheets: 22 goes 1 -> 2
# for `.status-card-v` (status.css), a big stat digit on the public status page —
# the same role as .status-num, which is already excepted. report.css's
# `.card .v` (24px) is the same kind of numeral and fits inside the existing
# budget of 2. Both are display digits, not body copy: they are excepted rather
# than folded onto the scale because shrinking them to 13.5px would make the
# headline figure smaller than the label under it.
EXCEPTIONS = {64: 1, 48: 1, 36: 1, 24: 2, 22: 2, 20: 1}


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
