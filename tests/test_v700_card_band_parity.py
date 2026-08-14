#!/usr/bin/env python3
"""A card's header band bleeds to the card edge, so its inset must track the
card's padding at EVERY density.

The band is drawn with negative margins that cancel the card's padding exactly:
`.dash-card` is `padding: 16px 18px` and the header is `margin: -16px -18px`.
Compact density re-pads the card to `11px 13px` and re-states the header inset
as `-11px -13px`.

That compact rule named TWO of the five header wrappers. The other three —
`.row-8-center`, `.ai-tool-head`, `.drift-prof-head` — kept the -16/-18 bleed
against an 11/13 card, so on 15 cards the band stuck out five pixels past its
own card on each side and five above it. Reported from the Drift profiles page.

This is the half-applied-rule shape: the base rule lists all five, and reading
the file for "is the band inset handled?" returns yes. The only way to see it
is to enumerate both lists and compare them, which is what this does.

It is invisible at the default density, which is why it survived. Nobody
reviews CSS with the compact toggle on.
"""
import re
import unittest
from pathlib import Path

_CSS = (Path(__file__).resolve().parent.parent
        / 'server' / 'html' / 'static' / 'css' / 'styles.css')

_INSET = re.compile(r'margin:\s*-(\d+)px\s+-(\d+)px')


def _rules():
    """(selector, body) for every rule in the stylesheet.

    A plain split rather than a regex over the selector shape: the first draft
    used `((?:[^{}]*?first-child,?\\s*)+)\\{` and that nested quantifier
    backtracks catastrophically on a 7,000-line file — the test did not fail,
    it ran for minutes. Linear beats clever here.
    """
    css = _CSS.read_text(encoding='utf-8')
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
    out = []
    for chunk in css.split('}'):
        if '{' not in chunk:
            continue
        sel, body = chunk.rsplit('{', 1)
        out.append((sel.split(';')[-1].strip(), body))
    return out


def _bands():
    """[(wrappers, top_inset, side_inset, is_compact)] for each band rule."""
    out = []
    for sel, body in _rules():
        if '.dash-card' not in sel or 'first-child' not in sel:
            continue
        m = _INSET.search(body)
        if not m:
            continue
        wrappers = set(re.findall(r'>\s*(\.[a-z0-9-]+):first-child', sel))
        if wrappers:
            out.append((wrappers, int(m.group(1)), int(m.group(2)),
                        'density-compact' in sel))
    return out


def _padding(selector):
    """`padding: A B` for a selector, as (A, B)."""
    for sel, body in _rules():
        if selector not in [x.strip() for x in sel.split(',')]:
            continue
        m = re.search(r'padding:\s*(\d+)px\s+(\d+)px', body)
        if m:
            return (int(m.group(1)), int(m.group(2)))
    return None


class TestTheParseWorks(unittest.TestCase):
    """Both assertions below compare two sets. A parse that finds nothing makes
    them trivially equal."""

    def test_it_finds_both_bands(self):
        bands = _bands()
        self.assertGreaterEqual(len(bands), 2, f'parsed {len(bands)} band rules')
        self.assertTrue(any(c for *_r, c in bands), 'no compact band rule found')
        self.assertTrue(any(not c for *_r, c in bands), 'no default band rule found')

    def test_it_finds_the_wrappers(self):
        default = next(w for w, _t, _s, c in _bands() if not c)
        self.assertIn('.section-title', default)
        self.assertGreaterEqual(len(default), 5,
                                f'only parsed {len(default)} wrappers: {default}')

    def test_it_reads_card_padding(self):
        self.assertEqual(_padding('.dash-card'), (16, 18))


class TestEveryWrapperIsHandledAtEveryDensity(unittest.TestCase):

    def test_the_compact_rule_covers_the_same_wrappers(self):
        default = next(w for w, _t, _s, c in _bands() if not c)
        compact = next(w for w, _t, _s, c in _bands() if c)
        missing = sorted(default - compact)
        self.assertEqual(
            missing, [],
            'these header wrappers get the bleeding band at the default '
            'density but keep the DEFAULT inset under compact density, so the '
            'band overhangs its own card:\n'
            + '\n'.join('  ' + m for m in missing))

    def test_each_inset_cancels_its_card_padding(self):
        """The whole point of the negative margin: it must equal the padding it
        is cancelling, or the band is inset or overhanging rather than flush."""
        for wrappers, top, side, compact in _bands():
            pad = _padding('body.density-compact .dash-card' if compact
                           else '.dash-card')
            self.assertIsNotNone(pad, f'card padding not found (compact={compact})')
            self.assertEqual(
                (top, side), pad,
                f'band inset -{top}px -{side}px does not cancel card padding '
                f'{pad[0]}px {pad[1]}px (compact={compact}, {sorted(wrappers)})')


if __name__ == '__main__':
    unittest.main()
