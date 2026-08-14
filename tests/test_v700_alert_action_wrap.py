#!/usr/bin/env python3
"""An Alerts row carries up to ten action buttons. They must wrap.

Reported from a live instance: "Triage Fix Mute Clear line Resolve Incident
Ticket … way too much side scroll". The cell was `<td class="nowrap">`, so ten
buttons laid out as one ~700px line and the whole table scrolled sideways to
fit a column nobody reads horizontally.

Measured in a browser after the fix: the cell settles at 288px and four lines,
and no ancestor of the table scrolls horizontally at 1440px. Both numbers are
load-bearing and both are properties of the RENDERED page, which is why this
file does not try to re-measure them — a Playwright test whose filename lacks
`e2e` runs in `make test-fast` AND the serial gate, and this one would buy a
few minutes of wall-clock forever to re-confirm a two-line CSS rule.

So this pins the two source facts that cannot drift silently, and leaves the
measurement to the rendered box-overflow sweep that already boots the seeded
stack:

  * the cell is not `nowrap` — that single class is what produced the bug;
  * the rule it uses actually wraps and is bounded, because a flex row without
    `flex-wrap` is a `nowrap` cell wearing a different name, and one without a
    width bound lets the column widen the table again instead.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js' / 'app-alerts.js'
_CSS = _ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'


def _rule(css, selector):
    m = re.search(re.escape(selector) + r'\s*\{([^}]*)\}', css)
    return ' '.join(m.group(1).split()) if m else None


class TestTheFilesAreReadable(unittest.TestCase):
    """Every assertion below is a substring search, and a search over an empty
    string fails in the reassuring direction for the negative ones."""

    def test_the_renderer_is_present(self):
        self.assertIn('alert-actions', _JS.read_text(encoding='utf-8'))

    def test_the_stylesheet_is_present(self):
        self.assertIsNotNone(_rule(_CSS.read_text(encoding='utf-8'), '.row-6-wrap'),
                             'the stylesheet did not parse — a known-good rule '
                             'is missing, so the checks below prove nothing')


class TestTheActionCellWraps(unittest.TestCase):

    def test_the_cell_is_not_nowrap(self):
        js = _JS.read_text(encoding='utf-8')
        self.assertNotIn('<td class="nowrap">${actions}</td>', js,
                         'the alerts action cell is back on `nowrap`: ten '
                         'buttons render as one long line and the table '
                         'scrolls sideways')

    def test_the_cell_uses_the_wrapping_container(self):
        js = _JS.read_text(encoding='utf-8')
        self.assertIn('class="alert-actions"', js,
                      'the action buttons are no longer in .alert-actions, so '
                      'whatever wraps them now is unpinned')

    def test_the_rule_wraps_and_is_bounded(self):
        body = _rule(_CSS.read_text(encoding='utf-8'), '.alert-actions')
        self.assertIsNotNone(body, '.alert-actions is gone from styles.css')
        self.assertIn('flex-wrap: wrap', body,
                      'a flex row that does not wrap is the original bug with '
                      'a new class name')
        self.assertRegex(body, r'max-width:\s*\d',
                         'without an upper bound the column widens the table '
                         'until it scrolls sideways again')
        self.assertRegex(body, r'min-width:\s*\d',
                         'without a lower bound the column collapses to the '
                         'widest single button and stacks one per line — '
                         'measured at 152px / 8 lines before this was added')


if __name__ == '__main__':
    unittest.main()
