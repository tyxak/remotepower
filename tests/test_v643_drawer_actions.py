#!/usr/bin/env python3
"""Two Copy summary buttons, and 28 actions with no way to narrow them.

The device drawer's quick-action grid had grown to 29 entries, two of which
were BOTH labelled "Copy summary" and did different things: `_copyDeviceSummary`
copied seven basic lines, `copyDeviceSummary` copied the rich summary (CPU, RAM,
uptime, load) and was the one fixed in v6.4.2 when it turned out to be reading
three sysinfo keys the heartbeat sanitizer never stores. Side by side in the
same grid, identical labels, different results, and nothing on screen to tell
them apart. The leftover is gone; the maintained one stays.

The filter is the long-deferred backlog item, which had been scoped as "must
force-load all tabs" — true of a drawer that had many, and it has had two for
some time now, with Actions the default. The grid was the thing worth filtering,
not the tabs.

The threshold matters more than it looks: an agentless host renders far fewer
actions, so the box hides — and a hidden box that is still filtering leaves the
operator looking at three buttons with nothing explaining why. It clears itself
on the way out.
"""
import re
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()


def _actions_block():
    """The drawer's `const actions = [...]` literal."""
    i = _APP.find("document.getElementById('drawer-actions-grid')")
    assert i > 0
    seg = _APP[max(0, i - 16000):i]
    m = list(re.finditer(r'const actions = \[', seg))[-1]
    return seg[m.start():]


def _labels():
    return re.findall(r"^\s*\['[a-zA-Z-]+',\s*'([^']+)'", _actions_block(), re.M)


class TestNoTwoActionsShareALabel(unittest.TestCase):
    def test_every_quick_action_label_is_unique(self):
        """The assertion that was false. Two buttons cannot claim to do the
        same thing and do different things."""
        labels = _labels()
        dupes = sorted({x for x in labels if labels.count(x) > 1})
        self.assertEqual(dupes, [], f'duplicate drawer action labels: {dupes}')

    def test_the_grid_is_not_empty(self):
        """Positive control: if the block regex ever stops matching, the
        uniqueness test above passes over an empty list and proves nothing."""
        self.assertGreater(len(_labels()), 20)

    def test_the_surviving_copy_summary_is_the_maintained_one(self):
        """_copyDeviceSummary was the thin one; copyDeviceSummary is the one
        v6.4.2 fixed and tests/test_v612_ux.py pins."""
        self.assertIn('Copy summary', _labels())
        self.assertNotIn('_copyDeviceSummary', _APP)
        self.assertIn('async function copyDeviceSummary(', _APP)


class TestTheFilter(unittest.TestCase):
    def test_the_input_exists_and_dispatches(self):
        self.assertIn('id="drawer-action-filter"', _HTML)
        self.assertIn('data-input="_drawerActionFilter"', _HTML)
        self.assertIn('function _drawerActionFilter(', _APP)

    def test_it_is_hidden_until_the_grid_is_long_enough(self):
        """A search box over four buttons is noise."""
        self.assertIn('_DRAWER_FILTER_MIN_ACTIONS', _APP)
        self.assertIn('id="drawer-action-filter-wrap"', _HTML)
        self.assertRegex(_APP, r'wrap\.classList\.toggle\(\'d-none\', tooFew\)')

    def test_hiding_the_box_also_clears_it(self):
        """The bug this guards: a hidden control that is still filtering."""
        body = re.search(r'function _drawerActionFilter\(\).*?\n\}', _APP, re.S).group(0)
        self.assertIn("if (tooFew && box.value) box.value = ''", body)

    def test_the_filter_survives_a_re_render(self):
        """The grid is rebuilt on every drawer open and on drawerStep. Without
        re-applying, stepping to the next host silently un-filters."""
        self.assertIn('_drawerActionFilter();   // re-apply', _APP)

    def test_matching_uses_a_data_attribute_not_text_content(self):
        """Each button is an icon <span> plus a text <span>; matching on
        textContent would also match the SVG's whitespace."""
        self.assertIn('data-act-label="', _APP)
        body = re.search(r'function _drawerActionFilter\(\).*?\n\}', _APP, re.S).group(0)
        self.assertIn('dataset.actLabel', body)
        self.assertNotIn('textContent', body)

    def test_a_no_match_state_exists_and_can_be_cleared(self):
        self.assertIn('id="drawer-action-filter-none"', _HTML)
        self.assertIn('data-action="clearDrawerActionFilter"', _HTML)
        self.assertIn('function clearDrawerActionFilter(', _APP)

    def test_the_no_match_hint_is_hidden_when_the_query_is_empty(self):
        """Otherwise clearing the box leaves 'No action matches' on screen
        above a full grid."""
        body = re.search(r'function _drawerActionFilter\(\).*?\n\}', _APP, re.S).group(0)
        self.assertRegex(body, r"toggle\('d-none', shown > 0 \|\| !q\)")

    def test_the_label_is_lowercased_on_both_sides(self):
        """Case-insensitive without a per-keystroke toLowerCase over the grid."""
        self.assertIn("label.toLowerCase()", _APP)
        body = re.search(r'function _drawerActionFilter\(\).*?\n\}', _APP, re.S).group(0)
        self.assertIn('.toLowerCase()', body)

    def test_the_input_is_labelled_for_a_screen_reader(self):
        i = _HTML.find('id="drawer-action-filter"')
        self.assertIn('aria-label=', _HTML[i:i + 400])


class TestTheJsParses(unittest.TestCase):
    def test_node_check(self):
        r = subprocess.run(['node', '--check',
                            str(_ROOT / 'server/html/static/js/app.js')],
                           capture_output=True, text=True)
        if r.returncode != 0 and 'not found' in (r.stderr or '').lower():
            self.skipTest('node unavailable')
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
