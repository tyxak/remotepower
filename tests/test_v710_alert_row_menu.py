#!/usr/bin/env python3
"""v7.1.0: an open alert keeps four actions on the row; the rest go in a menu.

The row carried up to eleven buttons. Wrapped inside a bounded column they took
three lines per alert, and one long evidence value (an 80-character path in a
`nowrap` span) set the Title column's minimum and pushed the table past its
card anyway. Measured after the change at 1440px: one line per row, no
horizontal scroll on the alerts table.

What is pinned, by running the real `_alertRowHtml` under V8:
  * Triage, Fix (when a playbook applies), Mute and Resolve stay on the row.
  * Everything else sits in the row's <template class="row-more-items"> and
    carries a text label, so nothing in the menu is icon-only.
  * A resolved alert keeps its copy-link icon and gets no menu.
  * A long evidence value is not inside a `nowrap` element any more.

And, from the source, the parts a browser needs: the menu handler exists, the
periodic refresh pauses while a menu is open, and the menu is fixed-position so
a scrolling table cannot clip it.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v642_alerts_ui import _HAVE_V8, _V8  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text(encoding='utf-8')
CSS = (ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text(encoding='utf-8')

PRIMARY = ('aiTriageAlert', 'mitigateAlert', 'muteAlert', 'resolveAlert')
SECONDARY = ('aiInvestigateAlert', 'clearLogLine', 'resolveAlertWithNote',
             'alertTimeline', 'declareIncident', 'copyAlertLink')


def _split(html):
    """(row part, menu part) of one rendered actions cell."""
    m = re.search(r'<template class="row-more-items">(.*?)</template>', html, re.S)
    if not m:
        return html, ''
    return html[:m.start()] + html[m.end():], m.group(1)


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) not installed')
class TestRowAndMenu(_V8):
    def _row(self, alert_js):
        c = self.ctx("var _icon = function () { return '<svg></svg>'; };"
                     "var __A = " + alert_js + ";")
        return self.jeval(c, "_alertRowHtml(__A, '')")

    def test_open_alert_splits_primary_and_secondary(self):
        html = self._row("{id:'a1', ts:1, severity:'high', event:'log_alert',"
                         " device_id:'d1', mitigation_kind:'disk',"
                         " payload:{sample:'boom', pattern:'ERR', unit:'nginx'}}")
        row, menu = _split(html)
        self.assertTrue(menu, 'no More menu on an open alert')
        for action in PRIMARY:
            self.assertIn(f'data-action="{action}"', row, f'{action} left the row')
            self.assertNotIn(f'data-action="{action}"', menu)
        for action in SECONDARY:
            self.assertIn(f'data-action="{action}"', menu, f'{action} is not in the menu')
            self.assertNotIn(f'data-action="{action}"', row, f'{action} is still on the row')
        self.assertEqual(row.count('data-action="rowMoreMenu"'), 1)
        self.assertIn('data-pass-btn="1"', row.split('data-action="rowMoreMenu"')[1][:40])

    def test_every_menu_item_has_a_text_label(self):
        html = self._row("{id:'a1', ts:1, severity:'low', device_id:'d1'}")
        _row, menu = _split(html)
        items = re.findall(r'<button[^>]*>(.*?)</button>', menu, re.S)
        self.assertGreaterEqual(len(items), 4)
        for inner in items:
            label = re.sub(r'<[^>]+>', '', inner).strip()
            self.assertTrue(label, f'icon-only menu item: {inner!r}')

    def test_resolved_alert_has_no_menu(self):
        html = self._row("{id:'a2', ts:1, severity:'low', resolved_at:2, resolved_by:'auto'}")
        self.assertNotIn('row-more-items', html)
        self.assertNotIn('rowMoreMenu', html)
        self.assertIn('data-action="copyAlertLink"', html)

    def test_long_evidence_value_can_break(self):
        path = '/var/lib/remotepower/' + 'x' * 70
        html = self._row("{id:'a3', ts:1, severity:'low', payload:{path:'%s'}}" % path)
        self.assertIn('class="alert-kv"', html)
        self.assertNotRegex(html, r'class="nowrap">path:',
                            'the evidence value is back inside a nowrap span')


class TestBrowserWiring(unittest.TestCase):
    def test_handler_and_close_paths_exist(self):
        self.assertRegex(APP, r'\bfunction rowMoreMenu\s*\(btn\)')
        self.assertRegex(APP, r'\bfunction _closeRowMore\s*\(')
        body = APP[APP.index('function _refreshShouldPause'):][:1500]
        self.assertIn("getElementById('row-more-pop')", body,
                      'the refresh tick would rewrite the row under an open menu')

    def test_menu_is_fixed_so_a_scrolling_table_cannot_clip_it(self):
        rules = re.findall(r'#row-more-pop\s*\{([^}]*)\}', CSS)
        self.assertTrue(rules, '#row-more-pop has no rule')
        self.assertIn('position: fixed', ' '.join(rules))

    def test_kv_value_breaks(self):
        m = re.search(r'\.alert-kv strong\s*\{([^}]*)\}', CSS)
        self.assertIsNotNone(m)
        self.assertIn('overflow-wrap: anywhere', m.group(1))


if __name__ == '__main__':
    unittest.main()
