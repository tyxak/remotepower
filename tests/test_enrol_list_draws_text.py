#!/usr/bin/env python3
"""The Enroll dialog draws what an administrator typed as text, never as markup.

A token's label is free text from any administrator, a tenant administrator included, and the platform operator's list of open install
commands shows every tenant's tokens. A label drawn as HTML would be a stored script in the operator's page. The product draws it with
textContent, but until this module nothing failed if a change switched that one line to innerHTML: the JS lint, the load check, the lazy
module guard and both rendered modules of the enrolment work all passed on a copy of the tree with exactly that change.

This module holds the source side (no markup sink in the dialog's scripts, found by reading them, with the scanner shown to flag each sink).
The rendered side is TestAStoredLabelIsText in test_enroll_many_hosts_e2e: it mints a token whose label is markup, opens the dialog, and checks
that the chip holds no element and that nothing in it ran.
"""
import re
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import srcpin  # noqa: E402

# every way a script turns a string into elements
SINKS = re.compile(r'\.innerHTML\b|\.outerHTML\b|\binsertAdjacentHTML\b|\bdocument\.write(?:ln)?\b|\bcreateContextualFragment\b|\bDOMParser\b|'
                   r'\.srcdoc\b|\bsetHTMLUnsafe\b|\bnew\s+Function\b|\beval\s*\(')

# the dialog's own functions in app.js: they print a token, a host name from the poll, and the commands built around the token
DIALOG_FUNCTIONS = ('openEnrollModal', '_enrollMaxUses', 'enrollUsesNote', 'enrollOpenRefresh', 'generateNewPin', 'generateDockerEnroll',
                    'copyDockerEnroll', 'generateQuickInstall', 'copyQuickEnroll', '_startEnrollWatch', '_enrollStatusEl')


def _without_comments(src):
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    return re.sub(r'(?m)(^|[^:\w"\'`])//.*$', r'\1', src)


def sinks_in(src):
    return sorted(set(m.group(0).strip() for m in SINKS.finditer(_without_comments(src))))


class TestTheScanner(unittest.TestCase):
    """The control: each way of writing markup is seen, and plain text is not flagged (a scan that sees nothing passes whatever the tree holds)."""

    def test_every_sink_is_seen(self):
        for line in ("label.innerHTML = String(r.label);", "row.outerHTML = x;", "box.insertAdjacentHTML('beforeend', s);", "document.write(s);",
                     "range.createContextualFragment(s)", "new DOMParser().parseFromString(s, 'text/html')", "frame.srcdoc = s;",
                     "el.setHTMLUnsafe(s)", "new Function(s)()", "eval(s)"):
            self.assertTrue(sinks_in(line), 'not seen: %s' % line)

    def test_text_and_comments_are_not_flagged(self):
        self.assertEqual(sinks_in("const l = _enrolNode('span', 'wiz-chip', String(r.label)); n.textContent = x; el.appendChild(n);"), [])
        self.assertEqual(sinks_in("// the label is set as text, never with innerHTML\n/* outerHTML would be wrong */ n.textContent = x;"), [])


class TestTheDialogWritesNoMarkup(unittest.TestCase):

    def test_the_list_module_holds_no_markup_sink(self):
        src = (_JS / 'app-enrol.js').read_text()
        self.assertGreater(len(_without_comments(src)), 1500, 'the module read as nearly empty: the scan sees nothing')
        self.assertIn("_enrolNode('span', 'wiz-chip', String(r.label))", src, 'the label is no longer set through textContent')
        self.assertEqual(sinks_in(src), [], 'app-enrol.js turns a string into markup: a label from a tenant administrator would run in the operator\'s page')

    def test_the_dialogs_functions_in_app_js_hold_none_either(self):
        js = (_JS / 'app.js').read_text()
        seen = 0
        for name in DIALOG_FUNCTIONS:
            body = srcpin.js_function(js, name)          # a renamed function raises here: the list has to follow it
            seen += len(body)
            self.assertEqual(sinks_in(body), [], '%s turns a string into markup' % name)
        self.assertGreater(seen, 4000, 'the functions read as nearly empty')

    def test_the_list_module_is_the_only_reader_of_the_list(self):
        # a second script that reads the list and draws a label has to be added to the scans above: this fails until it is
        readers = sorted(p.name for p in _JS.glob('app*.js') if re.search(r"api\('GET',\s*'/enrollment-tokens'", p.read_text()))
        self.assertEqual(readers, ['app-enrol.js'])


if __name__ == '__main__':
    unittest.main()
