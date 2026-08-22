#!/usr/bin/env python3
"""The wrapper-piercing control-height rule, checked in the source.

styles.css normalises every control in a toolbar row to 34px with a
DIRECT-CHILD selector, and app.js's `_wrapSelects()` inserts a
`<span class="rp-ddwrap">` between every `<select>` and its parent at runtime
— so the select becomes a grandchild and the `>` stops matching it. That left
25 rows across 20 pages with a select 2px taller than the buttons beside it.

The rendered walk in test_v702_control_heights_e2e.py is what FINDS a new
mismatch; these three cheap assertions are what stop the known one coming back
without paying for a browser. They live apart because a browser gate's cost is
part of its design: `make test-fast` skips only `*e2e*.py`, so the rendered
half would otherwise add a minute to every run anyone ever does.
"""
import re
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent


class TestTheWrapperPiercingArmIsStillThere(unittest.TestCase):
    """Cheap source companion to the browser walk above.

    The rendered test is what FINDS a new mismatch; this is what stops the
    known one coming back without waiting for a browser.
    """

    def setUp(self):
        self.css = (_ROOT / 'server' / 'html' / 'static' / 'css'
                    / 'styles.css').read_text()

    def test_the_stylesheet_is_readable(self):
        """Positive control — every assertion below is a substring search."""
        self.assertIn('.rp-ddwrap', self.css)
        self.assertGreater(len(self.css), 100000)

    def test_the_height_rule_reaches_through_rp_ddwrap(self):
        self.assertRegex(
            self.css,
            r'>\s*\.rp-ddwrap\s*>\s*:is\(select\.form-input,\s*select\.select-sm\)',
            'the control-height rule only matches a select that is a DIRECT '
            'child, and app.js wraps every select in an .rp-ddwrap span — so '
            'its select clauses are unreachable and wrapped selects render '
            '2px taller than the buttons beside them')

    def test_the_logs_search_input_is_on_the_shared_field_class(self):
        """It was the only visible text input in the product off .form-input,
        so the toolbar height contract (`input.form-input`) skipped it."""
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        m = re.search(r'<input[^>]*id="logs-search-input"[^>]*>', html)
        self.assertIsNotNone(m, 'the logs search input is gone')
        self.assertIn('form-input', m.group(0))


if __name__ == '__main__':
    unittest.main()
