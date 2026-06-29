"""Guardrail: index.html structural-tag balance.

A dropped close tag (e.g. an unclosed `<select>`) makes the browser auto-insert the
end tag at the next incompatible element, corrupting the DOM for everything after it
and breaking page rendering across the SPA — yet it passes jsload (JS-only) and the
rest of the suite. This test catches that class.

Added after a v5.5.0 `data-nofilter` edit dropped a `</select>` and shipped to TEST.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_HTML = (_ROOT / "server" / "html" / "index.html").read_text()

# Tags that are NEVER self-closing/void and whose mis-nesting corrupts the parse.
_PAIRED = ("select", "textarea", "table", "tbody", "thead", "tfoot", "form",
           "ul", "ol", "details", "fieldset")


class TestIndexHtmlTagBalance(unittest.TestCase):
    def test_paired_tags_balanced(self):
        for tag in _PAIRED:
            opens = len(re.findall(rf"<{tag}(?:\s[^>]*)?>", _HTML))
            closes = len(re.findall(rf"</{tag}>", _HTML))
            self.assertEqual(
                opens, closes,
                f"<{tag}> open/close mismatch in index.html: {opens} open vs "
                f"{closes} close — a dropped end tag corrupts the DOM parse.")


if __name__ == "__main__":
    unittest.main()
