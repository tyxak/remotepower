#!/usr/bin/env python3
"""v4.3.0 accessibility guardrails.

These pin the a11y floor so it can only ratchet up:
  * every icon-only button (svg-only content, no visible text) must carry an
    accessible name (aria-label or title) — in static HTML AND in the
    innerHTML template strings JS renders from;
  * every modal overlay is announced as a dialog (role="dialog" aria-modal);
  * filter/search inputs (placeholder-only affordances) carry aria-label;
  * the global keyboard-focus ring (:focus-visible) stays present.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_HTML = _ROOT / "server" / "html"
INDEX = (_HTML / "index.html").read_text()
CSS = (_HTML / "static" / "css" / "styles.css").read_text()
JS_FILES = sorted((_HTML / "static" / "js").glob("app*.js"))


def _unlabeled_icon_buttons(src, is_js):
    """Return [(line, attrs)] for svg-only <button>s without aria-label/title."""
    hits = []
    for m in re.finditer(r'<button\b([^>]*?)>(.*?)</button>', src, re.S):
        attrs, body = m.group(1), m.group(2)
        if 'aria-label' in attrs or 'title' in attrs:
            continue
        rest = re.sub(r'<svg\b.*?</svg>', '', body, flags=re.S)
        if is_js:
            # the _icon() helper renders an svg; other ${...} may be text
            rest = re.sub(r'\$\{_icon\([^)]*\)\}', '', rest)
            rest = re.sub(r'\$\{[^}]*\}', 'X', rest)
        rest = re.sub(r'<[^>]+>', '', rest)
        if rest.strip() == '' and ('<svg' in body or '_icon(' in body):
            hits.append((src[:m.start()].count('\n') + 1,
                         re.sub(r'\s+', ' ', attrs.strip())[:120]))
    return hits


class TestIconButtonsLabeled(unittest.TestCase):
    def test_static_html_icon_buttons_have_names(self):
        hits = _unlabeled_icon_buttons(INDEX, is_js=False)
        self.assertEqual(hits, [],
                         "icon-only <button>s in index.html without "
                         f"aria-label/title: {hits}")

    def test_js_template_icon_buttons_have_names(self):
        for f in JS_FILES:
            hits = _unlabeled_icon_buttons(f.read_text(), is_js=True)
            self.assertEqual(hits, [],
                             f"icon-only buttons rendered by {f.name} without "
                             f"aria-label/title: {hits}")


class TestModalsAnnounced(unittest.TestCase):
    def test_every_modal_overlay_is_a_dialog(self):
        overlays = re.findall(r'<div class="modal-overlay[^"]*"[^>]*>', INDEX)
        self.assertGreater(len(overlays), 50)
        missing = [o for o in overlays
                   if 'role="dialog"' not in o or 'aria-modal="true"' not in o]
        self.assertEqual(missing, [],
                         f"modal overlays missing role=dialog/aria-modal: {missing}")

    def test_device_drawer_is_a_dialog(self):
        m = re.search(r'<div id="device-drawer"[^>]*>', INDEX)
        self.assertIsNotNone(m)
        self.assertIn('role="dialog"', m.group(0))


class TestFilterInputsLabeled(unittest.TestCase):
    # NOTE: the `<input\b[^>]*>` scan stops at the first `>` — including a
    # literal `>` inside an attribute VALUE (data-filter-target="#x > *").
    # For such inputs, keep aria-label BEFORE the `>`-bearing attribute so
    # the truncated match still contains it.
    def test_filter_and_search_inputs_have_aria_label(self):
        missing = []
        for m in re.finditer(r'<input\b[^>]*>', INDEX):
            tag = m.group(0)
            if 'aria-label' in tag or 'placeholder' not in tag:
                continue
            if re.search(r'(?:id|class)="[^"]*(?:filter|search)[^"]*"', tag, re.I):
                missing.append(tag[:120])
        self.assertEqual(missing, [],
                         f"filter/search inputs without aria-label: {missing}")


class TestFocusRing(unittest.TestCase):
    def test_global_focus_visible_rule_present(self):
        self.assertRegex(
            CSS, r':focus-visible\s*\{[^}]*outline:',
            "the global :focus-visible keyboard-focus ring is gone")


if __name__ == '__main__':
    unittest.main()
