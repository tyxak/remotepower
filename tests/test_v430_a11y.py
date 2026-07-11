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
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(Path(__file__).parent))
from srcpin import js_function   # noqa: E402
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

    def test_every_modal_overlay_is_labelled(self):
        # v4.8.0 (#U1): every dialog must also carry an accessible NAME — either
        # aria-labelledby (pointing at its visible title) or aria-label.
        overlays = re.findall(r'<div class="modal-overlay[^"]*"[^>]*>', INDEX)
        missing = [o for o in overlays
                   if 'aria-labelledby="' not in o and 'aria-label="' not in o]
        self.assertEqual(missing, [],
                         f"modal overlays without an accessible name: {missing}")

    def test_labelledby_targets_exist_and_are_unique(self):
        # An aria-labelledby that points at a missing or duplicated id is worse
        # than none — assert referential integrity for every reference.
        refs = re.findall(r'aria-labelledby="([^"]+)"', INDEX)
        self.assertGreater(len(refs), 50)
        id_counts = {}
        for i in re.findall(r'\bid="([^"]+)"', INDEX):
            id_counts[i] = id_counts.get(i, 0) + 1
        broken = [r for r in refs if id_counts.get(r, 0) != 1]
        self.assertEqual(broken, [],
                         f"aria-labelledby refs with missing/duplicate id: {broken}")


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


class TestNavStarNotNestedInsideButton(unittest.TestCase):
    """v6.1.1 (#62) — the sidebar favorite-star toggle (.nav-star,
    role="button" tabindex="0") used to be injected as a DESCENDANT of the
    real <button class="nav-btn">, which axe-core's nested-interactive rule
    correctly flags (two independently-focusable/activatable controls,
    nested). Fixed by restructuring the star to a SIBLING of .nav-btn, both
    wrapped in a new .nav-item flex row. Verified live via Playwright + a
    real axe run in tests/test_a11y_axe.py (which now enforces this rule
    with NO exemption); these are the fast, non-browser structural pins."""

    APP_JS = next(f for f in JS_FILES if f.name == 'app.js').read_text()

    def test_init_favorites_does_not_append_star_into_button(self):
        fn = js_function(self.APP_JS, '_initFavorites')
        self.assertNotIn('btn.appendChild(star)', fn,
                         'the star must not be appended INTO the button again')
        self.assertIn('nav-item', fn, 'the star must be wrapped in a .nav-item sibling row')

    def test_render_favorites_star_lookup_is_not_a_button_descendant_query(self):
        fn = js_function(self.APP_JS, '_renderFavorites')
        # the old shape read `b.querySelector('.nav-star')` (star INSIDE b) --
        # the fixed shape must look at the wrapper instead.
        self.assertNotRegex(fn, r"\bb\.querySelector\('\.nav-star'\)",
                            'must not query the star as a descendant of the button')

    def test_click_delegate_handlers_do_not_use_ancestor_search_from_star(self):
        # star.closest('.nav-btn') walks UP the ancestor chain -- broken once
        # the star became a SIBLING (closest() can't walk sideways). Both the
        # click and keydown delegate handlers must use a same-parent lookup
        # instead.
        self.assertNotIn("star.closest('.nav-btn')", self.APP_JS,
                         'an ancestor search from the star can no longer find the button')

    def test_sidebar_search_index_excludes_pinned_clones_via_closest(self):
        fn = js_function(self.APP_JS, '_buildSidebarIdx')
        # nav-fav-clone now marks the WRAPPER, not the button -- a bare
        # :not(.nav-fav-clone) class check on the button would silently stop
        # excluding pinned clones (double-counting them in search results).
        self.assertIn("closest('.nav-fav-clone')", fn,
                      'must exclude pinned clones via ancestor search, not a bare class check')

    def test_css_hover_reveal_targets_the_wrapper_not_the_button(self):
        self.assertIn('.nav-item:hover .nav-star', CSS)
        self.assertIn('.nav-item:focus-within .nav-star', CSS)
        self.assertNotIn('.nav-btn:hover .nav-star', CSS,
                         'hover-reveal must key off .nav-item now the star is a sibling')

    def test_axe_nested_interactive_exemption_is_gone(self):
        axe_test = (_ROOT / "tests" / "test_a11y_axe.py").read_text()
        self.assertNotIn("'nested-interactive'", axe_test,
                         'the nested-interactive axe exemption should be fully removed, not just disabled')


if __name__ == '__main__':
    unittest.main()
