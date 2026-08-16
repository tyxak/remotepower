#!/usr/bin/env python3
"""v7.0.0: the sidebar could not be collapsed while any alert was open.

THE BUG. The "keep the sidebar visible while alerts are open" rule was written
as `body.sidebar-collapsed.has-active-alert .sidebar { width: 248px; … }`. But
`.sidebar-collapsed` is also the state of a sidebar the operator collapsed BY
HAND with auto-hide switched off — the two modes share that class. So with one
alert open, clicking Collapse moved the content (`.app-content` keeps the 56px
rail margin) while the sidebar stayed 248px wide on top of it. Turning auto-hide
off changed nothing, because no selector in the rule ever mentioned auto-hide.

THE FIX. app.js decides, in one place (`_applySidebarAlertPin`), whether open
alerts pin the rail open: they do only when auto-hide is ON and the operator has
not opted out. The CSS keys off that derived class, never off `.has-active-alert`
directly. The opt-out is the new "Keep hiding while alerts are open" checkbox.

The rendered half — that the sidebar actually measures 56px in each of those
states — is `tests/test_v700_sidebar_autohide_e2e.py`.
"""
import re
import unittest
from pathlib import Path

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from srcpin import js_function                                   # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_CSS = _ROOT / "server/html/static/css/styles.css"
_JS = _ROOT / "server/html/static/js/app.js"
_HTML = _ROOT / "server/html/index.html"
_I18N = _ROOT / "server/html/static/js/i18n.js"

PIN_CLASS = "sidebar-alert-pinned"


def _css_no_comments():
    """styles.css with /* … */ stripped.

    The fix's own comment explains the class it replaced, and an assertion that
    the old name is gone would fail on the explanation — assert against the
    code, never the prose describing it.
    """
    return re.sub(r"/\*.*?\*/", "", _CSS.read_text(), flags=re.S)


class TestAlertsDoNotBlockCollapse(unittest.TestCase):
    def test_nothing_drives_layout_off_the_bare_alert_count(self):
        """The regression itself.

        `has-active-alert` meant only "alerts are open" — it was true for a
        MANUALLY collapsed sidebar too, which is how the collapse button broke.
        The class is gone; the three-input pin below replaced it.
        """
        self.assertNotIn("has-active-alert", _css_no_comments())
        # Comments stripped on both sides: the fix's own explanation names the
        # class it removed, and a pin against prose is not a pin against code.
        live_js = [ln for ln in _JS.read_text().splitlines()
                   if not ln.lstrip().startswith("//")]
        self.assertEqual([ln for ln in live_js if "has-active-alert" in ln], [])

    def test_the_pin_class_carries_every_reveal_rule(self):
        """Positive control for the assertion above.

        Without this, deleting the whole block would pass `test_no_css_rule…`
        while removing the alerts-stay-visible behaviour entirely.
        """
        css = _css_no_comments()
        pinned = css.count(f"body.sidebar-collapsed.{PIN_CLASS}")
        self.assertGreaterEqual(
            pinned, 12,
            f"only {pinned} pinned-sidebar rules — the alert reveal (width, labels, "
            "group items, search, star, account row) lost some of its selectors")
        # The pin and the hover reveal must stay the same shape: every pinned
        # rule has a `.sidebar:hover` twin, or the two modes render differently.
        self.assertGreaterEqual(css.count("body.sidebar-collapsed .sidebar:hover"), 12)

    def test_the_pin_requires_autohide_and_honours_the_opt_out(self):
        js = _JS.read_text()
        body = js_function(js, "_applySidebarAlertPin")
        self.assertIn("_openAlertCount > 0", body)
        self.assertIn("classList.contains('autohide-sidebar')", body,
                      "the pin must not apply to a manually collapsed sidebar")
        self.assertIn("!_autohideThroughAlerts()", body,
                      "the pin must honour the keep-hiding opt-out")
        self.assertIn(f"classList.toggle('{PIN_CLASS}', pin)", body)

    def test_only_that_function_sets_the_pin_class(self):
        """One writer, so the three inputs can never disagree."""
        js = _JS.read_text()
        setters = [ln for ln in js.splitlines() if PIN_CLASS in ln]
        self.assertEqual(len(setters), 1, f"expected one writer, got: {setters}")

    def test_both_toggles_and_the_alert_paint_re_evaluate_the_pin(self):
        """A preference flip must take effect now, not at the next alert poll."""
        js = _JS.read_text()
        for fn in ("toggleAutohideSidebar", "toggleAutohideThroughAlerts",
                   "_paintAlertsBadge"):
            self.assertIn("_applySidebarAlertPin()", js_function(js, fn),
                          f"{fn} does not re-apply the sidebar pin")

    def test_the_alert_count_is_recorded_before_the_pin_reads_it(self):
        js = _JS.read_text()
        decl = js.index("let _openAlertCount = 0;")
        use = js.index("function _applySidebarAlertPin")
        self.assertLess(decl, use,
                        "_openAlertCount is in its temporal dead zone at the "
                        "point _applySidebarAlertPin is defined above it")
        self.assertIn("_openAlertCount = n;", js_function(js, "_paintAlertsBadge"))


class TestCollapseBreakpointMatchesTheButton(unittest.TestCase):
    """The Collapse button is hidden at ≤720px; the rules it drives must
    therefore start at 721px. They started at 769px — a floor left behind when
    v2.2.7 moved the drawer breakpoint 768→720 — so the button was visible and
    inert across a 48px band. The rendered proof is the e2e file; this pins the
    two numbers to each other so they cannot drift apart again."""

    def test_the_rail_rules_start_where_the_button_appears(self):
        css = _css_no_comments()
        # Walk back from the rule that hides the button to the media query it
        # sits in. A forward regex cannot do this: `[^}]*` stops at the sibling
        # rule's closing brace, and a DOTALL `.*?` would happily match a
        # @media header several blocks earlier.
        hide = css.find(".sidebar-collapse-btn { display: none !important; }")
        self.assertNotEqual(hide, -1, "the drawer block no longer hides the button")
        headers = re.findall(r"@media \(max-width: (\d+)px\) \{", css[:hide])
        self.assertTrue(headers, "the button-hiding rule left its max-width block")
        hidden_upto = int(headers[-1])

        rail = re.search(r"@media \(min-width: (\d+)px\) \{\s*"
                         r"body\.sidebar-collapsed \.sidebar \{", css)
        self.assertIsNotNone(rail, "the collapse-rail media block moved or changed shape")
        floor = int(rail.group(1)) if rail else 0

        self.assertEqual(
            floor, hidden_upto + 1,
            f"the Collapse button is visible above {hidden_upto}px but the rail "
            f"rules only start at {floor}px — every width in between renders a "
            "button that does nothing")

    def test_there_is_one_copy_of_the_rail_rules(self):
        """Two copies at two breakpoints is how the browser case got left
        behind: the gap was patched in the installed-PWA copy only."""
        css = _css_no_comments()
        self.assertEqual(
            css.count("body.sidebar-collapsed .app-content { margin-left: 56px; }"), 1,
            "the collapse-rail block is duplicated again — fix the breakpoint on "
            "the one copy instead of adding a display-mode-scoped twin")


class TestKeepHidingOptOut(unittest.TestCase):
    LABEL = "Keep hiding while alerts are open"

    def test_the_checkbox_is_wired_to_the_handler(self):
        html = _HTML.read_text()
        self.assertRegex(
            html,
            r'id="acct-autohide-thru-alerts"[^>]*data-change="toggleAutohideThroughAlerts"'
            r'[^>]*data-change-checked="1"')
        self.assertIn(self.LABEL, html)
        # Unticked by default: the shipped behaviour (alerts reveal the rail)
        # must not change for anyone who never opens this pane.
        row = re.search(r'<label class="form-row"><input type="checkbox" '
                        r'id="acct-autohide-thru-alerts"[^>]*>', html)
        self.assertIsNotNone(row, 'the opt-out checkbox row moved or changed shape')
        self.assertNotIn(" checked", row.group(0) if row else '')

    def test_the_preference_persists_per_browser(self):
        js = _JS.read_text()
        self.assertIn("rp_autohide_thru_alerts",
                      js_function(js, "toggleAutohideThroughAlerts"))
        self.assertIn("rp_autohide_thru_alerts", js_function(js, "_autohideThroughAlerts"))

    def test_the_checkbox_reflects_the_stored_value_on_load(self):
        js = _JS.read_text()
        init = js_function(js, "_initAutohide")
        self.assertIn("acct-autohide-thru-alerts", init)
        self.assertIn("_autohideThroughAlerts()", init)

    def test_the_label_is_translated_into_all_six_languages(self):
        i18n = _I18N.read_text()
        line = next((ln for ln in i18n.splitlines() if f"'{self.LABEL}'" in ln), '')
        self.assertTrue(line, "the new label has no DICT entry")
        for lang in ("fr", "de", "zh", "hi", "es", "ar"):
            self.assertIn(f"{lang}: '", line, f"{lang} translation missing")


if __name__ == "__main__":
    unittest.main()
