#!/usr/bin/env python3
"""The 7.4.9 interface polish, pinned (each rule was measured in a browser against the seeded demo before it was written).

The rendered gates (box overflow, icon-to-label gap, axe) ran on the changed interface and pass; this file keeps the changes from
being undone by accident, and holds the two bugs that were plain text: a rule that printed "≥ undefined" and a demo that fed it.
"""
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSS = re.sub(r"/\*.*?\*/", "", (ROOT / "server" / "html" / "static" / "css" / "styles.css").read_text(encoding="utf-8"), flags=re.S)
HTML = (ROOT / "server" / "html" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(encoding="utf-8")
LOGS = (ROOT / "server" / "html" / "static" / "js" / "app-logs.js").read_text(encoding="utf-8")


def css_has(selector, declaration):
    """A rule whose selector list contains `selector` and whose body contains `declaration`, anywhere in the sheet."""
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", CSS):
        sels = [s.strip() for s in m.group(1).split(",")]
        if selector in sels and declaration in re.sub(r"\s+", " ", m.group(2)):
            return True
    return False


class TestSpacingAndWrapping(unittest.TestCase):

    def test_a_cards_hint_does_not_touch_its_first_row(self):
        self.assertTrue(css_has(".dash-card > .hint:not(:last-child)", "margin-bottom: 12px"))

    def test_a_settings_row_does_not_touch_the_next_field(self):
        for sel in (".settings-row + .settings-row", ".settings-row + .form-group", ".form-group + .settings-row"):
            with self.subTest(selector=sel):
                self.assertTrue(css_has(sel, "margin-top: 16px"))

    def test_the_hosts_buttons_stay_on_one_line(self):
        self.assertTrue(css_has(".section-header > .row-8", "flex: 0 0 auto"))
        self.assertTrue(css_has(".section-header > .row-8 > button", "white-space: nowrap"))

    def test_a_clipped_os_name_ends_in_an_ellipsis(self):
        self.assertTrue(css_has(".devices-minimal-table .dev-os-cell", "text-overflow: ellipsis"))

    def test_short_pills_and_chips_do_not_wrap(self):
        self.assertTrue(css_has(".sev-pill", "white-space: nowrap"))
        self.assertTrue(css_has(".chk-pill", "white-space: nowrap"))
        self.assertTrue(css_has(".tl-devchip", "white-space: nowrap"))

    def test_a_drawer_action_label_may_wrap(self):
        self.assertTrue(css_has(".drawer-action-btn", "white-space: normal"))


class TestFocusAndRightToLeft(unittest.TestCase):

    def test_the_focus_ring_of_clipped_controls_sits_inside(self):
        for sel in ("thead th:focus-visible", ".doc-card > summary:focus-visible", ".segmented > button:focus-visible",
                    "tr.pointer:focus-visible", ".table-card td:focus-visible"):
            with self.subTest(selector=sel):
                self.assertTrue(css_has(sel, "outline-offset: -2px"))

    def test_checkbox_labels_use_logical_properties(self):
        self.assertTrue(css_has('label.form-label:has(> input[type="checkbox"])', "padding-inline-start: 26px"))
        self.assertTrue(css_has('label.form-label:has(> input[type="checkbox"]) > input[type="checkbox"]',
                                "inset-inline-start: 0"))

    def test_adjacent_cell_buttons_and_the_distro_icon_mirror(self):
        self.assertTrue(css_has("td > .btn-icon + .btn-icon", "margin-inline-start: 6px"))
        self.assertTrue(css_has(".distro-icon", "margin-inline-end: 6px"))


class TestBoxCapsAndNames(unittest.TestCase):

    def test_the_two_boxes_that_grew_without_limit_scroll(self):
        self.assertRegex(HTML, r'id="ai-rag-sources"[^>]*>|class="[^"]*\bscroll-cap\b[^"]*" id="ai-rag-sources"')
        self.assertIn('class="form-group isl-773 scroll-cap" id="ai-rag-sources"', HTML)
        self.assertIn('<pre id="sshgw-config" class="ff-mono scroll-cap"></pre>', HTML)

    def test_a_routing_matrix_checkbox_has_a_name(self):
        m = re.search(r'<input type="checkbox" aria-label="\$\{escAttr\(k\.label\)\}: \$\{escAttr\(CHANNEL_LABELS\[c\] \|\| c\)\}"[^>]*toggleChannelRoute', JS)
        self.assertIsNotNone(m, "each checkbox is named by the kind and the channel")

    def test_the_drawer_fields_are_not_squeezed_to_70px(self):
        for ident in ("ds-icon", "ds-snmp-community", "ds-snmp-v3-user", "ds-snmp-v3-auth-secret", "ds-snmp-v3-priv-secret"):
            with self.subTest(field=ident):
                m = re.search(r'<input[^>]*id="%s"' % ident, JS)
                self.assertIsNotNone(m)
                self.assertNotIn("isl-620", m.group(0))
        self.assertIn('class="form-input isl-620" id="ds-snmp-version"', JS, "the version select keeps its narrow width")


class TestLogRules(unittest.TestCase):

    def test_a_rule_without_a_threshold_prints_one_not_undefined(self):
        self.assertEqual(LOGS.count("≥ ${r.threshold ?? 1}"), 2)
        self.assertNotIn("≥ ${r.threshold}<", LOGS)

    def test_the_demo_rules_carry_the_fields_the_form_stores(self):
        spec = importlib.util.spec_from_file_location("seed_v749_ui", ROOT / "packaging" / "seed-demo-data.py")
        mod = importlib.util.module_from_spec(spec)                   # type: ignore[arg-type]
        spec.loader.exec_module(mod)                                  # type: ignore[union-attr]
        rules = mod.build_log_rules_global()["rules"]
        self.assertEqual(len(rules), 3)
        for r in rules:
            with self.subTest(rule=r["id"]):
                self.assertIsInstance(r["threshold"], int)
                self.assertGreaterEqual(r["threshold"], 1)
                self.assertTrue(r["created_by"])
                self.assertTrue(r["created_at"])


if __name__ == "__main__":
    unittest.main()
