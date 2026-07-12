"""v6.1.2 — guardrails for the frontend defects fixed this release.

These are source-level pins (the JS has no headless DOM in the unit suite; the
e2e suite covers behaviour). Each pins the SHAPE of the fix so the specific
mistake can't come back:

1. app-billing.js deleted rows by their RENDER-TIME INDEX and never re-rendered,
   so after removing any non-last row every surviving button's index was off by
   one and the next delete removed the wrong row — then Save persisted it.
2. app.js's device-backups table had a sortable `drill` header with no matching
   sortRows key, so the column showed a sort arrow but never reordered.
3. app-integrations.js's saveOpnsenseConfig repainted the drawer card instead of
   the surface actually open (the console modal), unlike every other OPNsense
   action, which uses _opnsenseSurface().
4. app.js carried an unreachable runbook renderer targeting an element id that
   no code creates.
"""

import re
import unittest
from pathlib import Path

_JS = Path(__file__).parent.parent / "server/html/static/js"


def _src(name):
    return (_JS / name).read_text()


class TestBillingRowDeleteUsesStableIds(unittest.TestCase):
    def setUp(self):
        self.src = _src("app-billing.js")

    def test_delete_handlers_no_longer_index_into_a_live_nodelist(self):
        # The bug in one line: `rows[i].remove()` where i was a render-time index.
        self.assertNotIn("rows[i].remove()", self.src)
        for fn in ("function rateCardDel", "function feeDel"):
            self.assertIn(fn, self.src)

    def test_rows_carry_a_stable_rid_and_delete_matches_on_it(self):
        self.assertIn("data-rid=", self.src)
        self.assertIn("function _bRowId", self.src)
        self.assertIn("tr[data-rid=", self.src)

    def test_no_add_handler_derives_its_arg_from_the_row_count(self):
        # `const i = tb.querySelectorAll('tr').length` is what made the arg
        # positional in the first place.
        self.assertNotIn("querySelectorAll('tr').length", self.src)


class TestBackupsDrillColumnSorts(unittest.TestCase):
    def test_every_data_col_in_the_backups_thead_has_a_sortrows_key(self):
        src = _src("app.js")
        # The getColumns callback for the device_backups table.
        m = re.search(
            r"tableCtl\.sortRows\('device_backups',\s*baks,\s*b\s*=>\s*\(\{(.*?)\}\)\)",
            src,
            re.S,
        )
        self.assertIsNotNone(m, "device_backups sortRows call not found")
        keys = set(re.findall(r"(\w+):", m.group(1)))
        # The thead that drives it.
        thead = re.search(
            r"<thead id=\"device-backups-thead\">(.*?)</thead>", src, re.S
        )
        self.assertIsNotNone(thead, "device-backups thead not found")
        cols = set(re.findall(r'data-col="(\w+)"', thead.group(1)))
        self.assertTrue(cols, "no sortable columns found")
        self.assertEqual(
            cols - keys,
            set(),
            "every sortable data-col must have a matching sortRows key",
        )


class TestOpnsenseSaveRepaintsTheActiveSurface(unittest.TestCase):
    def test_save_uses_the_surface_helper_not_a_hardcoded_drawer_id(self):
        src = _src("app-integrations.js")
        save = src[src.index("async function saveOpnsenseConfig") :]
        save = save[: save.index("\n// Pick the active OPNsense surface")]
        self.assertIn("_opnsenseSurface()", save)
        self.assertNotIn("getElementById('audit-body-opnsense')", save)


class TestDeadRunbookCodeRemoved(unittest.TestCase):
    def test_unreachable_renderer_and_its_callers_are_gone(self):
        app = _src("app.js")
        # The lookup itself, not any mention — the removal comment names the id.
        self.assertNotIn("getElementById('detail-runbook-section')", app)
        self.assertNotIn("function _renderRunbookSectionHtml", app)
        self.assertNotIn("async function refreshDetailRunbookSection", app)
        ai = _src("app-ai.js")
        self.assertNotIn("refreshDetailRunbookSection(", ai)

    def test_the_live_runbook_path_still_exists(self):
        # Deleting dead code must not have taken the working feature with it.
        app = _src("app.js")
        ai = _src("app-ai.js")
        self.assertIn("runbook-modal", app)
        self.assertIn("async function aiViewRunbook", ai)
        self.assertIn("async function aiGenerateRunbook", ai)


class TestContainerRenderFixes(unittest.TestCase):
    def test_loading_row_markup_is_well_formed(self):
        src = _src("app-containers.js")
        self.assertNotIn('Loading…</tbody>', src)
        self.assertIn('Loading…</td></tr>', src)

    def test_no_dead_ternary_with_identical_branches(self):
        src = _src("app-containers.js")
        self.assertNotIn("${r.is_stale ? '' : ''}", src)


class TestDaneRecordsEscaped(unittest.TestCase):
    def test_all_tlsa_fields_go_through_eschtml(self):
        src = _src("app-network.js")
        block = src[src.index("t.dane_records.map") :][:600]
        for field in ("usage", "selector", "matching_type"):
            self.assertNotIn(
                "${r.%s}" % field,
                block,
                f"r.{field} must not be interpolated raw into innerHTML",
            )


if __name__ == "__main__":
    unittest.main()
