"""v6.4.2: the fleet-ops screens, pinned as REACHABLE — not merely present.

The server half of these four features shipped a wave earlier with no UI at all,
which is the same dead end as a handler with no route: complete, tested, and
unusable. Each test here pins BOTH halves — the control exists AND the endpoint
it calls is registered — because either alone is a dead end.

Run: python3 -m pytest tests/test_v642_fleet_ops_ui.py -q
"""

import os
import re
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

_spec = importlib.util.spec_from_file_location("api_v642_fleetui", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_HTML = (_ROOT / "server/html/index.html").read_text()
_APP = (_ROOT / "server/html/static/js/app.js").read_text()
_LOGS = (_ROOT / "server/html/static/js/app-logs.js").read_text()
_ROUTES = set(api._build_exact_routes().keys())


def _dispatched(name):
    """Is this data-action name defined as a function anywhere in the client?"""
    for src in (_APP, _LOGS):
        if re.search(r"(?:async\s+)?function\s+" + re.escape(name) + r"\s*\(", src):
            return True
    return False


class TestBulkAttributeEdit(unittest.TestCase):
    def test_the_batch_bar_offers_it(self):
        self.assertIn('data-action="openBatchAttrs"', _HTML)

    def test_its_handlers_exist(self):
        for fn in ("openBatchAttrs", "closeBatchAttrs", "applyBatchAttrs"):
            self.assertTrue(_dispatched(fn), f"{fn} is dispatched but not defined")

    def test_the_route_it_posts_to_is_registered(self):
        self.assertIn(("POST", "/api/devices/bulk-attrs"), _ROUTES)

    def test_the_modal_lives_at_body_level(self):
        """A fixed overlay inside .container has its z-index sealed there and can
        never rise above the sidebar — the documented drawer bug."""
        body_split = _HTML.index("</div><!-- /app -->")
        self.assertGreater(_HTML.index('id="batch-attrs-modal"'), body_split,
                           "the modal is inside .container, not at body level")

    def test_blank_fields_are_omitted_not_sent_as_empty(self):
        """Both sides treat an absent key as 'do not touch'. Sending '' would
        CLEAR group/site across the whole selection."""
        body = re.search(r"async function applyBatchAttrs\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn("if (val('ba-group')) payload.group", body)
        self.assertIn("if (val('ba-site')) payload.site", body)

    def test_it_reports_the_shortfall_rather_than_hiding_it(self):
        """Out-of-scope ids are dropped server-side, so updated can be < requested."""
        body = re.search(r"async function applyBatchAttrs\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn("r.requested", body)
        self.assertIn("outside your scope", body)


class TestPatchApprovalUI(unittest.TestCase):
    def test_the_catalog_offers_approve_decline_clear(self):
        self.assertIn('data-action="setPatchApproval"', _APP)
        self.assertIn('data-action="clearPatchApproval"', _APP)

    def test_its_handlers_exist(self):
        for fn in ("setPatchApproval", "clearPatchApproval"):
            self.assertTrue(_dispatched(fn), f"{fn} is dispatched but not defined")

    def test_both_routes_are_registered(self):
        self.assertIn(("POST", "/api/patch-approvals"), _ROUTES)
        self.assertIn(("POST", "/api/patch-approvals/delete"), _ROUTES)

    def test_the_catalog_actually_supplies_the_approval_field(self):
        """The column reads p.approval; if the server stopped stamping it the
        column would silently render '—' for everything."""
        src = (_CGI / "api.py").read_text()
        cat = src[src.index("def handle_patch_catalog"):]
        cat = cat[:cat.index("\ndef ", 10)]
        self.assertIn("approval", cat)

    def test_decline_states_that_it_is_linux_only(self):
        """A decline is NOT enforced on Windows/macOS. A bare success toast here
        would be the success-toast-then-silence class."""
        body = re.search(r"async function setPatchApproval\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn("Windows and macOS", body)
        self.assertIn("uiConfirm", body)

    def test_the_new_column_is_sortable(self):
        """Every sortable th needs a data-col matching the sortRows getter."""
        fn = re.search(r"async function loadPatchCatalog\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn('data-col="approval"', fn)
        self.assertIn("approval: p.approval", fn)


class TestLogExportUI(unittest.TestCase):
    def test_the_toolbar_offers_both_formats(self):
        self.assertIn('data-action="exportLogs" data-arg="csv"', _HTML)
        self.assertIn('data-action="exportLogs" data-arg="ndjson"', _HTML)

    def test_its_handler_exists(self):
        self.assertTrue(_dispatched("exportLogs"))

    def test_the_route_is_registered(self):
        self.assertIn(("GET", "/api/logs/export"), _ROUTES)

    def test_it_downloads_rather_than_parsing_json(self):
        """api() parses JSON and would choke on a CSV body — the export must go
        through the blob-download helper."""
        body = re.search(r"function exportLogs\(.*?\n\}", _LOGS, re.S).group(0)
        self.assertIn("_downloadAuthed", body)
        self.assertNotRegex(body, r"\bapi\('GET'")

    def test_it_exports_what_the_toolbar_shows(self):
        """Otherwise 'Export' silently means something different from the screen."""
        body = re.search(r"function exportLogs\(.*?\n\}", _LOGS, re.S).group(0)
        for el in ("logs-search-input", "logs-device-filter", "logs-unit-filter"):
            self.assertIn(el, body)


class TestLogRetentionUI(unittest.TestCase):
    def test_both_inputs_exist(self):
        self.assertIn('id="ret-logbuf-h"', _HTML)
        self.assertIn('id="ret-logbuf-b"', _HTML)

    def test_load_and_save_read_one_shared_table(self):
        """These were two duplicated literals — which is how a field gets added
        to one half and silently never loads (or never saves) in the other."""
        self.assertEqual(_APP.count("_RETENTION_FIELDS = {"), 1)
        self.assertGreaterEqual(len(re.findall(r"Object\.entries\(_RETENTION_FIELDS\)", _APP)), 2)

    def test_the_new_keys_carry_their_own_bounds(self):
        """They are hours and bytes, not days — a single 0..3650 check would
        reject every legal value for both."""
        m = re.search(r"const _RETENTION_FIELDS = \{.*?\n\};", _APP, re.S).group(0)
        self.assertIn("'log_buffer_retention_hours',     0, 168", m)
        self.assertIn("'log_buffer_max_bytes_per_unit',  0, 67108864", m)


if __name__ == "__main__":
    unittest.main(verbosity=2)
