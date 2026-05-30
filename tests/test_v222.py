#!/usr/bin/env python3
"""
Tests for v2.2.2 — design polish hotfix.

Verifies:
  - handle_webhook_log tolerates both list and dict on-disk shapes
    (regression: pre-2.2.2 crashed 500 on bare-list webhook_log.json)
  - The Home dashboard uses the correct /webhook/log endpoint
  - Hover-action CSS positions the strip at row level (right: 24px,
    z-index >= 2, in CSS) and suppresses the focus outline that was
    being clipped by narrow cells in 2.2.1
  - The hoverActions span is placed in the first cell (checkbox), not
    the narrow last cell where its focus ring was being clipped
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"]    = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"]      = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v222", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


def _capture_respond():
    def fake_respond(status, data):
        raise _Captured(status, data)
    api.respond = fake_respond


def _stub_auth():
    api.require_auth         = lambda **kw: 'admin'
    api.require_admin_auth   = lambda: 'admin'


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api.DATA_DIR         = self._tmp
        api.WEBHOOK_LOG_FILE = self._tmp / 'webhook_log.json'
        _capture_respond()
        _stub_auth()


# ─── handle_webhook_log robustness ───────────────────────────────────────


class TestWebhookLogShape(_Base):

    def test_dict_with_entries(self):
        api.save(api.WEBHOOK_LOG_FILE, {
            'entries': [
                {'ts': 1, 'event': 'device_online'},
                {'ts': 2, 'event': 'device_offline'},
            ]
        })
        try: api.handle_webhook_log()
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(len(r.body), 2)
        # Reversed: newest first
        self.assertEqual(r.body[0]['ts'], 2)

    def test_bare_list_shape_tolerated(self):
        # v2.2.1 and earlier crashed 500 here: list.get('entries')
        # → AttributeError. v2.2.2 fix: tolerate the bare-list shape.
        api.save(api.WEBHOOK_LOG_FILE, [
            {'ts': 1, 'event': 'device_online'},
            {'ts': 2, 'event': 'device_offline'},
        ])
        try: api.handle_webhook_log()
        except _Captured as c: r = c
        self.assertEqual(r.status, 200,
                         "v2.2.2 must not crash on list-shaped webhook log")
        self.assertEqual(len(r.body), 2)

    def test_empty_file(self):
        # File missing → load() returns empty dict → entries empty list
        try: api.handle_webhook_log()
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, [])

    def test_garbage_shape_doesnt_crash(self):
        # Some integer / string ended up on disk somehow
        api.save(api.WEBHOOK_LOG_FILE, "not a list or dict")
        try: api.handle_webhook_log()
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, [])


# ─── Frontend asset fixes ────────────────────────────────────────────────


class TestPolishHotfixes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.css = (_ROOT / 'server/html/static/css/styles.css').read_text()
        cls.js  = client_js()

    def test_loadhome_uses_correct_webhook_path(self):
        # v2.2.1 used /webhook-log (404). v2.2.2 uses /webhook/log.
        self.assertNotIn("'/webhook-log", self.js,
                         "loadHome should not use the hyphenated path")
        self.assertIn("'/webhook/log'", self.js,
                      "loadHome should use the slashed path")

    def test_row_actions_has_breathing_room(self):
        # v2.2.2: row-actions positioned with `right: 24px` for a focus
        # ring that wasn't clipped on narrow cells.
        # v2.2.5: hover affordance removed entirely (was persistently
        # fiddly). This test is now a historical record: the row-actions
        # CSS rule still exists as a no-op `display: none`. See
        # TestHoverActionsRemoved in test_v225.py for the v2.2.5
        # invariant. We keep the test name and just assert the no-op.
        self.assertIn('tr.has-hover-actions .row-actions { display: none; }',
                      self.css,
                      "v2.2.5 turns the hover-actions rule into a no-op")

    def test_row_actions_focus_outline_suppressed(self):
        # v2.2.2: focus outline replaced with softer accent border.
        # v2.2.5: hover affordance removed entirely. No buttons in the
        # `.row-actions` strip means no focus to suppress. Kept as a
        # placeholder so the test count stays stable and the chain
        # of evolution is documented.
        self.assertNotIn('.row-actions button:focus', self.css,
                         "v2.2.5: focus rule no longer needed since "
                         "row-actions is hidden entirely")

    def test_row_actions_placed_in_first_cell(self):
        # v2.2.2: hoverActions span moved into the first (checkbox) cell
        # to fix focus-ring clipping in the narrow last cell.
        # v2.2.5: hoverActions span removed entirely. The first cell
        # contains the checkbox only. See TestHoverActionsRemoved.
        # Assert the inverse: no `hoverActions` reference in the
        # minimal row template.
        snippet_start = self.js.find('checkbox" ${isSel ? \'checked\' : \'\'}')
        self.assertGreater(snippet_start, 0)
        snippet = self.js[snippet_start:snippet_start + 600]
        self.assertNotIn('${hoverActions}', snippet,
                         "v2.2.5: hoverActions span removed; checkbox "
                         "cell holds only the checkbox now")


if __name__ == '__main__':
    unittest.main(verbosity=2)
