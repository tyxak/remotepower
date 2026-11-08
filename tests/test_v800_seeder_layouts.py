#!/usr/bin/env python3
"""8.0.0: the demo accounts keep two named Home layouts, and the server keeps every one of them.

Named layouts are an account preference, so a demo with none shows no switcher at all. The seed gives the three accounts that see Home the Security and
Patching layouts. The server drops any widget key it does not know and any layout past its limits (`_sanitise_ui_prefs`), and it drops silently, so the
seed is held to what the server would store: nothing may be lost on the way, or the demo shows a layout shorter than the one written here.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-seeder-layouts-"))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

_spec = importlib.util.spec_from_file_location("api_v800_layouts", _ROOT / "server" / "cgi-bin" / "api.py")
api = importlib.util.module_from_spec(_spec)             # type: ignore[arg-type]
_spec.loader.exec_module(api)                             # type: ignore[union-attr]
_spec2 = importlib.util.spec_from_file_location("seed_demo_layouts", _ROOT / "packaging" / "seed-demo-data.py")
seed = importlib.util.module_from_spec(_spec2)           # type: ignore[arg-type]
_spec2.loader.exec_module(seed)                           # type: ignore[union-attr]

USERS = seed.build_users()


class TestTheDemoKeepsNamedLayouts(unittest.TestCase):

    def test_the_accounts_that_open_home_have_two_layouts(self):
        for name in ("demo", "alice", "bob"):
            sets = (USERS[name].get("ui_prefs") or {}).get("dashboard_sets")
            self.assertEqual([s["name"] for s in sets], ["Security", "Patching"], name)

    def test_the_layout_in_use_stays_the_accounts_own(self):
        for name in ("demo", "alice", "bob"):
            self.assertNotIn("dashboard_set", USERS[name]["ui_prefs"], name)

    def test_the_server_keeps_every_layout_whole(self):
        for name in ("demo", "alice", "bob"):
            prefs = USERS[name]["ui_prefs"]
            kept = api._sanitise_ui_prefs(prefs)
            self.assertEqual(kept["dashboard_sets"], prefs["dashboard_sets"], "%s lost a widget or a layout on the way in" % name)

    def test_every_key_is_a_widget_the_server_knows(self):
        known = set(api.DASHBOARD_WIDGETS)
        for s in USERS["demo"]["ui_prefs"]["dashboard_sets"]:
            for item in s["w"]:
                self.assertIn(item.partition(":")[0], known, item)

    def test_the_control_notices_a_key_the_server_would_drop(self):
        bad = {"dashboard_sets": [{"id": "security", "name": "Security", "w": ["heatmap", "no-such-widget"]}]}
        self.assertNotEqual(api._sanitise_ui_prefs(bad)["dashboard_sets"], bad["dashboard_sets"])


if __name__ == "__main__":
    unittest.main()
