#!/usr/bin/env python3
"""Regression: group/tag/site-scoped service baselines must actually apply.

The heartbeat builds a `saved_dev` snapshot from a CURATED field set
(`_HEARTBEAT_PASSTHROUGH_FIELDS` + a few explicit assignments), then AFTER the
DEVICES_FILE lock calls `_service_baseline_units_for(saved_dev)` to union any
baseline units whose scope covers the device into the `services_watched` list
pushed to the agent.

The scope match (`_device_in_scope`) reads `dev.get('group'|'tags'|'site')`.
Those three fields were NOT in the passthrough contract, so `saved_dev` carried
none of them — every group/tag/site-scoped baseline evaluated against '' and
silently never applied; only `scope:{type:'all'}` baselines worked. This test
projects a device through the SAME contract the handler uses and asserts a
group/tag/site-scoped baseline resolves — so dropping any of the three fields
from the contract fails here instead of silently shipping broken baselines.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


def _project_saved_dev(dev, dev_id="dev1"):
    """Build saved_dev EXACTLY as handle_heartbeat does (name/last_seen/
    quarantined + the passthrough-contract loop), so the projection under test
    is the real one, not a hand-picked dict."""
    saved_dev = {}
    saved_dev["name"] = dev.get("name", dev_id)
    saved_dev["last_seen"] = dev.get("last_seen", 0)
    saved_dev["quarantined"] = bool(dev.get("quarantined", False))
    for k, factory in api._HEARTBEAT_PASSTHROUGH_FIELDS.items():
        saved_dev[k] = dev.get(k, factory())
    return saved_dev


class TestServiceBaselineScopeApplies(unittest.TestCase):
    def setUp(self):
        self.cfg = {
            "service_baselines": [
                {"id": "g", "name": "grp", "units": ["grp.service"],
                 "scope": {"type": "groups", "values": ["apt"]}},
                {"id": "t", "name": "tag", "units": ["tag.service"],
                 "scope": {"type": "tags", "values": ["servers"]}},
                {"id": "s", "name": "site", "units": ["site.service"],
                 "scope": {"type": "sites", "values": ["dc1"]}},
                {"id": "a", "name": "all", "units": ["all.service"],
                 "scope": {"type": "all"}},
            ]
        }

    def test_scope_fields_in_passthrough_contract(self):
        # The heartbeat snapshot MUST carry the scope attributes the baseline
        # matcher reads, or scoped baselines silently never apply.
        for f in ("group", "tags", "site"):
            self.assertIn(f, api._HEARTBEAT_PASSTHROUGH_FIELDS,
                          f"saved_dev must pass through {f!r} for baseline scoping")

    def test_group_scoped_baseline_applies(self):
        dev = {"name": "web01", "group": "apt", "tags": [], "services_watched": []}
        units = api._service_baseline_units_for(_project_saved_dev(dev), self.cfg)
        self.assertIn("grp.service", units)
        self.assertIn("all.service", units)   # all-scope always applies

    def test_tag_scoped_baseline_applies(self):
        dev = {"name": "web01", "group": "", "tags": ["servers"], "services_watched": []}
        units = api._service_baseline_units_for(_project_saved_dev(dev), self.cfg)
        self.assertIn("tag.service", units)

    def test_site_scoped_baseline_applies(self):
        dev = {"name": "web01", "group": "", "tags": [], "site": "dc1",
               "services_watched": []}
        units = api._service_baseline_units_for(_project_saved_dev(dev), self.cfg)
        self.assertIn("site.service", units)

    def test_out_of_scope_baseline_does_not_apply(self):
        dev = {"name": "ws01", "group": "pacman", "tags": ["workstations"],
               "site": "dc9", "services_watched": []}
        units = api._service_baseline_units_for(_project_saved_dev(dev), self.cfg)
        self.assertNotIn("grp.service", units)
        self.assertNotIn("tag.service", units)
        self.assertNotIn("site.service", units)
        self.assertIn("all.service", units)   # but the all-scope one still does


if __name__ == "__main__":
    unittest.main(verbosity=2)
