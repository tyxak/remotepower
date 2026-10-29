#!/usr/bin/env python3
"""v7.4.5, issue #55: the demo data carries the switch, in the shape the heartbeat stores.

The rendered gates (the accessibility sweep, the overflow and icon checks, the click sweep) measure the
seeded instance, so a page that only shows its new states for data nobody seeded is never measured in
them. Two demo hosts are marked internal: jellyfin.lab holds (private addresses only, its wildcard
sockets stored as lan and marked assumed) and nextcloud.lab does not (a public address, so its sockets
stay world and the page says why). The seeder writes the STORED shape directly, so this holds the shape
to the rule that makes it: running exposure_scope over the seeded record changes nothing.
"""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v702_seeder_shapes import _seeded_devices  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))
import exposure_scope as ex  # noqa: E402


class TestTheSeededSwitch(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.devs = _seeded_devices()

    def si(self, dev_id):
        return self.devs[dev_id]["sysinfo"]

    def test_the_host_that_holds(self):
        dev, si = self.devs["jf01"], self.si("jf01")
        self.assertIs(dev["exposure_internal"], True)
        self.assertEqual(ex.assess(si["host_addresses"]), ("private", []))
        assumed = [r for r in si["listening_ports"] if r.get("assumed")]
        self.assertGreaterEqual(len(assumed), 2, "the page has something to label")
        self.assertTrue(all(r["scope"] == "lan" and r["addr"] in ("0.0.0.0", "::") for r in assumed))
        self.assertEqual([r for r in si["listening_ports"] if r["scope"] == "world"], [])
        self.assertTrue(ex.host_state(True, si["host_addresses"])["assumed"])

    def test_the_host_that_does_not(self):
        dev, si = self.devs["nc01"], self.si("nc01")
        self.assertIs(dev["exposure_internal"], True)
        state = ex.host_state(True, si["host_addresses"])
        self.assertEqual((state["assumed"], state["blocked"], state["public"]), (False, "public_address", ["203.0.113.40"]))
        world = [r for r in si["listening_ports"] if r["scope"] == "world"]
        self.assertGreaterEqual(len(world), 2)
        self.assertTrue(all(not r.get("assumed") for r in si["listening_ports"]))

    def test_the_seeded_records_are_what_the_heartbeat_would_store(self):
        """Idempotent: grading them again changes nothing, so a demo agent's next report would agree."""
        for dev_id in ("jf01", "nc01"):
            si = copy.deepcopy(self.si(dev_id))
            self.assertEqual(ex.apply(self.devs[dev_id]["exposure_internal"], si), 0, dev_id)
            self.assertEqual(si, self.si(dev_id), dev_id)

    def test_that_check_can_fail(self):
        """The control: undoing the switch on the host that holds does change its rows."""
        si = copy.deepcopy(self.si("jf01"))
        self.assertGreaterEqual(ex.apply(False, si), 2)

    def test_no_other_host_carries_the_switch_or_the_addresses_or_a_mark(self):
        for dev_id, dev in self.devs.items():
            if dev_id in ("jf01", "nc01"):
                continue
            self.assertNotIn("exposure_internal", dev, dev_id)
            si = dev.get("sysinfo") or {}
            self.assertNotIn("host_addresses", si, dev_id)
            self.assertTrue(all(not r.get("assumed") for r in si.get("listening_ports") or []), dev_id)


if __name__ == "__main__":
    unittest.main()
