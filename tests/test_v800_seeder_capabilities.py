#!/usr/bin/env python3
"""8.0.0: the demo seeder says what a Linux agent and a satellite say about themselves.

Two signals have no page of their own and are read by code that decides what a host is given:

  sysinfo.probe_types      the monitor types the agent's own probe engine runs; a monitor of smtp, imap, ssh or ntp is handed only to a host that says so
  sysinfo.compose_rollback that the agent can put a compose project back on the images it had before an update; with the rollback option of the
                           automatic image update switched on, a host that does not say so is held back instead of updated

The demo seeded neither, so on the demo a host's monitors could only be the three of 7.4.9 and the rollback option held every host back. The Linux agent
sends both on every heartbeat, and so does the satellite (its X-RP-Probes header, kept on its record), so the seed does too. The Windows and macOS agents
say neither, and the seed leaves them out: a host that cannot do a thing must read as one that cannot.

The seed is run once for the whole process (test_v702_seeder_shapes keeps it), and the signals are read with the same helpers the server reads them with.
"""
import importlib.util
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v702_seeder_shapes as seeded  # noqa: E402 (it puts server/cgi-bin on the path and keeps the one seeding of the demo data)
import host_probe_handlers as H  # noqa: E402
import image_autoupdate as IA  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_NOT_LINUX = ("windows", "macos", "mac os", "junos", "unifi")


def _seeder_module():
    spec = importlib.util.spec_from_file_location("seed_demo_capabilities", _ROOT / "packaging" / "seed-demo-data.py")
    mod = importlib.util.module_from_spec(spec)             # type: ignore[arg-type]
    spec.loader.exec_module(mod)                             # type: ignore[union-attr]
    return mod


class TestTheSeederStatesWhatItsAgentsSay(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.devices = seeded._seeded_devices()
        cls.sats = json.loads((Path(seeded._SEEDED["dir"]) / "satellites.json").read_text())

    def population(self, linux):
        rows = [d for d in self.devices.values() if isinstance(d.get("sysinfo"), dict) and d["sysinfo"]]
        return [d for d in rows if linux == (not any(x in (d.get("os") or "").lower() for x in _NOT_LINUX))]

    def test_the_seeders_list_of_monitor_types_is_the_servers_list(self):
        self.assertEqual(list(_seeder_module()._AGENT_PROBE_TYPES), list(H.known_types()), "a type added to the server is added to the seed")

    def test_every_seeded_linux_agent_says_it_runs_every_type_and_can_roll_back(self):
        hosts = self.population(True)
        self.assertGreaterEqual(len(hosts), 5, "the seed has Linux agents to say it")
        for d in hosts:
            self.assertEqual(H.host_types(d), list(H.known_types()), d.get("name"))
            self.assertTrue(IA.can_roll_back(d), d.get("name"))

    def test_the_windows_and_macos_agents_say_neither_and_are_read_as_the_oldest_kind(self):
        hosts = self.population(False)
        hosts = [d for d in hosts if any(x in (d.get("os") or "").lower() for x in ("windows", "macos", "mac os"))]
        self.assertTrue(hosts, "the seed has a Windows or macOS agent to leave it out of")
        for d in hosts:
            self.assertNotIn("probe_types", d["sysinfo"], d.get("name"))
            self.assertNotIn("compose_rollback", d["sysinfo"], d.get("name"))
            self.assertEqual(H.host_types(d), list(H.SUPPORTED), d.get("name"))
            self.assertFalse(IA.can_roll_back(d), d.get("name"))

    def test_every_seeded_satellite_says_which_types_it_runs(self):
        self.assertTrue(self.sats)
        for sid, sat in self.sats.items():
            self.assertEqual(H.satellite_types(sat), list(H.known_types()), sat.get("name"))


class TestTheSeederStatesWhatItsAgentsFound(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.devices = seeded._seeded_devices()

    def test_every_linux_agent_says_what_it_found_and_the_windows_and_macos_agents_do_not(self):
        import app_catalog
        linux = [d for d in self.devices.values() if isinstance(d.get("sysinfo"), dict) and d["sysinfo"] and not any(x in (d.get("os") or "").lower() for x in _NOT_LINUX)]
        other = [d for d in self.devices.values() if isinstance(d.get("sysinfo"), dict) and d["sysinfo"] and any(x in (d.get("os") or "").lower() for x in ("windows", "macos", "mac os"))]
        self.assertGreaterEqual(len(linux), 5)
        self.assertTrue(other)
        for d in linux:
            self.assertIsInstance(d["sysinfo"].get("discovered"), list, d.get("name"))
        for d in other:
            self.assertNotIn("discovered", d["sysinfo"], d.get("name"))
        said = [d for d in linux if d["sysinfo"]["discovered"]]
        self.assertGreaterEqual(len(said), 8, "the demo has hosts that run apps")

    def test_each_row_is_what_the_servers_own_cleaner_keeps_and_the_port_is_one_of_the_apps(self):
        import app_catalog
        for d in self.devices.values():
            rows = (d.get("sysinfo") or {}).get("discovered") or []
            self.assertEqual(app_catalog.clean_found(rows), rows, d.get("name"))
            for row in rows:
                app = app_catalog.describe(row["id"])
                self.assertIn(row["port"], app["ports"], (d.get("name"), row["id"]))

    def test_the_demo_leaves_apps_for_the_connectors_and_the_monitor_button_to_offer(self):
        import app_catalog
        ids_found = {row["id"] for d in self.devices.values() for row in (d.get("sysinfo") or {}).get("discovered") or []}
        offered = {a for a in ids_found if app_catalog.describe(a)["connector"]}
        self.assertGreaterEqual(len(offered), 8, "apps a connector reads: %r" % sorted(offered))
        for needed in ("gitea", "vaultwarden", "syncthing", "node_exporter", "jellyfin", "postgres", "redis"):
            self.assertIn(needed, ids_found)


class TestTheSeederStatesWhoHoldsThePushChannel(unittest.TestCase):
    """A Linux agent that holds the push channel open says so in every heartbeat and the server keeps when (push_seen), which the page shows as a bolt. The demo had none, so the
    host list, the cards and the drawer were measured by the rendered gates without it."""

    @classmethod
    def setUpClass(cls):
        cls.devices = seeded._seeded_devices()

    def agents(self, linux):
        rows = [d for d in self.devices.values() if isinstance(d.get("sysinfo"), dict) and d["sysinfo"] and not d.get("agentless")]
        return [d for d in rows if linux == (not any(x in (d.get("os") or "").lower() for x in _NOT_LINUX))]

    def test_most_linux_agents_hold_it_and_some_do_not_and_the_server_reads_the_stamp_as_up(self):
        import api
        now = int(time.time())
        linux = self.agents(True)
        holding = [d for d in linux if "push_seen" in d]
        self.assertGreaterEqual(len(holding), 5)
        self.assertTrue([d for d in linux if "push_seen" not in d], "the page shows hosts without the bolt too")
        for d in holding:
            self.assertTrue(api._push_channel_up(d, now), d.get("name"))

    def test_the_windows_and_macos_agents_never_say_it(self):
        other = [d for d in self.agents(False) if any(x in (d.get("os") or "").lower() for x in ("windows", "macos", "mac os"))]
        self.assertTrue(other)
        for d in other:
            self.assertNotIn("push_seen", d, d.get("name"))


class TestTheSeederStatesSharedLogins(unittest.TestCase):
    """The demo has shared logins (a group's or a tag's), so the CMDB page's Scoped credentials table and a host's "Shared logins that apply to this host" have something to show
    to the rendered gates that measure the seeded instance. Metadata only, as the host credentials are."""

    @classmethod
    def setUpClass(cls):
        cls.devices = seeded._seeded_devices()
        cls.creds = json.loads((Path(seeded._SEEDED["dir"]) / "scoped_credentials.json").read_text())["creds"]

    def test_each_login_is_metadata_only_and_has_an_id_of_the_shape_the_api_mints(self):
        self.assertGreaterEqual(len(self.creds), 3)
        for c in self.creds:
            self.assertRegex(c["id"], r"^scred_[0-9a-f]{16}$")
            self.assertEqual((c["ct"], c["nonce"]), ("", ""), c["label"])
            self.assertIn(c["scope_type"], ("site", "group", "tag"))

    def test_each_login_applies_to_hosts_of_the_demo_by_the_servers_own_rule_and_some_host_has_none(self):
        import api
        applies = {c["label"]: [d["name"] for d in self.devices.values() if api._scoped_cred_applies(c, d)] for c in self.creds}
        for label, hosts in applies.items():
            self.assertTrue(hosts, "no host of the demo is in the scope of %s" % label)
        covered = {n for hosts in applies.values() for n in hosts}
        self.assertTrue([d["name"] for d in self.devices.values() if d["name"] not in covered], "every host has a shared login: the dialog's empty state is never seen")


if __name__ == "__main__":
    unittest.main()
