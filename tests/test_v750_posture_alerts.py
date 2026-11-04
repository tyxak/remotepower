#!/usr/bin/env python3
"""v7.5.0 (data binding): the rest of the posture trio raises an alert.

Windows and macOS raised an alert for each protection they lost. A Linux host that
lost its firewall, or whose disks are not encrypted, and a Mac that stopped
installing security updates, paged nobody, although the Checks page, the risk
score and the Advisory all said so.

Driven through the real `_ingest_posture_v3110` and the real alert ledger, so the
payload whitelist and the auto-resolve are in the path (a hand-built alert row
bypasses both and gives a false green). The Mac values come from the macOS
agent's own parser.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-posture-"))

_spec = importlib.util.spec_from_file_location("api_v750_posture", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_mspec = importlib.util.spec_from_file_location(
    "rp_mac_agent_v750_posture", ROOT / "client" / "remotepower-agent-mac.py")
macagent = importlib.util.module_from_spec(_mspec)
_mspec.loader.exec_module(macagent)

NEW = {
    "linux_firewall_off": ("linux_firewall_on", "firewall"),
    "linux_encryption_off": ("linux_encryption_on", "hardening"),
    "mac_update_off": ("mac_update_on", "mac_posture"),
}

_FW_OFF = {"active": False, "backends": [
    {"name": "nftables", "present": True, "active": False},
    {"name": "ufw", "present": True, "active": False}]}
_FW_ON = {"active": True, "backends": [{"name": "ufw", "present": True, "active": True}]}


def _mac(auto):
    """macOS posture as the agent's parser builds it (FileVault, firewall,
    Gatekeeper and SIP all fine; only the update setting varies)."""
    return macagent._parse_mac_posture(
        "FileVault is On.", "Firewall is enabled. (State = 1)", "assessments enabled",
        "System Integrity Protection status: enabled.", auto)


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._files = {}
        for a in ("POSTURE_STATE_FILE", "ALERTS_FILE", "FLEET_EVENTS_FILE",
                  "CONFIG_FILE", "DEVICES_FILE"):
            self._files[a] = getattr(api, a)
            # The storage backend keys the table on the basename, so keep it.
            setattr(api, a, self.d / pathlib.Path(self._files[a]).name)
        api.save(api.DEVICES_FILE, {"d1": {"name": "host1", "last_seen": 1,
                                           "monitored": True, "sysinfo": {}}})
        self.set_config()

    def tearDown(self):
        for a, v in self._files.items():
            setattr(api, a, v)
        api._LOAD_CACHE.clear()

    def set_config(self, **cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)

    def beat(self, si):
        api._invalidate_load_cache(api.ALERTS_FILE)
        api._ingest_posture_v3110("d1", "host1", si)
        api._invalidate_load_cache(api.ALERTS_FILE)

    def alerts(self, event=None):
        rows = (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
        return [a for a in rows if event is None or a.get("event") == event]

    def open(self, event):
        return [a for a in self.alerts(event) if not a.get("resolved_at")]

    def fleet_events(self):
        store = api.load(api.FLEET_EVENTS_FILE) or {}
        rows = store.get("events", []) if isinstance(store, dict) else store
        return [e.get("event") for e in rows]


class TestRegistry(unittest.TestCase):

    def test_each_condition_has_a_firing_event_and_a_recovering_one(self):
        for fire, (rec, kind) in NEW.items():
            self.assertIn(fire, api.EVENT_REGISTRY, fire)
            self.assertIn(rec, api.EVENT_REGISTRY, rec)
            self.assertEqual(api.EVENT_REGISTRY[fire]["kind"], kind)
            self.assertEqual(api.EVENT_REGISTRY[rec]["kind"], kind)
            self.assertEqual(api.EVENT_REGISTRY[fire]["severity"], "medium")
            self.assertEqual(api._ALERT_RECOVER.get(rec), fire)

    def test_every_kind_is_a_routing_kind(self):
        kinds = {row[0] for row in api.CHANNEL_KIND_DEFS}
        for _fire, (_rec, kind) in NEW.items():
            self.assertIn(kind, kinds)

    def test_the_events_are_in_the_settings_list(self):
        names = set(api.WEBHOOK_EVENT_NAMES)
        for fire, (rec, _kind) in NEW.items():
            self.assertIn(fire, names)
            self.assertIn(rec, names)

    def test_the_gate_that_calls_the_ingest_lists_the_two_new_keys(self):
        """A host that sends only these keys must still reach the function
        (7.0.2: FileVault off was silent on a Mac whose report carried none of
        the keys the gate listed)."""
        for k in ("firewall", "disk_encryption"):
            self.assertIn(k, api._POSTURE_INGEST_KEYS)


class TestLinuxFirewall(_Base):

    def test_a_host_with_no_active_ruleset_alerts_on_first_contact(self):
        self.beat({"firewall": _FW_OFF})
        opened = self.open("linux_firewall_off")
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0]["severity"], "medium")
        # The detail is whitelisted into the inbox row and names what was read.
        self.assertIn("nftables, ufw", opened[0]["payload"]["detail"])

    def test_a_steady_state_does_not_alert_again(self):
        for _ in range(3):
            self.beat({"firewall": _FW_OFF})
        self.assertEqual(len(self.alerts("linux_firewall_off")), 1)
        self.assertEqual(self.fleet_events().count("linux_firewall_off"), 1)

    def test_turning_the_firewall_on_resolves_the_alert(self):
        self.beat({"firewall": _FW_OFF})
        self.beat({"firewall": _FW_ON})
        self.assertEqual(self.open("linux_firewall_off"), [])
        self.assertEqual(len(self.alerts("linux_firewall_off")), 1)
        self.assertIn("linux_firewall_on", self.fleet_events())

    def test_an_unreadable_probe_neither_fires_nor_recovers(self):
        """active None is "could not read", not "off"."""
        self.beat({"firewall": {"active": None, "backends": []}})
        self.assertEqual(self.alerts(), [])
        self.beat({"firewall": _FW_OFF})
        self.beat({"firewall": {"active": None, "backends": []}})
        self.assertEqual(len(self.open("linux_firewall_off")), 1)
        self.beat({"firewall": _FW_ON})
        self.assertEqual(self.open("linux_firewall_off"), [])

    def test_a_healthy_firewall_raises_nothing(self):
        self.beat({"firewall": _FW_ON})
        self.assertEqual(self.alerts(), [])
        self.assertNotIn("linux_firewall_on", self.fleet_events())

    def test_a_host_that_reports_no_firewall_block_raises_nothing(self):
        self.beat({"mounts": []})
        self.assertEqual(self.alerts(), [])

    def test_the_firewall_alert_needs_no_opt_in(self):
        """It follows its Checks row, which is always on."""
        self.set_config(security_hardening_checks=False, disk_encryption_checks=False)
        self.beat({"firewall": _FW_OFF})
        self.assertEqual(len(self.open("linux_firewall_off")), 1)


class TestLinuxDiskEncryption(_Base):

    def test_nothing_without_the_opt_in(self):
        self.beat({"disk_encryption": {"encrypted": False}})
        self.assertEqual(self.alerts(), [])

    def test_alerts_and_recovers_when_the_check_is_enabled(self):
        self.set_config(disk_encryption_checks=True)
        self.beat({"disk_encryption": {"encrypted": False}})
        self.assertEqual(len(self.open("linux_encryption_off")), 1)
        self.beat({"disk_encryption": {"encrypted": True, "encrypted_mounts": ["/"]}})
        self.assertEqual(self.open("linux_encryption_off"), [])
        self.assertIn("linux_encryption_on", self.fleet_events())

    def test_a_host_that_cannot_see_device_mapper_says_nothing(self):
        """The agent returns {} then, and being unable to look is not a finding."""
        self.set_config(disk_encryption_checks=True)
        self.beat({"disk_encryption": {}})
        self.assertEqual(self.alerts(), [])

    def test_a_steady_state_does_not_alert_again(self):
        self.set_config(disk_encryption_checks=True)
        for _ in range(3):
            self.beat({"disk_encryption": {"encrypted": False}})
        self.assertEqual(len(self.alerts("linux_encryption_off")), 1)

    def test_switching_the_check_off_forgets_the_state(self):
        """Off resolves the open alert (handle_config_save); the stored state
        must not still say "already reported", or switching the check on again
        would stay silent for a host that is still unencrypted."""
        self.set_config(disk_encryption_checks=True)
        self.beat({"disk_encryption": {"encrypted": False}})
        self.set_config(disk_encryption_checks=False)
        self.beat({"disk_encryption": {"encrypted": False}})
        api._resolve_alerts_for_events(("linux_encryption_off",), by="test")
        api._invalidate_load_cache(api.ALERTS_FILE)
        self.assertEqual(self.open("linux_encryption_off"), [])
        self.set_config(disk_encryption_checks=True)
        self.beat({"disk_encryption": {"encrypted": False}})
        self.assertEqual(len(self.open("linux_encryption_off")), 1)


class TestSwitchingTheCheckOffInSettings(_Base):
    """handle_config_save resolves the open alert, like the hardening switch."""

    def setUp(self):
        super().setUp()
        self._users = (api.USERS_FILE, api.ROLES_FILE)
        api.USERS_FILE = self.d / pathlib.Path(self._users[0]).name
        api.ROLES_FILE = self.d / pathlib.Path(self._users[1]).name
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "verify_token", "audit_log",
                       "fire_webhook", "respond", "method", "get_json_obj")}
        api.require_admin_auth = lambda: "t"
        api.verify_token = lambda t: ("t", "admin")
        api.audit_log = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap["s"] = s
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "POST"

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api.USERS_FILE, api.ROLES_FILE = self._users
        super().tearDown()

    def _save(self, **body):
        api.get_json_obj = lambda: dict(body)
        # The save itself may notify; the beats before it must use the real
        # fire_webhook, so only the save runs with it silenced.
        real = api.fire_webhook
        api.fire_webhook = lambda *a, **k: None
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        finally:
            api.fire_webhook = real
        api._LOAD_CACHE.clear()

    def test_the_open_alert_is_resolved_when_the_check_is_switched_off(self):
        self.set_config(disk_encryption_checks=True)
        self.beat({"disk_encryption": {"encrypted": False}})
        self.assertEqual(len(self.open("linux_encryption_off")), 1)
        self._save(disk_encryption_checks=False)
        self.assertEqual(self.cap.get("s"), 200, self.cap)
        api._invalidate_load_cache(api.ALERTS_FILE)
        self.assertEqual(self.open("linux_encryption_off"), [])
        self.assertEqual(len(self.alerts("linux_encryption_off")), 1)

    def test_saving_the_setting_unchanged_leaves_the_alert_open(self):
        self.set_config(disk_encryption_checks=True)
        self.beat({"disk_encryption": {"encrypted": False}})
        self._save(disk_encryption_checks=True)
        api._invalidate_load_cache(api.ALERTS_FILE)
        self.assertEqual(len(self.open("linux_encryption_off")), 1)


class TestMacAutomaticUpdates(_Base):

    def test_the_parser_really_reports_the_setting_as_a_boolean(self):
        """The premise: the agent sends a bool under this key."""
        self.assertIs(_mac("0")["auto_security_update"], False)
        self.assertIs(_mac("1")["auto_security_update"], True)
        self.assertNotIn("auto_security_update", _mac(""))

    def test_off_alerts_and_on_resolves(self):
        self.beat({"mac_posture": _mac("0")})
        self.assertEqual(len(self.open("mac_update_off")), 1)
        self.assertEqual(self.open("mac_update_off")[0]["severity"], "medium")
        self.beat({"mac_posture": _mac("1")})
        self.assertEqual(self.open("mac_update_off"), [])
        self.assertIn("mac_update_on", self.fleet_events())

    def test_a_setting_the_agent_could_not_read_is_silent(self):
        self.beat({"mac_posture": _mac("")})
        self.assertEqual(self.alerts(), [])

    def test_it_does_not_disturb_the_other_four_mac_settings(self):
        """FileVault off, update on: one alert, and it is FileVault's."""
        mp = _mac("1")
        mp["filevault"] = False
        self.beat({"mac_posture": mp})
        self.assertEqual([a["event"] for a in self.alerts()], ["mac_filevault_off"])
        # Now the update setting goes off too: the second alert joins the first.
        mp["auto_security_update"] = False
        self.beat({"mac_posture": mp})
        self.assertEqual(sorted(a["event"] for a in self.open(None)),
                         ["mac_filevault_off", "mac_update_off"])


class TestThePageKnowsTheEvents(unittest.TestCase):
    """app.js: the activity feed lists and routes every event (test_v223 and
    test_v225 hold the general rule). This holds these six in BOTH places, which
    a plain substring check cannot: the name appears in each."""

    JS = (ROOT / "server/html/static/js/app.js").read_text()

    def _feed_set(self):
        start = self.JS.index("const FLEET_EVENTS = new Set([")
        return self.JS[start:self.JS.index("]);", start)]

    def _router(self):
        start = self.JS.index("function _homeActivityAttrs(")
        return self.JS[start:self.JS.index("default:", start)]

    def test_each_event_is_in_the_feed_set(self):
        feed = self._feed_set()
        for fire, (rec, _kind) in NEW.items():
            for ev in (fire, rec):
                self.assertIn("'%s'" % ev, feed, ev)

    def test_each_event_is_routed_to_the_host(self):
        router = self._router()
        for fire, (rec, _kind) in NEW.items():
            for ev in (fire, rec):
                self.assertIn("case '%s':" % ev, router, ev)


if __name__ == "__main__":
    unittest.main()
