"""v6.1.3 — USB device tripwire (competitive-gap item #12, reframed).

Detection, NOT control. Peripheral *enforcement* is endpoint-management
territory and clashes with the audit-first posture; "a USB device appeared on
this host" is a physical-access signal and fits the existing tripwire family
(hostkey_changed, canary_accessed, login_new_source).

Read from /sys/bus/usb rather than `lsusb`: sysfs IS bind-mounted into the
containerized agent, usbutils is NOT in the agent image — so lsusb would return
nothing there, silently, forever.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v613-usb-"))
_spec = importlib.util.spec_from_file_location("api_v613_usb", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_AGENT = _ROOT / "client" / "remotepower-agent.py"


class TestUsbTripwire(unittest.TestCase):
    def setUp(self):
        self.dev = "dev-usb-1"
        self.fired = []
        self._real_fire = api.fire_webhook
        api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))
        try:
            api._entity_write_one(api.POSTURE_STATE_FILE, self.dev, None)
        except Exception:
            pass

    def tearDown(self):
        api.fire_webhook = self._real_fire

    def _ingest(self, usb):
        # `mounts` stands in for a normal host's posture payload.
        api._ingest_posture_v3110(self.dev, "host-u", {"mounts": [], "usb": usb})

    def _events(self):
        return [e for e, _ in self.fired]

    def test_first_contact_baselines_silently(self):
        """A host enrolling with a dongle already attached is not a plug-in.
        Paging for every existing keyboard buries the one that matters."""
        self._ingest({"046d:c52b": "Logitech Receiver"})
        self.assertNotIn("usb_device_added", self._events())

    def test_new_device_fires(self):
        self._ingest({"046d:c52b": "Logitech Receiver"})
        self.fired.clear()
        self._ingest({"046d:c52b": "Logitech Receiver",
                      "0781:5583": "SanDisk Ultra Fit"})
        evs = [p for e, p in self.fired if e == "usb_device_added"]
        self.assertEqual(len(evs), 1)
        self.assertIn("SanDisk", evs[0]["detail"])

    def test_steady_state_does_not_re_fire(self):
        self._ingest({"0781:5583": "SanDisk Ultra Fit"})
        self.fired.clear()
        self._ingest({"0781:5583": "SanDisk Ultra Fit"})
        self.assertNotIn("usb_device_added", self._events())

    def test_removal_does_not_fire_and_replug_does(self):
        """No recover event by design: 'a USB device was plugged in' is an EVENT.
        An auto-resolving alert would let the exfil stick vanish from the inbox
        the moment it was unplugged — precisely backwards."""
        self._ingest({"a": "x", "0781:5583": "SanDisk"})
        self.fired.clear()
        self._ingest({"a": "x"})                       # unplugged
        self.assertEqual(self._events(), [])
        self._ingest({"a": "x", "0781:5583": "SanDisk"})   # re-plugged
        self.assertIn("usb_device_added", self._events())

    def test_keyed_by_vid_pid_so_a_port_move_is_not_a_new_device(self):
        """The kernel's bus/port path (1-1, 1-2) changes when you move the same
        stick to another port. Keying on that would cry wolf; VID:PID does not."""
        self._ingest({"0781:5583": "SanDisk Ultra Fit"})
        self.fired.clear()
        # Same VID:PID, and that is all the server ever sees — no port in the key.
        self._ingest({"0781:5583": "SanDisk Ultra Fit"})
        self.assertEqual(self._events(), [])


class TestWiring(unittest.TestCase):
    def test_event_registered_with_a_real_kind(self):
        ev = api.EVENT_REGISTRY["usb_device_added"]
        kinds = {k for k, _, _ in api.CHANNEL_KIND_DEFS}
        self.assertIn(ev["kind"], kinds, "kind missing from CHANNEL_KIND_DEFS")
        self.assertEqual(ev["severity"], "medium")

    def test_default_routing_does_not_page_or_hurt_health(self):
        """A USB plug-in is not a HEALTH problem, and an event that pings ntfy
        for a phone charger gets muted — losing the one that mattered."""
        slot = api._kind_default("usb")
        self.assertFalse(slot["webhook"])
        self.assertFalse(slot["needs_attention"])
        self.assertTrue(slot["alerts"], "must still be visible in the inbox")

    def test_usb_is_in_the_posture_ingest_gate(self):
        """THE trap. _ingest_posture_v3110 is called behind a key-presence gate;
        a host reporting no storage/firewall/timers/auth would never reach the
        compare block and the tripwire could never fire. Same class as the
        v6.0.1 mounts/mailq fix and the v6.1.2 'feature that can never fire'."""
        src = (_CGI / "api.py").read_text()
        i = src.index("_ingest_posture_v3110(dev_id, saved_dev.get('name'")
        gate = src[max(0, i - 700):i]
        self.assertIn("'usb'", gate)

    def test_safe_si_whitelists_usb(self):
        """safe_si is a whitelist — a field it drops never reaches the check."""
        src = (_CGI / "api.py").read_text()
        self.assertIn("safe_si['usb']", src)

    def test_agent_writes_usb_after_sysinfo_is_assigned(self):
        """The v6.1.2 batch-A bug: four collectors were written into `sysinfo`
        BEFORE its assignment, raising a swallowed UnboundLocalError, so all
        four were silently never sent. Keep this one on the right side of it."""
        src = _AGENT.read_text()
        assign = src.index("sysinfo = {")
        store = src.index("sysinfo['usb']")
        self.assertGreater(store, assign)

    def test_agent_reads_sysfs_not_lsusb(self):
        """usbutils is not in the agent image; sysfs IS mounted. lsusb would
        return nothing in a container, silently."""
        src = _AGENT.read_text()
        self.assertIn("/sys/bus/usb/devices", src)
        fn = src[src.index("def get_usb_devices"):src.index("def get_autoupdate_posture")]
        # No shell-out at all: the collector must read sysfs directly. (The
        # docstring names lsusb to explain why it is NOT used, so grep for the
        # subprocess call rather than the word.)
        self.assertNotIn("subprocess", fn)
        self.assertIn("host_path(", fn, "must go through host_path for containers")

    def test_frontend_has_both_spots(self):
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        self.assertIn("'usb_device_added'", js)
        self.assertIn("case 'usb_device_added':", js)


if __name__ == "__main__":
    unittest.main()
