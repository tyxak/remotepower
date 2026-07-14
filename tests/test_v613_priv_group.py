"""v6.2.0 — privileged-group-change tripwire (competitive-gap item #8).

Someone landing in sudo/wheel (Linux) or Administrators (Windows) is the classic
post-compromise persistence step. Both agents ALREADY reported the membership —
Linux `get_local_accounts()` parses /etc/group for sudo/wheel/admin members, the
Windows agent runs `Get-LocalGroupMember -Group Administrators`, and both set
`a['sudo']` — but nothing ever diffed it. This adds the baseline + edge-trigger.

These tests drive the REAL ingest path (`_ingest_hardware`), not a hand-built
`{'payload': ...}` dict. That matters: a hand-built alert bypasses the
`_record_alert` payload whitelist, which is exactly how the v4.9.0 recover-event
bug went green in CI while being broken in production.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v613-priv-"))
_spec = importlib.util.spec_from_file_location("api_v613_priv", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _accounts(*users_with_sudo):
    """Build an `accounts` payload. Each arg is (user, sudo)."""
    return [
        {
            "user": u,
            "uid": 1000 + i,
            "shell": "/bin/bash",
            "home": f"/home/{u}",
            "login": True,
            "locked": False,
            "sudo": sudo,
            "age_days": 10,
            "flags": (["sudo"] if sudo else []),
        }
        for i, (u, sudo) in enumerate(users_with_sudo)
    ]


class TestPrivGroupTripwire(unittest.TestCase):
    def setUp(self):
        self.dev = "dev-priv-1"
        self.fired = []
        self._real_fire = api.fire_webhook
        api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))
        # Clear any prior hardware rec for this device.
        try:
            api._entity_write_one(api.HARDWARE_FILE, self.dev, {})
        except Exception:
            pass

    def tearDown(self):
        # Restore, in a finally-equivalent — a leaked monkeypatch silently
        # inverts every later test in this process (CLAUDE.md false-green #2).
        api.fire_webhook = self._real_fire

    def _ingest(self, accts):
        api._ingest_hardware(self.dev, "host-a", {"accounts": accts}, time.time())

    def _events(self):
        return [e for e, _ in self.fired]

    def test_first_contact_baselines_silently(self):
        """Enrolling a host that already has admins is NOT a privilege grant.
        Firing here would make the first heartbeat of every host a HIGH alert."""
        self._ingest(_accounts(("root", True), ("alice", True), ("bob", False)))
        self.assertNotIn("priv_group_added", self._events())

    def test_added_privileged_user_fires_once(self):
        self._ingest(_accounts(("alice", True), ("bob", False)))
        self.fired.clear()

        # bob gains sudo.
        self._ingest(_accounts(("alice", True), ("bob", True)))
        evs = [(e, p) for e, p in self.fired if e == "priv_group_added"]
        self.assertEqual(len(evs), 1, "exactly one grant should fire")
        self.assertEqual(evs[0][1]["user"], "bob")
        self.assertEqual(evs[0][1]["device_id"], self.dev)
        self.assertIn("detail", evs[0][1])

        # Steady state: the same membership must NOT re-fire every heartbeat.
        self.fired.clear()
        self._ingest(_accounts(("alice", True), ("bob", True)))
        self.assertNotIn("priv_group_added", self._events())

    def test_removal_does_not_fire(self):
        """A removal is not a security signal. Crying wolf on it gets the event
        muted — and a muted event catches no real escalation (hostkey lesson)."""
        self._ingest(_accounts(("alice", True), ("bob", True)))
        self.fired.clear()
        self._ingest(_accounts(("alice", True), ("bob", False)))
        self.assertEqual(self._events(), [])

    def test_removal_then_readd_fires_again(self):
        """The baseline must track removals even though they don't fire, or a
        re-grant after a revoke would be invisible."""
        self._ingest(_accounts(("alice", True), ("bob", True)))
        self._ingest(_accounts(("alice", True), ("bob", False)))
        self.fired.clear()
        self._ingest(_accounts(("alice", True), ("bob", True)))
        evs = [p for e, p in self.fired if e == "priv_group_added"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["user"], "bob")

    def test_windows_administrators_membership_uses_the_same_flag(self):
        """The Windows agent sets sudo=is_admin from Get-LocalGroupMember, so
        the SAME server-side tripwire must cover Windows with no extra code."""
        self._ingest([{"user": "Administrator", "uid": 500, "sudo": True, "flags": ["admin"]}])
        self.fired.clear()
        self._ingest([
            {"user": "Administrator", "uid": 500, "sudo": True, "flags": ["admin"]},
            {"user": "attacker", "uid": 1001, "sudo": True, "flags": ["admin"]},
        ])
        evs = [p for e, p in self.fired if e == "priv_group_added"]
        self.assertEqual([p["user"] for p in evs], ["attacker"])


class TestRegistryWiring(unittest.TestCase):
    """The registry is the single source of truth; the derived tables and the
    two frontend spots must agree or the event silently half-works."""

    def test_event_is_registered_and_alertable(self):
        ev = api.EVENT_REGISTRY["priv_group_added"]
        self.assertEqual(ev["kind"], "accounts")
        # A key ABSENT from `severity` means it never reaches the Alerts inbox.
        self.assertEqual(ev["severity"], "high")

    def test_kind_exists_in_the_channel_matrix(self):
        kinds = {k for k, _, _ in api.CHANNEL_KIND_DEFS}
        self.assertIn(api.EVENT_REGISTRY["priv_group_added"]["kind"], kinds)

    def test_payload_keys_survive_the_record_alert_whitelist(self):
        """`user` + `detail` must be whitelisted or the stored alert loses its
        evidence — the silent-drop class that broke the v4.9.0 recover events."""
        src = (_CGI / "api.py").read_text()
        start = src.index("def _record_alert(")
        window = src[start:start + 6000]
        self.assertIn("'user'", window)
        self.assertIn("'detail'", window)

    def test_frontend_has_both_spots(self):
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        self.assertIn("'priv_group_added'", js, "missing from FLEET_EVENTS")
        self.assertIn("case 'priv_group_added':", js, "missing _homeActivityAttrs case")

    def test_notification_message_is_purpose_built(self):
        import notify
        msg = notify._webhook_message("priv_group_added", {"name": "host-a", "user": "bob"})
        self.assertIn("bob", msg)
        self.assertIn("host-a", msg)


if __name__ == "__main__":
    unittest.main()
