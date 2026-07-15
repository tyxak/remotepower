"""v6.2.2 — no alert may fire without an explanation.

A prod incident: two `nic_errors` alerts landed in the inbox reading only
"nic_errors: <host>" — the bare machine event name, no context. The cause was
systemic, not one-off: `_alert_title` (which builds the inbox row title) fell
through to `f'{event}: {name}'` for ANY event without a hand-written branch, and
34 alertable events had none.

The fix made the fallback prefer the fire-site's human `detail`, then the event's
EVENT_REGISTRY `label` — so every alertable event yields a readable sentence.
This guardrail proves it for EVERY alertable event and fails if a future event
regresses to the bare machine-name fallback.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v622-titles-"))
_spec = importlib.util.spec_from_file_location("api_v622_titles", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_spec_n = importlib.util.spec_from_file_location("notify_v622_titles", _CGI / "notify.py")
notify = importlib.util.module_from_spec(_spec_n)
_spec_n.loader.exec_module(notify)


def _alertable_events():
    """Events that land in the Alerts inbox = those with a `severity` key that
    aren't phantom aliases."""
    return sorted(
        ev for ev, spec in api.EVENT_REGISTRY.items()
        if "severity" in spec and not spec.get("phantom")
    )


class TestNoAlertWithoutExplanation(unittest.TestCase):
    def test_no_alertable_event_shows_bare_event_name(self):
        """`_alert_title` must never return the bare "event: host" fallback for an
        alertable event — every one has a hand-written branch or a registry label."""
        offenders = []
        for ev in _alertable_events():
            title = api._alert_title(ev, {"device_name": "HOSTX"})
            if title == f"{ev}: HOSTX":
                offenders.append(ev)
        self.assertEqual(
            offenders, [],
            "these alertable events render as a bare machine name in the inbox "
            "(add a branch or a non-empty EVENT_REGISTRY label): " + ", ".join(offenders),
        )

    def test_title_is_nonempty_and_not_raw_key(self):
        for ev in _alertable_events():
            title = api._alert_title(ev, {"device_name": "HOSTX"})
            self.assertTrue(title and title.strip(), f"{ev}: empty title")
            # The raw snake_case key must not be the whole title.
            self.assertNotEqual(title.strip(), ev, f"{ev}: title is the raw key")

    def test_detail_is_surfaced_in_the_title(self):
        """When a fire site provides `detail`, the operator must see it."""
        for ev in ("nic_errors", "modules_hidden", "win_bitlocker_off"):
            if ev not in api.EVENT_REGISTRY:
                continue
            title = api._alert_title(ev, {"device_name": "H", "detail": "SENTINEL-DETAIL"})
            self.assertIn("SENTINEL-DETAIL", title, f"{ev}: detail dropped from title")

    def test_nic_errors_title_reads_as_a_sentence(self):
        t = api._alert_title("nic_errors", {
            "device_name": "ns3204737", "iface": "eth0",
            "detail": "eth0: +12 errors/drops since the last heartbeat",
        })
        self.assertIn("ns3204737", t)
        self.assertIn("eth0", t)
        self.assertNotEqual(t, "nic_errors: ns3204737")

    def test_webhook_message_never_raw_snake_case(self):
        """The webhook/push body fallback humanizes the key and surfaces detail."""
        # detail-carrying event → detail shown
        m = notify._webhook_message("nic_errors", {"device_name": "h", "detail": "D"})
        self.assertIn("D", m)
        # detail-less, branch-less event → humanized, not raw key
        m2 = notify._webhook_message("smart_failure", {"device_name": "nas"})
        self.assertNotIn("smart_failure", m2)
        self.assertIn("nas", m2)


if __name__ == "__main__":
    unittest.main()
