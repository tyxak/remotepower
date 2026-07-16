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

    def test_failed_unit_names_the_unit(self):
        """'a systemd unit entered the failed state' is useless without the unit."""
        t = api._alert_title("failed_unit", {
            "device_name": "tviweb01", "unit": "nginx.service", "new_count": 1})
        self.assertIn("nginx.service", t)
        self.assertIn("tviweb01", t)
        # the '+N more' count survives (new_count is whitelisted in _record_alert)
        t2 = api._alert_title("failed_unit", {
            "device_name": "h", "unit": "a.service", "new_count": 3})
        self.assertIn("+2 more", t2)

    def test_fallback_surfaces_the_named_resource(self):
        """An event with no hand-written branch but a specific resource field
        (target/label/…) must name that resource, not just the label."""
        # mailflow_delayed has no dedicated title branch → exercises the fallback.
        t = api._alert_title("mailflow_delayed", {"device_name": "h", "target": "smtp.ex.com"})
        self.assertIn("smtp.ex.com", t)
        self.assertIn("h", t)

    def test_high_value_events_name_resource_and_values(self):
        cases = {
            "server_disk_low": ({"name": "srv", "used_pct": 92, "free_gb": 4.1,
                                 "total_gb": 50, "threshold": 85}, ["92%", "4.1", "50"]),
            "ups_critical": ({"device_name": "r1", "ups": "apc", "battery_pct": 12}, ["apc", "12%"]),
            "kernel_outdated": ({"device_name": "w2", "running": "6.1", "latest": "6.5"}, ["6.1", "6.5"]),
            "snmp_trap_received": ({"name": "sw", "count": 3, "oid": "1.3.6", "value": "x"}, ["1.3.6"]),
            "vault_break_glass": ({"device_name": "db", "label": "root", "requester": "al",
                                   "reason": "inc"}, ["root", "al", "inc"]),
            "ct_new_certificate": ({"domain": "a.ex", "cn": "a.ex", "issuer": "LE"}, ["a.ex", "LE"]),
            "ip_conflict": ({"ip": "10.0.0.5", "detail": "assigned to a, b"}, ["10.0.0.5"]),
            "smart_failure": ({"device_name": "nas", "disks": ["/dev/sda"]}, ["/dev/sda"]),
            "readonly_fs": ({"device_name": "db", "paths": ["/var"]}, ["/var"]),
        }
        for ev, (payload, musts) in cases.items():
            t = api._alert_title(ev, payload)
            for m in musts:
                self.assertIn(str(m), t, f"{ev}: title '{t}' missing '{m}'")

    def test_custom_metric_alert_reaches_inbox(self):
        # It carries severity in the payload; _alert_severity must not drop it.
        self.assertEqual(api._alert_severity("custom_metric_alert", {"severity": "high"}), "high")
        self.assertEqual(api._alert_severity("custom_metric_alert", {}), "medium")

    def test_fleet_level_event_keeps_its_resource(self):
        # S1: a fleet-level event (no device name) must still name its resource.
        t = api._alert_title("ct_new_certificate", {"domain": "x.example"})
        self.assertIn("x.example", t)

    def test_new_count_whitelisted_in_record_alert(self):
        src = (_CGI / "api.py").read_text()
        rec = src[src.index("def _record_alert"):src.index("def _record_alert") + 4000]
        self.assertIn("'new_count'", rec)

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
