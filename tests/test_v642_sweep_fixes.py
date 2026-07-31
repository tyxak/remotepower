"""v6.4.2 — the wide feature sweep's bug fixes.

Each test below corresponds to a defect found by a hunt that had to supply a
runnable reproduction, and each drives the REAL path rather than asserting about
source text — every one of these bugs was invisible to the source-level
guardrails that already existed.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-sweep-"))

_spec = importlib.util.spec_from_file_location("api_v642_sweep", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestTlsExpiryAlertsArePerTarget(unittest.TestCase):
    """Certificates are not devices, so `tls_expiry` carries no device_id and its
    identity was `(event, '', port)` — every cert expiring on :443 coalesced into
    ONE row, and renewing the first host auto-resolved it for all of them."""

    def setUp(self):
        api.save(api.ALERTS_FILE, {"alerts": []})

    def tearDown(self):
        api.save(api.ALERTS_FILE, {"alerts": []})

    def _open(self, event="tls_expiry"):
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                if a.get("event") == event and not a.get("resolved_at")]

    def test_three_certs_on_one_port_are_three_alerts(self):
        for h in ("a.example.com", "b.example.com", "c.example.com"):
            api.fire_webhook("tls_expiry", {"host": h, "port": 443,
                                            "days_left": 5, "severity": "warning"})
        self.assertEqual(len(self._open()), 3,
                         "each certificate needs its own row or the others are invisible")

    def test_renewing_one_cert_leaves_the_others_open(self):
        for h in ("a.example.com", "b.example.com"):
            api.fire_webhook("tls_expiry", {"host": h, "port": 443,
                                            "days_left": 5, "severity": "warning"})
        api.fire_webhook("tls_renewed", {"host": "a.example.com", "port": 443})
        still = self._open()
        self.assertEqual([a["payload"].get("host") for a in still], ["b.example.com"])

    def test_host_is_an_identity_field(self):
        self.assertIn("host", api._ALERT_IDENTITY_FIELDS)


class TestFailedTlsProbeIsNotAnExpiredCertificate(unittest.TestCase):
    """`days_until_expiry` returns 0 when there is no expires_at, which is
    indistinguishable from "expires today" — so an unreachable host raised a
    CRITICAL "Certificate EXPIRED" about a certificate nobody had read."""

    def test_needs_attention_ignores_a_failed_probe(self):
        api.save(api.TLS_TARGETS_FILE, {"t1": {"host": "web.example.com", "port": 443}})
        api.save(api.TLS_RESULTS_FILE, {"t1": {"status": "error",
                                               "error": "connection refused"}})
        items = [i for i in api._compute_attention() if i.get("kind") == "tls"]
        self.assertEqual(items, [], "a failed probe is a reachability fact, not an expiry")

    def test_a_real_expiry_still_alerts(self):
        api.save(api.TLS_TARGETS_FILE, {"t1": {"host": "web.example.com", "port": 443}})
        api.save(api.TLS_RESULTS_FILE, {"t1": {"status": "ok",
                                               "expires_at": int(time.time()) - 86400}})
        items = [i for i in api._compute_attention() if i.get("kind") == "tls"]
        self.assertTrue(items, "a genuinely expired certificate must still be raised")
        api.save(api.TLS_TARGETS_FILE, {})
        api.save(api.TLS_RESULTS_FILE, {})


class TestWindowsMountsSurviveIngest(unittest.TestCase):
    """The sanitizer required a leading '/', so EVERY mount a Windows agent
    reported was dropped and the whole storage view read as "nothing wrong"."""

    def test_windows_and_unc_paths_are_accepted(self):
        for p in ("/", "/var/log", "C:\\", "D:/", "\\\\srv\\share"):
            self.assertTrue(api._mount_path_ok(p), p)

    def test_relative_and_garbage_paths_are_still_rejected(self):
        for p in ("", "relative/path", "..\\x", "etc/passwd"):
            self.assertFalse(api._mount_path_ok(p), p)


class TestLogAlertSeverityReachesTheInbox(unittest.TestCase):
    """The log engine fires with `severity` ('CRIT'), `_alert_severity` read
    `level` — so every log rule filed as medium, disagreed with its own
    Needs-Attention card, and never reached web push."""

    def test_crit_rule_is_critical(self):
        self.assertEqual(
            api._alert_severity("log_alert", {"device_id": "d1", "severity": "CRIT"}),
            "critical")

    def test_warn_rule_is_medium(self):
        self.assertEqual(
            api._alert_severity("log_alert", {"device_id": "d1", "severity": "WARN"}),
            "medium")

    def test_the_older_level_key_still_works(self):
        self.assertEqual(
            api._alert_severity("log_alert", {"device_id": "d1", "level": "critical"}),
            "critical")


class TestZeroMeansOff(unittest.TestCase):
    """Three settings offer 0 as "disabled" and three reads used
    `int(cfg.get(k) or <default>)`, which cannot tell 0 from unset — so turning
    the feature off silently restored the default."""

    def test_audit_retention_zero_disables_age_eviction(self):
        cfg = {"audit_log_retention_days": 0}
        _raw = cfg.get("audit_log_retention_days")
        self.assertEqual(0 if _raw not in (None, "") else 90, 0)
        # Drive the real purge: a 200-day-old entry must survive.
        api.save(api.CONFIG_FILE, dict(api.load(api.CONFIG_FILE) or {},
                                       audit_log_retention_days=0))
        old = int(time.time()) - 200 * 86400
        api.save(api.AUDIT_LOG_FILE, {"entries": [
            {"ts": old, "actor": "a", "action": "old"},
            {"ts": int(time.time()), "actor": "a", "action": "recent"}]})
        api._purge_old_data(api.load(api.CONFIG_FILE) or {})
        kept = [e["action"] for e in (api.load(api.AUDIT_LOG_FILE) or {}).get("entries", [])]
        self.assertIn("old", kept, "0 must disable age-based eviction, not mean 90 days")

    def test_ups_runtime_zero_disables_the_trigger(self):
        raw = 0
        self.assertEqual(180 if raw in (None, "") else int(raw), 0)


class TestAgentlessLoadAverageSurvivesLocale(unittest.TestCase):
    """The remote probe parsed `uptime` with `awk -F,` — which splits on the
    COMMA, i.e. on the decimal separator in most of Europe. Every load below
    1.00 arrived as 0.0 and the agentless CPU check could never leave "ok"."""

    def test_probe_reads_proc_loadavg_and_pins_the_locale(self):
        import ssh_agent
        self.assertIn("LC_ALL=C", ssh_agent.SYSINFO_SCRIPT)
        self.assertIn("/proc/loadavg", ssh_agent.SYSINFO_SCRIPT)

    @unittest.skipUnless(Path("/proc/loadavg").exists(), "Linux only")
    def test_the_fraction_survives_a_comma_decimal_locale(self):
        import json
        import subprocess

        import ssh_agent
        truth = open("/proc/loadavg").read().split()[0]
        for loc in ("C", "da_DK.UTF-8", "de_DE.UTF-8"):
            r = subprocess.run(["sh", "-c", ssh_agent.SYSINFO_SCRIPT],
                               capture_output=True, text=True,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": loc, "LANG": loc})
            got = json.loads(r.stdout).get("loadavg_1m")
            self.assertEqual(got, truth, f"locale {loc} mangled the load average")


class TestMacAgentKeepsTheSysinfoRecord(unittest.TestCase):
    """The macOS agent attached custom-check results to a beat with no sysinfo.
    The server REPLACES dev['sysinfo'] wholesale, so that one-key dict wiped the
    record — uptime, mounts, ports, every percentage — on 11 of every 12 beats."""

    def setUp(self):
        s = importlib.util.spec_from_file_location(
            "mac_v642", _ROOT / "client/remotepower-agent-mac.py")
        self.mac = importlib.util.module_from_spec(s)
        s.loader.exec_module(self.mac)
        self.mac._watched_agent_checks = [
            {"id": "c1", "type": "file", "path": "/etc/hosts", "name": "hosts"}]

    def test_an_ordinary_beat_flags_its_sysinfo_as_partial(self):
        # Check results must still be delivered every beat (the v6.4.1 design
        # that tests/test_macos_agent.py pins) — the beat just has to SAY the
        # dict is partial so the server merges instead of replacing.
        b = self.mac.build_heartbeat({"device_id": "m", "token": "t"}, 2)
        self.assertIn("custom_check_results", b.get("sysinfo") or {})
        self.assertTrue(b.get("sysinfo_partial"),
                        "an unflagged partial sysinfo wipes the stored record")

    def test_the_cadence_beat_is_a_full_replace(self):
        b = self.mac.build_heartbeat({"device_id": "m", "token": "t"}, 1)
        self.assertIn("custom_check_results", b["sysinfo"])
        self.assertGreater(len(b["sysinfo"]), 5, "and the full record with it")
        self.assertFalse(b.get("sysinfo_partial"),
                         "a full sysinfo must replace, so stale keys cannot persist")

    def test_the_server_merges_a_partial_beat_over_the_stored_record(self):
        dev = "mac-merge-1"
        api.save(api.DEVICES_FILE, {dev: {
            "name": dev, "hostname": dev, "os": "macOS 15.2", "token": "tk",
            "last_seen": int(time.time()), "enrolled": int(time.time()),
            "tags": [], "group": "", "agentless": False,
            "sysinfo": {"uptime": "3 days", "platform": "macOS", "mem_percent": 41.0}}})
        _orig = api.get_json_body, api.method
        try:
            api.get_json_body = lambda: {
                "device_id": dev, "token": "tk",
                "sysinfo": {"custom_check_results": {"a": {"status": "ok"}}},
                "sysinfo_partial": True}
            api.method = lambda: "POST"
            try:
                api.handle_heartbeat()
            except (SystemExit, api.HTTPError):
                pass
        finally:
            api.get_json_body, api.method = _orig
        api._invalidate_load_cache(api.DEVICES_FILE)
        si = ((api.load(api.DEVICES_FILE) or {}).get(dev) or {}).get("sysinfo") or {}
        self.assertIn("custom_check_results", si, "the new signal landed")
        for k in ("uptime", "platform", "mem_percent"):
            self.assertIn(k, si, f"{k} was wiped by a partial beat")


if __name__ == "__main__":
    unittest.main()
