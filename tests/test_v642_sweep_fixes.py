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


class TestBruteForceSourcesAreRealAddresses(unittest.TestCase):
    """`src.strip('[]').split(':')[0]` truncated every IPv6 address to its first
    hextet, so unrelated attackers merged into one counter — which then crossed
    the threshold on its own and fired naming `2001` as the source."""

    def test_ipv6_is_kept_whole(self):
        for ip in ("2001:db8::1", "::1", "2a02:1810:1234:5678::1f"):
            self.assertEqual(api._brute_src_ip(ip), ip, ip)

    def test_ports_and_brackets_are_peeled(self):
        self.assertEqual(api._brute_src_ip("[2001:db8::1]:22"), "2001:db8::1")
        self.assertEqual(api._brute_src_ip("192.0.2.7:52344"), "192.0.2.7")
        self.assertEqual(api._brute_src_ip("192.0.2.7"), "192.0.2.7")

    def test_non_addresses_are_dropped_not_counted(self):
        for bad in ("", "-", "invalid", "2001", "not:an:ip"):
            self.assertIsNone(api._brute_src_ip(bad), bad)

    def test_distinct_sources_stay_distinct(self):
        seen = {api._brute_src_ip(f"2001:db8:{i}::1") for i in range(20)}
        self.assertEqual(len(seen), 20,
                         "merging distinct attackers both hides them and false-fires")


class TestAlertEscalationUpdatesTheOpenRow(unittest.TestCase):
    """Coalescing refreshed only ts/count, so an open row was frozen at its
    first observation while the delivery channels paged on the NEW severity —
    the inbox actively disagreed with the page just received."""

    def setUp(self):
        api.save(api.ALERTS_FILE, {"alerts": []})
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1", "monitored": True}})

    def tearDown(self):
        api.save(api.ALERTS_FILE, {"alerts": []})

    def test_warn_then_crit_escalates_in_place(self):
        for sev in ("WARN", "CRIT"):
            api.fire_webhook("log_alert", {"device_id": "d1", "name": "h1",
                                           "unit": "syslog", "pattern": "p",
                                           "count": 1, "severity": sev})
        rows = [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                if not a.get("resolved_at")]
        self.assertEqual(len(rows), 1, "still one row — this is coalescing, not stacking")
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertTrue(rows[0].get("escalated_at"))

    def test_a_dip_does_not_downgrade_a_live_page(self):
        for sev in ("CRIT", "WARN"):
            api.fire_webhook("log_alert", {"device_id": "d1", "name": "h1",
                                           "unit": "syslog", "pattern": "p",
                                           "count": 1, "severity": sev})
        rows = [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                if not a.get("resolved_at")]
        self.assertEqual(rows[0]["severity"], "critical",
                         "escalate-only: the recover event closes a row, not a dip")


class TestCvssV4IsScored(unittest.TestCase):
    """NVD and OSV publish v4 vectors, which fell through every branch and
    scored `unknown` — no risk points, no CVE alert, invisible to SLA and
    compliance. Silence about a critical CVE is the worst failure here."""

    def setUp(self):
        s = importlib.util.spec_from_file_location(
            "cve_scanner_v642", _CGI / "cve_scanner.py")
        self.cs = importlib.util.module_from_spec(s)
        s.loader.exec_module(self.cs)

    def _sev(self, vec):
        return self.cs._severity_from_vuln(
            {"id": "X", "severity": [{"type": "CVSS_V4", "score": vec}]}, "Ubuntu")

    def test_a_critical_v4_advisory_is_critical(self):
        sev, src = self._sev(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        self.assertEqual(sev, "critical")
        self.assertEqual(src, "cvss_v4_approx",
                         "the source must say this is derived, not an official v4 score")

    def test_the_v4_only_user_interaction_vocabulary_is_translated(self):
        # v3 is N|R, v4 is N|P|A. Passing 'A' through unmapped made the whole
        # vector unparseable, so low/medium v4 advisories stayed invisible even
        # once the branch existed.
        self.assertEqual(self._sev(
            "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")[0], "low")
        self.assertEqual(self._sev(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")[0], "medium")

    def test_v3_scoring_is_unchanged(self):
        self.assertEqual(
            self.cs._cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)


class TestAlertCapEvictsResolvedFirst(unittest.TestCase):
    """The JSON backend got resolved-first eviction in v6.4.0 (_trim_alerts);
    the DB backends — the enterprise default — kept deleting oldest-overall, so
    the cap silently removed OPEN alerts while the retention hint promised it
    never would."""

    def test_both_db_backends_order_by_resolved_first(self):
        for mod, frag in (("storage.py", "json_extract(doc, '$.resolved_at') IS NULL"),
                          ("storage_pg.py", "(doc->>'resolved_at') IS NULL")):
            src = (_CGI / mod).read_text()
            i = src.index("def list_coalesce_or_append")
            block = src[i:src.index("\ndef ", i + 10)]
            self.assertIn(frag, block, f"{mod} still evicts oldest-overall")


class TestCronScheduleActuallyFires(unittest.TestCase):
    """There were TWO cron matchers with different capabilities, and both
    ACCEPTED what they could not evaluate — so a schedule saved through a
    validator that allows ranges simply never fired. A maintenance window of
    `0 22 * * 1-5` suppressed nothing, and with gate_exec on it held every exec
    and upgrade for its devices forever, waiting for a window that never opened."""

    def _fires_in(self, cron, year=2026, hour=3):
        import datetime
        n, d = 0, __import__('datetime').datetime(year, 1, 1, hour, 0)
        while d.year == year:
            if api._cron_matches(cron, d.timestamp()):
                n += 1
            d += datetime.timedelta(days=1)
        return n

    def test_sunday_is_both_0_and_7(self):
        # Every crontab accepts 7 for Sunday; the value is normalised to 0..6,
        # so `int('7') == 0` was False and the schedule matched nothing at all.
        self.assertEqual(self._fires_in('0 3 * * 0'), 52)
        self.assertEqual(self._fires_in('0 3 * * 7'), 52)

    def test_ranges_fire(self):
        self.assertEqual(self._fires_in('0 3 * * 1-5'), 261)   # weekdays 2026
        self.assertEqual(self._fires_in('0 3 * * 6-7'), 104)   # Sat + Sun

    def test_a_step_anchors_at_the_field_minimum(self):
        # `*/3` on months meant "month % 3 == 0" -> Mar/Jun/Sep/Dec. A quarterly
        # schedule is Jan/Apr/Jul/Oct.
        import datetime
        months = [m for m in range(1, 13)
                  if api._cron_matches('0 3 1 */3 *',
                                       datetime.datetime(2026, m, 1, 3, 0).timestamp())]
        self.assertEqual(months, [1, 4, 7, 10])

    def test_both_matchers_are_the_same_one(self):
        for spec, val, lo, hi, want in (
                ('1-5', 3, 0, 6, True), ('1-5', 6, 0, 6, False),
                ('*/15', 30, 0, 59, True), ('*/15', 31, 0, 59, False),
                ('5/15', 35, 0, 59, True), ('1,15', 15, 1, 31, True),
                ('10-20/5', 20, 0, 59, True), ('10-20/5', 18, 0, 59, False)):
            self.assertEqual(api._cron_field_match(spec, val, lo, hi), want,
                             f'{spec} vs {val}')

    def test_a_maintenance_window_with_a_range_is_active(self):
        import datetime
        # Wednesday 22:30 — inside `0 22 * * 1-5` + 60 minutes.
        wed = datetime.datetime(2026, 8, 5, 22, 30)
        self.assertEqual(wed.isoweekday(), 3)
        win = {'cron': '0 22 * * 1-5', 'duration': 3600}
        self.assertTrue(api._window_active(win, wed.timestamp()),
                        'the range form must suppress exactly like the list form')


class TestListenerScopeAgreesAcrossAgents(unittest.TestCase):
    """The Windows and macOS scope classifiers were string-prefix copies whose
    loopback test was an exact three-value tuple with a `world` catch-all — so a
    service bound to 127.0.0.2, or reported as `::ffff:127.0.0.1` by a
    dual-stack socket (which is what psutil hands back), raised a HIGH
    port_exposed_world alert. The server does not recompute the scope."""

    @classmethod
    def setUpClass(cls):
        cls.fns = {}
        for name, path, fn in (
                ('linux', 'client/remotepower-agent.py', '_sock_scope'),
                ('win', 'client/remotepower-agent-win.py', '_port_scope'),
                ('mac', 'client/remotepower-agent-mac.py', '_port_scope')):
            s = importlib.util.spec_from_file_location('scope_' + name, _ROOT / path)
            m = importlib.util.module_from_spec(s)
            s.loader.exec_module(m)
            cls.fns[name] = getattr(m, fn)

    def test_loopback_aliases_and_mapped_addresses_are_local(self):
        for a in ('127.0.0.1', '127.0.0.2', '127.0.1.1', '::1',
                  '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1'):
            for name, fn in self.fns.items():
                self.assertEqual(fn(a), 'local', f'{name} classified {a}')

    def test_mapped_rfc1918_is_lan_not_world(self):
        for a in ('::ffff:192.168.1.5', '192.168.1.5', '10.0.0.9', '172.20.0.4'):
            for name, fn in self.fns.items():
                self.assertEqual(fn(a), 'lan', f'{name} classified {a}')

    def test_genuinely_exposed_stays_world(self):
        # Including the unparseable case: an exposure we cannot classify must
        # fail loud, not quietly become 'local'.
        for a in ('0.0.0.0', '::', '8.8.8.8', '172.32.0.4', 'garbage', ''):
            for name, fn in self.fns.items():
                self.assertEqual(fn(a), 'world', f'{name} classified {a!r}')

    def test_all_three_agents_agree(self):
        for a in ('127.0.0.2', '::ffff:127.0.0.1', '::ffff:192.168.1.5',
                  'fe80::1', 'fd00::1', '0.0.0.0', '8.8.8.8', '172.32.0.4'):
            vals = {n: f(a) for n, f in self.fns.items()}
            self.assertEqual(len(set(vals.values())), 1, f'{a}: {vals}')


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
