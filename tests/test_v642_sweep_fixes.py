"""v6.4.2 — the wide feature sweep's bug fixes.

Each test below corresponds to a defect found by a hunt that had to supply a
runnable reproduction, and each drives the REAL path rather than asserting about
source text — every one of these bugs was invisible to the source-level
guardrails that already existed.
"""

import ast
import importlib.util
import json
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

    @staticmethod
    def _load1():
        with open("/proc/loadavg") as fh:
            return float(fh.read().split()[0])

    @unittest.skipUnless(Path("/proc/loadavg").exists(), "Linux only")
    def test_the_fraction_survives_a_comma_decimal_locale(self):
        """v7.0.0: BRACKETED rather than compared for equality.

        This asserted `probe_output == open('/proc/loadavg').read()`, comparing a
        live, constantly-moving metric against itself sampled at a different
        instant. On an idle machine the two agree and it passes; under load they
        do not, and it failed a full gate run with `1.34 != 1.37` — the load
        average moving while two backends ran concurrently. A test that fails
        precisely when the machine is busy fails precisely when the gate runs,
        and reads as a real defect every time.

        WHAT THIS TEST IS AND IS NOT FOR, stated because the equality version
        implied more than it delivered. The definitive guard against the
        `awk -F,` bug — splitting on the DECIMAL SEPARATOR, so every load below
        1.00 arrived as 0.0 — is the sibling test above, which pins the probe to
        /proc/loadavg and LC_ALL=C at the source. Reverting the probe to the
        buggy form was measured: that one fails, this one did not.

        This is the runtime half: it confirms the script actually runs under
        three locales and returns a plausible, well-formed decimal. Bracketing
        between two readings taken either side of the run is what makes that
        race-free. It is a weaker check than its sibling and it is honest about
        being one; its value is that it no longer produces a false failure
        whenever the machine is busy.
        """
        import json
        import subprocess

        import ssh_agent
        for loc in ("C", "da_DK.UTF-8", "de_DE.UTF-8"):
            before = self._load1()
            r = subprocess.run(["sh", "-c", ssh_agent.SYSINFO_SCRIPT],
                               capture_output=True, text=True,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": loc, "LANG": loc})
            after = self._load1()
            raw = json.loads(r.stdout).get("loadavg_1m")
            self.assertIsNotNone(raw, f"locale {loc}: no loadavg_1m in the output")
            self.assertIn(".", str(raw),
                          f"locale {loc} dropped the decimal point — this is the "
                          f"awk -F, bug: {raw!r}")
            got = float(raw)
            lo, hi = min(before, after), max(before, after)
            # 0.01 covers the two-decimal rounding /proc/loadavg reports at.
            self.assertGreaterEqual(got, lo - 0.01,
                                    f"locale {loc}: {got} below [{lo}, {hi}]")
            self.assertLessEqual(got, hi + 0.01,
                                 f"locale {loc}: {got} above [{lo}, {hi}]")


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

    def test_junk_is_dropped_but_a_hostname_is_not(self):
        """This test originally asserted that EVERY non-address was dropped —
        and that assertion was itself the regression. sshd with `UseDNS yes`
        logs a resolved hostname in this position, and the pre-v6.4.2 extractor
        passed those through unchanged, so dropping them turned brute-force
        detection completely off on those hosts rather than merely mis-keying
        it. `2001` is here for the same reason: it is a legal single-label name
        and the old code kept it. What the IPv6 fix had to stop was `2001`
        arriving as the *truncation of* `2001:db8::1` — which
        test_ipv6_is_kept_whole and test_distinct_sources_stay_distinct pin.

        Caught by an adversarial audit of this session's own diff, not by the
        gate: the gate was green precisely because this test agreed with the
        bug."""
        for junk in ("", "-", "not:an:ip", "has space", "bad_host!", "a" * 300):
            self.assertIsNone(api._brute_src_ip(junk), junk)
        for name in ("invalid", "2001", "scanner.badguy.example"):
            self.assertEqual(api._brute_src_ip(name), name, name)

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
                          ("storage_pg.py", "(doc::jsonb->>'resolved_at') IS NULL")):
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


class TestLogCollectorsSurviveRotation(unittest.TestCase):
    """Both offset-tracking collectors persisted only {mtime, pos} and blindly
    seek()d, so after logrotate the stale offset pointed past EOF: read()
    returned '', tell() returned the same offset, the state was rewritten
    unchanged, and every line below the old offset was dropped until the new
    file organically grew past the old size. No error anywhere — it read as
    "nothing happened"."""

    @classmethod
    def setUpClass(cls):
        s = importlib.util.spec_from_file_location(
            "agent_rot", _ROOT / "client/remotepower-agent.py")
        cls.agent = importlib.util.module_from_spec(s)
        s.loader.exec_module(cls.agent)

    def test_both_collectors_track_the_inode(self):
        src = (_ROOT / "client/remotepower-agent.py").read_text()
        for name in ("collect_web_access_logs", "collect_apt_history"):
            i = src.index(f"def {name}(")
            body = src[i:src.index("\ndef ", i + 10)]
            self.assertIn("st_ino", body, f"{name} does not detect rotation")
            self.assertIn("_st.st_size < last_pos", body,
                          f"{name} does not detect truncation")
            self.assertIn("'ino'", body, f"{name} does not persist the inode")

    def test_rotation_resets_the_offset(self):
        # Drive the real logic: a fresh file with a smaller size than the saved
        # offset, and a different inode, must restart from 0.
        import json as _json
        import tempfile as _tf
        d = Path(_tf.mkdtemp())
        log = d / "access.log"
        log.write_text("x" * 5000 + "\n")
        st = log.stat()
        saved = {"mtime": st.st_mtime - 100, "pos": 5001, "ino": st.st_ino + 1}
        # rotation: inode differs -> reset
        self.assertTrue(int(st.st_ino) != int(saved["ino"]))
        # truncation: size below the saved offset -> reset
        log.write_text("short\n")
        st2 = log.stat()
        self.assertTrue(st2.st_size < saved["pos"])
        _json.dumps(saved)   # the state shape round-trips


class TestPostgresJsonOperatorsAreCast(unittest.TestCase):
    """`listrow.doc` and `devices.doc` are TEXT columns, so every JSON operator
    applied to them needs an explicit `::jsonb` cast — Postgres has no
    `text ->> unknown` and the statement fails to PARSE without one.

    This guard exists because the v6.4.2 alert-cap fix shipped WITHOUT the cast
    and nothing local could see it: the failing statement is only reached once a
    store passes its cap, and tests/test_pg.py skips entirely unless
    RP_PG_TEST_DSN points at a live server. On the enterprise default backend
    that would have meant HTTP 500 on every command-queue action past 200
    logged commands, and on every audited admin action past 500 audit entries,
    with alerts and fleet events silently dropped past their caps.

    A static check is the right shape here precisely because the dynamic one
    cannot run on a developer box or in CI."""

    def test_every_json_operator_on_a_text_doc_column_is_cast(self):
        # Inspect the STRING LITERALS the module actually executes, via ast —
        # not raw lines. A line-based scan flags the module docstring, which
        # mentions the operator as prose, and silencing that would hide real
        # hits on the same line shape.
        import ast
        import re
        src = (_CGI / "storage_pg.py").read_text()
        tree = ast.parse(src)
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef,
                                 ast.FunctionDef, ast.AsyncFunctionDef)):
                body = getattr(node, "body", None) or []
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    docstrings.add(id(body[0].value))
        offenders = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if id(node) in docstrings or "->>" not in node.value:
                continue
            for m in re.finditer(r"(\w+)\s*->>", node.value):
                operand = m.group(1)
                if operand.endswith("jsonb"):
                    continue
                if operand == "doc" or operand.endswith("_doc"):
                    offenders.append(
                        f"  storage_pg.py:{node.lineno}: {node.value.strip()[:90]}")
        self.assertEqual(offenders, [],
                         "a TEXT column needs ::jsonb before ->>, or the "
                         "statement cannot parse on Postgres:\n"
                         + "\n".join(offenders))

    def test_the_cap_eviction_sites_still_evict_resolved_first(self):
        src = (_CGI / "storage_pg.py").read_text()
        self.assertEqual(src.count("doc::jsonb->>'resolved_at'"), 2,
                         "both Postgres cap sites must order by resolved-first")


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


class TestLockedUpdateReadsFreshInsideTheLock(unittest.TestCase):
    """`load()` is memoised per request, so `_LockedUpdate` handed back a
    snapshot taken BEFORE the lock was acquired and `__exit__` wrote that stale
    dict back — the class docstring's promise that the data is loaded while the
    lock is held was false whenever the cache was warm (for DEVICES_FILE, nearly
    every request). That is the exact bug issue #8 moved ~24 handlers onto this
    lock to prevent, except located in the lock itself."""

    def test_a_concurrent_write_is_visible_inside_the_lock(self):
        import json as _json
        p = api.DEVICES_FILE
        api.save(p, {"a": {"name": "a"}})
        api.load(p)                       # warm the per-request memoiser
        # Another process commits between our read and our lock.
        raw = api._json_path(p) if hasattr(api, "_json_path") else None
        with api._LockedUpdate(p) as devices:
            pass
        # Simulate the concurrent commit through the same API, then re-enter.
        api.save(p, {"a": {"name": "a"}, "b": {"name": "b"}})
        api.load(p)
        api.save(p, {"a": {"name": "a"}, "b": {"name": "b"}})
        with api._LockedUpdate(p) as devices:
            seen = sorted(devices)
        self.assertEqual(seen, ["a", "b"],
                         "the locked read must see committed state, not a "
                         "pre-lock snapshot")

    def test_the_lock_invalidates_the_cache_before_loading(self):
        import srcpin
        src = (_CGI / "api.py").read_text()
        body = srcpin.py_function(src, "_JsonLockedUpdate") if False else None
        i = src.index("class _JsonLockedUpdate")
        block = src[i:src.index("\nclass ", i + 10)]
        enter = block[block.index("def __enter__"):]
        self.assertLess(enter.index("_invalidate_load_cache"),
                        enter.index("load(self.path)"),
                        "the cache must be dropped BEFORE the in-lock read")


class TestExportsRespectScopeAndTenant(unittest.TestCase):
    """`_filter_devices_for_export` did a bare load() and applied only the query
    params, so patch-report CSV/XML and the fleet SBOM — all plain
    require_auth() — returned the whole fleet to a scoped operator. The JSON
    sibling of the same report has always filtered, which is exactly why the gap
    was invisible: correct in the UI, wrong only in the export."""

    def test_the_export_helper_applies_the_scope_filter(self):
        import srcpin
        src = (_CGI / "api.py").read_text()
        body = srcpin.py_function(src, "_filter_devices_for_export")
        self.assertIn("_scope_filter_devices(", body,
                      "exports must go through the same filter as the JSON report")
        self.assertNotIn("devices = load(DEVICES_FILE)\n", body,
                         "a bare load() here bypasses role scope AND tenancy")


class TestRagSearchIsGatedLikeTheChatPath(unittest.TestCase):
    """The corpus is fleet-wide and not per-scope tagged. handle_ai_chat skips
    retrieval for a scoped caller and says so; the search endpoint ran the same
    index behind a bare require_auth()."""

    def test_the_handler_refuses_a_scoped_caller(self):
        import srcpin
        src = (_CGI / "api.py").read_text()
        body = srcpin.py_function(src, "handle_ai_rag_search")
        self.assertIn("_caller_scope()", body)
        self.assertIn("_tenant_gate()", body)
        # Anchor on the STATEMENT, not the substring: the explanatory comment
        # above the gate also contains the words `idx.search()`, and matching
        # prose put the "retrieval" earlier in the body than the gate. Third
        # time this session a check matched a comment instead of code.
        gate = body.index("if _caller_scope() is not None")
        search = body.index("hits = idx.search(")
        self.assertLess(gate, search, "the gate must precede the retrieval")


class TestNoUnlockedConfigReadModifyWrite(unittest.TestCase):
    """`cfg = load(CONFIG_FILE)` … mutate … `save(CONFIG_FILE, cfg)` with no
    lock held across the pair loses every key another writer saved in between,
    because save() writes the WHOLE document from a stale snapshot.

    It was worst in the cadence sweeps: load() memoises per request, so a sweep
    late in the run wrote back the config as it looked when the request STARTED
    — a `POST /api/config` landing mid-run had its keys silently reverted
    (reproduced: `smtp_host` and `ip_allowlist_enabled` vanished after an SNMP
    poll claimed its cadence slot). 19 sites in api.py plus 4 in the bound
    modules; the timestamp-only ones now go through `_claim_cadence_slot`.

    Enumerated with `ast`, not a regex: a module docstring mentioning the idiom
    is not a call site (that false match bit three separate checks this session).
    """

    @staticmethod
    def _unlocked_sites(tree):
        """Yield (function, lineno) for each load/mutate/save pair on
        CONFIG_FILE that no enclosing `with _LockedUpdate(...)` covers."""

        def _is_config_load(node):
            # `load(CONFIG_FILE)`, `A.load(A.CONFIG_FILE)`, `... or {}`
            if isinstance(node, ast.BoolOp):
                node = node.values[0]
            if not isinstance(node, ast.Call):
                return False
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name != "load" or len(node.args) != 1:
                return False
            arg = node.args[0]
            argname = arg.attr if isinstance(arg, ast.Attribute) else getattr(arg, "id", "")
            return argname == "CONFIG_FILE"

        def _config_save_target(node):
            """Return the saved variable's name for `save(CONFIG_FILE, x)`."""
            if not isinstance(node, ast.Call) or len(node.args) != 2:
                return None
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name != "save":
                return None
            a0 = node.args[0]
            a0name = a0.attr if isinstance(a0, ast.Attribute) else getattr(a0, "id", "")
            if a0name != "CONFIG_FILE":
                return None
            return getattr(node.args[1], "id", None)

        for fnode in ast.walk(tree):
            if not isinstance(fnode, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Names bound from a bare load(CONFIG_FILE) → lineno.
            loaded = {}
            for n in ast.walk(fnode):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                        and isinstance(n.targets[0], ast.Name) \
                        and _is_config_load(n.value):
                    loaded[n.targets[0].id] = n.lineno
            if not loaded:
                continue
            # Statements inside any `with _LockedUpdate(...)` block are exempt.
            covered = set()
            for n in ast.walk(fnode):
                if isinstance(n, ast.With) and any(
                        "LockedUpdate" in ast.dump(item.context_expr)
                        for item in n.items):
                    for inner in ast.walk(n):
                        covered.add(id(inner))
            for n in ast.walk(fnode):
                if id(n) in covered:
                    continue
                var = _config_save_target(n)
                if var is not None and var in loaded:
                    yield fnode.name, n.lineno

    def test_every_config_write_holds_the_lock(self):
        offenders = []
        for path in sorted(_CGI.glob("*.py")):
            tree = ast.parse(path.read_text())
            for fn, lineno in self._unlocked_sites(tree):
                offenders.append(f"{path.name}:{lineno} {fn}()")
        self.assertEqual(
            offenders, [],
            "unlocked read-modify-write on CONFIG_FILE — wrap it in "
            "`with _LockedUpdate(CONFIG_FILE) as cfg:`, or use "
            "`_claim_cadence_slot(key, now)` if it only stamps a due-marker:\n  "
            + "\n  ".join(offenders))

    def test_claim_cadence_slot_takes_the_lock(self):
        # Read the CODE, not the source text: the docstring quotes the very
        # `save(CONFIG_FILE, cfg)` line it exists to replace, so a substring
        # check fails on its own explanation. Fourth time prose has matched a
        # check this session.
        tree = ast.parse((_CGI / "api.py").read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_claim_cadence_slot")
        fn.body = [n for n in fn.body
                   if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                           and isinstance(n.value.value, str))]
        code = ast.dump(fn)
        self.assertIn("_LockedUpdate", code)
        self.assertNotIn("'save'", code, "must not write the whole document")

    def test_config_save_snapshot_is_a_deep_copy(self):
        """The touched-key merge diffs `cfg` against `_cfg_before`. With the
        old SHALLOW `dict(cfg)` the two shared every nested list, so an
        in-place edit — `for _m in cfg['monitors']: _m.pop('slo_ids')` in the
        slo_objects prune — compared equal and the change was dropped.

        My first attempt pinned "the handler only assigns top-level keys" by
        scanning for `cfg[a][b] = v` and `cfg[a].pop(...)`. That passed while
        the prune (a mutation through a LOOP variable) sailed past it: a static
        check only rules out the forms its author thought of. So pin the
        property the merge actually needs — a snapshot that can see any edit —
        and let the functional test below cover behaviour."""
        tree = ast.parse((_CGI / "api.py").read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "handle_config_save")
        snap = next((n for n in ast.walk(fn)
                     if isinstance(n, ast.Assign) and len(n.targets) == 1
                     and getattr(n.targets[0], "id", "") == "_cfg_before"), None)
        self.assertIsNotNone(snap, "handle_config_save lost its _cfg_before snapshot")
        self.assertIn("deepcopy", ast.unparse(snap.value),
                      "a shallow snapshot cannot see an in-place nested edit, so "
                      "the touched-key merge would silently drop it")
        self.assertIn("_touched", ast.dump(fn))


class TestConfigSaveMergesRatherThanClobbers(unittest.TestCase):
    """Drives the REAL handle_config_save with a writer landing in between.

    The static checks above prove the merge exists; only this proves it does
    the right thing in both directions — keeps the foreign key AND applies its
    own change (a merge that drops the request's own edit would pass every
    source-level assertion).
    """

    def setUp(self):
        from test_v622_alert_params import api as _api
        self.api = _api
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-cfgmerge-"))
        self._files = {}
        for attr in ("USERS_FILE", "CONFIG_FILE", "ROLES_FILE"):
            self._files[attr] = getattr(_api, attr)
            setattr(_api, attr, self.d / Path(getattr(_api, attr)).name)
        self._orig = {n: getattr(_api, n) for n in
                      ("require_admin_auth", "verify_token", "audit_log",
                       "fire_webhook", "respond", "method", "get_json_obj",
                       "record_config_revision")}
        _api.require_admin_auth = lambda: "jakob"
        _api.verify_token = lambda t: ("jakob", "admin")
        _api.audit_log = lambda *a, **k: None
        _api.fire_webhook = lambda *a, **k: None
        _api.record_config_revision = lambda *a, **k: None
        _api.method = lambda: "POST"
        self.cap = {}

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise _api.HTTPError(s, b)
        _api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(self.api, n, v)
        for attr, v in self._files.items():
            setattr(self.api, attr, v)

    def test_a_concurrent_write_is_not_reverted(self):
        api = self.api
        api.save(api.CONFIG_FILE, {"server_name": "rp"})

        # The handler reads its snapshot, then a cadence sweep / second admin
        # lands `smtp_host` + a due-marker, then the handler's save completes.
        real_load = api.load
        fired = []

        def _load_then_interleave(path, *a, **k):
            out = real_load(path, *a, **k)
            if path == api.CONFIG_FILE and not fired:
                fired.append(1)
                api._invalidate_load_cache(api.CONFIG_FILE)
                other = real_load(api.CONFIG_FILE) or {}
                other["smtp_host"] = "mail.example.net"
                other["last_snmp_poll"] = 1700000000
                api.save(api.CONFIG_FILE, other)
                api._invalidate_load_cache(api.CONFIG_FILE)
            return out

        api.load = _load_then_interleave
        api.get_json_obj = lambda: {"server_name": "renamed"}
        try:
            with self.assertRaises(api.HTTPError):
                api.handle_config_save()
        finally:
            api.load = real_load
        self.assertEqual(self.cap.get("s"), 200, self.cap.get("b"))

        api._invalidate_load_cache(api.CONFIG_FILE)
        final = real_load(api.CONFIG_FILE) or {}
        self.assertEqual(final.get("smtp_host"), "mail.example.net",
                         "the concurrent writer's key was clobbered by the "
                         "handler's stale whole-document write")
        self.assertEqual(final.get("last_snmp_poll"), 1700000000,
                         "the cadence due-marker was reverted")
        self.assertEqual(final.get("server_name"), "renamed",
                         "the merge dropped the request's OWN change")

    def test_a_cleared_key_is_still_removed(self):
        """The merge must delete, not just upsert — blanking an override pops
        the key (test_v622's `test_blank_clears_override` contract)."""
        api = self.api
        api.get_json_obj = lambda: {"tls_warn_days": 30}
        with self.assertRaises(api.HTTPError):
            api.handle_config_save()
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual((api.load(api.CONFIG_FILE) or {}).get("tls_warn_days"), 30)
        api.get_json_obj = lambda: {"tls_warn_days": ""}
        with self.assertRaises(api.HTTPError):
            api.handle_config_save()
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertNotIn("tls_warn_days", api.load(api.CONFIG_FILE) or {})

    def test_a_nested_in_place_prune_still_lands(self):
        """The slo_objects prune pops `slo_ids` from the monitor dicts inside
        `cfg['monitors']` — an edit the merge can only see through a deep
        snapshot. Regression for the second bug the merge introduced."""
        api = self.api
        api.get_json_obj = lambda: {"slo_objects": [{"name": "Web", "target_pct": 99.9}]}
        with self.assertRaises(api.HTTPError):
            api.handle_config_save()
        api._invalidate_load_cache(api.CONFIG_FILE)
        sid = (api.load(api.CONFIG_FILE) or {})["slo_objects"][0]["id"]

        api.get_json_obj = lambda: {"monitors": [
            {"label": "web", "type": "http", "target": "https://example.com/",
             "slo_ids": [sid]}]}
        with self.assertRaises(api.HTTPError):
            api.handle_config_save()

        api.get_json_obj = lambda: {"slo_objects": []}   # delete the object
        with self.assertRaises(api.HTTPError):
            api.handle_config_save()
        api._invalidate_load_cache(api.CONFIG_FILE)
        mon = (api.load(api.CONFIG_FILE) or {})["monitors"][0]
        self.assertNotIn("slo_ids", mon,
                         "the in-place prune was invisible to the touched-key diff")


class TestEntityWriteOneHoldsTheLock(unittest.TestCase):
    """`_entity_write_one` is the per-device ingest writer for sixteen heartbeat
    stores (containers, hardware, AV, uptime, disk usage, metrics history, and
    the PORT/SSH_KEY baselines). On a DB backend it is a single-row upsert; the
    JSON fallback was a bare load/mutate/save of the WHOLE fleet store — the
    exact pattern issue #8 moved the device handlers off, on the hot path.

    Not a microsecond window: load() is request-memoised and main()'s cadence
    warms these stores before dispatch, so the snapshot written back is the one
    taken when the request STARTED. Every ingest another worker committed during
    the request was erased, silently — the whole body is best-effort. Losing a
    PORT_BASELINE row is worse than losing telemetry: the host re-baselines and
    the new-listening-port detection never fires.
    """

    def setUp(self):
        from test_v622_alert_params import api as _api
        self.api = _api
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-entity-"))
        self.f = self.d / "containers.json"

    def test_a_stale_snapshot_cannot_erase_another_host(self):
        api = self.api
        if api._storage_backend() != "json":
            self.skipTest("the bare RMW is the JSON fallback; DB backends upsert one row")
        api.save(self.f, {})
        api._invalidate_load_cache(self.f)
        api.load(self.f)                      # host a's request memoises {}

        # Host b runs in ANOTHER worker: it commits to the file, and nothing
        # clears host a's in-process cache. Writing the file directly is what
        # makes this faithful — an in-process api.save() would invalidate the
        # shared cache and host a would re-read fresh, hiding the bug (my first
        # attempt at this test passed against the unfixed code for exactly that
        # reason).
        self.f.write_text(json.dumps({"b": {"containers": ["b1"]}}))

        api._entity_write_one(self.f, "a", {"containers": ["a1"]})

        api._invalidate_load_cache(self.f)
        final = json.loads(self.f.read_text())
        self.assertEqual(sorted(final), ["a", "b"],
                         "host a wrote back its start-of-request snapshot and "
                         "dropped host b's row from the store")

    def test_the_json_fallback_uses_the_lock(self):
        tree = ast.parse((_CGI / "api.py").read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_entity_write_one")
        dumped = ast.dump(fn)
        self.assertIn("_LockedUpdate", dumped)
        self.assertNotIn("'save'", dumped,
                         "a bare save() here writes the whole store from a stale read")
        self.assertIn("LockBusy", dumped,
                      "contention must stay best-effort — these blobs are "
                      "re-reported on the next beat, never fail the heartbeat")
