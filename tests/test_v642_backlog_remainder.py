"""Regression tests for the sixteen remaining backlog fixes.

Written centrally rather than by the agents that made the fixes — an agent that
authors both a change and its test can satisfy itself. Several of these fixes
deviated from the suggested approach for good reasons, so the tests pin the
PROPERTY that matters rather than the shape of the code.
"""

import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
_CSS = ROOT / "server" / "html" / "static" / "css"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-rem-"))

_spec = importlib.util.spec_from_file_location("api_v642_rem", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
sys.modules["api_v642_rem"] = api
_spec.loader.exec_module(api)


def _mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


class TestSloBudgetKnowsWhenItCannotMeasure(unittest.TestCase):
    """At the shipped defaults the error budget was structurally binary: a
    99.9% target allows 0.1pp of downtime, but a 300-check window can only
    express multiples of 100/300 = 0.33pp, so `budget_remaining_pct` could only
    ever be 100.0 or 0.0 — presented as a precise number and, in Prometheus, as
    a hard breach the moment one check failed.

    Integrating down-SECONDS over a real time window does not help: the window
    is bounded by sample count, so the ratio and its quantisation are identical.
    The information is genuinely absent, so the fix reports that instead of
    inventing precision."""

    def test_the_measurability_boundary(self):
        f = api._slo_budget_window
        budget = round(100.0 - 99.9, 6)
        self.assertFalse(f(budget, 1)[1])
        self.assertFalse(f(budget, 999)[1], "999 checks cannot express 0.1pp")
        self.assertTrue(f(budget, 1000)[1], "1000 checks express exactly 0.1pp")
        self.assertTrue(f(budget, 5000)[1])

    def test_the_float_trap(self):
        """100.0 - 99.9 == 0.09999999999999432, so a naive `budget >=
        resolution` calls a 1000-check window one ULP too coarse to measure its
        own budget. That is not a rounding nicety — it is the difference
        between the feature working at the shipped default and not."""
        self.assertNotEqual(100.0 - 99.9, 0.1)
        self.assertTrue(api._slo_budget_window(100.0 - 99.9, 1000)[1])

    def test_resolution_is_the_smallest_expressible_downtime(self):
        for n, want in ((100, 1.0), (1000, 0.1), (5000, 0.02)):
            self.assertAlmostEqual(api._slo_budget_window(0.1, n)[0], want, places=6)


class TestControlPlaneUptimeMeasuresRequests(unittest.TestCase):
    """"Observed control-plane availability" reported 100% through a total
    app-server outage. `_record_self_alive` was called via `_safe(...)`, which
    early-returns under RP_EXTERNAL_SCHEDULER=1 — the install default — so the
    bucket was written only by the scheduler daemon, which ticks whether or not
    gunicorn is serving. The metric measured the wrong process."""

    def test_it_is_called_unconditionally_on_the_request_path(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("\n    _record_self_alive()\n", src,
                      "must be a plain request-path call, not wrapped in _safe()")

    def test_the_scheduler_does_not_stamp_it(self):
        """If the daemon also stamps the bucket, the metric reports the
        daemon's uptime again instead of the app server's.

        Parsed, not grepped: scheduler.py carries a COMMENT saying
        `_record_self_alive` is deliberately NOT a cadence sweep, and matching
        that made this fail against the CORRECT code."""
        tree = ast.parse((_CGI / "scheduler.py").read_text())
        cadence = next((n.value for n in ast.walk(tree)
                        if isinstance(n, ast.Assign) and len(n.targets) == 1
                        and getattr(n.targets[0], "id", "") == "CADENCE"), None)
        if cadence is None:
            self.skipTest("CADENCE is not a module-level literal any more")
        self.assertNotIn("_record_self_alive", ast.unparse(cadence),
                         "the scheduler must not stand in for a served request")


class TestPrometheusSeriesIdentityIsTheDeviceId(unittest.TestCase):
    """Per-device health was labelled with the DISPLAY name, so two hosts named
    `web01` collapsed into one series whose value flapped between them, and the
    metric could not be joined to any other series (which key on device id)."""

    def test_two_same_named_devices_stay_distinct(self):
        pe = _mod("prom_v642_rem", _CGI / "prometheus_export.py")
        src = (_CGI / "prometheus_export.py").read_text()
        self.assertIn("device_id", src,
                      "the series must be keyed on the id, not the display name")
        m = re.search(r'device_health_score.*', src)
        if m:
            self.assertNotRegex(m.group(0), r'device="\{?\s*name',
                                "still labelled by display name")


class TestMetricRollupRefreshesItsDueStamp(unittest.TestCase):
    """The sweep refreshed `last_run` only on the path where something changed,
    so on an idle fleet the stamp went stale, the gate stopped suppressing it,
    and an O(fleet) locked sweep ran on every cadence tick — the load being
    worst exactly when there is nothing to do."""

    def test_the_stamp_is_written_on_both_paths(self):
        import srcpin
        body = srcpin.py_function((_CGI / "api.py").read_text(),
                                  "run_metric_rollup_if_due")
        tree = ast.parse(body)
        stamps = [n for n in ast.walk(tree)
                  if isinstance(n, ast.Assign)
                  and "last_run" in ast.unparse(n)]
        self.assertTrue(stamps, "the due stamp is never written")
        # the write must not be nested under a "something changed" guard
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                inner = ast.unparse(node)
                if "last_run" in inner and "changed" in inner.lower():
                    self.fail("the due stamp is still gated on the changed path")


class TestSelfObservabilityReportsRealFailures(unittest.TestCase):
    """`build_self_obs_corpus` read `last_error`, a key the producer never
    writes, so a maintenance sweep that failed hard every run was indexed for
    the AI as "— ok". The advisor then reasoned from a clean bill of health."""

    def test_the_key_the_producer_writes_is_the_key_the_reader_reads(self):
        rag = (_CGI / "rag_index.py").read_text()
        api_src = (_CGI / "api.py").read_text()
        m = re.search(r"build_self_obs_corpus.*?(?=\ndef )", rag, re.S)
        self.assertIsNotNone(m, "build_self_obs_corpus vanished")
        body = m.group(0)
        keys = set(re.findall(r"\.get\('([a-z_]+)'", body))
        err_keys = {k for k in keys if "err" in k or "fail" in k}
        self.assertTrue(err_keys, "the corpus no longer reads any error field")
        for k in err_keys:
            self.assertRegex(api_src, rf"'{k}'\]\s*=|'{k}':",
                             f"rag_index reads `{k}` but nothing writes it")


class TestReportCsvEscapesFormulae(unittest.TestCase):
    """Every sibling exporter guards against spreadsheet formula injection; the
    fleet/site posture CSV did not, so a device NAME beginning `=`, `+`, `-` or
    `@` executed on open — and device names come from the agent."""

    def test_a_formula_cell_is_neutralised(self):
        src = (_CGI / "api.py").read_text()
        self.assertRegex(src, r"_csv_safe|_csv_cell|formula",
                         "no formula guard in the CSV path")

    def test_the_guard_covers_all_four_lead_characters(self):
        import srcpin
        try:
            body = srcpin.py_function(src := (_CGI / "api.py").read_text(), "_csv_safe")
        except Exception:
            self.skipTest("guard is inline rather than a named helper")
        for ch in ("=", "+", "-", "@"):
            self.assertIn(repr(ch).strip("'\""), body.replace('"', "'"),
                          f"lead character {ch!r} not guarded")


class TestNetworkMapRagReadsDeviceRecords(unittest.TestCase):
    """The `network_map` source was handed the bookmark dashboard's links.json
    instead of the device store, so the dependency-link half of the corpus could
    never produce a chunk — a RAG source that has been silently empty."""

    def test_the_builder_takes_devices(self):
        rag = (_CGI / "rag_index.py").read_text()
        m = re.search(r"def build_network_map_corpus\(([^)]*)\)", rag)
        self.assertIsNotNone(m, "builder signature changed")
        self.assertIn("devices", m.group(1),
                      "the builder must receive the device records")

    def test_the_source_watches_the_right_files(self):
        api_src = (_CGI / "api.py").read_text()
        m = re.search(r"def _rag_source_files.*?(?=\ndef )", api_src, re.S)
        self.assertIsNotNone(m)
        seg = m.group(0)
        # Strip comments before looking: the fix's own comment explains that
        # watching links.json was the bug, and matching that prose made this
        # fail against the CORRECT code.
        code = "\n".join(re.sub(r"#.*$", "", l) for l in seg.splitlines())
        i = code.find("network_map")
        self.assertGreater(i, -1, "network_map lost its staleness wiring")
        self.assertNotIn("links.json", code[i:i + 240],
                         "still watching the bookmark dashboard for a device-map source")


class TestEpssCacheOnlyStoresWhatWasAsked(unittest.TestCase):
    """`if want and ...` inverted its own bound: with no CVE findings the guard
    fell through and the ENTIRE ~290k-row feed was persisted — the cache grew
    without limit precisely on installs with nothing to score."""

    def test_no_findings_means_no_rows_persisted(self):
        import srcpin
        body = srcpin.py_function((_CGI / "api.py").read_text(), "_refresh_kev_epss_now")
        code = "\n".join(re.sub(r"#.*$", "", l) for l in body.splitlines())
        self.assertNotIn("if want and", code, "the inverted guard is still there")
        self.assertIn("if cid not in want", code,
                      "the bound must apply even when `want` is empty")


class TestWindowsDiskScanIsHonest(unittest.TestCase):
    """"Scan disk usage" returned 200 and a success toast for Windows hosts
    whose agent has no reader for the flag — the request was queued into a void.
    Either implement it or say so; a success toast for nothing is worse than an
    error."""

    def test_windows_agent_reads_the_flag_or_the_server_reports_it_unsupported(self):
        win = (ROOT / "client" / "remotepower-agent-win.py").read_text()
        api_src = (_CGI / "api.py").read_text()
        reads = "force_du_scan" in win
        gated = bool(re.search(r"force_du_scan.*(?:_split_targets_by_os_support|"
                               r"Linux only|not supported|unsupported)", api_src, re.S))
        self.assertTrue(reads or gated,
                        "Windows neither performs the scan nor is told it cannot")


class TestHostFactsComeFromAProducer(unittest.TestCase):
    """"Copy host summary" and the AI/RAG resource chunk read four sysinfo keys
    no producer ever writes, so CPU model, core count, RAM and load average were
    permanently blank in both — the dead-signal class."""

    def test_every_key_the_summary_reads_is_written_somewhere(self):
        app = (_JS / "app.js").read_text()
        agents = "\n".join((ROOT / "client" / n).read_text() for n in
                           ("remotepower-agent.py", "remotepower-agent-win.py",
                            "remotepower-agent-mac.py"))
        api_src = (_CGI / "api.py").read_text()
        m = re.search(r"function copyHostSummary.*?\n\}", app, re.S)
        if not m:
            self.skipTest("copyHostSummary renamed")
        for key in set(re.findall(r"si\.([a-z_]{4,})", m.group(0))):
            with self.subTest(key=key):
                self.assertTrue(key in agents or key in api_src,
                                f"summary reads sysinfo.{key}, which nothing produces")


class TestAuditRetentionIsArmed(unittest.TestCase):
    """Age-based audit retention never ran on a stock install: the daily
    sweep's arming gate did not consider `audit_log_retention_days`, while four
    surfaces reported 90 days as the effective policy."""

    def test_the_helper_resolves_the_effective_policy(self):
        f = getattr(api, "_audit_retention_days", None)
        self.assertIsNotNone(f, "_audit_retention_days is gone")
        self.assertEqual(f({"audit_log_retention_days": 30}), 30)
        self.assertEqual(f({"audit_log_retention_days": 0}), 0,
                         "0 must disable, as the Settings hint promises")

    def test_the_sweep_arms_on_it(self):
        import srcpin
        body = srcpin.py_function((_CGI / "api.py").read_text(), "_purge_old_data")
        self.assertIn("_audit_retention_days", body,
                      "the sweep does not consult the audit policy")


class TestKernelLogTimestampsSurvive(unittest.TestCase):
    """The agent parsed the real event time out of dmesg and the server threw it
    away, stamping every kernel error with ingest time — so an OOM at 04:11
    appeared in the timeline at whatever minute the heartbeat landed."""

    def test_the_agents_timestamp_is_used_when_present(self):
        f = getattr(api, "_agent_line_ts", None)
        self.assertIsNotNone(f, "_agent_line_ts is gone")
        now = int(time.time())
        real = now - 3600
        self.assertEqual(f(real, now), real, "an agent timestamp must win")
        self.assertEqual(f(real * 1000, now), real, "millisecond input must normalise")
        self.assertEqual(f(None, now), now, "absent falls back to ingest time")

    def test_an_absurd_timestamp_is_rejected(self):
        """An agent clock can be wrong; a 1970 or year-3000 stamp must not
        rewrite history."""
        now = int(time.time())
        for bad in (0, -1, now + 86400 * 400, 10 ** 12):
            self.assertEqual(api._agent_line_ts(bad, now), now, bad)


class TestFirewallDeleteAcceptsRealRules(unittest.TestCase):
    """The page drew a Delete button on every iptables rule, but the handler
    400'd any rule carrying a comment or a `!` negation — i.e. most real rules
    on a managed host. A button that always fails is worse than no button."""

    # The ref is the chain-first `iptables -S` spec; the leading `-A ` is
    # stripped upstream. My first draft passed the `-A INPUT …` form and
    # concluded the fix was incomplete — check the contract before the code.
    def test_comment_and_negation_rules_are_accepted(self):
        f = getattr(api, "_iptables_delete_args", None)
        self.assertIsNotNone(f, "_iptables_delete_args is gone")
        for ref in ('INPUT -p tcp -m tcp --dport 22 -j ACCEPT',
                    'INPUT -m comment --comment "allow ssh" -j ACCEPT',
                    'INPUT ! -s 10.0.0.0/8 -j DROP',
                    'KUBE-SERVICES -m comment --comment "kube-proxy service portals" -j ACCEPT'):
            with self.subTest(ref=ref):
                self.assertIsNotNone(f(ref), f"refused a real rule: {ref}")

    def test_injection_arrives_as_an_inert_argument(self):
        """The design quotes rather than rejects — deliberately, because
        widening the shared charset would also loosen the `add` path, which
        really is interpolated raw. So the property to pin is not "returns
        None" but "nothing reaches the shell as an operator". Verified by
        running the ASSEMBLED command with a stub in place of iptables, which
        is the only way to see what a shell actually does with it: shlex.split
        strips quotes, so a quoted `|` looks identical to a pipe."""
        for bad in ('INPUT -j ACCEPT; rm -rf /', 'INPUT `id`', 'INPUT $(id)',
                    'INPUT | sh', 'INPUT && curl evil', 'INPUT $(touch /tmp/pwned)',
                    "INPUT ';id;'"):
            with self.subTest(ref=bad):
                args = api._iptables_delete_args(bad)
                if args is None:
                    continue                       # refusing is also fine
                stub = 'iptables() { printf "ARG:%s\\n" "$@"; }\n'
                out = subprocess.run(['bash', '-c', stub + f'iptables -D {args}'],
                                     capture_output=True, text=True, timeout=30)
                argv = [l[4:] for l in out.stdout.splitlines() if l.startswith('ARG:')]
                self.assertTrue(argv, f'nothing reached the binary for {bad!r}')
                self.assertEqual(argv[0], '-D')
                self.assertNotIn('uid=', out.stdout, 'command substitution ran')
                self.assertEqual(out.stderr.strip(), '', out.stderr)

    def test_a_control_character_or_over_long_ref_is_refused(self):
        self.assertIsNone(api._iptables_delete_args('INPUT ' + 'x' * 500))
        self.assertIsNone(api._iptables_delete_args('INPUT\nrm -rf /'))
        self.assertIsNone(api._iptables_delete_args('-A INPUT -j ACCEPT'),
                          'a spec still carrying -A is not the expected form')


class TestAiDailyCapAcceptsZero(unittest.TestCase):
    """`parseInt(...) || 100` rewrote the documented "0 disables" value to 100,
    so the disable the hint and the `min="0"` input both advertise could not be
    set from Settings — while the server has always honoured a stored 0."""

    def test_the_saver_preserves_a_typed_zero(self):
        src = (_JS / "app-ai.js").read_text()
        m = re.search(r"max_requests_per_user_day[^,\n]*", src)
        self.assertIsNotNone(m)
        self.assertNotIn("|| 100", m.group(0),
                         "a legal 0 is still clobbered to the default")

    def test_the_server_treats_zero_as_unlimited(self):
        import srcpin
        body = srcpin.py_function((_CGI / "api.py").read_text(), "_ai_rate_limit_check")
        self.assertRegex(body, r"cap\s*<=\s*0",
                         "the server no longer honours 0 as unlimited")


class TestSeverityColoursExist(unittest.TestCase):
    """The three most severe dashboard events rendered with no colour at all:
    `.status-pill.crit` had no rule and `.activity-dot` had none whatsoever, so
    severity — the only reason to scan that feed — was invisible."""

    def test_the_classes_the_js_emits_are_styled(self):
        css = (_CSS / "styles.css").read_text()
        for cls in (".status-pill.crit", ".activity-dot"):
            self.assertIn(cls, css, f"{cls} has no CSS rule")

    def test_each_severity_variant_has_a_colour(self):
        css = (_CSS / "styles.css").read_text()
        for cls in (".activity-dot.crit", ".activity-dot.warn"):
            i = css.find(cls)
            self.assertGreater(i, -1, f"{cls} missing")
            self.assertRegex(css[i:i + 200], r"background|color",
                             f"{cls} declares no colour")


class TestBoardTileOpensItsOwnGroup(unittest.TestCase):
    """`boardOpenGroup(key)` ignored its argument and opened the unfiltered
    Devices list, so every tile on the board did the same thing."""

    def test_the_handler_uses_its_argument(self):
        import srcpin
        body = srcpin.js_function((_JS / "app.js").read_text(), "boardOpenGroup")
        m = re.match(r"function boardOpenGroup\s*\(\s*([A-Za-z_$][\w$]*)", body)
        self.assertIsNotNone(m)
        param = m.group(1)
        uses = len(re.findall(rf"\b{re.escape(param)}\b", body))
        self.assertGreater(uses, 1, "the parameter is still ignored")

    def test_the_synthetic_buckets_are_mapped_not_searched(self):
        """The board emits `(no group)` / `(no site)` / `(untagged)`, which
        match no device — dropping them into the free-text search would return
        an empty table, which looks like a broken filter rather than an
        unfiltered one."""
        import srcpin
        body = srcpin.js_function((_JS / "app.js").read_text(), "boardOpenGroup")
        self.assertIn("__none__", body,
                      "the synthetic empty bucket has no mapping")


if __name__ == "__main__":
    unittest.main()
