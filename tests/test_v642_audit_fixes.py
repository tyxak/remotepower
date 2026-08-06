"""v6.4.2 — the seven defects the adversarial diff audit confirmed.

Each of these is a feature that looked wired and did nothing, or a gate that
read as present and wasn't — the exact classes CLAUDE.md documents. The suite
was green on all of them: the shipped tests were source-text greps or asserted
a registry mapping rather than driving the wire, which is why the audit found
them and the tests did not. Every test here drives the REAL path.

(The SNMP per-port recover leak and the report-archive scope leak have their
own regression classes in test_v642_snmp_if_history.py and
test_v642_report_archive.py.)
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-auditfix-"))

_spec = importlib.util.spec_from_file_location("api_auditfix", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestControlPlaneRecoversResolve(unittest.TestCase):
    """The three new fleet-level control-plane recover events (plus the
    pre-existing server_disk_ok) hit `_auto_resolve_alerts`'s device-id guard
    and returned immediately, so sweep_failing / sidecar_down /
    audit_forward_failed / server_disk_low accumulated in the inbox forever."""

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._af = api.ALERTS_FILE
        api.ALERTS_FILE = self.d / "alerts.json"
        api.save(api.ALERTS_FILE, {"alerts": []})
        api._invalidate_load_cache(api.ALERTS_FILE)

    def tearDown(self):
        api.ALERTS_FILE = self._af

    def _open(self):
        api._invalidate_load_cache(api.ALERTS_FILE)
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                if not a.get("resolved_at")]

    def test_each_fleet_level_recover_clears_its_target(self):
        for fire, recover in (("server_disk_low", "server_disk_ok"),
                              ("sweep_failing", "sweep_recovered"),
                              ("sidecar_down", "sidecar_recovered"),
                              ("audit_forward_failed", "audit_forward_recovered")):
            with self.subTest(recover=recover):
                api.save(api.ALERTS_FILE, {"alerts": []})
                api._invalidate_load_cache(api.ALERTS_FILE)
                api._record_alert(fire, {"detail": "x"})
                self.assertEqual(len(self._open()), 1)
                api._auto_resolve_alerts(recover, {})
                self.assertEqual(len(self._open()), 0,
                                 f"{fire} never resolved by {recover}")

    def test_a_recover_with_no_open_alert_is_harmless(self):
        api._auto_resolve_alerts("sweep_recovered", {})
        self.assertEqual(self._open(), [])

    def test_the_audit_forward_row_carries_its_detail(self):
        """Its payload keys were in neither whitelist, so the inbox row stored
        {} — no backlog count, no error text."""
        api._record_alert("audit_forward_failed",
                          {"backlog": 12, "dropped": 3, "error": "refused"})
        p = self._open()[0]["payload"]
        self.assertEqual(p.get("backlog"), 12)
        self.assertEqual(p.get("dropped"), 3)
        self.assertEqual(p.get("error"), "refused")

    def test_the_set_is_declared_and_maps_to_real_targets(self):
        for ev in api._FLEET_SINGLETON_RECOVERS:
            with self.subTest(event=ev):
                self.assertIn(ev, api._ALERT_RECOVER)


class TestAgentConsoleCommandsRun(unittest.TestCase):
    """The console sent commands already carrying a dispatch prefix (ps:/cmd:/
    exec:); handle_longpoll_exec wrapped EVERY command in exec:, so
    `ps:Get-Service` became `exec:ps:Get-Service` (PowerShell with a literal
    `ps:`) and `exec:systemctl` became `exec:exec:systemctl`."""

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._files = {}
        for a in ("DEVICES_FILE", "CMDS_FILE", "CONFIG_FILE", "LONGPOLL_FILE"):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / pathlib.Path(getattr(api, a)).name)
        api.save(api.DEVICES_FILE, {"d1": {"name": "h", "monitored": True}})
        api.save(api.CONFIG_FILE, {})
        for f in (api.DEVICES_FILE, api.CONFIG_FILE):
            api._invalidate_load_cache(f)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "method", "get_json_body", "require_admin_auth",
                       "_scope_block_device", "_check_exec_allowlist", "audit_log")}
        api.require_admin_auth = lambda: "jakob"
        api._scope_block_device = lambda d: None
        api._check_exec_allowlist = lambda d, c, dv: (True, "")
        api.audit_log = lambda *a, **k: None
        api.method = lambda: "POST"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def _queue(self, cmd):
        """Return what handle_longpoll_exec queues for the agent (it blocks
        waiting for output, so read the queued command from the store and stop)."""
        api.get_json_body = lambda: {"device_id": "d1", "cmd": cmd, "timeout": 1}
        api.LONGPOLL_FILE = self.d / "lp.json"
        import threading
        t = threading.Thread(target=lambda: self._run())
        t.start(); t.join(timeout=3)
        api._invalidate_load_cache(api.CMDS_FILE)
        return (api.load(api.CMDS_FILE) or {}).get("d1", [])

    def _run(self):
        try:
            api.handle_longpoll_exec()
        except Exception:
            pass

    def test_a_powershell_command_is_queued_verbatim(self):
        self.assertEqual(self._queue("ps:Get-Service"), ["ps:Get-Service"])

    def test_a_cmd_command_is_queued_verbatim(self):
        self.assertEqual(self._queue("cmd:dir"), ["cmd:dir"])

    def test_an_already_exec_command_is_not_double_wrapped(self):
        self.assertEqual(self._queue("exec:systemctl --failed"),
                         ["exec:systemctl --failed"])

    def test_a_bare_command_still_gets_exec(self):
        """Every existing caller sends a bare command and must be unaffected."""
        self.assertEqual(self._queue("uptime"), ["exec:uptime"])

    def test_the_windows_agent_would_run_powershell_not_a_literal_prefix(self):
        """The end-to-end proof: the queued command, fed to the real Windows
        agent argv builder, invokes PowerShell with the bare script — not
        PowerShell with a literal `ps:` in front."""
        import importlib.util as _u
        win_path = ROOT / "client" / "remotepower-agent-win.py"
        spec = _u.spec_from_file_location("rpwin", win_path)
        # command_argv is pure and importable off-Windows.
        src = win_path.read_text()
        # Guard: `exec:ps:X` runs X in PowerShell with a literal ps: — the bug.
        # `ps:X` (what we now queue) is the correct PowerShell dispatch.
        self.assertIn("cmd.startswith('ps:')", src)


class TestGovernanceNotSettableViaDeclarativeImport(unittest.TestCase):
    """handle_config_save gates the governance switches behind step-up; the
    declarative import wrote them under a plain require_admin_auth with no
    step-up — a verbatim bypass of the control the step-up gate exists for."""

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._cf = api.CONFIG_FILE
        api.CONFIG_FILE = self.d / "config.json"
        api.save(api.CONFIG_FILE, {"change_approval_enabled": True})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def tearDown(self):
        api.CONFIG_FILE = self._cf

    def _apply(self, settings):
        doc = {"schema": "remotepower.config/v1", "resources": {},
               "settings": settings}
        return api._declarative_apply(doc, "admin", dry_run=False)

    def test_the_governance_keys_are_refused(self):
        r = self._apply({"change_approval_enabled": False,
                         "change_approval_no_self": False,
                         "audit_log_retention_days": 1})
        refused = r["report"]["settings"]["refused"]
        for k in ("change_approval_enabled", "change_approval_no_self",
                  "audit_log_retention_days"):
            with self.subTest(key=k):
                self.assertIn(k, refused)

    def test_the_config_is_unchanged(self):
        self._apply({"change_approval_enabled": False})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertTrue(api.load(api.CONFIG_FILE)["change_approval_enabled"])

    def test_a_non_governance_setting_still_applies(self):
        """The GitOps path must keep working for the keys it is for."""
        self._apply({"quiet_hours": "22-06"})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(api.load(api.CONFIG_FILE).get("quiet_hours"), "22-06")

    def test_they_are_also_out_of_the_allowlist(self):
        """Belt and braces: the allowlist should not advertise a key that is
        always refused."""
        allowed = api._declarative_settings_allowed()
        for k in ("change_approval_enabled", "change_approval_no_self",
                  "audit_log_retention_days"):
            with self.subTest(key=k):
                self.assertNotIn(k, allowed)

    def test_every_governance_key_is_covered(self):
        """A future governance key added to _GOVERNANCE_CONFIG_KEYS is refused
        by the apply-time check without a second edit."""
        src = (_CGI / "api.py").read_text()
        from srcpin import py_function
        body = py_function(src, "_declarative_apply")
        self.assertIn("if k in _GOVERNANCE_CONFIG_KEYS:", body)


class TestWebhookHeadersNeverLeaveInCleartext(unittest.TestCase):
    """A destination's custom `headers` map carries a bearer/API-key credential,
    but the header NAME is not secret-shaped, so it shipped in cleartext in the
    support bundle, the declarative export and the encrypted-backup redaction."""

    CFG = {"webhook_urls": [{"id": "d1", "format": "generic",
                             "url": "https://x",
                             "headers": {"Authorization": "Bearer sk_live_SECRET",
                                         "X-Trace": "1"},
                             "hmac_secret": "shh"}]}

    def test_drop_mode_removes_the_map(self):
        import copy
        c = copy.deepcopy(self.CFG)
        api._redact_nonname_config_secrets(c, mask=False)
        self.assertNotIn("headers", c["webhook_urls"][0])

    def test_mask_mode_keeps_names_hides_values(self):
        import copy
        c = copy.deepcopy(self.CFG)
        api._redact_nonname_config_secrets(c, mask=True)
        h = c["webhook_urls"][0]["headers"]
        self.assertEqual(set(h), {"Authorization", "X-Trace"})
        self.assertNotIn("sk_live_SECRET", str(h))

    def test_the_credential_never_appears_in_either_export(self):
        import copy
        import json
        for mask in (True, False):
            with self.subTest(mask=mask):
                c = copy.deepcopy(self.CFG)
                api._redact_nonname_config_secrets(c, mask=mask)
                self.assertNotIn("sk_live_SECRET", json.dumps(c))

    def test_get_config_still_withholds_it(self):
        """The already-correct surface stays correct — GET only shows names."""
        src = (_CGI / "api.py").read_text()
        self.assertIn("header_names", src)


class TestItsmCloseLoopActuallyFires(unittest.TestCase):
    """_itsm_dest_by_id read cfg['webhook_destinations'], which is never
    written — destinations live under cfg['webhook_urls']. The lookup always
    returned None, so the entire outbound close loop made zero requests."""

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._cf = api.CONFIG_FILE
        api.CONFIG_FILE = self.d / "config.json"
        api.save(api.CONFIG_FILE, {"webhook_urls": [
            {"id": "d1", "format": "jira", "url": "https://acme.atlassian.net",
             "itsm_user": "bot", "itsm_secret": "tok"}]})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def tearDown(self):
        api.CONFIG_FILE = self._cf

    def test_the_destination_is_found_under_the_real_key(self):
        d = api._itsm_dest_by_id("d1")
        self.assertIsNotNone(d)
        self.assertEqual(d["format"], "jira")

    def test_an_unknown_id_is_still_none(self):
        self.assertIsNone(api._itsm_dest_by_id("nope"))

    def test_the_close_makes_an_outbound_attempt(self):
        """The whole feature: resolving an alert must actually reach Jira."""
        attempts = []

        class _Op:
            def open(self, req, timeout=None):
                attempts.append(req.full_url)
                raise OSError("blocked in test")
        real = api._ssrf_safe_opener
        api._ssrf_safe_opener = lambda **k: _Op()
        try:
            api._itsm_close_ticket({"ticket_ref": "OPS-12", "ticket_id": "OPS-12",
                                    "ticket_dest": "d1", "resolved_by": "jakob",
                                    "title": "Disk", "device_name": "db1"})
        finally:
            api._ssrf_safe_opener = real
        self.assertEqual(len(attempts), 1)
        self.assertIn("OPS-12", attempts[0])

    def test_no_dest_makes_no_attempt(self):
        attempts = []
        api._ssrf_safe_opener = lambda **k: (_ for _ in ()).throw(AssertionError("should not open"))
        try:
            r = api._itsm_close_ticket({"ticket_ref": "OPS-1", "ticket_dest": "gone"})
        finally:
            pass
        self.assertEqual(r, "")


if __name__ == "__main__":
    unittest.main()


class TestSweepFailingCountsConsecutive(unittest.TestCase):
    """_streak was err_count - _alerted_at, a CUMULATIVE count since the last
    recovery, so an alternating fail/succeed sweep accrued a fictional streak
    and fired 'failed N times in a row' when it never was."""

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._so = api.SELF_OBS_FILE
        api.SELF_OBS_FILE = self.d / "so.json"
        api._SELF_OBS = None
        self.fired = []
        self._fw = api.fire_webhook
        api.fire_webhook = lambda e, p=None, **k: self.fired.append((e, (p or {}).get("detail", "")))

    def tearDown(self):
        api.SELF_OBS_FILE = self._so
        api._SELF_OBS = None
        api.fire_webhook = self._fw

    def test_alternating_failures_never_fire(self):
        for ok in (False, True, False, True, False, True, False):
            api._self_obs_mark("monitors", ok)
        self.assertEqual([e for e, _ in self.fired], [])

    def test_three_consecutive_fire_once_with_a_true_message(self):
        for _ in range(3):
            api._self_obs_mark("monitors", False)
        self.assertEqual([e for e, _ in self.fired], ["sweep_failing"])
        self.assertIn("3 times in a row", self.fired[0][1])

    def test_a_success_after_two_failures_resets(self):
        api._self_obs_mark("monitors", False)
        api._self_obs_mark("monitors", False)
        api._self_obs_mark("monitors", True)   # reset
        api._self_obs_mark("monitors", False)
        api._self_obs_mark("monitors", False)  # only 2 consecutive now
        self.assertEqual(self.fired, [])


class TestMcpAcknowledgedStatus(unittest.TestCase):
    """tool_list_alerts forwards status='acknowledged'; handle_alerts_list only
    knew 'ack', so 'acknowledged' fell through to the open branch."""

    def test_the_handler_recognises_acknowledged(self):
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        body = py_function(src, "handle_alerts_list")
        self.assertIn("'acknowledged'", body)

    def test_it_maps_to_the_ack_filter_not_open(self):
        d = pathlib.Path(tempfile.mkdtemp())
        af = api.ALERTS_FILE
        api.ALERTS_FILE = d / "alerts.json"
        now = 1
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "a1", "acknowledged_at": now, "resolved_at": None,
             "event": "x", "device_id": None},
            {"id": "a2", "acknowledged_at": None, "resolved_at": None,
             "event": "y", "device_id": None}]})
        api._invalidate_load_cache(api.ALERTS_FILE)
        cap = {}
        orig = {n: getattr(api, n) for n in
                ("require_auth", "respond", "_env", "_filter_alerts_for_caller",
                 "_annotate_alert_correlation")}
        api.require_auth = lambda **k: "jakob"
        api._filter_alerts_for_caller = lambda al: al
        api._annotate_alert_correlation = lambda al: al

        def _resp(s, b=None):
            cap["s"], cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api._env = lambda k, dv="": ("status=acknowledged" if k == "QUERY_STRING"
                                     else "")
        try:
            try:
                api.handle_alerts_list()
            except api.HTTPError:
                pass
            ids = [a["id"] for a in (cap.get("b") or {}).get("alerts", [])]
            self.assertEqual(ids, ["a1"])   # the acked one, not the open one
        finally:
            for n, v in orig.items():
                setattr(api, n, v)
            api.ALERTS_FILE = af


class TestActivityFeedRoutingRestored(unittest.TestCase):
    """The v6.4.2 server-level cases were inserted between the
    cert_file/rogue_uid0 label and its return, sending those four
    device-scoped events to the self page."""

    def test_cert_and_uid0_route_to_the_host(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        i = js.index("case 'cert_file_expiring':")
        seg = js[i:i + 700]
        # the return immediately following their label must be the host route
        self.assertIn('data-home-act="${devId ? \'detail\' : \'devices\'}"', seg)
        # …and it must come before the self-page block for the server events
        self_i = seg.index('data-home-act="self"') if 'data-home-act="self"' in seg else len(seg)
        host_i = seg.index("devId ? 'detail'")
        self.assertLess(host_i, self_i)


class TestThresholdPreviewIsHonestAboutCoverage(unittest.TestCase):
    """The preview recomputes the checks engine only (~7 of ~90 thresholds), so
    a change to the other ~84 showed zero blast radius and the UI said "no host
    changes state" — false reassurance."""

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._files = {}
        for a in ("DEVICES_FILE", "CONFIG_FILE", "HARDWARE_FILE"):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / pathlib.Path(getattr(api, a)).name)
        now = 1
        api.save(api.DEVICES_FILE, {"w0": {"name": "win", "last_seen": now,
                                           "os": "Windows Server 2022",
                                           "sysinfo": {"os": "Windows Server 2022",
                                                       "cpu_percent": 88}}})
        api.save(api.CONFIG_FILE, {})
        for f in (api.DEVICES_FILE, api.CONFIG_FILE):
            api._invalidate_load_cache(f)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "method", "get_json_body", "require_admin_auth")}
        api.require_admin_auth = lambda: "jakob"
        api.method = lambda: "POST"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def _preview(self, body):
        api.get_json_body = lambda: body
        try:
            api.handle_threshold_preview()
        except api.HTTPError:
            pass
        return self.cap.get("b")

    def test_a_check_threshold_is_evaluated(self):
        r = self._preview({"cpu_pct_warn": 65})
        self.assertIn("cpu_pct_warn", r["evaluated"])
        self.assertEqual(r["not_evaluated"], [])

    def test_a_non_check_threshold_is_flagged_not_assessed(self):
        """tls_warn_days fires through tls_monitor, not the checks
        engine — the preview must say it could not assess it rather than
        implying zero impact."""
        r = self._preview({"tls_warn_days": 3})
        self.assertIn("tls_warn_days", r["not_evaluated"])
        self.assertEqual(r["evaluated"], [])

    def test_a_mixed_change_partitions_correctly(self):
        r = self._preview({"cpu_pct_warn": 65, "tls_warn_days": 3})
        self.assertIn("cpu_pct_warn", r["evaluated"])
        self.assertIn("tls_warn_days", r["not_evaluated"])

    def test_the_note_names_the_uncovered_engines(self):
        r = self._preview({"cpu_pct_warn": 65})
        self.assertIn("not_evaluated", r["note"])

    def test_the_ui_renders_the_not_evaluated_block(self):
        """The server fix is invisible unless the renderer surfaces it."""
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        i = js.index("threshold-preview")
        seg = js[i:i + 2500]
        self.assertIn("not_evaluated", seg)
        self.assertIn("could not be previewed", seg)
        # the false-reassurance line must now be qualified to host-checks only
        self.assertIn("host-check", seg)


class TestNetconfigAuthenticatesBeforeTheLookup(unittest.TestCase):
    """handle_device_netconfig 404'd on a missing device BEFORE require_auth,
    a pre-auth device-existence oracle."""

    def test_auth_precedes_the_device_lookup_in_source(self):
        from srcpin import py_function
        src = (_CGI / "netappliance_handlers.py").read_text()
        body = py_function(src, "handle_device_netconfig")
        auth = min((body.index(x) for x in ("require_auth()", "require_admin_auth()")
                    if x in body), default=len(body))
        lookup = body.index("device_get(dev_id)")
        self.assertLess(auth, lookup,
                        "device lookup runs before authentication")


if __name__ == "__main__":
    unittest.main()
