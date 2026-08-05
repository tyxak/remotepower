"""v6.4.2 — four places the product stopped being honest at fleet scale.

  1. The NOC board's problem strip applied its 80-host cap INSIDE the device
     loop and only sorted down-first afterwards. So the 80 kept were the 80
     earliest-ENROLLED problem hosts, not the 80 worst — a newly-enrolled
     production cluster that went down was invisible on the wall display
     because older, merely-warning hosts had filled the slots. The client then
     rendered `Needs attention (${data.problems.length})`, which reads as a
     fleet total and was the capped number, so a 400-host outage displayed as
     80. The tiles path two lines below already sorted THEN sliced.

  2. Command History was capped at 200 fleet-wide by a hardcoded constant and,
     unlike the audit log and the fleet-event feed, discarded its overflow
     entirely. One 400-host bulk action wrote 400 rows and wiped the page.

  3. Fifteen device pickers fetched the full non-slim /devices payload —
     sysinfo, port baselines, hardware health, an SNMP summary per device — to
     fill a `<select>` with {id, name}. `?slim=1` has existed since v3.3.0.

  4. The Devices header checkbox selected only the RENDERED page, so a 340-host
     filtered set had to be selected page by page, and the bulk-actions modal's
     own picker cannot express the page's site / status / SNMP / free-text
     filters at all.
"""

import gzip
import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-fleetscale642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestBoardKeepsTheWorstNotTheOldest(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self._saved = {k: getattr(api, k) for k in
                       ("require_auth", "_caller_scope", "_tenant_gate", "_env")}
        api.require_auth = lambda *a, **k: "jakob"
        api._caller_scope = lambda *a, **k: None
        api._tenant_gate = lambda *a, **k: None
        api._env = lambda k, d="": d
        api.save(api.ALERTS_FILE, {"alerts": [], "alert_seq": 0})
        # Pin BOTH halves — get_online_ttl returns max(min_online_ttl, ttl).
        api.save(api.CONFIG_FILE, {"online_ttl": 300, "min_online_ttl": 150})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def _board(self, devices):
        api.save(api.DEVICES_FILE, devices)
        api._LOAD_CACHE.clear()
        try:
            api.handle_board()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            return e.body

    def test_a_later_enrolled_down_host_is_not_hidden_by_older_ones(self):
        """The bug in one assertion. Store order is enrolment order, so the old
        code kept whatever came first — and every DOWN host enrolled after the
        cap filled never reached the wall display."""
        devs = {}
        for i in range(200):
            devs[f"boardold{i:03}"] = {"name": f"old-{i:03}",
                                       "last_seen": self.now - 99999}
        devs["boardnew"] = {"name": "new-and-down", "last_seen": self.now - 99999}
        names = [p["name"] for p in self._board(devs)["problems"]]
        self.assertIn("new-and-down", names,
                      "a later-enrolled failing host is invisible on the board")

    def test_down_sorts_above_warn(self):
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "wa", "event": "metric_warning", "device_id": "bwarn",
             "ts": self.now, "severity": "medium"}], "alert_seq": 1})
        api._LOAD_CACHE.clear()
        r = self._board({
            "bwarn": {"name": "warn-host", "last_seen": self.now},
            "bdown": {"name": "down-host", "last_seen": self.now - 99999},
        })
        statuses = [p["status"] for p in r["problems"]]
        if "warn" in statuses and "down" in statuses:
            self.assertLess(statuses.index("down"), statuses.index("warn"))

    def test_the_uncapped_total_is_reported(self):
        """The client showed the capped number as a fleet total, so a 400-host
        outage read as 80 on a screen the NOC trusts."""
        devs = {f"bt{i:03}": {"name": f"h{i:03}", "last_seen": self.now - 99999}
                for i in range(300)}
        r = self._board(devs)
        self.assertEqual(r["problems_total"], 300)
        self.assertEqual(len(r["problems"]), r["problems_cap"])
        self.assertLess(len(r["problems"]), r["problems_total"])

    def test_a_small_fleet_reports_total_equal_to_shown(self):
        r = self._board({"bs1": {"name": "a", "last_seen": self.now - 99999}})
        self.assertEqual(r["problems_total"], len(r["problems"]))

    def test_the_client_renders_n_of_m(self):
        js = (_JS / "app.js").read_text()
        self.assertIn("problems_total", js,
                      "the client still shows the capped count as the total")
        self.assertIn("of ${_pTot}", js)


class TestCommandHistoryIsTunableAndArchived(unittest.TestCase):
    def setUp(self):
        self._arch = api.DATA_DIR / "command_history_archive.jsonl.gz"
        if self._arch.exists():
            self._arch.unlink()
        api.save(api.HISTORY_FILE, {"entries": []})
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()

    def _rows(self):
        return (api.load(api.HISTORY_FILE) or {}).get("entries") or []

    def _archived(self):
        if not self._arch.exists():
            return []
        return [json.loads(l) for l in
                gzip.open(str(self._arch), "rt").read().strip().splitlines() if l]

    def test_the_default_is_unchanged(self):
        self.assertEqual(api._command_history_cap(), api.MAX_HISTORY)

    def test_the_cap_is_tunable(self):
        api.save(api.CONFIG_FILE, {"command_history_max": 5000})
        api._LOAD_CACHE.clear()
        self.assertEqual(api._command_history_cap(), 5000)

    def test_the_cap_is_clamped_both_ways(self):
        for raw, want in ((999999, api.MAX_HISTORY_CEILING), (1, 50),
                          ("nonsense", api.MAX_HISTORY)):
            with self.subTest(raw=raw):
                api.save(api.CONFIG_FILE, {"command_history_max": raw})
                api._LOAD_CACHE.clear()
                self.assertEqual(api._command_history_cap(), want)

    def test_evicted_rows_are_archived_not_discarded(self):
        """The audit log and the fleet-event feed both gzip their overflow; this
        one dropped it, so one bulk action made older rows unrecoverable."""
        for i in range(api.MAX_HISTORY + 10):
            api.log_command("jakob", f"hd{i}", f"host{i}", "reboot")
        self.assertEqual(len(self._rows()), api.MAX_HISTORY)
        arch = self._archived()
        self.assertEqual(len(arch), 10, "the evicted tail was discarded")
        self.assertEqual(arch[0]["device_id"], "hd0",
                         "the OLDEST rows are the ones that should be archived")

    def test_the_archive_keeps_the_full_record(self):
        for i in range(api.MAX_HISTORY + 1):
            api.log_command("jakob", f"ha{i}", f"host{i}", "systemctl restart x")
        row = self._archived()[0]
        for k in ("ts", "actor", "device_id", "device_name", "command"):
            self.assertIn(k, row)

    def test_nothing_is_archived_below_the_cap(self):
        for i in range(5):
            api.log_command("jakob", f"hn{i}", f"host{i}", "x")
        self.assertEqual(self._archived(), [])

    def test_the_config_key_round_trips_through_the_real_save(self):
        """The save whitelist is the silent one — a key missing from the int
        loop is accepted, dropped, and the Settings field silently does
        nothing."""
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def handle_config_save("):]
        fn = fn[:fn.index("\ndef ")]
        self.assertIn("'command_history_max'", fn,
                      "the Settings field would silently not persist")

    def test_the_settings_field_exists_and_is_mapped(self):
        html = (ROOT / "server" / "html" / "index.html").read_text()
        js = (_JS / "app.js").read_text()
        self.assertIn('id="ap-command-history-max"', html)
        self.assertIn("'ap-command-history-max'", js)
        self.assertIn("'command_history_max'", js)

    def test_the_model_accepts_it(self):
        import request_models
        ok, err = request_models.validate(
            request_models.ConfigSaveRequest, {"command_history_max": "500"})
        self.assertTrue(ok, err)


class TestDevicePickersAreSlim(unittest.TestCase):
    """A `<select>` of {id, name} does not need every host's mounts,
    listening_ports, package list and SSH host keys."""

    _PICKERS = ("app-logs.js", "app-containers.js", "app-calendar.js",
                "app-iac.js", "app-billing.js", "app-hostconfig.js",
                "app-ai.js", "app-tickets.js")

    def test_no_picker_module_fetches_the_full_payload(self):
        for f in self._PICKERS:
            with self.subTest(module=f):
                src = (_JS / f).read_text()
                self.assertNotIn("api('GET', '/devices')", src,
                                 "still downloading sysinfo + port baselines + "
                                 "hardware health to fill a dropdown")

    def test_the_slim_payload_still_carries_what_they_read(self):
        """Driven, not assumed — the fields these pickers filter and label on
        must survive `?slim=1`, or this trades a perf win for a broken picker."""
        saved = {k: getattr(api, k) for k in
                 ("require_auth", "_caller_scope", "_tenant_gate", "_env")}
        api.require_auth = lambda *a, **k: "jakob"
        api._caller_scope = lambda *a, **k: None
        api._tenant_gate = lambda *a, **k: None
        api._env = lambda k, d="": "slim=1" if k == "QUERY_STRING" else d
        api.save(api.DEVICES_FILE, {"slimdev": {
            "name": "web01", "ip": "10.0.0.1", "group": "prod",
            "hostname": "web01.lan", "agentless": False, "os": "Ubuntu",
            "version": "6.4.2", "last_seen": int(time.time()),
            "sysinfo": {"mounts": [1] * 50}}})
        api._LOAD_CACHE.clear()
        try:
            api.handle_devices_list()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            body = e.body
        finally:
            for k, v in saved.items():
                setattr(api, k, v)
        rows = body if isinstance(body, list) else (body or {}).get("devices", [])
        row = rows[0]
        for k in ("id", "name", "ip", "group", "hostname", "agentless", "os",
                  "version", "online", "last_seen", "tags"):
            with self.subTest(field=k):
                self.assertIn(k, row, "a picker reads this field")
        self.assertNotIn("sysinfo", row, "slim is not slim")

    def test_the_ticket_search_is_debounced(self):
        """It was `inp.oninput = () => _tkCreateDevResults(inp.value)` — a fetch
        per character. A downstream 500ms in-flight coalescer softened that to
        roughly two requests per burst, which is a mitigation, not a reason to
        keep firing on every keystroke."""
        src = (_JS / "app-tickets.js").read_text()
        self.assertIn("_tkDevSearchDebounced", src)
        # The comment above the fix quotes the old wiring on purpose — assert
        # against the CODE, or this passes/fails on prose.
        code = re.sub(r"^\s*//.*$", "", src, flags=re.M)
        self.assertNotIn("oninput = () => _tkCreateDevResults(", code)
        self.assertNotIn("oninput = () => _tkDetailDevResults(", code)

    def test_the_ticket_device_index_is_cached(self):
        src = (_JS / "app-tickets.js").read_text()
        self.assertIn("_tkDevIndexAt", src,
                      "attaching a second device re-fetched the whole fleet")


class TestSelectAllMatchingFilters(unittest.TestCase):
    def setUp(self):
        self.js = (_JS / "app.js").read_text()
        self.html = (ROOT / "server" / "html" / "index.html").read_text()

    def test_the_action_exists(self):
        self.assertRegex(self.js, r"\bfunction selectAllMatchingFilters\s*\(")
        self.assertIn('data-action="selectAllMatchingFilters"', self.html)

    def test_it_uses_the_filtered_set_not_the_rendered_page(self):
        """The header checkbox iterates `#devices-minimal-tbody tr.dev-row`,
        which is 15/50/100 rows. That is the finding."""
        body = self.js[self.js.index("function selectAllMatchingFilters"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("_devicesFilteredIds", body)
        self.assertNotIn("querySelectorAll", body)

    def test_the_filtered_ids_are_refreshed_on_every_render(self):
        """A stale list would select devices the operator has since filtered
        out — worse than not offering the button at all."""
        self.assertIn("_devicesFilteredIds = filtered.map", self.js)

    def test_the_button_hides_when_it_would_add_nothing(self):
        body = self.js[self.js.index("function updateBatchBar()"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("missing === 0", body)

    def test_it_reports_how_many_it_selected(self):
        body = self.js[self.js.index("function selectAllMatchingFilters"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("toast(", body,
                      "selecting 340 devices silently is its own surprise")

    def test_no_inline_handlers_or_styles(self):
        body = self.js[self.js.index("function selectAllMatchingFilters"):]
        body = body[:body.index("\n}\n")]
        self.assertNotRegex(body, r"\son\w+=")
        self.assertNotRegex(body, r'\sstyle="')


if __name__ == "__main__":
    unittest.main()


class TestGenericWebhookCustomHeaders(unittest.TestCase):
    """A generic webhook destination could send exactly three headers
    (X-Title, X-Priority, X-Tags) and had no way to carry an Authorization or
    X-API-Key. Only the 13 format-locked hosted services could authenticate, so
    self-hosted n8n with header auth, a Vector/Fluent Bit HTTP source wanting a
    bearer token, and any internal API gateway were reachable only by putting
    the credential in a URL query parameter — or by standing up a shim service
    purely to add one header. (HMAC signing exists, but that is a signature the
    receiver must be coded to verify, not a credential a gateway accepts.)
    """

    def setUp(self):
        self.sent = {}
        self._saved = {k: getattr(api, k) for k in
                       ("_ssrf_safe_opener", "_url_targets_local_or_meta",
                        "_log_webhook")}

        class _Resp:
            status = 200
            def read(self): return b"{}"
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def _open(req, *a, **k):
            self.sent["headers"] = dict(req.headers)
            return _Resp()

        api._ssrf_safe_opener = lambda *a, **k: type(
            "O", (), {"open": staticmethod(_open)})()
        api._url_targets_local_or_meta = lambda *a, **k: False
        api._log_webhook = lambda *a, **k: None

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def _send(self, **dest):
        self.sent.clear()
        d = dict({"id": "d1", "url": "https://n8n.lan/webhook/x",
                  "format": "generic", "enabled": True}, **dest)
        api._dispatch_one_webhook("device_offline", d, {"device_id": "h1"},
                                  "web01 is offline", "Device Offline", 3, {})
        # urllib title-cases header names on the way out.
        return {k.lower(): v for k, v in (self.sent.get("headers") or {}).items()}

    def test_a_custom_header_reaches_the_wire(self):
        h = self._send(headers={"Authorization": "Bearer tok123",
                                "X-API-Key": "k"})
        self.assertEqual(h.get("authorization"), "Bearer tok123")
        self.assertEqual(h.get("x-api-key"), "k")

    def test_the_built_in_headers_survive(self):
        h = self._send(headers={"Authorization": "Bearer t"})
        self.assertEqual(h.get("x-title"), "Device Offline")
        self.assertEqual(h.get("content-type"), "application/json")

    def test_a_transport_header_cannot_be_overridden(self):
        """`Host` decides where the request actually goes."""
        h = self._send(headers={"Host": "evil.internal"})
        self.assertNotEqual(h.get("host"), "evil.internal")

    def test_the_signature_headers_cannot_be_forged(self):
        """A custom header must never be able to overwrite the HMAC RemotePower
        computes — a receiver verifying the signature would accept a forged
        one."""
        h = self._send(hmac_secret="s",
                       headers={"X-RemotePower-Signature": "sha256=forged"})
        self.assertNotEqual(h.get("x-remotepower-signature"), "sha256=forged")
        self.assertTrue(h.get("x-remotepower-signature", "").startswith("sha256="),
                        "the real signature stopped being sent")

    def test_a_hosted_format_ignores_them(self):
        """Discord/Slack/Matrix builders own their own auth header; letting an
        operator overwrite it could only break the destination."""
        h = self._send(format="discord", headers={"Authorization": "Bearer leak"})
        self.assertNotEqual(h.get("authorization"), "Bearer leak")

    def test_an_illegal_header_name_is_rejected_at_save(self):
        """A header NAME goes onto the wire verbatim — a CR/LF or colon in it
        splits the request."""
        saved = {k: getattr(api, k, None) for k in
                 ("require_admin_auth", "method", "get_json_body", "_env",
                  "audit_log")}
        api.require_admin_auth = lambda *a, **k: "admin"
        api.method = lambda: "POST"
        api._env = lambda k, d="": d
        api.audit_log = lambda *a, **k: None
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        try:
            for bad in ("X-Evil: injected", "X-Evil\r\nHost", "Host"):
                with self.subTest(name=bad):
                    api.get_json_body = lambda _b=bad: {"webhook_urls": [
                        {"id": "d1", "url": "https://x/y", "format": "generic",
                         "headers": {_b: "v"}}]}
                    try:
                        api.handle_config_save()
                        status = None
                    except api.HTTPError as e:
                        status = e.status
                    except SystemExit:
                        status = "exit"
                    self.assertEqual(status, 400,
                                     "an unsafe header name was accepted")
        finally:
            for k, v in saved.items():
                if v is not None:
                    setattr(api, k, v)

    def test_the_values_are_never_echoed_back(self):
        """They are credentials. Same treatment as hmac_secret / matrix_token —
        sent once, never returned, re-entered to change."""
        saved = {k: getattr(api, k, None) for k in
                 ("require_auth", "verify_token", "get_token_from_request",
                  "method", "_env")}
        api.require_auth = lambda *a, **k: "admin"
        api.verify_token = lambda *a, **k: ("admin", "admin")
        api.get_token_from_request = lambda: "x"
        api.method = lambda: "GET"
        api._env = lambda k, d="": d
        api.save(api.CONFIG_FILE, {"webhook_urls": [
            {"id": "d1", "url": "https://x/y", "format": "generic",
             "headers": {"Authorization": "Bearer supersecret"}}]})
        api._LOAD_CACHE.clear()
        try:
            try:
                api.handle_config_get()
                self.fail("handler did not respond")
            except api.HTTPError as e:
                body = e.body
        finally:
            for k, v in saved.items():
                if v is not None:
                    setattr(api, k, v)
        self.assertNotIn("supersecret", json.dumps(body),
                         "the credential was echoed back to the browser")
        dest = body["webhook_urls"][0]
        self.assertEqual(dest.get("header_names"), ["Authorization"],
                         "the NAMES must come back, or the editor cannot show "
                         "what is configured")

    def test_the_editor_offers_the_field(self):
        js = (_JS / "app.js").read_text()
        self.assertIn('data-field="custom_headers"', js)
        self.assertIn("d.headers = hdrs", js,
                      "the field is rendered and never read back out")
