"""v6.4.2 — the external ticket loop closes in both directions.

Jira / ServiceNow / Zendesk destinations POSTed a create-ticket call on alert
ACK, stamped `ticket_ref`/`ticket_url` on the alert row, and never touched the
ticket again. No status read-back, no comment or transition on resolve, no
dedup, and no inbound webhook kind that could carry a closure back — while the
built-in helpdesk has always closed exactly this loop (tickets_handlers
resolves the linked alert when an internal ticket moves to resolved).

Both directions bit:

- A team living in Jira acks a `disk_predict_failure`, an issue opens, an
  engineer swaps the disk and closes the issue. RemotePower's alert stayed open
  forever: counting in the inbox, holding the host in Needs Attention, dragging
  the fleet health score down until somebody resolved it a second time in a
  second UI.
- A `patch_alert` that auto-heals — RemotePower re-evaluates and auto-resolves
  it — left an orphaned open Jira issue nobody would ever close.

And ack is re-runnable (un-ack then ack, or an escalation re-acking), so each
pass opened a fresh issue with the same summary.
"""

# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-itsm-"))

_spec = importlib.util.spec_from_file_location("api_itsm", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import notify  # noqa: E402

_DEST = {"id": "d1", "url": "https://acme.atlassian.net", "format": "jira",
         "itsm_user": "bot@acme.io", "itsm_secret": "tok",
         "jira_project": "OPS", "on_ack": True, "enabled": True}


class TestTheCloseBuilders(unittest.TestCase):
    def test_jira_comments_rather_than_transitioning(self):
        """Every Jira workflow names its transitions differently and addresses
        them by numeric id, so closing one needs configuration the operator has
        to supply. A comment always works, always tells the engineer looking at
        the ticket what happened, and never breaks because someone renamed a
        workflow step."""
        m, path, body, h = notify.build_itsm_close("jira", _DEST, "OPS-12", "OPS-12", "done")
        self.assertEqual(m, "POST")
        self.assertEqual(path, "/rest/api/2/issue/OPS-12/comment")
        self.assertIn(b"done", body)
        self.assertTrue(h["Authorization"].startswith("Basic "))

    def test_servicenow_resolves_the_incident(self):
        """A work note on an incident still sitting in the queue is not
        "closed" to anyone reading that queue."""
        m, path, body, _ = notify.build_itsm_close(
            "servicenow", _DEST, "INC0012", "sysid9", "done")
        self.assertEqual(m, "PATCH")
        self.assertIn("sysid9", path)
        self.assertIn(b'"state": "6"', body)

    def test_servicenow_needs_the_sys_id_not_the_number(self):
        """Addressing a ServiceNow incident by its INC number does not work —
        this is why ticket_id is stored alongside ticket_ref."""
        self.assertIsNone(notify.build_itsm_close(
            "servicenow", _DEST, "INC0012", "", "done"))

    def test_zendesk_solves_the_ticket(self):
        m, path, body, _ = notify.build_itsm_close("zendesk", _DEST, "4321", "4321", "done")
        self.assertEqual(m, "PUT")
        self.assertEqual(path, "/api/v2/tickets/4321.json")
        self.assertIn(b'"status": "solved"', body)

    def test_the_zendesk_comment_is_internal(self):
        """The requester does not need RemotePower's internal alert id."""
        _m, _p, body, _h = notify.build_itsm_close("zendesk", _DEST, "1", "1", "x")
        self.assertIn(b'"public": false', body)

    def test_a_reference_with_a_slash_cannot_escape_the_path(self):
        _m, path, _b, _h = notify.build_itsm_close(
            "jira", _DEST, "../../admin", "x", "y")
        self.assertNotIn("/../", path)

    def test_no_credentials_means_no_call(self):
        self.assertIsNone(notify.build_itsm_close("jira", {}, "OPS-1", "x", "y"))

    def test_no_reference_means_no_call(self):
        self.assertIsNone(notify.build_itsm_close("jira", _DEST, "", "", "y"))

    def test_an_unknown_format_means_no_call(self):
        self.assertIsNone(notify.build_itsm_close("trello", _DEST, "1", "1", "y"))

    def test_the_message_says_what_an_engineer_needs(self):
        msg = notify.itsm_close_message(
            {"title": "Disk failing", "device_name": "db1",
             "alertid": "alertid_000007"}, "jakob")
        for part in ("Disk failing", "db1", "jakob", "alertid_000007"):
            with self.subTest(part=part):
                self.assertIn(part, msg)

    def test_an_auto_resolve_does_not_claim_a_person_did_it(self):
        self.assertIn("automatically",
                      notify.itsm_close_message({"title": "Patches"}, "auto"))


class TestTheAddressableIdIsCaptured(unittest.TestCase):
    def test_jira(self):
        r = notify._parse_itsm_response("jira", "https://a.io/x", b'{"key":"OPS-9"}')
        self.assertEqual(r["ticket_id"], "OPS-9")

    def test_servicenow_keeps_both(self):
        raw = b'{"result":{"number":"INC001","sys_id":"abc123"}}'
        r = notify._parse_itsm_response("servicenow", "https://a.io/x", raw)
        self.assertEqual(r["ticket_ref"], "INC001")
        self.assertEqual(r["ticket_id"], "abc123")

    def test_zendesk(self):
        raw = b'{"ticket":{"id":77,"url":"https://a.io/t/77"}}'
        r = notify._parse_itsm_response("zendesk", "https://a.io/x", raw)
        self.assertEqual(r["ticket_id"], "77")


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("ALERTS_FILE", "CONFIG_FILE", "INBOUND_WEBHOOKS_FILE",
                     "DEVICES_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
            api._invalidate_load_cache(getattr(api, attr))
        self.cap = {}
        self.closed = []
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "method", "get_json_body", "audit_log",
                       "_log_inbound", "_itsm_close_ticket",
                       "_check_alert_mutation_perm", "_alert_mutable_by_caller",
                       "_dispatch_one_webhook", "_log_webhook")}
        api.audit_log = lambda *a, **k: None
        api._log_inbound = lambda *a, **k: None
        api._log_webhook = lambda *a, **k: None
        api._check_alert_mutation_perm = lambda: "jakob"
        api._alert_mutable_by_caller = lambda a: True
        api._itsm_close_ticket = lambda a: (self.closed.append(a), "closed")[1]
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

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get("b")

    def seed(self, **kw):
        alert = {"id": "a-1", "alertid": "alertid_000001", "event": "patch_alert",
                 "severity": "high", "title": "Patches pending",
                 "device_id": "d1", "device_name": "web1",
                 "ts": int(time.time()), "payload": {"device_id": "d1"},
                 "acknowledged_at": int(time.time()), "acknowledged_by": "jakob",
                 "resolved_at": None, "resolved_by": None}
        alert.update(kw)
        api.save(api.ALERTS_FILE, {"alerts": [alert]})
        api._invalidate_load_cache(api.ALERTS_FILE)
        return alert

    def alerts(self):
        api._invalidate_load_cache(api.ALERTS_FILE)
        return (api.load(api.ALERTS_FILE) or {}).get("alerts", [])


class TestOutboundClose(_Base):
    def test_a_manual_resolve_closes_the_ticket(self):
        self.seed(ticket_ref="OPS-12", ticket_id="OPS-12", ticket_dest="d1")
        api.get_json_body = lambda: {}
        self.call(api.handle_alert_resolve, "a-1")
        self.assertEqual(self.cap["s"], 200)
        self.assertEqual(len(self.closed), 1)
        self.assertEqual(self.closed[0]["ticket_ref"], "OPS-12")

    def test_it_carries_who_resolved_it(self):
        self.seed(ticket_ref="OPS-12", ticket_dest="d1")
        api.get_json_body = lambda: {}
        self.call(api.handle_alert_resolve, "a-1")
        self.assertEqual(self.closed[0]["resolved_by"], "jakob")

    def test_an_alert_with_no_ticket_makes_no_call(self):
        self.seed()
        api.get_json_body = lambda: {}
        self.call(api.handle_alert_resolve, "a-1")
        self.assertEqual(self.closed, [])

    def test_an_auto_resolve_closes_it_too(self):
        """The orphan case the finding names: a patch_alert that self-heals."""
        self.seed(event="patch_alert", ticket_ref="OPS-99", ticket_dest="d1")
        # `patch_ok` — the real recover event for patch_alert. `patch_cleared`
        # (my first guess) is not in _ALERT_RECOVER at all, so the test passed
        # nothing through the resolve path and would have gone green on a fix
        # that did not work.
        api._auto_resolve_alerts("patch_ok", {"device_id": "d1"})
        self.assertEqual([a["ticket_ref"] for a in self.closed], ["OPS-99"])
        self.assertTrue(self.alerts()[0]["resolved_at"])

    def test_the_close_runs_outside_the_alerts_lock(self):
        """It makes an outbound HTTP call and _log_webhook takes its own lock —
        inside, it would nest (the recurring lock-nesting bug) and hold the
        alert store open across a network timeout."""
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        for fn in ("_auto_resolve_alerts", "handle_alert_resolve"):
            with self.subTest(fn=fn):
                body = py_function(src, fn)
                i = body.index("_close_external_tickets")
                self.assertNotIn("_LockedUpdate", body[i:])

    def test_a_failing_provider_does_not_block_the_resolve(self):
        """RemotePower resolving its own alert must not depend on Jira."""
        api._itsm_close_ticket = lambda a: (_ for _ in ()).throw(OSError("down"))
        self.seed(ticket_ref="OPS-12", ticket_dest="d1")
        api.get_json_body = lambda: {}
        self.call(api.handle_alert_resolve, "a-1")
        self.assertEqual(self.cap["s"], 200)
        self.assertTrue(self.alerts()[0]["resolved_at"])


class TestNoDuplicateTickets(_Base):
    def _dests(self):
        api.save(api.CONFIG_FILE, {"webhook_urls": [dict(_DEST)]})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def test_a_second_ack_does_not_open_a_second_ticket(self):
        """Ack is re-runnable — un-ack then ack, or an escalation re-acking —
        and each pass used to open a fresh issue with the same summary."""
        self._dests()
        sent = []
        api._dispatch_one_webhook = lambda ev, d, *a: sent.append(d) or None
        api._fire_ack_webhooks({"id": "a-1", "ticket_ref": "OPS-12",
                                "payload": {}}, "jakob")
        self.assertEqual(sent, [])

    def test_a_non_itsm_destination_still_fires_on_a_re_ack(self):
        """The Slack ping SHOULD repeat — only ticket CREATION is idempotent."""
        api.save(api.CONFIG_FILE, {"webhook_urls": [
            dict(_DEST), {"id": "d2", "url": "https://hooks.slack.com/x",
                          "format": "slack", "on_ack": True, "enabled": True}]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        sent = []
        api._dispatch_one_webhook = lambda ev, d, *a: sent.append(d.get("id")) or None
        api._fire_ack_webhooks({"id": "a-1", "ticket_ref": "OPS-12",
                                "payload": {}}, "jakob")
        self.assertEqual(sent, ["d2"])

    def test_a_first_ack_still_opens_one(self):
        self._dests()
        sent = []
        api._dispatch_one_webhook = lambda ev, d, *a: sent.append(d.get("id")) or None
        api._fire_ack_webhooks({"id": "a-1", "payload": {}}, "jakob")
        self.assertEqual(sent, ["d1"])


class TestInboundCallback(_Base):
    def setUp(self):
        super().setUp()
        api.save(api.INBOUND_WEBHOOKS_FILE, {"tokens": [
            {"id": "t1", "label": "jira", "token": "rpwi_itsm", "enabled": True,
             "kind": "itsm"},
            {"id": "t2", "label": "alerts", "token": "rpwi_alert", "enabled": True,
             "kind": "alert"}]})
        api._invalidate_load_cache(api.INBOUND_WEBHOOKS_FILE)

    def post(self, body, token="rpwi_itsm"):
        api.get_json_body = lambda: body
        api._invalidate_load_cache(api.ALERTS_FILE)
        return self.call(api.handle_itsm_callback, token)

    def test_a_closed_jira_issue_resolves_the_alert(self):
        """The scenario the finding leads with: the engineer swapped the disk
        and closed the issue, and the alert sat open forever."""
        self.seed(ticket_ref="OPS-12", ticket_dest="d1")
        r = self.post({"issue": {"key": "OPS-12",
                                 "fields": {"status": {"name": "Done"}}}})
        self.assertEqual(r["resolved"], 1)
        a = self.alerts()[0]
        self.assertTrue(a["resolved_at"])
        self.assertEqual(a["resolved_by"], "itsm:OPS-12")

    def test_zendesk_and_servicenow_shapes_work_too(self):
        for body, ref in (({"ticket": {"id": 4321, "status": "solved"}}, "4321"),
                          ({"number": "INC0012", "state": "6"}, "INC0012")):
            with self.subTest(ref=ref):
                self.seed(ticket_ref=ref, ticket_dest="d1")
                self.assertEqual(self.post(body)["resolved"], 1)

    def test_our_own_shape_works_for_a_template_that_cannot_be_shaped(self):
        self.seed(ticket_ref="X-1", ticket_dest="d1")
        self.assertEqual(self.post({"ticket_ref": "X-1", "status": "closed"})["resolved"], 1)

    def test_a_non_closing_status_changes_nothing(self):
        """A Jira webhook fires on every field edit, not only on close."""
        self.seed(ticket_ref="OPS-12", ticket_dest="d1")
        r = self.post({"issue": {"key": "OPS-12",
                                 "fields": {"status": {"name": "In Progress"}}}})
        self.assertEqual(r["resolved"], 0)
        self.assertIsNone(self.alerts()[0]["resolved_at"])

    def test_a_missing_status_counts_as_closed(self):
        """Several providers let an operator wire a webhook that fires ONLY on
        transition-to-done and sends no status field. Refusing those would
        leave the loop open for the setups that configured it most carefully."""
        self.seed(ticket_ref="OPS-12", ticket_dest="d1")
        self.assertEqual(self.post({"ticket_ref": "OPS-12"})["resolved"], 1)

    def test_no_reference_is_a_400_that_says_what_to_send(self):
        self.post({"something": "else"})
        self.assertEqual(self.cap["s"], 400)
        self.assertIn("ticket_ref", self.cap["b"]["error"])

    def test_an_already_resolved_alert_is_not_touched_twice(self):
        self.seed(ticket_ref="OPS-12", resolved_at=1, resolved_by="jakob")
        self.assertEqual(self.post({"ticket_ref": "OPS-12"})["resolved"], 0)
        self.assertEqual(self.alerts()[0]["resolved_by"], "jakob")

    def test_a_different_ticket_does_not_resolve_this_alert(self):
        self.seed(ticket_ref="OPS-12", ticket_dest="d1")
        self.assertEqual(self.post({"ticket_ref": "OPS-99"})["resolved"], 0)

    def test_a_bad_token_is_401(self):
        self.post({"ticket_ref": "X"}, token="rpwi_nope")
        self.assertEqual(self.cap["s"], 401)

    def test_an_alert_token_cannot_be_used_here(self):
        """The same guard the syslog and SNMP-trap receivers have — a token
        pasted at the wrong URL should say so, not half-work."""
        self.post({"ticket_ref": "X"}, token="rpwi_alert")
        self.assertEqual(self.cap["s"], 400)
        self.assertIn("alert", self.cap["b"]["error"])


class TestWiring(unittest.TestCase):
    def test_the_token_kind_exists(self):
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        self.assertIn("'itsm'", py_function(src, "handle_inbound_webhooks_create"))

    def test_the_route_resolves(self):
        self.assertIn("/api/itsm/in/", (_CGI / "api.py").read_text())

    def test_the_ui_offers_the_kind_and_the_right_url(self):
        html = ROOT / "server" / "html" / "index.html"
        if not html.exists():
            self.skipTest("excluded from this tree")
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        self.assertIn('<option value="itsm">', html.read_text())
        self.assertIn("'/api/itsm/in/'", js)

    def test_the_internal_helpdesk_loop_is_untouched(self):
        """It already closed this loop; the point was to extend the pattern
        outward, not to replace it."""
        src = (_CGI / "api.py").read_text()
        self.assertIn("_apply_alert_recovery_to_tickets", src)


if __name__ == "__main__":
    unittest.main()
