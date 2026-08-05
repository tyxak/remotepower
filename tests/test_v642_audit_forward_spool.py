"""v6.4.2 — the audit log stops silently failing to reach the SIEM.

`audit_log()` called `_forward_audit(entry, cfg)` inline under
`except Exception: sys.stderr.write(...)`. A down collector, a refused TCP
syslog connection, a dropped UDP datagram, or one of THREE bare `return`s
inside `_forward_audit` (no target configured, the SSRF guard rejecting the
destination, DNS not resolving) discarded that entry from the SIEM forever.
No spool, no retry, no counter, no event, no health indicator.

The scenario is unremarkable: the collector is down over a long weekend, or an
operator fat-fingers `audit_forward_port`, or `webhook_block_local` starts
matching a collector that moved onto an internal address. Three days of admin
actions, break-glass reveals and session revocations never reach the SIEM,
nothing in the product says so, and the gap is unreconstructable afterwards
because the forwarder kept no cursor. The one place the operator would look —
the Security-posture checklist — reported `audit_forward: configured`, which
was true and answered a different question.

The local WORM copy always survived, so the record itself was never lost. The
compliance question "prove your security log in the SIEM is complete" was
unanswerable, which is the one that matters.

The webhook side has had a dead-letter queue, an inspection UI and a replay
button since v5.0.0. This is that shape, for audit.
"""

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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-afwd-"))

_spec = importlib.util.spec_from_file_location("api_afwd", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("AUDIT_FORWARD_SPOOL_FILE", "AUDIT_LOG_FILE", "CONFIG_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self._orig = {n: getattr(api, n) for n in
                      ("_forward_audit", "fire_webhook", "respond", "method",
                       "get_json_body", "require_admin_auth", "_get_client_ip")}
        self.fired = []
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, p or {}))
        api.require_admin_auth = lambda: "jakob"
        api._get_client_ip = lambda: "10.0.0.1"
        self.cap = {}

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.CONFIG_FILE, {"audit_forward_enabled": True,
                                   "audit_forward_mode": "http",
                                   "audit_forward_url": "https://siem.example/in"})
        for f in (api.CONFIG_FILE, api.AUDIT_FORWARD_SPOOL_FILE):
            api._invalidate_load_cache(f)

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def spool(self):
        api._invalidate_load_cache(api.AUDIT_FORWARD_SPOOL_FILE)
        return api.load(api.AUDIT_FORWARD_SPOOL_FILE) or {}

    def entry(self, n=1):
        return {"ts": int(time.time()), "actor": "jakob",
                "action": f"thing_{n}", "detail": "", "source_ip": "10.0.0.1"}


class TestFailuresAreSpooledNotDropped(_Base):
    def test_an_exception_spools_the_entry(self):
        api._forward_audit = lambda e, c: (_ for _ in ()).throw(OSError("connection refused"))
        api._spool_audit_forward(self.entry(), OSError("connection refused"))
        st = self.spool()
        self.assertEqual(len(st["entries"]), 1)
        self.assertIn("connection refused", st["last_error"])
        self.assertTrue(st.get("failing_since"))

    def test_a_declined_forward_is_spooled_too(self):
        """The three decline paths were bare `return`s — indistinguishable from
        success. An operator whose collector moved onto an address
        `webhook_block_local` matches lost every entry with nothing raised."""
        api.save(api.CONFIG_FILE, {"audit_forward_enabled": True,
                                   "audit_forward_mode": "http",
                                   "audit_forward_url": ""})
        api._invalidate_load_cache(api.CONFIG_FILE)
        why = api._forward_audit(self.entry(), api.load(api.CONFIG_FILE))
        self.assertTrue(why, "a forward that sent nothing must say so")
        self.assertIn("audit_forward_url", why)

    def test_the_ssrf_decline_names_itself(self):
        cfg = {"audit_forward_mode": "http", "webhook_block_local": True,
               "audit_forward_url": "http://169.254.169.254/latest/meta-data"}
        why = api._forward_audit(self.entry(), cfg)
        self.assertIn("SSRF", why)

    def test_a_successful_forward_returns_empty(self):
        """'' means delivered. Anything truthy is a reason it did not go."""
        sent = []
        cfg = {"audit_forward_mode": "syslog", "audit_forward_host": "127.0.0.1",
               "webhook_block_local": False}
        real_sock = api.socket.socket
        api.socket.socket = lambda *a, **k: type(
            "S", (), {"sendto": lambda s, p, addr: sent.append(p),
                      "close": lambda s: None})()
        try:
            self.assertEqual(api._forward_audit(self.entry(), cfg), "")
        finally:
            api.socket.socket = real_sock
        self.assertEqual(len(sent), 1)

    def test_an_unknown_mode_is_reported_not_swallowed(self):
        why = api._forward_audit(self.entry(), {"audit_forward_mode": "carrier-pigeon"})
        self.assertIn("carrier-pigeon", why)


class TestTheSpoolIsBounded(_Base):
    def test_the_oldest_go_and_the_loss_is_counted(self):
        """A silently truncated spool would recreate the very gap it exists to
        close, so the number of entries it could not hold is kept and surfaced."""
        api.MAX_AUDIT_FORWARD_SPOOL, real = 5, api.MAX_AUDIT_FORWARD_SPOOL
        try:
            for i in range(8):
                api._spool_audit_forward(self.entry(i), "down")
        finally:
            api.MAX_AUDIT_FORWARD_SPOOL = real
        st = self.spool()
        self.assertEqual(len(st["entries"]), 5)
        self.assertEqual(st["dropped"], 3)
        self.assertEqual(st["entries"][0]["action"], "thing_3")   # oldest evicted


class TestTheCircuitBreaker(_Base):
    def test_a_known_broken_forwarder_is_not_retried_inline(self):
        """The audit log is on the REQUEST path with a 5s connect timeout, so a
        wedged SIEM added up to 5s to every audited action."""
        api._spool_audit_forward(self.entry(), "down")
        self.assertTrue(api._audit_forward_breaker_open())

    def test_it_closes_once_the_attempt_is_old(self):
        api._spool_audit_forward(self.entry(), "down")
        with api._LockedUpdate(api.AUDIT_FORWARD_SPOOL_FILE) as st:
            st["last_attempt"] = int(time.time()) - 3600
        api._invalidate_load_cache(api.AUDIT_FORWARD_SPOOL_FILE)
        self.assertFalse(api._audit_forward_breaker_open())

    def test_a_healthy_forwarder_is_never_skipped(self):
        self.assertFalse(api._audit_forward_breaker_open())


class TestTheDrain(_Base):
    def _age(self, seconds):
        with api._LockedUpdate(api.AUDIT_FORWARD_SPOOL_FILE) as st:
            st["last_retry"] = int(time.time()) - seconds
            if st.get("failing_since"):
                st["failing_since"] = int(time.time()) - seconds
        api._invalidate_load_cache(api.AUDIT_FORWARD_SPOOL_FILE)

    def test_it_delivers_the_backlog_and_clears_it(self):
        for i in range(3):
            api._spool_audit_forward(self.entry(i), "down")
        self._age(3600)
        got = []
        api._forward_audit = lambda e, c: (got.append(e), "")[1]
        api.run_audit_forward_retry_if_due()
        self.assertEqual(len(got), 3)
        self.assertEqual(self.spool()["entries"], [])

    def test_a_partial_drain_keeps_the_rest_in_order(self):
        """The collector comes back, takes two, then falls over again. The
        third must still be there — and still be the third."""
        for i in range(3):
            api._spool_audit_forward(self.entry(i), "down")
        self._age(3600)
        n = {"i": 0}

        def _fwd(e, c):
            n["i"] += 1
            if n["i"] > 2:
                raise OSError("gone again")
            return ""
        api._forward_audit = _fwd
        api.run_audit_forward_retry_if_due()
        rest = self.spool()["entries"]
        self.assertEqual([r["action"] for r in rest], ["thing_2"])

    def test_it_respects_its_own_interval(self):
        """The FIRST attempt is prompt — a freshly spooled entry should not
        wait out an interval when the collector may already be back. It is the
        NEXT sweep that is throttled, so a hard-down collector is not hammered
        from every request."""
        api._spool_audit_forward(self.entry(0), "down")
        tries = []
        api._forward_audit = lambda e, c: (tries.append(e), "")[1]
        api.run_audit_forward_retry_if_due()
        self.assertEqual(len(tries), 1)               # prompt
        api._spool_audit_forward(self.entry(1), "down")
        api.run_audit_forward_retry_if_due()          # within the interval
        self.assertEqual(len(tries), 1, "the sweep ran again too soon")
        self.assertEqual(len(self.spool()["entries"]), 1)

    def test_forwarding_switched_off_keeps_the_backlog(self):
        """Turning it off should not silently discard entries the operator may
        still want delivered when they turn it back on."""
        api._spool_audit_forward(self.entry(), "down")
        self._age(3600)
        api.save(api.CONFIG_FILE, {"audit_forward_enabled": False})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.run_audit_forward_retry_if_due()
        self.assertEqual(len(self.spool()["entries"]), 1)
        self.assertFalse(self.spool().get("failing_since"),
                         "a disabled forwarder is not a live failure")

    def test_it_is_cheap_when_there_is_nothing_to_do(self):
        calls = []
        api._forward_audit = lambda e, c: calls.append(1)
        api.run_audit_forward_retry_if_due()
        self.assertEqual(calls, [])


class TestTheEventsFireOnceNotPerEntry(_Base):
    def _break_for(self, seconds, entries=1):
        for i in range(entries):
            api._spool_audit_forward(self.entry(i), "collector down")
        with api._LockedUpdate(api.AUDIT_FORWARD_SPOOL_FILE) as st:
            st["failing_since"] = int(time.time()) - seconds
            st["last_retry"] = 0
        api._invalidate_load_cache(api.AUDIT_FORWARD_SPOOL_FILE)

    def test_a_brief_outage_does_not_page_anyone(self):
        """A collector restart should not wake somebody — the entries are
        spooled either way."""
        self._break_for(10)
        api._forward_audit = lambda e, c: (_ for _ in ()).throw(OSError("down"))
        api.run_audit_forward_retry_if_due()
        self.assertEqual(self.fired, [])

    def test_a_sustained_outage_fires_once(self):
        self._break_for(api._AUDIT_FORWARD_ALERT_AFTER_S + 60, entries=4)
        api._forward_audit = lambda e, c: (_ for _ in ()).throw(OSError("down"))
        api.run_audit_forward_retry_if_due()
        self.assertEqual([e for e, _ in self.fired], ["audit_forward_failed"])
        self.assertEqual(self.fired[0][1]["backlog"], 4)
        # And not again on the next sweep — an outage that alerts every cycle is
        # a storm exactly when the operator can least read it.
        self.fired.clear()
        with api._LockedUpdate(api.AUDIT_FORWARD_SPOOL_FILE) as st:
            st["last_retry"] = 0
        api._invalidate_load_cache(api.AUDIT_FORWARD_SPOOL_FILE)
        api.run_audit_forward_retry_if_due()
        self.assertEqual(self.fired, [])

    def test_recovery_fires_only_if_it_had_alerted(self):
        self._break_for(api._AUDIT_FORWARD_ALERT_AFTER_S + 60, entries=2)
        api._forward_audit = lambda e, c: (_ for _ in ()).throw(OSError("down"))
        api.run_audit_forward_retry_if_due()
        self.fired.clear()
        with api._LockedUpdate(api.AUDIT_FORWARD_SPOOL_FILE) as st:
            st["last_retry"] = 0
        api._invalidate_load_cache(api.AUDIT_FORWARD_SPOOL_FILE)
        api._forward_audit = lambda e, c: ""
        api.run_audit_forward_retry_if_due()
        self.assertEqual([e for e, _ in self.fired], ["audit_forward_recovered"])
        self.assertEqual(self.fired[0][1]["delivered"], 2)

    def test_a_quiet_recovery_is_quiet(self):
        """Nothing alerted, so nothing needs an all-clear."""
        api._spool_audit_forward(self.entry(), "blip")
        with api._LockedUpdate(api.AUDIT_FORWARD_SPOOL_FILE) as st:
            st["last_retry"] = 0
        api._invalidate_load_cache(api.AUDIT_FORWARD_SPOOL_FILE)
        api._forward_audit = lambda e, c: ""
        api.run_audit_forward_retry_if_due()
        self.assertEqual(self.fired, [])
        self.assertTrue(self.spool().get("last_ok"))


class TestTheTestButtonStoppedLying(_Base):
    def test_a_declined_forward_reports_502_not_success(self):
        """The button an operator presses precisely to prove the pipe works was
        the one place that could report success for a forward that never left
        the box."""
        api.method = lambda: "POST"
        api.save(api.CONFIG_FILE, {"audit_forward_enabled": True,
                                   "audit_forward_mode": "http",
                                   "audit_forward_url": "http://127.0.0.1/in",
                                   "webhook_block_local": True})
        api._invalidate_load_cache(api.CONFIG_FILE)
        try:
            api.handle_audit_forward_test()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap["s"], 502)
        self.assertIn("declined", self.cap["b"]["error"])

    def test_a_real_send_still_reports_200(self):
        api.method = lambda: "POST"
        api._forward_audit = lambda e, c: ""
        try:
            api.handle_audit_forward_test()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap["s"], 200)


class TestPostureRowAnswersTheRightQuestion(_Base):
    def test_a_backlog_fails_the_row(self):
        """It used to answer "is a SIEM URL configured?" and present that as if
        it answered "is the SIEM getting the audit log?"."""
        src = (_CGI / "api.py").read_text()
        i = src.index("add('audit_forward'")
        block = src[max(0, i - 1400):i + 400]
        self.assertIn("_audit_forward_state()", block)
        self.assertIn("not delivered", block)

    def test_the_dropped_count_is_surfaced(self):
        src = (_CGI / "api.py").read_text()
        i = src.index("add('audit_forward'")
        self.assertIn("dropped past the spool cap", src[max(0, i - 1400):i + 400])


class TestRegistries(unittest.TestCase):
    """Every silent-failure class this codebase has hit came from one of these
    lists being updated and another not."""

    def test_the_events_are_registered(self):
        for ev in ("audit_forward_failed", "audit_forward_recovered"):
            with self.subTest(event=ev):
                self.assertIn(ev, api.EVENT_REGISTRY)
                self.assertIn(ev, {e[0] for e in api.WEBHOOK_EVENTS})

    def test_the_failure_reaches_the_inbox(self):
        self.assertEqual(api._ALERT_RULES.get("audit_forward_failed")[0], "high")

    def test_the_recovery_resolves_it(self):
        self.assertIn("audit_forward_failed",
                      api.EVENT_REGISTRY["audit_forward_recovered"]["resolves"])

    def test_the_sweep_is_in_both_cadence_registries(self):
        """main()'s _safe block and scheduler.py's CADENCE tuple are two
        registries; a sweep in one and not the other runs on the request path
        but not under an external scheduler (or vice versa)."""
        src = (_CGI / "api.py").read_text()
        sched = (_CGI / "scheduler.py").read_text()
        self.assertIn("_safe(run_audit_forward_retry_if_due", src)
        self.assertIn("'run_audit_forward_retry_if_due'", sched)

    def test_the_frontend_knows_the_events(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js")
        if not js.exists():
            self.skipTest("excluded from this tree")
        src = js.read_text()
        i = src.index("FLEET_EVENTS")
        for ev in ("audit_forward_failed", "audit_forward_recovered"):
            with self.subTest(event=ev):
                self.assertIn(f"'{ev}'", src[i:i + 12000])
                self.assertIn(f"case '{ev}'", src)

    def test_the_push_message_is_not_the_generic_fallback(self):
        import notify
        msg = notify._webhook_message("audit_forward_failed",
                                      {"backlog": 12, "dropped": 3,
                                       "error": "connection refused"})
        self.assertNotIn("unknown", msg)
        self.assertIn("12", msg)
        self.assertIn("3", msg)


if __name__ == "__main__":
    unittest.main()
