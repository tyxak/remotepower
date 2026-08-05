"""v6.4.2 — onboarding stops promising things it never checked.

Three findings, one theme: the product knows the answer and says nothing, or
says something it never verified.

  1. The setup checklist scored `notifications` DONE on a PRESENCE test, so one
     mis-pasted character in a Discord webhook path earned a green tick and
     "all set" — and the first real device_offline fired into a 404 with nobody
     paged, which is exactly what the checklist exists to prevent. The evidence
     was already collected (webhook_log.json) and already producible on demand
     (the "Send test webhook" button).

  2. That checklist had exactly one renderer: Settings → Install, reached only
     by opening Settings (which lands on General) and then clicking Install. A
     new operator lands on a dashboard of ~70 widgets all reading zero, and the
     one screen that says what to do next is two navigations away.

  3. The Enroll-device modal minted a token, printed the one-liners and went
     permanently silent. No poll, no pending state, no success state — the
     operator could not tell "it worked, wait 60s" from "the token was
     rejected", at the single highest-stakes moment in the first-run path.

And a bug found while wiring (1): `_log_email` wrote a BARE LIST over the
canonical `{'entries': […]}` dict, so the first email notification destroyed
every webhook delivery record and webhook logging then died permanently, its
AttributeError swallowed by its own bare except. Gating the checklist on that
evidence without fixing it would have made the tick unreachable.
"""

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-onboard642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_HTML = ROOT / "server" / "html"
_JS = _HTML / "static" / "js"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


def _entries():
    wl = api.load(api.WEBHOOK_LOG_FILE)
    if isinstance(wl, list):
        return wl
    return (wl or {}).get("entries") or []


class TestWebhookLogIsNotDestroyedByEmail(unittest.TestCase):
    """The delivery log is the operator's only evidence that alerts are getting
    out. One email wiped it and then killed webhook logging for good."""

    def setUp(self):
        api.save(api.WEBHOOK_LOG_FILE, {"entries": []})

    def test_an_email_does_not_wipe_webhook_entries(self):
        api._log_webhook("device_offline", "https://h/x", "ok", "sent")
        api._log_webhook("device_online", "https://h/x", "ok", "sent")
        self.assertEqual(len(_entries()), 2)
        api._log_email("cve_found", ["a@b.c"], "ok", "sent")
        self.assertEqual(len(_entries()), 3,
                         "the email replaced the log instead of appending — "
                         "every webhook delivery record is gone")

    def test_webhook_logging_survives_an_email(self):
        """The second-order failure: after the clobber, `wl.get('entries')` on a
        list raised into `except Exception: pass`, so webhook deliveries were
        silently never recorded again."""
        api._log_email("cve_found", ["a@b.c"], "ok", "sent")
        api._log_webhook("disk_full", "https://h/x", "ok", "sent")
        self.assertIn("disk_full", [e.get("event") for e in _entries()],
                      "webhook logging is dead after an email was sent")

    def test_a_clobbered_install_recovers_on_the_next_write(self):
        """Existing installs already have the bare list on disk. Fixing only the
        write side would leave them broken forever."""
        api.save(api.WEBHOOK_LOG_FILE,
                 [{"ts": 1, "event": "old (email)", "status": "ok", "detail": ""}])
        api._log_webhook("after", "https://h/x", "ok", "sent")
        got = api.load(api.WEBHOOK_LOG_FILE)
        self.assertIsInstance(got, dict, "shape was not migrated on read")
        self.assertEqual([e["event"] for e in got["entries"]],
                         ["old (email)", "after"],
                         "the pre-existing entry was dropped by the migration")

    def test_entries_stay_oldest_first(self):
        """The reader does `reversed(entries)`. `_log_email` used insert(0, …),
        so email rows rendered in the wrong order among the webhook ones."""
        api._log_webhook("first", "https://h/x", "ok", "")
        api._log_email("second", ["a@b.c"], "ok", "")
        api._log_webhook("third", "https://h/x", "ok", "")
        self.assertEqual([e["event"] for e in _entries()],
                         ["first", "second (email)", "third"])


class TestChecklistTickIsEvidence(unittest.TestCase):
    def setUp(self):
        self._verify = getattr(api, "require_auth", None)
        api.require_auth = lambda *a, **k: "admin"
        api.save(api.USERS_FILE, {"admin": {"pw": "x"}})
        api.save(api.DEVICES_FILE, {})
        api.save(api.WEBHOOK_LOG_FILE, {"entries": []})

    def tearDown(self):
        if self._verify is not None:
            api.require_auth = self._verify

    def _notif_step(self):
        try:
            api.handle_setup_status()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            body = e.body
        return next(s for s in body["steps"] if s["id"] == "notifications"), body

    def test_configured_but_never_delivered_is_not_done(self):
        """The whole finding: a typo'd Discord path scored a green tick."""
        api.save(api.CONFIG_FILE,
                 {"webhook_url": "https://discord.com/api/webhooks/TYPO"})
        step, body = self._notif_step()
        self.assertFalse(step["done"])
        self.assertTrue(step["configured"])
        self.assertFalse(step["verified"])
        self.assertFalse(body["complete"], "'all set' with nothing delivered")

    def test_a_failed_delivery_does_not_count(self):
        api.save(api.CONFIG_FILE, {"webhook_url": "https://discord.com/x"})
        api._log_webhook("test", "https://discord.com/x", "error", "404")
        step, _ = self._notif_step()
        self.assertFalse(step["done"],
                         "a 404 counted as proof the channel works")

    def test_a_successful_delivery_completes_it(self):
        api.save(api.CONFIG_FILE, {"webhook_url": "https://discord.com/x"})
        api._log_webhook("test", "https://discord.com/x", "ok", "delivered")
        step, _ = self._notif_step()
        self.assertTrue(step["done"])
        self.assertTrue(step["verified"])

    def test_an_email_delivery_also_counts(self):
        """SMTP is a first-class channel here; only counting webhooks would make
        the step unreachable on an email-only install."""
        api.save(api.CONFIG_FILE, {"smtp_enabled": True, "smtp_host": "mail.x"})
        api._log_email("test", ["a@b.c"], "ok", "sent")
        step, _ = self._notif_step()
        self.assertTrue(step["done"])

    def test_delivery_without_configuration_does_not_count(self):
        """A stale log entry from a channel that has since been removed must not
        keep the tick green."""
        api.save(api.CONFIG_FILE, {})
        api._log_webhook("test", "https://old/x", "ok", "delivered")
        step, _ = self._notif_step()
        self.assertFalse(step["done"])
        self.assertFalse(step["configured"])

    def test_the_detail_says_which_state_it_is_in(self):
        """Three different states need three different next actions; one static
        string cannot tell the operator which one they are in."""
        api.save(api.CONFIG_FILE, {})
        unconfigured, _ = self._notif_step()
        api.save(api.CONFIG_FILE, {"webhook_url": "https://x/y"})
        unverified, _ = self._notif_step()
        api._log_webhook("t", "https://x/y", "ok", "d")
        verified, _ = self._notif_step()
        details = {unconfigured["detail"], unverified["detail"],
                   verified["detail"]}
        self.assertEqual(len(details), 3, "two states share the same copy")
        # It must name the corrective action, not just report the state — an
        # operator who is told "not verified" and nothing else is stuck.
        self.assertIn("send a test", unverified["detail"].lower())

    def test_an_unreadable_log_does_not_break_the_checklist(self):
        api.save(api.CONFIG_FILE, {"webhook_url": "https://x/y"})
        try:
            api.save(api.WEBHOOK_LOG_FILE, "not a log at all")
            step, body = self._notif_step()
        finally:
            # Leave the store readable. A poisoned shared store is the class-4
            # order-dependency, and this one really did take out an unrelated
            # module (the Prometheus exporter iterated the string's CHARACTERS
            # and 500'd the whole scrape — a real bug, now fixed, but this test
            # must not be the thing that fires it at a neighbour).
            api.save(api.WEBHOOK_LOG_FILE, {"entries": []})
        self.assertFalse(step["done"])
        self.assertEqual(len(body["steps"]), 5, "the checklist itself broke")


class TestChecklistOnTheDashboard(unittest.TestCase):
    def setUp(self):
        self.js = (_JS / "app.js").read_text()
        self.html = (_HTML / "index.html").read_text()

    def test_the_widget_key_is_in_both_registries_in_the_same_order(self):
        """DASHBOARD_WIDGETS (server) and DASH_WIDGETS (client) must match key
        for key, in order — the existing guardrail pins equality, this pins that
        the new key is actually in both."""
        self.assertIn("setup", api.DASHBOARD_WIDGETS)
        m = re.search(r"DASH_WIDGETS = \[(.*?)\];", self.js, re.S)
        self.assertIsNotNone(m, "DASH_WIDGETS array not found")
        keys = re.findall(r"key:\s*'([a-z]+)'", m.group(1))
        self.assertEqual(keys, list(api.DASHBOARD_WIDGETS),
                         "the two widget registries drifted")

    def test_the_key_matches_the_registry_regex(self):
        """The lockstep test's regex is `key:\\s*'([a-z]+)'` — a digit or an
        underscore in the key makes the widget silently invisible to it."""
        self.assertRegex("setup", r"^[a-z]+$")

    def test_the_card_exists_in_the_dom(self):
        self.assertIn('data-widget="setup"', self.html,
                      "registered widget with no card — renders nowhere")
        self.assertIn('id="home-w-setup-body"', self.html)

    def test_the_renderer_exists_and_is_called(self):
        self.assertRegex(self.js, r"async function _renderSetupWidget\s*\(")
        self.assertIn("_renderSetupWidget();", self.js,
                      "the renderer is defined and never called")

    def test_it_is_on_by_default(self):
        """`opt: true` would put it in the catalog, off, waiting to be
        discovered — which is the finding, restated."""
        m = re.search(r"\{ key: 'setup',[^}]*\}", self.js)
        self.assertIsNotNone(m)
        self.assertNotIn("opt: true", m.group(0),
                         "a new operator would have to find it to see it")

    def test_it_hides_itself_once_onboarding_is_done(self):
        body = self.js[self.js.index("async function _renderSetupWidget"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("required_remaining", body)
        self.assertIn("d.complete", body)
        self.assertIn("hide()", body)

    def test_row_clicks_route_somewhere(self):
        self.assertIn('data-action="setupGoto"', self.js)
        self.assertRegex(self.js, r"\bfunction setupGoto\s*\(")

    def test_the_settings_tab_ids_it_targets_exist(self):
        """setupGoto clicks `settings-tab-btn-<tab>`; the tabs come from the
        server's step list, so a rename on either side is a dead click."""
        try:
            api.require_auth = lambda *a, **k: "admin"
            api.handle_setup_status()
            steps = []
        except api.HTTPError as e:
            steps = e.body["steps"]
        for st in steps:
            if st.get("tab"):
                with self.subTest(tab=st["tab"]):
                    self.assertIn(f'id="settings-tab-btn-{st["tab"]}"', self.html,
                                  "checklist step points at a tab that does "
                                  "not exist")

    def test_it_clicks_the_tab_rather_than_switching_it(self):
        """Each Settings tab carries a `data-action2` loader. Calling
        switchSettingsTab directly would swap the pane and never load it — and
        `showSettingsTab`, the obvious name, does not exist at all."""
        body = self.js[self.js.index("function setupGoto"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("settings-tab-btn-", body)
        self.assertIn(".click()", body)

    def test_dismissal_is_remembered(self):
        self.assertRegex(self.js, r"\bfunction dismissSetupCard\s*\(")
        self.assertIn("setup_card_dismissed", self.js)

    def test_no_inline_handlers_or_styles(self):
        body = self.js[self.js.index("async function _renderSetupWidget"):]
        body = body[:body.index("function dismissSetupCard")]
        self.assertNotRegex(body, r"\son\w+=")
        self.assertNotRegex(body, r'\sstyle="')


class TestEnrollmentConfirmation(unittest.TestCase):
    def setUp(self):
        self.js = (_JS / "app.js").read_text()
        self.html = (_HTML / "index.html").read_text()
        self.css = (_HTML / "static" / "css" / "styles.css").read_text()

    def test_there_is_a_status_region(self):
        self.assertIn('id="enroll-watch-status"', self.html,
                      "the modal still has nowhere to say anything")

    def test_the_status_region_is_announced(self):
        i = self.html.index('id="enroll-watch-status"')
        tag = self.html[max(0, i - 200):i + 200]
        self.assertIn('role="status"', tag)
        self.assertIn('aria-live="polite"', tag)

    def test_all_three_enroll_flows_start_the_watch(self):
        """Quick-install, Docker compose and the PIN were all equally silent —
        `startPinCountdown` only decremented the PIN's own TTL."""
        self.assertEqual(self.js.count("_startEnrollWatch("), 4,
                         "expected one definition plus three call sites")
        for fn in ("generateQuickInstall", "generateDockerEnroll",
                   "startPinCountdown"):
            with self.subTest(flow=fn):
                body = self.js[self.js.index("function " + fn):]
                body = body[:body.index("\n}\n") + 2] if "\n}\n" in body else body
                self.assertIn("_startEnrollWatch(", body,
                              f"{fn} is still silent about success")

    def test_the_poll_is_bounded(self):
        """An unbounded poll is its own bug; after a few minutes the honest
        answer is 'something is wrong', which it now says."""
        body = self.js[self.js.index("function _startEnrollWatch"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("_ENROLL_WATCH_LIMIT_MS", body)
        self.assertIn("_stopEnrollWatch()", body)

    def test_it_compares_seconds_to_seconds(self):
        """The device record's `enrolled` is epoch SECONDS. Passing
        Date.now() (milliseconds) would make the comparison never match and the
        watch would time out on every successful enrolment."""
        self.assertNotIn("_startEnrollWatch(Date.now())", self.js)
        self.assertIn("_startEnrollWatch(Math.round(Date.now() / 1000))",
                      self.js)

    def test_it_stops_when_the_modal_closes(self):
        body = self.js[self.js.index("function closeModal"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("_stopEnrollWatch()", body,
                      "the poll outlives the dialog nobody is looking at")

    def test_the_devices_endpoint_returns_the_field_it_watches(self):
        """The watcher filters on `enrolled`. If the roster stopped returning
        it, every enrolment would silently look like a timeout."""
        api.save(api.DEVICES_FILE,
                 {"d1": {"name": "web-01", "enrolled": 1700000000,
                         "last_seen": 1700000000}})
        api.require_auth = lambda *a, **k: "admin"
        api._caller_scope = lambda *a, **k: None
        try:
            api.handle_devices_list()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            body = e.body
        rows = body if isinstance(body, list) else (body or {}).get("devices", [])
        self.assertTrue(rows)
        self.assertIn("enrolled", rows[0],
                      "GET /devices no longer carries `enrolled` — the "
                      "enrollment watcher can never succeed")

    def test_the_status_class_is_styled(self):
        self.assertIn(".enroll-watch", self.css,
                      "an unstyled box renders as unformatted text")
        self.assertIn(".enroll-watch:empty", self.css,
                      "an empty status region must not draw a blank box before "
                      "a token is even minted")


if __name__ == "__main__":
    unittest.main()
