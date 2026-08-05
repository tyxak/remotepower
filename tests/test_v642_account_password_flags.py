"""v6.4.2 — `empty_password` / `stale_password` stop being a drawer badge.

The Linux agent has parsed /etc/shadow as root and tagged every local account
with `empty_password` (blank password field) and `stale_password` (login-capable,
unlocked, password older than a year) since v3.14.0. The server has sanitised and
persisted both flags into the hardware record for just as long. Of the four flags
in that list only `uid0` (→ `rogue_uid0`) and `sudo` (→ `priv_group_added`) were
ever consumed: the other two reached a per-device drawer badge and nothing else —
no alert, no check, no advisory finding, no RAG line.

That is worse than a missing feature, because `id.sshempty` — a CRITICAL advisory
finding — told the operator to go and answer the question by hand ("then audit for
accounts that actually have a blank password") while the answer sat in the same
store that finding was already reading.

Everything below is DRIVEN through the real path: the real heartbeat ingest, the
real checks engine, the real advisory builder, the real corpus builder. A grep
would prove the code exists, never that a blank-password account produces
anything — which is exactly the failure being fixed.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-acctpw642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)

import advisory      # noqa: E402
import checks        # noqa: E402
import rag_index     # noqa: E402


def _acct(user, uid, *flags, login=True, age=30, shell="/bin/bash"):
    return {"user": user, "uid": uid, "shell": shell, "home": f"/home/{user}",
            "login": login, "locked": False, "sudo": "sudo" in flags,
            "age_days": age, "flags": list(flags)}


class _IngestBase(unittest.TestCase):
    """Drives `_ingest_hardware`, capturing the events it emits."""

    def setUp(self):
        self.now = int(time.time())
        api.save(api.DEVICES_FILE,
                 {"h1": {"name": "web-01", "token": "t", "last_seen": self.now}})
        api.save(api.HARDWARE_FILE, {})
        self._real_fire = api.fire_webhook
        self.fired = []
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, dict(p or {})))

    def tearDown(self):
        api.fire_webhook = self._real_fire      # never leak the stub

    def ingest(self, accounts):
        self.fired.clear()
        api._ingest_hardware("h1", "web-01", {"accounts": accounts}, self.now)
        return [e for e, _p in self.fired]


class TestBlankPasswordFires(_IngestBase):
    def test_a_blank_password_account_fires_an_alert(self):
        events = self.ingest([_acct("root", 0, "sudo"),
                              _acct("svc", 1001, "empty_password")])
        self.assertIn("empty_password_account", events,
                      "a blank /etc/shadow password produced NO event — the "
                      "flag is a drawer badge again")

    def test_the_alert_names_the_account_and_says_what_to_do(self):
        self.ingest([_acct("svc", 1001, "empty_password")])
        payload = dict(self.fired[0][1])
        self.assertEqual(payload.get("user"), "svc")
        self.assertIn("passwd", payload.get("detail", ""),
                      "the alert must say how to fix it, not just that it is bad")

    def test_a_nologin_account_still_fires_but_says_so(self):
        """A passwordless nologin account is not remotely reachable via sshd,
        but `su - <user>` from any account still succeeds with no credential.
        It fires; the wording has to let the operator tell them apart."""
        self.ingest([_acct("svc", 1001, "empty_password",
                           login=False, shell="/usr/sbin/nologin")])
        self.assertEqual([e for e, _ in self.fired], ["empty_password_account"])
        self.assertIn("no login shell", self.fired[0][1].get("detail", ""))

    def test_it_is_edge_triggered_not_re_fired_every_heartbeat(self):
        """Same class as rogue_uid0 above it: a condition that is still true
        must not page again on the next heartbeat 60 seconds later."""
        first = self.ingest([_acct("svc", 1001, "empty_password")])
        self.assertIn("empty_password_account", first)
        again = self.ingest([_acct("svc", 1001, "empty_password")])
        self.assertNotIn("empty_password_account", again,
                         "re-fires on every heartbeat — the operator mutes it "
                         "within a day and the signal is lost")

    def test_a_second_account_appearing_does_fire(self):
        self.ingest([_acct("svc", 1001, "empty_password")])
        events = self.ingest([_acct("svc", 1001, "empty_password"),
                              _acct("test", 1002, "empty_password")])
        self.assertIn("empty_password_account", events)
        self.assertEqual(self.fired[0][1].get("user"), "test",
                         "the new account is the one worth naming")

    def test_it_clears_when_the_last_one_is_fixed(self):
        self.ingest([_acct("svc", 1001, "empty_password")])
        events = self.ingest([_acct("svc", 1001)])
        self.assertIn("empty_password_cleared", events,
                      "the alert would sit open forever")

    def test_it_does_not_clear_while_one_remains(self):
        """The recover event carries no per-user discriminator (device-id only),
        which is CORRECT only because it fires exclusively when none remain."""
        self.ingest([_acct("svc", 1001, "empty_password"),
                     _acct("test", 1002, "empty_password")])
        events = self.ingest([_acct("svc", 1001, "empty_password"),
                              _acct("test", 1002)])
        self.assertNotIn("empty_password_cleared", events,
                         "cleared while a blank-password account is still "
                         "there — the still-bad account goes silent")

    def test_stale_password_alone_does_not_page(self):
        """A year-old password is a hygiene finding, not a page. On a fleet of
        200 Linux hosts nearly every host has one; an alert per host would be
        muted within the week and take the blank-password alert with it. It is
        surfaced through the advisory and the Checks row instead."""
        events = self.ingest([_acct("bob", 1002, "stale_password", age=900)])
        self.assertEqual(events, [],
                         "stale passwords must not generate inbox noise")


class TestRegistryWiring(unittest.TestCase):
    def test_both_events_are_registered(self):
        for ev in ("empty_password_account", "empty_password_cleared"):
            self.assertIn(ev, api.EVENT_REGISTRY)
            self.assertEqual(api.EVENT_KIND_MAP.get(ev), "accounts",
                             "must ride the privileged-account channel, so an "
                             "operator routing account changes to a security "
                             "destination gets this on the same wire")

    def test_the_recover_resolves_the_firing_event(self):
        self.assertEqual(api._ALERT_RECOVER.get("empty_password_cleared"),
                         "empty_password_account")

    def test_the_firing_event_reaches_the_inbox(self):
        self.assertIn("severity", api.EVENT_REGISTRY["empty_password_account"],
                      "no severity key means it never reaches the Alerts inbox")

    def test_the_match_key_is_stored_on_the_alert(self):
        """`user` must survive `_record_alert`'s payload whitelist or the alert
        renders without naming the account."""
        api.save(api.ALERTS_FILE, {"alerts": [], "alert_seq": 0})
        api._record_alert("empty_password_account", {
            "device_id": "h1", "device_name": "web-01", "user": "svc",
            "detail": "…"})
        rows = (api.load(api.ALERTS_FILE) or {}).get("alerts") or []
        self.assertTrue(rows, "no alert row recorded")
        self.assertEqual((rows[-1].get("payload") or {}).get("user"), "svc",
                         "`user` was dropped by the _record_alert whitelist")

    def test_the_message_builder_has_a_branch(self):
        """Without one the notification reads 'empty_password_account: unknown'."""
        import notify
        msg = notify._webhook_message("empty_password_account", {
            "device_id": "h1", "name": "web-01",
            "detail": "'svc' has a blank password field in /etc/shadow"})
        self.assertIn("svc", msg)
        self.assertNotIn("unknown", msg.lower())

    def test_it_is_not_suppressible_by_a_maintenance_window(self):
        """Rebooting a box does not make a passwordless account acceptable —
        same call as rogue_uid0, which is also absent from the tuple."""
        self.assertNotIn("empty_password_account", api.SUPPRESSIBLE_EVENTS)


class TestChecksRow(unittest.TestCase):
    """The Checks page + fleet health, which is derived from it."""

    def _row(self, accounts):
        rows = checks._host_checks(
            "h1", {"name": "web-01", "last_seen": int(time.time())},
            hw_rec={"accounts": accounts}, now=int(time.time()))
        return next((r for r in rows if r["key"] == "account_passwords"), None)

    def test_blank_password_is_critical(self):
        r = self._row([_acct("svc", 1001, "empty_password")])
        self.assertIsNotNone(r, "no Local-account-passwords check row at all")
        self.assertEqual(r["status"], "critical")
        self.assertIn("svc", r["output"], "the row must name the account")

    def test_stale_password_is_a_warning_not_a_critical(self):
        r = self._row([_acct("bob", 1002, "stale_password", age=900)])
        self.assertEqual(r["status"], "warning")

    def test_a_clean_host_is_ok(self):
        r = self._row([_acct("root", 0, "sudo"), _acct("bob", 1002)])
        self.assertEqual(r["status"], "ok")

    def test_no_row_when_the_agent_reported_no_accounts(self):
        """An unprivileged agent cannot read /etc/shadow and a Windows/macOS
        agent reports no `accounts` at all. A green 'ok' row there would be a
        claim the product cannot back — show nothing instead."""
        self.assertIsNone(self._row([]))
        rows = checks._host_checks("h1", {"name": "w", "last_seen": 1},
                                   hw_rec={}, now=int(time.time()))
        self.assertNotIn("account_passwords", [r["key"] for r in rows])


class TestAdvisoryFindings(unittest.TestCase):
    """The fleet view: advisory findings group identical rows across hosts, so
    'which of my 200 hosts has a passwordless account' becomes one row."""

    def _build(self, accounts, ssh=None, dev_id="h1"):
        api.save(api.HARDWARE_FILE, {dev_id: {"accounts": accounts}})
        devs = {dev_id: {"name": "web-01",
                         "sysinfo": {"ssh_config": ssh} if ssh else {}}}
        return advisory.build(
            devs, accounts_by_dev=api._advisory_risky_accounts({dev_id}),
            now=int(time.time()))

    def _ids(self, out):
        return {f["id"] for f in out["findings"]}

    def test_blank_password_produces_a_finding(self):
        out = self._build([_acct("svc", 1001, "empty_password")])
        self.assertIn("id.emptypw", self._ids(out))

    def test_a_login_capable_blank_password_is_critical(self):
        out = self._build([_acct("svc", 1001, "empty_password", login=True)])
        f = next(f for f in out["findings"] if f["id"] == "id.emptypw")
        self.assertEqual(f["severity"], "critical")

    def test_a_nologin_blank_password_is_high_not_critical(self):
        out = self._build([_acct("svc", 1001, "empty_password", login=False,
                                 shell="/usr/sbin/nologin")])
        f = next(f for f in out["findings"] if f["id"] == "id.emptypw")
        self.assertEqual(f["severity"], "high",
                         "not remotely reachable via sshd — ranking it equal "
                         "to a login-capable one would bury the real ones")

    def test_stale_password_produces_a_low_finding(self):
        out = self._build([_acct("bob", 1002, "stale_password", age=900)])
        f = next((f for f in out["findings"] if f["id"] == "id.stalepw"), None)
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "low")

    def test_a_clean_host_produces_neither(self):
        out = self._build([_acct("root", 0, "sudo"), _acct("bob", 1002)])
        self.assertNotIn("id.emptypw", self._ids(out))
        self.assertNotIn("id.stalepw", self._ids(out))

    def test_sshempty_now_answers_its_own_question(self):
        """The finding used to end with 'then audit for accounts that actually
        have a blank password'. It now says how many there are."""
        out = self._build([_acct("svc", 1001, "empty_password")],
                          ssh={"permit_empty_passwords": "yes"})
        f = next(f for f in out["findings"] if f["id"] == "id.sshempty")
        self.assertNotIn("audit for accounts", f["fix"],
                         "still telling the operator to go and do by hand what "
                         "the store can answer")
        self.assertIn("1 account", f["fix"])

    def test_sshempty_says_so_when_nothing_is_exposed_today(self):
        out = self._build([_acct("bob", 1002)],
                          ssh={"permit_empty_passwords": "yes"})
        f = next(f for f in out["findings"] if f["id"] == "id.sshempty")
        self.assertIn("No account on this host currently has a blank", f["fix"])
        self.assertEqual(f["severity"], "critical",
                         "the setting is still critical on its own merits")

    def test_findings_carry_the_account_as_evidence(self):
        out = self._build([_acct("svc", 1001, "empty_password")])
        f = next(f for f in out["findings"] if f["id"] == "id.emptypw")
        self.assertTrue(any("svc" in e for e in f["evidence"]),
                        "a finding the operator cannot act on without opening "
                        "the drawer anyway is the same dead end")


class TestRagCorpus(unittest.TestCase):
    def test_the_advisor_is_told_about_blank_passwords(self):
        """`rag_index.py:2221` read only `_priv_users` — so an operator asking
        the AI advisor 'does anything on my fleet have a passwordless account?'
        got a confident answer from a model that had never been told."""
        store = {"h1": {"accounts": [_acct("svc", 1001, "empty_password"),
                                     _acct("bob", 1002, "stale_password",
                                           age=900)],
                        "collected_at": int(time.time())}}
        docs = rag_index.build_hardware_corpus(
            store, {"h1": {"name": "web-01"}}, now=int(time.time()))
        text = "\n".join(d["text"] for d in docs)
        self.assertIn("BLANK password", text)
        self.assertIn("svc", text)
        self.assertIn("over a year old", text)


class TestFrontendRegistries(unittest.TestCase):
    """Two registries the server cannot enforce; missing either makes the event
    vanish from the dashboard feed or render unclickable."""

    def setUp(self):
        self.js = (ROOT / "server" / "html" / "static" / "js"
                   / "app.js").read_text()

    def test_in_fleet_events(self):
        for ev in ("empty_password_account", "empty_password_cleared"):
            self.assertIn(f"'{ev}'", self.js,
                          "missing from FLEET_EVENTS — silently absent from "
                          "the dashboard activity feed")

    def test_has_a_home_activity_route(self):
        self.assertIn("case 'empty_password_account':", self.js,
                      "no _homeActivityAttrs case — the feed item is a dead "
                      "click")


if __name__ == "__main__":
    unittest.main()
