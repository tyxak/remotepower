#!/usr/bin/env python3
"""8.0.0: the e-mail guide tests what a person typed before it saves anything.

POST /api/smtp/test takes an optional `settings` object. The server lays it over a COPY of the saved settings (smtp_notifier.merge_test_settings),
sends the test message through the result and stores nothing, so a wrong password or port never replaces settings that work. This file holds
the merge function on its own, and the handler against a fake mail server that records what it was sent (tests/smtp_fake.py): the user name
and password it saw, whether the connection was encrypted, the addresses and the message.
"""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import api  # noqa: E402  (one shared import of api.py, with RP_DATA_DIR pinned before it)
from smtp_fake import FakeMail  # noqa: E402

import smtp_notifier as S  # noqa: E402

SAVED = {"smtp_host": "saved.example.com", "smtp_port": 587, "smtp_tls": "starttls", "smtp_verify_tls": True, "smtp_from": "saved@example.com",
         "smtp_username": "saved-user", "smtp_password": "saved-pw", "smtp_helo_name": "saved-helo", "smtp_recipients": "ops@example.com"}


class TestTheMerge(unittest.TestCase):

    def test_each_of_the_eight_settings_replaces_the_saved_one_and_nothing_else_changes(self):
        typed = {"smtp_host": "typed.example.com", "smtp_port": 2525, "smtp_tls": "tls", "smtp_verify_tls": False, "smtp_from": "typed@example.com",
                 "smtp_username": "typed-user", "smtp_password": "typed-pw", "smtp_helo_name": "typed-helo"}
        for key, value in typed.items():
            with self.subTest(key):
                out, bad = S.merge_test_settings(SAVED, {key: value})
                self.assertIsNone(bad)
                self.assertEqual(out[key], value)
                self.assertEqual({k: v for k, v in out.items() if k != key}, {k: v for k, v in SAVED.items() if k != key})
        out, bad = S.merge_test_settings(SAVED, typed)
        self.assertIsNone(bad)
        self.assertEqual({k: out[k] for k in typed}, typed)
        self.assertEqual(out["smtp_recipients"], SAVED["smtp_recipients"], "the recipients are not a setting of a test")

    def test_the_saved_settings_are_not_touched(self):
        before = json.dumps(SAVED, sort_keys=True)
        S.merge_test_settings(SAVED, {"smtp_host": "x", "smtp_password": "y"})
        self.assertEqual(json.dumps(SAVED, sort_keys=True), before)

    def test_a_password_that_is_empty_or_missing_keeps_the_saved_one(self):
        for settings in ({}, {"smtp_password": ""}, {"smtp_password": None}):
            with self.subTest(settings):
                self.assertEqual(S.merge_test_settings(SAVED, settings)[0]["smtp_password"], "saved-pw")

    def test_other_keys_are_ignored(self):
        out, bad = S.merge_test_settings(SAVED, {"smtp_recipients": "evil@example.com", "smtp_enabled": True, "webhook_url": "http://x", "email_events": {"a": 1}})
        self.assertIsNone(bad)
        self.assertEqual(out, SAVED)

    def test_text_is_trimmed_and_capped(self):
        out, _ = S.merge_test_settings({}, {"smtp_host": "  h.example.com  ", "smtp_username": "u" * 400, "smtp_helo_name": "h" * 400, "smtp_from": "f@" + "x" * 400,
                                            "smtp_password": "p" * 2000})
        self.assertEqual(out["smtp_host"], "h.example.com")
        self.assertEqual(len(out["smtp_username"]), 255)
        self.assertEqual(len(out["smtp_helo_name"]), 255)
        self.assertEqual(len(out["smtp_from"]), 255)
        self.assertEqual(len(out["smtp_password"]), 1024)

    def test_a_port_may_be_written_as_text(self):
        self.assertEqual(S.merge_test_settings({}, {"smtp_port": "2525"})[0]["smtp_port"], 2525)

    def test_a_value_the_save_would_refuse_is_refused_with_the_same_words(self):
        cases = [
            ({"smtp_port": 0}, "smtp_port must be 1–65535"),
            ({"smtp_port": 65536}, "smtp_port must be 1–65535"),
            ({"smtp_port": "abc"}, "smtp_port must be an integer"),
            ({"smtp_port": None}, "smtp_port must be an integer"),
            ({"smtp_port": True}, "smtp_port must be an integer"),
            ({"smtp_port": 10 ** 400}, "smtp_port must be 1–65535"),
            ({"smtp_tls": "ssl"}, "smtp_tls must be starttls, tls, or plain"),
            ({"smtp_tls": None}, "smtp_tls must be starttls, tls, or plain"),
            ({"smtp_verify_tls": "false"}, "smtp_verify_tls must be true or false"),
            ({"smtp_verify_tls": 0}, "smtp_verify_tls must be true or false"),
            ({"smtp_from": "nobody"}, "smtp_from must be a valid email address"),
            ({"smtp_password": 123}, "smtp_password must be text"),
            ({"smtp_password": ["x"]}, "smtp_password must be text"),
        ]
        for settings, message in cases:
            with self.subTest(settings):
                out, bad = S.merge_test_settings(SAVED, settings)
                self.assertEqual(bad, message)
                self.assertEqual(out, SAVED, "a refused object changes nothing")

    def test_what_is_not_an_object_is_refused(self):
        for settings in ([], "host", 5, [{"smtp_host": "x"}]):
            with self.subTest(settings):
                self.assertEqual(S.merge_test_settings(SAVED, settings)[1], "settings must be an object")

    def test_an_empty_from_address_is_left_for_the_sender_to_refuse(self):
        out, bad = S.merge_test_settings(SAVED, {"smtp_from": ""})
        self.assertIsNone(bad)
        with self.assertRaises(S.SmtpError) as c:
            S.send_email(out, ["a@b.com"], "s", "b", force=True)
        self.assertIn("smtp_from", str(c.exception))


def _call(handler, body, user="alice", env=None, verb="POST"):
    """The handler as one signed-in user, with the real auth and platform checks and the answer captured."""
    names = ("get_token_from_request", "method", "get_json_body", "get_json_obj", "audit_log", "respond", "verify_token")
    saved = {n: getattr(api, n) for n in names}
    saved_env = {k: os.environ.get(k) for k in ("CONTENT_LENGTH", *(env or {}))}
    box = {}
    role = (api.load(api.USERS_FILE) or {}).get(user, {}).get("role", "admin")
    api.verify_token = lambda t: (user, role)
    api.get_token_from_request = lambda: "t"
    api.method = lambda: verb
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: box.setdefault("audit", []).append(a)
    os.environ["CONTENT_LENGTH"] = str(len(json.dumps(body)))
    os.environ.update(env or {})

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            handler()
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    api._LOAD_CACHE.clear()
    return box


class _Handler(unittest.TestCase):

    def setUp(self):
        self.mails = []
        api.save(api.USERS_FILE, {"alice": {"role": "admin", "password_hash": "x", "created": 1}})
        api.save(api.CONFIG_FILE, dict(SAVED))
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for m in self.mails:
            m.stop()

    def mail(self, **kw):
        m = FakeMail(**kw)
        self.mails.append(m)
        return m

    def saved(self):
        api._LOAD_CACHE.clear()
        return api.load(api.CONFIG_FILE)

    def press(self, body, **kw):
        return _call(api.handle_smtp_test, body, **kw)


class TestTheTestWithSettingsThatAreNotSaved(_Handler):

    def test_the_message_goes_through_the_typed_server_with_the_typed_login_and_nothing_is_saved(self):
        mail = self.mail(tls="starttls", user="typed-user", password="typed-pw")
        before = json.dumps(self.saved(), sort_keys=True)
        box = self.press({"recipient": "me@example.com", "settings": {
            "smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "starttls", "smtp_verify_tls": False,
            "smtp_from": "typed@example.com", "smtp_username": "typed-user", "smtp_password": "typed-pw", "smtp_helo_name": "guide.test"}})
        self.assertEqual(box["status"], 200, box)
        self.assertTrue(box["body"]["ok"], box)
        self.assertEqual(box["body"]["recipients"], ["me@example.com"])
        s = mail.sessions[-1]
        self.assertTrue(s["tls"], "STARTTLS was used")
        self.assertEqual(s["auth"], ("typed-user", "typed-pw"))
        self.assertEqual((s["from"], s["to"]), ("typed@example.com", ["me@example.com"]))
        self.assertEqual(s["helo"], "guide.test")
        self.assertIn("Test email from RemotePower", s["data"])
        self.assertIn("Triggered by: alice", s["text"])
        self.assertEqual(json.dumps(self.saved(), sort_keys=True), before, "the saved settings are exactly as they were")

    def test_a_blank_password_keeps_the_saved_one_for_the_test(self):
        mail = self.mail(tls="none", user="saved-user", password="saved-pw")
        box = self.press({"recipient": "me@example.com", "settings": {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain",
                                                                    "smtp_password": ""}})
        self.assertTrue(box["body"]["ok"], box)
        self.assertEqual(mail.sessions[-1]["auth"], ("saved-user", "saved-pw"))

    def test_a_typed_password_wins_for_the_test_and_is_not_stored(self):
        mail = self.mail(tls="none", user="saved-user", password="other-pw")
        box = self.press({"recipient": "me@example.com", "settings": {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain",
                                                                    "smtp_password": "other-pw"}})
        self.assertTrue(box["body"]["ok"], box)
        self.assertEqual(self.saved()["smtp_password"], "saved-pw")

    def test_the_saved_recipients_are_used_when_no_recipient_is_given(self):
        mail = self.mail(tls="none")
        box = self.press({"settings": {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain", "smtp_username": ""}})
        self.assertTrue(box["body"]["ok"], box)
        self.assertEqual(mail.sessions[-1]["to"], ["ops@example.com"])

    def test_without_settings_the_saved_ones_are_used_as_before(self):
        mail = self.mail(tls="none", user="saved-user", password="saved-pw")
        api.save(api.CONFIG_FILE, dict(SAVED, smtp_host="127.0.0.1", smtp_port=mail.port, smtp_tls="plain"))
        api._LOAD_CACHE.clear()
        box = self.press({"recipient": "me@example.com"})
        self.assertTrue(box["body"]["ok"], box)
        self.assertEqual(mail.sessions[-1]["auth"], ("saved-user", "saved-pw"))
        self.assertNotIn("through", json.dumps(box.get("audit")), "the trail names the server only when it is not the saved one")

    def test_a_refused_login_is_answered_in_the_servers_own_words_and_nothing_is_saved(self):
        mail = self.mail(tls="none", user="u", password="right")
        box = self.press({"recipient": "me@example.com", "settings": {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain",
                                                                    "smtp_username": "u", "smtp_password": "wrong"}})
        self.assertEqual(box["status"], 200)
        self.assertFalse(box["body"]["ok"])
        self.assertIn("auth failed: 535", box["body"]["error"])
        self.assertEqual(self.saved(), dict(SAVED), "a failed test stores nothing either")

    def test_a_value_that_is_refused_answers_400_and_sends_nothing(self):
        mail = self.mail(tls="none")
        for settings, message in (({"smtp_port": 0}, "smtp_port must be 1–65535"), ({"smtp_tls": "ssl"}, "smtp_tls must be starttls, tls, or plain"),
                                  ({"smtp_from": "nobody"}, "smtp_from must be a valid email address"), ("host", "settings must be an object")):
            with self.subTest(settings):
                box = self.press({"recipient": "me@example.com", "settings": settings})
                self.assertEqual(box["status"], 400, box)
                self.assertEqual(box["body"]["error"], message)
        self.assertEqual(mail.sessions, [], "no connection was made")

    def test_implicit_tls_and_a_certificate_that_is_not_trusted(self):
        mail = self.mail(tls="implicit")
        base = {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "tls", "smtp_username": ""}
        refused = self.press({"recipient": "me@example.com", "settings": dict(base, smtp_verify_tls=True)})
        self.assertFalse(refused["body"]["ok"], "a self-signed certificate is refused while it is checked")
        self.assertIn("certificate", refused["body"]["error"].lower())
        allowed = self.press({"recipient": "me@example.com", "settings": dict(base, smtp_verify_tls=False)})
        self.assertTrue(allowed["body"]["ok"], allowed)
        self.assertTrue(mail.sessions[-1]["tls"])

    def test_the_trail_names_the_server_and_never_the_password(self):
        mail = self.mail(tls="none", user="u", password="hunter2-very-secret")
        box = self.press({"recipient": "me@example.com", "settings": {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain",
                                                                    "smtp_username": "u", "smtp_password": "hunter2-very-secret"}})
        self.assertTrue(box["body"]["ok"], box)
        line = json.dumps(box["audit"])
        self.assertIn("smtp_test", line)
        self.assertIn("127.0.0.1:%d, settings not saved" % mail.port, line)
        self.assertNotIn("hunter2-very-secret", line)
        self.assertNotIn("hunter2-very-secret", json.dumps(box["body"]))
        bad = self.press({"recipient": "me@example.com", "settings": {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain",
                                                                    "smtp_username": "u", "smtp_password": "nope-not-this"}})
        self.assertIn("smtp_test_failed", json.dumps(bad["audit"]))
        self.assertNotIn("nope-not-this", json.dumps(bad["audit"]))

    def test_the_sandbox_switch_does_not_hold_a_test_back(self):
        mail = self.mail(tls="none")
        api.save(api.CONFIG_FILE, dict(SAVED, notifications_test_mode=True))
        api._LOAD_CACHE.clear()
        box = self.press({"recipient": "me@example.com", "settings": {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain", "smtp_username": ""}})
        self.assertTrue(box["body"]["ok"], box)
        self.assertEqual(len(mail.sessions[-1]["to"]), 1, "the message reached the server")

    def test_the_password_variable_wins_over_a_typed_password_as_it_does_for_every_mail(self):
        mail = self.mail(tls="none", user="u", password="from-the-environment")
        box = self.press({"recipient": "me@example.com", "settings": {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain",
                                                                    "smtp_username": "u", "smtp_password": "typed"}},
                         env={"RP_SMTP_PASSWORD": "from-the-environment"})
        self.assertTrue(box["body"]["ok"], box)
        self.assertEqual(mail.sessions[-1]["auth"], ("u", "from-the-environment"))


class TestWhoMayTestWithOtherSettings(_Handler):
    """The new object does not loosen who may press the button: it still sends from the platform's own mail identity."""

    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, dict(SAVED, tenancy_enforced=True))
        api.save(api.TENANTS_FILE, {"tenantA": {"name": "A", "status": "active", "created": 1}})
        api.save(api.USERS_FILE, {"alice": {"role": "admin", "password_hash": "x", "created": 1},
                                  "tadmin": {"role": "admin", "tenant_id": "tenantA", "password_hash": "x", "created": 1},
                                  "viewer": {"role": "viewer", "password_hash": "x", "created": 1}})
        api._LOAD_CACHE.clear()

    def test_a_tenant_administrator_and_a_viewer_are_refused_and_no_connection_is_made(self):
        mail = self.mail(tls="none")
        body = {"recipient": "me@example.com", "settings": {"smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain", "smtp_username": ""}}
        for user in ("tadmin", "viewer"):
            with self.subTest(user):
                self.assertEqual(self.press(body, user=user)["status"], 403)
        self.assertEqual(mail.sessions, [])
        self.assertTrue(self.press(body, user="alice")["body"]["ok"], "the platform operator can")


class TestTheConnectionIsClosed(unittest.TestCase):
    """send_email leaves no connection behind, however it ends: a guide that tests again after each correction would pile them up."""

    def run_with_spy(self, mail_kw, cfg):
        import smtplib
        made = []

        class Spy(smtplib.SMTP):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                made.append(self)
        real = smtplib.SMTP
        smtplib.SMTP = Spy
        m = FakeMail(**mail_kw)
        try:
            try:
                S.send_email(dict(cfg, smtp_host="127.0.0.1", smtp_port=m.port, smtp_tls="plain", smtp_from="a@example.com"), ["b@example.com"], "s", "b", force=True)
                outcome = "sent"
            except S.SmtpError:
                outcome = "refused"
        finally:
            smtplib.SMTP = real
            m.stop()
        return outcome, made

    def test_every_way_out_closes_it(self):
        cases = [("sent", {}, {}), ("refused", {"user": "u", "password": "p"}, {"smtp_username": "u", "smtp_password": "wrong"}),
                 ("refused", {"refuse_sender": True}, {}), ("refused", {"refuse_rcpt": True}, {})]
        for want, mail_kw, cfg in cases:
            with self.subTest(mail_kw=mail_kw, cfg=cfg):
                outcome, made = self.run_with_spy(mail_kw, cfg)
                self.assertEqual(outcome, want)
                self.assertEqual(len(made), 1)
                self.assertIsNone(made[0].sock, "the connection is closed")


class TestTheSeriousEvents(_Handler):
    """The list the guide turns on for "only the serious events", derived here from the registry and not from the helper under test."""

    def meta(self):
        box = _call(api.handle_config_get, {}, verb="GET")
        self.assertEqual(box["status"], 200, box)
        return box["body"]["_meta"]["serious_events"]

    def test_it_is_what_the_alerts_page_rates_critical_or_high_and_the_recoveries_that_close_them(self):
        reg = api.EVENT_REGISTRY
        webhook = {w[0] for w in api.WEBHOOK_EVENTS}
        firing = {ev for ev, d in reg.items() if d.get("severity") in ("critical", "high")}
        closing = {ev for ev, d in reg.items() if set(d.get("resolves") or ()) & firing}
        want = sorted((firing | closing) & webhook)
        self.assertGreater(len(firing), 50, "the population is not empty")
        self.assertGreater(len(closing), 20)
        got = self.meta()
        self.assertEqual(got, want)
        for ev in ("device_offline", "device_online", "service_down", "monitor_down", "smart_failure", "backup_verify_failed"):
            self.assertIn(ev, got)
        for ev in ("new_port_detected", "patch_alert", "usb_device_added", "command_executed"):
            self.assertNotIn(ev, got)

    def test_every_name_in_it_is_one_the_save_accepts(self):
        got = self.meta()
        saved = _call(api.handle_config_save, {"email_events": {ev: True for ev in got}})
        self.assertEqual(saved["status"], 200, saved)
        api._LOAD_CACHE.clear()
        self.assertEqual(sorted(ev for ev, v in api.load(api.CONFIG_FILE)["email_events"].items() if v), got, "no name was dropped by the save")


class TestTheFakeServerItself(unittest.TestCase):
    """The tests above trust smtp_fake.py, so it has to refuse what a real server refuses."""

    def send(self, cfg):
        S.send_email(dict(cfg, smtp_host="127.0.0.1", smtp_from="a@example.com"), ["b@example.com"], "subject", "body text", force=True)

    def test_it_refuses_a_message_before_a_login_and_a_wrong_login(self):
        m = FakeMail(tls="none", user="u", password="p")
        try:
            with self.assertRaises(S.SmtpError) as c:
                self.send({"smtp_port": m.port, "smtp_tls": "plain"})
            self.assertIn("530", str(c.exception).replace("(", " "))
            with self.assertRaises(S.SmtpError):
                self.send({"smtp_port": m.port, "smtp_tls": "plain", "smtp_username": "u", "smtp_password": "x"})
            self.send({"smtp_port": m.port, "smtp_tls": "plain", "smtp_username": "u", "smtp_password": "p"})
            self.assertEqual(m.sessions[-1]["to"], ["b@example.com"])
            self.assertIn("body text", m.sessions[-1]["text"])
        finally:
            m.stop()

    def test_it_offers_login_only_after_the_encryption_when_it_is_set_to(self):
        m = FakeMail(tls="starttls", user="u", password="p")
        try:
            self.send({"smtp_port": m.port, "smtp_tls": "starttls", "smtp_verify_tls": False, "smtp_username": "u", "smtp_password": "p"})
            self.assertTrue(m.sessions[-1]["tls"])
            with self.assertRaises(S.SmtpError):
                self.send({"smtp_port": m.port, "smtp_tls": "plain", "smtp_username": "u", "smtp_password": "p"})
        finally:
            m.stop()

    def test_it_can_refuse_the_sender_and_the_recipient(self):
        for kw in ({"refuse_sender": True}, {"refuse_rcpt": True}):
            m = FakeMail(tls="none", **kw)
            try:
                with self.assertRaises(S.SmtpError):
                    self.send({"smtp_port": m.port, "smtp_tls": "plain"})
            finally:
                m.stop()


if __name__ == "__main__":
    unittest.main()
