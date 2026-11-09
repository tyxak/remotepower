#!/usr/bin/env python3
"""8.0.0: the email guide ("Set up email"), in a browser on the demo seed, against a fake mail server on the loopback.

Settings, Notifications has a form of about twenty boxes for email, and email is opt-in per event, so a person who fills the form and presses test
still gets no alerts. The guide asks in steps: which mail service (a card brings the server, the port, the encryption and a note on what to get
ready), the connection, who receives the alerts, a test that sends a real message through what was typed (the server tests settings that are not
saved), and which events are sent. Nothing is stored before the last step, and the last step saves what the form saves and puts it in the form.

The fake server (tests/smtp_fake.py) records what it was sent, so the tests read the user name and password it saw, whether the connection was
encrypted and the message itself, and the stored configuration is read from the file: a toast or a label proves nothing about either.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402
from smtp_fake import FakeMail  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}
KEYS = ("smtp_enabled", "smtp_host", "smtp_port", "smtp_tls", "smtp_verify_tls", "smtp_from", "smtp_username", "smtp_password", "smtp_helo_name",
        "smtp_recipients", "email_events", "webhook_events", "public_base_url")
PROVIDERS = ["gmail", "microsoft", "fastmail", "proton", "brevo", "mailgun", "sendgrid", "ses", "own", "local"]
BRANDS = {"Microsoft 365", "Fastmail", "Proton Mail Bridge", "Brevo", "Mailgun", "SendGrid", "Amazon SES"}
# (English text, language) pairs where the right translation is the same word
SAME = {("Port", "fr"), ("Port", "de"), ("Test", "fr"), ("Test", "de"), ("Server", "de"), ("Service", "fr"), ("Email", "de"), ("Documentation", "fr")}


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the wizard is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-smtp-wizard-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail("chromium not available: %s" % exc)
        return
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest("app stack not available: %s" % exc)
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir)


def tearDownModule():
    try:
        _STATE["browser"].close()
        _STATE["pw"].stop()
    finally:
        if _STATE.get("shutdown"):
            _STATE["shutdown"]()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheEmailGuide(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); "
                            "localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.original = cls.stored()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.restore(cls.original)
        finally:
            cls.ctx.close()

    @classmethod
    def api(cls, method, path, body=None):
        return cls.page.evaluate("async ([m, p, b]) => b === null ? await api(m, p) : await api(m, p, b)", [method, path, body])

    @classmethod
    def stored(cls):
        cfg = json.loads((Path(_STATE["data_dir"]) / "config.json").read_text())
        return {k: cfg.get(k) for k in KEYS}

    @classmethod
    def restore(cls, saved):
        body = {k: saved[k] for k in KEYS if saved.get(k) is not None}
        body["smtp_password"] = saved.get("smtp_password") or ""         # an empty one clears the saved password
        body["email_events"] = saved.get("email_events") or {}
        body["webhook_events"] = saved.get("webhook_events") or {}
        body["public_base_url"] = saved.get("public_base_url") or ""
        cls.api("POST", "/config", body)

    def blank(self):
        """No email set up: the starting point of every test, whatever the seed holds."""
        self.api("POST", "/config", {"smtp_enabled": False, "smtp_host": "", "smtp_port": 587, "smtp_tls": "starttls", "smtp_verify_tls": True,
                                     "smtp_from": "", "smtp_username": "", "smtp_password": "", "smtp_helo_name": "", "smtp_recipients": "", "email_events": {},
                                     "webhook_events": self.original["webhook_events"] or {}, "public_base_url": ""})
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")

    def setUp(self):
        self.mails = []
        self.blank()
        self.start = self.stored()

    def tearDown(self):
        for m in self.mails:
            m.stop()
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")

    def mail(self, **kw):
        m = FakeMail(**kw)
        self.mails.append(m)
        return m

    # ── steering ────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def close_guide(self):
        """Closes the dialog if one is open. A loop calls it FIRST, not last: a check that failed inside the round must not leave it open."""
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")

    def open(self, name="smtp"):
        self.page.evaluate("(n) => wizOpen(n)", name)
        self.page.wait_for_selector("#wizard-modal.active .wiz-choice", timeout=30000)

    def steps(self):
        return self.page.eval_on_selector_all("#wiz-steps .wiz-lbl", "els => els.map(e => e.textContent)")

    def pick(self, key):
        self.page.check('#wiz-body input[name="wiz-svc"][value="%s"]' % key)

    def next(self):
        self.page.click("#wiz-next")

    def message(self):
        return self.page.inner_text("#wiz-msg").strip()

    def fill(self, sel, value):
        self.page.fill(sel, value)

    def to_connection(self, key="own"):
        self.open()
        self.pick(key)
        self.next()
        self.page.wait_for_selector("#wiz-host")

    def connect(self, host="127.0.0.1", port=None, tls="plain", user="", password="", sender="guide@example.com", verify=None):
        self.page.select_option("#wiz-tls", tls)                  # the mode first: it moves the port while the port is a usual one
        self.fill("#wiz-host", host)
        if port is not None:
            self.fill("#wiz-port", str(port))
        self.fill("#wiz-user", user)
        self.fill("#wiz-pass", password)
        self.fill("#wiz-from", sender)
        if verify is not None:
            self.page.set_checked("#wiz-verify", verify)

    def to_test(self, mail=None, recipients="me@example.com, other@example.com", key="own", **conn):
        self.to_connection(key)
        if mail is not None:
            conn.setdefault("port", mail.port)
        self.connect(**conn)
        self.next()
        self.page.wait_for_selector("#wiz-rec")
        self.fill("#wiz-rec", recipients)
        self.next()
        self.page.wait_for_selector("#wiz-test")

    def run_test(self):
        self.page.click("#wiz-test")
        self.page.wait_for_selector("#wiz-result .wiz-state", timeout=30000)
        return self.page.inner_text("#wiz-result .wiz-state").strip()

    def result(self):
        return self.page.inner_text("#wiz-result")

    def finish(self):
        self.next()                                              # the Test step
        self.page.wait_for_selector("#wiz-body .wiz-list")
        self.next()                                              # Finish: Turn it on
        self.page.wait_for_selector("#wizard-modal", state="detached", timeout=20000)

    def to_the_end(self, mail, user="", password="", **kw):
        self.to_test(mail, user=user, password=password, **kw)
        self.assertEqual(self.run_test(), "Sent", self.result())

    # ── the entry points ────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_button_is_in_the_email_section_of_settings_and_opens_the_guide(self):
        self.page.evaluate("async () => { showPage('settings'); switchSettingsTab('notifs'); await loadSettings(); }")
        sel = '[data-action="wizOpen"][data-arg="smtp"]'
        self.page.wait_for_selector(sel, state="visible")
        self.assertEqual(self.page.inner_text(sel).strip(), "Guide me")
        near = self.page.evaluate("(s) => document.querySelector(s).closest('.settings-section').querySelector('.section-title').textContent", sel)
        self.assertEqual(near.strip(), "Email notifications (SMTP)")
        self.page.click(sel)
        self.page.wait_for_selector("#wizard-modal.active .wiz-choice", timeout=30000)
        self.assertEqual(self.page.inner_text("#wiz-title").strip(), "Set up email")

    def test_the_guide_lists_the_services_in_three_groups_and_none_is_chosen_when_email_is_not_set_up(self):
        self.open()
        self.assertEqual(self.steps(), ["Service", "Connection", "Recipients", "Test", "Finish"])
        shown = self.page.eval_on_selector_all('#wiz-body input[name="wiz-svc"]', "els => els.map(e => e.value)")
        self.assertEqual(shown, PROVIDERS)
        groups = self.page.eval_on_selector_all("#wiz-body .wiz-grp", "els => els.map(e => e.textContent)")
        self.assertEqual(groups, ["Mail accounts", "Sending services", "Your own server"])
        self.assertEqual(self.page.eval_on_selector_all('#wiz-body input[name="wiz-svc"]:checked', "els => els.length"), 0)
        self.assertFalse(self.page.is_visible("#wiz-body >> text=Email is already set up"))
        self.next()
        self.assertEqual(self.message(), "Choose a service")

    def test_the_notification_wizard_has_an_email_card_that_hands_over_to_the_guide(self):
        self.open("notify")
        groups = self.page.eval_on_selector_all("#wiz-body .wiz-grp", "els => els.map(e => e.textContent)")
        self.assertIn("Email", groups)
        card = self.page.locator('#wiz-body label.wiz-choice:has(input[value="email"])')
        self.assertEqual(card.locator(".wiz-choice-t").inner_text().strip(), "Email (SMTP)")
        self.assertEqual(card.locator(".wiz-choice-d").inner_text().strip(), "Opens the email guide.")
        self.page.check('#wiz-body input[name="wiz-fmt"][value="email"]')
        self.next()
        self.page.wait_for_selector('#wiz-body input[name="wiz-svc"]')
        self.assertEqual(self.page.inner_text("#wiz-title").strip(), "Set up email")
        self.assertEqual(self.steps(), ["Service", "Connection", "Recipients", "Test", "Finish"])
        self.assertEqual(self.page.eval_on_selector_all("#wizard-modal", "els => els.length"), 1, "one dialog, not two")
        self.assertEqual(self.stored(), self.start, "handing over saves nothing")
        # the other cards of the notification wizard still go on to their own Connection step
        self.page.evaluate("() => closeModal('wizard-modal')")
        self.open("notify")
        self.page.check('#wiz-body input[name="wiz-fmt"][value="slack"]')
        self.next()
        self.page.wait_for_selector("#wiz-url")
        self.assertEqual(self.steps(), ["Service", "Connection", "Test", "Finish"])

    # ── a service brings its settings ───────────────────────────────────────────────────────────────────────────────────────
    def read_connection(self):
        return {"host": self.page.input_value("#wiz-host"), "port": self.page.input_value("#wiz-port"), "tls": self.page.input_value("#wiz-tls"),
                "user": self.page.input_value("#wiz-user"), "verify": self.page.is_checked("#wiz-verify")}

    def test_each_service_brings_the_server_the_port_and_the_encryption_it_documents(self):
        want = {
            "gmail": ("smtp.gmail.com", "587", "starttls", "", True), "microsoft": ("smtp.office365.com", "587", "starttls", "", True),
            "fastmail": ("smtp.fastmail.com", "587", "starttls", "", True), "proton": ("127.0.0.1", "1025", "starttls", "", False),
            "brevo": ("smtp-relay.brevo.com", "587", "starttls", "", True), "mailgun": ("smtp.mailgun.org", "587", "starttls", "", True),
            "sendgrid": ("smtp.sendgrid.net", "587", "starttls", "apikey", True), "ses": ("email-smtp.us-east-1.amazonaws.com", "587", "starttls", "", True),
            "own": ("", "587", "starttls", "", True), "local": ("127.0.0.1", "25", "plain", "", True)}
        self.assertEqual(sorted(want), sorted(PROVIDERS))
        for key, (host, port, tls, user, verify) in want.items():
            with self.subTest(key):
                self.close_guide()
                self.to_connection(key)
                self.assertEqual(self.read_connection(), {"host": host, "port": port, "tls": tls, "user": user, "verify": verify})

    def test_every_service_has_a_note_on_what_to_get_ready(self):
        notes = set()
        for key in PROVIDERS:
            with self.subTest(key):
                self.close_guide()
                self.to_connection(key)
                note = self.page.inner_text("#wiz-body .hint").strip()
                self.assertGreater(len(note), 60, key)
                notes.add(note)
        self.assertEqual(len(notes), len(PROVIDERS), "each service says its own thing")

    def test_what_was_typed_stays_when_another_service_is_picked(self):
        self.to_connection("gmail")
        self.fill("#wiz-host", "relay.example.net")
        self.fill("#wiz-user", "me")
        self.page.click("#wiz-back")
        self.pick("sendgrid")
        self.next()
        self.assertEqual(self.page.input_value("#wiz-host"), "relay.example.net", "a server that was typed is kept")
        self.assertEqual(self.page.input_value("#wiz-user"), "me", "a user name that was typed is kept")
        self.assertEqual(self.page.input_value("#wiz-port"), "587", "a port that was not typed follows the service")
        self.page.click("#wiz-back")
        self.pick("local")
        self.next()
        self.assertEqual(self.page.input_value("#wiz-port"), "25")
        self.assertEqual(self.page.input_value("#wiz-tls"), "plain")

    def test_the_encryption_moves_the_port_while_it_is_a_usual_one_and_not_after_a_port_was_chosen(self):
        self.to_connection("own")
        self.page.select_option("#wiz-tls", "tls")
        self.assertEqual(self.page.input_value("#wiz-port"), "465")
        self.page.select_option("#wiz-tls", "plain")
        self.assertEqual(self.page.input_value("#wiz-port"), "25")
        self.fill("#wiz-port", "2525")
        self.page.select_option("#wiz-tls", "starttls")
        self.assertEqual(self.page.input_value("#wiz-port"), "2525", "an unusual port is the person's choice")

    def test_the_password_box_cannot_be_filled_with_this_sites_own_sign_in(self):
        self.to_connection("gmail")
        self.assertEqual(self.page.get_attribute("#wiz-pass", "type"), "password")
        self.assertEqual(self.page.get_attribute("#wiz-pass", "autocomplete"), "new-password")

    # ── the checks of the steps ─────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_connection_is_checked_in_the_words_the_page_already_uses(self):
        self.to_connection("gmail")
        self.next()
        self.assertEqual(self.message(), "This field is needed")
        self.assertEqual(self.page.evaluate("() => document.activeElement.id"), "wiz-user", "a login is needed for this service")
        self.fill("#wiz-user", "me@gmail.com")
        self.next()
        self.assertEqual(self.message(), "This field is needed")
        self.assertEqual(self.page.evaluate("() => document.activeElement.id"), "wiz-pass")
        self.fill("#wiz-pass", "app-password")
        self.next()
        self.assertEqual(self.message(), "Set the From address first")
        self.assertEqual(self.page.evaluate("() => document.activeElement.id"), "wiz-from")
        self.fill("#wiz-from", "nobody")
        self.next()
        self.assertEqual(self.message(), "That is not an address")
        self.fill("#wiz-from", "me@gmail.com")
        self.fill("#wiz-host", "")
        self.next()
        self.assertEqual(self.message(), "Set the server first")
        self.assertEqual(self.page.evaluate("() => document.activeElement.id"), "wiz-host")
        self.fill("#wiz-host", "smtp.gmail.com")
        for bad in ("", "0", "65536", "-1"):             # a number box takes no letters, so no letter is tried
            self.fill("#wiz-port", bad)
            self.next()
            self.assertIn(self.message(), ("Set a port from 1 to 65535",), bad)
        self.fill("#wiz-port", "587")
        self.next()
        self.page.wait_for_selector("#wiz-rec")

    def test_a_server_that_takes_mail_without_a_login_needs_neither_user_nor_password(self):
        self.to_connection("local")
        self.assertIn("Leave empty if the server needs no login.", self.page.inner_text("#wiz-body"))
        self.fill("#wiz-from", "guide@example.com")
        self.next()
        self.page.wait_for_selector("#wiz-rec")
        self.page.click("#wiz-back")
        self.fill("#wiz-user", "someone")
        self.next()
        self.assertEqual(self.message(), "This field is needed", "a user name brings the need for a password")

    def test_the_recipients_are_checked(self):
        self.to_connection("local")
        self.fill("#wiz-from", "guide@example.com")
        self.next()
        self.page.wait_for_selector("#wiz-rec")
        self.next()
        self.assertEqual(self.message(), "Add an address to send alerts to")
        self.fill("#wiz-rec", "ops@example.com, nope")
        self.next()
        self.assertEqual(self.message(), "That is not an address")
        self.fill("#wiz-rec", "ops@example.com;admin@example.com  third@example.com")
        self.next()
        self.page.wait_for_selector("#wiz-test")

    # ── the test sends a real message and saves nothing ─────────────────────────────────────────────────────────────────────
    def test_the_test_sends_through_what_was_typed_with_its_login_and_saves_nothing(self):
        mail = self.mail(tls="none", user="ops", password="s3cret-pw")
        self.to_test(mail, user="ops", password="s3cret-pw", sender="alerts@example.com")
        self.assertEqual(self.run_test(), "Sent", self.result())
        self.assertIn("me@example.com", self.page.inner_text("#wiz-result .wiz-chip"), "the message went to the first address")
        self.assertIn("inbox", self.result())
        s = mail.sessions[-1]
        self.assertEqual(s["auth"], ("ops", "s3cret-pw"))
        self.assertEqual((s["from"], s["to"]), ("alerts@example.com", ["me@example.com"]))
        self.assertIn("Test email from RemotePower", s["text"] + s["data"])
        self.assertEqual(self.stored(), self.start, "nothing was stored by a test")

    def test_starttls_works_when_the_certificate_check_is_off_and_names_the_certificate_when_it_is_on(self):
        mail = self.mail(tls="starttls", user="ops", password="pw")
        self.to_test(mail, tls="starttls", user="ops", password="pw", verify=True)
        self.assertEqual(self.run_test(), "Not sent")
        self.assertIn("certificate", self.result().lower())
        self.assertIn("turn off the certificate check", self.result())
        self.page.click("#wiz-back")
        self.page.click("#wiz-back")
        self.page.set_checked("#wiz-verify", False)
        self.next()
        self.page.wait_for_selector("#wiz-rec")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.assertEqual(self.page.inner_text("#wiz-result").strip(), "", "the old answer is gone with the change")
        self.assertEqual(self.run_test(), "Sent", self.result())
        self.assertTrue(mail.sessions[-1]["tls"], "the message went over STARTTLS")

    def test_a_refused_login_is_said_in_words_and_with_what_the_server_answered(self):
        mail = self.mail(tls="none", user="ops", password="right")
        self.to_test(mail, user="ops", password="wrong")
        self.assertEqual(self.run_test(), "Not sent")
        self.assertIn("refused the user name or password", self.result())
        self.assertIn("535", self.page.inner_text("#wiz-result .ff-mono"))
        self.assertEqual(self.stored(), self.start)

    def test_a_port_with_nothing_behind_it_and_a_name_that_does_not_exist_each_get_their_own_hint(self):
        self.to_test(None, port=free_port())
        self.assertEqual(self.run_test(), "Not sent")
        self.assertIn("Nothing answered on that port", self.result())
        self.page.click("#wiz-back")
        self.page.click("#wiz-back")
        self.fill("#wiz-host", "no-such-host.invalid")
        self.next()
        self.page.wait_for_selector("#wiz-rec")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.assertEqual(self.run_test(), "Not sent")
        self.assertIn("server name was not found", self.result())

    def test_a_sender_and_a_recipient_the_server_refuses_each_get_their_own_hint(self):
        for kw, words in (({"refuse_sender": True}, "did not accept the From address"), ({"refuse_rcpt": True}, "did not accept the recipient")):
            with self.subTest(kw):
                mail = self.mail(tls="none", **kw)
                self.close_guide()
                self.to_test(mail)
                self.assertEqual(self.run_test(), "Not sent")
                self.assertIn(words, self.result())

    def test_a_server_that_wants_a_login_is_told_to_have_one_when_there_is_none(self):
        mail = self.mail(tls="none", user="ops", password="pw")
        self.to_test(mail)
        self.assertEqual(self.run_test(), "Not sent")
        self.assertIn("refused the user name or password, or wants one", self.result())

    def test_a_change_after_the_test_drops_its_answer_and_the_finish_says_it_was_not_tested(self):
        # Each box that the test depends on drops the answer of the last test, so each is changed on its own: (what, steps back, the change).
        changes = [
            ("the recipients", 1, lambda: self.fill("#wiz-rec", "someone-else@example.com")),
            ("the server", 2, lambda: self.fill("#wiz-host", "localhost")),
            ("the TLS mode", 2, lambda: self.page.select_option("#wiz-tls", "tls")),
            ("the user name", 2, lambda: (self.fill("#wiz-user", "u2"), self.fill("#wiz-pass", "p2"))),     # a user name needs its password
            ("the password", 2, lambda: self.fill("#wiz-pass", "p2")),
            ("the From address", 2, lambda: self.fill("#wiz-from", "other@example.com")),
            ("the certificate box", 2, lambda: self.page.set_checked("#wiz-verify", False)),
        ]
        for what, back, change in changes:
            with self.subTest(what):
                self.close_guide()
                mail = self.mail(tls="none")
                self.to_test(mail)
                self.assertEqual(self.run_test(), "Sent")
                for _ in range(back):
                    self.page.click("#wiz-back")
                change()
                for _ in range(back):
                    self.next()
                    self.page.wait_for_selector("#wiz-rec" if back == 2 and _ == 0 else "#wiz-test")
                self.assertEqual(self.page.inner_text("#wiz-result").strip(), "", "the old answer is not shown after %s changed" % what)
                self.next()
                self.page.wait_for_selector("#wiz-body .wiz-list")
                self.assertIn("Not tested", self.page.inner_text("#wiz-body .wiz-list"), what)
                self.assertIn("It was not tested.", self.page.inner_text("#wiz-body"), what)

    # ── turning it on ───────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_turning_it_on_saves_what_the_form_saves_and_the_settings_form_shows_it(self):
        mail = self.mail(tls="none", user="ops", password="s3cret-pw")
        self.page.evaluate("async () => { showPage('settings'); switchSettingsTab('notifs'); await loadSettings(); }")
        self.assertEqual(self.page.input_value("#cfg-smtp-host"), "")
        self.to_the_end(mail, user="ops", password="s3cret-pw", sender="alerts@example.com")
        self.finish()
        saved = self.stored()
        self.assertTrue(saved["smtp_enabled"])
        self.assertEqual((saved["smtp_host"], saved["smtp_port"], saved["smtp_tls"], saved["smtp_verify_tls"]), ("127.0.0.1", mail.port, "plain", True))
        self.assertEqual((saved["smtp_from"], saved["smtp_username"]), ("alerts@example.com", "ops"))
        self.assertEqual(saved["smtp_recipients"], "me@example.com, other@example.com")
        # the form on the page shows it without a reload
        self.assertTrue(self.page.is_checked("#cfg-smtp-enabled"))
        self.assertEqual(self.page.input_value("#cfg-smtp-host"), "127.0.0.1")
        self.assertEqual(self.page.input_value("#cfg-smtp-port"), str(mail.port))
        self.assertEqual(self.page.input_value("#cfg-smtp-tls"), "plain")
        self.assertEqual(self.page.input_value("#cfg-smtp-from"), "alerts@example.com")
        self.assertEqual(self.page.input_value("#cfg-smtp-username"), "ops")
        self.assertEqual(self.page.input_value("#cfg-smtp-recipients"), "me@example.com, other@example.com")
        self.assertEqual(self.page.input_value("#cfg-smtp-password"), "", "the password box is never filled")
        # the saved password is the typed one: the Settings page's own test sends with it
        mail.sessions.clear()
        r = self.api("POST", "/smtp/test", {"recipient": "me@example.com"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(mail.sessions[-1]["auth"], ("ops", "s3cret-pw"))
        cfg = self.api("GET", "/config")
        self.assertTrue(cfg["smtp_password_set"])
        self.assertNotIn("s3cret-pw", json.dumps(cfg), "the password never comes back")

    def test_a_later_save_of_the_settings_form_keeps_what_the_guide_saved(self):
        mail = self.mail(tls="none")
        self.page.evaluate("async () => { showPage('settings'); switchSettingsTab('notifs'); await loadSettings(); }")
        self.fill("#cfg-public-base-url", "https://unsaved.example.com")             # an edit of something else, waiting in the form
        self.to_the_end(mail)
        self.finish()
        self.assertEqual(self.page.input_value("#cfg-public-base-url"), "https://unsaved.example.com", "an edit of another box is not thrown away")
        # the form saves every box, and some of them are controls that ask for a fresh sign-in: the confirmation is given first
        self.assertTrue(self.api("POST", "/auth/step-up", {"password": "demo"})["ok"])
        self.page.click("#btn-save-settings")
        # the form's own save went through: the edit that was waiting in it is stored (a save that never happened would prove nothing below)
        for _ in range(60):
            if json.loads((Path(_STATE["data_dir"]) / "config.json").read_text()).get("public_base_url") == "https://unsaved.example.com":
                break
            self.page.wait_for_timeout(250)
        self.assertEqual(json.loads((Path(_STATE["data_dir"]) / "config.json").read_text()).get("public_base_url"), "https://unsaved.example.com",
                         "the Settings form saved")
        saved = self.stored()
        self.assertEqual(saved["smtp_host"], "127.0.0.1", "the form did not write its old values over the guide's")
        self.assertTrue(saved["smtp_enabled"])
        self.assertEqual(saved["smtp_recipients"], "me@example.com, other@example.com")

    def serious(self):
        return set(self.api("GET", "/config")["_meta"]["serious_events"])

    def email_on(self):
        return {k for k, v in (self.stored()["email_events"] or {}).items() if v}

    def test_the_serious_events_choice_turns_on_the_critical_and_high_ones_and_their_recoveries(self):
        mail = self.mail(tls="none")
        self.to_the_end(mail)
        self.next()
        self.page.wait_for_selector("#wiz-body input[name='wiz-ev']")
        self.assertEqual(self.page.eval_on_selector("#wiz-body input[name='wiz-ev']:checked", "e => e.value"), "serious", "the default")
        self.next()
        self.page.wait_for_selector("#wizard-modal", state="detached", timeout=20000)
        on = self.email_on()
        self.assertEqual(on, self.serious())
        self.assertGreater(len(on), 50)
        for ev in ("device_offline", "device_online", "service_down", "monitor_down", "smart_failure"):
            self.assertIn(ev, on)
        for ev in ("new_port_detected", "patch_alert", "usb_device_added"):
            self.assertNotIn(ev, on, "a medium event is not a serious one")

    def test_the_every_event_choice_follows_the_webhooks_and_keeps_what_was_on(self):
        # two events the webhooks do not send: one is ticked for email already (kept), the other is not (not added)
        self.api("POST", "/config", {"webhook_events": {"new_port_detected": False, "usb_device_added": False},
                                     "email_events": {"new_port_detected": True, "patch_alert": True}})
        mail = self.mail(tls="none")
        self.to_the_end(mail)
        self.next()
        self.page.wait_for_selector("#wiz-body input[name='wiz-ev']")
        self.assertEqual(self.page.eval_on_selector("#wiz-body input[name='wiz-ev']:checked", "e => e.value"), "keep", "an event that is on already says keep")
        self.page.check("#wiz-body input[name='wiz-ev'][value='all']")
        self.next()
        self.page.wait_for_selector("#wizard-modal", state="detached", timeout=20000)
        cfg = self.api("GET", "/config")
        webhook = {k for k, v in cfg["webhook_events"].items() if v}
        self.assertGreater(len(webhook), 100)
        self.assertNotIn("usb_device_added", webhook)
        on = self.email_on()
        self.assertEqual(on, webhook | {"new_port_detected"}, "every event a webhook sends, and what was on before")
        self.assertNotIn("usb_device_added", on, "an event no webhook sends is not added")

    def test_the_keep_choice_leaves_the_event_table_as_it_was(self):
        self.api("POST", "/config", {"email_events": {"patch_alert": True, "device_offline": False}})
        before = self.stored()["email_events"]
        mail = self.mail(tls="none")
        self.to_the_end(mail)
        self.next()
        self.page.wait_for_selector("#wiz-body input[name='wiz-ev']")
        self.assertEqual(self.page.eval_on_selector("#wiz-body input[name='wiz-ev']:checked", "e => e.value"), "keep")
        self.next()
        self.page.wait_for_selector("#wizard-modal", state="detached", timeout=20000)
        self.assertEqual(self.stored()["email_events"], before)
        self.assertTrue(self.stored()["smtp_enabled"])

    def test_the_event_table_of_the_settings_page_shows_what_was_turned_on(self):
        mail = self.mail(tls="none")
        self.page.evaluate("async () => { showPage('settings'); switchSettingsTab('notifs'); await loadSettings(); }")
        self.assertEqual(self.page.eval_on_selector_all("#event-toggle-table .toggle-email:checked", "els => els.length"), 0)
        self.to_the_end(mail)
        self.finish()
        ticked = set(self.page.eval_on_selector_all("#event-toggle-table .toggle-email:checked", "els => els.map(e => e.dataset.event)"))
        self.assertEqual(ticked, self.email_on())
        self.assertIn("device_offline", ticked)

    # ── an earlier setup, and leaving early ─────────────────────────────────────────────────────────────────────────────────
    def saved_setup(self, mail):
        self.api("POST", "/config", {"smtp_enabled": True, "smtp_host": "127.0.0.1", "smtp_port": mail.port, "smtp_tls": "plain", "smtp_verify_tls": True,
                                     "smtp_from": "old@example.com", "smtp_username": "ops", "smtp_password": "saved-pw", "smtp_recipients": "old-rcpt@example.com"})

    def test_an_earlier_setup_is_read_in_and_a_second_run_keeps_its_password(self):
        mail = self.mail(tls="none", user="ops", password="saved-pw")
        self.saved_setup(mail)
        before = self.stored()
        self.open()
        self.assertIn("Email is already set up. This guide replaces those settings.", self.page.inner_text("#wiz-body"))
        self.assertEqual(self.page.eval_on_selector("#wiz-body input[name='wiz-svc']:checked", "e => e.value"), "own", "a server that is none of the services is another server")
        self.next()
        self.page.wait_for_selector("#wiz-host")
        self.assertEqual(self.read_connection()["host"], "127.0.0.1")
        self.assertEqual(self.page.input_value("#wiz-port"), str(mail.port))
        self.assertEqual(self.page.input_value("#wiz-user"), "ops")
        self.assertEqual(self.page.input_value("#wiz-from"), "old@example.com")
        self.assertIn("Leave empty to keep the saved password.", self.page.inner_text("#wiz-body"))
        self.assertEqual(self.page.input_value("#wiz-pass"), "", "the saved password is never shown")
        self.next()                                              # the password may stay empty: the saved one is for this server and user
        self.page.wait_for_selector("#wiz-rec")
        self.assertEqual(self.page.input_value("#wiz-rec"), "old-rcpt@example.com")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.assertEqual(self.run_test(), "Sent", self.result())
        self.assertEqual(mail.sessions[-1]["auth"], ("ops", "saved-pw"), "the test used the saved password")
        self.finish()
        self.assertEqual(self.stored()["smtp_password"], before["smtp_password"], "the saved password was not touched")

    def test_a_known_service_is_recognised_from_its_server(self):
        self.api("POST", "/config", {"smtp_host": "smtp.gmail.com", "smtp_port": 587, "smtp_username": "me@gmail.com", "smtp_from": "me@gmail.com"})
        self.open()
        self.assertEqual(self.page.eval_on_selector("#wiz-body input[name='wiz-svc']:checked", "e => e.value"), "gmail")
        self.page.evaluate("() => closeModal('wizard-modal')")
        self.api("POST", "/config", {"smtp_host": "email-smtp.eu-west-1.amazonaws.com"})
        self.open()
        self.assertEqual(self.page.eval_on_selector("#wiz-body input[name='wiz-svc']:checked", "e => e.value"), "ses")
        self.page.evaluate("() => closeModal('wizard-modal')")
        self.api("POST", "/config", {"smtp_host": "127.0.0.1", "smtp_port": 1025})
        self.open()
        self.assertEqual(self.page.eval_on_selector("#wiz-body input[name='wiz-svc']:checked", "e => e.value"), "proton")

    def test_another_server_or_user_needs_the_password_typed_again(self):
        mail = self.mail(tls="none", user="ops", password="saved-pw")
        self.saved_setup(mail)
        self.open()
        self.next()
        self.page.wait_for_selector("#wiz-host")
        self.fill("#wiz-host", "localhost")
        self.next()
        self.assertEqual(self.message(), "This field is needed")
        self.assertEqual(self.page.evaluate("() => document.activeElement.id"), "wiz-pass", "the saved password is not sent to a different server")
        self.fill("#wiz-host", "127.0.0.1")
        self.fill("#wiz-user", "someone-else")
        self.next()
        self.assertEqual(self.message(), "This field is needed")
        self.fill("#wiz-user", "ops")
        self.next()
        self.page.wait_for_selector("#wiz-rec")

    def test_closing_early_saves_nothing_even_after_a_test_that_worked(self):
        mail = self.mail(tls="none")
        self.to_the_end(mail)
        self.page.keyboard.press("Escape")
        self.page.wait_for_selector("#wizard-modal", state="detached", timeout=20000)
        self.assertEqual(self.stored(), self.start)
        self.open()
        self.pick("local")
        self.page.click("#wiz-cancel")
        self.page.wait_for_selector("#wizard-modal", state="detached", timeout=20000)
        self.assertEqual(self.stored(), self.start)

    def test_the_password_variable_is_named_and_the_box_is_not_needed(self):
        # the test stack's own environment has no RP_SMTP_PASSWORD: the settings the page reads say it has
        self.open()
        self.page.evaluate("() => { _wiz.st.cfg = Object.assign({}, _wiz.st.cfg, { smtp_password_from_env: true }); _wizSmtpFill(_wiz.st); }")
        self.pick("gmail")
        self.next()
        self.page.wait_for_selector("#wiz-host")
        self.assertIn("RP_SMTP_PASSWORD", self.page.inner_text("#wiz-body"))
        self.fill("#wiz-user", "me@gmail.com")
        self.fill("#wiz-from", "me@gmail.com")
        self.next()
        self.page.wait_for_selector("#wiz-rec")

    # ── words ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def own_texts(self):
        return self.page.evaluate("""() => {
          const out = new Set();
          document.querySelectorAll('#wizard-modal *').forEach(e => {
            if (e.closest('.ff-mono') || e.matches('.wiz-chip, .wiz-num, option, input, select, textarea, script, style, .visually-hidden')) return;
            const t = [...e.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim();
            if (t) out.add(t);
          });
          return [...out];
        }""")

    def test_every_word_of_every_step_has_a_translation_in_all_six_languages(self):
        mail = self.mail(tls="none", user="ops", password="right")
        seen = set()
        self.assertTrue(self.page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), "i18n.js did not load")

        def collect():
            seen.update(self.own_texts())
        self.open()
        collect()
        for key in PROVIDERS:
            self.pick(key)
            self.next()
            self.page.wait_for_selector("#wiz-host")
            collect()
            self.page.click("#wiz-back")
        self.pick("own")
        self.next()
        self.page.wait_for_selector("#wiz-host")
        self.connect(port=mail.port, user="ops", password="wrong")
        self.next()
        self.page.wait_for_selector("#wiz-rec")
        collect()
        self.fill("#wiz-rec", "me@example.com")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        collect()
        self.assertEqual(self.run_test(), "Not sent")
        collect()
        self.page.click("#wiz-back")
        self.page.click("#wiz-back")
        self.fill("#wiz-pass", "right")
        self.next()
        self.page.wait_for_selector("#wiz-rec")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.assertEqual(self.run_test(), "Sent")
        collect()
        self.next()
        self.page.wait_for_selector("#wiz-body .wiz-list")
        collect()
        self.assertTrue(self.page.is_visible("#wizard-modal"))
        # the error messages the steps give
        texts = {t for t in seen if not ("@" in t or t in BRANDS or t.startswith(("127.0.0.1", "smtp")) or t.replace(":", "").replace(".", "").isdigit())}
        self.assertGreater(len(texts), 40, "the population is not empty")
        langs = self.page.evaluate("() => RPi18n.langs.filter(l => l !== 'en')")
        self.assertEqual(sorted(langs), ["ar", "de", "es", "fr", "hi", "zh"])
        try:
            for lang in langs:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for t in sorted(texts):
                    got = self.page.evaluate("(k) => RPi18n.t(k)", t)
                    self.assertTrue(got, "%s: %r is empty" % (lang, t))
                    if (t, lang) not in SAME:
                        self.assertNotEqual(got, t, "%s: %r is not translated" % (lang, t))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")

    def test_no_script_error_was_raised(self):
        mail = self.mail(tls="none")
        self.to_the_end(mail)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
