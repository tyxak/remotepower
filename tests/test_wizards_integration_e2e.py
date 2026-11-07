#!/usr/bin/env python3
"""8.0.0: the Add an integration wizard, in a browser on the demo seed.

The Settings page adds an integration with a select of every connector and a card to fill in. The wizard asks for the same things in steps: a service
chosen from the catalog the server holds (grouped, with a search box), the address and the credentials THAT connector asks for, a test that saves
nothing, and the instance added to the list. A fake service on this machine's LAN address answers like an Uptime Kuma status page, because the server
refuses a loopback address for an integration, as it does for the page.

Held: the catalog on screen is the catalog the server sent (minus the virtualization platforms, which have their own page), the search hides what does
not match and says when nothing does, a service brings its own name and address and never overwrites what was typed, the required fields are required,
the test reports in words and saves nothing, the instance is added with its fields while the others and their secrets stay as they were (read from the
stored configuration), an edit waiting on the Settings page is neither saved nor lost, closing early saves nothing, and every word has a translation.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only. The tests that need a service on a LAN address skip
on a machine that has only a loopback one.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
# RP_BROWSER_REQUIRE turns "no browser here" from a silent pass into a failure, so it is part of the class condition
# (tests/test_ci_green_parity.py holds the shape).
_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}
# (English text, language) pairs where the right translation is the same word
SAME = {("Proxies", "es"), ("Downloads", "de"), ("Orchestration", "fr"), ("Optional", "de"), ("Apps", "de"), ("Network", "de"), ("Backup", "de"), ("Backup", "fr"), ("Storage", "fr"), ("Media", "fr")}


def lan_ip():
    """This machine's address on a network, which the server may probe. Empty when there is only a loopback one."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = ""
    finally:
        s.close()
    return "" if (not ip or ip.startswith("127.")) else ip


class _Kuma(BaseHTTPRequestHandler):
    """An Uptime Kuma published status page: two monitors, one down."""

    def do_GET(self):
        if self.path.startswith("/api/status-page/heartbeat/"):
            second = 1 if self.path.endswith("/allup") else 0          # Uptime Kuma's own numbers: 1 is up, 0 is down
            body = json.dumps({"heartbeatList": {"1": [{"status": 1}], "2": [{"status": second}]}}).encode()
            self.send_response(200)
        else:
            body, _ = b"{}", self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the wizard is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-integ-wizard-")
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


def _until(fn, seconds=20, step=0.25):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(step)
    return last


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheIntegrationWizard(unittest.TestCase):

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
        cls.ip = lan_ip()
        cls.kuma = None
        if cls.ip:
            cls.kuma = HTTPServer((cls.ip, 0), _Kuma)
            threading.Thread(target=cls.kuma.serve_forever, daemon=True).start()
            cls.kuma_url = "http://%s:%d" % (cls.ip, cls.kuma.server_address[1])
        cls.initial = cls.api("GET", "/integrations")
        cls.baseline = json.loads((Path(_STATE["data_dir"]) / "config.json").read_text()).get("integrations") or []

    @classmethod
    def tearDownClass(cls):
        try:
            if cls.kuma:
                cls.kuma.shutdown()
                cls.kuma.server_close()
        finally:
            cls.ctx.close()

    @classmethod
    def api(cls, method, path, body=None):
        return cls.page.evaluate("async ([m, p, b]) => b === null ? await api(m, p) : await api(m, p, b)", [method, path, body])

    def setUp(self):
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")

    def tearDown(self):
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")
        # What a test added goes: the list the server had when the module began goes back (a blank secret keeps the stored one). Only when
        # something changed: every save makes the server poll every integration on the next request, and the seeded ones are on hosts that do
        # not exist, so a save costs seconds that most of these tests never need to spend.
        if self.stored() != self.baseline:
            self.api("POST", "/integrations", {"integrations": self.initial["integrations"]})
            # the save writes every instance in its own normal form, which is not the seed's: that is the list to compare with from now on
            type(self).baseline = self.stored()

    def stored(self):
        return json.loads((Path(_STATE["data_dir"]) / "config.json").read_text()).get("integrations") or []

    def need_lan(self):
        if not self.kuma:
            self.skipTest("this machine has only a loopback address, which the server refuses for an integration")

    def open(self):
        self.page.evaluate("() => wizOpen('integration')")
        self.page.wait_for_selector("#wizard-modal.active .wiz-choice", timeout=30000)

    def steps(self):
        return self.page.eval_on_selector_all("#wiz-steps .wiz-lbl", "els => els.map(e => e.textContent)")

    def pick(self, type_):
        self.page.check('#wiz-body input[name="wiz-type"][value="%s"]' % type_)

    def next(self):
        self.page.click("#wiz-next")

    def message(self):
        return self.page.inner_text("#wiz-msg").strip()

    def fill(self, sel, value):
        self.page.fill(sel, value)

    def to_connection(self, type_):
        self.open()
        self.pick(type_)
        self.next()
        self.page.wait_for_selector("#wiz-name")

    # ── the catalog ───────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_it_shows_every_connector_the_server_has_grouped_without_the_virtualization_ones(self):
        catalog = self.api("GET", "/integrations")["catalog"]
        want = sorted(c["type"] for c in catalog if c["category"] != "virtualization")
        self.assertGreater(len(want), 40, "the population is not empty")
        self.open()
        self.assertEqual(self.steps(), ["Service", "Connection", "Test", "Finish"])
        shown = self.page.eval_on_selector_all('#wiz-body input[name="wiz-type"]', "els => els.map(e => e.value)")
        self.assertEqual(sorted(shown), want)
        virt = [c["type"] for c in catalog if c["category"] == "virtualization"]
        self.assertTrue(virt)
        self.assertEqual(set(shown) & set(virt), set())
        groups = self.page.eval_on_selector_all("#wiz-body .wiz-grp", "els => els.map(e => e.textContent)")
        self.assertEqual(groups[0], "Apps")
        self.assertEqual(len(groups), len(set(groups)), "each heading once")
        self.assertIn("Monitoring", groups)

    def test_the_search_hides_what_does_not_match_and_a_heading_with_nothing_under_it(self):
        self.open()
        self.fill("#wiz-search", "kuma")
        visible = self.page.eval_on_selector_all('#wiz-body label.wiz-choice:not([hidden]) input', "els => els.map(e => e.value)")
        self.assertEqual(visible, ["uptimekuma"])
        heads = self.page.eval_on_selector_all("#wiz-body .wiz-grp:not([hidden])", "els => els.map(e => e.textContent)")
        self.assertEqual(heads, ["Monitoring"])
        self.fill("#wiz-search", "zzzzzz")
        self.assertTrue(self.page.is_visible("#wiz-nomatch"))
        self.assertEqual(self.page.eval_on_selector_all('#wiz-body label.wiz-choice:not([hidden])', "els => els.length"), 0)
        self.fill("#wiz-search", "")
        self.assertFalse(self.page.is_visible("#wiz-nomatch"))
        self.assertGreater(self.page.eval_on_selector_all('#wiz-body label.wiz-choice:not([hidden])', "els => els.length"), 40)

    def test_the_search_also_finds_a_service_by_its_type(self):
        self.open()
        # The type of Nginx Proxy Manager is npm, and "npm" is not a part of its name: only the type can match it.
        self.fill("#wiz-search", "npm")
        self.assertEqual(self.page.eval_on_selector_all('#wiz-body label.wiz-choice:not([hidden]) input', "els => els.map(e => e.value)"), ["npm"])

    def test_a_step_cannot_be_left_without_a_service(self):
        self.open()
        self.next()
        self.assertEqual(self.message(), "Choose a service")
        self.assertEqual(self.steps()[0], "Service")

    # ── the connection ────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_a_service_brings_its_name_and_its_address_and_what_was_typed_stays(self):
        self.to_connection("tailscale")
        self.assertEqual(self.page.input_value("#wiz-name"), "Tailscale")
        self.assertEqual(self.page.input_value("#wiz-url"), "https://api.tailscale.com")
        self.page.click("#wiz-back")
        self.pick("uptimekuma")
        self.next()
        self.assertEqual(self.page.input_value("#wiz-name"), "Uptime Kuma")
        self.assertEqual(self.page.input_value("#wiz-url"), "", "a service with no fixed address has none")
        self.fill("#wiz-url", "http://kuma.lan:3001")
        self.fill("#wiz-name", "Kuma at home")
        self.page.click("#wiz-back")
        self.pick("pihole")
        self.next()
        self.assertEqual(self.page.input_value("#wiz-name"), "Kuma at home", "a name that was typed is kept")
        self.assertEqual(self.page.input_value("#wiz-url"), "http://kuma.lan:3001", "an address that was typed is kept")

    def test_the_fields_are_the_ones_that_connector_asks_for_and_optional_ones_say_so(self):
        catalog = {c["type"]: c for c in self.api("GET", "/integrations")["catalog"]}
        self.to_connection("tailscale")
        for f in catalog["tailscale"]["fields"]:
            self.assertTrue(self.page.is_visible("#wiz-f-" + f["key"]), f["key"])
            self.assertEqual(self.page.eval_on_selector("#wiz-f-%s" % f["key"], "e => e.type"), "password" if f["kind"] == "password" else "text")
        self.assertIn("Optional", self.page.inner_text("#wiz-body .form-group:has(#wiz-f-slug)"))
        self.assertNotIn("Optional", self.page.inner_text("#wiz-body .form-group:has(#wiz-f-secret)"))
        self.assertIn(catalog["tailscale"]["notes"], self.page.inner_text("#wiz-body"))

    def test_the_wizard_does_not_ask_for_a_field_a_connector_does_not_have(self):
        self.to_connection("caddy")
        self.assertEqual(self.page.eval_on_selector_all('#wiz-body [id^="wiz-f-"]', "els => els.length"), 0)

    def test_name_address_and_required_fields_are_checked_in_the_forms_own_words(self):
        self.to_connection("tailscale")
        self.fill("#wiz-name", "")
        self.next()
        self.assertEqual(self.message(), "Name required")
        self.fill("#wiz-name", "ts")
        self.fill("#wiz-url", "")
        self.next()
        self.assertEqual(self.message(), "Set a URL first")
        self.fill("#wiz-url", "ftp://x.example")
        self.next()
        self.assertEqual(self.message(), "The URL must start with http:// or https://")
        self.fill("#wiz-url", "https://api.tailscale.com")
        self.next()
        self.assertEqual(self.message(), "This field is needed")
        self.assertEqual(self.page.evaluate("() => document.activeElement.id"), "wiz-f-secret")
        self.fill("#wiz-f-secret", "tskey-api-x")
        self.next()
        self.page.wait_for_selector("#wiz-test")

    def test_the_certificate_box_starts_on_and_is_carried_to_the_test(self):
        self.to_connection("tailscale")
        self.assertTrue(self.page.is_checked("#wiz-verify"))
        self.page.uncheck("#wiz-verify")
        self.fill("#wiz-f-secret", "k")
        seen = []
        self.page.on("request", lambda r: seen.append(r.post_data) if r.url.endswith("/api/integrations/test") else None)
        self.next()
        self.page.click("#wiz-test")
        _until(lambda: seen)
        self.assertEqual(json.loads(seen[0])["verify_tls"], False)

    # ── the test ──────────────────────────────────────────────────────────────────────────────────────────────────────────
    def go_to_test(self, type_, url, **fields):
        self.to_connection(type_)
        self.fill("#wiz-url", url)
        for k, v in fields.items():
            self.fill("#wiz-f-" + k, v)
        self.next()
        self.page.wait_for_selector("#wiz-test")

    def test_a_service_that_answers_is_reachable_with_what_it_said_and_nothing_is_saved(self):
        self.need_lan()
        before = len(self.stored())
        self.go_to_test("uptimekuma", self.kuma_url, slug="allup")
        self.page.click("#wiz-test")
        self.page.wait_for_selector("#wiz-result .wiz-state")
        self.assertEqual(self.page.inner_text("#wiz-result .wiz-state"), "Reachable", self.page.inner_text("#wiz-result"))
        self.assertIn("2 monitors, 0 down", self.page.inner_text("#wiz-result"))
        self.assertIn("The service answered.", self.page.inner_text("#wiz-result"))
        self.assertNotIn("reports a problem", self.page.inner_text("#wiz-result"))
        self.assertIn("c-green", self.page.get_attribute("#wiz-result", "class"))
        self.assertEqual(len(self.stored()), before, "a test saves nothing")

    def test_a_service_that_answers_and_reports_a_problem_was_reached_and_says_so(self):
        # the connector calls this critical (a monitor is down), which is not the same as not being there
        self.need_lan()
        self.go_to_test("uptimekuma", self.kuma_url, slug="default")
        self.page.click("#wiz-test")
        self.page.wait_for_selector("#wiz-result .wiz-state")
        self.assertEqual(self.page.inner_text("#wiz-result .wiz-state"), "Reachable", self.page.inner_text("#wiz-result"))
        self.assertIn("reports a problem", self.page.inner_text("#wiz-result"))
        self.assertIn("2 monitors, 1 down", self.page.inner_text("#wiz-result"))
        self.assertIn("c-amber", self.page.get_attribute("#wiz-result", "class"))
        self.next()
        self.assertIn("Reachable", self.page.inner_text("#wiz-body"))
        self.assertNotIn("did not pass", self.page.inner_text("#wiz-body"))

    def test_a_service_that_does_not_answer_is_not_reachable_and_the_wizard_still_finishes(self):
        self.need_lan()
        s = socket.socket()
        s.bind((self.ip, 0))
        port = s.getsockname()[1]
        s.close()
        self.go_to_test("uptimekuma", "http://%s:%d" % (self.ip, port), slug="default")
        self.page.click("#wiz-test")
        self.page.wait_for_selector("#wiz-result .wiz-state", timeout=60000)      # the default 30 s ran out once while another suite used the machine
        self.assertEqual(self.page.inner_text("#wiz-result .wiz-state"), "Not reachable")
        self.next()
        self.assertIn("The test did not pass", self.page.inner_text("#wiz-body"))
        self.assertEqual(self.page.inner_text("#wiz-next"), "Add it")

    def test_a_connection_that_changed_since_the_test_has_no_verdict(self):
        self.need_lan()
        # Each box of the Connection step drops the answer of the last test, so each is changed on its own.
        changes = [
            ("the name", lambda: self.fill("#wiz-name", "renamed")),
            ("the address", lambda: self.fill("#wiz-url", self.kuma_url + "/")),
            ("a field of the service", lambda: self.fill("#wiz-f-slug", "another-page")),
            ("the certificate box", lambda: self.page.uncheck("#wiz-verify")),
        ]
        for what, change in changes:
            with self.subTest(what):
                self.setUp()
                self.go_to_test("uptimekuma", self.kuma_url, slug="default")
                self.page.click("#wiz-test")
                self.page.wait_for_selector("#wiz-result .wiz-state")
                self.page.click("#wiz-back")
                change()
                self.next()
                self.assertEqual(self.page.inner_text("#wiz-result").strip(), "", "the old answer is not shown after %s changed" % what)
                self.next()
                self.assertIn("Not tested", self.page.inner_text("#wiz-body"), what)

    # ── adding it ─────────────────────────────────────────────────────────────────────────────────────────────────────────
    def finish(self):
        self.next()
        self.page.wait_for_selector("#wizard-modal", state="detached", timeout=20000)

    def test_adding_it_stores_the_instance_with_its_fields_and_keeps_the_others_and_their_secrets(self):
        self.need_lan()
        keep = {"type": "uptimekuma", "label": "Keep me", "url": self.kuma_url, "slug": "default", "enabled": True, "verify_tls": True, "secret": "stored-secret-1"}
        self.assertTrue(self.api("POST", "/integrations", {"integrations": self.initial["integrations"] + [keep]})["ok"])
        n = len(self.stored())
        self.to_connection("uptimekuma")
        self.fill("#wiz-name", "Wizard kuma")
        self.fill("#wiz-url", self.kuma_url)
        self.fill("#wiz-f-slug", "other-page")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.next()
        self.assertIn("Wizard kuma", self.page.inner_text("#wiz-body"))
        self.finish()
        rows = self.stored()
        self.assertEqual(len(rows), n + 1)
        mine = [r for r in rows if r["label"] == "Wizard kuma"][0]
        self.assertEqual((mine["type"], mine["url"], mine["slug"], mine["enabled"], mine["verify_tls"]), ("uptimekuma", self.kuma_url, "other-page", True, True))
        self.assertTrue(mine["id"])
        old = [r for r in rows if r["label"] == "Keep me"][0]
        self.assertEqual(old.get("secret"), "stored-secret-1", "an instance that was there keeps its secret")

    def test_a_credential_that_was_typed_is_stored_and_one_left_empty_is_not(self):
        self.need_lan()
        self.to_connection("pihole")
        self.fill("#wiz-url", self.kuma_url)
        self.fill("#wiz-f-secret", "typed-app-password")
        self.next()
        self.next()
        self.finish()
        mine = [r for r in self.stored() if r["type"] == "pihole" and r["url"] == self.kuma_url][0]
        self.assertEqual(mine.get("secret"), "typed-app-password")

    def test_a_url_the_server_refuses_is_said_in_the_dialog_and_nothing_is_added(self):
        before = len(self.stored())
        self.to_connection("caddy")
        self.fill("#wiz-url", "http://127.0.0.1:2019")
        self.next()
        self.next()
        self.next()
        self.page.wait_for_function("() => document.getElementById('wiz-msg').textContent.trim().length > 0", timeout=20000)
        self.assertIn("blocked", self.message().lower())
        self.assertTrue(self.page.is_visible("#wizard-modal"), "the wizard stays open so the address can be fixed")
        self.assertEqual(len(self.stored()), before)

    def test_closing_early_saves_nothing(self):
        before = self.stored()
        self.to_connection("caddy")
        self.fill("#wiz-url", "http://192.168.1.5:2019")
        self.page.keyboard.press("Escape")
        self.page.wait_for_selector("#wizard-modal", state="detached")
        self.assertEqual(self.stored(), before)

    def test_the_settings_list_gets_the_new_instance_and_an_unsaved_edit_there_is_neither_saved_nor_lost(self):
        self.need_lan()
        page = self.page
        page.evaluate("() => { showPage('settings'); switchSettingsTab('integrations'); loadIntegrationsTab(); }")
        page.wait_for_function("() => typeof _integrations !== 'undefined' && _integrations.length > 0 && document.querySelector('#integrations-list .integration-card')", timeout=30000)
        page.evaluate("() => { _integrations[0].label = 'EDITED NOT SAVED'; renderIntegrations(); }")
        first_stored = self.stored()[0]["label"]
        self.to_connection("uptimekuma")
        self.fill("#wiz-name", "Wizard kuma 2")
        self.fill("#wiz-url", self.kuma_url)
        self.fill("#wiz-f-slug", "default")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.next()
        self.finish()
        labels = page.evaluate("() => _integrations.map(x => x.label)")
        self.assertIn("EDITED NOT SAVED", labels, "the edit that was waiting is still there")
        self.assertIn("Wizard kuma 2", labels, "the new instance is on the page")
        self.assertEqual(self.stored()[0]["label"], first_stored, "and it was not saved by the wizard")
        shown = page.eval_on_selector_all("#integrations-list .integration-card", "els => els.length")
        self.assertEqual(shown, page.evaluate("() => _integrations.filter(x => !_isVirtType(x.type)).length"), "every instance of the list has its card")

    # ── the page and the words ────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_button_is_beside_add_on_the_settings_page(self):
        self.page.evaluate("() => { showPage('settings'); switchSettingsTab('integrations'); }")
        self.page.wait_for_selector('[data-action="wizOpen"][data-arg="integration"]', state="visible", timeout=30000)
        self.assertEqual(self.page.inner_text('[data-action="wizOpen"][data-arg="integration"]').strip(), "Guide me")
        self.page.click('[data-action="wizOpen"][data-arg="integration"]')
        self.page.wait_for_selector("#wizard-modal.active .wiz-choice", timeout=30000)
        self.assertEqual(self.page.inner_text("#wiz-title"), "Add an integration")

    def test_every_word_has_a_translation_in_all_six_languages(self):
        page = self.page
        self.assertTrue(page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), "i18n.js did not load")
        keys = ["Add an integration", "Type a service name", "What do you want to connect?", "Choose a service", "No service matches.", "Check the TLS certificate",
                "Turn it off for a service with a self-signed certificate on your network.", "Optional", "Check that this server can reach it and that the key works.",
                "Test the connection", "Reachable", "Not reachable", "The service answered.",
                "The service answered and reports a problem. That is what its tile will show.", "Check the address and the key, and that this server can reach it.",
                "Testing…", "It was not tested. A wrong address shows up as a red tile at the first check.",
                "The test did not pass. You can still add it and fix it from its card.", "Add it", "Integration added", "Media", "Downloads", "Requests",
                "Proxies", "Orchestration", "Your own", "Apps", "Monitoring", "Network", "Storage", "Backup", "Security", "DNS"]
        try:
            for lang in page.evaluate("() => RPi18n.langs.filter(l => l !== 'en')"):
                page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for k in keys:
                    got = page.evaluate("(k) => RPi18n.t(k)", k)
                    self.assertTrue(got, "%s: %r is empty" % (lang, k))
                    if (k, lang) not in SAME and k != "DNS":      # a word that is the same in the language (an acronym, a loan word)
                        self.assertNotEqual(got, k, "%s: %r has no entry" % (lang, k))
        finally:
            page.evaluate("() => RPi18n.setLang('en', false)")

    def test_the_page_threw_nothing(self):
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
