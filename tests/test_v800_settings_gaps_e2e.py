#!/usr/bin/env python3
"""8.0.0: the two Settings controls the whole-code survey found missing, pressed in a browser on the demo seed.

tests/test_v800_settings_gaps.py holds the server's half. This file holds what an operator does: Settings, Alerts inbox has a switch for who may acknowledge, resolve and
assign alerts (on until it is turned off; the saved value comes back after a reload), and the SAML card has an SP entity ID field that is saved and shown again. Both are
translated in the six languages and nothing in the page broke.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}
LANGS = ("zh", "hi", "es", "ar", "de", "fr")


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the settings are backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-settings-gaps-e2e-")
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


def _path(name):
    return Path(_STATE["data_dir"]) / name


def read(name):
    return json.loads(_path(name).read_text())


def write(name, doc):
    # a file of the data directory that is written twice in the same second can be read by the server as the first version (its cache looks at the modification time),
    # so every write is given a modification time two seconds after the one it replaces
    tmp = _path(name).with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    before = _path(name).stat().st_mtime if _path(name).exists() else 0
    stamp = max(before + 2, time.time())
    os.utime(tmp, (stamp, stamp))
    os.replace(tmp, _path(name))


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheSettingsControlsInABrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors, cls.saves = ctx, ctx.new_page(), [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("request", lambda r: cls.saves.append(json.loads(r.post_data or "{}")) if r.method == "POST" and r.url.endswith("/api/config") else None)
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.config0 = read("config.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("config.json", cls.config0)
        finally:
            cls.ctx.close()

    def setUp(self):
        cfg = json.loads(json.dumps(self.config0))
        cfg.pop("viewers_can_ack_alerts", None)
        cfg.pop("saml_sp_entity_id", None)
        write("config.json", cfg)
        del self.saves[:]

    def open_settings(self, control):
        """Settings, on the pane that holds `control`, opened the way a person opens it: the tab is pressed, and its own handlers load what the pane shows."""
        with self.page.expect_response(lambda r: r.url.endswith("/api/config") and r.request.method == "GET", timeout=60000):
            self.page.evaluate("() => showPage('settings')")
        pane = self.page.evaluate("(id) => document.getElementById(id).closest('.settings-pane').id.replace('settings-pane-', '')", control)
        self.page.click("#settings-tab-btn-" + pane)
        self.page.wait_for_selector("#" + control, state="visible", timeout=20000)
        self.page.wait_for_timeout(1200)

    def press_and_wait_for_the_save(self, selector):
        """Press a save button and wait for the answer 200. Changing a governance switch asks for the password first (the page's step-up dialog); the demo's settings
        make the whole-form save one of those, so the dialog is answered the way its operator would."""
        answers = []

        def seen(r):
            if r.url.endswith("/api/config") and r.request.method == "POST":
                answers.append(r.status)

        self.page.on("response", seen)
        try:
            self.page.click(selector)
            deadline = time.time() + 40
            while time.time() < deadline and answers[-1:] != [200]:
                if self.page.evaluate("() => { const m = document.getElementById('step-up-modal'); return !!m && m.classList.contains('active'); }"):
                    self.page.fill("#step-up-password", "demo")
                    self.page.click('#step-up-modal [data-action="stepUpSubmit"]')
                    self.page.wait_for_timeout(1500)
                self.page.wait_for_timeout(200)
        finally:
            self.page.remove_listener("response", seen)
        self.assertEqual(answers[-1:], [200], "answers of POST /api/config: %r" % answers)

    def test_the_alerts_inbox_switch_is_on_until_it_is_turned_off(self):
        self.open_settings("cfg-viewers-can-ack")
        self.assertTrue(self.page.is_checked("#cfg-viewers-can-ack"), "no key in the configuration reads as on, as the server reads it")

    def test_turning_it_off_is_saved_and_comes_back_and_turning_it_on_again_is_too(self):
        self.open_settings("cfg-viewers-can-ack")
        self.page.uncheck("#cfg-viewers-can-ack")
        self.press_and_wait_for_the_save("#btn-save-settings")
        self.assertIs(read("config.json").get("viewers_can_ack_alerts"), False)
        self.assertIs(self.saves[-1].get("viewers_can_ack_alerts"), False)
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2500)
        self.open_settings("cfg-viewers-can-ack")
        self.assertFalse(self.page.is_checked("#cfg-viewers-can-ack"), "the saved 'off' is what the form shows after a reload")
        self.page.check("#cfg-viewers-can-ack")
        self.press_and_wait_for_the_save("#btn-save-settings")
        self.assertIs(read("config.json").get("viewers_can_ack_alerts"), True)

    def test_the_saml_card_saves_the_sp_entity_id_and_shows_it_again(self):
        self.open_settings("saml-sp-entity-id")
        self.assertEqual(self.page.input_value("#saml-sp-entity-id"), "")
        self.page.fill("#saml-sp-entity-id", "  urn:remotepower:demo  ")
        self.press_and_wait_for_the_save('button[data-action="saveSamlConfig"]')
        self.assertEqual(read("config.json").get("saml_sp_entity_id"), "urn:remotepower:demo", "trimmed, as the neighbouring fields are")
        self.assertEqual(self.saves[-1].get("saml_sp_entity_id"), "urn:remotepower:demo")
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2500)
        self.open_settings("saml-sp-entity-id")
        self.page.wait_for_function("() => document.getElementById('saml-sp-entity-id').value === 'urn:remotepower:demo'", timeout=20000)
        self.page.fill("#saml-sp-entity-id", "")
        self.press_and_wait_for_the_save('button[data-action="saveSamlConfig"]')
        self.assertEqual(read("config.json").get("saml_sp_entity_id"), "", "blank goes back to the metadata URL")

    def test_the_words_are_translated_in_all_six_languages(self):
        self.open_settings("saml-sp-entity-id")
        self.page.evaluate("async () => { await _ensureI18n(); }")
        grab = """() => {
          const lab = document.getElementById('saml-sp-entity-id').parentElement;
          const ack = document.getElementById('cfg-viewers-can-ack').parentElement;
          return {
            sp: [...lab.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent.trim()).join(''),
            spHint: lab.querySelector('.hint').textContent,
            spPlaceholder: document.getElementById('saml-sp-entity-id').getAttribute('placeholder'),
            ack: [...ack.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent.trim()).join(''),
            ackHint: ack.parentElement.nextElementSibling.textContent};
        }"""
        english = self.page.evaluate(grab)
        self.assertEqual(english["sp"], "SP entity ID (optional)")
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(grab)
                bad += [(lang, k) for k in english if now[k] == english[k]]
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_settings("cfg-viewers-can-ack")
        self.open_settings("saml-sp-entity-id")
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
