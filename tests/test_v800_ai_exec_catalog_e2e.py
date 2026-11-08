#!/usr/bin/env python3
"""8.0.0: the governed executor's list of what it may pick from, in a browser on the demo seed.

`GET /api/ai-exec/catalog` was written so an operator can read, in one place, everything the AI could ever propose, and no page asked for it. The AI triage view now has **Actions it may
pick from** next to **Propose fix**: it opens the list in place, under the verdict, with each action's name, id, description and the first characters of the hash of the body it would run,
and a second click closes it. tests/test_v800_ai_exec_scripts.py holds the route (the saved scripts are in it, one tenant's are not shown to another); this file holds what a person sees:
a script saved through the library's own route is on the list, the list is what the route answers, the verdict stays on screen, a failed read says so in words, the button is not there when the
module is off, and the words are translated.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import hashlib
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
except ImportError:  # pragma: no cover
    sync_playwright = None

_STATE = {}
LANGS = ("zh", "hi", "es", "ar", "de", "fr")
BODY = "systemctl restart nginx"


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the list is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-ai-exec-catalog-e2e-")
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


def _login(browser, user):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(_STATE["base"] + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(3000)
    return ctx, page, errors


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheListOfWhatTheExecutorMayPick(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _login(_STATE["browser"], "alice")  # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.set_default_timeout(20000)
        cls.config0 = read("config.json")
        write("config.json", dict(cls.config0, ai_exec_enabled=True))
        cls.page.reload()
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(2500)
        cls.script = cls.page.evaluate(
            "async (b) => { const r = await api('POST', '/scripts', {name: 'Restart nginx', description: 'bounce the proxy', body: b}); return r && r.script ? {id: r.script.id} : {error: r}; }", BODY
        )
        assert cls.script.get("id"), cls.script
        cls.page.evaluate("() => { showPage('alerts'); }")
        cls.page.wait_for_function("() => typeof _renderTriageResult === 'function'", timeout=30000)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.page.evaluate("async (id) => { await api('DELETE', '/scripts/' + id); }", cls.script["id"])
            write("config.json", cls.config0)
        finally:
            cls.ctx.close()

    def tearDown(self):
        self.page.unroute_all(behavior="ignoreErrors")
        self.page.evaluate("() => { closeModal('ai-insight-modal'); window._modules = Object.assign({}, window._modules, {ai_exec: true}); }")

    def render(self):
        # the verdict goes into the body of the AI insight dialog, the container the product itself renders it in
        self.page.evaluate(
            """() => { openModal('ai-insight-modal');
            _renderTriageResult(document.getElementById('ai-insight-body'),
                {verdict: {root_cause: 'The disk is full', recommended_action: 'Clean the package cache', confidence: 'high'}, at: Math.floor(Date.now() / 1000), by: 'alice'}, 'al1', 'dev1'); }"""
        )
        self.page.wait_for_selector("#ai-insight-body .ai-content", timeout=15000)

    def toggle(self):
        self.page.click('#ai-insight-body [data-action="aiExecCatalogToggle"]')

    def open_list(self):
        self.render()
        self.toggle()
        self.page.wait_for_selector("#ai-exec-catalog li", timeout=30000)

    def test_the_list_opens_under_the_verdict_and_names_each_action(self):
        self.open_list()
        text = self.page.inner_text("#ai-exec-catalog")
        sid = self.script["id"]
        for expected in ("Restart nginx", "script:" + sid, "bounce the proxy", "sha256 " + hashlib.sha256(BODY.encode()).hexdigest()[:12], "playbook:reboot"):
            self.assertIn(expected, text)
        self.assertIn("The executor can only pick from these. It cannot write a command", text)
        self.assertIn("The disk is full", self.page.inner_text("#ai-insight-body"), "the verdict stays on screen while the list is open")

    def test_the_list_is_what_the_route_answers(self):
        self.open_list()
        wanted = self.page.evaluate("async () => { const r = await api('GET', '/ai-exec/catalog'); return r.catalog.map(c => c.id); }")
        shown = self.page.evaluate("() => [...document.querySelectorAll('#ai-exec-catalog li code')].map(e => e.textContent)")
        self.assertEqual(sorted(shown), sorted(wanted))
        self.assertGreaterEqual(len(wanted), 2, "a saved script and at least one built-in playbook")

    def test_a_second_click_closes_it(self):
        self.open_list()
        self.toggle()
        self.assertEqual(self.page.inner_html("#ai-exec-catalog"), "")
        self.toggle()
        self.page.wait_for_selector("#ai-exec-catalog li", timeout=30000)

    def test_the_button_cannot_be_pressed_again_while_the_list_is_loading(self):
        held = []
        self.page.route("**/api/ai-exec/catalog", lambda route: held.append(route))
        self.render()
        self.toggle()
        self.page.wait_for_function("() => document.querySelector('#ai-exec-catalog p') !== null", timeout=15000)
        self.assertTrue(self.page.is_disabled('#ai-insight-body [data-action="aiExecCatalogToggle"]'), "one request at a time")
        for route in held:
            route.continue_()
        self.page.wait_for_selector("#ai-exec-catalog li", timeout=30000)
        self.assertEqual(len(held), 1)

    def test_a_failed_read_says_so_in_words(self):
        self.page.route("**/api/ai-exec/catalog", lambda route: route.abort())
        self.render()
        self.toggle()
        self.page.wait_for_selector("#ai-exec-catalog .c-red", timeout=15000)
        self.assertEqual(self.page.inner_text("#ai-exec-catalog .c-red").strip(), "The server did not answer.")

    def test_the_server_s_own_reason_is_shown_when_it_gives_one(self):
        # the reason is text: a tag in it is shown as typed and never becomes markup
        reason = "Not allowed for <b>this</b> account"
        self.page.route("**/api/ai-exec/catalog", lambda route: route.fulfill(status=403, content_type="application/json", body=json.dumps({"error": reason})))
        self.render()
        self.toggle()
        self.page.wait_for_selector("#ai-exec-catalog .c-red", timeout=15000)
        self.assertEqual(self.page.inner_text("#ai-exec-catalog .c-red").strip(), reason)
        self.assertEqual(self.page.locator("#ai-exec-catalog b").count(), 0)

    def test_with_the_module_off_there_is_no_button_and_no_box(self):
        self.page.evaluate("() => { window._modules = Object.assign({}, window._modules, {ai_exec: false}); }")
        self.render()
        self.assertEqual(self.page.locator('#ai-insight-body [data-action="aiExecCatalogToggle"]').count(), 0)
        self.assertEqual(self.page.locator("#ai-exec-catalog").count(), 0)
        self.assertIn("The disk is full", self.page.inner_text("#ai-insight-body"))

    def test_the_button_and_the_sentence_are_translated_in_all_six_languages(self):
        self.open_list()
        self.page.evaluate("async () => { await _ensureI18n(); }")
        button = '#ai-insight-body [data-action="aiExecCatalogToggle"]'
        english = (self.page.inner_text(button).strip(), self.page.inner_text("#ai-exec-catalog p.hint").strip())
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = (self.page.inner_text(button).strip(), self.page.inner_text("#ai-exec-catalog p.hint").strip())
                if now[0] == english[0] or now[1] == english[1]:
                    bad.append((lang, now))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_list()
        self.toggle()
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
