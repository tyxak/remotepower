#!/usr/bin/env python3
"""8.0.0: Roll back, in a host's docker compose dialog, in a browser on the demo seed.

tests/test_v210.py holds the route (what it queues, what it refuses) and tests/test_v800_compose_rollback.py holds the agent's verb. This file holds what a person
uses: the dialog has the button, pressing it asks first and queues nothing until it is confirmed, a confirmed rollback queues `compose:rollback:<dir>` on the real
server for a host whose agent says it can roll back, a host whose agent does not say so is refused in words and nothing is queued, and the button, its tooltip and
the question have a translation in all six languages.

The demo seed gives its Linux agents the flag (tests/test_v800_seeder_capabilities.py), so the first two use the seed as it is.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import subprocess
import sys
import tempfile
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
BUTTON = "Roll back"
TITLE = "Put the project back on the images it ran before its last update"
QUESTION = ("Roll back this project to the images it ran before its last update? The agent puts the earlier images back and starts the project without pulling. "
            "Data the newer version wrote is not rolled back.")
LANGS = ("zh", "hi", "es", "ar", "de", "fr")


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the dialog is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-compose-rollback-")
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


def read(name, default=None):
    return json.loads(_path(name).read_text()) if _path(name).exists() else default


def write(name, doc):
    tmp = _path(name).with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    os.replace(tmp, _path(name))


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestRollBackInTheComposeDialog(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors, cls.posts = ctx, ctx.new_page(), [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("request", lambda r: cls.posts.append(r) if r.method == "POST" and "/compose/action" in r.url else None)
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.devices0 = read("devices.json")
        cls.commands0 = read("commands.json", {})
        capable = [(i, d) for i, d in cls.devices0.items() if d.get("compose_projects") and (d.get("sysinfo") or {}).get("compose_rollback") is True]
        assert capable, "the seed has a Linux agent with compose projects that says it can roll back"
        cls.host_id, cls.host = capable[0]

    @classmethod
    def tearDownClass(cls):
        try:
            write("devices.json", cls.devices0)
            write("commands.json", cls.commands0)
        finally:
            cls.ctx.close()

    def setUp(self):
        write("devices.json", self.devices0)
        write("commands.json", self.commands0)
        del self.posts[:]

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          document.getElementById('toast-container').textContent = '';
        }""")

    def open_dialog(self):
        self.page.evaluate("([id, name]) => openComposeModal(id, name)", [self.host_id, self.host["name"]])
        self.page.wait_for_function("() => { const s = document.getElementById('compose-project-pick'); return s && s.value && s.value[0] === '/'; }", timeout=30000)
        return self.page.eval_on_selector("#compose-project-pick", "s => s.value")

    def press(self):
        self.page.click('#compose-modal [data-action="runCompose"][data-arg="rollback"]')
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=10000)

    def queued(self):
        return [c for c in (read("commands.json", {}).get(self.host_id) or []) if str(c).startswith("compose:rollback:")]

    def test_the_dialog_has_the_button_and_it_asks_before_anything_is_queued(self):
        self.open_dialog()
        button = self.page.locator('#compose-modal [data-action="runCompose"][data-arg="rollback"]')
        self.assertEqual(button.count(), 1)
        self.assertEqual(button.inner_text().strip(), BUTTON)
        self.press()
        self.assertEqual(self.page.inner_text("#ui-prompt-message"), QUESTION)
        self.assertEqual(self.page.inner_text("#ui-prompt-confirm").strip(), BUTTON)
        self.assertEqual((len(self.posts), self.queued()), (0, []), "nothing leaves the page while the question is open")
        self.page.click('#ui-prompt-modal [data-action="_uiPromptCancel"]')
        self.page.wait_for_selector("#ui-prompt-modal.active", state="detached", timeout=10000)
        self.page.wait_for_timeout(800)
        self.assertEqual((len(self.posts), self.queued()), (0, []), "No is an answer")

    def test_a_confirmed_rollback_queues_the_command_for_the_project_that_was_picked(self):
        directory = self.open_dialog()
        self.press()
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_function("() => document.getElementById('compose-result').textContent.indexOf('compose:rollback:') !== -1", timeout=20000)
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(json.loads(self.posts[0].post_data), {"action": "rollback", "dir": directory})
        self.assertEqual(self.queued(), ["compose:rollback:" + directory])
        self.assertIn("Queued: compose:rollback:" + directory, self.page.inner_text("#compose-result"))

    def test_a_host_whose_agent_does_not_say_it_can_is_refused_in_words_and_nothing_is_queued(self):
        devices = json.loads(json.dumps(self.devices0))
        devices[self.host_id]["sysinfo"].pop("compose_rollback")
        write("devices.json", devices)
        self.open_dialog()
        self.press()
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_function("() => document.getElementById('toast-container').textContent.indexOf('cannot roll back an update') !== -1", timeout=20000)
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.queued(), [])
        self.assertNotIn("Queued:", self.page.inner_text("#compose-result"))

    def test_the_button_its_tooltip_and_the_question_are_translated_in_all_six_languages(self):
        self.open_dialog()
        self.page.evaluate("async () => { await _ensureI18n(); }")     # the dictionary is a lazy module: an English page has not fetched it
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.mouse.move(1, 1)                          # the tooltip script takes the title off the element under the pointer
                got = self.page.eval_on_selector('#compose-modal [data-action="runCompose"][data-arg="rollback"]',
                                                 "b => [b.textContent.trim(), b.getAttribute('title') || b.getAttribute('data-title') || '']")
                for what, english, text in (("button", BUTTON, got[0]), ("tooltip", TITLE, got[1])):
                    if not text or text == english:
                        bad.append((lang, what, text))
                self.press()
                question = self.page.inner_text("#ui-prompt-message")
                if not question or question == QUESTION:
                    bad.append((lang, "question", question[:40]))
                self.page.click('#ui-prompt-modal [data-action="_uiPromptCancel"]')
                self.page.wait_for_selector("#ui-prompt-modal.active", state="detached", timeout=10000)
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])
        self.assertEqual(self.posts, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_dialog()
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
