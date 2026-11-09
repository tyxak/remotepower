#!/usr/bin/env python3
"""8.0.0: the force-upgrade question says so when the agent cannot take the update, on the demo seed in a browser.

GET /api/agent-compat was written "so the UI can warn before an update queues a mismatch" and nothing asked it. The question now does, once, before it is shown: an agent a major
version ahead of the server would be put back to the server's build, one more than a major behind may need a fresh install, and every other agent gets the question it always
had. An answer that does not come (the route fails) leaves the question as it was. Refusing the question sends nothing; accepting it still sends the update.

The server's version is read from the code, and the three agent versions are worked out from its major: one major ahead (put back by the update), more than a major behind
(may need a fresh install) and one major behind (fine). Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import re
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
# the version of the server in this tree, read from the code: a literal here went stale at every version bump (the first failure of the 8.0.0 gate)
_SERVER = re.search(r"SERVER_VERSION = '([^']+)'", (_ROOT / "server" / "cgi-bin" / "api.py").read_text()).group(1)
_MAJOR = int(_SERVER.split(".")[0])
AHEAD = "%d.0.0" % (_MAJOR + 1)      # a major ahead of the server
BEHIND = "%d.0.0" % (_MAJOR - 3)     # more than a major behind
FINE = "%d.4.0" % (_MAJOR - 1)       # one major behind, which the update can take

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
        raise unittest.SkipTest("the lists are backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-agent-compat-e2e-")
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
class TestTheForceUpgradeQuestionKnowsTheAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors, cls.posts = ctx, ctx.new_page(), [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("request", lambda r: cls.posts.append(r.url.split("/api", 1)[-1]) if r.method == "POST" and r.url.endswith("/agent/force-upgrade") else None)
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.devices0 = read("devices.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("devices.json", cls.devices0)
        finally:
            cls.ctx.close()

    def setUp(self):
        write("devices.json", self.devices0)
        del self.posts[:]

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          if (typeof closeDeviceDrawer === 'function') closeDeviceDrawer();
          if (window.__realApi) { window.api = window.__realApi; window.__realApi = null; }
        }""")

    def with_version(self, dev_id, version):
        devices = json.loads(json.dumps(self.devices0))
        devices[dev_id]["version"] = version
        write("devices.json", devices)

    def ask(self, dev_id):
        """Press the drawer's Force-upgrade button and return the text of the question."""
        name = read("devices.json")[dev_id]["name"]
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", [dev_id, name])
        self.page.wait_for_function("() => /Online|Offline/.test(document.getElementById('drawer-device-sub').textContent)", timeout=30000)
        self.page.click('#drawer-tab-actions button:has-text("Force-upgrade")')
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=20000)
        return self.page.inner_text("#ui-prompt-message")

    def answer(self, yes):
        self.page.click("#ui-prompt-confirm" if yes else '#ui-prompt-modal [data-action="_uiPromptCancel"]')
        self.page.wait_for_selector("#ui-prompt-modal.active", state="detached", timeout=10000)
        self.page.wait_for_timeout(700)

    def test_an_agent_that_can_take_the_update_gets_the_question_it_always_had(self):
        self.with_version("gt01", FINE)
        text = self.ask("gt01")
        self.assertIn('Force-upgrade agent on "', text)
        self.assertNotIn("Not compatible", text)
        self.answer(False)
        self.assertEqual(self.posts, [], "refusing sends nothing")

    def test_an_agent_ahead_of_the_server_is_told_the_update_would_put_it_back(self):
        self.with_version("gt01", AHEAD)
        text = self.ask("gt01")
        self.assertIn("Not compatible with this server:", text)
        self.assertIn("agent %s is newer than server %s" % (AHEAD, _SERVER), text)
        self.assertIn("upgrade the server first", text)
        self.answer(False)
        self.assertEqual(self.posts, [])

    def test_an_agent_more_than_a_major_behind_is_told_to_reinstall(self):
        self.with_version("gt01", BEHIND)
        text = self.ask("gt01")
        self.assertIn("Not compatible with this server:", text)
        self.assertIn(">1 major behind", text)
        self.assertIn("reinstall the agent", text)
        self.answer(False)

    def test_the_warning_is_this_hosts_own(self):
        devices = json.loads(json.dumps(self.devices0))
        devices["gt01"]["version"] = AHEAD
        devices["jf01"]["version"] = FINE
        write("devices.json", devices)
        self.assertNotIn("Not compatible", self.ask("jf01"), "gt01's version is not jf01's")
        self.answer(False)

    def test_the_warning_is_not_a_refusal_accepting_still_sends_the_update(self):
        self.with_version("gt01", AHEAD)
        self.ask("gt01")
        self.answer(True)
        self.assertEqual(len(self.posts), 1)
        self.assertTrue(self.posts[0].endswith("/devices/gt01/agent/force-upgrade"), self.posts)

    def test_a_route_that_fails_leaves_the_question_as_it_was(self):
        self.with_version("gt01", AHEAD)
        self.page.evaluate("""() => {
          window.__realApi = window.api;
          window.api = function (m, p, ...rest) {
            if (m === 'GET' && p === '/agent-compat') return Promise.reject(new Error('down'));
            return window.__realApi.call(this, m, p, ...rest);
          };
        }""")
        text = self.ask("gt01")
        self.assertIn('Force-upgrade agent on "', text)
        self.assertNotIn("Not compatible", text)
        self.answer(False)

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.with_version("gt01", AHEAD)
        self.ask("gt01")
        self.answer(False)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
