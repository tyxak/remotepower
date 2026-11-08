#!/usr/bin/env python3
"""8.0.0: the host drawer's "Business services that depend on this host", on the demo seed in a browser.

GET /api/business-services/impact was written for a host's page and had none. The drawer now asks for it on every open: a host that is a part of a service lists it with its
state, a host that reaches a service only because another service holds it says so, a host in no service has no section, the name of a service is text and never markup, the
answer for the host that was open before does not paint over the one open now, a link opens the service's own dialog, every word has a translation and nothing broke.

The demo (packaging/seed-demo-data.py): jf01 is a part of Media, and Media is a part of Home services; ng01 is a part of Public website; gt01 is in none.
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
        raise unittest.SkipTest("the lists are backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-host-services-e2e-")
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
class TestTheHostDrawerListsItsServices(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.defs0 = read("business_services.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("business_services.json", cls.defs0)
        finally:
            cls.ctx.close()

    def setUp(self):
        write("business_services.json", self.defs0)

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          if (typeof closeDeviceDrawer === 'function') closeDeviceDrawer();
          if (window.__realApi) { window.api = window.__realApi; window.__realApi = null; }
          (window.__held || []).splice(0).forEach(release => release());
        }""")

    def open_drawer(self, dev_id):
        name = read("devices.json")[dev_id]["name"]
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", [dev_id, name])
        self.page.wait_for_function("() => /Online|Offline/.test(document.getElementById('drawer-device-sub').textContent)", timeout=30000)

    def rows(self):
        return self.page.evaluate("""() => [...document.querySelectorAll('#drawer-services-list > div')].map(r => ({
          name: r.querySelector('a').textContent, text: r.textContent.replace(/\\s+/g, ' ').trim()}))""")

    def wait_rows(self, n):
        self.page.wait_for_function("(n) => { const s = document.getElementById('drawer-services-section'); return s && !s.hidden && document.querySelectorAll('#drawer-services-list > div').length >= n; }", arg=n, timeout=30000)

    def test_a_host_lists_the_service_that_holds_it_and_the_service_that_holds_that_one(self):
        self.open_drawer("jf01")
        self.wait_rows(2)
        rows = self.rows()
        self.assertEqual([r["name"] for r in rows], ["Home services", "Media"], "sorted by name")
        media = [r for r in rows if r["name"] == "Media"][0]
        home = [r for r in rows if r["name"] == "Home services"][0]
        self.assertIn("Up", media["text"], "Media is up in the demo")
        self.assertNotIn("through another service", media["text"], "jf01 is a part of Media itself")
        self.assertIn("Degraded", home["text"])
        self.assertIn("through another service", home["text"], "Home services holds Media, not the host")

    def test_a_host_that_is_down_with_its_service_says_so(self):
        self.open_drawer("ng01")
        self.wait_rows(1)
        rows = self.rows()
        self.assertEqual([r["name"] for r in rows], ["Public website"])
        self.assertIn("Down", rows[0]["text"])

    def test_a_host_in_no_service_has_no_section(self):
        self.open_drawer("gt01")
        self.page.wait_for_timeout(1500)
        self.assertTrue(self.page.eval_on_selector("#drawer-services-section", "s => s.hidden"))
        self.assertEqual(self.page.eval_on_selector("#drawer-services-list", "b => b.children.length"), 0)

    def test_a_services_name_is_text_and_never_markup(self):
        defs = json.loads(json.dumps(self.defs0))
        sid = [k for k, v in defs.items() if v["name"] == "Public website"][0]
        defs[sid]["name"] = '<img src=x onerror="window.__pwned=1">Public'
        write("business_services.json", defs)
        self.open_drawer("ng01")
        self.wait_rows(1)
        self.assertEqual(self.page.eval_on_selector_all("#drawer-services-list img", "els => els.length"), 0)
        self.assertEqual(self.page.evaluate("() => window.__pwned || 0"), 0)
        self.assertIn("<img", self.rows()[0]["name"])

    def test_the_link_closes_the_drawer_and_opens_the_services_own_dialog(self):
        self.open_drawer("jf01")
        self.wait_rows(2)
        self.page.click('#drawer-services-list a:has-text("Media")')
        self.page.wait_for_selector("#bs-detail-modal.active", timeout=20000)
        self.page.wait_for_function("() => document.getElementById('bs-detail-title').textContent === 'Media'", timeout=20000)
        self.assertFalse(self.page.evaluate("() => document.getElementById('device-drawer') && document.getElementById('device-drawer').classList.contains('open')"), "the drawer is closed")
        self.assertGreaterEqual(self.page.eval_on_selector_all("#bs-detail-members tr", "els => els.length"), 3)

    def test_an_answer_for_the_host_that_was_open_before_does_not_paint_over_this_one(self):
        self.page.evaluate("""() => {
          window.__held = [];
          window.__realApi = window.api;
          window.api = function (m, p, ...rest) {
            const out = window.__realApi.call(this, m, p, ...rest);
            if (m !== 'GET' || !/device_id=jf01$/.test(p)) return out;
            return out.then(v => new Promise(r => window.__held.push(() => r(v))));
          };
        }""")
        self.page.evaluate("() => openDeviceDrawer('jf01', 'jellyfin.lab')")
        self.page.wait_for_function("() => window.__held.length >= 1", timeout=30000)
        self.page.evaluate("() => openDeviceDrawer('ng01', 'nginx.lab')")
        self.wait_rows(1)
        self.page.evaluate("() => window.__held.splice(0).forEach(release => release())")
        self.page.wait_for_timeout(1200)
        self.assertEqual([r["name"] for r in self.rows()], ["Public website"], "the answer of the host that was closed arrived late and was dropped")

    def test_another_hosts_services_are_not_left_under_this_hosts_name_while_its_own_are_on_the_way(self):
        self.open_drawer("jf01")
        self.wait_rows(2)
        self.page.evaluate("""() => {
          window.__held = [];
          window.__realApi = window.api;
          window.api = function (m, p, ...rest) {
            const out = window.__realApi.call(this, m, p, ...rest);
            if (m !== 'GET' || !/device_id=gt01$/.test(p)) return out;
            return out.then(v => new Promise(r => window.__held.push(() => r(v))));
          };
        }""")
        self.page.evaluate("() => openDeviceDrawer('gt01', 'gitea.lab')")
        self.page.wait_for_function("() => window.__held.length >= 1", timeout=30000)
        self.assertEqual(self.page.evaluate("() => [document.getElementById('drawer-services-section').hidden, document.querySelectorAll('#drawer-services-list > div').length]"), [True, 0],
                         "nothing of jf01 is on screen under gt01")

    def test_the_words_are_translated_in_all_six_languages(self):
        self.open_drawer("jf01")
        self.wait_rows(2)
        self.page.evaluate("async () => { await _ensureI18n(); }")      # the dictionary is a lazy module: an English page has not fetched it
        grab = """() => ({
          title: document.querySelector('#drawer-services-section .section-title').textContent,
          hint: document.querySelector('#drawer-services-section > .hint').textContent,
          via: document.querySelector('#drawer-services-list .hint').textContent,
          state: document.querySelector('#drawer-services-list > div span span:last-child').textContent})"""
        english = self.page.evaluate(grab)
        self.assertEqual(english["title"], "Business services that depend on this host")
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
        self.open_drawer("jf01")
        self.wait_rows(2)
        self.open_drawer("gt01")
        self.page.wait_for_timeout(800)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
