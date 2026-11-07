#!/usr/bin/env python3
"""8.0.0: the public demo in a browser. A seed made the way install-demo.sh makes it (`--look pilot --typeface b612`) is drawn in the
Pilot look with B612 for someone who has never been here, on the sign-in page and after it, and a person's own choice still wins.

What is read is what the page does, not what a setting says: the attributes the stylesheet reads on <body> (`data-look`,
`data-typeface`, `data-theme`), the font family the browser resolves for the page, whether the B612 files were fetched and loaded,
and, for the look, the hero that only Pilot draws on Home. A fresh browser context with nothing in localStorage is what a
first-time visitor is. The sign-in page has no account, so it can learn the default only from the unauthenticated
/api/public-info; a version that applied it only after /api/me would pass every test that signs in first, which is why the first
test does not.

* a first visit: the sign-in page is Pilot, B612 and the Pilot palette, and the font files are fetched;
* the next visit: the browser's copy draws the same page even when /api/public-info cannot be reached;
* signed in: still Pilot and B612, Home draws the hero, My Account shows what the page uses, and the account has stored nothing (a
  default is not a choice);
* an account that chose Classic and the system font gets them, after a reload too, and gets the default back when it chooses nothing;
* Settings > Branding shows the default, a change reaches the page at once and the next visitor's sign-in page, and it is no lock.

The filename carries 'e2e', so make test-fast skips it; the serial gate runs it. Self-skips without playwright / Chromium /
gunicorn, and runs under the default storage backend only.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402
from test_v749_typeface_font import PINS  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False

_ROOT = Path(__file__).resolve().parent.parent
# RP_BROWSER_REQUIRE turns "no browser here" from a silent pass into a failure, so it is part of the class condition
# (tests/test_ci_green_parity.py holds the shape).
_GATE = browser_available() or browser_required.required()

# the system stack as the browser reports it (Chromium writes the quotes with double marks)
SYSTEM_STACK = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'

STATE = """() => {
  const b = document.body;
  const faces = [...document.fonts].filter(f => f.family.replace(/['"]/g, '') === 'B612').map(f => f.weight + ':' + f.status);
  return { look: b.dataset.look || null, face: b.dataset.typeface || null, theme: b.dataset.theme || null,
           copy: [localStorage.getItem('rp_look'), localStorage.getItem('rp_typeface')],
           family: getComputedStyle(b).fontFamily, faces };
}"""

# Home's hero is drawn for Pilot only: under Classic the host is empty and hidden
HERO = """() => { const h = document.getElementById('home-hero');
  return h ? { hidden: h.hidden, ready: h.classList.contains('is-ready'), dots: h.querySelectorAll('.pilot-hero .pilot-dot').length } : null; }"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheDemoLooksNew(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("the default is backend-agnostic: measured once, under the default backend")
        if not _HAVE_PLAYWRIGHT:
            browser_required.skip_or_fail("playwright is not installed")
        seeder = _ROOT / "packaging" / "seed-demo-data.py"
        if not seeder.is_file():
            raise unittest.SkipTest("demo seeder not in this tree")
        data_dir = tempfile.mkdtemp(prefix="rp-demo-look-e2e-")
        # the flags the installer passes to the first seed and to the unit that re-seeds the demo
        proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply", "--look", "pilot", "--typeface", "b612"],
                              capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail("chromium not available: %s" % exc)
        try:
            cls.base, shutdown = start_stack(data_dir=data_dir)
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest("app stack not available: %s" % exc)
        cls._stop = [shutdown]                                   # in a list: a function kept on the class would be a method

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._stop[0]()

    # ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def setUp(self):
        self.errors = {}                                         # per page: what it threw
        self.failed = {}                                         # per page: the requests that did not complete

    def visit(self, user=None, block_public_info=False):
        """A first-time visitor's browser (nothing stored, the product tour waved off); signed in when a user is named."""
        ctx = self.browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        self.addCleanup(ctx.close)
        page = ctx.new_page()
        self.errors[id(page)] = []
        self.failed[id(page)] = []
        page.on("pageerror", lambda e: self.errors[id(page)].append(str(e)))
        page.on("requestfailed", lambda r: self.failed[id(page)].append(r.url))
        if block_public_info:
            ctx.route("**/api/public-info", lambda r: r.abort())
        page.goto(self.base + "/index.html")
        if user:
            self.sign_in(page, user)
        return page

    def sign_in(self, page, user):
        page.wait_for_selector("#login-form")
        page.fill("#login-user", user)                           # the seeder builds its own operator accounts: there is no 'admin'
        page.fill("#login-pass", "demo")
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector("#app", state="visible", timeout=90000)
        page.wait_for_timeout(3500)

    def reload(self, page):
        page.reload()
        page.wait_for_selector("#app", state="visible", timeout=90000)
        page.wait_for_timeout(3500)

    def api(self, page, method, path, body=None):
        # the page's api() sends a body whenever it is given one, and a GET may not have any: pass it only when there is one
        if body is None:
            return page.evaluate("async ([m, p]) => await api(m, p)", [method, path])
        return page.evaluate("async ([m, p, b]) => await api(m, p, b)", [method, path, body])

    def state(self, page):
        return page.evaluate(STATE)

    def settled(self, page, look, face, seconds=20):
        """The page's state once it is (look, face), or the last state read when it never gets there: a failed wait is then an
        assertion that shows what the page was, not a timeout."""
        deadline = time.time() + seconds
        s = self.state(page)
        while (s["look"], s["face"]) != (look, face) and time.time() < deadline:
            time.sleep(0.25)
            s = self.state(page)
        return s

    def config_value(self, page, key, want, seconds=30):
        """The configuration's `key` once it is `want`, or the last value read. Polled from here: a page.wait_for_function whose
        predicate is async returns at once, because the promise it gets back is already truthy."""
        deadline = time.time() + seconds
        got = self.api(page, "GET", "/config").get(key)
        while got != want and time.time() < deadline:
            time.sleep(0.4)
            got = self.api(page, "GET", "/config").get(key)
        return got

    def font_requests(self, page):
        return sorted({u.rsplit("/", 1)[-1] for u in self.requested(page) if "/vendor/fonts/" in u})

    def requested(self, page):
        return page.evaluate("() => performance.getEntriesByType('resource').map(e => e.name)")

    def loaded_faces(self, page, at_least):
        page.wait_for_function("n => [...document.fonts].filter(f => f.family.replace(/['\\\"]/g, '') === 'B612'"
                               " && f.status === 'loaded').length >= n", arg=at_least, timeout=30000)

    def public_info(self):
        with urllib.request.urlopen(self.base + "/api/public-info", timeout=30) as r:
            return json.loads(r.read().decode())

    def account(self, page):
        page.evaluate("showPage('account')")
        page.wait_for_selector("#acct-look button", timeout=30000)
        page.wait_for_selector("#acct-typeface", state="visible", timeout=30000)

    def flush(self, page):
        page.wait_for_timeout(1800)                              # the prefs are posted 600 ms after the last change

    def home(self, page):
        """Home, drawn: the page reopens on the last page a person had open, and a hero in a page that is not showing is hidden."""
        page.evaluate("showPage('home')")
        page.wait_for_selector("#page-home.active", timeout=30000)
        page.wait_for_function("() => { const t = document.getElementById('home-tiles'); return !!t && t.children.length > 0; }", timeout=30000)

    def wait_hero(self, page):
        page.wait_for_selector("#home-hero.is-ready", state="visible", timeout=30000)

    # ── before anyone has signed in ──────────────────────────────────────────────────────────────────────────────────────────
    def test_a_first_visit_to_the_sign_in_page_is_pilot_and_b612(self):
        page = self.visit()
        s = self.settled(page, "pilot", "b612")
        self.assertEqual((s["look"], s["face"]), ("pilot", "b612"), s)
        self.assertEqual(s["theme"], "pilot", "the look brings its own dark palette, not Midnight: %s" % s)
        self.assertTrue(s["family"].startswith("B612, "), s["family"])
        self.loaded_faces(page, 1)
        fetched = self.font_requests(page)
        self.assertTrue(fetched, "no B612 file was fetched for a first-time visitor")
        self.assertTrue(set(fetched) <= set(PINS), fetched)
        self.assertEqual(s["copy"], ["pilot", "b612"], "the browser keeps a copy, so the next visit is drawn right away")
        self.assertFalse(page.is_visible("#app"), "nobody has signed in")
        self.assertEqual(self.errors[id(page)], [])

    def test_the_next_visit_is_drawn_from_the_browsers_copy_even_when_the_server_cannot_be_asked(self):
        page = self.visit()
        self.assertEqual(self.settled(page, "pilot", "b612")["copy"], ["pilot", "b612"])
        # the same browser, the endpoint refusing: the sign-in page must not fall back to Classic and the system font
        page.context.route("**/api/public-info", lambda r: r.abort())
        page.reload()
        page.wait_for_selector("#login-form")
        page.wait_for_timeout(2500)
        self.assertTrue([u for u in self.failed[id(page)] if u.endswith("/api/public-info")], "the endpoint was not asked: no control")
        s = self.state(page)
        self.assertEqual((s["look"], s["face"], s["theme"]), ("pilot", "b612", "pilot"), s)

    def test_the_endpoint_the_sign_in_page_asks_carries_the_default_and_no_lock(self):
        info = self.public_info()
        self.assertEqual((info["look"], info["typeface"], info["look_locked"]), ("pilot", "b612", False))

    # ── signed in ────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_signed_in_it_is_still_pilot_home_draws_the_hero_and_nothing_was_stored(self):
        page = self.visit("alice")
        s = self.settled(page, "pilot", "b612")
        self.assertEqual((s["look"], s["face"], s["theme"]), ("pilot", "b612", "pilot"), s)
        self.loaded_faces(page, 2)
        self.wait_hero(page)
        hero = page.evaluate(HERO)
        self.assertEqual((hero["hidden"], hero["ready"]), (False, True))
        self.assertGreater(hero["dots"], 0, "the hero has a dot for each host of the seeded fleet")
        self.account(page)
        self.assertEqual(page.eval_on_selector("#acct-typeface", "e => e.value"), "b612", "the picker shows what the page uses")
        self.assertEqual(page.eval_on_selector("#acct-look .look-card.sel .tc-name", "e => e.textContent.trim()"), "Pilot")
        prefs = self.api(page, "GET", "/ui-prefs")
        self.assertNotIn("look", prefs, "a default is not the account's choice")
        self.assertNotIn("typeface", prefs, "a default is not the account's choice")
        self.assertEqual(self.errors[id(page)], [])

    def test_an_account_that_chose_classic_and_the_system_font_gets_them_and_the_default_back_when_it_chooses_nothing(self):
        page = self.visit("bob")
        before = self.api(page, "GET", "/ui-prefs")
        self.assertNotIn("look", before)
        self.addCleanup(lambda: self.api(page, "POST", "/ui-prefs", before))      # the account goes back to what it had
        self.assertEqual((self.state(page)["look"], self.state(page)["face"]), ("pilot", "b612"))
        self.account(page)
        page.click('#acct-look button[data-arg="classic"]')
        page.select_option("#acct-typeface", "system")
        self.flush(page)
        stored = self.api(page, "GET", "/ui-prefs")
        self.assertEqual((stored.get("look"), stored.get("typeface")), ("classic", "system"), "the choice is the account's, stored")
        self.reload(page)
        s = self.state(page)
        self.assertEqual((s["look"], s["face"], s["family"]), ("classic", None, SYSTEM_STACK), s)
        self.assertNotEqual(s["theme"], "pilot", s)
        self.home(page)                                          # Home has drawn: the control that "no hero" is not "not drawn yet"
        self.assertEqual(page.evaluate(HERO), {"hidden": True, "ready": False, "dots": 0}, "Classic draws no hero")
        # choosing nothing is the default again, after a reload too
        self.api(page, "POST", "/ui-prefs", before)
        self.reload(page)
        s = self.settled(page, "pilot", "b612")
        self.assertEqual((s["look"], s["face"], s["theme"]), ("pilot", "b612", "pilot"), s)
        self.home(page)
        self.wait_hero(page)
        self.assertEqual(self.errors[id(page)], [])

    # ── the setting behind it ────────────────────────────────────────────────────────────────────────────────────────────────
    def test_settings_branding_shows_the_default_and_a_change_reaches_the_page_and_the_next_visitor(self):
        page = self.visit("alice")
        self.addCleanup(lambda: self.api(page, "POST", "/config", {"brand_typeface": "b612"}))     # the demo goes back to its default
        page.evaluate("showPage('settings')")
        page.wait_for_selector("#cfg-brand-typeface", state="attached", timeout=30000)
        page.evaluate("switchSettingsTab('advanced')")
        page.wait_for_selector("#cfg-brand-typeface", state="visible", timeout=30000)
        page.wait_for_function("() => document.getElementById('cfg-brand-typeface').value === 'b612'", timeout=30000)
        self.assertEqual(page.eval_on_selector_all("#cfg-brand-typeface option", "els => els.map(e => e.value)"), ["", "system", "b612"])
        self.assertEqual(page.eval_on_selector("#cfg-brand-look", "e => e.value"), "pilot")
        self.assertFalse(page.eval_on_selector("#cfg-brand-look-locked", "e => e.checked"), "the demo default is not a lock")
        page.select_option("#cfg-brand-typeface", "system")
        page.click('[data-action="saveBranding"]')
        self.assertEqual(self.config_value(page, "brand_typeface", "system"), "system", "the save did not reach the server")
        # the page that saved it follows at once (the account has chosen nothing)
        s = self.settled(page, "pilot", None)
        self.assertEqual((s["look"], s["face"], s["family"]), ("pilot", None, SYSTEM_STACK), s)
        # and the next visitor, before anyone has signed in
        self.assertEqual((self.public_info()["look"], self.public_info()["typeface"]), ("pilot", "system"))
        other = self.visit()
        s = self.settled(other, "pilot", None)
        self.assertEqual((s["look"], s["face"], s["family"]), ("pilot", None, SYSTEM_STACK), s)
        self.assertEqual(self.errors[id(page)] + self.errors[id(other)], [])


if __name__ == "__main__":
    unittest.main()
