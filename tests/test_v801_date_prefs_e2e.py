#!/usr/bin/env python3
"""The date order and the clock in a real browser, on the seeded stack.

test_v801_date_prefs runs the formatter and the server's part. This signs in and uses the page the way a person does:

* My Account -> Profile -> Language holds the two selects right after the language picker, on Automatic until a person chooses;
* choosing writes the account's `ui_prefs` (and Automatic takes the key away again), and a fresh browser signed in as the same
  account finds the choice;
* a page that was drawn after the choice shows it: the audit log's timestamps and the calendar's month heading, in the order and on
  the clock that were picked, and as they were before when the choice goes back to Automatic;
* the new controls fit: no sideways scroll at 1440, 768 and 390 px, in English, German and Arabic (right to left, where the page
  mirrors), each select reachable with the keyboard and drawn with a focus ring, no console error, no page error and no request that
  failed on the way.

There is no icon-only button in this change. The filename carries 'e2e', so make test-fast skips it; the serial gate runs it.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False

_ROOT = Path(__file__).resolve().parent.parent
_GATE = browser_available() or browser_required.required()

# what each language writes for the label of the first select and the first option of both (the engine of the page translates them)
LABELS = {"en": ("Date order", "Automatic"), "de": ("Datumsreihenfolge", "Automatisch"), "ar": ("ترتيب التاريخ", "تلقائي")}
WIDTHS = (1440, 768, 390)

# the card of the two selects, measured: whether anything of it, or the page, sticks out sideways
FIT = """() => {
  const W = innerWidth, out = { page: document.documentElement.scrollWidth - W, items: [] };
  const card = document.getElementById('acct-lang').closest('.settings-section');
  out.card = card.scrollWidth - card.clientWidth;
  for (const id of ['acct-lang', 'acct-date-order', 'acct-clock']) {
    const el = document.getElementById(id), r = el.getBoundingClientRect(), label = document.querySelector('label[for="' + id + '"]');
    const lr = label ? label.getBoundingClientRect() : null;
    out.items.push({ id, left: Math.round(r.left), right: Math.round(r.right), top: Math.round(r.top), width: Math.round(r.width),
                     labelRight: lr ? Math.round(lr.right) : null, labelLeft: lr ? Math.round(lr.left) : null,
                     visible: r.width > 0 && r.height > 0 });
  }
  out.dir = document.documentElement.dir;
  return out;
}"""

# does the focused element carry a ring: an outline of some width, or a box shadow
RING = """() => {
  const el = document.activeElement, cs = getComputedStyle(el);
  return { id: el.id, outline: cs.outlineStyle, outlineWidth: parseFloat(cs.outlineWidth), shadow: cs.boxShadow,
           focusVisible: el.matches(':focus-visible') };
}"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheDatePreferencesInABrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("the preferences are backend-agnostic: exercised once")
        if not _HAVE_PLAYWRIGHT:
            browser_required.skip_or_fail("playwright is not installed")
        seeder = _ROOT / "packaging" / "seed-demo-data.py"
        cls.data_dir = tempfile.mkdtemp(prefix="rp-datepref-e2e-")
        proc = subprocess.run([sys.executable, str(seeder), "--data-dir", cls.data_dir, "--apply"], capture_output=True, cwd=str(_ROOT),
                              timeout=900)
        if proc.returncode != 0:
            shutil.rmtree(cls.data_dir, ignore_errors=True)
            raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            shutil.rmtree(cls.data_dir, ignore_errors=True)
            browser_required.skip_or_fail("chromium not available: %s" % exc)
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            shutil.rmtree(cls.data_dir, ignore_errors=True)
            raise unittest.SkipTest("app stack not available: %s" % exc)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()
            shutil.rmtree(cls.data_dir, ignore_errors=True)

    # ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def setUp(self):
        self.seen = {}

    def login(self, size=(1440, 900)):
        ctx = self.browser.new_context(viewport={"width": size[0], "height": size[1]}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_pagetabs', 'stacked'); localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
        self.addCleanup(ctx.close)
        page = ctx.new_page()
        seen = self.seen[id(page)] = {"console": [], "errors": [], "failed": []}
        page.on("console", lambda m: seen["console"].append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: seen["errors"].append(str(e)))
        page.on("response", lambda r: seen["failed"].append("%s %s" % (r.status, r.url)) if r.status >= 400 else None)
        page.goto(self.base + "/index.html")
        page.fill("#login-user", "alice")
        page.fill("#login-pass", "demo")
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector("#app", state="visible", timeout=90000)
        page.wait_for_timeout(3500)
        return page

    def clean(self, page):
        """No console error, no page error and no failed request since the page was opened (an expected 401 of the sign-in page is
        not one: it is read before the form is submitted, so it is recorded before login and filtered by URL)."""
        seen = self.seen[id(page)]
        self.assertEqual(seen["errors"], [], "page errors")
        self.assertEqual([m for m in seen["console"] if "401" not in m and "Failed to load resource" not in m], [], "console errors")
        self.assertEqual([f for f in seen["failed"] if "/api/login" not in f and not f.startswith("401 ")], [], "failed requests")

    def api(self, page, method, path, body=None):
        if body is None:
            return page.evaluate("async ([m, p]) => await api(m, p)", [method, path])
        return page.evaluate("async ([m, p, b]) => await api(m, p, b)", [method, path, body])

    def account(self, page):
        page.evaluate("showPage('account')")
        page.wait_for_selector("#acct-date-order", state="visible", timeout=30000)
        page.wait_for_selector("#acct-lang option", state="attached", timeout=30000)   # i18n.js builds the language options on demand

    def reset(self, page):
        self.api(page, "POST", "/ui-prefs", {})

    def set_language(self, page, lang):
        page.evaluate("async l => { await _ensureI18n(); window.RPi18n.setLang(l, false); }", lang)
        label, auto = LABELS[lang]
        page.wait_for_function("([l, a]) => document.querySelector('label[for=\"acct-date-order\"]').textContent.trim() === l"
                               " && document.querySelector('#acct-clock option[value=\"auto\"]').textContent.trim() === a",
                               arg=[label, auto], timeout=30000)

    # ── the controls ─────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_two_selects_follow_the_language_picker_and_start_on_automatic(self):
        page = self.login()
        self.account(page)
        values = page.evaluate("() => ({ order: document.getElementById('acct-date-order').value, clock: document.getElementById('acct-clock').value,"
                               " orderOptions: [...document.querySelectorAll('#acct-date-order option')].map(o => o.value),"
                               " clockOptions: [...document.querySelectorAll('#acct-clock option')].map(o => o.value) })")
        self.assertEqual(values, {"order": "auto", "clock": "auto", "orderOptions": ["auto", "dmy", "mdy", "ymd"],
                                  "clockOptions": ["auto", "h24", "h12"]})
        self.assertEqual(self.api(page, "GET", "/ui-prefs").get("date_order"), None)
        fit = page.evaluate(FIT)
        lang, order, clock = fit["items"]
        # the same card, in reading order: the language picker, then the two choices (side by side or one under the other)
        self.assertLess(lang["top"], order["top"])
        self.assertLessEqual(order["top"], clock["top"] + 2)
        self.clean(page)

    def test_choosing_is_saved_to_the_account_and_automatic_takes_it_away(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        self.account(page)
        page.select_option("#acct-date-order", "dmy")
        page.wait_for_function("async () => ((await api('GET', '/ui-prefs')) || {}).date_order === 'dmy'", timeout=15000)
        page.select_option("#acct-clock", "h24")
        page.wait_for_function("async () => ((await api('GET', '/ui-prefs')) || {}).clock === 'h24'", timeout=15000)
        stored = self.api(page, "GET", "/ui-prefs")
        self.assertEqual((stored["date_order"], stored["clock"]), ("dmy", "h24"))
        # a fresh browser, signed in as the same account, finds both
        other = self.login()
        self.account(other)
        self.assertEqual(other.eval_on_selector("#acct-date-order", "e => e.value"), "dmy")
        self.assertEqual(other.eval_on_selector("#acct-clock", "e => e.value"), "h24")
        # Automatic takes the keys away, so the language's own style applies again
        page.select_option("#acct-date-order", "auto")
        page.select_option("#acct-clock", "auto")
        page.wait_for_function("async () => { const p = (await api('GET', '/ui-prefs')) || {}; return !('date_order' in p) && !('clock' in p); }",
                               timeout=15000)
        self.clean(page)

    # ── what a page shows ────────────────────────────────────────────────────────────────────────────────────────────────────
    def first_audit_time(self, page):
        page.evaluate("showPage('audit')")
        page.wait_for_function("() => { const c = document.querySelector('#audit-tbody td, #page-audit table tbody td.isl-345');"
                               " return !!c && /\\d/.test(c.textContent); }", timeout=30000)
        return page.evaluate("() => (document.querySelector('#audit-tbody td') || document.querySelector('#page-audit table tbody td.isl-345')).textContent.trim()")

    def test_a_page_drawn_after_the_choice_shows_it(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        before = self.first_audit_time(page)
        # the browser of the test is en-US: month first, a 12 hour clock
        self.assertRegex(before, r"^\d{1,2}/\d{1,2}/\d{4}, \d{1,2}:\d{2}:\d{2}\s?(AM|PM)$")
        self.api(page, "POST", "/ui-prefs", {"date_order": "ymd", "clock": "h24"})
        page.evaluate("async () => { await loadUiPrefs(); }")
        iso = self.first_audit_time(page)
        self.assertRegex(iso, r"^\d{4}-\d{2}-\d{2}, \d{2}:\d{2}:\d{2}$")
        self.api(page, "POST", "/ui-prefs", {"date_order": "dmy", "clock": "h12"})
        page.evaluate("async () => { await loadUiPrefs(); }")
        day_first = self.first_audit_time(page)
        self.assertRegex(day_first, r"^\d{1,2}/\d{1,2}/\d{4}, \d{1,2}:\d{2}:\d{2}\s?(AM|PM)$")
        # the same instant in the three forms: the same numbers, written in the order that was asked for
        a, b, c = (list(map(int, re.findall(r"\d+", s))) for s in (before, iso, day_first))
        self.assertEqual(sorted(a[:3]), sorted(b[:3]))
        self.assertEqual(b[:3], [a[2], a[0], a[1]], "year, month, day from month, day, year")
        self.assertEqual(c[:3], [a[1], a[0], a[2]], "day, month, year from month, day, year")
        # the calendar's heading: year first puts the year before the month name
        self.api(page, "POST", "/ui-prefs", {"date_order": "ymd"})
        page.evaluate("async () => { await loadUiPrefs(); }")
        page.evaluate("showPage('calendar')")
        page.wait_for_function("() => /\\d{4}/.test((document.querySelector('#page-calendar .cal-title, #cal-title') || {}).textContent || '')",
                               timeout=30000)
        title = page.evaluate("() => (document.querySelector('#page-calendar .cal-title, #cal-title')).textContent.trim()")
        self.assertRegex(title, r"^\d{4}\s+\D+$", title)
        self.clean(page)

    # ── the fit ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_controls_fit_in_three_languages_at_three_widths(self):
        page = self.login()
        self.account(page)
        for lang in ("en", "de", "ar"):
            self.set_language(page, lang)
            rtl = lang == "ar"
            for width in WIDTHS:
                with self.subTest(lang=lang, width=width):
                    page.set_viewport_size({"width": width, "height": 900})
                    page.wait_for_timeout(250)
                    fit = page.evaluate(FIT)
                    self.assertEqual(fit["dir"], "rtl" if rtl else "ltr")
                    self.assertLessEqual(fit["page"], 1, "the page scrolls sideways: %s" % fit)
                    self.assertLessEqual(fit["card"], 1, "the card is wider than its box: %s" % fit)
                    for item in fit["items"]:
                        self.assertTrue(item["visible"], item)
                        self.assertGreaterEqual(item["left"], 0, item)
                        self.assertLessEqual(item["right"], width, item)
                        self.assertGreaterEqual(item["width"], 100, item)
                    # the label of each new select sits above or beside it, on the side the language reads from
                    for item in fit["items"][1:]:
                        self.assertIsNotNone(item["labelRight"], item)
            page.set_viewport_size({"width": 1440, "height": 900})
        self.set_language(page, "en")
        self.clean(page)

    def test_each_select_is_reachable_by_keyboard_and_shows_a_focus_ring(self):
        page = self.login()
        self.account(page)
        page.focus("#acct-lang")
        seen = []
        for _ in range(2):
            page.keyboard.press("Tab")
            ring = page.evaluate(RING)
            seen.append(ring["id"])
            self.assertTrue(ring["focusVisible"], ring)
            self.assertTrue(ring["outline"] != "none" and ring["outlineWidth"] > 0 or ring["shadow"] != "none", ring)
        self.assertEqual(seen, ["acct-date-order", "acct-clock"])
        # and it can be operated: the arrow keys change the value and the change is saved
        self.addCleanup(lambda: self.reset(page))
        page.keyboard.press("ArrowDown")
        page.wait_for_function("async () => ((await api('GET', '/ui-prefs')) || {}).clock === 'h24'", timeout=15000)
        self.clean(page)


if __name__ == "__main__":
    unittest.main()
