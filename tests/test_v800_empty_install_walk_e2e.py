#!/usr/bin/env python3
"""8.0.0: every sidebar page of an EMPTY install, walked once: no blank table, no loader that never ends, no failure message, no failed request, no script error.

The demo-seeded walks (axe, box overflow, icon gap, click sweep on the seed) see pages full of rows; the click sweep that runs on an empty fleet only presses buttons. Nothing
looked at what a person sees on the first day, with nothing configured. A survey did, over 79 pages, and found one table with its header and nothing else: the DNS records
table before a provider has credentials. A first-day page that says nothing about why it is empty reads as broken, so this holds it at zero.

What counts, for a page that is on screen once its own loaders have had their turn:
  blank table      a table nobody can miss (on screen, not inside a closed <details>) whose body has no text at all
  loader that stays  the word Loading still on the page after the wait
  failure message  "Failed to load", "Could not load" or "Error loading" in the page's text
  failed request   a response of 400 or more from /api (the walk itself asks for nothing the install cannot answer)
  script error     an uncaught error on the page

PAGES_NOT_ON_SCREEN lists the pages an empty install does not show (a module that is off until it is switched on), each with its reason; an entry that turns up on screen fails the
walk, so the list only gets shorter. The walk proves it sees: it finds the empty DNS message (a table it must read), and it flags a blank table planted on a page. Self-skips
without playwright / Chromium / gunicorn.
"""
import json
import os
import re
import sys
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

PAGES_NOT_ON_SCREEN = {
    "sshgw": "the SSH gateway is an optional daemon; its page is hidden until the gateway is switched on",
}

# one scan of a page: what is on screen right now. Read twice by the control, so it is a string and not a method.
SCAN = """(pg) => {
  const root = document.getElementById('page-' + pg);
  const onScreen = el => {
    const r = el.getBoundingClientRect();
    if (!(r.width > 0 && r.height > 0)) return false;
    if (getComputedStyle(el).visibility === 'hidden') return false;
    const d = el.closest('details');
    return !(d && !d.open);
  };
  const blank = [];
  for (const t of root.querySelectorAll('table')) {
    if (!onScreen(t)) continue;
    const rows = [...t.querySelectorAll('tbody tr')];
    if (rows.length === 0 || rows.map(r => r.textContent.trim()).join('') === '')
      blank.push((t.id || (t.closest('[id]') || {}).id || '?') + ' (' + t.querySelectorAll('thead th').length + ' columns)');
  }
  const text = root.innerText || '';
  return {
    blank,
    loading: (text.match(/Loading[^\\n]{0,30}/g) || []).slice(0, 3),
    failed: (text.match(/(Failed to load|Could not load|Error loading)[^\\n]{0,60}/gi) || []).slice(0, 3),
    chars: text.length,
  };
}"""


def _sidebar_pages():
    html = (_ROOT / "server" / "html" / "index.html").read_text()
    pages = []
    for m in re.finditer(r'class="nav-btn[^"]*" data-page="([a-z-]+)"', html):
        if m.group(1) not in pages:
            pages.append(m.group(1))
    return pages


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what a page says on a first day does not depend on the storage backend: measured once, under the default one")
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail("chromium not available: %s" % exc)
        return
    try:
        base, shutdown = start_stack()
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest("app stack not available: %s" % exc)
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown)


def tearDownModule():
    try:
        _STATE["browser"].close()
        _STATE["pw"].stop()
    finally:
        if _STATE.get("shutdown"):
            _STATE["shutdown"]()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestAnEmptyInstallSaysWhyEachPageIsEmpty(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page = ctx, ctx.new_page()
        cls.errors, cls.failed_requests = [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("response", lambda r: cls.failed_requests.append("%s %s" % (r.status, r.url.split("/api", 1)[-1].split("?")[0])) if r.status >= 400 and "/api/" in r.url else None)
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "admin")                # a fresh data directory has the one default account
        cls.page.fill("#login-pass", "remotepower")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=60000)
        cls.page.evaluate("document.getElementById('tour-backdrop')?.remove(); document.getElementById('tour-pop')?.remove();")
        cls.page.wait_for_timeout(2500)
        cls.walk = cls._walk()

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    @classmethod
    def _settle(cls):
        """Give the page's own loaders their turn: until no 'Loading' is on screen, at most three seconds, then a beat for what they drew."""
        try:
            cls.page.wait_for_function("() => !/Loading/.test(document.querySelector('.page.active, .page:not(.d-none)') ? '' : '')", timeout=100)
        except Exception:
            pass
        deadline = 3000
        waited = 0
        while waited < deadline:
            if not cls.page.evaluate("() => /Loading/.test(document.body.innerText)"):
                break
            cls.page.wait_for_timeout(250)
            waited += 250
        cls.page.wait_for_timeout(400)

    @classmethod
    def _walk(cls):
        out = {}
        for pg in _sidebar_pages():
            del cls.errors[:]
            del cls.failed_requests[:]
            cls.page.evaluate("(p) => { const b = document.querySelector(`.nav-btn[data-page='${p}']`); if (b) b.click(); }", pg)
            try:
                cls.page.wait_for_selector("#page-" + pg, state="visible", timeout=4000)
            except Exception:
                out[pg] = {"on_screen": False}
                continue
            cls._settle()
            res = cls.page.evaluate(SCAN, pg)
            res.update(on_screen=True, requests=sorted(set(cls.failed_requests)), errors=[e[:140] for e in cls.errors])
            out[pg] = res
        return out

    def test_the_walk_saw_the_pages_and_the_pages_that_are_not_on_screen_are_the_listed_ones(self):
        walked = [p for p, r in self.walk.items() if r["on_screen"]]
        self.assertGreater(len(walked), 70, "the walk looked at the pages: %d of %d" % (len(walked), len(self.walk)))
        hidden = sorted(p for p, r in self.walk.items() if not r["on_screen"])
        self.assertEqual(hidden, sorted(PAGES_NOT_ON_SCREEN), "a page that is not on screen is listed with its reason; a listed one that is now on screen is taken off the list")

    def test_no_page_has_a_blank_table(self):
        bad = {p: r["blank"] for p, r in self.walk.items() if r["on_screen"] and r["blank"]}
        self.assertEqual(bad, {}, "a table with its header and nothing under it")

    def test_no_page_still_says_loading_after_its_loaders_have_run(self):
        bad = {p: r["loading"] for p, r in self.walk.items() if r["on_screen"] and r["loading"]}
        self.assertEqual(bad, {})

    def test_no_page_says_it_failed_to_load_on_a_fresh_install(self):
        bad = {p: r["failed"] for p, r in self.walk.items() if r["on_screen"] and r["failed"]}
        self.assertEqual(bad, {})

    def test_no_page_asks_for_something_the_install_cannot_answer(self):
        bad = {p: r["requests"] for p, r in self.walk.items() if r["on_screen"] and r["requests"]}
        self.assertEqual(bad, {})

    def test_no_page_throws(self):
        bad = {p: r["errors"] for p, r in self.walk.items() if r["on_screen"] and r["errors"]}
        self.assertEqual(bad, {})

    def test_the_dns_table_says_what_to_do_before_a_provider_has_credentials(self):
        self.page.evaluate("() => { const b = document.querySelector(\".nav-btn[data-page='dns']\"); if (b) b.click(); }")
        self.page.wait_for_selector("#page-dns", state="visible", timeout=10000)
        self.page.wait_for_function("() => /No zone to list yet/.test(document.getElementById('dns-tbody').textContent)", timeout=10000)
        self.assertEqual(self.page.inner_text("#dns-tbody").strip(), "No zone to list yet. Give the provider credentials, then pick a zone.")

    def test_the_dns_table_says_so_when_the_token_sees_no_zone(self):
        """The other way to get here: the provider has credentials, the zone list comes back empty, and the records are asked for with no zone chosen."""
        self.page.evaluate("() => { const b = document.querySelector(\".nav-btn[data-page='dns']\"); if (b) b.click(); }")
        self.page.wait_for_selector("#page-dns", state="visible", timeout=10000)
        self.page.evaluate("""async () => {
          document.getElementById('dns-tbody').innerHTML = '';
          document.getElementById('dns-zone').innerHTML = '';
          await loadDnsRecords();
        }""")
        self.assertEqual(self.page.inner_text("#dns-tbody").strip(), "No zone to list yet. Give the provider credentials, then pick a zone.")

    def test_the_scan_flags_a_blank_table_when_one_is_on_screen_and_not_one_in_a_closed_details(self):
        """Without this a scan that looked at nothing would pass. A table with a header and an empty body is planted on the page being scanned."""
        self.page.evaluate("() => { const b = document.querySelector(\".nav-btn[data-page='dns']\"); if (b) b.click(); }")
        self.page.wait_for_selector("#page-dns", state="visible", timeout=10000)
        self.page.evaluate("""() => {
          const root = document.getElementById('page-dns');
          root.insertAdjacentHTML('beforeend',
            '<table id="planted-blank"><thead><tr><th>A</th><th>B</th></tr></thead><tbody></tbody></table>' +
            '<details id="planted-closed"><summary>more</summary><table id="planted-hidden"><thead><tr><th>C</th></tr></thead><tbody></tbody></table></details>');
        }""")
        try:
            res = self.page.evaluate(SCAN, "dns")
        finally:
            self.page.evaluate("() => { document.getElementById('planted-blank')?.remove(); document.getElementById('planted-closed')?.remove(); }")
        self.assertIn("planted-blank (2 columns)", res["blank"])
        self.assertFalse([b for b in res["blank"] if b.startswith("planted-hidden")], "a table in a closed details is not on screen")


if __name__ == "__main__":
    unittest.main()
