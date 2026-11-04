#!/usr/bin/env python3
"""7.4.9: the typeface option in a real browser, on the seeded stack.

The other typeface tests read the stylesheet and run the functions. This one signs in and uses the page the way a person does:

* nobody has to choose anything: the system font is drawn, the page has no `data-typeface`, and no font file is fetched. The
  B612 faces are declared in the stylesheet and sit unloaded, which is the whole cost of having the option;
* choosing B612 under My Account → Appearance fetches the two faces the page uses (the pinned files, once each), the glyphs are
  drawn from them (the browser's own report of the fonts used for a node, not just the computed `font-family`), the choice is saved
  to the account and is still there after a reload;
* the wordmark beside the logo is drawn the same under both, and so are the monospace text and the logo files;
* the account's typeface follows the person to a fresh browser and does not follow a browser to the next person who signs in on it;
* it combines with either look;
* Chinese, Hindi and Arabic text and symbols are not drawn from B612, which holds Latin letters only;
* when the font file cannot be fetched the page is still whole: the next font in the stack draws it and nothing throws;
* B612 is wider than the system font, so the stylesheet draws it at 92%. This measures what that buys: sixteen views are rendered
  once, the typeface is switched in place, and the clipped text, the lines that wrap and the elements that spill past the screen
  are compared, in English and German at a desktop and a phone width. Only what B612 adds counts, and only text cut off, an
  element past the screen edge and a page that scrolls sideways fail it (the table above DIFF_VIEWS has the numbers at 92, 100 and
  108%, and the test fails at the last two).

The filename carries 'e2e', so make test-fast skips it; the serial gate runs it. Each test signs in in a context of its own.
"""
import os
import subprocess
import sys
import tempfile
import unittest
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
_GATE = browser_available() or browser_required.required()

# the system stack as the browser reports it (Chromium writes the quotes with double marks)
SYSTEM_STACK = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'

STATE = """() => {
  const b = document.body;
  const faces = [...document.fonts].filter(f => f.family.replace(/['"]/g, '') === 'B612').map(f => f.weight + ':' + f.status);
  return { face: b.dataset.typeface || null, copy: localStorage.getItem('rp_typeface'), family: getComputedStyle(b).fontFamily,
           look: b.dataset.look || null, faces };
}"""

# the wordmark and the monospace version pill, as drawn
BRAND = """() => {
  const part = sel => { const e = document.querySelector(sel); if (!e) return null; const c = getComputedStyle(e), r = e.getBoundingClientRect();
    const o = { size: c.fontSize, weight: c.fontWeight, spacing: c.letterSpacing, w: Math.round(r.width * 100) / 100,
                h: Math.round(r.height * 100) / 100, text: e.textContent };
    if (e.textContent.trim()) o.family = c.fontFamily;       // an <img> inherits a family and draws nothing with it
    return o; };
  return { text: part('.sidebar .brand .logo-text'), version: part('.sidebar .brand .brand-v'), img: part('.sidebar .brand .logo-img') };
}"""

# the sideways differential: what one element does, recorded with the system font and again with B612 in the same DOM
MEASURE = """() => {
  const W = innerWidth, rows = [];
  const roots = [document.querySelector('#app .page.active'), document.querySelector('.sidebar'), document.querySelector('header')].filter(Boolean);
  const ownLines = (el, lh) => { const tops = [];
    for (const n of el.childNodes) if (n.nodeType === 3 && n.textContent.trim()) { const r = document.createRange(); r.selectNodeContents(n);
      for (const q of r.getClientRects()) if (q.width > 0) tops.push(q.top); }
    tops.sort((a, b) => a - b); let lines = 0, last = -1e9;
    for (const t of tops) { if (t - last >= 0.6 * lh) { lines++; last = t; } }   // a fallback glyph sits a few px off its line: that is not a line
    return lines; };
  const scrollsOrHides = el => { for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
    const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden' || o === 'clip') return true; } return false; };
  let idx = 0;
  for (const root of roots) for (const el of root.querySelectorAll('*')) {
    idx++;
    if (el.closest('svg')) continue;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    if (String(el.className).includes('skeleton')) continue;        // a loading placeholder, not content
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) continue;
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    const rec = { i: idx, tag: el.tagName, txt: (el.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 30),
      cls: String(el.className && el.className.baseVal !== undefined ? el.className.baseVal : el.className).slice(0, 44),
      w: Math.round(r.width), ws: cs.whiteSpace };
    if (own) rec.lines = ownLines(el, parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.2);
    const ox = cs.overflowX;
    if ((ox === 'hidden' || ox === 'clip' || cs.textOverflow === 'ellipsis') && el.scrollWidth > el.clientWidth + 1) { rec.clip = true; rec.cut = el.scrollWidth - el.clientWidth; rec.ell = cs.textOverflow === 'ellipsis'; }
    if ((r.right > W + 1 || r.left < -1) && !scrollsOrHides(el)) rec.spill = Math.round(Math.max(r.right - W, -r.left));
    rows.push(rec);
  }
  return { page: document.documentElement.scrollWidth - innerWidth, rows };
}"""


def differences(a, b):
    """What B612 adds: [(kind, element of b, element of a)] for two MEASURE results taken over the same DOM."""
    by = {r["i"]: r for r in a["rows"]}
    out = []
    for rb in b["rows"]:
        ra = by.get(rb["i"])
        if ra is None:
            continue
        if rb.get("clip") and not ra.get("clip"):
            out.append(("clipped", rb, ra))
        elif rb.get("clip") and ra.get("clip") and not rb.get("ell") and rb["cut"] > ra["cut"] + 4:
            out.append(("clipped more", rb, ra))                   # an ellipsis is how long text is meant to end; a hard cut is not
        if ra.get("lines") == 1 and rb.get("lines", 1) >= 2 and ra["ws"] not in ("pre", "pre-wrap"):
            out.append(("wrapped", rb, ra))
        if rb.get("spill") and not ra.get("spill"):
            out.append(("spills", rb, ra))
    if b["page"] > a["page"] + 1:
        out.append(("page scrolls sideways", {"tag": "DOC", "cls": "", "txt": "+%dpx" % (b["page"] - a["page"]), "w": 0}, {}))
    return out


# The views the comparison renders, the languages it switches between in place and the widths it runs at. The views are the ones
# with the most width-sensitive chrome in a walk of all of them (tables with long cells, chips, calendar events, titles that end in
# an ellipsis, long headings): sixteen views, English and German (the longest strings), a desktop and a phone. Measured on the
# seeded stack, with the system stack resolving to Liberation Sans (Arial's widths), 64 cells and about 56,000 element readings:
#
#   size-adjust   newly clipped (readings / elements)   pages that scroll sideways   wrapped onto a second line
#      92%                     0 / 0                              0                          92      <- what the stylesheet draws
#     100%                     4 / 2                              0                         185
#     108%                    16 / 9                              1                         307
#
# so the 92% is the largest of the three that keeps every word on screen, and the test fails at the other two.
DIFF_VIEWS = ("home", "devices", "alerts", "monitor", "tickets", "patches", "cve", "containers", "ipintel", "compliance", "calendar",
              "kb", "users", "settings", "account", "logs")
DIFF_LANGS = ("en", "de")
DIFF_WIDTHS = (1440, 390)
# What is a failure. Text cut off that was whole, an element past the edge of the screen, a page that scrolls sideways. A line that
# wraps is not: it is how a page takes a wider face, which words land on the edge depends on the machine's own font, and a wrap
# loses nothing. Text that was already cut (a chip 33 px wide, a title ending in an ellipsis) may end a little sooner.
HARD = ("clipped", "spills", "page scrolls sideways")


def describe(view, issue):
    kind, rb, ra = issue
    return "%s: %s %s.%s %r (%spx, was %spx)" % (view, kind, rb.get("tag"), rb.get("cls"), rb.get("txt"), rb.get("w"), ra.get("w"))


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheTypefaceInABrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("the typeface is backend-agnostic: exercised once")
        if not _HAVE_PLAYWRIGHT:
            browser_required.skip_or_fail("playwright is not installed")
        seeder = _ROOT / "packaging" / "seed-demo-data.py"
        data_dir = tempfile.mkdtemp(prefix="rp-typeface-e2e-")
        proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT),
                              timeout=600)
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
            cls.base, cls._shutdown = start_stack(data_dir=data_dir)
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest("app stack not available: %s" % exc)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    # ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def setUp(self):
        self.seen = {}                                           # per page: the requests, the responses and the errors it saw

    def requests(self, page):
        return self.seen[id(page)]["requests"]

    def responses(self, page):
        return self.seen[id(page)]["responses"]

    def errors(self, page):
        return self.seen[id(page)]["errors"]

    def login(self, user="alice", init="", size=(1440, 900), route=None):
        ctx = self.browser.new_context(viewport={"width": size[0], "height": size[1]}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); %s } catch (e) {}" % init)
        self.addCleanup(ctx.close)
        page = ctx.new_page()
        seen = self.seen[id(page)] = {"requests": [], "responses": {}, "errors": []}
        page.on("request", lambda r: seen["requests"].append(r.url))
        page.on("response", lambda r: seen["responses"].setdefault(r.url, r))
        page.on("pageerror", lambda e: seen["errors"].append(str(e)))
        if route:
            ctx.route(route, lambda r: r.abort())
        page.goto(self.base + "/index.html")
        page.fill("#login-user", user)
        page.fill("#login-pass", "demo")
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector("#app", state="visible", timeout=90000)
        page.wait_for_timeout(3500)
        return page

    def reload(self, page):
        page.reload()
        page.wait_for_selector("#app", state="visible", timeout=90000)
        page.wait_for_timeout(3500)

    def api(self, page, method, path, body=None):
        if body is None:
            return page.evaluate("async ([m, p]) => await api(m, p)", [method, path])
        return page.evaluate("async ([m, p, b]) => await api(m, p, b)", [method, path, body])

    def state(self, page):
        return page.evaluate(STATE)

    def account(self, page):
        page.evaluate("showPage('account')")
        # the select is visible before the picker has set its value; the look cards are built by the same function
        page.wait_for_selector("#acct-look button", timeout=30000)
        page.wait_for_selector("#acct-typeface", state="visible", timeout=30000)

    def flush(self, page):
        page.wait_for_timeout(1800)                              # the prefs are posted 600 ms after the last change

    def reset(self, page):
        self.api(page, "POST", "/ui-prefs", {})

    def font_requests(self, page):
        return sorted({u.rsplit("/", 1)[-1] for u in self.requests(page) if "/vendor/fonts/" in u})

    def postscript(self, page, selector):
        """The PostScript names of the font files the browser used to draw a node's text."""
        return sorted(f["postScriptName"] for f in self._platform_fonts(page, selector))

    def drawn_with(self, page, selector):
        """The families the browser really used to draw a node's text (CDP), not what the style asked for."""
        return [(f["familyName"], f.get("isCustomFont")) for f in self._platform_fonts(page, selector)]

    def _platform_fonts(self, page, selector):
        client = page.context.new_cdp_session(page)
        client.send("DOM.enable")
        client.send("CSS.enable")
        root = client.send("DOM.getDocument", {"depth": 0})["root"]["nodeId"]
        node = client.send("DOM.querySelector", {"nodeId": root, "selector": selector})["nodeId"]
        self.assertTrue(node, "no node for %s" % selector)
        fonts = client.send("CSS.getPlatformFontsForNode", {"nodeId": node})["fonts"]
        client.detach()
        return fonts

    def wait_faces(self, page):
        page.wait_for_function("() => [...document.fonts].filter(f => f.family.replace(/['\\\"]/g, '') === 'B612'"
                               " && f.status === 'loaded').length >= 2", timeout=30000)

    # ── the default ──────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_nobody_has_to_choose_the_system_font_is_drawn_and_no_font_is_fetched(self):
        page = self.login()
        for name in ("home", "devices", "alerts", "account"):
            page.evaluate("n => showPage(n)", name)
            page.wait_for_timeout(1200)
        s = self.state(page)
        self.assertEqual((s["face"], s["copy"]), (None, "system"))
        self.assertEqual(s["family"], SYSTEM_STACK)
        self.assertEqual(self.font_requests(page), [], "the default must not fetch a font file")
        # declared, never used: the whole cost of having the option
        self.assertEqual(sorted(s["faces"]), ["400 500:unloaded", "600 700:unloaded"])
        self.assertEqual(page.eval_on_selector("#acct-typeface", "e => e.value"), "system")
        self.assertEqual(page.eval_on_selector_all("#acct-typeface option", "els => els.map(e => e.value)"), ["system", "b612"])
        self.assertEqual(self.errors(page), [])

    # ── choosing B612 ────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_choosing_b612_fetches_the_two_faces_draws_with_them_and_is_saved(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        page.evaluate("showPage('devices')")
        page.wait_for_selector("#page-devices .page-title", timeout=30000)
        before = self.drawn_with(page, "#page-devices .page-title")
        self.assertNotIn("B612", [f for f, _c in before])
        self.account(page)
        page.select_option("#acct-typeface", "b612")
        self.wait_faces(page)
        s = self.state(page)
        self.assertEqual((s["face"], s["copy"]), ("b612", "b612"))
        self.assertTrue(s["family"].startswith('B612, '), s["family"])
        self.assertEqual(sorted(s["faces"]), ["400 500:loaded", "600 700:loaded"])
        # the glyphs come from the vendored files, once each, and they are the pinned bytes
        self.assertEqual(self.font_requests(page), sorted(PINS))
        for name, (_sha, size) in PINS.items():
            url = [u for u in self.responses(page) if u.endswith("/" + name)][0]
            resp = self.responses(page)[url]
            self.assertEqual(resp.status, 200, name)
            self.assertEqual(len(resp.body()), size, name)
            self.assertEqual(sum(1 for u in self.requests(page) if u.endswith("/" + name)), 1, "%s was fetched more than once" % name)
        page.evaluate("showPage('devices')")
        page.wait_for_selector("#page-devices .page-title", timeout=30000)
        used = self.drawn_with(page, "#page-devices .page-title")
        self.assertIn(("B612", True), used, "the title is not drawn from the B612 file: %s" % used)
        self.assertIn(("B612", True), self.drawn_with(page, "#page-devices .page-subtitle"))
        self.assertEqual(self.postscript(page, "#page-devices .page-title"), ["B612-Bold"])
        self.assertEqual(self.postscript(page, "#page-devices .page-subtitle"), ["B612-Regular"])
        self.flush(page)
        self.assertEqual(self.api(page, "GET", "/ui-prefs").get("typeface"), "b612")
        self.reload(page)
        s = self.state(page)
        self.assertEqual((s["face"], s["copy"]), ("b612", "b612"))
        self.assertEqual(self.errors(page), [])

    def test_going_back_to_the_system_font_takes_the_attribute_and_the_family_away(self):
        page = self.login(init="localStorage.setItem('rp_typeface', 'b612');")
        self.addCleanup(lambda: self.reset(page))
        self.api(page, "POST", "/ui-prefs", {"typeface": "b612"})
        self.reload(page)
        self.assertEqual(self.state(page)["face"], "b612")
        self.account(page)
        page.select_option("#acct-typeface", "system")
        s = self.state(page)
        self.assertEqual((s["face"], s["copy"], s["family"]), (None, "system", SYSTEM_STACK))
        self.flush(page)
        self.assertEqual(self.api(page, "GET", "/ui-prefs").get("typeface"), "system")

    # ── what must not change ─────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_wordmark_the_version_pill_and_the_logo_are_drawn_the_same_under_both(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        system = page.evaluate(BRAND)
        self.assertIsNotNone(system["text"])
        self.assertEqual(system["text"]["family"], SYSTEM_STACK)
        self.account(page)
        page.select_option("#acct-typeface", "b612")
        self.wait_faces(page)
        b612 = page.evaluate(BRAND)
        self.assertEqual(b612, system, "the brand text, the version pill or the logo changed with the typeface")
        self.assertNotIn("B612", [f for f, _c in self.drawn_with(page, ".sidebar .brand .logo-text")])
        # mono text keeps its own stack
        self.assertNotIn("B612", [f for f, _c in self.drawn_with(page, ".sidebar .brand .brand-v")])
        git = subprocess.run(["git", "status", "--porcelain", "--", "server/html/static/img"], capture_output=True, text=True,
                             cwd=str(_ROOT))
        if git.returncode == 0:
            self.assertEqual(git.stdout.strip(), "", "the logo files are as committed")

    def test_the_account_page_itself_is_drawn_in_the_choice_and_the_select_says_so(self):
        page = self.login(init="localStorage.setItem('rp_typeface', 'b612');")
        self.addCleanup(lambda: self.reset(page))
        self.api(page, "POST", "/ui-prefs", {"typeface": "b612"})
        self.reload(page)
        self.account(page)
        self.assertEqual(page.eval_on_selector("#acct-typeface", "e => e.value"), "b612")
        self.assertEqual(page.eval_on_selector("#acct-typeface option:checked", "e => e.textContent"), "B612")

    # ── whose typeface it is ─────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_typeface_follows_the_account_to_a_fresh_browser_and_not_to_the_next_person(self):
        first = self.login()
        self.addCleanup(lambda: self.reset(first))
        self.api(first, "POST", "/ui-prefs", {"typeface": "b612"})
        second = self.login()                                    # no copy, no session: only the account knows
        self.assertEqual(self.state(second)["face"], "b612")
        # a browser the last person left on B612: the next person has not chosen, so they get the system font, and the copy is corrected
        third = self.login(user="bob", init="localStorage.setItem('rp_typeface', 'b612');")
        s = self.state(third)
        self.assertEqual((s["face"], s["copy"], s["family"]), (None, "system", SYSTEM_STACK))

    # ── with either look ─────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_it_combines_with_either_look_and_the_look_keeps_its_own_state(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        self.api(page, "POST", "/ui-prefs", {"typeface": "b612", "look": "pilot"})
        self.reload(page)
        s = self.state(page)
        self.assertEqual((s["face"], s["look"]), ("b612", "pilot"))
        page.wait_for_selector("#home-hero.is-ready", timeout=30000)
        self.wait_faces(page)
        self.assertIn(("B612", True), self.drawn_with(page, "#page-home .page-title"))
        # the hero's labels are monospace in Pilot, and the typeface does not reach them
        self.assertNotIn("B612", [f for f, _c in self.drawn_with(page, "#home-hero .pilot-eyebrow")])
        page.evaluate("setLookUI('classic')")
        s = self.state(page)
        self.assertEqual((s["face"], s["look"]), ("b612", "classic"))
        self.assertIn(("B612", True), self.drawn_with(page, "#page-home .page-title"))
        self.assertTrue(page.evaluate("typeof window.setTypefaceUI === 'function'"))
        self.assertEqual(self.errors(page), [])

    # ── the scripts B612 does not hold ───────────────────────────────────────────────────────────────────────────────────────
    def test_chinese_text_is_not_drawn_from_b612(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        self.api(page, "POST", "/ui-prefs", {"typeface": "b612"})
        self.reload(page)
        self.assertEqual(self.state(page)["face"], "b612")
        page.evaluate("showPage('devices')")
        page.wait_for_selector("#page-devices .page-title", timeout=30000)
        # the control: in English the same title is drawn from B612, so the Chinese result below is not B612 being switched off
        self.assertIn(("B612", True), self.drawn_with(page, "#page-devices .page-title"))
        page.evaluate("() => _ensureI18n()")
        page.evaluate("l => RPi18n.setLang(l, false)", "zh")
        page.wait_for_timeout(800)
        title = page.inner_text("#page-devices .page-title")
        self.assertTrue(any("\u4e00" <= ch <= "\u9fff" for ch in title), "the title did not translate: %r" % title)
        used = self.drawn_with(page, "#page-devices .page-title")
        self.assertTrue(used, "the browser reported no font for the title")
        self.assertNotIn("B612", [f for f, _c in used], used)
        page.evaluate("() => RPi18n.setLang('en', false)")

    # ── when the file cannot be fetched ──────────────────────────────────────────────────────────────────────────────────────
    def test_the_page_is_whole_when_the_font_cannot_be_fetched(self):
        page = self.login(route="**/vendor/fonts/files/**")
        self.addCleanup(lambda: self.reset(page))
        self.api(page, "POST", "/ui-prefs", {"typeface": "b612"})
        self.reload(page)
        page.evaluate("showPage('devices')")
        page.wait_for_selector("#page-devices .page-title", timeout=30000)
        page.wait_for_timeout(1500)
        s = self.state(page)
        self.assertEqual(s["face"], "b612")
        title = page.eval_on_selector("#page-devices .page-title", "e => { const r = e.getBoundingClientRect(); return [r.width, r.height, e.textContent.trim()]; }")
        self.assertGreater(title[0], 20)
        self.assertGreater(title[1], 8)
        self.assertTrue(title[2])
        used = [f for f, _c in self.drawn_with(page, "#page-devices .page-title")]
        self.assertTrue(used and "B612" not in used, "the next font in the stack should have drawn the page: %s" % used)
        self.assertEqual(self.font_requests(page), sorted(PINS), "the page should have asked for the faces it could not get")
        self.assertTrue(any(f.endswith(":error") for f in s["faces"]), "the browser did not report the failed fetch: %s" % s["faces"])
        self.assertEqual(self.errors(page), [], "a missing font file must not throw")

    # ── what B612's width does to the layout ─────────────────────────────────────────────────────────────────────────────────
    def measure_both(self, page):
        """The same DOM measured with the system font and with B612, as (system, b612). Both faces are loaded first, so the switch
        is a restyle and not a fetch."""
        page.evaluate("() => { delete document.body.dataset.typeface; }")
        a = page.evaluate(MEASURE)
        page.evaluate("() => { document.body.dataset.typeface = 'b612'; }")
        b = page.evaluate(MEASURE)
        page.evaluate("() => { delete document.body.dataset.typeface; }")
        return a, b

    def test_b612_adds_no_clipped_text_wrapped_control_or_sideways_scroll(self):
        found, seen, wraps = [], 0, 0
        for width in DIFF_WIDTHS:
            page = self.login(size=(width, 900))
            page.evaluate("async () => { await Promise.all([document.fonts.load('400 13px B612'), document.fonts.load('700 13px B612')]); }")
            page.evaluate("() => _ensureI18n()")
            for view in DIFF_VIEWS:
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", view)
                page.wait_for_timeout(1500)
                for lang in DIFF_LANGS:
                    page.evaluate("l => { try { RPi18n.setLang(l, false) } catch (e) {} }", lang)
                    page.wait_for_timeout(100)
                    a, b = self.measure_both(page)
                    if len(a["rows"]) != len(b["rows"]):          # the page redrew between the two reads: once more
                        a, b = self.measure_both(page)
                    seen += len(a["rows"])
                    issues = differences(a, b)
                    wraps += sum(1 for issue in issues if issue[0] == "wrapped")
                    found += ["%dpx %s %s" % (width, lang, describe(view, issue)) for issue in issues if issue[0] in HARD]
                page.evaluate("() => { try { RPi18n.setLang('en', false) } catch (e) {} }")
        self.assertGreater(seen, 40000, "a comparison over almost nothing proves nothing: %d element readings" % seen)
        self.assertGreater(wraps, 0, "B612 is wider than the system font, so something wraps; a comparison that sees none is not looking")
        self.assertEqual(found, [], "\n".join(found))

    def test_the_comparison_sees_what_only_b612_would_add(self):
        """Control: a block that is wide only once B612 is on is reported. A comparison that cannot fail proves nothing."""
        page = self.login(size=(390, 844))
        page.evaluate("showPage('devices')")
        page.wait_for_timeout(1500)
        a = page.evaluate(MEASURE)
        page.evaluate("""() => { const d = document.createElement('div'); d.id = 'probe-wide'; d.textContent = 'x';
                                 d.style.setProperty('width', '700px'); d.style.setProperty('height', '4px');
                                 document.querySelector('#app .page.active').appendChild(d); }""")
        page.evaluate("() => { document.body.dataset.typeface = 'b612'; }")
        b = page.evaluate(MEASURE)
        self.assertIn("page scrolls sideways", [kind for kind, _b, _a in differences(a, b)])
        same = differences(a, a)
        self.assertEqual(same, [], "the same page against itself must report nothing")


class TestTheComparisonSeesWhatItIsFor(unittest.TestCase):
    """The comparison, on measurements written by hand: each way B612 can hurt a page is found, and what the system font already
    did is not blamed on the typeface."""

    @staticmethod
    def doc(rows, page=0):
        return {"page": page, "rows": rows}

    @staticmethod
    def row(i, **kw):
        base = {"i": i, "tag": "BUTTON", "cls": "btn", "txt": "Save", "w": 80, "ws": "normal"}
        base.update(kw)
        return base

    def kinds(self, a, b):
        return [kind for kind, _b, _a in differences(a, b)]

    def test_text_clipped_only_with_b612_is_found(self):
        self.assertEqual(self.kinds(self.doc([self.row(1)]), self.doc([self.row(1, clip=True, cut=9)])), ["clipped"])

    def test_a_hard_cut_that_gets_worse_is_found_and_a_pixel_is_not(self):
        a = self.doc([self.row(1, clip=True, cut=10)])
        self.assertEqual(self.kinds(a, self.doc([self.row(1, clip=True, cut=30)])), ["clipped more"])
        self.assertEqual(self.kinds(a, self.doc([self.row(1, clip=True, cut=12)])), [])

    def test_an_ellipsis_may_truncate_further(self):
        a = self.doc([self.row(1, clip=True, cut=10, ell=True)])
        self.assertEqual(self.kinds(a, self.doc([self.row(1, clip=True, cut=40, ell=True)])), [])

    def test_a_control_that_wraps_only_with_b612_is_found(self):
        a, b = self.doc([self.row(1, lines=1)]), self.doc([self.row(1, lines=2)])
        self.assertEqual(self.kinds(a, b), ["wrapped"])

    def test_text_that_already_wrapped_is_not_blamed(self):
        a, b = self.doc([self.row(1, lines=2)]), self.doc([self.row(1, lines=3)])
        self.assertEqual(self.kinds(a, b), [])

    def test_preformatted_text_is_not_a_wrap(self):
        a, b = self.doc([self.row(1, lines=1, ws="pre")]), self.doc([self.row(1, lines=2, ws="pre")])
        self.assertEqual(self.kinds(a, b), [])

    def test_an_element_that_spills_only_with_b612_is_found_and_one_that_already_did_is_not(self):
        self.assertEqual(self.kinds(self.doc([self.row(1)]), self.doc([self.row(1, spill=40)])), ["spills"])
        self.assertEqual(self.kinds(self.doc([self.row(1, spill=40)]), self.doc([self.row(1, spill=60)])), [])

    def test_a_page_that_scrolls_further_sideways_is_found(self):
        self.assertEqual(self.kinds(self.doc([], page=0), self.doc([], page=30)), ["page scrolls sideways"])
        self.assertEqual(self.kinds(self.doc([], page=30), self.doc([], page=30)), [])
        self.assertEqual(self.kinds(self.doc([], page=30), self.doc([], page=31)), [])

    def test_an_element_that_exists_in_only_one_reading_is_skipped(self):
        self.assertEqual(self.kinds(self.doc([self.row(1)]), self.doc([self.row(1), self.row(2, lines=3, clip=True, cut=99)])), [])

    def test_describe_names_the_element(self):
        line = describe("devices", ("wrapped", self.row(1, cls="btn x", txt="Save changes", w=140), self.row(1, w=110)))
        self.assertIn("devices", line)
        self.assertIn("wrapped", line)
        self.assertIn("BUTTON.btn x", line)
        self.assertIn("140px, was 110px", line)


if __name__ == "__main__":
    unittest.main()
