#!/usr/bin/env python3
"""7.4.9: the look switch in a real browser, on the seeded stack.

The other look tests run the functions and read the stylesheet. This one signs in and uses the page the way a person does:

* nobody has to choose anything: Classic is drawn, Home has no hero, the Effects row is not offered;
* choosing Pilot under My Account → Appearance draws the hero, with one dot for every host and a legend that adds up, and the
  tile it replaces steps aside; the choice is saved to the account and is still there after a reload;
* the account's look follows the person to a fresh browser, and does not follow a browser to the next person who signs in on it;
* an administrator's default applies until somebody chooses, and a lock holds everybody, the account's own choice included;
* Reduced effects take the glow and the texture off and change no colour;
* the palette a browser uses when it has chosen none follows the look, and a palette that was chosen stays;
* the logo and the brand text are drawn the same under both looks;
* Pilot has no serious accessibility violation on the pages it restyles, in both of its palettes, and the hero stays inside the
  page on a phone and with a fleet far larger than the demo's.

The filename carries 'e2e', so make test-fast skips it; the serial gate runs it. Each test signs in in a context of its own.
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

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False

try:
    from axe_core_python.sync_playwright import Axe
    _HAVE_AXE = True
except ImportError:
    _HAVE_AXE = False

_ROOT = Path(__file__).resolve().parent.parent
_GATE = browser_available() or browser_required.required()

STATE = """() => {
  const b = document.body, hero = document.getElementById('home-hero');
  const tile = document.querySelector('#home-tiles .tile[data-arg="devices"]');
  return { look: b.dataset.look || null, fx: b.dataset.fx || null, theme: b.dataset.theme || null,
    light: b.classList.contains('light'), copy: localStorage.getItem('rp_look'), fxcopy: localStorage.getItem('rp_fx'),
    heroReady: !!hero && hero.classList.contains('is-ready'), heroHidden: hero ? hero.hidden : null,
    heroKids: hero ? hero.children.length : null, tile: tile ? getComputedStyle(tile).display : null };
}"""

# the blurred shadows of an element, as [{blur, alpha}]: a computed box-shadow is a list of shadows whose colour may be written as
# rgba() or as color(srgb ... / alpha), so the alpha is read from either
SHADOWS = """(sel) => {
  const el = document.querySelector(sel); if (!el) return null;
  const v = getComputedStyle(el).boxShadow; if (!v || v === 'none') return [];
  const parts = []; let depth = 0, cur = '';
  for (const ch of v) { if (ch === '(') depth++; if (ch === ')') depth--;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch; }
  parts.push(cur);
  return parts.map(p => {
    const colour = p.match(/(rgba?|color)\\([^)]*\\)/);
    const nums = [...p.replace(/(rgba?|color)\\([^)]*\\)/g, '').matchAll(/(-?\\d*\\.?\\d+)px/g)].map(m => parseFloat(m[1]));
    let alpha = 1;
    if (colour) {
      const s = colour[0];
      if (s.startsWith('rgba')) { const c = s.slice(s.indexOf('(') + 1, -1).split(','); alpha = c.length > 3 ? parseFloat(c[3]) : 1; }
      else if (s.startsWith('color')) { const m = s.match(/\\/\\s*([\\d.]+)/); alpha = m ? parseFloat(m[1]) : 1; }
    } else if (/transparent/.test(p)) alpha = 0;
    return { blur: nums[2] || 0, alpha };
  });
}"""

# axe cannot judge text that sits over the hero's dot texture (it reports such text as incomplete, not as a failure: a mutation that
# painted the captions dark grey passed the axe sweep), so the contrast of the hero's own text is measured here, with the WCAG
# formula, against the first opaque background above it. The last lines are the control: the same measure on a caption forced to the
# colour of its own background (invisible text, in any palette) has to come back under 4.5.
HERO_CONTRAST = """() => {
  const chan = v => { v /= 255; return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  const parse = c => (c.match(/[\\d.]+/g) || []).map(Number);
  const lum = c => { const [r, g, b] = parse(c); return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b); };
  const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  const bgOf = el => { for (let e = el; e; e = e.parentElement) { const c = getComputedStyle(e).backgroundColor, p = parse(c);
      if (p.length === 3 || (p.length > 3 && p[3] === 1)) return c; } return 'rgb(255, 255, 255)'; };
  const sel = '#home-hero .pilot-eyebrow, #home-hero .pilot-cap, #home-hero .pilot-glabel, #home-hero .pilot-key > span';
  const rows = [...document.querySelectorAll(sel)].map(e => ({ text: e.textContent.trim().slice(0, 30), fg: getComputedStyle(e).color,
    bg: bgOf(e), ratio: ratio(getComputedStyle(e).color, bgOf(e)) }));
  const cap = document.querySelector('#home-hero .pilot-cap'); let forced = null;
  if (cap) { const old = cap.style.color; cap.style.setProperty('color', bgOf(cap)); forced = ratio(getComputedStyle(cap).color, bgOf(cap)); cap.style.color = old; }
  return { rows, forced };
}"""

# A shadow (a ring or a glow) that reaches past an ancestor which clips it is drawn with a flat edge. The fleet field scrolls, a dot's
# glow reaches 10px past the dot, and with no padding the top row and the left column lost their halo, which the owner saw on the test
# trunk: no layout measurement can see it, because every box was where it should be. This looks for it directly. For every outer shadow
# of an element inside the root it takes the room the shadow needs on each side and compares it with the padding box of each clipping
# ancestor (hidden, clip, auto or scroll). An element that is itself cut or scrolled is ordinary clipping and is skipped. It returns how
# many shadows it examined, so an empty answer over nothing cannot pass, and the worst overshoot per element, ancestor and side.
GLOW_CLIPPED = """(rootSel) => {
  const root = document.querySelector(rootSel), found = new Map();
  let examined = 0;
  const split = v => { const parts = []; let depth = 0, cur = '';
    for (const ch of v) { if (ch === '(') depth++; if (ch === ')') depth--; if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch; }
    parts.push(cur); return parts; };
  const alphaOf = s => { const c = s.match(/(rgba?|color)\\([^)]*\\)/); if (!c) return /transparent/.test(s) ? 0 : 1;
    const t = c[0]; if (t.startsWith('rgba')) { const q = t.slice(t.indexOf('(') + 1, -1).split(','); return q.length > 3 ? parseFloat(q[3]) : 1; }
    if (t.startsWith('color')) { const m = t.match(/\\/\\s*([\\d.]+)/); return m ? parseFloat(m[1]) : 1; } return 1; };
  const clips = el => { const list = []; for (let p = el.parentElement; p && p !== document.documentElement; p = p.parentElement) {
      const c = getComputedStyle(p); if (['hidden', 'auto', 'scroll', 'clip'].includes(c.overflowX) || ['hidden', 'auto', 'scroll', 'clip'].includes(c.overflowY)) list.push(p); } return list; };
  const name = e => e.tagName + '.' + String(e.className && e.className.baseVal !== undefined ? e.className.baseVal : e.className).trim().split(/\\s+/).slice(0, 3).join('.');
  for (const el of root.querySelectorAll('*')) {
    if (el.closest('svg')) continue;
    const cs = getComputedStyle(el); if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const v = cs.boxShadow; if (!v || v === 'none') continue;
    const r = el.getBoundingClientRect(); if (r.width === 0 || r.height === 0) continue;
    for (const part of split(v)) {
      if (/inset/.test(part) || alphaOf(part) < 0.05) continue;
      const nums = [...part.replace(/(rgba?|color)\\([^)]*\\)/g, '').matchAll(/(-?\\d*\\.?\\d+)px/g)].map(m => parseFloat(m[1]));
      const [ox, oy, blur, spread] = [nums[0] || 0, nums[1] || 0, nums[2] || 0, nums[3] || 0], grow = blur + spread;
      if (grow < 1) continue;
      examined++;
      const sh = { l: r.left - grow + ox, t: r.top - grow + oy, r: r.right + grow + ox, b: r.bottom + grow + oy };
      for (const a of clips(el)) {
        const ar = a.getBoundingClientRect(), L = ar.left + a.clientLeft, T = ar.top + a.clientTop, R = L + a.clientWidth, B = T + a.clientHeight;
        if (r.left < L - 0.5 || r.top < T - 0.5 || r.right > R + 0.5 || r.bottom > B + 0.5) continue;
        for (const [side, over] of Object.entries({ left: L - sh.l, top: T - sh.t, right: sh.r - R, bottom: sh.b - B })) {
          if (over <= 0.5) continue;
          const key = name(el) + ' < ' + name(a) + ' ' + side, old = found.get(key);
          if (!old || over > old.over) found.set(key, { el: name(el), clip: name(a), side, over: Math.round(over * 10) / 10 });
        }
      }
    }
  }
  return { examined, found: [...found.values()] };
}"""

# the owner's fleet: four host groups, five healthy, two critical, two not monitored
NINE_HOSTS = [
    {"id": "a1", "name": "nas-a", "group": "agentless", "online": True, "monitored": False},
    {"id": "a2", "name": "nas-b", "group": "agentless", "online": True, "monitored": False},
    {"id": "p1", "name": "web01", "group": "apt", "online": True, "monitored": True},
    {"id": "p2", "name": "web02", "group": "apt", "online": True, "monitored": True},
    {"id": "p3", "name": "web03", "group": "apt", "online": False, "monitored": True},
    {"id": "h1", "name": "pve01", "group": "apt-hypervisor", "online": True, "monitored": True},
    {"id": "h2", "name": "pve02", "group": "apt-hypervisor", "online": False, "monitored": True},
    {"id": "m1", "name": "arch01", "group": "pacman", "online": True, "monitored": True},
    {"id": "m2", "name": "arch02", "group": "pacman", "online": True, "monitored": True},
]


def fleet(n):
    """A fleet of n hosts in seven groups: a tenth offline, a thirteenth not monitored."""
    return [{"id": "x%d" % i, "name": "host%04d" % i, "group": "g%d" % (i % 7), "online": i % 11 != 0, "monitored": i % 13 != 0}
            for i in range(n)]


# draws the hero with the real module, from hosts passed as data (the page's policy refuses eval)
DRAW = "devs => _pilotHeroRender(document.getElementById('home-hero'), devs, {devices: []})"


LOGO = """() => {
  const img = document.querySelector('.sidebar .brand .logo-img'), txt = document.querySelector('.sidebar .brand .logo-text');
  const part = e => { const c = getComputedStyle(e), r = e.getBoundingClientRect();
    return { w: r.width, h: r.height, radius: c.borderRadius, filter: c.filter, shadow: c.boxShadow, opacity: c.opacity,
             display: c.display, weight: c.fontWeight, size: c.fontSize, spacing: c.letterSpacing, family: c.fontFamily }; };
  return { src: img.getAttribute('src'), img: part(img), text: txt.textContent, txt: part(txt) };
}"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheLookSwitchInABrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("the look is backend-agnostic: exercised once")
        if not (_HAVE_PLAYWRIGHT and _HAVE_AXE):
            browser_required.skip_or_fail("playwright + axe-core-python are not installed")
        seeder = _ROOT / "packaging" / "seed-demo-data.py"
        data_dir = tempfile.mkdtemp(prefix="rp-look-e2e-")
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
        cls.axe = Axe()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    # ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def login(self, user="alice", init="", size=(1440, 900)):
        ctx = self.browser.new_context(viewport={"width": size[0], "height": size[1]}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")  # one long page: every card is in this walk
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); %s } catch (e) {}" % init)
        self.addCleanup(ctx.close)
        page = ctx.new_page()
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
        # the page's api() sends a body whenever it is given one, and a GET may not have any: pass it only when there is one
        if body is None:
            return page.evaluate("async ([m, p]) => await api(m, p)", [method, path])
        return page.evaluate("async ([m, p, b]) => await api(m, p, b)", [method, path, body])

    def state(self, page):
        return page.evaluate(STATE)

    def account(self, page):
        page.evaluate("showPage('account')")
        page.wait_for_selector("#acct-look button", timeout=30000)

    def flush(self, page):
        # the prefs are posted 600 ms after the last change
        page.wait_for_timeout(1800)

    def reset(self, page, prefs=None):
        self.api(page, "POST", "/ui-prefs", prefs or {})

    def set_default(self, page, look="", locked=False):
        r = self.api(page, "POST", "/config", {"brand_look": look, "brand_look_locked": locked})
        self.assertTrue(r and r.get("ok"), r)

    def wait_hero(self, page):
        page.wait_for_selector("#home-hero.is-ready", timeout=30000)

    # ── the default ──────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_nobody_has_to_choose_classic_is_drawn(self):
        page = self.login()
        s = self.state(page)
        self.assertEqual((s["look"], s["fx"], s["theme"]), ("classic", None, None))
        self.assertEqual((s["heroReady"], s["heroHidden"], s["heroKids"]), (False, True, 0))
        self.assertNotEqual(s["tile"], "none", "Classic keeps the Hosts online tile")
        self.account(page)
        self.assertEqual(page.eval_on_selector_all("#acct-look button", "els => els.map(e => e.dataset.arg)"), ["classic", "pilot"])
        self.assertEqual(page.eval_on_selector_all("#acct-look button.sel", "els => els.map(e => e.dataset.arg)"), ["classic"])
        self.assertEqual(page.get_attribute('#acct-look button[data-arg="classic"]', "aria-pressed"), "true")
        self.assertEqual(page.get_attribute('#acct-look button[data-arg="pilot"]', "aria-pressed"), "false")
        self.assertIn("d-none", page.get_attribute("#acct-fx-wrap", "class") or "", "Effects only matter under Pilot")

    # ── choosing Pilot ───────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_choosing_pilot_draws_the_hero_and_is_saved_to_the_account(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        self.account(page)
        page.click('#acct-look button[data-arg="pilot"]')
        s = self.state(page)
        self.assertEqual((s["look"], s["theme"], s["light"], s["copy"]), ("pilot", "pilot", False, "pilot"))
        self.assertNotIn("d-none", page.get_attribute("#acct-fx-wrap", "class") or "x")
        self.assertEqual(page.eval_on_selector_all("#acct-look button.sel", "els => els.map(e => e.dataset.arg)"), ["pilot"])

        page.evaluate("showPage('home')")
        self.wait_hero(page)
        home = self.api(page, "GET", "/home")
        devs = home["devices"]
        dots = page.eval_on_selector_all("#home-hero .pilot-matrix .pilot-dot", "els => els.length")
        self.assertEqual(dots, len(devs))
        counts = page.eval_on_selector_all("#home-hero .pilot-key .pilot-count", "els => els.map(e => parseInt(e.textContent, 10))")
        self.assertEqual(sum(counts), len(devs), "the legend has to add up to the hosts drawn")
        online = len([d for d in devs if d.get("monitored") is not False and d.get("online")])
        self.assertEqual(page.inner_text("#home-hero .pilot-num .visually-hidden"), str(online))
        self.assertEqual(self.state(page)["tile"], "none", "the tile steps aside once the hero is there")
        # the hero's readout opens the host list, like the tile it replaces
        page.click("#home-hero .pilot-readout")
        page.wait_for_function("() => document.getElementById('page-devices').classList.contains('active')", timeout=15000)

        self.flush(page)
        prefs = self.api(page, "GET", "/ui-prefs")
        self.assertEqual(prefs.get("look"), "pilot")
        self.reload(page)
        s = self.state(page)
        self.assertEqual((s["look"], s["copy"]), ("pilot", "pilot"))
        # a reload restores the page named in the address, which is the host list after the click above
        page.evaluate("showPage('home')")
        self.wait_hero(page)

    def test_a_click_on_a_dot_opens_that_host(self):
        page = self.login(init="localStorage.setItem('rp_look', 'pilot');")
        self.addCleanup(lambda: self.reset(page))
        self.api(page, "POST", "/ui-prefs", {"look": "pilot"})
        self.reload(page)
        self.wait_hero(page)
        name = page.get_attribute("#home-hero .pilot-dot[data-dev]", "data-name")
        page.click("#home-hero .pilot-dot[data-dev]")
        page.wait_for_selector("#device-drawer.open", timeout=15000)
        self.assertIn(name, page.inner_text("#drawer-device-name"))

    # ── whose look it is ─────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_look_follows_the_account_to_a_fresh_browser_and_not_to_the_next_person(self):
        first = self.login()
        self.addCleanup(lambda: self.reset(first))
        self.api(first, "POST", "/ui-prefs", {"look": "pilot"})
        second = self.login()                                    # no copy, no session: only the account knows
        self.assertEqual(self.state(second)["look"], "pilot")
        self.wait_hero(second)
        # a browser the last person left on Pilot: the next person has not chosen, so they get Classic and the copy is corrected
        third = self.login(user="bob", init="localStorage.setItem('rp_look', 'pilot');")
        s = self.state(third)
        self.assertEqual((s["look"], s["copy"]), ("classic", "classic"))
        self.assertEqual((s["heroReady"], s["heroKids"]), (False, 0))

    # ── the administrator ────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_an_administrators_default_applies_until_somebody_chooses(self):
        page = self.login()
        self.addCleanup(lambda: (self.set_default(page), self.reset(page)))
        self.set_default(page, "pilot", False)
        self.reload(page)
        self.assertEqual(self.state(page)["look"], "pilot")
        self.wait_hero(page)
        self.account(page)
        self.assertEqual(page.eval_on_selector_all("#acct-look button:disabled", "els => els.length"), 0, "unlocked: still a choice")
        page.click('#acct-look button[data-arg="classic"]')
        self.assertEqual(self.state(page)["look"], "classic")
        self.flush(page)
        self.reload(page)
        self.assertEqual(self.state(page)["look"], "classic", "a person's own choice beats the default")

    def test_a_lock_holds_everybody_the_accounts_own_choice_included(self):
        page = self.login()
        self.addCleanup(lambda: (self.set_default(page), self.reset(page)))
        self.api(page, "POST", "/ui-prefs", {"look": "classic"})
        self.set_default(page, "pilot", True)
        self.reload(page)
        self.assertEqual(self.state(page)["look"], "pilot")
        self.account(page)
        self.assertEqual(page.eval_on_selector_all("#acct-look button:disabled", "els => els.length"), 2)
        self.assertNotIn("d-none", page.get_attribute("#acct-look-locked", "class") or "x")
        page.evaluate("setLookUI('classic')")                       # the dispatch a click would make, past the disabled button
        self.assertEqual(self.state(page)["look"], "pilot")
        self.set_default(page, "pilot", False)                      # unlocked again: the account's own choice is back
        self.reload(page)
        self.assertEqual(self.state(page)["look"], "classic")

    # ── effects ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_reduced_effects_take_the_glow_and_the_texture_off_and_change_no_colour(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        self.api(page, "POST", "/ui-prefs", {"look": "pilot"})
        self.reload(page)
        self.wait_hero(page)
        dot = "#home-hero .pilot-matrix .pilot-dot.is-ok"
        glow = page.evaluate(SHADOWS, dot)
        self.assertTrue(any(s["blur"] > 0 and s["alpha"] > 0 for s in glow), glow)
        colour = page.eval_on_selector(dot, "e => getComputedStyle(e).backgroundColor")
        texture = page.evaluate("() => getComputedStyle(document.querySelector('#home-hero .pilot-hero'), '::before').opacity")
        self.assertGreater(float(texture), 0)

        self.account(page)
        page.select_option("#acct-fx", "reduced")
        page.evaluate("showPage('home')")
        self.wait_hero(page)
        self.assertEqual(self.state(page)["fx"], "reduced")
        glow = page.evaluate(SHADOWS, dot)
        self.assertTrue(glow and all(s["alpha"] == 0 for s in glow if s["blur"] > 0), glow)
        self.assertTrue(any(s["blur"] == 0 for s in glow), "the ring is part of the shape and stays")
        self.assertEqual(page.eval_on_selector(dot, "e => getComputedStyle(e).backgroundColor"), colour)
        self.assertEqual(float(page.evaluate("() => getComputedStyle(document.querySelector('#home-hero .pilot-hero'), '::before').opacity")), 0)
        self.flush(page)
        self.assertEqual(self.api(page, "GET", "/ui-prefs").get("effects"), "reduced")

    # ── palettes ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_palette_a_browser_uses_when_it_chose_none_follows_the_look(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        page.evaluate("() => { localStorage.removeItem('rp_theme'); applyTheme(); }")
        s = self.state(page)
        self.assertEqual((s["look"], s["theme"], s["light"]), ("classic", None, False))
        page.evaluate("setLookUI('pilot')")
        s = self.state(page)
        self.assertEqual((s["theme"], s["light"]), ("pilot", False))
        page.click(".theme-btn")                                  # the header's dark/light flip
        s = self.state(page)
        self.assertEqual((s["theme"], s["light"]), ("pilot-paper", True))
        page.click(".theme-btn")
        self.assertEqual(self.state(page)["theme"], "pilot")
        page.evaluate("setLookUI('classic')")
        # the flip stored an explicit choice, so Midnight is not forced back on: what was chosen stays under either look
        page.evaluate("() => { localStorage.setItem('rp_theme', 'nord'); applyTheme(); }")
        page.evaluate("setLookUI('pilot')")
        self.assertEqual(self.state(page)["theme"], "nord")
        page.evaluate("setLookUI('classic')")
        self.assertEqual(self.state(page)["theme"], "nord")

    # ── the logo ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_logo_and_the_brand_text_are_the_same_under_both_looks(self):
        page = self.login()
        self.addCleanup(lambda: self.reset(page))
        classic = page.evaluate(LOGO)
        digest = "async (src) => { const b = await (await fetch(src)).arrayBuffer(); const h = await crypto.subtle.digest('SHA-256', b);" \
                 " return [...new Uint8Array(h)].map(x => x.toString(16).padStart(2, '0')).join(''); }"
        classic_hash = page.evaluate(digest, classic["src"])
        page.evaluate("setLookUI('pilot')")
        pilot = page.evaluate(LOGO)
        self.assertEqual(self.state(page)["look"], "pilot")
        self.assertEqual(pilot, classic)
        self.assertEqual(page.evaluate(digest, pilot["src"]), classic_hash)
        git = subprocess.run(["git", "status", "--porcelain", "--", "server/html/static/img"], capture_output=True, text=True,
                             cwd=str(_ROOT))
        if git.returncode == 0:
            self.assertEqual(git.stdout.strip(), "", "the logo files are as committed")

    # ── what Pilot restyles, measured ────────────────────────────────────────────────────────────────────────────────────────
    def test_pilot_has_no_serious_accessibility_violation_in_either_palette(self):
        from test_a11y_axe import _SERIOUS_IMPACTS, _run_axe
        pages = ("home", "devices", "alerts", "monitor", "tickets", "patches", "cve", "logs", "settings", "account", "users")
        for theme in ("pilot", "pilot-paper"):
            page = self.login(init="localStorage.setItem('rp_theme', %s);" % json.dumps(theme))
            self.addCleanup(lambda p=page: self.reset(p))
            self.api(page, "POST", "/ui-prefs", {"look": "pilot"})
            self.reload(page)
            self.assertEqual((self.state(page)["look"], self.state(page)["theme"]), ("pilot", theme))
            seen, found = 0, []
            for name in pages:
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(2000)
                if name == "home":
                    self.wait_hero(page)
                res = _run_axe(page, self.axe, {})
                seen += sum(len(p.get("nodes") or []) for p in res.get("passes") or [])
                for v in res.get("violations") or []:
                    if v.get("impact") in _SERIOUS_IMPACTS:
                        for n in v.get("nodes") or []:
                            found.append("%s/%s: [%s] %s :: %s" % (theme, name, v["id"], (n.get("target") or ["?"])[0],
                                                                  n.get("html", "")[:90]))
            self.assertGreater(seen, 1500, "a sweep over almost nothing proves nothing: %d nodes passed" % seen)
            self.assertEqual(found, [], "\n".join(found))
            # the host drawer, a surface of its own, under the same look
            first = self.api(page, "GET", "/devices")[0]
            page.evaluate("([i, n]) => openDeviceDrawer(i, n)", [first["id"], first["name"]])
            page.wait_for_timeout(2500)
            res = page.evaluate("axe.run('#device-drawer', {}).then(r => r)")
            drawer = ["%s: %s" % (v["id"], (n.get("target") or ["?"])[0]) for v in res.get("violations") or []
                      if v.get("impact") in _SERIOUS_IMPACTS for n in v.get("nodes") or []]
            self.assertEqual(drawer, [], theme)

    def test_the_heros_own_text_reads_on_its_surface_in_pilot_and_in_other_palettes(self):
        for theme in ("pilot", "pilot-paper", "nord", "paper"):
            with self.subTest(theme=theme):
                page = self.login(init="localStorage.setItem('rp_theme', %s);" % json.dumps(theme))
                self.addCleanup(lambda p=page: self.reset(p))
                self.api(page, "POST", "/ui-prefs", {"look": "pilot"})
                self.reload(page)
                self.wait_hero(page)
                got = page.evaluate(HERO_CONTRAST)
                self.assertGreater(len(got["rows"]), 6, "the measure looked at almost nothing: %s" % got["rows"])
                self.assertEqual([r for r in got["rows"] if r["ratio"] < 4.5], [], theme)
                self.assertIsNotNone(got["forced"])
                self.assertLess(got["forced"], 4.5, "the measure cannot fail: a caption in its own background colour came back at %s" % got["forced"])

    def test_no_dot_has_its_glow_cut_off_by_the_box_that_holds_it(self):
        page = self.login(init="localStorage.setItem('rp_look', 'pilot');")
        self.addCleanup(lambda: self.reset(page))
        self.api(page, "POST", "/ui-prefs", {"look": "pilot"})
        self.reload(page)
        self.wait_hero(page)
        page.evaluate("() => { window._homeLastRender = null; window.loadHome = () => {}; }")     # Home redraws itself: freeze it while measuring
        for label, devs, sized in (("nine hosts in four groups", NINE_HOSTS, True), ("a hundred hosts", fleet(100), True),
                                   ("sixteen hundred and fifty hosts", fleet(1650), False)):
            page.evaluate(DRAW, devs)
            lit = page.eval_on_selector_all("#home-hero .pilot-matrix .pilot-dot:not(.is-none)", "els => els.length")
            self.assertGreater(lit, 0, label)
            got = page.evaluate(GLOW_CLIPPED, "#home-hero")
            if sized:
                self.assertGreater(got["examined"], 0, "%s: the measure looked at no shadow at all" % label)
            self.assertEqual(got["found"], [], "%s: a clipping box cuts the halo of a dot: %s" % (label, got["found"]))
        # the nine hosts again, and what the room is for: the first dot sits where it always sat, level with the label above and the
        # legend below, so the padding that makes room for the glow has been given back to the layout
        page.evaluate(DRAW, NINE_HOSTS)
        left = page.evaluate("""() => { const q = s => document.querySelector(s).getBoundingClientRect().left;
            return [q('#home-hero .pilot-field .pilot-eyebrow'), q('#home-hero .pilot-matrix .pilot-dot'), q('#home-hero .pilot-legend')]; }""")
        self.assertLess(abs(left[0] - left[1]), 0.5, left)
        self.assertLess(abs(left[2] - left[1]), 0.5, left)
        # the control: the defect itself. Take the room away and the same measure has to find the dots' halo cut by the matrix.
        page.evaluate("""() => { const m = document.querySelector('#home-hero .pilot-matrix');
                                 m.style.setProperty('padding', '0'); m.style.setProperty('margin', '0'); }""")
        cut = page.evaluate(GLOW_CLIPPED, "#home-hero")["found"]
        dots = [f for f in cut if f["el"].startswith("SPAN.pilot-dot") and f["clip"].startswith("DIV.pilot-matrix")]
        self.assertTrue(dots, "the measure cannot see the defect it was written for: %s" % cut)
        self.assertGreaterEqual(max(f["over"] for f in dots), 9.5, dots)
        self.assertIn("top", {f["side"] for f in dots})

    def test_the_hero_stays_inside_the_page_on_a_phone_and_with_a_huge_fleet(self):
        from test_a11y_axe import _SERIOUS_IMPACTS
        for size in ((1440, 900), (390, 844)):
            page = self.login(size=size, init="localStorage.setItem('rp_look', 'pilot');")
            self.addCleanup(lambda p=page: self.reset(p))
            self.api(page, "POST", "/ui-prefs", {"look": "pilot"})
            self.reload(page)
            self.wait_hero(page)
            width = page.evaluate("() => [document.documentElement.scrollWidth, innerWidth]")
            self.assertLessEqual(width[0], width[1] + 1, "the page scrolls sideways at %s: %s" % (size, width))
            box = page.evaluate("() => { const r = document.querySelector('#home-hero .pilot-hero').getBoundingClientRect();"
                                " return [r.left, r.right, innerWidth]; }")
            self.assertGreaterEqual(box[0], 0)
            self.assertLessEqual(box[1], box[2] + 1)
            # a fleet far larger than the demo's, drawn by the real module
            made = page.evaluate("""() => {
              const devs = []; for (let i = 0; i < 1650; i++) devs.push({id: 'x' + i, name: 'host' + String(i).padStart(4, '0'),
                group: 'g' + (i % 7), online: i % 11 !== 0, monitored: i % 13 !== 0});
              const host = document.getElementById('home-hero'); const t0 = performance.now();
              _pilotHeroRender(host, devs, {devices: []});
              const ms = performance.now() - t0, m = host.querySelector('.pilot-matrix');
              return { ms, dots: m.querySelectorAll('.pilot-dot').length, more: [...host.querySelectorAll('.pilot-cap')].map(e => e.textContent),
                       max: getComputedStyle(m).maxHeight, h: m.clientHeight, sh: m.scrollHeight, tab: m.getAttribute('tabindex'),
                       role: m.getAttribute('role'), hidden: m.getAttribute('aria-hidden'), sw: document.documentElement.scrollWidth, iw: innerWidth };
            }""")
            self.assertEqual(made["dots"], 1500)
            self.assertIn("+150", made["more"])
            self.assertEqual(made["max"], "340px")
            self.assertLessEqual(made["h"], 340)
            self.assertLessEqual(made["ms"], 2000, "drawing the largest field took %.0f ms" % made["ms"])
            self.assertLessEqual(made["sw"], made["iw"] + 1)
            if made["sh"] > made["h"] + 1:
                self.assertEqual((made["tab"], made["role"], made["hidden"]), ("0", "group", None), "a scrolling field is reachable")
            page.evaluate(self.axe.axe_script)
            res = page.evaluate("axe.run('#home-hero', {}).then(r => r)")
            bad = ["%s: %s" % (v["id"], (n.get("target") or ["?"])[0]) for v in res.get("violations") or []
                   if v.get("impact") in _SERIOUS_IMPACTS for n in v.get("nodes") or []]
            self.assertEqual(bad, [], size)


if __name__ == "__main__":
    unittest.main()
