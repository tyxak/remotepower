#!/usr/bin/env python3
"""The smart-group preview in a real browser, on the seeded stack.

test_v801_smart_group_preview drives the handler. This signs in as an administrator and uses the editor the way a person does:

* the editor (Settings -> Tags & Groups -> Smart groups -> New smart group) has a Preview members button beside Save, and nothing is
  shown before it is pressed;
* pressing it shows "N hosts match" and the first names, for the rules as they stand in the form, before anything is saved: the count
  is the number of hosts the demo fleet holds for that rule, a rule that matches more than fifty names fifty of them and says so, a
  rule that matches none says 0, and no group has been created (the list of groups is the same afterwards);
* a host name that is markup is drawn as text and never as an element;
* the answer goes when a rule in the form changes, so it is never read against rules it was not made for;
* a form with no rule answers with the same words as a save, in the box;
* the saved group that follows has the members the preview listed;
* it fits: no sideways scroll at 1440, 768 and 390 px, in English, German and Arabic (where the page mirrors), the button is reachable
  by keyboard and drawn with a focus ring, and nothing logs a console error, a page error or a failed request on the way;
* focus: after a press from the keyboard (Enter or Space) the button is dimmed and aria-busy while the answer is on its way, a second
  press changes nothing, and focus is on the button again when the answer is in. The same holds for a button whose handler disables
  it itself, which a scan of the async handlers a data-action starts finds in 35 others (it counts a flag set anywhere in the body).

The button has a text label, so there is no icon-only button to check. The filename carries 'e2e', so make test-fast skips it; the
serial gate runs it.
"""
import os
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

LABELS = {"en": ("Preview members", "hosts match"), "de": ("Mitglieder in der Vorschau", "Hosts passen"),
          "ar": ("معاينة الأعضاء", "مضيفات مطابقة")}
WIDTHS = (1440, 768, 390)

FIT = """() => {
  const W = innerWidth, modal = document.querySelector('#smart-group-modal .modal'), btn = document.getElementById('sg-preview-btn');
  const box = document.getElementById('sg-preview'), r = btn.getBoundingClientRect(), m = modal.getBoundingClientRect();
  return { page: document.documentElement.scrollWidth - W, modal: modal.scrollWidth - modal.clientWidth,
           btn: { left: Math.round(r.left), right: Math.round(r.right), width: Math.round(r.width) },
           modalBox: { left: Math.round(m.left), right: Math.round(m.right) }, box: box.scrollWidth - box.clientWidth, dir: document.documentElement.dir };
}"""

RING = """() => { const el = document.activeElement, cs = getComputedStyle(el);
  return { id: el.id, outline: cs.outlineStyle, outlineWidth: parseFloat(cs.outlineWidth), shadow: cs.boxShadow, focusVisible: el.matches(':focus-visible') }; }"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheSmartGroupPreviewInABrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("the editor is backend-agnostic: exercised once")
        if not _HAVE_PLAYWRIGHT:
            browser_required.skip_or_fail("playwright is not installed")
        seeder = _ROOT / "packaging" / "seed-demo-data.py"
        cls.data_dir = tempfile.mkdtemp(prefix="rp-sgprev-e2e-")
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

    def clean(self, page, refused=0):
        """No page error, no console error and no failed request since the page was opened. `refused` is how many times the test
        itself asked the preview for something the server refuses (a form with no rule: a 400 is the answer it is there to show)."""
        seen = self.seen[id(page)]
        self.assertEqual(seen["errors"], [], "page errors")
        self.assertEqual([m for m in seen["console"] if "401" not in m and "Failed to load resource" not in m], [], "console errors")
        failed = [f for f in seen["failed"] if "/api/login" not in f and not f.startswith("401 ")]
        asked = [f for f in failed if f.startswith("400 ") and f.endswith("/api/smart-groups/preview")]
        self.assertEqual(len(asked), refused, "the preview was refused %d times, the test expected %d" % (len(asked), refused))
        self.assertEqual([f for f in failed if f not in asked], [], "failed requests")

    def api(self, page, method, path, body=None):
        if body is None:
            return page.evaluate("async ([m, p]) => await api(m, p)", [method, path])
        return page.evaluate("async ([m, p, b]) => await api(m, p, b)", [method, path, body])

    def open_editor(self, page):
        page.evaluate("showPage('settings')")
        page.wait_for_function("() => typeof openSmartGroupCreate === 'function'", timeout=30000)
        page.evaluate("openSmartGroupCreate()")
        page.wait_for_selector("#smart-group-modal.active", state="attached", timeout=15000)
        page.wait_for_selector("#sg-preview-btn", state="visible", timeout=15000)

    def fill(self, page, **fields):
        for key, value in fields.items():
            page.fill("#sg-" + key, value)

    def fleet(self, page):
        """Every host of the demo fleet as the page itself reads it."""
        data = self.api(page, "GET", "/devices")
        rows = data if isinstance(data, list) else (data or {}).get("devices") or []
        self.assertGreater(len(rows), 10, "control: the demo fleet is there")
        return rows

    def preview_text(self, page):
        return page.evaluate("() => document.getElementById('sg-preview').innerText.trim()")

    def press_preview(self, page):
        page.click("#sg-preview-btn")
        page.wait_for_function("() => { const t = document.getElementById('sg-preview').innerText; return t.trim() !== '' && !/Checking/.test(t); }",
                               timeout=30000)

    # ── the button ───────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_button_is_beside_save_and_nothing_is_shown_until_it_is_pressed(self):
        page = self.login()
        self.open_editor(page)
        self.assertEqual(self.preview_text(page), "")
        label = page.eval_on_selector("#sg-preview-btn", "e => e.textContent.trim()")
        self.assertEqual(label, "Preview members")
        order = page.evaluate("() => { const m = document.getElementById('smart-group-modal');"
                              " const ids = [...m.querySelectorAll('button')].map(b => b.id || b.dataset.action);"
                              " return ids; }")
        self.assertLess(order.index("sg-preview-btn"), order.index("saveSmartGroup"), "the preview comes before Save")
        self.clean(page)

    def test_it_shows_the_count_and_the_first_names_before_anything_is_saved(self):
        page = self.login()
        groups_before = self.api(page, "GET", "/smart-groups")["smart_groups"]
        fleet = self.fleet(page)
        some_group = next(h["group"] for h in fleet if h.get("group"))
        expect = [h for h in fleet if h.get("group") == some_group]
        self.open_editor(page)
        self.fill(page, group=some_group)
        self.press_preview(page)
        text = self.preview_text(page)
        self.assertRegex(text, r"^%d hosts? match" % len(expect), text)
        names = page.eval_on_selector_all("#sg-preview [data-sg-host]", "els => els.map(e => e.textContent.trim())")
        self.assertLessEqual(len(expect), 50, "control: the demo fleet is smaller than the cap, so every match is listed")
        self.assertEqual(sorted(names), sorted(h.get("name") or h.get("id") for h in expect))
        # nothing was created
        self.assertEqual(self.api(page, "GET", "/smart-groups")["smart_groups"], groups_before)
        self.clean(page)

    def test_a_rule_that_matches_none_says_zero(self):
        page = self.login()
        self.open_editor(page)
        self.fill(page, group="no-such-group-anywhere")
        self.press_preview(page)
        self.assertRegex(self.preview_text(page), r"^0 hosts match")
        self.assertEqual(page.eval_on_selector_all("#sg-preview [data-sg-host]", "els => els.length"), 0)
        self.clean(page)

    def test_fifty_names_of_a_longer_list_scroll_inside_their_box_and_say_so(self):
        """The demo fleet is smaller than fifty hosts, so the server's answer for a big fleet is put in the page's way (the handler
        tests hold the cap at 50 over 120 hosts); what is measured here is what the page does with it, in a real layout."""
        import json
        page = self.login()
        hosts = [{"id": "h%03d" % i, "name": ("host-%03d" % i) + ("-" + "very-long-name-" * 6 if i % 7 == 0 else "")} for i in range(50)]
        page.route("**/api/smart-groups/preview", lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps({"count": 120, "limit": 50, "hosts": hosts})))
        self.open_editor(page)
        self.fill(page, group="web")
        self.press_preview(page)
        text = self.preview_text(page)
        self.assertRegex(text, r"^120 hosts match")
        self.assertIn("The first 50 are shown.", text)
        self.assertEqual(page.eval_on_selector_all("#sg-preview [data-sg-host]", "els => els.length"), 50)
        for width in WIDTHS:
            with self.subTest(width=width):
                page.set_viewport_size({"width": width, "height": 900})
                page.wait_for_timeout(250)
                m = page.evaluate("""() => { const list = document.querySelector('#sg-preview .scroll-cap-sm'), cs = getComputedStyle(list);
                    return { overflowY: cs.overflowY, scrolls: list.scrollHeight > list.clientHeight, height: list.clientHeight,
                             sideways: list.scrollWidth - list.clientWidth, page: document.documentElement.scrollWidth - innerWidth }; }""")
                self.assertIn(m["overflowY"], ("auto", "scroll"), m)
                self.assertTrue(m["scrolls"], "fifty names did not scroll inside their box: %s" % m)
                self.assertLess(m["height"], 200, m)
                self.assertLessEqual(m["page"], 1, m)
        self.clean(page)

    def test_a_host_name_that_is_markup_is_drawn_as_text(self):
        page = self.login()
        self.open_editor(page)
        # the page's own renderer, with an answer that carries a hostile name (the server hands names back as text; the page escapes)
        page.evaluate("""() => {
          const real = window.api;
          window.api = async (m, p, b) => (p === '/smart-groups/preview'
            ? { count: 2, limit: 50, hosts: [{ id: 'x1', name: '<img src=x onerror=window.__pwn=1>' }, { id: 'x2', name: '"><script>window.__pwn=2</script>' }] }
            : real(m, p, b));
        }""")
        self.fill(page, group="web")
        self.press_preview(page)
        self.assertEqual(page.evaluate("() => document.querySelectorAll('#sg-preview img, #sg-preview script').length"), 0)
        self.assertIsNone(page.evaluate("() => window.__pwn || null"))
        names = page.eval_on_selector_all("#sg-preview [data-sg-host]", "els => els.map(e => e.textContent)")
        self.assertEqual(names, ['<img src=x onerror=window.__pwn=1>', '"><script>window.__pwn=2</script>'])
        self.clean(page)

    def test_the_answer_goes_when_a_rule_changes_and_an_empty_form_answers_as_a_save_does(self):
        page = self.login()
        self.open_editor(page)
        self.press_preview(page)
        self.assertEqual(self.preview_text(page), "at least one rule is required")
        fleet = self.fleet(page)
        self.fill(page, group=next(h["group"] for h in fleet if h.get("group")))
        self.press_preview(page)
        self.assertRegex(self.preview_text(page), r"hosts? match")
        page.fill("#sg-tag", "x")
        self.assertEqual(self.preview_text(page), "", "the answer was made for other rules")
        self.press_preview(page)
        self.assertRegex(self.preview_text(page), r"^\d+ hosts? match")
        page.fill("#sg-name", "typing-a-name-keeps-it")
        self.assertRegex(self.preview_text(page), r"hosts? match", "the name is not a rule")
        self.clean(page, refused=1)

    def test_the_group_saved_after_a_preview_has_the_members_it_listed(self):
        page = self.login()
        fleet = self.fleet(page)
        some_group = next(h["group"] for h in fleet if h.get("group"))
        self.open_editor(page)
        self.fill(page, group=some_group, name="preview-then-save")
        self.press_preview(page)
        listed = page.eval_on_selector_all("#sg-preview [data-sg-host]", "els => els.map(e => e.dataset.id)")
        page.click("[data-action='saveSmartGroup']")
        page.wait_for_function("async () => ((await api('GET', '/smart-groups?members=1')) || {smart_groups: []}).smart_groups"
                               ".some(g => g.name === 'preview-then-save')", timeout=30000)
        self.addCleanup(lambda: self.api(page, "DELETE", "/smart-groups/preview-then-save"))
        saved = next(g for g in self.api(page, "GET", "/smart-groups?members=1")["smart_groups"] if g["name"] == "preview-then-save")
        self.assertEqual(listed, saved["members"][:len(listed)])
        self.clean(page)

    # ── the fit ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_it_fits_in_three_languages_at_three_widths(self):
        page = self.login()
        self.open_editor(page)
        page.fill("#sg-group", "x" * 40)
        self.press_preview(page)
        for lang in ("en", "de", "ar"):
            page.evaluate("async l => { await _ensureI18n(); window.RPi18n.setLang(l, false); }", lang)
            label, counted = LABELS[lang]
            page.wait_for_function("l => document.getElementById('sg-preview-btn').textContent.trim() === l", arg=label, timeout=30000)
            for width in WIDTHS:
                with self.subTest(lang=lang, width=width):
                    page.set_viewport_size({"width": width, "height": 900})
                    page.wait_for_timeout(250)
                    fit = page.evaluate(FIT)
                    self.assertEqual(fit["dir"], "rtl" if lang == "ar" else "ltr")
                    self.assertLessEqual(fit["page"], 1, fit)
                    self.assertLessEqual(fit["modal"], 1, fit)
                    self.assertLessEqual(fit["box"], 1, fit)
                    self.assertGreaterEqual(fit["btn"]["left"], fit["modalBox"]["left"] - 1, fit)
                    self.assertLessEqual(fit["btn"]["right"], fit["modalBox"]["right"] + 1, fit)
            page.set_viewport_size({"width": 1440, "height": 900})
        self.assertIn(LABELS["ar"][1], page.evaluate("() => document.getElementById('sg-preview').innerText"),
                      "the answer was drawn in English before the language changed and translates with it")
        page.evaluate("window.RPi18n.setLang('en', false)")
        self.clean(page)

    def test_the_button_is_reachable_by_keyboard_and_shows_a_focus_ring(self):
        page = self.login()
        self.open_editor(page)
        page.focus("#sg-cpu")
        reached = False
        for _ in range(8):
            page.keyboard.press("Tab")
            ring = page.evaluate(RING)
            if ring["id"] == "sg-preview-btn":
                reached = True
                self.assertTrue(ring["focusVisible"], ring)
                self.assertTrue(ring["outline"] != "none" and ring["outlineWidth"] > 0 or ring["shadow"] != "none", ring)
                break
        self.assertTrue(reached, "Tab never reached the preview button")
        page.fill("#sg-group", "web")
        page.focus("#sg-preview-btn")
        page.keyboard.press("Enter")
        page.wait_for_function("() => /hosts? match/.test(document.getElementById('sg-preview').innerText)", timeout=30000)
        self.clean(page)

    def test_focus_is_on_the_button_when_the_answer_is_in_after_a_press_from_the_keyboard(self):
        """Pressing the button used to disable it from inside its own handler, and a disabled control that has focus leaves it on the
        body: a keyboard user started again from the top of the page and a screen reader lost its place. The dispatcher dims the button
        while the answer comes (aria-busy), ignores a second press, and gives focus back when the answer is in."""
        page = self.login()
        self.open_editor(page)
        page.fill("#sg-group", "web")
        # a slow answer, so that the presses below land while it is in flight; the page's own api() answers after it
        page.evaluate("""() => { window.__previews = 0; const real = window.api;
          window.api = async (m, p, b) => { if (p === '/smart-groups/preview') { window.__previews++; await new Promise(r => setTimeout(r, 700)); }
                                            return real(m, p, b); }; }""")
        where = """() => { const b = document.getElementById('sg-preview-btn'), a = document.activeElement;
                           return { id: a.id || a.tagName, busy: b.getAttribute('aria-busy'), disabled: b.disabled,
                                    previews: window.__previews }; }"""
        for first, again in (("Enter", "Enter"), ("Space", "Enter")):
            with self.subTest(key=first):
                page.evaluate("() => { _clearSmartGroupPreview(); window.__previews = 0; }")        # the box is empty again, as a change to a rule leaves it
                page.focus("#sg-preview-btn")
                page.keyboard.press(first)
                page.wait_for_timeout(200)                         # the answer is held for 700 ms: this is while it is on its way
                busy = page.evaluate("() => document.getElementById('sg-preview-btn').getAttribute('aria-busy')")
                self.assertEqual(busy, "true", "the dispatcher did not mark the button busy while the answer was on its way")
                page.keyboard.press(again)                         # one more press changes nothing
                page.wait_for_function("() => /hosts? match/.test(document.getElementById('sg-preview').innerText)", timeout=30000)
                page.wait_for_function("() => !document.getElementById('sg-preview-btn').disabled", timeout=10000)
                got = page.evaluate(where)
                self.assertEqual(got, {"id": "sg-preview-btn", "busy": None, "disabled": False, "previews": 1}, got)
        self.clean(page)

    def test_a_button_whose_handler_disables_it_gets_focus_back_too(self):
        """Older handlers disable the button they were started from, before their first await (a scan of the async handlers a data-action
        starts finds 35 besides this one that set a disabled flag in their body). The control is the browser: it drops focus when the
        focused button is disabled; the dispatcher read the focus before the handler ran and gives it back."""
        page = self.login()
        got = page.evaluate("""async () => {
            const b = document.createElement('button'); b.id = 'kb-self'; b.textContent = 'x'; document.body.appendChild(b);
            window.kbSelfDisable = async () => { b.disabled = true; await new Promise(r => setTimeout(r, 150)); b.disabled = false; };
            b.setAttribute('data-action', 'kbSelfDisable'); b.focus();
            b.click();
            const during = document.activeElement === b;
            await new Promise(r => setTimeout(r, 500));
            const after = document.activeElement === b;
            b.remove();
            return { during, after };
        }""")
        self.assertFalse(got["during"], "control: the browser leaves focus on the body when the focused button is disabled")
        self.assertTrue(got["after"], "focus was not given back to the button its handler had disabled: %s" % got)
        self.clean(page)


if __name__ == "__main__":
    unittest.main()
