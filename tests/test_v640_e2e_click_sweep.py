#!/usr/bin/env python3
"""v6.4.0: click-simulation sweep — every data-action button actually CLICKED.

The page-smoke suite proves every page OPENS clean; nothing ever pressed the
buttons. This crawls each sidebar page and genuinely clicks one instance of
every visible `data-action` / `data-action-btn` control (real Chromium click →
the real dispatcher → the real handler), failing on any uncaught JS error
attributed to the action that triggered it.

Scope notes:
- The stack is a scratch data dir, so "destructive" clicks are safe — that's
  the point (a delete handler that throws is exactly what we're hunting).
- Session-ending and stack-ending actions are denylisted (logout etc.), as are
  actions that intentionally navigate away from the SPA.
- Modals opened by a click are force-closed before the next click; a native
  dialog (none should exist post-uiConfirm migration) is auto-dismissed.
- Empty-fleet reality: row-level buttons don't render without devices, so this
  covers the static controls + empty-state CTAs — the majority surface.

Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import re
import unittest
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False

_ROOT = Path(__file__).resolve().parent.parent

# Actions that end the session / navigate off the SPA / stop the stack.
_DENY = re.compile(
    r"logout|doLogout|downloadDiagnostics|exportEverything|restartServer|"
    r"shutdownServer|factoryReset|serverSelfUpdate|openSwagger|openApiDocs",
    re.I)


def _sidebar_pages():
    html = (_ROOT / "server/html/index.html").read_text()
    pages = []
    for m in re.finditer(r'class="nav-btn[^"]*" data-page="([a-z-]+)"', html):
        if m.group(1) not in pages:
            pages.append(m.group(1))
    return pages


@unittest.skipUnless(_HAVE_PLAYWRIGHT, "playwright not installed (pip install "
                     "playwright && python -m playwright install chromium)")
class TestEveryButtonClicksClean(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os as _os
        import sys as _sys
        _here = _os.path.dirname(_os.path.abspath(__file__))
        if _here not in _sys.path:
            _sys.path.insert(0, _here)
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            raise unittest.SkipTest(f"chromium not available: {exc}")
        try:
            cls.base, cls._shutdown = start_stack()
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f"app stack not available: {exc}")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def test_click_every_visible_action_on_every_page(self):
        page = self.browser.new_page()
        errors = []          # (page, action, error)
        current = ["login", "-"]
        page.on("pageerror",
                lambda e: errors.append((current[0], current[1], str(e))))
        page.on("dialog", lambda d: d.dismiss())

        page.goto(self.base + "/index.html")
        page.fill("#login-user", "admin")
        page.fill("#login-pass", "remotepower")
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector("#app", state="visible", timeout=15000)
        # Kill the onboarding tour backdrop (fresh data dir auto-starts it).
        page.evaluate("document.getElementById('tour-backdrop')?.remove();"
                      "document.getElementById('tour-pop')?.remove();")

        clicked_total = 0
        for pg in _sidebar_pages():
            current[0] = pg
            current[1] = "(navigate)"
            page.evaluate(
                "(p) => { const b = document.querySelector("
                "`.nav-btn[data-page='${p}']`); if (b) b.click(); }", pg)
            page.wait_for_timeout(250)
            # unique action names among VISIBLE controls on this page
            names = page.evaluate("""() => {
              const out = new Set();
              for (const el of document.querySelectorAll(
                       '[data-action],[data-action-btn]')) {
                const r = el.getBoundingClientRect();
                if (r.width > 0 && r.height > 0) {
                  out.add(el.dataset.action || el.dataset.actionBtn);
                }
              }
              return [...out];
            }""")
            for name in names:
                if not name or _DENY.search(name):
                    continue
                current[1] = name
                page.evaluate("""(name) => {
                  const els = document.querySelectorAll(
                    `[data-action='${name}'],[data-action-btn='${name}']`);
                  for (const el of els) {
                    const r = el.getBoundingClientRect();
                    if (r.width > 0 && r.height > 0) { el.click(); return; }
                  }
                }""", name)
                clicked_total += 1
                page.wait_for_timeout(60)
                # force-close whatever the click opened so the page stays usable
                page.evaluate(
                    "document.querySelectorAll('.modal-overlay.active')"
                    ".forEach(m => m.classList.remove('active'));"
                    "document.querySelectorAll('.drawer.open')"
                    ".forEach(d => d.classList.remove('open'));")
            # settle any late async fallout still attributed to this page
            current[1] = "(settle)"
            page.wait_for_timeout(150)

        page.close()
        self.assertGreater(clicked_total, 150,
                           "click enumeration collapsed — the sweep clicked "
                           f"only {clicked_total} actions")
        listing = [f"{p} → {a}: {e.splitlines()[0][:160]}"
                   for p, a, e in errors]
        self.assertEqual(listing, [],
                         f"uncaught JS errors from real clicks "
                         f"({clicked_total} actions clicked):\n  "
                         + "\n  ".join(listing))


if __name__ == "__main__":
    unittest.main()
