"""v6.4.3: app-integrations.js is lazy — verified in a browser, not by reading.

57 KB moved off the eager path, which took the eager-JS budget from 435 bytes of
headroom back to ~56 KB and let the ratchet be tightened rather than raised
again. The migration was recorded as open work at the time precisely because it
looked risky: three of the module's renderers are called from the DEVICE DRAWER,
which is not page-scoped, so `_LAZY_PAGE_MODULES` alone cannot cover them and a
careless move renders those tabs blank for exactly the vendor devices the tabs
exist for.

Source analysis says it is safe: every direct call from eager code was
enumerated (three, all now behind an explicit `await _loadJsModule(...)`) and
everything else reaches the module through the data-action dispatcher, which
already loads the remaining modules and replays the click on an unknown action.

Source analysis is what said the last four UI defects in this release were fine.
So this drives a real browser: load the page, confirm the module is NOT fetched
at boot, then reach it both ways — by navigating to its page, and through the
dispatcher — and confirm its symbols become live each time.
"""

import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts that directory on sys.path for
# free, so the omission is invisible there; `python3 -m unittest
# tests.<this>` reaches the method and fails on the import.
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
_MODULE = "app-integrations.js"


def _browser_ok():
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as p:
            p.chromium.launch().close()
        return True
    except Exception:
        return False


class TestItIsNotEagerAnyMore(unittest.TestCase):
    """Cheap source-level facts. These cannot prove it WORKS, only that the
    move happened — the browser test below is the one that matters."""

    @classmethod
    def setUpClass(cls):
        cls.html = (_ROOT / "server" / "html" / "index.html").read_text(encoding="utf-8")
        cls.app = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )

    def test_no_eager_script_tag(self):
        self.assertNotIn(f'src="static/js/{_MODULE}', self.html)

    def test_a_control_module_is_still_eager(self):
        """Positive control: the extraction must be able to SEE an eager tag,
        or the assertion above passes for the wrong reason."""
        self.assertIn('src="static/js/app.js', self.html)

    def test_it_is_registered_for_its_own_page(self):
        self.assertIn(f"integrations: ['{_MODULE}']", self.app)

    def test_every_drawer_call_site_awaits_it(self):
        """The three renderers the drawer calls directly. The drawer is not
        page-scoped, so registration alone does not cover them."""
        for fn in (
            "_renderRouterosCard",
            "_renderOpnsenseCard",
            "_renderSynologyCard",
        ):
            i = self.app.index(fn + "(body")
            window = self.app[max(0, i - 500) : i]
            self.assertIn(
                f"_loadJsModule('{_MODULE}')",
                window,
                f"{fn} is called without awaiting the module it lives in — the "
                "drawer tab will render blank",
            )


@unittest.skipUnless(_browser_ok(), "no usable chromium")
class TestItActuallyLoadsOnDemand(unittest.TestCase):
    """The part source analysis cannot answer."""

    def _page(self, pw):
        browser = pw.chromium.launch()
        ctx = browser.new_context()
        page = ctx.new_page()
        fetched = []
        page.on("request", lambda r: fetched.append(r.url) if _MODULE in r.url else None)
        return browser, page, fetched

    def test_not_fetched_at_boot_then_fetched_on_demand(self):
        from playwright.sync_api import sync_playwright

        import e2e_harness

        # start_stack returns (base_url, shutdown) — a tuple, not an object.
        base_url, shutdown = e2e_harness.start_stack()
        try:
            with sync_playwright() as pw:
                browser, page, fetched = self._page(pw)
                try:
                    page.goto(base_url, wait_until="networkidle", timeout=90_000)
                    self.assertEqual(
                        [],
                        fetched,
                        "the module was fetched at boot — it is still eager in "
                        "effect, and the budget saving is imaginary",
                    )
                    # Reaching it must make its symbols live.
                    page.evaluate("() => _loadJsModule('%s')" % _MODULE)
                    page.wait_for_function(
                        "() => typeof _renderRouterosCard === 'function'",
                        timeout=30_000,
                    )
                    self.assertTrue(fetched, "on-demand load never fetched the module")
                finally:
                    browser.close()
        finally:
            shutdown()


if __name__ == "__main__":
    unittest.main()
