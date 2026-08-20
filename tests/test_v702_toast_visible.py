#!/usr/bin/env python3
"""No toast in the product was ever visible.

`styles.css:4112` declares `.toast-container { display: flex }`. 700 lines
later, `:4812` declared `.toast-container { display: none }` — same specificity,
no !important, later in the same file, so it won. Every toast the product
raises was built, appended and timed out inside a zero-height container.

It came from the CSP L1 migration. The rule started life in an inline `<style>`
in `<head>`, BEFORE the stylesheet `<link>` — an anti-FOUC hide that the
stylesheet then overrode on load. Moved into the stylesheet it landed after the
canonical declaration instead of before it, and the hide became permanent. The
comment above the canonical rule still says that `<style>` "was removed"; it had
been relocated.

`.refresh-bar` sat in the same migrated block with the same collision, so the
auto-refresh progress strip was invisible too while app.js kept driving its
scaleX transform once a second.

This is a rendered gate on purpose. Every rule involved is individually correct
and the source reads as though toasts work — the only place the fault is visible
is the cascade, which means a browser. It is also why the source-level typography
and class-parity gates never saw it.
"""
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CSS = _ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'
_HTML = _ROOT / 'server' / 'html' / 'index.html'

try:
    from playwright.sync_api import sync_playwright
    _PW = True
except ImportError:                                    # pragma: no cover
    _PW = False


def _browser_available():
    if not _PW:
        return False
    try:
        with sync_playwright() as p:
            p.chromium.launch().close()
        return True
    except Exception:
        return False


# __CSS__ is substituted with str.replace, not %-formatting: the page
# text contains literal percent signs (translateX(120%)) that would
# break a format string.
_PAGE = """<!doctype html><html><head><style>__CSS__</style></head><body>
<div class="toast-container" id="toast-container" role="status"
     aria-live="polite" aria-atomic="true"></div>
<div class="refresh-bar"><div class="refresh-progress w-full"
     id="refresh-progress"></div></div>
<script>
  const c = document.getElementById('toast-container');
  for (const kind of ['success', 'error']) {
    const e = document.createElement('div');
    e.className = 'toast ' + kind;
    e.textContent = kind === 'error' ? 'Could not save' : 'Saved';
    c.appendChild(e);
    // app.js adds .show on the next frame; `.toast` starts at
    // translateX(120%), so measuring without it reads the pre-slide position
    // and reports a correct toast as off-screen. Mirror the real sequence.
    e.classList.add('show');
  }
</script></body></html>"""


@unittest.skipUnless(_browser_available(), 'no Chromium available')
class TestAToastIsActuallyOnScreen(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._pw = sync_playwright().start()
        cls._b = cls._pw.chromium.launch()
        cls.page = cls._b.new_page()
        cls.page.set_viewport_size({'width': 1280, 'height': 900})
        cls.page.set_content(_PAGE.replace('__CSS__', _CSS.read_text()))

    @classmethod
    def tearDownClass(cls):
        cls._b.close()
        cls._pw.stop()

    def test_the_instrument_can_see_a_styled_element(self):
        """Positive control. If the stylesheet did not load, every assertion
        below would report a finding that is really an empty page."""
        h = self.page.evaluate(
            "() => getComputedStyle(document.querySelector('.toast.success'))"
            ".borderLeftWidth")
        self.assertNotEqual('0px', h,
                            'the stylesheet did not load — nothing below means '
                            'anything')

    def test_the_container_is_not_display_none(self):
        self.assertEqual('flex', self.page.evaluate(
            "() => getComputedStyle(document.getElementById('toast-container'))"
            ".display"))

    def test_a_toast_has_a_real_box(self):
        box = self.page.evaluate(
            "() => document.querySelector('.toast.success')"
            ".getBoundingClientRect()")
        self.assertGreater(box['height'], 20, 'the toast has no height')
        self.assertGreater(box['width'], 80, 'the toast has no width')

    def test_a_toast_is_inside_the_viewport(self):
        """Rendered but positioned off-screen is the same outcome for the
        operator as not rendered at all."""
        r = self.page.evaluate("""() => {
            const t = document.querySelector('.toast.error').getBoundingClientRect();
            return {t: {top: t.top, left: t.left, bottom: t.bottom, right: t.right},
                    w: innerWidth, h: innerHeight};
        }""")
        t = r['t']
        self.assertGreaterEqual(t['bottom'], 0)
        self.assertLessEqual(t['top'], r['h'])
        self.assertGreaterEqual(t['right'], 0)
        self.assertLessEqual(t['left'], r['w'])

    def test_the_error_toast_is_visible_too(self):
        """The api() error path added this release raises error toasts. If the
        container is hidden that fix reports failures to nobody."""
        self.assertTrue(self.page.evaluate(
            "() => {const t = document.querySelector('.toast.error');"
            " return !!(t.offsetWidth || t.offsetHeight);}"))

    def test_the_refresh_strip_renders(self):
        r = self.page.evaluate(
            "() => {const b = document.querySelector('.refresh-bar');"
            " return {d: getComputedStyle(b).display,"
            "         h: b.getBoundingClientRect().height};}")
        self.assertNotEqual('none', r['d'])
        self.assertGreater(r['h'], 0,
                           'app.js drives this strip once a second; hidden, '
                           'that work paints nothing')


class TestNoLaterRuleReHidesThem(unittest.TestCase):
    """Source-level backstop that cannot skip. The rendered class above needs a
    browser; this one runs everywhere and catches a re-introduction directly."""

    _TARGETS = ('.toast-container', '.refresh-bar')

    def test_no_unconditional_display_none_after_the_canonical_rule(self):
        css = _CSS.read_text()
        stripped = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
        for sel in self._TARGETS:
            anchor = stripped.index(sel + '  ') if (sel + '  ') in stripped \
                else stripped.index(sel)
            tail = stripped[anchor:]
            for m in re.finditer(
                    re.escape(sel) + r'\s*\{([^}]*)\}', tail):
                body = m.group(1)
                if 'display' not in body or 'none' not in body:
                    continue
                # A hide scoped to a state (printing, a body class) is fine —
                # only an unconditional one at top level is the bug.
                before = tail[:m.start()]
                depth = before.count('{') - before.count('}')
                self.assertGreater(
                    depth, 0,
                    f'{sel} is hidden again by a top-level rule after its '
                    f'canonical declaration — this is the cascade bug that '
                    f'made every toast invisible')

    def test_the_canonical_declarations_are_still_there(self):
        """Positive control for the scan above: deleting the display:flex rule
        would also make the assertion pass, for the wrong reason."""
        css = _CSS.read_text()
        self.assertRegex(css, r'\.toast-container\s*\{[^}]*display:\s*flex')
        self.assertRegex(css, r'\.refresh-bar\s*\{[^}]*display:\s*block')

    def test_index_html_has_no_inline_style_block_reintroducing_it(self):
        html = _HTML.read_text()
        for m in re.finditer(r'<style[^>]*>(.*?)</style>', html, re.S):
            for sel in self._TARGETS:
                self.assertNotIn(sel, m.group(1),
                                 f'{sel} is styled from an inline <style> '
                                 'again — that is where this bug came from')


if __name__ == '__main__':
    unittest.main()
