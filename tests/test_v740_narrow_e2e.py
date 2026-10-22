#!/usr/bin/env python3
"""7.4.0: no page scrolls sideways on a phone, in any of the five translations that run longer than English.

390 px wide, every sidebar page and every Settings pane on the seeded instance. Each page is rendered
once and then switched between languages in place (RPi18n.setLang), so the same DOM is measured in
each and the numbers line up.

Measured on 2026-10-22, 97 views x 5 languages: nine views ran past the screen. Four were a row of
buttons that cannot wrap ("Envoyer un e-mail de test" next to two other buttons on the ticket
mailbox pane, "Tester la connexion" on Proxmox), the rest were the faint page watermark, whose
fixed box reached past the right edge in a right-to-left page. Chinese and Hindi were clean.

The control injects a 700 px wide block into the page and expects to see it.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import browser_required

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

LANGS = ('zh', 'hi', 'es', 'ar', 'fr', 'de')
WIDTH = 390

_WIDER = "() => document.documentElement.scrollWidth - window.innerWidth"

# Who sticks out: the elements that span past either edge (the left edge scrolls in a right-to-left page). The sidebar is
# parked off-screen on a phone and the skip link sits outside on purpose, so neither counts.
_WHO = """() => {
  const W = window.innerWidth, out = [];
  document.querySelectorAll('body *').forEach(el => {
    if (el.closest('.sidebar, .skip-link, svg')) return;
    const r = el.getBoundingClientRect();
    if (r.width === 0 || (r.right <= W + 1 && r.left >= -1)) return;
    const cs = getComputedStyle(el);
    if (cs.display === 'none') return;
    let p = el.parentElement, clipped = false;
    while (p && p !== document.body) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') { clipped = true; break; } p = p.parentElement; }
    if (clipped) return;
    out.push(cs.position + ' ' + el.tagName + (el.id ? '#' + el.id : '') + '.' + String(el.className.baseVal !== undefined ? el.className.baseVal : el.className).slice(0, 30) + ' "' + (el.textContent || '').trim().slice(0, 24) + '" spans ' + Math.round(r.left) + '..' + Math.round(r.right) + ' in ' + (() => { const c = []; let q = el.parentElement; while (q && c.length < 4 && q !== document.body) { const b = q.getBoundingClientRect(); c.push(q.tagName + '.' + String(q.className).slice(0, 20) + '[' + getComputedStyle(q).display + ' ' + Math.round(b.left) + '..' + Math.round(b.right) + ']'); q = q.parentElement; } return c.join(' < '); })());
  });
  return out.slice(-3);
}"""


class TestNoPageScrollsSidewaysOnAPhone(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic, measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-narrow-')
        proc = subprocess.run(
            [sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply'],
            capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            cls.browser.close(); cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close(); cls._pw.stop()
        finally:
            cls._shutdown()

    def _pages(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        seen, out = set(), []
        for m in re.finditer(r'class="nav-btn[^"]*"[^>]*\sdata-page="([a-z-]+)"', html):
            if m.group(1) not in seen:
                seen.add(m.group(1)); out.append(m.group(1))
        return out

    def _login(self):
        ctx = self.browser.new_context(viewport={'width': WIDTH, 'height': 900}, service_workers='block')
        page = ctx.new_page()
        page.goto(self.base + '/index.html')
        page.fill('#login-user', 'alice')
        page.fill('#login-pass', 'demo')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=90000)
        page.wait_for_timeout(6000)
        # i18n.js is loaded on demand. Without this, RPi18n is undefined, every setLang below throws
        # inside a try/catch, and the whole walk measures English six times.
        page.evaluate("() => _ensureI18n()")
        return ctx, page

    def test_every_view_fits_the_screen_in_every_language(self):
        ctx, page = self._login()
        wide, views = {}, 0
        # Control: the switch has to take. Arabic turns the document right to left; English turns it back.
        page.evaluate("() => RPi18n.setLang('ar', false)")
        page.wait_for_timeout(300)
        self.assertEqual(page.evaluate("() => document.documentElement.dir"), 'rtl', 'setLang did not switch the page')
        page.evaluate("() => RPi18n.setLang('en', false)")

        def measure(view):
            nonlocal views
            views += 1
            for lang in LANGS:
                page.evaluate("l => { try { RPi18n.setLang(l, false) } catch (e) {} }", lang)
                page.wait_for_timeout(120)
                over = page.evaluate(_WIDER)
                if over > 1:
                    wide.setdefault(view, []).append('%s +%dpx %s' % (lang, over, page.evaluate(_WHO)))
            page.evaluate("() => { try { RPi18n.setLang('en', false) } catch (e) {} }")

        try:
            for name in self._pages():
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(1500)
                measure(name)
                if name == 'settings':
                    tabs = page.evaluate("() => [...document.querySelectorAll('.settings-tab[data-tab]')]"
                                         ".map(b => b.dataset.tab)")
                    for tb in tabs:
                        try:
                            page.evaluate("t => document.querySelector('.settings-tab[data-tab=\"'+t+'\"]').click()", tb)
                        except Exception:
                            continue
                        page.wait_for_timeout(400)
                        measure('settings:' + tb)
        finally:
            page.close(); ctx.close()
        self.assertGreaterEqual(views, 90, 'the walk visited fewer views than exist')
        self.assertEqual(wide, {}, 'these views scroll sideways at %d px:\n%s' % (
            WIDTH, '\n'.join('  %s: %s' % kv for kv in sorted(wide.items()))))

    def test_the_measurement_sees_a_wide_block(self):
        """Control: a block wider than the screen is reported."""
        ctx, page = self._login()
        try:
            page.evaluate("() => { const d = document.createElement('div');"
                          " d.style.cssText = 'width:700px;height:4px'; d.id = 'probe-wide';"
                          " document.querySelector('#app .page.active').appendChild(d); }")
            self.assertGreater(page.evaluate(_WIDER), 100)
        finally:
            page.close(); ctx.close()


if __name__ == '__main__':
    unittest.main()
