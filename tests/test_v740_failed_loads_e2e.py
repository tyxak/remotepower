#!/usr/bin/env python3
"""7.4.0: a page never stays on "Loading…", and never prints "undefined", whatever the server answers.

Two walks over every sidebar page, each in a browser against the real stack:

  * a fresh install (nothing configured, no hosts): every optional module is off, every list is
    empty, and a loader that only handles the "enabled" case leaves its card waiting forever.
    Provisioning did: the Ansible card sat on "Loading…" for as long as Provisioning was off,
    which is the default.
  * every GET answered with a 500: a loader that treats an error body as data prints
    "undefined hosts" (Power, Disk health), and one that stops early leaves the cards it was
    going to fill on "Loading…" (Alerts, Tuning, KMIP, Compliance, Patches).

A page that fails to load has to say so and offer a retry. The control: a placeholder injected
into a page must be found by the same measurement, so a pass cannot come from looking at nothing.
"""
import os
import re
import sys
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

# Text that means "a loader has not finished". The skeleton blocks are not text and do not count.
_STUCK = """() => [...document.querySelectorAll('#app .page.active *')]
  .filter(e => e.children.length === 0 && /^\\s*Loading(…|\\.\\.\\.)?\\s*$/.test(e.textContent) && e.offsetParent)
  .map(e => { let a = e; while (a && !a.id) a = a.parentElement; return (a ? a.id : '?') + '/' + e.tagName; })"""

_BROKEN_TEXT = re.compile(r'\bundefined\b|\bNaN\b|\[object ')

# Paths a signed-in page has no way to survive losing, and the sign-in itself.
_KEEP = ('/auth', '/login', '/session', '/me')

# Pages whose "Loading…" is not a loader: none yet. Each entry needs a reason.
EXEMPT = {}


class TestNoPageStaysLoading(unittest.TestCase):
    # Numbered: the Server status page lists the errors the browser reported, so the walk that causes
    # errors has to run after the one that reads that page.
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic, measured once')
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack()
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

    def _walk(self, fail_gets):
        """{page: [problems]} for every sidebar page, plus the count of pages visited."""
        # The service worker would answer some requests itself, past page.route().
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        page = ctx.new_page()
        refused = []
        page.on('response', lambda r: refused.append((r.status, r.url.split('/api/')[-1][:60]))
                if r.status >= 400 and not fail_gets else None)
        thrown = []
        page.on('pageerror', lambda e: thrown.append(str(e)[:120]))
        found, visited = {}, 0
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'admin')
            page.fill('#login-pass', 'remotepower')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            if fail_gets:
                page.route('**/api/**', lambda r: r.fulfill(
                    status=500, content_type='application/json', body='{"error":"boom"}')
                    if r.request.method == 'GET' and not any(k in r.request.url for k in _KEEP)
                    else r.continue_())
            for name in self._pages():
                before = len(refused)
                threw = len(thrown)
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(2500)
                problems = []
                if name not in EXEMPT:
                    problems += ['still loading: ' + s for s in page.evaluate(_STUCK)]
                text = page.evaluate("() => { const p = document.querySelector('#app .page.active');"
                                     " return p ? p.innerText : '' }")
                for m in _BROKEN_TEXT.finditer(text):
                    problems.append('prints %r: ...%s...' % (m.group(0), text[max(0, m.start() - 30):m.end() + 30]
                                                             .replace('\n', ' ')))
                    break
                if thrown[threw:]:
                    problems.append('uncaught: %s' % thrown[threw:][:2])
                if refused[before:]:
                    problems.append('answered %s' % refused[before:][:3])
                visited += 1
                if problems:
                    found[name] = problems
        finally:
            page.close(); ctx.close()
        return visited, found

    def test_1_a_fresh_install_finishes_loading_everywhere(self):
        visited, found = self._walk(fail_gets=False)
        self.assertGreaterEqual(visited, 80, 'the walk visited fewer pages than exist')
        self.assertEqual(found, {}, 'on a fresh install these pages wait, print a broken value or hit an error:\n'
                         + '\n'.join('  %s: %s' % kv for kv in sorted(found.items())))

    def test_2_a_failing_server_leaves_no_card_waiting(self):
        visited, found = self._walk(fail_gets=True)
        self.assertGreaterEqual(visited, 80, 'the walk visited fewer pages than exist')
        self.assertEqual(found, {}, 'with every GET answering 500 these pages wait or print a broken value:\n'
                         + '\n'.join('  %s: %s' % kv for kv in sorted(found.items())))

    def test_3_the_measurement_finds_a_placeholder(self):
        """Control: a "Loading…" cell added to the active page is reported."""
        ctx = self.browser.new_context(service_workers='block')
        page = ctx.new_page()
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'admin')
            page.fill('#login-pass', 'remotepower')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(3000)
            page.evaluate("() => { const p = document.querySelector('#app .page.active');"
                          " const d = document.createElement('div'); d.id = 'probe-card';"
                          " d.innerHTML = '<div class=\"empty-state\">Loading…</div>'; p.appendChild(d); }")
            self.assertIn('probe-card/DIV', page.evaluate(_STUCK))
        finally:
            page.close(); ctx.close()


if __name__ == '__main__':
    unittest.main()
