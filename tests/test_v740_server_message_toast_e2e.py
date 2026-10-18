#!/usr/bin/env python3
"""7.4.0: a refused request reads in the person's language, with the request left as it is.

api() used to toast "GET /devices/x/checks failed — Host not found": one text node holding a
method, a path and the reason. The translator matches a whole text node against the dictionary, so
no message could ever be shown in German. The toast is now the reason alone, with the request on a
line of its own ("GET /devices/x/checks · 404") that the translator skips.

tests/test_v740_server_messages_i18n.py asks the engine's lookup for every message. This drives the
rest of the path in a real browser against the real server: the toast markup, the tree walker that
visits its text node, the observer that notices a node added after the page loaded, and the history
list that prints the same message a second time. The two halves are each correct on their own; only
the pair shows the person a translated refusal.

Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import os as _os
import sys as _sys
import unittest

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402
import browser_required  # noqa: E402

_GATE = browser_available() or browser_required.required()

if browser_available():
    from playwright.sync_api import sync_playwright

LANGS = ('de', 'fr', 'es', 'zh', 'hi', 'ar')
MESSAGE = 'Host not found'                       # what GET /api/devices/<unknown>/checks answers, with a 404
PATH = '/devices/ghost-host/checks'


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestARefusalReadsInYourLanguage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not browser_available():
            browser_required.skip_or_fail(SKIP_REASON)
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
            cls.browser.close()
            cls._pw.stop()
            browser_required.skip_or_fail(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def _open_app(self):
        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.goto(self.base + '/index.html')
        page.fill('#login-user', 'admin')
        page.fill('#login-pass', 'remotepower')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=30000)
        # The dictionary is a script the app fetches on demand (English never needs it); its promise settles when RPi18n exists.
        page.evaluate("() => _ensureI18n()")
        return page

    def _refuse(self, page):
        """Make the server refuse a request through the page's own api(), the way a click does."""
        page.evaluate("document.querySelectorAll('.toast').forEach(t => t.remove())")
        page.evaluate("path => api('GET', path)", PATH)
        page.wait_for_selector('.toast.error', timeout=10000)

    def _toast(self, page):
        return page.evaluate("""() => {
            const t = [...document.querySelectorAll('.toast.error')].pop();
            const body = t.children[1];                       // the message span; the icon is children[0]
            const detail = body.querySelector('.toast-detail');
            return {message: body.firstChild.nodeValue, detail: detail && detail.textContent,
                    detailDir: detail && detail.getAttribute('dir'), nodes: body.childNodes.length};
        }""")

    def test_english_is_the_reason_and_the_request_sits_under_it(self):
        page = self._open_app()
        self._refuse(page)
        got = self._toast(page)
        self.assertEqual(got['message'], MESSAGE)
        self.assertEqual(got['detail'], f'GET {PATH} · 404')
        self.assertEqual(got['detailDir'], 'ltr')
        self.assertEqual(got['nodes'], 2, 'the message and the request line are two nodes')

    def test_every_language_translates_the_message_and_leaves_the_request_alone(self):
        page = self._open_app()
        for lang in LANGS:
            with self.subTest(lang=lang):
                page.evaluate("l => RPi18n.setLang(l, false)", lang)
                expected = page.evaluate("m => RPi18n.t(m)", MESSAGE)
                self.assertNotEqual(expected, MESSAGE, f'{lang}: the dictionary has no entry for {MESSAGE!r}')
                self._refuse(page)
                # The observer translates a node added after the page loaded; give it a moment.
                page.wait_for_function(
                    """e => { const t = [...document.querySelectorAll('.toast.error')].pop();
                              return t && t.children[1].firstChild.nodeValue.trim() === e; }""",
                    arg=expected, timeout=5000)
                got = self._toast(page)
                self.assertEqual(got['message'].strip(), expected)
                self.assertEqual(got['detail'], f'GET {PATH} · 404', f'{lang}: the request line must not be translated')
                self.assertEqual(got['detailDir'], 'ltr')

    def test_the_history_list_translates_the_same_message(self):
        page = self._open_app()
        page.evaluate("l => RPi18n.setLang(l, false)", 'de')
        expected = page.evaluate("m => RPi18n.t(m)", MESSAGE)
        self._refuse(page)
        page.click('#toast-history-btn')
        page.wait_for_selector('#toast-history-list .toast-hist-msg', timeout=5000)
        page.wait_for_function(
            """e => { const m = document.querySelector('#toast-history-list .toast-hist-msg');
                      return m && m.firstChild.nodeValue.trim() === e; }""",
            arg=expected, timeout=5000)
        detail = page.evaluate("document.querySelector('#toast-history-list .toast-detail').textContent")
        self.assertEqual(detail, f'GET {PATH} · 404')

    def test_switching_back_to_english_restores_the_message(self):
        page = self._open_app()
        page.evaluate("l => RPi18n.setLang(l, false)", 'fr')
        self._refuse(page)
        page.evaluate("l => RPi18n.setLang(l, false)", 'en')
        page.wait_for_function(
            """m => { const t = [...document.querySelectorAll('.toast.error')].pop();
                      return t && t.children[1].firstChild.nodeValue.trim() === m; }""",
            arg=MESSAGE, timeout=5000)


if __name__ == '__main__':
    unittest.main()
