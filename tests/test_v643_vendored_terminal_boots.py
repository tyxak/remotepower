#!/usr/bin/env python3
"""The vendored terminal must actually start, not merely be present on disk.

Earlier this cycle a Swagger UI version bump rendered the API Reference
completely blank. The files were correct, the diff looked perfect, and the only
evidence was a console message: the SRI hashes still pinned the old bytes, so
the browser refused to execute either resource. `test_v306` catches that exact
failure now by recomputing each vendored file's SHA-384 and requiring the pin to
match.

This file covers the other half — that the library, once loaded, still WORKS.
A hash can match a file that a major version bump has made incompatible with the
five calls we make against it, and the symptom is the same either way: an empty
box where the terminal should be, discovered by an operator rather than a test.

The web terminal is the highest-consequence place for that. It is how an
operator reaches a host that is already in trouble, so it fails at exactly the
moment nobody has patience for it.

WHAT THIS DRIVES, deliberately mirroring `app-remote.js`:
  * `new Terminal({...})` with the same constructor options, including the
    self-hosted JetBrains Mono font stack;
  * `loadAddon(new FitAddon())`, `open()`, `fit()`, `focus()`;
  * `write()` with an ANSI colour escape, then reads the terminal BUFFER to
    confirm the text arrived and the escape was consumed rather than printed;
  * real keystrokes through the browser, asserting they reach `onData` — that
    is the callback the websocket sends to the remote shell, so if it breaks,
    typing goes nowhere;
  * a resize, asserting `onResize` fires — that is what keeps the remote pty's
    geometry correct.

It cannot reach a real shell, and that limit is why the 6.0.0 bump sat deferred.
What it can do is exercise every boundary between our code and the library,
which is where a major version bump actually breaks.

TWO TRAPS, both of which produced a confident wrong answer while writing this:
  1. `write()` is QUEUED and flushed on a later frame. Reading the buffer in the
     same evaluate returns an empty string on every version — which looks like a
     dead renderer and is a dead probe. Read after a flush.
  2. `innerText` of the terminal container is empty regardless of whether
     anything rendered, so asserting on it passes and proves nothing. The buffer
     API is the truth.
"""
import functools
import http.server
import os
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import browser_required

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-xterm-'))

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_VENDOR = _ROOT / 'server' / 'html' / 'static' / 'vendor'

# Loaded exactly as app-remote.js loads them, from the real vendored files.
_PAGE = """<!doctype html><meta charset="utf-8">
<link rel="stylesheet" href="/xterm/xterm.min.css">
<div id="t" style="width:800px;height:400px"></div>
<script src="/xterm/xterm.min.js"></script>
<script src="/xterm-addon-fit/addon-fit.min.js"></script>
"""

_BOOT = """() => {
  const out = {globals: {}, ok: false, err: null};
  out.globals.Terminal = typeof window.Terminal;
  out.globals.FitAddon = typeof (window.FitAddon && window.FitAddon.FitAddon);
  try {
    const Term = window.Terminal;
    const FitAddon = window.FitAddon && window.FitAddon.FitAddon;
    const term = new Term({
      fontFamily: '"JetBrains Mono", Menlo, Monaco, "Courier New", monospace',
      fontSize: 13,
      theme: {background: '#000000', foreground: '#dddddd'},
      cursorBlink: true,
    });
    const fit = FitAddon ? new FitAddon() : null;
    if (fit) term.loadAddon(fit);
    term.open(document.getElementById('t'));
    if (fit) fit.fit();
    term.focus();
    window.__typed = [];
    window.__resized = [];
    term.onData(d => window.__typed.push(d));
    term.onResize(({cols, rows}) => window.__resized.push([cols, rows]));
    term.write('hello \\x1b[31mred\\x1b[0m world\\r\\n');
    out.cols = term.cols;
    out.rows = term.rows;
    out.domRows = document.querySelectorAll('#t .xterm-rows > div').length;
    window.__term = term;
    window.__fit = fit;
    out.ok = true;
  } catch (e) { out.err = String(e).slice(0, 300); }
  return out;
}"""


class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            body = _PAGE.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()


class TestVendoredTerminalBoots(unittest.TestCase):
    """Served over http rather than file://, because file:// dodges the load
    path the browser actually takes for these resources."""

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        for rel in ('xterm/xterm.min.js', 'xterm/xterm.min.css',
                    'xterm-addon-fit/addon-fit.min.js'):
            if not (_VENDOR / rel).is_file():
                raise unittest.SkipTest(f'{rel} not in this tree')
        handler = functools.partial(_Handler, directory=str(_VENDOR))
        cls.srv = socketserver.TCPServer(('127.0.0.1', 0), handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            cls.srv.shutdown()
            browser_required.skip_or_fail(f'chromium not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        for close in (getattr(cls, 'browser', None), getattr(cls, '_pw', None)):
            try:
                close.close() if hasattr(close, 'close') else close.stop()
            except Exception:
                pass
        try:
            cls.srv.shutdown()
        except Exception:
            pass

    def setUp(self):
        self.page = self.browser.new_page()
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)[:200]))
        self.page.on('console', lambda m: (
            self.errors.append('console: ' + m.text[:200])
            if m.type == 'error' else None))
        self.page.goto(f'http://127.0.0.1:{self.port}/')
        self.page.wait_for_timeout(600)
        self.boot = self.page.evaluate(_BOOT)

    def tearDown(self):
        try:
            self.page.close()
        except Exception:
            pass

    def test_the_globals_the_app_reaches_for_exist(self):
        """app-remote.js uses `window.Terminal` and `window.FitAddon.FitAddon`.
        A build that stopped exposing UMD globals would break silently."""
        self.assertEqual(self.boot['globals']['Terminal'], 'function',
                         'window.Terminal is not a constructor')
        self.assertEqual(self.boot['globals']['FitAddon'], 'function',
                         'window.FitAddon.FitAddon is not a constructor')

    def test_it_boots_without_throwing(self):
        self.assertIsNone(self.boot['err'], self.boot['err'])
        self.assertTrue(self.boot['ok'])

    def test_it_sized_itself_to_the_container(self):
        """fit() not working is the difference between a usable terminal and an
        80x24 box in the corner of a full-screen panel."""
        self.assertGreater(self.boot['cols'], 40, self.boot)
        self.assertGreater(self.boot['rows'], 10, self.boot)
        self.assertGreater(self.boot['domRows'], 10,
                           'no rows rendered into the DOM')

    def test_written_output_reaches_the_buffer(self):
        """The OUTPUT path. Read after a flush — write() is queued, and reading
        it synchronously returns '' on every version, which is a dead probe
        rather than a dead renderer.
        """
        self.page.wait_for_timeout(400)
        line = self.page.evaluate(
            "() => window.__term.buffer.active.getLine(0).translateToString(true)")
        self.assertEqual(line, 'hello red world',
                         'the write did not reach the terminal buffer, or the '
                         'ANSI colour escape was printed instead of consumed')

    def test_keystrokes_reach_ondata(self):
        """The INPUT path: onData is what the websocket forwards to the remote
        shell. Driven with real browser keystrokes, not a synthetic call."""
        self.page.click('#t')
        self.page.keyboard.type('ls -la')
        self.page.keyboard.press('Enter')
        self.page.wait_for_timeout(250)
        typed = ''.join(self.page.evaluate("() => window.__typed || []"))
        self.assertEqual(typed, 'ls -la\r',
                         'keystrokes did not reach onData — typing in the web '
                         'terminal would go nowhere')

    def test_resize_reaches_onresize(self):
        """onResize is what tells the remote pty its new geometry; without it
        the shell keeps drawing to the old width."""
        self.page.evaluate(
            "() => { document.getElementById('t').style.width = '400px'; }")
        self.page.evaluate("() => window.__fit && window.__fit.fit()")
        self.page.wait_for_timeout(250)
        resized = self.page.evaluate("() => window.__resized || []")
        self.assertTrue(resized, 'onResize never fired after a fit()')
        self.assertGreater(resized[-1][0], 0)

    def test_no_console_or_page_errors(self):
        """The Swagger failure was visible ONLY in the console."""
        self.assertEqual(self.errors, [], f'errors during boot: {self.errors}')


if __name__ == '__main__':
    unittest.main()
