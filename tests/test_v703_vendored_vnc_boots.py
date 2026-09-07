#!/usr/bin/env python3
"""The vendored VNC viewer must actually speak RFB, not merely be on disk.

`VENDORED.md` records noVNC 1.5.0 → 1.7.0 as deferred, and gives the reason:
nothing in the suite drives the VNC console, so a bump would have been two
minor versions of unverified change in the one viewer an operator reaches for
when a host has no working shell. The xterm.js 6.0.0 bump earned its confidence
from `test_v643_vendored_terminal_boots.py`; this is the missing equivalent,
and the recorded order was a boot test first, then the bump.

WHAT THIS DRIVES, mirroring `app-remote.js`:
  * `import('/static/vendor/novnc/core/rfb.js')` and its DEFAULT export — the
    exact specifier and shape the app uses;
  * `new RFB(target, channel, {})` in the RAW-CHANNEL form. The app opens its
    own WebSocket, sends an SSH preamble and waits for `{connected}` before
    handing the live socket over, so the URL form noVNC's own docs lead with is
    not the one that matters here;
  * the `scaleViewport` / `clipViewport` setters;
  * `addEventListener` for `connect`, `disconnect`, `credentialsrequired` and
    `securityfailure` — all four the app registers;
  * `sendCredentials({password})` and `disconnect()`.

And it drives them against a REAL RFB 3.8 handshake, played by a fake channel
in the page: version exchange, security type None, SecurityResult, ClientInit,
ServerInit, then a Raw-encoded framebuffer rectangle in whatever pixel format
the client asked for. The `connect` event only fires once ServerInit has been
parsed, so it is evidence the protocol engine works rather than evidence the
constructor exists. The painted rectangle is then read back off the canvas.

A second test runs the same handshake and refuses the security type, to pin
that `securityfailure` fires — the app shows the operator a message from that
handler, and a listener that stopped being called would leave them with a
viewer that says "connecting…" forever.

The channel is fake on purpose. A real VNC server is not available in CI, and
the layer this is protecting is the boundary between our five calls and the
library, which is where a version bump actually breaks.

COST: ~11s, and the filename has no `e2e` in it, so this runs in `make
test-fast` as well as the serial gate — the same bargain its terminal sibling
strikes, and the same order of magnitude. If it ever grows to minutes it should
be renamed into the e2e set rather than left on everyone's fast path.
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

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-vnc-'))

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_VENDOR = _ROOT / 'server' / 'html' / 'static' / 'vendor'

# The module specifier is the one app-remote.js uses, so the directory is
# served at /static/vendor/ and a moved file fails here the same way it would
# fail in the product.
_PAGE = """<!doctype html><meta charset="utf-8">
<title>novnc boot</title>
<div id="vnc-canvas" style="width:800px;height:600px"></div>
"""

# A fake raw channel that plays the SERVER side of RFB 3.8. Websock.attach
# checks for an exact property list, so every one of them is defined here —
# send, close, binaryType, onerror, onmessage, onopen, protocol, readyState.
_HARNESS = r"""
window.__mkServer = function (opts) {
  const o = opts || {};
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const log = [];
  const chan = {
    binaryType: 'blob',
    protocol: '',
    readyState: 'open',
    onmessage: null, onopen: null, onerror: null, onclose: null,
    send(data) { server.onClientData(new Uint8Array(data)); },
    close() { this.readyState = 'closed'; if (this.onclose) this.onclose({code: 1000}); },
  };
  // Deferred, not synchronous. noVNC calls chan.send() from INSIDE its own
  // receive handler, so pushing the reply straight back re-enters that handler
  // while its receive queue is mid-compaction and the bytes are dropped: the
  // client sits in state 'Security' having seen nothing, which reads exactly
  // like a library that stopped speaking RFB 3.8. A real socket is never
  // re-entrant like this, so the deferral is what makes the fake faithful.
  function push(bytes) {
    const buf = new Uint8Array(bytes).buffer;
    setTimeout(() => { if (chan.onmessage) chan.onmessage({data: buf}); }, 0);
  }
  const server = {
    log, chan, state: 'version', pf: null, painted: false,
    start() { push(enc.encode('RFB 003.008\n')); },
    onClientData(buf) {
      log.push([server.state, buf.length]);
      if (server.state === 'version') {
        // 12 bytes: "RFB 003.008\n"
        server.clientVersion = dec.decode(buf);
        // One security type. 1 = None, 2 = VNC auth (used by the refusal test).
        push([1, o.securityType || 1]);
        server.state = 'security';
        return;
      }
      if (server.state === 'security') {
        server.chosen = buf[0];
        if (o.refuse) {
          // SecurityResult = 1 (failed) + a reason string, which is what a
          // server sends when it rejects the chosen type.
          const reason = enc.encode('nope');
          push([0, 0, 0, 1, 0, 0, 0, reason.length, ...reason]);
          server.state = 'done';
          return;
        }
        push([0, 0, 0, 0]);          // SecurityResult = OK
        server.state = 'clientinit';
        return;
      }
      if (server.state === 'clientinit') {
        server.shared = buf[0];
        const name = enc.encode('RemotePower test display');
        const init = [
          0x02, 0x80,               // width  640
          0x01, 0xe0,               // height 480
          32, 24, 0, 1,             // bpp, depth, big-endian, true-colour
          0, 255, 0, 255, 0, 255,   // red/green/blue max
          16, 8, 0,                 // red/green/blue shift
          0, 0, 0,                  // padding
          0, 0, 0, name.length, ...name,
        ];
        push(init);
        server.state = 'ready';
        return;
      }
      // Client messages after ServerInit. 0 = SetPixelFormat, 2 = SetEncodings,
      // 3 = FramebufferUpdateRequest.
      let i = 0;
      while (i < buf.length) {
        const type = buf[i];
        if (type === 0 && buf.length - i >= 20) {
          const pf = buf.slice(i + 4, i + 20);
          server.pf = {
            bpp: pf[0], depth: pf[1], bigEndian: pf[2], trueColor: pf[3],
            redMax: (pf[4] << 8) | pf[5], greenMax: (pf[6] << 8) | pf[7],
            blueMax: (pf[8] << 8) | pf[9],
            redShift: pf[10], greenShift: pf[11], blueShift: pf[12],
          };
          i += 20;
        } else if (type === 2 && buf.length - i >= 4) {
          const n = (buf[i + 2] << 8) | buf[i + 3];
          i += 4 + 4 * n;
        } else if (type === 3 && buf.length - i >= 10) {
          i += 10;
          if (!server.painted) { server.painted = true; server.sendRect(); }
        } else {
          break;
        }
      }
    },
    // One Raw-encoded rectangle in the pixel format the CLIENT asked for, so
    // this does not quietly depend on noVNC's current preference.
    sendRect() {
      const pf = server.pf || {bpp: 32, redShift: 16, greenShift: 8, blueShift: 0,
                               bigEndian: 0};
      const bytes = Math.max(1, pf.bpp / 8);
      const W = 8, H = 8;
      // Solid red.
      const value = (255 << pf.redShift) >>> 0;
      const px = [];
      for (let n = 0; n < W * H; n++) {
        for (let b = 0; b < bytes; b++) {
          const shift = pf.bigEndian ? (bytes - 1 - b) * 8 : b * 8;
          px.push((value >>> shift) & 0xff);
        }
      }
      push([0, 0, 0, 1,                 // FramebufferUpdate, padding, 1 rect
            0, 0, 0, 0,                 // x, y
            0, W, 0, H,                 // width, height
            0, 0, 0, 0,                 // encoding 0 = Raw
            ...px]);
    },
  };
  return server;
};

window.__boot = async function (opts) {
  const out = {events: [], err: null, ok: false};
  try {
    const mod = await import('/static/vendor/novnc/core/rfb.js');
    out.defaultExport = typeof mod.default;
    const RFB = mod.default;
    const server = window.__mkServer(opts);
    window.__server = server;
    const target = document.getElementById('vnc-canvas');
    const rfb = new RFB(target, server.chan, {});
    window.__rfb = rfb;
    rfb.scaleViewport = true;
    rfb.clipViewport = true;
    out.scaleViewport = rfb.scaleViewport;
    out.clipViewport = rfb.clipViewport;
    for (const ev of ['connect', 'disconnect', 'credentialsrequired',
                      'securityfailure']) {
      rfb.addEventListener(ev, (e) => out.events.push(ev));
    }
    out.hasSendCredentials = typeof rfb.sendCredentials;
    out.hasDisconnect = typeof rfb.disconnect;
    window.__out = out;
    server.start();
    out.ok = true;
  } catch (e) {
    out.err = String(e).slice(0, 300);
    window.__out = out;
  }
  return out;
};
"""


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

    def guess_type(self, path):
        # A wrong Content-Type on a .js file makes the browser refuse the module
        # import outright, which would look exactly like a broken library.
        if str(path).endswith('.js'):
            return 'text/javascript'
        return super().guess_type(path)


class _VncCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if not (_VENDOR / 'novnc' / 'core' / 'rfb.js').is_file():
            raise unittest.SkipTest('novnc not in this tree')
        # Serve the whole html dir so /static/vendor/... resolves exactly as it
        # does in the product.
        root = _ROOT / 'server' / 'html'
        handler = functools.partial(_Handler, directory=str(root))
        cls.srv = socketserver.TCPServer(('127.0.0.1', 0), handler)
        cls.srv.allow_reuse_address = True
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

    def _open(self, **opts):
        self.page = self.browser.new_page()
        self.addCleanup(lambda: self.page.close())
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)[:200]))
        self.page.on('console', lambda m: (
            self.errors.append('console: ' + m.text[:200])
            if m.type == 'error' else None))
        self.page.goto(f'http://127.0.0.1:{self.port}/')
        self.page.add_script_tag(content=_HARNESS)
        self.page.evaluate('(o) => window.__boot(o)', opts)
        self.page.wait_for_timeout(700)
        return self.page.evaluate('() => window.__out')


class TestVendoredVncBoots(_VncCase):

    def setUp(self):
        self.boot = self._open()

    def test_the_module_shape_the_app_imports(self):
        """app-remote.js does `import(...).then(mod => mod.default)`. A build
        that moved the constructor off the default export breaks that line and
        nothing else would notice."""
        self.assertIsNone(self.boot['err'], self.boot['err'])
        self.assertEqual(self.boot['defaultExport'], 'function')

    def test_the_raw_channel_form_is_accepted(self):
        """`new RFB(target, channel, {})`. Websock.attach validates the channel
        against a fixed property list and throws if one is missing, so a
        changed list would fail right here."""
        self.assertTrue(self.boot['ok'], self.boot)
        self.assertEqual(self.boot['hasSendCredentials'], 'function')
        self.assertEqual(self.boot['hasDisconnect'], 'function')

    def test_the_viewport_setters_still_exist(self):
        self.assertIs(self.boot['scaleViewport'], True)
        self.assertIs(self.boot['clipViewport'], True)

    def test_the_handshake_completes_and_connect_fires(self):
        """The whole point. `connect` fires only after the version exchange,
        the security negotiation, SecurityResult, ClientInit and ServerInit
        have all been parsed — so this is the protocol engine working, not the
        constructor existing."""
        events = self.page.evaluate('() => window.__out.events')
        self.assertIn('connect', events,
                      f'RFB never reached connected. Server saw: '
                      f'{self.page.evaluate("() => window.__server.log")}')
        self.assertNotIn('securityfailure', events)

    def test_the_server_saw_every_handshake_step(self):
        """Positive control on the harness itself: if the fake server had
        stalled at step one, `connect` above could only fail, and a reader
        could not tell a broken library from a broken probe."""
        states = [row[0] for row in self.page.evaluate('() => window.__server.log')]
        for step in ('version', 'security', 'clientinit'):
            self.assertIn(step, states, f'the client never completed {step}')
        self.assertEqual(self.page.evaluate('() => window.__server.state'), 'ready')

    def test_it_created_a_canvas_at_the_size_the_server_declared(self):
        """ServerInit said 640x480. A canvas of another size means the
        framebuffer geometry was misread, which is a decode bug wearing a
        rendering costume."""
        size = self.page.evaluate(
            "() => { const c = document.querySelector('#vnc-canvas canvas');"
            "return c ? [c.width, c.height] : null; }")
        self.assertEqual(size, [640, 480])

    def test_a_framebuffer_rectangle_actually_paints(self):
        """The rectangle is encoded in the pixel format the CLIENT asked for,
        so this does not depend on noVNC's current preference. Reading the
        canvas back is the only evidence that decode and draw both ran —
        the container's innerText is empty either way, which is the trap the
        terminal boot test records."""
        self.page.wait_for_timeout(500)
        px = self.page.evaluate(
            "() => { const c = document.querySelector('#vnc-canvas canvas');"
            "if (!c) return null;"
            "const d = c.getContext('2d').getImageData(2, 2, 1, 1).data;"
            "return [d[0], d[1], d[2], d[3]]; }")
        self.assertIsNotNone(px, 'no canvas to read')
        self.assertGreater(px[0], 200, f'expected a red pixel, got {px}')
        self.assertLess(px[1], 60, f'expected a red pixel, got {px}')
        self.assertLess(px[2], 60, f'expected a red pixel, got {px}')

    def test_disconnect_is_callable_and_fires_its_event(self):
        """vncDisconnect() calls this. A viewer that cannot be closed leaves a
        session open against the host."""
        self.page.evaluate('() => window.__rfb.disconnect()')
        self.page.wait_for_timeout(400)
        self.assertIn('disconnect', self.page.evaluate('() => window.__out.events'))

    def test_the_page_console_is_clean(self):
        self.assertEqual([e for e in self.errors if 'favicon' not in e], [])


class TestSecurityFailureStillReaches_TheApp(_VncCase):
    """The app puts a message on screen from this handler. If it stopped
    firing, a refused connection would sit at 'connecting…' forever."""

    def setUp(self):
        self.boot = self._open(refuse=True)

    def test_a_refused_security_result_fires_securityfailure(self):
        self.page.wait_for_timeout(400)
        events = self.page.evaluate('() => window.__out.events')
        self.assertIn('securityfailure', events,
                      f'server log: {self.page.evaluate("() => window.__server.log")}')
        self.assertNotIn('connect', events)


if __name__ == '__main__':
    unittest.main()
