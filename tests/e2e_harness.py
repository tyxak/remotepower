#!/usr/bin/env python3
"""Local full-stack harness for the browser smoke tests (test_v430_e2e.py).

Serves the real app the way production does, without nginx:
  * static files straight from server/html/
  * /api/* proxied over plain HTTP to a real gunicorn+wsgi.py (the same
    Flask app / gunicorn invocation remotepower-wsgi.service runs) — so the
    e2e suite exercises the production app-server path, not a test-only shim.

Returns (base_url, shutdown_callable). Everything runs on localhost with a
throwaway RP_DATA_DIR.
"""
import gc
import http.client
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_HTML = _ROOT / 'server' / 'html'


_BROWSER_OK = None


def browser_available():
    """True only if the e2e suite can actually RUN — playwright importable AND a
    chromium binary on disk AND gunicorn present.

    The per-file guards used to test only `import playwright`, which is a
    different question: `pip install playwright` gives you the module, while the
    browser needs a separate `playwright install chromium`. On a box in that
    state every e2e class ERRORED at `chromium.launch()` instead of skipping, so
    the whole suite — `make test`, `make test-fast`, `make check` — exited
    non-zero for an environmental reason. Cached; the probe starts the driver.
    """
    global _BROWSER_OK
    if _BROWSER_OK is None:
        _BROWSER_OK = False
        try:
            from playwright.sync_api import sync_playwright
            import gunicorn  # noqa: F401
            # Actually launch and close. Checking `chromium.executable_path`
            # instead looks cheaper but tests the WRONG binary — that property
            # points at chromium-<rev>/chrome-linux64/chrome while a default
            # `launch()` runs chromium_headless_shell-<rev>, so the two can
            # disagree in both directions. A real launch is ground truth for
            # the exact call every e2e setUpClass makes, and it costs ~1s once.
            with sync_playwright() as p:
                p.chromium.launch().close()
            _BROWSER_OK = True
        except Exception:
            _BROWSER_OK = False
    return _BROWSER_OK


SKIP_REASON = ('needs playwright + a chromium binary + gunicorn — '
               'pip install playwright gunicorn && playwright install chromium')


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def park_the_old_heap():
    """Move everything the process holds now out of the garbage collector's sight.

    The whole suite runs in ONE process, and by the time the browser modules come it holds millions of objects: 14.6 million and 12 GB after 2,400 tests, and one full
    collection took 3.5 s (90 pauses over 0.2 s, the longest 5 s, measured on the exact discover order). This harness answers the browser from threads of that process (the
    static files and the proxy to gunicorn), so a full collection stops every request for seconds, and a test that waits a second or two for an answer loses at random: the cron words
    test failed in two full runs and in no run of its module on its own. Freezing what exists leaves the collector only what a module makes itself. A collection first, so that
    garbage already waiting is freed and not parked for good; the next call (the next module) has only what came since to look through.
    """
    gc.collect()
    gc.freeze()


def start_stack(data_dir=None):
    """Boot the real gunicorn+wsgi stack. Returns (base_url, shutdown).

    `data_dir` lets a caller boot against a PRE-POPULATED store. It defaults to
    a fresh temp dir, which is what every existing caller wants — but it meant
    the a11y sweep, which walks all 74 pages, only ever saw EMPTY ONES. Every
    table rendered its empty state, so any violation that lives in a populated
    row (an unnamed control inside a row, a status pill's contrast, a header
    that only exists once there is data) was structurally invisible to a gate
    whose whole purpose is to see it.
    """
    park_the_old_heap()
    data_dir = data_dir or tempfile.mkdtemp(prefix='rp-e2e-data-')
    gunicorn_port = _free_port()

    # `--timeout 120` matches what ships (remotepower-wsgi.service and
    # docker/entrypoint.sh both set it). Without it gunicorn uses its DEFAULT of
    # 30s, so this harness was killing workers on requests production would have
    # served — and a killed worker mid-request surfaces as a page that never
    # renders, i.e. the `wait_for_selector` timeout long recorded as "e2e flake
    # under load".
    #
    # It is easy to hit: on a freshly seeded store every cadence sweep is due at
    # once, so the first request runs them ON the request path (the out-of-band
    # scheduler that normally owns them is not running here). Measured on this
    # box: 60s for the first request, which the 30s default turned into a killed
    # worker and a connection-refused cascade rather than a slow success.
    # gunicorn's stderr goes to a file. It used to go to a pipe that nothing read while the stack ran, and a pipe holds
    # 64 KB: past that every worker thread blocks in write(2) the next time it logs (a traceback from a sweep, a
    # warning for an oversized request line), the logging lock is held by the blocked one, and the stack stops
    # answering. A security probe that made the server log a few hundred lines found it; a test that logs a little never
    # does, which is how it stayed.
    errlog = tempfile.TemporaryFile()
    worker = subprocess.Popen(
        [sys.executable, '-m', 'gunicorn', '--workers', '2', '--threads', '8',
         '--timeout', '120',
         '--bind', f'127.0.0.1:{gunicorn_port}', 'wsgi:application'],
        cwd=str(_CGI),
        env=dict(os.environ, RP_DATA_DIR=data_dir),
        stderr=errlog)
    deadline = time.time() + 60
    while True:
        if worker.poll() is not None:
            errlog.seek(0)
            raise RuntimeError('gunicorn died: ' + errlog.read().decode(errors='replace'))
        try:
            socket.create_connection(('127.0.0.1', gunicorn_port), timeout=0.5).close()
            break
        except OSError:
            if time.time() > deadline:
                worker.kill()
                raise RuntimeError('gunicorn never started listening')
            time.sleep(0.1)

    # Each of the `--workers 2` gunicorn processes independently imports
    # wsgi.py -> api.py and runs ensure_default_user() at import time
    # (must_change_password=True, which gates most endpoints). The smoke
    # tests exercise the app POST-login, so clear the flag -- first-login
    # flow has its own coverage elsewhere. Done through the storage layer
    # (a one-shot api import in a subprocess) so it works on BOTH backends:
    # under RP_STORAGE_BACKEND=sqlite there is no users.json file to edit.
    #
    # The readiness wait above only proves ONE worker's listen() succeeded
    # (often before either worker has finished importing) -- a slower
    # second worker can still be mid-import when the fixup below runs, and
    # its OWN ensure_default_user() call re-seeds must_change_password=True
    # right after, silently clobbering the fix. This is a real race that
    # got worse under host load (a slow worker import widens the window)
    # and showed up as an intermittent post-login redirect to Settings
    # instead of Home in test_a11y_axe.py / test_v430_e2e.py. Re-apply the
    # fixup a few times over ~1.5s to absorb a straggler worker.
    _fix_cmd = [sys.executable, '-c',
                'import sys; sys.path.insert(0, sys.argv[1]); import api; '
                # Clear the flag for EVERY user, not just 'admin'. A caller
                # booting against a pre-populated data_dir (the seeded a11y
                # sweep) has its own operator accounts and no 'admin' at all,
                # and the hardcoded subscript raised KeyError before the stack
                # could come up.
                'u = api.load(api.USERS_FILE) or {}; '
                '[v.update(must_change_password=False) '
                ' for v in u.values() if isinstance(v, dict)]; '
                'api.save(api.USERS_FILE, u)',
                str(_CGI)]
    for attempt in range(5):
        fix = subprocess.run(_fix_cmd, env=dict(os.environ, RP_DATA_DIR=data_dir),
                              capture_output=True, timeout=120)
        if fix.returncode != 0:
            worker.terminate()
            raise RuntimeError('seed-user fixup failed: '
                               + fix.stderr.decode(errors='replace'))
        if attempt < 4:
            time.sleep(0.3)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(_HTML), **k)

        def log_message(self, *a):
            pass

        def _proxy_api(self):
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(length) if length else b''
            conn = http.client.HTTPConnection('127.0.0.1', gunicorn_port, timeout=60)
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ('host', 'content-length')}
            headers['Content-Length'] = str(len(body))
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
            conn.close()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in ('content-length', 'transfer-encoding', 'connection'):
                    continue
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path.startswith('/api/'):
                return self._proxy_api()
            # v7.0.0: serve docs/ too. The static root is server/html, so every
            # `docs/*.md` request 404'd and the in-app documentation viewer
            # showed its "could not load" fallback — which means the viewer, and
            # the markdown renderer behind it, could not be measured here AT ALL.
            # A browser check against it reported "0 tables, 0 raw pipe rows" and
            # read like a clean result. A real deployment serves the directory
            # from the install root beside server/html, so this matches it.
            if self.path.startswith('/docs/') and self.path.endswith('.md'):
                rel = self.path.lstrip('/').split('?', 1)[0]
                target = (_ROOT / rel).resolve()
                if target.is_file() and str(target).startswith(str(_ROOT / 'docs')):
                    payload = target.read_bytes()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/markdown; charset=utf-8')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                self.send_error(404)
                return
            return super().do_GET()

        def do_POST(self):
            if self.path.startswith('/api/'):
                return self._proxy_api()
            self.send_error(405)

        do_PUT = do_DELETE = do_PATCH = do_POST

    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{httpd.server_address[1]}'

    def shutdown():
        httpd.shutdown()
        httpd.server_close()
        worker.terminate()
        try:
            worker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            worker.kill()
        errlog.close()

    return base, shutdown
