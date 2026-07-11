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


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_stack():
    data_dir = tempfile.mkdtemp(prefix='rp-e2e-data-')
    gunicorn_port = _free_port()

    worker = subprocess.Popen(
        [sys.executable, '-m', 'gunicorn', '--workers', '2', '--threads', '8',
         '--bind', f'127.0.0.1:{gunicorn_port}', 'wsgi:application'],
        cwd=str(_CGI),
        env=dict(os.environ, RP_DATA_DIR=data_dir),
        stderr=subprocess.PIPE)
    deadline = time.time() + 60
    while True:
        if worker.poll() is not None:
            raise RuntimeError('gunicorn died: '
                               + worker.stderr.read().decode(errors='replace'))
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
                'u = api.load(api.USERS_FILE); '
                "u['admin']['must_change_password'] = False; "
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
        worker.terminate()
        try:
            worker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            worker.kill()

    return base, shutdown
