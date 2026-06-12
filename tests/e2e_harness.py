#!/usr/bin/env python3
"""Local full-stack harness for the browser smoke tests (test_v430_e2e.py).

Serves the real app the way production does, without nginx:
  * static files straight from server/html/
  * /api/* proxied over SCGI to a real api_worker.py (the v4.3.0 persistent
    worker) — so the e2e suite exercises the production worker path, not a
    test-only shim.

Returns (base_url, shutdown_callable). Everything runs on localhost with a
throwaway RP_DATA_DIR.
"""
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


def _scgi_request(sock_path, env, body=b''):
    """One SCGI round-trip; returns the raw CGI-style response bytes."""
    blob = b''.join(k.encode() + b'\x00' + v.encode() + b'\x00'
                    for k, v in env.items())
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(sock_path)
    s.sendall(str(len(blob)).encode() + b':' + blob + b',' + body)
    chunks = []
    while True:
        c = s.recv(65536)
        if not c:
            break
        chunks.append(c)
    s.close()
    return b''.join(chunks)


def start_stack():
    data_dir = tempfile.mkdtemp(prefix='rp-e2e-data-')
    sock_dir = tempfile.mkdtemp(prefix='rp-e2e-sock-')
    sock_path = os.path.join(sock_dir, 'api.sock')

    worker = subprocess.Popen(
        [sys.executable, str(_CGI / 'api_worker.py')],
        env=dict(os.environ, RP_DATA_DIR=data_dir, RP_SCGI_SOCKET=sock_path,
                 RP_WORKER_MAX='8'),
        stderr=subprocess.PIPE)
    deadline = time.time() + 60
    while not os.path.exists(sock_path):
        if worker.poll() is not None:
            raise RuntimeError('api worker died: '
                               + worker.stderr.read().decode(errors='replace'))
        if time.time() > deadline:
            worker.kill()
            raise RuntimeError('api worker socket never appeared')
        time.sleep(0.1)

    # The worker's import seeded the default admin (must_change_password=True,
    # which gates most endpoints). The smoke tests exercise the app POST-login,
    # so clear the flag — first-login flow has its own coverage elsewhere.
    # Done through the storage layer (a one-shot api import in a subprocess)
    # so it works on BOTH backends: under RP_STORAGE_BACKEND=sqlite there is
    # no users.json file to edit.
    fix = subprocess.run(
        [sys.executable, '-c',
         'import sys; sys.path.insert(0, sys.argv[1]); import api; '
         'u = api.load(api.USERS_FILE); '
         "u['admin']['must_change_password'] = False; "
         'api.save(api.USERS_FILE, u)',
         str(_CGI)],
        env=dict(os.environ, RP_DATA_DIR=data_dir),
        capture_output=True, timeout=120)
    if fix.returncode != 0:
        worker.kill()
        raise RuntimeError('seed-user fixup failed: '
                           + fix.stderr.decode(errors='replace'))

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(_HTML), **k)

        def log_message(self, *a):
            pass

        def _proxy_api(self):
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(length) if length else b''
            path, _, query = self.path.partition('?')
            env = {
                'CONTENT_LENGTH': str(len(body)),
                'SCGI': '1',
                'REQUEST_METHOD': self.command,
                'PATH_INFO': path,
                'QUERY_STRING': query,
                'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                'REMOTE_ADDR': '127.0.0.1',
                'RP_DATA_DIR': data_dir,
            }
            for name, val in self.headers.items():
                env['HTTP_' + name.upper().replace('-', '_')] = val
            raw = _scgi_request(sock_path, env, body)
            head, _, payload = raw.partition(b'\n\n')
            if b'\r\n\r\n' in raw and (raw.index(b'\r\n\r\n') < len(head)):
                head, _, payload = raw.partition(b'\r\n\r\n')
            status = 200
            hdrs = []
            for line in head.decode(errors='replace').splitlines():
                k, _, v = line.partition(':')
                if k.strip().lower() == 'status':
                    status = int(v.strip().split()[0])
                elif _:
                    hdrs.append((k.strip(), v.strip()))
            self.send_response(status)
            for k, v in hdrs:
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
