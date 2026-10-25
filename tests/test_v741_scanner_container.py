#!/usr/bin/env python3
"""v7.4.1, issue #33: the scanner container is not "unhealthy", and it waits for
the server before it polls it.

Dockerfile.scanner is built FROM the app image, so it inherited the app's
HEALTHCHECK, a probe of http://localhost:8080/api/health. The scanner serves
nothing there, so the check got "connection refused" for the life of the
container while the worker ran normally, and anything that waits for health
reported the deploy as failed. The same image also started at once, polled an
address nobody was listening on yet, and logged a refusal.

The guard has two halves. The Dockerfile half enumerates every image derived
from the app image and requires each to decide its own health check. The
entrypoint half runs the real script against a real HTTP server that comes up a
few seconds late.
"""
import os
import re
import socket
import subprocess
import tempfile
import textwrap
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_ENTRYPOINT = _ROOT / 'docker' / 'scanner-entrypoint.sh'


def derived_dockerfiles():
    """Dockerfiles at the repo root whose base is the app image. The base arrives
    through `ARG BASE_IMAGE=...` and `FROM ${BASE_IMAGE}`, so resolve that."""
    out = []
    for p in sorted(_ROOT.glob('Dockerfile*')):
        text = p.read_text()
        args = dict(re.findall(r'^ARG\s+(\w+)=(\S+)', text, re.M))
        for ref in re.findall(r'^FROM\s+(\S+)', text, re.M):
            ref = re.sub(r'\$\{(\w+)\}', lambda m: args.get(m.group(1), ''), ref)
            if 'tyxak/remotepower:' in ref or ref.endswith('tyxak/remotepower'):
                out.append(p)
                break
    return out


class TestAnImageBuiltFromTheAppImageChoosesItsOwnHealthCheck(unittest.TestCase):

    def test_the_population_is_the_scanner_and_not_empty(self):
        names = [p.name for p in derived_dockerfiles()]
        self.assertEqual(names, ['Dockerfile.scanner'], names)

    def test_each_derived_image_decides_its_own(self):
        for p in derived_dockerfiles():
            self.assertRegex(p.read_text(), r'(?m)^HEALTHCHECK\b', p.name)

    def test_the_app_image_still_has_its_check(self):
        """The control: the check the scanner inherited is real, so the thing
        the derived image must override exists."""
        self.assertRegex((_ROOT / 'Dockerfile').read_text(),
                         r'(?m)^HEALTHCHECK .*\n.*localhost:8080/api/health')

    def test_the_scanner_keeps_no_probe_of_8080(self):
        text = (_ROOT / 'Dockerfile.scanner').read_text()
        self.assertRegex(text, r'(?m)^HEALTHCHECK NONE$')
        code = '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))
        self.assertNotIn('8080/api/health', code)

    def test_the_compose_scanner_service_adds_no_probe_either(self):
        compose = (_ROOT / 'docker-compose.yml').read_text()
        block = re.search(r'^  scanner:\n(?P<b>(?:    .*\n|\n)+)', compose, re.M)
        self.assertTrue(block, 'scanner service not found in docker-compose.yml')
        self.assertNotIn('healthcheck:', block.group('b'))


# ───────────────────────── the entrypoint, run for real ─────────────────────────

def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class _Health(BaseHTTPRequestHandler):
    status = 200

    def do_GET(self):
        self.send_response(self.status)
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, format, *args):
        pass


def _serve_after(port, delay, status=200):
    """Open the port `delay` seconds from now; return (thread, stop-event)."""
    stop = threading.Event()
    handler = type('H', (_Health,), {'status': status})

    def run():
        time.sleep(delay)
        srv = HTTPServer(('127.0.0.1', port), handler)
        srv.timeout = 0.2
        while not stop.is_set():
            srv.handle_request()
        srv.server_close()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, stop


class TestTheEntrypointWaitsForTheServer(unittest.TestCase):

    def run_entrypoint(self, port, wait_secs, up_after=None, status=200):
        tmp = Path(tempfile.mkdtemp(prefix='rp-v741-scanner-'))
        (tmp / '.scanner-token').write_text('tok')
        worker = tmp / 'worker.py'
        worker.write_text(textwrap.dedent('''
            import os, time
            print("WORKER-STARTED", time.time(), flush=True)
        '''))
        env = dict(os.environ,
                   RP_DATA_DIR=str(tmp),
                   RP_HEALTH_URL=f'http://127.0.0.1:{port}/api/health',
                   RP_SERVER_WAIT_SECS=str(wait_secs),
                   RP_SCANNER_BIN=str(worker))
        stop = None
        if up_after is not None:
            stop = _serve_after(port, up_after, status)[1]
        t0 = time.time()
        try:
            r = subprocess.run(['bash', str(_ENTRYPOINT)], env=env, capture_output=True,
                               text=True, timeout=60)
        finally:
            if stop:
                stop.set()
        started = None
        m = re.search(r'WORKER-STARTED ([\d.]+)', r.stdout)
        if m:
            started = float(m.group(1)) - t0
        return r, started

    def test_the_worker_starts_only_after_the_server_answers(self):
        r, started = self.run_entrypoint(_free_port(), wait_secs=30, up_after=3)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIsNotNone(started, r.stdout + r.stderr)
        self.assertGreaterEqual(started, 3.0, 'the worker did not wait for the server')
        self.assertLess(started, 12.0)
        self.assertIn('waiting for the server', r.stdout)
        self.assertNotIn('did not answer', r.stderr)

    def test_a_server_that_answers_503_is_not_ready(self):
        port = _free_port()
        r, started = self.run_entrypoint(port, wait_secs=4, up_after=0, status=503)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertGreaterEqual(started, 3.5, '503 was taken for "ready"')
        self.assertIn('did not answer', r.stderr)

    def test_the_worker_still_starts_when_the_server_never_answers(self):
        """The wait is a courtesy, not a gate: the worker retries on its own, and
        a scanner that never started would hide the reason in a stopped container."""
        r, started = self.run_entrypoint(_free_port(), wait_secs=2)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIsNotNone(started, r.stdout + r.stderr)
        self.assertIn('did not answer', r.stderr)


if __name__ == '__main__':
    unittest.main()
