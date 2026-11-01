#!/usr/bin/env python3
"""The browser harness must not let gunicorn's logging fill a pipe.

It started gunicorn with stderr=PIPE and never read it. A pipe holds 64 KB; past that the next write(2) of a worker thread
blocks, the thread holds the logging lock, every other thread waits for it, and the whole stack stops answering with
all of its connections in CLOSE-WAIT. A security probe that sent a few hundred oversized request lines (each one a
warning in gunicorn's log) found it on 2026-10-31. A test that logs a little never fills the pipe, so it never showed.

This sends enough oversized request lines to log more than 64 KB and then asks for a page. On the old harness the page
never comes back inside the timeout. It needs only gunicorn, but it is gated like every other browser file, on the shared
probe with RP_BROWSER_REQUIRE folded in, so a box that cannot run the stack fails when it is meant to and skips otherwise.
"""
import http.client
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheStackKeepsAnsweringWhileItLogsALot(unittest.TestCase):
    def test_more_than_a_pipe_of_log_lines_does_not_stop_it(self):
        if not browser_available():
            browser_required.skip_or_fail(SKIP_REASON)
        from e2e_harness import start_stack
        base, shutdown = start_stack(data_dir=tempfile.mkdtemp(prefix="rp-harness-stderr-"))
        host, port = base.replace("http://", "").split(":")
        try:
            # gunicorn logs a warning for each request line over 4094 bytes ("Request Line is too large"), about 130
            # bytes each; 900 of them are about 117 KB, well past 64 KB. They go through the harness' own /api proxy.
            for _ in range(900):
                conn = http.client.HTTPConnection(host, int(port), timeout=30)
                conn.request("GET", "/api/" + "A" * 5000)
                conn.getresponse().read()
                conn.close()
            conn = http.client.HTTPConnection(host, int(port), timeout=15)
            conn.request("GET", "/api/status")
            status = conn.getresponse().status
            conn.close()
            self.assertLess(status, 500, "the stack answered an error after logging more than a pipe's worth")
        finally:
            shutdown()


if __name__ == "__main__":
    unittest.main()
