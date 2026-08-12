#!/usr/bin/env python3
"""Four "fixed loopback base" comments, and nothing enforcing any of them.

The three sidecar daemons (flowd, kmipd, syslogd) and the TLS-expiry cron each
POST to a base URL taken from a systemd `Environment=` value. Every urlopen()
call site carried a note saying the base is a fixed loopback address and that
"no file:/ or custom scheme can reach here".

That was true by convention and by nothing else. urllib honours `file://`, so a
base set to one turns an internal POST into a local file read — and the comment
would still be sitting there claiming it could not happen. A comment is not a
control; this is the control.

The cron was worse than its three siblings: it had neither the enforcement NOR
the annotation, which is why semgrep flagged it and not them. The annotation is
what made the difference, not the safety.
"""
import os
import subprocess
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
DAEMONS = {
    'server/flow/remotepower-flowd.py': 'RP_FLOW_SERVER_URL',
    'server/kmip/remotepower-kmipd.py': 'RP_KMIP_SERVER_URL',
    'server/syslog/remotepower-syslogd.py': 'RP_SYSLOG_SERVER_URL',
}
CRON = 'server/cgi-bin/remotepower-tls-check'


def _run(path, env, val):
    return subprocess.run(
        [sys.executable, '-c', f"import runpy; runpy.run_path({str(_ROOT / path)!r})"],
        env=dict(os.environ, **{env: val}),
        capture_output=True, text=True, timeout=60)


class TestANonHttpBaseIsRefused(unittest.TestCase):
    def test_each_daemon_refuses_a_file_url(self):
        """The behaviour the comments claimed. Driven, not read: a source grep
        for the guard would pass against a guard that never runs."""
        for path, env in DAEMONS.items():
            with self.subTest(daemon=Path(path).name):
                r = _run(path, env, 'file:///etc/shadow')
                self.assertIn('must be an http(s) URL', r.stderr + r.stdout)

    def test_each_daemon_still_accepts_a_normal_base(self):
        """The other direction. A guard that refuses everything satisfies the
        assertion above and breaks every deployment."""
        for path, env in DAEMONS.items():
            with self.subTest(daemon=Path(path).name):
                r = _run(path, env, 'http://127.0.0.1:8090')
                self.assertNotIn('must be an http(s) URL', r.stderr + r.stdout)

    def test_https_is_accepted_too(self):
        """A satellite reaching the control plane over TLS is a supported
        deployment; refusing https would be the over-block."""
        for path, env in DAEMONS.items():
            with self.subTest(daemon=Path(path).name):
                r = _run(path, env, 'https://rp.internal:8443')
                self.assertNotIn('must be an http(s) URL', r.stderr + r.stdout)

    def test_the_default_needs_no_environment_variable(self):
        for path, env in DAEMONS.items():
            with self.subTest(daemon=Path(path).name):
                e = dict(os.environ)
                e.pop(env, None)
                r = subprocess.run(
                    [sys.executable, '-c',
                     f"import runpy; runpy.run_path({str(_ROOT / path)!r})"],
                    env=e, capture_output=True, text=True, timeout=60)
                self.assertNotIn('must be an http(s) URL', r.stderr + r.stdout)


class TestTheCronGuardsItToo(unittest.TestCase):
    """The TLS cron is not importable in isolation (it runs a scan), so this
    one is pinned on source — but on the GUARD, not on a comment claiming
    safety."""

    def test_the_scheme_is_checked_before_the_request(self):
        src = (_ROOT / CRON).read_text()
        self.assertIn("startswith(('http://', 'https://'))", src)
        guard = src.index("startswith(('http://', 'https://'))")
        call = src.index('urllib.request.urlopen(req')
        self.assertLess(guard, call,
                        'the scheme check must precede the request it protects')

    def test_it_carries_the_same_annotation_as_its_siblings(self):
        """It was the only one of the four without one, which is the entire
        reason the scanner singled it out."""
        src = (_ROOT / CRON).read_text()
        self.assertIn('nosec B310', src)
        self.assertIn('nosemgrep', src)


if __name__ == '__main__':
    unittest.main()
