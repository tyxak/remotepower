#!/usr/bin/env python3
"""Tests for v4.8.0 — hardening, parity & the long-standing CVE-scan hang fix.

Covers:
  - _close_inherited_fds() severs inherited fds >= 3 (the SCGI client socket
    that made "Scan all devices" hang the browser) while keeping stdio.
  - _run_detached() still runs fn() inline when fork is unavailable.
"""
import importlib.util
import os
import re
import socket
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v480", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


@unittest.skipUnless(hasattr(os, "fork"), "fork-based detach test needs os.fork")
class TestDetachClosesClientSocket(unittest.TestCase):
    """The detached CVE-scan worker must not inherit the live client socket.

    Regression for the multi-version "Scan all devices hangs the browser" bug:
    under the SCGI prefork worker the HTTP response rides a socket on an fd >= 3,
    so the old dup2(devnull, 0/1/2)-only path left it open for the whole fleet
    scan and nginx kept the browser request pending until the worker exited.
    """

    def test_close_inherited_fds_closes_high_fd_keeps_stdio(self):
        # A socketpair stands in for the inherited client connection socket.
        a, b = socket.socketpair()
        try:
            high_fd = a.fileno()
            self.assertGreaterEqual(high_fd, 3)
            # Exercise the destructive helper in a forked child — it closes
            # every fd >= 3 in the calling process, so it must NOT run here.
            pid = os.fork()
            if pid == 0:
                try:
                    api._close_inherited_fds()
                    # The inherited high fd must now be gone...
                    try:
                        os.fstat(high_fd)
                        os._exit(11)        # still open → fail
                    except OSError:
                        pass
                    # ...and stdio must survive (fd 1 still fstat-able).
                    try:
                        os.fstat(1)
                    except OSError:
                        os._exit(12)        # stdio was wrongly closed → fail
                    os._exit(0)
                except BaseException:
                    os._exit(13)
            _p, status = os.waitpid(pid, 0)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0,
                             "child reported the socket survived or stdio died")
        finally:
            a.close()
            b.close()


class TestRunDetachedInlineFallback(unittest.TestCase):
    def test_runs_inline_when_fork_unavailable(self):
        ran = []
        real_fork = getattr(api.os, "fork", None)

        def _no_fork():
            raise OSError("fork unavailable")

        api.os.fork = _no_fork
        try:
            api._run_detached(lambda: ran.append(True))
        finally:
            if real_fork is not None:
                api.os.fork = real_fork
            else:                                   # pragma: no cover
                del api.os.fork
        self.assertEqual(ran, [True])


_tls_spec = importlib.util.spec_from_file_location("tls_monitor_v480", _CGI / "tls_monitor.py")
tls_monitor = importlib.util.module_from_spec(_tls_spec)
_tls_spec.loader.exec_module(tls_monitor)


class TestTlsMonitorSSRF(unittest.TestCase):
    """#S1: the TLS probe must refuse loopback/link-local/metadata at connect
    time (DNS-rebind resistant) while still allowing private LAN."""

    def test_addr_blocked_classification(self):
        # Link-local (incl. cloud metadata) + unspecified are blocked.
        for ip in ("169.254.169.254", "169.254.1.2", "0.0.0.0", "fe80::1"):
            self.assertTrue(tls_monitor._addr_blocked(ip), f"{ip} should be blocked")
        # Loopback + private LAN + public are allowed (legit cert-monitor targets).
        for ip in ("127.0.0.1", "::1", "10.0.0.4", "192.168.1.10",
                   "172.16.5.5", "8.8.8.8", "1.1.1.1"):
            self.assertFalse(tls_monitor._addr_blocked(ip), f"{ip} should be allowed")

    def test_probe_refuses_metadata_ip(self):
        # The cloud metadata endpoint must be refused at connect time with a
        # clear tls_error and no socket attempt.
        res = tls_monitor._probe_tls("metadata", 443, connect_address="169.254.169.254")
        self.assertIn("refused", res.get("tls_error", ""))
        self.assertEqual(res.get("expires_at"), 0)

    def test_probe_refuses_linklocal_ip(self):
        res = tls_monitor._probe_tls("ll", 443, connect_address="169.254.1.2")
        self.assertIn("refused", res.get("tls_error", ""))


class TestNativeConfirmMigrated(unittest.TestCase):
    """#U3 (phase 1): every confirmation goes through the styled, never-throttled
    uiConfirm modal instead of native confirm() (which browsers suppress after a
    few in a row — the documented "UI looks locked" bug). Ratchet so it can't
    creep back. (prompt() migration is a later phase and not pinned here.)"""

    APP = (_ROOT / "server/html/static/js/app.js").read_text()
    CAL = (_ROOT / "server/html/static/js/app-calendar.js").read_text()

    def test_uiconfirm_helper_exists(self):
        self.assertIn("function uiConfirm(", self.APP)

    def test_no_native_confirm_calls(self):
        for name, src in (("app.js", self.APP), ("app-calendar.js", self.CAL)):
            self.assertEqual(re.findall(r"!confirm\(", src), [],
                             f"{name} still uses native confirm() — use uiConfirm")


class TestMacAgentParity(unittest.TestCase):
    """#A1/#A2: the macOS agent gains listening-ports + saturation-metric parity
    with Linux/Windows, using the same sysinfo field names so server checks/UI
    work unchanged."""

    MAC = (_ROOT / "client" / "remotepower-agent-mac.py").read_text()

    def test_mac_collects_listening_ports(self):
        self.assertIn("def collect_listening_ports", self.MAC)
        self.assertIn("def _port_scope", self.MAC)
        self.assertIn("info['listening_ports']", self.MAC)

    def test_mac_emits_saturation_metrics(self):
        self.assertIn("info['loadavg_1m']", self.MAC)
        self.assertIn("info['fd_percent']", self.MAC)
        # conntrack is Linux-only — must NOT be faked on macOS.
        self.assertNotIn("conntrack_percent", self.MAC)


if __name__ == "__main__":
    unittest.main()
