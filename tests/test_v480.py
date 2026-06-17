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

    def test_no_native_prompt_calls(self):
        # #U3 phase 2: native prompt() is also gone (uiPrompt everywhere). Skip
        # full-line comments (which mention prompt() in prose) and ignore
        # uiPrompt( (capital P — excluded by the negative lookbehind anyway).
        for name, src in (("app.js", self.APP), ("app-calendar.js", self.CAL)):
            bad = []
            for line in src.split("\n"):
                s = line.lstrip()
                if s.startswith("//") or s.startswith("*"):
                    continue
                if re.search(r"(?<![\w.])prompt\(", line):
                    bad.append(line.strip()[:80])
            self.assertEqual(bad, [], f"{name} still calls native prompt(): {bad}")


class TestServedAgentInstaller(unittest.TestCase):
    """v4.8.0: GET /api/agent/install (alias /install) serves a one-line agent
    installer with the requesting server's URL baked in — the foundation for the
    'Add device' one-liner and SSH-push."""

    def test_url_baked_from_request(self):
        s = api._render_agent_install({"HTTP_HOST": "rp.lan", "REQUEST_SCHEME": "https"})
        self.assertIn('RP_SERVER="https://rp.lan"', s)
        self.assertNotIn("@@SERVER@@", s)
        self.assertNotIn("@@TOKEN@@", s)
        self.assertIn("/api/agent/download", s)   # downloads the binary
        self.assertIn("enroll-token", s)          # enrols with --token
        self.assertIn("--token", s)

    def test_token_baked_from_query(self):
        s = api._render_agent_install({"HTTP_HOST": "rp.lan", "REQUEST_SCHEME": "https",
                                       "QUERY_STRING": "t=rp_TOK12345"})
        self.assertIn('RP_TOKEN="rp_TOK12345"', s)   # one-line wget|sh, no args
        self.assertNotIn("@@TOKEN@@", s)

    def test_token_sanitized(self):
        s = api._render_agent_install({"HTTP_HOST": "h", "QUERY_STRING": "t=a;b`c$d e"})
        line = [l for l in s.splitlines() if l.startswith("RP_TOKEN=")][0]
        val = line.split('"')[1]                 # the value between the quotes
        for bad in (";", "$", "`", " ", '"'):
            self.assertNotIn(bad, val)

    def test_integrity_and_uninstall_present(self):
        s = api._render_agent_install({"HTTP_HOST": "h"})
        self.assertIn("/api/agent/version", s)     # fetches the published sha256
        self.assertIn("checksum mismatch", s)      # refuses a tampered binary
        self.assertIn("--uninstall", s)            # supports uninstall

    def test_https_default(self):
        s = api._render_agent_install({"HTTP_HOST": "h"})
        self.assertIn('RP_SERVER="https://h"', s)

    def test_host_sanitized_no_shell_break(self):
        s = api._render_agent_install({"HTTP_HOST": 'a";id;`x` $y', "REQUEST_SCHEME": "https"})
        line = [l for l in s.splitlines() if l.startswith("RP_SERVER=")][0]
        self.assertEqual(line.count('"'), 2)               # only the wrapping quotes
        for bad in (";", "$", "`", " "):
            self.assertNotIn(bad, line)

    def test_script_is_valid_posix_sh(self):
        import subprocess
        s = api._render_agent_install({"HTTP_HOST": "h"})
        p = Path(tempfile.gettempdir()) / "rp_install_test.sh"
        p.write_text(s)
        r = subprocess.run(["sh", "-n", str(p)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_endpoint_registered_and_exempt(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("'/api/agent/install'", src)         # route + exempt list
        self.assertIn("def handle_agent_install", src)


class TestAuditClearDiagnostics(unittest.TestCase):
    """v4.8.0: the clear-audit-log gate reports WHY it failed (missing / wrong /
    no-local-password) instead of one ambiguous 'password required' that read as
    'the button did nothing' when a password WAS given. All three are still 403."""

    def _call(self, actor, user_rec, body):
        api.require_admin_auth = lambda: actor
        api.method = lambda: 'DELETE'
        api.get_json_body = lambda: body
        api.save(api.USERS_FILE, {actor: user_rec})
        try:
            api.handle_audit_log_clear()
            return 200, ""
        except api.HTTPError as e:
            return e.status, (e.body or {}).get("error", "")

    def test_missing_password(self):
        s, err = self._call("admin",
                            {"role": "admin", "password_hash": api.hash_password("pw")}, {})
        self.assertEqual(s, 403)
        self.assertIn("Enter your admin password", err)

    def test_no_local_password_sso(self):
        # Sentinel hash ('!...') = SSO/passkey-provisioned admin, no local password.
        s, err = self._call("admin",
                            {"role": "admin", "password_hash": "!" + "a" * 64},
                            {"password": "whatever"})
        self.assertEqual(s, 403)
        self.assertIn("no local password", err)

    def test_wrong_password(self):
        s, err = self._call("admin",
                            {"role": "admin", "password_hash": api.hash_password("right")},
                            {"password": "wrong"})
        self.assertEqual(s, 403)
        self.assertIn("Incorrect admin password", err)


class TestWinAgentGpu(unittest.TestCase):
    """#A3 (Windows GPU): nvidia-smi telemetry on the slow cadence, emitting the
    SAME `gpus` schema the Linux agent does (zero server change)."""

    WIN = (_ROOT / "client" / "remotepower-agent-win.py").read_text()

    def test_win_has_nvidia_gpu_collector(self):
        self.assertIn("def get_gpu_status", self.WIN)
        self.assertIn("nvidia-smi", self.WIN)
        self.assertIn("payload['gpus']", self.WIN)

    def test_win_gpu_schema_matches_linux(self):
        # Same keys the Linux agent emits + the fleet GPU page consumes.
        for key in ("'vendor'", "util_pct", "mem_used_mb", "mem_total_mb",
                    "temp_c", "power_w", "fan_pct"):
            self.assertIn(key, self.WIN, f"win GPU entry missing {key}")

    def test_win_gpu_is_slow_cadence(self):
        # Must ride the existing slow gate (poll_count % 12), not every heartbeat.
        i = self.WIN.index("payload['gpus']")
        window = self.WIN[max(0, i - 1200):i]
        self.assertIn("poll_count % 12", window)


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


class TestMetricWebhookFiresPostLock(unittest.TestCase):
    """B2 (lock-nesting): process_metric_thresholds must BUFFER metric_* webhooks
    and return them for the caller to fire after the _DeviceUpdate lock releases —
    never fire_webhook() inline (nesting drops the alert under SQLite)."""

    def test_buffers_instead_of_firing_inline(self):
        fired = []
        orig = api.fire_webhook
        api.fire_webhook = lambda ev, pl: fired.append((ev, pl))
        try:
            # warning -> critical is an escalation (never flap-held), so it fires
            # deterministically on the first call.
            dev = {'name': 'h1', 'metric_state': {'memory:': 'warning'}}
            pending = api.process_metric_thresholds('d1', dev, {'mem_percent': 99.0},
                                                    defer=True)
        finally:
            api.fire_webhook = orig
        self.assertEqual(fired, [], 'defer=True must not fire inline (heartbeat fires post-lock)')
        self.assertTrue(any(ev == 'metric_critical' for ev, _ in pending),
                        f'expected a buffered metric_critical, got {pending}')


class TestSecurityGates(unittest.TestCase):
    """Source-level guards for the v4.8.0 security fixes."""

    def test_proxmox_test_preflights_host(self):
        import inspect
        self.assertIn('_url_targets_local_or_meta',
                      inspect.getsource(api.handle_proxmox_test))

    def test_drift_mutations_require_mitigate(self):
        import inspect
        self.assertIn("require_perm('mitigate'",
                      inspect.getsource(api.handle_device_drift_baseline))
        self.assertIn("require_perm('mitigate'",
                      inspect.getsource(api.handle_device_drift_reset))

    def test_dmarc_clear_is_admin_gated(self):
        import inspect
        src = inspect.getsource(api.handle_dmarc_clear)
        self.assertIn('require_admin_auth', src)
        self.assertIn('DMARC_REPORTS_FILE', src)

    def test_webpush_send_accepts_injected_opener(self):
        import importlib
        import inspect
        sys.path.insert(0, str(_CGI))
        webpush = importlib.import_module('webpush')
        self.assertIn('opener', inspect.signature(webpush.send).parameters)


class TestIpReputationMonitor(unittest.TestCase):
    """v4.8.0 IP reputation (DNSBL) monitor under Reputation/DMARC."""

    def test_handlers_admin_gated(self):
        import inspect
        for fn in (api.handle_reputation_add, api.handle_reputation_scan,
                   api.handle_reputation_delete):
            self.assertIn('require_admin_auth', inspect.getsource(fn))

    def test_scan_fires_blacklisted_on_new_listing(self):
        orig = api.ip_reputation.check_ip
        api.ip_reputation.check_ip = lambda ip, zones=None: {
            'ip': ip, 'listed_on': [{'name': 'BL', 'zone': 'bl.test'}],
            'errors': {}, 'listed_count': 1, 'ok': True}
        try:
            targets = {'iprep_x': {'ip': '1.2.3.4', 'label': ''}}
            results = {}
            pending, scanned = api._scan_ip_reputation(targets, results)
        finally:
            api.ip_reputation.check_ip = orig
        self.assertEqual([e for e, _ in pending], ['ip_blacklisted'])
        self.assertEqual(scanned, 1)
        self.assertEqual(results['iprep_x']['listed_count'], 1)

    def test_scan_rate_limit_skips_fresh_and_caps(self):
        import time as _t
        calls = []
        orig = api.ip_reputation.check_ip
        api.ip_reputation.check_ip = lambda ip, zones=None: calls.append(ip) or {
            'ip': ip, 'listed_on': [], 'errors': {}, 'listed_count': 0, 'ok': True}
        try:
            now = int(_t.time())
            targets = {f'iprep_{i}': {'ip': f'10.0.0.{i}', 'label': ''} for i in range(5)}
            # all checked 1s ago -> min_recheck=60 skips every one
            results = {tid: {'checked_at': now - 1, 'listed_count': 0} for tid in targets}
            _, scanned = api._scan_ip_reputation(targets, results, min_recheck=60)
            self.assertEqual(scanned, 0)
            self.assertEqual(calls, [])
            # stale -> due, but max_ips caps the burst at 2
            results = {tid: {'checked_at': now - 99999, 'listed_count': 0} for tid in targets}
            _, scanned = api._scan_ip_reputation(targets, results, min_recheck=60, max_ips=2)
            self.assertEqual(scanned, 2)
        finally:
            api.ip_reputation.check_ip = orig

    def test_reputation_events_registered(self):
        self.assertIn('ip_blacklisted', api.WEBHOOK_EVENT_NAMES)
        self.assertIn('ip_blacklist_cleared', api.WEBHOOK_EVENT_NAMES)


class TestVersionBumps(unittest.TestCase):
    """Strict version-surface pins for v4.8.0 — loosen to regex on the next bump
    (see tests/test_v470.py for the loosened pattern)."""
    V = '4.8.0'

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, self.V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{self.V}'",
                      (_ROOT / 'client/remotepower-agent.py').read_text())
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            self.assertIn(f"VERSION = '{self.V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / 'client/remotepower-agent.py').read_bytes(),
                         (_ROOT / 'client/remotepower-agent').read_bytes())

    def test_sw_and_cachebust(self):
        self.assertIn(f'remotepower-shell-v{self.V}',
                      (_ROOT / 'server/html/sw.js').read_text())
        self.assertIn(f'?v={self.V}', (_ROOT / 'server/html/index.html').read_text())

    def test_no_stale_cachebust(self):
        html = (_ROOT / 'server/html/index.html').read_text()
        self.assertEqual(set(re.findall(r'\?v=(4\.7\.0[^"&]*)', html)), set(),
                         'stale ?v=4.7.0 cache-busts left')

    def test_readme_and_changelog(self):
        self.assertIn(f'version-{self.V}-blue', (_ROOT / 'README.md').read_text())
        self.assertIn(f'v{self.V}', (_ROOT / 'CHANGELOG.md').read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f'docs/v{self.V}.md').exists())

    def test_old_version_doc_pruned(self):
        self.assertFalse((_ROOT / 'docs/v4.4.1.md').exists(),
                         'docs/v4.4.1.md should be pruned to keep last 5')

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / 'docs').glob('v*.md'))
        self.assertEqual(len(vdocs), 5, f'expected exactly 5 version docs, got {vdocs}')

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}",
                      (_ROOT / 'server/html/index.html').read_text())


if __name__ == "__main__":
    unittest.main()
