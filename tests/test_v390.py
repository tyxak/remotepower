"""v3.9.0 release tests.

v3.9.0 is a second bind-it-together / hardening / polish sweep on top of
v3.8.0. These tests pin the new fixes so they can't silently regress:

  * Security — HTTP uptime-monitor SSRF (connect-time peer recheck + IP
    classifier) and inbound-webhook alert-link scheme validation.
  * Fixes — false "didn't take" patch-verify badge, the stray-return metric
    threshold bug, and the tls_expiry severity/title field mismatch.
  * Bind — CPU-load history, swap sparkline, rkhunter last-run, systemd
    alias (canonical), livepatch state.
  * Polish — three newly sortable tables, Lucide icons, close-button a11y.

Strict version pins live here until v3.10.0 ships, at which point this
file's pins loosen to a regex (see test_v380.py for the loosened form).
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path


class _StdinShim:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
from clientjs import client_js

API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
APP = client_js()


class TestVersionBumps(unittest.TestCase):
    EXPECTED = '3.9.0'

    def test_versions(self):
        self.assertRegex(API, r"SERVER_VERSION\s*=\s*'3\.9\.0'")
        self.assertRegex((REPO_ROOT / 'client' / 'remotepower-agent.py').read_text(),
                         r"\nVERSION\s*=\s*'3\.9\.0'")
        self.assertIn("'remotepower-shell-v3.9.0'", (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text())
        self.assertIn('?v=3.9.0', HTML)
        self.assertIn('version-3.9.0-blue.svg', (REPO_ROOT / 'README.md').read_text())

    def test_agent_extensionless_matches(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b)

    def test_changelog_and_doc(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertEqual(m.group(1), self.EXPECTED)
        self.assertTrue((REPO_ROOT / 'docs' / 'v3.9.0.md').exists())
        self.assertTrue((REPO_ROOT / 'docs' / 'security-review-3.9.0.md').exists())


# ─── functional base (temp data dir, fresh api import) ───────────────────────

class _ApiTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_v390_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        if 'api' in sys.modules:
            del sys.modules['api']
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)

    def _seed_admin(self):
        users = self.api.load(self.api.USERS_FILE)
        users['admin'] = {'password_hash': self.api.hash_password('x'), 'role': 'admin'}
        self.api.save(self.api.USERS_FILE, users)
        token = 'adm-' + os.urandom(8).hex()
        toks = self.api.load(self.api.TOKENS_FILE)
        toks[token] = {'user': 'admin', 'created': int(time.time()), 'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, toks)
        os.environ['HTTP_X_TOKEN'] = token


class TestV390MonitorSSRF(_ApiTestBase):
    """HTTP uptime-monitor target validation routes through the shared IP
    classifier (closes the IPv6 / integer-IP / DNS-rebinding holes)."""

    def setUp(self):
        self.api.save(self.api.CONFIG_FILE, {})  # allow_internal_monitors=False

    def test_blocks_metadata_and_encoded_loopback(self):
        san = self.api._sanitize_monitor_target
        self.assertIsNone(san('http', 'http://169.254.169.254/'))   # cloud metadata
        self.assertIsNone(san('http', 'http://[::1]/'))             # IPv6 loopback
        self.assertIsNone(san('http', 'http://2130706433/'))        # int-encoded 127.0.0.1
        self.assertIsNone(san('http', 'http://127.0.0.1/'))         # loopback
        self.assertIsNone(san('http', 'file:///etc/passwd'))        # non-http scheme

    def test_allows_public_and_lan(self):
        san = self.api._sanitize_monitor_target
        self.assertEqual(san('http', 'http://example.com/'), 'http://example.com/')
        # RFC1918 LAN is allowed by design (fleet monitor).
        self.assertEqual(san('http', 'http://192.168.1.10/'), 'http://192.168.1.10/')

    def test_execute_uses_ssrf_safe_opener(self):
        # The fetch must go through the connect-time guard, not bare urlopen.
        block = API[API.index("elif mtype == 'http':"):]
        block = block[:block.index('results.append')]
        self.assertIn('_ssrf_safe_opener(', block)
        self.assertIn('no_redirect=True', block)
        self.assertNotIn('urllib.request.urlopen(', block)

    def test_redirect_counts_as_up(self):
        # Regression: the no-redirect SSRF opener surfaces a 3xx as an
        # HTTPError. A redirecting endpoint (e.g. Jellyfin → 302) must still
        # read 'up'; a genuine 4xx/5xx stays down. Pre-v3.9.0 urlopen followed
        # the redirect to a 2xx, so this preserves that result.
        import urllib.error

        def _fake_opener(code):
            class _O:
                def open(self, req, timeout=None):
                    raise urllib.error.HTTPError(req.full_url, code, 'x', {}, None)
            return _O()

        orig = self.api._ssrf_safe_opener
        try:
            self.api._ssrf_safe_opener = lambda **k: _fake_opener(302)
            r = self.api._execute_monitor_checks(
                [{'type': 'http', 'target': 'https://jelly.example.com:8920', 'label': 'j'}])
            self.assertTrue(r[0]['ok']); self.assertEqual(r[0]['detail'], '302')

            self.api._ssrf_safe_opener = lambda **k: _fake_opener(404)
            r = self.api._execute_monitor_checks(
                [{'type': 'http', 'target': 'https://example.com/', 'label': 'x'}])
            self.assertFalse(r[0]['ok']); self.assertEqual(r[0]['detail'], '404')
        finally:
            self.api._ssrf_safe_opener = orig


class TestV390InboundLinks(unittest.TestCase):
    def test_inbound_alert_links_scheme_validated(self):
        block = API[API.index("links = body.get('links')"):]
        block = block[:block.index("summary['links']")]
        self.assertIn('_validate_link_url(', block)


class TestV390CommandQueue(_ApiTestBase):
    """Everything queued for an agent shows in the dispatch log, and the queue
    is fully clearable (per-command, per-device, and globally)."""

    def setUp(self):
        self._seed_admin()
        os.environ['REQUEST_METHOD'] = 'DELETE'

    def tearDown(self):
        os.environ['REQUEST_METHOD'] = 'GET'
        os.environ.pop('HTTP_X_TOKEN', None)

    def test_clear_all_pending_empties_every_queue(self):
        self.api.save(self.api.DEVICES_FILE, {
            'd-1': {'name': 'a', 'last_seen': 0},
            'd-2': {'name': 'b', 'last_seen': 0}})
        self.api.save(self.api.CMDS_FILE, {'d-1': ['reboot', 'exec:uptime'], 'd-2': ['shutdown']})
        with self.assertRaises(self.api.HTTPError) as ctx:
            self.api.handle_command_queue_clear_all()
        self.assertEqual(ctx.exception.status, 200)
        self.assertEqual(ctx.exception.body['removed'], 3)
        self.assertEqual(ctx.exception.body['devices'], 2)
        cmds = self.api.load(self.api.CMDS_FILE)
        self.assertEqual(cmds.get('d-1'), [])
        self.assertEqual(cmds.get('d-2'), [])

    def test_acme_action_lands_in_dispatch_log(self):
        # Regression: ACME renew/revoke/issue used to enqueue without logging,
        # so they were invisible in the Command Queue's "recently dispatched".
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.save(self.api.DEVICES_FILE, {'d-1': {'name': 'host-a', 'last_seen': 0}})
        self.api.save(self.api.CMDS_FILE, {})
        self.api.save(self.api.HISTORY_FILE, {'entries': []})
        res = self.api._acme_queue_command('d-1', 'renew', 'example.com', 'acme.sh --renew -d example.com')
        self.assertTrue(res and res.get('ok'))
        cmds = (self.api.load(self.api.HISTORY_FILE) or {}).get('entries', [])
        self.assertTrue(any('acme' in (e.get('command') or '') for e in cmds),
                        'ACME action must appear in the command history')

    def test_clear_all_route_registered(self):
        self.assertIn("('DELETE', '/api/command-queue'): handle_command_queue_clear_all", API)


class TestV390UpgradeVerify(_ApiTestBase):
    """The post-upgrade 'didn't take' badge no longer false-alarms."""

    def _dev(self, queued_ago, before, cur, seen_ago):
        now = int(time.time())
        return {'upgrade_queued_at': now - queued_ago,
                'upgrade_pending_before': before,
                'last_seen': now - seen_ago,
                'sysinfo': {'packages': {'upgradable': cur}}}, now

    def test_dropped_count_is_ok(self):
        dev, now = self._dev(7200, 5, 0, 10)
        self.assertEqual(self.api._upgrade_verify_status(dev, now), 'ok')

    def test_nothing_pending_is_not_stalled(self):
        # before<=0: a fleet-wide upgrade hit an already-patched host.
        dev, now = self._dev(7200, 0, 0, 10)
        self.assertIsNone(self.api._upgrade_verify_status(dev, now))

    def test_offline_host_stays_pending(self):
        ttl = self.api.get_online_ttl()
        dev, now = self._dev(7200, 5, 5, ttl + 60)
        self.assertEqual(self.api._upgrade_verify_status(dev, now), 'pending')

    def test_online_unchanged_after_an_hour_is_stalled(self):
        dev, now = self._dev(7200, 5, 5, 10)
        self.assertEqual(self.api._upgrade_verify_status(dev, now), 'stalled')

    def test_no_baseline_does_not_hang_verifying(self):
        # before=None (the agent hadn't reported a patch count when the upgrade
        # was queued) used to wedge on 'verifying…' forever. Now: nothing to
        # verify → no badge.
        dev, now = self._dev(7200, None, 0, 10)
        self.assertIsNone(self.api._upgrade_verify_status(dev, now))

    def test_missing_current_count_recent_is_pending(self):
        dev, now = self._dev(600, 5, None, 10)
        self.assertEqual(self.api._upgrade_verify_status(dev, now), 'pending')

    def test_missing_current_count_online_over_an_hour_gives_up(self):
        # Online for >1h with still no fresh package count → stop hanging.
        dev, now = self._dev(7200, 5, None, 10)
        self.assertIsNone(self.api._upgrade_verify_status(dev, now))

    def test_recheck_button_forces_package_scan(self):
        # The patch report exposes a Re-check button (force scan) when a
        # verification is pending/stalled, wired to the existing handler.
        self.assertIn("data-action-btn=\"_forcePackageScanBtn\"", APP)
        self.assertRegex(APP, r"upgrade_verify === 'pending' \|\| d\.upgrade_verify === 'stalled'")


class TestV390ImageUpdate(_ApiTestBase):
    """One-click container image update (pull + recreate) from Image Updates."""

    def test_normalize_keeps_compose_dir(self):
        import containers as cmod
        out = cmod.normalize_container({'name': 'seerr', 'image': 'x', 'tag': 'latest',
                                        'compose_dir': '/home/jmo/jellyseer'})
        self.assertEqual(out['compose_dir'], '/home/jmo/jellyseer')

    def test_update_in_allowed_actions(self):
        self.assertIn('update', self.api.COMPOSE_ALLOWED_ACTIONS)

    def test_compose_update_accepts_container_reported_dir(self):
        # A dir reported only via a running container's label (not via the
        # compose_projects discovery) is still accepted — that's what the
        # Image Updates "Update" button sends.
        self._seed_admin()
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, {'d-1': {'name': 'host', 'last_seen': now}})
        self.api.save(self.api.CONTAINERS_FILE, {'d-1': {'ts': now, 'items': [
            {'name': 'seerr', 'image': 'ghcr.io/seerr-team/seerr', 'tag': 'latest',
             'compose_dir': '/home/jmo/jellyseer'}]}})
        self.api.save(self.api.CMDS_FILE, {})
        body = json.dumps({'action': 'update', 'dir': '/home/jmo/jellyseer'}).encode()
        os.environ['REQUEST_METHOD'] = 'POST'
        os.environ['CONTENT_LENGTH'] = str(len(body))
        self.api.sys.stdin = _StdinShim(body)
        try:
            with self.assertRaises(self.api.HTTPError) as ctx:
                self.api.handle_device_compose_action('d-1')
            self.assertEqual(ctx.exception.status, 200)
            cmds = self.api.load(self.api.CMDS_FILE)
            self.assertIn('compose:update:/home/jmo/jellyseer', cmds.get('d-1', []))
        finally:
            os.environ['REQUEST_METHOD'] = 'GET'
            os.environ['CONTENT_LENGTH'] = '0'
            os.environ.pop('HTTP_X_TOKEN', None)

    def test_unreported_dir_rejected(self):
        # Defence-in-depth: a dir the device never reported is refused.
        self._seed_admin()
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, {'d-1': {'name': 'host', 'last_seen': now}})
        self.api.save(self.api.CONTAINERS_FILE, {'d-1': {'ts': now, 'items': []}})
        body = json.dumps({'action': 'update', 'dir': '/etc'}).encode()
        os.environ['REQUEST_METHOD'] = 'POST'
        os.environ['CONTENT_LENGTH'] = str(len(body))
        self.api.sys.stdin = _StdinShim(body)
        try:
            with self.assertRaises(self.api.HTTPError) as ctx:
                self.api.handle_device_compose_action('d-1')
            self.assertEqual(ctx.exception.status, 400)
        finally:
            os.environ['REQUEST_METHOD'] = 'GET'
            os.environ['CONTENT_LENGTH'] = '0'
            os.environ.pop('HTTP_X_TOKEN', None)


class TestV390ImageUpdateUI(unittest.TestCase):
    def test_update_button_and_handler_present(self):
        self.assertIn('updateImageNow', APP)
        self.assertIn('data-action="updateImageNow"', APP)
        self.assertIn("action: 'update'", APP)


class TestV390TlsSeverity(_ApiTestBase):
    def setUp(self):
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})

    def test_title_uses_days_left(self):
        title = self.api._alert_title('tls_expiry',
                                      {'host': 'h.example.com', 'days_left': 9})
        self.assertIn('9d', title)


class TestV390MetricThreshold(unittest.TestCase):
    def test_no_bare_return_in_cpu_branch(self):
        # The stray `return` that aborted the whole function (skipping the disk
        # loop + state write) is gone; a `transitioned` flag gates the update.
        block = API[API.index('# CPU as load ratio'):]
        block = block[:block.index("# Disks: per-mount")]
        self.assertIn('transitioned = False', block)
        self.assertNotIn('                    return', block)


class TestV390Bind(_ApiTestBase):
    def test_record_metrics_keeps_swap(self):
        self.api.save(self.api.METRICS_FILE, {})
        self.api._record_metrics('d-swap', {'cpu_percent': 5, 'mem_percent': 10,
                                            'disk_percent': 20, 'swap_percent': 42})
        rows = self.api.load(self.api.METRICS_FILE).get('d-swap', [])
        self.assertTrue(rows and rows[-1].get('swap') == 42)

    def test_daily_sampler_keeps_loadavg(self):
        # The daily metrics sample must retain loadavg + core count for the
        # Trends CPU-load series.
        block = API[API.index("'swap_percent': sysinfo.get('swap_percent'),"):]
        block = block[:block.index("'state': {")]
        self.assertIn("'loadavg_1m'", block)
        self.assertIn("'cpu_count'", block)

    def test_metrics_history_exposes_cpu_load(self):
        block = API[API.index('def handle_device_metrics_history'):]
        block = block[:block.index("respond(200, {'device_id': dev_id, 'series'")]
        self.assertIn("'cpu load %'", block)

    def test_service_sanitizer_keeps_canonical(self):
        out = self.api._sanitize_service_entry(
            {'unit': 'mysql.service', 'active': 'active', 'sub': 'running',
             'since': 0, 'canonical': 'mariadb.service'})
        self.assertEqual(out.get('canonical'), 'mariadb.service')
        # No canonical key when it equals the watched unit.
        out2 = self.api._sanitize_service_entry(
            {'unit': 'nginx.service', 'active': 'active', 'canonical': 'nginx.service'})
        self.assertNotIn('canonical', out2)


class TestV390Polish(unittest.TestCase):
    def test_three_tables_wired_for_sort(self):
        for thead, prefs in (('logs-rules-thead', 'logs_rules_device'),
                             ('logs-rules-global-thead', 'logs_rules_global'),
                             ('maint-supp-thead', 'maint_supp')):
            self.assertIn(f"wireSortOnly('{thead}', '{prefs}'", APP,
                          f'{thead} missing sort wiring')

    def test_rkhunter_last_run_rendered(self):
        self.assertIn('r2.last_run_ts', APP)

    def test_livepatch_state_rendered(self):
        self.assertIn('k.livepatch.state', APP)

    def test_swap_sparkline_track(self):
        self.assertIn("spark('swap'", APP)

    def test_toast_uses_svg_icons(self):
        # Toast icons are Lucide SVG, not the old ✓/✕/ℹ glyphs.
        block = APP[APP.index('function toast('):]
        block = block[:block.index('toast-container')]
        self.assertIn('_icon(', block)
        for glyph in ('✓', '✕', 'ℹ'):
            self.assertNotIn(glyph, block)

    def test_new_icons_registered(self):
        for name in ('play', 'check', 'x', 'info'):
            self.assertRegex(APP, rf'\n\s*{name}:\s*\'')

    def test_close_buttons_have_aria_label(self):
        # The device-drawer close button is icon-only; it must be labelled.
        seg = HTML[HTML.index('data-action="closeDeviceDrawer"'):]
        seg = seg[:seg.index('</button>')]
        self.assertIn('aria-label="Close"', seg)


if __name__ == '__main__':
    unittest.main()
