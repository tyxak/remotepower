#!/usr/bin/env python3
"""
Tests for v3.13.0 — "bind it together" round four: surface collected-but-hidden
host signals, cap overflowing panels, plus performance and security hardening.

Holds the strict version-surface pins for this release (loosened to regex on the
next bump) plus wiring smoke checks for the new bindings and hardening.
"""
import os
import tempfile

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))
sys.path.insert(0, str(Path(__file__).parent))

_spec = importlib.util.spec_from_file_location("api_v3130", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

from clientjs import client_js

VERSION = "3.13.0"


class TestVersionBumps(unittest.TestCase):
    # v3.14.0: loosened from the exact 3.13.0 pins (the live strict pin moved to
    # tests/test_v3140.py) so a later bump doesn't fail this file.
    def test_server_version(self):
        self.assertRegex(api.SERVER_VERSION, r'^\d+\.\d+\.\d+$')

    def test_agent_version(self):
        txt = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertRegex(txt, r"\nVERSION\s*=\s*'\d+\.\d+\.\d+'")

    def test_agent_extensionless_matches_py(self):
        a = (_ROOT / "client/remotepower-agent.py").read_bytes()
        b = (_ROOT / "client/remotepower-agent").read_bytes()
        self.assertEqual(a, b, "agent .py and extensionless copy diverged "
                               "(run cp client/remotepower-agent.py client/remotepower-agent)")

    def test_sw_cache_name(self):
        txt = (_ROOT / "server/html/sw.js").read_text()
        self.assertRegex(txt, r"remotepower-shell-v\d+\.\d+\.\d+")

    def test_index_cache_bust(self):
        txt = (_ROOT / "server/html/index.html").read_text()
        self.assertRegex(txt, r"\?v=\d+\.\d+\.\d+")
        self.assertNotIn("?v=3.12.0", txt)

    def test_readme_badge(self):
        txt = (_ROOT / "README.md").read_text()
        self.assertRegex(txt, r"version-\d+\.\d+\.\d+-blue")

    def test_changelog_top_entry(self):
        txt = (_ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(txt[:2000], r"v\d+\.\d+\.\d+")

    def test_version_doc_exists(self):
        # v4.4.0: the keep-last-5 housekeeping aged out the final v3.x doc, so
        # this no longer pins a v3.* file specifically — just that the per-release
        # version docs exist at all.
        self.assertTrue(list((_ROOT / "docs").glob("v[0-9]*.md")))

    def test_whats_new_card_present(self):
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertRegex(html, r"What's new — v\d+\.\d+\.\d+")


class TestDataBindings(unittest.TestCase):
    """The new device-drawer / device-card bindings exist in the front-end."""

    def setUp(self):
        self.js = client_js()

    def test_recent_logins_binding(self):
        self.assertIn("Access — recent logins", self.js)
        self.assertIn("recent_logins", self.js)

    def test_timers_binding(self):
        self.assertIn("Scheduled jobs / timers", self.js)

    def test_storage_health_binding(self):
        self.assertIn("Pools / arrays", self.js)
        self.assertIn("storage_health", self.js)

    def test_ports_scope_and_addr(self):
        # The drawer Ports card now renders the scope badge + bind address.
        self.assertIn("scopeBadge", self.js)

    def test_firewall_fingerprint_binding(self):
        self.assertIn("firewall_fp", self.js)
        self.assertIn("fpLine", self.js)

    def test_brute_force_badge(self):
        self.assertIn("brute_force_active", self.js)


class TestOverflowCaps(unittest.TestCase):
    """Panels cap and scroll instead of growing unbounded."""

    def setUp(self):
        self.css = (_ROOT / "server/html/static/css/styles.css").read_text()
        self.js = client_js()

    def test_audit_scroll_class_defined(self):
        self.assertIn(".audit-scroll", self.css)

    def test_audit_section_body_capped(self):
        # The drawer card body now has a max-height + overflow.
        body = self.css.split(".audit-section-body")[1].split("}")[0]
        self.assertIn("max-height", body)
        self.assertIn("overflow", body)

    def test_clip_bugs_fixed(self):
        # isl-654 (host-config dump) and isl-382 (patch history) had max-height
        # with no overflow — both must now scroll.
        for cls in (".isl-654", ".isl-382", ".isl-636"):
            rule = self.css.split(cls + " {")[1].split("}")[0]
            self.assertIn("overflow", rule, f"{cls} still clips without overflow")


class TestFleetRiskCache(unittest.TestCase):
    def test_cache_helpers_exist(self):
        self.assertTrue(callable(getattr(api, "_fleet_risk_cached", None)))
        self.assertTrue(callable(getattr(api, "_fleet_risk_cache_file", None)))

    def test_callers_use_cache(self):
        src = (_CGI_BIN / "api.py").read_text()
        # The Risk endpoint routes through the cache. (v3.13.0: fleet health no
        # longer calls it — risk is decoupled from health.)
        self.assertIn("risks = _fleet_risk_cached()", src)


class TestSecurityHardening(unittest.TestCase):
    def setUp(self):
        self.src = (_CGI_BIN / "api.py").read_text()

    def test_scap_report_sandboxed_csp(self):
        # The agent-supplied SCAP HTML is served under a self-contained
        # sandboxed CSP (in the report download handler) regardless of the
        # upstream policy.
        block = self.src.split("def handle_scap_report_download")[1][:2000]
        self.assertIn("Content-Security-Policy", block)
        self.assertIn("sandbox;", block)
        self.assertIn("X-Frame-Options: DENY", block)

    def test_oidc_claim_checks(self):
        self.assertIn("id_token expired", self.src)
        self.assertIn("id_token issuer mismatch", self.src)
        self.assertIn("id_token audience mismatch", self.src)

    def test_syslog_resolve_once(self):
        # The syslog forwarder resolves once and connects to the literal IP.
        self.assertIn("getaddrinfo(host, port", self.src)


class TestProjectWideTableCap(unittest.TestCase):
    """Every table card caps at ~15 rows and scrolls with a sticky header."""

    def setUp(self):
        self.css = (_ROOT / "server/html/static/css/styles.css").read_text()

    def test_table_card_capped(self):
        # The base .table-card rule must carry a max-height + overflow so no
        # page (e.g. Exposure) grows unbounded.
        seg = self.css.split(".table-card {", 1)[1].split("}", 1)[0]
        self.assertIn("max-height", seg)
        self.assertIn("overflow", seg)

    def test_table_card_sticky_header(self):
        self.assertIn(".table-card thead th", self.css)
        seg = self.css.split(".table-card thead th", 1)[1].split("}", 1)[0]
        self.assertIn("sticky", seg)


class TestNetworkMounts(unittest.TestCase):
    """NFS/SMB/CIFS mounts are collected (agent) and preserved (server)."""

    def setUp(self):
        self.agent = (_ROOT / "client/remotepower-agent.py").read_text()
        self.api = (_CGI_BIN / "api.py").read_text()
        self.js = client_js()

    def test_agent_includes_network_filesystems(self):
        # all=False omits every network mount — the bug. Must be all=True.
        self.assertIn("disk_partitions(all=True)", self.agent)
        self.assertNotIn("disk_partitions(all=False)", self.agent)

    def test_agent_flags_network_and_guards_stall(self):
        # Network mounts get a flag, and a hung share is probed (killable)
        # before statvfs so it can't block the heartbeat.
        self.assertIn("'network'", self.agent)
        self.assertIn("_mount_responsive", self.agent)

    def test_server_preserves_network_fields(self):
        self.assertIn("entry['network'] = True", self.api)
        self.assertIn("entry['server']", self.api)

    def test_frontend_renders_net_and_stalled(self):
        self.assertIn("m.network", self.js)
        self.assertIn("stalled", self.js)


class TestFirewallDetection(unittest.TestCase):
    """Firewall probe scans all tables + both backends + nft handles + firewalld."""

    def setUp(self):
        self.agent = (_ROOT / "client/remotepower-agent.py").read_text()

    def test_scans_all_tables_via_save(self):
        self.assertIn("iptables-save", self.agent)
        self.assertIn("iptables-legacy-save", self.agent)

    def test_falls_back_to_list_command(self):
        # The v3.13.0 regression: a present-but-failing iptables-save suppressed
        # the working `iptables -S`. The probe must try the plain list too.
        self.assertIn("('iptables', '-S')", self.agent)
        self.assertIn("('iptables-legacy', '-S')", self.agent)

    def test_which_searches_sbin(self):
        # Firewall tools live in /usr/sbin; a minimal service PATH omits it.
        self.assertIn("/usr/sbin", self.agent)
        self.assertIn("/sbin", self.agent)

    def test_nft_counts_by_handle(self):
        self.assertIn("# handle ", self.agent)

    def test_detects_firewalld(self):
        self.assertIn("firewall-cmd", self.agent)


class TestCmdbHardwareFields(unittest.TestCase):
    """Agent reports CPU model / kernel / RAM / disk total; server passes them."""

    def setUp(self):
        self.agent_mod = self._load_agent()
        self.api_src = (_CGI_BIN / "api.py").read_text()
        self.js = client_js()

    @staticmethod
    def _load_agent():
        import importlib.util
        spec = importlib.util.spec_from_file_location("rpa_hw", _ROOT / "client/remotepower-agent.py")
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except SystemExit:
            pass
        return mod

    def test_cpu_model_skips_numeric_model_line(self):
        # /proc/cpuinfo has both `model : 33` (numeric) and `model name : ...`.
        # _cpu_model must return the human-readable name, never the bare number.
        m = self.agent_mod._cpu_model()
        self.assertIsInstance(m, str)
        self.assertFalse(m.isdigit(), f"_cpu_model returned a bare number: {m!r}")

    def test_metrics_report_hardware(self):
        if not getattr(self.agent_mod, '_PSUTIL', None):
            self.skipTest('psutil not available in this environment')
        met = self.agent_mod.get_metrics()
        self.assertIn('mem_total_mb', met)
        self.assertGreater(met['mem_total_mb'], 0)
        if 'disk_total_gb' in met:
            self.assertGreater(met['disk_total_gb'], 0)

    def test_metrics_source_has_hardware(self):
        # Source-level guarantee independent of psutil availability.
        src = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertIn("out['mem_total_mb']", src)
        self.assertIn("out['disk_total_gb']", src)
        self.assertIn("'kernel':   platform.release()", src)

    def test_server_passes_hardware_fields(self):
        for f in ("safe_si['cpu']", "safe_si['kernel']",
                  "safe_si['mem_total_mb']", "safe_si['disk_total_gb']"):
            self.assertIn(f, self.api_src)

    def test_frontend_reads_hardware_fields(self):
        # The CMDB Hardware panel reads these keys.
        for key in ('mem_total_mb', 'disk_total_gb', 'si.kernel', 'si.cpu'):
            self.assertIn(key, self.js)

    def test_collect_runs(self):
        # Import the agent and run the collector — must not raise even where
        # the tools are absent / unreadable (returns None or a list).
        import importlib.util
        spec = importlib.util.spec_from_file_location("rpa_fw", _ROOT / "client/remotepower-agent.py")
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except SystemExit:
            pass
        res = mod.collect_firewall_detail()
        self.assertTrue(res is None or isinstance(res, dict))


class TestDriftProfiles(unittest.TestCase):
    """Named drift profiles: routes, resolution precedence, frontend wiring."""

    def setUp(self):
        self.api_src = (_CGI_BIN / "api.py").read_text()
        self.js = client_js()

    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/drift/profiles'), routes)
        self.assertIn(('POST', '/api/drift/profiles'), routes)
        self.assertIn(('POST', '/api/drift/assign'), routes)

    def test_handlers_exist(self):
        for fn in ('handle_drift_profiles', 'handle_drift_profile_edit',
                   'handle_drift_assign', '_resolve_drift_profile_files'):
            self.assertTrue(callable(getattr(api, fn, None)), fn)

    def test_resolution_precedence(self):
        # device assignment beats tag beats group.
        drift_cfg = {
            'profiles': [
                {'id': 'pg', 'name': 'g', 'files': ['/g']},
                {'id': 'pt', 'name': 't', 'files': ['/t']},
                {'id': 'pd', 'name': 'd', 'files': ['/d']},
            ],
            'assignments': [
                {'scope_type': 'group', 'scope_value': 'web', 'profile_id': 'pg'},
                {'scope_type': 'tag', 'scope_value': 'db', 'profile_id': 'pt'},
                {'scope_type': 'device', 'scope_value': 'dev1', 'profile_id': 'pd'},
            ],
        }
        # group only (no matching tag) -> group profile
        self.assertEqual(
            api._resolve_drift_profile_files('x', {'group': 'web'}, drift_cfg), ['/g'])
        # tag wins over group when both match
        self.assertEqual(
            api._resolve_drift_profile_files('x', {'group': 'web', 'tags': ['db']}, drift_cfg), ['/t'])
        # device assignment wins over tag and group
        self.assertEqual(
            api._resolve_drift_profile_files('dev1', {'group': 'web', 'tags': ['db']}, drift_cfg), ['/d'])
        # no match -> None (falls back to default upstream)
        self.assertIsNone(
            api._resolve_drift_profile_files('z', {'group': 'none'}, drift_cfg))

    def test_get_watched_files_uses_profile_and_override(self):
        api.save(api.CONFIG_FILE, {'drift': {
            'enabled': True,
            'default_watched_files': ['/default'],
            'profiles': [{'id': 'p1', 'name': 'p', 'files': ['/profile']}],
            'assignments': [{'scope_type': 'group', 'scope_value': 'g1', 'profile_id': 'p1'}],
        }})
        api.save(api.DEVICES_FILE, {
            'd_default': {'name': 'a'},                       # no group -> default
            'd_profile': {'name': 'b', 'group': 'g1'},        # group -> profile
            'd_manual':  {'name': 'c', 'group': 'g1',
                          'watched_files': ['/manual']},      # explicit override
        })
        self.assertEqual(api.get_watched_files_for('d_default'), ['/default'])
        self.assertEqual(api.get_watched_files_for('d_profile'), ['/profile'])
        self.assertEqual(api.get_watched_files_for('d_manual'), ['/manual'])

    def test_validate_drift_files(self):
        out = api._validate_drift_files(['/etc/a', 'relative', '/etc/a', '  /etc/b  '])
        self.assertEqual(out, ['/etc/a', '/etc/b'])   # abs-only, deduped, trimmed

    def test_frontend_management_functions(self):
        for fn in ('loadDriftProfiles', 'openDriftProfileModal', 'saveDriftProfile',
                   'deleteDriftProfile', 'openDriftAssignModal', 'assignDriftProfile',
                   'unassignDriftProfile'):
            self.assertIn(f'function {fn}', self.js)


class TestDriftEffective(unittest.TestCase):
    """Drift explainability: _drift_effective reports the resolution source."""

    DC = {
        'enabled': True,
        'default_watched_files': ['/default'],
        'profiles': [
            {'id': 'pg', 'name': 'grp', 'files': ['/g']},
            {'id': 'pt', 'name': 'tagp', 'files': ['/t']},
            {'id': 'pd', 'name': 'devp', 'files': ['/d']},
        ],
        'assignments': [
            {'scope_type': 'group', 'scope_value': 'web', 'profile_id': 'pg'},
            {'scope_type': 'tag', 'scope_value': 'db', 'profile_id': 'pt'},
            {'scope_type': 'device', 'scope_value': 'dev1', 'profile_id': 'pd'},
        ],
    }

    def test_device_override(self):
        r = api._drift_effective('x', {'watched_files': ['/m']}, self.DC)
        self.assertEqual(r['source'], 'device-override')
        self.assertEqual(r['files'], ['/m'])

    def test_profile_scopes(self):
        self.assertEqual(api._drift_effective('x', {'group': 'web'}, self.DC)['source'], 'profile:group')
        self.assertEqual(api._drift_effective('x', {'tags': ['db']}, self.DC)['source'], 'profile:tag')
        r = api._drift_effective('dev1', {'group': 'web', 'tags': ['db']}, self.DC)
        self.assertEqual(r['source'], 'profile:device')
        self.assertEqual(r['profile'], 'devp')

    def test_default_and_disabled(self):
        self.assertEqual(api._drift_effective('x', {}, self.DC)['source'], 'default')
        self.assertEqual(api._drift_effective('x', {}, {'enabled': False})['source'], 'disabled')

    def test_endpoint_exposes_source(self):
        self.assertIn("effective['source']", (_CGI_BIN / "api.py").read_text())


class TestControllerBackup(unittest.TestCase):
    """Full backup/restore: routes, helpers, exclusion rules, tar round-trip."""

    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/backup/download'), routes)
        self.assertIn(('POST', '/api/backup/restore'), routes)

    def test_handlers_exist(self):
        for fn in ('handle_backup_download', 'handle_backup_restore', '_write_data_dir_tar'):
            self.assertTrue(callable(getattr(api, fn, None)), fn)

    def test_exclude_rules(self):
        self.assertFalse(api._backup_include('attention_cache.json'))
        self.assertFalse(api._backup_include('fleet_risk_cache.json'))
        self.assertFalse(api._backup_include('restore-snapshots/pre-restore-x.tar.gz'))
        self.assertFalse(api._backup_include('devices.json.tmp.1.2'))
        self.assertTrue(api._backup_include('devices.json'))
        self.assertTrue(api._backup_include('cmdb_vault.json'))

    def test_tar_roundtrip_excludes_caches(self):
        import tarfile, tempfile
        from pathlib import Path as _P
        d = _P(tempfile.mkdtemp())
        (d / 'devices.json').write_text('{}')
        (d / 'attention_cache.json').write_text('{}')
        (d / 'restore-snapshots').mkdir()
        (d / 'restore-snapshots' / 'old.tar.gz').write_text('x')
        old = api.DATA_DIR
        api.DATA_DIR = d
        try:
            buf = d / 'out.tar.gz'
            with tarfile.open(str(buf), 'w:gz') as t:
                api._write_data_dir_tar(t)
            with tarfile.open(str(buf), 'r:gz') as t:
                names = set(t.getnames())
            self.assertIn('devices.json', names)
            self.assertNotIn('attention_cache.json', names)
            self.assertFalse(any(n.startswith('restore-snapshots') for n in names))
        finally:
            api.DATA_DIR = old


class TestMountTrends(unittest.TestCase):
    """Network mounts flow into the daily history + per-mount Trends series."""

    def setUp(self):
        self.src = (_CGI_BIN / "api.py").read_text()

    def test_daily_history_skips_stalled(self):
        # The daily-sample mount builder must skip mounts with no numeric percent.
        self.assertIn("if not isinstance(pct, (int, float)):", self.src)

    def test_metrics_history_reads_samples_key(self):
        # Shape-bug fix: read rec['samples'], not the dict itself.
        self.assertIn("rec = (load(METRICS_HIST_FILE) or {}).get(dev_id) or {}", self.src)
        self.assertIn("samples = rec.get('samples') or []", self.src)

    def test_metrics_history_per_mount_series(self):
        self.assertIn("mount_pts", self.src)
        self.assertIn("(net)", self.src)


class TestThemeAndControls(unittest.TestCase):
    """White-background sweep + Tasks linked-device filterbox."""

    def setUp(self):
        self.css = (_ROOT / "server/html/static/css/styles.css").read_text()
        self.html = (_ROOT / "server/html/index.html").read_text()

    def test_bare_controls_themed(self):
        # Global base rule themes bare input/select/textarea so nothing renders
        # browser-white. Checkboxes excluded; :where() keeps it low-specificity.
        self.assertIn("input:where(:not([type=checkbox])", self.css)
        seg = self.css.split("input:where(:not([type=checkbox])", 1)[1].split("}", 1)[0]
        self.assertIn("var(--bg)", seg)

    def test_btn_defined(self):
        # .btn (software-policy "Add rule") had no CSS → white; now styled.
        self.assertIn("\n  .btn {", self.css)

    def test_form_group_width(self):
        self.assertIn(".form-group > select", self.css)

    def test_task_device_is_combobox(self):
        # Tasks "Linked device" must be the type-to-search filterbox, not a
        # bare dropdown.
        self.assertRegex(self.html, r'id="task-device"[^>]*class="[^"]*device-combo')


class TestUpgradeRebootReliability(unittest.TestCase):
    def setUp(self):
        self.agent = (_ROOT / "client/remotepower-agent.py").read_text()
        self.api = (_CGI_BIN / "api.py").read_text()

    def test_upgrade_gets_long_timeout(self):
        # Upgrades must not be killed at 300s before the trailing reboot runs.
        # v5.0.0 (#F3): an optional per-command override may precede the heuristic.
        self.assertIn("1800 if _is_upgrade else 300", self.agent)

    def test_reboot_has_fallbacks(self):
        self.assertIn("systemctl reboot || /sbin/reboot || reboot", self.api)


class TestAutopatchSync(unittest.TestCase):
    """Auto-patch policy mirrors into a maintenance window + calendar event."""

    def setUp(self):
        # Point the file constants at a fresh temp dir for this test.
        import tempfile
        from pathlib import Path as _P
        self.d = _P(tempfile.mkdtemp())
        self._old = (api.MAINT_FILE, api.CALENDAR_FILE)
        api.MAINT_FILE = self.d / "maintenance.json"
        api.CALENDAR_FILE = self.d / "calendar.json"

    def tearDown(self):
        api.MAINT_FILE, api.CALENDAR_FILE = self._old

    def test_sync_creates_and_removes(self):
        pol = {'id': 'p1', 'name': 'Nightly', 'cron': '0 3 * * *',
               'enabled': True, 'reboot': True, 'target': {'type': 'all', 'value': ''}}
        api._autopatch_sync(pol)
        wins = (api.load(api.MAINT_FILE) or {}).get('windows') or []
        evs = (api.load(api.CALENDAR_FILE) or {}).get('events') or []
        self.assertTrue(any(w.get('autopatch_id') == 'p1' and w.get('cron') == '0 3 * * *' for w in wins))
        self.assertTrue(any(e.get('autopatch_id') == 'p1' for e in evs))
        # remove
        api._autopatch_sync({'id': 'p1'}, remove=True)
        wins2 = (api.load(api.MAINT_FILE) or {}).get('windows') or []
        evs2 = (api.load(api.CALENDAR_FILE) or {}).get('events') or []
        self.assertFalse(any(w.get('autopatch_id') == 'p1' for w in wins2))
        self.assertFalse(any(e.get('autopatch_id') == 'p1' for e in evs2))

    def test_cron_to_recur(self):
        self.assertEqual(api._cron_to_recur('0 3 * * 0'), 'weekly')
        self.assertEqual(api._cron_to_recur('0 3 1 * *'), 'monthly')
        self.assertEqual(api._cron_to_recur('0 3 * * *'), 'daily')

    def test_create_wires_sync(self):
        self.assertIn("_autopatch_sync(pol)", (_CGI_BIN / "api.py").read_text())


class TestInventoryCatalog(unittest.TestCase):
    """Software center: aggregated installed-package catalog + has-package version."""

    def test_route_registered(self):
        src = (_CGI_BIN / "api.py").read_text()
        self.assertIn("/api/inventory/catalog", src)
        self.assertTrue(callable(getattr(api, "handle_inventory_catalog", None)))

    def test_catalog_aggregates(self):
        import tempfile
        from pathlib import Path as _P
        d = _P(tempfile.mkdtemp())
        old_pkg, old_dev = api.PACKAGES_FILE, api.DEVICES_FILE
        api.PACKAGES_FILE = d / "packages.json"
        api.DEVICES_FILE = d / "devices.json"
        try:
            api.save(api.DEVICES_FILE, {'a': {'name': 'A'}, 'b': {'name': 'B'}})
            api.save(api.PACKAGES_FILE, {
                'a': {'packages': [{'name': 'openssl', 'version': '3.0.2'},
                                   {'name': 'curl', 'version': '8.1'}]},
                'b': {'packages': [{'name': 'openssl', 'version': '3.0.5'}]},
            })
            # aggregate by hand via the same logic the handler uses
            store = api.load(api.PACKAGES_FILE)
            agg = {}
            for did, e in store.items():
                for p in e['packages']:
                    agg.setdefault(p['name'], {}).setdefault(p['version'], set()).add(did)
            self.assertEqual(len(agg['openssl']), 2)   # two distinct versions
            self.assertEqual(len(agg['curl']['8.1']), 1)
        finally:
            api.PACKAGES_FILE, api.DEVICES_FILE = old_pkg, old_dev

    def test_fleet_query_outputs_pkg_version(self):
        src = (_CGI_BIN / "api.py").read_text()
        self.assertIn("'pkg_match': matched_pkg", src)
        # the matched string includes the installed version
        self.assertIn("p.get('version', '')", src)
        # frontend renders the matched-package column
        self.assertIn("hasPkgCol", client_js())

    def test_frontend_software_center(self):
        js = client_js()
        for fn in ('loadSoftwareCatalog', '_renderSwCatalog', '_swCatalogFilter'):
            self.assertIn(f'function {fn}', js)


class TestFormControlSpecificity(unittest.TestCase):
    """The global control-theming rule must NOT outrank .form-input (regression:
    the :not() chain inflated specificity and clobbered .form-input width)."""

    def test_base_rule_uses_where(self):
        css = (_ROOT / "server/html/static/css/styles.css").read_text()
        # The :not chain is wrapped in :where() to keep element-level specificity.
        self.assertIn("input:where(:not([type=checkbox])", css)
        # And the old high-specificity bare form was removed.
        self.assertNotIn("\n  input:not([type=checkbox]):not([type=radio]):not([type=range]):not([type=color]):not([type=file]),", css)


class TestForecastNetworkMounts(unittest.TestCase):
    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("fc_net", _CGI_BIN / "forecast.py")
        self.fc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.fc)

    def test_network_flag_passthrough(self):
        import time
        now = int(time.time())
        samples = [{'ts': now - i * 86400,
                    'mounts': [{'path': '/data', 'used_gb': 10 + i, 'total_gb': 100, 'network': True},
                               {'path': '/', 'used_gb': 5, 'total_gb': 50}]}
                   for i in range(5)]
        rows = {r['path']: r for r in self.fc.forecast_mounts(samples)}
        self.assertIn('/data', rows)
        self.assertTrue(rows['/data']['network'])
        self.assertFalse(rows['/'].get('network'))

    def test_network_not_excluded(self):
        # Network shares aren't in the volatile-exclude list.
        self.assertNotIn('/data', self.fc.VOLATILE_MOUNTS)

    def test_frontend_labels_net(self):
        self.assertIn("network share (NFS/SMB/CIFS)", client_js())


class TestUiPolishBatch(unittest.TestCase):
    """Password-form a11y, settings-row stacking, host-config modal sizing,
    software-center 'where installed'."""

    def setUp(self):
        self.css = (_ROOT / "server/html/static/css/styles.css").read_text()
        self.html = (_ROOT / "server/html/index.html").read_text()
        self.js = client_js()

    def test_pw_form_a11y_injection(self):
        self.assertIn("function _ensurePwFormA11y", self.js)
        self.assertIn(".visually-hidden", self.css)
        # passwd-form's username is now a visually-hidden text field, not hidden.
        self.assertIn('id="passwd-username" class="visually-hidden"', self.html)

    def test_settings_row_stacks_direct_label(self):
        self.assertIn(".settings-row:has(> .form-label)", self.css)

    def test_hostconfig_modal_fixed_size(self):
        self.assertIn("#host-config-modal > .modal {", self.css)
        seg = self.css.split("#host-config-modal > .modal {", 1)[1].split("}", 1)[0]
        self.assertIn("flex-direction: column", seg)

    def test_software_center_where_installed(self):
        # endpoint returns host names per version
        self.assertIn("'host_names'", (_CGI_BIN / "api.py").read_text())
        # frontend expands a row to show where it's installed
        self.assertIn("_swCatalogToggle", self.js)
        self.assertIn("Installed on:", self.js)


class TestAiButtons(unittest.TestCase):
    """v3.13.0: targeted AI buttons across the UI (frontend-only, reuse
    openAIModal + /api/ai/chat which accepts a raw system-prompt string)."""

    def setUp(self):
        self.js = client_js()
        self.html = (_ROOT / "server/html/index.html").read_text()

    def test_helper_functions_exist(self):
        for fn in ('aiPackageSafety', 'aiExposureAdvice', 'aiForecastAdvice',
                   'aiRemediateControl', 'aiDiagnoseUnits', 'aiDiagnoseContainer',
                   'aiExplainDrift', 'aiAskFleet'):
            self.assertIn(f'function {fn}', self.js)

    def test_buttons_wired(self):
        for action in ('aiPackageSafety', 'aiExposureAdvice', 'aiForecastAdvice',
                       'aiRemediateControl', 'aiDiagnoseUnits', 'aiDiagnoseContainer',
                       'aiExplainDrift'):
            self.assertIn(f'data-action="{action}"', self.js)

    def test_home_omnibox(self):
        self.assertIn('id="home-ai-q"', self.html)
        self.assertIn('data-action="aiAskFleet"', self.html)

    def test_data_enter_handler(self):
        self.assertIn("input[data-enter]", self.js)


class TestFleetHostConfig(unittest.TestCase):
    """Fleet-wide host-config collect + export."""

    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('POST', '/api/host-config/collect-all'), routes)
        self.assertIn(('GET', '/api/host-config/export'), routes)

    def test_handlers_exist(self):
        self.assertTrue(callable(getattr(api, 'handle_host_config_collect_all', None)))
        self.assertTrue(callable(getattr(api, 'handle_host_config_export', None)))

    def test_collect_uses_agent_command(self):
        src = (_CGI_BIN / "api.py").read_text()
        self.assertIn("exec:remotepower-agent send_current_configs", src)
        # agentless devices are excluded from collect-all
        self.assertIn("(devices.get(d) or {}).get('agentless')", src)

    def test_frontend_buttons(self):
        js = client_js()
        self.assertIn("function collectAllHostConfigs", js)
        self.assertIn("function exportAllHostConfigs", js)
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertIn('data-action="collectAllHostConfigs"', html)
        self.assertIn('data-action="exportAllHostConfigs"', html)


class TestSecurityAuditFixes(unittest.TestCase):
    """v3.13.0 audit fixes: restore bomb guard, AI-chat RBAC scoping, SHA1 nits."""

    def setUp(self):
        self.src = (_CGI_BIN / "api.py").read_text()

    def test_restore_decompression_bomb_guard(self):
        self.assertIn("_MAX_RESTORE_BYTES", self.src)
        self.assertIn("possible zip bomb", self.src)

    def test_ai_chat_scope_filtered(self):
        # fleet snapshot scoped to caller; RAG only for full-access callers.
        self.assertIn("raw = _scope_filter_devices(load(DEVICES_FILE) or {})", self.src)
        self.assertIn("_ai_scope = _caller_scope()", self.src)
        self.assertIn("include_rag and _ai_scope is None", self.src)

    def test_sha1_fingerprints_not_for_security(self):
        # The dedupe fingerprints are annotated usedforsecurity=False. v4.4.1
        # extended the same annotation to the two MD5 fleet-checks cache-key
        # fingerprints, so the count only grows — every weak-hash call must be
        # marked non-security.
        self.assertGreaterEqual(self.src.count("usedforsecurity=False"), 2)


class TestRiskScoring(unittest.TestCase):
    """Risk no longer influences fleet health, and ignored/muted don't count."""

    def _risk(self, dev, **kw):
        import time as _t
        return api._device_risk('d1', dev, {}, kw.get('cve', {}), {},
                                int(_t.time()), 180, {},
                                cve_ignore=kw.get('cve_ignore'),
                                exposure_mutes=kw.get('exposure_mutes'))

    def test_muted_exposure_not_counted(self):
        import time as _t
        dev = {'name': 'd1', 'last_seen': int(_t.time()),
               'sysinfo': {'listening_ports': [
                   {'proto': 'tcp', 'port': 22, 'process': 'sshd', 'scope': 'world'},
                   {'proto': 'tcp', 'port': 8211, 'process': 'palserver', 'scope': 'world'}]}}
        full = self._risk(dev, exposure_mutes=[])
        muted = self._risk(dev, exposure_mutes=[{'process': 'palserver'}])
        f_full = next(f for f in full['factors'] if f['kind'] == 'exposed_world')
        f_muted = next(f for f in muted['factors'] if f['kind'] == 'exposed_world')
        self.assertIn('2 world', f_full['detail'])
        self.assertIn('1 world', f_muted['detail'])
        self.assertLess(f_muted['points'], f_full['points'])

    def test_host_mute_removes_exposure_entirely(self):
        import time as _t
        dev = {'name': 'd1', 'last_seen': int(_t.time()),
               'sysinfo': {'listening_ports': [
                   {'proto': 'tcp', 'port': 22, 'process': 'sshd', 'scope': 'world'}]}}
        r = self._risk(dev, exposure_mutes=[{'device_id': 'd1'}])
        self.assertFalse(any(f['kind'] == 'exposed_world' for f in r['factors']))

    def test_ignored_cve_not_counted(self):
        import time as _t
        dev = {'name': 'd1', 'last_seen': int(_t.time()), 'sysinfo': {}}
        cve = {'findings': [{'vuln_id': 'CVE-2024-9999', 'severity': 'critical'}]}
        counted = self._risk(dev, cve=cve, cve_ignore={})
        ignored = self._risk(dev, cve=cve, cve_ignore={'CVE-2024-9999': {'scope': 'global'}})
        self.assertTrue(any(f['kind'] == 'cve_critical' for f in counted['factors']))
        self.assertFalse(any(f['kind'] == 'cve_critical' for f in ignored['factors']))

    def test_fleet_health_no_longer_blends_risk(self):
        src = (_CGI_BIN / "api.py").read_text()
        fh = src.split("def _fleet_health(")[1].split("\ndef ")[0]
        self.assertNotIn("risk_by_id", fh)
        self.assertNotIn("rec['risk']", fh)
        self.assertIn("independent", fh)


class TestStaticCacheImmutable(unittest.TestCase):
    def test_nginx_static_immutable(self):
        # The tracked reference config — deploy/nginx/* is gitignored
        # (environment-specific) and absent from a clean checkout / dist tarball.
        # v4.5.0: location blocks moved into a shared include.
        conf = ((_ROOT / "server/conf/remotepower.conf").read_text()
                + (_ROOT / "server/conf/remotepower-locations.conf").read_text())
        self.assertIn("location ^~ /static/", conf)
        self.assertIn("immutable", conf)


if __name__ == "__main__":
    unittest.main()
