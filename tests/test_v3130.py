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
    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, VERSION)

    def test_agent_version(self):
        txt = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertIn(f"VERSION      = '{VERSION}'", txt)

    def test_agent_extensionless_matches_py(self):
        a = (_ROOT / "client/remotepower-agent.py").read_bytes()
        b = (_ROOT / "client/remotepower-agent").read_bytes()
        self.assertEqual(a, b, "agent .py and extensionless copy diverged "
                               "(run cp client/remotepower-agent.py client/remotepower-agent)")

    def test_sw_cache_name(self):
        txt = (_ROOT / "server/html/sw.js").read_text()
        self.assertIn(f"remotepower-shell-v{VERSION}", txt)

    def test_index_cache_bust(self):
        txt = (_ROOT / "server/html/index.html").read_text()
        self.assertIn(f"?v={VERSION}", txt)
        self.assertNotIn("?v=3.12.0", txt)

    def test_readme_badge(self):
        txt = (_ROOT / "README.md").read_text()
        self.assertIn(f"version-{VERSION}-blue", txt)

    def test_changelog_top_entry(self):
        txt = (_ROOT / "CHANGELOG.md").read_text()
        self.assertIn(f"v{VERSION}", txt[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{VERSION}.md").exists())

    def test_whats_new_card_present(self):
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertIn(f"What's new — v{VERSION}", html)


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
        # Both the risk endpoint and fleet health route through the cache.
        self.assertIn("risks = _fleet_risk_cached()", src)
        self.assertIn("_fleet_risk_cached(use_cache=use_cache)", src)


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


class TestStaticCacheImmutable(unittest.TestCase):
    def test_nginx_static_immutable(self):
        # The tracked reference config — deploy/nginx/* is gitignored
        # (environment-specific) and absent from a clean checkout / dist tarball.
        conf = (_ROOT / "server/conf/remotepower.conf").read_text()
        self.assertIn("location ^~ /static/", conf)
        self.assertIn("immutable", conf)


if __name__ == "__main__":
    unittest.main()
