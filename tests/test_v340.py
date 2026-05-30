"""v3.4.0 release tests.

Strict version pins for v3.4.0. The v3.3.4 strict pins loosen to regex
when this file ships, following the same convention every prior
release-bump test followed.

v3.4.0's headline feature is "RAG over your infrastructure": a pure-stdlib
retrieval layer (rag_index.py) that indexes device state, docs, CMDB, and
history, with lexical BM25 always available and an optional embeddings
rerank when the provider supports it. The behavioural regression tests for
retrieval live in tests/test_rag.py; this file pins the version bump + that
the feature is wired and shipped end to end.
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """v3.4.0 takes the strict version pin (following prior convention)."""
    EXPECTED = '3.4.0'

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertIn(f"'remotepower-shell-v{self.EXPECTED}'", sw,
            f'sw.js CACHE_NAME must be bumped to remotepower-shell-v{self.EXPECTED}')

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn(f'?v={self.EXPECTED}', html,
            f'index.html cache-bust ?v= must be {self.EXPECTED}')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertIn(f'version-{self.EXPECTED}-blue.svg', text,
            'README.md version badge not bumped')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v<x.y.z> header')
        self.assertEqual(m.group(1), self.EXPECTED,
            f'CHANGELOG.md top entry is v{m.group(1)}, expected v{self.EXPECTED}')

    def test_release_notes_doc_present(self):
        path = REPO_ROOT / 'docs' / f'v{self.EXPECTED}.md'
        self.assertTrue(path.exists(), f'docs/v{self.EXPECTED}.md is missing')
        self.assertIn(self.EXPECTED, path.read_text())


class TestRagShipped(unittest.TestCase):
    """The RAG feature must be wired end to end, not just present in a module."""

    CGI = REPO_ROOT / 'server' / 'cgi-bin'

    def test_rag_index_module_present(self):
        mod = self.CGI / 'rag_index.py'
        self.assertTrue(mod.exists(), 'rag_index.py is missing')
        text = mod.read_text()
        for sym in ('def tokenize', 'def chunk_markdown', 'class InfraIndex',
                    'def build_live_state_corpus', 'def build_cmdb_corpus',
                    'def rrf_fuse', 'def cosine'):
            self.assertIn(sym, text, f'rag_index.py missing {sym!r}')

    def test_provider_embed_present(self):
        text = (self.CGI / 'ai_provider.py').read_text()
        self.assertIn('def embed(', text)
        self.assertIn('EMBEDDING_PROVIDERS', text)
        self.assertIn('def supports_embeddings', text)

    def test_ai_context_retrieved_block(self):
        text = (self.CGI / 'ai_context.py').read_text()
        self.assertIn('def build_retrieved_context', text)
        self.assertIn('<retrieved_context>', text)

    def test_api_endpoints_routed(self):
        text = (self.CGI / 'api.py').read_text()
        for route in ('/api/ai/rag/status', '/api/ai/rag/reindex',
                      '/api/ai/rag/search'):
            self.assertIn(route, text, f'route {route} not wired in api.py')
        for fn in ('def handle_ai_rag_status', 'def handle_ai_rag_reindex',
                   'def handle_ai_rag_search', 'def _rag_retrieve',
                   'def _rag_build_corpus'):
            self.assertIn(fn, text, f'{fn} missing from api.py')
        # chat injection: retrieved context is passed into the prompt builder
        self.assertIn('retrieved=retrieved', text)
        self.assertIn('import rag_index', text)

    def test_rag_config_defaults(self):
        text = (self.CGI / 'api.py').read_text()
        self.assertIn("'rag': {", text)
        self.assertIn("'embeddings_enabled'", text)
        self.assertIn("'include_rag'", text)

    def test_ui_controls_present(self):
        app = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        for fn in ('function aiRagReindex', 'function aiRagTestSearch',
                   'function loadRAGStatus', 'function _ragRenderSearch'):
            self.assertIn(fn, app, f'{fn} missing from app.js')
        # the results table must wire the sort control off data-col
        self.assertIn("wireSortOnly('ai-rag-results-thead'", app)
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('ai-rag-enabled', html)
        self.assertIn('aiRagReindex', html)

    def test_docs_deployed_for_rag(self):
        # both installers must place product docs where the indexer reads them
        for script in ('deploy-server.sh', 'install-server.sh'):
            text = (REPO_ROOT / script).read_text()
            self.assertIn('/docs', text)
            self.assertRegex(text, r'docs/\*\.md')

    def test_rag_reference_doc_present(self):
        path = REPO_ROOT / 'docs' / 'rag.md'
        self.assertTrue(path.exists(), 'docs/rag.md is missing')


# ─────────────────────────────────────────────────────────────────────────────
# v3.4.0 feature batch: hardware health, speedtest, network discovery, resource
# forecasting, "what changed", AI insights (anomaly / cron / runbook / doc),
# device quarantine, compliance reports, Helm status.
# ─────────────────────────────────────────────────────────────────────────────
import sys
import datetime as _dt
sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))


def forecast_day():
    import forecast
    return forecast.DAY


class TestForecast(unittest.TestCase):
    def setUp(self):
        import forecast
        self.f = forecast
        self.now = int(_dt.datetime(2026, 5, 30).timestamp())

    def _rising_samples(self, n=10, slope_gb=2.0, total=50.0, start=10.0):
        out = []
        for i in range(n):
            ts = self.now - (n - 1 - i) * forecast_day()
            out.append({'date': f'd{i}', 'ts': ts,
                        'mounts': [{'path': '/', 'used_gb': start + i * slope_gb,
                                    'total_gb': total, 'percent': 0}],
                        'state': {'pkg_upgradable': i, 'ports': ['tcp/22'],
                                  'reboot_required': False, 'failed_units': []}})
        return out

    def test_linear_fit_slope(self):
        slope, intercept = self.f.linear_fit([0, 1, 2, 3], [0, 2, 4, 6])
        self.assertAlmostEqual(slope, 2.0)
        self.assertAlmostEqual(intercept, 0.0)

    def test_linear_fit_degenerate(self):
        self.assertEqual(self.f.linear_fit([], []), (0.0, 0.0))
        self.assertEqual(self.f.linear_fit([5], [9]), (0.0, 9.0))

    def test_forecast_rising_disk(self):
        out = self.f.forecast_mounts(self._rising_samples())
        self.assertEqual(len(out), 1)
        row = out[0]
        # used reaches 28 at the last point, 22 GB headroom, 2 GB/day -> 11 days
        self.assertAlmostEqual(row['trend_gb_per_day'], 2.0, places=2)
        self.assertAlmostEqual(row['days_to_full'], 11.0, places=1)
        self.assertIsNotNone(row['fill_date_ts'])

    def test_forecast_flat_disk_never_fills(self):
        flat = self._rising_samples(slope_gb=0.0)
        out = self.f.forecast_mounts(flat)
        self.assertIsNone(out[0]['days_to_full'])

    def test_forecast_too_few_points(self):
        self.assertEqual(self.f.forecast_mounts(self._rising_samples(n=2)), [])

    def test_what_changed(self):
        wc = self.f.what_changed(self._rising_samples(), 7, self.now)
        joined = ' '.join(wc['changes'])
        self.assertIn('Pending updates', joined)
        self.assertIn('grew', joined)

    def test_what_changed_empty(self):
        wc = self.f.what_changed([], 7, self.now)
        self.assertEqual(wc['changes'], [])


class TestCronBuilder(unittest.TestCase):
    def setUp(self):
        import ai_insights
        self.ai = ai_insights

    def test_validate_ok(self):
        self.assertEqual(self.ai.validate_cron('0 6 * * 1-5'), (True, ''))
        self.assertEqual(self.ai.validate_cron('*/15 * * * *')[0], True)

    def test_validate_bad(self):
        self.assertFalse(self.ai.validate_cron('0 6 * *')[0])     # 4 fields
        self.assertFalse(self.ai.validate_cron('99 6 * * *')[0])  # out of range

    def test_next_runs_daily(self):
        runs = self.ai.next_cron_runs('30 2 * * *', 3, _dt.datetime(2026, 5, 30, 1, 0))
        self.assertEqual([r.strftime('%H:%M') for r in runs], ['02:30', '02:30', '02:30'])
        self.assertEqual(runs[0].day, 30)
        self.assertEqual(runs[1].day, 31)

    def test_next_runs_weekday_only(self):
        # Friday 2026-05-29 18:00 -> next weekday 6am is Mon 2026-06-01
        runs = self.ai.next_cron_runs('0 6 * * 1-5', 1, _dt.datetime(2026, 5, 29, 18, 0))
        self.assertEqual(runs[0].weekday(), 0)  # Monday

    def test_parse_cron_response_json(self):
        out = self.ai.parse_cron_response('{"cron":"*/15 * * * *","explanation":"x"}')
        self.assertTrue(out['valid'])
        self.assertEqual(out['cron'], '*/15 * * * *')

    def test_parse_cron_response_fenced(self):
        out = self.ai.parse_cron_response('```json\n{"cron":"0 0 * * 0"}\n```')
        self.assertTrue(out['valid'])

    def test_parse_cron_response_empty(self):
        out = self.ai.parse_cron_response('no idea')
        self.assertFalse(out['valid'])


class TestAiInsightsParsing(unittest.TestCase):
    def setUp(self):
        import ai_insights
        self.ai = ai_insights

    def test_extract_json_array(self):
        self.assertEqual(self.ai.extract_json('junk [1,2,3] tail'), [1, 2, 3])

    def test_parse_anomaly_sorts_by_severity(self):
        txt = '[{"device":"a","severity":"low","finding":"x","why":"y"},' \
              '{"device":"b","severity":"high","finding":"x","why":"y"}]'
        out = self.ai.parse_anomaly_response(txt)
        self.assertEqual(out[0]['device'], 'b')   # high first
        self.assertEqual(out[0]['severity'], 'high')

    def test_parse_anomaly_bad_input(self):
        self.assertEqual(self.ai.parse_anomaly_response('not json'), [])

    def test_prompts_are_tuples(self):
        s, m = self.ai.cron_prompt('every day')
        self.assertIsInstance(s, str)
        self.assertIsInstance(m, list)


class TestCompliance(unittest.TestCase):
    def setUp(self):
        import compliance
        self.c = compliance

    def _good_facts(self):
        return {'pending_patches_devices': [], 'cve_critical_high': 0,
                'tls_expiring': [], 'tls_monitored': 2, 'failed_backups': [],
                'backup_monitors': 1, 'mfa_enabled': True, 'audit_log_enabled': True,
                'encrypted_vault': True, 'new_ports': [], 'ssh_key_changes': [],
                'brute_force': [], 'reboot_required': []}

    def test_all_pass(self):
        rep = self.c.build_report(self._good_facts())
        self.assertEqual(rep['summary']['fail'], 0)
        self.assertEqual(rep['frameworks']['pci']['score'], 100.0)

    def test_failures_detected(self):
        facts = self._good_facts()
        facts['pending_patches_devices'] = ['web01']
        facts['mfa_enabled'] = False
        rep = self.c.build_report(facts)
        self.assertGreater(rep['summary']['fail'], 0)
        self.assertLess(rep['frameworks']['pci']['score'], 100.0)

    def test_framework_filter(self):
        rep = self.c.build_report(self._good_facts(), ['pci'])
        self.assertEqual(set(rep['frameworks'].keys()), {'pci'})

    def test_new_ports_do_not_fail_compliance(self):
        # A pile of "new since baseline" ports must NOT read as a compliance
        # failure — new != unauthorized, and the baseline flood after the
        # port-audit revival shouldn't show as 50 red fails.
        facts = self._good_facts()
        facts['new_ports'] = [f'host:{p}' for p in range(50)]
        facts['ports_monitored'] = 3
        rep = self.c.build_report(facts)
        rows = {ctl['id']: ctl['status']
                for fw in rep['frameworks'].values() for ctl in fw['controls']}
        self.assertEqual(rows['1.2.1'], 'na')     # can't assess firewall rules
        self.assertEqual(rows['CC7.1'], 'pass')   # detection is active

    def test_na_when_unmeasurable(self):
        facts = self._good_facts()
        facts['tls_monitored'] = 0
        facts['backup_monitors'] = 0
        rep = self.c.build_report(facts)
        self.assertGreater(rep['summary']['na'], 0)


class TestAgentProbes(unittest.TestCase):
    AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()

    def test_probe_functions_present(self):
        for fn in ('def get_smart_status', 'def get_kernel_status',
                   'def get_hardware_inventory', 'def run_speedtest',
                   'def run_netscan', 'def get_helm_releases'):
            self.assertIn(fn, self.AGENT, f'{fn} missing from agent')

    def test_command_verbs_wired(self):
        self.assertIn("cmd == 'speedtest'", self.AGENT)
        self.assertIn("cmd.startswith('netscan:')", self.AGENT)

    def test_speedtest_uses_librespeed(self):
        self.assertIn('librespeed-cli', self.AGENT)

    def test_payload_keys_attached(self):
        for key in ("payload['smart']", "payload['kernel']",
                    "payload['hardware']", "payload['helm']"):
            self.assertIn(key, self.AGENT)


class TestServerWiring(unittest.TestCase):
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()

    def test_ingest_functions(self):
        for fn in ('def _ingest_hardware', 'def _ingest_helm',
                   'def _ingest_speedtest', 'def _ingest_netscan',
                   'def _maybe_sample_metrics'):
            self.assertIn(fn, self.API)

    def test_handlers_present(self):
        for fn in ('def handle_device_hardware', 'def handle_device_speedtest',
                   'def handle_device_netscan', 'def handle_device_forecast',
                   'def handle_device_changes', 'def handle_device_quarantine',
                   'def handle_device_helm', 'def handle_device_runbook',
                   'def handle_device_doc_draft', 'def handle_ai_cron',
                   'def handle_ai_anomaly', 'def handle_discovery',
                   'def handle_compliance'):
            self.assertIn(fn, self.API)

    def test_routes_registered(self):
        for route in ("endswith('/hardware') and m == 'GET'",
                      "endswith('/speedtest') and m == 'POST'",
                      "endswith('/quarantine') and m == 'PATCH'",
                      "pi == '/api/ai/cron'", "pi == '/api/compliance'",
                      "pi == '/api/discovery'"):
            self.assertIn(route, self.API)

    def test_new_events_registered(self):
        self.assertIn("'smart_failure'", self.API)
        self.assertIn("'kernel_outdated'", self.API)

    def test_saved_dev_sysinfo_cached(self):
        # Regression: the post-lock port audit + metrics sampler read
        # saved_dev['sysinfo']; it must be populated inside the lock or both
        # silently no-op.
        self.assertIn("saved_dev['sysinfo'] = safe_si", self.API)

    def test_host_config_apply_gated(self):
        # host_config_desired must only be pushed when the per-device
        # apply_enabled opt-in is set — never auto-apply a drift-only baseline.
        self.assertIn("saved_dev['host_config']", self.API)
        seg = self.API[self.API.index('host_config_desired ='):
                       self.API.index('host_config_desired =') + 400]
        self.assertIn('apply_enabled', seg,
            'host_config push must be gated on apply_enabled')

    def test_diagnostic_endpoints_admin_only(self):
        # speedtest + netscan execute on the host → admin, not any viewer.
        seg = self.API[self.API.index('def handle_device_speedtest'):
                       self.API.index('def handle_discovery')]
        self.assertEqual(seg.count('require_admin_auth()'), 2,
            'speedtest and netscan must both require admin')

    def test_quarantine_enforced(self):
        # both the queue-time guard and the dispatch chokepoint must check it
        self.assertIn('def _device_quarantined', self.API)
        self.assertIn("Device is quarantined", self.API)
        self.assertIn("saved_dev.get('quarantined')", self.API)

    def test_data_files_defined(self):
        for const in ('HARDWARE_FILE', 'SPEEDTEST_FILE', 'DISCOVERY_FILE',
                      'METRICS_HIST_FILE', 'HELM_FILE'):
            self.assertIn(const + ' ', self.API)

    def test_smart_failed_helper_used_everywhere(self):
        # one definition, used by ingest + NA + the device-card badge
        self.assertIn('def _smart_disk_failed', self.API)
        # per-failed-disk-set edge trigger (re-arms / fires for already-failed)
        self.assertIn('_smart_failed_devs', self.API)
        # the old !=PASSED test (which wrongly caught UNKNOWN) must be gone
        self.assertNotIn("d.get('health') != 'PASSED'", self.API)
        app = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn('function _smartDiskFailed', app)
        self.assertNotIn("d.health !== 'PASSED'", app)

    def test_webhook_rate_limit(self):
        self.assertIn('def _webhook_rate_limit_ok', self.API)
        self.assertIn('WEBHOOK_RATE_MAX', self.API)
        # the gate is invoked in the dispatch path
        self.assertIn('if not _webhook_rate_limit_ok()', self.API)

    def test_new_port_informational_default(self):
        self.assertIn('CHANNEL_KIND_DEFAULTS', self.API)
        self.assertIn("'new_port'", self.API)
        self.assertIn('def _kind_default', self.API)

    def test_compliance_facts_use_real_event_data(self):
        # ports / ssh-key / brute-force must be derived from the fleet event
        # log, not hardcoded to [] (which would be a silent false-pass).
        facts = self.API[self.API.index('def _compliance_facts'):
                         self.API.index('def _any_user_has_totp')]
        self.assertIn('FLEET_EVENTS_FILE', facts)
        self.assertIn("new_port_detected", facts)
        self.assertIn("ssh_key_added", facts)
        self.assertIn("brute_force_detected", facts)


class TestHardwareUI(unittest.TestCase):
    APP = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()

    def test_drawer_section_registered(self):
        self.assertIn("key: 'hardware'", self.APP)
        self.assertIn("key: 'helm'", self.APP)

    def test_renderers_and_actions(self):
        for fn in ('function _renderHardwareSection', 'function deviceSpeedtest',
                   'function deviceNetscan', 'function toggleQuarantine'):
            self.assertIn(fn, self.APP, f'{fn} missing from app.js')

    def test_smart_table_sorts(self):
        # the SMART table must wire the shared sort control off data-col
        self.assertIn("wireSortOnly('hw-smart-thead'", self.APP)
        self.assertIn("wireSortOnly('helm-thead'", self.APP)

    def test_quarantine_toggle_present(self):
        self.assertIn('ds-quarantine', self.APP)
        self.assertIn("data-change=\"toggleQuarantine\"", self.APP)


class TestSshExecHardening(unittest.TestCase):
    def setUp(self):
        import ssh_exec
        self.m = ssh_exec

    def test_rejects_dash_host(self):
        with self.assertRaises(self.m.SshError):
            self.m._ssh_base_argv('-oProxyCommand=evil', 'root', 22, key_path='/tmp/k')

    def test_rejects_dash_user(self):
        with self.assertRaises(self.m.SshError):
            self.m._ssh_base_argv('nas.local', '-oProxyCommand=x', 22, key_path='/tmp/k')

    def test_normal_host_user_ok(self):
        argv = self.m._ssh_base_argv('nas.local', 'admin', 22, key_path='/tmp/k')
        self.assertEqual(argv[-1], 'admin@nas.local')


class TestProxmoxLxcWizard(unittest.TestCase):
    def setUp(self):
        import proxmox_client
        self.p = proxmox_client
        self.pc = {'enabled': True, 'host': 'h', 'node': 'pve',
                   'token_id': 't', 'token_secret': 's', 'verify_tls': False}

    def _base(self, **over):
        b = dict(vmid=200, hostname='web1',
                 ostemplate='local:vztmpl/debian-12.tar.zst', storage='local-lvm',
                 disk_gb=8, cores=2, memory_mb=1024, swap_mb=512, bridge='vmbr0',
                 ip='dhcp', password='secret', unprivileged=True, start=True)
        b.update(over); return b

    def test_client_functions_exist(self):
        for fn in ('create_lxc', 'list_storages', 'list_templates',
                   'next_vmid', 'list_bridges'):
            self.assertTrue(hasattr(self.p, fn), fn)

    def test_validation_rejects(self):
        for over, frag in [({'vmid': 5}, 'VMID'), ({'hostname': '-x'}, 'Hostname'),
                           ({'ostemplate': 'no'}, 'template'), ({'disk_gb': 0}, 'Disk'),
                           ({'ip': '9/9'}, 'IP'), ({'password': '', 'ssh_public_key': ''}, 'SSH'),
                           ({'password': 'abc'}, 'at least 5')]:
            with self.assertRaises(self.p.ProxmoxError):
                self.p.create_lxc(self.pc, self._base(**over))

    def test_validation_rejects_bad_octets(self):
        # The dotted-quad regex alone accepts nonsense like 999.x or a /33
        # prefix; the octet/prefix range-check must reject them locally so the
        # operator gets a clear error instead of an opaque Proxmox 500.
        for over in ({'ip': '999.1.1.1/24'}, {'ip': '192.168.1.50/33'},
                     {'ip': '192.168.1/24'},
                     {'ip': '192.168.1.50/24', 'gateway': '192.168.1.300'}):
            with self.assertRaises(self.p.ProxmoxError):
                self.p.create_lxc(self.pc, self._base(**over))

    def test_list_bridges_includes_ovs(self):
        self.p._request = lambda pc, path, method='GET', data=None: [
            {'iface': 'vmbr0', 'type': 'bridge'},
            {'iface': 'vmbr2', 'type': 'bridge'},
            {'iface': 'vmbr1', 'type': 'OVSBridge'},
            {'iface': 'eno1', 'type': 'eth'},
        ]
        self.assertEqual(self.p.list_bridges(self.pc), ['vmbr0', 'vmbr1', 'vmbr2'])

    def test_valid_build_payload(self):
        cap = {}
        self.p._request = lambda pc, path, method='GET', data=None: (
            cap.update(path=path, method=method, data=data) or 'UPID:x')
        r = self.p.create_lxc(self.pc, self._base(ip='192.168.1.9/24', gateway='192.168.1.1'))
        self.assertTrue(r['ok'])
        self.assertEqual(cap['method'], 'POST')
        self.assertIn('/nodes/pve/lxc', cap['path'])
        self.assertEqual(cap['data']['rootfs'], 'local-lvm:8')
        self.assertIn('gw=192.168.1.1', cap['data']['net0'])
        self.assertEqual(cap['data']['unprivileged'], 1)

    def test_server_wiring(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('def handle_proxmox_lxc_create', api)
        self.assertIn("'/api/proxmox/lxc/create-options'", api)
        self.assertIn("'/api/proxmox/lxc/create'", api)
        # create routes MUST precede the generic /lxc/ POST action route
        self.assertLess(api.index("'/api/proxmox/lxc/create'"),
                        api.index("pi.startswith('/api/proxmox/lxc/') and m == 'POST'"))
        app = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn('function openLxcCreateWizard', app)
        self.assertIn('function submitLxcCreate', app)


class TestProxmoxLxcDelete(unittest.TestCase):
    def setUp(self):
        import proxmox_client
        self.p = proxmox_client
        self.pc = {'enabled': True, 'host': 'h', 'node': 'pve',
                   'token_id': 't', 'token_secret': 's', 'verify_tls': False}

    def test_delete_stopped_goes_straight_to_delete(self):
        calls = []
        def req(pc, path, method='GET', data=None):
            calls.append((method, path))
            return {'status': 'stopped'} if path.endswith('/status/current') else 'UPID:del'
        self.p._request = req
        r = self.p.delete_lxc(self.pc, 205)
        self.assertTrue(r['ok'])
        self.assertFalse(r['stopped'])
        self.assertIn(('DELETE', '/nodes/pve/lxc/205'), calls)

    def test_delete_running_auto_stops_first(self):
        seq = {'n': 0}
        sent = []
        def req(pc, path, method='GET', data=None):
            sent.append((method, path))
            if path.endswith('/status/current'):
                seq['n'] += 1
                return {'status': 'running' if seq['n'] == 1 else 'stopped'}
            return 'UPID:x'
        self.p._request = req
        self.p.time.sleep = lambda s: None
        r = self.p.delete_lxc(self.pc, 206)
        self.assertTrue(r['stopped'])
        self.assertIn(('POST', '/nodes/pve/lxc/206/status/stop'), sent)
        self.assertIn(('DELETE', '/nodes/pve/lxc/206'), sent)

    def test_server_wiring(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('def handle_proxmox_lxc_delete', api)
        self.assertIn("pi.startswith('/api/proxmox/lxc/') and m == 'DELETE'", api)
        self.assertIn("'proxmox_lxc_delete'", api)
        app = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn('function lxcDeleteOpen', app)
        self.assertIn('function confirmLxcDelete', app)
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="lxc-delete-modal"', html)
        self.assertIn('id="lxc-del-confirm"', html)   # type-to-confirm input


class TestFleetUI(unittest.TestCase):
    APP  = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_fleet_functions_present(self):
        for fn in ('function loadCompliance', 'function loadDiscovery',
                   'function aiAnomalyScan', 'function aiCronBuild',
                   'function deviceRunbook', 'function deviceDocDraft'):
            self.assertIn(fn, self.APP, f'{fn} missing from app.js')

    def test_showpage_wires_new_pages(self):
        self.assertIn("name === 'compliance'", self.APP)
        self.assertIn('loadDiscovery()', self.APP)

    def test_compliance_page_and_nav(self):
        self.assertIn('id="page-compliance"', self.HTML)
        self.assertIn('data-page="compliance"', self.HTML)

    def test_ai_tools_and_modal(self):
        self.assertIn('id="ai-page-tools"', self.HTML)
        self.assertIn('id="ai-insight-modal"', self.HTML)
        self.assertIn('data-action="aiAnomalyScan"', self.HTML)
        self.assertIn('data-action="aiCronBuild"', self.HTML)

    def test_discovery_section_present(self):
        self.assertIn('id="discovery-body"', self.HTML)
        self.assertIn("wireSortOnly('discovery-thead'", self.APP)

    def test_ux_polish(self):
        # drawer audit sections render in labeled groups
        self.assertIn('_AUDIT_GROUP_ORDER', self.APP)
        self.assertIn('audit-group-label', self.APP)
        # compliance/anomaly use the shared sev-pill vocabulary
        self.assertIn('sev-pill', self.APP)
        # dismiss-on-visit nav "new" badge
        self.assertIn('function _markNavSeen', self.APP)
        self.assertIn('data-new="compliance"', self.HTML)


class TestCrossFeatureLinks(unittest.TestCase):
    APP = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()

    def test_link_functions_present(self):
        for fn in ('function anomalyOpenDevice', 'function anomalyRunbook',
                   'function complianceFix', 'function discoveryAddDevice'):
            self.assertIn(fn, self.APP, f'{fn} missing from app.js')

    def test_runbook_accepts_prefill(self):
        self.assertIn('function deviceRunbook(id, name, prefill)', self.APP)

    def test_agentless_open_accepts_prefill(self):
        self.assertIn('function agentlessAddOpen(prefill)', self.APP)

    def test_more_cross_links(self):
        for fn in ('function openDriftForDevice',):
            self.assertIn(fn, self.APP)
        # CVE drawer section → prefilled remediation runbook
        self.assertIn('Suggest a remediation runbook', self.APP)
        # "What changed" → drift
        self.assertIn('openDriftForDevice', self.APP)
        # NA renderer routes the hardware kind
        self.assertIn('hardware:', self.APP)

    def test_device_card_hw_badge(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("row['hw_health']", api)
        self.assertIn("'smart_failed'", api)
        self.assertIn("'kernel_reboot'", api)
        self.assertIn('hwPill', self.APP)
        self.assertIn('hw-pill', self.APP)

    def test_na_surfaces_hardware(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        # the NA cards live near the end of _compute_attention
        seg = api[api.index('def _compute_attention'):
                  api.index('def _attention_cache_file')]
        self.assertIn("'kind': 'hardware'", seg)
        self.assertIn('forecast.forecast_mounts', seg)
        self.assertIn('SMART failure on', seg)

    def test_compliance_topic_emitted(self):
        import compliance
        rep = compliance.build_report({'pending_patches_devices': ['x'],
            'cve_critical_high': 0, 'tls_expiring': [], 'tls_monitored': 1,
            'failed_backups': [], 'backup_monitors': 1, 'mfa_enabled': True,
            'audit_log_enabled': True, 'encrypted_vault': True, 'new_ports': [],
            'ssh_key_changes': [], 'brute_force': [], 'reboot_required': []}, ['pci'])
        topics = {c['topic'] for c in rep['frameworks']['pci']['controls']}
        self.assertIn('patches', topics)
        self.assertIn('cve', topics)


if __name__ == '__main__':
    unittest.main()
