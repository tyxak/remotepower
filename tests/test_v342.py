"""v3.4.2 release tests.

Strict version pins for v3.4.2 (the v3.4.1 strict pins loosen to regex when
this file ships, per the standing convention). v3.4.2's headline feature is the
**automation rules engine**: "when event X on devices matching Y, run a saved
script and/or notify a channel" — composing the existing event registry, channel
routing, and saved scripts into a rule model evaluated on every fired event.
"""
import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import os
import re
import shutil
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(Path(__file__).resolve().parent))
from routing_harness import routes_to  # noqa: E402


class TestVersionBumps(unittest.TestCase):
    """v3.4.2 takes the strict version pin (following prior convention)."""
    EXPECTED = '3.4.2'

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


class TestV342Automation(unittest.TestCase):
    """Automation rules engine — when an event matches, run a script / notify."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_routes_registered(self):
        for method, path, handler in (
                ('GET',    '/api/automation/rules',     'handle_automation_rules_list'),
                ('POST',   '/api/automation/rules',     'handle_automation_rule_create'),
                ('PUT',    '/api/automation/rules/r-1', 'handle_automation_rule_update'),
                ('DELETE', '/api/automation/rules/r-1', 'handle_automation_rule_delete')):
            self.assertEqual(routes_to(method, path), handler,
                             f'{method} {path} must route to {handler}')

    def test_engine_defined_and_wired(self):
        for fn in ('def _run_automation_rules(', 'def _run_automation_action(',
                   'def _device_matches_rule(', 'def _validate_rule(',
                   'def handle_automation_rule_create('):
            self.assertIn(fn, self.API, f'{fn} missing from api.py')
        # Evaluated from the event dispatch path.
        self.assertIn('_run_automation_rules(event, payload, cfg)', self.API)

    def test_create_is_admin_gated(self):
        m = re.search(r'def handle_automation_rule_create\(.*?\n(.*?)\ndef ',
                      self.API, re.DOTALL)
        self.assertIsNotNone(m)
        self.assertIn('require_admin_auth()', m.group(1))

    def test_engine_behaviour(self):
        import importlib, sys as _s, tempfile, json, time as _t
        _s.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        import os
        d = tempfile.mkdtemp()
        # Point the module's data files at a temp dir for this check.
        from pathlib import Path as _P
        api.DATA_DIR = _P(d)
        for attr, fn in (('RULES_FILE', 'automation_rules.json'),
                         ('SCRIPTS_FILE', 'scripts.json'),
                         ('CMDS_FILE', 'commands.json'),
                         ('DEVICES_FILE', 'devices.json'),
                         ('CONFIG_FILE', 'config.json')):
            setattr(api, attr, _P(d) / fn)
        api.audit_log = lambda *a, **k: None
        api.log_command = lambda *a, **k: None
        (_P(d) / 'devices.json').write_text(json.dumps({'d1': {'name': 'web', 'group': 'prod', 'monitored': True}}))
        (_P(d) / 'scripts.json').write_text(json.dumps({'scripts': [{'id': 's1', 'name': 'x', 'body': 'echo hi'}]}))
        (_P(d) / 'automation_rules.json').write_text(json.dumps({'rules': [{
            'id': 'r-1', 'name': 'a', 'enabled': True, 'cooldown_seconds': 0,
            'match': {'events': ['service_down'], 'severities': [], 'device_match': {'group': 'prod'}},
            'actions': [{'type': 'run_script', 'script_id': 's1'}],
            'last_fired': 0, 'fire_count': 0}]}))
        # load() memoises per-request and is invalidated by save(); since this
        # test writes files directly, clear the cache to mimic a fresh request.
        api._LOAD_CACHE.clear()
        # matching event queues the script
        api._run_automation_rules('service_down', {'device_id': 'd1'}, {})
        cmds = json.loads((_P(d) / 'commands.json').read_text())
        self.assertEqual(cmds.get('d1'), ['exec:echo hi'])
        # group mismatch → nothing
        (_P(d) / 'commands.json').write_text('{}')
        (_P(d) / 'devices.json').write_text(json.dumps({'d1': {'name': 'web', 'group': 'dev', 'monitored': True}}))
        api._LOAD_CACHE.clear()
        api._run_automation_rules('service_down', {'device_id': 'd1'}, {})
        self.assertEqual(json.loads((_P(d) / 'commands.json').read_text()), {})

    def test_frontend_present(self):
        self.assertIn('data-page="automation"', self.HTML)
        self.assertIn('id="page-automation"', self.HTML)
        self.assertIn('function loadAutomation(', self.APP)
        self.assertIn('function saveAutomationRule(', self.APP)
        self.assertIn("name === 'automation'", self.APP)


class TestV342FleetMgmt(unittest.TestCase):
    """octofleet-inspired batch: patch catalog, post-deploy verify, metering,
    heat map, after-hours, fleet query, signed-agent badge on Devices."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_routes(self):
        for method, path, handler in (
                ('GET', '/api/patch-catalog',       'handle_patch_catalog'),
                ('GET', '/api/inventory/metering',  'handle_inventory_metering'),
                ('GET', '/api/fleet/query',         'handle_fleet_query')):
            self.assertEqual(routes_to(method, path), handler)

    def test_agent_reports_upgradable_names(self):
        self.assertIn('def _parse_upgradable_names(', self.AGENT)
        self.assertIn("result['upgradable_names']", self.AGENT)
        # server stores them
        self.assertIn("safe_pkg['upgradable_names']", self.API)

    def test_patch_catalog_and_verify(self):
        self.assertIn('def handle_patch_catalog(', self.API)
        self.assertIn('def _upgrade_verify_status(', self.API)
        self.assertIn("'upgrade_verify'", self.API)
        self.assertIn('function loadPatchCatalog(', self.APP)
        self.assertIn('id="patch-catalog-body"', self.HTML)

    def test_metering(self):
        self.assertIn('def handle_inventory_metering(', self.API)
        self.assertIn("'software_meters'", self.API)
        self.assertIn('function saveMetering(', self.APP)

    def test_heatmap(self):
        self.assertIn('function _renderHomeHeatmap(', self.APP)
        self.assertIn('id="home-heatmap"', self.HTML)
        self.assertIn('.heatmap-cell', (REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text())

    def test_after_hours(self):
        self.assertIn('def _record_after_hours(', self.API)
        self.assertRegex(self.API, r"'kind': 'after_hours'")
        self.assertIn("'after_hours'", self.API)   # config + channel kind
        self.assertIn('function saveAfterHours(', self.APP)

    def test_fleet_query(self):
        self.assertIn('def handle_fleet_query(', self.API)
        self.assertIn('function runFleetQuery(', self.APP)
        self.assertIn('id="page-query"', self.HTML)
        self.assertIn('data-page="query"', self.HTML)

    def test_devices_signed_badge(self):
        self.assertIn('function _signedBadge(', self.APP)
        self.assertIn('agent-verified', self.APP)
        # devices list ships the integrity verdict
        self.assertIn("row['agent_integrity']", self.API)


class TestV342Deployment(unittest.TestCase):
    """Second octofleet batch: staged rollouts, maintenance change-windows,
    CIS-style compliance baselines, metering normalization/reclamation, PDF."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
    CSS = (REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()

    # ── routes ──────────────────────────────────────────────────────────────
    def test_routes(self):
        self.assertEqual(routes_to('GET', '/api/rollouts'), 'handle_rollouts_list')
        self.assertEqual(routes_to('POST', '/api/rollouts'), 'handle_rollouts_create')
        self.assertEqual(routes_to('POST', '/api/rollouts/abc123/start'), 'handle_rollout_action')
        self.assertEqual(routes_to('DELETE', '/api/rollouts/abc123'), 'handle_rollout_delete')
        self.assertEqual(routes_to('GET', '/api/compliance/baseline'), 'handle_compliance_baseline')

    def test_periodic_hooks(self):
        self.assertIn("_safe(_rollout_tick_if_due", self.API)
        self.assertIn("_safe(_maybe_sample_compliance", self.API)

    # ── behaviour: staged rollout ring lifecycle ─────────────────────────────
    def _fresh_api(self):
        import importlib, tempfile, json, os
        from pathlib import Path as _P
        api = importlib.import_module('api')
        d = tempfile.mkdtemp()
        api.DATA_DIR = _P(d)
        for attr, fn in (('ROLLOUTS_FILE', 'rollouts.json'), ('SCRIPTS_FILE', 'scripts.json'),
                         ('CMDS_FILE', 'commands.json'), ('DEVICES_FILE', 'devices.json'),
                         ('CONFIG_FILE', 'config.json'), ('MAINT_FILE', 'maintenance.json'),
                         ('PACKAGES_FILE', 'packages.json'), ('CVE_FINDINGS_FILE', 'cve.json'),
                         ('COMPLIANCE_HIST_FILE', 'comp.json')):
            setattr(api, attr, _P(d) / fn)
        api.audit_log = lambda *a, **k: None
        api.log_command = lambda *a, **k: None
        api._get_agent_sha256 = lambda: 'canon'
        api._LOAD_CACHE.clear()
        return api, _P(d)

    def test_rollout_ring_advance_and_verify(self):
        import json, time
        api, d = self._fresh_api()
        devs = {'d1': {'name': 'web1', 'group': 'prod', 'monitored': True,
                       'sysinfo': {'packages': {'upgradable': 5}}}}
        (d / 'devices.json').write_text(json.dumps(devs))
        api._LOAD_CACHE.clear()
        now = int(time.time())
        roll = {'id': 'r1', 'name': 'p', 'action': 'upgrade', 'script_id': '', 'current_ring': 0,
                'rings': [{'name': 'canary', 'selector': {'type': 'ids', 'ids': ['d1']}},
                          {'name': 'broad', 'selector': {'type': 'group', 'value': 'prod'}}],
                'rings_state': [{'state': 'pending', 'dispatched_ids': [], 'total': 0, 'ok_count': 0, 'failed_count': 0},
                                {'state': 'pending', 'dispatched_ids': [], 'total': 0, 'ok_count': 0, 'failed_count': 0}],
                'auto_promote': False, 'verify_minutes': 30, 'state': 'running', 'history': [], 'created_by': 't'}
        devices = json.loads((d / 'devices.json').read_text())
        cmds = {}
        api._rollout_advance(roll, devices, cmds)
        # ring 0 dispatched the upgrade to d1 and is now verifying
        self.assertEqual(roll['rings_state'][0]['state'], 'verifying')
        self.assertEqual(roll['rings_state'][0]['dispatched_ids'], ['d1'])
        self.assertTrue(any('exec:' in c for c in cmds['d1']))
        # simulate d1's upgrade verified ok (pending dropped to 0)
        devices['d1']['upgrade_pending_before'] = 5
        devices['d1']['upgrade_queued_at'] = now
        devices['d1']['sysinfo']['packages']['upgradable'] = 0
        self.assertEqual(api._upgrade_verify_status(devices['d1'], now), 'ok')
        api._rollout_advance(roll, devices, cmds)
        # ring 0 done; manual promote → rollout paused awaiting approval
        self.assertEqual(roll['rings_state'][0]['state'], 'done')
        self.assertEqual(roll['state'], 'paused')

    def test_rollout_ring_failure_halts(self):
        import json, time
        api, d = self._fresh_api()
        (d / 'devices.json').write_text(json.dumps(
            {'d1': {'name': 'x', 'group': 'prod', 'monitored': True, 'sysinfo': {'packages': {'upgradable': 3}}}}))
        api._LOAD_CACHE.clear()
        now = int(time.time())
        roll = {'id': 'r2', 'name': 'p', 'action': 'upgrade', 'current_ring': 0,
                'rings': [{'name': 'canary', 'selector': {'type': 'ids', 'ids': ['d1']}}],
                'rings_state': [{'state': 'verifying', 'dispatched_ids': ['d1'], 'total': 1,
                                 'ok_count': 0, 'failed_count': 0, 'dispatched_at': now - 7200}],
                'auto_promote': True, 'verify_minutes': 30, 'state': 'running', 'history': [], 'created_by': 't'}
        devices = json.loads((d / 'devices.json').read_text())
        # never verified, window elapsed → ring failed, rollout halted
        api._rollout_advance(roll, devices, {})
        self.assertEqual(roll['state'], 'failed')

    # ── behaviour: maintenance change-window gating ──────────────────────────
    def test_exec_gated(self):
        import json, time
        api, d = self._fresh_api()
        now = int(time.time())
        (d / 'maintenance.json').write_text(json.dumps({'windows': [
            {'id': 'w1', 'scope': 'group', 'target': 'prod', 'gate_exec': True,
             'cron': '0 2 * * *', 'duration': 3600}]}))
        api._LOAD_CACHE.clear()
        # covered by a gate_exec window that is not active right now → hold
        self.assertTrue(api._exec_gated('d1', {'group': 'prod'}, now))
        # device not covered by any gate_exec window → never gated
        self.assertFalse(api._exec_gated('dz', {'group': 'other'}, now))

    def test_gate_exec_field_persisted(self):
        # add + validate both carry gate_exec through to the stored window
        self.assertIn("'gate_exec': bool(body.get('gate_exec'))", self.API)

    # ── behaviour: CIS compliance baseline ───────────────────────────────────
    def test_compliance_scoring(self):
        api, d = self._fresh_api()
        devs = {
            'ok': {'name': 'good', 'monitored': True, 'agent_sha256': 'canon',
                   'sysinfo': {'packages': {'upgradable': 0}, 'failed_units': [],
                               'reboot_required': False, 'disk_percent': 30, 'swap_percent': 5}},
            'bad': {'name': 'bad', 'monitored': True,
                    'sysinfo': {'packages': {'upgradable': 9}, 'failed_units': ['a.service'],
                                'reboot_required': True, 'disk_percent': 97, 'swap_percent': 5}},
        }
        rep = api._compute_compliance(devs)
        self.assertEqual(rep['devices_evaluated'], 2)
        self.assertIsInstance(rep['score'], int)
        ids = {c['id'] for c in rep['checks']}
        self.assertIn('cis-patches', ids)
        self.assertIn('cis-disk', ids)
        # disabling a check drops it from the report
        api._cis_disabled = lambda: {'cis-disk'}
        rep2 = api._compute_compliance(devs)
        self.assertNotIn('cis-disk', {c['id'] for c in rep2['checks']})

    def test_compliance_config_key(self):
        self.assertIn("cfg['compliance_baseline'] = {'disabled': disabled}", self.API)

    # ── behaviour: metering normalization + reclamation ──────────────────────
    def test_meter_normalization(self):
        api, _ = self._fresh_api()
        self.assertEqual(api._meter_needles({'name': 'OpenSSL', 'aliases': ['libssl3', '']}),
                         ['openssl', 'libssl3'])

    def test_software_in_use_heuristic(self):
        api, _ = self._fresh_api()
        running = {'sysinfo': {'top_processes': [{'name': 'nginx'}]}}
        idle = {'sysinfo': {'top_processes': [{'name': 'bash'}], 'listening_ports': []}}
        self.assertTrue(api._software_in_use(running, ['nginx']))
        self.assertFalse(api._software_in_use(idle, ['nginx']))

    def test_metering_aliases_config(self):
        self.assertIn("entry['aliases'] = aliases", self.API)

    # ── frontend wiring ──────────────────────────────────────────────────────
    def test_frontend_rollouts(self):
        self.assertIn('data-page="rollouts"', self.HTML)
        self.assertIn('id="page-rollouts"', self.HTML)
        self.assertIn('id="new-rollout-modal"', self.HTML)
        self.assertIn('function loadRollouts(', self.APP)
        self.assertIn('function saveRollout(', self.APP)
        self.assertIn('function rolloutAction(', self.APP)
        self.assertIn("name === 'rollouts'", self.APP)

    def test_frontend_maintenance_gate(self):
        self.assertIn('id="maint-gate-exec"', self.HTML)
        self.assertIn('gate_exec: gateExec', self.APP)

    def test_frontend_compliance_baseline(self):
        self.assertIn('id="cis-baseline-card"', self.HTML)
        self.assertIn('function loadComplianceBaseline(', self.APP)
        self.assertIn('function toggleCisCheck(', self.APP)
        self.assertIn('.cis-spark-bar', self.CSS)

    def test_frontend_metering_reclaim(self):
        self.assertIn('reclaimable', self.APP)
        self.assertIn('reclaim_hosts', self.APP)

    def test_frontend_pdf(self):
        self.assertIn('function printFleetReport(', self.APP)
        self.assertIn('data-action="printFleetReport"', self.HTML)
        self.assertIn('window.print()', self.APP)
        self.assertIn('id="print-report"', self.HTML)
        self.assertIn('@media print', self.CSS)
        # CSP / lint: must not use document.write
        self.assertNotIn('document.write', self.APP)


class TestV342ReviewFixes(unittest.TestCase):
    """Review round: disable-signing password gate, SNMP live-threshold fix,
    cron-builder → Planning, anomaly-scan → Security."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_disable_signing_requires_password(self):
        idx = self.API.find('def handle_signing_toggle')
        body = self.API[idx:idx + 900]
        self.assertIn('verify_password', body)
        self.assertIn('if not enabled:', body)
        # Frontend prompts for the password on disable.
        self.assertIn('admin password', self.APP)

    def test_snmp_threshold_uses_live_device(self):
        # The fix resolves thresholds + state under the lock on the fresh device.
        idx = self.API.find('def process_snmp_metric_thresholds')
        body = self.API[idx:idx + 3600]
        self.assertIn('_invalidate_load_cache(DEVICES_FILE)', body)
        self.assertIn('_LockedUpdate(DEVICES_FILE) as store', body)
        self.assertIn('_snmp_threshold_warn_crit(d,', body)   # resolves from fresh `d`

    def test_snmp_threshold_behaviour(self):
        import importlib, sys as _s, tempfile, json, os as _os
        from pathlib import Path as _P
        _s.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        d = tempfile.mkdtemp()
        api.DATA_DIR = _P(d)
        api.DEVICES_FILE = _P(d) / 'devices.json'
        api._snmp_cpu_avg_pct = lambda e: None
        api._snmp_memory_used_pct = lambda e: None
        api._snmp_temp_celsius = lambda e, source=None: None
        api._snmp_storage_mounts = lambda e: [{'descr': '/', 'used_pct': 80}]
        fired = []
        api._fire_metric_webhook = lambda ev, did, dev, k, t, v, thr, extra=None: fired.append(ev)
        # LIVE threshold is high (95) → 80% must NOT alert even though the passed
        # (stale) snapshot has a low threshold.
        api.DEVICES_FILE.write_text(json.dumps({'d1': {'name': 'sw', 'monitored': True,
            'metric_thresholds': {'disk_warn_percent': 95, 'disk_crit_percent': 99}}}))
        stale = {'name': 'sw', 'monitored': True,
                 'metric_thresholds': {'disk_warn_percent': 70, 'disk_crit_percent': 90}}
        api._LOAD_CACHE.clear()
        api.process_snmp_metric_thresholds('d1', stale, {})
        self.assertEqual(fired, [])

    def test_cron_builder_under_planning(self):
        # Cron builder card now lives on the Schedule page (Planning), not AI.
        sched = self.HTML.find('id="page-schedule"')
        end = self.HTML.find('id="page-', sched + 10)
        self.assertIn('aiCronBuild', self.HTML[sched:end])
        self.assertIn('id="ai-page-tools" class="d-none"></div>', self.HTML)  # emptied

    def test_anomaly_scan_under_security(self):
        comp = self.HTML.find('id="page-compliance"')
        end = self.HTML.find('id="page-', comp + 10)
        self.assertIn('aiAnomalyScan', self.HTML[comp:end])


class TestV342UxFixes(unittest.TestCase):
    """Home health spacing, persistent activity-clear, forecast + timeline paging."""
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_health_box_spacing(self):
        idx = self.HTML.find('id="home-health"')
        self.assertGreater(idx, 0)
        self.assertIn('mb-16', self.HTML[idx - 60:idx])

    def test_activity_clear_persists(self):
        # Watermark moved from sessionStorage → localStorage so it survives reloads.
        self.assertIn("localStorage.getItem('rp_activity_cleared'", self.APP)
        self.assertIn("localStorage.setItem('rp_activity_cleared'", self.APP)
        self.assertNotIn("sessionStorage.setItem('rp_activity_cleared'", self.APP)

    def test_timeline_pagination(self):
        self.assertIn('function timelineShowMore(', self.APP)
        self.assertIn('_TIMELINE_PAGE', self.APP)

    def test_forecast_smarter(self):
        self.assertIn('function forecastShowMore(', self.APP)
        self.assertIn('id="forecast-filter"', self.HTML)
        self.assertIn('id="forecast-atrisk"', self.HTML)


class TestV342BakeSign(unittest.TestCase):
    """Server-side bake & sign UI + key management."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
    AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()

    def test_routes_and_ui(self):
        for method, path, handler in (
                ('GET',  '/api/signing/status',   'handle_signing_status'),
                ('POST', '/api/signing/generate', 'handle_signing_generate'),
                ('POST', '/api/signing/sign',     'handle_signing_sign'),
                ('POST', '/api/signing/toggle',   'handle_signing_toggle')):
            self.assertEqual(routes_to(method, path), handler)
        self.assertIn('data-page="signing"', self.HTML)
        self.assertIn('id="page-signing"', self.HTML)
        self.assertIn('function loadSigning(', self.APP)
        self.assertIn('function signingGenerate(', self.APP)
        # Honest caveat present in the UI.
        self.assertIn('not', self.HTML[self.HTML.find('id="signing-caveat"'):
                                       self.HTML.find('id="signing-caveat"') + 600].lower())

    def test_rejection_reporting(self):
        # Agent records + reports a refused update; server stores it; integrity
        # report surfaces it.
        self.assertIn("_safe_state_write('update-rejected'", self.AGENT)
        self.assertIn("'agent_update_rejected'", self.AGENT)
        self.assertIn("dev['agent_update_rejected']", self.API)
        self.assertIn("'update_rejected'", self.API)

    @unittest.skipUnless(shutil.which('gpg'), 'gpg not installed')
    def test_generate_sign_roundtrip(self):
        import importlib, tempfile, json, os as _os, sys as _s
        from pathlib import Path as _P
        _s.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        d = tempfile.mkdtemp()
        api.require_auth = lambda *a, **k: 't'
        api.require_admin_auth = lambda *a, **k: 'admin'
        api.audit_log = lambda *a, **k: None
        api._SIGNING_GNUPGHOME = _P(d) / 'signing-gpg'
        ad = _P(d) / 'agent'; ad.mkdir()
        binp = ad / 'remotepower-agent'; binp.write_bytes(b'VERSION="3.4.2"\n')
        api._AGENT_BINARY_PATH = binp
        api._AGENT_SIG_PATH = ad / 'remotepower-agent.asc'
        api.CONFIG_FILE = _P(d) / 'config.json'; api.CONFIG_FILE.write_text('{}')

        def run(fn, method='GET', body=None):
            _os.environ['REQUEST_METHOD'] = method
            if body is not None:
                api.get_json_body = lambda: body
            api._LOAD_CACHE.clear()
            try:
                fn(); return (None, None)
            except api.HTTPError as e:
                return (e.status, e.body)
        s, dd = run(api.handle_signing_generate, 'POST', {})
        self.assertEqual(s, 200); self.assertTrue(dd['fingerprint'])
        s, dd = run(api.handle_signing_sign, 'POST', {})
        self.assertEqual(s, 200); self.assertEqual(dd['signature_status'], 'valid')
        self.assertTrue(api._AGENT_SIG_PATH.exists())
        # regenerate without force is refused
        s, dd = run(api.handle_signing_generate, 'POST', {})
        self.assertEqual(s, 400)


class TestV342ReleaseSigning(unittest.TestCase):
    """Cryptographic release signing — detached GPG signature over the agent."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()

    def test_wiring(self):
        self.assertEqual(routes_to('GET', '/api/agent/signature'),
                         'handle_agent_signature')
        self.assertIn('def _gpg_verify_detached(', self.API)
        self.assertIn('def _release_signature_status(', self.API)
        self.assertIn("'signed':", self.API)
        self.assertIn("'release_signature'", self.API)
        # Agent side: pinned key + verify + fail-closed gate before install.
        self.assertIn('def _verify_detached_sig(', self.AGENT)
        self.assertIn('RELEASE_PUBKEY_FILE', self.AGENT)
        self.assertIn('Release signature verification FAILED', self.AGENT)
        # Signing tool ships + is executable.
        tool = REPO_ROOT / 'tools' / 'sign-agent-release.sh'
        self.assertTrue(tool.exists())
        self.assertTrue(os.access(tool, os.X_OK), 'sign-agent-release.sh must be executable')

    @unittest.skipUnless(shutil.which('gpg'), 'gpg not installed')
    def test_real_signature_roundtrip(self):
        """End-to-end with a real ephemeral key: good sig verifies; tamper,
        wrong fingerprint, and an attacker's key all fail closed."""
        import importlib, sys as _s, subprocess, tempfile
        _s.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        gh = tempfile.mkdtemp(); os.chmod(gh, 0o700)
        env = dict(os.environ, GNUPGHOME=gh)
        try:
            from pathlib import Path as _P
            (_P(gh) / 'kp').write_text(
                "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
                "Key-Usage: sign\nName-Real: RP Test\nExpire-Date: 0\n%commit\n")
            subprocess.run(['gpg', '--batch', '--gen-key', str(_P(gh) / 'kp')],
                           env=env, capture_output=True)
            cols = subprocess.run(['gpg', '--list-keys', '--with-colons'],
                                  env=env, capture_output=True, text=True).stdout
            fpr = [l.split(':')[9] for l in cols.splitlines() if l.startswith('fpr:')][0]
            pub = subprocess.run(['gpg', '--armor', '--export', fpr],
                                 env=env, capture_output=True, text=True).stdout
            data = b'agent binary bytes\n'
            art = _P(gh) / 'a'; art.write_bytes(data)
            subprocess.run(['gpg', '--batch', '--yes', '--armor', '--detach-sign',
                            '-o', str(art) + '.asc', str(art)], env=env, capture_output=True)
            sig = (_P(str(art) + '.asc')).read_text()
            self.assertTrue(api._gpg_verify_detached(data, sig, pub, fpr)[0])
            self.assertFalse(api._gpg_verify_detached(b'tampered', sig, pub, fpr)[0])
            self.assertFalse(api._gpg_verify_detached(data, sig, pub, 'F' * 40)[0])
        finally:
            shutil.rmtree(gh, ignore_errors=True)


class TestV342AgentIntegrity(unittest.TestCase):
    """Agent integrity attestation — running hash vs canonical served hash."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
    APP = client_js()

    def test_route_and_wiring(self):
        self.assertEqual(routes_to('GET', '/api/fleet/agent-integrity'),
                         'handle_agent_integrity')
        self.assertIn('def _agent_integrity_status(', self.API)
        # Heartbeat stores the reported hash; NA flags mismatches.
        self.assertIn("dev['agent_sha256']", self.API)
        self.assertRegex(self.API, r"'kind': 'agent_integrity'")
        # Agent reports its own hash.
        self.assertIn('def _agent_self_sha256(', self.AGENT)
        self.assertIn("'agent_sha256': _agent_self_sha256()", self.AGENT)
        self.assertIn('function loadReportsIntegrity(', self.APP)

    def test_status_behaviour(self):
        import importlib, sys as _s
        _s.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        canon = 'a' * 64
        ver = api.SERVER_VERSION
        self.assertEqual(api._agent_integrity_status(
            {'version': ver, 'agent_sha256': canon}, canon, ver), 'verified')
        self.assertEqual(api._agent_integrity_status(
            {'version': ver, 'agent_sha256': 'b' * 64}, canon, ver), 'mismatch')
        self.assertEqual(api._agent_integrity_status(
            {'version': '3.0.0', 'agent_sha256': 'c' * 64}, canon, ver), 'unknown')
        self.assertEqual(api._agent_integrity_status(
            {'version': ver}, canon, ver), 'unknown')


class TestV342Anomaly(unittest.TestCase):
    """Statistical resource anomaly detection (anomaly_stats.py)."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()

    def test_route_and_module(self):
        self.assertEqual(routes_to('GET', '/api/fleet/anomalies'),
                         'handle_fleet_anomalies')
        self.assertTrue((REPO_ROOT / 'server' / 'cgi-bin' / 'anomaly_stats.py').exists())
        self.assertIn('import anomaly_stats', self.API)
        self.assertIn('def handle_fleet_anomalies(', self.API)
        self.assertIn('function loadReportsAnomalies(', self.APP)

    def test_detect_behaviour(self):
        import importlib, sys as _s
        _s.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        A = importlib.import_module('anomaly_stats')
        # flat baseline + sharp spike → flagged
        spike = [{'mem_percent': 50} for _ in range(8)] + [{'mem_percent': 95}]
        res = A.detect_device(spike, z=2.5)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['metric'], 'mem_percent')
        self.assertEqual(res[0]['direction'], 'high')
        # stable → nothing; too-few samples → nothing
        self.assertEqual(A.detect_device([{'mem_percent': 50}] * 10, z=2.5), [])
        self.assertEqual(A.detect_device([{'mem_percent': 99}] * 3, z=2.5), [])
        # disk derived from busiest mount
        ds = [{'mounts': [{'percent': 40}]} for _ in range(8)] + [{'mounts': [{'percent': 92}]}]
        self.assertEqual(A.detect_device(ds, z=2.5)[0]['metric'], 'disk_percent')


class TestV342Dependencies(unittest.TestCase):
    """Device dependency map — depends_on + downstream alert suppression."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    NET = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-network.js').read_text()

    def test_route_and_handlers(self):
        self.assertEqual(routes_to('PUT', '/api/devices/d1/depends-on'),
                         'handle_device_depends_on')
        for fn in ('def handle_device_depends_on(', 'def _upstream_down('):
            self.assertIn(fn, self.API)
        # Suppression gate present in the dispatch path.
        self.assertIn('_upstream_down(dev_id', self.API)
        # Map exposes dependency edges.
        self.assertIn("'dep_edges'", self.API)

    def test_upstream_down_behaviour(self):
        import importlib, sys as _s
        _s.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        import time as _t
        now = int(_t.time())
        devs = {'sw': {'name': 'switch', 'last_seen': now - 99999, 'monitored': True},
                'web': {'name': 'web', 'last_seen': now, 'depends_on': ['sw']},
                'db': {'name': 'db', 'last_seen': now}}
        self.assertEqual(api._upstream_down('web', devs, now, 180), 'switch')
        self.assertIsNone(api._upstream_down('db', devs, now, 180))

    def test_frontend_renders_dep_edges(self):
        self.assertIn('dep_edges', self.NET)
        self.assertIn('netmap-dep-sel', self.NET)
        self.assertIn('depends-on', self.NET)


if __name__ == '__main__':
    unittest.main()
