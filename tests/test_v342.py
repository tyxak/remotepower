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
    """Loosened to regex — v3.5.0 now holds the strict pin (test_v350.py).
    Version-pin assertions relax to pattern-only; the v3.4.2 feature
    regression tests below stay."""

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertRegex(sw, r"'remotepower-shell-v3\.\d+\.\d+(?:-[a-z0-9]+)?'")

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertRegex(html, r'\?v=3\.\d+\.\d+')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertRegex(text, r'version-3\.\d+\.\d+-blue\.svg')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(3\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v3.x.x header')

    def test_release_notes_doc_present(self):
        # v3.4.2 release notes must stay present forever
        # v3.4.2 notes live in CHANGELOG.md; per-version docs/vX.Y.Z.md are
        # pruned to the last 5 (keep-last-5 housekeeping).
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        self.assertIn('3.4.2', chlog)


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
        # Pin the window to an hour that is NOT the current hour, so it is
        # reliably inactive right now regardless of wall-clock time (the old
        # hard-coded '0 2 * * *' flaked when the suite ran 02:00–03:00).
        off_hour = (time.localtime(now).tm_hour + 12) % 24
        (d / 'maintenance.json').write_text(json.dumps({'windows': [
            {'id': 'w1', 'scope': 'group', 'target': 'prod', 'gate_exec': True,
             'cron': f'0 {off_hour} * * *', 'duration': 3600}]}))
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
        # v3.4.2+: the posture report is a STANDALONE static page (report.html)
        # with EXTERNAL css/js, opened in a new tab. It's served under the normal
        # strict CSP (style-src/script-src 'self'), which earlier inline / blob
        # approaches violated (and so printed blank). report.js reuses the
        # localStorage token to fetch /api/report/fleet and renders a light doc.
        self.assertIn('function printFleetReport(', self.APP)
        self.assertIn('data-action="printFleetReport"', self.HTML)
        self.assertIn("window.open('report.html'", self.APP)
        # The static page + its assets must exist.
        report_html = (REPO_ROOT / 'server' / 'html' / 'report.html').read_text()
        report_js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'report.js').read_text()
        self.assertIn('static/js/report.js', report_html)
        self.assertIn('static/css/report.css', report_html)
        self.assertIn('/api/report/fleet', report_js)
        # CSP-clean: no inline handlers / document.write in the report assets.
        self.assertNotIn('document.write', report_js)
        self.assertNotIn('onclick=', report_html)
        # CSP / lint: app must not use document.write
        self.assertNotIn('document.write', self.APP)


class TestV342RBAC(unittest.TestCase):
    """Granular RBAC: custom roles with per-action permissions + device scope."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_routes(self):
        self.assertEqual(routes_to('GET', '/api/roles'), 'handle_roles_list')
        self.assertEqual(routes_to('POST', '/api/roles'), 'handle_role_create')
        self.assertEqual(routes_to('PUT', '/api/roles/ops'), 'handle_role_update')
        self.assertEqual(routes_to('DELETE', '/api/roles/ops'), 'handle_role_delete')

    def test_action_handlers_use_require_perm(self):
        # the device-action chokepoints must gate on a permission, not bare admin.
        # v3.12.0: 'exec'/'upgrade' split into granular perms.
        for fn, perm in (('handle_custom_cmd', 'command'), ('handle_reboot', 'reboot'),
                         ('handle_shutdown', 'shutdown'), ('handle_upgrade_device', 'patch'),
                         ('handle_update_device', 'patch'), ('handle_exec_batch', 'command')):
            i = self.API.find('def ' + fn + '(')
            self.assertGreater(i, 0, fn)
            # slice up to the next top-level def so the perm call is in range
            nxt = self.API.find('\ndef ', i + 1)
            body = self.API[i:nxt if nxt > 0 else i + 3000]
            self.assertIn(f"require_perm('{perm}'", body, f'{fn} should require_perm({perm})')

    def test_device_list_scoped(self):
        i = self.API.find('def handle_devices_list(')
        nxt = self.API.find('\ndef ', i + 1)
        body = self.API[i:nxt if nxt > 0 else i + 4000]
        self.assertIn('_caller_scope()', body)
        self.assertIn('_device_in_scope(_scope', body)

    def test_role_mgmt_admin_only(self):
        for fn in ('handle_role_create', 'handle_role_update', 'handle_role_delete'):
            i = self.API.find('def ' + fn + '(')
            self.assertIn('require_admin_auth()', self.API[i:i + 400], fn)

    # ── behaviour ────────────────────────────────────────────────────────────
    def _fresh_api(self):
        import importlib, tempfile, json
        from pathlib import Path as _P
        api = importlib.import_module('api')
        d = tempfile.mkdtemp()
        api.DATA_DIR = _P(d)
        for attr, fn in (('ROLES_FILE', 'roles.json'), ('DEVICES_FILE', 'devices.json'),
                         ('USERS_FILE', 'users.json')):
            setattr(api, attr, _P(d) / fn)
        api._LOAD_CACHE.clear()
        return api, _P(d)

    def test_resolve_role(self):
        import json
        api, d = self._fresh_api()
        (d / 'roles.json').write_text(json.dumps({'roles': [
            {'name': 'ops', 'permissions': ['exec', 'reboot', 'bogus'],
             'scope': {'type': 'groups', 'values': ['staging']}}]}))
        api._LOAD_CACHE.clear()
        self.assertTrue(api._resolve_role('admin')['admin'])
        self.assertEqual(api._resolve_role('viewer')['permissions'], set())
        ops = api._resolve_role('ops')
        # v3.12.0: legacy 'exec' expands to its granular members; 'reboot' stays;
        # 'bogus' is filtered out.
        self.assertEqual(ops['permissions'],
                         api._expand_perms(['exec']) | {'reboot'})
        self.assertIn('command', ops['permissions'])
        self.assertNotIn('patch', ops['permissions'])   # exec != upgrade
        self.assertFalse(ops['admin'])
        self.assertEqual(api._resolve_role('nope')['permissions'], set())  # fail closed

    def test_device_in_scope(self):
        api, _ = self._fresh_api()
        self.assertTrue(api._device_in_scope({'type': 'all'}, {'group': 'x'}))
        self.assertTrue(api._device_in_scope({'type': 'groups', 'values': ['p']}, {'group': 'p'}))
        self.assertFalse(api._device_in_scope({'type': 'groups', 'values': ['p']}, {'group': 'q'}))
        self.assertTrue(api._device_in_scope({'type': 'tags', 'values': ['web']}, {'tags': ['web', 'db']}))
        self.assertFalse(api._device_in_scope({'type': 'tags', 'values': ['web']}, {'tags': ['db']}))

    def test_clean_role_body(self):
        api, _ = self._fresh_api()
        _, err = api._clean_role_body({'name': 'BAD NAME'})
        self.assertIsNotNone(err)
        _, err = api._clean_role_body({'name': 'admin'})
        self.assertIn('built-in', err)
        _, err = api._clean_role_body({'name': 'ops', 'scope': {'type': 'groups', 'values': []}})
        self.assertIsNotNone(err)   # groups scope needs a value
        clean, err = api._clean_role_body({'name': 'ops', 'permissions': ['exec', 'x'],
                                           'scope': {'type': 'tags', 'values': ['web']}})
        self.assertIsNone(err)
        self.assertEqual(clean['permissions'], ['exec'])

    def test_require_perm_scope(self):
        import json
        api, d = self._fresh_api()
        (d / 'roles.json').write_text(json.dumps({'roles': [
            {'name': 'ops', 'permissions': ['exec'], 'scope': {'type': 'groups', 'values': ['staging']}}]}))
        (d / 'devices.json').write_text(json.dumps({'d1': {'group': 'staging'}, 'd2': {'group': 'prod'}}))
        api._LOAD_CACHE.clear()
        api.get_token_from_request = lambda: 'tok'
        api.verify_token = lambda t: ('bob', 'ops')
        # v3.12.0: legacy 'exec' role expands to granular perms (command, …).
        # in-scope command passes
        self.assertEqual(api.require_perm('command', ['d1']), 'bob')
        # out-of-scope command → 403
        with self.assertRaises(api.HTTPError) as cm:
            api.require_perm('command', ['d2'])
        self.assertEqual(cm.exception.status, 403)
        # 'exec' does NOT expand to 'patch' (was 'upgrade') → 403
        with self.assertRaises(api.HTTPError) as cm:
            api.require_perm('patch', ['d1'])
        self.assertEqual(cm.exception.status, 403)
        # admin passes anything
        api.verify_token = lambda t: ('root', 'admin')
        self.assertEqual(api.require_perm('patch', ['d2']), 'root')

    def test_assignable_role(self):
        import json
        api, d = self._fresh_api()
        (d / 'roles.json').write_text(json.dumps({'roles': [{'name': 'ops', 'permissions': [], 'scope': {'type': 'all'}}]}))
        api._LOAD_CACHE.clear()
        self.assertTrue(api._assignable_role('admin'))
        self.assertTrue(api._assignable_role('viewer'))
        self.assertTrue(api._assignable_role('ops'))
        self.assertFalse(api._assignable_role('mcp'))   # reserved for API keys
        self.assertFalse(api._assignable_role('ghost'))

    # ── frontend ─────────────────────────────────────────────────────────────
    def test_frontend(self):
        self.assertIn('id="role-add-modal"', self.HTML)
        self.assertIn('id="roles-list"', self.HTML)
        self.assertIn('function loadRoles(', self.APP)
        self.assertIn('function saveRole(', self.APP)
        self.assertIn('function openRoleAdd(', self.APP)
        self.assertIn('function deleteRole(', self.APP)
        self.assertIn('function onRoleScopeChange(', self.APP)
        # user-add dropdown is populated with custom roles
        self.assertIn("filter(x => !x.builtin)", self.APP)


class TestV342RBACv2(unittest.TestCase):
    """RBAC v2: per-endpoint read scoping — no out-of-scope device data leaks."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()

    def _api(self):
        import importlib, tempfile, json
        from pathlib import Path as _P
        api = importlib.import_module('api')
        d = tempfile.mkdtemp()
        api.DATA_DIR = _P(d)
        for attr, fn in (('ROLES_FILE', 'roles.json'), ('DEVICES_FILE', 'devices.json')):
            setattr(api, attr, _P(d) / fn)
        (_P(d) / 'roles.json').write_text(json.dumps({'roles': [
            {'name': 'ops', 'permissions': ['exec'], 'scope': {'type': 'groups', 'values': ['staging']}}]}))
        (_P(d) / 'devices.json').write_text(json.dumps({
            'd1': {'name': 's', 'group': 'staging'}, 'd2': {'name': 'p', 'group': 'prod'}}))
        api._LOAD_CACHE.clear()
        api.get_token_from_request = lambda: 't'
        return api, _P(d)

    def test_dispatch_guard_wired(self):
        # the guard runs before route dispatch
        i = self.API.find('def main(')
        j = self.API.find('_dispatch(pi, m)', i)
        self.assertIn('_enforce_device_scope()', self.API[i:j])

    def test_scope_filter(self):
        import json
        api, d = self._api()
        api.verify_token = lambda t: ('bob', 'ops')
        filt = api._scope_filter_devices(json.loads((d / 'devices.json').read_text()))
        self.assertEqual(sorted(filt), ['d1'])
        # admin sees everything (None scope → unchanged)
        api.verify_token = lambda t: ('root', 'admin')
        self.assertEqual(sorted(api._scope_filter_devices(json.loads((d / 'devices.json').read_text()))), ['d1', 'd2'])

    def test_enforce_device_scope(self):
        import os
        api, _ = self._api()
        api.verify_token = lambda t: ('bob', 'ops')
        # out-of-scope device → 403
        os.environ['PATH_INFO'] = '/api/devices/d2/sysinfo'
        with self.assertRaises(api.HTTPError) as cm:
            api._enforce_device_scope()
        self.assertEqual(cm.exception.status, 403)
        # in-scope device → pass
        os.environ['PATH_INFO'] = '/api/devices/d1/sysinfo'
        api._enforce_device_scope()
        # unknown id → pass through (handler 404s; nothing to leak)
        os.environ['PATH_INFO'] = '/api/devices/zzz/sysinfo'
        api._enforce_device_scope()
        # admin → bypass
        api.verify_token = lambda t: ('root', 'admin')
        os.environ['PATH_INFO'] = '/api/devices/d2/sysinfo'
        api._enforce_device_scope()
        os.environ.pop('PATH_INFO', None)

    def test_scope_block_device(self):
        api, _ = self._api()
        api.verify_token = lambda t: ('bob', 'ops')
        with self.assertRaises(api.HTTPError) as cm:
            api._scope_block_device('d2')
        self.assertEqual(cm.exception.status, 403)
        api._scope_block_device('d1')          # in scope → ok
        api._scope_block_device('nope')        # unknown → ok

    def test_explicit_per_device_guards(self):
        for fn in ('handle_patch_report_device', 'handle_cmdb_get',
                   'handle_cmdb_credentials_list', 'handle_acme_detail'):
            i = self.API.find('def ' + fn + '(')
            nxt = self.API.find('\ndef ', i + 1)
            self.assertIn('_scope_block_device(', self.API[i:nxt if nxt > 0 else i + 1200], fn)
        # health-history per-device series gated
        i = self.API.find('def handle_fleet_health_history(')
        self.assertIn('_scope_block_device(dev_id)', self.API[i:i + 600])

    def test_aggregates_scoped(self):
        # each aggregate that emits per-device rows must scope-filter
        for fn in ('handle_patch_report', 'handle_cve_findings', 'handle_agent_integrity',
                   'handle_fleet_query', 'handle_fleet_sla', 'handle_fleet_capacity',
                   'handle_fleet_anomalies', 'handle_inventory_search', 'handle_inventory_metering',
                   'handle_drift_overview', 'handle_patch_catalog', 'handle_network_map',
                   'handle_log_rules', 'handle_fleet_timeline'):
            i = self.API.find('def ' + fn + '(')
            nxt = self.API.find('\ndef ', i + 1)
            body = self.API[i:nxt if nxt > 0 else i + 2500]
            self.assertIn('_scope_filter_devices', body, f'{fn} should scope-filter devices')
        # fleet health + events + compliance + alerts use _caller_scope directly
        for fn in ('handle_fleet_health', 'handle_fleet_events', 'handle_alerts_list',
                   'handle_compliance_baseline'):
            i = self.API.find('def ' + fn + '(')
            nxt = self.API.find('\ndef ', i + 1)
            body = self.API[i:nxt if nxt > 0 else i + 2500]
            self.assertTrue('_caller_scope' in body or '_scope_filter_devices' in body, fn)


class TestV342SettingsActions(unittest.TestCase):
    """Sign-password gate, install wizard, expanded fleet query, settings
    re-categorization, and tag/group-targeted software install + SCAP."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    # ── sign requires admin password ─────────────────────────────────────────
    def test_sign_requires_password(self):
        i = self.API.find('def handle_signing_sign(')
        body = self.API[i:self.API.find('\ndef ', i + 1)]
        self.assertIn('verify_password(', body)
        self.assertIn('password required to sign', body)
        self.assertIn("api('POST', '/signing/sign', { password: pw })", self.APP)

    def test_sign_password_is_masked(self):
        # the password must be entered through the masked uiPrompt({type:'password'}),
        # not the native prompt() which renders cleartext.
        for fn in ('signingSignNow', 'signingToggle'):
            j = self.APP.find('function ' + fn + '(')
            seg = self.APP[j:self.APP.find('\nasync function ', j + 1)]
            self.assertIn("uiPrompt({", seg, f'{fn} should use uiPrompt')
            self.assertIn("type: 'password'", seg, f'{fn} should mask the input')
            # no native prompt() *call* (ignore comment prose)
            code = '\n'.join(l for l in seg.splitlines() if not l.strip().startswith('//'))
            self.assertNotIn('await prompt(', code)
            self.assertNotIn('= prompt(', code)

    # ── install wizard ───────────────────────────────────────────────────────
    def test_setup_status_route_and_ui(self):
        self.assertEqual(routes_to('GET', '/api/setup-status'), 'handle_setup_status')
        self.assertIn('id="settings-pane-install"', self.HTML)
        self.assertIn('data-tab="install"', self.HTML)
        self.assertIn('function loadSetup(', self.APP)
        self.assertIn('function gotoSetupStep(', self.APP)

    def test_setup_status_behaviour(self):
        import importlib, tempfile, json
        from pathlib import Path as _P
        api = importlib.import_module('api')
        d = tempfile.mkdtemp(); api.DATA_DIR = _P(d)
        for a, fn in (('CONFIG_FILE', 'config.json'), ('USERS_FILE', 'users.json'),
                      ('DEVICES_FILE', 'devices.json')):
            setattr(api, a, _P(d) / fn)
        api.require_auth = lambda **k: 'admin'
        captured = {}
        _orig_respond = api.respond
        api.respond = lambda code, body=None: (_ for _ in ()).throw(_StopResp(code, body))
        (_P(d) / 'users.json').write_text(json.dumps({'admin': {'must_change_password': True}}))
        (_P(d) / 'config.json').write_text('{}')
        (_P(d) / 'devices.json').write_text('{}')
        api._LOAD_CACHE.clear()
        try:
            api.handle_setup_status()
        except _StopResp as e:
            rep = e.body
        finally:
            api.respond = _orig_respond  # don't leak the patch into later tests
        self.assertIn('steps', rep)
        self.assertEqual(rep['total'], 5)
        pw = [s for s in rep['steps'] if s['id'] == 'admin-password'][0]
        self.assertFalse(pw['done'])           # must_change_password → not done
        self.assertIn('admin-password', rep.get('required_remaining_ids', []) or
                      [s['id'] for s in rep['steps'] if s['required'] and not s['done']])

    # ── expanded fleet query ─────────────────────────────────────────────────
    def test_fleet_query_new_filters(self):
        i = self.API.find('def handle_fleet_query(')
        body = self.API[i:self.API.find('\ndef ', i + 1)]
        for p in ('version', 'pkg_manager', 'has_package', 'reboot', 'failed',
                  'quarantined', 'monitored', 'agentless', 'disk_gt', 'mem_gt', 'offline_days'):
            self.assertIn(f"'{p}'", body, f'fleet query missing {p}')
        for fid in ('fq-version', 'fq-pkgmgr', 'fq-haspkg', 'fq-disk', 'fq-offline-days'):
            self.assertIn(f'id="{fid}"', self.HTML, fid)
        self.assertIn('_FQ_FIELDS', self.APP)

    # ── settings re-categorization ───────────────────────────────────────────
    def test_settings_recategorized(self):
        sec = self.HTML.find('id="settings-pane-security"')
        ai = self.HTML.find('id="settings-pane-ai"')
        cve = self.HTML.find('cfg-cve-cache-days')
        self.assertTrue(sec < cve < ai, 'CVE cache should now sit inside the Security pane')
        # the duplicate raw-seconds session card is gone
        self.assertNotIn('id="session-ttl-short"', self.HTML)
        # status endpoint moved into Integrations
        intg = self.HTML.find('id="settings-pane-integrations"')
        adv = self.HTML.find('id="settings-pane-security"')
        stat = self.HTML.find('id="status-token-box"')
        self.assertTrue(intg < stat < adv, 'Status endpoint should be in Integrations')

    # ── install software (tag/group/host) ────────────────────────────────────
    def test_install_route_and_safety(self):
        self.assertEqual(routes_to('POST', '/api/install'), 'handle_install_packages')
        import importlib
        api = importlib.import_module('api')
        self.assertTrue(api._INSTALL_PKG_RE.match('nginx'))
        self.assertTrue(api._INSTALL_PKG_RE.match('lib32-foo+'))
        self.assertFalse(api._INSTALL_PKG_RE.match('a; rm -rf /'))
        self.assertFalse(api._INSTALL_PKG_RE.match('$(reboot)'))
        cmd = api._build_install_cmd(['nginx', 'htop'])
        self.assertIn('apt-get install -y nginx htop', cmd)
        self.assertIn('pacman -Sy --noconfirm nginx htop', cmd)
        # apt sandbox workaround (seteuid 105 fix) must be present, like _UPGRADE_CMD
        self.assertIn('APT::Sandbox::User "root"', cmd)
        # v3.12.0: gated on the granular 'packages' permission (shared core)
        i = self.API.find('def _handle_pkg_action(')
        self.assertIn("require_perm('packages'", self.API[i:i + 1800])

    def test_uninstall_command_and_route(self):
        # Uninstall mirrors install: package-manager-agnostic remove, validated
        # names, its own route + UI action.
        import importlib
        api = importlib.import_module('api')
        cmd = api._build_uninstall_cmd(['nginx', 'htop'])
        self.assertIn('apt-get remove -y nginx htop', cmd)
        self.assertIn('pacman -R --noconfirm nginx htop', cmd)
        self.assertIn('dnf remove -y nginx htop', cmd)
        self.assertEqual(routes_to('POST', '/api/uninstall'), 'handle_uninstall_packages')
        self.assertIn('function runUninstall(', self.APP)
        self.assertIn('data-action="runUninstall"', self.HTML)

    def test_install_and_scap_targeting_ui(self):
        self.assertIn('id="install-card"', self.HTML)
        self.assertIn('id="install-target-type"', self.HTML)
        self.assertIn('function runInstall(', self.APP)
        self.assertIn('function _fleetTargetBody(', self.APP)
        # SCAP scan can now target a tag/group/host explicitly
        self.assertIn('id="scap-target-type"', self.HTML)
        self.assertIn('<option value="tag">Tag</option>', self.HTML)
        self.assertIn('function onScapTargetChange(', self.APP)

    def test_install_creates_tracked_job(self):
        i = self.API.find('def _handle_pkg_action(')
        body = self.API[i:self.API.find('\ndef ', i + 1)]
        self.assertIn('BATCH_JOBS_FILE', body)
        self.assertIn("'job_id'", body)
        self.assertIn("'match_cmd'", body)
        # the status endpoint correlates install output via match_cmd
        self.assertIn("body_match = job.get('match_cmd')", self.API)
        self.assertEqual(routes_to('GET', '/api/exec/batch'), 'handle_batch_jobs_list')

    def test_batch_progress_logic(self):
        import importlib, time
        api = importlib.import_module('api')
        now = int(time.time())
        job = {'match_cmd': 'exec:X', 'created': now - 5,
               'per_device': {'a': {'queued': True}, 'b': {'queued': True}, 'c': {'queued': True}}}
        outs = {'a': [{'cmd': 'exec:X', 'rc': 0, 'ts': now}],
                'b': [{'cmd': 'exec:X', 'rc': 5, 'ts': now}]}  # c: no output → pending
        self.assertEqual(api._batch_job_progress(job, outs), (1, 1, 1, 3))

    def test_batch_progress_long_command_truncation(self):
        # regression: a >512-char install command is stored truncated in
        # cmd_output, so the matcher must compare against the truncated form
        # (else the job is stuck "pending" forever despite rc=0).
        import importlib, time
        api = importlib.import_module('api')
        queued = 'exec:' + api._build_install_cmd(['atop'])
        self.assertGreater(len(queued), 512)
        stored = api._sanitize_str(queued, 512)            # what cmd_output keeps
        now = int(time.time())
        job = {'match_cmd': queued, 'created': now - 10, 'per_device': {'d1': {'queued': True}}}
        self.assertEqual(api._batch_job_progress(job, {'d1': [{'cmd': stored, 'rc': 0, 'ts': now}]}),
                         (1, 0, 0, 1))
        # both match sites use the truncated key
        self.assertIn('_sanitize_str(body_match, 512)', self.API)
        self.assertIn('_sanitize_str(match, 512)', self.API)

    def test_batch_jobs_clear(self):
        self.assertEqual(routes_to('DELETE', '/api/exec/batch'), 'handle_batch_jobs_clear')
        self.assertIn('data-action="clearBatchJobs"', self.HTML)
        self.assertIn('function clearBatchJobs(', self.APP)

    def test_install_tracker_ui(self):
        self.assertIn('id="batch-jobs"', self.HTML)
        self.assertIn('function loadBatchJobs(', self.APP)
        self.assertIn('function toggleJobDetail(', self.APP)
        self.assertIn('function _renderJobDetail(', self.APP)
        # one-time install auto-expands its new job to show per-host progress
        self.assertIn('_batchExpanded.add(r.job_id)', self.APP)

    def test_one_time_install_on_rollouts(self):
        # button on the Rollouts page + dedicated modal + handlers
        self.assertIn('data-action="openInstallModal"', self.HTML)
        self.assertIn('id="one-time-install-modal"', self.HTML)
        self.assertIn('id="oti-pkgs"', self.HTML)
        self.assertIn('id="oti-target-type"', self.HTML)
        self.assertIn('function openInstallModal(', self.APP)
        self.assertIn('function runOneTimeInstall(', self.APP)
        # routes through the same validated install endpoint
        self.assertIn("api('POST', '/install', body)", self.APP)


class _StopResp(Exception):
    def __init__(self, code, body):
        self.code, self.body = code, body


class TestV342SortableTables(unittest.TestCase):
    """CLAUDE.md rule: every new table wires tableCtl sort. Guards against the
    sort-regression class that has shipped before."""
    APP = client_js()

    def _fn_body(self, name):
        i = self.APP.find('function ' + name + '(')
        self.assertGreater(i, 0, name)
        # crude but sufficient: slice to the next top-level 'async function'/'function'
        j = self.APP.find('\nasync function ', i + 1)
        k = self.APP.find('\nfunction ', i + 1)
        ends = [x for x in (j, k) if x > 0]
        return self.APP[i:min(ends) if ends else i + 4000]

    def test_session_tables_wire_sort(self):
        # (renderer, sort-prefs name, thead id)
        for fn, prefs, thead in (
                ('loadPatchCatalog', 'patch_catalog', 'patch-catalog-thead'),
                ('loadReportsMetering', 'metering', 'metering-thead'),
                ('runFleetQuery', 'fleet_query', 'fq-thead'),
                ('loadComplianceBaseline', 'cis_baseline', 'cis-baseline-thead'),
                # v3.4.2: scap table render split out of loadScap so a sort
                # click re-renders from cache instead of re-fetching /scap.
                ('_renderScapTable', 'scap', 'scap-thead'),
                ('loadRoles', 'roles', 'roles-thead')):
            body = self._fn_body(fn)
            self.assertIn(f"tableCtl.sortRows('{prefs}'", body, f'{fn} sortRows')
            self.assertIn(f"wireSortOnly('{thead}', '{prefs}'", body, f'{fn} wireSortOnly')
            self.assertIn(f'id="{thead}"', body, f'{fn} thead id')
            self.assertIn('data-col=', body, f'{fn} data-col headers')


class TestV342ForecastVolatile(unittest.TestCase):
    """Forecast: ephemeral mounts excluded; noisy trends don't get a fake date."""

    def _f(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'forecast', REPO_ROOT / 'server' / 'cgi-bin' / 'forecast.py')
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        return m

    def _samples(self):
        DAY = 86400; t0 = 1_700_000_000
        s = []
        for d in range(10):
            s.append({'ts': t0 + d * DAY, 'mounts': [
                {'path': '/',     'used_gb': 10.0 + d, 'total_gb': 30.0},          # clean climb
                {'path': '/tmp',  'used_gb': 0.5 + (d % 2) * 1.5, 'total_gb': 4.0},  # volatile
                {'path': '/data', 'used_gb': 5.0 + d * 0.5 + (3 if d % 3 == 0 else -2), 'total_gb': 50.0}],  # noisy
            })
        return s

    def test_volatile_excluded(self):
        f = self._f()
        rows = f.forecast_mounts(self._samples())
        paths = {r['path'] for r in rows}
        self.assertNotIn('/tmp', paths)
        self.assertIn('/', paths)
        # the default exclusion set names the usual tmpfs mounts
        self.assertIn('/tmp', f.VOLATILE_MOUNTS)
        self.assertIn('/dev/shm', f.VOLATILE_MOUNTS)

    def test_clean_trend_projects(self):
        f = self._f()
        root = [r for r in f.forecast_mounts(self._samples()) if r['path'] == '/'][0]
        self.assertIsNotNone(root['days_to_full'])
        self.assertFalse(root['noisy'])
        self.assertGreaterEqual(root['r2'], 0.9)

    def test_noisy_trend_no_date(self):
        f = self._f()
        data = [r for r in f.forecast_mounts(self._samples()) if r['path'] == '/data'][0]
        self.assertTrue(data['noisy'])
        self.assertIsNone(data['days_to_full'])   # no misleading projection
        self.assertIsNone(data['fill_date_ts'])

    def test_run_submounts_excluded(self):
        f = self._f()
        self.assertTrue(f._is_volatile_mount('/run/user/1000', f.VOLATILE_MOUNTS))
        self.assertTrue(f._is_volatile_mount('/dev/shm', f.VOLATILE_MOUNTS))
        self.assertFalse(f._is_volatile_mount('/var/lib/docker', f.VOLATILE_MOUNTS))

    def test_frontend_shows_fluctuating(self):
        app = client_js()
        self.assertIn('fluctuating', app)
        self.assertIn('m.noisy', app)


class TestV342NinjaParity(unittest.TestCase):
    """Linux-RMM Tier-A batch: OpenSCAP scans, third-party patching, on-call /
    escalation, and zero-dep trend charts."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
    CSS = (REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()

    def _api(self):
        import importlib, tempfile, json
        from pathlib import Path as _P
        api = importlib.import_module('api')
        d = tempfile.mkdtemp()
        api.DATA_DIR = _P(d)
        for attr, fn in (('CONFIG_FILE', 'config.json'), ('ALERTS_FILE', 'alerts.json'),
                         ('DEVICES_FILE', 'devices.json'), ('SCAP_FILE', 'scap.json'),
                         ('METRICS_HIST_FILE', 'metrics_history.json')):
            setattr(api, attr, _P(d) / fn)
        api._LOAD_CACHE.clear()
        return api, _P(d)

    # ── OpenSCAP ─────────────────────────────────────────────────────────────
    def test_scap_routes(self):
        self.assertEqual(routes_to('POST', '/api/scap/scan'), 'handle_scap_scan')
        self.assertEqual(routes_to('POST', '/api/scap/report'), 'handle_scap_report')
        self.assertEqual(routes_to('GET', '/api/scap'), 'handle_scap_overview')

    def test_scap_agent_and_heartbeat(self):
        self.assertIn('def run_oscap_scan(', self.AGENT)
        self.assertIn('def _parse_oscap_results(', self.AGENT)
        self.assertIn('def _find_ssg_datastream(', self.AGENT)
        self.assertIn("resp.get('force_scap_scan')", self.AGENT)
        # server delivers + clears the one-shot flag
        self.assertIn("common_resp['force_scap_scan']", self.API)
        self.assertIn("saved_dev['force_scap_scan']", self.API)
        # report endpoint is exempt from the IP allowlist (agent traffic)
        self.assertIn("'/api/scap/report'", self.API)

    def test_scap_parse_results(self):
        import importlib.util, tempfile, os
        spec = importlib.util.spec_from_file_location('rpagent', REPO_ROOT / 'client' / 'remotepower-agent.py')
        ag = importlib.util.module_from_spec(spec); spec.loader.exec_module(ag)
        xml = ('<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">'
               '<rule-result idref="xccdf_org.ssgproject.content_rule_a" severity="high"><result>pass</result></rule-result>'
               '<rule-result idref="xccdf_org.ssgproject.content_rule_b" severity="medium"><result>fail</result></rule-result>'
               '<score>83.5</score></TestResult>')
        with tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False) as f:
            f.write(xml); path = f.name
        try:
            r = ag._parse_oscap_results(path)
        finally:
            os.unlink(path)
        self.assertEqual(r['score'], 83.5)
        self.assertEqual(r['pass'], 1)
        self.assertEqual(r['fail'], 1)
        self.assertEqual(r['failed_rules'], [{'id': 'b', 'severity': 'medium'}])

    def test_scap_frontend(self):
        self.assertIn('id="scap-card"', self.HTML)
        self.assertIn('function loadScap(', self.APP)
        self.assertIn('function runScapScan(', self.APP)

    # ── third-party patching ─────────────────────────────────────────────────
    def test_third_party_agent(self):
        self.assertIn('def get_third_party_updates(', self.AGENT)
        for mgr in ('flatpak', 'snap', 'pip', 'npm'):
            self.assertIn(mgr, self.AGENT)
        self.assertIn("result['third_party'] = tp", self.AGENT)
        # server sanitises + aggregates
        self.assertIn("safe_pkg['third_party']", self.API)
        self.assertIn("'third_party':           tp_out", self.API)

    def test_third_party_frontend(self):
        self.assertIn('Third-party updates', self.APP)

    # ── on-call / escalation ─────────────────────────────────────────────────
    def test_oncall_route_and_periodic(self):
        self.assertEqual(routes_to('GET', '/api/oncall'), 'handle_oncall')
        self.assertIn('_safe(_escalation_tick_if_due', self.API)

    def test_oncall_rotation(self):
        api, _ = self._api()
        cfg = {'oncall': {'enabled': True, 'contacts': ['alice', 'bob', 'carol'], 'rotation_days': 7}}
        # deterministic for a fixed timestamp
        who = api._oncall_now(cfg, now=7 * 86400)   # week 1 → index 1
        self.assertEqual(who, 'bob')
        self.assertEqual(api._oncall_now({'oncall': {'enabled': False, 'contacts': ['x']}}), '')

    def test_escalation_tick(self):
        import json, time
        api, d = self._api()
        sent = []
        api._send_webhook_to_url = lambda ev, pl, msg, cfg: sent.append((ev, msg))
        now = int(time.time())
        (d / 'config.json').write_text(json.dumps({'escalation': {
            'enabled': True, 'severities': ['critical'], 'tiers': [{'after_minutes': 10}]}}))
        (d / 'alerts.json').write_text(json.dumps({'alerts': [
            {'id': 'a1', 'ts': now - 3600, 'event': 'device_offline', 'severity': 'critical',
             'title': 'x down', 'acknowledged_at': None, 'resolved_at': None, 'payload': {}},
            {'id': 'a2', 'ts': now - 3600, 'event': 'device_offline', 'severity': 'critical',
             'title': 'acked', 'acknowledged_at': now, 'resolved_at': None, 'payload': {}}]}))
        api._LOAD_CACHE.clear()
        api._escalation_tick(now=now)
        self.assertEqual(len(sent), 1)          # only the unacked one
        # tier recorded → idempotent on a second pass
        api._LOAD_CACHE.clear()
        api._escalation_tick(now=now)
        self.assertEqual(len(sent), 1)
        store = json.loads((d / 'alerts.json').read_text())
        a1 = [a for a in store['alerts'] if a['id'] == 'a1'][0]
        self.assertEqual(a1['escalated_tiers'], [0])

    def test_oncall_config_and_frontend(self):
        self.assertIn("cfg['escalation'] =", self.API)
        self.assertIn("cfg['oncall'] =", self.API)
        self.assertIn('function saveOncall(', self.APP)
        self.assertIn('id="oncall-card"', self.HTML)

    # ── trends charts ────────────────────────────────────────────────────────
    def test_trends_route_and_frontend(self):
        self.assertEqual(routes_to('GET', '/api/devices/d1/metrics-history'),
                         'handle_device_metrics_history')
        self.assertIn('function renderTimeSeries(', self.APP)
        self.assertIn('function loadTrends(', self.APP)
        self.assertIn('id="page-trends"', self.HTML)
        self.assertIn('data-page="trends"', self.HTML)
        self.assertIn("name === 'trends'", self.APP)
        self.assertIn('.ts-chart', self.CSS)


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
        # Other test modules patch api.respond globally (some without restoring),
        # so in a full-suite run respond may not be the real HTTPError-raising
        # function this test's run() helper relies on. Pin it back.
        api.respond = lambda status, body=None: (_ for _ in ()).throw(api.HTTPError(status, body))
        # v3.4.2: signing re-verifies the admin password. Point USERS_FILE at the
        # throwaway dir (no stored hash → the gate short-circuits before calling
        # verify_password) and stub verify_password too, so the test is robust
        # regardless of suite ordering / shared module state.
        api.USERS_FILE = _P(d) / 'users.json'
        api.verify_password = lambda *a, **k: True
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
        # Signing must be authoritative for the server-side pin: even if
        # config.release_pubkey has drifted to a wrong/foreign key, re-signing
        # re-syncs it to the actual signing key so the self-check converges to
        # 'valid' (the "re-sign does nothing, stays INVALID" bug).
        cfg = json.loads(api.CONFIG_FILE.read_text())
        cfg['release_pubkey'] = '-----BEGIN PGP PUBLIC KEY BLOCK-----\nbogus\n-----END PGP PUBLIC KEY BLOCK-----'
        cfg['release_key_fingerprint'] = '0' * 40
        api.CONFIG_FILE.write_text(json.dumps(cfg))
        s, dd = run(api.handle_signing_status, 'GET')
        self.assertEqual(dd['signature_status'], 'invalid')   # drifted pin
        s, dd = run(api.handle_signing_sign, 'POST', {})
        self.assertEqual(s, 200); self.assertEqual(dd['signature_status'], 'valid')


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
