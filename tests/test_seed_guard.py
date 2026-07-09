#!/usr/bin/env python3
"""Regression tests for the seed-demo-data.py production-safety guard.

A miss here once clobbered a live /var/lib/remotepower with fake data. The
guard (_guard_demo_target) must refuse to --apply into anything that looks
like production. These tests load the script as a module and exercise the
guard directly.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).parent.parent / "packaging" / "seed-demo-data.py"


def _load():
    spec = importlib.util.spec_from_file_location("seed_demo_data", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # safe: main() is gated by __name__ guard
    return mod


class TestSeedGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load()

    def _tmp(self):
        return Path(tempfile.mkdtemp(prefix="rp_seedguard_"))

    def test_default_dir_is_demo_not_production(self):
        self.assertEqual(str(self.m.DEFAULT_DATA_DIR), "/var/lib/remotepower-demo")
        self.assertIn("/var/lib/remotepower", self.m.PROTECTED_DATA_DIRS)

    def test_empty_dir_is_allowed(self):
        d = self._tmp()
        (d / "x").rmdir() if (d / "x").exists() else None
        ok, _ = self.m._guard_demo_target(d)
        self.assertTrue(ok)

    def test_production_path_blocked(self):
        ok, reason = self.m._guard_demo_target(Path("/var/lib/remotepower"))
        self.assertFalse(ok)
        self.assertIn("production", reason.lower())

    def test_real_accounts_blocked_even_with_override_and_marker(self):
        d = self._tmp()
        (d / self.m.DEMO_MARKER).write_text("x")          # even if mismarked
        (d / "users.json").write_text(json.dumps({"jmo": {"role": "admin"}}))
        ok, reason = self.m._guard_demo_target(d, override=True)   # even with override
        self.assertFalse(ok)
        self.assertIn("non-demo", reason.lower())

    def test_default_admin_does_not_block_demo_seed(self):
        # The app auto-creates a never-used `admin` (must_change_password) on a
        # fresh demo instance; that must NOT block seeding (it used to).
        d = self._tmp()
        (d / self.m.DEMO_MARKER).write_text("x")
        (d / "users.json").write_text(json.dumps(
            {"admin": {"role": "admin", "must_change_password": True,
                       "password_hash": "x"}}))
        ok, _ = self.m._guard_demo_target(d)
        self.assertTrue(ok)
        # …but a real admin (password changed → no flag) still blocks.
        (d / "users.json").write_text(json.dumps(
            {"admin": {"role": "admin", "password_hash": "x"}}))
        ok2, reason2 = self.m._guard_demo_target(d)
        self.assertFalse(ok2)
        self.assertIn("non-demo", reason2.lower())

    def test_demo_accounts_only_not_treated_as_real(self):
        d = self._tmp()
        (d / "users.json").write_text(json.dumps({"demo": {}, "alice": {}, "bob": {}}))
        # demo accounts alone shouldn't trip the real-account check; but the dir
        # is non-empty without a marker, so it's still blocked by rule 3 …
        ok, reason = self.m._guard_demo_target(d)
        self.assertFalse(ok)
        self.assertIn(self.m.DEMO_MARKER, reason)
        # … and allowed once the marker is present.
        (d / self.m.DEMO_MARKER).write_text("x")
        ok2, _ = self.m._guard_demo_target(d)
        self.assertTrue(ok2)

    def test_nonempty_unmarked_dir_blocked(self):
        d = self._tmp()
        (d / "devices.json").write_text("{}")
        ok, reason = self.m._guard_demo_target(d)
        self.assertFalse(ok)
        self.assertIn(self.m.DEMO_MARKER, reason)

    def test_unreadable_users_json_blocked(self):
        d = self._tmp()
        (d / "users.json").write_text("{not valid json")
        ok, _ = self.m._guard_demo_target(d, override=True)
        self.assertFalse(ok)


class TestSeedNewData(unittest.TestCase):
    """The v5.0.0 demo additions seed valid, self-consistent data."""

    @classmethod
    def setUpClass(cls):
        cls.m = _load()

    def test_new_files_registered(self):
        for f in ('thermal_history.json', 'dmarc_targets.json',
                  'dmarc_results.json', 'ip_reputation_targets.json',
                  'ip_reputation_results.json', 'resolver_health_targets.json',
                  'resolver_health_results.json'):
            self.assertIn(f, self.m.BUILDERS, f)

    def test_monitor_target_result_ids_match(self):
        # A target with no matching result (or vice versa) renders broken rows.
        for base in ('dmarc', 'ip_reputation', 'resolver_health'):
            t = self.m.BUILDERS[f'{base}_targets.json']()
            r = self.m.BUILDERS[f'{base}_results.json']()
            self.assertEqual(set(t), set(r), base)

    def test_business_function_allowlist(self):
        allowed = {'', 'Application Operation', 'OS Operation', 'Server Camp'}
        cmdb = self.m.build_cmdb()
        vals = {v.get('business_function', '') for v in cmdb.values()}
        self.assertTrue(vals <= allowed, vals)
        self.assertTrue({'Application Operation', 'OS Operation', 'Server Camp'} & vals)

    def test_thermal_history_shape(self):
        th = self.m.build_thermal_history()
        self.assertTrue(th)
        for rec in th.values():
            self.assertTrue(rec['samples'])
            self.assertIn('temp', rec['samples'][0])
            self.assertIn('ts', rec['samples'][0])


class TestV610CoverageFill(unittest.TestCase):
    """v6.1.0: closed the gap between docs/features.md and what the demo
    actually seeds (a full audit found ~20 sections with no representative
    data). Every new field/file below was verified against the server
    handler that reads it (server/cgi-bin/api.py), not guessed — these tests
    pin the specific field names/cross-references that were easy to get
    subtly wrong (e.g. `via_satellite` not `satellite_id`, `commands.json`
    is a flat dict of strings not objects, escalation/oncall are two keys
    not one)."""

    @classmethod
    def setUpClass(cls):
        cls.m = _load()

    def test_new_files_registered(self):
        for f in ('tasks.json', 'racks.json', 'subnets.json',
                  'device_profiles.json', 'smart_groups.json',
                  'backup_state.json', 'mailflow_state.json', 'ct_watch.json',
                  'patch_age.json', 'image_cves.json', 'cve_campaigns.json',
                  'lldp_neighbors.json', 'sudo_log.json', 'incidents.json',
                  'commands.json', 'update_logs.json'):
            self.assertIn(f, self.m.BUILDERS, f)

    def test_all_builders_run_and_produce_json_safe_output(self):
        for name, builder in self.m.BUILDERS.items():
            data = builder()
            json.dumps(data)  # must not raise (no sets/non-serializable values)
            self.assertIsInstance(data, (dict, list), name)

    def test_finance_account_does_not_block_reseed(self):
        # Regression: _DEMO_ACCOUNTS was missing 'finance' (added later for
        # billing), so every re-seed after the first was silently refused —
        # breaking the documented cron re-seed workflow.
        self.assertIn('finance', self.m._DEMO_ACCOUNTS)

    def test_monitors_use_verified_field_names(self):
        # Real field is `via_satellite`, NOT `satellite_id`; http_flow steps
        # are `steps`, NOT `http_flow_steps`.
        monitors = self.m.build_config()['monitors']
        self.assertTrue(monitors)
        satellite_monitors = [m for m in monitors if 'via_satellite' in m]
        self.assertTrue(satellite_monitors)
        self.assertNotIn('satellite_id', str(monitors))
        flow_monitors = [m for m in monitors if m.get('type') == 'http_flow']
        self.assertTrue(flow_monitors)
        self.assertIn('steps', flow_monitors[0])
        self.assertNotIn('http_flow_steps', flow_monitors[0])
        valid_types = {'ping', 'tcp', 'http', 'dns', 'icmp', 'db', 'http_flow', 'path'}
        for mon in monitors:
            self.assertIn(mon['type'], valid_types, mon)

    def test_commands_json_is_flat_dict_of_strings_not_objects(self):
        # Real shape is device_id -> [raw command strings]; an earlier draft
        # assumed a richer per-item object shape, which the server does not
        # read this way (handle_command_queue, api.py).
        commands = self.m.BUILDERS['commands.json']()
        self.assertTrue(commands)
        for dev_id, queued in commands.items():
            self.assertIsInstance(queued, list, dev_id)
            for item in queued:
                self.assertIsInstance(item, str, (dev_id, item))

    def test_escalation_and_oncall_are_separate_keys(self):
        cfg = self.m.build_config()
        self.assertIn('escalation', cfg)
        self.assertIn('oncall', cfg)
        self.assertIn('tiers', cfg['escalation'])
        self.assertIn('contacts', cfg['oncall'])

    def test_patch_sla_is_config_key_patch_age_is_state_file(self):
        # Rules live in config.json['patch_sla']; patch_age.json holds the
        # computed aging state. Confirms the two weren't conflated.
        cfg = self.m.build_config()
        self.assertIn('patch_sla', cfg)
        self.assertNotIn('patch_age', cfg)
        patch_age = self.m.BUILDERS['patch_age.json']()
        self.assertIn('_breaching', patch_age)

    def test_remediation_enabled_is_per_device_not_config(self):
        # Real field is devices.json[id]['remediation_enabled'], NOT a
        # config.json key.
        cfg = self.m.build_config()
        self.assertNotIn('remediation_enabled', cfg)
        devices = self.m.build_devices()
        self.assertTrue(any(d.get('remediation_enabled') for d in devices.values()))

    def test_connector_credentials_disabled_to_prevent_outbound_calls(self):
        # Proxmox/OPNsense enabled:false is load-bearing — GET requests
        # aren't blocked by read-only mode, so an enabled fake connector
        # would fire a real outbound call on ordinary page loads.
        cfg = self.m.build_config()
        self.assertFalse(cfg.get('proxmox_enabled'))
        devices = self.m.build_devices()
        opnsense_devices = [d for d in devices.values() if 'opnsense' in d]
        self.assertTrue(opnsense_devices)
        for d in opnsense_devices:
            self.assertFalse(d['opnsense']['enabled'])

    def test_portal_enabled_requires_base_url(self):
        # handle_config_save rejects portal_enabled:true with an empty
        # portal_base_url — the seed must satisfy that pairing.
        cfg = self.m.build_config()
        if cfg.get('portal_enabled'):
            self.assertTrue(cfg.get('portal_base_url'))

    def test_portal_contact_has_no_password_field(self):
        # Portal auth is magic-link only — no credential material belongs
        # on a contact record.
        contacts = self.m.build_contacts()['contacts']
        portal_contacts = [c for c in contacts if c.get('portal_enabled')]
        self.assertTrue(portal_contacts)
        for c in portal_contacts:
            self.assertTrue(c.get('site'))
            self.assertNotIn('password', c)
            self.assertNotIn('password_hash', c)

    def test_monitoring_profile_script_ids_exist_in_custom_scripts(self):
        cfg = self.m.build_config()
        cs_ids = set(self.m.build_custom_scripts().keys())
        for profile in cfg.get('monitoring_profiles', []):
            for sid in profile['script_ids']:
                self.assertIn(sid, cs_ids)

    def test_alert_runbook_targets_exist_in_kb(self):
        cfg = self.m.build_config()
        kb_ids = {a['id'] for a in self.m.build_kb()['articles']}
        for target in cfg.get('alert_runbooks', {}).values():
            self.assertIn(target, kb_ids)

    def test_rack_ids_referenced_from_cmdb_exist_in_racks(self):
        rack_ids = set(self.m.BUILDERS['racks.json']().keys())
        cmdb = self.m.build_cmdb()
        used = {v['rack_id'] for v in cmdb.values() if v.get('rack_id')}
        self.assertTrue(used)
        self.assertTrue(used <= rack_ids)

    def test_via_satellite_ids_exist_in_satellites(self):
        cfg = self.m.build_config()
        sat_ids = set(self.m.build_satellites().keys())
        referenced = {m['via_satellite'] for m in cfg['monitors'] if 'via_satellite' in m}
        self.assertTrue(referenced)
        self.assertTrue(referenced <= sat_ids)

    def test_sites_have_lat_lng(self):
        sites = self.m.build_sites()
        for site in sites.values():
            self.assertIn('lat', site)
            self.assertIn('lng', site)
            self.assertTrue(-90 <= site['lat'] <= 90)
            self.assertTrue(-180 <= site['lng'] <= 180)

    def test_backup_state_keys_match_backup_monitors_paths(self):
        cfg = self.m.build_config()
        monitor_paths = {m['path'] for m in cfg['backup_monitors']}
        state = self.m.BUILDERS['backup_state.json']()
        for key in state:
            path = key.partition(':')[2]
            self.assertIn(path, monitor_paths, key)

    def test_task_states_are_valid(self):
        valid = {'upcoming', 'ongoing', 'pending', 'closed'}
        tasks = self.m.BUILDERS['tasks.json']()['tasks']
        self.assertTrue(tasks)
        for t in tasks:
            self.assertIn(t['state'], valid, t)

    def test_incident_impact_and_status_are_valid(self):
        valid_impact = {'minor', 'major', 'maintenance'}
        valid_status = {'investigating', 'identified', 'monitoring', 'resolved'}
        incidents = self.m.BUILDERS['incidents.json']()['incidents']
        self.assertTrue(incidents)
        for inc in incidents:
            self.assertIn(inc['impact'], valid_impact, inc)
            self.assertIn(inc['status'], valid_status, inc)
            for upd in inc['updates']:
                self.assertIn(upd['status'], valid_status, upd)

    def test_device_interfaces_field_not_seeded_dead_code(self):
        # Confirmed via research that dev['interfaces'] is never read by any
        # handler (only cmdb.json interfaces and sysinfo.network are real) —
        # seeding it would misrepresent server behavior.
        devices = self.m.build_devices()
        for d in devices.values():
            self.assertNotIn('interfaces', d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
