#!/usr/bin/env python3
"""Device profiles: four defects in the one bulk-threshold path that ships.

The backlog asked for "bulk apply of metric thresholds across selected
devices". That feature ALREADY EXISTS — `POST /api/device-profiles/{id}/apply`
stamps thresholds across a device list — so the item as written was half
refuted. What the investigation found instead were four shipped defects in it:

1. NO warn < crit CHECK. The per-device PATCH has always enforced it; the
   profile path did not. A profile with mem_warn=90 / mem_crit=50 was accepted
   and stamped fleet-wide, making `warning` unreachable while `critical` fired
   at 50%. A threshold pair that cannot both fire is never what anyone meant.

2. OUT-OF-RANGE VALUES WERE SILENTLY DROPPED. The key simply never landed in
   the cleaned dict, the profile saved, and the toast said "Profile saved" — so
   the operator believed a threshold existed that did not. The same shape as
   the Alert-parameters bug fixed earlier in this release.

3. APPLY REPLACED THE WHOLE THRESHOLDS DICT, destroying a device's per-mount
   overrides — while the modal promised "applying a profile only stamps the
   fields it defines". True between top-level fields, false INSIDE
   metric_thresholds, which is exactly where the fiddly per-mount work lives.

4. NO TENANT ISOLATION AT ALL. A tenant-scoped admin could list, edit and
   DELETE another tenant's profiles. Smart groups — their sibling from the same
   batch — already stamp and gate on `tenant`.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643prof-'))

_spec = importlib.util.spec_from_file_location('api_v643_prof', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    TENANCY = True

    def setUp(self):
        self.cap = {}
        api.save(api.CONFIG_FILE, {'tenancy_enforced': self.TENANCY})
        api.save(api.TENANTS_FILE, {'default': {'name': 'P'}, 'acme': {'name': 'A'}})
        api.save(api.USERS_FILE, {
            'root':   {'role': 'admin', 'tenant_id': 'default'},
            'tadmin': {'role': 'admin', 'tenant_id': 'acme'}})
        api.save(api.DEVICE_PROFILES_FILE, {})
        api.save(api.DEVICES_FILE, {})
        for f in (api.CONFIG_FILE, api.TENANTS_FILE, api.USERS_FILE,
                  api.DEVICE_PROFILES_FILE, api.DEVICES_FILE):
            api._invalidate_load_cache(f)
        self._orig = {k: getattr(api, k) for k in (
            'require_admin_auth', 'method', 'get_json_obj', 'get_json_body',
            'respond', 'audit_log', 'verify_token', 'get_token_from_request')}
        api.audit_log = lambda *a, **k: None

        def _r(status, data=None, *a, **k):
            self.cap['s'], self.cap['d'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _r
        self._as('root')

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _as(self, actor):
        api.require_admin_auth = lambda *a, **k: actor
        role = (api.load(api.USERS_FILE) or {}).get(actor, {}).get('role', 'admin')
        api.verify_token = lambda *a, **k: (actor, role)
        api.get_token_from_request = lambda *a, **k: 'tok-' + actor

    def _call(self, fn, *args, body=None, m='POST'):
        api.method = lambda: m
        api.get_json_obj = lambda: (body or {})
        api.get_json_body = lambda *a, **k: (body or {})
        try:
            fn(*args)
        except (SystemExit, api.HTTPError):
            pass
        api._invalidate_load_cache(api.DEVICE_PROFILES_FILE)
        api._invalidate_load_cache(api.DEVICES_FILE)
        return self.cap

    def _profiles(self):
        return api.load(api.DEVICE_PROFILES_FILE) or {}


class TestThresholdValidation(_Base):
    def test_warning_above_critical_is_refused(self):
        r = self._call(api.handle_device_profiles, body={
            'name': 'bad', 'metric_thresholds': {
                'mem_warn_percent': 90, 'mem_crit_percent': 50}})
        self.assertEqual(r.get('s'), 400,
                         'a profile whose warning can never fire was accepted '
                         'and stamped across the fleet')
        self.assertIn('below critical', str(r.get('d')))

    def test_a_sane_pair_is_accepted(self):
        """Positive control — a validator that refused everything would pass
        the test above."""
        r = self._call(api.handle_device_profiles, body={
            'name': 'good', 'metric_thresholds': {
                'mem_warn_percent': 70, 'mem_crit_percent': 90}})
        self.assertEqual(r.get('s'), 201, r.get('d'))

    def test_equal_values_are_refused_too(self):
        r = self._call(api.handle_device_profiles, body={
            'name': 'eq', 'metric_thresholds': {
                'disk_warn_percent': 80, 'disk_crit_percent': 80}})
        self.assertEqual(r.get('s'), 400)

    def test_out_of_range_is_refused_not_dropped(self):
        r = self._call(api.handle_device_profiles, body={
            'name': 'oor', 'metric_thresholds': {'mem_warn_percent': 150}})
        self.assertEqual(r.get('s'), 400,
                         'an out-of-range value was silently dropped and the '
                         'profile saved, so the operator believed a threshold '
                         'existed that did not')
        self.assertEqual(self._profiles(), {}, 'the profile was stored anyway')

    def test_a_non_number_is_refused(self):
        r = self._call(api.handle_device_profiles, body={
            'name': 'nan', 'metric_thresholds': {'mem_warn_percent': 'high'}})
        self.assertEqual(r.get('s'), 400)

    def test_only_one_side_of_a_pair_is_fine(self):
        """A profile may define just the warning; there is nothing to compare."""
        r = self._call(api.handle_device_profiles, body={
            'name': 'warnonly', 'metric_thresholds': {'mem_warn_percent': 70}})
        self.assertEqual(r.get('s'), 201, r.get('d'))


class TestApplyMergesRatherThanReplaces(_Base):
    def test_per_mount_overrides_survive(self):
        """The modal promises "applying a profile only stamps the fields it
        defines". Replacing the dict broke that promise where it mattered most
        — the per-mount thresholds an operator hand-tuned."""
        dev = {'name': 'web01', 'metric_thresholds': {
            'disk_per_mount': {'/var': {'warn': 70, 'crit': 85}},
            'swap_warn_percent': 40}}
        out = api._apply_profile_to_device(
            dev, {'metric_thresholds': {'mem_warn_percent': 70}})
        mt = out['metric_thresholds']
        self.assertIn('disk_per_mount', mt,
                      'the per-mount overrides were destroyed')
        self.assertEqual(mt['disk_per_mount']['/var']['warn'], 70)
        self.assertEqual(mt['swap_warn_percent'], 40,
                         'a threshold the profile does not define was cleared')
        self.assertEqual(mt['mem_warn_percent'], 70,
                         'the profile value was not applied')

    def test_the_profile_still_wins_on_conflict(self):
        """Positive control: merging must not mean "ignore the profile"."""
        dev = {'metric_thresholds': {'mem_warn_percent': 40}}
        out = api._apply_profile_to_device(
            dev, {'metric_thresholds': {'mem_warn_percent': 80}})
        self.assertEqual(out['metric_thresholds']['mem_warn_percent'], 80)

    def test_metric_state_is_still_cleared(self):
        dev = {'metric_thresholds': {}, 'metric_state': {'mem': 'warning'}}
        out = api._apply_profile_to_device(
            dev, {'metric_thresholds': {'mem_warn_percent': 80}})
        self.assertNotIn('metric_state', out,
                         'stale state would re-evaluate against old thresholds')


class TestProfileTenancy(_Base):
    def _seed(self):
        api.save(api.DEVICE_PROFILES_FILE, {
            'p_def': {'name': 'platform', 'tenant': 'default'},
            'p_acme': {'name': 'acme prof', 'tenant': 'acme'}})
        api._invalidate_load_cache(api.DEVICE_PROFILES_FILE)

    def test_a_tenant_admin_lists_only_its_own(self):
        self._seed(); self._as('tadmin')
        r = self._call(api.handle_device_profiles, m='GET')
        names = {p['name'] for p in (r['d'] or {}).get('profiles', [])}
        self.assertEqual(names, {'acme prof'}, str(names))

    def test_a_superadmin_lists_everything(self):
        self._seed(); self._as('root')
        r = self._call(api.handle_device_profiles, m='GET')
        self.assertEqual(len((r['d'] or {}).get('profiles', [])), 2)

    def test_a_tenant_admin_cannot_delete_another_tenants_profile(self):
        self._seed(); self._as('tadmin')
        r = self._call(api.handle_device_profile, 'p_def', m='DELETE')
        self.assertEqual(r.get('s'), 404)
        self.assertIn('p_def', self._profiles(), 'the profile was deleted')

    def test_a_tenant_admin_cannot_edit_another_tenants_profile(self):
        self._seed(); self._as('tadmin')
        r = self._call(api.handle_device_profile, 'p_def',
                       body={'name': 'pwned'}, m='PATCH')
        self.assertEqual(r.get('s'), 404)
        self.assertEqual(self._profiles()['p_def']['name'], 'platform')

    def test_it_CAN_still_manage_its_own(self):
        """Positive control — a gate that refused everything would pass all
        three tests above while breaking the feature."""
        self._seed(); self._as('tadmin')
        r = self._call(api.handle_device_profile, 'p_acme',
                       body={'name': 'renamed'}, m='PATCH')
        self.assertEqual(r.get('s'), 200, r.get('d'))
        self.assertEqual(self._profiles()['p_acme']['name'], 'renamed')

    def test_a_new_profile_is_stamped_with_the_creators_tenant(self):
        self._as('tadmin')
        self._call(api.handle_device_profiles,
                   body={'name': 'mine', 'poll_interval': 60})
        made = [p for p in self._profiles().values() if p.get('name') == 'mine']
        self.assertTrue(made)
        self.assertEqual(made[0].get('tenant'), 'acme')

    def test_apply_refuses_another_tenants_profile(self):
        """The DEVICES were already tenant-filtered here; the PROFILE was not,
        so a tenant admin could stamp another tenant's profile onto its own
        hosts — reading a configuration it should not see."""
        self._seed(); self._as('tadmin')
        r = self._call(api.handle_device_profile_apply, 'p_def',
                       body={'device_ids': ['d1']})
        self.assertEqual(r.get('s'), 404)


class TestSingleTenantInstallsAreUnaffected(_Base):
    TENANCY = False

    def test_every_admin_sees_every_profile(self):
        api.save(api.DEVICE_PROFILES_FILE, {
            'p1': {'name': 'a', 'tenant': 'default'},
            'p2': {'name': 'b', 'tenant': 'acme'}})
        api._invalidate_load_cache(api.DEVICE_PROFILES_FILE)
        self._as('tadmin')
        r = self._call(api.handle_device_profiles, m='GET')
        self.assertEqual(len((r['d'] or {}).get('profiles', [])), 2)


if __name__ == '__main__':
    unittest.main()
