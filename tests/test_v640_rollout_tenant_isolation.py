"""v6.4.0 pre-release security hunt — cross-tenant RCE via rollouts + autopatch.

CONFIRMED CRITICAL (adversarial audit): rollouts and auto-patch policies are a
second device-targeting path that bypasses the `_resolve_targets` chokepoint
entirely and had NO tenant/scope filtering. A tenant admin (role 'admin',
scope None, tenant != default) could `POST /api/rollouts` with an ids/group/tag
selector — or create an auto-patch policy with `target={'type':'all'}` — and
fan `reboot` / `upgrade` / arbitrary `exec:<script>` out to another tenant's
hosts.

Fix: a `tenant_gate` is stamped on the rollout / policy at create time (None for
a superadmin or when tenancy is off; the tenant id for a tenant admin) and the
dispatcher (`_rollout_dispatch_ring`) and flat-target resolver
(`_autopatch_target_devices`) confine resolution to that gate.

These tests drive the REAL dispatch/resolution code (not the HTTP handlers), so
they pass only if the gate is actually enforced.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v640-roll-')
    spec = importlib.util.spec_from_file_location('api_v640_roll', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.api.save(self.api.CONFIG_FILE, {'tenancy_enforced': True})
        self.api._LOAD_CACHE.clear()
        self.devices = {
            'devA': {'name': 'A-host', 'tenant': 'tenantA', 'token': 'ta',
                     'version': '1.0', 'group': 'prod', 'tags': ['prod']},
            'devB': {'name': 'B-host', 'tenant': 'tenantB', 'token': 'tb',
                     'version': '2.0', 'group': 'prod', 'tags': ['prod']},
        }
        self.api.save(self.api.DEVICES_FILE, self.devices)


class TestRolloutDispatchTenantGate(_Base):
    """_rollout_dispatch_ring confines ring resolution to roll['tenant_gate']."""

    def _dispatch(self, selector, gate):
        roll = {'action': 'reboot', 'rings': [{'name': 'r', 'selector': selector}],
                'tenant_gate': gate, 'created_by': 'attacker'}
        cmds = {}
        dispatched, _q = self.api._rollout_dispatch_ring(roll, 0, dict(self.devices), cmds)
        return dispatched, cmds

    def test_ids_selector_cannot_cross_tenant(self):
        # tenantA admin names tenantB's device by id → must NOT be dispatched.
        dispatched, cmds = self._dispatch({'type': 'ids', 'ids': ['devB']}, 'tenantA')
        self.assertNotIn('devB', dispatched)
        self.assertNotIn('devB', cmds)

    def test_group_selector_cannot_cross_tenant(self):
        # group 'prod' spans both tenants; a tenantA admin reaches only devA.
        dispatched, cmds = self._dispatch({'type': 'group', 'value': 'prod'}, 'tenantA')
        self.assertIn('devA', dispatched)
        self.assertNotIn('devB', dispatched)
        self.assertNotIn('devB', cmds)

    def test_tag_selector_cannot_cross_tenant(self):
        dispatched, _ = self._dispatch({'type': 'tag', 'value': 'prod'}, 'tenantB')
        self.assertIn('devB', dispatched)
        self.assertNotIn('devA', dispatched)

    def test_superadmin_gate_none_reaches_all(self):
        # A superadmin / tenancy-off rollout (gate None) is unrestricted.
        dispatched, _ = self._dispatch({'type': 'group', 'value': 'prod'}, None)
        self.assertIn('devA', dispatched)
        self.assertIn('devB', dispatched)


class TestAutopatchTargetTenantGate(_Base):
    """_autopatch_target_devices honours the policy tenant_gate."""

    def test_all_target_confined_to_tenant(self):
        got = self.api._autopatch_target_devices({'type': 'all'}, 'tenantA')
        self.assertEqual(set(got), {'devA'})

    def test_group_target_confined_to_tenant(self):
        got = self.api._autopatch_target_devices({'type': 'group', 'value': 'prod'}, 'tenantB')
        self.assertEqual(set(got), {'devB'})

    def test_gate_none_reaches_all(self):
        got = self.api._autopatch_target_devices({'type': 'all'}, None)
        self.assertEqual(set(got), {'devA', 'devB'})


if __name__ == '__main__':
    unittest.main()
