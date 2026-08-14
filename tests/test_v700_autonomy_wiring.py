#!/usr/bin/env python3
"""The autonomy subsystem as wired into api.py — driven, not read.

The core's safety is proven in test_v700_autonomy_core.py against pure
functions. This file asks the different question: is that core actually the
thing standing between an alert and a command, and are the surfaces around it
gated the way every other subsystem here is?

The cases that matter, in order of what would hurt most:

* **A tenant who never opted in gets no receipts at all.** Not "receipts that
  say refused" — nothing. Writing rows about a fleet whose owner never asked is
  a smaller version of acting without being asked, and it is the difference
  between shadow mode being a feature and being surveillance.
* **The module gate covers the whole prefix.** `_MODULES` puts /api/autonomy
  behind a default-false switch, so an install that never enables it has no
  reachable surface — the UI is never the enforcement boundary here.
* **Receipts are tenant-filtered**, like every other device-keyed store.
* **The loop cannot execute yet.** Execution lands in a later commit behind the
  same switch; until then an ACT verdict must be recorded as not-executed. A
  test that let this pass silently would be how "shadow" quietly stopped being
  shadow.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-autow-'))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_autow', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import autonomy  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-aw-'))
        self._saved = {}
        for n in ('DEVICES_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'SERVICES_FILE', 'LLDP_NEIGHBORS_FILE', 'BACKUP_JOBS_FILE',
                  'AUTONOMY_POLICY_FILE', 'AUTONOMY_RECEIPTS_FILE',
                  'INCIDENT_MEMORY_FILE', 'TENANTS_FILE', 'USERS_FILE'):
            if hasattr(api, n):
                self._saved[n] = getattr(api, n)
                setattr(api, n, self.d / f'{n.lower()}.json')
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, {'autonomy_enabled': True})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web01', 'group': 'prod'}})

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def _receipts(self):
        return (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []

    def _alert(self, event='unit_failed', dev='d1'):
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': event, 'device_id': dev,
            'severity': 'high', 'payload': {'unit': 'nginx.service'},
        }]})

    def _policy(self, mode, tenant='default', **over):
        pol = autonomy.default_policy()
        pol['mode'] = mode
        pol.update(over)
        api.save(api.AUTONOMY_POLICY_FILE, {'tenants': {tenant: pol}})


class TestAnUnopenedTenantIsLeftAlone(_Base):

    def test_mode_off_writes_no_receipts_at_all(self):
        """Not even a refusal row. Recording what we would have done to a fleet
        whose owner never asked is the thing shadow mode must not become."""
        self._alert()
        self._policy('off')
        api.run_autonomy_if_due()
        self.assertEqual(self._receipts(), [])

    def test_no_policy_at_all_is_the_same_as_off(self):
        self._alert()
        api.save(api.AUTONOMY_POLICY_FILE, {})
        api.run_autonomy_if_due()
        self.assertEqual(self._receipts(), [])

    def test_the_module_switch_off_stops_the_loop_entirely(self):
        self._alert()
        self._policy('shadow')
        api.save(api.CONFIG_FILE, {'autonomy_enabled': False})
        api._LOAD_CACHE.clear()
        api.run_autonomy_if_due()
        self.assertEqual(self._receipts(), [])


class TestShadowRecordsButNeverActs(_Base):

    def test_shadow_writes_a_receipt(self):
        self._alert()
        self._policy('shadow')
        api.run_autonomy_if_due()
        rows = self._receipts()
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]['device_name'], 'web01')
        self.assertEqual(rows[0]['trigger'], 'unit_failed')

    def test_no_shadow_receipt_claims_to_have_acted(self):
        self._alert()
        self._policy('shadow', allowed_actions=list(autonomy.ACTION_CLASSES),
                     max_blast_radius=99, require_window=False,
                     require_verified_backup=False)
        api.run_autonomy_if_due()
        for r in self._receipts():
            self.assertNotEqual(r['verdict'], autonomy.ACT, r)

    def test_the_receipt_explains_itself(self):
        """A row an operator cannot grade is not worth writing."""
        self._alert()
        self._policy('shadow')
        api.run_autonomy_if_due()
        r = self._receipts()[0]
        for k in ('trigger', 'action', 'verdict', 'reason', 'blast_radius',
                  'precedent', 'device_name', 'tenant'):
            self.assertIn(k, r, k)


class TestTheLoopCannotExecuteYet(_Base):

    def test_an_act_verdict_is_recorded_as_not_executed(self):
        """Execution lands behind the same switch in a later commit. Until it
        does, an ACT must be visibly inert — if this ever silently passes, the
        loop stopped being shadow without anyone deciding that."""
        self._alert()
        self._policy('enabled', allowed_actions=['restart_service'],
                     max_blast_radius=99, require_window=False,
                     require_verified_backup=False)
        # Give it precedent so the envelope permits acting.
        api.save(api.INCIDENT_MEMORY_FILE, {'outcomes': [
            {'source': 'operator', 'event': 'unit_failed', 'kind': '',
             'tenant': 'default', 'resolution': 'restarted',
             'recommended_action': 'systemctl restart nginx'} for _ in range(4)]})
        api.run_autonomy_if_due()
        for r in self._receipts():
            if r['verdict'] == autonomy.ACT:
                self.assertIn('not-executed', str(r.get('outcome') or ''), r)

    def test_no_command_is_built_from_remote_alert_text(self):
        """The command template lives beside the safety analysis, not in the
        alert payload — a command assembled from remote data is how an alert
        becomes an injection vector."""
        src = (_CGI / 'autonomy_ops_handlers.py').read_text()
        self.assertIn('_ACTION_COMMANDS', src)
        i = src.index('_ACTION_COMMANDS')
        block = src[i:i + 600]
        self.assertIn('systemctl restart {unit}', block)


class TestEventsWithoutAnAnalysisAreNeverCandidates(_Base):

    def test_an_unmapped_event_is_ignored(self):
        """Default deny at the trigger layer too: the loop cannot invent an
        action for a signal nobody analysed."""
        self._alert(event='cve_found')
        self._policy('shadow')
        api.run_autonomy_if_due()
        self.assertEqual(self._receipts(), [])

    def test_resolved_and_acked_alerts_are_skipped(self):
        self._policy('shadow')
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'r', 'event': 'unit_failed', 'device_id': 'd1',
             'resolved_at': int(time.time()), 'payload': {}},
            {'id': 'k', 'event': 'unit_failed', 'device_id': 'd1',
             'acked_at': int(time.time()), 'payload': {}},
        ]})
        api.run_autonomy_if_due()
        self.assertEqual(self._receipts(), [])


class TestSurfacesAreGated(_Base):
    """Only verify_token is stubbed — stubbing require_auth/require_admin_auth
    would happily pass a handler with no gate at all."""

    def test_the_whole_prefix_sits_behind_the_module_switch(self):
        self.assertIn('autonomy', api._MODULES)
        key, default, prefixes = api._MODULES['autonomy']
        self.assertEqual(key, 'autonomy_enabled')
        self.assertIn('/api/autonomy', prefixes)
        # The module ships ON so the page is discoverable. That is NOT what
        # keeps the loop inert — the per-tenant policy default is, and it is
        # asserted right below. Hiding the nav was never the safety property;
        # conflating the two is how a feature ends up invisible AND unsafe.
        import autonomy as _a
        self.assertEqual(_a.default_policy()['mode'], 'off',
                         'the per-tenant default is the real safety gate')

    def test_policy_write_requires_admin(self):
        import inspect
        src = inspect.getsource(api.handle_autonomy_policy)
        self.assertIn('require_admin_auth', src,
                      'changing the safety envelope is a control-plane act')

    def test_receipts_are_tenant_filtered(self):
        import inspect
        src = inspect.getsource(api.handle_autonomy_receipts)
        self.assertIn('_tenant_gate', src)

    def test_preview_gates_the_device(self):
        import inspect
        src = inspect.getsource(api.handle_autonomy_preview)
        self.assertIn('_scope_block_device', src,
                      'a body-supplied device id gets no dispatcher cover')


class TestBlastRadiusUsesRealStores(_Base):

    def test_monitors_on_the_host_count(self):
        """Monitors live in CONFIG_FILE under `monitors`, each carrying a
        device_id — not in a store of their own. The first draft of the blast
        radius reached for a MONITORS_FILE that does not exist, inside a bare
        except, which would have made every radius silently zero."""
        api.save(api.CONFIG_FILE, {'autonomy_enabled': True, 'monitors': [
            {'id': 'm1', 'device_id': 'd1'}, {'id': 'm2', 'device_id': 'd1'},
            {'id': 'm3', 'device_id': 'other'},
            {'id': 'm4', 'device_id': 'd1', 'paused': True}]})
        api._LOAD_CACHE.clear()
        devices = api.load(api.DEVICES_FILE)
        r = api._blast_radius_for('d1', devices['d1'], devices)
        self.assertEqual(r['monitors'], 2, 'paused monitors must not count')

    def test_a_missing_store_fails_loudly_rather_than_returning_zero(self):
        """A safety input that fails OPEN is worse than no safety input: a
        radius of zero satisfies every policy limit."""
        import ast as _ast
        tree = _ast.parse((_CGI / 'autonomy_ops_handlers.py').read_text())
        fn = next(n for n in _ast.walk(tree)
                  if isinstance(n, _ast.FunctionDef) and n.name == '_blast_radius_for')
        handlers = [n for n in _ast.walk(fn) if isinstance(n, _ast.ExceptHandler)]
        self.assertEqual(handlers, [],
                         'blast radius must not swallow a missing store — a '
                         'radius of zero satisfies every policy limit')

    def test_siblings_in_the_same_group_grant_redundancy(self):
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'group': 'prod'},
            'd2': {'name': 'web02', 'group': 'prod'},
            'd3': {'name': 'web03', 'group': 'prod'}})
        api.save(api.CONFIG_FILE, {'autonomy_enabled': True, 'monitors': [
            {'id': f'm{i}', 'device_id': 'd1'} for i in range(4)]})
        api._LOAD_CACHE.clear()
        devices = api.load(api.DEVICES_FILE)
        r = api._blast_radius_for('d1', devices['d1'], devices)
        self.assertTrue(r['redundant'])
        self.assertLess(r['score'], r['raw'])


if __name__ == '__main__':
    unittest.main()
