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
import re
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
        # CMDS_FILE belongs here: two tests below COUNT the commands that
        # reached the queue, and without the redirect they count whatever any
        # other module left in the shared store. That is what made
        # test_the_queue_agrees_with_the_receipts report 4 against a ceiling of
        # 3 in a large mixed run while passing alone, with its own module, and
        # across every v7 module — a rate limit appearing to leak when the
        # fixture was reading someone else's rows.
        for n in ('DEVICES_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'SERVICES_FILE', 'LLDP_NEIGHBORS_FILE', 'BACKUP_JOBS_FILE',
                  'AUTONOMY_POLICY_FILE', 'AUTONOMY_RECEIPTS_FILE', 'CMDS_FILE',
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

    def _alert(self, event='failed_unit', dev='d1'):
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
        self.assertEqual(rows[0]['trigger'], 'failed_unit')

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


class TestTheLoopExecutes(_Base):

    def test_an_act_verdict_dispatches_and_owes_a_verification(self):
        """v7.0.0: ACT now dispatches. The receipt must say what happened to
        the command AND carry the before-snapshot plus the time the second
        checks sample is owed — a dispatch with no verify_due is an action
        nobody will ever grade."""
        self._alert()
        self._policy('enabled', allowed_actions=['restart_service'],
                     max_blast_radius=99, require_window=False,
                     require_verified_backup=False)
        # Give it precedent so the envelope permits acting.
        api.save(api.INCIDENT_MEMORY_FILE, {'outcomes': [
            {'source': 'operator', 'event': 'failed_unit', 'kind': '',
             'tenant': 'default', 'resolution': 'restarted',
             'recommended_action': 'systemctl restart nginx'} for _ in range(4)]})
        api.run_autonomy_if_due()
        acted = [r for r in self._receipts() if r['verdict'] == autonomy.ACT]
        self.assertTrue(acted, 'nothing acted — the envelope refused, so this '
                               'test is measuring the wrong thing')
        for r in acted:
            self.assertEqual(r.get('outcome'), 'queued', r)
            self.assertIsNotNone(r.get('verify_due'),
                                 'an action with no verify_due is one nobody '
                                 'will ever grade')
            self.assertIsNotNone(r.get('before_checks'),
                                 'no before-snapshot — the comparison has '
                                 'nothing to compare against')
            # The normalisation that makes the comparison mean anything.
            self.assertIn('failing', r['before_checks'],
                          '_host_check_summary has no `failing` key; without '
                          'normalising it, verification compares 0 with 0 on '
                          'every host and reports every action as verified')
            self.assertIsNone(r.get('verified'), 'not verified yet')
            self.assertNotIn('rolled_back', r)

    def test_the_command_actually_reaches_the_queue(self):
        """'queued' in a receipt is a claim. This checks the command channel."""
        self._alert()
        self._policy('enabled', allowed_actions=['restart_service'],
                     max_blast_radius=99, require_window=False,
                     require_verified_backup=False, approval_for_destructive=False)
        api.save(api.INCIDENT_MEMORY_FILE, {'outcomes': [
            {'source': 'operator', 'event': 'failed_unit', 'kind': '',
             'tenant': 'default', 'resolution': 'restarted',
             'recommended_action': 'systemctl restart nginx'} for _ in range(4)]})
        api.run_autonomy_if_due()
        queued = (api.load(api.CMDS_FILE) or {}).get('d1') or []
        self.assertIn('svc:restart:nginx.service', [str(c) for c in queued],
                      f'the receipt said queued; the queue holds {queued}')

    def test_no_command_is_built_from_remote_alert_text(self):
        """The command SHAPE lives beside the safety analysis; the alert may
        only supply a parameter, and only one that survives sanitising. A
        command assembled from remote data is how an alert becomes an
        injection vector."""
        import autonomy_ops_handlers as _ops
        for action, tmpl in _ops._ACTION_COMMANDS.items():
            for t in ([tmpl] if isinstance(tmpl, str) else list(tmpl.values())):
                # Every substitution point is a named parameter this module
                # declares. An f-string or a concatenation would not be.
                for field in re.findall(r'\{(\w+)\}', t):
                    self.assertTrue(
                        field == 'runtime' or field in _ops._ACTION_PARAMS,
                        f'{action}: {{{field}}} has no declared source')

    def test_a_hostile_parameter_cannot_change_the_verb(self):
        """The wire format is colon-delimited and the agent re-splits it, so a
        unit named `x:stop:sshd` would arrive as a different action."""
        cmd, prob = api._resolve_params(
            'svc:restart:{unit}', {'unit': 'x:stop:sshd'}, 'd1')
        self.assertEqual(cmd, '')
        self.assertEqual(prob, 'missing_parameter')


class TestTheRateLimitHoldsWithinOneSweep(_Base):
    """The ceiling exists to stop a flapping host becoming a storm — and a
    flapping host produces its alerts ALL AT ONCE, so they land in one sweep.

    Receipts are appended after the candidate loop, so a rate check that counts
    only the stored receipts gives every candidate in a sweep the same
    pre-sweep number. Measured before the fix: a ceiling of 3 against 12
    candidate alerts dispatched all 12. The limit held only in the case where
    nobody needed it to.
    """

    def _many_alerts(self, n):
        api.save(api.DEVICES_FILE, {f'd{i}': {'name': f'web{i:02d}', 'group': 'prod'}
                                    for i in range(n)})
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': f'a{i}', 'event': 'failed_unit', 'device_id': f'd{i}',
            'severity': 'high', 'payload': {'unit': 'nginx.service'},
        } for i in range(n)]})
        api.save(api.INCIDENT_MEMORY_FILE, {'outcomes': [
            {'source': 'operator', 'event': 'failed_unit', 'kind': '',
             'tenant': 'default', 'resolution': 'restarted',
             'recommended_action': 'systemctl restart nginx'} for _ in range(4)]})

    def test_it_stops_at_the_ceiling(self):
        self._many_alerts(12)
        self._policy('enabled', allowed_actions=['restart_service'],
                     max_blast_radius=99, require_window=False,
                     require_verified_backup=False, approval_for_destructive=False,
                     max_actions_per_hour=3)
        api.run_autonomy_if_due()
        acted = [r for r in self._receipts() if r['verdict'] == autonomy.ACT]
        limited = [r for r in self._receipts() if r.get('reason') == 'rate_limited']
        self.assertEqual(len(acted), 3,
                         f'ceiling is 3, {len(acted)} actions dispatched in one '
                         f'sweep')
        self.assertTrue(limited, 'nothing was recorded as rate-limited, so the '
                                 'refusals are invisible to the operator')

    def test_the_queue_agrees_with_the_receipts(self):
        """A receipt saying 'queued' three times while twelve commands sit in
        the queue would make the ceiling a fiction in the only place that
        matters."""
        self._many_alerts(12)
        self._policy('enabled', allowed_actions=['restart_service'],
                     max_blast_radius=99, require_window=False,
                     require_verified_backup=False, approval_for_destructive=False,
                     max_actions_per_hour=3)
        api.run_autonomy_if_due()
        cmds = api.load(api.CMDS_FILE) or {}
        queued = sum(len(v or []) for v in cmds.values())
        self.assertEqual(queued, 3, f'{queued} commands reached the queue')


class TestVerificationClosesTheLoop(_Base):
    """Dispatch is asynchronous, so "did it work" is answered on a later sweep.

    The comparison uses the host's OWN checks engine, so the loop cannot invent
    a definition of healthy nobody else shares — and it does not roll anything
    back, because nothing here can be rolled back.
    """

    def _acted_receipt(self, before_failing, verify_due_offset=-1):
        """A receipt in the state a dispatch leaves behind."""
        now = int(time.time())
        api.save(api.AUTONOMY_RECEIPTS_FILE, {'receipts': [{
            'ts': now - 5000, 'tenant': 'default', 'device_id': 'd1',
            'device_name': 'web01', 'trigger': 'failed_unit',
            'action': 'restart_service', 'command': 'svc:restart:nginx.service',
            'verdict': autonomy.ACT, 'reason': 'ok', 'outcome': 'queued',
            'verified': None, 'verify_due': now + verify_due_offset,
            'before_checks': {'failing': before_failing},
        }], 'last_run': 0})
        return now

    def test_a_receipt_whose_window_has_not_elapsed_is_left_alone(self):
        """Verifying before the agent has had a chance to run the command would
        report every action as a failure."""
        self._acted_receipt(0, verify_due_offset=+9999)
        api._verify_due_receipts(int(time.time()))
        self.assertIsNone(self._receipts()[0]['verified'])

    def test_no_regression_verifies_the_action(self):
        self._acted_receipt(9)          # it was bad before; anything is an improvement
        api._verify_due_receipts(int(time.time()))
        r = self._receipts()[0]
        self.assertIs(r['verified'], True)
        self.assertIn('after_checks', r)

    def test_a_regression_marks_it_failed_and_raises_the_alert(self):
        """The honest capability: say the fix made things worse. There is no
        rollback — you cannot un-restart a service."""
        self._acted_receipt(0)          # nothing was failing before
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None, **kw: fired.append((ev, payload))
        try:
            # Force the "after" sample to look worse than the before.
            real_sum = api._host_check_summary
            api._host_check_summary = lambda checks: {
                'counts': {'ok': 0, 'warning': 0, 'critical': 3, 'unknown': 0},
                'worst': 'critical', 'total': 3}
            try:
                api._verify_due_receipts(int(time.time()))
            finally:
                api._host_check_summary = real_sum
        finally:
            api.fire_webhook = real
        r = self._receipts()[0]
        self.assertIs(r['verified'], False)
        self.assertIn('verification failed', str(r.get('outcome')))
        self.assertEqual([e for e, _p in fired], ['remediation_failed'],
                         'a fix that made things worse must page somebody')

    def test_the_event_it_raises_is_a_real_one(self):
        """An invented event name reaches no channel and no inbox."""
        self.assertIn('remediation_failed', api.EVENT_REGISTRY)
        self.assertIn('severity', api.EVENT_REGISTRY['remediation_failed'])


class TestEscalationBecomesARealApproval(_Base):

    def test_it_parks_a_confirmation_an_admin_can_see(self):
        """An ESCALATE verdict that only wrote the word "escalate" into a
        receipt would be a queue nobody can approve."""
        self._alert()
        self._policy('enabled', allowed_actions=['reboot'],
                     max_blast_radius=99, require_window=False,
                     require_verified_backup=False, approval_for_destructive=True)
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'reboot_required', 'device_id': 'd1',
            'severity': 'high', 'payload': {}}]})
        api.save(api.INCIDENT_MEMORY_FILE, {'outcomes': [
            {'source': 'operator', 'event': 'reboot_required', 'kind': '',
             'tenant': 'default', 'resolution': 'rebooted',
             'recommended_action': 'reboot'} for _ in range(4)]})
        api.run_autonomy_if_due()
        esc = [r for r in self._receipts() if r['verdict'] == autonomy.ESCALATE]
        self.assertTrue(esc, f'nothing escalated: {self._receipts()}')
        self.assertIn('approval', str(esc[0].get('outcome')))
        self.assertTrue(esc[0].get('confirmation_id'),
                        'no confirmation id — the approval is not in the ledger')
        pend = api.load(api.CONFIRMATIONS_FILE) or {}
        blob = repr(pend)
        self.assertIn(esc[0]['confirmation_id'], blob,
                      'the id is in the receipt but not in the confirmations '
                      'store, so no admin can act on it')


class TestEventsWithoutAnAnalysisAreNeverCandidates(_Base):

    UNMAPPED = 'smart_failure'

    def test_the_unmapped_event_is_a_real_one(self):
        """Otherwise the test below proves only that a typo is ignored, which
        it would be either way. `cve_found` used to be used here and has since
        been mapped to `patch` — the test would have kept passing while
        measuring nothing."""
        import autonomy_ops_handlers as _ops
        self.assertIn(self.UNMAPPED, api.EVENT_REGISTRY)
        self.assertNotIn(self.UNMAPPED, _ops._EVENT_ACTIONS)

    def test_an_unmapped_event_is_ignored(self):
        """Default deny at the trigger layer too: the loop cannot invent an
        action for a signal nobody analysed."""
        self._alert(event=self.UNMAPPED)
        self._policy('shadow')
        api.run_autonomy_if_due()
        self.assertEqual(self._receipts(), [])

    def test_resolved_and_acked_alerts_are_skipped(self):
        self._policy('shadow')
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'r', 'event': 'failed_unit', 'device_id': 'd1',
             'resolved_at': int(time.time()), 'payload': {}},
            {'id': 'k', 'event': 'failed_unit', 'device_id': 'd1',
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
