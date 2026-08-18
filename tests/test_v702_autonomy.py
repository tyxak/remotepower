#!/usr/bin/env python3
"""v7.0.2 — why the loop refused everything, and what it does now.

Reported from a live instance: the Autonomy page held 22 receipts, every one a
refusal, and not a single shadow verdict in weeks of sweeps. Four separate
causes, each of which this file pins:

1. **Precedent could not accumulate.** `precedent_confidence` only counted an
   outcome that carried a `recommended_action`, which is filled from an AI triage
   verdict and nothing else. With AI off — the default — confidence was 0.0 for
   any number of prior incidents. Worse than neutral: an operator-sourced outcome
   is weighted DOUBLE, so a fleet whose incidents people fix scored LOWER than a
   fleet with no memory at all.

2. **Nothing recorded a fix that worked.** Two sweeps computed exactly that and
   kept only the failure half.

3. **The maintenance-window gate had never run.** The loop called
   `A._in_maintenance_window` behind a `hasattr` guard, and no such function
   exists, so a ticked checkbox did nothing.

4. **`no_verified_backup` on actions a backup has nothing to do with.**

Plus the parameter-alias hazard found on the way: `name` was an alias for every
resource parameter, and every payload in this codebase uses `name` for the
DEVICE.

Each test drives the real path. A receipt hand-built as a dict would bypass the
whitelists and the coalesce identity, which is the false-green this project has
been bitten by before.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702-'))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_v702', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import autonomy  # noqa: E402
import autonomy_ops_handlers as ops  # noqa: E402

# api.py execs its OWN private instance of the ops module, so this second import
# is a different object whose `A` proxy is None until bound. Without this every
# helper below raises AttributeError on None, which reads as a broken helper
# rather than an unbound module.
ops.bind(vars(api))

_STORES = ('DEVICES_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'SERVICES_FILE',
           'LLDP_NEIGHBORS_FILE', 'BACKUP_JOBS_FILE', 'AUTONOMY_POLICY_FILE',
           'AUTONOMY_RECEIPTS_FILE', 'CMDS_FILE', 'INCIDENT_MEMORY_FILE',
           'TENANTS_FILE', 'USERS_FILE', 'MAINT_FILE', 'REMEDIATIONS_FILE',
           'RULES_FILE', 'AUDIT_LOG_FILE')


def _iso(offset):
    import datetime
    return datetime.datetime.fromtimestamp(
        time.time() + offset, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class _Base(unittest.TestCase):

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-v702-'))
        self._saved = {}
        for n in _STORES:
            if hasattr(api, n):
                self._saved[n] = getattr(api, n)
                setattr(api, n, self.d / f'{n.lower()}.json')
        self._mitigate = api.MITIGATE_LOGS_DIR
        api.MITIGATE_LOGS_DIR = self.d / 'mitigate_logs'
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, {'autonomy_enabled': True})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web01', 'group': 'prod'}})

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api.MITIGATE_LOGS_DIR = self._mitigate
        api._LOAD_CACHE.clear()

    # ── helpers ──────────────────────────────────────────────────────────────
    def _policy(self, mode='shadow', tenant='default', **over):
        p = autonomy.default_policy()
        p['mode'] = mode
        p['max_blast_radius'] = 99
        p.update(over)
        api.save(api.AUTONOMY_POLICY_FILE, {'tenants': {tenant: p}})
        api._LOAD_CACHE.clear()

    def _alert(self, event='failed_unit', payload=None, dev='d1'):
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': event, 'device_id': dev, 'severity': 'high',
            'payload': payload if payload is not None else {'unit': 'nginx.service'},
        }]})
        api._LOAD_CACHE.clear()

    def _run(self):
        api.save(api.AUTONOMY_RECEIPTS_FILE, {'receipts': [], 'last_run': 0})
        api._LOAD_CACHE.clear()
        api.run_autonomy_if_due()
        return (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []

    def _verdict(self):
        rows = self._run()
        self.assertEqual(len(rows), 1, rows)
        return rows[0]['verdict'], rows[0]['reason']

    def _memory(self, n, **over):
        """n prior outcomes for failed_unit, operator-sourced, no AI field."""
        row = {'source': 'operator', 'event': 'failed_unit', 'kind': '',
               'tenant': 'default', 'resolution': 'resolved by alice',
               'root_cause': 'restarted nginx and it came back',
               'recommended_action': ''}
        row.update(over)
        api.save(api.INCIDENT_MEMORY_FILE, {'outcomes': [dict(row) for _ in range(n)]})
        api._LOAD_CACHE.clear()


class TestPrecedentCountsWhatAPersonWroteDown(unittest.TestCase):
    """The arithmetic, in isolation from any store."""

    def test_operator_notes_count_as_evidence(self):
        rows = [{'source': 'operator', 'resolution': 'resolved by alice',
                 'root_cause': 'restarted nginx', 'recommended_action': ''}] * 2
        conf, samples, action = autonomy.precedent_confidence(rows)
        self.assertEqual(samples, 2)
        self.assertEqual(conf, 1.0,
                         'an operator-resolved fleet scored 0.0 and refused with '
                         'low_confidence forever')
        self.assertEqual(action, 'restarted nginx')

    def test_a_fix_command_is_the_strongest_source(self):
        rows = [{'source': 'rule', 'resolution': 'cleared',
                 'fix_command': 'svc:restart:nginx',
                 'root_cause': 'ignored', 'recommended_action': 'also ignored'}]
        self.assertEqual(autonomy.precedent_confidence(rows)[2], 'svc:restart:nginx')

    def test_an_outcome_recording_nothing_still_counts_for_nothing(self):
        """Negative control. Widening the rule must not make every row evidence."""
        rows = [{'source': 'operator', 'resolution': 'auto-resolved',
                 'root_cause': '', 'recommended_action': ''}]
        self.assertEqual(autonomy.precedent_confidence(rows)[0], 0.0)

    def test_an_ai_row_does_not_get_the_operator_fallback(self):
        """`root_cause` counts only where a person wrote it. An AI-authored root
        cause with no recommended action is an observation, not a fix."""
        rows = [{'source': 'ai', 'resolution': 'x', 'root_cause': 'disk full',
                 'recommended_action': ''}]
        self.assertEqual(autonomy.precedent_confidence(rows)[0], 0.0)

    def test_the_operator_weighting_still_favours_the_human(self):
        ai = [{'source': 'ai', 'resolution': 'x', 'recommended_action': 'restart'}]
        human = [{'source': 'operator', 'resolution': 'x', 'root_cause': 'restart'}]
        bad = [{'source': 'ai', 'resolution': '', 'recommended_action': ''}]
        self.assertGreater(autonomy.precedent_confidence(human + bad)[0],
                           autonomy.precedent_confidence(ai + bad)[0])


class TestAFixThatWorkedBecomesPrecedent(_Base):

    def test_it_stores_one_outcome_and_only_one(self):
        self.assertTrue(api.capture_fix_outcome(
            alert_id='al-1', event='failed_unit', device_id='d1',
            device_name='web01', tenant='default', actor='alice',
            fix_command='svc:restart:nginx.service', source='operator'))
        self.assertFalse(api.capture_fix_outcome(
            alert_id='al-1', event='failed_unit', device_id='d1'),
            'a second sweep over the same alert must not add a second outcome — '
            'MIN_PRECEDENT_SAMPLES is 2, so that would satisfy "two prior '
            'incidents" on the strength of one')
        rows = (api.load(api.INCIDENT_MEMORY_FILE) or {}).get('outcomes') or []
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['source'], 'operator')
        self.assertEqual(rows[0]['fix_command'], 'svc:restart:nginx.service')

    def test_a_rule_fix_is_not_badged_as_a_person(self):
        """The incident-memory card badges anything non-operator as "AI" and
        precedent_confidence weights `operator` double."""
        api.capture_fix_outcome(alert_id='al-2', event='failed_unit',
                                device_id='d1', source='rule',
                                fix_command='automation rule Restart nginx')
        rows = (api.load(api.INCIDENT_MEMORY_FILE) or {}).get('outcomes') or []
        self.assertEqual(rows[0]['source'], 'rule')

    def test_an_outcome_with_no_event_is_refused(self):
        self.assertFalse(api.capture_fix_outcome(
            alert_id='al-3', event='', device_id='d1'))

    def test_two_of_them_satisfy_the_evidence_gate(self):
        """End to end: the point of the whole change."""
        for i in (1, 2):
            api.capture_fix_outcome(
                alert_id=f'al-{i}', event='failed_unit', device_id='d1',
                tenant='default', fix_command='svc:restart:nginx.service',
                source='operator', actor='alice')
        api._LOAD_CACHE.clear()
        similar = api._similar_incidents(
            'failed_unit', api.EVENT_KIND_MAP.get('failed_unit'), 'default')
        conf, samples, _a = autonomy.precedent_confidence(similar)
        self.assertEqual(samples, 2)
        self.assertGreaterEqual(conf, autonomy.MIN_PRECEDENT_CONFIDENCE)


class TestTheOperatorFixSweepRecordsTheSuccess(_Base):
    """`run_mitigate_verify_if_due` knew the answer and threw it away."""

    def _queued_fix(self, alert_id='a1', ago=1000):
        api.MITIGATE_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        import json
        meta = api.MITIGATE_LOGS_DIR / 'd1__abc123.meta.json'
        meta.write_text(json.dumps({
            'kind': 'service', 'target': 'nginx', 'phase': 'fix',
            'destructive': False, 'queued_at': int(time.time()) - ago,
            'actor': 'alice', 'cmd': 'systemctl restart nginx',
            'alert_id': alert_id, 'device_id': 'd1'}))
        return meta

    def _sweep(self):
        api.save(api.CONFIG_FILE, {'autonomy_enabled': True,
                                   'last_mitigate_verify': 0})
        api._LOAD_CACHE.clear()
        api.run_mitigate_verify_if_due()
        return (api.load(api.INCIDENT_MEMORY_FILE) or {}).get('outcomes') or []

    def test_a_cleared_alert_becomes_precedent(self):
        self._queued_fix()
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'severity': 'high', 'resolved_at': int(time.time())}]})
        rows = self._sweep()
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]['event'], 'failed_unit',
                         'the event comes off the ALERT — the mitigation meta '
                         'only knows the playbook kind')
        self.assertEqual(rows[0]['source'], 'operator')
        self.assertIn('systemctl restart nginx', rows[0]['fix_command'])

    def test_an_alert_that_stayed_open_records_nothing(self):
        """Positive control in the other direction: without this, a sweep that
        recorded EVERY fix would pass the test above."""
        self._queued_fix()
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'severity': 'high'}]})
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None, **kw: fired.append(ev)
        try:
            rows = self._sweep()
        finally:
            api.fire_webhook = real
        self.assertEqual(rows, [])
        self.assertEqual(fired, ['mitigation_unverified'])


class TestTheRuleRemediationSweepRecordsItToo(_Base):

    def test_a_verified_attempt_becomes_precedent(self):
        now = int(time.time())
        api.save(api.REMEDIATIONS_FILE, {'attempts': [{
            'id': 'rem-1', 'ts': now - 600, 'rule_id': 'r1',
            'rule_name': 'Restart nginx', 'device_id': 'd1',
            'device_name': 'web01', 'event': 'failed_unit',
            'script_id': 's1', 'status': 'queued', 'verify_at': now - 10,
        }], 'last_verify': 0})
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a9', 'event': 'failed_unit', 'device_id': 'd1',
            'severity': 'high', 'resolved_at': now - 5}]})
        api.save(api.RULES_FILE, {'rules': [{'id': 'r1', 'enabled': True}]})
        api._LOAD_CACHE.clear()
        self.assertIn('failed_unit', api._AUTO_RESOLVABLE_EVENTS,
                      'an event outside this set is marked unverifiable and '
                      'never reaches the branch under test')
        api.run_remediation_verify_if_due()
        rows = (api.load(api.INCIDENT_MEMORY_FILE) or {}).get('outcomes') or []
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]['source'], 'rule')
        self.assertEqual(rows[0]['alert_id'], 'a9',
                         'keyed on the real alert id, so the note harvester '
                         'cannot record the same incident a second time')


class TestTheLoopsOwnVerifiedActionsCount(_Base):
    """The third precedent source, and the strictest: it acted, the host's own
    checks did not get worse, AND the alert it was triggered by closed."""

    def _acted(self, alert_id='a1', before_failing=9):
        now = int(time.time())
        api.save(api.AUTONOMY_RECEIPTS_FILE, {'receipts': [{
            'id': 'rcpt_1', 'ts': now - 5000, 'tenant': 'default',
            'device_id': 'd1', 'device_name': 'web01', 'trigger': 'failed_unit',
            'alert_id': alert_id, 'action': 'restart_service',
            'command': 'svc:restart:nginx.service', 'verdict': autonomy.ACT,
            'reason': 'ok', 'outcome': 'queued', 'verified': None,
            'verify_due': now - 1, 'before_checks': {'failing': before_failing},
        }], 'last_run': 0})
        api._LOAD_CACHE.clear()
        return now

    def _outcomes(self):
        return (api.load(api.INCIDENT_MEMORY_FILE) or {}).get('outcomes') or []

    def test_a_receipt_carries_the_alert_it_came_from(self):
        """Without this the standard below cannot be applied at all."""
        plan = ops._build_plan({'event': 'failed_unit', 'id': 'a1',
                                'payload': {'unit': 'nginx.service'}},
                               'restart_service', {'os': 'Debian 12'}, 'd1',
                               {'score': 0}, '')
        rec = autonomy.receipt(plan, autonomy.Decision(verdict='act', reason='ok'))
        self.assertEqual(rec['alert_id'], 'a1')

    def test_a_verified_action_whose_alert_cleared_becomes_precedent(self):
        self._acted()
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'resolved_at': int(time.time())}]})
        api._LOAD_CACHE.clear()
        api._verify_due_receipts(int(time.time()))
        rows = self._outcomes()
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]['source'], 'autonomy')
        self.assertEqual(rows[0]['fix_command'], 'svc:restart:nginx.service')

    def test_an_alert_still_open_is_not_a_fix(self):
        """Stricter than `verified`. Checks-did-not-worsen on its own would let
        an action that changed nothing count as evidence that it works."""
        self._acted()
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1'}]})
        api._LOAD_CACHE.clear()
        api._verify_due_receipts(int(time.time()))
        self.assertIs((api.load(api.AUTONOMY_RECEIPTS_FILE) or {})
                      ['receipts'][0]['verified'], True,
                      'the receipt still verifies — only the precedent is withheld')
        self.assertEqual(self._outcomes(), [])

    def test_an_action_that_made_things_worse_records_nothing(self):
        self._acted(before_failing=0)
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'resolved_at': int(time.time())}]})
        api._LOAD_CACHE.clear()
        real_sum, real_fire = api._host_check_summary, api.fire_webhook
        api._host_check_summary = lambda checks: {
            'counts': {'ok': 0, 'warning': 0, 'critical': 3, 'unknown': 0},
            'worst': 'critical', 'total': 3}
        api.fire_webhook = lambda *a, **k: None
        try:
            api._verify_due_receipts(int(time.time()))
        finally:
            api._host_check_summary, api.fire_webhook = real_sum, real_fire
        self.assertEqual(self._outcomes(), [])


class TestABackupIsNotWhatMakesEveryActionSafe(_Base):

    def _decide(self, action, **over):
        pol = autonomy.normalize_policy({
            'mode': 'enabled', 'allowed_actions': [action],
            'max_blast_radius': 99, 'require_window': False,
            'approval_for_destructive': False, **over})
        return autonomy.decide(
            action=action, policy=pol, module_enabled=True, tenant_ok=True,
            radius={'score': 0}, precedent_conf=1.0, precedent_samples=9,
            backup_verified=False, os_family='linux')

    def test_restarting_networking_no_longer_asks_for_a_restore_drill(self):
        self.assertEqual(self._decide('restart_networking').verdict, autonomy.ACT)

    def test_patching_still_does(self):
        d = self._decide('patch')
        self.assertEqual(d.verdict, autonomy.REFUSE)
        self.assertEqual(d['reason'], 'no_verified_backup')

    def test_remounting_read_only_still_does(self):
        self.assertEqual(self._decide('remount_rw')['reason'], 'no_verified_backup')

    def test_an_action_class_that_forgets_the_key_gets_the_strict_default(self):
        """Fail-safe: absent means `destructive`."""
        autonomy.ACTION_CLASSES['_probe'] = {
            'destructive': True, 'default_allowed': False,
            'platforms': ('linux',), 'label': 'probe'}
        try:
            self.assertEqual(self._decide('_probe')['reason'], 'no_verified_backup')
        finally:
            autonomy.ACTION_CLASSES.pop('_probe')

    def test_every_class_that_can_lose_data_declares_it(self):
        for name in ('remount_rw', 'reboot', 'patch', 'rotate_credential'):
            self.assertTrue(autonomy.ACTION_CLASSES[name]['requires_backup'], name)
        for name in ('kill_process', 'restart_networking', 'enable_firewall',
                     'shutdown_host'):
            self.assertFalse(autonomy.ACTION_CLASSES[name]['requires_backup'], name)


class TestTheWindowGateActuallyRuns(_Base):
    """It called a function that does not exist, behind a hasattr guard."""

    def test_there_is_no_such_helper_to_call(self):
        self.assertFalse(hasattr(api, '_in_maintenance_window'),
                         'if this ever exists, the loop should probably use it')

    def _window(self, **over):
        w = {'id': 'w1', 'scope': 'device', 'target': 'd1', 'gate_exec': True,
             'start': _iso(7200), 'end': _iso(10800)}
        w.update(over)
        api.save(api.MAINT_FILE, {'windows': [w]})
        api._LOAD_CACHE.clear()

    def setUp(self):
        super().setUp()
        self._alert()
        self._policy(require_precedent=False)

    def test_no_windows_at_all_holds_nothing(self):
        self.assertEqual(self._verdict(), ('shadow', 'ok'))

    def test_a_closed_change_window_refuses(self):
        self._window()
        self.assertEqual(self._verdict(), ('refuse', 'outside_window'))

    def test_an_open_change_window_does_not(self):
        self._window(start=_iso(-600), end=_iso(3600))
        self.assertEqual(self._verdict(), ('shadow', 'ok'))

    def test_a_plain_maintenance_window_is_not_a_change_window(self):
        """A window without change gating means "expect noise from this host",
        not "only touch it now". Reading it the other way would make the loop
        act precisely when nobody is watching the alerts."""
        self._window(gate_exec=False)
        self.assertEqual(self._verdict(), ('shadow', 'ok'))

    def test_the_setting_can_be_switched_off(self):
        self._window()
        self._policy(require_precedent=False, require_window=False)
        self.assertEqual(self._verdict(), ('shadow', 'ok'))

    def test_a_numeric_window_start_does_not_raise(self):
        """`_window_active` catches only ValueError, so a non-string start used
        to raise AttributeError out of the maintenance check and into the
        heartbeat's command dispatch."""
        self._window(start=int(time.time()) + 7200, end=int(time.time()) + 10800)
        self.assertEqual(self._verdict(), ('refuse', 'outside_window'))


class TestThePrecedentWaiver(_Base):

    def setUp(self):
        super().setUp()
        self._alert()

    def test_the_default_still_asks_for_precedent(self):
        self._policy()
        self.assertEqual(self._verdict(), ('refuse', 'no_precedent'))

    def test_waiving_it_reaches_a_verdict(self):
        self._policy(require_precedent=False)
        self.assertEqual(self._verdict(), ('shadow', 'ok'))

    def test_waiving_it_does_not_leave_a_second_door_shut(self):
        """Two weak priors used to refuse with `low_confidence` regardless, so
        turning the knob off swapped one refusal for another."""
        self._memory(2, resolution='', root_cause='')
        self._policy(require_precedent=False)
        self.assertEqual(self._verdict(), ('shadow', 'ok'))

    def test_a_waiver_cannot_manufacture_a_command(self):
        """`has_plan` means a CONCRETE command from the catalog. An alert that
        names no unit still has nothing to run."""
        self._alert(payload={'name': 'web01'})
        self._policy(require_precedent=False)
        self.assertEqual(self._verdict(), ('refuse', 'missing_parameter'))

    def test_operator_written_precedent_alone_is_enough(self):
        """The whole complaint, in one test: no AI, no waiver, two prior fixes
        an operator wrote down — and the loop reaches a verdict."""
        self._memory(2)
        self._policy()
        self.assertEqual(self._verdict(), ('shadow', 'ok'))

    def test_the_knob_survives_a_real_policy_save(self):
        """The save-whitelist class: a Settings toggle that silently does not
        persist reads exactly like a broken feature."""
        cap = {}

        def _respond(status, data=None):
            cap['status'], cap['data'] = status, data
            raise api.HTTPError(status, data)
        saved = (api.respond, api.method, api.get_json_obj,
                 api.require_admin_auth, api.audit_log)
        api.respond = _respond
        api.method = lambda: 'PUT'
        api.get_json_obj = lambda: {'policy': {
            'mode': 'shadow', 'require_precedent': False,
            'allowed_actions': ['restart_service']}}
        api.require_admin_auth = lambda *a, **k: 'alice'
        api.audit_log = lambda *a, **k: None
        try:
            try:
                api.handle_autonomy_policy()
            except api.HTTPError:
                pass
        finally:
            (api.respond, api.method, api.get_json_obj,
             api.require_admin_auth, api.audit_log) = saved
        api._LOAD_CACHE.clear()
        stored = (api.load(api.AUTONOMY_POLICY_FILE) or {}).get('tenants', {})
        self.assertIs(stored['default']['require_precedent'], False, stored)


class TestTheNewActionsProduceRealCommands(_Base):

    CASES = (
        ('mount_issue', 'remount_all', {'path': '/srv'}, 'Debian 12',
         'exec:mount -a'),
        ('autoupdate_disabled', 'enable_autoupdates', {'detail': 'x'}, 'Debian 12',
         'exec:systemctl enable --now unattended-upgrades.service'),
        ('av_realtime_off', 'enable_av_realtime', {'tool': 'defender'},
         'Windows Server 2022', 'ps:Set-MpPreference -DisableRealtimeMonitoring $false'),
        ('mac_gatekeeper_off', 'enable_gatekeeper', {'detail': 'x'}, 'macOS 14',
         'exec:spctl --master-enable'),
        ('ups_critical', 'shutdown_host', {'ups': 'apc'}, 'Debian 12', 'shutdown'),
        ('resolver_unhealthy', 'flush_dns_cache', {'detail': 'x'}, 'Debian 12',
         'exec:resolvectl flush-caches'),
    )

    def test_each_builds_the_command_it_claims(self):
        for event, action, payload, osname, expect in self.CASES:
            plan = ops._build_plan({'event': event, 'payload': payload}, action,
                                   {'os': osname}, 'd1', {'score': 0}, '')
            self.assertIsNone(plan['problem'], f'{event}: {plan}')
            self.assertTrue(plan['command'].startswith(expect),
                            f'{event}: {plan["command"]!r}')

    def test_each_event_maps_to_the_action_under_test(self):
        """Control: without this the case table could drift away from the
        catalog and still pass, because _build_plan takes the action directly."""
        for event, action, *_rest in self.CASES:
            self.assertIn(action, ops._EVENT_ACTIONS.get(event, ()), event)

    def test_the_gentler_dns_rung_comes_first(self):
        self.assertEqual(ops._EVENT_ACTIONS['resolver_unhealthy'][0],
                         'flush_dns_cache')


class TestTheDeviceNameIsNeverAResourceName(_Base):
    """`name` was an alias for {unit}, {container}, {process}, {mount}, {pool}
    and every payload here uses it for the DEVICE."""

    def test_no_alias_chain_reaches_the_device_name(self):
        for field, aliases in ops._ACTION_PARAMS.items():
            self.assertNotIn('name', aliases, field)
            self.assertNotIn('label', aliases, field)

    def test_the_loop_refuses_rather_than_aiming_at_the_host(self):
        self._alert(payload={'name': 'web01'})
        self._policy(require_precedent=False)
        rows = self._run()
        self.assertEqual(rows[0]['reason'], 'missing_parameter')
        self.assertEqual(rows[0]['command'], '')
        self.assertEqual((api.load(api.CMDS_FILE) or {}).get('d1') or [], [])

    def test_the_scrub_payload_key_is_the_one_the_event_sends(self):
        """`scrub_overdue` fires {'pool': …}; the alias list asked for `disk`."""
        cmd, prob = ops._resolve_params('exec:zpool scrub -- {pool}',
                                        {'pool': 'tank', 'name': 'web01'}, 'd1')
        self.assertIsNone(prob)
        self.assertEqual(cmd, 'exec:zpool scrub -- tank')


class TestReceiptsCanBeCleared(_Base):

    def setUp(self):
        super().setUp()
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        self._saved_fns = {n: getattr(api, n) for n in
                           ('respond', 'method', 'audit_log',
                            'get_token_from_request', 'verify_token')}
        api.respond = _respond
        api.method = lambda: 'DELETE'
        self.audit = []
        api.audit_log = lambda *a, **k: self.audit.append((a, k))
        api.get_token_from_request = lambda: 'tok'
        api.save(api.AUTONOMY_RECEIPTS_FILE, {'receipts': [
            {'id': 'r1', 'tenant': 'default', 'verdict': 'refuse',
             'reason': 'no_precedent'},
            {'id': 'r2', 'tenant': 'default', 'verdict': 'act', 'verified': None,
             'verify_due': int(time.time()) + 900},
            {'id': 'r3', 'tenant': 'other', 'verdict': 'shadow'},
        ], 'last_run': 12345})
        api._LOAD_CACHE.clear()
        self._qs = os.environ.get('QUERY_STRING')
        os.environ['QUERY_STRING'] = ''

    def tearDown(self):
        for n, v in self._saved_fns.items():
            setattr(api, n, v)
        if self._qs is None:
            os.environ.pop('QUERY_STRING', None)
        else:
            os.environ['QUERY_STRING'] = self._qs
        super().tearDown()

    def _as(self, role):
        api.verify_token = lambda _t=None, _r=role: ('u_' + _r, _r)

    def _call(self, qs=''):
        os.environ['QUERY_STRING'] = qs
        self.cap.clear()
        try:
            api.handle_autonomy_receipts_clear()
            return 200
        except api.HTTPError:
            return self.cap.get('status')

    def _rows(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []

    def test_a_read_only_role_cannot_clear(self):
        """Only verify_token is stubbed — stubbing require_admin_auth would pass
        a handler with no gate at all."""
        for role in ('viewer', 'mcp', 'auditor', 'finance'):
            self._as(role)
            self.assertEqual(self._call(), 403, role)
        self.assertEqual(len(self._rows()), 3)

    def test_an_admin_clears_only_their_own_tenant(self):
        self._as('admin')
        real = api._tenant_gate
        api._tenant_gate = lambda: 'default'
        try:
            self.assertEqual(self._call(), 200)
        finally:
            api._tenant_gate = real
        self.assertEqual([r['id'] for r in self._rows()], ['r3'])
        self.assertEqual(self.cap['data']['removed'], 2)
        self.assertEqual(self.cap['data']['awaiting_verification'], 1,
                         'deleting a row that still owes a verification sample '
                         'drops the second half of its measurement — say so')

    def test_another_tenants_receipt_is_not_found_rather_than_deleted(self):
        self._as('admin')
        real = api._tenant_gate
        api._tenant_gate = lambda: 'default'
        try:
            self.assertEqual(self._call('id=r3'), 404)
        finally:
            api._tenant_gate = real
        self.assertEqual(len(self._rows()), 3)

    def test_one_row_by_id(self):
        self._as('admin')
        self.assertEqual(self._call('id=r1'), 200)
        self.assertEqual(sorted(r['id'] for r in self._rows()), ['r2', 'r3'])

    def test_the_sweep_cadence_marker_survives(self):
        """Resetting last_run would make the next request re-evaluate every
        open alert."""
        self._as('admin')
        self._call()
        self.assertEqual((api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('last_run'),
                         12345)

    def test_the_clear_is_audited_with_its_counts(self):
        self._as('admin')
        self._call()
        self.assertTrue(self.audit, 'an unaudited wipe of the decision ledger')
        detail = str(self.audit[-1])
        self.assertIn('autonomy_receipts_clear', detail)
        self.assertIn('removed=3', detail)

    def test_the_route_is_wired(self):
        routes = api._build_exact_routes()
        self.assertIn(('DELETE', '/api/autonomy/receipts'), routes)
        self.assertIs(routes[('DELETE', '/api/autonomy/receipts')],
                      api.handle_autonomy_receipts_clear)


if __name__ == '__main__':
    unittest.main()
