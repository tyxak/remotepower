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
           'RULES_FILE', 'AUDIT_LOG_FILE', 'CMD_OUTPUT_FILE',
           # The escalation tests COUNT rows here. Without the redirect they
           # count whatever any other test in this process left behind, which
           # is the shared-store class CLAUDE.md records — it read as a dedupe
           # that half worked.
           'CONFIRMATIONS_FILE')


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

    def test_a_purged_alert_is_not_evidence_that_the_fix_worked(self):
        """"Cleared" is inferred from the alert not being in the OPEN set, and an
        alert removed by retention, an inbox clear or the 5000-row cap is also
        not in that set. Good enough to decide whether to warn the operator; not
        good enough to become durable evidence that an action works.

        What stops it is that a purged alert has no row to read an event off,
        and capture_fix_outcome refuses an outcome that names no event. Two
        guards written for this during review turned out to change nothing —
        mutating each left this test green, which is how they were found — and
        both were removed rather than left looking load-bearing. What is pinned
        here is the OUTCOME, not any one link."""
        self._queued_fix()
        api.save(api.ALERTS_FILE, {'alerts': []})     # the row is gone entirely
        api._LOAD_CACHE.clear()
        self.assertEqual(self._sweep(), [])

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

    def _agent_reported(self, rc=0, cmd='svc:restart:nginx.service'):
        """The agent's own answer for the command, which is what makes an
        action's success a fact rather than an inference."""
        api.save(api.CMD_OUTPUT_FILE, {'d1': [
            {'ts': int(time.time()), 'cmd': cmd, 'output': 'ok', 'rc': rc}]})
        api._LOAD_CACHE.clear()

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
        self._agent_reported(rc=0)
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'resolved_at': int(time.time())}]})
        api._LOAD_CACHE.clear()
        api._verify_due_receipts(int(time.time()))
        rows = self._outcomes()
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]['source'], 'autonomy')
        self.assertEqual(rows[0]['fix_command'], 'svc:restart:nginx.service')

    def test_a_command_the_agent_never_ran_is_not_a_fix(self):
        """No report at all means the host never collected it — offline, or its
        poll interval outran the window. An alert that cleared on its own in the
        meantime is not evidence about a command that never ran."""
        self._acted()
        api.save(api.CMD_OUTPUT_FILE, {})
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'resolved_at': int(time.time())}]})
        api._LOAD_CACHE.clear()
        api._verify_due_receipts(int(time.time()))
        self.assertEqual(self._outcomes(), [])
        rec = (api.load(api.AUTONOMY_RECEIPTS_FILE) or {})['receipts'][0]
        self.assertIsNone(rec['rc'])
        self.assertIn('no result from the agent', rec['outcome'])

    def test_a_command_that_exited_non_zero_is_not_a_fix(self):
        """Four of the catalog's actions are one-liners whose only failure
        signal is the exit code. A command that exits 127 because the tool is
        not installed and one that worked used to produce identical receipts."""
        self._acted()
        self._agent_reported(rc=127)
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'resolved_at': int(time.time())}]})
        api._LOAD_CACHE.clear()
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None, **kw: fired.append((ev, payload))
        try:
            api._verify_due_receipts(int(time.time()))
        finally:
            api.fire_webhook = real
        self.assertEqual(self._outcomes(), [])
        rec = (api.load(api.AUTONOMY_RECEIPTS_FILE) or {})['receipts'][0]
        self.assertEqual(rec['rc'], 127)
        self.assertIs(rec['verified'], False)
        self.assertIn('exited 127', rec['outcome'])
        self.assertEqual([e for e, _p in fired], ['remediation_failed'])
        self.assertIn('127', str(fired[0][1].get('detail')))

    def test_a_result_from_before_the_dispatch_does_not_count(self):
        """A host runs the same command more than once over its life, and the
        previous run's success is not evidence about this one."""
        now = self._acted()
        api.save(api.CMD_OUTPUT_FILE, {'d1': [
            {'ts': now - 99999, 'cmd': 'svc:restart:nginx.service',
             'output': 'ok', 'rc': 0}]})
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'resolved_at': int(time.time())}]})
        api._LOAD_CACHE.clear()
        api._verify_due_receipts(int(time.time()))
        self.assertEqual(self._outcomes(), [])

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
        for name in ('kill_process', 'restart_networking', 'enable_firewall'):
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
        ('av_realtime_off', 'enable_av_realtime', {'tool': 'defender'},
         'Windows Server 2022', 'ps:Set-MpPreference -DisableRealtimeMonitoring $false'),
        ('mac_gatekeeper_off', 'enable_gatekeeper', {'detail': 'x'}, 'macOS 14',
         'exec:spctl --master-enable'),
        ('disk_predict_fail', 'clear_tmp', {}, 'Debian 12',
         'exec:systemd-tmpfiles --clean'),
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

    def test_no_action_is_mapped_to_an_event_that_names_no_device(self):
        """The sweep resolves a device before it does anything else, so a
        FLEET-SINGLETON event is a mapping it can never act on — and it fails
        silently, because the candidate is dropped before a receipt is written.

        Three rows were exactly that until v7.0.2. The set is checked against the
        payloads those events really fire with, not against a memory of them.
        """
        singletons = {
            'wan_down': "its own source comment says 'fleet singleton, no device_id'",
            'wan_up': 'same',
            'mailflow_delayed': 'a server-side mail round-trip, not a host',
            'mailflow_ok': 'same',
            'resolver_unhealthy': 'a server-side DNS check over operator targets',
            'resolver_recovered': 'same',
            'server_disk_low': "the CONTROLLER's own data directory — the payload "
                               "is {'target': 'server', 'name': 'RemotePower server'}",
            'server_disk_ok': 'same',
        }
        mapped = set(ops._EVENT_ACTIONS)
        self.assertEqual(sorted(mapped & set(singletons)), [],
                         'these events carry no device_id, so the loop can never '
                         'act on them:\n' + '\n'.join(
                             f'  {e}: {singletons[e]}'
                             for e in sorted(mapped & set(singletons))))

    def test_the_probe_would_notice(self):
        """Control: the set above must name events that EXIST, or the assertion
        is comparing two empty sets."""
        for name in ('wan_down', 'mailflow_delayed', 'resolver_unhealthy'):
            self.assertIn(name, api.EVENT_REGISTRY, name)


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


class TestTheWindowGateFailsClosed(_Base):
    """Every failure path in `_exec_gated` means ALLOW — right for the dispatch
    path, which holds rather than drops, and wrong here. This file's own
    blast-radius helper states the rule: a safety input that fails open is worse
    than no safety input."""

    def test_an_unreadable_window_store_holds(self):
        self._alert()
        self._policy(require_precedent=False)
        real = api._exec_gated
        api._exec_gated = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('boom'))
        try:
            self.assertEqual(self._verdict(), ('refuse', 'outside_window'))
        finally:
            api._exec_gated = real

    def test_and_a_readable_one_still_allows(self):
        """Control: fail-closed must not mean closed."""
        self._alert()
        self._policy(require_precedent=False)
        self.assertEqual(self._verdict(), ('shadow', 'ok'))


class TestPrecedentIsForThisEventNotItsKind(_Base):
    """`_similar_incidents` matches same-event OR same-KIND. Right for a triage
    tool showing a human related history; here it let a prior fix for one event
    justify acting on another that merely shares a kind — `service` alone pools
    service_down, unit_flapping and failed_unit, whose ladders differ."""

    def _other_event_precedent(self, event):
        api.save(api.INCIDENT_MEMORY_FILE, {'outcomes': [
            {'source': 'operator', 'event': event,
             'kind': api.EVENT_KIND_MAP.get(event), 'tenant': 'default',
             'resolution': 'fixed', 'fix_command': 'svc:restart:nginx.service'}
            for _ in range(4)]})
        api._LOAD_CACHE.clear()

    # kind `storage` pools these two, and their ladders could hardly differ
    # more: start a scrub, versus remount a filesystem the kernel forced
    # read-only. Chosen over the service pair because it is the pairing that
    # makes the consequence obvious.
    PRIOR, NOW = 'scrub_overdue', 'readonly_fs'

    def test_the_pair_really_shares_a_kind(self):
        """Control for the test below — an earlier draft used two events that do
        NOT share a kind, and would have passed while proving nothing."""
        self.assertEqual(api.EVENT_KIND_MAP.get(self.PRIOR),
                         api.EVENT_KIND_MAP.get(self.NOW))
        self.assertNotEqual(self.PRIOR, self.NOW)

    def test_a_sibling_event_in_the_same_kind_is_not_precedent(self):
        self._other_event_precedent(self.PRIOR)
        self._alert(event=self.NOW, payload={'paths': ['/srv']})
        self._policy(allowed_actions=['remount_rw'],
                     require_verified_backup=False)
        self.assertEqual(self._verdict(), ('refuse', 'no_precedent'))

    def test_the_same_event_still_is(self):
        """Control."""
        self._other_event_precedent(self.NOW)
        self._alert(event=self.NOW, payload={'paths': ['/srv']})
        self._policy(allowed_actions=['remount_rw'],
                     require_verified_backup=False)
        self.assertEqual(self._verdict(), ('shadow', 'ok'))


class TestTheHarvesterDoesNotBurnIdsItStoresNothingFor(_Base):
    """`seen` is the ring capture_fix_outcome dedups against. Marking an alert
    seen without storing an outcome meant a later, machine-checkable fix could
    never be recorded for it."""

    def _resolved_alert_with_an_empty_verdict(self):
        now = int(time.time())
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a7', 'event': 'failed_unit', 'device_id': 'd1',
            'severity': 'high', 'resolved_at': now,
            'ai_triage': {'verdict': {}},        # no root cause, no note
        }]})
        api.save(api.INCIDENT_MEMORY_FILE, {'outcomes': [], 'seen': [],
                                            'last_run': 0})
        api._LOAD_CACHE.clear()

    def test_an_alert_worth_nothing_yet_stays_capturable(self):
        self._resolved_alert_with_an_empty_verdict()
        api.run_incident_memory_if_due()
        mem = api.load(api.INCIDENT_MEMORY_FILE) or {}
        self.assertEqual(mem.get('outcomes') or [], [], 'nothing to store yet')
        self.assertNotIn('a7', mem.get('seen') or [],
                         'the id was burned, so the verified fix that arrives '
                         'later can never be recorded for it')
        self.assertTrue(api.capture_fix_outcome(
            alert_id='a7', event='failed_unit', device_id='d1',
            tenant='default', fix_command='svc:restart:nginx', source='autonomy'))

    def test_an_alert_worth_storing_is_still_deduped(self):
        """Control: the ring must still close an id once something IS stored."""
        now = int(time.time())
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a8', 'event': 'failed_unit', 'device_id': 'd1',
            'severity': 'high', 'resolved_at': now,
            'resolve_note': 'restarted nginx',
        }]})
        api.save(api.INCIDENT_MEMORY_FILE, {'outcomes': [], 'seen': [],
                                            'last_run': 0})
        api._LOAD_CACHE.clear()
        api.run_incident_memory_if_due()
        mem = api.load(api.INCIDENT_MEMORY_FILE) or {}
        self.assertEqual(len(mem.get('outcomes') or []), 1)
        self.assertIn('a8', mem.get('seen') or [])
        self.assertFalse(api.capture_fix_outcome(
            alert_id='a8', event='failed_unit', device_id='d1', source='autonomy'))


class TestTheVerifyWindowOutlastsThePollInterval(_Base):
    """A fixed 15 minutes against a device polling hourly guarantees the second
    checks sample is taken before the agent could have collected the command."""

    def test_a_slow_polling_host_gets_a_longer_window(self):
        self.assertEqual(ops._verify_delay_for({'poll_interval': 3600}), 7200)

    def test_a_normal_host_keeps_the_shipped_window(self):
        self.assertEqual(ops._verify_delay_for({'poll_interval': 60}),
                         ops._VERIFY_DELAY_S)
        self.assertEqual(ops._verify_delay_for({}), ops._VERIFY_DELAY_S)
        self.assertEqual(ops._verify_delay_for({'poll_interval': 'junk'}),
                         ops._VERIFY_DELAY_S)

    def test_the_receipt_uses_it(self):
        api.save(api.DEVICES_FILE,
                 {'d1': {'name': 'web01', 'group': 'prod', 'poll_interval': 3600}})
        self._alert()
        self._policy('enabled', allowed_actions=['restart_service'],
                     require_precedent=False, approval_for_destructive=False)
        rows = self._run()
        acted = [r for r in rows if r['verdict'] == autonomy.ACT]
        self.assertTrue(acted, rows)
        self.assertGreaterEqual(acted[0]['verify_due'] - acted[0]['ts'], 7200)


class TestEscalationDoesNotBecomeAStorm(_Base):
    """Fixing the backup gate made ESCALATE reachable for the first time, and
    the escalation path had never been exercised: the loop has no per-alert
    memory, re-evaluates every open candidate every five minutes, and an alert
    awaiting approval is still open by definition."""

    def _setup(self):
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'gateway_unreachable', 'device_id': 'd1',
            'severity': 'high', 'payload': {}}]})
        self._policy('enabled', allowed_actions=['restart_networking'],
                     require_precedent=False, approval_for_destructive=True)
        api._LOAD_CACHE.clear()

    def _sweep(self):
        api.save(api.AUTONOMY_RECEIPTS_FILE, {'receipts': [], 'last_run': 0})
        api._LOAD_CACHE.clear()
        api.run_autonomy_if_due()

    def _confirmations(self):
        st = api.load(api.CONFIRMATIONS_FILE) or {}
        return st.get('confirmations') or []

    def test_twelve_sweeps_park_one_confirmation(self):
        self._setup()
        for _ in range(12):
            self._sweep()
        pending = [c for c in self._confirmations() if c.get('status') == 'pending']
        self.assertEqual(len(pending), 1,
                         f'{len(pending)} confirmations for one open alert — an '
                         f'approval queue nobody can work through, and from the '
                         f'second hour an expiry alert for each')

    def test_the_receipt_says_it_is_already_waiting(self):
        self._setup()
        self._sweep()
        first = self._confirmations()[0]['id']
        self._sweep()
        rows = (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []
        self.assertTrue(rows, 'no receipt at all')
        self.assertIn('already awaiting approval', str(rows[0].get('outcome')))
        self.assertEqual(rows[0].get('confirmation_id'), first)

    def test_escalations_count_across_sweeps_too(self):
        """The ceiling has two halves — what this sweep has done, and what the
        stored receipts say the last hour did. Counting only ACT left the second
        half blind, so three escalations per sweep, every five minutes, all
        stayed under a ceiling of three.

        One host per sweep so the dedup above cannot be what stops it.
        """
        api.save(api.DEVICES_FILE, {f'd{i}': {'name': f'h{i}', 'group': 'prod'}
                                    for i in range(5)})
        self._policy('enabled', allowed_actions=['restart_networking'],
                     require_precedent=False, approval_for_destructive=True,
                     max_actions_per_hour=3)
        api.save(api.AUTONOMY_RECEIPTS_FILE, {'receipts': [], 'last_run': 0})
        seen = []
        for i in range(5):
            api.save(api.ALERTS_FILE, {'alerts': [{
                'id': f'a{i}', 'event': 'gateway_unreachable', 'device_id': f'd{i}',
                'severity': 'high', 'payload': {}}]})
            with api._LockedUpdate(api.AUTONOMY_RECEIPTS_FILE) as st:
                st['last_run'] = 0          # due again, receipts kept
            api._LOAD_CACHE.clear()
            api.run_autonomy_if_due()
            rows = (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []
            seen.append(rows[-1]['reason'] if rows else None)
        self.assertEqual(seen[:3], ['needs_approval'] * 3, seen)
        self.assertEqual(seen[3:], ['rate_limited', 'rate_limited'],
                         f'the ceiling is 3 and five sweeps escalated: {seen}')

    def test_the_in_sweep_counter_holds_too(self):
        """The other half: a flapping fleet produces its alerts all at once, so
        they land in ONE sweep."""
        api.save(api.DEVICES_FILE, {f'd{i}': {'name': f'h{i}', 'group': 'prod'}
                                    for i in range(8)})
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': f'a{i}', 'event': 'gateway_unreachable', 'device_id': f'd{i}',
            'severity': 'high', 'payload': {}} for i in range(8)]})
        self._policy('enabled', allowed_actions=['restart_networking'],
                     require_precedent=False, approval_for_destructive=True,
                     max_actions_per_hour=3)
        api._LOAD_CACHE.clear()
        self._sweep()
        rows = (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []
        esc = [r for r in rows if r['verdict'] == autonomy.ESCALATE]
        limited = [r for r in rows if r.get('reason') == 'rate_limited']
        self.assertEqual(len(esc), 3, f'ceiling is 3, {len(esc)} escalated')
        self.assertTrue(limited, 'the rest were not recorded as rate-limited')


class TestPrecedentNeedsAResolvedRowNotAnAbsentOne(_Base):
    """`_verify_due_receipts` passes the receipt's own `trigger` as the event,
    which is always populated — so unlike its sibling sweeps it has no accidental
    net when the alert row is simply GONE."""

    def _acted(self, alert_id='a1'):
        now = int(time.time())
        api.save(api.AUTONOMY_RECEIPTS_FILE, {'receipts': [{
            'id': 'rcpt_x', 'ts': now - 5000, 'tenant': 'default',
            'device_id': 'd1', 'device_name': 'web01', 'trigger': 'failed_unit',
            'alert_id': alert_id, 'action': 'restart_service',
            'command': 'svc:restart:nginx.service', 'verdict': autonomy.ACT,
            'reason': 'ok', 'outcome': 'queued', 'verified': None,
            'verify_due': now - 1, 'before_checks': {'failing': 9},
        }], 'last_run': 0})
        api._LOAD_CACHE.clear()

    def _outcomes(self):
        return (api.load(api.INCIDENT_MEMORY_FILE) or {}).get('outcomes') or []

    def test_an_admin_clearing_the_inbox_does_not_manufacture_precedent(self):
        self._acted()
        api.save(api.ALERTS_FILE, {'alerts': []})     # DELETE /api/alerts?scope=all
        api._LOAD_CACHE.clear()
        api._verify_due_receipts(int(time.time()))
        self.assertEqual(self._outcomes(), [],
                         'one admin clearing alerts turned an in-flight receipt '
                         'into precedent at confidence 1.0')

    def test_a_corrupt_store_does_not_either(self):
        self._acted()
        api.save(api.ALERTS_FILE, {})                 # load() gives {} on corruption
        api._LOAD_CACHE.clear()
        api._verify_due_receipts(int(time.time()))
        self.assertEqual(self._outcomes(), [])

    def test_a_genuinely_resolved_alert_still_counts(self):
        """Control: the guard must not refuse the case it exists to admit."""
        self._acted()
        api.save(api.CMD_OUTPUT_FILE, {'d1': [
            {'ts': int(time.time()), 'cmd': 'svc:restart:nginx.service',
             'output': 'ok', 'rc': 0}]})
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'resolved_at': int(time.time())}]})
        api._LOAD_CACHE.clear()
        api._verify_due_receipts(int(time.time()))
        self.assertEqual(len(self._outcomes()), 1, self._outcomes())


class TestTheWindowsScriptChannelsCanBeGated(unittest.TestCase):
    """`ps:` and `cmd:` run PowerShell and cmd.exe as SYSTEM — the Windows
    equivalent of `exec:` — and had no branch in `_command_kind`, so both
    classified as 'other'. 'other' is not in _APPROVAL_KINDS_ALL, so those
    commands could not be put behind the four-eyes gate even by an operator who
    wanted them there."""

    def test_they_classify_as_exec(self):
        self.assertEqual(api._command_kind('ps:Set-MpPreference -X $false'), 'exec')
        self.assertEqual(api._command_kind('cmd:ipconfig /flushdns'), 'exec')

    def test_and_exec_is_a_kind_the_gate_offers(self):
        self.assertIn('exec', api._APPROVAL_KINDS_ALL)

    def test_the_other_verbs_are_unchanged(self):
        for cmd, kind in (('exec:ls', 'exec'), ('reboot', 'reboot'),
                          ('svc:restart:nginx', 'service'),
                          ('container:docker:restart:web', 'container'),
                          ('upgrade', 'upgrade')):
            self.assertEqual(api._command_kind(cmd), kind, cmd)


class TestTheBackupGateCanActuallyBeSatisfied(_Base):
    """It read `BACKUP_JOBS_FILE[dev_id]['restore_drill']['ok']`. That store is
    `{'jobs': [ … ]}` — a list under one key — so the lookup is None on every
    fleet that has ever existed, and nothing anywhere writes a `restore_drill`
    field into it. `require_verified_backup` is on by default, so patch, reboot,
    remount_rw and rotate_credential were refused unconditionally, forever,
    with a reason telling the operator to go and drill their backups."""

    def _state(self, **rows):
        api.save(api.DATA_DIR / 'backup_state.json', rows)
        api._LOAD_CACHE.clear()

    def setUp(self):
        super().setUp()
        self._saved_dd = api.DATA_DIR
        api.DATA_DIR = self.d

    def tearDown(self):
        api.DATA_DIR = self._saved_dd
        super().tearDown()

    def test_a_recent_passing_drill_satisfies_it(self):
        now = int(time.time())
        self._state(**{'d1:/srv': {'drill_status': 'ok', 'drill_at': now - 3600}})
        self.assertTrue(ops._backup_is_verified('d1'))

    def test_nothing_recorded_does_not(self):
        self._state()
        self.assertFalse(ops._backup_is_verified('d1'))

    def test_a_failed_drill_does_not(self):
        now = int(time.time())
        self._state(**{'d1:/srv': {'drill_status': 'failed', 'drill_at': now}})
        self.assertFalse(ops._backup_is_verified('d1'))

    def test_a_two_year_old_drill_does_not(self):
        self._state(**{'d1:/srv': {'drill_status': 'ok',
                                   'drill_at': int(time.time()) - 700 * 86400}})
        self.assertFalse(ops._backup_is_verified('d1'))

    def test_another_hosts_drill_does_not(self):
        now = int(time.time())
        self._state(**{'d2:/srv': {'drill_status': 'ok', 'drill_at': now}})
        self.assertFalse(ops._backup_is_verified('d1'))

    def test_the_field_it_reads_is_the_one_the_heartbeat_writes(self):
        """The producer is api.py's restore_drills ingest. If the key names ever
        drift apart this goes back to being unsatisfiable, silently."""
        import inspect
        src = inspect.getsource(api.handle_heartbeat) if hasattr(
            api, 'handle_heartbeat') else (_CGI / 'api.py').read_text()
        for key in ("'drill_status'", "'drill_at'"):
            self.assertIn(key, src, key)

    def test_the_whole_gate_end_to_end(self):
        """The point: an action that needs a backup now CAN pass."""
        now = int(time.time())
        self._state(**{'d1:/srv': {'drill_status': 'ok', 'drill_at': now - 60}})
        self._alert(event='reboot_required', payload={})
        self._policy('shadow', allowed_actions=['reboot'],
                     require_precedent=False)
        self.assertEqual(self._verdict(), ('shadow', 'ok'))

    def test_and_still_refuses_without_one(self):
        """Control in the other direction."""
        self._state()
        self._alert(event='reboot_required', payload={})
        self._policy('shadow', allowed_actions=['reboot'],
                     require_precedent=False)
        self.assertEqual(self._verdict(), ('refuse', 'no_verified_backup'))


class TestAnAcknowledgedAlertIsLeftAlone(_Base):

    def test_acknowledging_stops_the_loop(self):
        """`acked_at` appears nowhere else in the codebase — the field an alert
        carries is `acknowledged_at`. So an operator saying "I have got this"
        had never once stopped the loop from acting on it."""
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'failed_unit', 'device_id': 'd1',
            'severity': 'high', 'acknowledged_at': int(time.time()),
            'payload': {'unit': 'nginx.service'}}]})
        api._LOAD_CACHE.clear()
        self._policy(require_precedent=False)
        self.assertEqual(self._run(), [])

    def test_an_unacknowledged_one_is_still_a_candidate(self):
        """Control: without this, a filter that dropped everything would pass."""
        self._alert()
        self._policy(require_precedent=False)
        self.assertEqual(len(self._run()), 1)

    def test_the_field_name_is_the_one_the_store_uses(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("'acknowledged_at': None", src,
                      'the alert row no longer carries this field')


class TestAPartialPolicySaveDoesNotWidenTheAllowList(_Base):

    def _put(self, body):
        cap = {}

        def _respond(status, data=None):
            cap['status'], cap['data'] = status, data
            raise api.HTTPError(status, data)
        saved = (api.respond, api.method, api.get_json_obj,
                 api.require_admin_auth, api.audit_log)
        api.respond = _respond
        api.method = lambda: 'PUT'
        api.get_json_obj = lambda: body
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
        return (api.load(api.AUTONOMY_POLICY_FILE) or {}).get('tenants', {}).get('default')

    def test_a_mode_only_put_leaves_the_allow_list_alone(self):
        """The default allow-list is permissive by design, so merging an update
        over the DEFAULTS re-granted 13 action classes to a tenant that had
        narrowed to one — and reported success."""
        self._policy('shadow', allowed_actions=['restart_service'])
        after = self._put({'policy': {'mode': 'enabled'}})
        self.assertEqual(after['allowed_actions'], ['restart_service'], after)
        self.assertEqual(after['mode'], 'enabled')

    def test_a_put_that_names_the_list_still_replaces_it(self):
        """Control: absent means leave alone, present means set."""
        self._policy('shadow', allowed_actions=['restart_service'])
        after = self._put({'policy': {'allowed_actions': ['clear_journal']}})
        self.assertEqual(after['allowed_actions'], ['clear_journal'])

    def test_a_tenant_with_no_policy_still_gets_the_defaults(self):
        api.save(api.AUTONOMY_POLICY_FILE, {})
        api._LOAD_CACHE.clear()
        after = self._put({'policy': {'mode': 'shadow'}})
        self.assertGreater(len(after['allowed_actions']), 5)


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

    def test_a_scoped_role_sees_only_its_own_hosts_receipts(self):
        """The filter had the tenant half and not the ROLE half, so a role
        confined to one group could read the decision history of the whole
        fleet — hostnames and commands included. `handle_alerts_clear` gets both
        from _filter_alerts_for_caller; there is no such helper for this store."""
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'group': 'prod'},
            'd2': {'name': 'lab01', 'group': 'lab'}})
        api.save(api.ROLES_FILE, {'roles': [
            {'name': 'prod-op', 'permissions': ['exec'],
             'scope': {'type': 'groups', 'values': ['prod']}}]})
        api.save(api.AUTONOMY_RECEIPTS_FILE, {'receipts': [
            {'id': 'p1', 'tenant': 'default', 'device_id': 'd1',
             'device_name': 'web01', 'verdict': 'shadow'},
            {'id': 'l1', 'tenant': 'default', 'device_id': 'd2',
             'device_name': 'lab01', 'verdict': 'shadow'},
        ], 'last_run': 1})
        api._LOAD_CACHE.clear()
        self._as('prod-op')
        rows = api._visible_receipts(
            (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts'))
        self.assertEqual([r['id'] for r in rows], ['p1'],
                         'a prod-scoped role can see the lab host\'s receipts')
        # A non-admin cannot delete anything at all — the admin gate is in front
        # of the scope filter. The filter still matters on that path because a
        # SCOPED API KEY confines an admin-role caller too (_caller_scope
        # intersects the two).
        self.assertEqual(self._call('id=l1'), 403)
        self.assertEqual(len(self._rows()), 2)

    def test_an_unscoped_admin_still_sees_a_decommissioned_hosts_receipts(self):
        """Filtering an unscoped caller against the live device set would hide
        the receipts of hosts that have since been removed — and a receipt is
        self-contained precisely because the fleet changes."""
        api.save(api.DEVICES_FILE, {})
        api._LOAD_CACHE.clear()
        self._as('admin')
        rows = api._visible_receipts(
            (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts'))
        self.assertEqual(len(rows), 3)

    def test_the_route_is_wired(self):
        routes = api._build_exact_routes()
        self.assertIn(('DELETE', '/api/autonomy/receipts'), routes)
        self.assertIs(routes[('DELETE', '/api/autonomy/receipts')],
                      api.handle_autonomy_receipts_clear)


if __name__ == '__main__':
    unittest.main()


class TestAWindowThatCoversNothingSaysSo(_Base):
    """A group- or tag-scoped window matches an EXACT string, and `group` is
    operator-editable free text that nothing repoints. Rename `prod` to
    `production` and every window scoped to `prod` quietly stops covering
    anything — which for a change-gated window is the difference between
    changes being held to the window and running whenever they like. The list
    rendered it identically: same reason, same schedule, no hint."""

    def setUp(self):
        super().setUp()
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        self._saved = {n: getattr(api, n) for n in ('respond', 'require_auth')}
        api.respond = _respond
        api.require_auth = lambda *a, **k: 'alice'
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'group': 'prod', 'tags': ['edge']},
            'd2': {'name': 'web02', 'group': 'prod'},
            'd3': {'name': 'lab01', 'group': 'lab'}})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        super().tearDown()

    def _list(self, *windows):
        api.save(api.MAINT_FILE, {'windows': list(windows)})
        api._LOAD_CACHE.clear()
        self.cap.clear()
        try:
            api.handle_maintenance_list()
        except api.HTTPError:
            pass
        return {w['id']: w for w in (self.cap['data'] or {}).get('windows', [])}

    def test_a_group_window_counts_its_hosts(self):
        out = self._list({'id': 'w1', 'scope': 'group', 'target': 'prod',
                          'gate_exec': True, 'reason': 'patching'})
        self.assertEqual(out['w1']['covers'], 2)

    def test_a_renamed_group_leaves_it_covering_nothing(self):
        out = self._list({'id': 'w1', 'scope': 'group', 'target': 'production',
                          'gate_exec': True, 'reason': 'patching'})
        self.assertEqual(out['w1']['covers'], 0,
                         'the window matches no host and the list said nothing')

    def test_device_tag_and_global_scopes_all_report(self):
        out = self._list(
            {'id': 'wd', 'scope': 'device', 'target': 'd1'},
            {'id': 'wx', 'scope': 'device', 'target': 'gone'},
            {'id': 'wt', 'scope': 'tag', 'target': 'edge'},
            {'id': 'wg', 'scope': 'global', 'target': ''})
        self.assertEqual(out['wd']['covers'], 1)
        self.assertEqual(out['wx']['covers'], 0)
        self.assertEqual(out['wt']['covers'], 1)
        self.assertEqual(out['wg']['covers'], 3)

    def test_an_unknown_scope_says_nothing_rather_than_zero(self):
        """A scope this build does not know is not evidence of no coverage."""
        out = self._list({'id': 'w9', 'scope': 'smart', 'target': 'x'})
        self.assertIsNone(out['w9']['covers'])

    def test_the_page_renders_the_warning(self):
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        self.assertIn('covers nothing', js)
