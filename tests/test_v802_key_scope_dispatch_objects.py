#!/usr/bin/env python3
"""What a key with a host scope makes and sets going keeps to that scope when it runs, not only while the key is asking.

A key can be given part of the fleet, and the scope confines even an administrator's key. The routes that act on a host the moment they are
asked check it. Four kinds of object are different: they are made now and act later, on the hosts a stored selector names, from the
scheduler or from an event, where there is no request and so no key to ask. They carried the creator's tenant for exactly that reason
(`tenant_gate`) and did not carry the creator's scope. A key limited to the group prod could make

* an auto-patch policy for the group dev, run it (or wait for its cron) and have the upgrade, with the reboot, queued on the dev hosts;
* a rollout whose ring named a dev host, start it and have the host upgraded;
* an automation rule with no host match and a saved script, which queued the script as root on whichever host fired the event next (and a
  rule that adds a tag put hosts outside its scope into it);
* a maintenance window for everything, which suppressed the alerts of every host and held their changes.

Each now carries the scope of the key that made it (`scope_gate`, the sibling of `tenant_gate`) and the dispatch keeps to it. What this holds,
with real keys and sessions through the real route table, and the real dispatchers (the cron sweep, the rollout tick, the rule matcher, the
window test) run in the same process on the same stores:

* what each dispatcher queued on the host outside the key's scope: nothing, for the policy by run and by cron, for a policy with rings, for a
  rollout that names the host, for a rule that runs a script and one that adds a tag, and the window does not cover it. The host inside the
  scope is reached by each, so the instrument can see a queue;
* an object that has no stamp (an administrator's, with no scope) reaches both hosts as it always did, and what an administrator makes has no
  stamp; a key cannot run, start, edit or change it (403 `beyond_key_scope`), and an administrator's session can;
* a key edits and runs its own, and a stamp stays what it was; a retarget by a person with no limit is theirs to make;
* the policy's mirror window carries the stamp too (it is the thing that suppressed every host's alerts for a policy for everything);
* the class: every function that stamps a tenant on an object stamps a scope as well, or is on the list of those that dispatch nothing.
"""
import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import credential_scan  # noqa: E402
import real_stack  # noqa: E402

_DRIVER = r'''
GROUPS = lambda *v: {'type': 'groups', 'values': list(v)}
add_key('SKEY', 'svc', scope=GROUPS('prod'))          # an administrator key limited to the group prod: web1 is inside it, db1 is outside
add_key('WIDE', 'boss')                                # an administrator key with no scope
queued = lambda dev: list(get('CMDS_FILE').get(dev) or [])
fresh = lambda: put('CMDS_FILE', {})
reach = lambda: {d: len(queued(d)) for d in ('web1', 'db1')}


def rearm():
    """Every request runs the cron sweeps, so a policy that is due has usually been fired by one already. Marking all of them due again
    lets the sweep that a test calls itself be the one that fires them."""
    store = get('AUTOPATCH_FILE')
    for p in store['policies']:
        p['last_fired_minute'] = int(now // 60) - 1
    put('AUTOPATCH_FILE', store)


def find(attr, key, ident):
    return next((r for r in (get(attr).get(key) or []) if isinstance(r, dict) and r.get('id') == ident), None)


code = lambda r: (r[1] or {}).get('code')

# ---------------------------------------------------------------- auto-patch policies
mk = lambda token, name, target, **more: call('POST', '/api/autopatch', token, dict({'name': name, 'cron': '* * * * *', 'target': target}, **more))
run = lambda token, pid: call('POST', '/api/autopatch/%s/run' % pid, token, {})
policy = lambda attr='AUTOPATCH_FILE': get(attr)['policies']

st, js = mk('SKEY', 'out', {'type': 'group', 'value': 'dev'}, reboot=True)
ap_out = js['id']
out['ap_stamp'] = [st, find('AUTOPATCH_FILE', 'policies', ap_out).get('scope_gate')]
fresh()
out['ap_run_out'] = [run('SKEY', ap_out)[0], (call('GET', '/api/autopatch', 'SKEY')[1] or {}).get('ok'), reach()]
st, js = mk('SKEY', 'in', {'type': 'group', 'value': 'prod'})
ap_in = js['id']
fresh()
r = run('SKEY', ap_in)
out['ap_run_in'] = [r[0], r[1].get('queued'), reach()]
st, js = mk('SKEY', 'all', {'type': 'all'})
ap_all = js['id']
fresh()
r = run('SKEY', ap_all)
out['ap_run_all'] = [r[0], reach()]
st, js = mk('SKEY', 'device', {'type': 'device', 'value': 'db1'})
fresh()
r = run('SKEY', js['id'])
out['ap_run_device'] = [r[0], r[1].get('queued'), reach()]

# the cron sweep has no request: a policy that is due is fired by what it carries
fresh()
rearm()
api.process_autopatch()
out['ap_cron_keys'] = reach()
st, js = mk('WIDE', 'wide', {'type': 'group', 'value': 'dev'})
ap_wide = js['id']
out['ap_wide_stamp'] = [st, find('AUTOPATCH_FILE', 'policies', ap_wide).get('scope_gate')]
fresh()
rearm()
api.process_autopatch()
out['ap_cron_wide_added'] = reach()

# an object that has no stamp: a key cannot run or edit it, a session can
out['ap_key_runs_wide'] = [run('SKEY', ap_wide)[0], code(run('SKEY', ap_wide))]
out['ap_key_edits_wide'] = call('PUT', '/api/autopatch/%s' % ap_wide, 'SKEY', {'name': 'taken over'})
out['ap_wide_name'] = find('AUTOPATCH_FILE', 'policies', ap_wide)['name']
fresh()
out['ap_session_runs_wide'] = [run(SESS['admin'], ap_wide)[0], reach()]

# a key edits its own, and the stamp stays
out['ap_key_edits_own'] = call('PUT', '/api/autopatch/%s' % ap_in, 'SKEY', {'name': 'renamed', 'target': {'type': 'group', 'value': 'dev'}})[0]
out['ap_own_after'] = {k: find('AUTOPATCH_FILE', 'policies', ap_in).get(k) for k in ('name', 'scope_gate')}
# a retarget by a person with no limit is theirs to make
out['ap_session_retargets'] = call('PUT', '/api/autopatch/%s' % ap_in, SESS['admin'], {'target': {'type': 'group', 'value': 'dev'}})[0]
out['ap_retarget_stamp'] = find('AUTOPATCH_FILE', 'policies', ap_in).get('scope_gate')

# rings: the policy spawns a rollout, and the rollout carries the stamp (the first ring names a host inside the scope and one outside)
st, js = mk('SKEY', 'ringed', {'type': 'all'}, rings=[{'name': 'first', 'selector': {'type': 'ids', 'ids': ['web1', 'db1']}}])
ap_ring = js['id']
fresh()
r = run('SKEY', ap_ring)
out['ap_ring_run'] = [r[0], r[1].get('queued')]
for _ in range(3):
    api._rollout_tick()
spawned = next((r for r in get('ROLLOUTS_FILE').get('rollouts', []) if r.get('_autopatch_id') == ap_ring), {})
out['ap_ring_stamp'] = spawned.get('scope_gate')
out['ap_ring_dispatched'] = sorted({d for s in spawned.get('rings_state', []) for d in (s.get('dispatched_ids') or [])})
out['ap_ring_reach'] = reach()

# the window the policy mirrors into the maintenance store carries the stamp
mirror = find('MAINT_FILE', 'windows', 'ap_' + ap_out)
out['ap_mirror'] = [bool(mirror), (mirror or {}).get('scope_gate')]
mirror_all = find('MAINT_FILE', 'windows', 'ap_' + ap_all)
out['ap_mirror_all_applies'] = {d: api._window_applies(mirror_all, d, dev=api.device_get(d)) for d in ('web1', 'db1')}

# ---------------------------------------------------------------- rollouts
mkr = lambda token, ids, name='roll': call('POST', '/api/rollouts', token, {'name': name, 'action': 'upgrade',
                                                                             'rings': [{'name': 'one', 'selector': {'type': 'ids', 'ids': ids}}]})
act = lambda token, rid, what: call('POST', '/api/rollouts/%s/%s' % (rid, what), token, {})
dispatched = lambda rid: sorted({d for s in find('ROLLOUTS_FILE', 'rollouts', rid).get('rings_state', []) for d in (s.get('dispatched_ids') or [])})

st, js = mkr('SKEY', ['web1', 'db1'], 'by-key')
ro_key = js['rollout']['id']
out['ro_stamp'] = [st, find('ROLLOUTS_FILE', 'rollouts', ro_key).get('scope_gate')]
fresh()
out['ro_key_starts_own'] = act('SKEY', ro_key, 'start')[0]
for _ in range(3):
    api._rollout_tick()
out['ro_key_dispatched'] = dispatched(ro_key)
out['ro_key_reach'] = reach()

# a script rollout with a rollback script: the rollback is a rollout of its own, and carries the stamp of the one it undoes
st, js = call('POST', '/api/scripts', 'SKEY', {'name': 'rollback-probe', 'body': 'id'})
undo_id = js['script']['id']
st, js = call('POST', '/api/rollouts', 'SKEY', {'name': 'script-roll', 'action': 'script', 'script_id': undo_id, 'rollback_script_id': undo_id,
                                                'rings': [{'name': 'one', 'selector': {'type': 'ids', 'ids': ['web1', 'db1']}}]})
ro_script = js['rollout']['id']
act('SKEY', ro_script, 'start')
for _ in range(3):
    api._rollout_tick()
r = act('SKEY', ro_script, 'rollback')
rb_id = (r[1] or {}).get('rollback_id')
rb = find('ROLLOUTS_FILE', 'rollouts', rb_id) or {}
out['ro_rollback'] = [r[0], bool(rb_id), rb.get('scope_gate'), rb.get('tenant_gate')]

st, js = mkr('WIDE', ['web1', 'db1'], 'by-wide')
ro_wide = js['rollout']['id']
out['ro_wide_stamp'] = [st, find('ROLLOUTS_FILE', 'rollouts', ro_wide).get('scope_gate')]
out['ro_key_starts_wide'] = [act('SKEY', ro_wide, 'start')[0], code(act('SKEY', ro_wide, 'start'))]
out['ro_wide_state_after_key'] = find('ROLLOUTS_FILE', 'rollouts', ro_wide)['state']
fresh()
out['ro_session_starts_wide'] = act(SESS['admin'], ro_wide, 'start')[0]
for _ in range(3):
    api._rollout_tick()
out['ro_wide_dispatched'] = dispatched(ro_wide)
out['ro_wide_reach'] = reach()
out['ro_key_resume_wide'] = [act('SKEY', ro_wide, 'resume')[0], code(act('SKEY', ro_wide, 'resume'))]
out['ro_key_promote_wide'] = [act('SKEY', ro_wide, 'promote')[0], code(act('SKEY', ro_wide, 'promote'))]
out['ro_key_rollback_wide'] = [act('SKEY', ro_wide, 'rollback')[0], code(act('SKEY', ro_wide, 'rollback'))]
out['ro_key_cancels_wide'] = [act('SKEY', ro_wide, 'cancel')[0], find('ROLLOUTS_FILE', 'rollouts', ro_wide)['state']]

# ---------------------------------------------------------------- automation rules
st, js = call('POST', '/api/scripts', 'SKEY', {'name': 'probe', 'body': 'id'})
script_id = js['script']['id']
mkrule = lambda token, name, actions: call('POST', '/api/automation/rules', token,
                                            {'name': name, 'match': {'events': ['device_offline']}, 'actions': actions, 'cooldown_seconds': 0})
cfg = api._config_ro()
fire = lambda dev, payload=None: api._run_automation_rules('device_offline', dict({'device_id': dev, 'device_name': dev}, **(payload or {})) if dev else {}, cfg)
rule = lambda rid: find('RULES_FILE', 'rules', rid)

st, js = mkrule('SKEY', 'runs a script', [{'type': 'run_script', 'script_id': script_id}])
ru_key = js['id']
out['ru_stamp'] = [st, rule(ru_key).get('scope_gate')]
fresh()
fire('db1')
out['ru_script_db1'] = queued('db1')
fire('web1')
out['ru_script_web1'] = queued('web1')
st, js = mkrule('SKEY', 'adds a tag', [{'type': 'add_tag', 'tag': 'seen'}])
ru_tag = js['id']
fire('db1')
fire('web1')
tags = lambda d: get('DEVICES_FILE')[d].get('tags') or []
out['ru_tag'] = {'web1': 'seen' in tags('web1'), 'db1': 'seen' in tags('db1')}
# an event that names no host is not a host in the key's scope
before = rule(ru_key)['fire_count']
fire(None)
out['ru_no_host_fired'] = rule(ru_key)['fire_count'] - before

st, js = mkrule('WIDE', 'unscoped', [{'type': 'run_script', 'script_id': script_id}])
ru_wide = js['id']
out['ru_wide_stamp'] = [st, rule(ru_wide).get('scope_gate')]
fresh()
fire('db1')
out['ru_wide_db1'] = queued('db1')
before = rule(ru_wide)['fire_count']
fire(None)
out['ru_wide_no_host_fired'] = rule(ru_wide)['fire_count'] - before
body = {'name': 'taken over', 'match': {'events': ['device_offline']}, 'actions': [{'type': 'add_tag', 'tag': 'x'}], 'cooldown_seconds': 0}
out['ru_key_edits_wide'] = [call('PUT', '/api/automation/rules/%s' % ru_wide, 'SKEY', body)[0],
                            code(call('PUT', '/api/automation/rules/%s' % ru_wide, 'SKEY', body))]
out['ru_wide_name'] = rule(ru_wide)['name']
out['ru_key_edits_own'] = call('PUT', '/api/automation/rules/%s' % ru_key, 'SKEY', dict(body, name='renamed'))[0]
out['ru_own_after'] = {k: rule(ru_key).get(k) for k in ('name', 'scope_gate')}
out['ru_session_edits_wide'] = call('PUT', '/api/automation/rules/%s' % ru_wide, SESS['admin'], dict(body, name='by a person'))[0]

# ---------------------------------------------------------------- maintenance windows
mkw = lambda token, **more: call('POST', '/api/maintenance', token, dict({'scope': 'global', 'reason': 'probe', 'cron': '* * * * *', 'duration': 3600}, **more))
applies = lambda wid: {d: api._window_applies(find('MAINT_FILE', 'windows', wid), d, dev=api.device_get(d)) for d in ('web1', 'db1')}
st, js = mkw('SKEY')
wi_key = js['window']['id']
out['wi_stamp'] = [st, find('MAINT_FILE', 'windows', wi_key).get('scope_gate')]
out['wi_key_applies'] = applies(wi_key)
st, js = mkw('WIDE')
wi_wide = js['window']['id']
out['wi_wide_stamp'] = [st, find('MAINT_FILE', 'windows', wi_wide).get('scope_gate')]
out['wi_wide_applies'] = applies(wi_wide)
upd = {'scope': 'global', 'reason': 'taken over', 'cron': '* * * * *', 'duration': 3600}
out['wi_key_edits_wide'] = [call('PUT', '/api/maintenance/%s' % wi_wide, 'SKEY', upd)[0], code(call('PUT', '/api/maintenance/%s' % wi_wide, 'SKEY', upd))]
out['wi_wide_reason'] = find('MAINT_FILE', 'windows', wi_wide)['reason']
out['wi_key_edits_own'] = call('PUT', '/api/maintenance/%s' % wi_key, 'SKEY', dict(upd, reason='renamed'))[0]
out['wi_own_after'] = {k: find('MAINT_FILE', 'windows', wi_key).get(k) for k in ('reason', 'scope_gate')}
out['wi_session_edits_wide'] = call('PUT', '/api/maintenance/%s' % wi_wide, SESS['admin'], dict(upd, reason='by a person'))[0]

# ---------------------------------------------------------------- what a person with no limit makes has no stamp
st, js = mk(SESS['admin'], 'by a person', {'type': 'group', 'value': 'dev'})
out['session_stamps'] = {'policy': find('AUTOPATCH_FILE', 'policies', js['id']).get('scope_gate'),
                         'rollout': find('ROLLOUTS_FILE', 'rollouts', mkr(SESS['admin'], ['db1'])[1]['rollout']['id']).get('scope_gate'),
                         'rule': rule(mkrule(SESS['admin'], 'by a person', [{'type': 'add_tag', 'tag': 'p'}])[1]['id']).get('scope_gate'),
                         'window': find('MAINT_FILE', 'windows', mkw(SESS['admin'])[1]['window']['id']).get('scope_gate')}

# ---------------------------------------------------------------- a start that waits for a second administrator
doc = get('CONFIG_FILE')
doc['change_approval_enabled'] = True
put('CONFIG_FILE', doc)
st, js = mkr('WIDE', ['db1'], 'needs approval')
ro_gate = js['rollout']['id']
parked = lambda: len(get('CONFIRMATIONS_FILE').get('confirmations') or [])
before = parked()
r = act('SKEY', ro_gate, 'start')
out['ro_parked_by_key'] = [r[0], code(r), parked() - before]          # a refused key leaves no request for the second administrator
r = act(SESS['admin'], ro_gate, 'start')
out['ro_parked_by_person'] = [r[0], parked() - before]               # the control: a person with no limit parks it
'''

_PURE = r'''
G = {'type': 'groups', 'values': ['prod']}
w = api._host_in_stamped_scope
out['unit'] = {
    'no_stamp': w(None, {'group': 'dev'}), 'empty_stamp': w({}, {'group': 'dev'}),
    'inside': w(G, {'group': 'prod'}), 'outside': w(G, {'group': 'dev'}), 'no_group': w(G, {}),
    'tags_inside': w({'type': 'tags', 'values': ['web']}, {'tags': ['web', 'x']}), 'tags_outside': w({'type': 'tags', 'values': ['web']}, {'tags': ['db']}),
    'composite_both': w({'type': 'all_of', 'scopes': [G, {'type': 'tags', 'values': ['web']}]}, {'group': 'prod', 'tags': ['web']}),
    'composite_one': w({'type': 'all_of', 'scopes': [G, {'type': 'tags', 'values': ['web']}]}, {'group': 'prod', 'tags': ['db']}),
    'damaged_string': w('prod', {'group': 'prod'}), 'damaged_list': w(['prod'], {'group': 'prod'}), 'host_not_a_dict': w(G, None),
}
out['stamp_of_no_limit'] = api._caller_scope_stamp()
'''


class TestWhatAKeyMakesKeepsToTheKeysScope(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('flask is not installed')
        cls.out = real_stack.run(_DRIVER)

    def prod(self):
        return {'web1': 1, 'db1': 0}

    def test_the_policy_carries_the_scope_of_the_key_that_made_it(self):
        self.assertEqual(self.out['ap_stamp'], [200, {'type': 'groups', 'values': ['prod']}])

    def test_a_policy_for_a_group_outside_the_scope_queues_nothing_when_run(self):
        st, ok, reach = self.out['ap_run_out']
        self.assertEqual((st, reach), (200, {'web1': 0, 'db1': 0}), 'the policy for the group dev queued something')

    def test_a_policy_inside_the_scope_still_works_and_reaches_only_its_hosts(self):
        st, queued, reach = self.out['ap_run_in']
        self.assertEqual(st, 200)
        self.assertGreaterEqual(queued, 1, 'the control: the dispatcher queues on a host inside the scope')
        self.assertEqual(reach['db1'], 0)
        self.assertGreaterEqual(reach['web1'], 1)

    def test_a_policy_for_everything_reaches_the_hosts_of_the_key_and_no_others(self):
        st, reach = self.out['ap_run_all']
        self.assertEqual(st, 200)
        self.assertGreaterEqual(reach['web1'], 1)
        self.assertEqual(reach['db1'], 0, 'everything meant everything the key may reach')

    def test_a_policy_that_names_a_host_outside_the_scope_queues_nothing(self):
        st, queued, reach = self.out['ap_run_device']
        self.assertEqual((st, queued, reach['db1']), (200, 0, 0))

    def test_the_cron_sweep_keeps_to_the_scope_too_and_reaches_the_host_for_an_unscoped_policy(self):
        """No request, so only what the policy carries confines it. The second half is the control: the same sweep does queue on the host
        outside the key's scope for a policy that has no stamp."""
        self.assertEqual(self.out['ap_cron_keys']['db1'], 0)
        self.assertGreaterEqual(self.out['ap_cron_keys']['web1'], 1)
        self.assertEqual(self.out['ap_wide_stamp'], [200, None])
        self.assertGreaterEqual(self.out['ap_cron_wide_added']['db1'], 1, 'the control: the sweep reaches the dev host for a policy with no stamp')

    def test_a_key_cannot_run_or_edit_a_policy_that_reaches_more_and_a_session_can(self):
        self.assertEqual(self.out['ap_key_runs_wide'], [403, 'beyond_key_scope'])
        st, body = self.out['ap_key_edits_wide']
        self.assertEqual((st, (body or {}).get('code')), (403, 'beyond_key_scope'))
        self.assertEqual(self.out['ap_wide_name'], 'wide', 'the refused edit changed the policy')
        st, reach = self.out['ap_session_runs_wide']
        self.assertEqual(st, 200)
        self.assertGreaterEqual(reach['db1'], 1, 'an administrator with no scope runs it as before')

    def test_a_key_edits_its_own_policy_and_the_stamp_stays_and_a_person_may_retarget_it(self):
        self.assertEqual(self.out['ap_key_edits_own'], 200)
        self.assertEqual(self.out['ap_own_after'], {'name': 'renamed', 'scope_gate': {'type': 'groups', 'values': ['prod']}})
        self.assertEqual(self.out['ap_session_retargets'], 200)
        self.assertEqual(self.out['ap_retarget_stamp'], None, 'a retarget by a person with no limit is theirs: it carries no stamp, as a policy of theirs would')

    def test_a_policy_with_rings_spawns_a_rollout_that_carries_the_stamp(self):
        self.assertEqual(self.out['ap_ring_run'], [200, 1], 'the run counts the hosts the rings will reach: the ring names two and one is in the scope')
        self.assertEqual(self.out['ap_ring_stamp'], {'type': 'groups', 'values': ['prod']})
        self.assertIn('web1', self.out['ap_ring_dispatched'], 'the control: the rings reached the host inside the scope')
        self.assertNotIn('db1', self.out['ap_ring_dispatched'])
        self.assertEqual(self.out['ap_ring_reach']['db1'], 0)

    def test_the_window_a_policy_mirrors_carries_the_stamp_and_covers_only_the_scope(self):
        self.assertEqual(self.out['ap_mirror'], [True, {'type': 'groups', 'values': ['prod']}])
        self.assertEqual(self.out['ap_mirror_all_applies'], {'web1': True, 'db1': False},
                         'the window for a policy for everything silenced the alerts of every host')


class TestRollouts(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.out = TestWhatAKeyMakesKeepsToTheKeysScope.out if hasattr(TestWhatAKeyMakesKeepsToTheKeysScope, 'out') else real_stack.run(_DRIVER)

    def test_a_rollout_that_names_a_host_outside_the_scope_does_not_reach_it(self):
        self.assertEqual(self.out['ro_stamp'], [200, {'type': 'groups', 'values': ['prod']}])
        self.assertEqual(self.out['ro_key_starts_own'], 200)
        self.assertEqual(self.out['ro_key_dispatched'], ['web1'], 'the ring named web1 and db1')
        self.assertEqual(self.out['ro_key_reach']['db1'], 0)
        self.assertGreaterEqual(self.out['ro_key_reach']['web1'], 1)

    def test_a_rollout_with_no_stamp_reaches_both_when_a_person_starts_it(self):
        self.assertEqual(self.out['ro_wide_stamp'], [200, None])
        self.assertEqual(self.out['ro_session_starts_wide'], 200)
        self.assertEqual(self.out['ro_wide_dispatched'], ['db1', 'web1'], 'the control: the dispatcher reaches the dev host for a rollout with no stamp')

    def test_a_key_cannot_start_resume_promote_or_roll_back_a_rollout_that_reaches_more(self):
        for name in ('ro_key_starts_wide', 'ro_key_resume_wide', 'ro_key_promote_wide', 'ro_key_rollback_wide'):
            with self.subTest(action=name):
                self.assertEqual(self.out[name][-1], 'beyond_key_scope')
                self.assertEqual(self.out[name][0], 403)
        self.assertEqual(self.out['ro_wide_state_after_key'], 'draft', 'the refused start started it')

    def test_a_rollback_is_a_rollout_that_carries_the_stamp_of_the_one_it_undoes(self):
        st, made, scope, tenant = self.out['ro_rollback']
        self.assertEqual((st, made), (200, True))
        self.assertEqual(scope, {'type': 'groups', 'values': ['prod']})
        self.assertIsNone(tenant, 'the platform operator\'s own: no tenant gate, as the rollout it undoes')

    def test_a_key_can_still_stop_a_rollout_that_reaches_more(self):
        """Pausing and cancelling take nothing further: they only stop the dispatch."""
        self.assertEqual(self.out['ro_key_cancels_wide'], [200, 'cancelled'])

    def test_a_refused_start_leaves_no_request_for_a_second_administrator(self):
        """With approval on, a start waits for a second administrator. The refusal comes first, so the key leaves nothing to approve, and a
        person with no limit parks it as before."""
        self.assertEqual(self.out['ro_parked_by_key'], [403, 'beyond_key_scope', 0])
        self.assertEqual(self.out['ro_parked_by_person'], [202, 1])


class TestRules(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.out = TestWhatAKeyMakesKeepsToTheKeysScope.out if hasattr(TestWhatAKeyMakesKeepsToTheKeysScope, 'out') else real_stack.run(_DRIVER)

    def test_a_rule_that_runs_a_script_runs_it_on_the_hosts_in_the_scope_only(self):
        self.assertEqual(self.out['ru_stamp'], [201, {'type': 'groups', 'values': ['prod']}])
        self.assertEqual(self.out['ru_script_db1'], [], 'an event on the host outside the scope queued the script as root')
        self.assertEqual(self.out['ru_script_web1'], ['exec:id'], 'the control: an event on a host inside the scope queues it')

    def test_a_rule_that_adds_a_tag_does_not_put_a_host_outside_the_scope_into_it(self):
        self.assertEqual(self.out['ru_tag'], {'web1': True, 'db1': False})

    def test_an_event_that_names_no_host_does_not_fire_a_rule_with_a_stamp_and_fires_one_without(self):
        self.assertEqual(self.out['ru_no_host_fired'], 0)
        self.assertEqual(self.out['ru_wide_no_host_fired'], 1, 'the control: the rule with no stamp fired')

    def test_a_rule_with_no_stamp_reaches_the_host_outside_the_scope_as_it_always_did(self):
        self.assertEqual(self.out['ru_wide_stamp'], [201, None])
        self.assertEqual(self.out['ru_wide_db1'], ['exec:id'])

    def test_a_key_edits_its_own_rule_and_not_one_that_reaches_more(self):
        self.assertEqual(self.out['ru_key_edits_wide'], [403, 'beyond_key_scope'])
        self.assertEqual(self.out['ru_wide_name'], 'unscoped', 'the refused edit changed the rule')
        self.assertEqual(self.out['ru_key_edits_own'], 200)
        self.assertEqual(self.out['ru_own_after'], {'name': 'renamed', 'scope_gate': {'type': 'groups', 'values': ['prod']}})
        self.assertEqual(self.out['ru_session_edits_wide'], 200)


class TestWindows(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.out = TestWhatAKeyMakesKeepsToTheKeysScope.out if hasattr(TestWhatAKeyMakesKeepsToTheKeysScope, 'out') else real_stack.run(_DRIVER)

    def test_a_window_for_everything_covers_the_hosts_in_the_scope_only(self):
        self.assertEqual(self.out['wi_stamp'], [200, {'type': 'groups', 'values': ['prod']}])
        self.assertEqual(self.out['wi_key_applies'], {'web1': True, 'db1': False})

    def test_a_window_with_no_stamp_covers_both_as_it_always_did(self):
        self.assertEqual(self.out['wi_wide_stamp'], [200, None])
        self.assertEqual(self.out['wi_wide_applies'], {'web1': True, 'db1': True})

    def test_a_key_edits_its_own_window_and_not_one_that_reaches_more(self):
        self.assertEqual(self.out['wi_key_edits_wide'], [403, 'beyond_key_scope'])
        self.assertEqual(self.out['wi_wide_reason'], 'probe', 'the refused edit changed the window')
        self.assertEqual(self.out['wi_key_edits_own'], 200)
        self.assertEqual(self.out['wi_own_after'], {'reason': 'renamed', 'scope_gate': {'type': 'groups', 'values': ['prod']}})
        self.assertEqual(self.out['wi_session_edits_wide'], 200)


class TestAPersonWithNoLimitIsNotChanged(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.out = TestWhatAKeyMakesKeepsToTheKeysScope.out if hasattr(TestWhatAKeyMakesKeepsToTheKeysScope, 'out') else real_stack.run(_DRIVER)

    def test_what_a_session_makes_has_no_stamp(self):
        self.assertEqual(self.out['session_stamps'], {'policy': None, 'rollout': None, 'rule': None, 'window': None})


class TestTheStampTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.out = real_stack.run(_PURE)

    def test_the_helper(self):
        u = self.out['unit']
        for name in ('no_stamp', 'empty_stamp', 'inside', 'tags_inside', 'composite_both'):
            self.assertTrue(u[name], name)
        for name in ('outside', 'no_group', 'tags_outside', 'composite_one', 'damaged_string', 'damaged_list', 'host_not_a_dict'):
            self.assertFalse(u[name], name + ': a damaged stamp or a host that is not a record admits nothing')
        self.assertIsNone(self.out['stamp_of_no_limit'], 'a caller with nothing confining it stamps nothing')


# ── the class ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# The functions that write a tenant on an object and no scope, each with the reason.
_STAMPS_NO_SCOPE = {
    'handle_scripts_add': 'the script library: a script is text that is run on a host by a route that asks for the host, or by a rule or a rollout, which carry the stamp',
}


def _key_writes(node, key):
    """Whether a function writes `key` as a key of a dict it builds or as an item it assigns (`x[key] = ...`)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == key for k in n.keys):
            return True
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and t.slice.value == key for t in n.targets):
            return True
    return False


class TestEveryStampOfATenantHasAStampOfAScope(unittest.TestCase):

    @staticmethod
    def population():
        return {fn.name for _path, fn in credential_scan.functions() if _key_writes(fn, 'tenant_gate')}

    def test_every_function_that_stamps_a_tenant_stamps_a_scope_or_is_listed(self):
        found = self.population()
        for name in ('handle_autopatch_create', 'handle_autopatch_update', 'handle_automation_rule_create', 'handle_maintenance_add',
                     'handle_rollouts_create', '_autopatch_spawn_rollout', '_autopatch_sync'):
            self.assertIn(name, found, 'the scan no longer sees %s, which it must (the control of this scan)' % name)
        self.assertGreaterEqual(len(found), 8)
        missing = sorted(fn.name for _path, fn in credential_scan.functions()
                         if fn.name in found and not _key_writes(fn, 'scope_gate') and fn.name not in _STAMPS_NO_SCOPE)
        self.assertEqual(missing, [], 'these stamp the tenant of the caller on an object that is dispatched later and not the scope: %s' % missing)
        stale = sorted(n for n in _STAMPS_NO_SCOPE if n not in found)
        self.assertEqual(stale, [], 'listed, but no longer stamps a tenant: %s' % stale)

    def test_the_listed_ones_do_not_stamp_a_scope_already(self):
        for fn in (f for _p, f in credential_scan.functions() if f.name in _STAMPS_NO_SCOPE):
            with self.subTest(function=fn.name):
                self.assertFalse(_key_writes(fn, 'scope_gate'), '%s stamps a scope already: it belongs with the ones that do' % fn.name)


if __name__ == '__main__':
    unittest.main()
