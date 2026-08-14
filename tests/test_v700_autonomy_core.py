#!/usr/bin/env python3
"""The autonomous-remediation decision core: prove the unsafe states are unreachable.

Everything `decide()` approves ends up running a command on somebody's
production host, so these are not coverage tests — each one is an attempt to get
an ACT out of the function in a situation where acting would be wrong.

The three properties the module claims, and how they are attacked here:

1. **Default deny** — an unrecognised action, or one absent from the policy
   allow-list, must refuse. Attacked by inventing action names and by handing in
   a policy that names an action this build has never heard of.
2. **Shadow cannot act** — attacked EXHAUSTIVELY: every combination of the
   inputs that produce ACT is re-run with mode='shadow', and none may return
   ACT. This is the property an operator relies on when they agree to run the
   loop for a quarter, so it is not enough to test the happy path.
3. **Refusals are machine-readable** — every returned reason must be in the
   closed REASONS set, or the receipt aggregates silently lose a category.

The fixture is a helper that returns the MINIMAL inputs for an ACT, so each test
perturbs exactly one thing. That matters: a test that builds its own dict per
case drifts, and then a refusal is credited to the wrong cause.
"""
import itertools
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-auto-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import autonomy as A  # noqa: E402


def _policy(**over):
    p = A.default_policy()
    p['mode'] = 'enabled'
    p['max_blast_radius'] = 5
    p.update(over)
    return p


def _inputs(**over):
    """The minimal set that yields ACT. Every test changes exactly one key."""
    base = dict(
        action='restart_service',
        policy=_policy(),
        module_enabled=True,
        tenant_ok=True,
        radius=A.blast_radius('d1', monitors=['m1']),
        precedent_conf=1.0,
        precedent_samples=3,
        backup_verified=True,
        in_window=True,
        actions_this_hour=0,
        dry_run_ok=True,
        has_plan=False,
    )
    base.update(over)
    return base


class TestTheFixtureActuallyActs(unittest.TestCase):
    """Positive control. Every refusal test below is meaningless if the baseline
    does not ACT — a broken fixture would make them all pass while proving
    nothing, which is the exact failure this project keeps finding."""

    def test_baseline_is_an_act(self):
        d = A.decide(**_inputs())
        self.assertEqual(d.verdict, A.ACT, d)
        self.assertTrue(d.acted)
        self.assertEqual(d['reason'], 'ok')


class TestDefaultDeny(unittest.TestCase):

    def test_unknown_action_refuses(self):
        for bogus in ('rm_rf', 'restart_Service', '', None, 'REBOOT'):
            d = A.decide(**_inputs(action=bogus))
            self.assertEqual(d.verdict, A.REFUSE, bogus)
            self.assertIn(d['reason'], ('unknown_action', 'action_not_allowed'))

    def test_action_not_in_allow_list_refuses(self):
        d = A.decide(**_inputs(policy=_policy(allowed_actions=['clear_cache'])))
        self.assertEqual(d.verdict, A.REFUSE)
        self.assertEqual(d['reason'], 'action_not_allowed')

    def test_policy_cannot_smuggle_in_an_unknown_action(self):
        """A policy written by hand or by a newer build must not enable an
        action this build has no safety analysis for."""
        p = A.normalize_policy({'mode': 'enabled',
                                'allowed_actions': ['restart_service', 'launch_missiles']})
        self.assertNotIn('launch_missiles', p['allowed_actions'])
        self.assertIn('restart_service', p['allowed_actions'])

    def test_unrecognised_mode_refuses(self):
        for mode in ('ENABLED', 'on', 'yes', '', None, 'shadow_mode'):
            d = A.decide(**_inputs(policy=_policy(mode=mode)))
            self.assertEqual(d.verdict, A.REFUSE, mode)
            self.assertEqual(d['reason'], 'mode_off')

    def test_shipped_default_does_nothing(self):
        """Not shadow — off. Shadow would start writing receipts about a fleet
        whose owner never opted in."""
        self.assertEqual(A.default_policy()['mode'], 'off')
        d = A.decide(**_inputs(policy=A.default_policy()))
        self.assertEqual(d.verdict, A.REFUSE)
        self.assertEqual(d['reason'], 'mode_off')

    def test_destructive_actions_are_not_allowed_by_default(self):
        allowed = A.default_policy()['allowed_actions']
        for name, spec in A.ACTION_CLASSES.items():
            if spec['destructive']:
                self.assertNotIn(name, allowed,
                                 f'{name} is destructive and default-allowed')


class TestShadowCanNeverAct(unittest.TestCase):
    """The property the whole adoption story rests on."""

    def test_shadow_returns_shadow_on_the_acting_baseline(self):
        d = A.decide(**_inputs(policy=_policy(mode='shadow')))
        self.assertEqual(d.verdict, A.SHADOW)

    def test_no_input_combination_lets_shadow_act(self):
        """Exhaustive over every axis that influences the verdict. If any
        combination reaches ACT under shadow, the mode is a lie."""
        axes = {
            'action': list(A.ACTION_CLASSES),
            'tenant_ok': [True, False],
            'precedent_conf': [0.0, 0.5, 1.0],
            'precedent_samples': [0, 2, 9],
            'backup_verified': [True, False],
            'in_window': [True, False],
            'actions_this_hour': [0, 99],
            'dry_run_ok': [True, False],
            'has_plan': [True, False],
        }
        keys = list(axes)
        combos = list(itertools.product(*(axes[k] for k in keys)))
        self.assertGreater(len(combos), 500, 'the sweep collapsed')
        pol = _policy(mode='shadow', allowed_actions=list(A.ACTION_CLASSES),
                      max_blast_radius=99)
        acted = []
        for combo in combos:
            kw = dict(zip(keys, combo))
            d = A.decide(**_inputs(policy=pol, **kw))
            if d.verdict == A.ACT:
                acted.append(kw)
        self.assertEqual(acted, [], f'shadow mode ACTED in {len(acted)} cases')

    def test_shadow_still_reports_what_it_would_have_done(self):
        """A shadow receipt that carried no reasoning would be useless for
        grading — the point is to be able to judge the decision."""
        d = A.decide(**_inputs(policy=_policy(mode='shadow')))
        self.assertEqual(d['action'], 'restart_service')
        self.assertIn('blast_radius', d)
        self.assertEqual(d['precedent_samples'], 3)


class TestEvidenceIsRequired(unittest.TestCase):

    def test_no_precedent_and_no_plan_refuses(self):
        d = A.decide(**_inputs(precedent_samples=0, has_plan=False))
        self.assertEqual(d.verdict, A.REFUSE)
        self.assertEqual(d['reason'], 'no_precedent')

    def test_weak_precedent_refuses(self):
        d = A.decide(**_inputs(precedent_samples=5, precedent_conf=0.4))
        self.assertEqual(d.verdict, A.REFUSE)
        self.assertEqual(d['reason'], 'low_confidence')

    def test_a_single_prior_incident_is_not_a_pattern(self):
        d = A.decide(**_inputs(precedent_samples=1, precedent_conf=1.0))
        self.assertEqual(d.verdict, A.REFUSE)
        self.assertEqual(d['reason'], 'no_precedent')

    def test_operator_confirmed_outcomes_outweigh_ai_ones(self):
        """An AI verdict nobody contradicted is weaker evidence than a human
        writing down what fixed it."""
        ai = [{'source': 'ai', 'resolution': 'x', 'recommended_action': 'restart nginx'}]
        human = [{'source': 'operator', 'resolution': 'x', 'recommended_action': 'restart nginx'}]
        mixed_bad_ai = ai + [{'source': 'ai', 'resolution': '', 'recommended_action': ''}]
        mixed_bad_human = human + [{'source': 'ai', 'resolution': '', 'recommended_action': ''}]
        _, _, act = A.precedent_confidence(human)
        self.assertEqual(act, 'restart nginx')
        self.assertGreater(A.precedent_confidence(mixed_bad_human)[0],
                           A.precedent_confidence(mixed_bad_ai)[0])

    def test_empty_precedent_is_zero_not_a_crash(self):
        self.assertEqual(A.precedent_confidence([])[0], 0.0)
        self.assertEqual(A.precedent_confidence(None)[0], 0.0)
        self.assertEqual(A.precedent_confidence([None, 'junk', 42])[0], 0.0)


class TestBlastRadius(unittest.TestCase):

    def test_over_the_limit_refuses_and_says_by_how_much(self):
        big = A.blast_radius('d1', monitors=['a', 'b'], containers=['c'],
                             status_services=['s'], peers=['p'])
        d = A.decide(**_inputs(radius=big, policy=_policy(max_blast_radius=2)))
        self.assertEqual(d.verdict, A.REFUSE)
        self.assertEqual(d['reason'], 'blast_radius')
        self.assertEqual(d['limit'], 2)
        self.assertEqual(d['blast_radius']['score'], 5)

    def test_redundancy_discounts_the_score(self):
        """Taking one of three replicas is not the same as taking the only one,
        and a policy that could not tell them apart would block everything."""
        alone = A.blast_radius('d1', monitors=['a', 'b', 'c'])
        one_of_three = A.blast_radius('d1', monitors=['a', 'b', 'c'],
                                      redundancy_group='web', group_size=3)
        self.assertEqual(alone['score'], 3)
        self.assertLess(one_of_three['score'], alone['score'])
        self.assertTrue(one_of_three['redundant'])

    def test_redundancy_never_discounts_to_zero(self):
        r = A.blast_radius('d1', monitors=['a'], redundancy_group='web',
                           group_size=50)
        self.assertGreaterEqual(r['score'], 1)

    def test_at_exactly_the_limit_is_allowed(self):
        r = A.blast_radius('d1', monitors=['a', 'b'])
        d = A.decide(**_inputs(radius=r, policy=_policy(max_blast_radius=2)))
        self.assertEqual(d.verdict, A.ACT, d)


class TestDestructiveActionsAreGated(unittest.TestCase):

    def _destructive_inputs(self, **over):
        pol = _policy(allowed_actions=['reboot'], approval_for_destructive=False)
        return _inputs(action='reboot', policy=pol, **over)

    def test_destructive_without_verified_backup_refuses(self):
        d = A.decide(**self._destructive_inputs(backup_verified=False))
        self.assertEqual(d.verdict, A.REFUSE)
        self.assertEqual(d['reason'], 'no_verified_backup')

    def test_destructive_with_verified_backup_may_act(self):
        d = A.decide(**self._destructive_inputs(backup_verified=True))
        self.assertEqual(d.verdict, A.ACT, d)

    def test_approval_flag_escalates_rather_than_acting(self):
        pol = _policy(allowed_actions=['reboot'], approval_for_destructive=True)
        d = A.decide(**_inputs(action='reboot', policy=pol))
        self.assertEqual(d.verdict, A.ESCALATE)
        self.assertEqual(d['reason'], 'needs_approval')

    def test_non_destructive_does_not_require_a_backup(self):
        d = A.decide(**_inputs(backup_verified=False))
        self.assertEqual(d.verdict, A.ACT, d)


class TestTheRemainingGuards(unittest.TestCase):

    def test_module_off_refuses_before_anything_else(self):
        d = A.decide(**_inputs(module_enabled=False))
        self.assertEqual(d['reason'], 'module_off')
        self.assertNotIn('blast_radius', d,
                         'a disabled module should not imply we looked at the fleet')

    def test_cross_tenant_refuses(self):
        d = A.decide(**_inputs(tenant_ok=False))
        self.assertEqual(d['reason'], 'tenant_mismatch')

    def test_outside_the_window_refuses(self):
        d = A.decide(**_inputs(in_window=False))
        self.assertEqual(d['reason'], 'outside_window')

    def test_window_can_be_waived_by_policy(self):
        d = A.decide(**_inputs(in_window=False, policy=_policy(require_window=False)))
        self.assertEqual(d.verdict, A.ACT, d)

    def test_rate_limit_refuses(self):
        d = A.decide(**_inputs(actions_this_hour=3,
                               policy=_policy(max_actions_per_hour=3)))
        self.assertEqual(d['reason'], 'rate_limited')

    def test_failed_dry_run_refuses(self):
        d = A.decide(**_inputs(dry_run_ok=False))
        self.assertEqual(d['reason'], 'dry_run_failed')


class TestEveryReasonIsMachineReadable(unittest.TestCase):

    def test_all_returned_reasons_are_in_the_closed_set(self):
        """A reason outside REASONS means the receipt aggregates silently lose a
        category — 'blocked 41 times for ???'."""
        cases = [
            _inputs(module_enabled=False), _inputs(policy=_policy(mode='off')),
            _inputs(action='nope'), _inputs(tenant_ok=False),
            _inputs(precedent_samples=0), _inputs(precedent_samples=5, precedent_conf=0.1),
            _inputs(radius=A.blast_radius('d', monitors=list('abcdefgh'))),
            _inputs(in_window=False), _inputs(actions_this_hour=99),
            _inputs(dry_run_ok=False), _inputs(),
            _inputs(policy=_policy(mode='shadow')),
        ]
        seen = set()
        for kw in cases:
            d = A.decide(**kw)
            self.assertIn(d['reason'], A.REASONS, d)
            self.assertIn(d['verdict'], A.VERDICTS, d)
            seen.add(d['reason'])
        self.assertGreaterEqual(len(seen), 9, f'only exercised {seen}')


class TestVerificationDecidesSuccess(unittest.TestCase):
    """The checks engine decides whether it worked — not a model, and not the
    absence of an exception."""

    def test_more_failing_checks_after_is_a_regression(self):
        self.assertTrue(A.verification_failed({'failing': 1}, {'failing': 2}))

    def test_same_or_fewer_is_not(self):
        self.assertFalse(A.verification_failed({'failing': 2}, {'failing': 2}))
        self.assertFalse(A.verification_failed({'failing': 2}, {'failing': 0}))

    def test_missing_counts_do_not_crash_or_falsely_roll_back(self):
        self.assertFalse(A.verification_failed(None, None))
        self.assertFalse(A.verification_failed({}, {}))


class TestReceiptIsSelfContained(unittest.TestCase):

    def test_it_carries_the_reasoning_not_a_pointer_to_it(self):
        """The alert will be pruned and the fleet will have changed by the time
        anyone asks why this happened."""
        plan = {'ts': 1, 'tenant': 'default', 'device_id': 'd1',
                'device_name': 'web01', 'trigger': 'unit_failed',
                'action': 'restart_service', 'command': 'systemctl restart nginx',
                'precedent_action': 'restart nginx', 'dry_run': 'ok'}
        d = A.decide(**_inputs())
        r = A.receipt(plan, d, outcome='ok', verified=True)
        for k in ('trigger', 'action', 'command', 'verdict', 'reason',
                  'blast_radius', 'precedent', 'dry_run', 'outcome', 'verified'):
            self.assertIn(k, r, k)
        self.assertEqual(r['precedent']['samples'], 3)
        self.assertEqual(r['device_name'], 'web01')
        self.assertFalse(r['rolled_back'])


if __name__ == '__main__':
    unittest.main()
