#!/usr/bin/env python3
"""The demo install showed the bug this release fixes, not the fix.

v7.0.2 is about the autonomy loop refusing everything for want of precedent.
`MIN_PRECEDENT_SAMPLES` is 2, and the demo seeder wrote three incident outcomes,
one per signature. So a demo Autonomy page showed `no_precedent` on every
decision — the exact state the release notes describe as the problem.

It also carried no `fix_command` on any row. That is the strongest of the three
precedent sources and the only machine-checkable one: `outcome_action` reads it
ahead of an AI recommendation and ahead of an operator's prose. Nothing on the
demo exercised the capture path v7.0.2 added.

CLAUDE.md's rule for this: the seeder is a producer under contract, and the
rendered gates all measure the seeded instance — so a seeder that cannot reach a
feature's threshold makes that feature invisible to every one of them.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-seedprec-'))
_spec = importlib.util.spec_from_file_location('api_seed_prec', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import autonomy                                                  # noqa: E402


def _seeder():
    p = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not p.exists():
        return None
    spec = importlib.util.spec_from_loader(
        'rp_seed_prec',
        importlib.machinery.SourceFileLoader('rp_seed_prec', str(p)))
    m = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(m)
    except SystemExit:
        pass
    return m


class TestTheDemoCanReachThePrecedentThreshold(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.seed = _seeder()
        if cls.seed is None:
            raise unittest.SkipTest('seeder excluded from dist tree')
        cls.rows = cls.seed.build_incident_memory()['outcomes']

    def test_the_threshold_is_what_we_think_it_is(self):
        """Premise. If MIN_PRECEDENT_SAMPLES moves, the count below has to
        move with it — pin the relationship, not the number."""
        self.assertGreaterEqual(autonomy.MIN_PRECEDENT_SAMPLES, 1)

    def test_at_least_one_signature_has_enough_samples(self):
        counts = Counter((r.get('event'), r.get('kind')) for r in self.rows)
        best = counts.most_common(1)[0] if counts else ((None, None), 0)
        self.assertGreaterEqual(
            best[1], autonomy.MIN_PRECEDENT_SAMPLES,
            f'the widest signature has {best[1]} outcome(s) against a '
            f'threshold of {autonomy.MIN_PRECEDENT_SAMPLES} — the demo '
            f'Autonomy page refuses everything with no_precedent, which is the '
            f'state this release exists to fix')

    def test_every_outcome_yields_an_action(self):
        """An outcome that yields no action counts toward the denominator and
        nothing toward the numerator — the arithmetic that made a fleet whose
        incidents people fix score lower than one with no memory."""
        empty = [r.get('alert_id') for r in self.rows
                 if not autonomy.outcome_action(r)]
        self.assertEqual([], empty, f'outcomes with no action: {empty}')

    def test_the_machine_checkable_source_is_represented(self):
        """`fix_command` is what outcome_action reads first and the only one
        that is not prose. A demo without it never shows the capture path
        v7.0.2 added."""
        n = sum(1 for r in self.rows if str(r.get('fix_command') or '').strip())
        self.assertGreaterEqual(n, 2, 'no seeded outcome carries a fix_command')

    def test_all_three_capture_sources_appear(self):
        """Operator fix, automation-rule remediation, and the loop's own
        verified action — the three the release notes name."""
        srcs = {r.get('source') for r in self.rows}
        for want in ('operator', 'automation', 'autonomy'):
            self.assertIn(want, srcs, f'no seeded outcome from {want}')

    def test_the_fix_commands_use_the_typed_grammar(self):
        """A raw shell string bypasses the platform table and the
        maintenance/quarantine gates, so a demo teaching the wrong shape is
        worse than one teaching none."""
        for r in self.rows:
            cmd = str(r.get('fix_command') or '').strip()
            if not cmd:
                continue
            with self.subTest(cmd=cmd):
                self.assertRegex(cmd, r'^(svc|container|exec|ps):')

    def test_the_seen_ring_covers_every_row(self):
        """capture_fix_outcome is idempotent per alert via this ring. A row
        absent from it would be re-captured by the next sweep and two outcomes
        from one incident satisfy a threshold of two on the strength of one."""
        mem = self.seed.build_incident_memory()
        self.assertEqual(sorted(r['alert_id'] for r in mem['outcomes']),
                         sorted(mem['seen']))

    def test_alert_ids_are_unique(self):
        ids = [r['alert_id'] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == '__main__':
    unittest.main()
