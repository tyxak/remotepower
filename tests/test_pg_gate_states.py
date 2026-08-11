#!/usr/bin/env python3
"""The Postgres gate has THREE states and must treat them differently.

v6.4.3 put Postgres — the enterprise default since v6.1.0 — into the release
gate for the first time, because its suite had been self-skipping for three
years while printing OK. The first version of that fix over-corrected:
`PG_STRICT=1` failed on ANY skip, which on a machine with no Postgres and no
container runtime made `make pre-release` impossible to pass.

That is not a stricter gate, it is a bypassed one. The pre-push hook can only
be satisfied by `make pre-release` writing its stamp, so an unpassable
sub-gate routes the maintainer to `git push --no-verify` — which skips the
other four sub-gates (both backends, the staged dist tree, CI-dep parity and
CodeQL) as well. CLAUDE.md records that `--no-verify` has already been used
once for a prod push; making it the only route would make it routine.

So the three states:

  1. DSN configured, database REACHABLE  → tests run. Pass.
  2. DSN configured, database DEAD       → hard fail under PG_STRICT, with NO
                                           override. This is the state that
                                           lies: it looks like coverage and is
                                           not, and it is what this box was in.
  3. No DSN at all                       → fail under PG_STRICT unless the
                                           operator sets RP_PG_CI_ONLY=1,
                                           which says out loud that Postgres
                                           coverage is deferred to CI (where
                                           RP_PG_REQUIRE=1 runs it for real on
                                           every release push).

State 3's escape hatch is a skip switch, and that is the point: an explicit,
logged choice is a different thing from a silent one. The whole release is
about that distinction.

Source-level, because exercising the real target needs a Postgres — which is
precisely what may not exist.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_MK = _ROOT / 'Makefile'
_TESTPG = _ROOT / 'tests' / 'test_pg.py'


@unittest.skipUnless(_MK.exists(), 'excluded from dist tree')
class TestTheThreeStates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = _MK.read_text()
        i = src.index('\ntest-pg:')
        j = src.index('\n\n', i)
        cls.recipe = src[i:j]

    def test_the_recipe_was_found(self):
        """Without this, every assertion below would run against ''."""
        self.assertIn('unittest tests.test_pg', self.recipe)
        self.assertGreater(len(self.recipe), 500)

    def test_a_dead_dsn_fails_regardless_of_the_ci_only_override(self):
        """The override must not rescue state 2. A configured-but-unreachable
        DSN is the dangerous state — it reads as coverage."""
        # the dead-DSN branch must be checked BEFORE the RP_PG_CI_ONLY branch,
        # and must not itself consult RP_PG_CI_ONLY
        i_dead = self.recipe.index('$$dead')
        i_ci = self.recipe.index('RP_PG_CI_ONLY')
        self.assertLess(i_dead, i_ci,
                        'the CI-only override is evaluated before the dead-DSN '
                        'check, so an unreachable database can be waved through')
        branch = self.recipe[i_dead:i_ci]
        self.assertIn('exit 1', branch)

    def test_no_dsn_fails_without_the_explicit_override(self):
        self.assertRegex(
            self.recipe,
            r'PG_STRICT\)"\s*\]\s*&&\s*\[\s*-z\s*"\$\$RP_PG_CI_ONLY"',
            'the no-DSN path no longer requires an explicit acknowledgement')

    def test_the_override_is_reported_not_silent(self):
        """A skip switch that prints nothing is the thing this release removed."""
        self.assertIn('DEFERRED TO CI', self.recipe)

    def test_pre_release_still_sets_pg_strict(self):
        mk = _MK.read_text()
        self.assertRegex(mk, re.compile(r'^pre-release:\s*PG_STRICT\s*=\s*1', re.M))
        self.assertRegex(mk, re.compile(r'^pre-release:.*\btest-pg\b', re.M),
                         'test-pg dropped out of the pre-release chain')

    def test_the_two_skip_reasons_the_recipe_greps_for_both_exist(self):
        """The recipe classifies by matching the skip TEXT. If either string is
        reworded in test_pg.py, the classification silently collapses — a dead
        DSN would stop being detected as such and fall through to the
        overridable branch."""
        src = _TESTPG.read_text()
        for phrase in ('no Postgres DSN', 'DSN configured but unreachable'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, src,
                              f'{phrase!r} is gone from test_pg.py but the '
                              'Makefile still greps for it')
                self.assertIn(phrase, self.recipe)


if __name__ == '__main__':
    unittest.main()
