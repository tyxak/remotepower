#!/usr/bin/env python3
"""The decision core's validation must survive `python -O`.

`_decision()` is the single chokepoint that refuses an unrecognised verdict or
an undeclared reason, in the module whose entire job is to be the mechanical
gate on running commands against production hosts. It was written with two
`assert` statements.

`python -O` removes asserts. So under optimisation the only thing keeping a
typo'd verdict out of a receipt — and out of the ACT branch — would silently not
exist. Nothing in this repo runs the server with `-O` today, which is exactly
what makes it worth pinning: the failure would arrive as a deployment change
nobody connected to autonomy, and it would arrive silently.

bandit flags this as B101 at Low severity and it is not a false positive here.
The severity is about the general case; this instance is the validation on the
highest-stakes decision in the product.

The test runs a real child interpreter with `-O`, because asserting it in this
process proves nothing — this process is not optimised, so the asserts would
still be present and every check would pass whether or not the fix is there.
"""
import subprocess
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'

_PROBE = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('autonomy_o', {cgi!r} + '/autonomy.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
print('OPTIMISED' if not __debug__ else 'NOT-OPTIMISED')
try:
    a._decision('not-a-verdict', 'ok')
    print('VERDICT-ACCEPTED')
except Exception as e:
    print('VERDICT-REJECTED', type(e).__name__)
try:
    a._decision(a.REFUSE, 'not-a-declared-reason')
    print('REASON-ACCEPTED')
except Exception as e:
    print('REASON-REJECTED', type(e).__name__)
"""


def _run(*flags):
    r = subprocess.run([sys.executable, *flags, '-c', _PROBE.format(cgi=str(_CGI))],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise AssertionError(f'probe failed: {r.stderr[-800:]}')
    return r.stdout.split()


class TestTheProbeIsMeasuringWhatItThinks(unittest.TestCase):
    """Without these, "rejected under -O" could mean the flag never applied."""

    def test_the_child_without_O_is_not_optimised(self):
        self.assertIn('NOT-OPTIMISED', _run())

    def test_the_child_with_O_really_is_optimised(self):
        self.assertIn('OPTIMISED', _run('-O'))
        self.assertNotIn('NOT-OPTIMISED', _run('-O'))


class TestValidationHoldsUnderOptimisation(unittest.TestCase):

    def test_an_unknown_verdict_is_rejected_with_O(self):
        out = _run('-O')
        self.assertIn('VERDICT-REJECTED', out,
                      'an unrecognised verdict was ACCEPTED under -O — the '
                      'check is an assert and the interpreter removed it')

    def test_an_undeclared_reason_is_rejected_with_O(self):
        out = _run('-O')
        self.assertIn('REASON-REJECTED', out,
                      'an undeclared reason was ACCEPTED under -O, so a receipt '
                      'could carry a refusal code the UI cannot aggregate')

    def test_it_is_rejected_without_O_too(self):
        out = _run()
        self.assertIn('VERDICT-REJECTED', out)
        self.assertIn('REASON-REJECTED', out)

    def test_the_source_carries_no_assert_based_validation(self):
        """Direct check on the mechanism, so the intent survives a refactor
        that keeps the behaviour but reintroduces an assert."""
        src = (_CGI / 'autonomy.py').read_text(encoding='utf-8')
        offenders = [ln.strip() for ln in src.split('\n')
                     if ln.strip().startswith('assert ')]
        self.assertEqual(
            offenders, [],
            'autonomy.py validates with assert again, which `python -O` '
            'removes:\n' + '\n'.join('  ' + o for o in offenders))


if __name__ == '__main__':
    unittest.main()
