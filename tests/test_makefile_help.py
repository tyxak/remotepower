#!/usr/bin/env python3
"""`make help` must describe the Makefile that exists.

It had drifted to advertising "1064+ tests" against an actual 11,305 — off by
an order of magnitude — while omitting `pre-release`, the gate a production
push is not allowed to skip, and every backend-specific test target. `make
help` is what a contributor reads first, so a stale one teaches the wrong
workflow on contact.

This pins it BOTH ways, which is the part that keeps it honest:
  * a target advertised in help that does not exist  -> a broken instruction
  * a target that exists and is not in help          -> an undiscoverable one

The second is how it decayed: nine targets were added over several releases and
none of them reached the help text, because nothing required it.
"""
import re
import unittest
from pathlib import Path

_MK = Path(__file__).resolve().parent.parent / 'Makefile'


@unittest.skipUnless(_MK.exists(), 'excluded from dist tree')
class TestMakeHelpMatchesTheMakefile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = _MK.read_text()
        i = src.index('help:\n')
        j = src.index('\n\n', i)
        cls.help = src[i:j]
        cls.advertised = set(re.findall(r'make ([a-z][a-z0-9-]*)', cls.help))
        cls.real = set(re.findall(r'^([a-z][a-z0-9-]*):', src, re.M))

    def test_the_help_block_was_found(self):
        """Without this, a changed layout would empty both sets and the two
        assertions below would pass against nothing."""
        self.assertGreater(len(self.advertised), 15)
        self.assertGreater(len(self.real), 15)

    def test_every_advertised_target_exists(self):
        missing = sorted(self.advertised - self.real)
        self.assertEqual(missing, [], f'help advertises targets that do not '
                                      f'exist: {missing}')

    def test_every_target_is_advertised(self):
        undocumented = sorted(self.real - self.advertised - {'help'})
        self.assertEqual(undocumented, [], '\n'.join([
            'these targets exist but `make help` does not mention them:',
            *undocumented, '',
            'Add a line. This is how the help text decayed into describing a '
            'fraction of the Makefile while claiming a test count from years '
            'earlier.']))

    def test_the_pre_tag_gate_is_documented_as_such(self):
        """`make check` is NOT the release gate and the help text used to imply
        it was ("CI gate"), while omitting pre-release entirely — which is the
        one a production push cannot skip."""
        self.assertIn('pre-release', self.help)
        self.assertIn('stamp', self.help,
                      'help should say pre-release writes the push stamp the '
                      'pre-push hook requires — that is why it cannot be skipped')

    def test_no_stale_test_count(self):
        """The specific rot: a hardcoded count that aged a decade."""
        counts = re.findall(r'([0-9,]{3,})\+? tests', self.help)
        self.assertEqual(counts, [], f'help hardcodes a test count {counts}; it '
                                     'will be wrong within a week — describe '
                                     'what the target does instead')


if __name__ == '__main__':
    unittest.main()
