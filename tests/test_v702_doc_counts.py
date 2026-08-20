#!/usr/bin/env python3
"""Counts quoted in the docs must match the code.

CLAUDE.md records that the connector count has shipped wrong twice. It had
drifted again: features.md and the README both said **44** while the registry
held 49 (48 named apps plus the generic Custom HTTP probe, which both documents
already list separately).

A number in prose has no way to stay true on its own — nobody re-counts when
adding the fiftieth connector. So the number gets asked of the code here rather
than trusted, and the failure message says what to change it to.

Deliberately narrow. It covers the counts that (a) a reader would act on and
(b) can be derived unambiguously. A count that needs judgement to define is
worse pinned than unpinned, because the pin then argues with every honest
change.
"""
import importlib.util
import os
import pathlib
import re
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702dc-'))
sys.path.insert(0, str(_CGI))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTheConnectorCountIsCurrent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        integ = _load('integrations_v702dc', _CGI / 'integrations.py')
        cls.registered = set(integ.CONNECTORS)
        # `custom_probe` is the generic user-defined HTTP check, which both
        # documents count separately as "+ Custom HTTP".
        cls.named = cls.registered - {'custom_probe'}

    def test_the_registry_is_populated(self):
        """Positive control — an import that registered nothing would make
        every assertion below agree with any number."""
        self.assertGreater(len(self.registered), 30)
        self.assertIn('custom_probe', self.registered,
                      'the generic probe is gone, so the "+ Custom HTTP" '
                      'phrasing in the docs no longer describes anything')

    def test_features_md_matches(self):
        row = (_ROOT / 'docs' / 'features.md').read_text()
        m = re.search(r'\|\s*(\d+)\s+connectors \(\+ Custom HTTP\)', row)
        self.assertTrue(m, 'the connectors row moved or was reworded')
        self.assertEqual(int(m.group(1)), len(self.named),
                         f'docs/features.md says {m.group(1)}; there are '
                         f'{len(self.named)} named connectors')

    def test_readme_matches(self):
        txt = (_ROOT / 'README.md').read_text()
        m = re.search(r'\*\*Integrate\*\* — (\d+) connectors', txt)
        self.assertTrue(m, 'the README integrate line moved or was reworded')
        self.assertEqual(int(m.group(1)), len(self.named),
                         f'README.md says {m.group(1)}; there are '
                         f'{len(self.named)} named connectors')

    def test_both_documents_agree_with_each_other(self):
        """They drifted apart before agreeing with the code again; a mismatch
        between them is its own signal."""
        feat = re.search(r'\|\s*(\d+)\s+connectors \(\+ Custom HTTP\)',
                         (_ROOT / 'docs' / 'features.md').read_text())
        rd = re.search(r'\*\*Integrate\*\* — (\d+) connectors',
                       (_ROOT / 'README.md').read_text())
        self.assertEqual(feat.group(1), rd.group(1))


class TestTheAutonomyActionCountIsCurrent(unittest.TestCase):
    """The action catalog is quoted in the release docs and drives a policy
    checkbox per action, so a wrong number is a wrong safety story."""

    def test_the_release_pins_it(self):
        autonomy = _load('autonomy_v702dc', _CGI / 'autonomy.py')
        n = len(autonomy.ACTION_CLASSES)
        self.assertGreater(n, 10, 'the catalog is empty — nothing below means '
                                  'anything')
        pins = (_ROOT / 'tests' / 'test_v702.py').read_text()
        m = re.search(r'len\(\s*\w*\.?ACTION_CLASSES\s*\)\s*,\s*(\d+)', pins)
        if not m:
            self.skipTest('the release pins the catalog some other way')
        self.assertEqual(int(m.group(1)), n)


if __name__ == '__main__':
    unittest.main()
