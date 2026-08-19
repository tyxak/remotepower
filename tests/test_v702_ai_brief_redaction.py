#!/usr/bin/env python3
"""The Ask-AI brief carried hostnames, against the promise on the button.

The Ask AI button on the Security Advisory page says it sends "a redacted
summary — titles, severities and host counts only, never the evidence". Two
docstrings repeat it, and the redaction is done server-side for exactly the
right reason: the AI provider may be off-box.

The redaction sends the finding TITLE. Most titles interpolate only counts
("12 pending package updates") and are fine. Four do not:

  TLS expired / expiring   f'TLS certificate for {label} ...' where label is
                           host:port — and the TLS monitor exists to watch
                           INTERNAL hosts, so this is internal DNS
  Protect check failing    an operator-authored check name
  External scanner finding the tool's own title, which can carry paths and URLs

So an operator who read the button and turned on a cloud AI provider was
sending internal hostnames to it. Findings can now declare an `ai_title`; the
brief prefers it.

The subtle half is the grouping: `summarize_for_ai` reads the GROUPS, not the
raw findings, so an `ai_title` that the grouping drops is a redaction that
silently does nothing. That is checked here on its own.
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('advisory_v702', _CGI / 'advisory.py')
advisory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(advisory)

_SECRETS = ('vault.internal.corp', 'git.internal.corp', '8200',
            'nightly-payroll-export', '/srv/secret/path',
            'admin:hunter2@10.0.0.9')


class TestNoHostnameReachesTheBrief(unittest.TestCase):

    def _brief_from_tls(self, tls_expiring):
        """The REAL path: build() groups, summarize_for_ai redacts. There is no
        standalone group_findings — the grouping is inline in build(), and it is
        the step that used to drop ai_title, so going through it is the point."""
        adv = advisory.build({'d1': {'name': 'web01'}},
                             tls_expiring=tls_expiring, now=1_700_000_000)
        return advisory.summarize_for_ai(adv, 'the fleet')

    def _brief(self, findings):
        """summarize_for_ai over hand-built groups, for the cases where
        driving build() would need a whole fleet fixture."""
        return advisory.summarize_for_ai(
            {'findings': findings, 'device_count': 3}, 'the fleet')

    def test_a_tls_hostname_does_not_leave_the_box(self):
        brief = self._brief_from_tls([
            {'label': 'vault.internal.corp:8200', 'days_left': -3},
            {'label': 'git.internal.corp', 'days_left': 5}])
        for s in ('vault.internal.corp', 'git.internal.corp', '8200'):
            self.assertNotIn(s, brief, f'{s} reached the AI provider')

    def test_the_finding_still_says_it_in_the_UI(self):
        """The control. Redacting the operator's own screen would be a
        regression dressed as a fix — they need to know WHICH certificate."""
        f = advisory._tls_findings([{'label': 'vault.internal.corp:8200',
                                     'days_left': -3}])
        self.assertIn('vault.internal.corp:8200', f[0]['title'])

    def test_the_severity_and_shape_survive_redaction(self):
        """A brief that redacted itself into uselessness would pass the test
        above. The model still needs the layer, the severity and the count."""
        brief = self._brief_from_tls([
            {'label': 'vault.internal.corp:8200', 'days_left': -3}])
        self.assertIn('CRITICAL', brief)
        self.assertIn('exposure', brief)
        self.assertIn('host(s)', brief)
        self.assertIn('TLS certificate', brief)

    def test_a_count_only_title_is_sent_unchanged(self):
        """Most titles carry no evidence and must not be flattened — "12
        pending updates" is the information."""
        f = advisory._finding('os.patch', 'os', 'medium',
                              '12 pending package updates', 'why', 'fix')
        self.assertIn('12 pending package updates', self._brief([f]))


class TestTheGroupingCarriesItThrough(unittest.TestCase):
    """summarize_for_ai reads the groups. An ai_title dropped here is a
    redaction that does nothing, and every test above would still pass if the
    brief happened to be built from raw findings."""

    def test_the_grouping_keeps_ai_title(self):
        adv = advisory.build({'d1': {'name': 'web01'}},
                             tls_expiring=[{'label': 'vault.internal.corp',
                                            'days_left': -1}],
                             now=1_700_000_000)
        tls = [g for g in adv['findings'] if g['id'].startswith('exp.tls')]
        self.assertTrue(tls, 'no TLS group built — the fixture is wrong')
        self.assertEqual(tls[0].get('ai_title'),
                         'A monitored TLS certificate has expired')

    def test_the_brief_reads_the_grouped_findings(self):
        """States the coupling the tests above depend on, so a refactor that
        changed it would fail here rather than silently."""
        import inspect
        src = inspect.getsource(advisory.summarize_for_ai)
        self.assertIn("advisory.get('findings')", src)
        self.assertIn('ai_title', src)


class TestEveryRiskyTitleDeclaresOne(unittest.TestCase):
    """The population, not the rule. A title interpolating a COUNT is safe; one
    interpolating anything else is the thing that broke the promise, and a new
    one added next year must be caught."""

    SAFE = re.compile(
        r'^(len\(|.*\bdays\b|.*\battempts\b|.*\bupgradable\b|.*\bsec\b|'
        r'.*\bdev\.get\(.os.\)|.*scap_rec)', re.S)

    def test_no_interpolated_title_lacks_ai_title_unless_it_is_a_count(self):
        import ast
        src = (_CGI / 'advisory.py').read_text()
        offenders = []
        for node in ast.walk(ast.parse(src)):
            if not (isinstance(node, ast.Call)
                    and getattr(node.func, 'id', '') == '_finding'):
                continue
            if len(node.args) < 4:
                continue
            title = node.args[3]
            if isinstance(title, ast.Constant):
                continue          # a literal carries nothing
            has_ai = any(k.arg == 'ai_title' for k in node.keywords)
            if has_ai:
                continue
            # Which values does the f-string interpolate?
            vals = [ast.unparse(v.value) for v in ast.walk(title)
                    if isinstance(v, ast.FormattedValue)]
            # Counts and scores are numbers about the fleet, not names from
            # inside it. Anything else is a candidate.
            risky = [v for v in vals if not (
                v.startswith('len(') or v in ('days', 'attempts', 'upgradable',
                                              'sec', 'tool', 'score')
                or 'len(' in v or v.startswith("dev.get('os')")
                or v.startswith('scap_rec'))]
            if risky:
                offenders.append(f'advisory.py:{node.lineno}: {risky}')
        self.assertEqual(offenders, [],
                         'these titles interpolate something other than a '
                         'count and are sent to the AI provider — give each an '
                         'ai_title:\n  ' + '\n  '.join(offenders))

    def test_the_scanner_would_notice_a_new_one(self):
        """Positive control: without it, a broken visitor reports zero
        offenders and reads as a clean file."""
        import ast
        src = ("_finding('a.b', 'os', 'high', f'leaky {hostname} here', 'w', 'f')\n")
        found = 0
        for node in ast.walk(ast.parse(src)):
            if (isinstance(node, ast.Call)
                    and getattr(node.func, 'id', '') == '_finding'
                    and not isinstance(node.args[3], ast.Constant)
                    and not any(k.arg == 'ai_title' for k in node.keywords)):
                found += 1
        self.assertEqual(found, 1)


if __name__ == '__main__':
    unittest.main()
