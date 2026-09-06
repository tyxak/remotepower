#!/usr/bin/env python3
"""Three registries describe the report's sections and all three disagreed.

  * the server tuple `_ALL_REPORT_SECTIONS` — what a definition may select and
    what the JSON carries;
  * `_REPORT_SECTION_LABELS` in app.js — the checkbox list in the Custom
    reports editor;
  * `report.js` — what the printed document actually renders.

`posture` was in the server tuple and missing from the labels, so its checkbox
rendered as the raw slug. The comment directly above that object predicts
exactly that outcome and nothing checked it.

Worse, `sla` and `attention` appeared in the server tuple AND in the labels and
were rendered nowhere in the printed document. An operator ticked "SLA /
uptime", the server measured thirty days of fleet uptime, shipped it in the
JSON, and the PDF said nothing about it — which for an MSP report is often the
figure the document exists for. The CSV renderer emits both; only the printed
one dropped them, and a section that renders nothing is indistinguishable from
one that was never selected.

So this pins the three against each other rather than pinning a list. Adding a
section to the server tuple now fails here until it has a label and a renderer.
"""
import ast
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_REPORTS = _ROOT / 'server' / 'cgi-bin' / 'reports_handlers.py'
_APP = _ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
_REPORT_JS = _ROOT / 'server' / 'html' / 'static' / 'js' / 'report.js'

# Sections the printed document renders through another section's block rather
# than one of its own, with the reason.
RENDERED_ELSEWHERE = {
    'devices': 'the four summary cards at the top carry online/total',
    'health': 'the Health card carries the score and grade',
    'patches': 'the Patches card carries the pending count',
    'cve': 'the CVEs card carries the critical and high counts',
}


def server_sections():
    tree = ast.parse(_REPORTS.read_text(encoding='utf-8'))
    found = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in ('_REPORT_SECTIONS',
                                                    '_REPORT_OPT_IN_SECTIONS'):
                found[t.id] = [e.value for e in node.value.elts
                               if isinstance(e, ast.Constant)]
    assert found, 'the report section tuples are no longer module constants'
    return found.get('_REPORT_SECTIONS', []) + found.get('_REPORT_OPT_IN_SECTIONS', [])


def client_labels():
    """Strip comments first — a `// v7.0.3:` line inside the object matches the
    key pattern and the version number arrives as a section called '3'. The
    detector was wrong before the registry was, which is the usual order."""
    src = _APP.read_text(encoding='utf-8')
    i = src.index('const _REPORT_SECTION_LABELS = {')
    block = src[i:src.index('};', i)]
    code = '\n'.join(l for l in block.splitlines()
                     if not l.lstrip().startswith('//'))
    return set(re.findall(r'(\w+)\s*:\s*[\'"]', code))


def rendered_sections():
    return set(re.findall(r'rep\.([a-z_]+)', _REPORT_JS.read_text(encoding='utf-8')))


class TestTheThreeRegistriesAgree(unittest.TestCase):

    def test_every_server_section_has_a_checkbox_label(self):
        missing = sorted(set(server_sections()) - client_labels())
        self.assertEqual(
            missing, [],
            'these sections can be selected but have no label, so the '
            'checkbox shows the raw slug: ' + str(missing))

    def test_every_server_section_reaches_the_printed_document(self):
        rendered = rendered_sections()
        missing = sorted(s for s in server_sections()
                         if s not in rendered and s not in RENDERED_ELSEWHERE)
        self.assertEqual(
            missing, [],
            'these sections are selectable and computed and the printed report '
            'renders nothing for them, which is indistinguishable from not '
            'having selected them: ' + str(missing))

    def test_no_label_names_a_section_the_server_does_not_have(self):
        extra = sorted(client_labels() - set(server_sections()))
        self.assertEqual(extra, [],
                         f'checkbox for a section the server ignores: {extra}')

    def test_every_render_exemption_is_still_a_real_section(self):
        stale = sorted(set(RENDERED_ELSEWHERE) - set(server_sections()))
        self.assertEqual(stale, [],
                         f'exemption for a section that is gone: {stale}')


class TestTheDerivationsAreHonest(unittest.TestCase):

    def test_all_three_derivations_are_non_empty(self):
        self.assertGreaterEqual(len(server_sections()), 8, server_sections())
        self.assertGreaterEqual(len(client_labels()), 8, sorted(client_labels()))
        self.assertGreaterEqual(len(rendered_sections()), 8,
                                sorted(rendered_sections()))

    def test_the_two_that_were_missing_are_rendered_now(self):
        rendered = rendered_sections()
        for s in ('sla', 'attention'):
            self.assertIn(s, rendered,
                          f'{s} is back to being computed and never printed')

    def test_posture_has_its_label(self):
        self.assertIn('posture', client_labels())


if __name__ == '__main__':
    unittest.main()
