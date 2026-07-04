"""Wave-1 improvement-program guardrails (internal plan: improvement-program).

One test class per shipped wave-1 item. Each class is self-contained so
items can land (and be reviewed) one commit at a time.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestGrafanaDashboard(unittest.TestCase):
    """W1-46: contrib/grafana dashboard stays valid + in sync with the
    /api/metrics exposition (prometheus_export.py)."""

    DASH = ROOT / 'contrib' / 'grafana' / 'remotepower-fleet.json'
    EXPORT = ROOT / 'server' / 'cgi-bin' / 'prometheus_export.py'

    def _dashboard(self):
        return json.loads(self.DASH.read_text())

    def test_dashboard_parses_and_has_panels(self):
        d = self._dashboard()
        self.assertEqual(d['uid'], 'remotepower-fleet')
        panels = [p for p in d['panels'] if p.get('type') != 'row']
        self.assertGreaterEqual(len(panels), 15)
        # importable: datasource is the __inputs template var, not a baked uid
        self.assertEqual(d['__inputs'][0]['name'], 'DS_PROMETHEUS')

    def test_every_dashboard_metric_exists_in_exposition(self):
        exported = set(re.findall(r'remotepower_[a-z0-9_]+',
                                  self.EXPORT.read_text()))
        used = set(re.findall(r'remotepower_[a-z0-9_]+',
                              self.DASH.read_text()))
        self.assertTrue(used, 'dashboard references no metrics?')
        missing = used - exported
        self.assertFalse(
            missing,
            f'dashboard queries metrics the exposition never emits: {missing}')

    def test_panels_have_datasource_and_targets(self):
        d = self._dashboard()
        for p in d['panels']:
            if p.get('type') == 'row':
                continue
            self.assertTrue(p.get('targets'), f'panel {p["title"]}: no targets')
            for t in p['targets']:
                self.assertEqual(t['datasource']['uid'], '${DS_PROMETHEUS}',
                                 f'panel {p["title"]}: hard-wired datasource')

    def test_docs_link_the_dashboard(self):
        self.assertIn('contrib/grafana', (ROOT / 'docs' / 'README.md').read_text())
        self.assertIn('contrib/grafana',
                      (ROOT / 'server' / 'html' / 'index.html').read_text())


if __name__ == '__main__':
    unittest.main()
