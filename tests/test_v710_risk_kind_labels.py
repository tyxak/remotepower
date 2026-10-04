"""Risk factor chips carry a label, and every label is translated.

A Risk row listed its factors as the machine kind with underscores removed and the points
appended, "cve kev +12", in one text node. That is neither readable English nor a dictionary key.
Each kind now has a short label in `_RISK_KIND_LABEL`, rendered in its own span, and every label
has an entry in all six languages.

The population is the server's own weight table: a factor added to `_RISK_WEIGHTS` without a label
and a translation fails here.
"""
import ast
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v710_i18n_glue import dict_rows   # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text(encoding='utf-8')
_API = _ROOT / 'server' / 'cgi-bin' / 'api.py'
_LANGS = ('de', 'fr', 'es', 'zh', 'hi', 'ar')


def server_kinds():
    mod = ast.parse(_API.read_text(encoding='utf-8'))
    for node in mod.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '_RISK_WEIGHTS' for t in node.targets):
            return {k.value for k in node.value.keys}
    raise AssertionError('_RISK_WEIGHTS not found in api.py')


def js_labels():
    m = re.search(r'const _RISK_KIND_LABEL = \{(.*?)\n\};', _APP, re.S)
    assert m, '_RISK_KIND_LABEL not found in app.js'
    return dict(re.findall(r"(\w+): '([^']*)'", m.group(1)))


class TestRiskKindLabels(unittest.TestCase):

    def test_there_are_server_kinds_and_labels(self):
        """Control: an empty population would make the checks below pass without looking."""
        self.assertGreaterEqual(len(server_kinds()), 35)
        self.assertGreaterEqual(len(js_labels()), 35)

    def test_every_server_kind_has_a_label_and_nothing_else_does(self):
        kinds, labels = server_kinds(), js_labels()
        self.assertEqual([], sorted(kinds - set(labels)), 'risk factor kinds with no chip label')
        self.assertEqual([], sorted(set(labels) - kinds), 'labels for kinds the server never sends')

    def test_every_label_is_translated_into_all_six_languages(self):
        rows = dict_rows()
        missing = [lab for lab in sorted(set(js_labels().values()))
                   if not (rows.get(lab) and all(rows[lab].get(l) for l in _LANGS))]
        self.assertEqual([], missing)

    def test_the_chip_renders_the_label_in_its_own_span(self):
        self.assertIn("<span>${escHtml(_RISK_KIND_LABEL[f.kind] || f.kind.replace(/_/g, ' '))}</span> +${f.points}", _APP)


if __name__ == '__main__':
    unittest.main()
