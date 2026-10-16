"""No native alert(), confirm() or prompt() in any client script.

Browsers throttle and suppress native dialogs after a few in a row (the "the UI
looks locked" bug that brought uiConfirm in), they cannot be styled or
translated, and prompt() shows a typed password in clear text. The earlier gate
(test_v480.TestNativeConfirmMigrated) read two files of 49 and only the negated
`!confirm(` form, and never looked for alert(): a guard whose population was two
files. This one reads every script under static/js.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'

# A call, not a mention: `alert(s)` in a sentence and `confirm()` in prose are
# not calls, and neither is a method such as `modal.confirm(`. A call is written
# with no space before the parenthesis; prose inside a multi-line template
# ("a device offline alert (0 = default)") has one.
_CALL = re.compile(r'(?<![\w.$])(?:window\.)?(alert|confirm|prompt)\((?![s)]\))')
_STRING = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"|`(?:[^`\\\n]|\\.)*`")


def native_calls(src):
    """[(line number, dialog)] for every native dialog call outside comments and
    string literals."""
    out = []
    for n, line in enumerate(src.split('\n'), 1):
        s = line.lstrip()
        if s.startswith(('//', '*', '/*')):
            continue
        code = _STRING.sub('""', line.split(' // ')[0])
        out += [(n, m.group(1)) for m in _CALL.finditer(code)]
    return out


class TestNoNativeDialogs(unittest.TestCase):

    def test_the_scanner_sees_a_call_and_skips_a_mention(self):
        """Control: without it, a scanner that matched nothing would pass."""
        sample = ("alert('x');\nif (!confirm('sure?')) return;\nconst v = window.prompt('n');\n"
                  "// prose that says confirm() and prompt()\ntoast(`Cleared ${n} alert(s)`);\n"
                  "const s = 'call alert() later';\nmodal.confirm(x);\nuiConfirm({});\n"
                  "  raises an offline alert (0 = default) and a system prompt (12 chars)\n")
        self.assertEqual(native_calls(sample), [(1, 'alert'), (2, 'confirm'), (3, 'prompt')])

    def test_every_client_script_is_read(self):
        scripts = sorted(_JS.glob('*.js'))
        self.assertGreaterEqual(len(scripts), 40, 'control: the population of scripts')
        self.assertIn('app.js', [p.name for p in scripts])

    def test_no_script_calls_a_native_dialog(self):
        bad = {}
        for p in sorted(_JS.glob('*.js')):
            found = native_calls(p.read_text(errors='replace'))
            if found:
                bad[p.name] = found
        self.assertEqual(bad, {}, 'use uiConfirm / uiPrompt / toast instead')


if __name__ == '__main__':
    unittest.main()
