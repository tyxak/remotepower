#!/usr/bin/env python3
"""A mutation that was refused reported success.

`api()` RESOLVES on 4xx — only a 401 (which logs out and returns null) and a 5xx
or network failure reject. So `try { await api(...) } catch` never sees a
refusal, and a caller that toasts success on the next line says the thing
happened when the server said no. CLAUDE.md records this root-causing three
"the feature does nothing / lies" bugs in one session.

`_saveSwPolicy` was one: it toasted "Policy saved — undefined rules, undefined
violations" whenever the POST was refused, and reloaded the list unchanged.

The gate is over the POPULATION — every mutating api() call whose result is
assigned — rather than over this one function, because the point of the class is
that the correct sites make the file read as though it is handled. 537 sites,
and the ones that check do so in several shapes (`if (!r?.ok)`, `if (r &&
!r.error)`, a `_kmipOk()` helper), so the check accepts any of them.
"""
import pathlib
import re
import unittest

_JS = pathlib.Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js'

# Any of these, within a short window after the assignment, counts as handled.
_CHECKED = re.compile(
    r'\.(error|ok|approval_required|status)\b'
    r'|\?\.\s*(error|ok)\b'
    r'|_kmipOk\('
    r'|\|\|\s*\[\]|\|\|\s*\{\}'          # defensive fallback on a read
)
# Wide enough to clear a multi-line call: app-hostconfig.js's /ai/chat POST
# spans ~18 lines of prompt text before its check, and a 14-line window
# reported that correct site as unhandled.
_WINDOW = 30


def _sites():
    """(file, line, var, window) for every assigned mutating api() call."""
    out = []
    for f in sorted(_JS.glob('*.js')):
        L = f.read_text().splitlines()
        for i, l in enumerate(L):
            m = re.search(
                r"(?:const|let|var)\s+(\w+)\s*=\s*await\s+api\(\s*'(POST|PUT|PATCH|DELETE)'",
                l)
            if m:
                out.append((f.name, i + 1, m.group(1),
                            '\n'.join(L[i:i + _WINDOW])))
    return out


class TestEveryMutationChecksItsResult(unittest.TestCase):

    def test_the_scan_finds_the_call_sites(self):
        """Positive control. A changed idiom empties this and the assertion
        below passes over nothing."""
        self.assertGreater(len(_sites()), 300)

    def test_none_of_them_ignores_a_refusal(self):
        bad = []
        for name, line, var, win in _sites():
            if _CHECKED.search(win):
                continue
            if re.search(rf'\bif\s*\(\s*!?\s*{re.escape(var)}\b', win):
                continue
            bad.append(f'{name}:{line}')
        self.assertEqual(
            [], bad,
            'these assign a mutating api() result and never look at it, so a '
            '4xx refusal is reported as success (api() resolves — only 401 and '
            f'5xx/network reject): {bad}')

    def test_the_detector_can_tell_handled_from_unhandled(self):
        """Both directions, on synthetic input — otherwise a regex that matched
        everything would report the codebase clean."""
        handled = "const r = await api('POST', '/x');\nif (!r?.ok) return;"
        unhandled = "const r = await api('POST', '/x');\ntoast(`saved ${r.n}`);"
        self.assertTrue(_CHECKED.search(handled))
        self.assertFalse(_CHECKED.search(unhandled))


class TestTheOneThatWasWrong(unittest.TestCase):
    """Named, because a population check goes green again the day someone
    reformats this function."""

    def test_save_software_policy_checks_before_it_claims_success(self):
        src = (_JS / 'app.js').read_text()
        i = src.index('async function _saveSwPolicy()')
        body = src[i:src.index('\n}\n', i)]
        # Strip comments first. The comment explaining this fix quotes the very
        # toast it is about ("Policy saved — undefined rules"), so an ordering
        # check over the raw body compares against prose and fails on correct
        # code — CLAUDE.md's assert-against-code-not-comments, committed here by
        # this very test on its first run.
        code = '\n'.join(l for l in body.splitlines()
                         if not l.strip().startswith('//'))
        self.assertLess(code.index('res.error'), code.index('Policy saved'),
                        'it still toasts success before looking at the result')

    def test_it_keeps_the_catch_for_the_failures_that_do_reject(self):
        """A 5xx and a dropped connection DO reject, so removing the catch
        would trade one silent failure for another."""
        src = (_JS / 'app.js').read_text()
        i = src.index('async function _saveSwPolicy()')
        self.assertIn('catch', src[i:src.index('\n}\n', i)])


if __name__ == '__main__':
    unittest.main()
