#!/usr/bin/env python3
"""`api()` RESOLVES on a refusal — so a success toast must read the body.

THE MECHANISM
-------------
`api()` (app.js) throws only on a fetch-level rejection. Every HTTP status
except 401 falls through to `return await r.json()`. So this:

    try {
      await api('POST', '/app-catalog/deploy', {...});
      toast('Deploy queued', 'success');
    } catch (e) { toast(String(e), 'error'); }

has a DEAD catch. When the server answers `403 {"error": "compose deploys are
disabled on this device"}` the catch never runs and the operator gets a green
"Deploy queued" for something that will never happen. That case was reachable
on ANY default device, because `compose_enabled` defaults to false.

CLAUDE.md already root-causes this shape three times ("the agent console printed
'(no output)' for a 202 approval, the report-archive card painted an empty state
instead of hiding on a 403, the palette knowledge-search never latched its 403
circuit-breaker") and two one-off regression tests exist for individual
instances. Nothing generalised it. This does.

WHAT IT FLAGS — deliberately narrow
-----------------------------------
A MUTATING `await api('POST'|'PUT'|'PATCH'|'DELETE', …)` whose result is
DISCARDED (not assigned, not returned), followed within 10 lines by a
`, 'success')` toast, with no error check in between. If the response was
thrown away entirely, the success toast cannot possibly be conditional on it —
no judgement call, no taste.

It does NOT try to police calls whose result IS captured; `if (res)` is wrong
too (truthy for `{error: …}`) but distinguishing a good check from a bad one
statically produces false positives, and a noisy gate gets switched off. The
narrow rule caught 9 of the 11 real sites; the other two were found by reading.

Ceiling is ZERO. Every instance was fixed when this landed, so there is no
baseline to grandfather. A genuinely fire-and-forget call should either not
toast success, or say what it actually knows.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS_DIR = ROOT / "server" / "html" / "static" / "js"

_MUTATING = re.compile(r"""await\s+api\(\s*['"](?:POST|PUT|PATCH|DELETE)['"]""")
# result captured: `const r = await api(`, `r = await api(`, `return await api(`
_CAPTURED = re.compile(
    r"""(?:const|let|var)\s+\w+\s*=\s*await\s+api\(|\w+\s*=\s*await\s+api\(|"""
    r"""return\s+await\s+api\(""")
_SUCCESS_TOAST = re.compile(r",\s*'success'\s*\)")
# any sign the code looked at the outcome before claiming success
_CHECKED = re.compile(r"\.error|\?\.ok|\.ok\b|!r\b|!res\b|catch\s*\(")

LOOKAHEAD = 10


def _unchecked_success_toasts(lines):
    """(lineno, text) for each discarded mutating call followed by a success
    toast with nothing checked in between."""
    out = []
    for i, line in enumerate(lines):
        if not _MUTATING.search(line) or _CAPTURED.search(line):
            continue
        window = lines[i:i + LOOKAHEAD]
        for j, w in enumerate(window):
            if _SUCCESS_TOAST.search(w):
                if not _CHECKED.search("\n".join(window[:j + 1])):
                    out.append((i + 1, line.strip()[:80]))
                break
    return out


class TestNoUncheckedSuccessToast(unittest.TestCase):
    def test_every_mutating_call_reads_its_response(self):
        problems = []
        for path in sorted(JS_DIR.glob("*.js")):
            for lineno, text in _unchecked_success_toasts(path.read_text().splitlines()):
                problems.append(f"{path.name}:{lineno}  {text}")
        self.assertEqual(
            problems, [],
            "these mutating calls discard the response and then toast success "
            "— api() RESOLVES on 400/403, so the toast fires on a refusal:\n  "
            + "\n  ".join(problems)
            + "\nGuard with the idiom already used at ~130 sites:\n"
            "    const r = await api('POST', …);\n"
            "    if (!r || r.error) { toast(r?.error || 'Failed', 'error'); return; }")

    def test_the_detector_is_not_vacuous(self):
        """A gate that matches nothing is the false-green shape this codebase
        keeps hitting, so prove the scanner still fires on the real thing.

        This sample is the shape of the shipped app-hostops.js bug."""
        sample = """
          try {
            await api('POST', '/app-catalog/deploy', { device_id: d.id });
            toast('Deploy queued', 'success');
          } catch (e) { toast(String(e), 'error'); }
        """.strip().splitlines()
        self.assertEqual(len(_unchecked_success_toasts(sample)), 1)

    def test_a_guarded_call_is_not_flagged(self):
        """The corrected shape must pass, or the gate is unfixable and gets
        deleted rather than satisfied."""
        sample = """
          const r = await api('POST', '/app-catalog/deploy', { device_id: d.id });
          if (!r || r.error) { toast(r?.error || 'Failed', 'error'); return; }
          toast('Deploy queued', 'success');
        """.strip().splitlines()
        self.assertEqual(_unchecked_success_toasts(sample), [])

    def test_it_is_actually_scanning_the_app(self):
        """Guard the guard: if the glob or the path ever goes wrong this file
        would pass by scanning nothing at all."""
        joined = "\n".join(p.read_text() for p in JS_DIR.glob("*.js"))
        self.assertGreater(len(_MUTATING.findall(joined)), 100,
                           "found almost no mutating api() calls — the scan "
                           "is pointed at the wrong place")


if __name__ == "__main__":
    unittest.main()
