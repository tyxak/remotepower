"""JS correctness lint: the bug classes `node --check` and `no-undef` cannot see.

`node --check` accepts a file that declares the same function twice, repeats an
object key, or lets a `case` run into the next one. All three are silent at
runtime: the LAST declaration wins, the LAST key wins, and the fall-through just
happens. They shipped before:

  * `status.js` declared `fmtAbs` twice in one scope (epoch seconds, then an ISO
    string). The second replaced the first for every caller, so the public status
    page printed incident times as January 1970.
  * `i18n.js` held 52 repeated keys, 18 of them with different text, so a wording
    fix had been dead since the day it landed.
  * a grouped `case` block lost its `return` to a later insertion and 19 events
    opened the wrong page.

eslint's core correctness rules find all of them, one file at a time (the files
share a browser global scope, so a cross-file duplicate is checked separately by
`test_no_function_defined_in_two_files`).

Skips when eslint is not installed, like `test_js_noundef`. The control feeds a
file with each defect and requires every rule to fire, so a run that read nothing
cannot pass.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / "server" / "html" / "static" / "js"
_ESLINT = shutil.which("eslint")

# `no-fallthrough` runs with allowEmptyCase: a grouped `case 'a': case 'b':`
# with a comment between the labels is the project's routing idiom and is not a
# fall-through. A case WITH statements that runs into the next one still fails.
_RULES = {
    "no-redeclare": "error",
    "no-dupe-keys": "error",
    "no-dupe-else-if": "error",
    "no-duplicate-case": "error",
    "no-func-assign": "error",
    "no-const-assign": "error",
    "no-unreachable": "error",
    "no-self-assign": "error",
    "no-unsafe-negation": "error",
    "no-sparse-arrays": "error",
    "use-isnan": "error",
    "valid-typeof": "error",
    "no-fallthrough": ["error", {"allowEmptyCase": True}],
}

_CONTROL = """\
function dup(a) { return a; }
function dup(b) { return b; }
var o = { k: 1, k: 2 };
function sw(x) { switch (x) { case 1: go(); case 2: return 2; } }
function isn(x) { return x === NaN; }
function ty(x) { return typeof x === 'strnig'; }
const c = 1; c = 2;
function un() { return 1; foo(); }
function dc(x) { switch (x) { case 1: return 1; case 1: return 2; } }
"""

_CONTROL_RULES = {"no-redeclare", "no-dupe-keys", "no-fallthrough", "use-isnan",
                  "valid-typeof", "no-const-assign", "no-unreachable", "no-duplicate-case"}


def _config():
    return ("export default [{ files: ['**/*.js'], languageOptions: "
            "{ ecmaVersion: 'latest', sourceType: 'script' }, rules: "
            + json.dumps(_RULES) + " }];\n")


class TestJsCorrectnessLint(unittest.TestCase):
    def _lint(self, workdir, names):
        r = subprocess.run(
            [_ESLINT, "--no-config-lookup", "--config", "eslint.config.mjs",
             *names, "--format", "json"],
            capture_output=True, text=True, timeout=300, cwd=str(workdir))
        try:
            results = json.loads(r.stdout)
        except json.JSONDecodeError:
            self.fail(f"eslint did not produce JSON (rc={r.returncode}):\n"
                      f"{r.stdout[:800]}\n{r.stderr[:800]}")
        out = []
        for f in results:
            for m in f.get("messages", []):
                if m.get("ruleId") is None and "ignored" in m.get("message", "").lower():
                    self.fail("eslint linted nothing: " + m.get("message", ""))
                out.append((Path(f["filePath"]).name, m.get("line"), m.get("ruleId"),
                            m.get("message", "")))
        return out, len(results)

    @unittest.skipUnless(_ESLINT, "eslint not installed")
    def test_the_rules_catch_what_they_are_for(self):
        with tempfile.TemporaryDirectory(prefix="rp-jslint-") as d:
            d = Path(d)
            (d / "eslint.config.mjs").write_text(_config())
            (d / "control.js").write_text(_CONTROL)
            msgs, _ = self._lint(d, ["control.js"])
        fired = {m[2] for m in msgs}
        self.assertTrue(_CONTROL_RULES <= fired,
                        f"these rules did not fire on a file written to trip them: "
                        f"{sorted(_CONTROL_RULES - fired)}. Saw {sorted(fired)}")

    @unittest.skipUnless(_ESLINT, "eslint not installed")
    def test_no_client_js_file_has_a_correctness_defect(self):
        files = sorted(p.name for p in JS.glob("*.js"))
        self.assertGreater(len(files), 40, "the file list is empty or truncated")
        with tempfile.TemporaryDirectory(prefix="rp-jslint-") as d:
            d = Path(d)
            (d / "eslint.config.mjs").write_text(_config())
            for n in files:
                shutil.copy(JS / n, d / n)
            msgs, linted = self._lint(d, files)
        self.assertEqual(linted, len(files), "eslint did not read every file it was given")
        self.assertEqual(
            msgs, [],
            "client JS correctness defects (file, line, rule):\n  "
            + "\n  ".join(f"{f}:{ln}  {rule}  {text}" for f, ln, rule, text in msgs))

    def test_no_function_defined_in_two_files(self):
        """The page scripts share one global scope, so a name declared at the top
        level of two files is replaced silently by whichever loads last. The one
        known override is declared on purpose."""
        allowed = {"filterVirtualization": {"app.js", "app-virt.js"}}
        defs = defaultdict(set)
        names = sorted(JS.glob("app*.js")) + [JS / "wg-access.js"]
        self.assertGreater(len(names), 30)
        for p in names:
            t = p.read_text()
            for m in re.finditer(r"^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", t, re.M):
                defs[m.group(1)].add(p.name)
            for m in re.finditer(r"^(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=", t, re.M):
                defs[m.group(1)].add(p.name)
        self.assertGreater(len(defs), 2000, "the scan read too few top-level names")
        dup = {k: sorted(v) for k, v in defs.items()
               if len(v) > 1 and v != allowed.get(k)}
        self.assertEqual(dup, {}, "top-level names defined in more than one file "
                                  "(the later load silently wins)")


if __name__ == "__main__":
    unittest.main()
