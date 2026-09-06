"""The JS defects eslint finds and reading does not.

`test_js_noundef.py` runs eslint for `no-undef` alone. CLAUDE.md records two
more classes it found in this codebase — a grouped `case` block that lost its
`return` to a later insertion, and 52 duplicate keys in `i18n.js` where JS keeps
the LAST definition silently — and neither is reachable by reading. Both have
their own dedicated gates now, which is right for the specific bugs; this file
runs the general rules that would have caught them and the rest of the family:
a reassigned function, `typeof x == 'strng'`, `x !== NaN`, unreachable code, an
assignment inside an `if`.

Found on its first run: `loadDashboardSettings` was reassigned over itself nine
thousand lines below its own declaration, to bolt two lines onto the end. It
worked — the dispatcher resolves `window[name]` at click time — but it worked by
luck, and it re-fetched `/config` for values the original already had. The two
lines live in the function now.

Files are linted one at a time rather than concatenated: these rules are all
within-file, and per-file output names the file directly.

Two traps, both hit while writing this:
  * `no-fallthrough` reports a COMMENT between grouped bare `case` labels as a
    fallthrough unless `allowEmptyCase` is set. The activity-routing switch has
    dozens of those and every one was a false positive — the instrument, not the
    code, which is this project's usual order. The control below proves the rule
    still catches a case with actual statements falling through.
  * eslint silently ignores a target outside its config's base path, reporting
    one message with a null ruleId. Lint from the temp dir with bare filenames
    and fail hard on any "ignored" message, exactly as the no-undef gate does.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

_ESLINT = shutil.which("eslint")
_JS_DIR = Path(__file__).resolve().parent.parent / "server" / "html" / "static" / "js"

# Correctness rules only. Nothing stylistic: a gate that reports formatting gets
# switched off, and takes the real findings with it.
_RULES = {
    "no-fallthrough": ["error", {"allowEmptyCase": True}],
    "no-dupe-keys": "error",
    "no-dupe-args": "error",
    "no-dupe-else-if": "error",
    "no-dupe-class-members": "error",
    "no-duplicate-case": "error",
    "no-func-assign": "error",
    "no-obj-calls": "error",
    "no-unreachable": "error",
    "no-unsafe-negation": "error",
    "no-unsafe-optional-chaining": "error",
    "no-self-assign": "error",
    "no-self-compare": "error",
    "no-sparse-arrays": "error",
    "no-compare-neg-zero": "error",
    "no-loss-of-precision": "error",
    "no-new-native-nonconstructor": "error",
    "no-async-promise-executor": "error",
    "no-setter-return": "error",
    "getter-return": "error",
    "use-isnan": "error",
    "valid-typeof": "error",
}

_CONFIG = ("export default [{ files: ['**/*.js'], languageOptions: "
           "{ ecmaVersion: 'latest', sourceType: 'script' }, rules: "
           + json.dumps(_RULES) + " }];\n")

# A file with one of each defect the rules above exist for. Used as a control,
# so a blind eslint fails here rather than passing the real bundle.
_CONTROL = """
function ctl(x) {
  switch (x) {
    case 1:
      doThing();
    case 2:
      return 2;
  }
}
var o = { a: 1, b: 2, a: 3 };
function dup() { return 1; }
dup = function () { return 2; };
if (typeof x === 'strng') { ctl(1); }
if (x === NaN) { ctl(2); }
"""
_CONTROL_RULES = {"no-fallthrough", "no-dupe-keys", "no-func-assign",
                  "valid-typeof", "use-isnan"}


class TestJsCorrectnessRules(unittest.TestCase):

    def _lint(self, workdir, target):
        r = subprocess.run(
            [_ESLINT, "--no-config-lookup", "--config", "eslint.config.mjs",
             target, "--format", "json"],
            capture_output=True, text=True, timeout=300, cwd=str(workdir))
        try:
            results = json.loads(r.stdout)
        except json.JSONDecodeError:
            self.fail(f"eslint did not produce JSON (rc={r.returncode}):\n"
                      f"{r.stdout[:1000]}\n{r.stderr[:1000]}")
        out = []
        for f in results:
            for m in f.get("messages", []):
                if m.get("ruleId") is None and "ignored" in m.get("message", "").lower():
                    self.fail("eslint LINTED NOTHING — it reported the target "
                              "as ignored, so an empty result means nothing: "
                              + m.get("message", ""))
                out.append((Path(f.get("filePath", "?")).name,
                            m.get("line"), m.get("ruleId"), m.get("message")))
        return out

    @unittest.skipUnless(_ESLINT, "eslint not installed")
    def test_the_control_file_is_caught(self):
        """Run first. A gate that lints nothing passes the real check below."""
        with tempfile.TemporaryDirectory(prefix="rp-jsrules-ctl-") as d:
            d = Path(d)
            (d / "eslint.config.mjs").write_text(_CONFIG)
            probe = d / "control.js"
            probe.write_text(_CONTROL)
            self.assertIn("no-dupe-keys" if False else "a: 3", probe.read_text(),
                          "control file did not land on disk")
            found = {rule for _f, _l, rule, _m in self._lint(d, "control.js")}
            missing = sorted(_CONTROL_RULES - found)
            self.assertEqual(
                missing, [],
                "eslint did not report defects that are definitely in the "
                f"control file, so its verdict on the real files is worthless. "
                f"Missing: {missing}; saw: {sorted(found)}")

    @unittest.skipUnless(_ESLINT, "eslint not installed")
    def test_no_correctness_defects_in_the_shipped_javascript(self):
        files = sorted(p for p in _JS_DIR.glob("*.js") if p.is_file())
        self.assertGreater(len(files), 30,
                           f"only {len(files)} JS files found — the derivation "
                           "of what to lint has collapsed")
        with tempfile.TemporaryDirectory(prefix="rp-jsrules-") as d:
            d = Path(d)
            (d / "eslint.config.mjs").write_text(_CONFIG)
            for src in files:
                (d / src.name).write_text(src.read_text(encoding="utf-8"))
            findings = self._lint(d, ".")
        listing = sorted(f"{f}:{ln} {rule} — {msg}"
                         for f, ln, rule, msg in findings)
        self.assertEqual(listing, [],
                         "eslint correctness rules found defects reading does "
                         "not:\n  " + "\n  ".join(listing))


if __name__ == "__main__":
    unittest.main()
