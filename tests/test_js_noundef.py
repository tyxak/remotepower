"""JS undefined-global gate — the `ruff F821` of the client side.

`node --check` catches syntax and tests/test_jsload.py catches load-time
ReferenceErrors, but a CALL to a global that doesn't exist only dies at
runtime, in whatever branch finally reaches it, silently for everyone who
doesn't open the console. That class has shipped repeatedly (the invented-name
sweep: `fmtTime`, `_currentPage`, and the `openDeviceInfo` netmap fallthrough
this gate found on its first run).

Mechanism: concatenate every static/js file in index.html declaration order
(they share one browser global scope, so the concatenation has identical
name-resolution semantics) and run eslint's `no-undef` over the bundle with
ONLY the browser/vendored globals from tests/js_global_allowlist.txt
predeclared. Any other undefined identifier is a failure.

Skips when eslint isn't installed (same pattern as the py_mini_racer skip in
test_jsload) — dev boxes with eslint get the check; CI's backstop is the
V8 load test plus this running on the dev box before every push.

The bundle is linted with the subprocess CWD set to the temp dir and both
paths passed as bare filenames. eslint resolves a target against the config's
base path, so an absolute path into /tmp with cwd at the repo root comes back
as one message — ruleId None, "File ignored because outside of base path" —
and a filter for ruleId == 'no-undef' then finds nothing to report. This gate
passed that way for its whole life: 5 MB of JS in 0.10s, which is less time
than reading the file takes. Two things now stop that recurring: an ignored
file is a hard failure, and the test lints a copy of its own bundle with a
call to a name that does not exist and requires eslint to catch it.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _jsload_harness as H  # noqa: E402

_ESLINT = shutil.which("eslint")
_ALLOWLIST = Path(__file__).resolve().parent / "js_global_allowlist.txt"


def _bundle_without_stub():
    parts = []
    for name in H._load_order():
        f = H._JS_DIR / name
        if f.is_file():
            parts.append(f"\n// ===== {name} =====\n" + f.read_text())
    return "\n".join(parts)


class TestNoUndefinedGlobals(unittest.TestCase):
    def _run_eslint(self, workdir, target):
        """eslint --format json over `target`, run FROM `workdir`.

        cwd and a bare filename are load-bearing: an absolute path outside the
        config's base path is silently ignored rather than linted.
        """
        r = subprocess.run(
            [_ESLINT, "--no-config-lookup", "--config", "eslint.config.mjs",
             target, "--format", "json"],
            capture_output=True, text=True, timeout=300, cwd=str(workdir))
        try:
            results = json.loads(r.stdout)
        except json.JSONDecodeError:
            self.fail(f"eslint did not produce JSON (rc={r.returncode}):\n"
                      f"{r.stdout[:1000]}\n{r.stderr[:1000]}")
        messages = [m for f in results for m in f.get("messages", [])]
        skipped = [m for m in messages
                   if m.get("ruleId") is None and "ignored" in m.get("message", "").lower()]
        self.assertEqual(
            skipped, [],
            "eslint LINTED NOTHING — it reported the bundle as ignored, so a "
            "no-undef filter over its output is empty for the wrong reason:\n"
            + "\n".join(m.get("message", "") for m in skipped))
        return messages

    @staticmethod
    def _undef_names(messages):
        offenders = {}
        for m in messages:
            if m.get("ruleId") == "no-undef":
                offenders.setdefault(m["message"].split("'")[1], m["line"])
        return offenders

    @unittest.skipUnless(_ESLINT, "eslint not installed")
    def test_no_undefined_global_references(self):
        globals_ = [ln.strip() for ln in _ALLOWLIST.read_text().splitlines()
                    if ln.strip() and not ln.startswith("#")]
        with tempfile.TemporaryDirectory(prefix="rp-noundef-") as d:
            d = Path(d)
            src = _bundle_without_stub()
            (d / "bundle.js").write_text(src)
            (d / "eslint.config.mjs").write_text(
                "export default [{ files: ['**/*.js'], languageOptions: "
                "{ ecmaVersion: 'latest', sourceType: 'script', globals: "
                + json.dumps({g: "readonly" for g in globals_})
                + " }, rules: { 'no-undef': 'error' } }];\n")

            # Positive control, run first so a blind eslint fails here rather
            # than reporting a clean bundle. A name this improbable cannot
            # already be defined, and the check that it landed in the file
            # keeps a control that silently did not apply from looking like a
            # working one.
            canary = "__rp_noundef_canary_should_be_flagged__"
            probe = d / "control.js"
            probe.write_text(src + f"\n{canary}();\n")
            self.assertIn(canary, probe.read_text(), "control mutation did not apply")
            control = self._undef_names(self._run_eslint(d, "control.js"))
            self.assertIn(
                canary, control,
                "eslint did not flag a call to an undefined function in the "
                "bundle — this gate is not reading the JS, so its verdict on "
                f"the real bundle means nothing. Saw: {sorted(control)}")

            offenders = self._undef_names(self._run_eslint(d, "bundle.js"))

        listing = sorted(f"{n} (first at bundle line {ln})"
                         for n, ln in offenders.items())
        self.assertEqual(listing, [],
                         "undefined globals referenced by client JS — a "
                         "misspelled/missing function, or a NEW browser API "
                         "that belongs in tests/js_global_allowlist.txt:\n  "
                         + "\n  ".join(listing))


if __name__ == "__main__":
    unittest.main()
