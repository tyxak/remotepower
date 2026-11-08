#!/usr/bin/env python3
"""8.0.0: a local variable the page computes is a local variable the page uses (the JS twin of ruff's F841).

Four places lost a colour or a dimming when the inline styles became classes, and every one of them left the same trace: a variable computed from the data and never read (`rowStyle`, `statusColor`, `col`, and
the Online line's inline expression). eslint's `no-unused-vars` with `vars: "local"` lists exactly those, one per function, and nothing else: top-level functions are reached through `data-action` names the
rule cannot see, so the global scope is not asked about. A name that starts with an underscore (`_x`, or `[_a, b]` in a destructuring) says on purpose that it is not used.

The bundle is the one tests/test_js_noundef.py builds (every static/js file in index.html order, one browser global scope) and is linted the same way: from a temporary directory, by bare file name, with an
ignored file counted as a failure, and a control that adds an unused variable to a copy of the bundle and requires eslint to name it. Skips when eslint is not installed, like that gate.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_js_noundef as N  # noqa: E402

_RULE = ["error", {"vars": "local", "args": "none", "caughtErrors": "none", "ignoreRestSiblings": True,
                   "varsIgnorePattern": "^_", "destructuredArrayIgnorePattern": "^_"}]


def _unused(workdir, target):
    """eslint --format json over `target`, run from `workdir`; the names reported as unused locals, as {name: line}."""
    r = subprocess.run([N._ESLINT, "--no-config-lookup", "--config", "eslint.config.mjs", target, "--format", "json"],
                       capture_output=True, text=True, timeout=300, cwd=str(workdir))
    results = json.loads(r.stdout)           # a run that printed no JSON fails here, loudly
    messages = [m for f in results for m in f.get("messages", [])]
    ignored = [m for m in messages if m.get("ruleId") is None and "ignored" in m.get("message", "").lower()]
    assert not ignored, "eslint linted nothing: " + "; ".join(m["message"] for m in ignored)
    out = {}
    for m in messages:
        if m.get("ruleId") == "no-unused-vars":
            out.setdefault(m["message"].split("'")[1], m["line"])
    return out


class TestNoLocalVariableIsComputedAndNeverRead(unittest.TestCase):
    @unittest.skipUnless(N._ESLINT, "eslint not installed")
    def test_the_bundle_has_none(self):
        with tempfile.TemporaryDirectory(prefix="rp-unused-") as d:
            d = Path(d)
            src = N._bundle_without_stub()
            (d / "bundle.js").write_text(src)
            (d / "eslint.config.mjs").write_text("export default [{ files: ['**/*.js'], languageOptions: { ecmaVersion: 'latest', sourceType: 'script' }, "
                                                 "rules: { 'no-unused-vars': " + json.dumps(_RULE) + " } }];\n")
            # Control first: a blind eslint must fail here, not report a clean bundle.
            canary = "__rp_unused_canary__"
            probe = d / "control.js"
            probe.write_text(src + f"\nfunction {canary}() {{ const rowStyle = 1; return 0; }}\n")
            self.assertIn(canary, probe.read_text(), "control mutation did not apply")
            self.assertIn("rowStyle", _unused(d, "control.js"), "eslint did not name an unused local added to the bundle: this gate is not reading the JS")
            found = _unused(d, "bundle.js")
        self.assertEqual(found, {}, "local variables computed and never read (a dropped colour, a dead branch). Use the value, delete it, or start the name with an underscore on purpose:\n  "
                                    + "\n  ".join(f"{n} (bundle line {ln})" for n, ln in sorted(found.items())))


if __name__ == "__main__":
    unittest.main()
