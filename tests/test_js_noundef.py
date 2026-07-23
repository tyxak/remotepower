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
    @unittest.skipUnless(_ESLINT, "eslint not installed")
    def test_no_undefined_global_references(self):
        globals_ = [ln.strip() for ln in _ALLOWLIST.read_text().splitlines()
                    if ln.strip() and not ln.startswith("#")]
        with tempfile.TemporaryDirectory(prefix="rp-noundef-") as d:
            d = Path(d)
            bundle = d / "bundle.js"
            bundle.write_text(_bundle_without_stub())
            cfg = d / "eslint.config.mjs"
            cfg.write_text(
                "export default [{ files: ['**/*.js'], languageOptions: "
                "{ ecmaVersion: 'latest', sourceType: 'script', globals: "
                + json.dumps({g: "readonly" for g in globals_})
                + " }, rules: { 'no-undef': 'error' } }];\n")
            r = subprocess.run(
                [_ESLINT, "--no-config-lookup", "--config", str(cfg),
                 str(bundle), "--format", "json"],
                capture_output=True, text=True, timeout=300)
            try:
                results = json.loads(r.stdout)
            except json.JSONDecodeError:
                self.fail(f"eslint did not produce JSON (rc={r.returncode}):\n"
                          f"{r.stdout[:1000]}\n{r.stderr[:1000]}")
        offenders = {}
        for f in results:
            for m in f.get("messages", []):
                if m.get("ruleId") == "no-undef":
                    name = m["message"].split("'")[1]
                    offenders.setdefault(name, m["line"])
        listing = sorted(f"{n} (first at bundle line {ln})"
                         for n, ln in offenders.items())
        self.assertEqual(listing, [],
                         "undefined globals referenced by client JS — a "
                         "misspelled/missing function, or a NEW browser API "
                         "that belongs in tests/js_global_allowlist.txt:\n  "
                         + "\n  ".join(listing))


if __name__ == "__main__":
    unittest.main()
