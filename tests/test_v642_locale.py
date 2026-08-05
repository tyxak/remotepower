"""v6.4.2 — timestamps follow the in-app language, not the browser's.

The product ships a locale layer: `_localeTag()` reads `window.RPi18n.current`
so the language picker drives date/number/currency formatting, and its own
comment states that contract. Four call sites used it. 77 called
`toLocaleString()` bare, which follows the browser/OS locale instead.

So a German NOC running the UI in German on a browser installed as en-US got
German nav, German buttons, German page titles — and every timestamp in the
audit log, alert inbox, command history, monitor history and patch report as
`8/1/2026, 3:47:12 PM`. A month-first date next to a day-first mental model is a
real misread on a change window or a maintenance schedule.

`_localeTag()`'s own map also covered only en/zh/hi/es/ar while `LANGS` declares
seven — so `de` and `fr`, the two newest supported languages, fell back to
English formatting even on the four sites that DID route through it.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_JS = ROOT / "server" / "html" / "static" / "js"

# These four load NO app.js (checked against their <script> tags) — `_localeTag`
# and the `_fmtAbs*` helpers do not exist in their scope, and reaching for one
# would be an undefined global on the public status page, the printable report,
# the customer portal and the fleet-query page. They also have no language
# picker, being unauthenticated or print surfaces, so the browser locale IS the
# right answer there.
_STANDALONE = {"fleet-query.js", "portal.js", "report.js", "status.js"}

_BARE = re.compile(r"\.toLocale(?:String|DateString|TimeString)\(\s*\)")


class TestLocaleTagCoversEveryShippedLanguage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = (_JS / "app.js").read_text()
        cls.i18n = (_JS / "i18n.js").read_text()

    def test_every_declared_language_is_mapped(self):
        m = re.search(r"var LANGS = \[([^\]]+)\]", self.i18n)
        self.assertIsNotNone(m, "LANGS not found")
        langs = re.findall(r"'([a-z]{2})'", m.group(1))
        fn = self.app[self.app.index("function _localeTag"):]
        fn = fn[:fn.index("\n}\n")]
        for lang in langs:
            with self.subTest(lang=lang):
                self.assertRegex(fn, r"\b%s:\s*'" % lang,
                                 f"'{lang}' is a shipped UI language and falls "
                                 "back to en-US formatting")

    def test_the_funnel_helpers_exist(self):
        for fn in ("_fmtAbsTs", "_fmtAbsDate", "_fmtAbsTime"):
            with self.subTest(fn=fn):
                self.assertRegex(self.app, r"\bfunction %s\s*\(" % fn)

    def test_the_helpers_pass_the_app_locale(self):
        for fn in ("_fmtAbsTs", "_fmtAbsDate", "_fmtAbsTime"):
            with self.subTest(fn=fn):
                body = self.app[self.app.index("function %s(" % fn):]
                body = body[:body.index("\n}\n")]
                self.assertIn("_localeTag()", body)


class TestNoBareLocaleCallsInAppModules(unittest.TestCase):
    """The whole finding, as a gate."""

    def test_no_app_module_formats_against_the_browser_locale(self):
        offenders = []
        for f in sorted(_JS.glob("*.js")):
            if f.name in _STANDALONE or f.name == "i18n.js":
                continue
            for m in _BARE.finditer(f.read_text()):
                offenders.append(f"{f.name}: {m.group(0)}")
        self.assertEqual(offenders, [],
                         "these render a date against the BROWSER locale, so an "
                         "operator who picked another language in the app still "
                         "sees their OS's format. Use _fmtAbsTs / _fmtAbsDate / "
                         "_fmtAbsTime:\n  " + "\n  ".join(offenders))

    def test_the_standalone_pages_are_genuinely_standalone(self):
        """The carve-out has to stay true. If one of these ever starts loading
        app.js, it should join the gate rather than keep its exemption."""
        html = ROOT / "server" / "html"
        for js in sorted(_STANDALONE):
            page = html / (js.replace(".js", ".html"))
            if not page.exists():
                continue
            with self.subTest(page=page.name):
                self.assertNotIn("js/app.js", page.read_text(),
                                 f"{page.name} loads app.js now — drop it from "
                                 "the exemption list")

    def test_the_gate_would_actually_catch_one(self):
        """A gate that matches nothing is the false-green shape this codebase
        keeps hitting — prove the pattern fires."""
        self.assertTrue(_BARE.search("new Date().toLocaleString()"))
        self.assertFalse(_BARE.search("new Date().toLocaleString(_localeTag())"))


class TestTheSweepDidNotBreakTheSemantics(unittest.TestCase):
    """`new Date(x * 1000).toLocaleString()` → `_fmtAbsTs(x)` is only correct
    when x is SECONDS. Anything else kept its own Date construction and merely
    gained the locale argument — the rewrite must never have changed which
    instant is rendered."""

    def test_helper_calls_are_not_passed_milliseconds(self):
        bad = []
        for f in sorted(_JS.glob("*.js")):
            if f.name in _STANDALONE:
                continue
            for m in re.finditer(r"_fmtAbs(?:Ts|Date|Time)\(([^)]*)\)",
                                 f.read_text()):
                arg = m.group(1)
                if "* 1000" in arg or "*1000" in arg or "Date.now()" in arg:
                    bad.append(f"{f.name}: {m.group(0)}")
        self.assertEqual(bad, [],
                         "the helpers take UNIX SECONDS; these pass "
                         "milliseconds, so the rendered date is wrong by ~50000 "
                         "years:\n  " + "\n  ".join(bad))


if __name__ == "__main__":
    unittest.main()
