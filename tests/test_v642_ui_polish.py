"""v6.4.2: two small UI-craft defects that both silently degraded output.

  * `_fmtBytes` stopped at GB, so multi-terabyte totals (WireGuard tunnel
    counters, netflow byte sums) rendered as four- and five-digit GB numbers.
  * `.modal-subtitle` carried no `white-space` rule, so the paragraph break that
    ~40 uiConfirm/uiPrompt call sites author to separate the action from its
    consequence collapsed into one run-on grey line — burying escape hatches
    like "Use Clear resolved if you only want to purge resolved" mid-sentence.

The byte formatter is EXECUTED here rather than grepped: a rung boundary is
exactly the kind of thing a source assertion gets wrong.

Run: python3 -m pytest tests/test_v642_ui_polish.py -q
"""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_APP = _ROOT / "server/html/static/js/app.js"
_CSS = _ROOT / "server/html/static/css/styles.css"

_KIB, _MIB, _GIB = 1024, 1024 ** 2, 1024 ** 3
_TIB, _PIB = 1024 ** 4, 1024 ** 5


class TestFmtBytesRungs(unittest.TestCase):
    """Extract the real function and run it in node — no reimplementation."""

    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if not cls.node:
            raise unittest.SkipTest("node not available")
        src = _APP.read_text()
        m = re.search(r"^function _fmtBytes\(n\) \{.*?^\}", src, re.S | re.M)
        assert m, "_fmtBytes not found in app.js"
        cls.fn = m.group(0)

    def _fmt(self, values):
        script = self.fn + "\nconst out=[];" + \
            "".join(f"out.push(String(_fmtBytes({v})));" for v in values) + \
            "\nconsole.log(JSON.stringify(out));"
        r = subprocess.run([self.node, "-e", script], capture_output=True,
                           text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        import json
        return json.loads(r.stdout)

    def test_every_rung_including_terabytes(self):
        got = self._fmt([0, 512, 2 * _KIB, 5 * _MIB, 3 * _GIB,
                         _TIB, 4.5 * _TIB, 2 * _PIB])
        self.assertEqual(got, ["0 B", "512 B", "2.0 KB", "5.0 MB", "3.0 GB",
                               "1.0 TB", "4.5 TB", "2.0 PB"])

    def test_a_multi_terabyte_total_is_not_a_five_digit_gb_number(self):
        """The actual reported symptom."""
        got = self._fmt([9 * _TIB])[0]
        self.assertTrue(got.endswith(" TB"), got)
        # Guards the regression directly: 9216.0 GB is what the old rung gave.
        self.assertNotIn("GB", got)

    def test_boundaries_step_exactly_at_the_power_of_1024(self):
        below, at = self._fmt([_TIB - 1, _TIB])
        self.assertTrue(below.endswith(" GB"), below)
        self.assertTrue(at.endswith(" TB"), at)


class TestConfirmDialogKeepsAuthoredLineBreaks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.css = _CSS.read_text()
        cls.app = _APP.read_text()

    def test_modal_subtitle_preserves_newlines(self):
        m = re.search(r"\.modal-subtitle\s*\{[^}]*\}", self.css)
        self.assertIsNotNone(m, ".modal-subtitle rule not found")
        self.assertIn("white-space: pre-line", m.group(0),
                      "authored \\n\\n in confirm messages collapses to one line")

    def test_the_message_sink_is_textcontent_so_pre_line_is_the_right_lever(self):
        """If the sink ever became innerHTML, pre-line would be the wrong fix
        (and an escaping problem would be the bigger one)."""
        m = re.search(r"function uiConfirm\(.*?\n\}", self.app, re.S)
        self.assertIsNotNone(m)
        self.assertIn("msg.textContent = message", m.group(0))

    def test_no_static_subtitle_relies_on_newline_collapsing(self):
        """pre-line honours source newlines too, so a static element whose text
        is wrapped across source lines would newly break. None are — pin it, so
        someone reflowing index.html finds out here rather than in a screenshot.
        """
        html = (_ROOT / "server/html/index.html").read_text()
        multi = [m for m in re.finditer(
            r'<(\w+)[^>]*class="[^"]*modal-subtitle[^"]*"[^>]*>(.*?)</\1>', html, re.S)
            if "\n" in m.group(2).strip()]
        self.assertEqual(multi, [], "a static .modal-subtitle now spans source "
                                    "lines and will render an unintended break")


if __name__ == "__main__":
    unittest.main(verbosity=2)
