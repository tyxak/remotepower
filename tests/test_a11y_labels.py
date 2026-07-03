"""Form-control accessibility ratchet.

Every interactive form control (`<input>`, `<select>`, `<textarea>`) should
expose an *accessible name* so screen-reader users know what it does. A control
has an accessible name when it satisfies ONE of:

  (a) a `<label for="itsid">` points at it,
  (b) it is wrapped inside a `<label>…</label>`, or
  (c) it carries an `aria-label` (or `aria-labelledby`) attribute.

`type="hidden"` / `submit` / `button` / `reset` / `image` inputs are not
name-bearing controls and are excluded.

This test re-implements the analyzer (so it is self-contained and reproducible)
and asserts the number of *unnamed* controls in `server/html/index.html` never
grows past a baseline. The number may only shrink — add a `<label for>`, wrap in
a `<label>`, or add an `aria-label` to bring it down; never bump the baseline up.

History: before the v-a11y sweep there were 313 unnamed controls; adding
`aria-label` to all of them brought the count to 0.
"""

import re
import pathlib
import unittest

HTML_PATH = pathlib.Path(__file__).resolve().parents[1] / "server" / "html" / "index.html"

# Measured baselines. PRE_FIX is what the file carried before the a11y sweep;
# POST_FIX (== the ratchet ceiling) is the count after adding aria-labels.
PRE_FIX_UNNAMED = 313
BASELINE_UNNAMED = 0  # ratchet ceiling — assertions below allow <= this only

_SKIP_INPUT_TYPES = {"hidden", "submit", "button", "reset", "image"}
_CONTROL_RE = re.compile(r"<(input|select|textarea)\b([^>]*?)/?>", re.IGNORECASE)
_CONTROL_ANY = re.compile(r"<(input|select|textarea)\b", re.IGNORECASE)
_LABEL_PAIR = re.compile(r"<label\b[^>]*>.*?</label>", re.IGNORECASE | re.DOTALL)


def _attrs(s):
    d = {}
    for m in re.finditer(r'([a-zA-Z_:][-a-zA-Z0-9_:]*)\s*=\s*"([^"]*)"', s):
        d.setdefault(m.group(1).lower(), m.group(2))
    for m in re.finditer(r"(?:^|\s)([a-zA-Z_:][-a-zA-Z0-9_:]*)(?=\s|$)(?!\s*=)", s):
        d.setdefault(m.group(1).lower(), "")
    return d


def _inside_label_positions(html):
    """Return a function pos -> bool: is `pos` nested inside an open <label>?"""
    tokens = [(m.start(), 1) for m in re.finditer(r"<label\b", html)]
    tokens += [(m.start(), -1) for m in re.finditer(r"</label>", html)]
    tokens.sort()

    def inside(pos):
        depth = 0
        for tpos, delta in tokens:
            if tpos >= pos:
                break
            depth += delta
        return depth > 0

    return inside


def unnamed_controls(html):
    """List of (pos, tag, id) for controls with NO accessible name."""
    label_for = set(re.findall(r'<label\b[^>]*\bfor="([^"]+)"', html))
    inside = _inside_label_positions(html)
    out = []
    for m in _CONTROL_RE.finditer(html):
        tag = m.group(1).lower()
        a = _attrs(m.group(2))
        if tag == "input" and a.get("type", "").lower() in _SKIP_INPUT_TYPES:
            continue
        if a.get("aria-label") or a.get("aria-labelledby"):
            continue
        cid = a.get("id")
        if cid and cid in label_for:
            continue
        if inside(m.start()):
            continue
        out.append((m.start(), tag, cid))
    return out


class TestFormControlAccessibleNames(unittest.TestCase):
    def setUp(self):
        self.html = HTML_PATH.read_text()

    def test_no_empty_aria_labels(self):
        self.assertNotIn('aria-label=""', self.html,
                         "empty aria-label conveys no accessible name")

    def test_unnamed_control_count_does_not_regress(self):
        unnamed = unnamed_controls(self.html)
        self.assertLessEqual(
            len(unnamed), BASELINE_UNNAMED,
            "form controls without an accessible name (label[for] / wrapping "
            "<label> / aria-label) grew past the ratchet baseline "
            f"{BASELINE_UNNAMED}. New offenders (pos, tag, id):\n"
            + "\n".join(f"  {p} {t} id={i}" for p, t, i in unnamed[:40]))

    def test_improved_substantially_over_pre_fix(self):
        """The sweep must have removed at least 100 unnamed controls."""
        remaining = len(unnamed_controls(self.html))
        self.assertLessEqual(
            remaining, PRE_FIX_UNNAMED - 100,
            f"expected the a11y sweep to cut >=100 unnamed controls from the "
            f"pre-fix baseline of {PRE_FIX_UNNAMED}; still {remaining} remain.")


if __name__ == "__main__":
    unittest.main()
