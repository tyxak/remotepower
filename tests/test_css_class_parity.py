"""CSS class parity — a class referenced in markup must exist somewhere.

A class that exists in neither styles.css nor any JS selector renders an
unstyled box with no error anywhere (the `usage-bar-fill` invented-class
class). This gate's first run found the host-config logrotate/cron textareas
had referenced isl-752/isl-753 since their introduction with no CSS ever
defined (fixed — mono font), plus the phantom isl-iadd token (removed).

A referenced class counts as RESOLVED when it is:
  - defined in static/css/styles.css, or
  - used as a JS hook (querySelector/closest/getElementsByClassName/
    classList.contains) — functional, styling not intended.

Everything else must be in the LEGACY set below (referenced with no styles
and no hook — reviewed 2026-07-24 as harmless no-ops; remove or style them
when touching that surface, and DELETE them from this set when you do).
A NEW unresolved class fails the gate.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_HTML = ROOT / "server" / "html"
_JS = _HTML / "static" / "js"
_CSS = _HTML / "static" / "css" / "styles.css"

# Reviewed no-op classes (see module docstring). Shrink-only.
LEGACY_UNSTYLED = {
    "audit-table", "auto-rule-main", "badge", "badge-crit", "banner-toggle",
    "border-b-subtle", "chip", "cmdb-doc-card", "drawer-action-icon",
    "empty-actions", "enroll-quick", "form-stack", "gpu-meter", "hh-detail",
    "journal-line", "log-unit-badge", "meta-item", "modal-header", "mw-140",
    "mw-300", "netmap-scope-wrap", "noprint", "os-icon", "pad-4", "pad-6",
    "pill", "pl-16", "prompt-maxtok", "prompt-numctx", "prompt-temp",
    "prompt-topp", "recovery-code", "row-16-wrap", "row-flex", "rp-tag",
    "settings-filter-row", "skeleton-block", "th-actions", "theme-card-name",
    "tk-th-cb",
}


def _class_token(t):
    """A plausible class token: len>=2, no template-artifact tails."""
    return bool(re.fullmatch(r"[A-Za-z][\w-]*[\w]", t))


class TestClassParity(unittest.TestCase):
    def test_every_referenced_class_resolves(self):
        defined = set(re.findall(r"\.([A-Za-z][\w-]*)", _CSS.read_text()))
        all_js = {p.name: re.sub(r"^\s*//.*$", "", p.read_text(), flags=re.M)
                  for p in _JS.glob("*.js")}
        hooks = set()
        for t in all_js.values():
            hooks |= set(re.findall(
                r"querySelector(?:All)?\(\s*[`'\"][^`'\"]*\.([A-Za-z][\w-]*)", t))
            hooks |= set(re.findall(r"closest\(\s*'[^']*\.([A-Za-z][\w-]*)", t))
            hooks |= set(re.findall(r"getElementsByClassName\('([\w-]+)'", t))
            hooks |= set(re.findall(r"classList\.contains\('([\w-]+)'", t))

        used = {}

        def add(tok, src):
            for t in tok.split():
                if _class_token(t):
                    used.setdefault(t, set()).add(src)

        add_html = (_HTML / "index.html").read_text()
        for m in re.findall(r'class="([^"$]+)"', add_html):
            add(m, "index.html")
        for name, t in all_js.items():
            if not name.startswith("app"):
                continue
            for m in re.findall(r'class="([^"$`{]+)"', t):
                add(m, name)
            for m in re.findall(r"class='([^'$`{]+)'", t):
                add(m, name)
            for m in re.findall(r"classList\.(?:add|toggle)\('([\w-]+)'", t):
                add(m, name)

        unresolved = sorted(
            f'{c} ({", ".join(sorted(srcs)[:3])})'
            for c, srcs in used.items()
            if c not in defined and c not in hooks and c not in LEGACY_UNSTYLED)
        self.assertEqual(unresolved, [],
                         "classes referenced in markup with no CSS definition "
                         "and no JS hook — they render unstyled silently. "
                         "Define the style, use an existing utility class, or "
                         "(reviewed) add to LEGACY_UNSTYLED:\n  "
                         + "\n  ".join(unresolved))

    def test_legacy_set_stays_pruned(self):
        """An entry that gained styles/hooks (or vanished) must leave the set."""
        defined = set(re.findall(r"\.([A-Za-z][\w-]*)", _CSS.read_text()))
        stale = sorted(c for c in LEGACY_UNSTYLED if c in defined)
        self.assertEqual(stale, [],
                         "LEGACY_UNSTYLED entries now defined in CSS — remove "
                         "them from the set:\n  " + "\n  ".join(stale))


if __name__ == "__main__":
    unittest.main()
