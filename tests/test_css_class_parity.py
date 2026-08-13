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
    "settings-filter-row", "th-actions", "theme-card-name",
    "tk-th-cb",
    # v6.4.3: surfaced when this gate stopped counting classes named in
    # COMMENTS as defined. All nine were already reviewed decisions whose only
    # trace in the stylesheet is the comment recording them — which is exactly
    # why the old raw-text read resolved them and why they look new here.
    #   .isl-3xx/4xx/5xx/6xx — "dynamic colour, applied via data-color
    #     attribute": deliberately carry no static rule, the colour arrives from
    #     the attribute at render time.
    #   .nav-alert / .nav-warn — the v6 flat design dropped the icon tints and
    #     colours the count text instead. styles.css says so verbatim: "JS still
    #     sets the classes; they're just unstyled now."
    "isl-376", "isl-377", "isl-401", "isl-457", "isl-536", "isl-543", "isl-648",
    "nav-alert", "nav-warn",
}


def _class_token(t):
    """A plausible class token: len>=2, no template-artifact tails."""
    return bool(re.fullmatch(r"[A-Za-z][\w-]*[\w]", t))


def _css_without_comments():
    """CSS with /* … */ stripped.

    v6.4.3: both checks below read the RAW file, so a class named in a comment
    counted as DEFINED — and the comments in styles.css are largely RETIREMENT
    notes explaining why a class was removed, which is precisely the class most
    likely to still be referenced somewhere.

    Proven on `.section-label`: retired at v6.4.1 with a comment naming it, no
    rule left, still used by one card in index.html — and this gate resolved it
    as defined, so the card silently rendered as 13.5px body text where a
    13px/620 header belonged. Stripping comments turns that into a failure.
    """
    return re.sub(r"/\*.*?\*/", "", _CSS.read_text(), flags=re.S)


class TestClassParity(unittest.TestCase):
    def test_every_referenced_class_resolves(self):
        defined = set(re.findall(r"\.([A-Za-z][\w-]*)", _css_without_comments()))
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
        defined = set(re.findall(r"\.([A-Za-z][\w-]*)", _css_without_comments()))
        stale = sorted(c for c in LEGACY_UNSTYLED if c in defined)
        self.assertEqual(stale, [],
                         "LEGACY_UNSTYLED entries now defined in CSS — remove "
                         "them from the set:\n  " + "\n  ".join(stale))


if __name__ == "__main__":
    unittest.main()
