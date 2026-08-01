#!/usr/bin/env python3
"""v6.4.2: structural guards for the index.html markup added this cycle.

Three things landed in `server/html/index.html`:

1. A **change-password control on the Account page**. Before this the change-
   password form was reachable from exactly one place — the lock icon in the
   Users admin table — so a non-admin had no way at all to change their own
   password.
2. **ARIA state on the custom widgets**: `aria-expanded` on the 12-domain
   sidebar accordion, and `tablist`/`tab`/`tabpanel` on the tab strips whose
   markup is a flat strip of buttons over panels that exist in the document.
3. The **keyboard-reachability audit** behind item 3 of the sweep: every
   element in the static markup that the document-level `click` dispatcher can
   fire must be reachable by keyboard.

Everything here parses the document (`html.parser`) and asserts on the element
tree — a substring grep would pass on markup inside a comment, on a duplicated
id, or on an `aria-controls` pointing at nothing. Where a claim spans files
(does the new button actually open a working modal?) the assertion is made
against the ids the handler in app.js really touches, not against its name.
"""
import re
import unittest
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_HTML = _ROOT / "server" / "html" / "index.html"
_APPJS = _ROOT / "server" / "html" / "static" / "js" / "app.js"

# Void elements never open a scope, so they must not be pushed on the stack.
_VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())


class _El:
    __slots__ = ("tag", "attrs", "line", "parent", "children", "text")

    def __init__(self, tag, attrs, line, parent):
        self.tag, self.attrs, self.line, self.parent = tag, attrs, line, parent
        self.children = []
        self.text = []

    def get(self, name, default=None):
        return self.attrs.get(name, default)

    def classes(self):
        return set((self.get("class") or "").split())

    def ancestors(self):
        node = self.parent
        while node is not None:
            yield node
            node = node.parent

    def inner_text(self):
        out = list(self.text)
        for c in self.children:
            out.append(c.inner_text())
        return re.sub(r"\s+", " ", "".join(out)).strip()

    def __repr__(self):                                    # pragma: no cover
        return "<%s#%s line %d>" % (self.tag, self.get("id") or "", self.line)


class _Tree(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _El("#document", {}, 0, None)
        self._stack = [self.root]
        self.all = []

    def handle_starttag(self, tag, attrs):
        el = _El(tag, dict(attrs), self.getpos()[0], self._stack[-1])
        self._stack[-1].children.append(el)
        self.all.append(el)
        if tag not in _VOID:
            self._stack.append(el)

    def handle_startendtag(self, tag, attrs):
        el = _El(tag, dict(attrs), self.getpos()[0], self._stack[-1])
        self._stack[-1].children.append(el)
        self.all.append(el)

    def handle_endtag(self, tag):
        for i in range(len(self._stack) - 1, 0, -1):
            if self._stack[i].tag == tag:
                del self._stack[i:]
                return
        # Stray close tag (or a tag the source leaves implicitly open) — ignore.

    def handle_data(self, data):
        self._stack[-1].text.append(data)


def _parse():
    t = _Tree()
    t.feed(_HTML.read_text(encoding="utf-8"))
    return t


_TREE = _parse()
_ALL = _TREE.all
_BY_ID = {}
for _e in _ALL:
    if _e.get("id"):
        _BY_ID.setdefault(_e.get("id"), _e)


def _by_id(i):
    return _BY_ID.get(i)


def _find(pred):
    return [e for e in _ALL if pred(e)]


class TestDocumentIntegrity(unittest.TestCase):
    """The whole-document invariants every addition here relies on."""

    def test_ids_are_unique(self):
        ids = [e.get("id") for e in _ALL if e.get("id")]
        dupes = sorted(k for k, v in Counter(ids).items() if v > 1)
        self.assertEqual(dupes, [], "duplicate element ids in index.html: %s" % dupes)

    def test_no_aria_reference_dangles(self):
        """`aria-controls`/`aria-labelledby` pointing at a missing id is worse
        than no ARIA — the relationship is announced and then leads nowhere."""
        bad = []
        for e in _ALL:
            for attr in ("aria-controls", "aria-labelledby", "aria-describedby"):
                for ref in (e.get(attr) or "").split():
                    if ref not in _BY_ID:
                        bad.append("line %d <%s %s=%s>" % (e.line, e.tag, attr, ref))
        self.assertEqual(bad, [], "dangling ARIA id references: %s" % bad)


class TestAccountPasswordSection(unittest.TestCase):
    """The Account page gained the only self-service password control."""

    def setUp(self):
        self.sec = _by_id("account-password-section")
        self.assertIsNotNone(self.sec, "#account-password-section is missing")

    def test_lives_on_the_account_page_as_a_settings_section(self):
        self.assertIn("settings-section", self.sec.classes())
        page = [a for a in self.sec.ancestors() if a.get("id") == "page-account"]
        self.assertTrue(page, "the password section is not inside #page-account")

    def test_section_title_is_the_first_child_and_on_the_page_idiom(self):
        first = self.sec.children[0]
        self.assertIn("section-title", first.classes(),
                      "a card's first child must be its .section-title heading")
        self.assertEqual(first.tag, "div")
        self.assertEqual(first.inner_text(), "Password")

    def test_has_a_hint_explaining_it(self):
        hints = [c for c in self.sec.children if "hint" in c.classes()]
        self.assertEqual(len(hints), 1, "expected exactly one <p class=hint>")
        self.assertEqual(hints[0].tag, "p")
        self.assertGreater(len(hints[0].inner_text()), 30)

    def test_button_dispatches_openPasswd_and_is_a_real_button(self):
        btns = [c for c in self.sec.children if c.tag == "button"]
        self.assertEqual(len(btns), 1)
        b = btns[0]
        # NOT openPasswd: the data-action dispatcher passes data-arg, and with
        # none the username field receives the literal string "undefined", which
        # then 403s as a non-admin changing someone else's password. openMyPasswd
        # resolves the signed-in account itself; the admin Users-table row keeps
        # openPasswd with an explicit username, the only case that may target
        # someone else.
        self.assertEqual(b.get("data-action"), "openMyPasswd")
        self.assertEqual(b.get("id"), "acct-passwd-btn")
        self.assertIn("btn-icon", b.classes())

    def test_button_icon_is_inline_lucide_svg_not_an_emoji(self):
        b = [c for c in self.sec.children if c.tag == "button"][0]
        svgs = [c for c in b.children if c.tag == "svg"]
        self.assertEqual(len(svgs), 1, "the button needs exactly one inline SVG icon")
        self.assertEqual(svgs[0].get("stroke"), "currentColor")
        # html.parser lower-cases attribute names, so `viewBox` arrives as
        # `viewbox` — assert on what the parser hands back, not on the source.
        self.assertEqual(svgs[0].get("viewbox"), "0 0 24 24")
        self.assertEqual(svgs[0].get("width"), "14")
        self.assertEqual(svgs[0].get("aria-hidden"), "true")
        # No character outside Latin-1 punctuation/letters: catches an emoji or
        # a pictograph slipped in as the icon.
        for ch in self.sec.inner_text():
            self.assertLess(ord(ch), 0x2500, "non-icon pictograph %r in the section" % ch)

    def test_section_is_csp_clean(self):
        for e in [self.sec] + _descendants(self.sec):
            self.assertIsNone(e.get("style"), "inline style= at line %d" % e.line)
            for k in e.attrs:
                self.assertFalse(k.startswith("on"), "inline %s= at line %d" % (k, e.line))

    def test_the_modal_the_button_opens_is_actually_wired(self):
        """Cross-file wiring: every element id `openPasswd`/`submitPasswd` touch
        must exist here, or the button opens a modal that cannot work."""
        js = _APPJS.read_text(encoding="utf-8")
        body = ""
        for name in ("openPasswd", "submitPasswd"):
            m = re.search(r"^(?:async )?function %s\(.*$" % name, js, re.M)
            self.assertIsNotNone(m, "%s() no longer exists in app.js" % name)
            body += m.group(0)
        touched = set(re.findall(r"getElementById\('([a-z0-9-]+)'\)", body))
        touched |= set(re.findall(r"(?:open|close)Modal\('([a-z0-9-]+)'\)", body))
        self.assertIn("passwd-modal", touched, "handler extraction looks broken")
        missing = sorted(t for t in touched if t not in _BY_ID)
        self.assertEqual(missing, [],
                         "the password handler references ids absent from "
                         "index.html: %s" % missing)


def _descendants(el):
    out = []
    stack = list(el.children)
    while stack:
        e = stack.pop()
        out.append(e)
        stack.extend(e.children)
    return out


class TestSidebarAccordionAria(unittest.TestCase):
    """The 12-domain accordion exposes its expanded state."""

    def setUp(self):
        self.groups = _find(lambda e: "sidebar-group" in e.classes() and e.get("data-group"))
        self.assertGreaterEqual(len(self.groups), 12, "sidebar group extraction looks broken")

    def test_every_group_toggle_has_aria_expanded_and_controls_its_items(self):
        for g in self.groups:
            name = g.get("data-group")
            toggles = [c for c in g.children if "sidebar-group-toggle" in c.classes()]
            self.assertEqual(len(toggles), 1, "group %s: expected one toggle" % name)
            t = toggles[0]
            self.assertEqual(t.tag, "button")
            self.assertIn(t.get("aria-expanded"), ("true", "false"),
                          "group %s: toggle has no aria-expanded" % name)
            items = [c for c in g.children if "sidebar-group-items" in c.classes()]
            self.assertEqual(len(items), 1, "group %s: expected one items panel" % name)
            self.assertEqual(t.get("aria-controls"), items[0].get("id"),
                             "group %s: aria-controls must name its items panel" % name)

    def test_static_state_matches_the_shipped_default(self):
        """_restoreSidebarGroups() collapses every group when nothing is stored,
        so the static default is `false` for all twelve. A `true` here would be
        a lie on a fresh session."""
        for g in self.groups:
            t = [c for c in g.children if "sidebar-group-toggle" in c.classes()][0]
            collapsed = "collapsed" in g.classes()
            self.assertEqual(t.get("aria-expanded"), "false",
                             "group %s ships aria-expanded=%r (collapsed=%s)"
                             % (g.get("data-group"), t.get("aria-expanded"), collapsed))


class TestTabWidgetAria(unittest.TestCase):
    """Every tablist added is complete: tabs, panels and exactly one selection."""

    def setUp(self):
        self.tablists = _find(lambda e: e.get("role") == "tablist")
        self.assertGreaterEqual(len(self.tablists), 4, "tablist extraction looks broken")

    def test_each_tablist_owns_its_tabs_and_labels_itself(self):
        for tl in self.tablists:
            tabs = [d for d in _descendants(tl) if d.get("role") == "tab"]
            self.assertGreaterEqual(len(tabs), 2,
                                    "tablist at line %d has %d tabs" % (tl.line, len(tabs)))
            self.assertTrue(tl.get("aria-label"),
                            "tablist at line %d has no accessible name" % tl.line)
            # Anything focusable inside a tablist that is not a tab breaks the
            # widget's semantics — that is why the billing strip (which carries
            # an "AI review" button) is deliberately not a tablist.
            for d in _descendants(tl):
                if d.tag == "button":
                    self.assertEqual(d.get("role"), "tab",
                                     "non-tab <button> inside the tablist at line %d" % tl.line)

    def test_exactly_one_tab_selected_per_tablist_and_it_is_the_active_one(self):
        for tl in self.tablists:
            tabs = [d for d in _descendants(tl) if d.get("role") == "tab"]
            selected = [t for t in tabs if t.get("aria-selected") == "true"]
            self.assertEqual(len(selected), 1,
                             "tablist at line %d has %d selected tabs"
                             % (tl.line, len(selected)))
            for t in tabs:
                self.assertIn(t.get("aria-selected"), ("true", "false"),
                              "tab at line %d has no aria-selected" % t.line)
                # The CSS `active` class is the visual truth; the ARIA state
                # must not contradict it or a screen reader is told the wrong
                # tab is open.
                self.assertEqual(t.get("aria-selected") == "true",
                                 "active" in t.classes(),
                                 "tab at line %d: aria-selected disagrees with "
                                 ".active" % t.line)

    def test_every_tab_controls_a_real_tabpanel_that_points_back(self):
        tabs = _find(lambda e: e.get("role") == "tab")
        self.assertGreaterEqual(len(tabs), 20)
        for t in tabs:
            panel_id = t.get("aria-controls")
            self.assertTrue(panel_id, "tab at line %d controls nothing" % t.line)
            panel = _by_id(panel_id)
            self.assertIsNotNone(panel, "tab at line %d: no #%s" % (t.line, panel_id))
            self.assertEqual(panel.get("role"), "tabpanel",
                             "#%s is not role=tabpanel" % panel_id)
            self.assertTrue(t.get("id"), "tab at line %d needs an id to label its "
                                         "panel" % t.line)
            self.assertEqual(panel.get("aria-labelledby"), t.get("id"),
                             "#%s must be labelled by its tab" % panel_id)

    def test_no_orphan_tabpanels(self):
        controlled = {t.get("aria-controls") for t in _find(lambda e: e.get("role") == "tab")}
        orphans = sorted(p.get("id") for p in _find(lambda e: e.get("role") == "tabpanel")
                         if p.get("id") not in controlled)
        self.assertEqual(orphans, [], "tabpanels no tab controls: %s" % orphans)

    def test_settings_tab_cluster_wrappers_are_flattened(self):
        """A tablist's required owned element is `tab`; the four visual clusters
        would otherwise sit between the list and its tabs."""
        groups = _find(lambda e: "settings-tab-group" in e.classes())
        self.assertGreaterEqual(len(groups), 4)
        for g in groups:
            self.assertEqual(g.get("role"), "presentation",
                             "cluster wrapper at line %d is not flattened" % g.line)
        for lbl in _find(lambda e: "settings-tab-group-label" in e.classes()):
            self.assertEqual(lbl.get("aria-hidden"), "true",
                             "cluster label at line %d leaks into the tablist" % lbl.line)


class TestClickTargetsAreKeyboardReachable(unittest.TestCase):
    """Every statically-authored control the document `click` dispatcher can
    fire must be operable without a mouse."""

    # Attributes the delegated click listeners in app.js match on.
    CLICK_ATTRS = ("data-action", "data-action-btn", "data-drawer-act", "data-home-act")
    # Natively focusable + activatable by Enter/Space.
    NATIVE = frozenset({"button", "input", "select", "textarea", "summary"})

    def test_no_unreachable_click_target(self):
        bad = []
        seen = 0
        for e in _ALL:
            if not any(e.get(a) for a in self.CLICK_ATTRS):
                continue
            seen += 1
            if e.tag in self.NATIVE:
                continue
            if e.tag == "a" and e.get("href") is not None:
                continue
            if "drawer-backdrop" in e.classes():
                # A click-outside dismiss layer, not a control: it duplicates
                # the drawer's real Close button, and Escape closes the drawer
                # (app.js keydown). Giving it a tabindex would put a nameless
                # stop in the tab order.
                continue
            if e.get("role") == "button" and e.get("tabindex") == "0":
                continue
            bad.append("line %d <%s class=%r %s>"
                       % (e.line, e.tag, e.get("class"),
                          [a for a in self.CLICK_ATTRS if e.get(a)]))
        self.assertGreater(seen, 400, "click-target extraction looks broken")
        self.assertEqual(bad, [],
                         "click-dispatched elements with no keyboard path: %s" % bad)

    def test_role_button_click_targets_carry_an_accessible_name(self):
        for e in _ALL:
            if e.get("role") != "button" or not e.get("data-action"):
                continue
            self.assertTrue(e.get("aria-label") or e.get("title") or e.inner_text(),
                            "nameless role=button at line %d" % e.line)


if __name__ == "__main__":
    unittest.main()
