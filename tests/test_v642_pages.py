#!/usr/bin/env python3
"""v6.4.2 — the two new fleet pages (Needs Attention, Tags & groups).

Both shipped as markup first, with their loaders landing separately, so the
failure mode this guards is a page shell that *looks* right and is unreachable
or unsortable: a nav entry in the wrong accordion group, a `<th>` with no
`data-col` (the sort click then silently does nothing), a doc pointer at a file
that does not exist, or an overlay nested inside `.container` (the z-index trap
that shipped the split-drawer bug).

Everything here goes through a real parse of index.html, not a substring
search — a `grep` for `data-col=` proves a string exists, never that the
attribute sits on a `<th>` inside the right `<thead>`.
"""

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = _ROOT / "server" / "html" / "index.html"
_DOCS = _ROOT / "docs"

# Elements that never carry an end tag; without these the ancestor stack drifts
# and every later element reports a bogus parent.
_VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
    # SVG leaves used inline throughout the sidebar / icon markup
    "path", "circle", "line", "polyline", "polygon", "rect", "ellipse", "use",
    "stop", "feoffset", "fegaussianblur", "femerge", "femergenode",
}


class _Node:
    __slots__ = ("tag", "attrs", "parent", "children", "text")

    def __init__(self, tag, attrs, parent):
        self.tag = tag
        self.attrs = attrs
        self.parent = parent
        self.children = []
        self.text = []

    # ── helpers the assertions read ───────────────────────────────────────
    def get(self, name, default=None):
        return self.attrs.get(name, default)

    def classes(self):
        return set((self.get("class") or "").split())

    def ancestors(self):
        n = self.parent
        while n is not None:
            yield n
            n = n.parent

    def descendants(self):
        for c in self.children:
            yield c
            yield from c.descendants()

    def find_all(self, tag=None, cls=None, **attrs):
        for n in self.descendants():
            if tag and n.tag != tag:
                continue
            if cls and cls not in n.classes():
                continue
            if any(n.get(k) != v for k, v in attrs.items()):
                continue
            yield n

    def inner_text(self):
        out = list(self.text)
        for c in self.children:
            out.append(c.inner_text())
        return re.sub(r"\s+", " ", "".join(out)).strip()

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<{self.tag} {self.attrs.get('id') or self.attrs.get('class', '')}>"


class _Tree(HTMLParser):
    """Lenient DOM builder. A stray end tag pops to its nearest matching
    ancestor and is otherwise ignored, so a malformed island elsewhere in this
    11k-line file cannot corrupt the parts under test."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Node("#document", {}, None)
        self._stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, dict(attrs), self._stack[-1])
        self._stack[-1].children.append(node)
        if tag not in _VOID:
            self._stack.append(node)

    def handle_startendtag(self, tag, attrs):
        node = _Node(tag, dict(attrs), self._stack[-1])
        self._stack[-1].children.append(node)

    def handle_endtag(self, tag):
        for i in range(len(self._stack) - 1, 0, -1):
            if self._stack[i].tag == tag:
                del self._stack[i:]
                return

    def handle_data(self, data):
        self._stack[-1].text.append(data)


def _parse():
    p = _Tree()
    p.feed(_HTML.read_text())
    return p.root


_DOC = _parse()


def _by_id(node_id):
    for n in _DOC.descendants():
        if n.get("id") == node_id:
            return n
    return None


def _nav_button(page):
    hits = [n for n in _DOC.descendants()
            if n.tag == "button" and n.get("data-page") == page
            and "nav-btn" in n.classes()]
    return hits


def _group_of(node):
    """The `data-group` of the sidebar accordion a node sits in, or None."""
    for a in node.ancestors():
        g = a.get("data-group")
        if g:
            return g
    return None


class PageShellMixin:
    """Shared shape assertions — a page is a `.page` div with a title, a
    subtitle carrying a documentation pointer, and a sortable table."""

    PAGE_ID = ""
    NAV_PAGE = ""
    NAV_GROUP = ""
    DOC = ""
    THEADS = ()
    TBODIES = ()

    def page(self):
        node = _by_id(self.PAGE_ID)
        self.assertIsNotNone(node, f"#{self.PAGE_ID} is missing from index.html")
        return node

    def test_page_is_a_page_div_inside_the_container(self):
        node = self.page()
        self.assertEqual(node.tag, "div")
        self.assertIn("page", node.classes(),
                      "a page div without .page is never shown by showPage()")
        self.assertNotIn("active", node.classes(),
                         "only the home page may ship pre-activated")
        self.assertTrue(
            any("container" in a.classes() for a in node.ancestors()),
            "pages live inside .container with their siblings")

    def test_page_has_a_title_and_a_subtitle(self):
        node = self.page()
        titles = [n for n in node.find_all(cls="page-title")]
        subs = [n for n in node.find_all(cls="page-subtitle")]
        self.assertEqual(len(titles), 1, "exactly one .page-title per page")
        self.assertEqual(len(subs), 1, "exactly one .page-subtitle per page")
        self.assertTrue(titles[0].inner_text(), "the page title is empty")
        self.assertTrue(subs[0].inner_text(), "the page subtitle is empty")

    def test_subtitle_carries_a_doc_pointer_that_resolves(self):
        sub = next(self.page().find_all(cls="page-subtitle"))
        links = [a for a in sub.find_all("a")
                 if (a.get("href") or "").startswith("docs/")]
        self.assertTrue(links, "the page subtitle has no docs/ pointer")
        href = links[0].get("href")
        self.assertEqual(href, self.DOC)
        self.assertIn("c-accent", links[0].classes(),
                      "doc pointers use the .c-accent idiom")
        self.assertTrue((_DOCS / href.split("/", 1)[1]).exists(),
                        f"{href} does not exist — the pointer is a dead link")

    def test_nav_entry_exists_once_in_the_right_accordion_group(self):
        hits = _nav_button(self.NAV_PAGE)
        self.assertEqual(len(hits), 1,
                         f'expected exactly one nav-btn for data-page="'
                         f'{self.NAV_PAGE}", found {len(hits)}')
        self.assertEqual(_group_of(hits[0]), self.NAV_GROUP)
        self.assertTrue(hits[0].get("title"),
                        "every nav button carries a hover title")

    def test_nav_entry_label_is_a_span_and_its_icon_is_an_svg(self):
        btn = _nav_button(self.NAV_PAGE)[0]
        spans = [c for c in btn.children if c.tag == "span"]
        self.assertEqual(len(spans), 1, "nav label is a single bare <span>")
        self.assertTrue(spans[0].inner_text())
        svgs = [c for c in btn.children if c.tag == "svg"]
        self.assertEqual(len(svgs), 1, "nav icon is one inline SVG")
        self.assertEqual(svgs[0].get("stroke"), "currentColor",
                         "Lucide-style icons stroke with currentColor")
        # An emoji where a glyph icon belongs is the house rule this catches.
        self.assertFalse(
            re.search(r"[\U0001F300-\U0001FAFF←-➿]", btn.inner_text()),
            "no emoji in UI chrome")

    def test_every_sortable_header_is_well_formed(self):
        node = self.page()
        for thead_id, expected in self.THEADS:
            thead = _by_id(thead_id)
            self.assertIsNotNone(thead, f"#{thead_id} is missing")
            self.assertEqual(thead.tag, "thead")
            self.assertIn(thead, list(node.descendants()),
                          f"#{thead_id} is not inside #{self.PAGE_ID}")
            ths = [n for n in thead.find_all("th")]
            self.assertTrue(ths, f"#{thead_id} has no <th>")
            cols = [t.get("data-col") for t in ths if t.get("data-col")]
            self.assertEqual(cols, list(expected),
                             f"#{thead_id} data-col keys drifted")
            self.assertEqual(len(cols), len(set(cols)),
                             "duplicate data-col keys make sorting ambiguous")
            for t in ths:
                self.assertEqual(t.get("scope"), "col",
                                 "every header cell declares scope=col")
                col = t.get("data-col")
                if col is None:
                    # Only the trailing action column may be key-less, and it
                    # must be empty — a labelled header with no data-col reads
                    # as sortable and silently is not.
                    self.assertEqual(t.inner_text(), "",
                                     "a labelled <th> must carry a data-col")
                else:
                    self.assertRegex(col, r"^[a-z][a-z0-9_]*$")
                    self.assertTrue(t.inner_text(),
                                    "a sortable header needs a visible label")

    def test_table_body_exists_and_is_height_capped(self):
        node = self.page()
        for tbody_id, colspan in self.TBODIES:
            tbody = _by_id(tbody_id)
            self.assertIsNotNone(tbody, f"#{tbody_id} is missing")
            self.assertEqual(tbody.tag, "tbody")
            self.assertIn(tbody, list(node.descendants()))
            # A variable-row table caps its height and scrolls internally.
            capped = any(
                "scrollable-table-wrap" in a.classes() or "table-card" in a.classes()
                for a in tbody.ancestors())
            self.assertTrue(capped,
                            f"#{tbody_id} grows unbounded — wrap it in "
                            f".scrollable-table-wrap or .table-card")
            # The placeholder row must span the whole table or it renders as a
            # one-cell stub with the rest of the header floating over nothing.
            cells = [c for c in tbody.find_all("td")]
            self.assertEqual(len(cells), 1, "one placeholder cell before load")
            self.assertEqual(cells[0].get("colspan"), str(colspan))
            self.assertTrue(cells[0].inner_text())

    def test_page_markup_is_csp_clean(self):
        node = self.page()
        for n in [node] + list(node.descendants()):
            self.assertNotIn("style", n.attrs,
                             f"inline style attribute on <{n.tag}> dies under CSP")
            bad = [k for k in n.attrs if re.fullmatch(r"on[a-z]+", k)]
            self.assertEqual(bad, [],
                             f"inline event handler {bad} on <{n.tag}>")

    def test_every_form_control_has_an_accessible_name(self):
        node = self.page()
        labelled = {lb.get("for") for lb in node.find_all("label") if lb.get("for")}
        for n in node.descendants():
            if n.tag not in ("input", "select", "textarea"):
                continue
            if n.get("type") == "hidden":
                continue
            named = (n.get("aria-label") or n.get("aria-labelledby")
                     or n.get("id") in labelled
                     or any(a.tag == "label" for a in n.ancestors()))
            self.assertTrue(named,
                            f"<{n.tag} id={n.get('id')}> has no accessible name")


class TestNeedsAttentionPage(PageShellMixin, unittest.TestCase):
    PAGE_ID = "page-attention"
    NAV_PAGE = "attention"
    NAV_GROUP = "monitoring"
    DOC = "docs/attention.md"
    # Order matches the cells loadAttentionPage()'s row-builder emits; the keys
    # match its getColumns(), or the header sorts a column that isn't there.
    # Order matches the cells the row-builder emits; the keys match its
    # getColumns(), or a header sorts a column the rows do not carry.
    THEADS = (("attention-thead", ("severity", "kind", "device", "summary")),)
    TBODIES = (("attention-tbody", 5),)

    def test_filter_controls_exist_with_the_ids_the_loader_binds(self):
        node = self.page()
        for ident, tag in (("attention-sev-filter", "select"),
                           ("attention-kind-filter", "select"),
                           ("attention-device-filter", "select"),
                           ("attention-filter", "input"),
                           ("attention-counts", "div")):
            el = _by_id(ident)
            self.assertIsNotNone(el, f"#{ident} is missing")
            self.assertEqual(el.tag, tag)
            self.assertIn(el, list(node.descendants()))

    def test_severity_filter_offers_the_severities_the_digest_emits(self):
        sel = _by_id("attention-sev-filter")
        values = [o.get("value") for o in sel.find_all("option")]
        # 'all' is the show-everything sentinel the renderer tests for; the rest
        # mirror the severities _compute_attention emits.
        self.assertEqual(values, ["all", "critical", "warning", "info"])

    def test_dynamic_pickers_ship_only_their_all_sentinel(self):
        """The loader replaceChildren()s these from the rows it fetched — a
        hardcoded option list here is a lie before the first load and gone
        after it."""
        for ident in ("attention-kind-filter", "attention-device-filter"):
            opts = [o.get("value") for o in _by_id(ident).find_all("option")]
            self.assertEqual(opts, ["all"], f"#{ident} presets options")

    def test_controls_dispatch_through_data_attributes_not_inline_js(self):
        for ident in ("attention-sev-filter", "attention-kind-filter",
                      "attention-device-filter"):
            self.assertEqual(_by_id(ident).get("data-change"),
                             "renderAttentionPage")
        # The free-text box is wired by tableCtl.register(filterInput), which
        # attaches its own debounced listener — a data-input here would render
        # every keystroke twice.
        self.assertIsNone(_by_id("attention-filter").get("data-input"))
        node = self.page()
        actions = {b.get("data-action") for b in node.find_all("button")
                   if b.get("data-action")}
        self.assertIn("loadAttentionPage", actions,
                      "the page needs a refresh control bound to its loader")


class TestTagsAndGroupsPage(PageShellMixin, unittest.TestCase):
    PAGE_ID = "page-taxonomy"
    NAV_PAGE = "taxonomy"
    NAV_GROUP = "fleet"
    DOC = "docs/fleet-management.md"
    THEADS = (
        ("taxonomy-tags-thead", ("name", "device_count")),
        ("taxonomy-groups-thead", ("name", "device_count")),
    )
    TBODIES = (("taxonomy-tags-tbody", 3), ("taxonomy-groups-tbody", 3))

    def test_each_table_sits_in_its_own_titled_card(self):
        node = self.page()
        cards = [c for c in node.find_all(cls="dash-card")]
        self.assertEqual(len(cards), 2, "one card for tags, one for groups")
        for card in cards:
            first = next((c for c in card.children if c.tag != "#text"), None)
            self.assertIsNotNone(first)
            self.assertIn("section-title", first.classes(),
                          "a card's first child is its .section-title")
            self.assertTrue(first.inner_text())
        self.assertEqual([next(c.find_all(cls="section-title")).inner_text()
                          for c in cards], ["Tags", "Groups"])

    def test_each_table_has_its_own_filter_input(self):
        node = self.page()
        for ident in ("taxonomy-tags-filter", "taxonomy-groups-filter"):
            el = _by_id(ident)
            self.assertIsNotNone(el, f"#{ident} is missing")
            self.assertEqual(el.tag, "input")
            self.assertIn(el, list(node.descendants()))
            # tableCtl.register() attaches the listener itself; a data-input
            # would add a second one on top of it.
            self.assertIsNone(el.get("data-input"))

    def test_summary_and_refresh_are_present(self):
        node = self.page()
        summary = _by_id("taxonomy-summary")
        self.assertIsNotNone(summary, "#taxonomy-summary is missing")
        self.assertIn(summary, list(node.descendants()))
        self.assertEqual(summary.inner_text(), "",
                         "the summary line is filled in by the renderer")
        actions = {b.get("data-action") for b in node.find_all("button")
                   if b.get("data-action")}
        self.assertIn("loadTaxonomy", actions)

    def test_groups_card_states_what_a_rename_does_not_touch(self):
        """Groups were read-only here until v6.4.2, and the card said so —
        which was right while the only primitive was PATCH-per-device.

        The atomic endpoints exist now, so the card carries the write actions
        and the honest caveat has moved: a rename does NOT rewrite the role
        scopes, alert routing, auto-patch targets, rollout rings or smart
        groups that name the group. That is the sentence worth pinning, because
        it is the one an operator needs before pressing the button.
        """
        text = list(self.page().find_all(cls="dash-card"))[1].inner_text().lower()
        self.assertIn("not", text)
        self.assertIn("role scopes", text)
        self.assertNotIn("read-only", text,
                         "the card still claims groups are read-only, but the "
                         "table now offers rename/merge/delete")

    def test_no_orphan_rename_dialog_is_left_behind(self):
        """An earlier shell carried a taxonomy-rename-modal; the loader drives
        rename/merge through uiPrompt/uiConfirm instead, so a leftover dialog
        would be dead markup nothing can open."""
        self.assertIsNone(_by_id("taxonomy-rename-modal"))


class TestNavOrderingContract(unittest.TestCase):
    """test_v234 pins Monitoring before Security; the new entries must not
    reorder the accordion, and a nav button must name a page that exists."""

    def test_monitoring_group_still_precedes_security(self):
        html = _HTML.read_text()
        mon = html.index('data-group="monitoring"')
        sec = html.index('data-group="security"')
        self.assertLess(mon, sec)

    def test_new_nav_entries_point_at_pages_that_exist(self):
        page_ids = {n.get("id") for n in _DOC.descendants()
                    if "page" in n.classes() and (n.get("id") or "").startswith("page-")}
        for page in ("attention", "taxonomy"):
            self.assertIn(f"page-{page}", page_ids,
                          f'nav data-page="{page}" has no #page-{page}')

    def test_needs_attention_is_the_first_monitoring_entry(self):
        """It is the triage entry point for the group; the dashboard card links
        here, so burying it under Live Monitor would hide the full list."""
        items = _by_id("sbg-monitoring")
        self.assertIsNotNone(items)
        pages = [n.get("data-page") for n in items.find_all("button", cls="nav-btn")]
        self.assertEqual(pages[0], "attention")


if __name__ == "__main__":
    unittest.main()
