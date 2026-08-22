#!/usr/bin/env python3
"""The MCP tool inventory was wrong on every doc surface that carried a count.

`mcp/remotepower-mcp.py` defines 21 tools — 16 read, 5 guarded write. The
in-app Documentation page said "18 tools: 14 read + 4 guarded write" and then
enumerated exactly those 18. `docs/README.md` said "14 read + 4 guarded write".
`docs/mcp.md` got the headline right and its read table listed 14 of the 16,
and its threat-model row still said writes were "limited to the four
compiled-in, pre-saved actions".

`list_alerts` and `get_attention` appeared in no documentation anywhere. Their
own tool descriptions call them the right first call for "what is wrong right
now?" and the better call for "what should I work on?" — so an operator wiring
Claude Desktop from either the in-app page or docs/README.md provisioned a
token and never learned the assistant could read the alert inbox or the
needs-attention digest.

The counts are derived from the TOOLS literal here rather than restated, so a
new tool fails this until the docs name it.
"""
import ast
import pathlib
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MCP = _ROOT / 'mcp' / 'remotepower-mcp.py'


def _tools():
    src = _MCP.read_text()
    for n in ast.parse(src).body:
        if isinstance(n, ast.Assign) and any(
                getattr(t, 'id', '') == 'TOOLS' for t in n.targets):
            return [ast.literal_eval(k) for k in n.value.keys]
    raise AssertionError('TOOLS literal not found')


# Writes are the tools that change fleet state. `search_fleet` POSTs a query
# body and is a READ — classifying by HTTP method calls it a write, which is
# how a scan of this file can get the split wrong by one in each column.
_WRITE = {'acknowledge_alert', 'reboot_device', 'run_saved_script',
          'force_package_scan', 'force_acme_rescan'}


class TestThePremise(unittest.TestCase):

    def test_the_tools_literal_is_readable(self):
        names = _tools()
        self.assertGreater(len(names), 15)
        self.assertEqual(sorted(set(names)), sorted(names), 'duplicate tool')

    def test_every_declared_write_exists(self):
        """If a write tool is renamed, the split below silently shifts and the
        doc counts this file checks become wrong in a new way."""
        names = set(_tools())
        self.assertTrue(_WRITE <= names, sorted(_WRITE - names))


class TestEveryDocSurfaceAgrees(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.names = _tools()
        cls.total = len(cls.names)
        cls.writes = len(_WRITE)
        cls.reads = cls.total - cls.writes

    def test_the_in_app_documentation_page(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn(
            f'<strong>{self.total} tools: {self.reads} read + '
            f'{self.writes} guarded write.</strong>', html)

    def test_the_in_app_page_enumerates_every_tool(self):
        """The count and the list are separate claims. Fixing the number and
        leaving the list short is the state docs/mcp.md was already in."""
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        # Bound by CONTENT, not a character count: the enumeration is one <p>,
        # so end at its closing tag. A fixed window is a guess about how long
        # the paragraph is and silently stops covering the tail when a tool is
        # added — which is the failure this test exists to catch.
        i = html.index(' tools: ')
        block = html[i:html.index('</p>', i)]
        missing = [n for n in self.names if f'<code>{n}</code>' not in block]
        self.assertEqual([], missing,
                         f'named nowhere on the in-app page: {missing}')

    def test_docs_readme(self):
        md = (_ROOT / 'docs' / 'README.md').read_text()
        self.assertIn(f'{self.reads} read + {self.writes} guarded write', md)

    def test_docs_mcp_headline(self):
        md = (_ROOT / 'docs' / 'mcp.md').read_text()
        self.assertIn(f'**{self.total} tools — {self.reads} read, '
                      f'{self.writes} guarded write.**', md)

    def test_docs_mcp_names_every_tool(self):
        md = (_ROOT / 'docs' / 'mcp.md').read_text()
        missing = [n for n in self.names if f'`{n}`' not in md]
        self.assertEqual([], missing,
                         f'undocumented in the MCP guide: {missing}')

    def test_docs_mcp_does_not_still_say_four_writes(self):
        """The count appears as a word in the threat-model row, which a
        numeric search does not reach."""
        md = (_ROOT / 'docs' / 'mcp.md').read_text()
        for word in ('the four compiled-in', 'the four write'):
            self.assertNotIn(word, md)

    def test_no_surface_still_carries_the_old_numbers(self):
        stale = ('18 tools', '14 read', '4 guarded write')
        for rel in ('docs/mcp.md', 'docs/README.md', 'server/html/index.html',
                    'README.md', 'docs/features.md'):
            p = _ROOT / rel
            if not p.exists():
                continue
            body = p.read_text()
            for s in stale:
                self.assertNotIn(s, body, f'{rel} still says "{s}"')


class TestTheTwoToolsThatWereDocumentedNowhere(unittest.TestCase):
    """Named explicitly. They are the two an operator most wants and they were
    invisible on every surface; a generic count check would pass again the day
    someone trims a table."""

    _SURFACES = ('docs/mcp.md', 'server/html/index.html')

    def test_list_alerts_and_get_attention_are_described(self):
        for rel in self._SURFACES:
            body = (_ROOT / rel).read_text()
            for tool in ('list_alerts', 'get_attention'):
                self.assertIn(tool, body, f'{tool} is absent from {rel}')

    def test_the_mcp_guide_says_what_they_return(self):
        md = (_ROOT / 'docs' / 'mcp.md').read_text()
        row = next((l for l in md.splitlines()
                    if l.startswith('| `list_alerts`')), '')
        self.assertGreater(len(row), 80, 'list_alerts has a name but no '
                                         'description in the tool table')
        row = next((l for l in md.splitlines()
                    if l.startswith('| `get_attention`')), '')
        self.assertGreater(len(row), 80)


if __name__ == '__main__':
    unittest.main()
