#!/usr/bin/env python3
"""An endpoint built for a purpose, with nothing calling it, is not a feature.

`GET /api/sessions` shipped in v6.4.2 with a docstring calling it "the
access-review companion to GET /api/me/sessions" — the answer to "who is logged
in right now, from where, and since when", which the docstring itself says "had
no answer anywhere in the product". It was admin-gated, tenant-scoped and
audited. No client ever called it. The answer existed and was unreachable, which
is the same as not having it, except that a reviewer reading api.py would
conclude the gap was closed.

This is the dead-signal class from CLAUDE.md, seen from the other end: usually
a consumer reads a key no producer writes; here a producer writes an answer no
consumer reads. Both are found the same way — by checking the OTHER side.

The tests below pin the surface end to end: route, client call, dispatch names,
DOM ids, and the two properties that make the control honest rather than merely
present (revocation is per-user because that is all the server offers, and a
numeric-looking username survives the dispatcher's Number() coercion).
"""
import json
import re
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_API = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()


class TestTheEndpointHasAClient(unittest.TestCase):
    def test_the_route_exists(self):
        self.assertIn("('GET', '/api/sessions'): handle_sessions_list", _API)

    def test_a_client_actually_calls_it(self):
        """The assertion that would have failed for the whole of v6.4.2."""
        self.assertRegex(_APP, r"api\('GET',\s*'/sessions'\)")

    def test_and_the_revoke_endpoint_too(self):
        self.assertRegex(_APP, r"api\('POST',\s*'/sessions/revoke'")


class TestItIsReachable(unittest.TestCase):
    """Wired at every layer — a function nothing dispatches to is still dead."""

    def test_the_panel_exists(self):
        self.assertIn('id="sessions-result"', _HTML)
        self.assertIn('id="sessions-count"', _HTML)

    def test_the_button_dispatches_to_a_real_function(self):
        self.assertIn('data-action="loadActiveSessions"', _HTML)
        self.assertIn('async function loadActiveSessions(', _APP)

    def test_the_revoke_button_dispatches_to_a_real_function(self):
        self.assertIn('data-action="revokeUserSessions"', _APP)
        self.assertIn('async function revokeUserSessions(', _APP)

    def test_the_ids_the_renderer_writes_to_are_the_ids_the_page_declares(self):
        for el in ('sessions-result', 'sessions-count'):
            with self.subTest(el=el):
                self.assertIn(f"getElementById('{el}')", _APP)
                self.assertIn(f'id="{el}"', _HTML)


class TestItDoesNotOverpromise(unittest.TestCase):
    def test_revocation_is_described_as_per_user(self):
        """The server has no per-session admin revoke — POST /api/sessions/revoke
        takes a username and signs the account out everywhere. A per-row button
        labelled "Revoke" would read as "this session" and drop three browsers.
        The label has to say what actually happens."""
        m = re.search(r'async function loadActiveSessions\(.*?\n\}', _APP, re.S)
        self.assertIsNotNone(m)
        self.assertIn('Revoke user', m.group(0))

    def test_the_server_really_has_no_per_session_admin_revoke(self):
        """The positive control for the test above: if a per-session admin
        revoke is ever added, that test's premise is stale and the button
        should become per-row. This fails when that happens."""
        self.assertNotRegex(
            _API, r"\('DELETE', '/api/sessions/[^']*\{")
        m = re.search(r'def handle_revoke_sessions\(.*?\n(?=def |class )', _API, re.S)
        self.assertIn("body.get('username'", m.group(0))

    def test_a_numeric_username_survives_the_dispatcher(self):
        """`data-arg` is coerced with `!isNaN(v) ? Number(v) : v`, so a username
        of "1042" arrives as an integer and would be sent as a JSON number."""
        m = re.search(r'async function revokeUserSessions\(.*?\n\}', _APP, re.S)
        self.assertIn('String(username)', m.group(0))

    def test_the_current_session_is_not_offered_a_revoke(self):
        m = re.search(r'async function loadActiveSessions\(.*?\n\}', _APP, re.S)
        self.assertIn('s.current', m.group(0))


class TestItObeysThePageRules(unittest.TestCase):
    def test_the_table_scrolls_rather_than_growing(self):
        """CLAUDE.md's box-overflow rule: a variable row count caps and scrolls.
        A fleet with 200 logins would otherwise push the whole pane off-screen."""
        m = re.search(r'async function loadActiveSessions\(.*?\n\}', _APP, re.S)
        self.assertIn('scrollable-table-wrap audit-scroll', m.group(0))

    def test_no_inline_style_or_handler_reaches_the_dom(self):
        """CSP is `script-src 'self'; style-src 'self'` — an inline style= or
        on*= in an innerHTML string silently does nothing."""
        m = re.search(r'async function loadActiveSessions\(.*?\n\}', _APP, re.S)
        body = m.group(0)
        self.assertNotRegex(body, r'\sstyle="')
        self.assertNotRegex(body, r'\son(click|change|input)=')

    def test_every_rendered_value_is_escaped(self):
        """user/role/source/ip come from a token store an operator does not
        fully control (the UA and IP are attacker-influenceable on login)."""
        m = re.search(r'async function loadActiveSessions\(.*?\n\}', _APP, re.S)
        body = m.group(0)
        for field in ('s.user', 's.role', 's.source', 's.ip'):
            with self.subTest(field=field):
                self.assertRegex(body, r'escHtml\(%s' % re.escape(field))

    def test_the_panel_points_at_its_documentation(self):
        i = _HTML.find('id="sessions-result"')
        self.assertGreater(i, 0)
        self.assertIn('docs/access-review.md', _HTML[max(0, i - 1500):i])


class TestTheOperatorProcedureDocsExist(unittest.TestCase):
    """compliance.md names three operator responsibilities that are procedures,
    not settings. "You own this" is not guidance; each now says which surface
    answers which part."""

    DOCS = ('access-review.md', 'incident-response.md', 'data-retention.md')

    def test_each_doc_exists(self):
        for d in self.DOCS:
            with self.subTest(doc=d):
                self.assertTrue((_ROOT / 'docs' / d).is_file())

    def test_compliance_links_to_each(self):
        src = (_ROOT / 'docs' / 'compliance.md').read_text()
        for d in self.DOCS:
            with self.subTest(doc=d):
                self.assertIn(f']({d})', src)

    def test_the_docs_index_lists_each(self):
        src = (_ROOT / 'docs' / 'README.md').read_text()
        for d in self.DOCS:
            with self.subTest(doc=d):
                self.assertIn(f']({d})', src)

    def test_no_dangling_relative_links(self):
        for d in self.DOCS:
            src = (_ROOT / 'docs' / d).read_text()
            for target in re.findall(r'\]\(([A-Za-z0-9_.-]+\.md)\)', src):
                with self.subTest(doc=d, target=target):
                    self.assertTrue((_ROOT / 'docs' / target).is_file())


class TestTheJsParses(unittest.TestCase):
    def test_node_check(self):
        r = subprocess.run(
            ['node', '--check', str(_ROOT / 'server/html/static/js/app.js')],
            capture_output=True, text=True)
        if r.returncode != 0 and 'not found' in (r.stderr or '').lower():
            self.skipTest('node unavailable')
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
