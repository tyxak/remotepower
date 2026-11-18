#!/usr/bin/env python3
"""The install link carries a token, so the web server does not write it to its access log.

`wget -qO- "https://server/install?t=<token>" | sudo sh` puts the enrolment token in the query string. A token made for many hosts is
still good after the first host has used it, and nginx's default access log prints the request line whole, query string included, so
the token sat in the log for as long as the token lived and for as long as the log was kept. The two locations that take the link
(`/install` for Linux and macOS, `/install.ps1` for Windows) do not log now, in both shipped snippets (bare metal and Docker).

The population is derived from the snippets, not listed: every location that forwards its query string to the app (`$is_args$args` or
`$args` in its body) is one the token can travel through. nginx matches a location on the path alone, so a request for `/install?t=x`
is answered by the exact-match location for `/install`, which is checked with the model of nginx's rules that
test_v703_nginx_location_precedence already holds. No nginx binary is needed.
"""
import re
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_HERE))
import srcpin  # noqa: E402
import test_v703_nginx_location_precedence as prec  # noqa: E402  (its model of how nginx picks a location, not its tests)

CONFIGS = prec._CONFIGS
INSTALL_ROUTES = {'/install': '/api/agent/install', '/install.ps1': '/api/agent/win/install'}


def blocks(text):
    """[(kind, pattern, body)] for every `location` of a snippet; comments are removed from the body, nested blocks stay."""
    out = []
    for m in prec._LOC.finditer(text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = re.sub(r'(?m)#.*$', '', text[m.end():i])
        kind = 'exact' if m.group(1) else 'stop_prefix' if m.group(2) else 'regex' if m.group(3) else 'prefix'
        out.append((kind, m.group(4), body))
    return out


def forwarding(text):
    """The locations that hand the query string to the app."""
    return [b for b in blocks(text) if '$args' in b[2]]


def logs_off(body):
    return bool(re.search(r'(?m)^\s*access_log\s+off\s*;', body))


class TestTheLocationsThatTakeTheLink(unittest.TestCase):

    def test_the_locations_that_forward_the_query_string_are_the_two_install_routes(self):
        # the control as well as the rule: if the derivation saw nothing, the next test would pass over nothing
        for name, path in CONFIGS.items():
            with self.subTest(config=name):
                found = forwarding(path.read_text())
                self.assertEqual({(k, p) for k, p, _ in found}, {('exact', r) for r in INSTALL_ROUTES}, 'a location forwards the query string that this test does not know')
                for _kind, pattern, body in found:
                    target = re.search(r'proxy_pass\s+http://127\.0\.0\.1:8090(\S+?)\$is_args\$args;', body)
                    self.assertTrue(target, pattern)
                    self.assertEqual(target.group(1), INSTALL_ROUTES[pattern])

    def test_each_of_them_has_the_access_log_off(self):
        for name, path in CONFIGS.items():
            with self.subTest(config=name):
                for _kind, pattern, body in forwarding(path.read_text()):
                    self.assertTrue(logs_off(body), '%s: the location for %s writes the link, token included, to the access log' % (name, pattern))

    def test_a_request_with_a_token_is_answered_by_one_of_them(self):
        # nginx matches the path, never the query string: the request line `GET /install?t=x` is the location for `/install`
        for name, path in CONFIGS.items():
            text = path.read_text()
            locations = prec.parse_locations(text)
            for uri in INSTALL_ROUTES:
                with self.subTest(config=name, uri=uri):
                    won = prec.resolve(locations, uri)
                    self.assertEqual(won, ('exact', uri), 'another location answers %s: %s' % (uri, won))
                    body = next(b for k, p, b in blocks(text) if (k, p) == won)
                    self.assertTrue(logs_off(body))

    def test_the_other_locations_still_log_so_that_this_is_not_a_blanket_switch_off(self):
        # a location that does not take the link keeps the server's access log: the line is not in the server block either
        for name, path in CONFIGS.items():
            text = path.read_text()
            others = [b for b in blocks(text) if b not in forwarding(text)]
            self.assertGreater(len(others), 5, name)
            self.assertFalse([p for _k, p, body in others if logs_off(body)], '%s: a location other than the install routes stopped logging' % name)


class TestTheAppTakesTheTokenFromTheQueryString(unittest.TestCase):
    """The premise the snippets rest on, checked in the app: the two routes read `t` from the query string."""

    def test_both_installers_read_the_token_from_the_query(self):
        src = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        for renderer in ('_render_agent_install', '_render_win_install'):
            with self.subTest(renderer=renderer):
                body = srcpin.py_function(src, renderer)
                self.assertIn('QUERY_STRING', body)
                self.assertIn("qs.get('t')", body)
        # and each route's handler is the one that calls its renderer
        self.assertIn('_render_agent_install(', srcpin.py_function(src, 'handle_agent_install'))
        self.assertIn('_render_win_install(', srcpin.py_function(src, 'handle_win_install'))


class TestTheGuideSaysSo(unittest.TestCase):

    def section(self):
        text = (_ROOT / 'docs' / 'install.md').read_text()
        start = text.index('### One command for many hosts')
        return text[start:text.index('\n---\n', start)]

    def test_the_guide_names_the_copies_the_access_log_and_the_revoke(self):
        section = self.section()
        for needle in ('shell history', 'access log', 'access_log off', 'proxy', 'revoke the command'):
            self.assertIn(needle, section, 'the many-hosts section does not mention: ' + needle)
        # and both routes the snippets cover
        self.assertIn('/install.ps1?t=', section)
        self.assertIn('location = /install', section)


if __name__ == '__main__':
    unittest.main()
