#!/usr/bin/env python3
"""Logging out must not leave the previous user's fleet data in the page.

`doLogout` cleared the ETag cache — added in v6.1.2 with the note that it "holds
real fleet data keyed only by URL", so a stale hit would hand the next user the
previous one's counts. The reasoning was right and the coverage was one cache.

A sweep counted **70 module-level caches across 20 files** holding exactly that
kind of data — alerts, audit-log rows, CMDB assets, scoped credentials, device
rows, roles, API keys — and `doLogout` reset **none** of them. On a shared
workstation the next person to log in gets pages that render from the previous
user's cache before their own fetch lands.

The fix is a reload rather than a list. Enumerating 70 names works today and
rots at the 71st, and they are script-scoped `let` bindings that nothing outside
their own file can reset anyway. A reload lands on the same login page and takes
every one of them, including the ones added next year.

This file therefore checks the PROPERTY (nothing survives) rather than a list —
and checks the loop guard, because a logout that reloads into a logout is worse
than the bug.
"""
import pathlib
import re
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402


def _logout():
    return srcpin.js_function((_JS / 'app.js').read_text(), 'doLogout')


class TestLogoutDropsEverything(unittest.TestCase):

    def test_it_reloads(self):
        self.assertIn('location.reload', _logout(),
                      'without this, 70 page caches survive into the next '
                      'session')

    def test_the_reload_cannot_loop(self):
        body = _logout()
        self.assertIn('__rpLoggingOut', body,
                      'a 401 on the login page would reload into a logout')
        self.assertRegex(body, r'if\s*\(!window\.__rpLoggingOut\)')

    def test_the_token_is_gone_before_the_reload(self):
        """Order matters: reloading with the token still in storage would log
        straight back in as the previous user."""
        body = _logout()
        self.assertLess(body.index("removeItem('rp_token')"),
                        body.index('location.reload'))

    def test_the_earlier_clears_are_still_there(self):
        """The reload makes them redundant, not wrong — and a browser that
        blocks the reload still gets them."""
        body = _logout()
        for token in ('_clearEtagCache', "removeItem('rp_me')", 'clearInterval'):
            self.assertIn(token, body, token)


class TestThePopulationIsWhatMotivatedIt(unittest.TestCase):
    """If the page caches ever go away, this file's reasoning goes with them —
    so the count is asserted, loosely, rather than described."""

    def test_there_really_are_many_page_caches(self):
        n = 0
        for f in sorted(_JS.glob('app*.js')):
            n += len(re.findall(
                r'^(?:let|var)\s+_\w*(?:Cache|Rows|Resp|Data|List)\w*\s*=\s*'
                r'(?:\[\]|\{\}|null|new Map\(\))', f.read_text(), re.M))
        self.assertGreater(n, 30,
                           f'only {n} page caches found — if these are gone, '
                           f'the reload may no longer be needed')


if __name__ == '__main__':
    unittest.main()
