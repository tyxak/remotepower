"""7.4.0 — the Back button follows the pages.

Before this, showPage rewrote the single history entry (replaceState), so Back
left the app instead of going to the page before. A change of page now pushes an
entry. Refining the page you are on (a settings tab, a saved view, the device
drawer) and routing that comes from history (Back, Forward, a pasted hash, the
boot restore) still rewrite the current entry, so Back never unwinds those.

These tests EXECUTE `_syncPageHash` and `_routeBarePageHash` in V8 against a
fake history stack. The real browser is driven by test_v740_back_button_e2e.py.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from clientjs import client_js  # noqa: E402
from srcpin import js_function  # noqa: E402
from test_v642_app_core import _HAVE_V8, _ctx, _json  # noqa: E402

# A history stack with the semantics that matter: pushState drops the forward
# entries and appends, replaceState overwrites the current one, and moving does
# not run any app code (the test calls the hashchange handler by hand, as the
# browser would).
HISTORY = r"""
var __entries = [''], __at = 0;
Object.defineProperty(location, 'hash', {
  get: function () { return __entries[__at]; },
  set: function (v) { __entries[__at] = v; }, configurable: true });
var history = {
  pushState: function (s, t, h) { __entries = __entries.slice(0, __at + 1); __entries.push(h); __at++; },
  replaceState: function (s, t, h) { __entries[__at] = h; },
};
function __back() { if (__at > 0) __at--; }
function __forward() { if (__at < __entries.length - 1) __at++; }
"""


def _history_ctx(*extra_fns, extra=""):
    ctx = _ctx("_syncPageHash", *extra_fns, extra=HISTORY + extra)
    return ctx


def _entries(ctx):
    return ctx.eval("JSON.stringify(__entries)")


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestAChangeOfPagePushesAnEntry(unittest.TestCase):
    def test_clicking_through_pages_adds_one_entry_each(self):
        ctx = _history_ctx()
        ctx.eval("_syncPageHash('devices', 'home'); _syncPageHash('alerts', 'devices');")
        self.assertEqual(_entries(ctx), '["","#devices","#alerts"]')

    def test_the_same_page_again_adds_nothing(self):
        ctx = _history_ctx()
        ctx.eval("_syncPageHash('devices', 'home'); _syncPageHash('devices', 'devices');")
        self.assertEqual(_entries(ctx), '["","#devices"]')

    def test_the_first_landing_replaces_instead_of_pushing(self):
        """Home shown on a bare URL is the same page: the entry the app was
        opened on takes the hash, and Back from it leaves the app."""
        ctx = _history_ctx()
        ctx.eval("_syncPageHash('home', 'home');")
        self.assertEqual(_entries(ctx), '["#home"]')

    def test_routing_that_comes_from_history_rewrites_the_entry(self):
        ctx = _history_ctx()
        ctx.eval("_syncPageHash('devices', 'home'); location.hash = '#alerts/abc';"
                 "_syncPageHash('alerts', 'devices', { replace: true });")
        self.assertEqual(_entries(ctx), '["","#alerts"]', 'a deep link normalised itself into a new entry')

    def test_a_settings_tab_is_left_alone_and_arriving_there_pushes_the_root(self):
        ctx = _history_ctx()
        ctx.eval("_syncPageHash('settings', 'home');")
        self.assertEqual(_entries(ctx), '["","#settings"]')
        ctx.eval("location.hash = '#settings/notifs'; _syncPageHash('settings', 'settings');")
        self.assertEqual(_entries(ctx), '["","#settings/notifs"]', 'the tab hash was overwritten')


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestBackAndForwardWriteNothing(unittest.TestCase):
    def test_back_then_forward_walk_the_pages_and_add_no_entries(self):
        ctx = _history_ctx()
        ctx.eval("_syncPageHash('devices', 'home'); _syncPageHash('alerts', 'devices');"
                 "_syncPageHash('monitor', 'alerts');")
        self.assertEqual(_entries(ctx), '["","#devices","#alerts","#monitor"]')
        for want_hash, was, page in (('#alerts', 'monitor', 'alerts'), ('#devices', 'alerts', 'devices')):
            ctx.eval("__back();")
            self.assertEqual(ctx.eval("location.hash"), want_hash)
            ctx.eval(f"_syncPageHash('{page}', '{was}', {{ replace: true }});")   # what the router does
        ctx.eval("__forward(); _syncPageHash('alerts', 'devices', { replace: true });")
        self.assertEqual(_entries(ctx), '["","#devices","#alerts","#monitor"]',
                         'Back/Forward rewrote or truncated the history')
        self.assertEqual(ctx.eval("__at"), 2)

    def test_a_new_page_after_back_drops_the_forward_entries_like_any_site(self):
        ctx = _history_ctx()
        ctx.eval("_syncPageHash('devices', 'home'); _syncPageHash('alerts', 'devices'); __back();"
                 "_syncPageHash('monitor', 'devices');")
        self.assertEqual(_entries(ctx), '["","#devices","#monitor"]')


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestTheRouterRoutesFromHistory(unittest.TestCase):
    def _ctx(self, active="thermal"):
        pages = ("home", "thermal", "risk", "settings")
        kids = [{"tag": "div", "id": "page-" + p,
                 "cls": "page active" if p == active else "page"} for p in pages]
        ctx = _ctx("_routeBarePageHash", extra="""
          var calls = [], tabs = [];
          function showPage(n, b, o) { calls.push([n, o || null]); }
          function switchSettingsTab(t) { tabs.push(t); }
        """)
        ctx.eval("build(%s);" % _json({"tag": "div", "id": "app", "kids": kids}))
        return ctx

    def test_every_route_it_makes_replaces_the_entry(self):
        ctx = self._ctx()
        ctx.eval("location.hash = '#risk'; _routeBarePageHash();")
        self.assertEqual(ctx.eval("JSON.stringify(calls)"), '[["risk",{"replace":true}]]')

    def test_the_entry_the_app_was_opened_on_is_home(self):
        """Back to a bare URL has no hash to name a page."""
        ctx = self._ctx(active="thermal")
        ctx.eval("location.hash = ''; _routeBarePageHash();")
        self.assertEqual(ctx.eval("JSON.stringify(calls)"), '[["home",{"replace":true}]]')

    def test_a_bare_url_on_home_changes_nothing(self):
        ctx = self._ctx(active="home")
        ctx.eval("location.hash = ''; _routeBarePageHash();")
        self.assertEqual(ctx.eval("calls.length"), 0)


class TestEveryRouteFromHistoryReplaces(unittest.TestCase):
    """Source pins for the wiring the V8 tests above cannot reach: showPage and
    its callers need the whole app. The population is derived, and each member
    must contain a showPage call, so an emptied list cannot pass."""
    SRC = client_js()
    ROUTERS = ('_routeFromHashOnBoot', '_routeBarePageHash', '_applyInitialViewHash', '_openDeviceFromHash')

    def test_the_routers_that_follow_the_hash_pass_replace(self):
        for name in self.ROUTERS:
            body = js_function(self.SRC, name)
            calls = re.findall(r'showPage\([^;]*\);', body)
            self.assertTrue(calls, f'control: {name} has no showPage call to check')
            for c in calls:
                self.assertIn('replace: true', c, f'{name}: {c}')

    def test_the_alert_deep_link_handler_replaces(self):
        m = re.search(r"window\.addEventListener\('hashchange', \(\) => \{\n  const m = \(location\.hash \|\| ''\)"
                      r"\.match\(/\^#alerts.*?\n\}\);", self.SRC, re.S)
        self.assertIsNotNone(m, 'control: the alert deep-link handler was not found')
        self.assertIn("showPage('alerts'", m.group(0))
        self.assertIn('replace: true', m.group(0))

    def test_showpage_syncs_through_the_one_helper_and_hands_opts_on(self):
        body = js_function(self.SRC, 'showPage')
        self.assertIn('_syncPageHash(name, _wasPage, opts)', body)
        self.assertEqual(len(re.findall(r'(?<!function )showPage\(name, btn, opts\)', body)), 2,
                         'both re-entries (dirty-settings confirm, lazy module) must pass opts on')
        # the page that was showing is read BEFORE the active class is moved
        self.assertLess(body.index('const _wasPage'), body.index("classList.remove('active')"))

    def test_there_is_exactly_one_pushstate_in_the_client(self):
        """A second one is how history fills up with entries Back has to unwind:
        the reason showPage replaced for four years."""
        found = [m.start() for m in re.finditer(r'history\.pushState\(', self.SRC)]
        self.assertEqual(len(found), 1, 'history.pushState appears %d times' % len(found))
        self.assertIn('history.pushState', js_function(self.SRC, '_syncPageHash'))

    def test_a_called_off_navigation_puts_the_url_back(self):
        """Unsaved Settings + Back: the URL has already moved when the confirm
        opens, so Stay must put it back on the page that stayed."""
        body = js_function(self.SRC, 'showPage')
        self.assertIn('_visiblePageHash()', body)


if __name__ == '__main__':
    unittest.main()
