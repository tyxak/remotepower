#!/usr/bin/env python3
"""The VPN dashboard widget, and the auth boundary it must not cross.

`/api/home` is `require_auth()` — EVERY role reaches it, including viewer, mcp
and finance. The VPN endpoints are `require_admin_or_auditor_auth()`. So
emitting VPN data into the home payload unconditionally would quietly widen VPN
read access to every authenticated role: a product decision nobody made, taken
by accident, in a widget.

The datum is therefore withheld for other roles, and only ever carries COUNTS —
never client names, public keys or endpoints. The dashboard question is "is
anyone connected", not "who".

The widget itself is the documented seven-place template, and CLAUDE.md is
explicit that the two registries must stay in lockstep and that a key must
match /[a-z]+/ (no digits, no underscores) or the guard's own regex silently
stops seeing it.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643vpn-'))

_spec = importlib.util.spec_from_file_location('api_v643_vpn', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        now = int(time.time())
        api.save(api.VPN_FILE, {'tunnels': [{
            'id': 't1', 'name': 'office',
            'clients': [
                {'name': 'laptop', 'last_handshake': now - 30},     # connected
                {'name': 'phone',  'last_handshake': now - 90000},  # stale
                {'name': 'spare',  'last_handshake': 0},            # never
            ]}]})
        api._invalidate_load_cache(api.VPN_FILE)
        self._orig = (api.verify_token, api.get_token_from_request)

    def tearDown(self):
        api.verify_token, api.get_token_from_request = self._orig

    def _as(self, role):
        api.verify_token = lambda *a, **k: ('u', role)
        api.get_token_from_request = lambda *a, **k: 'tok'

    def _widget(self, role):
        self._as(role)
        out = api._dashboard_extra_widgets({}, {}, int(time.time()), want={'vpn'})
        return out.get('vpn')


class TestTheAuthBoundaryHolds(_Base):
    def test_an_admin_gets_the_counts(self):
        w = self._widget('admin')
        self.assertIsNotNone(w, 'the widget datum is missing for an admin')
        self.assertEqual(w['connected'], 1)
        self.assertEqual(w['total'], 3)
        self.assertEqual(w['tunnels'], 1)

    def test_an_auditor_gets_it_too(self):
        """Auditor already has VPN read access, so withholding it here would be
        an inconsistency in the other direction."""
        self.assertIsNotNone(self._widget('auditor'))

    def test_a_viewer_does_not(self):
        self.assertIsNone(self._widget('viewer'),
                          'VPN data reached a role that cannot call the VPN '
                          'endpoints — /api/home is require_auth(), so this '
                          'widens VPN read access to everyone')

    def test_an_mcp_token_does_not(self):
        self.assertIsNone(self._widget('mcp'))

    def test_a_finance_role_does_not(self):
        self.assertIsNone(self._widget('finance'))

    def test_it_never_carries_names_or_endpoints(self):
        """Counts only. A dashboard needs "is anyone connected", and a client
        roster in the home payload is a different disclosure entirely."""
        w = self._widget('admin')
        blob = str(w)
        for leak in ('laptop', 'phone', 'spare', 'endpoint', 'public_key'):
            self.assertNotIn(leak, blob, f'{leak!r} leaked into /api/home')
        self.assertEqual(set(w), {'connected', 'total', 'tunnels'})


class TestItIsNotComputedWhenNotDisplayed(_Base):
    def test_the_want_gate_is_honoured(self):
        """Every server-backed widget is gated on the client's enabled-widget
        hint so a hidden widget costs nothing."""
        self._as('admin')
        out = api._dashboard_extra_widgets({}, {}, int(time.time()), want=set())
        self.assertNotIn('vpn', out)

    def test_want_none_means_all(self):
        self._as('admin')
        out = api._dashboard_extra_widgets({}, {}, int(time.time()), want=None)
        self.assertIn('vpn', out)


class TestTheSevenPlaceTemplate(unittest.TestCase):
    """Miss one and the widget ships dead — the renderer especially, which no
    guardrail covers."""

    def test_the_two_registries_are_in_lockstep(self):
        import re
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        # SCOPE TO THE DASH_WIDGETS BLOCK. My first version ran the key regex
        # over the whole file and matched 112 unrelated `key:` properties, so it
        # "found" a drift that did not exist and blamed the new widget. The
        # existing guardrail (test_v3140) extracts the block first; copying it
        # is the point — an independent re-implementation of a pin is just a
        # second thing to get wrong.
        m = re.search(r"DASH_WIDGETS = \[(.*?)\];", js, re.S)
        self.assertIsNotNone(m, 'DASH_WIDGETS block not found')
        keys = tuple(re.findall(r"key:\s*'([a-z]+)'", m.group(1)))
        self.assertIn('vpn', keys, 'missing from DASH_WIDGETS')
        self.assertIn('vpn', api.DASHBOARD_WIDGETS, 'missing from the server tuple')
        self.assertEqual(keys, api.DASHBOARD_WIDGETS,
                         'the registries drifted — a guardrail pins them equal')

    def test_the_key_matches_the_guards_own_regex(self):
        """/[a-z]+/ — a digit or underscore makes the lockstep guard silently
        stop seeing the key, which is worse than failing."""
        import re
        self.assertRegex('vpn', r'^[a-z]+$')
        self.assertTrue(re.fullmatch(r'[a-z]+', 'vpn'))

    def test_the_card_exists(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('data-widget="vpn"', html)
        self.assertIn('id="home-w-vpn-body"', html)

    def test_the_renderer_exists_and_targets_the_card(self):
        """The one place with no guardrail behind it. A widget with a registry
        entry, a card and no renderer is an empty box forever."""
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("_setWidget('home-w-vpn-body'", js)

    def test_the_label_is_translated(self):
        i18n = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js').read_text()
        self.assertIn("'VPN clients':", i18n)

    def test_the_empty_state_explains_itself(self):
        """A role that cannot see VPN data must not be shown "0 / 0" — that
        reads as "the VPN is down" rather than "you cannot see this"."""
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        i = js.index("_setWidget('home-w-vpn-body'")
        self.assertIn('admin or auditor', js[i:i + 1200])


if __name__ == '__main__':
    unittest.main()
