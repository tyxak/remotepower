#!/usr/bin/env python3
"""Tenant administration had a server API and no way to reach it.

The multi-tenancy switches have been in Settings since v3.14.0, and the hint
beside them said, in as many words, that tenants and user assignment are
"managed via the API". Creating a tenant, renaming one, suspending one,
deleting one and assigning a user to one all existed as endpoints and had no
UI at all.

That is a distinct shape from the dead-signal class this release keeps finding.
Nothing here was broken and nothing was silently dropped — the feature simply
stopped one layer short, and the gap was documented rather than closed, which
is why it survived several releases. An enterprise feature an operator can
switch ON from the interface but cannot ADMINISTER from the interface is half
shipped, and the half that is missing is the half they need on the day they
onboard their second customer.

WHAT THIS PINS, and why each one:

* The section exists, is superadmin-gated, and starts hidden. A panel that
  renders for someone who cannot use it is worse than no panel: every button
  in it fails.
* The hidden state corresponds to a REAL server refusal. Hiding a control is
  never enforcement, so the test drives the handlers directly and requires a
  non-superadmin to be refused by the server — the UI gate and the API gate
  have to agree, or the panel is security theatre.
* Every control's `data-action` resolves to a function that exists. This is the
  failure mode where a button is wired to a name nobody defined: it dies at
  runtime in a branch nobody exercises, and JavaScript says nothing.
* The default tenant offers no destructive buttons, because the server refuses
  to rename, suspend or delete it. Offering a control whose only outcome is an
  error message is the "success toast on a refusal" class in advance.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-tenui-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(_ROOT / 'tests'))

from srcpin import js_function  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_tenui', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()

# The section markup, bounded by content rather than a character count.
_SEC = _HTML[_HTML.index('id="tenants-section"'):]
_SEC = _SEC[:_SEC.index('</div>\n\n          <!--')] if '</div>\n\n          <!--' in _SEC \
    else _SEC[:6000]


class TestTheSectionIsPresentAndGated(unittest.TestCase):

    def test_the_section_exists(self):
        self.assertIn('id="tenants-section"', _HTML)
        self.assertIn('<div class="section-title">Tenants</div>', _HTML)

    def test_it_starts_hidden(self):
        """It is revealed only after the superadmin-only list call succeeds."""
        m = re.search(r'<div class="([^"]*)" id="tenants-section"', _HTML)
        self.assertIsNotNone(m, 'section div not found in the expected shape')
        self.assertIn('hidden', m.group(1),
                      'the panel renders before the API confirms the caller is '
                      'a superadmin — every button in it would fail')

    def test_the_loader_hides_it_again_on_refusal(self):
        """api() RESOLVES on a 403 instead of throwing, so a `.catch` would
        never run and the panel would stay up for a refused caller. The loader
        has to detect the refusal on the BODY."""
        fn = js_function(_APP, '_loadTenants')
        self.assertIn("sec.classList.add('hidden')", fn)
        self.assertRegex(fn, r'if \(!r \|\| !r\.ok',
                         'refusal must be detected on the resolved body')

    def test_it_carries_a_doc_pointer(self):
        self.assertIn('docs/scaling.md', _SEC)


class TestEveryControlIsWired(unittest.TestCase):
    """A data-action naming a function nobody defined dies at runtime, in a
    branch nobody clicks, silently."""

    ACTIONS = ('createTenant', 'renameTenant', 'toggleTenantStatus',
               'deleteTenant', 'assignUserTenant')

    def test_the_actions_are_referenced_in_the_ui(self):
        for a in self.ACTIONS:
            self.assertTrue(
                f'data-action="{a}"' in _HTML or f'data-action="{a}"' in _APP,
                f'{a} is defined but no control invokes it')

    def test_each_action_has_a_function(self):
        for a in self.ACTIONS:
            self.assertRegex(
                _APP, rf'\basync function {a}\s*\(|\bfunction {a}\s*\(',
                f'data-action="{a}" resolves to nothing')

    def test_the_pickers_the_assign_action_reads_exist(self):
        for el in ('tenant-assign-user', 'tenant-assign-tenant'):
            self.assertIn(f'id="{el}"', _HTML, f'{el} is read by JS but absent')

    def test_the_list_container_exists(self):
        self.assertIn('id="tenants-list"', _HTML)

    def test_no_inline_handler_or_style_was_introduced(self):
        """Production serves `script-src 'self'` with no unsafe-inline, so an
        inline on*= or style= in this markup silently does nothing."""
        self.assertNotRegex(_SEC, r'\son[a-z]+\s*=')
        self.assertNotRegex(_SEC, r'\sstyle\s*=\s*"')

    def test_no_emoji_icon(self):
        """House rule: Lucide-style SVG, never an emoji."""
        self.assertNotRegex(_SEC, r'[\U0001F300-\U0001FAFF←-⇿☀-➿]')


class TestTheBuiltinTenantOffersNoDestructiveControls(unittest.TestCase):

    def test_the_renderer_branches_on_builtin(self):
        """The server refuses to rename, suspend or delete the default tenant.
        Rendering those buttons anyway produces a control whose only possible
        outcome is an error."""
        fn = js_function(_APP, '_loadTenants')
        self.assertIn('t.builtin', fn)
        i = fn.index('t.builtin')
        head = fn[i:i + 200]
        self.assertIn('built-in', head,
                      'builtin tenants must render a label, not action buttons')


class TestTheServerReallyRefusesNonSuperadmins(unittest.TestCase):
    """Hiding a panel is not enforcement. If the API were open, the feature
    would be reachable with curl regardless of what the UI shows."""

    HANDLERS = ('handle_tenants_list', 'handle_tenant_create',
                'handle_tenant_update', 'handle_tenant_delete',
                'handle_tenant_assign_user')

    def test_every_tenant_handler_requires_superadmin(self):
        import inspect
        for name in self.HANDLERS:
            fn = getattr(api, name, None)
            self.assertIsNotNone(fn, f'{name} does not exist')
            src = inspect.getsource(fn)
            self.assertIn(
                'require_superadmin_auth', src,
                f'{name} does not gate on require_superadmin_auth — a tenant '
                f'admin resolves to role=admin, so any weaker gate passes them')

    def test_a_non_superadmin_is_actually_refused(self):
        """Drives the real gate rather than reading it.

        Only verify_token is stubbed — stubbing require_superadmin_auth itself
        would happily pass a handler that has no gate at all.

        The fixture has to seed BOTH stores, through the storage layer. A
        tenant that is absent from TENANTS_FILE resolves to the default tenant,
        which would make this "tenant admin" a superadmin and the test would
        pass for the wrong reason; and a raw file write would land nowhere on
        the SQLite/Postgres backends, where a storage key is a table row.
        """
        saved = {n: getattr(api, n) for n in ('USERS_FILE', 'TENANTS_FILE',
                                              'CONFIG_FILE')}
        d = Path(tempfile.mkdtemp(prefix='rp-tenrefuse-'))
        real_vt = api.verify_token
        real_rctx_tenant = getattr(api._RCTX, 'apikey_tenant', None)
        try:
            for n in saved:
                setattr(api, n, d / f'{n.lower()}.json')
            api._RCTX.apikey_tenant = None
            api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
            api.save(api.TENANTS_FILE, {
                api.DEFAULT_TENANT: {'name': 'Default', 'builtin': True,
                                     'status': 'active'},
                'tn_other': {'name': 'Other', 'status': 'active'}})
            api.save(api.USERS_FILE, {
                'bob': {'role': 'admin', 'tenant_id': 'tn_other'}})
            api.verify_token = lambda *a, **k: ('bob', 'admin')

            # Control: the fixture must actually produce a NON-superadmin, or
            # the refusal below would be measuring nothing.
            self.assertFalse(api._caller_is_superadmin(),
                             'fixture failed to make bob a tenant-scoped admin')

            with self.assertRaises((SystemExit, api.HTTPError)) as cm:
                api.handle_tenants_list()
            status = getattr(cm.exception, 'status', None)
            if status is not None:
                self.assertEqual(status, 403, f'expected 403, got {status}')

            # And the positive direction: a superadmin CAN list. Without this,
            # a handler that refused everyone would pass the assertion above.
            api.save(api.USERS_FILE, {
                'root': {'role': 'admin', 'tenant_id': api.DEFAULT_TENANT}})
            api.verify_token = lambda *a, **k: ('root', 'admin')
            self.assertTrue(api._caller_is_superadmin())
            with self.assertRaises((SystemExit, api.HTTPError)) as cm2:
                api.handle_tenants_list()
            self.assertEqual(getattr(cm2.exception, 'status', None), 200,
                             'a superadmin must be able to list tenants')
        finally:
            api.verify_token = real_vt
            api._RCTX.apikey_tenant = real_rctx_tenant
            for n, v in saved.items():
                setattr(api, n, v)


if __name__ == '__main__':
    unittest.main()
