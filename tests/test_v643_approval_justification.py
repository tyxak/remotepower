#!/usr/bin/env python3
"""A parked four-eyes change must be able to carry a reason.

v6.4.2 built this feature in three parts and connected two of them. The
confirmation record stores `reason` and `ticket_ref`; `_park_for_approval`
accepts them; `_confirmationWhy` in app.js renders them, and correctly prints
an amber "no reason given" when they are absent. What was missing was the
supply: `_approval_context(body)` — the helper that extracts them from a
request — had ZERO call sites anywhere in the repo, and no dialog offered a
field. So every human-originated parked change reached its approver reading
"no reason given", and that text was accurate.

features.md sells this as the control an auditor tests for CC8.1 / A.8.32,
which made it a docs-truth defect on a compliance surface rather than a missing
nicety. It was live in production.

The tests below pin both ends, because either alone leaves the feature dead:
the server must extract, and the dialogs must offer.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_HTML = _ROOT / 'server' / 'html' / 'index.html'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643appr-'))

_spec = importlib.util.spec_from_file_location('api_v643_appr', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

# The kinds that are parked by default (api._APPROVAL_GATED_KINDS).
GATED = ('reboot', 'shutdown', 'update', 'uninstall', 'upgrade', 'container')


class TestTheExtractorIsActuallyCalled(unittest.TestCase):
    def test_approval_context_has_call_sites(self):
        """The whole defect in one assertion. It is defined, documented,
        exercised by nothing."""
        hits = 0
        for p in list(_CGI.glob('*.py')):
            src = re.sub(r'#[^\n]*', '', p.read_text())      # code, not comments
            hits += len(re.findall(r'(?<!def )_approval_context\(', src))
        self.assertGreaterEqual(
            hits, len(GATED) - 1,
            f'_approval_context is called {hits} time(s). Every approval-gated '
            f'kind {GATED} should thread it, or a parked change of that kind '
            'reaches its approver with no justification and the Confirmations '
            'table shows "no reason given" forever.')

    def test_it_reads_both_spellings(self):
        self.assertEqual(api._approval_context({'reason': 'a', 'ticket_ref': 'B-1'}),
                         ('a', 'B-1'))
        self.assertEqual(api._approval_context({'change_reason': 'a', 'ticket': 'B-1'}),
                         ('a', 'B-1'))

    def test_a_body_with_neither_is_unchanged_behaviour(self):
        """Optional on every caller: a request that offers nothing must behave
        exactly as it did before this existed."""
        self.assertEqual(api._approval_context({}), (None, None))
        self.assertEqual(api._approval_context(None), (None, None))
        self.assertEqual(api._approval_context([1, 2]), (None, None))

    def test_park_for_approval_stores_what_it_is_given(self):
        self.assertIn('reason', api._park_for_approval.__code__.co_varnames)
        self.assertIn('ticket_ref', api._park_for_approval.__code__.co_varnames)


class TestTheDialogsOfferAField(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _HTML.read_text()
        cls.js = re.sub(r'//[^\n]*', '', (_JS / 'app.js').read_text())

    def test_both_confirm_dialogs_have_the_pair(self):
        for prefix in ('reboot', 'shutdown'):
            with self.subTest(prefix=prefix):
                self.assertIn(f'id="{prefix}-approval-grp"', self.html)
                self.assertIn(f'id="{prefix}-reason"', self.html)
                self.assertIn(f'id="{prefix}-ticket"', self.html)

    def test_the_confirm_handlers_send_them(self):
        for fn in ('confirmReboot', 'confirmShutdown'):
            with self.subTest(fn=fn):
                i = self.js.index(f'async function {fn}(')
                body = self.js[i:i + 700]
                self.assertIn('_approvalFields(', body,
                              f'{fn} does not read the justification fields, so '
                              'whatever the operator types is discarded')

    def test_the_fields_are_hidden_unless_four_eyes_is_on(self):
        """Asking every operator "why?" for an action they can take
        unilaterally is noise, and noise is how a control gets ignored."""
        self.assertIn('_changeApprovalOn', self.js)
        i = self.js.index('function _prepApprovalFields(')
        body = self.js[i:i + 500]
        self.assertIn("classList.toggle('d-none', !_changeApprovalOn)", body)

    def test_the_fields_are_cleared_between_opens(self):
        """Otherwise one change's justification silently rides along on the
        next one — which is worse than no reason at all, because it is a
        plausible WRONG reason in an audit record."""
        i = self.js.index('function _prepApprovalFields(')
        body = self.js[i:i + 500]
        self.assertEqual(body.count("value = ''"), 2)

    def test_prep_runs_from_openmodal_not_from_each_opener(self):
        """reboot and shutdown are opened from four places (drawer x2, command
        palette x2). Hooking each opener means the fifth one silently reuses
        the previous reason."""
        i = self.js.index('function openModal(')
        body = self.js[i:i + 900]
        self.assertIn('_prepApprovalFields(', body)

    def test_the_server_tells_the_client_whether_to_show_them(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("'change_approval_enabled': bool(cfg.get('change_approval_enabled'))",
                      src, 'the /api/home config echo no longer carries the flag, '
                           'so the fields can never appear')


class TestTheRendererStillCallsOutAnAbsentReason(unittest.TestCase):
    """This half already worked and is the reason the gap was invisible: the
    UI honestly reported that nothing had been recorded, every time."""

    def test_no_reason_given_is_still_rendered(self):
        js = (_JS / 'app.js').read_text()
        i = js.index('function _confirmationWhy(')
        self.assertIn('no reason given', js[i:i + 900])


if __name__ == '__main__':
    unittest.main()
