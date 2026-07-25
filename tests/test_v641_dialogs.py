"""v6.4.1: dialog behaviour and sizing.

Three changes, all of which regress silently if the wiring is lost:

  * Every dialog carries a × in its top-right corner. It is INJECTED by
    openModal rather than hand-added to the ~90 static overlays, so it cannot
    be forgotten on a new modal — but that also means nothing in the static
    HTML proves it exists, hence these tests.
  * A backdrop click no longer dismisses on desktop. Losing a half-filled form
    to a stray click beside the dialog is a real cost; Escape and the × remain.
    Touch/narrow viewports keep backdrop dismissal, where the dialog can fill
    the screen and the corner button is a smaller target.
  * One width scale. The CMDB, ticket and storage dialogs each carried their
    own `min(940px, 94vw)` while everything else sat at 680px, so two dialogs
    opened from the same page were visibly different widths.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
HTML = (ROOT / 'server' / 'html' / 'index.html').read_text()

import clientjs  # noqa: E402

JS = clientjs.client_js()


class TestCloseButtonInjection(unittest.TestCase):
    def test_injector_exists_and_runs_on_open(self):
        self.assertIn('function _ensureModalClose(', JS)
        opener = JS[JS.index('function openModal('):]
        self.assertIn('_ensureModalClose(el)', opener[:opener.index('function closeModal(')])

    def test_self_activating_modals_are_covered_too(self):
        # drift / AI / runbook add .active themselves and never call openModal;
        # they all go through _raiseModalZ, so the hook sits there as well.
        raise_fn = JS[JS.index('function _raiseModalZ('):]
        self.assertIn('_ensureModalClose(el)', raise_fn[:raise_fn.index('function openModal(')])

    def test_button_routes_through_closeModal(self):
        fn = JS[JS.index('function _ensureModalClose('):]
        fn = fn[:fn.index('\nfunction openModal(')]
        self.assertIn("closeModal(el.id)", fn)
        # Idempotent — reopening a modal must not stack up buttons.
        self.assertIn("querySelector(':scope > .modal-close')", fn)

    def test_no_inline_handler(self):
        # CSP: script-src 'self' with no unsafe-inline. An onclick attribute
        # here would silently never fire.
        fn = JS[JS.index('function _ensureModalClose('):]
        fn = fn[:fn.index('\nfunction openModal(')]
        self.assertNotIn('onclick', fn)
        self.assertIn('addEventListener', fn)

    def test_uses_svg_not_an_emoji_or_glyph(self):
        fn = JS[JS.index('function _ensureModalClose('):]
        fn = fn[:fn.index('\nfunction openModal(')]
        self.assertIn('createElementNS', fn)
        self.assertNotIn('×', fn)
        self.assertNotIn('✕', fn)

    def test_has_an_accessible_name(self):
        fn = JS[JS.index('function _ensureModalClose('):]
        fn = fn[:fn.index('\nfunction openModal(')]
        self.assertIn("aria-label", fn)

    def test_styled(self):
        self.assertIn('.modal-close {', CSS)
        block = CSS[CSS.index('.modal-close {'):]
        block = block[:block.index('}')]
        self.assertIn('position: absolute', block)
        # A long title must not run underneath the button.
        self.assertIn('.modal-title { padding-right:', CSS)


class TestBackdropDismissal(unittest.TestCase):
    def test_gate_exists(self):
        self.assertIn('function _backdropDismisses(', JS)

    def test_desktop_pointer_and_width_are_both_considered(self):
        fn = JS[JS.index('function _backdropDismisses('):]
        fn = fn[:fn.index('}', fn.index('return')) + 1]
        self.assertIn('max-width: 900px', fn)
        self.assertIn('pointer: coarse', fn)

    def test_both_backdrop_handlers_are_gated(self):
        # The generic overlay handler AND the ui-prompt one (which resolves a
        # promise) — missing either leaves an inconsistent dismissal rule.
        for anchor in ("if (e.target === el && _backdropDismisses()) closeModal(el.id);",
                       "e.target.id === 'ui-prompt-modal' && _backdropDismisses()"):
            self.assertIn(anchor, JS)

    def test_escape_still_closes(self):
        # Removing backdrop dismissal is only acceptable because Escape stays.
        self.assertIn("if (e.key === 'Escape')", JS)


class TestOneWidthScale(unittest.TestCase):
    def test_tokens_defined(self):
        for tok in ('--modal-w:', '--modal-w-wide:', '--modal-w-xwide:'):
            self.assertIn(tok, CSS)

    def test_tiers_use_the_tokens(self):
        self.assertIn('max-width: var(--modal-w);', CSS)
        self.assertIn('.modal-wide { max-width: var(--modal-w-wide); }', CSS)
        self.assertIn('.modal-xwide { max-width: var(--modal-w-xwide); }', CSS)

    def test_no_ad_hoc_940_overrides_remain(self):
        self.assertNotIn('max-width: min(940px, 94vw)', CSS)

    def test_wide_tier_matches_the_cmdb_reference(self):
        m = re.search(r'--modal-w-wide:\s*min\((\d+)px', CSS)
        self.assertTrue(m, 'wide tier is no longer a min(Npx, vw) value')
        self.assertEqual(m.group(1), '940')

    def test_per_modal_rules_reference_the_token_not_a_literal(self):
        for mid in ('#cmdb-asset-modal', '#ticket-detail-modal'):
            rule = CSS[CSS.index(mid + ' > .modal {'):]
            rule = rule[:rule.index('}')]
            self.assertIn('var(--modal-w-wide)', rule, mid)

    def test_storage_modal_keeps_its_width_via_the_shared_class(self):
        # Its bespoke override was removed — it must carry .modal-wide instead,
        # or it silently shrinks to the narrow default.
        row = [ln for ln in HTML.splitlines() if 'id="storage-maint-modal"' in ln][0]
        self.assertIn('modal modal-wide', row)


class TestControlsWidened(unittest.TestCase):
    """Short-labelled controls were cramped; the numeric alert-parameter inputs
    and bare toolbar selects were the worst."""

    def test_bare_selects_get_a_floor(self):
        self.assertIn('.input-auto { width: auto; min-width: 160px;', CSS)
        self.assertIn('.isl-79 { width:auto; min-width:160px }', CSS)

    def test_numeric_inputs_widened(self):
        self.assertIn('.isl-80 { width:150px }', CSS)
        self.assertIn('.isl-81 { width:130px }', CSS)

    def test_small_buttons_have_more_horizontal_padding(self):
        for cls, pad in (('.btn-sm', '5px 16px'), ('.btn-xs', '3px 13px')):
            self.assertIn(f'{cls} {{ padding: {pad};', CSS)

    def test_floor_matches_the_existing_select_sm_precedent(self):
        # One value for "a select's minimum width", not two.
        self.assertIn('min-width: 160px', CSS[CSS.index('.select-sm {'):][:400])


if __name__ == '__main__':
    unittest.main()
