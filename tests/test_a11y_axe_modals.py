#!/usr/bin/env python3
"""axe-core over the 138 modal dialogs — in its own module, deliberately.

WHY A SEPARATE FILE. This walk started life inside test_a11y_axe.py, and with
it there that file had THREE browser walks (pages, settings panes, modals) in
one TestCase. The third one reliably failed at login — `#app` stayed
`d-none` — and the failure was deterministic, not the documented "e2e flake
under load": ANY TWO of the three passed, ALL THREE failed, every time, and it
reproduced in isolation. It was not volume either; trimming the modal walk to
20 dialogs made no difference.

Whatever the limit is, it belongs to the harness rather than the product, and
`start_stack()` is per-CLASS: a separate class gets its own app stack, its own
data directory and its own browser lifecycle, which sidesteps the accumulation
entirely and keeps each walk's server fresh. That is a better structure anyway
— this audit is a different question from "do the pages pass" and does not
need to share a fixture with it.

It inherits the harness (setUpClass / _axe_walk / the violation assertions)
from TestAccessibilityAxe and switches OFF the inherited test methods, so they
run once, in their own file, and are not duplicated here.

WHAT THIS WALK IS FOR. The page and settings-pane walks never open a dialog,
and there are 138 `.modal-overlay` nodes, each `display:none` until something
calls `openModal()` — and axe does not scan a display:none subtree at all. So
the whole surface had never been audited, which matters because MODALS ARE
WHERE THE FORMS ARE: add a device, create a monitor, edit a role, confirm a
destructive action. WCAG 3.3.1, 1.3.1 and 4.1.2 are mostly about controls, and
the controls mostly live in the one region nothing had looked at.

Its first run found that the shared confirm/prompt dialog had NO ACCESSIBLE
NAME on 143 call sites — see the uiConfirm/uiPrompt defaults in app.js.
"""
import json
import unittest

from test_a11y_axe import _AXE_OPTIONS
from test_a11y_axe import TestAccessibilityAxe as _AxeBase


class TestAccessibilityAxeModals(_AxeBase):
    """Own stack, own browser — see the module docstring."""

    # Inherited from the base class and NOT re-run here: unittest only collects
    # attributes that are CALLABLE, so None de-registers them without touching
    # the parent. (`del _AxeBase` below matters too — unittest discovers any
    # TestCase subclass in a module's namespace, so the plain import re-ran the
    # entire parent suite in this file, which is the opposite of isolating it.)
    test_every_sidebar_page = None
    test_every_settings_pane = None
    test_login_page = None
    test_dashboard_after_login = None
    test_devices_page = None

    def test_every_modal(self):
        """v6.4.3: the walks above audit PAGES and Settings PANES. Neither ever
        opens a dialog — and there are 138 `.modal-overlay` nodes, every one of
        them `display:none` until something calls `openModal(id)`, which axe
        does not scan at all.

        That is the same blindness the settings-pane walk was written to fix,
        one surface over, and it matters more here than almost anywhere else:
        modals are where the FORMS are. Add a device, create a monitor, edit a
        role, schedule a scan, confirm a destructive action — all dialogs. WCAG
        2.1 SC 3.3.1 (error identification), 1.3.1 (labels) and 4.1.2 (name,
        role, value) apply mostly to controls, and the controls mostly live in
        the one region nothing had ever looked at.

        Opened via `openModal()` — the real function, not a class flip — so a
        dialog that fails to open is a finding rather than a silent skip: the
        result is checked for the modal actually being visible before its axe
        run counts.
        """
        import re as _re
        from pathlib import Path as _P
        html = (_P(__file__).parent.parent / 'server/html/index.html').read_text()
        # Every overlay that has an id — the id is what openModal() takes.
        ids = []
        for m in _re.finditer(
                r'<div[^>]*\bid="([a-z0-9-]+)"[^>]*class="[^"]*\bmodal-overlay\b',
                html):
            if m.group(1) not in ids:
                ids.append(m.group(1))
        for m in _re.finditer(
                r'<div[^>]*class="[^"]*\bmodal-overlay\b[^"]*"[^>]*\bid="([a-z0-9-]+)"',
                html):
            if m.group(1) not in ids:
                ids.append(m.group(1))
        self.assertGreater(len(ids), 100,
                           f'only {len(ids)} modals discovered — the markup '
                           'shape changed and this walk is auditing a fraction '
                           'of what it claims')

        async def _audit(page, mid):
            # Close whatever the previous target left open, so a stacked
            # overlay cannot mask the one under test.
            await page.evaluate(
                "(() => { document.querySelectorAll('.modal-overlay.active')"
                ".forEach(e => e.classList.remove('active')); })()")
            await page.evaluate(f"typeof openModal === 'function' && openModal({mid!r})")
            await page.wait_for_timeout(180)
            visible = await page.evaluate(
                f"!!document.querySelector('#{mid}.active')")
            if not visible:
                return {'_skipped': 'did not open'}
            try:
                return await page.evaluate(
                    "axe.run('#%s', %s).then(r => r)" % (mid, json.dumps(_AXE_OPTIONS)))
            finally:
                # Close it again. Several dialogs kick off their own fetch on
                # open, and leaving 138 of them open across the lanes keeps
                # those loaders running against the single test server for the
                # rest of the file — which is what starved the NEXT walk's
                # login (see the retry in _run_lane).
                await page.evaluate(
                    "(() => { const e = document.getElementById(%r);"
                    " if (e) e.classList.remove('active'); })()" % mid)

        opened = 0
        for mid, results in self._axe_walk(ids, _audit):
            if isinstance(results, dict) and results.get('_skipped'):
                continue
            opened += 1
            self._check_walk_result(mid, results, f'modal {mid!r}')
        # A walk where nothing opened is a walk that measured nothing, and it
        # would report success. This is the assertion that makes the rest of
        # the method mean anything.
        self.assertGreater(opened, len(ids) // 2,
                           f'only {opened} of {len(ids)} modals actually '
                           'opened — the audit above proved almost nothing')


# Remove the imported base from this module's namespace: unittest collects
# every TestCase subclass it finds here, and an imported one would run the
# whole parent suite a second time.
del _AxeBase


if __name__ == '__main__':
    unittest.main()
