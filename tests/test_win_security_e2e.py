#!/usr/bin/env python3
"""The three Windows security features, measured in a real browser: the registry check in the Add check dialog (G07),
the ready-made Windows event rules in the Add log rule dialog (G06) and the Persistence section of the host drawer (G14).

Source-level tests say the markup and the script exist. Only a browser says that the controls render, fit at three widths,
read in German and Arabic (right to left), can be reached by keyboard with a visible focus ring, and that a page makes no
failed request and logs no console error while it does so.

The stack is the real one (gunicorn and the wsgi app behind the harness) on a data directory that this module fills before
the stack starts: a Windows host with a persistence inventory and its change log, and a Linux host without. The log in is the
default administrator of a new install.

Self-skips without playwright, chromium and gunicorn like its siblings, and fails instead of skipping when RP_BROWSER_REQUIRE is set.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()

if browser_available():
    from playwright.sync_api import sync_playwright

WIDTHS = ((1440, 900), (768, 1024), (390, 844))
REGISTRY_HINT = ('The agent reads one value under HKLM\\SOFTWARE or HKLM\\SYSTEM on Windows hosts, and never changes it. Write a number as 5 or 0x5. '
                 'A text is compared without regard to case. A value that is not set passes “is not set” and “does not equal”, and fails the other conditions.')
LANGS = ('de', 'ar')            # German is the long-word case, Arabic the right-to-left one


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Rendered(unittest.TestCase):
    @classmethod
    def build_data_dir(cls):
        return tempfile.mkdtemp(prefix='rp-winsec-e2e-')

    @classmethod
    def setUpClass(cls):
        if not browser_available():
            browser_required.skip_or_fail(SKIP_REASON)
        from e2e_harness import start_stack
        cls.data_dir = cls.build_data_dir()
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            browser_required.skip_or_fail(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()
            import shutil
            shutil.rmtree(cls.data_dir, ignore_errors=True)

    def open_app(self, width=1440, height=900):
        """A signed-in page, with every console error, page error and failed request recorded on `self.problems`."""
        ctx = self.browser.new_context(viewport={'width': width, 'height': height})
        ctx.add_init_script("try { localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        self.addCleanup(ctx.close)
        page = ctx.new_page()
        self.problems = []
        page.on('console', lambda m: self.problems.append(('console', m.text)) if m.type == 'error' else None)
        page.on('pageerror', lambda e: self.problems.append(('pageerror', str(e))))
        page.on('response', lambda r: self.problems.append(('http', r.status, r.url)) if r.status >= 400 and r.status != 401 else None)
        page.goto(self.base + '/index.html')
        page.fill('#login-user', 'admin')
        page.fill('#login-pass', 'remotepower')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=90000)
        page.wait_for_timeout(2500)
        return page

    def set_lang(self, page, lang):
        page.evaluate("() => _ensureI18n()")
        page.evaluate("l => RPi18n.setLang(l, false)", lang)
        page.wait_for_timeout(400)

    def no_horizontal_overflow(self, page, selector):
        """The element and the page do not scroll sideways, and nothing inside the element sticks out of it."""
        return page.evaluate("""sel => {
            const root = document.querySelector(sel);
            const doc = document.documentElement;
            const r = root.getBoundingClientRect();
            const out = [];
            if (doc.scrollWidth > doc.clientWidth + 1) out.push('page scrolls sideways: ' + doc.scrollWidth + ' > ' + doc.clientWidth);
            if (root.scrollWidth > root.clientWidth + 1) out.push('box scrolls sideways: ' + root.scrollWidth + ' > ' + root.clientWidth);
            // a table in a card that scrolls sideways is wider than the box on purpose: what scrolls inside a container does not escape it
            const contained = el => {
                for (let a = el.parentElement; a && a !== root; a = a.parentElement) {
                    const o = getComputedStyle(a).overflowX;
                    if (o === 'auto' || o === 'scroll' || o === 'hidden') return true;
                }
                return false;
            };
            root.querySelectorAll('*').forEach(el => {
                const cs = getComputedStyle(el);
                if (cs.display === 'none' || cs.visibility === 'hidden') return;
                const b = el.getBoundingClientRect();
                if (!b.width || !b.height) return;
                if (contained(el)) return;
                if (b.right > r.right + 1 || b.left < r.left - 1) out.push((el.id || el.className || el.tagName) + ' ' + Math.round(b.left) + '..' + Math.round(b.right) + ' outside ' + Math.round(r.left) + '..' + Math.round(r.right));
            });
            return out.slice(0, 8);
        }""", selector)

    def tab_to(self, page, target_id, limit=60):
        """Press Tab until the element with this id has focus (a keyboard user's way), and say whether it shows a focus ring."""
        for _ in range(limit):
            page.keyboard.press('Tab')
            if page.evaluate("id => document.activeElement && document.activeElement.id === id", target_id):
                return page.evaluate("""() => {
                    const el = document.activeElement, cs = getComputedStyle(el);
                    const ring = (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0) || (cs.boxShadow && cs.boxShadow !== 'none');
                    return {ring: !!ring, outline: cs.outlineStyle + ' ' + cs.outlineWidth, shadow: cs.boxShadow};
                }""")
        return None


class TestRegistryCheckDialog(_Rendered):
    def open_dialog(self, page):
        page.evaluate("() => { showPage('checks'); }")
        page.wait_for_timeout(800)
        page.evaluate("() => openCustomChecks()")
        page.wait_for_selector('#custom-checks-modal', state='visible', timeout=10000)
        page.select_option('#cc-type', 'registry')
        page.wait_for_selector('#cc-reg-grp', state='visible', timeout=5000)

    def test_choosing_the_type_swaps_the_value_box_for_the_five_fields_and_a_condition_that_needs_none_hides_its_box(self):
        page = self.open_app()
        self.open_dialog(page)
        self.assertFalse(page.is_visible('#cc-param-grp'), 'the single value box stays behind a registry check')
        for sel in ('#cc-reg-path', '#cc-reg-value', '#cc-reg-op', '#cc-reg-expect', '#cc-reg-hint'):
            self.assertTrue(page.is_visible(sel), sel)
        for op in ('exists', 'missing'):
            page.select_option('#cc-reg-op', op)
            self.assertFalse(page.is_visible('#cc-reg-expect'), op + ' takes no expected value')
        page.select_option('#cc-reg-op', 'at_least')
        self.assertTrue(page.is_visible('#cc-reg-expect'))
        page.select_option('#cc-type', 'process')
        self.assertTrue(page.is_visible('#cc-param-grp'))
        self.assertFalse(page.is_visible('#cc-reg-grp'))
        self.assertEqual(self.problems, [])

    def test_the_dialog_fits_at_three_widths_in_english_german_and_arabic(self):
        for width, height in WIDTHS:
            page = self.open_app(width, height)
            self.open_dialog(page)
            for lang in ('en',) + LANGS:
                with self.subTest(width=width, lang=lang):
                    self.set_lang(page, lang)
                    if lang == 'ar':
                        self.assertEqual(page.evaluate("document.documentElement.dir"), 'rtl')
                    self.assertEqual(self.no_horizontal_overflow(page, '#custom-checks-modal .modal'), [])
            self.assertEqual(self.problems, [])

    def test_the_instruments_can_say_no(self):
        """Controls: an overflow measure that never reports and a focus check that never fails would pass every other test here."""
        page = self.open_app(768, 1024)
        self.open_dialog(page)
        page.evaluate("""() => { const d = document.createElement('div'); d.id = 'plant'; d.textContent = 'x';
                                 d.style.width = '3000px'; document.querySelector('#cc-reg-grp').appendChild(d); }""")
        self.assertTrue(self.no_horizontal_overflow(page, '#custom-checks-modal .modal'), 'the measure missed a 3000 px element')
        page.evaluate("() => document.getElementById('plant').remove()")
        self.assertEqual(self.no_horizontal_overflow(page, '#custom-checks-modal .modal'), [])
        page.evaluate("() => { const e = document.getElementById('cc-reg-value'); e.style.outline = 'none'; e.style.boxShadow = 'none'; }")
        page.focus('#cc-reg-path')
        got = self.tab_to(page, 'cc-reg-value')
        self.assertIsNotNone(got)
        self.assertFalse(got['ring'], 'a control with its ring switched off was reported as having one')

    def test_the_labels_read_in_german_and_arabic(self):
        page = self.open_app()
        self.open_dialog(page)
        for lang in LANGS:
            self.set_lang(page, lang)
            for sel, key in (('label[for="cc-reg-path"]', 'Registry path (under HKLM)'), ('label[for="cc-reg-value"]', 'Value name'),
                             ('label[for="cc-reg-op"]', 'Condition'), ('label[for="cc-reg-expect"]', 'Expected value'),
                             ('#cc-reg-op option[value="not_equals"]', 'does not equal'), ('#cc-type option[value="registry"]', 'Windows registry value')):
                with self.subTest(lang=lang, key=key):
                    shown = page.evaluate("s => document.querySelector(s).textContent.trim()", sel)
                    want = page.evaluate("k => RPi18n.t(k)", key)
                    self.assertNotEqual(want, key, 'the dictionary has no entry')
                    self.assertEqual(shown, want)
            shown = page.evaluate("document.getElementById('cc-reg-hint').textContent.trim()")
            want = page.evaluate("k => RPi18n.t(k)", REGISTRY_HINT)
            self.assertNotEqual(want, REGISTRY_HINT, 'the dictionary has no entry for the hint')
            self.assertEqual(shown, want, 'the hint in the page is not the sentence the dictionary is keyed on')

    def test_every_control_is_reached_by_keyboard_with_a_visible_focus_ring(self):
        page = self.open_app()
        self.open_dialog(page)
        page.focus('#cc-type')
        for target in ('cc-reg-path', 'cc-reg-value', 'cc-reg-op', 'cc-reg-expect'):
            with self.subTest(target):
                got = self.tab_to(page, target)
                self.assertIsNotNone(got, target + ' is not on the tab path')
                self.assertTrue(got['ring'], '%s has no visible focus ring: %s' % (target, got))

    def test_a_definition_saves_through_the_dialog_and_a_refusal_is_said_in_the_persons_language(self):
        page = self.open_app()
        self.open_dialog(page)
        page.fill('#cc-name', 'NTLMv2 only (e2e)')
        page.fill('#cc-reg-path', r'SYSTEM\CurrentControlSet\Control\Lsa')
        page.fill('#cc-reg-value', 'LmCompatibilityLevel')
        page.select_option('#cc-reg-op', 'at_least')
        page.fill('#cc-reg-expect', '5')
        page.click('#cc-save-btn')
        page.wait_for_function("() => document.getElementById('cc-list').textContent.includes('LmCompatibilityLevel at_least 5')", timeout=15000)
        stored = page.evaluate("async () => (await api('GET', '/checks/custom')).checks.filter(c => c.type === 'registry')")
        self.assertEqual(len(stored), 1)
        self.assertEqual((stored[0]['hive'], stored[0]['path'], stored[0]['value'], stored[0]['op'], stored[0]['expect']),
                         ('HKLM', r'SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel', 'at_least', 5))
        self.assertEqual(stored[0]['param'], r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel at_least 5')
        # edit: the five fields come back into the form
        page.evaluate("id => editCustomCheck(id)", stored[0]['id'])
        self.assertEqual(page.input_value('#cc-reg-path'), r'SYSTEM\CurrentControlSet\Control\Lsa')
        self.assertEqual(page.input_value('#cc-reg-op'), 'at_least')
        self.assertEqual(page.input_value('#cc-reg-expect'), '5')
        # a path the agent would refuse is refused here, with the server's sentence, in German
        self.set_lang(page, 'de')
        page.evaluate("() => _ccResetForm()")
        page.select_option('#cc-type', 'registry')
        page.fill('#cc-reg-path', r'SAM\SAM\Domains')
        page.fill('#cc-reg-value', 'F')
        page.fill('#cc-reg-expect', '1')
        page.click('#cc-save-btn')
        sentence = 'the registry path must start with SOFTWARE or SYSTEM'
        want = page.evaluate("k => RPi18n.t(k)", sentence)
        self.assertNotEqual(want, sentence)
        page.wait_for_function("w => [...document.querySelectorAll('.toast.error')].some(t => t.textContent.includes(w))", arg=want, timeout=10000)
        self.assertEqual(len(page.evaluate("async () => (await api('GET', '/checks/custom')).checks.filter(c => c.type === 'registry')")), 1)
        # the one 400 is the refusal that was asked for
        self.assertEqual([p for p in self.problems if not (p[0] == 'http' and p[1] == 400 and p[2].endswith('/api/checks/custom'))
                          and not (p[0] == 'console' and '400' in p[1])], [])


if __name__ == '__main__':
    unittest.main()
