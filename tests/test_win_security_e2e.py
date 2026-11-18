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
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()

if browser_available():
    from playwright.sync_api import sync_playwright

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'

WIDTHS = ((1440, 900), (768, 1024), (390, 844))
REGISTRY_HINT = ('The agent reads one value under HKLM\\SOFTWARE or HKLM\\SYSTEM on Windows hosts, and never changes it. Write a number as 5 or 0x5. '
                 'A text is compared without regard to case. A value that is not set passes “is not set” and “does not equal”, and fails the other conditions.')
LANGS = ('de', 'ar')            # German is the long-word case, Arabic the right-to-left one


def seed_data_dir(data_dir, hosts, stores):
    """Hosts and stores written through the storage layer in a subprocess (the way the harness clears the first-login flag), so it holds on every backend.

    `hosts` maps a host id to its fields (`token` is the plain token the host's heartbeat will send); `stores` maps the name of an api.py storage attribute
    to the value saved in it. The default administrator is created by the same import."""
    spec = {'hosts': hosts, 'stores': stores}
    code = ('import sys, json, time\n'
            'sys.path.insert(0, sys.argv[1])\n'
            'import api\n'
            'spec = json.loads(sys.argv[2])\n'
            'now = int(time.time())\n'
            'devs = {}\n'
            'for did, d in spec["hosts"].items():\n'
            '    row = {"name": did, "hostname": did, "last_seen": now, "enrolled": now - 86400 * 30, "tags": [], "group": "", "sysinfo": {},\n'
            '           "agentless": False, "ip": "10.0.0.5", "version": "8.0.1", "monitored": True}\n'
            '    row.update(d)\n'
            '    devs[did] = row\n'
            'api.save(api.DEVICES_FILE, devs)\n'
            'for attr, value in spec["stores"].items():\n'
            '    api.save(getattr(api, attr), value)\n')
    done = subprocess.run([sys.executable, '-c', code, str(_CGI), json.dumps(spec)], env=dict(os.environ, RP_DATA_DIR=str(data_dir)),
                          capture_output=True, timeout=120)
    if done.returncode != 0:
        raise RuntimeError('seeding the data directory failed: ' + done.stderr.decode(errors='replace')[-600:])


def post_json(base, path, body):
    """(status, body) of a POST to the stack the way an agent makes one: no session, the host's own token in the body."""
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Rendered(unittest.TestCase):
    HOSTS = {}                  # id -> {'os': ..., 'token': ...}: written to the data directory before the stack starts
    STORES = {}                 # api attribute name -> the value saved under it

    @classmethod
    def build_data_dir(cls):
        data_dir = tempfile.mkdtemp(prefix='rp-winsec-e2e-')
        if cls.HOSTS or cls.STORES:
            seed_data_dir(data_dir, cls.HOSTS, cls.STORES)
        return data_dir

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


def _load_windows_agent():
    """The real Windows agent, imported on this machine (nothing in it runs unless called)."""
    spec = importlib.util.spec_from_file_location('rp_win_agent_e2e', _ROOT / 'client' / 'remotepower-agent-win.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestLogRuleTemplatePicker(_Rendered):
    """G06: the Ready-made Windows rule list of the Add log rule dialog, and what the text of an event does once it is a log line."""
    HOSTS = {'winhost': {'os': 'Windows 11 Pro', 'token': 'e2e-win-token'}, 'linhost': {'os': 'Debian GNU/Linux 12', 'token': 'e2e-lin-token'}}
    HOSTILE = '<img src=x onerror=window.__pwned=1>'

    def open_dialog(self, page, tab='global'):
        page.evaluate("() => showPage('logs')")
        page.wait_for_function("() => { const s = document.getElementById('logs-device-filter'); return s && s.options.length >= 3 && typeof logRulePickTemplate === 'function'; }",
                               timeout=40000)
        page.evaluate("t => switchRulesTab(t)", tab)
        page.evaluate("() => openAddRuleModal()")
        page.wait_for_selector('#log-rule-modal', state='visible', timeout=10000)
        page.wait_for_selector('#log-rule-tpl-row', state='visible', timeout=5000)

    def templates(self, page):
        return page.evaluate("() => LOG_RULE_TEMPLATES.map(t => ({id: t.id, label: t.label, note: t.note, unit: t.unit, pattern: t.pattern, threshold: t.threshold,"
                             " severity: t.severity, message: t.message}))")

    def test_each_template_fills_the_form_and_its_note_names_what_the_event_needs(self):
        page = self.open_app()
        self.open_dialog(page)
        tpls = self.templates(page)
        self.assertEqual(len(tpls), 8)
        self.assertEqual(page.evaluate("() => document.getElementById('log-rule-tpl').options.length"), 9, 'the "write my own" row and the eight rules')
        for t in tpls:
            with self.subTest(t['id']):
                page.select_option('#log-rule-tpl', t['id'])
                self.assertEqual(page.input_value('#log-rule-unit'), t['unit'])
                self.assertEqual(page.input_value('#log-rule-pattern'), t['pattern'])
                self.assertEqual(page.input_value('#log-rule-threshold'), str(t['threshold']))
                self.assertEqual(page.input_value('#log-rule-severity'), t['severity'])
                self.assertEqual(page.input_value('#log-rule-template'), t['message'])
                self.assertEqual(page.input_value('#log-rule-exclude'), '')
                self.assertTrue(page.is_checked('input[name="log-rule-source"][value="unit"]'))
                self.assertEqual(page.inner_text('#log-rule-tpl-note').strip(), t['note'])
        page.select_option('#log-rule-tpl', '')
        self.assertEqual(page.inner_text('#log-rule-tpl-note').strip(), '', 'choosing "write my own" takes the note away')
        self.assertEqual(self.problems, [])

    def test_the_dialog_fits_at_three_widths_in_english_german_and_arabic_with_the_longest_note_showing(self):
        for width, height in WIDTHS:
            page = self.open_app(width, height)
            self.open_dialog(page)
            longest = max(self.templates(page), key=lambda t: len(t['note']))
            page.select_option('#log-rule-tpl', longest['id'])
            for lang in ('en',) + LANGS:
                with self.subTest(width=width, lang=lang):
                    self.set_lang(page, lang)
                    if lang == 'ar':
                        self.assertEqual(page.evaluate("document.documentElement.dir"), 'rtl')
                    self.assertEqual(self.no_horizontal_overflow(page, '#log-rule-modal .modal'), [])
            self.assertEqual(self.problems, [])

    def test_the_instruments_can_say_no(self):
        page = self.open_app(768, 1024)
        self.open_dialog(page)
        page.evaluate("""() => { const d = document.createElement('div'); d.id = 'plant'; d.textContent = 'x';
                                 d.style.width = '3000px'; document.querySelector('#log-rule-tpl-row').appendChild(d); }""")
        self.assertTrue(self.no_horizontal_overflow(page, '#log-rule-modal .modal'), 'the measure missed a 3000 px element')
        page.evaluate("() => document.getElementById('plant').remove()")
        self.assertEqual(self.no_horizontal_overflow(page, '#log-rule-modal .modal'), [])
        page.evaluate("() => { const e = document.getElementById('log-rule-tpl'); e.style.outline = 'none'; e.style.boxShadow = 'none'; }")
        page.focus('#log-rule-device')
        got = self.tab_to(page, 'log-rule-tpl')
        self.assertIsNotNone(got)
        self.assertFalse(got['ring'], 'a control with its ring switched off was reported as having one')

    def test_the_list_the_note_and_the_options_read_in_german_and_arabic_whichever_comes_first(self):
        page = self.open_app()
        self.open_dialog(page)
        tpls = self.templates(page)
        pick = next(t for t in tpls if t['id'] == 'administrators-member-added')
        for lang in LANGS:
            # the language is chosen while the dialog is open: the label, the first row, the rules and the note change
            self.set_lang(page, lang)
            page.select_option('#log-rule-tpl', pick['id'])
            page.wait_for_timeout(300)
            for sel, key in (('label[for="log-rule-tpl"]', 'Ready-made Windows rule'), ('#log-rule-tpl option[value=""]', 'None, I will write my own'),
                             ('#log-rule-tpl option[value="%s"]' % pick['id'], pick['label']), ('#log-rule-tpl-note', pick['note'])):
                with self.subTest(order='open first', lang=lang, key=key[:30]):
                    shown = page.evaluate("s => document.querySelector(s).textContent.trim()", sel)
                    want = page.evaluate("k => RPi18n.t(k)", key)
                    self.assertNotEqual(want, key, 'the dictionary has no entry')
                    self.assertEqual(shown, want)
        # the language is already German when the dialog opens: the options are made then, and are in German
        page.evaluate("() => closeModal('log-rule-modal')")
        self.set_lang(page, 'de')
        page.evaluate("() => openAddRuleModal()")
        page.wait_for_selector('#log-rule-tpl-row', state='visible', timeout=5000)
        page.wait_for_timeout(400)
        for t in tpls:
            shown = page.evaluate("v => document.querySelector('#log-rule-tpl option[value=\"' + v + '\"]').textContent.trim()", t['id'])
            want = page.evaluate("k => RPi18n.t(k)", t['label'])
            with self.subTest(order='language first', template=t['id']):
                self.assertNotEqual(want, t['label'])
                self.assertEqual(shown, want)

    def test_the_picker_is_reached_by_keyboard_shows_a_focus_ring_and_a_key_press_fills_the_form(self):
        page = self.open_app()
        self.open_dialog(page, tab='device')
        page.focus('#log-rule-device')
        got = self.tab_to(page, 'log-rule-tpl')
        self.assertIsNotNone(got, 'the picker is not on the tab path')
        self.assertTrue(got['ring'], 'the picker has no visible focus ring: %s' % got)
        first = self.templates(page)[0]
        page.keyboard.press('ArrowDown')
        page.wait_for_function("u => document.getElementById('log-rule-unit').value === u", arg=first['unit'], timeout=5000)
        self.assertEqual(page.input_value('#log-rule-pattern'), first['pattern'])

    def test_a_rule_that_is_being_edited_has_no_picker_and_adding_one_brings_it_back(self):
        page = self.open_app()
        self.open_dialog(page)
        page.select_option('#log-rule-tpl', 'audit-log-cleared')
        page.click('#log-rule-modal .btn-primary')
        page.wait_for_function("() => document.getElementById('logs-rules-global-tbody').textContent.includes('eventlog.Security.1102')", timeout=15000)
        page.click('#logs-rules-global-tbody button[data-action-btn="_editLogRuleBtn"]')
        page.wait_for_selector('#log-rule-modal', state='visible', timeout=5000)
        self.assertEqual(page.input_value('#log-rule-unit'), 'eventlog.Security.1102')
        self.assertFalse(page.is_visible('#log-rule-tpl-row'), 'a rule that exists is not started from a template')
        page.evaluate("() => closeModal('log-rule-modal')")
        page.evaluate("() => openAddRuleModal()")
        self.assertTrue(page.is_visible('#log-rule-tpl-row'))
        self.assertEqual(page.input_value('#log-rule-tpl'), '', 'the picker starts on its first row')
        self.assertEqual(page.input_value('#log-rule-unit'), '', 'the form is empty, not the last template')

    def test_a_saved_template_is_asked_for_by_the_host_and_what_a_name_in_an_event_carries_is_only_ever_text(self):
        win = _load_windows_agent()
        import win_event_samples as S
        page = self.open_app()
        self.open_dialog(page)
        page.select_option('#log-rule-tpl', 'failed-logons')
        page.click('#log-rule-modal .btn-primary')
        page.wait_for_function("() => document.getElementById('logs-rules-global-tbody').textContent.includes('eventlog.Security.4625')", timeout=15000)
        rules = page.evaluate("async () => (await api('GET', '/logs/rules/global')).rules.filter(r => r.unit === 'eventlog.Security.4625')")
        self.assertEqual([(r['threshold'], r['severity']) for r in rules], [(10, 'WARN')])
        # the Windows host is asked for the event on its next check-in, and the Linux one is not
        st, resp = post_json(self.base, '/api/heartbeat', {'device_id': 'winhost', 'token': 'e2e-win-token', 'sysinfo': {}})
        self.assertEqual(st, 200, resp)
        self.assertIn({'unit': 'eventlog.Security.4625'}, resp['log_watch'])
        st, resp = post_json(self.base, '/api/heartbeat', {'device_id': 'linhost', 'token': 'e2e-lin-token', 'sysinfo': {}})
        self.assertEqual(st, 200, resp)
        self.assertNotIn('eventlog.Security.4625', [r.get('unit') for r in resp['log_watch']])
        # ten failed logons, one of them by a user whose name is markup, as the real agent writes them
        now_ms = int(time.time() * 1000)
        lines = [{'message': win._winevt_line(win._winevt_parse(S.failed_logon(rid=900 + i, user=self.HOSTILE if i == 0 else 'bob%d' % i))[0]), 'ts': now_ms + i}
                 for i in range(10)]
        self.assertIn('user="%s"' % self.HOSTILE, lines[0]['message'], 'the agent keeps the name, and it is cut and quoted only')
        st, resp = post_json(self.base, '/api/logs', {'device_id': 'winhost', 'token': 'e2e-win-token', 'units': {'eventlog.Security.4625': lines}})
        self.assertEqual(st, 200, resp)
        page.evaluate("() => showPage('logs')")
        page.wait_for_function("() => typeof startLogsTail === 'function' && document.getElementById('logs-viewer')", timeout=40000)
        page.evaluate("() => startLogsTail()")
        page.wait_for_function("(h) => document.getElementById('logs-viewer').textContent.includes(h)", arg=self.HOSTILE, timeout=20000)
        self.assertIsNone(page.query_selector('#logs-viewer img'), 'a name in an event became an element of the page')
        self.assertIsNone(page.evaluate("() => window.__pwned || null"))
        # the alert shows the matched line as text too
        page.evaluate("() => showPage('alerts')")
        page.wait_for_function("(h) => document.body.textContent.includes(h)", arg=self.HOSTILE, timeout=30000)
        self.assertEqual(page.evaluate("() => document.querySelectorAll('img[src=\"x\"]').length"), 0)
        self.assertIsNone(page.evaluate("() => window.__pwned || null"))
        self.assertEqual(self.problems, [])


def _persistence_record(hostile):
    """The row of persistence.json for a Windows host as the server writes it: a baseline an hour ago, then a snapshot in which one Run value is new (its name is markup and
    its command is a path of 240 characters with no space in it), one is gone, a startup file is new, the services list was cut and the scheduled tasks could not be read."""
    sys.path.insert(0, str(_CGI))
    import persistence as P
    long_path = 'C:\\\\Users\\\\bob\\\\' + 'A' * 150 + '\\\\payload.exe'
    first = {'v': 1,
             'run': {'ok': True, 'cut': False, 'items': [['Run', 'OneDrive', '"C:\\\\Program Files\\\\OneDrive.exe" /background'], ['Run', 'Old', 'C:\\\\Old\\\\old.exe']]},
             'winlogon': {'ok': True, 'cut': False, 'items': [['Winlogon', 'Shell', 'explorer.exe'], ['Winlogon', 'Userinit', 'C:\\\\Windows\\\\system32\\\\userinit.exe,']]},
             'services': {'ok': True, 'cut': False, 'items': [['Service', 'Updater', 'C:\\\\Users\\\\bob\\\\AppData\\\\Local\\\\Temp\\\\upd.exe -k run']]},
             'tasks': {'ok': True, 'cut': False, 'items': [['\\\\Vendor', 'Task1', 'C:\\\\Vendor\\\\t.exe /x']]},
             'startup': {'ok': True, 'cut': False, 'items': [['All users', 'OneNote.lnk', '1893 bytes']]}}
    second = dict(first)
    second['run'] = {'ok': True, 'cut': False, 'items': [first['run']['items'][0], ['Run', hostile, long_path + ' --token abc123']]}
    second['services'] = {'ok': True, 'cut': True, 'items': first['services']['items']}
    second['tasks'] = {'ok': False, 'cut': False, 'items': []}
    second['startup'] = {'ok': True, 'cut': False, 'items': first['startup']['items'] + [['User bob', 'evil.lnk', '700 bytes']]}
    t0 = int(time.time()) - 7200
    rec, _added, _removed = P.apply_snapshot({}, P.clean_snapshot(first), t0)
    rec, _added, _removed = P.apply_snapshot(rec, P.clean_snapshot(second), t0 + 3600)
    return rec


def _snapshot(*run):
    """A snapshot a host would send, for the check-ins of the alert test: the Run values given, every other place read and empty."""
    snap = {'v': 1}
    for cat in ('run', 'winlogon', 'services', 'tasks', 'startup'):
        snap[cat] = {'ok': True, 'cut': False, 'items': [list(r) for r in run] if cat == 'run' else []}
    return snap


class TestPersistenceSection(_Rendered):
    """G14: the Persistence section of a host's page, and what a new entry's text does in the inbox and the feed."""
    HOSTILE = '<img src=x onerror=window.__pwned=1>'
    HOSTS = {'winhost': {'os': 'Windows 11 Pro', 'token': 'e2e-pers-token'}, 'linhost': {'os': 'Debian GNU/Linux 12', 'token': 'e2e-lin-token'},
             'winalert': {'os': 'Windows 10 Pro', 'token': 'e2e-alert-token'}}

    @classmethod
    def build_data_dir(cls):
        cls.STORES = {'PERSISTENCE_FILE': {'winhost': _persistence_record(cls.HOSTILE)}}
        return super().build_data_dir()

    def open_drawer(self, page, host='winhost', wait=True):
        page.evaluate("h => openDeviceDrawer(h, h)", host)
        page.wait_for_selector('#device-drawer.open', timeout=20000)
        if wait:
            page.wait_for_selector('#drawer-persistence-section', state='visible', timeout=20000)

    def test_the_section_lists_the_changes_and_what_is_on_the_host_now_and_a_name_is_only_text(self):
        page = self.open_app()
        self.open_drawer(page)
        text = page.inner_text('#drawer-persistence-section')
        for want in ('Persistence', 'First inventory', 'Last inventory', 'Changes', 'On the host now', 'Added', 'Removed', 'Run key', 'Service', 'Startup folder',
                     'OneDrive', 'Old', 'evil.lnk', 'Updater', 'Task1', 'explorer.exe', self.HOSTILE):
            self.assertIn(want, text, want)
        self.assertEqual(page.evaluate("() => document.querySelectorAll('#drawer-persistence-section .patch-badge').length"), 3, 'two added, one removed')
        self.assertEqual(page.evaluate("() => [...document.querySelectorAll('#drawer-persistence-changes .patch-badge')].map(b => b.textContent.trim())"),
                         ['Added', 'Added', 'Removed'])
        self.assertIn('This place could not be read at the last inventory. It is shown as it was.', text)
        self.assertIn('This list was cut at its limit, so changes in it are not tracked.', text)
        self.assertNotIn('abc123', text, 'a password in a command line never reaches the page')
        self.assertIn('[REDACTED]', text)
        self.assertIsNone(page.query_selector('#drawer-persistence-section img'), 'the name of an entry became an element of the page')
        self.assertIsNone(page.evaluate("() => window.__pwned || null"))
        self.assertEqual(self.problems, [])

    def test_a_host_that_is_not_a_windows_one_has_no_section_and_asks_for_nothing(self):
        page = self.open_app()
        requests = []
        page.on('request', lambda r: requests.append(r.url))
        self.open_drawer(page, 'linhost', wait=False)
        page.wait_for_timeout(2500)
        self.assertFalse(page.is_visible('#drawer-persistence-section'))
        self.assertEqual([u for u in requests if u.endswith('/persistence')], [], 'no request for a host that cannot have an inventory')
        page.evaluate("() => closeDeviceDrawer()")
        self.open_drawer(page, 'winhost')
        self.assertTrue([u for u in requests if u.endswith('/devices/winhost/persistence')], 'the control: a Windows host does ask')

    def test_the_section_fits_at_three_widths_in_english_german_and_arabic_with_a_path_that_has_no_space_in_it(self):
        for width, height in WIDTHS:
            page = self.open_app(width, height)
            self.open_drawer(page)
            for lang in ('en',) + LANGS:
                with self.subTest(width=width, lang=lang):
                    self.set_lang(page, lang)
                    if lang == 'ar':
                        self.assertEqual(page.evaluate("document.documentElement.dir"), 'rtl')
                    self.assertEqual(self.no_horizontal_overflow(page, '#drawer-persistence-section'), [])
                    # the two lists scroll up and down; a command that cannot break would make them scroll sideways instead, which the measure above does not count
                    sideways = page.evaluate("() => ['drawer-persistence-changes', 'drawer-persistence-list'].map(id => { const e = document.getElementById(id); return e.scrollWidth - e.clientWidth; })")
                    self.assertEqual([n > 1 for n in sideways], [False, False], 'a list scrolls sideways: %s' % sideways)
            self.assertEqual(self.problems, [])

    def test_the_instruments_can_say_no(self):
        page = self.open_app(768, 1024)
        self.open_drawer(page)
        page.evaluate("""() => { const d = document.createElement('div'); d.id = 'plant'; d.textContent = 'x';
                                 d.style.minWidth = '3000px'; document.querySelector('#drawer-persistence-when').appendChild(d); }""")
        self.assertTrue(self.no_horizontal_overflow(page, '#drawer-persistence-section'), 'the measure missed a 3000 px element')
        page.evaluate("() => document.getElementById('plant').remove()")
        self.assertEqual(self.no_horizontal_overflow(page, '#drawer-persistence-section'), [])
        page.evaluate("() => { const e = document.getElementById('drawer-persistence-doc'); e.style.outline = 'none'; e.style.boxShadow = 'none'; }")
        page.focus('#drawer-persistence-section .section-title')
        got = self.tab_to(page, 'drawer-persistence-doc')
        self.assertIsNotNone(got)
        self.assertFalse(got['ring'], 'a control with its ring switched off was reported as having one')

    def test_every_label_reads_in_german_and_arabic(self):
        page = self.open_app()
        self.open_drawer(page)
        for lang in LANGS:
            self.set_lang(page, lang)
            page.wait_for_timeout(300)
            checks = [('#drawer-persistence-section .section-title', 'Persistence')]
            for want in ('First inventory', 'Last inventory', 'Changes', 'On the host now', 'Added', 'Removed', 'Run key', 'Startup folder', 'Service',
                         'This place could not be read at the last inventory. It is shown as it was.', 'This list was cut at its limit, so changes in it are not tracked.'):
                checks.append((None, want))
            for sel, key in checks:
                want = page.evaluate("k => RPi18n.t(k)", key)
                with self.subTest(lang=lang, key=key[:40]):
                    self.assertNotEqual(want, key, 'the dictionary has no entry')
                    if sel:
                        self.assertEqual(page.evaluate("s => document.querySelector(s).textContent.trim()", sel), want)
                    else:
                        self.assertTrue(page.evaluate("w => [...document.querySelectorAll('#drawer-persistence-section *')].some(e => e.children.length === 0 && e.textContent.trim() === w)", want),
                                        '%s is not shown as %s' % (key, want))
            hint = page.evaluate("() => document.querySelector('#drawer-persistence-section p.hint').firstChild.textContent.trim()")
            want = page.evaluate("k => RPi18n.t(k)", "What starts by itself on this Windows host: Run keys, the Winlogon shell, services that run from a temporary or user folder, "
                                                      "scheduled tasks that are not Microsoft's, and startup folders. Once a first inventory is on record, a new entry raises an alert.")
            self.assertEqual(hint, want)

    def test_the_documentation_link_is_reached_by_keyboard_with_a_visible_focus_ring(self):
        page = self.open_app()
        self.open_drawer(page)
        page.focus('#drawer-persistence-section .section-title')
        got = self.tab_to(page, 'drawer-persistence-doc')
        self.assertIsNotNone(got, 'the link is not on the tab path')
        self.assertTrue(got['ring'], 'the link has no visible focus ring: %s' % got)

    def test_a_new_entry_whose_name_is_markup_is_text_in_the_inbox_and_the_feed(self):
        keep = ['Run', 'OneDrive', '"C:\\\\Program Files\\\\OneDrive.exe" /background']
        st, resp = post_json(self.base, '/api/heartbeat', {'device_id': 'winalert', 'token': 'e2e-alert-token', 'sysinfo': {'persistence': _snapshot(keep)}})
        self.assertEqual(st, 200, resp)
        st, resp = post_json(self.base, '/api/heartbeat', {'device_id': 'winalert', 'token': 'e2e-alert-token',
                                                           'sysinfo': {'persistence': _snapshot(keep, ['Run', self.HOSTILE, 'C:\\\\Users\\\\bob\\\\x.exe --password hunter2'])}})
        self.assertEqual(st, 200, resp)
        page = self.open_app()
        page.evaluate("() => showPage('alerts')")
        page.wait_for_function("() => { const p = document.getElementById('page-alerts'); return !!p && p.textContent.includes('New startup entry on winalert'); }", timeout=30000)
        body = page.inner_text('#page-alerts')
        self.assertIn(self.HOSTILE, body, 'the name is on the page as text')
        self.assertIn('Run key: ', body)
        self.assertNotIn('hunter2', body)
        self.assertEqual(page.evaluate("() => document.querySelectorAll('img[src=\"x\"]').length"), 0)
        self.assertIsNone(page.evaluate("() => window.__pwned || null"))
        page.evaluate("() => showPage('home')")
        page.wait_for_function("() => document.getElementById('page-home').textContent.includes('1 new startup entry')", timeout=30000)
        self.assertIn(self.HOSTILE, page.evaluate("() => document.getElementById('page-home').textContent"), 'the feed row quotes the entry')
        self.assertEqual(page.evaluate("() => document.querySelectorAll('img[src=\"x\"]').length"), 0, 'the activity feed shows the name as text too')
        self.assertIsNone(page.evaluate("() => window.__pwned || null"))
        self.assertEqual([p for p in self.problems if not (p[0] == 'http' and p[1] == 404 and p[2].endswith('/x'))
                          and not (p[0] == 'console' and '404' in p[1])], [])


if __name__ == '__main__':
    unittest.main()
