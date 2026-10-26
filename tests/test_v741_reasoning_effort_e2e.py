#!/usr/bin/env python3
"""7.4.1, issue #40, in a browser: the Reasoning effort setting can be found, set and saved.

Driven on a seeded instance with the controls a person uses:

  * Settings -> AI assistant has a Reasoning effort select. It is there for the providers that take
    the field (OpenAI, DeepSeek, Ollama, LocalAI) and hidden for the ones that do not (Anthropic,
    opencode, openclaw). The row is hidden with the d-none class, which is the mechanism the
    maintenance form (#41) got wrong, so the visibility is measured, not read from the source.
  * A value chosen there is saved by the real save and read back after a reload of the settings.
  * Each prompt's Fine-tuning has its own select, opened from the real summary, saved with the real
    button and cleared with Reset; blank follows the global setting.

The wire, the handlers and the routes are test_v741_reasoning_effort. Self-skips without
playwright/chromium/gunicorn.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()

_STACK = {}

# the providers whose chat API has the field
_TAKES_IT = ('openai', 'deepseek', 'ollama', 'localai')
_DOES_NOT = ('anthropic', 'opencode', 'openclaw')


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('what is measured is the page, not the backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-reasoning-')
    proc = subprocess.run([sys.executable, str(seeder), '--data-dir', data_dir, '--apply'],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail(f'chromium not available: {exc}')
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest(f'app stack not available: {exc}')
    page = browser.new_page(viewport={'width': 1440, 'height': 900})
    page.set_default_timeout(15000)
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    page.goto(base + '/index.html')
    page.fill('#login-user', 'alice')
    page.fill('#login-pass', 'demo')
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector('#app', state='visible', timeout=90000)
    page.wait_for_timeout(6000)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK['browser'].close()
        _STACK['pw'].stop()
    finally:
        _STACK['shutdown']()
        _STACK.clear()


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Base(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.page = _STACK['page']

    def open_ai_settings(self):
        self.page.evaluate("n => showPage(n)", 'settings')
        self.page.wait_for_timeout(1500)
        self.page.click('#settings-tab-btn-ai')
        self.page.wait_for_selector('#settings-pane-ai', state='visible')
        self.page.wait_for_function("() => typeof _aiCfgCache !== 'undefined' && _aiCfgCache !== null")
        self.page.wait_for_timeout(800)

    def stored_config(self):
        return self.page.evaluate("() => api('GET', '/ai/config')")

    def stored_params(self, key):
        return self.page.evaluate("""async k => {
            const r = await api('GET', '/ai/params');
            return (r.params || []).find(p => p.key === k) || null; }""", key)


class TestTheSettingsRow(_Base):

    def test_the_row_follows_the_provider(self):
        self.open_ai_settings()
        for provider in _TAKES_IT + _DOES_NOT:
            with self.subTest(provider=provider):
                self.page.select_option('#ai-provider', provider)
                self.page.wait_for_timeout(150)
                shown = self.page.locator('#ai-reasoning-effort').is_visible()
                self.assertEqual(shown, provider in _TAKES_IT,
                                 'Reasoning effort is %s for %s' % ('shown' if shown else 'hidden', provider))
        self.page.select_option('#ai-provider', 'ollama')

    def test_the_select_offers_the_five_choices_with_readable_labels(self):
        self.open_ai_settings()
        self.page.select_option('#ai-provider', 'ollama')
        opts = self.page.eval_on_selector_all('#ai-reasoning-effort option',
                                              "els => els.map(e => [e.value, e.textContent.trim()])")
        self.assertEqual([v for v, _ in opts], ['', 'none', 'low', 'medium', 'high'])
        self.assertEqual(opts[0][1], 'Provider default (nothing is sent)')
        self.assertEqual(opts[1][1], 'None (turn thinking off)')
        label = self.page.locator('label[for="ai-reasoning-effort"]').inner_text()
        self.assertEqual(label.strip(), 'Reasoning effort')

    def test_a_chosen_level_is_saved_and_comes_back(self):
        self.open_ai_settings()
        self.page.select_option('#ai-provider', 'ollama')
        self.page.select_option('#ai-reasoning-effort', 'none')
        self.assertTrue(self.page.evaluate("() => saveAISettings()"))
        self.assertEqual(self.stored_config()['reasoning_effort'], 'none')
        # a reload of the settings shows it again
        self.page.select_option('#ai-reasoning-effort', 'high')
        self.page.evaluate("() => loadAISettings()")
        self.page.wait_for_timeout(800)
        self.assertEqual(self.page.input_value('#ai-reasoning-effort'), 'none')
        # blank clears it
        self.page.select_option('#ai-reasoning-effort', '')
        self.assertTrue(self.page.evaluate("() => saveAISettings()"))
        self.assertEqual(self.stored_config()['reasoning_effort'], '')

    def test_switching_to_a_provider_without_the_field_keeps_the_value(self):
        self.open_ai_settings()
        self.page.select_option('#ai-provider', 'ollama')
        self.page.select_option('#ai-reasoning-effort', 'low')
        self.page.select_option('#ai-provider', 'anthropic')
        self.assertFalse(self.page.locator('#ai-reasoning-effort').is_visible())
        self.page.select_option('#ai-provider', 'ollama')
        self.assertEqual(self.page.input_value('#ai-reasoning-effort'), 'low')
        self.page.select_option('#ai-reasoning-effort', '')


class TestFineTuningPerPrompt(_Base):

    def first_card(self):
        self.open_ai_settings()
        self.page.wait_for_selector('#ai-prompts-list .prompt-card')
        return self.page.locator('#ai-prompts-list .prompt-card').first

    def test_a_prompt_can_be_given_its_own_level_and_lose_it_again(self):
        card = self.first_card()
        key = card.get_attribute('data-key')
        self.assertTrue(key)
        card.locator('summary').click()
        select = card.locator('[data-field="reasoning-effort"]')
        self.assertTrue(select.is_visible(), 'the Fine-tuning select is not on screen after opening it')
        self.assertEqual(select.input_value(), '')
        self.assertEqual(select.locator('option').first.inner_text().strip(), 'Use the global setting')
        select.select_option('low')
        card.locator('button[data-action-btn="_saveAiParamsBtn"]').click()
        self.page.wait_for_function(
            "k => api('GET', '/ai/params').then(r => (r.params || []).some(p => p.key === k && p.reasoning_effort === 'low'))",
            arg=key, timeout=8000)
        self.assertEqual(self.stored_params(key)['reasoning_effort'], 'low')
        # the list reloads after a save; the card is marked as tuned and the value is shown
        self.page.wait_for_timeout(2200)
        card = self.page.locator('#ai-prompts-list .prompt-card[data-key="%s"]' % key)
        self.assertIn('tuned', card.inner_text())
        self.assertEqual(card.locator('[data-field="reasoning-effort"]').input_value(), 'low')
        # Reset tuning clears it
        card.locator('button[data-action-btn="_resetAiParamsBtn"]').click()
        self.page.wait_for_function(
            "k => api('GET', '/ai/params').then(r => (r.params || []).some(p => p.key === k && !p.reasoning_effort))",
            arg=key, timeout=8000)
        self.assertIsNone(self.stored_params(key)['reasoning_effort'])

    def test_blank_saves_as_no_override(self):
        card = self.first_card()
        key = card.get_attribute('data-key')
        card.locator('summary').click()
        card.locator('input.prompt-temp').fill('0.4')
        card.locator('button[data-action-btn="_saveAiParamsBtn"]').click()
        self.page.wait_for_function(
            "k => api('GET', '/ai/params').then(r => (r.params || []).some(p => p.key === k && p.temperature === 0.4))",
            arg=key, timeout=8000)
        row = self.stored_params(key)
        self.assertEqual((row['temperature'], row['reasoning_effort']), (0.4, None))
        self.page.evaluate("k => api('POST', '/ai/params', {key: k})", key)


if __name__ == '__main__':
    unittest.main()
