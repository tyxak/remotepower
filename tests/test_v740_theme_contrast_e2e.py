#!/usr/bin/env python3
"""Colour contrast in every theme, measured in the browser on the seeded fleet.

test_a11y_axe runs axe with every rule, but only in the default theme, so the
other twelve palettes were never measured. At v7.4.0 a census found 11 of 13
themes failing, 2,405 serious color-contrast nodes over nine populated pages,
while that gate stayed green. tests/test_v740_theme_contrast checks the palette
arithmetic from the stylesheet; this checks what an operator actually sees,
including colours set from scripts and backgrounds the stylesheet model cannot
compose.

Each theme logs in in its own browser context (rp_theme set before app.js
runs), visits the same nine populated pages and runs axe's color-contrast rule.
Ceiling: zero serious or critical nodes in every theme.

Controls, so a pass means something:
  - the theme each context reports is the theme it was given (thirteen runs of
    the default palette would pass and measure one);
  - every theme measures a real population: axe counts the text nodes that
    passed, and an empty page passes trivially;
  - the scan sees a failure: a page title painted a shade off its background
    must come back as a violation.

The filename carries 'e2e', so make test-fast skips it; the serial gate runs it.
The themes walk in parallel lanes against one seeded stack (about two minutes).
"""
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402

try:
    from playwright.async_api import async_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False

try:
    from axe_core_python.sync_playwright import Axe
    _HAVE_AXE = True
except ImportError:
    _HAVE_AXE = False

_DEPS = _HAVE_PLAYWRIGHT and _HAVE_AXE
_GATE = _DEPS or browser_required.required()
_ROOT = Path(__file__).resolve().parent.parent

# Populated pages with the widest spread of components: status pills, severity
# badges, tinted rows, muted metadata, charts' legends, the activity feed.
PAGES = ('home', 'devices', 'alerts', 'monitor', 'containers', 'tickets', 'reports', 'self', 'logs')
LANES = 7
_OPTS = {'runOnly': {'type': 'rule', 'values': ['color-contrast']}}
_SETTLE = """*, *::before, *::after { animation-duration: 0s !important; animation-delay: 0s !important;
  transition-duration: 0s !important; transition-delay: 0s !important; }"""
# The dashboard fades its cards in; axe samples one instant, and a node caught
# mid-fade composites against the background (see test_a11y_axe._SETTLE_CSS).
_FINISH = """() => { (document.getAnimations ? document.getAnimations() : [])
  .forEach(a => { try { a.finish(); } catch (e) {} }); }"""
_APPLIED = """() => document.body.dataset.theme
  || (document.body.classList.contains('light') ? 'light' : 'dark')"""


def themes():
    """Every concrete palette in the app's catalog (auto and schedule pick one of these)."""
    src = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
    return re.findall(r"\{\s*id:'([a-z-]+)',\s*name:'[^']*',\s*type:'(?:dark|light)'", src)


async def _axe(page, script):
    await page.add_style_tag(content=_SETTLE)
    await page.evaluate(_FINISH)
    await page.evaluate(script)
    return await page.evaluate('axe.run(%s).then(r => r)' % json.dumps(_OPTS))


def _serious(res):
    out = []
    for v in res.get('violations') or []:
        if v.get('impact') not in ('critical', 'serious'):
            continue
        for n in v.get('nodes') or []:
            data = {}
            for chk in n.get('any') or []:
                if chk.get('id') == 'color-contrast' and isinstance(chk.get('data'), dict):
                    data = chk['data']
            out.append({'target': (n.get('target') or ['?'])[0], 'fg': data.get('fgColor'),
                        'bg': data.get('bgColor'), 'ratio': data.get('contrastRatio')})
    return out


def _passed(res):
    return sum(len(p.get('nodes') or []) for p in res.get('passes') or [])


async def _theme_walk(browser, base, theme, script, plant=False):
    ctx = await browser.new_context(viewport={'width': 1440, 'height': 900})
    await ctx.add_init_script(
        "try { localStorage.setItem('rp_theme', %s); localStorage.setItem('rp_tour_done', '1'); } catch (e) {}"
        % json.dumps(theme))
    page = await ctx.new_page()
    out = {'theme': theme, 'pages': {}, 'passed': 0, 'planted': None}
    try:
        await page.goto(base + '/index.html')
        await page.fill('#login-user', 'alice')
        await page.fill('#login-pass', 'demo')
        await page.click('#login-form button[type="submit"]')
        await page.wait_for_selector('#app', state='visible', timeout=90000)
        await page.wait_for_timeout(5000)
        out['applied'] = await page.evaluate(_APPLIED)
        for name in PAGES:
            await page.evaluate('n => { try { showPage(n) } catch (e) {} }', name)
            await page.wait_for_timeout(1500)
            res = await _axe(page, script)
            out['pages'][name] = _serious(res)
            out['passed'] += _passed(res)
        if plant:
            # The control: the active page's title a shade off its background
            # (about 1.6:1). Not the background colour itself: axe files 1:1 as
            # "incomplete", text that may be hidden on purpose, not a violation.
            await page.evaluate("""() => {
              const t = document.querySelector('.page.active .page-title') || document.querySelector('.page-title');
              const [r, g, b] = getComputedStyle(document.body).backgroundColor.match(/\\d+/g).map(Number);
              const d = (r + g + b) / 3 < 128 ? 40 : -40;
              t.style.color = `rgb(${r + d}, ${g + d}, ${b + d})`;
            }""")
            res = await _axe(page, script)
            out['planted'] = _serious(res)
    finally:
        await ctx.close()
    return out


async def _walk(base, todo, script, plant_theme):
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        sem = asyncio.Semaphore(LANES)

        async def one(t):
            async with sem:
                return await _theme_walk(browser, base, t, script, plant=(t == plant_theme))
        try:
            return await asyncio.gather(*(one(t) for t in todo))
        finally:
            await browser.close()


@unittest.skipUnless(_GATE, 'playwright + axe-core-python not installed')
class TestEveryThemeReadsAtAA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('colour is backend-agnostic, measured once')
        if not _DEPS:
            browser_required.skip_or_fail('playwright + axe-core-python are not installed')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-contrast-')
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply'],
                              capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            raise unittest.SkipTest(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        cls._shutdown()

    def test_every_theme(self):
        todo = themes()
        self.assertGreaterEqual(len(todo), 13, 'control: the theme catalog was read')
        try:
            results = asyncio.run(_walk(self.base, todo, Axe().axe_script, plant_theme='dark'))
        except Exception as exc:
            browser_required.skip_or_fail(f'chromium not available: {exc}')
            return
        bad = []
        for r in results:
            self.assertEqual(r.get('applied'), r['theme'], 'control: the context runs the theme it was given')
            self.assertGreater(r['passed'], 300, 'control: %s measured text nodes' % r['theme'])
            for name, nodes in r['pages'].items():
                for n in nodes:
                    bad.append('%-15s %-10s %s  %s on %s = %s:1' % (r['theme'], name, n['target'][:60],
                                                                    n['fg'], n['bg'], n['ratio']))
        self.assertEqual(bad, [], '%d node(s) under AA:\n%s' % (len(bad), '\n'.join(bad[:40])))
        planted = next(r for r in results if r['theme'] == 'dark')['planted']
        self.assertTrue(planted, 'control: a title a shade off its background must fail the scan')


if __name__ == '__main__':
    unittest.main()
