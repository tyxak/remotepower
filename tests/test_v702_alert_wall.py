#!/usr/bin/env python3
"""The Alert inbox card, full screen — for a wall display or a spare monitor.

Entered from a button on the card, or with `?alertwall=1` so it can be a wall
display's browser start URL (which is how one is actually configured — the same
reason `?kiosk=1` exists).

**Why it fullscreens the DOCUMENT ROOT and not the card.** A fullscreen element
paints above everything outside it, and every `.modal-overlay` in this product
is a body-level sibling of `#app` (CLAUDE.md: `.container` is a z-index:1
stacking trap, so overlays live at body level). Fullscreening the card alone
therefore hides the ack-with-note dialog, the mute dialog, the AI-triage panel
and every toast BEHIND it — measured before building: with the card fullscreen,
`elementFromPoint()` at an open modal's centre returns the card.

So the card is promoted with a body class instead and the root goes fullscreen,
which is what kiosk mode already does. Modals, toasts and drawers stay inside
the fullscreen root and keep working. This file pins that, because the obvious
implementation is the broken one and it looks correct until someone clicks a row
action on the wall.

A DISPLAY mode, not a security boundary: the API enforces the token's role, so a
wall left on a viewer token is read-only because the ROLE says so.
"""
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CSS = _ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'
_HTML = _ROOT / 'server' / 'html' / 'index.html'
_APP = _ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
_I18N = _ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'

try:
    from playwright.sync_api import sync_playwright
    _PW = True
except ImportError:                                      # pragma: no cover
    _PW = False


def _browser():
    if not _PW:
        return False
    try:
        with sync_playwright() as p:
            p.chromium.launch().close()
        return True
    except Exception:
        return False


class TestItIsWired(unittest.TestCase):

    def test_the_card_has_the_button(self):
        html = _HTML.read_text()
        i = html.index('<div class="section-title">Alert inbox</div>')
        card = html[i:html.index('<div id="alerts-summary"', i)]
        self.assertIn('data-action="enterAlertWall"', card,
                      'the Full screen button is not on the Alert inbox card')
        self.assertIn('Full screen', card)

    def test_both_handlers_exist(self):
        app = _APP.read_text()
        self.assertIn('function enterAlertWall(', app)
        self.assertIn('function exitAlertWall(', app)

    def test_there_are_two_ways_out(self):
        """A full-screen view you can only leave by knowing a key is a trap on a
        touch-only wall panel with no keyboard — the same reason the kiosk exit
        button exists."""
        self.assertIn('data-action="exitAlertWall"', _HTML.read_text())
        app = _APP.read_text()
        self.assertRegex(app, r"Escape'.*alertwall.*exitAlertWall")

    def test_leaving_fullscreen_any_other_way_drops_the_class(self):
        """F11, the OS, the browser's own Esc — if the class survives, the
        chrome stays hidden and the page looks broken with no way back."""
        app = _APP.read_text()
        i = app.index("fullscreenchange")
        self.assertIn("classList.remove('alertwall')", app[i:i + 400])

    def test_the_url_can_start_it(self):
        app = _APP.read_text()
        self.assertIn("q.get('alertwall') === '1'", app)

    def test_it_refuses_when_the_module_is_off(self):
        """alerts is a gateable module. Opening a wall onto a 404ing page would
        show an error every refresh, forever."""
        app = _APP.read_text()
        i = app.index('function enterAlertWall(')
        body = app[i:app.index('\n}', i)]
        self.assertIn("_moduleOffFor('alerts')", body)

    def test_it_does_not_double_fetch(self):
        """showPage('alerts') already calls loadAlerts(); calling it again here
        fetched the inbox twice on every open."""
        app = _APP.read_text()
        i = app.index('function enterAlertWall(')
        body = app[i:app.index('\n}', i)]
        # Strip comments: the comment explaining this very fix names
        # loadAlerts(), so a raw substring search reports the bug as present in
        # correct code. Fourth time this trap has been walked into today.
        code = '\n'.join(l for l in body.splitlines()
                         if not l.strip().startswith('//'))
        self.assertNotIn('loadAlerts()', code)


class TestItFullscreensTheRootNotTheCard(unittest.TestCase):
    """The design decision, pinned. Fullscreening the card is the obvious
    implementation and it silently breaks every dialog the card can open."""

    def test_the_request_targets_the_document_root(self):
        app = _APP.read_text()
        i = app.index('function enterAlertWall(')
        body = app[i:app.index('\n}\n', i)]
        self.assertIn('document.documentElement.requestFullscreen', body)
        self.assertNotIn('.dash-card', body.split('requestFullscreen')[0][-200:])

    def test_the_card_is_promoted_by_a_class_not_by_fullscreen(self):
        css = _CSS.read_text()
        self.assertIn('body.alertwall #page-alerts > .dash-card', css)

    def test_overlays_are_still_body_level(self):
        """The premise. If modals ever moved inside .container, fullscreening
        the root would stop saving them and this whole design needs revisiting."""
        html = _HTML.read_text()
        i = html.index('<div class="alertwall-exit">')
        self.assertNotIn('<div class="container"', html[i:],
                         'the exit affordance is no longer at body level')


@unittest.skipUnless(_browser(), 'no Chromium available')
class TestItRenders(unittest.TestCase):
    """Every CSS rule here is individually correct; only the rendered result
    shows whether the card actually fills the screen and the table still
    scrolls inside it."""

    W, H = 1920, 1080

    @classmethod
    def setUpClass(cls):
        rows = ''.join('<tr><td>h</td><td>device_offline</td></tr>' for _ in range(60))
        page = ("""<!doctype html><html><head><style>__CSS__</style></head><body>
        <div id="app"><div class="sidebar">S</div><header>T</header>
         <div class="app-content"><div class="container">
          <div id="page-alerts" class="page active">
           <div class="page-title">Alerts</div><div class="page-subtitle">sub</div>
           <div class="dash-card"><div class="section-title">Alert inbox</div>
            <div class="table-card"><table><tbody>__ROWS__</tbody></table></div></div>
          </div>
          <div id="page-devices" class="page">other</div>
         </div></div></div>
        <div class="alertwall-exit"><button class="btn-secondary">Exit full screen</button></div>
        <div class="modal-overlay active" id="m"><div class="modal">
          <div class="modal-title">Acknowledge</div></div></div>
        <div class="toast-container" id="toast-container"></div>
        </body></html>""").replace('__CSS__', _CSS.read_text()).replace('__ROWS__', rows)
        cls._pw = sync_playwright().start()
        cls._b = cls._pw.chromium.launch()
        cls.page = cls._b.new_page()
        cls.page.set_viewport_size({'width': cls.W, 'height': cls.H})
        cls.page.set_content(page)

    @classmethod
    def tearDownClass(cls):
        cls._b.close()
        cls._pw.stop()

    def _wall(self, on):
        self.page.evaluate("(on)=>document.body.classList.toggle('alertwall', on)", on)
        self.page.wait_for_timeout(80)

    def test_the_stylesheet_loaded(self):
        """Positive control — otherwise every measurement below is of an
        unstyled page, where the card has no size and nothing is hidden, and
        the assertions mean nothing."""
        self._wall(False)
        r = self.page.evaluate("""() => ({
            pad: getComputedStyle(document.querySelector('.dash-card')).paddingTop,
            radius: getComputedStyle(document.querySelector('.dash-card')).borderRadius})""")
        self.assertNotEqual('0px', r['pad'], 'the stylesheet did not load')
        self.assertNotEqual('0px', r['radius'])

    def test_off_by_default(self):
        self._wall(False)
        r = self.page.evaluate("""() => ({
            sidebar: getComputedStyle(document.querySelector('.sidebar')).display,
            exit: getComputedStyle(document.querySelector('.alertwall-exit')).display})""")
        self.assertNotEqual('none', r['sidebar'])
        self.assertEqual('none', r['exit'], 'the exit button shows outside the wall')

    def test_the_card_fills_the_viewport(self):
        self._wall(True)
        box = self.page.evaluate(
            "() => document.querySelector('#page-alerts > .dash-card').getBoundingClientRect()")
        self.assertGreater(box['height'], self.H * 0.95)
        self.assertGreater(box['width'], self.W * 0.95)

    def test_it_fills_the_viewport_mid_animation_too(self):
        """.page.active runs `rp-page-in`, which puts a TRANSFORM on the page —
        and a transformed ancestor becomes the containing block for its
        position:fixed descendants. While that 140ms animation ran, the card
        sized against a 30px-tall #page-alerts instead of the viewport and the
        wall opened as a sliver.

        Whether you saw it depended on how fast the machine was, which is why
        this measures with NO settle time at all. The first probe of this
        feature waited, saw 1920x1080, and reported it working."""
        self._wall(False)
        self.page.evaluate("""() => {
            const p = document.getElementById('page-alerts');
            p.classList.remove('active');
            void p.offsetWidth;                 // force the animation to restart
            p.classList.add('active');
            document.body.classList.add('alertwall');
        }""")
        # deliberately no wait_for_timeout
        box = self.page.evaluate(
            "() => document.querySelector('#page-alerts > .dash-card').getBoundingClientRect()")
        self.assertGreater(box['height'], self.H * 0.95,
                           f'the wall opened {box["height"]:.0f}px tall — the '
                           f'page transform is a containing block again')

    def test_the_page_transform_is_neutralised(self):
        """The mechanism, not just the symptom: if a transform ever comes back
        on the page, `fixed` stops meaning the viewport."""
        self._wall(True)
        t = self.page.evaluate(
            "() => getComputedStyle(document.getElementById('page-alerts')).transform")
        self.assertEqual('none', t)

    def test_the_chrome_is_gone(self):
        self._wall(True)
        r = self.page.evaluate("""() => ({
            sidebar: getComputedStyle(document.querySelector('.sidebar')).display,
            header: getComputedStyle(document.querySelector('header')).display,
            title: getComputedStyle(document.querySelector('.page-title')).display,
            other: getComputedStyle(document.querySelector('#page-devices')).display})""")
        for k, v in r.items():
            with self.subTest(part=k):
                self.assertEqual('none', v)

    def test_the_table_scrolls_inside_instead_of_off_the_screen(self):
        """min-height:0 on the flex child is load-bearing: a flex item's default
        min-height is auto, so without it the table refuses to shrink and pushes
        its own scrollbar off the bottom of a screen nobody is sitting at."""
        self._wall(True)
        r = self.page.evaluate("""() => {
            const t=document.querySelector('.table-card');
            return {scrolls: t.scrollHeight > t.clientHeight + 1,
                    pageScrolls: document.documentElement.scrollHeight > innerHeight + 2,
                    hOverflow: document.documentElement.scrollWidth > innerWidth + 1};}""")
        self.assertTrue(r['scrolls'], 'the table does not scroll internally')
        self.assertFalse(r['pageScrolls'], 'the page itself scrolls')
        self.assertFalse(r['hOverflow'])

    def test_a_modal_opened_from_the_wall_is_on_top(self):
        """The reason the root is fullscreened rather than the card."""
        self._wall(True)
        top = self.page.evaluate("""() => {
            const m=document.querySelector('#m .modal').getBoundingClientRect();
            const el=document.elementFromPoint(m.left+m.width/2, m.top+m.height/2);
            return el ? (el.className || el.tagName) : null;}""")
        self.assertIn('modal', str(top),
                      'a dialog opened from the wall renders behind it')

    def test_a_toast_is_visible_on_the_wall(self):
        self._wall(True)
        r = self.page.evaluate("""() => {
            const c=document.getElementById('toast-container');
            c.innerHTML='';
            const t=document.createElement('div');
            t.className='toast success'; t.textContent='Acknowledged';
            c.appendChild(t); t.classList.add('show');
            const b=t.getBoundingClientRect();
            return {h:b.height, top:(document.elementFromPoint(b.left+b.width/2,b.top+b.height/2)||{}).className};}""")
        self.assertGreater(r['h'], 20)
        self.assertIn('toast', str(r['top']))

    def test_it_is_bigger_than_the_normal_view(self):
        """The point of the wall is reading it from across a room."""
        self._wall(False)
        small = self.page.evaluate(
            "() => getComputedStyle(document.querySelector('#page-alerts table')).fontSize")
        self._wall(True)
        big = self.page.evaluate(
            "() => getComputedStyle(document.querySelector('#page-alerts table')).fontSize")
        self.assertGreater(float(big[:-2]), float(small[:-2]))


class TestItIsTranslated(unittest.TestCase):
    def test_the_new_strings_have_dict_entries(self):
        i18n = _I18N.read_text()
        for s in ('Full screen', 'Exit full screen', 'Leave full screen (Esc)',
                  'The alerts module is switched off'):
            with self.subTest(string=s):
                self.assertIn(s, i18n)


if __name__ == '__main__':
    unittest.main()
