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
        self.assertIn('body.alertwall #alerts-inbox-card', css)

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
        """Renders the REAL index.html, not a hand-built fixture.

        The first version of this harness built its own alerts page with one
        .dash-card in it. The real page has three — the inbox, the MTTR
        timeline and "What happened last time" — so `#page-alerts > .dash-card`
        promoting ALL of them to position:fixed inset:0, last-in-DOM painting
        on top, was invisible here and shipped. The wall opened on the wrong
        card and a user reported it within the hour.

        A fixture encodes what I already believe the markup is, so it can only
        confirm it. Two details the fixture also got wrong, both load-bearing:
        the alerts page ships as an inert <template> stamped on first visit,
        and #app carries d-none until login."""
        html = (_ROOT / 'server/html/index.html').read_text()
        html = re.sub(r'<script\b.*?</script>', '', html, flags=re.S)
        # Strip the stylesheet links: the real sheet loading beside the injected
        # copy is how a mutation test of this CSS silently tests the shipped
        # rules instead of the mutated ones.
        html, n = re.subn(r'<link[^>]+rel="stylesheet"[^>]*>', '', html)
        assert n >= 1, 'no stylesheet link found to strip'
        html = html.replace('</head>', '<style>%s</style></head>' % _CSS.read_text())
        cls._pw = sync_playwright().start()
        cls._b = cls._pw.chromium.launch()
        cls.page = cls._b.new_page()
        cls.page.set_viewport_size({'width': cls.W, 'height': cls.H})
        cls.page.set_content(html)
        cls.page.evaluate("""(rows) => {
            document.getElementById('app').classList.remove('d-none');   // shown after login
            // exactly what showPage() does for a lazy page
            const t = document.querySelector('template[data-page-tpl="alerts"]');
            if (t) t.parentNode.insertBefore(t.content.cloneNode(true), t);
            document.querySelectorAll('.page').forEach(e => e.classList.remove('active'));
            document.getElementById('page-alerts').classList.add('active');
            // a full inbox, so the table has something to scroll
            document.getElementById('alerts-tbody').innerHTML = rows;
        }""", ''.join('<tr><td>h</td><td>device_offline</td></tr>' for _ in range(60)))
        cls.page.wait_for_timeout(250)   # let the 140ms page-in animation settle

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
            pad: getComputedStyle(document.getElementById('alerts-inbox-card')).paddingTop,
            radius: getComputedStyle(document.getElementById('alerts-inbox-card')).borderRadius})""")
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
            "() => document.getElementById('alerts-inbox-card').getBoundingClientRect()")
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
            "() => document.getElementById('alerts-inbox-card').getBoundingClientRect()")
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
            title: getComputedStyle(document.querySelector('#page-alerts > .page-title')).display,
            other: getComputedStyle(document.querySelector('#page-devices')).display})""")
        for k, v in r.items():
            with self.subTest(part=k):
                self.assertEqual('none', v)

    def test_the_table_scrolls_inside_instead_of_off_the_screen(self):
        """A flex item's automatic minimum size is its content, so the table
        would rather push its own scrollbar off the bottom of a screen nobody is
        sitting at than shrink. overflow-y:auto on the item zeroes that minimum,
        which is why no explicit min-height:0 is needed here."""
        self._wall(True)
        r = self.page.evaluate("""() => {
            const t=document.querySelector('#alerts-inbox-card .table-card');
            return {scrolls: t.scrollHeight > t.clientHeight + 1,
                    pageScrolls: document.documentElement.scrollHeight > innerHeight + 2,
                    hOverflow: document.documentElement.scrollWidth > innerWidth + 1};}""")
        self.assertTrue(r['scrolls'], 'the table does not scroll internally')
        self.assertFalse(r['pageScrolls'], 'the page itself scrolls')
        self.assertFalse(r['hOverflow'])

    def test_a_modal_opened_from_the_wall_is_on_top(self):
        """The reason the root is fullscreened rather than the card."""
        self._wall(True)
        # The dialog is opened HERE and closed again, not left open by
        # setUpClass — an overlay covering the viewport silently swallows every
        # other test's hit-test at the centre of the screen.
        self.page.evaluate(
            "()=>document.getElementById('log-ack-modal').classList.add('active')")
        self.addCleanup(self.page.evaluate,
            "()=>document.getElementById('log-ack-modal').classList.remove('active')")
        # Ask whether the point lands INSIDE the dialog, not what the topmost
        # node is called — the real dialog has form controls at its centre, so
        # pinning the class name only ever described the fixture's markup.
        top = self.page.evaluate("""() => {
            const d=document.querySelector('#log-ack-modal .modal');
            const m=d.getBoundingClientRect();
            const el=document.elementFromPoint(m.left+m.width/2, m.top+m.height/2);
            return {inside: !!(el && d.contains(el)),
                    hit: el ? (el.className || el.tagName) : null};}""")
        self.assertTrue(top['inside'],
                        'a dialog opened from the wall renders behind it; the '
                        'wall painted %r over its centre' % (top['hit'],))

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

    def test_the_wall_shows_the_inbox_and_not_a_neighbouring_card(self):
        """The bug this file exists to keep out.

        #page-alerts has three sibling .dash-cards. Promoting them by
        `#page-alerts > .dash-card` gave all three position:fixed inset:0 —
        same stacking context, same auto z-index — so the LAST in DOM order
        painted over the others and the wall opened on "What happened last
        time". Every rule involved was individually correct; only the rendered
        result shows which card an operator is actually looking at."""
        self._wall(True)
        r = self.page.evaluate("""() => {
            const cards=[...document.querySelectorAll('#page-alerts > .dash-card')];
            const shown=cards.filter(c=>getComputedStyle(c).display!=='none');
            const e=document.elementFromPoint(innerWidth/2, innerHeight/2);
            const c=e&&e.closest('.dash-card');
            const t=c&&c.querySelector('.section-title');
            return {total: cards.length, shown: shown.length,
                    onTopId: c ? (c.id||'(no id)') : null,
                    onTop: t ? t.textContent.trim() : null};}""")
        # Population control: if the page ever ships with a single card this
        # test would pass without exercising anything, so say so instead.
        self.assertGreater(r['total'], 1,
                           'the alerts page no longer has sibling cards — this '
                           'test can no longer see the bug it was written for')
        self.assertEqual('alerts-inbox-card', r['onTopId'],
                         'the wall opened on %r' % (r['onTop'],))
        self.assertEqual(1, r['shown'],
                         'the wall must promote exactly one card; %d are visible'
                         % r['shown'])

    def test_no_page_background_shows_beside_the_wall(self):
        """html reserves a scrollbar gutter permanently (scrollbar-gutter:
        stable), so hiding body's overflow leaves a strip of page background
        down the right edge of an otherwise full-bleed wall."""
        self._wall(True)
        r = self.page.evaluate("""() => {
            const c=document.getElementById('alerts-inbox-card').getBoundingClientRect();
            return {w: Math.round(c.width), vw: innerWidth,
                    edge: document.elementFromPoint(innerWidth-2, innerHeight/2)
                          ?.closest('#alerts-inbox-card') ? 'card' : 'not the card'};}""")
        self.assertEqual(r['vw'], r['w'],
                         'the card stops %dpx short of the right edge' % (r['vw']-r['w']))
        self.assertEqual('card', r['edge'])

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
