"""7.4.0 — the tooltip that stands in for the browser's own.

`place()` is pure, so it is executed here in V8 with no layout engine. What the
script does to the page (takes the title, keeps the name, gives it back) needs a
browser: test_v740_tooltip_e2e.py. The wiring pins at the bottom hold what neither
can see.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from clientjs import client_js  # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                                # pragma: no cover - env dependent
    _HAVE_V8 = False

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / 'server' / 'html' / 'static' / 'js' / 'app-tooltip.js'
CSS = ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'
INDEX = ROOT / 'server' / 'html' / 'index.html'

# What the script needs at load time and nothing more: it only registers listeners.
STUBS = """
var window = globalThis;
var __listeners = [];
var document = { addEventListener: function (n) { __listeners.push(n); }, documentElement: {} };
window.addEventListener = function (n) { __listeners.push(n); };
"""


def _ctx():
    ctx = MiniRacer()
    ctx.eval(STUBS)
    ctx.eval(JS.read_text())
    return ctx


def rect(left, top, w=40, h=24):
    return {'left': left, 'top': top, 'right': left + w, 'bottom': top + h, 'width': w, 'height': h}


def place(ctx, a, t=(120, 30), v=(1000, 700), side='below'):
    import json
    return json.loads(ctx.eval(
        'JSON.stringify(RPTooltip.place(%s, {w:%d,h:%d}, {w:%d,h:%d}, %s))'
        % (json.dumps(a), t[0], t[1], v[0], v[1], json.dumps(side))))


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) not installed')
class TestPlacement(unittest.TestCase):
    def setUp(self):
        self.ctx = _ctx()

    def test_it_registers_its_listeners_and_nothing_runs_at_load(self):
        import json
        listeners = set(json.loads(self.ctx.eval('JSON.stringify(__listeners)')))
        for need in ('pointerover', 'pointerout', 'focusin', 'focusout', 'keydown',
                     'touchstart', 'click', 'scroll', 'resize', 'pointerdown'):
            self.assertIn(need, listeners)

    def test_below_and_centred_by_default(self):
        at = place(self.ctx, rect(400, 100))
        self.assertEqual(at['side'], 'below')
        self.assertEqual(at['top'], 100 + 24 + 8)
        self.assertEqual(at['left'], 400 + 20 - 60)

    def test_above_when_there_is_no_room_below(self):
        at = place(self.ctx, rect(400, 670))
        self.assertEqual(at['side'], 'above')
        self.assertEqual(at['top'], 670 - 8 - 30)

    def test_below_when_there_is_no_room_either_way(self):
        at = place(self.ctx, rect(400, 10), v=(1000, 50))
        self.assertEqual(at['side'], 'below')

    def test_it_stays_inside_the_window_on_both_edges(self):
        left = place(self.ctx, rect(0, 100))
        right = place(self.ctx, rect(980, 100))
        self.assertEqual(left['left'], 8)
        self.assertEqual(right['left'], 1000 - 120 - 8)

    def test_beside_the_sidebar(self):
        at = place(self.ctx, rect(0, 200, 56, 36), side='right')
        self.assertEqual((at['side'], at['left']), ('right', 56 + 8))
        self.assertEqual(at['top'], 200 + (36 - 30) // 2)

    def test_the_other_side_when_only_it_has_room(self):
        at = place(self.ctx, rect(960, 200, 40, 36), side='right')
        self.assertEqual(at['side'], 'left')
        rtl = place(self.ctx, rect(0, 200, 40, 36), side='left')
        self.assertEqual(rtl['side'], 'right')

    def test_no_placement_ever_leaves_the_window(self):
        """Sweep elements over a grid, with tooltips of several sizes."""
        for t in ((40, 20), (120, 30), (320, 90)):
            for x in range(0, 1000, 83):
                for y in range(0, 700, 61):
                    for side in ('below', 'right', 'left'):
                        at = place(self.ctx, rect(x, y), t=t, side=side)
                        self.assertGreaterEqual(at['left'], 8, (t, x, y, side, at))
                        self.assertLessEqual(at['left'] + t[0], 1000 - 8, (t, x, y, side, at))
                        self.assertGreaterEqual(at['top'], 8, (t, x, y, side, at))
                        self.assertLessEqual(at['top'] + t[1], 700 - 8, (t, x, y, side, at))


class TestTheWiring(unittest.TestCase):
    SRC = JS.read_text()

    def test_it_is_loaded_eagerly_and_is_not_in_the_lazy_map(self):
        html = INDEX.read_text()
        self.assertRegex(html, r'<script defer src="static/js/app-tooltip\.js\?v=[0-9.\-]+"></script>')
        self.assertNotIn("'app-tooltip.js'", client_js().split('// ===== app-tooltip.js =====')[0])

    def test_the_tooltip_is_a_direct_child_of_body(self):
        """A fixed overlay inside .container has its z-index sealed under the sidebar."""
        self.assertIn('document.body.appendChild(tip)', self.SRC)
        self.assertIn("tip.setAttribute('role', 'tooltip')", self.SRC)

    def test_it_never_writes_markup(self):
        """Titles are text. The words go in with textContent, never innerHTML."""
        self.assertIn('t.textContent = words', self.SRC)
        self.assertNotIn('innerHTML', self.SRC)

    def test_form_fields_and_frames_keep_the_browsers_tooltip(self):
        self.assertIn('INPUT|SELECT|TEXTAREA|IFRAME', self.SRC)

    def test_the_stylesheet_has_the_rule_and_it_sits_above_everything(self):
        css = CSS.read_text()
        m = re.search(r'#rp-tooltip\s*\{([^}]*)\}', css)
        self.assertIsNotNone(m, 'control: the rule was found')
        body = m.group(1)
        z = int(re.search(r'z-index:\s*(\d+)', body).group(1))
        # the highest z-index any other rule sets
        others = [int(n) for n in re.findall(r'z-index:\s*(\d{3,})', css.replace(m.group(0), ''))]
        self.assertGreater(z, max(others), 'the tooltip must top toasts, modals and the drawer')
        for token in ('var(--surface)', 'var(--text)', 'var(--hair)'):
            self.assertIn(token, body)
        self.assertNotRegex(body, r'#[0-9a-fA-F]{3,8}\b', 'a literal colour will not follow the theme')
        self.assertRegex(body, r'font-size:\s*12px')

    def test_no_inline_style_or_handler_in_the_script(self):
        self.assertNotRegex(self.SRC, r'setAttribute\(\s*[\'"]style')
        self.assertNotRegex(self.SRC, r'\bon[a-z]+\s*=\s*[\'"]')


if __name__ == '__main__':
    unittest.main()
