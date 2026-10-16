"""Every text colour clears WCAG AA in every theme, computed from the stylesheet.

At v7.4.0 a browser census (axe color-contrast on nine populated pages, every
theme) found 11 of 13 themes failing, 2,405 serious nodes in all: --muted under
4.5:1 on the surfaces of nine palettes, status colours used as text (Nord's red
was 2.45:1 on its own surface), hard-coded severity inks (#ff8c00 was 2.05:1 on
a light theme), and 49 rules that painted a status colour as text on its own
tint while the --*-on-tint inks existed for exactly that. The axe gate in
test_a11y_axe runs the default theme only, so none of it was seen.

The palettes now carry ink tokens: --muted (adjusted in place, it is text by
nature), --red/green/amber/orange-ink for status text, --*-on-tint for text on a
family's tint, and --on-red / --on-amber for text on a solid fill. The status
colours themselves stay fills: a dot or a bar keeps its hue.

This gate replays the cascade (test_v642_css.Palettes) for every palette and
accent and checks each ink against every background it is painted on; and it
holds the rule shapes that keep text on the inks. The browser census over the
real pages is test_v740_theme_contrast_e2e.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_v642_css as C  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_CSS = _ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
AA = 4.5
FAMILIES = ('muted', 'red', 'green', 'amber', 'orange', 'purple')
_TINT_BG = re.compile(r'background(?:-color)?\s*:\s*(rgba\([^)]*\)|var\(--(?:green|amber|red)-soft\))')


def _rules(src):
    """[(selector, declaration body)] for every innermost block, comments removed."""
    nc = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    return [(m.group(1).strip(), m.group(2)) for m in re.finditer(r'([^{}]*)\{([^{}]*)\}', nc)]


def tints_by_family(src):
    """{family: {tint}} for every rule that paints a family's on-tint ink on a tint."""
    out = {f: set() for f in FAMILIES}
    for _sel, body in _rules(src):
        col = re.search(r'(?<![-\w])color\s*:\s*var\(--(muted|red|green|amber|orange|purple)-on-tint\)', body)
        bg = _TINT_BG.search(body)
        if col and bg:
            out[col.group(1)].add(bg.group(1).replace(' ', ''))
    return out


def _soft(src, light):
    blocks = re.findall(r'\{([^{}]*--green-soft[^{}]*)\}', src)
    pick = blocks[1] if light and len(blocks) > 1 else blocks[0]
    return {k: v.strip() for k, v in re.findall(r'(--(?:green|amber|red)-soft)\s*:\s*([^;]+);', pick)}


def failures(src):
    """Every (palette, ink, background, ratio) below AA, and how many pairs were checked."""
    pal = C.Palettes(src)
    tints = tints_by_family(src)
    bad, checked = [], 0
    states = [('dark', None, False), ('light', None, True)]
    for t in pal.themes:
        states.append((t, t, C.luminance(pal.resolve(theme=t)['--bg']) > 0.5))
    for name, theme, light in states:
        vals = pal.resolve(theme=theme, light=light)
        vals.update(_soft(src, light))
        surfaces = [vals['--bg'], vals['--surface'], vals['--surface2']]
        plain = list(surfaces)
        if vals.get('--hair-2', '').startswith('rgba'):
            plain += [C._over(vals['--hair-2'], s) for s in surfaces]
        for accent in [None] + pal.accents:
            soft = pal.resolve(theme=theme, accent=accent, light=light).get('--accent-soft')
            if soft:
                plain += [C._over(soft, s) for s in surfaces]

        def check(token, bgs, ink=None):
            nonlocal checked
            ink = ink or vals.get(token)
            if ink is None:
                bad.append((name, token, 'not defined', 0))
                return
            for bg in bgs:
                checked += 1
                r = C.contrast(ink, bg)
                if r < AA:
                    bad.append((name, token, bg, round(r, 2)))

        for token in ('--text', '--muted', '--red-ink', '--green-ink', '--amber-ink', '--orange-ink', '--purple-ink'):
            check(token, plain)
        for fam in FAMILIES:
            tint_bgs = []
            for t in tints[fam]:
                m = re.fullmatch(r'var\((--[\w-]+)\)', t)
                tint = vals.get(m.group(1), t) if m else t
                tint_bgs += [C._over(tint, s) for s in surfaces]
            check('--%s-on-tint' % fam, tint_bgs)
        check('--on-red', [vals['--red']])
        check('--on-amber', [vals['--amber']])
    return bad, checked


class TestEveryInkClearsAA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _CSS.read_text()

    def test_the_population(self):
        """Control: the palettes, accents and tints were found, and many pairs checked."""
        pal = C.Palettes(self.src)
        self.assertGreaterEqual(len(pal.themes), 11)
        tints = tints_by_family(self.src)
        for fam in ('red', 'green', 'amber', 'muted'):
            self.assertTrue(tints[fam], 'no tint found for ' + fam)
        _, checked = failures(self.src)
        self.assertGreater(checked, 3000)

    def test_the_gate_sees_the_old_failures(self):
        """Control: Nord's text red and the old light --muted fail when put back."""
        old = self.src.replace('--red-ink:#eacacd', '--red-ink:#bf616a')
        self.assertNotEqual(old, self.src, 'control: the Nord ink is where this test expects it')
        bad, _ = failures(old)
        self.assertTrue(any(n == 'nord' and t == '--red-ink' for n, t, _bg, _r in bad))

    def test_every_ink_in_every_theme(self):
        bad, _ = failures(self.src)
        self.assertEqual(bad, [], '\n'.join('%-16s %-16s on %s = %s:1' % b for b in bad))


# A hard-coded text colour drawn on something other than the theme's surfaces,
# with the reason. Everything else is computed against every theme.
HEX_EXEMPT = {
    '.isl-5': 'the demo banner link, on the banner\'s own fixed blue-violet gradient (.isl-4)',
}


def _strip_print(css):
    """The stylesheet less its @media print blocks (those paint on white paper)."""
    while True:
        m = re.search(r'@media\s+print\s*\{', css)
        if not m:
            return css
        depth, j = 1, m.end()
        while depth and j < len(css):
            depth += {'{': 1, '}': -1}.get(css[j], 0)
            j += 1
        css = css[:m.start()] + css[j:]


def hex_text_failures(src):
    """(selector, ink, palette, ratio) for every hard-coded text colour under AA,
    against the theme surfaces, or its own background over them when it sets one."""
    pal = C.Palettes(src)
    states = [('dark', None, False), ('light', None, True)]
    for t in pal.themes:
        states.append((t, t, C.luminance(pal.resolve(theme=t)['--bg']) > 0.5))
    bad, seen = [], 0
    for sel, body in _rules(_strip_print(re.sub(r'/\*.*?\*/', '', src, flags=re.S))):
        m = re.search(r'(?<![-\w])color\s*:\s*(#[0-9a-fA-F]{3,8})\b', body)
        if not m or 'print' in sel or sel.split(',')[-1].strip() in HEX_EXEMPT:
            continue
        seen += 1
        ink = m.group(1)
        own = re.search(r'background(?:-color)?\s*:\s*(#[0-9a-fA-F]{3,8}|rgba?\([^)]*\))\s*[;}]?', body)
        only = re.match(r'body\[data-theme="([\w-]+)"\]', sel.strip())
        for name, theme, light in states:
            if sel.strip().startswith('body.light') and not light:
                continue
            if only and only.group(1) != theme:
                continue
            v = pal.resolve(theme=theme, light=light)
            for surface in (v['--bg'], v['--surface'], v['--surface2']):
                bg = surface
                if own:
                    bg = C._over(own.group(1), surface) if own.group(1).startswith('rgba') else own.group(1)
                r = C.contrast(ink, bg)
                if r < AA:
                    bad.append((sel.strip()[-50:], ink, name, round(r, 2)))
                    break
    return bad, seen


class TestHardCodedTextColours(unittest.TestCase):
    """A fixed hex text colour cannot follow the theme, so it has to read in all of them.

    Fifteen did not at v7.4.0 (the command badges, the SNMP and GPU pills, the
    favourite stars, the Tasks board headers), on pages the browser census does
    not visit; they moved to the theme's inks."""

    def test_the_scan_sees_a_fixed_colour_that_fails(self):
        src = _CSS.read_text() + '\n.rp-control { color: #a78bfa; }\n'
        bad, seen = hex_text_failures(src)
        self.assertGreater(seen, 3, 'control: the hard-coded colours were found')
        self.assertTrue(any(b[0].endswith('.rp-control') for b in bad))

    def test_every_hard_coded_text_colour_reads_in_every_theme(self):
        bad, _ = hex_text_failures(_CSS.read_text())
        self.assertEqual(bad, [], 'use a theme ink (var(--X-ink), var(--X-on-tint)), '
                                  'or list it in HEX_EXEMPT with what it is drawn on:\n'
                         + '\n'.join('%-50s %s in %s = %s:1' % b for b in bad))


class TestTextUsesTheInks(unittest.TestCase):
    """The rule shapes that keep text on the inks."""

    @classmethod
    def setUpClass(cls):
        cls.src = _CSS.read_text()

    def test_no_rule_paints_a_fill_colour_as_text(self):
        bad = [sel[-70:] for sel, body in _rules(self.src)
               if re.search(r'(?<![-\w])color\s*:\s*var\(--(red|green|amber|orange|purple)\)', body)]
        self.assertEqual(bad, [], 'text uses var(--X-ink), or var(--X-on-tint) on a tint')

    def test_text_on_a_tint_uses_the_on_tint_ink(self):
        bad = [sel[-70:] for sel, body in _rules(self.src)
               if _TINT_BG.search(body)
               and re.search(r'(?<![-\w])color\s*:\s*var\(--(muted|red-ink|green-ink|amber-ink|orange-ink|purple-ink)\)', body)]
        self.assertEqual(bad, [], 'a rule with a tinted background paints its text with an -on-tint ink')

    def test_scripts_set_text_colour_through_the_inks(self):
        bad = []
        for p in sorted(_JS.glob('*.js')):
            if p.name == 'i18n.js':
                continue
            for n, ln in enumerate(p.read_text().split('\n'), 1):
                if re.search(r'\.style\.color\s*=', ln) and re.search(r'var\(--(red|green|amber|orange)\)', ln):
                    bad.append('%s:%d' % (p.name, n))
        self.assertEqual(bad, [])
        app = (_JS / 'app.js').read_text()
        self.assertIn('node.style.color = _textInk(node.dataset.color)', app,
                      'data-color always sets text colour, so it goes through _textInk')
        self.assertIn("el.style.color = _textInk(el.dataset.color)", app)


if __name__ == '__main__':
    unittest.main()
