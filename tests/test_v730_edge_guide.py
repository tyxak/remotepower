"""docs/edge-sources.md states numbers, defaults, permission rows and the words the
page shows. Each one is derived here from the code that ships, so the guide cannot
drift from it.

A setup guide is read by someone who is half way through a Cloudflare form, and a
wrong number or a permission row that no longer matches is the kind of mistake they
cannot see: the page just refuses. The population is derived (the request builders,
the page's phrase tables, the trap kinds), so a new one added on the code side fails
here until the guide says it.
"""
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import edge_evidence as ee  # noqa: E402
import edge_intel_handlers as eh  # noqa: E402
import ip_intel  # noqa: E402

_GUIDE_FILE = _ROOT / 'docs' / 'edge-sources.md'
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_IPI_HANDLERS = (_ROOT / 'server' / 'cgi-bin' / 'ip_intel_handlers.py').read_text()


def _guide():
    if not _GUIDE_FILE.exists():
        raise unittest.SkipTest('docs excluded from this tree')
    return _GUIDE_FILE.read_text()


def _section(text, title):
    m = re.search(r'^## %s\n(.*?)(?=^## |\Z)' % re.escape(title), text, re.S | re.M)
    assert m, 'no section "%s" in the guide' % title
    return m.group(1)


def _table(text):
    """The first pipe table in `text` as a list of cell lists, header and rule dropped."""
    rows = []
    for line in text.splitlines():
        if re.match(r'^\s*\|.*\|\s*$', line):
            cells = [c.strip() for c in line.strip().strip('|').split('|')]
            if all(re.fullmatch(r':?-{2,}:?', c) for c in cells):
                continue
            rows.append(cells)
        elif rows:
            break
    return rows[1:]


def _tables(text):
    """Every pipe table in `text`, each as a list of cell lists, header and rule dropped."""
    out, cur = [], []
    for line in text.splitlines():
        if re.match(r'^\s*\|.*\|\s*$', line):
            cells = [c.strip() for c in line.strip().strip('|').split('|')]
            if not all(re.fullmatch(r':?-{2,}:?', c) for c in cells):
                cur.append(cells)
        elif cur:
            out.append(cur[1:])
            cur = []
    if cur:
        out.append(cur[1:])
    return out


def _ticks(cell):
    return re.findall(r'`([^`]+)`', cell)


def _js_table(name):
    """{key: value} of a `const NAME = {...};` of string values in app-ipintel.js."""
    m = re.search(r'^const %s = \{(.*?)^\};' % re.escape(name), _JS, re.S | re.M)
    assert m, name
    out = {}
    for k, a, b in re.findall(r"(\w+):\s*(?:'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\")", m.group(1)):
        out[k] = (a or b).replace("\\'", "'")
    return out


def _n(n):
    return f'{n:,}'


class TestTheNumbersAreTheCodes(unittest.TestCase):
    def setUp(self):
        self.limits = {r[0]: r[1] for r in _table(_section(_guide(), 'Limits'))}

    def row(self, key):
        for k, v in self.limits.items():
            if k.startswith(key):
                return v
        self.fail('the Limits table has no row starting "%s": %s' % (key, sorted(self.limits)))

    def test_how_often_it_reads(self):
        text = self.row('How often')
        self.assertIn('Every %d minutes by default' % ip_intel.DEFAULTS['edge_poll_minutes'], text)
        lo, hi = re.search(r"\('edge_poll_minutes', (\d+), (\d+)\)", _IPI_HANDLERS).groups()
        self.assertIn('%s to %s' % (_n(int(lo)), _n(int(hi))), text)

    def test_the_look_back_and_the_lag(self):
        words = {1: 'One', 6: 'Six', 12: 'Twelve', 24: 'Twenty-four'}
        hours = eh.LOOKBACK_S // 3600
        self.assertIn(hours, words, 'extend the word map for a new look-back')
        self.assertIn(words[hours] + ' hours', self.row('How far back'))
        self.assertIn('%d seconds' % eh.LAG_S, self.row('Delay'))

    def test_zones_events_rules_and_honeypot_lines(self):
        self.assertIn('Up to %d' % ee.MAX_ZONES, self.row('Zones'))
        self.assertIn(_n(ee.MAX_EVENTS), self.row('Single events'))
        rules = self.row('Custom rules')
        self.assertIn('first %d zones' % eh.RULE_ZONES, rules)
        self.assertIn('up to %d rules' % eh.RULES_PER_ZONE, rules)
        self.assertEqual(eh.RULES_TTL_S, 3600, 'the guide says "once an hour"')
        self.assertIn('once an hour', rules)
        trap = self.row('Honeypot log')
        self.assertIn('Up to %d Workers' % ee.MAX_WORKERS, trap)
        self.assertIn('%s lines' % _n(ee.TRAP_LINES), trap)


class TestTheFieldsAreTheCard(unittest.TestCase):
    def setUp(self):
        self.guide = _guide()
        self.rows = _table(_section(self.guide, 'Step 3: Enter it in RemotePower'))

    def cell(self, label):
        for r in self.rows:
            if r[0].startswith(label) or r[0].replace('**', '').startswith(label):
                return r
        self.fail('no row for "%s"' % label)

    def test_the_defaults(self):
        d = ip_intel.DEFAULTS
        tick = lambda v: 'ticked' if v else 'unticked'   # noqa: E731
        self.assertEqual(self.cell('**Firewall events**')[-1], tick(d['edge_cf_events']))
        self.assertEqual(self.cell('**Honeypot Worker log**')[-1], tick(d['edge_trap']))
        self.assertEqual(self.cell('**Count refusals')[-1], tick(d['edge_count_list_rules']))
        self.assertEqual(self.cell('The switch at the top')[-1], tick(d['edge_enabled']))
        self.assertEqual(self.cell('**Read every')[-1], str(d['edge_poll_minutes']))
        self.assertEqual(self.cell('**Report after Cloudflare refusals**')[-1], str(d['edge_report_after']))
        self.assertEqual(self.cell('**Worker names**')[-1], '`%s`' % d['edge_workers'][0])
        self.assertEqual(d['edge_zone_ids'], [])
        self.assertEqual(self.cell('**Zones**')[-1], 'empty')
        self.assertEqual(d['edge_account_id'], '')

    def test_every_field_on_the_card_is_in_the_guide(self):
        card = _HTML[_HTML.index('id="ipintel-edge-card"'):_HTML.index('id="ipintel-edge-status-card"')]
        labels = [re.sub(r'<[^>]+>', '', m).strip() for m in re.findall(r'<label[^>]*>(.*?)</label>', card, re.S)]
        self.assertGreaterEqual(len(labels), 8, labels)
        for label in labels:
            short = re.split(r' \(', label)[0] if label.startswith(('Zones', 'Worker names')) else label
            self.assertTrue(short in self.guide, 'the card has a field the guide does not name: ' + label)

    def test_the_switch_is_worded_as_on_the_card(self):
        m = re.search(r'id="ipintel-edge"> (.*?)</label>', _HTML)
        self.assertIn(m.group(1), self.guide)


class TestThePermissionRows(unittest.TestCase):
    # what each request needs, written once: a new request builder fails the first test
    NEEDS = {
        'zones_request': ('Zone', 'Zone', '/zones'),
        'rules_request': ('Zone', 'Zone WAF', '/rulesets/phases/'),
        'firewall_request': ('Zone', 'Analytics', '/graphql'),
        'events_request': ('Zone', 'Analytics', '/graphql'),
        'trap_request': ('Account', 'Workers Observability', '/workers/observability/'),
    }

    def test_every_request_builder_has_a_row(self):
        builders = {n for n in dir(ee) if n.endswith('_request') and callable(getattr(ee, n))}
        self.assertEqual(builders, set(self.NEEDS),
                         'a request the code makes has no permission row here, or the guide: add it to the '
                         'table in step 1 and to NEEDS')

    def test_the_urls_are_what_the_rows_say(self):
        z, a = '7' * 32, 'a' * 32
        built = {
            'zones_request': ee.zones_request('t', a),
            'rules_request': ee.rules_request('t', z),
            'firewall_request': ee.firewall_request('t', [z], 1, 2),
            'events_request': ee.events_request('t', [z], 1, 2),
            'trap_request': ee.trap_request('t', a, 'trap-sink', 1, 2),
        }
        for name, req in built.items():
            self.assertIn(self.NEEDS[name][2], req['url'], name)

    def test_the_guide_lists_exactly_those_rows_and_all_are_read(self):
        rows = _table(_section(_guide(), 'Step 1: Create the API token').split('### The permission rows')[1])
        got = {(r[0], r[1]) for r in rows}
        self.assertEqual(got, {(s, p) for s, p, _u in self.NEEDS.values()})
        self.assertEqual({r[2] for r in rows}, {'Read'}, 'a token that only reads')


class TestTheWordsAreThePages(unittest.TestCase):
    """Exact sets, from the one table that lists them: a phrase the guide also says
    somewhere else must not be able to hide that its own table dropped it."""

    def setUp(self):
        self.guide = _guide()
        self.card = _tables(_section(self.guide, 'What you see'))
        self.test = _tables(_section(self.guide, 'Step 4: Test the connection'))

    def test_the_states_a_feed_can_show(self):
        row = next(r for r in self.card[0] if r[0] == '**State**')
        self.assertEqual(set(_ticks(row[1])), set(_js_table('_IPI_FEED_STATE').values()))

    def test_the_checks_test_connection_runs(self):
        names = {r[0].replace('**', '') for r in self.test[0]}
        self.assertEqual(names, set(_js_table('_IPI_CHECK').values()))

    def test_the_states_a_check_can_end_in(self):
        states = {_ticks(r[0])[0] for r in self.test[1]}
        self.assertEqual(states, set(_js_table('_IPI_CHECK_STATE').values()))

    def test_the_reasons_a_line_is_set_aside(self):
        reasons = {r[0] for r in self.card[1]}
        self.assertEqual(reasons, set(_js_table('_IPI_ASIDE').values()))

    def test_the_notes_under_the_card(self):
        flat = self.guide.replace('\n', ' ').replace('  ', ' ')
        for note in ('Rules could not be read, so a rule that also blocks an IP list cannot be told apart.',
                     'More events than one read can hold; some were not counted.',
                     'Cloudflare refused the grouped view, so the events are read one at a time.'):
            self.assertIn(note, _JS, 'the page no longer says it')
            self.assertIn(note, flat)


class TestTheHoneypotContract(unittest.TestCase):
    def test_kinds_and_actions(self):
        guide = _guide()
        part = _section(guide, 'The honeypot Worker log')
        for kind in ee._TRAP_TOKEN:
            self.assertIn('`%s`' % kind, part, kind)
        for action in ee._TRAP_DECIDED + ee._TRAP_SKIPPED:
            self.assertIn('`%s`' % action, part, action)
        self.assertIn('`trap hit`', part)


class TestTheVoice(unittest.TestCase):
    def test_it_is_a_public_page(self):
        guide = _guide()
        self.assertNotRegex(guide, r'-internal\.md')
        self.assertNotRegex(guide, r'\b[0-9a-f]{32}\b', 'a real zone or account id')
        for word in ('genuine', 'genuinely', 'verbatim', 'deliberate', 'deliberately'):
            self.assertNotRegex(guide, r'(?i)\b%s\b' % word, word)
        self.assertNotRegex(guide, r'(?i)tviweb|tvipper|atramentum|bymanden')

    def test_it_stays_inside_what_the_in_app_viewer_renders(self):
        guide = _guide()
        self.assertNotRegex(guide, r'(?m)^\s*(---|\*\*\*)\s*$', 'no horizontal rules')
        self.assertNotRegex(guide, r'!\[', 'no images')
        self.assertNotRegex(guide, r'</?[a-z]+[^>]*>', 'no HTML')

    def test_no_bold_or_code_span_crosses_a_line(self):
        """The in-app viewer matches `**bold**` and `code` one line at a time, so a span
        wrapped over two lines shows its markers. GitHub accepts it, which is why it
        reads as fine in the source."""
        fence, crossing = False, []
        for n, line in enumerate(_guide().split('\n'), 1):
            if line.strip().startswith('```'):
                fence = not fence
                continue
            if not fence and (len(re.findall(r'\*\*', line)) % 2 or line.count('`') % 2):
                crossing.append((n, line.strip()[:70]))
        self.assertEqual(crossing, [])


if __name__ == '__main__':
    unittest.main()
