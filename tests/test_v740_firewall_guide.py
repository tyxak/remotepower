"""docs/firewall-sources.md states numbers, labels, example log lines and report texts.
Each one is derived here from the code that ships, so the guide cannot drift from it.

The guide is read by someone half way through a firewall's logging form, with a
Log sources card open beside it. A threshold that moved, a prefix word the reader no
longer accepts, or an example line in a layout the parser stopped reading is the kind of
mistake they cannot see: the page just shows nothing. So:

  * the numbers come from the constants of the reader and the intake;
  * the words a RouterOS prefix must contain come from the reader's own list;
  * every example log line in the guide is run through the real reader and must be read
    as what the guide says it is;
  * every report text in the guide equals what `evidence_comment` writes for that evidence;
  * the labels the guide quotes exist on the page, and the page's phrase tables agree with
    the server's.
"""
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import appliance_evidence as ae  # noqa: E402
import ip_intel  # noqa: E402
import ip_intel_handlers as iih  # noqa: E402
import threat_evidence as te  # noqa: E402

_GUIDE_PATH = _ROOT / 'docs' / 'firewall-sources.md'
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text(encoding='utf-8')
_API = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text(encoding='utf-8')


def _guide():
    if not _GUIDE_PATH.exists():
        raise unittest.SkipTest('docs excluded from this tree')
    return _GUIDE_PATH.read_text(encoding='utf-8')


def _flat(text):
    """The text with every run of whitespace a single space: the guide wraps its lines, so a
    bold label or a sentence can break across two."""
    return ' '.join(text.split())


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


def _code_lines(text):
    """Every line inside a fenced block."""
    out, fence = [], False
    for line in text.splitlines():
        if line.strip().startswith('```'):
            fence = not fence
        elif fence:
            out.append(line.strip())
    return out


def _js_table(name):
    """{key: value} of a `const NAME = {...};` of string values in app-ipintel.js."""
    m = re.search(r'^const %s = \{(.*?)^\};' % re.escape(name), _JS, re.S | re.M)
    assert m, name
    out = {}
    for k, a, b in re.findall(r"(\w+):\s*(?:'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\")", m.group(1)):
        out[k] = (a or b).replace("\\'", "'")
    return out


def _const(name):
    m = re.search(r'^%s\s*=\s*(\d+)' % re.escape(name), _API, re.M)
    assert m, 'api.py has no %s' % name
    return int(m.group(1))


def _n(n):
    return f'{n:,}'


def _on_the_page(label):
    """True when `label` is the text of a label, a section title or a form-label heading on the
    page. Prose that merely mentions it (the What's new card says "Security -> Threat intel ->
    Firewalls and routers") does not count: a renamed card would still pass a plain substring."""
    return re.search(r'(?:>|<input[^>]*>)\s*%s[^<]*</(?:label|div)>' % re.escape(label), _HTML) is not None


class TestTheNumbersAreTheCodes(unittest.TestCase):
    def setUp(self):
        self.guide = _guide()

    def test_what_makes_an_address_a_scanner(self):
        g = self.guide
        self.assertIn(f'**{ae.SCAN_PORTS} different ports**', g)
        self.assertIn(f'**{ae.SCAN_PACKETS} times**', g)
        row = [r for r in _table(_section(g, 'What it reads')) if r[0] == 'Refused packets'][0]
        self.assertIn(f'tries {ae.SCAN_PORTS} different ports, or is refused {ae.SCAN_PACKETS} times, '
                      f'within {ae.WINDOW_S // 60} minutes', row[2])
        self.assertEqual(ae.WINDOW_S % 60, 0)
        self.assertIn(f'within {ae.WINDOW_S // 60} minutes of its first refused packet', _flat(g))

    def test_two_hits_on_the_decoy_port(self):
        row = [r for r in _table(_section(self.guide, 'What it reads')) if r[0] == 'Decoy port'][0]
        self.assertEqual(ae.TRAP_HITS, 2, 'the guide says twice')
        self.assertIn('connects to the port twice', row[2])
        self.assertIn('Two connections are enough', _flat(self.guide))

    def test_the_limits_table(self):
        limits = {r[0]: r[1] for r in _table(_section(self.guide, 'Limits'))}

        def row(prefix):
            for k, v in limits.items():
                if k.startswith(prefix):
                    return v
            self.fail('the Limits table has no row starting "%s": %s' % (prefix, sorted(limits)))

        self.assertIn(_n(ae.MAX_TRACKED), row('Addresses counted per firewall'))
        self.assertIn(str(ae.MAX_PORTS), row('Ports remembered'))
        self.assertGreater(ae.MAX_PORTS, ae.SCAN_PORTS, 'the guide says "more than the 10 a scan needs"')
        self.assertIn(f'{ae.WINDOW_S // 60} minutes', row('Time an address is counted over'))
        self.assertIn(str(_const('_SYSLOG_MAX_LINES_PER_POST')), row('Lines in one post'))
        self.assertIn(_n(_const('_SYSLOG_MAX_LINE')), row('Line length kept'))
        self.assertIn(_n(iih.SENSOR_EVENTS_PER_HOUR), row('Addresses queued from one host'))
        self.assertIn('UTC', row('Counts on the Log sources card'))

    def test_the_cut_off_of_a_long_line_is_the_intakes(self):
        self.assertIn(f'keeps {_n(_const("_SYSLOG_MAX_LINE"))} characters of a line', _flat(self.guide))

    def test_the_defaults_it_quotes(self):
        g = self.guide
        self.assertEqual(ip_intel.DEFAULTS['report_min_count'], 10)
        self.assertIn('(10 by default)', g)
        thr, win = _const('BRUTE_THRESHOLD'), _const('BRUTE_WINDOW_SECONDS') // 60
        self.assertIn(f'{thr} failures in {win} minutes', g)
        self.assertIs(ip_intel.DEFAULTS['appliance_enabled'], False)
        self.assertIn('It stays off until you turn it on', _flat(g))

    def test_the_categories_it_names(self):
        g = self.guide
        for cls in ('port_scan', 'decoy_port'):
            self.assertEqual(te.CLASSES[cls]['abuseipdb'], (14,), cls)
            self.assertEqual(te.CLASSES[cls]['sniffcat'], (4,), cls)
        self.assertIn('AbuseIPDB category 14 and SniffCat category 4', _flat(g))
        ssh, other = ip_intel.CATEGORIES['ssh'], ip_intel.CATEGORIES['other']
        self.assertEqual((ssh['abuseipdb'], ssh['sniffcat']), ([18, 22], [17, 18]))
        self.assertEqual((other['abuseipdb'], other['sniffcat']), ([18], [17]))
        self.assertIn('18 and 22 at AbuseIPDB and 17 and 18 at SniffCat', g)
        self.assertIn('Any other failed sign-in is 18 at AbuseIPDB and 17 at SniffCat', _flat(g))


class TestTheWordsAreTheReaders(unittest.TestCase):
    def setUp(self):
        self.guide = _guide()

    def test_the_prefix_words_that_mark_a_refusal(self):
        para = re.search(r'A prefix that contains (.*?)\s+marks the rule as a refusal', self.guide, re.S)
        self.assertIsNotNone(para, 'the paragraph about the prefix is gone')
        said = re.findall(r'`([^`]+)`', para.group(1))
        self.assertEqual(said, list(ae.DROP_WORDS), 'the guide lists the words the reader accepts, in its order')

    def test_the_decoy_prefix(self):
        g = self.guide
        self.assertIn(f'must contain `{ae.TRAP_MARK}`', _flat(g))
        self.assertIn(f'log-prefix={ae.TRAP_MARK}', g)
        self.assertIn(f'firewall,info {ae.TRAP_MARK} input:', g)

    def test_the_login_lines(self):
        """The lines in the sign-in table are ones the brute-force counter was given a pattern for,
        and so is each service the RouterOS row names."""
        pats = [p for group in ae.LOGIN_PATTERNS.values() for p in group]
        rows = {r[0]: r[1] for r in _table(_section(self.guide, 'Failed sign-ins'))}
        ros = re.findall(r'`([^`]+)`', rows['RouterOS, any service'])
        self.assertTrue(ros[0].startswith('login failure for user admin from 203.0.113.9 via '), ros)
        for via in ['ssh'] + [w.replace('via ', '') for w in ros[1:]]:
            line = f'login failure for user admin from 203.0.113.9 via {via}'
            self.assertTrue(any(p.search(line) for p in pats), f'no pattern reads {line!r}')
        web = re.findall(r'`([^`]+)`', rows['OPNsense, web interface'])[0]
        self.assertTrue(any(p.search(web) for p in pats), web)
        ssh = re.findall(r'`([^`]+)`', rows['OPNsense, SSH'])[0]
        self.assertIn('Failed password for root from 203.0.113.9 port', ssh)

    def test_the_signature_table_follows_the_classifier(self):
        """One row of the Suricata table per rule of the classifier, in its order, and a
        signature built from the words of each row is filed under the class it names."""
        rows = _table(_section(self.guide, 'OPNsense').split('### Suricata', 1)[1].split('### CrowdSec', 1)[0])
        said = [r[1] for r in rows]
        by_class = [te.CLASSES[c]['phrase'] for c, _ in ae._IDS_RULES]
        for phrase in by_class:
            self.assertIn(phrase, said, 'a class the classifier can return is missing from the table')
        samples = {
            'remote code execution attempts': 'ET EXPLOIT Apache Log4j RCE Attempt',
            'SQL injection': 'ET WEB_SERVER SQL Injection Attempt',
            'cross-site scripting': 'ET WEB_SERVER XSS Attempt',
            'path traversal': 'ET WEB_SERVER Directory Traversal',
            'request flooding': 'ET DOS Possible Flood',
            'vulnerability scanning': 'ET SCAN Nmap Scripting Engine',
            'FTP brute force': 'ET FTP login brute force',
            'mail login brute force': 'ET SMTP auth brute force',
            'service login brute force': 'ET RDP login brute force',
            'port scanning': 'ET SCAN Potential SSH Scan',
            'probing for exposed files and admin pages': 'ET WEB_SERVER Something',
        }
        for phrase, sig in samples.items():
            cls = ae.classify_ids(sig, 'Attempted Information Leak' if phrase.startswith('probing') else '')
            self.assertEqual(te.CLASSES[cls]['phrase'], phrase, sig)

    def test_what_the_classifier_drops(self):
        for sig in ('ET DROP Dshield Block Listed Source', 'ET CINS Active Threat Intelligence Poor Reputation IP',
                    'ET COMPROMISED Known Compromised or Hostile Host', 'ET TOR Known Tor Exit Node',
                    'ET INFO Possible Kali Linux Hostname', 'ET POLICY Dropbox', 'ET CHAT Skype', 'ET GAMES Steam',
                    'ET P2P BitTorrent', 'ET DNS Query', 'ET MALWARE Win32/Foo', 'ET TROJAN Foo', 'ET CNC Foo',
                    'SURICATA STREAM reassembly', 'ET SCAN outbound probe'):
            self.assertIsNone(ae.classify_ids(sig, ''), sig)


class TestTheExamplesAreRead(unittest.TestCase):
    """Every example log line in the guide goes through the reader."""

    def setUp(self):
        self.lines = _code_lines(_guide())

    def one(self, prefix):
        found = [ln for ln in self.lines if ln.startswith(prefix)]
        self.assertEqual(len(found), 1, f'expected one example line starting {prefix!r}: {found}')
        return found[0]

    def test_the_pf_line(self):
        kind, rec = ae.read_line(self.one('1 2026-'))
        self.assertEqual(kind, 'fw')
        self.assertEqual((rec['action'], rec['dir'], rec['proto'], rec['src'], rec['dport'], rec['flags']),
                         ('block', 'in', 'tcp', '203.0.113.9', 22, {'S'}))
        self.assertEqual(ae.probe_of(rec), (22, False), 'the example is a refused probe')

    def test_the_routeros_lines(self):
        refused = ae.parse_routeros_firewall(self.one('firewall,info drop-in'))
        self.assertEqual((refused['action'], refused['trap'], refused['proto'], refused['dport']),
                         ('block', False, 'tcp', 23))
        self.assertEqual(ae.probe_of(refused), (23, False))
        decoy = ae.parse_routeros_firewall(self.one('firewall,info rp-trap'))
        self.assertEqual((decoy['trap'], decoy['dport'], decoy['flags']), (True, 2222, {'S'}))
        self.assertEqual(ae.probe_of(decoy), (2222, True))
        # and as the router sends them, behind a BSD header
        kind, rec = ae.read_line('Oct 17 09:42:22 MikroTik ' + self.one('firewall,info rp-trap'))
        self.assertEqual((kind, rec['trap']), ('fw', True))

    def test_the_suricata_line(self):
        msg = self.one('[1:')
        kind, rec = ae.read_line('1 2026-10-17T09:42:22+02:00 OPNsense01.example.org suricata 51234 - - ' + msg)
        self.assertEqual(kind, 'ids')
        self.assertEqual((rec['src'], rec['cls'], rec['dport']), ('203.0.113.9', 'port_scan', 22))

    def test_the_crowdsec_line(self):
        line = self.one('crowdsec alert ')
        rec = ae.parse_crowdsec(line)
        self.assertEqual((rec['scenario'], rec['src'], rec['events'], rec['decision']),
                         ('crowdsecurity/ssh-bf', '203.0.113.9', 6, True))
        alert = {'scenario': 'crowdsecurity/ssh-bf', 'source': {'ip': '203.0.113.9', 'scope': 'Ip'},
                 'events_count': 6, 'decisions': [{'origin': 'crowdsec', 'type': 'ban'}]}
        self.assertEqual(ae.crowdsec_lines([alert]), [line], 'the guide shows the line RemotePower writes')

    def test_no_example_uses_a_real_address(self):
        """Documentation ranges only (RFC 5737), so a reader cannot paste someone's address."""
        for ln in self.lines:
            for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', ln):
                if ip.startswith(('203.0.113.', '192.0.2.', '198.51.100.', '10.', '127.', '0.')):
                    continue
                self.assertTrue(ip.startswith(('64240', '2909')) or re.fullmatch(r'\d+\.\d+\.\d+\.\d+', ip) is None,
                                f'{ip} in {ln[:60]!r}')


class TestTheReportTexts(unittest.TestCase):
    def test_each_text_is_what_the_server_writes(self):
        said = [ln for ln in _code_lines(_guide()) if 'reported by RemotePower' in ln]
        self.assertEqual(len(said), 3)
        scan = {'ip': '185.220.101.7', 'first': 1000, 'last': 1000 + 16 * 60, 'src': {'fw': 38},
                'tok': {'fw': {'fw:scan': 38}}}
        decoy = {'ip': '185.220.101.7', 'first': 1000, 'last': 1000, 'src': {'dp': 2},
                 'tok': {'dp': {'dp:hit': 2}}, 'trp': 1}
        ids = {'ip': '185.220.101.7', 'first': 1000, 'last': 1000, 'src': {'ids': 12},
               'tok': {'ids': {'ids:scanner': 12}}}
        wrote = []
        for raw in (scan, decoy, ids):
            ev = te.normalize_event(raw, now=1000 + 16 * 60, families=te.APPLIANCE_SOURCES)
            self.assertIsNotNone(ev, raw)
            wrote.append(ip_intel.evidence_comment(ev))
        self.assertEqual(said, wrote)


class TestTheLabelsAreThePage(unittest.TestCase):
    def test_the_labels_the_guide_quotes_exist_on_the_page(self):
        g = _flat(_guide())
        for label in ('Firewalls and routers', 'Read the syslog of firewalls and routers',
                      'Report attackers back to both services', 'Report after attempts',
                      'Never block or report', 'Never report an address when all it did was',
                      'Log sources'):
            self.assertIn(label, g, label)
            self.assertTrue(_on_the_page(label), f'{label!r} is not the text of a label or a title on the page')
        self.assertFalse(_on_the_page('Firewall sources'),
                         'control: a phrase that only prose uses must not count as a label')

    def test_the_source_names_on_the_log_sources_card(self):
        sources = _js_table('_IPI_SOURCE')
        g = _guide()
        for kind, label in (('fw', 'Firewall log'), ('ids', 'Intrusion detection alerts'), ('cs', 'CrowdSec alerts')):
            self.assertEqual(sources[kind], label)
            self.assertIn(f'| {label} |', g)
        self.assertEqual(sources['dp'], 'Decoy port')

    def test_the_page_and_the_server_say_the_same_about_the_new_classes(self):
        classes = _js_table('_IPI_CLASS')
        for cls in ('port_scan', 'decoy_port'):
            self.assertEqual(classes[cls], te.CLASSES[cls]['phrase'])
        g = _flat(_guide())
        for phrase in ('port scanning', 'connecting to a decoy port'):
            self.assertIn(f'**{phrase}**', g, 'the guide names the two kinds a reader can hold back')

    def test_the_card_links_the_guide_and_the_guide_exists(self):
        self.assertIn('href="docs/firewall-sources.md"', _HTML)
        self.assertTrue(_GUIDE_PATH.exists() or not (_ROOT / 'docs').exists())


class TestTheGuideSaysWhatItDoesNotKnow(unittest.TestCase):
    """The readers were run against a real OPNsense firewall log and nothing else. The guide
    says so, and this fails the day it is no longer true and nobody changed the sentence."""

    def test_only_the_pf_reader_has_met_a_real_device(self):
        g = _flat(_guide())
        self.assertIn('has been run against a real OPNsense', g)
        self.assertIn('have not yet read a live firewall or router', g)
        src = (_ROOT / 'tests' / 'test_v740_appliance_evidence.py').read_text(encoding='utf-8')
        self.assertIn('no device of those\nkinds has been read yet', src)


if __name__ == '__main__':
    unittest.main()
