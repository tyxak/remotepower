"""docs/honeypot-worker.md hands a stranger a script and a config file to paste, so both are
run here, not read.

A guide like this fails in ways its reader cannot see. The Worker deploys, answers, and
RemotePower shows nothing, because one string in a log line differs from the one the reader
filters on. So the script is executed under node, every line it prints is fed to
RemotePower's own parser (edge_evidence.parse_trap -> trap_events -> threat_evidence), and the
sentences the page quotes are the ones the code produces.

What this cannot cover is Cloudflare's side: how Workers Logs stores a line and what the
Observability API returns. The script prints the same JSON object per hit as the operator's own
long-running Worker, which RemotePower's query shape was taken from; the page tells the reader
how to confirm it in their own dashboard (Step 4).
"""
import datetime
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import edge_evidence as ee  # noqa: E402
import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402

_GUIDE_PATH = _ROOT / 'docs' / 'honeypot-worker.md'
_NODE = shutil.which('node')

ATK = '185.220.101.7'       # a routable address: RemotePower sets aside documentation ranges
NOW = 1_790_000_000


def _guide():
    if not _GUIDE_PATH.exists():
        raise unittest.SkipTest('docs excluded from this tree')
    return _GUIDE_PATH.read_text()


def _blocks(text, lang):
    """The fenced code blocks of one language, in order."""
    out, cur, name = [], None, ''
    for line in text.split('\n'):
        m = re.match(r'^```(\w*)\s*$', line)
        if m:
            if cur is None:
                cur, name = [], m.group(1)
            else:
                if name == lang:
                    out.append('\n'.join(cur) + '\n')
                cur = None
            continue
        if cur is not None:
            cur.append(line)
    return out


def _script():
    blocks = _blocks(_guide(), 'js')
    assert len(blocks) == 1, 'the guide holds exactly one script, found %d' % len(blocks)
    return blocks[0]


def _config_text():
    blocks = [b for b in _blocks(_guide(), 'toml') if re.search(r'(?m)^name\s*=', b)]
    assert len(blocks) == 1, 'the guide holds exactly one wrangler.toml, found %d' % len(blocks)
    return blocks[0]


def _config():
    return tomllib.loads(_config_text())


def _traps():
    """[(kind, prefix)] read from the TRAPS array in the script."""
    m = re.search(r'const TRAPS = \[(.*?)^\];', _script(), re.S | re.M)
    assert m, 'no TRAPS array in the script'
    return re.findall(r'\["(\w+)",\s*"([^"]+)"\]', m.group(1))


def _const(name):
    m = re.search(r'^const %s = (\d+);' % name, _script(), re.M)
    assert m, name
    return int(m.group(1))


# The driver imports the guide's script as a module and calls its fetch() the way the
# runtime does. The request is a plain object with no body methods on purpose: a script
# that reads the body throws here, which is how "never reads a request body" is pinned.
_DRIVER = r"""
import fs from 'node:fs';
import worker from './worker.mjs';
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const results = [];
let origin = 0;
globalThis.fetch = async () => { origin += 1; return new Response('origin page', { status: 200 }); };
const realNow = Date.now;
for (const c of cases) {
  const logs = [];
  console.log = (...a) => { logs.push(a.join(' ')); };
  Date.now = c.now === undefined ? realNow : () => c.now;
  const req = { url: c.url, method: c.method || 'GET', headers: new Headers(c.headers || {}), cf: c.cf };
  let out;
  try {
    const res = await worker.fetch(req, c.env === undefined ? {} : c.env);
    out = { status: res.status, type: res.headers.get('content-type'),
            cache: res.headers.get('cache-control'), robots: res.headers.get('x-robots-tag'),
            body: await res.text(), logs, origin };
  } catch (e) {
    out = { error: String(e), logs };
  }
  results.push(out);
}
process.stdout.write(JSON.stringify(results));
"""


def _run(cases):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / 'worker.mjs').write_text(_script())
        (td / 'driver.mjs').write_text(_DRIVER)
        (td / 'cases.json').write_text(json.dumps(cases))
        p = subprocess.run([_NODE, 'driver.mjs', 'cases.json'], cwd=td, capture_output=True,
                           text=True, timeout=120)
    assert p.returncode == 0, p.stderr[-2000:]
    return json.loads(p.stdout)


def _case(path, ip=ATK, **kw):
    headers = {'user-agent': 'scanner/1.0'}
    if ip is not None:
        headers['cf-connecting-ip'] = ip
    headers.update(kw.pop('headers', {}))
    c = {'url': 'https://example.com' + path, 'headers': headers, 'cf': {'country': 'DK'}}
    c.update(kw)
    return c


# ── the script, run ────────────────────────────────────────────────────────────

@unittest.skipUnless(_NODE, 'node not installed')
class TestTheScriptRuns(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _guide()
        cls.traps = _traps()
        cases, cls.index = [], {}

        def add(name, case):
            cls.index[name] = len(cases)
            cases.append(case)

        for kind, prefix in cls.traps:
            add('trap:' + prefix, _case(prefix + 'probe'))
        add('plain', _case('/about'))
        add('home', _case('/'))
        add('acme', _case('/.well-known/acme-challenge/abc'))
        add('security_txt', _case('/.well-known/security.txt'))
        add('env', _case('/.env'))
        add('env_upper', _case('/.ENV'))
        add('git_head', _case('/.git/HEAD'))
        add('git_config', _case('/.git/config'))
        add('git_other', _case('/.git/index'))
        add('login_get', _case('/wp-login.php', ip='45.9.20.50'))
        add('login_post', _case('/wp-login.php', ip='45.9.20.50', method='POST'))
        add('own', _case('/.env', ip='203.0.113.7', env={'ALLOW': ' 198.51.100.4 , 203.0.113.7,, '}))
        add('own_v6', _case('/.env', ip='2001:db8::1', env={'ALLOW': '2001:db8::1'}))
        add('not_own', _case('/.env', ip='203.0.113.8', env={'ALLOW': '203.0.113.7'}))
        add('no_ip', _case('/.env', ip=None))
        add('no_cf', {'url': 'https://example.com/.env', 'headers': {'cf-connecting-ip': '45.9.20.51'}})
        add('no_env_var', _case('/.env', ip='45.9.20.52', env={}))
        add('long', _case('/.env' + 'a' * 5000, ip='45.9.20.53',
                          headers={'user-agent': 'x"\\' + '\u00e6\u00f8\u00e5' * 2000}))   # a header value is bytes (latin-1)
        add('head', _case('/.env', ip='45.9.20.54', method='HEAD'))
        for i in range(120):
            add('flood:%d' % i, _case('/.env', ip='45.9.20.60'))
        for i in range(25):
            add('win:%d' % i, _case('/.env', ip='45.9.20.61', now=10_000_000))
        add('win:after', _case('/.env', ip='45.9.20.61', now=10_000_000 + 3_600_001))
        for i in range(5100):
            add('many:%d' % i, _case('/.env', ip='45.%d.%d.%d' % (100 + i // 65025, (i // 255) % 255, i % 255 + 1),
                                     now=30_000_000))
        add('many:after', _case('/.env', ip='45.9.20.99', now=30_000_000))
        cls.res = _run(cases)

    def r(self, name):
        return self.res[self.index[name]]

    def lines(self, name):
        return [json.loads(x) for x in self.r(name)['logs']]

    def test_the_population_is_not_empty(self):
        """Control: with no traps, no requests and no lines, every check below would pass."""
        self.assertGreaterEqual(len(self.traps), 10)
        self.assertEqual({k for k, _ in self.traps}, {'bait', 'login'})
        self.assertEqual(len(self.res), len(self.index))
        self.assertTrue(any(self.r(n)['logs'] for n in self.index))

    def test_nothing_throws(self):
        bad = {n: r['error'] for n, r in zip(self.index, self.res) if 'error' in r}
        self.assertEqual(bad, {})

    def test_every_decoy_path_is_answered_and_logged_with_its_kind(self):
        for kind, prefix in self.traps:
            r = self.r('trap:' + prefix)
            self.assertEqual(r['origin'], 0, 'a decoy path went through to the site: ' + prefix)
            self.assertIn(r['status'], (200, 404), prefix)
            ls = self.lines('trap:' + prefix)
            self.assertEqual(len(ls), 1, prefix)
            self.assertEqual(ls[0]['kind'], kind, prefix)
            self.assertEqual(ls[0]['msg'], 'trap hit')
            self.assertEqual(ls[0]['ip'], ATK)

    def test_a_path_that_is_not_a_decoy_goes_through_and_logs_nothing(self):
        for name in ('plain', 'home', 'acme', 'security_txt'):
            r = self.r(name)
            self.assertEqual(r['body'], 'origin page', name)
            self.assertEqual(r['logs'], [], name)

    def test_the_certificate_and_security_paths_are_never_a_decoy(self):
        """/.well-known/ carries ACME challenges and security.txt. A prefix that caught it
        would break certificate renewal for the whole site."""
        for kind, prefix in self.traps:
            self.assertFalse('/.well-known/'.startswith(prefix), prefix)

    def test_the_decoys_answer_with_made_up_content_and_stay_out_of_caches_and_search(self):
        env = self.r('env')
        self.assertEqual(env['status'], 200)
        self.assertIn('DB_PASSWORD=change-me', env['body'])
        self.assertEqual(self.r('git_head')['body'], 'ref: refs/heads/main\n')
        self.assertIn('[core]', self.r('git_config')['body'])
        self.assertEqual(self.r('git_other')['status'], 404)
        for name in ('env', 'git_head', 'git_other', 'login_get'):
            r = self.r(name)
            self.assertEqual(r['cache'], 'no-store', name)
            self.assertIn('noindex', r['robots'], name)

    def test_matching_ignores_case(self):
        self.assertEqual(self.r('env_upper')['status'], 200)
        self.assertEqual(self.lines('env_upper')[0]['kind'], 'bait')

    def test_the_fake_login_answers_get_and_post_without_reading_the_body(self):
        for name in ('login_get', 'login_post'):
            r = self.r(name)
            self.assertEqual(r['status'], 200, name)
            self.assertIn('text/html', r['type'], name)
            self.assertIn('type="password"', r['body'], name)
            self.assertEqual(len(self.lines(name)), 1, name)
        self.assertEqual(self.lines('login_post')[0]['method'], 'POST')
        self.assertNotIn('error', self.r('login_post'))   # the request had no body methods

    def test_one_line_is_one_json_object_with_the_fields_remotepower_reads(self):
        line = self.lines('env')[0]
        for key in ('msg', 'kind', 'ip', 'action', 'at'):
            self.assertIn(key, line, key)
        self.assertEqual(line['action'], 'recorded')
        self.assertRegex(line['at'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$')
        self.assertGreater(ee._epoch(line['at']), 0)
        # one line, so the whole thing is one printed string
        self.assertEqual(len(self.r('env')['logs']), 1)
        self.assertNotIn('\n', self.r('env')['logs'][0])

    def test_your_own_addresses_are_logged_as_allowlisted(self):
        self.assertEqual(self.lines('own')[0]['action'], 'allowlisted')
        self.assertEqual(self.lines('own_v6')[0]['action'], 'allowlisted')
        self.assertEqual(self.lines('not_own')[0]['action'], 'recorded')
        self.assertEqual(self.lines('no_env_var')[0]['action'], 'recorded')

    def test_a_visit_without_an_address_is_answered_and_not_logged(self):
        r = self.r('no_ip')
        self.assertEqual(r['status'], 200)
        self.assertEqual(r['logs'], [])

    def test_a_missing_cf_object_is_an_empty_country(self):
        self.assertEqual(self.lines('no_cf')[0]['country'], '')
        self.assertEqual(self.lines('env')[0]['country'], 'DK')

    def test_what_the_visitor_controls_is_cut_to_a_length(self):
        r = self.r('long')
        self.assertNotIn('error', r)
        line = json.loads(r['logs'][0])
        self.assertLessEqual(len(line['path']), 200)
        self.assertLessEqual(len(line['ua']), 160)
        self.assertLess(len(r['logs'][0]), 2500)

    def test_head_is_answered(self):
        self.assertEqual(self.r('head')['status'], 200)
        self.assertEqual(self.lines('head')[0]['method'], 'HEAD')

    def test_a_flood_is_logged_for_the_first_FIRST_visits_and_then_every_nth(self):
        first, every = _const('FIRST'), _const('THEN_EVERY')
        n = sum(len(self.r('flood:%d' % i)['logs']) for i in range(120))
        want = first + len([i for i in range(first + 1, 121) if i % every == 0])
        self.assertEqual(n, want)
        self.assertLess(n, 120)

    def test_the_count_starts_again_after_the_window(self):
        self.assertEqual(sum(len(self.r('win:%d' % i)['logs']) for i in range(25)), min(25, _const('FIRST')))
        self.assertEqual(len(self.r('win:after')['logs']), 1)

    def test_thousands_of_different_addresses_are_all_logged_and_nothing_breaks(self):
        logged = sum(1 for i in range(5100) if self.r('many:%d' % i)['logs'])
        self.assertEqual(logged, 5100)
        self.assertEqual(len(self.r('many:after')['logs']), 1)

    def test_first_stays_at_or_above_the_default_report_threshold(self):
        self.assertGreaterEqual(_const('FIRST'), ip_intel.DEFAULTS['report_min_count'])

    def test_no_secret_shaped_string_is_in_the_script(self):
        self.assertIsNone(re.search(r'[A-Za-z0-9+/=_-]{32,}', _script()))


# ── what RemotePower does with it ──────────────────────────────────────────────

@unittest.skipUnless(_NODE, 'node not installed')
class TestRemotePowerReadsWhatItPrints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _guide()
        cases = [_case('/.env%d' % i, ip=ATK) for i in range(8)]
        cases += [_case('/wp-login.php', ip=ATK, method='POST') for _ in range(4)]
        cases.append(_case('/.env', ip=ATK, env={'ALLOW': ATK}))          # the same address, listed
        cases.append(_case('/.env', ip='203.0.113.7'))                     # a documentation address
        res = _run(cases)
        lines = [json.loads(x) for r in res for x in r['logs']]
        # The script stamps real time. The sentence the guide quotes needs a known window,
        # so the 12 recorded hits are spread over 220 seconds.
        cls.lines = lines
        rec = [x for x in lines if x['action'] == 'recorded' and x['ip'] == ATK]
        assert len(rec) == 12, len(rec)
        for i, x in enumerate(rec):
            x['at'] = datetime.datetime.fromtimestamp(NOW + i * 20, datetime.timezone.utc).strftime(
                '%Y-%m-%dT%H:%M:%S.000Z')
        cls.rec = rec

    def wrap(self, lines, as_string=False):
        evs = [{'source': json.dumps(x) if as_string else dict(x)} for x in lines]
        return {'success': True, 'result': {'events': {'events': evs}}}

    def test_every_printed_line_is_a_hit_and_both_wrappers_read_the_same(self):
        for as_string in (False, True):
            r = ee.parse_trap(200, self.wrap(self.lines, as_string))
            self.assertTrue(r['ok'])
            self.assertEqual(len(r['hits']), len(self.lines), as_string)
            self.assertTrue(all(h['kind'] and h['ip'] and h['action'] for h in r['hits']))

    def test_hits_become_evidence_filed_as_probing(self):
        hits = ee.parse_trap(200, self.wrap(self.rec))['hits']
        evs, st = ee.trap_events(hits, now=NOW + 400)
        self.assertEqual(st['kept'], 12)
        self.assertEqual(st['ignored'], {})
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual(ev['ip'], ATK)
        self.assertEqual(ev['tok']['trap'], {'trap:bait': 8, 'trap:login': 4})
        self.assertEqual(ev['trp'], 0)               # the script never decides, so nothing is "banned"
        self.assertIn('probe', te.classes(ev))

    def test_an_allowlisted_line_is_set_aside_and_a_documentation_address_is_not_public(self):
        evs, st = ee.trap_events(ee.parse_trap(200, self.wrap(self.lines))['hits'], now=NOW + 400)
        self.assertEqual(st['ignored'].get('own_or_shared_address'), 1)
        self.assertEqual(st['ignored'].get('not_public'), 1)
        self.assertEqual(st['kept'], 12)

    def test_an_address_is_reported_at_the_default_number_of_hits(self):
        need = ip_intel.DEFAULTS['report_min_count']
        enough = ee.trap_events(ee.parse_trap(200, self.wrap(self.rec[:need]))['hits'], now=NOW + 400)[0][0]
        short = ee.trap_events(ee.parse_trap(200, self.wrap(self.rec[:need - 1]))['hits'], now=NOW + 400)[0][0]
        self.assertTrue(te.qualifies(enough, need)[0])
        ok, why = te.qualifies(short, need)
        self.assertFalse(ok)
        self.assertEqual(why, '%d of %d attempts so far' % (need - 1, need))

    def test_the_kinds_it_writes_are_kinds_remotepower_files_as_evidence(self):
        for kind in {k for k, _ in _traps()}:
            self.assertIn(kind, ee._TRAP_TOKEN, kind)
            self.assertTrue(te.TRAP_KINDS.get(ee._TRAP_TOKEN[kind]), kind)

    def test_the_actions_it_writes_are_the_ones_the_guide_says_they_are(self):
        self.assertIn('allowlisted', ee._TRAP_SKIPPED)
        self.assertNotIn('recorded', ee._TRAP_DECIDED + ee._TRAP_SKIPPED)
        self.assertEqual({x['action'] for x in self.lines}, {'recorded', 'allowlisted'})

    def test_the_sentence_the_guide_quotes_is_the_one_the_code_writes(self):
        ev = ee.trap_events(ee.parse_trap(200, self.wrap(self.rec))['hits'], now=NOW + 400)[0][0]
        self.assertIn(ip_intel.evidence_comment(ev), _guide())

    def test_the_status_the_guide_quotes_is_the_one_the_code_writes(self):
        need = ip_intel.DEFAULTS['report_min_count']
        short = ee.trap_events(ee.parse_trap(200, self.wrap(self.rec[:need - 1]))['hits'], now=NOW + 400)[0][0]
        why = te.qualifies(short, need)[1].replace(' of ', ' / ')
        self.assertIn('`not reported: %s`' % why, _guide())


# ── the config, and the page around it ─────────────────────────────────────────

class TestTheConfig(unittest.TestCase):

    def test_it_is_the_worker_remotepower_reads_by_default(self):
        cfg = _config()
        self.assertEqual(cfg['name'], ip_intel.DEFAULTS['edge_workers'][0])
        self.assertTrue(ee.valid_worker(cfg['name']))

    def test_logs_are_on_and_the_workers_dev_address_is_off(self):
        cfg = _config()
        self.assertIs(cfg['observability']['enabled'], True)
        self.assertIs(cfg['workers_dev'], False)
        self.assertEqual(cfg['main'], 'worker.js')

    def test_the_compatibility_date_is_a_real_date_that_is_not_in_the_future(self):
        d = datetime.date.fromisoformat(_config()['compatibility_date'])
        self.assertLessEqual(d, datetime.date.today())

    def test_routes_are_top_level_not_inside_vars(self):
        """In TOML a key after a [table] header belongs to that table."""
        cfg = _config()
        self.assertIsInstance(cfg['routes'], list)
        self.assertNotIn('routes', cfg['vars'])
        self.assertIn('ALLOW', cfg['vars'])
        self.assertIsInstance(cfg['vars']['ALLOW'], str)

    def test_every_decoy_has_a_route_and_every_route_a_decoy(self):
        routes = _config()['routes']
        self.assertEqual({r['zone_name'] for r in routes}, {'example.com'})
        paths = []
        for r in routes:
            m = re.fullmatch(r'\*example\.com(/[^*?]+)\*', r['pattern'])
            self.assertIsNotNone(m, 'a route may end in a wildcard and hold no query or infix one: ' + r['pattern'])
            paths.append(m.group(1))
        self.assertEqual(len(paths), len(set(paths)), 'a route is listed twice')
        want = [p for _, p in _traps()]
        self.assertEqual(sorted(paths), sorted(want))

    def test_every_prefix_is_lower_case_and_starts_with_a_slash(self):
        for kind, prefix in _traps():
            self.assertEqual(prefix, prefix.lower())
            self.assertTrue(prefix.startswith('/'), prefix)

    def test_the_second_toml_example_is_a_valid_allow_line(self):
        ex = [b for b in _blocks(_guide(), 'toml') if b.startswith('ALLOW')]
        self.assertEqual(len(ex), 1)
        allow = tomllib.loads(ex[0])['ALLOW']
        for a in allow.split(','):
            ipaddress.ip_address(a.strip())


class TestThePage(unittest.TestCase):

    def test_the_kinds_table_names_exactly_the_kinds_the_script_writes(self):
        guide = _guide()
        m = re.search(r'^\| `kind` \|.*?\n((?:\|.*\n)+)', guide, re.M)
        self.assertIsNotNone(m)
        rows = [r.split('|')[1].strip() for r in m.group(1).strip().split('\n')]
        rows = [r.strip('`') for r in rows if not re.fullmatch(r'-+', r)]
        self.assertEqual(set(rows), {k for k, _ in _traps()})

    def test_the_numbers_are_the_codes(self):
        guide = _guide()
        n = ip_intel.DEFAULTS['report_min_count']
        self.assertIn('which is %d unless you changed it' % n, guide)
        words = {5: 'five', 10: 'ten', 15: 'fifteen', 30: 'thirty'}
        self.assertIn('every %s minutes unless you changed it' % words[ip_intel.DEFAULTS['edge_poll_minutes']], guide)
        self.assertIn('Up to {:,} lines per Worker'.format(ee.TRAP_LINES), guide)
        first, every = _const('FIRST'), _const('THEN_EVERY')
        self.assertIn('first %d visits' % first, guide)
        self.assertIn('every %dth' % every, guide)
        self.assertIn('With the default of %d, %d leaves room' % (n, first), guide)

    def test_the_page_is_linked_from_the_index_and_from_both_guides_it_extends(self):
        for rel in ('README.md', 'edge-sources.md', 'ip-intel.md'):
            p = _ROOT / 'docs' / rel
            if not p.exists():
                self.skipTest('docs excluded from this tree')
            self.assertIn('(honeypot-worker.md)', p.read_text(), rel)

    def test_it_is_a_public_page(self):
        guide = _guide()
        self.assertNotRegex(guide, r'-internal\.md')
        self.assertNotRegex(guide, r'\b[0-9a-f]{32}\b', 'a real zone or account id')
        for word in ('genuine', 'genuinely', 'verbatim', 'deliberate', 'deliberately'):
            self.assertNotRegex(guide, r'(?i)\b%s\b' % word, word)
        self.assertNotRegex(guide, r'(?i)tviweb|tvipper|bymanden|atramentum')
        self.assertNotRegex(guide, r'(?i)trap_(bait|robots|login|impostor|private)|trap-edge|trap-watch|SINK_KEY')

    def test_every_address_in_it_is_a_documentation_or_loopback_address(self):
        """A guide copied from a working install is where a real address slips in."""
        guide = _guide()
        nets = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24',
                                                  '127.0.0.0/8', '2001:db8::/32')]
        found = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', guide)
        found += re.findall(r'(?<![\w:])[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![\w:])', guide)
        self.assertGreaterEqual(len(found), 3, 'control: the scan found nothing to check')
        bad = []
        for a in found:
            try:
                ip = ipaddress.ip_address(a)
            except ValueError:
                continue
            if not any(ip in n for n in nets):
                bad.append(a)
        self.assertEqual(bad, [])

    def test_it_stays_inside_what_the_in_app_viewer_renders(self):
        """No horizontal rules, images or HTML outside a code fence, and no bold, code or link
        written over two lines: the in-app viewer matches them one line at a time."""
        fence, plain = False, []
        for line in _guide().split('\n'):
            if line.strip().startswith('```'):
                fence = not fence
                continue
            if not fence:
                plain.append(line)
        text = '\n'.join(plain)
        self.assertNotRegex(text, r'(?m)^\s*(---|\*\*\*)\s*$', 'no horizontal rules')
        self.assertNotRegex(text, r'!\[', 'no images')
        self.assertNotRegex(text, r'</?[a-z]+[^>]*>', 'no HTML')
        crossing = [ln.strip()[:70] for ln in plain
                    if len(re.findall(r'\*\*', ln)) % 2 or ln.count('`') % 2 or ln.count('[') != ln.count(']')]
        self.assertEqual(crossing, [])


if __name__ == '__main__':
    unittest.main()
