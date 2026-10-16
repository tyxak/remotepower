"""docs/honeypot-traps.md replaces the first guide's script with one that has more traps, so
it is held to the same standard: the script is run, not read.

What this adds to test_v730_honeypot_guide:

  * every trap kind the page names is written by the script, and RemotePower files each one
    as the page says (the "Filed as" column is the class phrase the code uses);
  * the check table in Step 4 is replayed: every `curl` row is turned into a request, run
    through the script, and the `kind` the row claims is the kind that is logged;
  * the first guide's traps all still answer the same way, so a reader who swaps scripts
    loses nothing;
  * the planted password cannot be on by default (a published default would be a known
    password), is read only where the page says, and is never written to the log.

Cloudflare's side (how Workers Logs stores a line, what Custom Domains do with a name) is
not reachable from here and is not claimed; see the docstring of test_v730_honeypot_guide.
"""
import base64
import json
import re
import shlex
import sys
import tomllib
import unittest
import urllib.robotparser
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import edge_evidence as ee  # noqa: E402
import honeypot_worker_harness as H  # noqa: E402
import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402

_GUIDE_PATH = _ROOT / 'docs' / 'honeypot-traps.md'
_FIRST_PATH = _ROOT / 'docs' / 'honeypot-worker.md'
_NODE = H.NODE
ATK = H.ATK
PW = 'Zk3-Qw9_Lm4xT7vB2n'
DECOY = 'vpn-portal.example.com'
# What a site may answer for /robots.txt, other than the file itself.
ROBOTS_STATUSES = (301, 302, 304, 400, 401, 403, 404, 410, 429, 500, 502, 503)
# Shapes a site's own robots.txt takes, the crawlers they speak to, and paths of the site.
ROBOTS_FILES = {
    'named': 'User-agent: Googlebot\nDisallow: /tmp/\n',
    'mixed': ('# our rules\nUser-agent: Googlebot\nUser-agent: Bingbot\nCrawl-delay: 5\nDisallow: /tmp/\n\n'
              'User-agent: *\nDisallow: /admin/\nAllow: /admin/help\n\n'
              'Sitemap: https://example.com/sitemap.xml\n'),
    'crlf': 'User-agent: Googlebot\r\nDisallow: /tmp/\r\n\r\nUser-agent: *\r\nDisallow: /admin/\r\n',
    'agents_only': 'User-agent: Googlebot\nDisallow: /tmp/\n\nUser-agent: BadBot\n',
    'split_agents': 'User-agent: Googlebot\n\nuser-agent: Bingbot\nDisallow: /tmp/\n',
}
AGENTS = ('Googlebot', 'Bingbot', 'BadBot', 'SomeOtherBot')
OWN_PATHS = ('/', '/about', '/tmp/x', '/admin/x', '/admin/help', '/backups/', '/old-backups')
ENV = {'CANARY_PASSWORD': PW, 'DECOY_HOSTS': DECOY + ', other.example.com', 'ALLOW': '203.0.113.7, 2001:DB8::1'}


def _read(path):
    if not path.exists():
        raise unittest.SkipTest('docs excluded from this tree')
    return path.read_text()


def _guide():
    return _read(_GUIDE_PATH)


def _script():
    return H.script_of(_guide())


def _config_text():
    return H.config_text_of(_guide())


def _config():
    return H.config_of(_guide())


def _traps():
    return H.traps_of(_script())


def _const(name):
    return H.const_of(_script(), name)


_section = H.section
_table = H.table


def _kinds_in(cell):
    return re.findall(r'`(\w+)`', cell)


def _robots(text):
    """A robots.txt as Python's parser reads it: a crawler gets the group that names it,
    and the `*` group only when none does."""
    rp = urllib.robotparser.RobotFileParser()
    rp.parse(text.splitlines())
    return rp


def _in_order(needles, hay):
    """Every needle is in hay, in the same order."""
    rest = iter(hay)
    return all(any(n == h for h in rest) for n in needles)


def _check_rows():
    """[(command, kind or None)] from the Step 4 table."""
    sec = _section(_guide(), 'Step 4: Deploy and check each one')
    rows = []
    for cells in _table(sec[sec.index('| Ask for'):]):
        cmd = re.search(r'`(curl [^`]+)`', cells[0])
        assert cmd, cells
        kinds = _kinds_in(cells[2])
        rows.append((cmd.group(1), kinds[0] if kinds else None))
    return rows


def _request_of(command):
    """A `curl` line from the page as a harness case."""
    toks = shlex.split(command)
    url = next(t for t in toks if t.startswith('https://'))
    data = None
    if '-d' in toks:
        data = toks[toks.index('-d') + 1].replace('YOUR-PASSWORD', PW)
    m = re.match(r'https://([^/]+)(/.*)?$', url)
    host, path = m.group(1), m.group(2) or '/'
    kw = {'env': ENV}
    if data is not None:
        kw.update(method='POST', body=data, headers={'content-length': str(len(data))})
    return H.case(path, host=host, **kw)


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

        C = H.case
        for kind, prefix in cls.traps:
            add('trap:' + prefix, C(prefix + 'x', env=ENV))
        for n, p in (('plain', '/about'), ('home', '/'), ('acme', '/.well-known/acme-challenge/abc'),
                     ('sec', '/.well-known/security.txt'), ('backupsish', '/backupsfoo')):
            add(n, C(p, env=ENV))
        # the fake git repository
        for n, p in (('git_head', '/.git/HEAD'), ('git_config', '/.git/config'),
                     ('git_ref', '/.git/refs/heads/main'), ('git_obj', '/.git/objects/ab/cdef'),
                     ('git_index', '/.git/index'), ('git_dir', '/.git/')):
            add(n, C(p, env=ENV))
        # robots.txt
        add('robots_own', C('/robots.txt', originBody='User-agent: Googlebot\nDisallow: /tmp/\n'))
        for name, text in ROBOTS_FILES.items():
            add('robots_file:' + name, C('/robots.txt', originBody=text))
        for st in ROBOTS_STATUSES:
            add('robots_status:%d' % st, C('/robots.txt', originStatus=st,
                                           originBody=None if st == 304 else 'site answer %d' % st))
        add('robots_down', C('/robots.txt', originFail=True))
        add('robots_decoy_host', C('/robots.txt', host=DECOY, env=ENV))
        # the fake directory
        for n, p in (('m_root', '/backups'), ('m_root_slash', '/backups/'), ('m_db', '/backups/db/'),
                     ('m_db_bare', '/backups/db'), ('m_www', '/backups/www/'),
                     ('m_loot', '/backups/db/site-2024-11-02.sql.gz'), ('m_loot2', '/backups/www/uploads.zip'),
                     ('m_loot_missing', '/backups/db/dump.sql'), ('m_readme', '/backups/readme.txt'),
                     ('m_missing', '/backups/zzz/'), ('m_upper', '/BACKUPS/DB/')):
            add(n, C(p, env=ENV))
        # the planted password
        body = 'log=admin&pwd=' + PW
        post = dict(method='POST', headers={'content-length': str(len(body))}, body=body, env=ENV)
        add('env_on', C('/.env', env=ENV))
        add('env_off', C('/.env', env={}))
        add('env_short', C('/.env', env={'CANARY_PASSWORD': 'short'}))
        add('c_post', C('/wp-login.php', **post))
        add('c_post_encoded', C('/wp-login.php', method='POST', env={'CANARY_PASSWORD': 'a b+c&d=e/f12'},
                                headers={'content-length': '40'}, body='pwd=a%20b%2Bc%26d%3De%2Ff12'))
        add('c_post_wrong', C('/wp-login.php', method='POST', headers={'content-length': '19'},
                              body='log=admin&pwd=wrong', env=ENV))
        add('c_post_nolen', C('/wp-login.php', method='POST', body=body, env=ENV))
        add('c_post_big', C('/wp-login.php', method='POST', headers={'content-length': '4097'},
                            body=body + 'x' * 5000, env=ENV))
        add('c_post_off', C('/wp-login.php', method='POST', headers={'content-length': str(len(body))},
                            body=body, env={}))
        add('c_post_bait', C('/.env', method='POST', headers={'content-length': str(len(body))},
                             body=body, env=ENV))
        basic = 'Basic ' + base64.b64encode(('admin:' + PW).encode()).decode()
        add('c_basic', C('/phpmyadmin/', headers={'authorization': basic}, env=ENV))
        add('c_basic_env', C('/.env', headers={'authorization': basic}, env=ENV))
        add('c_basic_bad', C('/phpmyadmin/', headers={'authorization': 'Basic !!!not-base64'}, env=ENV))
        add('c_bad_percent', C('/wp-login.php', method='POST', headers={'content-length': '7'},
                               body='%E0%A4%A', env=ENV))
        add('c_post_lost', C('/wp-login.php', method='POST', headers={'content-length': '40'},
                             bodyFail=True, env=ENV))
        add('d_post_lost', C('/login', host=DECOY, method='POST', headers={'content-length': '40'},
                             bodyFail=True, env=ENV))
        # decoy hosts
        add('d_get', C('/', host=DECOY, env=ENV))
        add('d_path', C('/admin/users', host=DECOY, env=ENV))
        add('d_post', C('/login', host=DECOY, method='POST', headers={'content-length': '3'}, body='a=b', env=ENV))
        add('d_canary', C('/login', host=DECOY, method='POST',
                          headers={'content-length': str(len(body))}, body=body, env=ENV))
        add('d_other', C('/', host='other.example.com', env=ENV))
        add('d_notlisted', C('/', host='other2.example.com', env=ENV))
        add('d_empty', C('/', host=DECOY, env={'DECOY_HOSTS': ''}))
        # your own addresses
        add('own', C('/.env', ip='203.0.113.7', env=ENV))
        add('own_v6_case', C('/.env', ip='2001:db8::1', env=ENV))
        add('not_own', C('/.env', ip='203.0.113.8', env=ENV))
        add('no_ip', C('/.env', ip=None, env=ENV))
        add('head', C('/.env', ip='45.9.20.54', method='HEAD', env=ENV))
        add('long', C('/.env' + 'a' * 5000, ip='45.9.20.53', env=ENV,
                      headers={'user-agent': 'x"\\' + '\u00e6\u00f8\u00e5' * 2000}))
        for i in range(120):
            add('flood:%d' % i, C('/.env', ip='45.9.20.60', env=ENV))
        for i in range(25):
            add('win:%d' % i, C('/.env', ip='45.9.20.61', now=10_000_000, env=ENV))
        add('win:after', C('/.env', ip='45.9.20.61', now=10_000_000 + 3_600_001, env=ENV))
        cls.res = H.run(_script(), cases)

    def r(self, name):
        return self.res[self.index[name]]

    def lines(self, name):
        return [json.loads(x) for x in self.r(name)['logs']]

    def kind(self, name):
        ls = self.lines(name)
        self.assertEqual(len(ls), 1, name)
        return ls[0]['kind']

    # the population ------------------------------------------------------------

    def test_the_population_is_not_empty(self):
        """Control: with no traps, no requests and no lines every check below would pass."""
        self.assertGreaterEqual(len(self.traps), 20)
        self.assertEqual(len(self.res), len(self.index))
        self.assertTrue(any(self.r(n)['logs'] for n in self.index))

    def test_nothing_throws(self):
        bad = {n: r['error'] for n, r in zip(self.index, self.res) if 'error' in r}
        self.assertEqual(bad, {})

    def test_every_trap_in_the_table_is_answered_and_logged_with_its_kind(self):
        for kind, prefix in self.traps:
            r = self.r('trap:' + prefix)
            self.assertEqual(r['fetched'], 0, 'went through to the site: ' + prefix)
            self.assertEqual(self.kind('trap:' + prefix), kind, prefix)
            self.assertIn(r['status'], (200, 404), prefix)
            ls = self.lines('trap:' + prefix)
            self.assertEqual((ls[0]['msg'], ls[0]['ip']), ('trap hit', ATK), prefix)

    def test_a_path_that_is_not_a_trap_goes_through_and_logs_nothing(self):
        for name in ('plain', 'home', 'acme', 'sec', 'backupsish'):
            r = self.r(name)
            self.assertEqual((r['body'], r['fetched'], r['logs']), ('origin page', 1, []), name)

    def test_the_certificate_and_security_paths_are_never_a_trap(self):
        """/.well-known/ carries ACME challenges and security.txt."""
        for _, prefix in self.traps:
            self.assertFalse('/.well-known/'.startswith(prefix), prefix)

    # the fake git repository and the fake directory ----------------------------

    def test_the_fake_git_repository(self):
        self.assertEqual(self.r('git_head')['body'], 'ref: refs/heads/main\n')
        self.assertIn('[core]', self.r('git_config')['body'])
        self.assertRegex(self.r('git_ref')['body'], r'^[0-9a-f]{40}\n$')
        self.assertEqual(self.r('git_obj')['status'], 404)
        self.assertEqual([self.kind(n) for n in ('git_head', 'git_config')], ['bait', 'bait'])
        self.assertEqual([self.kind(n) for n in ('git_ref', 'git_obj', 'git_index')], ['gitdump'] * 3)

    def test_the_fake_directory_has_three_levels_and_each_is_its_own_kind(self):
        self.assertEqual(self.kind('m_root'), 'mazeentry')
        self.assertEqual(self.kind('m_root_slash'), 'mazeentry')
        self.assertEqual([self.kind('m_db'), self.kind('m_db_bare'), self.kind('m_www')], ['maze'] * 3)
        self.assertEqual([self.kind('m_loot'), self.kind('m_loot2'), self.kind('m_loot_missing')], ['mazeloot'] * 3)
        self.assertEqual([self.kind('m_readme'), self.kind('m_missing')], ['maze', 'maze'])
        self.assertEqual(self.kind('m_upper'), 'maze')

    def test_the_fake_directory_lists_only_what_is_in_the_script_and_links_by_full_path(self):
        root = self.r('m_root')['body']
        self.assertIn('href="/backups/db/"', root)
        self.assertIn('href="/backups/readme.txt"', root)
        self.assertNotIn('href="db/"', root)
        self.assertIn('site-2024-11-02.sql.gz', self.r('m_db')['body'])
        self.assertEqual(self.r('m_db_bare')['body'], self.r('m_db')['body'])
        self.assertEqual(self.r('m_loot')['status'], 200)
        for n in ('m_loot_missing', 'm_missing'):
            self.assertEqual(self.r(n)['status'], 404, n)

    def test_the_fake_directory_is_a_closed_tree(self):
        """A crawler of it must come to an end: every link in every listing leads to a page
        that is a file or a listing in the tree, and none leads out of it."""
        script = _script()
        tree = dict(re.findall(r'"(/backups/[^"]*)": \[([^\]]*)\]', script))
        self.assertGreaterEqual(len(tree), 3)
        for d, names in tree.items():
            for n in re.findall(r'"([^"]+)"', names):
                if n.endswith('/'):
                    self.assertIn(d + n, tree, 'a link to a listing that does not exist: ' + d + n)

    # robots.txt -----------------------------------------------------------------

    def test_robots_txt_is_your_own_file_with_the_decoys_added_and_is_not_a_hit(self):
        r = self.r('robots_own')
        self.assertEqual(r['logs'], [])
        self.assertTrue(_in_order(['User-agent: Googlebot', 'Disallow: /tmp/'], r['body'].split('\n')))
        group = r['body'].split('\n\n')[-1]
        want = [p for k, p in self.traps if k == 'robots']
        self.assertGreaterEqual(len(want), 3)
        self.assertEqual(group, 'User-agent: *\n' + '\n'.join('Disallow: ' + p for p in want) + '\n')

    def test_every_crawler_is_kept_off_the_decoys_and_nothing_else_changes(self):
        """A crawler that finds a group for itself reads only that group (RFC 9309, 2.2.1),
        so a decoy that is only in a `User-agent: *` group is open to it, and a crawler
        that obeyed robots.txt would be filed as one that did not."""
        decoys = ['https://example.com%sx' % p for k, p in self.traps if k == 'robots']
        mixed = _robots(ROBOTS_FILES['mixed'])
        self.assertNotEqual(mixed.can_fetch('Googlebot', 'https://example.com/admin/x'),
                            mixed.can_fetch('SomeOtherBot', 'https://example.com/admin/x'),
                            'control: the parser gives a crawler its own group')
        def everyone(text):
            return len(re.findall(r'(?im)^user-agent:\s*\*\s*$', text))

        for name, own in ROBOTS_FILES.items():
            out = self.r('robots_file:' + name)['body']
            before, after = _robots(own), _robots(out)
            self.assertTrue(_in_order(own.rstrip().split('\n'), out.split('\n')), name)
            # a second `*` group is merged by a parser that follows RFC 9309, and is all a
            # parser that keeps the last one would read
            self.assertEqual(everyone(out), max(1, everyone(own)), name)
            for agent in AGENTS:
                for url in decoys:
                    self.assertFalse(after.can_fetch(agent, url), (name, agent, url))
                for path in OWN_PATHS:
                    url = 'https://example.com' + path
                    self.assertEqual(after.can_fetch(agent, url), before.can_fetch(agent, url), (name, agent, path))

    def robots_alone(self):
        """The statuses of the site's answer that the Worker turns into the decoys alone."""
        want = 'User-agent: *\n' + ''.join('Disallow: %s\n' % p for k, p in self.traps if k == 'robots')
        return [st for st in ROBOTS_STATUSES
                if (self.r('robots_status:%d' % st)['status'], self.r('robots_status:%d' % st)['body']) == (200, want)]

    def test_robots_txt_is_the_decoys_alone_only_when_your_site_has_none(self):
        """404 and 410 say there is no file, which lets a crawler go anywhere, so the decoys
        only narrow that."""
        self.assertEqual(self.robots_alone(), [404, 410])

    def test_any_other_answer_from_your_site_is_passed_on_unchanged(self):
        """A 5xx tells crawlers to stay out until the site answers (RFC 9309, 2.3.1.4), a
        redirect points them at the file to read, and a 304 says their copy is still good.
        Swapping any of these for a 200 with only the decoys in it told crawlers they
        could go anywhere."""
        passed = [st for st in ROBOTS_STATUSES if st not in (404, 410)]
        self.assertGreaterEqual(len(passed), 8, 'control')
        for st in passed:
            r = self.r('robots_status:%d' % st)
            self.assertEqual((r['status'], r['fetched'], r['logs']), (st, 1, []), st)
            self.assertEqual(r['body'], '' if st == 304 else 'site answer %d' % st, st)

    def test_robots_txt_is_a_503_when_your_site_cannot_be_reached(self):
        r = self.r('robots_down')
        self.assertEqual((r['status'], r['logs']), (503, []))
        self.assertNotIn('Disallow', r['body'])

    def test_the_troubleshooting_row_names_the_answers_that_give_the_decoys_alone(self):
        rows = _table(_section(_guide(), 'Troubleshooting'))
        alone = [r for r in rows if 'only the decoy lines' in r[0]]
        self.assertEqual(len(alone), 1)
        self.assertEqual(sorted(int(s) for s in re.findall(r'`(\d{3})`', alone[0][1])), self.robots_alone())
        other = [r for r in rows if r[0].startswith('`robots.txt` answers with')]
        self.assertEqual(len(other), 1, 'a row for the answers the Worker passes on')

    def test_a_decoy_host_does_not_get_the_robots_treatment(self):
        self.assertEqual(self.kind('robots_decoy_host'), 'decoy')

    # the planted password --------------------------------------------------------

    def test_the_password_is_handed_out_only_when_one_is_set(self):
        self.assertIn('ADMIN_PASSWORD=' + PW, self.r('env_on')['body'])
        self.assertIn('ADMIN_USER=admin', self.r('env_on')['body'])
        for n in ('env_off', 'env_short'):
            self.assertNotIn('ADMIN_', self.r(n)['body'], n)
        self.assertEqual(self.kind('env_on'), 'bait')

    def test_a_post_with_the_password_is_a_canary_use_and_a_wrong_one_is_a_login(self):
        self.assertEqual(self.kind('c_post'), 'canary_use')
        self.assertEqual(self.kind('c_post_encoded'), 'canary_use')
        self.assertEqual(self.kind('c_post_wrong'), 'login')

    def test_a_basic_header_with_the_password_is_a_canary_use_on_any_trap(self):
        self.assertEqual(self.kind('c_basic'), 'canary_use')
        self.assertEqual(self.kind('c_basic_env'), 'canary_use')
        self.assertEqual(self.kind('c_basic_bad'), 'login')

    def test_the_answer_does_not_change_when_a_visit_turns_out_to_be_a_canary_use(self):
        """The visitor must not be able to tell it was noticed."""
        self.assertEqual(self.r('c_basic_env')['body'], self.r('env_on')['body'])
        self.assertEqual(self.r('c_post')['body'], self.r('c_post_wrong')['body'])

    def test_a_body_is_read_only_for_a_short_post_to_a_login_page_with_a_password_set(self):
        reads = {n: self.r(n)['bodyReads'] for n in self.index if n.startswith(('c_', 'd_', 'trap:'))}
        self.assertEqual(reads['c_post'], 1)
        self.assertEqual(reads['c_post_wrong'], 1)
        for n in ('c_post_nolen', 'c_post_big', 'c_post_off', 'c_post_bait'):
            self.assertEqual(reads[n], 0, n)
        for n in [k for k in reads if k.startswith('trap:')]:
            self.assertEqual(reads[n], 0, n)
        self.assertEqual(self.kind('c_post_nolen'), 'login')
        self.assertEqual(self.kind('c_post_big'), 'login')
        self.assertEqual(self.kind('c_post_off'), 'login')
        self.assertEqual(self.kind('c_post_bait'), 'bait')

    def test_the_password_and_the_body_never_reach_the_log(self):
        for n, r in zip(self.index, self.res):
            for line in r['logs']:
                self.assertNotIn(PW, line, n)
                self.assertNotIn('log=admin', line, n)
                self.assertNotIn('authorization', line.lower(), n)

    def test_a_malformed_body_or_header_is_not_an_error(self):
        self.assertNotIn('error', self.r('c_bad_percent'))
        self.assertEqual(self.kind('c_bad_percent'), 'login')

    def test_a_body_that_cannot_be_read_is_still_logged_and_answered(self):
        """A client that drops its upload makes the read fail. The visit is still a hit,
        and the visitor still gets the fake page, not an error that gives the trap away."""
        for n, kind in (('c_post_lost', 'login'), ('d_post_lost', 'decoy_login')):
            r = self.r(n)
            self.assertNotIn('error', r, n)
            self.assertEqual(r['bodyReads'], 1, n)
            self.assertEqual(self.kind(n), kind, n)
            self.assertIn('type="password"', r['body'], n)

    # decoy hosts ------------------------------------------------------------------

    def test_a_decoy_host_is_a_decoy_for_every_path_and_a_post_is_a_sign_in(self):
        self.assertEqual([self.kind('d_get'), self.kind('d_path')], ['decoy', 'decoy'])
        self.assertEqual(self.kind('d_post'), 'decoy_login')
        self.assertEqual(self.kind('d_other'), 'decoy')       # the list is trimmed
        for n in ('d_get', 'd_path', 'd_post'):
            self.assertIn('type="password"', self.r(n)['body'], n)

    def test_a_decoy_host_sign_in_with_the_password_is_a_canary_use(self):
        self.assertEqual(self.kind('d_canary'), 'canary_use')

    def test_a_host_that_is_not_listed_is_your_site(self):
        for n in ('d_notlisted', 'd_empty'):
            r = self.r(n)
            self.assertEqual((r['body'], r['logs'], r['fetched']), ('origin page', [], 1), n)

    # your own addresses, the log, the throttle ---------------------------------

    def test_your_own_addresses_are_allowlisted_and_the_match_ignores_case(self):
        self.assertEqual(self.lines('own')[0]['action'], 'allowlisted')
        self.assertEqual(self.lines('own_v6_case')[0]['action'], 'allowlisted')
        self.assertEqual(self.lines('not_own')[0]['action'], 'recorded')

    def test_a_visit_without_an_address_is_answered_and_not_logged(self):
        r = self.r('no_ip')
        self.assertEqual((r['status'], r['logs']), (200, []))

    def test_one_line_has_the_fields_remotepower_reads(self):
        line = self.lines('env_on')[0]
        for key in ('msg', 'kind', 'ip', 'action', 'at'):
            self.assertIn(key, line, key)
        self.assertRegex(line['at'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$')
        self.assertEqual(len(self.r('env_on')['logs']), 1)

    def test_what_the_visitor_controls_is_cut_to_a_length(self):
        line = json.loads(self.r('long')['logs'][0])
        self.assertLessEqual(len(line['path']), 200)
        self.assertLessEqual(len(line['ua']), 160)

    def test_head_is_answered(self):
        self.assertEqual(self.r('head')['status'], 200)

    def test_a_flood_is_logged_for_the_first_FIRST_visits_and_then_every_nth(self):
        first, every = _const('FIRST'), _const('THEN_EVERY')
        n = sum(len(self.r('flood:%d' % i)['logs']) for i in range(120))
        self.assertEqual(n, first + len([i for i in range(first + 1, 121) if i % every == 0]))

    def test_the_count_starts_again_after_the_window(self):
        self.assertEqual(sum(len(self.r('win:%d' % i)['logs']) for i in range(25)), _const('FIRST'))
        self.assertEqual(len(self.r('win:after')['logs']), 1)

    def test_first_stays_at_or_above_the_default_report_threshold(self):
        self.assertGreaterEqual(_const('FIRST'), ip_intel.DEFAULTS['report_min_count'])

    def test_no_secret_shaped_string_is_in_the_script(self):
        self.assertIsNone(re.search(r'[A-Za-z0-9+/=_-]{41,}', _script()))
        for m in re.findall(r'[A-Za-z0-9+/=_-]{32,}', _script()):
            self.assertRegex(m, r'^[0-9a-f]{40}$', 'only the made-up git hash may look like a secret')

    # the first guide's script, and the page's own commands --------------------

    def test_every_trap_of_the_first_guide_answers_with_the_same_kind(self):
        first = H.traps_of(H.script_of(_read(_FIRST_PATH)))
        self.assertGreaterEqual(len(first), 10)
        res = H.run(_script(), [H.case(p + 'probe') for _, p in first])
        for (kind, prefix), r in zip(first, res):
            ls = [json.loads(x) for x in r['logs']]
            self.assertEqual([l['kind'] for l in ls], [kind], prefix)

    def test_every_check_in_step_4_does_what_the_row_says(self):
        rows = _check_rows()
        self.assertGreaterEqual(len(rows), 10)
        res = H.run(_script(), [_request_of(c) for c, _ in rows])
        for (cmd, kind), r in zip(rows, res):
            self.assertNotIn('error', r, cmd)
            ls = [json.loads(x) for x in r['logs']]
            self.assertEqual([l['kind'] for l in ls], [kind] if kind else [], cmd)

    def test_step_4_has_a_check_for_every_kind_the_script_writes(self):
        self.assertEqual({k for _, k in _check_rows() if k}, {k for k, _ in self.traps} |
                         {'mazeentry', 'maze', 'mazeloot', 'canary_use', 'decoy', 'decoy_login'})


# ── what RemotePower does with it ──────────────────────────────────────────────

@unittest.skipUnless(_NODE, 'node not installed')
class TestRemotePowerReadsWhatItPrints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _guide()
        rows = _check_rows()
        res = H.run(_script(), [_request_of(c) for c, _ in rows])
        cls.lines = [json.loads(x) for r in res for x in r['logs']]
        assert len(cls.lines) >= 10, len(cls.lines)

    def hits(self, as_string=False):
        evs = [{'source': json.dumps(x) if as_string else dict(x)} for x in self.lines]
        return ee.parse_trap(200, {'success': True, 'result': {'events': {'events': evs}}})['hits']

    def test_every_kind_the_page_checks_is_a_kind_remotepower_files_as_evidence(self):
        for kind in {l['kind'] for l in self.lines}:
            self.assertIn(kind, ee._TRAP_TOKEN, kind)
            self.assertTrue(te.TRAP_KINDS.get(ee._TRAP_TOKEN[kind]), kind)

    def test_both_wrappers_read_the_same_hits_and_none_is_decided(self):
        a, b = self.hits(False), self.hits(True)
        self.assertEqual(len(a), len(self.lines))
        self.assertEqual([h['kind'] for h in a], [h['kind'] for h in b])
        evs, st = ee.trap_events(a, now=1_790_000_000)
        self.assertEqual(st['ignored'], {})
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]['trp'], 0, 'the script never decides, so nothing is a ban')

    def test_the_filed_as_column_is_the_phrase_the_code_uses(self):
        rows = _table(_section(_guide(), 'What each trap catches'))
        seen = set()
        for cells in rows:
            kinds = _kinds_in(cells[1])
            self.assertTrue(kinds, cells)
            for kind in kinds:
                cls = te.TRAP_KINDS[ee._TRAP_TOKEN[kind]]
                self.assertIn(te.CLASSES[cls]['phrase'].lower(), cells[3].lower(), kind)
                seen.add(kind)
        self.assertEqual(seen, {k for k, _ in _traps()} | {'mazeentry', 'maze', 'mazeloot', 'canary_use', 'decoy', 'decoy_login'})

    def test_the_planted_password_and_the_decoy_sign_in_are_their_own_classes(self):
        evs, _ = ee.trap_events([h for h in self.hits() if h['kind'] in ('canary_use', 'decoy_login')],
                                now=1_790_000_000)
        cls = te.classes(evs[0])
        self.assertIn('canary', cls)
        self.assertIn('decoy_login', cls)


# ── the config, and the page around it ─────────────────────────────────────────

class TestTheConfig(unittest.TestCase):

    def test_it_is_the_worker_remotepower_reads_by_default(self):
        cfg = _config()
        self.assertEqual(cfg['name'], ip_intel.DEFAULTS['edge_workers'][0])
        self.assertIs(cfg['observability']['enabled'], True)
        self.assertIs(cfg['workers_dev'], False)
        self.assertEqual(cfg['main'], 'worker.js')

    def test_nothing_that_needs_your_input_is_on_by_default(self):
        """A published default is a known value: a password set here would be known to every
        scanner, and a decoy host would be one nobody chose."""
        cfg = _config()
        self.assertEqual(cfg['vars']['CANARY_PASSWORD'], '')
        self.assertEqual(cfg['vars']['DECOY_HOSTS'], '')
        self.assertEqual(cfg['vars']['ALLOW'], '')
        self.assertFalse([r for r in cfg['routes'] if r.get('custom_domain')],
                         'a Custom Domain line is on by default')

    def test_routes_are_top_level_and_every_route_is_a_trap_the_script_knows(self):
        cfg = _config()
        self.assertNotIn('routes', cfg['vars'])
        paths = []
        for r in cfg['routes']:
            self.assertEqual(r['zone_name'], 'example.com')
            m = re.fullmatch(r'\*example\.com(/[^*?]+?)\*?', r['pattern'])
            self.assertIsNotNone(m, r['pattern'])
            paths.append(r['pattern'].split('example.com', 1)[1])
        self.assertEqual(len(paths), len(set(paths)), 'a route is listed twice')
        prefixes = {'%s*' % p for _, p in _traps()}
        extra = {'/robots.txt', '/backups*'}
        self.assertEqual(set(paths) - prefixes - extra, set())

    def test_every_trap_in_the_script_has_a_route_on_or_commented_out(self):
        text = _config_text()
        have = set(re.findall(r'^\s*#?\s*\{ pattern = "\*example\.com(/[^"]+)"', text, re.M))
        roots = [h[:-1] for h in have if h.endswith('*')]
        for _, prefix in _traps():
            # a route covers every path that starts with it: `/.git*` is the route of
            # `/.git/objects/` too, which is what the page's table says
            self.assertTrue(any(prefix.startswith(r) for r in roots), 'no route covers ' + prefix)
        self.assertIn('/robots.txt', have)
        self.assertIn('/backups*', have)

    def test_the_wordpress_routes_are_off_and_exactly_the_wordpress_traps(self):
        cfg = _config()
        active = {r['pattern'].split('example.com', 1)[1] for r in cfg['routes']}
        wp = {p + '*' for k, p in _traps() if k in ('wpprobe', 'wpenum')}
        self.assertEqual(len(wp), 3)
        self.assertEqual(active & wp, set(), 'a WordPress route is on by default')
        commented = set(re.findall(r'^\s*#\s*\{ pattern = "\*example\.com(/wp[^"]+)"', _config_text(), re.M))
        self.assertEqual(commented, wp)

    def test_every_wordpress_route_that_is_on_is_named_where_a_wordpress_site_looks(self):
        """A WordPress site serves these paths, so the routes for them that are on by
        default are the ones it has to delete. Step 3 tells a WordPress site what to do,
        and the config is where the lines are deleted, so both name each of them."""
        active = {r['pattern'].split('example.com', 1)[1].rstrip('*') for r in _config()['routes']}
        wordpress = [p for _, p in _traps() if p.startswith(('/wp-', '/xmlrpc'))]
        self.assertGreaterEqual(len(wordpress), 5, 'control: the WordPress paths of the script')
        on = [p for p in wordpress if p in active]
        self.assertTrue(on, 'control: no WordPress route is on by default')
        step = [line for line in _section(_guide(), 'Step 3: Choose your traps').splitlines() if 'WordPress' in line]
        self.assertEqual(len(step), 1)
        comments = [line for line in _config_text().splitlines()
                    if line.strip().startswith('#') and 'WordPress' in line]
        for p in on:
            self.assertIn('`%s`' % p, step[0], p)
            self.assertTrue(any(p.lstrip('/') in c for c in comments), 'no config comment names ' + p)

    def test_the_robots_decoys_and_their_routes_agree(self):
        cfg = _config()
        active = {r['pattern'].split('example.com', 1)[1] for r in cfg['routes']}
        decoys = {p + '*' for k, p in _traps() if k == 'robots'}
        self.assertEqual(len(decoys), 3)
        self.assertTrue(decoys <= active)
        self.assertIn('/robots.txt', active)

    def test_with_every_switch_on_it_is_still_valid_toml(self):
        on = re.sub(r'(?m)^(\s*)# (\{ pattern = )', r'\1\2', _config_text())
        on = on.replace('DECOY_HOSTS = ""', 'DECOY_HOSTS = "%s"' % DECOY)
        cfg = tomllib.loads(on)
        self.assertGreater(len(cfg['routes']), len(_config()['routes']))
        domains = [r for r in cfg['routes'] if r.get('custom_domain')]
        self.assertEqual(len(domains), 1)
        self.assertRegex(domains[0]['pattern'], r'^[a-z0-9.-]+$', 'a Custom Domain is a bare host name')
        self.assertNotIn('zone_name', domains[0])
        self.assertIn(domains[0]['pattern'], cfg['vars']['DECOY_HOSTS'].split(','))

    def test_the_decoy_host_in_the_commented_example_is_the_one_the_check_table_asks_for(self):
        self.assertIn('"%s"' % DECOY, _config_text())
        self.assertTrue(any(DECOY in c for c, _ in _check_rows()))


class TestThePage(unittest.TestCase):

    def test_the_numbers_are_the_codes(self):
        guide, script = _guide(), _script()
        self.assertIn('which is %d unless you changed it' % ip_intel.DEFAULTS['report_min_count'], guide)
        self.assertEqual(re.search(r'pw\.length >= (\d+)', script).group(1), '12')
        self.assertIn('12 or more random letters', guide)
        self.assertEqual(re.search(r'length <= (\d+)', script).group(1), '4096')
        self.assertIn('up to 4 KB', guide)
        self.assertIn('4 KB or less', guide)

    def test_the_three_robots_decoys_and_the_three_wordpress_routes_are_what_the_steps_say(self):
        kinds = [k for k, _ in _traps()]
        self.assertEqual(kinds.count('robots'), 3)
        self.assertEqual(kinds.count('wpprobe') + kinds.count('wpenum'), 3)
        guide = _guide()
        self.assertIn('Edit the three `robots` lines', guide)
        self.assertIn('the three matching routes', guide)
        self.assertIn('the three WordPress routes', guide)

    def test_the_pages_link_each_other_and_the_index_lists_this_one(self):
        guide = _guide()
        self.assertIn('(honeypot-worker.md)', guide)
        self.assertIn('(honeypot-worker.md#block-what-it-finds)', guide)
        for rel in ('README.md', 'honeypot-worker.md'):
            p = _ROOT / 'docs' / rel
            if not p.exists():
                self.skipTest('docs excluded from this tree')
            self.assertIn('(honeypot-traps.md)', p.read_text(), rel)
        intro = _read(_FIRST_PATH).split('On this page:')[0]
        self.assertIn('(honeypot-traps.md)', intro, 'the first guide points to this one where it begins')

    def test_the_section_this_page_points_to_exists_and_is_in_the_first_guides_contents(self):
        first = _read(_FIRST_PATH)
        self.assertRegex(first, r'(?m)^## Block what it finds$')
        self.assertIn('(#block-what-it-finds)', first)

    def test_it_says_what_it_leaves_out(self):
        sec = _section(_guide(), 'What this page leaves out')
        for word in ('search engine', 'Private host names', 'Answering back', 'A ban in the Worker'):
            self.assertIn(word, sec, word)

    def test_it_is_a_public_page(self):
        self.assertEqual(H.voice_problems(_guide()), [])

    def test_every_address_in_it_is_a_documentation_or_loopback_address(self):
        n, bad = H.address_problems(_guide())
        self.assertGreaterEqual(n, 1, 'control: the scan found nothing to check')
        self.assertEqual(bad, [])

    def test_it_stays_inside_what_the_in_app_viewer_renders(self):
        self.assertEqual(H.viewer_problems(_guide()), [])


if __name__ == '__main__':
    unittest.main()
