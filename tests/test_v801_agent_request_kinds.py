"""The Linux agent says what kind of probing a request was (8.0.1).

The sensor had one pattern for "a file nobody legitimately requests" and one kind for it, `probe`; an open-proxy
request and a refused admin tool were `probe` too. So a report could only say "probing". The one pattern is four
now, and the classifier answers `config`, `wordpress`, `enum`, `probe`, `proxy` or `admin`.

What has to hold:

  * splitting the pattern moved nothing in or out: the four match exactly what the one matched. The 8.0.0 pattern is
    kept below as the reference, and a corpus built from its own alternatives is run through both;
  * a request that was `probe` is exactly one of the six kinds now, the one its target names, and a request that was
    something else is what it was;
  * every kind the classifier can return is a kind the server knows, so nothing the agent sends is dropped;
  * a 2xx answer still counts as "answered" for the kinds that need no refusal to be hostile.
"""
import ast
import importlib.util
import itertools
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-kinds-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402
from test_v720_threat_sensor_agent import A1, NOW, combined, run_access  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_AGENT = _ROOT / 'client' / 'remotepower-agent.py'

# The pattern as 8.0.0 had it, kept as the reference the four are held to. Not used by any code.
OLD_PROBE = re.compile(
    r'/\.(?:env|git|svn|hg|ds_store|aws|ssh|bash_history|htpasswd|npmrc|docker|kube|vscode|idea|'
    r'gitlab-ci\.yml|travis\.yml)(?:[/.?]|$)|'
    r'/wp-config(?:\.php)?(?:\.|~|$)|'
    r'\.(?:bak|old|orig|save|swp|sql|dump)(?:$|\?)|'
    r'/(?:backup|backups|db|dump|database|site|www|wwwroot|web|public_html|html|htdocs)\.'
    r'(?:zip|tar|tgz|gz|7z|rar|sql)(?:$|\?)|'
    r'/composer\.(?:json|lock)(?:$|\?)|/wp-admin/(?:setup-config|install)\.php|'
    r'/wp-content/plugins/[^/]+/(?:readme|changelog)\.txt|[?&]author=\d+(?:$|&)|'
    r'/(?:id_rsa|id_dsa|authorized_keys)(?:$|\?)|/(?:sftp|ftp)-config\.json|/\.dockerenv|'
    r'/phpunit\.xsd', re.I)

DOTFILES = ('env', 'git', 'svn', 'hg', 'ds_store', 'aws', 'ssh', 'bash_history', 'htpasswd', 'npmrc', 'docker', 'kube',
            'vscode', 'idea', 'gitlab-ci.yml', 'travis.yml')
LEFTOVERS = ('bak', 'old', 'orig', 'save', 'swp', 'sql', 'dump')
ARCHIVES = ('backup', 'backups', 'db', 'dump', 'database', 'site', 'www', 'wwwroot', 'web', 'public_html', 'html', 'htdocs')
PACKED = ('zip', 'tar', 'tgz', 'gz', '7z', 'rar', 'sql')


def load_agent():
    spec = importlib.util.spec_from_file_location('agent_request_kinds', _AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def corpus():
    """Request targets made from every alternative of the 8.0.0 pattern, each written the ways a scanner writes it and the
    ways that should not match, and near-misses."""
    hits = ['/.' + d for d in DOTFILES]
    hits += ['/wp-config.php', '/wp-config', '/wp-config.php.bak', '/wp-config.php~', '/wp-config.old']
    hits += ['/index.php.' + x for x in LEFTOVERS] + ['/data.' + x for x in LEFTOVERS]
    hits += [f'/{a}.{p}' for a, p in itertools.product(ARCHIVES, PACKED)]
    hits += ['/composer.json', '/composer.lock', '/wp-admin/setup-config.php', '/wp-admin/install.php',
             '/wp-content/plugins/akismet/readme.txt', '/wp-content/plugins/x/changelog.txt',
             '/?author=1', '/blog/?p=2&author=37', '/id_rsa', '/id_dsa', '/authorized_keys', '/sftp-config.json',
             '/ftp-config.json', '/.dockerenv', '/phpunit.xsd']
    near = ['/', '/index.html', '/env', '/.environment', '/.gitx', '/wp-configuration', '/wp-config-sample.php',
            '/backup', '/backup.txt', '/db.json', '/composer.phar', '/wp-admin/', '/wp-admin/admin-ajax.php',
            '/wp-content/plugins/akismet/', '/wp-content/themes/x/readme.txt', '/?authors=1', '/?author=x', '/id_rsa.pub.txt',
            '/sftp-config.json5', '/phpunit.xml', '/robots.txt', '/favicon.ico', '/static/app.old.js', '/bakery', '/a.sqlite',
            '/about.html?ref=.env', '/search?q=backup.zip.exe', '/img/site.png', '/www', '/web.config', '/html/index.htm']
    out = set()
    for t in hits + near:
        for shape in (t, '/sub' + t, '/a/b' + t, t + '/', t + '?x=1', t + '.txt', t.upper(), quote(t, safe='/?&='),
                      quote(quote(t, safe='/?&='), safe='/?&=%'), t + '/HEAD', t + '&x=1', 'https://example.com' + t):
            out.add(shape)
    return sorted(out)


class _Agent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()
        cls.four = (cls.agent._TS_RE_CONFIG, cls.agent._TS_RE_WORDPRESS, cls.agent._TS_RE_ENUM, cls.agent._TS_RE_PROBE)


class TestTheSplitMovedNothing(_Agent):
    def test_the_four_patterns_match_what_the_one_matched(self):
        targets = corpus()
        self.assertGreater(len(targets), 1500)
        matched = 0
        for t in targets:
            u = self.agent._ts_decode(t)
            old = bool(OLD_PROBE.search(u))
            new = [bool(rx.search(u)) for rx in self.four]
            self.assertEqual(any(new), old, t)
            matched += old
        self.assertGreater(matched, 500, 'the corpus has to hold matches')
        self.assertGreater(len(targets) - matched, 500, '... and targets that do not match')

    def test_each_of_the_four_is_reached_and_each_has_targets_it_leaves_alone(self):
        targets = [self.agent._ts_decode(t) for t in corpus()]
        for rx, name in zip(self.four, ('config', 'wordpress', 'enum', 'probe')):
            hits = sum(1 for u in targets if rx.search(u))
            self.assertGreater(hits, 3, name)
            self.assertLess(hits, len(targets), name)

    def test_the_four_share_the_reference_patterns_alternatives(self):
        """Every alternative of the 8.0.0 pattern is in exactly one of the four, and they hold nothing else."""
        def alternatives(pattern):
            out, depth, cur = [], 0, ''
            for ch in pattern:
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                if ch == '|' and depth == 0:
                    out.append(cur)
                    cur = ''
                else:
                    cur += ch
            return out + [cur]
        old = alternatives(OLD_PROBE.pattern)
        new = [a for rx in self.four for a in alternatives(rx.pattern)]
        self.assertEqual(len(old), 12)
        self.assertEqual(sorted(new), sorted(old))
        self.assertEqual({rx.flags for rx in self.four}, {OLD_PROBE.flags})


class TestTheKindOfARequest(_Agent):
    def kinds(self, method, target, status=404, ua=''):
        return self.agent._ts_classify(method, target, status, ua)

    def was(self, method, target, status):
        """What 8.0.0 called this request, from its three rules for `probe`; None when it was not a probe."""
        u = self.agent._ts_decode(target)
        for rx in (self.agent._TS_RE_RCE, self.agent._TS_RE_SQLI, self.agent._TS_RE_TRAVERSAL, self.agent._TS_RE_XSS):
            if rx.search(u):
                return None
        if method == 'POST' and self.agent._TS_RE_LOGIN.match(u):
            return None
        if OLD_PROBE.search(u) or method == 'CONNECT' or u.startswith(('http://', 'https://', 'ftp://')):
            return 'probe'
        if status in (400, 403, 404, 405, 410, 444) and self.agent._TS_RE_PROBE_REFUSED.search(u):
            return 'probe'
        return None

    def test_named_requests(self):
        for method, target, status, want in (
                ('GET', '/.env', 404, 'config'), ('GET', '/.git/config', 200, 'config'), ('GET', '/wp-config.php.bak', 404, 'config'),
                ('GET', '/backup.zip', 404, 'config'), ('GET', '/db.sql', 403, 'config'), ('GET', '/composer.json', 200, 'config'),
                ('GET', '/id_rsa', 404, 'config'), ('GET', '/.aws/credentials', 404, 'config'),
                ('GET', '/?author=3', 200, 'enum'), ('GET', '/blog/?author=12&x=1', 301, 'enum'),
                ('GET', '/wp-admin/install.php', 404, 'wordpress'), ('GET', '/wp-admin/setup-config.php', 200, 'wordpress'),
                ('GET', '/wp-content/plugins/x/readme.txt', 200, 'wordpress'),
                ('GET', '/phpunit.xsd', 404, 'probe'),
                ('CONNECT', 'example.com:443', 400, 'proxy'), ('GET', 'http://example.com/', 400, 'proxy'),
                ('GET', 'ftp://example.com/x', 400, 'proxy'),
                ('GET', '/phpmyadmin/', 404, 'admin'), ('GET', '/server-status', 403, 'admin'), ('GET', '/actuator', 404, 'admin'),
                ('GET', '/cgi-bin/test', 403, 'admin')):
            self.assertEqual(self.kinds(method, target, status), (want,), (method, target, status))

    def test_what_a_real_site_serves_is_nothing_when_it_is_served(self):
        for target in ('/phpmyadmin/', '/server-status', '/actuator', '/info.php'):
            for status in (200, 301, 401):
                self.assertEqual(self.kinds('GET', target, status), (), (target, status))

    def test_an_attack_is_still_that_attack_and_never_a_kind_of_probing(self):
        self.assertEqual(self.kinds('GET', "/.env?x=1' union select 1,2 from users--"), ('sqli',))
        self.assertEqual(self.kinds('GET', '/.git/../../etc/passwd'), ('traversal',))
        self.assertEqual(self.kinds('GET', '/wp-config.php.bak?a=${jndi:ldap://e/a}'), ('rce',))
        self.assertEqual(self.kinds('POST', '/wp-login.php', 200), ('login',))
        self.assertEqual(self.kinds('GET', '/.env', 404, 'zgrab/0.x'), ('config', 'scanner'))

    def test_what_was_a_probe_is_one_of_the_six_and_what_was_not_is_unchanged(self):
        probe_kinds = {'config', 'wordpress', 'enum', 'probe', 'proxy', 'admin'}
        seen, was_probe = set(), 0
        targets = corpus() + ['/phpmyadmin/', '/pma/index.php', '/server-status', '/cgi-bin/x', '/manager/html', '/solr/',
                              '/index.php?id=1 union select 1,2', '/a/../../etc/passwd', '/x?<script>alert(1)</script>']
        for method, target, status in itertools.product(('GET', 'POST', 'CONNECT'), targets, (200, 404)):
            got = [k for k in self.kinds(method, target, status) if k != 'scanner']
            before = self.was(method, target, status)
            if before == 'probe':
                was_probe += 1
                self.assertEqual(len(got), 1, (method, target, status))
                self.assertIn(got[0], probe_kinds, (method, target, status))
                seen.add(got[0])
            else:
                self.assertEqual(set(got) & probe_kinds, set(), (method, target, status, got))
        self.assertGreater(was_probe, 2000)
        self.assertEqual(seen, probe_kinds, 'a kind this battery never reached')


class TestTheServerKnowsEveryKind(_Agent):
    def returned(self):
        """The kinds _ts_classify can return, read from its source: every string it assigns to `kind`, and 'scanner'."""
        src = _AGENT.read_text()
        fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == '_ts_classify')
        kinds = {n.value.value for n in ast.walk(fn)
                 if isinstance(n, ast.Assign) and any(getattr(t, 'id', '') == 'kind' for t in n.targets)
                 and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)}
        appended = {a.value for n in ast.walk(fn) if isinstance(n, ast.Call) and getattr(n.func, 'attr', '') == 'append'
                    for a in n.args if isinstance(a, ast.Constant)}
        return kinds | appended

    def test_the_classifier_returns_these_kinds(self):
        self.assertEqual(self.returned(), {'rce', 'sqli', 'traversal', 'xss', 'login', 'config', 'enum', 'wordpress', 'probe',
                                           'proxy', 'admin', 'flood', 'scanner'})

    def test_each_is_a_request_kind_of_the_servers(self):
        for kind in self.returned():
            self.assertIn(kind, te._REQ_KINDS, kind)
            self.assertTrue(te.token_valid('req:' + kind), kind)
        want = {'config': 'config_probe', 'wordpress': 'wordpress', 'enum': 'user_enum', 'proxy': 'proxy_probe',
                'admin': 'admin_probe', 'probe': 'probe'}
        self.assertEqual({k: te._REQ_KINDS[k] for k in want}, want)

    def test_a_kind_that_needs_no_refusal_counts_as_answered(self):
        self.assertEqual(set(self.agent._TS_ANSWERABLE), {'probe', 'config', 'wordpress', 'enum', 'proxy', 'rce', 'sqli',
                                                          'traversal', 'xss'})
        lines = [combined(A1, NOW - 60 + i, 'GET /.env HTTP/1.1', 200) for i in range(3)]
        lines += [combined(A1, NOW - 50 + i, 'GET /phpmyadmin/ HTTP/1.1', 200) for i in range(3)]
        _agg, ev, *_ = run_access(self.agent, lines)
        self.assertEqual(ev[A1]['tok']['web'], {'req:config': 3}, 'an admin tool that answered is the operator, not a hit')
        self.assertEqual((ev[A1]['ans'], ev[A1]['src']), (3, {'web': 3}))

    def test_what_the_agent_sends_is_what_a_report_says(self):
        lines = ([combined(A1, NOW - 90 + i, 'GET /.env HTTP/1.1', 404) for i in range(4)]
                 + [combined(A1, NOW - 80 + i, 'GET /wp-admin/install.php HTTP/1.1', 404) for i in range(3)]
                 + [combined(A1, NOW - 70 + i, 'GET /?author=%d HTTP/1.1' % i, 200) for i in range(3)]
                 + [combined(A1, NOW - 60, 'CONNECT example.com:443 HTTP/1.1', 400)])
        _agg, ev, *_ = run_access(self.agent, lines)
        self.assertEqual(ev[A1]['tok']['web'], {'req:config': 4, 'req:wordpress': 3, 'req:enum': 3, 'req:proxy': 1})
        e = te.normalize_event(ev[A1], now=NOW)
        self.assertEqual(e['tok']['web'], ev[A1]['tok']['web'], 'the server keeps every token the agent sent')
        self.assertEqual(te.classes(e), {'config_probe': 4, 'wordpress': 3, 'user_enum': 3, 'proxy_probe': 1})
        text = ip_intel.evidence_comment(e)
        self.assertTrue(text.startswith('probing for configuration files, keys and backups, '), text)
        self.assertNotIn('probing for exposed files and admin pages', text)

    def test_a_denied_path_in_apaches_log_is_named_by_what_was_asked_for(self):
        """AH01630 names the path it denied. The pattern for the path did not know that message, so every denied
        request was the general `probe`."""
        m = self.agent._TS_APC_FILE_RE.search('AH01630: client denied by server configuration: /var/www/html/.git/config')
        self.assertEqual(m.group(1), '/var/www/html/.git/config')
        self.assertEqual(self.agent._ts_classify('GET', m.group(1), 403), ('config',))
        self.assertIsNone(self.agent._TS_APC_FILE_RE.search('AH00489: Apache/2.4.58 configured -- resuming normal operations'))


if __name__ == '__main__':
    unittest.main()
