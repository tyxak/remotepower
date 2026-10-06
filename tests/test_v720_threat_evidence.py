"""threat_evidence: the closed vocabulary between a host's logs and a report.

The agent is root on a machine an attacker may already be on, and a report is
public and filed under the operator's account. So the two things worth proving
are that nothing outside the vocabulary survives ingest, and that nothing an
attacker typed can reach the words of a report.
"""
import ipaddress
import random
import re
import string
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import threat_evidence as te  # noqa: E402

NOW = 1_790_000_000
ATTACKER = '185.220.101.7'

# What AbuseIPDB and SniffCat document, so a category id that does not exist
# fails here instead of in a 422 from the provider.
ABUSEIPDB_IDS = set(range(1, 24))
SNIFFCAT_IDS = set(range(1, 28))


def ev(**kw):
    """A normalised event for ATTACKER with whatever the test sets."""
    raw = {'ip': ATTACKER, 'first': NOW - 600, 'last': NOW}
    raw.update(kw)
    out = te.normalize_event(raw, now=NOW)
    assert out is not None, raw
    return out


class TestNormalize(unittest.TestCase):
    def test_only_public_addresses_survive(self):
        for ip in ('10.0.0.5', '192.168.1.1', '127.0.0.1', '169.254.1.1', '::1',
                   'fd00::1', '224.0.0.1', '203.0.113.9', 'not-an-ip', '', None, 7):
            self.assertIsNone(te.normalize_event({'ip': ip, 'src': {'web': 5}}, now=NOW), ip)
        self.assertEqual(te.normalize_event({'ip': '::ffff:8.8.8.8', 'src': {'web': 5}}, now=NOW)['ip'],
                         '8.8.8.8')
        self.assertEqual(te.normalize_event({'ip': '2a0b:f4c0:16c:1::77', 'src': {'web': 5}}, now=NOW)['ip'],
                         '2a0b:f4c0:16c:1::77')

    def test_not_a_dict_and_no_evidence(self):
        for raw in (None, [], 'x', 3, {'ip': ATTACKER}, {'ip': ATTACKER, 'src': {}, 'tok': {}}):
            self.assertIsNone(te.normalize_event(raw, now=NOW))

    def test_tokens_outside_the_vocabulary_are_dropped(self):
        good = ['req:sqli', 'crs:942100', 'crstag:attack-sqli', 'jail:sshd',
                'cs:crowdsecurity/ssh-bf']
        bad = ['req:drop table', 'req:SQLI', 'crs:abc', 'crs:12', 'crstag:paranoia-level/1',
               'jail:', 'jail:a b', 'jail:x\ny', 'jail:' + 'a' * 41, 'cs:../etc/passwd',
               'cs:' + 'a' * 97, 'x:y', 'sqli', '', 'req:sqli\n', 'jail:ok\x00']
        out = te.normalize_event(
            {'ip': ATTACKER, 'tok': {'web': {t: 3 for t in good + bad}}}, now=NOW)
        self.assertEqual(sorted(out['tok']['web']), sorted(good))
        for t in bad:
            self.assertNotIn(t, out['tok']['web'])

    def test_non_token_values_are_dropped(self):
        out = te.normalize_event({'ip': ATTACKER, 'tok': {'web': {'req:sqli': 2, 7: 3, None: 1, ('a',): 1}}}, now=NOW)
        self.assertEqual(out['tok'], {'web': {'req:sqli': 2}})

    def test_counts_are_clamped_and_never_negative(self):
        out = te.normalize_event({'ip': ATTACKER, 'src': {'web': -5, 'waf': 10 ** 12, 'f2b': True, 'cs': 'x', 'err': 2.9},
                                  'ans': -1, 'blk': 10 ** 9, 'dec': 'many'}, now=NOW)
        self.assertEqual(out['src'], {'waf': 1_000_000, 'err': 2})
        self.assertEqual((out['ans'], out['blk'], out['dec']), (0, 1_000_000, 0))

    def test_unknown_families_are_ignored(self):
        out = te.normalize_event({'ip': ATTACKER, 'src': {'web': 1, 'evil': 9},
                                  'tok': {'web': {'req:sqli': 1}, 'evil': {'req:sqli': 9}}}, now=NOW)
        self.assertEqual(set(out['src']), {'web'})
        self.assertEqual(set(out['tok']), {'web'})

    def test_token_and_jail_and_cve_caps(self):
        toks = {f'crs:{942000 + i}': 100 - i for i in range(60)}
        out = te.normalize_event({
            'ip': ATTACKER, 'tok': {'waf': toks},
            'ban': [f'jail{i}' for i in range(30)] + ['bad jail', 7],
            'cve': ['CVE-2021-44228', 'CVE-2021-44228', 'cve-2021-1', 'CVE-1-2'] + [f'CVE-2023-{1000 + i}' for i in range(20)],
        }, now=NOW)
        self.assertEqual(len(out['tok']['waf']), 24)
        self.assertIn('crs:942000', out['tok']['waf'], 'the biggest counts are the ones kept')
        self.assertEqual(len(out['ban']), 8)
        self.assertNotIn('bad jail', out['ban'])
        self.assertEqual(len(out['cve']), 5)
        nl = te.normalize_event({'ip': ATTACKER, 'src': {'web': 1}, 'ban': ['sshd\n', 'ok-jail'],
                                 'cve': ['CVE-2021-44228\n', 'CVE-2021-44229']}, now=NOW)
        self.assertEqual((nl['ban'], nl['cve']), (['ok-jail'], ['CVE-2021-44229']),
                         'a trailing newline got through a `$` anchor')
        self.assertEqual(out['cve'].count('CVE-2021-44228'), 1)
        self.assertTrue(all(re.fullmatch(r'CVE-\d{4}-\d{4,7}', c) for c in out['cve']))

    def test_timestamps_are_clamped_and_ordered(self):
        out = te.normalize_event({'ip': ATTACKER, 'src': {'web': 1}, 'first': NOW + 10 ** 6, 'last': 5}, now=NOW)
        self.assertLessEqual(out['last'], NOW + 300)
        self.assertGreaterEqual(out['first'], NOW - 7 * 86400)
        self.assertLessEqual(out['first'], out['last'])
        out = te.normalize_event({'ip': ATTACKER, 'src': {'web': 1}, 'first': 'x', 'last': None}, now=NOW)
        self.assertEqual((out['first'], out['last']), (NOW, NOW))


class TestRuleTables(unittest.TestCase):
    JAILS = {
        'sshd': 'ssh_brute', 'openssh': 'ssh_brute',
        'nginx-http-auth': 'login_brute', 'apache-auth': 'login_brute',
        'wordpress-hard': 'login_brute', 'web-wordpress': 'login_brute',
        'nginx-wplogin': 'login_brute', 'nginx-xmlrpc': 'login_brute',
        'roundcube-auth': 'login_brute',
        'nginx-botsearch': 'probe', 'apache-noscript': 'probe', 'apache-nohome': 'probe',
        'apache-overflows': 'probe', 'nginx-noproxy': 'probe',
        'nginx-sensitive-files': 'probe', 'nginx-blocked': 'probe',
        'nginx-limit-req': 'flood', 'nginx-dos': 'flood',
        'apache-badbots': 'bad_bot', 'nginx-unwanted-bots': 'bad_bot',
        'apache-fakegooglebot': 'bad_bot',
        'modsec': 'waf', 'apache-modsecurity': 'waf',
        'apache-shellshock': 'rce', 'nginx-php-injection': 'rce', 'nginx-rce': 'rce',
        'php-url-fopen': 'traversal',
        'postfix': 'mail_brute', 'postfix-sasl': 'mail_brute', 'dovecot': 'mail_brute',
        'courier-auth': 'mail_brute',
        'proftpd': 'ftp_brute', 'vsftpd': 'ftp_brute', 'pure-ftpd': 'ftp_brute',
        'mysqld-auth': 'service_brute', 'rdp': 'service_brute',
        'portscan': 'port_scan',
        'recidive': None, 'named-refused': None, '': None,
    }

    def test_jail_names(self):
        for name, want in self.JAILS.items():
            self.assertEqual(te.jail_class(name), want, name)

    def test_a_short_token_inside_a_longer_word_is_not_a_match(self):
        """`rdp` is inside `wordpress` and `rce` inside `force`. Matching
        substrings reported a WordPress jail as an RDP brute-forcer."""
        for name in ('wordpress-hard', 'nginx-brute-force', 'resource-guard', 'source-ip',
                     'author-enum', 'swpscan'):
            self.assertNotIn(te.jail_class(name), ('service_brute', 'rce', 'flood'), name)
        self.assertEqual(te.jail_class('wordpress-hard'), 'login_brute')
        self.assertIsNone(te.jail_class('nginx-brute-force'))

    SCENARIOS = {
        'crowdsecurity/ssh-bf': 'ssh_brute', 'crowdsecurity/ssh-slow-bf': 'ssh_brute',
        'crowdsecurity/ssh-cve-2024-6387': 'ssh_brute',
        'crowdsecurity/http-probing': 'probe', 'crowdsecurity/http-sensitive-files': 'probe',
        'crowdsecurity/http-admin-interface-probing': 'probe',
        'crowdsecurity/http-wordpress-scan': 'probe', 'crowdsecurity/http-open-proxy': 'probe',
        'crowdsecurity/http-sqli-probing': 'sqli', 'crowdsecurity/http-xss-probing': 'xss',
        'crowdsecurity/http-path-traversal-probing': 'traversal',
        'crowdsecurity/http-bad-user-agent': 'scanner',
        'crowdsecurity/http-wordpress_bf': 'login_brute', 'crowdsecurity/http-generic-bf': 'login_brute',
        'LePresidente/http-generic-401-bf': 'login_brute',
        'crowdsecurity/http-backdoors-attempts': 'rce', 'crowdsecurity/http-cve-probing': 'rce',
        'crowdsecurity/vpatch-CVE-2023-1234': 'rce',
        'crowdsecurity/apache_log4j2_cve-2021-44228': 'rce',
        'crowdsecurity/appsec-generic': 'waf',
        'crowdsecurity/nginx-req-limit-exceeded': 'flood',
        'crowdsecurity/postfix-spam': 'mail_brute',
        'crowdsecurity/mysql-bf': 'service_brute',
        'crowdsecurity/iptables-scan-multi_ports': 'port_scan',
        # an aggressive crawler is not an attack, so it is not reported as one
        'crowdsecurity/http-crawl-non_statics': None,
    }

    def test_crowdsec_scenarios(self):
        for name, want in self.SCENARIOS.items():
            self.assertEqual(te.scenario_class(name), want, name)

    def test_crs_rule_ranges(self):
        want = {913100: 'scanner', 920350: 'waf', 921110: 'waf', 930100: 'traversal',
                931100: 'traversal', 932100: 'rce', 933150: 'rce', 934100: 'rce',
                941100: 'xss', 942100: 'sqli', 943100: 'waf', 944150: 'rce',
                1000010: 'waf',
                # summaries of the transaction and rules about OUR response
                949110: None, 959100: None, 980130: None, 950130: None, 910100: None}
        for rid, cls in want.items():
            self.assertEqual(te.crs_class(rid), cls, rid)
        self.assertIsNone(te.crs_class('x'))
        self.assertIsNone(te.crs_class(None))

    def test_crs_tags_and_request_kinds(self):
        self.assertEqual(te.token_class('crstag:attack-sqli'), 'sqli')
        self.assertEqual(te.token_class('crstag:attack-lfi'), 'traversal')
        self.assertEqual(te.token_class('crstag:attack-reputation-scanner'), 'scanner')
        self.assertIsNone(te.token_class('crstag:attack-disclosure'))
        for kind, cls in (('sqli', 'sqli'), ('xss', 'xss'), ('traversal', 'traversal'),
                          ('rce', 'rce'), ('probe', 'probe'), ('scanner', 'scanner'),
                          ('login', 'login_brute'), ('flood', 'flood')):
            self.assertEqual(te.token_class(f'req:{kind}'), cls)
        self.assertIsNone(te.token_class('req:nonsense'))
        self.assertIsNone(te.token_class(None))

    def test_the_registry_has_no_dead_class_and_no_invented_category(self):
        """A control: the population is not empty, every class can be reached
        from some token, and every category id exists at the provider."""
        self.assertGreaterEqual(len(te.CLASSES), 14)
        reachable = set(te._REQ_KINDS.values()) | set(te._CRS_TAGS.values())
        reachable |= {c for c, _ in te._JAIL_RULES} | {c for c, _ in te._CS_RULES}
        reachable |= {te.crs_class(i) for i in range(900000, 1000000, 1000)} - {None}
        self.assertEqual(set(te.CLASSES) - reachable, set(), 'a class no token can produce')
        for name, c in te.CLASSES.items():
            self.assertTrue(c['abuseipdb'] and c['sniffcat'], name)
            self.assertTrue(set(c['abuseipdb']) <= ABUSEIPDB_IDS, name)
            self.assertTrue(set(c['sniffcat']) <= SNIFFCAT_IDS, name)
            self.assertGreater(c['weight'], 0, name)
            self.assertGreaterEqual(len(c['phrase']), 5, name)


class TestEvidenceMath(unittest.TestCase):
    def test_a_class_takes_the_largest_count_never_the_sum(self):
        e = ev(tok={'web': {'req:sqli': 40}, 'waf': {'crs:942100': 40, 'crs:942190': 12,
                                                     'crstag:attack-sqli': 40}})
        self.assertEqual(te.classes(e)['sqli'], 40)

    def test_hostile_count_is_the_largest_family(self):
        e = ev(src={'web': 40, 'waf': 12, 'f2b': 7})
        self.assertEqual(te.hostile_count(e), 40)
        self.assertEqual(te.hostile_count(ev(tok={'web': {'req:xss': 9}})), 9)

    def test_the_generic_waf_class_steps_aside_for_a_specific_one(self):
        e = ev(src={'waf': 9}, tok={'waf': {'crs:942100': 9}})
        self.assertEqual([c for c, _ in te.dominant(e)], ['sqli'])
        only_waf = ev(src={'waf': 9}, tok={'waf': {'crs:920350': 9}})
        self.assertEqual([c for c, _ in te.dominant(only_waf)], ['waf'])

    def test_dominant_orders_by_weight_times_count(self):
        e = ev(tok={'web': {'req:rce': 2, 'req:probe': 30, 'req:sqli': 1}})
        self.assertEqual([c for c, _ in te.dominant(e)], ['probe', 'rce', 'sqli'])
        self.assertEqual(len(te.dominant(ev(tok={'web': {f'req:{k}': 5 for k in
                                                         ('sqli', 'xss', 'rce', 'probe', 'scanner')}}))), 3)

    def test_qualifies(self):
        # nothing recognisable: never reportable, whatever the count
        ok, why = te.qualifies(ev(src={'web': 500}, tok={'web': {'jail:recidive': 500}}), 10)
        self.assertFalse(ok)
        self.assertIn('nothing recognisable', why)
        # a ban is enough on its own
        ok, why = te.qualifies(ev(ban=['sshd'], tok={'f2b': {'jail:sshd': 1}}), 10)
        self.assertEqual((ok, why), (True, 'confirmed by fail2ban'))
        ok, why = te.qualifies(ev(dec=1, tok={'cs': {'cs:crowdsecurity/ssh-bf': 6}}), 10)
        self.assertEqual((ok, why), (True, 'confirmed by CrowdSec'))
        # the WAF refusing it three times is enough
        ok, why = te.qualifies(ev(src={'waf': 3}, tok={'waf': {'crs:942100': 3}}), 10)
        self.assertTrue(ok)
        self.assertIn('WAF 3 times', why)
        ok, why = te.qualifies(ev(src={'waf': 2}, tok={'waf': {'crs:942100': 2}}), 10)
        self.assertFalse(ok)
        # otherwise the operator's own threshold
        ok, _ = te.qualifies(ev(src={'web': 10}, tok={'web': {'req:probe': 10}}), 10)
        self.assertTrue(ok)
        ok, why = te.qualifies(ev(src={'web': 4}, tok={'web': {'req:probe': 4}}), 10)
        self.assertEqual((ok, why), (False, '4 of 10 attempts so far'))
        ok, _ = te.qualifies(ev(src={'web': 1}, tok={'web': {'req:probe': 1}}), 0)
        self.assertTrue(ok, 'a threshold of 0 behaves as 1')

    def test_categories_follow_the_evidence(self):
        ssh = ev(ban=['sshd'])
        self.assertEqual(te.categories(ssh, 'abuseipdb'), [18, 22])
        self.assertEqual(te.categories(ssh, 'sniffcat'), [17, 18])
        sqli = ev(tok={'web': {'req:sqli': 12}})
        self.assertEqual(te.categories(sqli, 'abuseipdb'), [16, 21])
        self.assertEqual(te.categories(sqli, 'sniffcat'), [12, 21])
        both = ev(tok={'web': {'req:sqli': 12, 'req:traversal': 5, 'req:rce': 1}})
        a = te.categories(both, 'abuseipdb')
        self.assertTrue({16, 21, 15} <= set(a), a)
        self.assertEqual(len(a), len(set(a)), 'a category listed twice')
        self.assertTrue({12, 16, 13, 21} <= set(te.categories(both, 'sniffcat')))
        self.assertEqual(te.categories(ev(tok={'f2b': {'jail:recidive': 1}}, ban=['recidive']), 'abuseipdb'), [])

    def test_category_ids_always_exist_at_the_provider(self):
        # one token per class that names it, so each class is exercised alone
        token = {'ssh_brute': 'jail:sshd', 'login_brute': 'req:login', 'sqli': 'req:sqli',
                 'xss': 'req:xss', 'traversal': 'req:traversal', 'rce': 'req:rce',
                 'probe': 'req:probe', 'scanner': 'req:scanner', 'flood': 'req:flood',
                 'bad_bot': 'jail:apache-badbots', 'waf': 'crs:920350',
                 'mail_brute': 'jail:postfix', 'ftp_brute': 'jail:proftpd',
                 'service_brute': 'jail:mysqld-auth', 'port_scan': 'jail:portscan'}
        self.assertEqual(set(token), set(te.CLASSES), 'a class with no token in this test')
        for cls, tok in token.items():
            e = ev(tok={'web': {tok: 5}})
            self.assertEqual(list(te.classes(e)), [cls], cls)
            for prov, ids in (('abuseipdb', ABUSEIPDB_IDS), ('sniffcat', SNIFFCAT_IDS)):
                got = te.categories(e, prov)
                self.assertTrue(got, (cls, prov))
                self.assertTrue(set(got) <= ids, (cls, prov, got))

    def test_web_only(self):
        self.assertTrue(te.web_only(ev(tok={'web': {'req:sqli': 4, 'req:login': 2}})))
        self.assertFalse(te.web_only(ev(ban=['sshd'])))
        self.assertFalse(te.web_only(ev(tok={'web': {'req:sqli': 4}}, ban=['postfix'])))


class TestMerge(unittest.TestCase):
    def test_counts_add_and_nothing_is_changed(self):
        a = ev(src={'web': 10, 'waf': 2}, tok={'web': {'req:sqli': 10}}, ans=1, blk=5,
               ban=['sshd'], cve=['CVE-2021-44228'], first=NOW - 900, last=NOW - 300)
        b = ev(src={'web': 5, 'f2b': 1}, tok={'web': {'req:sqli': 5, 'req:xss': 2}}, ans=2, blk=1,
               ban=['sshd', 'postfix'], dec=1, cve=['CVE-2022-22965'], first=NOW - 200, last=NOW)
        snap_a, snap_b = repr(a), repr(b)
        m = te.merge(a, b)
        self.assertEqual(m['src'], {'web': 15, 'waf': 2, 'f2b': 1})
        self.assertEqual(m['tok']['web'], {'req:sqli': 15, 'req:xss': 2})
        self.assertEqual((m['ans'], m['blk'], m['dec']), (3, 6, 1))
        self.assertEqual(m['ban'], ['sshd', 'postfix'])
        self.assertEqual(m['cve'], ['CVE-2021-44228', 'CVE-2022-22965'])
        self.assertEqual((m['first'], m['last']), (NOW - 900, NOW))
        self.assertEqual((repr(a), repr(b)), (snap_a, snap_b))

    def test_merge_with_nothing_and_caps(self):
        a = ev(src={'web': 3}, tok={'web': {'req:sqli': 3}})
        self.assertEqual(te.merge(a, None)['src'], {'web': 3})
        self.assertEqual(te.merge(None, a)['ip'], ATTACKER)
        big = ev(src={'web': 900_000}, tok={'web': {'req:sqli': 900_000}})
        self.assertEqual(te.merge(big, big)['src']['web'], 1_000_000)


class TestWordsOfAReport(unittest.TestCase):
    def test_phrases(self):
        e = ev(tok={'web': {'req:sqli': 14, 'req:traversal': 5}, 'waf': {'crs:942100': 9}},
               src={'web': 40, 'waf': 12})
        self.assertEqual(te.attack_phrase(e), 'SQL injection and path traversal')
        self.assertEqual(te.seen_by(e), 'web server log and WAF')
        self.assertEqual(te.what_word(e), 'web')

    def test_cve_ids_ride_along_but_only_two(self):
        e = ev(tok={'waf': {'crs:944150': 3}}, src={'waf': 3},
               cve=['CVE-2021-44228', 'CVE-2022-22965', 'CVE-2023-1234'])
        self.assertEqual(te.attack_phrase(e), 'remote code execution attempts (CVE-2021-44228, CVE-2022-22965)')

    def test_seen_by_names_each_source_once(self):
        e = ev(src={'web': 3, 'err': 2, 'f2b': 1, 'cs': 1}, ban=['sshd'], dec=1)
        self.assertEqual(te.seen_by(e), 'web server log, fail2ban and CrowdSec')
        self.assertEqual(te.seen_by(ev(ban=['sshd'])), 'fail2ban')

    def test_what_word_keeps_the_older_placeholder_values(self):
        self.assertEqual(te.what_word(ev(ban=['sshd'])), 'SSH')
        self.assertEqual(te.what_word(ev(tok={'web': {'req:login': 12}})), 'web login')
        self.assertEqual(te.what_word(ev(ban=['postfix'])), 'mail login')
        self.assertEqual(te.what_word(ev(ban=['proftpd'])), 'FTP login')

    def test_window_is_a_minute_at_least_and_a_day_at_most(self):
        self.assertEqual(te.window_seconds(ev(src={'web': 1}, first=NOW, last=NOW)), 60)
        self.assertEqual(te.window_seconds(ev(src={'web': 1}, first=NOW - 600, last=NOW)), 600)
        self.assertEqual(te.window_seconds(ev(src={'web': 1}, first=NOW - 5 * 86400, last=NOW)), 86400)

    _MARKER = 'ZZPWNEDZZ'

    def _assert_clean(self, text):
        """The words of a report are fixed phrases, numbers, and CVE ids."""
        allowed = {c['phrase'] for c in te.CLASSES.values()} | set(te.SOURCE_PHRASE.values())
        allowed_words = set(re.findall(r'[A-Za-z0-9-]+', ' '.join(allowed))) | {'and', 'CVE'}
        self.assertNotIn(self._MARKER.lower(), text.lower())
        stray = {w for w in re.findall(r'[A-Za-z0-9-]+', text)
                 if w not in allowed_words
                 and not re.fullmatch(r'CVE-\d{4}-\d{4,7}|SSH|web|login|mail|FTP|port|\d+', w)}
        self.assertEqual(stray, set(), text)

    def test_nothing_an_attacker_types_reaches_the_words(self):
        """Every string field an agent sends is filled with attacker text, some
        of it shaped like a valid token. The words of the report must come from
        the fixed phrases alone."""
        marker = self._MARKER
        rng = random.Random(720)
        alphabet = string.ascii_letters + string.digits + ' -_./:;<>"\'\\\n\t\x00{}$%'

        def junk():
            return marker + ''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))

        for _ in range(300):
            toks = {}
            for fam in te.SOURCES:
                toks[fam] = {junk(): rng.randint(1, 50) for _ in range(5)}
                toks[fam].update({f'jail:{marker}{rng.randint(0, 9)}': 3,
                                  f'cs:{marker}/{rng.randint(0, 9)}': 3,
                                  f'crstag:attack-{marker.lower()}': 3,
                                  'req:sqli': rng.randint(0, 5)})
            raw = {'ip': ATTACKER, 'src': {f: rng.randint(1, 40) for f in te.SOURCES},
                   'tok': toks, 'ban': [junk() for _ in range(5)] + [marker + 'jail'],
                   'cve': [junk(), 'CVE-2021-44228'], 'dec': rng.randint(0, 2),
                   'first': NOW - 100, 'last': NOW}
            e = te.normalize_event(raw, now=NOW)
            self.assertIsNotNone(e)
            for text in (te.attack_phrase(e), te.seen_by(e), te.what_word(e)):
                self._assert_clean(text)

    def test_the_checker_rejects_a_leak_and_accepts_the_real_words(self):
        """A check that cannot fail proves nothing. Feed the checker text that
        carries attacker words and it must object; feed it real output and it
        must not."""
        for leaked in ('SQL injection ZZPWNEDZZ', 'SQL injection and rm -rf', 'ssh from host.example.com',
                       'CVE-2021-44228 <script>'):
            with self.assertRaises(AssertionError, msg=leaked):
                self._assert_clean(leaked)
        e = ev(tok={'web': {'req:sqli': 14, 'req:traversal': 5}}, src={'web': 14, 'waf': 3}, cve=['CVE-2021-44228'])
        for text in (te.attack_phrase(e), te.seen_by(e), te.what_word(e), 'web server log, WAF and fail2ban'):
            self._assert_clean(text)


class TestInfrastructure(unittest.TestCase):
    PUBLISHED_V4 = ('173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 '
                    '108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 '
                    '162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22').split()
    PUBLISHED_V6 = ('2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 '
                    '2a06:98c0::/29 2c0f:f248::/32').split()

    def test_the_list_is_the_published_one(self):
        self.assertEqual(sorted(te.CLOUDFLARE_RANGES), sorted(self.PUBLISHED_V4 + self.PUBLISHED_V6))
        self.assertEqual(len(te.CLOUDFLARE_RANGES), 22)

    def test_every_range_is_recognised_at_both_ends(self):
        for cidr in te.CLOUDFLARE_RANGES:
            net = ipaddress.ip_network(cidr)
            self.assertTrue(te.infra_reason(str(net[0])), cidr)
            self.assertTrue(te.infra_reason(str(net[-1])), cidr)

    def test_the_edges_of_a_range_are_exact(self):
        # 104.16.0.0/13 ends at 104.23.255.255 and 104.24.0.0/14 at 104.27.255.255
        for ip, want in (('104.15.255.255', False), ('104.16.0.0', True), ('104.27.255.255', True),
                         ('104.28.0.0', False), ('2606:46ff:ffff:ffff:ffff:ffff:ffff:ffff', False),
                         ('2606:4700::', True), ('2606:4700:ffff:ffff:ffff:ffff:ffff:ffff', True),
                         ('2606:4701::', False)):
            self.assertEqual(bool(te.infra_reason(ip)), want, ip)

    def test_ordinary_addresses_are_not_infrastructure(self):
        for ip in (ATTACKER, '8.8.8.8', '1.1.1.1', '104.15.255.255', '104.32.0.1', '2001:4860:4860::8888',
                   '', 'nope', None):
            self.assertEqual(te.infra_reason(ip), '', ip)
        self.assertIn('Cloudflare', te.infra_reason('104.16.5.5'))
        self.assertIn('Cloudflare', te.infra_reason('2606:4700::1111'))
        self.assertIn('Cloudflare', te.infra_reason('::ffff:104.16.5.5'))


if __name__ == '__main__':
    unittest.main()
