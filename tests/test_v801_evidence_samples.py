"""What the logs showed, kept as samples (8.0.1): the server half.

Found on a live instance: six addresses that CrowdSec had banned could not be reported ("not reported: nothing recognisable in the logs"). Each
had one CrowdSec decision, no class, and nothing about what it had asked for. Two things were missing:

  * CrowdSec names the server could not class. Of the 241 scenarios with a source address in the public hub index, 20 mapped to nothing, and of
    its 243 AppSec rule names 15 did (`generic-wordpress-uploads-listing`, `generic-wordpress-uploads-php`, `base-config`, `crs`, ...). The
    names are frozen in tests/data/crowdsec_hub_2026-11-14.tsv; a class may not move, and a name that stays unmapped has to be listed here
    with the reason.
  * The request itself. The vocabulary carried counts and tokens only. An address now carries up to MAX_SAMPLES samples (method, path, status,
    log, time), and a sample is never kept as it arrived: the server rebuilds it from parts it checks itself.

The agent's half is in test_v801_agent_samples.py, the report and the page in test_v801_sample_reports.py.
"""
import random
import re
import string
import sys
import time
import unittest
from pathlib import Path
from typing import Any

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import threat_evidence as te  # noqa: E402

NOW = 1_790_000_000
IP = '45.33.32.156'
DATA = Path(__file__).resolve().parent / 'data' / 'crowdsec_hub_2026-11-14.tsv'

# Names in the hub index that map to no class, and why. A name that starts to map has to come off this list (the test says so), so it only shrinks.
ON_PURPOSE = {
    'Guezli/mailcow-f2b-feed': "copies fail2ban's bans into CrowdSec: a second engine's decision, no behaviour of its own",
    'crowdsecurity/amavis-blocked': 'mail the filter blocked for its content: spam or a virus, not a login attack',
    # v7.2.0 decided that an aggressive crawler is not an attack, so it is not reported as one (test_v720_threat_evidence pins the first)
    'crowdsecurity/http-crawl-non_statics': 'an aggressive crawler is not an attack, so it is not reported as one (v7.2.0)',
    'aidalinfo/couchdb-crawl': 'the same decision: a crawl is not an attack',
    'crowdsecurity/experimental-no-user-agent': 'an experimental rule that says only that a header is missing',
    'crowdsecurity/freeswitch-acl-reject': 'VoIP connections an access list refused',
    'crowdsecurity/http-generic-test': "CrowdSec's own test scenario",
    'crowdsecurity/http-magento-ccs': 'card stuffing: no honest category on either service',
    'crowdsecurity/http-magento-ccs-by-as': 'card stuffing, spread over one network',
    'crowdsecurity/http-magento-ccs-by-country': 'card stuffing, spread over one country',
    'crowdsecurity/palo-alto-threat': "a firewall's threat log by severity, with no attack named",
    'crowdsecurity/suricata-alerts': "any emerging-threat rule: the agent's Suricata reader classes alerts itself, by signature",
    'crowdsecurity/wireguard-auth': 'rejected VPN handshakes',
    'mstilkerich/bind9-refused': 'DNS queries a policy refused',
}


# 8.0.1: probing and a service's login got kinds (threat_evidence.FAMILIES). The file above is the list as it was frozen,
# and these are the names that moved since: each from a general class to one of its own kinds, and no other name moved.
MOVED = {
    'aidalinfo/couchdb-bf': ('service_brute', 'db_brute'),
    'crowdsecurity/mariadb-bf': ('service_brute', 'db_brute'),
    'crowdsecurity/mssql-bf': ('service_brute', 'db_brute'),
    'crowdsecurity/mysql-bf': ('service_brute', 'db_brute'),
    'crowdsecurity/pgsql-bf': ('service_brute', 'db_brute'),
    'timokoessler/mongodb-bf': ('service_brute', 'db_brute'),
    'crowdsecurity/smb-bf': ('service_brute', 'smb_brute'),
    'crowdsecurity/telnet-bf': ('service_brute', 'telnet_brute'),
    'crowdsecurity/generic-wordpress-uploads-listing': ('probe', 'wordpress'),
    'crowdsecurity/http-wordpress-scan': ('probe', 'wordpress'),
    'crowdsecurity/http-admin-interface-probing': ('probe', 'admin_probe'),
    'crowdsecurity/http-sap-interface-probing': ('probe', 'admin_probe'),
    'crowdsecurity/http-open-proxy': ('probe', 'proxy_probe'),
    'crowdsecurity/http-sensitive-files': ('probe', 'config_probe'),
    'crowdsecurity/http-wordpress_wpconfig': ('probe', 'config_probe'),
    'crowdsecurity/http-wordpress_user-enum': ('probe', 'user_enum'),
}


def ev(**kw):
    raw = {'ip': IP, 'first': NOW - 600, 'last': NOW}
    raw.update(kw)
    out = te.normalize_event(raw, now=NOW)
    assert out is not None, raw
    return out


def smp(path: Any = '/wp-login.php', method: Any = 'GET', status: Any = 404, fam: Any = 'web', t: Any = NOW - 30):
    return {'f': fam, 'm': method, 'p': path, 'c': status, 't': t}


class TestHubMapping(unittest.TestCase):
    """The scenario and AppSec rule names of the public hub index, as of 2026-11-14."""

    @classmethod
    def setUpClass(cls):
        cls.rows = [ln.split('\t') for ln in DATA.read_text().splitlines() if ln.strip()]

    def test_the_snapshot_is_the_whole_list(self):
        self.assertGreater(len(self.rows), 450)
        self.assertEqual(len({n for n, _c in self.rows}), len(self.rows), 'a name twice')

    def test_every_name_keeps_the_class_it_had_or_moved_to_a_kind_of_it(self):
        moved = {n: (None if c == '-' else c, te.scenario_class(n)) for n, c in self.rows
                 if te.scenario_class(n) != (None if c == '-' else c)}
        self.assertEqual(moved, MOVED)
        self.assertEqual(len(MOVED), 16)
        for name, (old, new) in MOVED.items():
            self.assertIn(new, te.FAMILIES.get(old, ()), f'{name}: {old} to {new} is not a general class to one of its kinds')

    def test_a_name_that_looks_like_a_moved_one_gains_nothing(self):
        """The rules that name a kind are as narrow as the names they were written for: a scan of a database is not
        a brute force of one, and a name with no class before has none now."""
        for name in ('acme/mssql-scan', 'acme/sap-interface', 'aidalinfo/couchdb-crawl', 'acme/couchdb-sync'):
            self.assertIsNone(te.scenario_class(name), name)
        self.assertEqual(te.scenario_class('acme/mysql-scan'), 'db_brute',
                         'the control: "mysql" was a service login before, so it is a database login now')

    def test_what_stays_unmapped_is_listed_with_its_reason(self):
        unmapped = {n for n, c in self.rows if c == '-'}
        self.assertEqual(unmapped - set(ON_PURPOSE), set(), 'a name with no class and no reason')
        self.assertEqual(set(ON_PURPOSE) - unmapped, set(),
                         'a name that maps now: take it off ON_PURPOSE')
        self.assertTrue(all(len(r) > 12 for r in ON_PURPOSE.values()))

    def test_the_names_the_stuck_addresses_needed(self):
        want = {
            'crowdsecurity/generic-wordpress-uploads-listing': 'wordpress',     # a kind of probing since 8.0.1
            'crowdsecurity/generic-wordpress-uploads-php': 'rce',
            'crowdsecurity/generic-freemarker-ssti': 'rce',
            'crowdsecurity/base-config': 'waf',
            'crowdsecurity/crs': 'waf',
        }
        for name, cls in want.items():
            self.assertEqual(te.scenario_class(name), cls, name)

    def test_the_scan_names(self):
        want = {
            'ltsich/http-w00tw00t': 'probe', 'crowdsecurity/http-wordpress_wpconfig': 'config_probe',
            'PumbaLP/cowrie-precision': 'service_brute', 'corvese/apache-guacamole_bf': 'service_brute',
            'corvese/apache-guacamole_user_enum': 'service_brute',
            'crowdsecurity/vmware-vcenter-vmsa-2021-0027': 'rce', 'barnoux/crs-anomaly-score': 'waf',
        }
        for name, cls in want.items():
            self.assertEqual(te.scenario_class(name), cls, name)

    def test_a_crawl_is_still_not_an_attack(self):
        # the v7.2.0 decision, held here as well as in test_v720_threat_evidence
        for name in ('crowdsecurity/http-crawl-non_statics', 'aidalinfo/couchdb-crawl'):
            self.assertIsNone(te.scenario_class(name), name)

    def test_a_name_that_mapped_before_does_not_change_class(self):
        # asterisk_user_enum was service_brute (by "asterisk") before the underscore patterns existed
        self.assertEqual(te.scenario_class('crowdsecurity/asterisk_user_enum'), 'service_brute')
        for name, cls in (('crowdsecurity/ssh-bf', 'ssh_brute'), ('crowdsecurity/http-probing', 'probe'),
                          ('crowdsecurity/http-bad-user-agent', 'scanner'),
                          ('crowdsecurity/appsec-native', 'waf'), ('crowdsecurity/http-wordpress_bf', 'login_brute'),
                          ('crowdsecurity/vpatch-CVE-2024-27198', 'rce')):
            self.assertEqual(te.scenario_class(name), cls, name)


# What the cleaner must do with each shape of request target.
PATHS = [
    ('/wp-login.php', '/wp-login.php'),
    ('/.env', '/.env'),
    ('/../../etc/passwd', '/../../etc/passwd'),
    ('/..%2f..%2fetc/passwd', '/..%2f..%2fetc/passwd'),
    ('/', '/'),
    # the query string is where a request keeps what it carries
    ('/wp-login.php?log=admin&pwd=hunter2', '/wp-login.php'),
    ('/index.php?s=/Index/\\think\\app/invokefunction', '/index.php'),
    ('/a#fragment', '/a'),
    ('/?XDEBUG_SESSION_START=phpstorm', '/'),
    # a path parameter carries the same
    ('/index.php;jsessionid=ABCDEF123', '/index.php...'),
    ('/cgi-bin/luci/;stok=/locale', '/cgi-bin/luci/...'),
    # a URL inside the path names a host
    ('/wp-content/uploads/2024/11/a-768x1024.jpg%20768w,%20https:/shop.example.test/wp-content/uploads/b.jpg%201920w/',
     '/wp-content/uploads/2024/11/a-768x1024.jpg%20768w...'),
    ('/x/ftp:/host/y', '/x/...'),
    # markup, quotes, a pattern, a command: the path ends before it
    ('/x<script>alert(1)</script>', '/x...'),
    ('/x"onload="y', '/x...'),
    ("/x'or'1", '/x...'),
    ('/x`id`', '/x...'),
    ('/a/b c', '/a/b...'),
    ('/${jndi:ldap://h/a}', '/...'),
    ('/x\x00y', '/x...'),
    ('/x\ny', '/x...'),
    ('/café', '/caf...'),
    ('/x‮y', '/x...'),
    # not a path
    ('http://example.test/x', ''),
    ('//example.test/x', ''),
    ('example.test/x', ''),
    ('*', ''),
    ('', ''),
    (None, ''),
    (5, ''),
    (['/x'], ''),
    ('／x', ''),                      # a fullwidth slash is not a slash
]


class TestCleanPath(unittest.TestCase):
    def test_each_shape(self):
        for raw, want in PATHS:
            self.assertEqual(te.clean_path(raw), want, repr(raw))

    def test_cleaning_what_it_returned_changes_nothing(self):
        for raw, _want in PATHS:
            once = te.clean_path(raw)
            self.assertEqual(te.clean_path(once), once, repr(raw))

    def test_the_length_is_bounded_and_a_cut_says_so(self):
        out = te.clean_path('/' + 'a' * 500)
        self.assertEqual(out, '/' + 'a' * (te.SAMPLE_PATH_MAX - 1) + '...')
        self.assertEqual(te.clean_path(out), out)
        exact = '/' + 'b' * (te.SAMPLE_PATH_MAX - 1)
        self.assertEqual(te.clean_path(exact), exact, 'a path of exactly the limit is not cut')

    def test_a_secret_in_the_query_or_a_parameter_never_survives(self):
        for raw in ('/a?token=SECRET', '/a;jsessionid=SECRET', '/a/SECRET?x', '/a?x=1#SECRET'):
            out = te.clean_path(raw)
            self.assertEqual(out.count('SECRET'), 1 if raw.startswith('/a/SECRET') else 0, (raw, out))

    def test_a_host_name_in_the_path_never_survives(self):
        out = te.clean_path('/img.jpg%20768w,%20https:/private.corp.example/wp-content/x.jpg')
        self.assertNotIn('corp', out)
        self.assertNotIn('example', out)

    def test_fuzz_what_comes_out_is_always_in_the_alphabet(self):
        rnd = random.Random(801)
        pool = string.printable + 'é‮／ \x00\x7f%?#;:<>"\'`${}()[]\\|^~' * 3
        shapes = {'empty': 0, 'clean': 0, 'cut': 0}
        ok = re.compile(r'/[A-Za-z0-9._~/%+-]*(?:\.\.\.)?')
        for _ in range(4000):
            n = rnd.choice((0, 1, 5, 30, 90, 300))
            raw = rnd.choice(('', '/', '/', '/a/')) + ''.join(rnd.choice(pool) for _ in range(n))
            out = te.clean_path(raw)
            if not out:
                shapes['empty'] += 1
                continue
            self.assertRegex(out, ok)
            self.assertLessEqual(len(out), te.SAMPLE_PATH_MAX + 3)
            self.assertEqual(te.clean_path(out), out)
            shapes['cut' if out.endswith('...') else 'clean'] += 1
        self.assertTrue(all(shapes.values()), f'a branch the fuzz never reached: {shapes}')


class TestNormalizeSample(unittest.TestCase):
    def test_a_good_sample_is_kept_exactly(self):
        got = te.normalize_sample(smp(), NOW)
        self.assertEqual(got, smp())

    def test_only_the_five_fields_survive(self):
        got = te.normalize_sample(dict(smp(), x='<script>', ua='sqlmap', ref='https://h/', url='/y?z=1'), NOW)
        self.assertEqual(set(got), {'f', 'm', 'p', 'c', 't'})

    def test_the_log_must_be_one_the_sender_may_speak_for(self):
        self.assertIsNone(te.normalize_sample(smp(fam='cf'), NOW))          # an agent cannot claim Cloudflare
        self.assertIsNone(te.normalize_sample(smp(fam='trap'), NOW))
        self.assertIsNone(te.normalize_sample(smp(fam='nope'), NOW))
        self.assertIsNone(te.normalize_sample(smp(fam=5), NOW))
        self.assertIsNone(te.normalize_sample(smp(fam='web'), NOW, families=te.EDGE_SOURCES))
        self.assertEqual(te.normalize_sample(smp(fam='cf'), NOW, families=te.EDGE_SOURCES)['f'], 'cf')
        for fam in te.AGENT_SOURCES:
            self.assertEqual(te.normalize_sample(smp(fam=fam), NOW)['f'], fam)

    def test_the_method_comes_from_a_list(self):
        for m in te._SAMPLE_METHODS:
            self.assertEqual(te.normalize_sample(smp(method=m), NOW)['m'], m)
        for bad in ('get', 'GGET', 'GET /x', '\x16\x03\x01', '', None, 5, ['GET']):
            got = te.normalize_sample(smp(method=bad), NOW)
            self.assertEqual(got['m'], '', repr(bad))           # still a sample: the path says something
            self.assertEqual(got['p'], '/wp-login.php')

    def test_the_path_is_required_and_cleaned(self):
        for bad in (None, '', 'x', 'http://h/x', '//h', 5, ['/x']):
            self.assertIsNone(te.normalize_sample(smp(path=bad), NOW), repr(bad))
        self.assertEqual(te.normalize_sample(smp(path='/a?b=c'), NOW)['p'], '/a')

    def test_the_status_is_a_status(self):
        for raw, want in ((403, 403), ('404', 404), (403.9, 403), (99, 0), (600, 0), ('x', 0), (None, 0), (True, 0), (-5, 0), (10 ** 30, 0)):
            self.assertEqual(te.normalize_sample(smp(status=raw), NOW)['c'], want, repr(raw))

    def test_the_time_is_held_to_the_window(self):
        self.assertEqual(te.normalize_sample(smp(t=NOW + 10 ** 6), NOW)['t'], NOW + 300)
        self.assertEqual(te.normalize_sample(smp(t=1), NOW)['t'], NOW - 7 * 86400)
        self.assertEqual(te.normalize_sample(smp(t='x'), NOW)['t'], NOW)
        # without a clock (merging what a ledger holds) the stamp is kept, inside 0..2100
        self.assertEqual(te.normalize_sample(smp(t=1234), None)['t'], 1234)
        self.assertEqual(te.normalize_sample(smp(t=10 ** 15), None)['t'], te._SAMPLE_T_MAX)
        self.assertEqual(te.normalize_sample(smp(t=-9), None)['t'], 0)

    def test_what_is_not_a_dict_is_nothing(self):
        for junk in (None, 5, 'x', ['/x'], ('/x',), b'/x', {1, 2}):
            self.assertIsNone(te.normalize_sample(junk, NOW), repr(junk))

    def test_the_list_is_short_and_distinct(self):
        raw = [smp('/a'), smp('/a'), smp('/b'), smp('/a', method='POST'), smp('/c'), smp('/d')]
        got = te.normalize_samples(raw, NOW)
        self.assertEqual([(s['m'], s['p']) for s in got], [('GET', '/a'), ('GET', '/b'), ('POST', '/a')])
        self.assertLessEqual(len(got), te.MAX_SAMPLES)

    def test_a_huge_or_wrong_list_costs_nothing(self):
        t0 = time.monotonic()
        got = te.normalize_samples([smp('/%d' % i) for i in range(100_000)], NOW)
        self.assertEqual(len(got), te.MAX_SAMPLES)
        self.assertLess(time.monotonic() - t0, 2.0)
        for junk in (None, 'x', 5, {'f': 'web'}, [None, 5, 'x', {}]):
            self.assertEqual(te.normalize_samples(junk, NOW), [])

    def test_sample_text(self):
        self.assertEqual(te.sample_text(smp()), 'GET /wp-login.php (404)')
        self.assertEqual(te.sample_text(smp(status=0)), 'GET /wp-login.php')
        self.assertEqual(te.sample_text(smp(method='')), '/wp-login.php (404)')


class TestEventAndLedger(unittest.TestCase):
    def test_an_event_carries_its_samples(self):
        e = ev(src={'web': 4}, smp=[smp('/.env'), smp('/x<y>')])
        self.assertEqual([s['p'] for s in e['smp']], ['/.env', '/x...'])
        self.assertEqual(te.blank()['smp'], [])

    def test_a_family_the_sender_may_not_claim_loses_the_sample(self):
        raw = {'ip': IP, 'first': NOW - 60, 'last': NOW, 'src': {'cf': 3}, 'smp': [smp(fam='web'), smp('/b', fam='cf')]}
        e = te.normalize_event(raw, now=NOW, families=te.EDGE_SOURCES)
        self.assertEqual([s['p'] for s in e['smp']], ['/b'])

    def test_samples_alone_are_not_an_event(self):
        self.assertIsNone(te.normalize_event({'ip': IP, 'smp': [smp()]}, now=NOW))

    def test_a_wrong_type_is_nothing(self):
        for junk in ('/x', 5, {'p': '/x'}, [[]], None):
            self.assertEqual(ev(src={'web': 4}, smp=junk)['smp'], [])

    def test_merge_keeps_the_earlier_first_and_the_set_distinct(self):
        a = ev(src={'web': 4}, smp=[smp('/a'), smp('/b')])
        b = ev(src={'web': 3}, smp=[smp('/b'), smp('/c'), smp('/d')])
        got = te.merge(a, b)
        self.assertEqual([s['p'] for s in got['smp']], ['/a', '/b', '/c'])
        self.assertEqual(te.merge(None, b)['smp'], b['smp'])
        self.assertEqual(te.merge(a, None)['smp'], a['smp'])
        self.assertEqual(te.merge(None, None)['smp'], [])

    def test_merge_checks_what_the_ledger_held(self):
        # a ledger is read back from storage: a sample in it is not trusted either
        stored = dict(te.blank(IP), smp=[{'f': 'web', 'm': 'GET', 'p': '/a<script>', 'c': 403, 't': 5},
                                         {'f': 'web', 'm': 'GET', 'p': '<img>', 'c': 403, 't': 5}, 'junk'])
        got = te.merge(stored, ev(src={'web': 3}))
        self.assertEqual([s['p'] for s in got['smp']], ['/a...'])

    def test_slim_keeps_at_most_the_limit(self):
        e = dict(te.blank(IP), smp=[smp('/%d' % i) for i in range(9)])
        self.assertEqual(len(te.slim(e)['smp']), te.MAX_SAMPLES)

    def test_samples_decide_nothing(self):
        # they are read by a person; the classes, the counts and the verdict come from tokens and numbers as before
        plain = ev(src={'web': 12}, tok={'web': {'req:probe': 12}})
        rich = ev(src={'web': 12}, tok={'web': {'req:probe': 12}}, smp=[smp('/.env'), smp('/wp-login.php')])
        self.assertEqual(te.classes(plain), te.classes(rich))
        self.assertEqual(te.qualifies(plain, 10), te.qualifies(rich, 10))
        self.assertEqual(te.hostile_count(plain), te.hostile_count(rich))
        bare = ev(src={'web': 12}, smp=[smp('/.env')])
        self.assertEqual(te.qualifies(bare, 10), (False, 'nothing recognisable in the logs'))


class TestWhyNothingWasReported(unittest.TestCase):
    NAME = 'crowdsecurity/http-generic-test'

    def test_an_unmapped_scenario_is_named(self):
        e = ev(src={'cs': 1}, tok={'cs': {'cs:' + self.NAME: 1}}, dec=1)
        self.assertEqual(te.qualifies(e, 10), (False, 'no attack category for the CrowdSec scenario ' + self.NAME))

    def test_a_mapped_scenario_reports(self):
        e = ev(src={'cs': 1}, tok={'cs': {'cs:crowdsecurity/generic-wordpress-uploads-listing': 1}}, dec=1)
        self.assertEqual(te.classes(e), {'wordpress': 1})
        self.assertEqual(te.qualifies(e, 10), (True, 'confirmed by CrowdSec'))

    def test_an_unmapped_jail_is_named(self):
        e = ev(src={'f2b': 1}, ban=['recidive'])
        self.assertEqual(te.qualifies(e, 10), (False, 'no attack category for the fail2ban jail recidive'))

    def test_the_scenario_comes_before_the_jail(self):
        e = ev(src={'cs': 1, 'f2b': 1}, tok={'cs': {'cs:' + self.NAME: 1}}, ban=['recidive'], dec=1)
        self.assertIn('CrowdSec scenario', te.qualifies(e, 10)[1])

    def test_a_decision_with_no_name_keeps_the_old_words(self):
        e = ev(src={'cs': 1}, dec=1)
        self.assertEqual(te.qualifies(e, 10), (False, 'nothing recognisable in the logs'))

    def test_the_text_has_the_shape_the_page_reads(self):
        # app-ipintel.js splits it with one pattern: the name is what follows the fixed words
        for name in (self.NAME, 'tyxak/own-thing', 'x', 'a_b.c/d-e'):
            e = ev(src={'cs': 1}, tok={'cs': {'cs:' + name: 1}}, dec=1)
            why = te.qualifies(e, 10)[1]
            m = re.fullmatch(r'no attack category for the CrowdSec scenario ([A-Za-z0-9][A-Za-z0-9_./-]*)', why)
            self.assertIsNotNone(m, why)
            self.assertEqual(m.group(1) if m else None, name)

    def test_cs_scenarios_are_ranked_and_classed(self):
        e = ev(src={'cs': 5}, tok={'cs': {'cs:crowdsecurity/ssh-bf': 2, 'cs:' + self.NAME: 5, 'req:probe': 9}})
        self.assertEqual(te.cs_scenarios(e), [(self.NAME, 5, None), ('crowdsecurity/ssh-bf', 2, 'ssh_brute')])

    def test_a_name_that_fails_the_token_check_is_not_listed(self):
        # normalize_event drops it; a ledger read back from storage may still hold one
        e = dict(te.blank(IP), tok={'cs': {'cs:bad name': 3, 'cs:' + 'x' * 120: 3, 'cs:ok': 1}})
        self.assertEqual([n for n, _c, _k in te.cs_scenarios(e)], ['ok'])


if __name__ == '__main__':
    unittest.main()
