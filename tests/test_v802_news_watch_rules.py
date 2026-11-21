#!/usr/bin/env python3
"""8.0.2: the security news watch, the pure part -- reading a feed, deciding what is critical, deciding what concerns the hosts, and remembering what was seen.

The headlines below are written in the shape of a security news feed's, not copied from one. The negative cases matter as much as the positive ones: a classifier that
calls everything critical raises an alert per article, and a matcher that lets a package called "patch" match the word "patch" makes every article relevant.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-newswatch-rules-'))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import news_watch as N  # noqa: E402

NOW = 1_800_000_000


def rss(*items, title='Example Security News'):
    body = ''.join(items)
    return f'<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>{title}</title>{body}</channel></rss>'.encode()


def item(title, summary='', guid=None, link=None, pub='Fri, 20 Nov 2026 17:50:00 +0530'):
    g = f'<guid isPermaLink="false">{guid}</guid>' if guid else ''
    ln = f'<link>{link}</link>' if link else ''
    return f'<item><title><![CDATA[{title}]]></title><description><![CDATA[{summary}]]></description>{ln}{g}<pubDate>{pub}</pubDate></item>'


# ── reading a feed ───────────────────────────────────────────────────────────

class TestParseFeed(unittest.TestCase):

    def test_an_rss_item_is_read_whole(self):
        got = N.parse_feed(rss(item('PHP Fixes 7 Critical Flaws', 'Remote code execution in <b>PHP</b>.\n\nUpdate now.', guid='g1', link='https://news.example.net/php.html')))
        self.assertEqual(got['title'], 'Example Security News')
        (it,) = got['items']
        self.assertEqual(it['title'], 'PHP Fixes 7 Critical Flaws')
        self.assertEqual(it['summary'], 'Remote code execution in PHP . Update now.')
        self.assertEqual(it['link'], 'https://news.example.net/php.html')
        self.assertEqual(it['id'], N.item_id('g1'))
        self.assertEqual(it['published'], int(datetime(2026, 11, 20, 12, 20, tzinfo=timezone.utc).timestamp()))

    def test_the_date_is_read_in_its_own_zone(self):
        got = N.parse_feed(rss(item('a', pub='Fri, 20 Nov 2026 17:50:00 +0530', guid='a'), item('b', pub='Fri, 20 Nov 2026 12:20:00 +0000', guid='b')))
        self.assertEqual(got['items'][0]['published'], got['items'][1]['published'], 'the same instant, written in two zones')

    def test_an_atom_entry_is_read(self):
        atom = (b'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Atom News</title>'
                b'<entry><title>Critical flaw in nginx</title><id>tag:example.net,2026:1</id><updated>2026-11-20T12:20:00Z</updated>'
                b'<link rel="alternate" href="https://news.example.net/nginx"/><link rel="self" href="https://news.example.net/self"/>'
                b'<summary>An unauthenticated attacker can run code.</summary></entry></feed>')
        got = N.parse_feed(atom)
        (it,) = got['items']
        self.assertEqual((got['title'], it['title'], it['link']), ('Atom News', 'Critical flaw in nginx', 'https://news.example.net/nginx'))
        self.assertEqual(it['published'], N.parse_time('Fri, 20 Nov 2026 12:20:00 +0000'))

    def test_an_rss_one_feed_is_read(self):
        rdf = (b'<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/">'
               b'<channel><title>RDF News</title></channel><item><title>Zero-day in a browser</title><link>https://news.example.net/z</link><description>x</description></item></rdf:RDF>')
        got = N.parse_feed(rdf)
        self.assertEqual((got['title'], [i['title'] for i in got['items']]), ('RDF News', ['Zero-day in a browser']))

    def test_markup_entities_and_control_characters_are_taken_out(self):
        got = N.parse_feed(rss(item('<script>alert(1)</script>Fix &amp; patch', '<img src=x onerror=alert(1)> text &lt;b&gt;bold&lt;/b&gt;', guid='x')))
        (it,) = got['items']
        self.assertNotIn('<', it['title'] + it['summary'])
        self.assertIn('Fix & patch', it['title'])
        self.assertEqual(N._clean('a\x07b\x1fc\x7fd', 50), 'a b c d', 'control characters become blanks')

    def test_only_an_http_or_https_link_is_kept(self):
        for bad in ('javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', 'ftp://x/y', '//no-scheme', 'https://'):
            got = N.parse_feed(rss(item('t', guid='g', link=bad)))
            self.assertEqual(got['items'][0]['link'], '', bad)
        self.assertEqual(N.parse_feed(rss(item('t', guid='g', link='http://news.example.net/a?b=1')))['items'][0]['link'], 'http://news.example.net/a?b=1')

    def test_lengths_are_cut(self):
        got = N.parse_feed(rss(item('T' * 900, 'S' * 9000, guid='g', link='https://x.example/' + 'a' * 800)))
        (it,) = got['items']
        self.assertEqual((len(it['title']), len(it['summary']), it['link']), (N.TITLE_LEN, N.TEXT_LEN, ''))

    def test_at_most_the_first_items_are_read(self):
        got = N.parse_feed(rss(*[item(f't{i}', guid=f'g{i}') for i in range(N.MAX_ITEMS_PER_FEED + 25)]))
        self.assertEqual(len(got['items']), N.MAX_ITEMS_PER_FEED)

    def test_an_item_without_any_name_is_left_out(self):
        got = N.parse_feed(b'<rss version="2.0"><channel><item><description>no title, no link, no guid</description></item><item><title>kept</title></item></channel></rss>')
        self.assertEqual([i['title'] for i in got['items']], ['kept'])

    def test_a_dtd_or_an_entity_is_refused(self):
        bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
                b'<rss version="2.0"><channel><title>&lol2;</title></channel></rss>')
        with self.assertRaises(ValueError):
            N.parse_feed(bomb)
        with self.assertRaises(ValueError):
            N.parse_feed(b'<?xml version="1.0"?><!DOCTYPE rss SYSTEM "file:///etc/passwd"><rss version="2.0"><channel/></rss>')

    def test_things_that_are_not_a_feed_are_refused(self):
        for bad in (b'', b'not xml at all', b'<html><body>hello</body></html>', b'<rss', b'{"json": true}'):
            with self.assertRaises(ValueError, msg=bad):
                N.parse_feed(bad)
        with self.assertRaises(ValueError):
            N.parse_feed('a string, not bytes')

    def test_a_feed_over_the_size_limit_is_refused(self):
        with self.assertRaises(ValueError):
            N.parse_feed(b'<rss version="2.0"><channel>' + b' ' * (N.MAX_FEED_BYTES + 1) + b'</channel></rss>')

    def test_a_date_that_cannot_be_read_is_none(self):
        for bad in ('', 'yesterday', 'Fri, 99 Nov 2026 99:99:99 +0000', None, 7, '99999-99-99'):
            self.assertIsNone(N.parse_time(bad), bad)


# ── is it critical ───────────────────────────────────────────────────────────

CRITICAL = [
    # (headline, summary, a reason it must give)
    ('PHP Fixes 7 Critical Flaws, Including Bugs That Could Allow Remote Code Execution', '', 'critical'),
    ('Hackers Exploit Critical Cisco Expressway Flaw, Breach Four Devices', '', 'exploited'),
    ('Critical VMware vCenter Zero-Day Flaw Lets Network Attackers Bypass Authentication', '', 'zero_day'),
    ('10-Year-Old NGINX HTTP/2 Flaw Lets Unauthenticated Attackers Execute Code on Servers', '', 'unauth_exec'),
    ('Java4Shell Flaw Enables Pre-Auth RCE in Jira, Jenkins and More', '', 'unauth_exec'),
    ('New Unpatched Windows 0-Day Lets Someone Run Programs on a Locked PC', '', 'zero_day'),
    ('Apache Roller RCE Flaw Under Active Exploitation', '', 'exploited'),
    ('Attackers Exploit UnrealIRCd Flaw That Enables Server-Level Command Injection', '', 'exploited'),
    ('Drupal Patches Installer Flaw', 'The flaw has a CVSS score of 9.8 and lets anyone take over a site.', 'cvss'),
    ('Router firmware update', 'Rated CVSS v3.1 base score: 10.0 by the vendor.', 'cvss'),
    ('Six Unpatched Controller Flaws Could Allow Remote Takeover Without Login', '', 'unauth_exec'),
    ('Patch Tuesday fixes bugs', 'One of them, CVE-2026-1234, is exploited in the wild.', 'exploited'),
]

NOT_CRITICAL = [
    ('The Path to AI Autonomy in the SOC', 'Security leaders are about to hand AI agents a lot more authority.'),
    ('ROMULUS ClickFix Attacks Deliver RAT That Can Spy on Users and Control PCs', 'A phishing campaign.'),
    ('Attacks on critical infrastructure rise', 'Operators of critical infrastructure, critical sectors and critical services report more incidents.'),
    ('Researchers Detail iPhone Flaw That Let Apps Record Audio', 'Apple fixed it in a recent update.'),
    ('Retadup Worm Resurfaces 7 Years After Takedown to Spread Malware', 'It spreads through USB drives.'),
    ('Hackers Exploit Trust in Open Source to Spread Malware', 'Fake packages are uploaded to a registry.'),    # "exploit" with no flaw in sight
    ('Router firmware update', 'Rated CVSS v3.1 base score: 7.5, which is high.'),
    ('Router firmware update', 'CVSS 4.0 describes the scale; this one scores 6.1.'),
    ('Vendor ships tool', 'The tool affects 10 vendors and has a CVSS score of 7.5 for one of them.'),
    ('⚡ Weekly Recap: Zero-Days, Exploited Flaws, Critical RCE and More', 'Everything this week: a zero-day, an exploited flaw, a critical RCE.'),
    ('ThreatsDay: Critical Flaws, 0-Days and Exploits', 'A round-up.'),
    ('Webinar: How to Close the Gap Attackers Exploit', 'A critical flaw is explained.'),
    ('AI Pentesting Checklist for Web Apps', 'Ask 15 questions about unauthenticated RCE before you choose.'),
]


class TestClassify(unittest.TestCase):

    def test_headlines_that_report_a_critical_flaw(self):
        for title, summary, reason in CRITICAL:
            c = N.classify(title, summary)
            self.assertTrue(c['critical'], (title, c))
            self.assertIn(reason, c['reasons'], (title, c))
            self.assertTrue(set(c['reasons']) <= set(N.REASONS), c['reasons'])

    def test_headlines_that_do_not(self):
        for title, summary in NOT_CRITICAL:
            c = N.classify(title, summary)
            self.assertFalse(c['critical'], (title, c))
            self.assertEqual(c['reasons'], [], (title, c))

    def test_the_population_has_both_kinds(self):
        self.assertGreaterEqual(len(CRITICAL), 12)
        self.assertGreaterEqual(len(NOT_CRITICAL), 13)

    def test_a_cvss_score_is_read_after_the_version_of_the_scale(self):
        for text, want in (('CVSS 9.8', 9.8), ('CVSS v3.1 score of 9.1', 9.1), ('CVSS version 4.0 base 10', 10.0), ('CVSS score: 10.0', 10.0), ('cvss 9', 9.0)):
            c = N.classify('x', text)
            self.assertEqual(c['cvss'], want, text)
        for text in ('CVSS 8.9', 'CVSS 3.1', 'CVSS v4.0', 'CVSS score 11', 'no score here'):
            self.assertIsNone(N.classify('x', text)['cvss'], text)

    def test_a_cve_in_the_known_exploited_list_counts_on_its_own(self):
        c = N.classify('Library update', 'Fixes CVE-2026-4242 among others.', kev={'CVE-2026-4242'})
        self.assertEqual((c['critical'], c['reasons'], c['cves']), (True, ['kev'], ['CVE-2026-4242']))
        c = N.classify('Library update', 'Fixes CVE-2026-4242 among others.', kev={'CVE-2026-9999'})
        self.assertFalse(c['critical'])
        self.assertEqual(c['cves'], ['CVE-2026-4242'], 'the id is still named')

    def test_cve_ids_are_collected_once_upper_case_and_capped(self):
        text = 'cve-2026-1111 and CVE-2026-1111, CVE-2026-2222 ' + ' '.join(f'CVE-2026-{3000 + i}' for i in range(30))
        ids = N.cves_in(text)
        self.assertEqual(ids[:2], ['CVE-2026-1111', 'CVE-2026-2222'])
        self.assertEqual(len(ids), N.MAX_CVES)

    def test_the_word_critical_needs_a_flaw_beside_it(self):
        self.assertFalse(N.classify('A critical week for the team', 'Nothing was broken.')['critical'])
        self.assertTrue(N.classify('A critical bug in the parser', '')['critical'])

    def test_the_classifier_survives_hostile_text(self):
        for hostile in ('CVSS ' * 5000, 'critical ' * 5000 + 'flaw', '(' * 5000, 'CVE-' + '9' * 10000, '\x00' * 100):
            N.classify(hostile, hostile)


# ── does it concern the hosts ────────────────────────────────────────────────

class TestCriticalWords(unittest.TestCase):
    """The seventh reason (8.0.2): a word or phrase the operator chose. The nickname of a flaw comes before its CVE and its score, and a product name is worth a headline."""

    def test_a_word_makes_an_item_critical_whatever_else_it_says(self):
        got = N.classify('A new wp2shell attack on WordPress sites', 'Researchers describe how it works.', set(), ['wp2shell'])
        self.assertEqual((got['critical'], got['reasons']), (True, ['word']))
        self.assertEqual(N.classify('A new wp2shell attack on WordPress sites', '', set(), [])['critical'], False, 'control: with no word it is not critical')
        self.assertEqual(N.classify('A new wp2shell attack on WordPress sites', '', set())['reasons'], [], 'and the default is no words')

    def test_it_is_a_whole_word_or_phrase_in_any_case_in_the_headline_or_the_summary(self):
        words = ['wp2shell', 'remote code execution']
        self.assertEqual(N.classify('Fresh WP2Shell research', '', set(), words)['reasons'], ['word'], 'any case')
        self.assertEqual(N.classify('Quiet news', 'Details of the wp2shell family.', set(), words)['reasons'], ['word'], 'the summary counts')
        self.assertEqual(N.classify('wp2shells everywhere', '', set(), words)['reasons'], [], 'inside a longer word is not the word')
        self.assertEqual(N.classify('awp2shell', '', set(), words)['reasons'], [], 'nor at the end of one')
        self.assertEqual(N.classify('Quiet news about Remote  Code\nExecution tooling', '', set(), words)['reasons'], ['word'], 'a phrase, with any blanks between its parts')
        self.assertEqual(N.classify('remote code', 'execution is not the phrase together', set(), words)['reasons'], [], 'the parts apart are not the phrase')

    def test_it_comes_with_the_other_reasons_and_not_instead_of_them(self):
        got = N.classify('Critical wp2shell flaw is being actively exploited', '', set(), ['wp2shell'])
        self.assertEqual(got['reasons'], ['critical', 'exploited', 'word'], 'in the order of the reasons, the word last')
        self.assertTrue(set(got['reasons']) <= set(N.REASONS))
        self.assertEqual(N.REASONS[-1], 'word')

    def test_a_round_up_or_a_webinar_is_not_critical_for_a_word_either(self):
        for title in ('Weekly Recap: wp2shell and more', 'Webinar: how wp2shell works', 'ThreatsDay Bulletin: wp2shell', 'A checklist after wp2shell'):
            self.assertEqual(N.classify(title, '', set(), ['wp2shell'])['critical'], False, title)

    def test_the_words_an_operator_writes_are_cleaned_and_the_everyday_ones_refused(self):
        self.assertEqual(N.clean_critical_words('wp2shell\nPHP2Shell, remote  code execution; Log4Shell\n\n  wp2shell '), (['wp2shell', 'php2shell', 'remote code execution', 'log4shell'], None),
                         'a line, a comma or a semicolon ends a word; blanks inside are one; each is kept once')
        self.assertEqual(N.clean_critical_words(''), ([], None))
        self.assertEqual(N.clean_critical_words(['Foo-Bar', 'a.b.c', 'x_y_z']), (['foo-bar', 'a.b.c', 'x_y_z'], None))
        for bad, text in ((['ab'], 'ab'), (['x' * 41], 'x' * 40), (['-lead'], '-lead'), (['trail-'], 'trail-'), (['has/slash'], 'has/slash'), (['semi:colon'], 'semi:colon'), ([5], 'text'), (7, 'list'),
                          (['patch'], 'patch'), (['file'], 'file')):
            words, why = N.clean_critical_words(bad)
            self.assertIsNone(words, bad)
            self.assertIn(text, why, bad)
        self.assertEqual(N.clean_critical_words(['patch notes'])[1], None, 'an everyday word inside a phrase is part of the phrase')
        words, why = N.clean_critical_words(['okword', '<script>alert(1)</script>'])
        self.assertIsNone(words)
        self.assertNotIn('<', why, 'what was typed is shown without its markup')
        many = ['word%03d' % i for i in range(N.MAX_CRITICAL_WORDS)]
        self.assertEqual(N.clean_critical_words(many), (many, None))
        self.assertIn('at most', N.clean_critical_words(many + ['word999'])[1])

    def test_they_are_read_defensively_one_at_a_time_and_kept_in_the_settings(self):
        got = N.settings({'critical_words': ['WP2Shell', 'ab', 5, None, 'wp2shell', 'patch', 'remote code execution', 'has/slash']})
        self.assertEqual(got['critical_words'], ['wp2shell', 'remote code execution'], 'a damaged entry is left out and the others stay')
        for junk in ('wp2shell', {'a': 1}, 7, None):
            self.assertEqual(N.settings({'critical_words': junk})['critical_words'], [])
        self.assertEqual(len(N.settings({'critical_words': ['word%03d' % i for i in range(N.MAX_CRITICAL_WORDS + 20)]})['critical_words']), N.MAX_CRITICAL_WORDS)
        self.assertEqual(N.settings(None)['critical_words'], [])
        self.assertIsNot(N.settings(None)['critical_words'], N.settings(None)['critical_words'])
        self.assertEqual(N.clean_update({'critical_words': 'wp2shell\nlog4shell'}), ({'critical_words': ['wp2shell', 'log4shell']}, None))
        self.assertEqual(N.clean_update({'scope': 'all'}), ({'scope': 'all'}, None), 'a field that is not in the body is left as it is')
        update, why = N.clean_update({'critical_words': ['patch']})
        self.assertIsNone(update)
        self.assertIn('everyday word', why)

    def test_process_classifies_new_items_with_the_words(self):
        rec, new = N.process({}, parsed(('a', 'A wp2shell attack', '', NOW - 60)), NOW, (), ['wp2shell'])
        self.assertEqual([(n['critical'], n['reasons']) for n in new], [(True, ['word'])])
        rec, new = N.process(rec, parsed(('a', 'A wp2shell attack', '', NOW - 60), ('b', 'More about wp2shell', '', NOW - 30), ('c', 'Quiet', '', NOW - 30)), NOW + 1800, (), ['wp2shell'])
        self.assertEqual([(n['id'], n['critical'], n['fresh']) for n in new], [('b', True, True), ('c', False, True)])
        rec, new = N.process({}, parsed(('d', 'A wp2shell attack', '', NOW - 60)), NOW)
        self.assertEqual([n['critical'] for n in new], [False], 'with no words given, the same headline is not critical')


class TestRelevance(unittest.TestCase):

    def test_a_package_is_one_word(self):
        cases = {
            'php8.3-fpm': {'php'}, 'php-common': {'php'}, 'libapache2-mod-php8.3': {'apache'}, 'apache2': {'apache'}, 'nginx-common': {'nginx'},
            'openssh-server': {'openssh'}, 'postgresql-16': {'postgresql'}, 'linux-image-6.8.0-45-generic': {'linux', 'kernel'},
            'libssl3': {'openssl', 'libssl', 'ssl'}, 'libcurl4': {'curl', 'libcurl'}, 'python3-pip': {'python'}, 'openjdk-17-jre-headless': {'openjdk', 'java'},
            'xz-utils': {'xz'}, 'liblzma5': {'xz', 'lzma', 'liblzma'}, 'kernel-core': {'kernel', 'linux'}, 'httpd': {'httpd', 'apache'},
        }
        for name, want in cases.items():
            self.assertTrue(want <= N.package_tokens(name), (name, N.package_tokens(name)))

    def test_a_package_named_like_an_ordinary_word_stands_for_nothing(self):
        for name in ('patch', 'file', 'make', 'less', 'login', 'mount', 'time', 'which', 'tree', 'init', 'base-files', 'common-utils', 'device-mapper', 'screen', 'shared-mime-info',
                     'default-jre', 'source-highlight', 'team', 'power-profiles-daemon', 'input-utils', 'cloud-init', 'network-manager', 'security-tools'):
            self.assertEqual(N.package_tokens(name), set(), name)

    def test_junk_in_a_package_list_does_not_raise(self):
        for junk in (None, 7, [], {}, '', '---', 'a', '..', b'bytes'):
            self.assertIsInstance(N.package_tokens(junk), set)
        self.assertEqual(N.vocabulary({'h': {'packages': [None, 7, {'name': None}, {'name': 'php8.3-cli'}, 'nginx']}, 'g': 'not a map', 'i': {'packages': 'no'}}), {'php', 'nginx'})

    def test_the_words_an_item_names(self):
        vocab = N.vocabulary({'web': {'packages': [{'name': 'php8.3-fpm'}, {'name': 'nginx'}, {'name': 'patch'}, {'name': 'openssl'}, {'name': 'linux-image-6.8.0'}]}})
        text = 'PHP Fixes 7 Critical Flaws. The patch for PHP8 and an NGINX bug; also the Linux kernel and OpenSSL.'
        self.assertEqual(N.software_in(text, vocab), ['kernel', 'linux', 'nginx', 'openssl', 'php'])
        self.assertEqual(N.software_in('A patch for the file and the time it takes, which is long.', vocab), [], 'ordinary words match nothing')
        self.assertEqual(N.software_in('', vocab), [])
        self.assertEqual(N.software_in('PHP', set()), [])

    def test_a_word_inside_another_word_is_not_a_mention(self):
        vocab = {'php', 'git'}
        self.assertEqual(N.software_in('phpmyadmin and github and digital', vocab), [], 'whole words only')
        self.assertEqual(N.software_in('php-fpm and git/ssh', vocab), ['git', 'php'])


# ── what the hosts have and what they run ───────────────────────────────────

NOW_S = 1_800_000_000


def pkgs(*names):
    return {'web01': {'packages': [{'name': n} for n in names]}}


def host(procs=(), ports=(), last_seen=NOW_S, **kw):
    """A host as the agent reports it: process names and (program, port, scope) of the sockets that listen."""
    d = {'name': 'h', 'last_seen': last_seen, 'sysinfo': {'proc_names': list(procs), 'listening_ports': [{'process': p, 'port': n, 'scope': sc, 'proto': 'tcp'} for p, n, sc in ports]}}
    d.update(kw)
    return d


class TestFleetSoftware(unittest.TestCase):

    # the first words of package names on a Debian or Ubuntu server that made "console", "language", "http", "command", "software", "xml", "uri", "firmware", "amd" and "intel"
    # appear as "software on your hosts" for a real fleet, and a headline about a management console relevant
    EVERYDAY = ['console-setup', 'console-common', 'language-selector-common', 'language-pack-en', 'libhttp-date-perl', 'command-not-found', 'software-properties-common',
                'xml-core', 'liburi-perl', 'amd64-microcode', 'intel-microcode', 'firmware-sof-signed', 'patch', 'file', 'shared-mime-info']
    REAL = ['php8.3-fpm', 'nginx', 'openssh-server', 'ruby3.1', 'postgresql-16', 'linux-image-6.8.0-45-generic', 'libssl3', 'apache2', 'libc6']

    def test_the_everyday_words_of_a_real_fleet_are_not_software_it_has(self):
        fleet = N.fleet_software(pkgs(*self.EVERYDAY, *self.REAL))
        self.assertEqual(fleet['installed'], {'php', 'nginx', 'openssh', 'ruby', 'postgresql', 'linux', 'kernel', 'openssl', 'apache', 'glibc'})
        for word in ('console', 'language', 'http', 'command', 'software', 'xml', 'uri', 'firmware', 'amd', 'intel', 'patch', 'file', 'shared'):
            self.assertNotIn(word, fleet['installed'], word)
        text = 'The management console of the appliance has a flaw. The command line, the software and the firmware, XML over HTTP to a URI, on AMD and Intel hardware.'
        self.assertEqual(N.mentions(text, fleet), ([], []), 'the headline that matched console, command, software, xml, uri, firmware, amd and intel before')

    def test_the_known_words_are_a_list_of_software_and_no_everyday_word(self):
        self.assertFalse(N.KNOWN_SOFTWARE & N.STOP, 'a word cannot be both software people write about and one the matcher ignores')
        self.assertGreaterEqual(len(N.KNOWN_SOFTWARE), 100)
        for word in ('php', 'nginx', 'openssh', 'linux', 'postgresql', 'docker', 'java', 'ruby', 'python'):
            self.assertIn(word, N.KNOWN_SOFTWARE)

    def test_a_kernel_thread_or_a_program_nothing_installed_gives_a_name_to_is_not_software_that_runs(self):
        fleet = N.fleet_software({}, {'a': host(procs=['migration/0', 'watchdog/0', 'kworker/0:1', 'rcu_sched', 'weirdd', 'login', 'time'])})
        self.assertEqual(fleet['running'], {}, 'none of these is a word of a package, of the list, or of App discovery')
        self.assertEqual(N.mentions('A migration of the watchdog, the time to login', fleet), ([], []))

    def test_software_that_is_not_in_the_list_counts_as_soon_as_it_runs(self):
        store, devs = pkgs('unrealircd', 'nginx'), {'a': host(procs=['unrealircd'])}
        fleet = N.fleet_software(store, devs)
        self.assertNotIn('unrealircd', fleet['installed'], 'installed alone is not enough for a word that is not in the list')
        self.assertEqual(set(fleet['running']), {'unrealircd'})
        self.assertEqual(N.mentions('Attackers exploit an UnrealIRCd flaw', fleet), (['unrealircd'], ['unrealircd']))
        self.assertEqual(N.mentions('Attackers exploit an UnrealIRCd flaw', N.fleet_software(store, {})), ([], []), 'installed and not running: no')

    def test_what_runs_is_counted_by_host_and_a_socket_that_listens_to_the_internet_is_said(self):
        devs = {'a': host(procs=['nginx', 'php-fpm8.3'], ports=[('nginx', 443, 'world'), ('php-fpm8.3', 9000, 'local')]),
                'b': host(procs=['nginx', 'sshd'], ports=[('nginx', 80, 'lan'), ('sshd', 22, 'world')]),
                'c': host(procs=['sshd'])}
        run = N.fleet_software(pkgs('nginx', 'php8.3-fpm', 'openssh-server'), devs)['running']
        self.assertEqual(run['nginx'], {'hosts': 2, 'world': True})
        self.assertEqual(run['php'], {'hosts': 1, 'world': False}, 'php-fpm listens on the host only')
        self.assertEqual(run['openssh'], {'hosts': 2, 'world': True}, 'sshd is openssh')

    def test_a_host_that_has_not_reported_without_an_agent_or_decommissioned_is_no_evidence(self):
        devs = {'old': host(procs=['nginx'], last_seen=NOW_S - N.RUNNING_STALE_S - 10), 'agentless': host(procs=['nginx'], agentless=True),
                'gone': host(procs=['nginx'], decommissioned=True), 'ok': host(procs=['nginx'], last_seen=NOW_S - 60)}
        self.assertEqual(N.running_software(devs, now=NOW_S)['nginx']['hosts'], 1)
        self.assertEqual(N.running_software({'old': devs['old']}, now=NOW_S), {})
        self.assertEqual(N.running_software({'old': devs['old']})['nginx']['hosts'], 1, 'no clock given, no host is stale')

    def test_a_container_that_is_up_counts_and_one_that_stopped_does_not(self):
        devs = {'a': host(), 'b': host()}
        boxes = {'a': {'items': [{'image': 'grafana/grafana:10.2', 'status': 'Up 2 days'}, {'image': 'ghcr.io/x/redis@sha256:abc', 'status': 'Exited (0) 3 hours ago'}]},
                 'b': {'items': [{'image': 'nextcloud', 'status': 'running'}, {'image': 'postgres:16', 'status': 'paused'}]}}
        run = N.running_software(devs, boxes)
        self.assertEqual(set(run), {'grafana', 'nextcloud'})

    def test_hosts_that_report_junk_never_raise(self):
        junk = {'a': 'x', 'b': {'sysinfo': 'no'}, 'c': {'sysinfo': {'proc_names': 'no', 'listening_ports': [1, None, {'process': 5}, {'process': 'nginx', 'scope': 7}]}},
                'd': {'sysinfo': {'proc_names': [None, 5, ['x'], 'nginx']}}, 7: None, None: {}}
        self.assertEqual(set(N.running_software(junk, {'d': 'no', 'c': {'items': 'no'}, 'x': None})), {'nginx'})
        for bad in (None, [], 'x', 7):
            self.assertEqual(N.running_software(bad, bad), {})
            self.assertEqual(N.fleet_software(bad, bad, bad), {'installed': set(), 'running': {}})
        self.assertEqual(N.mentions(None, {}), ([], []))
        self.assertEqual(N.mentions('PHP', None), ([], []))

    def test_names_an_operator_adds_count_as_software_the_hosts_have(self):
        store = pkgs('unrealircd', 'console-setup', 'squidguard')
        fleet = N.fleet_software(store, extra=['unrealircd'])
        self.assertEqual(fleet['installed'] & {'unrealircd', 'console', 'squidguard'}, {'unrealircd'}, 'only the name that was added, and not the others')
        self.assertEqual(N.mentions('An UnrealIRCd flaw lets attackers run code', fleet), (['unrealircd'], []))
        self.assertEqual(N.mentions('An UnrealIRCd flaw lets attackers run code', N.fleet_software(store)), ([], []), 'without the name it is not matched')
        fleet = N.fleet_software({}, {'a': host(procs=['myappd'])}, extra=('myappd',))
        self.assertEqual(set(fleet['running']), {'myappd'}, 'a program that runs under an added name counts, with no package of that name')
        for junk in (None, 'unrealircd', 7, {'a': 1}):
            self.assertEqual(N.fleet_software(store, extra=junk)['installed'] & {'unrealircd'}, set(), junk)

    def test_the_apache_web_server_is_not_every_apache_project(self):
        fleet = N.fleet_software(pkgs('apache2'), {'a': host(procs=['apache2'])})
        self.assertEqual(N.mentions('Critical Apache Roller RCE Flaw Under Active Exploitation', fleet), ([], []))
        self.assertEqual(N.mentions('Apache Tomcat and Apache Kafka fix flaws', fleet), ([], []))
        for text in ('Apache HTTP Server 2.4 flaw', 'Apache web server flaw', 'A flaw in Apache 2.4.58', 'httpd and apache2 are affected', 'Apache2 flaw'):
            self.assertEqual(N.mentions(text, fleet)[1], ['apache'], text)

    def test_a_node_is_not_node_js_and_the_kernel_of_windows_is_not_linux(self):
        fleet = N.fleet_software(pkgs('nodejs', 'linux-image-6.8.0'), {'a': host(procs=['node', 'nodejs'])})
        self.assertEqual(N.mentions('A malicious node in the cluster can read secrets', fleet), ([], []))
        self.assertEqual(N.mentions('A Node.js flaw lets a package run code', fleet)[1], ['node'])
        self.assertEqual(N.mentions('Windows kernel zero-day under attack', fleet), ([], []))
        self.assertEqual(N.mentions('macOS kernel flaw', fleet), ([], []))
        self.assertEqual(N.mentions('Linux kernel flaw', fleet)[0], ['kernel', 'linux'])
        self.assertEqual(N.mentions('A kernel flaw', fleet)[0], ['kernel'], 'an unqualified kernel is read as the one the hosts run')

    def test_a_real_fleet_and_the_headlines_that_were_wrong_before(self):
        store = pkgs(*self.EVERYDAY, *self.REAL, 'java-common', 'openjdk-17-jre-headless')
        devs = {'a': host(procs=['systemd', 'sshd', 'nginx', 'php-fpm8.3', 'cron', 'migration/0'], ports=[('nginx', 443, 'world'), ('php-fpm8.3', 9000, 'local')])}
        fleet = N.fleet_software(store, devs)
        cases = [
            # (headline and summary, what it names, what of that runs)
            ('PHP Fixes 7 Critical Flaws, Including Bugs That Could Allow Remote Code Execution. The PHP language project fixed them.', ['php'], ['php']),
            ('Critical VMware vCenter Zero-Day Flaw Lets Network Attackers Bypass Authentication. The management console and the command line are affected.', [], []),
            ('10-Year-Old NGINX HTTP/2 Flaw Lets Unauthenticated Attackers Execute Code on Servers. The HTTP server is nginx.', ['nginx'], ['nginx']),
            ('Ruby Ships Fixes for 7 Flaws, Including Critical Ruby2Shell. Default Rails apps are at risk.', ['ruby'], []),
            ('Critical Apache Roller RCE Flaw Under Active Exploitation. The Java software parses XML.', ['java'], []),
            ('F5 Warns 6 Critical BIG-IP Flaws Can Crash Traffic. An attacker can run a command in the software.', [], []),
            ('Java4Shell Flaw Enables Pre-Auth RCE in Jira. Java applications run on AMD and Intel hardware, with firmware updates.', ['java'], []),
            ('Hijacked Optimizely Scripts Served Card Skimmer. Report URI, a firm that monitors the scripts, said so.', [], []),
        ]
        for text, names, running in cases:
            self.assertEqual(N.mentions(text, fleet), (names, running), text[:60])


# ── what has been seen ───────────────────────────────────────────────────────

def parsed(*specs):
    """items as parse_feed returns them: (id, title, summary, published) -> dicts."""
    return [{'id': i, 'title': t, 'link': '', 'published': p, 'summary': s} for i, t, s, p in specs]


class TestProcess(unittest.TestCase):

    CRIT = 'Critical RCE flaw in PHP'

    def test_the_first_read_of_a_feed_only_records(self):
        rec, new = N.process({}, parsed(('a', self.CRIT, '', NOW - 60), ('b', 'Quiet news', '', NOW - 60)), NOW)
        self.assertEqual([n['fresh'] for n in new], [False, False], 'nothing is fresh on the first read, however recent')
        self.assertEqual((rec['baselined'], sorted(rec['seen'])), (True, ['a', 'b']))
        self.assertTrue(new[0]['critical'] and not new[1]['critical'], 'but each is classified, so the page can list them')

    def test_after_that_a_new_item_is_fresh_and_a_seen_one_is_not_new(self):
        rec, _ = N.process({}, parsed(('a', self.CRIT, '', NOW - 60)), NOW)
        rec, new = N.process(rec, parsed(('a', self.CRIT, '', NOW - 60), ('c', 'Critical flaw in nginx', '', NOW - 30)), NOW + 1800)
        self.assertEqual([(n['id'], n['fresh'], n['critical']) for n in new], [('c', True, True)])
        rec, new = N.process(rec, parsed(('a', self.CRIT, '', NOW - 60), ('c', 'Critical flaw in nginx', '', NOW - 30)), NOW + 3600)
        self.assertEqual(new, [], 'the same items again are nothing')

    def test_an_item_older_than_three_days_is_new_but_not_fresh(self):
        rec, _ = N.process({}, parsed(('a', 'x', '', NOW)), NOW)
        rec, new = N.process(rec, parsed(('old', self.CRIT, '', NOW - N.MAX_AGE_S - 10), ('edge', self.CRIT, '', NOW - N.MAX_AGE_S + 10), ('undated', self.CRIT, '', None)), NOW)
        self.assertEqual({n['id']: n['fresh'] for n in new}, {'old': False, 'edge': True, 'undated': True})

    def test_an_item_dated_in_the_future_is_fresh(self):
        rec, _ = N.process({}, [], NOW)
        rec, new = N.process(rec, parsed(('f', self.CRIT, '', NOW + 10 * 86400)), NOW)
        self.assertTrue(new[0]['fresh'])

    def test_the_memory_is_bounded_and_forgets_the_oldest(self):
        rec = {}
        for i in range(N.MAX_SEEN + 80):
            rec, _ = N.process(rec, parsed((f'id{i}', 'x', '', NOW)), NOW + i)
        self.assertEqual(len(rec['seen']), N.MAX_SEEN)
        self.assertNotIn('id0', rec['seen'])
        self.assertIn(f'id{N.MAX_SEEN + 79}', rec['seen'])

    def test_a_damaged_record_is_read_as_a_feed_never_read(self):
        for junk in (None, 'x', 7, [], {'seen': 'no', 'baselined': 'yes'}, {'seen': {'a': 'text', 5: 1, 'b': True}}):
            rec, new = N.process(junk, parsed(('a', 'x', '', NOW)), NOW)
            self.assertEqual([n['fresh'] for n in new], [False], junk)
            self.assertEqual(sorted(rec['seen']), ['a'])


# ── the settings ─────────────────────────────────────────────────────────────

class TestSettings(unittest.TestCase):

    def test_what_counts_has_three_choices_and_the_default_is_the_middle_one(self):
        self.assertEqual(N.SCOPES, ('running', 'relevant', 'all'))
        self.assertEqual(N.settings(None)['scope'], 'relevant')
        for scope in N.SCOPES:
            self.assertEqual(N.settings({'scope': scope})['scope'], scope)
            self.assertEqual(N.clean_update({'scope': scope}), ({'scope': scope}, None))
        self.assertEqual(N.settings({'scope': 'installed'})['scope'], 'relevant')

    def test_the_names_an_operator_adds_are_words_of_letters_and_digits_and_never_everyday_words(self):
        self.assertEqual(N.clean_words('unrealircd, squidguard\nphp8  Exim4'), (['unrealircd', 'squidguard', 'php', 'exim'], None))
        self.assertEqual(N.clean_words(['UnrealIRCd6', 'unrealircd']), (['unrealircd'], None), 'a version is dropped and a name is kept once')
        self.assertEqual(N.clean_words(''), ([], None))
        for bad, word in ((['console'], 'console'), (['patch'], 'patch'), (['a-b'], 'a-b'), (['ab'], 'ab'), (['x' * 40], 'x' * 40), ([5], 'text'), (7, 'list'),
                          (['has space'], 'has')):
            words, why = N.clean_words(bad)
            self.assertIsNone(words, bad)
            self.assertIn(word, why, bad)
        words, why = N.clean_words(['okname', '<script>alert(1)</script>'])
        self.assertIsNone(words)
        self.assertNotIn('<', why, 'what was typed is shown without its markup')
        self.assertEqual(N.clean_words([f'name{chr(97 + i % 26)}{chr(97 + i // 26)}x' for i in range(N.MAX_WORDS)])[1], None)
        self.assertIn('at most', N.clean_words([f'name{chr(97 + i % 26)}{chr(97 + i // 26)}x' for i in range(N.MAX_WORDS + 1)])[1])

    def test_the_names_are_read_defensively_one_at_a_time(self):
        got = N.settings({'words': ['UnrealIRCd6', 'console', 'x', 5, None, 'unrealircd', 'ok-name', 'squidguard']})
        self.assertEqual(got['words'], ['unrealircd', 'squidguard'], 'a damaged entry is left out and the others stay')
        for junk in ('unrealircd', {'a': 1}, 7, None):
            self.assertEqual(N.settings({'words': junk})['words'], [])
        self.assertEqual(len(N.settings({'words': [f'name{chr(97 + i % 26)}{chr(97 + i // 26)}x' for i in range(N.MAX_WORDS + 20)]})['words']), N.MAX_WORDS)
        self.assertEqual(N.clean_update({'words': 'unrealircd\nsquidguard'}), ({'words': ['unrealircd', 'squidguard']}, None))
        update, why = N.clean_update({'words': ['console']})
        self.assertIsNone(update)
        self.assertIn('everyday word', why)

    def test_the_defaults_are_off_and_read_the_one_feed(self):
        s = N.settings(None)
        self.assertEqual(s, {'enabled': False, 'feeds': ['https://feeds.feedburner.com/TheHackersNews'], 'scope': 'relevant', 'action': 'scan', 'words': [], 'critical_words': []})
        self.assertIsNot(N.settings(None)['feeds'], N.settings(None)['feeds'], 'a copy each time: one caller cannot change the next one default')

    def test_damaged_settings_read_as_defaults_field_by_field(self):
        s = N.settings({'enabled': 'yes', 'feeds': 'not a list', 'scope': 'everything', 'action': 7})
        self.assertEqual(s, N.settings(None))
        s = N.settings({'enabled': True, 'feeds': ['https://a.example/rss', 'javascript:alert(1)', 5, 'https://a.example/rss', 'https://u:p@b.example/x'], 'scope': 'all', 'action': 'list'})
        self.assertEqual(s, {'enabled': True, 'feeds': ['https://a.example/rss'], 'scope': 'all', 'action': 'list', 'words': [], 'critical_words': []})

    def test_a_feed_address_has_to_be_a_public_looking_http_address(self):
        good = ['https://feeds.example.net/rss.xml', 'http://news.example.net/feed?format=rss', 'https://news.example.net:8443/a/b.atom', 'https://xn--bcher-kva.example/feed',
                'https://news.example.net/feed?author=smith&keyword=php&category=security']
        for url in good:
            self.assertEqual(N.valid_feed_url(url), (url, None), url)
        bad = ['', '   ', 'ftp://x.example/rss', 'file:///etc/passwd', 'javascript:alert(1)', '//x.example/rss', 'https://', 'https:///path', 'x.example/rss',
               'https://user:pass@x.example/rss', 'https://user@x.example/rss', 'https://x.example/rss?token=abc', 'https://x.example/rss?api_key=abc', 'https://x.example/rss?Auth=1',
               'https://x.example/rss?password=1', 'https://x.example/rss?sig=1', 'https://x.example/rss?key=1', 'https://x.example/rss?access_token=1', 'https://x.example/rss?X-Api-Key=1',
               'https://x.example/rss?a=1&secret=2', 'https://x.example:notaport/rss', 'https://x.example/a b',
               'https://x.example/a\nb', 'https://x.example/' + 'a' * 400, 5, None, ['https://x.example']]
        for url in bad:
            got, why = N.valid_feed_url(url)
            self.assertIsNone(got, url)
            self.assertTrue(why, url)

    def test_the_update_names_the_first_thing_that_is_wrong(self):
        self.assertEqual(N.clean_update({}), ({}, None))
        self.assertEqual(N.clean_update({'enabled': True, 'scope': 'all', 'action': 'alert', 'feeds': ['https://a.example/x']}),
                         ({'enabled': True, 'scope': 'all', 'action': 'alert', 'feeds': ['https://a.example/x']}, None))
        self.assertEqual(N.clean_update({'enabled': 'true'})[0], {'enabled': True})
        self.assertEqual(N.clean_update({'feeds': 'https://a.example/x\n\n  https://b.example/y  \nhttps://a.example/x'})[0], {'feeds': ['https://a.example/x', 'https://b.example/y']})
        for body, word in (({'enabled': 'maybe'}, 'enabled'), ({'enabled': 1}, 'enabled'), ({'scope': 'x'}, 'scope'), ({'action': 'x'}, 'action'), ({'feeds': 7}, 'feeds'),
                           ({'feeds': ['ftp://x']}, 'http'), ({'feeds': ['https://x.example'] * 1 + [f'https://h{i}.example' for i in range(N.MAX_FEEDS)]}, 'at most')):
            update, why = N.clean_update(body)
            self.assertIsNone(update, body)
            self.assertIn(word, why, body)

    def test_a_body_that_is_not_a_map_changes_nothing(self):
        for junk in (None, [], 'x', 7):
            self.assertEqual(N.clean_update(junk), ({}, None))


if __name__ == '__main__':
    unittest.main()
