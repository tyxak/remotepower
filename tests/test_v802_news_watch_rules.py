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

    def test_the_defaults_are_off_and_read_the_one_feed(self):
        s = N.settings(None)
        self.assertEqual(s, {'enabled': False, 'feeds': ['https://feeds.feedburner.com/TheHackersNews'], 'scope': 'relevant', 'action': 'scan'})
        self.assertIsNot(N.settings(None)['feeds'], N.settings(None)['feeds'], 'a copy each time: one caller cannot change the next one default')

    def test_damaged_settings_read_as_defaults_field_by_field(self):
        s = N.settings({'enabled': 'yes', 'feeds': 'not a list', 'scope': 'everything', 'action': 7})
        self.assertEqual(s, N.settings(None))
        s = N.settings({'enabled': True, 'feeds': ['https://a.example/rss', 'javascript:alert(1)', 5, 'https://a.example/rss', 'https://u:p@b.example/x'], 'scope': 'all', 'action': 'list'})
        self.assertEqual(s, {'enabled': True, 'feeds': ['https://a.example/rss'], 'scope': 'all', 'action': 'list'})

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
