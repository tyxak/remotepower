"""Probing and a service's login have kinds (8.0.1).

Until 8.0.1 every source that saw an address look for something said `probe`: a request for /.env, for
phpMyAdmin, for a WordPress file, a walk through the honeypot's fake backups. A day of reports read as one
sentence fourteen times. `probe` and `service_brute` are general classes now, each with finer kinds
(threat_evidence.FAMILIES), and a source names the kind when it can tell.

What has to hold, and where a half-applied rule would hide:

  * the families are well formed, and every class files under category ids the two services have;
  * a report leaves the general class out when its kinds account for it, and keeps it when they do not:
    one request for /.env and fifty a source could only call probing are both, not fifty-one of the first;
  * ignoring a general class ignores its kinds, so an ignore list from before means what it meant, and
    ignoring one kind does not hold back an address that mostly did something else. Both through the real sweep;
  * every source names only classes the vocabulary has, and every kind can be reached from a source;
  * the page's tables and the guides' tables are the code's.
"""
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-classes-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import appliance_evidence as ae  # noqa: E402
import edge_evidence as ee  # noqa: E402
import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402
from test_ip_intel import ATTACKER  # noqa: E402
from test_v720_threat_report_engine import _Engine, raw_event  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
NOW = 1_790_000_000

# Both lists as the services publish them (abuseipdb.com/categories and sniffcat.com/documentation/categories, 2026-11-15).
ABUSEIPDB_IDS = set(range(1, 24))
SNIFFCAT_IDS = set(range(1, 28))

# One token that names each class of a family, and the source family it arrives in.
TOKEN = {
    'probe': ('web', 'req:probe'), 'config_probe': ('web', 'req:config'), 'admin_probe': ('web', 'req:admin'),
    'wordpress': ('web', 'req:wordpress'), 'user_enum': ('web', 'req:enum'), 'proxy_probe': ('web', 'req:proxy'),
    'host_recon': ('cf', 'req:recon'), 'method_probe': ('cf', 'req:method'), 'decoy_loot': ('trap', 'trap:gitdump'),
    'service_brute': ('cs', 'cs:crowdsecurity/vnc-bf'), 'rdp_brute': ('cs', 'cs:crowdsecurity/rdp-bf'),
    'smb_brute': ('cs', 'cs:crowdsecurity/smb-bf'), 'telnet_brute': ('cs', 'cs:crowdsecurity/telnet-bf'),
    'db_brute': ('cs', 'cs:crowdsecurity/mysql-bf'),
}


def ev(counts):
    """Evidence in which each class of `counts` was seen that many times, through the vocabulary's own check."""
    raw = {'ip': ATTACKER, 'first': NOW - 600, 'last': NOW, 'src': {}, 'tok': {}}
    for cls, n in counts.items():
        fam, token = TOKEN[cls]
        raw['tok'].setdefault(fam, {})[token] = n
        raw['src'][fam] = max(raw['src'].get(fam, 0), n)
    out = te.normalize_event(raw, now=NOW, families=te.SOURCES)
    assert out is not None, counts
    assert te.classes(out) == counts, (te.classes(out), counts)
    return out


def spoken(counts):
    return [c for c, _n in te.dominant(ev(counts), 9)]


class TestTheFamilies(unittest.TestCase):
    def test_they_are_well_formed(self):
        self.assertEqual(set(te.FAMILIES), {'probe', 'service_brute'})
        kinds = [k for ks in te.FAMILIES.values() for k in ks]
        self.assertEqual(len(kinds), 12)
        self.assertEqual(len(kinds), len(set(kinds)), 'a kind in two families')
        self.assertEqual(set(kinds) & set(te.FAMILIES), set(), 'a general class that is also a kind')
        for general, ks in te.FAMILIES.items():
            self.assertIn(general, te.CLASSES)
            for k in ks:
                self.assertIn(k, te.CLASSES)
                self.assertEqual(te.GENERAL_OF[k], general)
        self.assertEqual(set(te.GENERAL_OF), set(kinds))
        self.assertEqual(set(TOKEN), set(kinds) | set(te.FAMILIES), 'this module has no token for a class of a family')

    def test_every_class_files_under_ids_the_services_have(self):
        self.assertGreaterEqual(len(te.CLASSES), 31)
        for cls, info in te.CLASSES.items():
            self.assertTrue(str(info['phrase']).strip(), cls)
            self.assertGreaterEqual(info['weight'], 1, cls)
            for prov, ids in (('abuseipdb', ABUSEIPDB_IDS), ('sniffcat', SNIFFCAT_IDS)):
                self.assertTrue(info[prov], (cls, prov))
                self.assertTrue(set(info[prov]) <= ids, (cls, prov, info[prov]))

    def test_the_kinds_say_what_they_are_and_file_where_they_belong(self):
        want = {
            'config_probe': ('probing for configuration files, keys and backups', (15, 21), (11, 21)),
            'admin_probe': ('probing for admin, login and debug pages', (21,), (21,)),
            'wordpress': ('WordPress probing', (21,), (21,)),
            'user_enum': ('user enumeration', (21,), (21,)),
            'proxy_probe': ('open proxy probing', (21,), (21,)),
            'host_recon': ('probing private host names', (21,), (21,)),
            'method_probe': ('probing with unusual HTTP methods', (21,), (21,)),
            'decoy_loot': ('downloading files from a decoy backup or repository', (15, 21), (11, 21)),
            'rdp_brute': ('RDP brute force', (18,), (17, 22)),
            'smb_brute': ('SMB brute force', (18,), (17, 24)),
            'telnet_brute': ('Telnet brute force', (18,), (17, 23)),
            'db_brute': ('database login brute force', (18,), (17,)),
        }
        self.assertEqual(set(want), set(te.GENERAL_OF))
        for cls, (phrase, abuse, sniff) in want.items():
            info = te.CLASSES[cls]
            self.assertEqual((info['phrase'], info['abuseipdb'], info['sniffcat']), (phrase, abuse, sniff), cls)
        self.assertEqual(len({i['phrase'] for i in te.CLASSES.values()}), len(te.CLASSES), 'two classes with one phrase')

    def test_a_kind_of_probing_is_a_web_class_and_a_service_is_not(self):
        for k in te.FAMILIES['probe']:
            e = ev({k: 3})
            self.assertTrue(te.web_only(e), k)
            self.assertEqual(te.what_word(e), 'web', k)
        self.assertEqual({k: te.what_word(ev({k: 3})) for k in te.FAMILIES['service_brute']},
                         {'rdp_brute': 'RDP', 'smb_brute': 'SMB', 'telnet_brute': 'Telnet', 'db_brute': 'database login'})
        for k in te.FAMILIES['service_brute']:
            self.assertFalse(te.web_only(ev({k: 3})), k)

    def test_the_request_kinds_are_one_table(self):
        """The token pattern is built from the table of kinds, so a kind cannot be accepted and mean nothing."""
        self.assertGreaterEqual(len(te._REQ_KINDS), 15)
        for kind, cls in te._REQ_KINDS.items():
            self.assertTrue(te.token_valid('req:' + kind), kind)
            self.assertEqual(te.token_class('req:' + kind), cls)
            self.assertIn(cls, te.CLASSES)
            self.assertEqual(te.token_class(te.req_token(cls)), cls)
        for bad in ('req:secrets', 'req:config_probe', 'req:CONFIG', 'req:config\n', 'req:', 'req:configx'):
            self.assertFalse(te.token_valid(bad), repr(bad))
        self.assertIsNone(te.req_token('waf'))


class TestWhatAReportSays(unittest.TestCase):
    def test_a_general_class_alone_is_said(self):
        self.assertEqual(spoken({'probe': 12}), ['probe'])
        self.assertEqual(spoken({'service_brute': 12}), ['service_brute'])

    def test_it_steps_aside_when_its_kinds_account_for_it(self):
        for general, kinds in te.FAMILIES.items():
            for k in kinds:
                for n_general, n_kind in ((1, 12), (5, 5), (12, 12)):
                    self.assertEqual(spoken({k: n_kind, general: n_general}), [k], (k, n_general, n_kind))

    def test_it_stays_when_they_do_not(self):
        """One request for /.env and fifty a source could only call probing: naming the kind alone would put all
        fifty-one under it, and under its category."""
        for general, kinds in te.FAMILIES.items():
            for k in kinds:
                e = ev({k: 1, general: 50})
                self.assertEqual(set(te.report_classes(e)), {k, general}, k)
                self.assertIn(te.CLASSES[general]['phrase'], te.attack_phrase(e))
                self.assertIn(te.CLASSES[k]['phrase'], te.attack_phrase(e))
                for prov in ('abuseipdb', 'sniffcat'):
                    self.assertTrue(set(te.CLASSES[general][prov]) <= set(te.categories(e, prov)), (k, prov))
        self.assertEqual(spoken({'config_probe': 5, 'probe': 6}), ['config_probe', 'probe'], 'one more than the kind explains')

    def test_several_kinds_account_for_it_together(self):
        self.assertEqual(set(spoken({'config_probe': 3, 'admin_probe': 3, 'probe': 6})), {'config_probe', 'admin_probe'})
        self.assertEqual(set(spoken({'config_probe': 3, 'admin_probe': 3, 'probe': 7})), {'config_probe', 'admin_probe', 'probe'})

    def test_one_family_says_nothing_about_the_other(self):
        self.assertEqual(set(spoken({'rdp_brute': 9, 'probe': 2})), {'rdp_brute', 'probe'})
        self.assertEqual(set(spoken({'config_probe': 9, 'service_brute': 2})), {'config_probe', 'service_brute'})

    def test_the_generic_waf_class_still_steps_aside(self):
        e = te.normalize_event({'ip': ATTACKER, 'first': NOW - 60, 'last': NOW, 'src': {'web': 4, 'waf': 4},
                                'tok': {'web': {'req:config': 4}, 'waf': {'crs:920350': 4}}}, now=NOW)
        self.assertEqual(te.classes(e), {'config_probe': 4, 'waf': 4})
        self.assertEqual([c for c, _n in te.dominant(e)], ['config_probe'])

    def test_the_sentence_and_the_ids_of_a_report(self):
        e = ev({'config_probe': 12})
        self.assertEqual(ip_intel.evidence_comment(e), 'probing for configuration files, keys and backups: 12 attempts '
                                                       'within 10 minutes, seen by web server log (reported by RemotePower)')
        self.assertEqual((te.categories(e, 'abuseipdb'), te.categories(e, 'sniffcat')), ([15, 21], [11, 21]))
        e = ev({'rdp_brute': 3})
        self.assertEqual((te.categories(e, 'abuseipdb'), te.categories(e, 'sniffcat')), ([18], [17, 22]))


class TestWhatIgnoringMeans(unittest.TestCase):
    def held(self, counts, ignored):
        ids, err = ip_intel.clean_ignore_classes(ignored)
        self.assertIsNone(err)
        return bool(ip_intel.ignore_reason(ATTACKER, [], te.report_classes(ev(counts)), set(ids)))

    def test_every_class_of_a_family_can_be_ticked(self):
        for cls in TOKEN:
            self.assertEqual(ip_intel.clean_ignore_classes([cls]), ([cls], None))

    def test_the_general_class_covers_each_of_its_kinds_and_no_other_family(self):
        for general, kinds in te.FAMILIES.items():
            other = next(g for g in te.FAMILIES if g != general)
            self.assertEqual(te.with_kinds([general]), {general, *kinds})
            for k in kinds:
                self.assertTrue(self.held({k: 5}, [general]), k)
                self.assertTrue(self.held({k: 5, general: 50}, [general]), k)
                self.assertFalse(self.held({k: 5}, [other]), k)
        self.assertEqual(te.with_kinds(['sqli', 'config_probe']), {'sqli', 'config_probe'}, 'a kind covers nothing but itself')
        self.assertEqual(te.with_kinds([]), set())

    def test_a_kind_ticked_on_its_own_covers_only_what_that_kind_accounts_for(self):
        self.assertTrue(self.held({'config_probe': 12}, ['config_probe']))
        self.assertTrue(self.held({'config_probe': 12, 'probe': 1}, ['config_probe']), 'the same probing seen twice')
        self.assertFalse(self.held({'probe': 12}, ['config_probe']), 'the control: the general class is not ticked')
        self.assertFalse(self.held({'config_probe': 1, 'probe': 50}, ['config_probe']))
        self.assertFalse(self.held({'admin_probe': 5}, ['config_probe']))
        self.assertFalse(self.held({'rdp_brute': 1, 'service_brute': 30}, ['rdp_brute']))
        self.assertTrue(self.held({'rdp_brute': 3}, ['rdp_brute']))

    def test_one_other_thing_and_it_is_reported(self):
        e = te.normalize_event({'ip': ATTACKER, 'first': NOW - 60, 'last': NOW, 'src': {'web': 9},
                                'tok': {'web': {'req:config': 5, 'req:sqli': 4}}}, now=NOW)
        self.assertEqual(ip_intel.ignore_reason(ATTACKER, [], te.report_classes(e), {'probe'}), '')
        self.assertEqual(ip_intel.ignore_reason(ATTACKER, [], te.report_classes(e), {'probe', 'sqli'}), 'only attacks you ignore')


class TestTheSweepHonoursTheKinds(_Engine):
    """The real sweep, queue and ledger, the services faked at the one seam that touches the network."""

    def reported(self):
        return len(self.posts())

    def test_control_a_kind_is_reported_by_its_name_and_its_ids(self):
        self.feed(raw_event(src={'web': 12}, tok={'web': {'req:config': 12}}))
        self.sweep()
        self.assertEqual(self.reported(), 2)
        form = {k: v[0] for k, v in parse_qs(self.post_to('abuseipdb')[0]['body'].decode()).items()}
        self.assertEqual(form['categories'], '15,21')
        self.assertTrue(form['comment'].startswith('probing for configuration files, keys and backups: 12 attempts'), form['comment'])
        self.assertEqual(json.loads(self.post_to('sniffcat')[0]['body'])['categories'], [11, 21])

    def test_a_list_that_ignored_probing_ignores_every_kind_of_it(self):
        self.policy(ignore_classes=['probe'])
        for i, kind in enumerate(('config', 'admin', 'wordpress', 'enum', 'proxy', 'probe')):
            self.feed(raw_event('185.220.101.%d' % (20 + i), src={'web': 12}, tok={'web': {'req:' + kind: 12}}))
        self.sweep()
        self.assertEqual(self.reported(), 0)
        errors = [str(a.get('errors')) for a in self.store()['attackers'].values()]
        self.assertEqual(len(errors), 6)
        self.assertTrue(all('only attacks you ignore' in e for e in errors), errors)

    def test_ignoring_one_kind_does_not_ignore_probing_in_general(self):
        self.policy(ignore_classes=['config_probe'])
        self.feed(raw_event(src={'web': 12}, tok={'web': {'req:probe': 12}}))
        self.sweep()
        self.assertEqual(self.reported(), 2)

    def test_ignoring_one_kind_does_not_hold_back_an_address_that_mostly_did_something_else(self):
        self.policy(ignore_classes=['config_probe'])
        self.feed(raw_event(src={'web': 51}, tok={'web': {'req:config': 1, 'req:probe': 50}}))
        self.sweep()
        self.assertEqual(self.reported(), 2)
        comment = json.loads(self.post_to('sniffcat')[0]['body'])['comment']
        self.assertTrue(comment.startswith('probing for exposed files and admin pages and probing for configuration files, '
                                           'keys and backups: 51 attempts'), comment)

    def test_the_kind_that_was_ticked_is_held_back(self):
        self.policy(ignore_classes=['config_probe'])
        self.feed(raw_event(src={'web': 12}, tok={'web': {'req:config': 12}}))
        self.sweep()
        self.assertEqual(self.reported(), 0)
        self.assertIn('only attacks you ignore', str(self.att()['errors']))

    def test_a_service_login_follows_the_same_rule(self):
        self.policy(ignore_classes=['service_brute'])
        self.feed(raw_event(src={'cs': 3}, tok={'cs': {'cs:crowdsecurity/rdp-bf': 3}}, dec=1))
        self.sweep()
        self.assertEqual(self.reported(), 0, 'a list that ignored a service login ignores RDP')
        self.policy(ignore_classes=['rdp_brute'])
        self.feed(raw_event('185.220.101.30', src={'cs': 3}, tok={'cs': {'cs:crowdsecurity/vnc-bf': 3}}, dec=1))
        self.sweep()
        self.assertEqual(self.reported(), 2, 'ignoring RDP does not ignore a login that is not RDP')


class TestEverySourceNamesAClassTheVocabularyHas(unittest.TestCase):
    def sources(self):
        return {
            'traps': set(te.TRAP_KINDS.values()),
            'request kinds': set(te._REQ_KINDS.values()),
            'fail2ban jails': {c for c, _rx in te._JAIL_RULES},
            'CrowdSec names': {c for c, _rx in te._CS_RULES},
            'Cloudflare rule words': {c for c, _rx in ee._RULE_WORDS},
            'intrusion detection': {c for c, _rx in ae._IDS_RULES},
        }

    def test_nothing_outside_the_vocabulary(self):
        for name, classes in self.sources().items():
            self.assertGreaterEqual(len(classes), 4, name)
            self.assertEqual(classes - set(te.CLASSES), set(), name)
        self.assertEqual({c for c, _rx in ae._IDS_RULES} - set(te.IDS_CLASSES), set())

    def test_every_kind_can_be_reached(self):
        reach = set().union(*self.sources().values())
        self.assertEqual(set(te.GENERAL_OF) - reach, set(), 'a kind no source can say is a label nobody will see')
        by = self.sources()
        self.assertEqual(set(te.FAMILIES['service_brute']) - (by['fail2ban jails'] & by['CrowdSec names']), set())
        self.assertEqual(set(te.FAMILIES['probe']) - by['request kinds'] - by['traps'], set())

    def test_the_kinds_come_before_their_general_class_in_every_ordered_table(self):
        """The first rule that matches wins, so a general class above one of its kinds would take every name."""
        for name, rules in (('fail2ban jails', te._JAIL_RULES), ('CrowdSec names', te._CS_RULES),
                            ('Cloudflare rule words', ee._RULE_WORDS), ('intrusion detection', ae._IDS_RULES)):
            order = [c for c, _rx in rules]
            for general, kinds in te.FAMILIES.items():
                if general not in order:
                    continue
                for k in kinds:
                    if k in order:
                        self.assertLess(order.index(k), order.index(general), f'{name}: {k} after {general}')

    def test_an_address_in_a_rule_description_is_not_what_the_rule_is_about(self):
        self.assertEqual(ee.rule_class('Block non-admin on private hosts (edge fw_private)'), 'host_recon')
        self.assertEqual(ee.rule_class('Block .env, .git, .sql and .bak files'), 'config_probe')
        self.assertEqual(ee.rule_class('Block .env and exploit paths'), 'config_probe')
        self.assertEqual(ee.rule_class('Block SQL injection'), 'sqli', 'the control')

    def test_a_signature_that_spells_out_postgresql_is_a_database_login(self):
        for sig in ('ET SCAN Multiple PostgreSQL Login Failures Possible Brute Force Attempt',
                    'GPL SQL PostgreSQL authentication failed', 'ET SCAN Postgres login brute force',
                    'ET SCAN Multiple MySQL Login Failures Possible Brute Force Attempt'):
            self.assertEqual(ae.classify_ids(sig, ''), 'db_brute', sig)


def _js_table(name):
    """A `const NAME = {...};` table of the page as a Python value. Keys are bare words and strings are single-quoted."""
    m = re.search(r'^const %s = (\{.*?^\});' % re.escape(name), _JS, re.S | re.M)
    assert m, name
    body = re.sub(r'//[^\n]*', '', m.group(1))
    body = re.sub(r"'((?:[^'\\]|\\.)*)'", lambda q: json.dumps(q.group(1)), body)
    body = re.sub(r'([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:', r'\1"\2":', body)
    body = re.sub(r',(\s*[}\]])', r'\1', body)
    return json.loads(body)


class TestThePageAndTheGuides(unittest.TestCase):
    def test_the_pages_tables_are_the_servers(self):
        self.assertEqual(_js_table('_IPI_CLASS'), {c: i['phrase'] for c, i in te.CLASSES.items()})
        self.assertEqual(_js_table('_IPI_FAMILY'), {g: list(ks) for g, ks in te.FAMILIES.items()})

    def table(self, path, heading_cell):
        """The rows of the Markdown table whose header starts with `heading_cell`, each as its cells."""
        lines = (_ROOT / path).read_text().splitlines()
        start = next(i for i, ln in enumerate(lines) if ln.startswith('| ' + heading_cell))
        rows = []
        for ln in lines[start + 2:]:
            if not ln.startswith('|'):
                break
            rows.append([c.strip() for c in ln.strip().strip('|').split('|')])
        return rows

    def test_the_guides_table_of_kinds_is_the_family(self):
        rows = self.table('docs/ip-intel.md', 'Kind | What the address asked for')
        said = [r[0] for r in rows]
        want = [te.CLASSES[k]['phrase'] for k in te.FAMILIES['probe']]
        self.assertEqual(len(said), 8)
        self.assertEqual(sorted(s.lower() for s in said), sorted(w.lower() for w in want))
        self.assertTrue(all(len(r[1]) > 10 for r in rows), 'a kind with nothing said about it')

    def test_the_guides_table_of_rule_words_is_the_code(self):
        """One row for each rule, in the code's order, and every word a row quotes puts a rule under that row's class."""
        rows = self.table('docs/edge-sources.md', 'The description mentions | Reported as')
        self.assertEqual([r[1] for r in rows], [te.CLASSES[c]['phrase'] for c, _rx in ee._RULE_WORDS])
        words = 0
        for (cls, _rx), (cell, _phrase) in zip(ee._RULE_WORDS, rows):
            quoted = re.findall(r'"([^"]+)"|`([^`]+)`', cell)
            self.assertTrue(quoted, cell)
            for pair in quoted:
                word = pair[0] or pair[1]
                self.assertEqual(ee.rule_class(f'Block {word} requests'), cls, f'{word!r} in the row for {cls}')
                words += 1
        self.assertGreaterEqual(words, 40)


if __name__ == '__main__':
    unittest.main()
