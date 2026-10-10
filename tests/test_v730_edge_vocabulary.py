"""The vocabulary's edge half (v7.3.0): Cloudflare's firewall events and the edge
honeypot's hits, which the SERVER reads from api.cloudflare.com and which no agent
may claim.

What is worth proving, as in the agent half: nothing outside the vocabulary
survives, nothing an attacker typed reaches the words of a report, and a sender
cannot speak for a family that is not its own.
"""
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import threat_evidence as te  # noqa: E402

NOW = 1_790_000_000
ATTACKER = '185.220.101.7'


def edge(**kw):
    raw = {'ip': ATTACKER, 'first': NOW - 600, 'last': NOW}
    raw.update(kw)
    out = te.normalize_event(raw, now=NOW, families=te.EDGE_SOURCES)
    assert out is not None, raw
    return out


class TestFamilies(unittest.TestCase):
    def test_the_two_sets_do_not_overlap_and_make_up_the_whole(self):
        self.assertEqual(set(te.AGENT_SOURCES) & set(te.EDGE_SOURCES), set())
        self.assertEqual(set(te.SOURCES), set(te.AGENT_SOURCES) | set(te.EDGE_SOURCES))
        self.assertEqual(set(te.EDGE_SOURCES), {'cf', 'trap'})

    def test_every_family_has_words(self):
        for fam in te.SOURCES:
            self.assertTrue(te.SOURCE_PHRASE[fam], fam)

    def test_an_agent_cannot_claim_the_edge(self):
        """An agent is read with AGENT_SOURCES: Cloudflare's and the honeypot's
        families, the honeypot's ban decision and the tokens are all dropped."""
        raw = {'ip': ATTACKER, 'src': {'trap': 50, 'cf': 50, 'web': 4},
               'tok': {'trap': {'trap:canary': 9}, 'cf': {'cf:waf': 9}, 'web': {'req:sqli': 4}},
               'trp': 3}
        out = te.normalize_event(raw, now=NOW)
        self.assertEqual(out['src'], {'web': 4})
        self.assertEqual(set(out['tok']), {'web'})
        self.assertEqual(out['trp'], 0)
        self.assertEqual(te.confirmed_by(out), '')

    def test_an_agent_with_only_edge_claims_has_no_evidence(self):
        raw = {'ip': ATTACKER, 'src': {'trap': 50}, 'tok': {'trap': {'trap:canary': 9}}, 'trp': 5}
        self.assertIsNone(te.normalize_event(raw, now=NOW))

    def test_the_edge_cannot_speak_for_a_host_log(self):
        raw = {'ip': ATTACKER, 'src': {'web': 50, 'f2b': 9, 'cf': 3},
               'tok': {'web': {'req:sqli': 9}, 'cf': {'cf:waf': 3}},
               'ban': ['sshd'], 'dec': 4, 'trp': 1}
        out = te.normalize_event(raw, now=NOW, families=te.EDGE_SOURCES)
        self.assertEqual(out['src'], {'cf': 3})
        self.assertEqual(out['ban'], [])
        self.assertEqual(out['dec'], 0)
        self.assertEqual(out['trp'], 1)


class TestTokens(unittest.TestCase):
    def test_every_trap_kind_and_cloudflare_mechanism_is_a_valid_token(self):
        for kind in te.TRAP_KINDS:
            self.assertTrue(te.token_valid(f'trap:{kind}'), kind)
        for kind in te.CF_KINDS:
            self.assertTrue(te.token_valid(f'cf:{kind}'), kind)
        self.assertTrue(te.token_valid('fw:scan'))

    def test_a_token_that_is_not_in_the_list_is_dropped(self):
        for bad in ('trap:unknown', 'trap:', 'trap:bait\n', 'trap:BAIT', 'trap:bait,x',
                    'cf:managed', 'cf:', 'cf:waf\n', 'cf:../etc', 'fw:flood', 'fw:', 'fw:scan\n'):
            self.assertFalse(te.token_valid(bad), repr(bad))
        out = edge(tok={'trap': {'trap:bait': 2, 'trap:rm -rf': 9}}, src={'trap': 2})
        self.assertEqual(out['tok'], {'trap': {'trap:bait': 2}})

    def test_the_classes(self):
        self.assertEqual(te.token_class('trap:robots'), 'bad_bot')
        self.assertEqual(te.token_class('trap:impostor'), 'bad_bot')
        self.assertEqual(te.token_class('trap:bait'), 'probe')
        self.assertEqual(te.token_class('trap:canary'), 'canary')
        self.assertEqual(te.token_class('trap:decoylogin'), 'decoy_login')
        self.assertEqual(te.token_class('cf:ddos'), 'ddos')
        self.assertEqual(te.token_class('cf:ratelimit'), 'flood')
        self.assertEqual(te.token_class('cf:custom'), 'waf')
        self.assertEqual(te.token_class('fw:scan'), 'port_scan')

    def test_every_kind_the_tables_name_has_a_category_at_both_providers(self):
        for table in (te.TRAP_KINDS, te.CF_KINDS):
            for kind, cls in table.items():
                if cls is None:
                    continue
                self.assertIn(cls, te.CLASSES, kind)


class TestDecisions(unittest.TestCase):
    def test_a_honeypot_ban_is_a_decision_like_fail2bans(self):
        e = edge(src={'trap': 1}, tok={'trap': {'trap:bait': 1}}, trp=1)
        self.assertEqual(te.confirmed_by(e), 'the edge honeypot')
        ok, why = te.qualifies(e, 10)
        self.assertTrue(ok, why)
        self.assertIn('edge honeypot', why)

    def test_hits_alone_wait_for_the_count_like_any_log(self):
        e = edge(src={'trap': 4}, tok={'trap': {'trap:login': 4}})
        ok, why = te.qualifies(e, 10)
        self.assertFalse(ok)
        self.assertEqual(why, '4 of 10 attempts so far')
        self.assertTrue(te.qualifies(edge(src={'trap': 12}, tok={'trap': {'trap:login': 12}}), 10)[0])

    def test_a_trap_that_means_nothing_is_not_a_class(self):
        e = edge(src={'trap': 30}, tok={'trap': {'trap:oddclient': 30}})
        self.assertEqual(te.classes(e), {})
        self.assertEqual(te.qualifies(e, 1), (False, 'nothing recognisable in the logs'))

    def test_cloudflare_refusals_count_like_the_waf(self):
        two = edge(src={'cf': 2}, tok={'cf': {'cf:custom': 2}})
        three = edge(src={'cf': 3}, tok={'cf': {'cf:custom': 3}})
        self.assertFalse(te.qualifies(two, 10)[0])
        ok, why = te.qualifies(three, 10)
        self.assertTrue(ok)
        self.assertEqual(why, 'blocked by Cloudflare 3 times')

    def test_the_decision_survives_merge_and_slim(self):
        a = edge(src={'trap': 1}, tok={'trap': {'trap:bait': 1}}, trp=1)
        b = edge(src={'cf': 4}, tok={'cf': {'cf:custom': 4}})
        m = te.merge(a, b)
        self.assertEqual(m['trp'], 1)
        self.assertEqual(te.slim(m)['trp'], 1)
        self.assertEqual(te.merge(m, a)['trp'], 2)


class TestWords(unittest.TestCase):
    def test_a_report_from_the_honeypot_names_what_was_seen(self):
        e = edge(src={'trap': 3}, tok={'trap': {'trap:robots': 2, 'trap:bait': 1}}, trp=1)
        self.assertEqual(te.seen_by(e), 'edge honeypot')
        phrase = te.attack_phrase(e)
        self.assertIn('probing', phrase)
        self.assertIn('crawling', phrase)

    def test_the_providers_get_categories_that_exist(self):
        for toks, want_abuse, want_sniff in (
            ({'trap:robots': 1}, {19}, {15}),
            ({'trap:impostor': 1}, {19}, {15}),
            ({'trap:canary': 1}, {15, 21}, {11, 21}),
            ({'trap:decoylogin': 1}, {18, 21}, {17, 21}),
            ({'cf:ddos': 5}, {4}, {3, 21}),
        ):
            fam = 'cf' if next(iter(toks)).startswith('cf:') else 'trap'
            e = edge(src={fam: 5}, tok={fam: toks})
            self.assertEqual(set(te.categories(e, 'abuseipdb')), want_abuse, toks)
            self.assertEqual(set(te.categories(e, 'sniffcat')), want_sniff, toks)

    def test_nothing_an_attacker_typed_can_reach_the_words(self):
        """The edge normalizer is handed hostile text in every field it could
        carry; the phrase and the source words come from tables."""
        evil = '"; DROP TABLE x; <script>alert(1)</script> http://evil.example/'
        e = te.normalize_event(
            {'ip': ATTACKER, 'src': {'trap': 3, 'cf': 2}, 'trp': 1,
             'tok': {'trap': {'trap:bait': 3, evil: 5}, 'cf': {'cf:custom': 2, 'cf:' + evil: 1}},
             'cve': [evil, 'CVE-2021-44228'], 'path': evil, 'ua': evil, 'host': evil},
            now=NOW, families=te.EDGE_SOURCES)
        text = te.attack_phrase(e) + ' | ' + te.seen_by(e)
        self.assertNotIn('evil', text)
        self.assertNotIn('<', text)
        self.assertNotIn('DROP', text)
        self.assertEqual(e['cve'], ['CVE-2021-44228'])


if __name__ == '__main__':
    unittest.main()
