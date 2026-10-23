"""Reputation-list hits are shown beside an address and nothing else (v7.4.0).

A firewall's intrusion detection matches traffic against lists (Spamhaus DROP, Dshield, CINS, compromised
hosts, Tor). A hit says the address is on somebody's list, not what it did to you, so it is never evidence:
no report, no lookup, no block, no row of its own. It is kept for 30 days in the scan document and shown
on the Threat Intel page when the address is there for another reason. The lines are the ones a real
OPNsense 26 / Suricata 8 sent on 2026-10-23.
"""
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import appliance_evidence as ae  # noqa: E402
import srcpin  # noqa: E402
import appliance_sensor_handlers as ash  # noqa: E402
from test_ip_intel import ATTACKER  # noqa: E402
from test_v740_appliance_evidence import suricata_fast  # noqa: E402
from test_v740_appliance_sensor import _Fw, wire  # noqa: E402

OTHER = '91.240.118.9'
SPAM = 'ET DROP Spamhaus DROP Listed Traffic Inbound group 17'
DSH = 'ET DROP Dshield Block Listed Source group 1'
CINS = 'ET CINS Active Threat Intelligence Poor Reputation IP group 39'


def hit(sig, ip=ATTACKER, n=1):
    return wire('[Drop] ' + suricata_fast(sig, '(null)', src=ip, dst='10.0.0.2:7777'), app='suricata', n=n)


class TestNamesTheList(unittest.TestCase):
    def test_the_lists_a_rule_set_carries(self):
        for sig, name in ((SPAM, 'Spamhaus'), (DSH, 'Dshield'), (CINS, 'CINS'),
                          ('ET COMPROMISED Known Compromised or Hostile Host Traffic', 'Compromised hosts'),
                          ('ET TOR Known Tor Exit Node Traffic group 1', 'Tor'),
                          ('ET DROP Something Else', 'Other block lists')):
            self.assertEqual(ae.reputation_of(sig), name, sig)

    def test_an_attack_signature_is_not_a_list(self):
        for sig in ('ET SCAN Potential SSH Scan', 'ET EXPLOIT Possible Vacron NVR Remote Command Execution', ''):
            self.assertIsNone(ae.reputation_of(sig), sig)

    def test_scan_collects_them_and_makes_no_event(self):
        listed = {}
        hits, events, stats = ae.scan([hit(SPAM), hit(SPAM, n=2), hit(DSH, ip=OTHER, n=3)], listed)
        self.assertEqual(listed, {ATTACKER: {'Spamhaus': 2}, OTHER: {'Dshield': 1}})
        self.assertEqual((hits, events), ([], []))
        self.assertEqual(stats['ids']['parsed'], 3)

    def test_without_the_argument_nothing_changes(self):
        self.assertEqual(ae.scan([hit(SPAM)])[1], [])


class TestKeptAndExpired(unittest.TestCase):
    def test_merge_adds_counts_and_drops_the_old(self):
        now = 10_000_000
        old = {'1.2.3.4': {'at': now - 31 * 86400, 'l': {'CINS': 5}},
               ATTACKER: {'at': now - 100, 'l': {'Spamhaus': 1}}}
        got = ash.merge_listed(old, {ATTACKER: {'Spamhaus': 2, 'Dshield': 1}, OTHER: {'Tor': 1}}, now)
        self.assertNotIn('1.2.3.4', got)
        self.assertEqual(got[ATTACKER], {'at': now, 'l': {'Spamhaus': 3, 'Dshield': 1}})
        self.assertEqual(got[OTHER]['l'], {'Tor': 1})

    def test_a_flood_cannot_grow_the_document(self):
        now = 10_000_000
        old = {f'10.9.{i // 250}.{i % 250}': {'at': now - 5000 + i, 'l': {'CINS': 1}} for i in range(ash.LISTED_MAX)}
        got = ash.merge_listed(old, {OTHER: {'CINS': 1}}, now)
        self.assertEqual(len(got), ash.LISTED_MAX)
        self.assertIn(OTHER, got)
        self.assertNotIn('10.9.0.0', got)          # the oldest went

    def test_a_garbled_document_is_ignored(self):
        self.assertEqual(ash.merge_listed('junk', {OTHER: {'Tor': 1}}, 5), {OTHER: {'at': 5, 'l': {'Tor': 1}}})
        self.assertEqual(ash.merge_listed({'x': 'y', 'z': {'l': 3}}, {}, 5), {})

    def test_listed_for_reads_only_the_hosts_given(self):
        doc = {'fw1': {'listed': {ATTACKER: {'at': 100, 'l': {'CINS': 2}}}},
               'fw2': {'listed': {ATTACKER: {'at': 200, 'l': {'CINS': 1, 'Tor': 1}}}}}
        self.assertEqual(ash.listed_for(doc, {'fw1'}, 300)[ATTACKER], {'at': 100, 'l': {'CINS': 2}, 'on': ['fw1']})
        both = ash.listed_for(doc, {'fw1', 'fw2'}, 300)[ATTACKER]
        self.assertEqual((both['at'], both['l']), (200, {'CINS': 3, 'Tor': 1}))
        self.assertEqual(ash.listed_for(doc, set(), 300), {})


class TestEndToEnd(_Fw):
    def listed(self):
        return (self.scan_doc().get('fw1') or {}).get('listed') or {}

    def test_a_hit_is_kept_and_nothing_is_made_of_it(self):
        self.post([hit(SPAM, n=i) for i in range(30)])
        self.assertEqual(self.listed()[ATTACKER]['l'], {'Spamhaus': 30})
        self.assertEqual(self.queue(), [])                       # no lookup, no report waiting
        self.assertEqual(self.store().get('attackers') or {}, {})  # no row of its own
        self.sweep()
        self.assertEqual((self.abuse_posts(), self.sniff_posts()), ([], []))

    def test_the_page_shows_it_beside_an_address_that_is_there_for_another_reason(self):
        self.post(self.scan(ports=12))
        self.sweep()
        self.post([hit(SPAM), hit(DSH, n=2), hit(SPAM, n=3)])
        att = [a for a in self.view()['attackers'] if a['ip'] == ATTACKER][0]
        self.assertEqual(att['listed']['lists'], {'Spamhaus': 2, 'Dshield': 1})
        self.assertEqual(att['listed']['hosts'], ['opnsense01'])
        # and it did not turn into evidence: the class is still the scan
        self.assertEqual([c['id'] for c in att['evidence']['classes']], ['port_scan'])

    def test_an_address_without_a_hit_has_none(self):
        self.post(self.scan(ports=12))
        self.sweep()
        att = [a for a in self.view()['attackers'] if a['ip'] == ATTACKER][0]
        self.assertIsNone(att['listed'])

    def test_off_keeps_nothing(self):
        self.policy(appliance_enabled=False)
        self.post([hit(SPAM)])
        self.assertEqual(self.listed(), {})

    def test_an_attack_alert_still_settles_as_before(self):
        self.post([wire('[Drop] ' + suricata_fast('ET SCAN Potential SSH Scan', 'Attempted Information Leak'),
                        app='suricata')])
        self.assertTrue(self.queue())
        self.assertEqual(self.listed(), {})


_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()


@unittest.skipUnless(shutil.which('node'), 'needs node')
class TestThePage(unittest.TestCase):
    def render(self, att):
        script = '\n'.join([
            re.search(r'^function escHtml\(.*$', _APP, re.M).group(0),
            re.search(r'^function escAttr\(.*$', _APP, re.M).group(0),
            'const _ipiOpen = new Set(["1.2.3.4"]); const _IPI_SOURCE = {}; const _ipiClassName = x => x;'
            ' const _ipiReason = x => x; const timeAgo = t => "5 min ago";',
            srcpin.js_function(_JS, '_ipiPhrase'),
            re.search(r'^const _IPI_LIST_WORDS = .*$', _JS, re.M).group(0),
            srcpin.js_function(_JS, '_ipiListedText'),
            srcpin.js_function(_JS, '_ipiEvidenceHtml'),
            srcpin.js_function(_JS, '_ipiDetailHtml'),
            srcpin.js_function(_JS, '_ipiEvidenceText'),
            'const a = %s;' % json.dumps(att),
            'console.log(JSON.stringify({cell: _ipiEvidenceHtml(a), detail: _ipiDetailHtml(a), text: _ipiEvidenceText(a)}));',
        ])
        out = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_it_shows_in_the_cell_and_the_detail_and_the_filter(self):
        r = self.render({'ip': '1.2.3.4', 'evidence': None, 'report_log': [],
                         'listed': {'lists': {'Spamhaus': 3, 'Compromised hosts': 1}, 'at': 5,
                                    'hosts': ['opnsense01']}})
        self.assertIn('Spamhaus', r['cell'])
        self.assertIn('<span>Compromised hosts</span> ×1', r['cell'])      # a phrase, so it is translated
        self.assertIn('data-ipi-toggle', r['cell'])                              # an address with only this can still open
        self.assertIn('opnsense01', r['detail'])
        self.assertIn('context only, not reported', r['detail'])
        self.assertIn('Spamhaus', r['text'])

    def test_a_hostile_host_name_is_escaped(self):
        r = self.render({'ip': '1.2.3.4', 'evidence': None, 'report_log': [],
                         'listed': {'lists': {'<img src=x>': 1}, 'at': 5, 'hosts': ['<b>x</b>']}})
        self.assertNotIn('<img', r['cell'] + r['detail'])
        self.assertNotIn('<b>x', r['detail'])

    def test_nothing_listed_and_no_evidence_is_a_dash(self):
        r = self.render({'ip': '1.2.3.4', 'evidence': None, 'report_log': [], 'listed': None})
        self.assertIn('—', r['cell'])


if __name__ == '__main__':
    unittest.main()
