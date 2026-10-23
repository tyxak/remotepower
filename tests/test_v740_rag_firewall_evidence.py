#!/usr/bin/env python3
"""7.4.0: the AI corpus says what a firewall's attackers did, not only how often.

A firewall's sensor reports port scans, IDS alerts and decoy-port hits. The
per-host attacker document used to print every count as "failed logins", so
"who scanned the firewall" had no answer. It now names the dominant classes
and the CVE ids a signature carried, as the edge-source document already did.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v740rag-'))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import rag_index  # noqa: E402

NOW = 1_800_000_000
SCANNER = '192.0.2.40'
RCE = '192.0.2.42'
SSH = '198.51.100.110'


def _intel():
    return {'attackers': {
        SCANNER: {'verdict': {'score': 78}, 'last_seen': NOW,
                  'devices': {'fw': {'count': 38, 'unit': 'threat-sensor', 'at': NOW}},
                  'ev_reported': {'at': NOW, 'ev': {
                      'ip': SCANNER, 'src': {'fw': 38}, 'tok': {'fw': {'fw:scan': 38}}}}},
        RCE: {'verdict': {'score': 84}, 'last_seen': NOW,
              'devices': {'fw': {'count': 14, 'unit': 'threat-sensor', 'at': NOW}},
              'ev_reported': {'at': NOW, 'ev': {
                  'ip': RCE, 'cve': ['CVE-2021-44228'], 'src': {'ids': 14},
                  'tok': {'ids': {'ids:rce': 14}}}}},
        SSH: {'verdict': {'score': 97}, 'last_seen': NOW,
              'devices': {'fw': {'count': 162, 'unit': 'sshd.service', 'at': NOW}}},
    }, 'blocks': {}}


class FirewallAttackerDoc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        docs = rag_index.build_threats_corpus({'fw': {'name': 'opnsense.lab'}}, _intel(), [], now=NOW)
        cls.text = next(d['text'] for d in docs if d['title'].startswith('opnsense.lab'))
        cls.rows = {l.split(':')[0]: l for l in cls.text.splitlines() if ':' in l}

    def test_sensor_counts_are_events_not_logins(self):
        self.assertIn('38 events seen by the firewall sensor', self.rows[SCANNER])
        self.assertNotIn('failed logins', self.rows[SCANNER])

    def test_login_failures_keep_their_wording(self):
        self.assertIn('162 failed logins (sshd.service)', self.rows[SSH])

    def test_what_the_address_did_is_named(self):
        self.assertIn('port scanning', self.rows[SCANNER])
        self.assertIn('CVE-2021-44228', self.rows[RCE])

    def test_no_evidence_adds_no_dangling_text(self):
        self.assertNotIn(', ,', self.rows[SSH])
        self.assertEqual(rag_index._attacker_did({}), '')
        self.assertEqual(rag_index._attacker_did({'ev': {'ip': 'x'}}), '')

    def test_header_does_not_call_every_source_brute_force(self):
        self.assertIn('attacking sources', self.text.splitlines()[0])


if __name__ == '__main__':
    unittest.main()
