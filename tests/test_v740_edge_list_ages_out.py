"""The Cloudflare list does not pile up (v7.4.0).

An address leaves the list at the next sync when nothing asks for it any more: its blacklist dropped it,
the 14 days a found address may be idle ran out, or a ban made by hand expired. Driven for real over
three weeks against the small Cloudflare of the sync tests, so a change that stopped removing, or kept
last month's copy of a source, fails here instead of showing as a list that is always full.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ipintel_store  # noqa: E402
from test_v730_edge_blocklist_sync import T, _Lists  # noqa: E402

DAY = 86400
A, B, C, D = '185.220.101.1', '185.220.101.2', '185.220.101.3', '45.155.205.1'
X, Y, Z = '203.0.115.10', '203.0.115.20', '203.0.115.30'


class TestNothingStaysForever(_Lists):
    def setUp(self):
        super().setUp()
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'], cfg['sniffcat_api_key'] = 'a' * 80, 's' * 40
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=True, edgelist_own=True, edgelist_own_score=75,
                    edgelist_own_days=14, edgelist_always=[Z], edgelist_hours=6)
        self.abuse, self.sniff = [A, B, C], [D]
        ipintel_store.update(self.api, attackers={X: {'first_seen': T - 60, 'last_seen': T - 60,
                                                      'devices': {'d1': {'count': 30, 'at': T - 60}},
                                                      'verdict': {'score': 90}}},
                             edgeban={Y: {'at': T, 'until': T + DAY, 'by': 'alice'}})
        self.api._LOAD_CACHE.clear()

    def items(self):
        return sorted(self.only_list()['items'])

    def test_each_reason_to_leave_is_acted_on(self):
        self.tick(at=T)
        self.assertEqual(self.items(), sorted([A, B, C, D, X, Y, Z]))

        # a week on: a blacklist dropped two addresses, the ban ran out, the found address is still fresh
        self.abuse, self.sniff = [B, C], []
        el = self.tick(at=T + 7 * DAY)
        self.assertEqual(self.items(), sorted([B, C, X, Z]))
        self.assertEqual(el['last']['removed'], 3)

        # three weeks on: nothing saw the found address for 21 days, so it goes as well
        el = self.tick(at=T + 21 * DAY)
        self.assertEqual(self.items(), sorted([B, C, Z]))
        self.assertEqual(el['last']['removed'], 1)

        # what the operator typed stays, and a quiet sync changes nothing
        el = self.tick(at=T + 22 * DAY)
        self.assertEqual((self.items(), el['last']['removed'], el['last']['added']), (sorted([B, C, Z]), 0, 0))

    def test_a_found_address_that_is_seen_again_stays(self):
        self.tick(at=T)
        ipintel_store.update(self.api, attackers={X: {'first_seen': T - 60, 'last_seen': T + 20 * DAY,
                                                      'devices': {'d1': {'count': 30, 'at': T + 20 * DAY}},
                                                      'verdict': {'score': 90}}})
        self.api._LOAD_CACHE.clear()
        self.tick(at=T + 21 * DAY)
        self.assertIn(X, self.items())


if __name__ == '__main__':
    unittest.main()
