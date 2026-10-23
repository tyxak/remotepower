"""Threat Intel forgets an address nobody has seen for 90 days (v7.4.0).

The table was bounded by count only (5,000, oldest first), so a quiet install kept every address it had
ever met, and the Edge blocklist's "found by RemotePower" source (14 days by default) was the only
thing that aged anything. These tests run the real sweep: old rows go, recent rows stay, what a clear
left behind goes once its day is over, and a blocklist set to look further back than 90 days keeps what
it still wants.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v730_ipintel_clear import A1, A2, A3, A4, A5, DAY, T, _Clear, att, seen  # noqa: E402


class TestAgesOut(_Clear):
    def seed(self, **extra):
        self.put(attackers={
            A1: att(seen('d1'), last=T - 100 * DAY),                       # old
            A2: att(seen('d1'), last=T - 10 * DAY),                        # recent
            A3: {'reported': {'abuseipdb': T - 2 * DAY}},                  # a clear's leftover, day over
            A4: {'reported': {'abuseipdb': T - 600}},                      # a clear's leftover, still held
            A5: att(seen('d1'), last=T - 89 * DAY),                        # just inside
        }, **extra)

    def test_old_rows_go_and_recent_ones_stay(self):
        self.seed()
        got = self.sweep_at(T).get('attackers')
        self.assertEqual(sorted(got), sorted([A2, A4, A5]))

    def test_the_edge_list_looking_further_back_is_respected(self):
        # the setting's ceiling is 365 days: a row 100 days old is wanted by the list, so it stays
        self.seed()
        cfg = self.api.load(self.api.CONFIG_FILE) or {}
        cfg['ip_intel'] = dict(cfg.get('ip_intel') or {}, edgelist_own_days=365)
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.assertIn(A1, self.sweep_at(T).get('attackers'))

    def test_a_garbled_row_does_not_stop_the_sweep(self):
        self.put(attackers={A1: 'junk', A2: att(seen('d1'), last=T - DAY)})
        self.assertEqual(list(self.sweep_at(T).get('attackers')), [A2])


if __name__ == '__main__':
    unittest.main()
