#!/usr/bin/env python3
"""7.4.0: the log sensor keeps an address that scans slowly.

A plain web address is sent once it has THREAT_MIN_HITS (3) hostile requests in a pass. An address that
sends one request a minute never gets there inside a pass, and each pass started from nothing, so it was
dropped every time and never reported. What a pass saw of an address under the minimum is carried to the
next pass now, added to its count, and cleared once the address is sent or has gone quiet for the
lookback.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_v720_threat_sensor_agent import NOW, load_agent  # noqa: E402

SLOW = '45.155.205.9'
OTHER = '185.220.101.7'


def one_pass(agent, carry, now, hits=((SLOW, 1),)):
    agg = agent._TsAgg(now)
    agg.carry = carry
    for ip, n in hits:
        for _ in range(n):
            agg.hit('web', '/var/log/nginx/access.log', ip, now, ['req:probe'], 1)
    events, dropped = agg.events()
    return {e['ip']: e for e in events}, agg.carry_out, dropped


class TestSlowScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent('agent_slow_scanner')

    def test_one_request_a_pass_is_sent_on_the_third(self):
        carry = {}
        for i in range(2):
            sent, carry, _ = one_pass(self.agent, carry, NOW + 60 * i)
            self.assertEqual(sent, {}, 'pass %d is still under the minimum' % (i + 1))
            self.assertEqual(carry[SLOW]['src'], {'web': i + 1})
        sent, carry, _ = one_pass(self.agent, carry, NOW + 120)
        self.assertEqual(sent[SLOW]['src'], {'web': 3})
        self.assertEqual(sent[SLOW]['tok']['web'], {'req:probe': 3})
        self.assertNotIn(SLOW, carry, 'what was sent is not counted a second time')

    def test_an_address_that_goes_quiet_is_forgotten(self):
        _, carry, _ = one_pass(self.agent, {}, NOW)
        later = NOW + self.agent.THREAT_LOOKBACK_S + 10
        sent, carry, _ = one_pass(self.agent, carry, later, hits=((OTHER, 1),))
        self.assertNotIn(SLOW, carry)
        self.assertIn(OTHER, carry)

    def test_the_carry_is_bounded(self):
        a = self.agent
        hits = [('45.%d.%d.9' % (i // 250 + 1, i % 250 + 1), 1) for i in range(a.THREAT_CARRY_MAX + 300)]
        _, carry, _ = one_pass(a, {}, NOW, hits=hits)
        self.assertEqual(len(carry), a.THREAT_CARRY_MAX)

    def test_a_damaged_carry_is_ignored(self):
        sent, carry, _ = one_pass(self.agent, {SLOW: 'junk', OTHER: {'last': 'x', 'src': None}}, NOW)
        self.assertEqual(sent, {})
        self.assertEqual(carry[SLOW]['src'], {'web': 1})

    def test_the_carry_travels_in_the_sensor_state(self):
        src = (Path(__file__).resolve().parent.parent / 'client' / 'remotepower-agent.py').read_text()
        self.assertIn("agg.carry = state.get('carry')", src)
        self.assertIn("'carry': agg.carry_out", src)


if __name__ == '__main__':
    unittest.main()
