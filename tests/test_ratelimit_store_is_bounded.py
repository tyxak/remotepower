"""The rate-limit store cannot be grown without limit by an unauthenticated caller.

Every limiter keeps its state in one shared document, `ratelimit.json`, one key per
(scope, address) or per user name, and every limited request reads and rewrites the
whole document under a lock. Nothing ever removed an entry that had gone quiet. A
caller who varies what the key is made of (a fresh user name on each failed login,
a fresh source address from an IPv6 block) therefore added an entry per request for
ever, and each of those requests then cost more than the one before it: the login
and enrolment endpoints slowed for everybody and the disk filled.

Entries that can no longer change a decision are now dropped, a cap holds even when
every entry is recent, and a lock that is still running is never the one evicted.

Separately, the 6-digit enrolment PIN was limited per source address only, which an
IPv6 block makes meaningless; PIN attempts now also share one server-wide budget.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-rlbound-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class _Captured(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


def _fresh():
    d = tempfile.mkdtemp(prefix='rp-rlbound-')
    os.environ['RP_DATA_DIR'] = d
    for name in ('USERS_FILE', 'TOKENS_FILE', 'DEVICES_FILE', 'AUDIT_LOG_FILE', 'CONFIG_FILE',
                 'RATELIMIT_FILE', 'PINS_FILE', 'ENROLL_TOKENS_FILE'):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    api._begin_request()


class TestPrune(unittest.TestCase):
    def setUp(self):
        _fresh()

    def test_old_entries_go_and_live_ones_stay(self):
        now = int(time.time())
        rl = {}
        for i in range(api._RL_PRUNE_ABOVE + 50):
            rl[f'iprl:login:10.{i // 256}.{i % 256}.1'] = {'hits': [now - 3 * 3600]}      # long quiet
        rl['iprl:login:198.51.100.7'] = {'hits': [now - 5]}                                  # live
        rl['login:alice'] = {'failures': [], 'locked_until': now + 600, 'lockout_count': 2}  # locked
        rl['login:bob'] = {'failures': [now - 20], 'locked_until': 0}                        # counting
        rl['login:old'] = {'failures': [now - 3 * 86400], 'locked_until': 0}                 # idle for days
        api._ratelimit_prune(rl, now)
        self.assertIn('iprl:login:198.51.100.7', rl)
        self.assertIn('login:alice', rl)
        self.assertIn('login:bob', rl)
        self.assertNotIn('login:old', rl)
        self.assertEqual(len([k for k in rl if k.startswith('iprl:login:10.')]), 0)

    def test_a_small_store_is_left_alone(self):
        now = int(time.time())
        rl = {'iprl:login:203.0.113.1': {'hits': [now - 99999]}}
        api._ratelimit_prune(rl, now)
        self.assertIn('iprl:login:203.0.113.1', rl)

    def test_the_cap_holds_even_when_everything_is_recent(self):
        now = int(time.time())
        rl = {f'iprl:login:flood-{i}': {'hits': [now - (i % 60)]} for i in range(api._RL_HARD_CAP + 3000)}
        rl['login:victim'] = {'failures': [], 'locked_until': now + 7000, 'lockout_count': 5}
        api._ratelimit_prune(rl, now)
        self.assertLessEqual(len(rl), api._RL_HARD_CAP)
        self.assertIn('login:victim', rl)                     # a running lockout is never the one evicted

    def test_failed_logins_under_fresh_names_do_not_grow_the_store_for_ever(self):
        now = int(time.time())
        seed = {f'login:ghost{i}': {'failures': [now - 4 * 86400], 'locked_until': 0}
                for i in range(api._RL_PRUNE_ABOVE + 100)}
        api.save(api.RATELIMIT_FILE, seed)
        api._begin_request()
        api._record_login_failure('somebody-new')
        after = api.load(api.RATELIMIT_FILE)
        self.assertLess(len(after), api._RL_PRUNE_ABOVE)
        self.assertIn('login:somebody-new', after)

    def test_the_address_limiter_prunes_as_it_records(self):
        now = int(time.time())
        seed = {f'iprl:login:192.0.2.{i % 250}-{i}': {'hits': [now - 5 * 3600]}
                for i in range(api._RL_PRUNE_ABOVE + 100)}
        api.save(api.RATELIMIT_FILE, seed)
        api._begin_request()
        self.assertTrue(api._ip_ratelimit('login', '203.0.113.5', 20, window=60))
        after = api.load(api.RATELIMIT_FILE)
        self.assertLess(len(after), api._RL_PRUNE_ABOVE)
        self.assertIn('iprl:login:203.0.113.5', after)

    def test_limiting_still_works(self):
        for _ in range(5):
            self.assertTrue(api._ip_ratelimit('t', '203.0.113.9', 5, window=60))
        self.assertFalse(api._ip_ratelimit('t', '203.0.113.9', 5, window=60))


class TestEnrolPinBudget(unittest.TestCase):
    def setUp(self):
        _fresh()

    def _enroll(self, body, ip):
        api._begin_request()
        os.environ['REQUEST_METHOD'] = 'POST'
        os.environ['PATH_INFO'] = '/api/enroll/register'
        os.environ['REMOTE_ADDR'] = ip
        raw = json.dumps(body).encode()
        os.environ['CONTENT_LENGTH'] = str(len(raw))
        api.sys.stdin = _Stdin(raw)

        def fake(status, data=None, *a, **k):
            raise _Captured(status, data)
        orig = api.respond
        api.respond = fake
        try:
            api.handle_enroll_register()
            return None
        except _Captured as c:
            return c.status
        finally:
            api.respond = orig

    def test_guessing_from_many_addresses_hits_one_shared_budget(self):
        body = {'pin': '000000', 'hostname': 'rogue', 'name': 'rogue', 'os': 'Linux', 'version': '7.3.0'}
        statuses = [self._enroll(body, f'2001:db8::{i + 1}') for i in range(80)]
        self.assertEqual(statuses[0], 403)                       # a wrong PIN, answered as before
        self.assertIn(429, statuses)                             # and the shared budget runs out
        first_429 = statuses.index(429)
        self.assertLessEqual(first_429, 61)

    def test_an_enrolment_token_is_not_charged_to_the_pin_budget(self):
        body = {'enrollment_token': 'x' * 40, 'hostname': 'h', 'name': 'h', 'os': 'Linux', 'version': '7.3.0'}
        statuses = [self._enroll(body, f'2001:db8::{i + 1}') for i in range(80)]
        self.assertNotIn(429, statuses)                          # bulk cloud-init enrolment keeps working


if __name__ == '__main__':
    unittest.main()
