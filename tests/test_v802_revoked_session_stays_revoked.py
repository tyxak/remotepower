#!/usr/bin/env python3
"""A revoked session stays revoked: the session store is never saved from a snapshot.

`verify_token` (the check every authenticated request makes) read the whole session store and, when it stamped `last_seen` (once a minute for each session),
expired a session or evicted one, saved THAT snapshot back with no lock held across the read and the write. Every other writer of the store (sign-in, sign-out, the
revocation of a user's sessions, the sign-out of the other sessions that a password change does) takes `_LockedUpdate(TOKENS_FILE)`. A revocation that landed between
the snapshot and the save was overwritten with the snapshot: the revoked session, an administrator's if that is what was stolen, was valid again with no log line, and a
session a sign-in had created in the same window was gone. Measured with real threaded requests and no hook in the product (600 sessions, 60 revocations): 54 of 60 came
back on JSON, 31 on SQLite. `cleanup_tokens` (every sign-in) and the step-up check had the same shape.

Here the window is held open at the exact point the old code was exposed: one request is paused right after it has read the session store, outside any lock, while the
revocation goes through the real route; then the request is let go.

* a stamp, an expiry and an eviction change the one session they are about, under the store's lock, and what was revoked in the meantime stays revoked;
* a session that is gone when the stamp is written is refused;
* a sign-in's cleanup of expired sessions neither puts back a revoked one nor drops a new one;
* the step-up stamp cannot bring back a session that ended while the password was checked;
* the positive controls: the stamp is written when nothing intervenes, an expired session is removed, and the sessions next to it are untouched.
"""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-revoked-'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stores_support as S  # noqa: E402

setUpModule, tearDownModule = S.set_up_module, S.tear_down_module
api = S.api

VICTIM_PW = 'Vict1m-Passw0rd!x'
BYSTANDER_PW = 'Byst4nder-Passw0rd!x'


class PausedAfterRead:
    """Pauses the request of one thread right after `caller` read the session store (outside any lock), until `go()`.

    `caller` is the name of the function that makes the read: the pause must sit at the read the stamp or the removal is decided on, not at an earlier one."""

    def __init__(self, caller):
        self.caller, self.ident = caller, None
        self.paused, self.release, self.armed, self._real = threading.Event(), threading.Event(), True, None

    def __enter__(self):
        self._real = api.load
        me = self

        def load(path, *a, **k):
            out = me._real(path, *a, **k)
            if me.armed and threading.get_ident() == me.ident and Path(str(path)).name == 'tokens.json' and sys._getframe(1).f_code.co_name == me.caller:
                me.armed = False
                me.paused.set()
                me.release.wait(30)
            return out

        api.load = load
        return self

    def __exit__(self, *exc):
        api.load = self._real
        self.release.set()
        return False

    def go(self):
        self.release.set()


class _Sessions(S.Case):
    def setUp(self):
        super().setUp()
        self.add_user('victim', 'viewer', VICTIM_PW)
        self.add_user('bystander', 'viewer', BYSTANDER_PW)
        self.victim = self.sign_in('victim', VICTIM_PW)
        self.stolen = self.sign_in('victim', VICTIM_PW)          # a second session of the same account, the one an attacker holds
        self.bystander = self.sign_in('bystander', BYSTANDER_PW)
        self.age_sessions()

    def age_sessions(self, **who):
        """Every session of the victim and the bystander was last seen five minutes ago, so the next request of each stamps `last_seen`."""
        with api._LockedUpdate(api.TOKENS_FILE) as toks:
            for e in toks.values():
                if isinstance(e, dict) and e.get('user') in ('victim', 'bystander'):
                    e['last_seen'] = int(time.time()) - 300
        api._LOAD_CACHE.clear()

    def me(self, token):
        return S.call('GET', '/api/me', token=token)[0]

    def request_in_thread(self, pause, token):
        out = {}

        def run():
            pause.ident = threading.get_ident()
            out['status'] = self.me(token)

        t = threading.Thread(target=run)
        t.start()
        self.assertTrue(pause.paused.wait(30), 'the request never read the session store through %s' % pause.caller)
        return t, out

    def store(self):
        api._LOAD_CACHE.clear()
        return api.load(api.TOKENS_FILE)

    def alive(self, token):
        return api._token_hash(token) in self.store()


class TestAStampKeepsARevocation(_Sessions):
    def test_the_stamp_is_written_when_nothing_intervenes(self):
        """Positive control: the activity stamp still happens, with the address and the browser of the request."""
        before = self.store()[api._token_hash(self.bystander)]['last_seen']
        self.assertEqual(self.me(self.bystander), 200)
        after = self.store()[api._token_hash(self.bystander)]
        self.assertGreater(after['last_seen'], before)
        self.assertIn('ip', after)

    def test_an_administrators_revocation_between_the_read_and_the_stamp_stays(self):
        with PausedAfterRead('verify_token') as pause:
            t, out = self.request_in_thread(pause, self.bystander)
            st, d = S.call('POST', '/api/sessions/revoke', {'username': 'victim'}, token=self.admin)
            self.assertEqual(st, 200, d)
            self.assertEqual(self.me(self.victim), 401, 'control: right after the revocation the token is refused')
            pause.go()
            t.join(30)
        self.assertEqual(out.get('status'), 200, 'the bystander is not affected by the other account being revoked')
        self.assertEqual(self.me(self.victim), 401, 'the revoked session came back when the stamp of another session was written')
        self.assertEqual(self.me(self.stolen), 401)
        self.assertFalse(self.alive(self.victim))
        self.assertTrue(self.alive(self.bystander), 'the session next to it is untouched')

    def test_the_sign_out_of_other_sessions_that_a_password_change_does_stays(self):
        """The owner changes their password to evict a stolen session: the stolen one must not come back."""
        with PausedAfterRead('verify_token') as pause:
            t, out = self.request_in_thread(pause, self.bystander)
            st, d = S.call('POST', '/api/users/passwd', {'username': 'victim', 'old_password': VICTIM_PW, 'new_password': 'N3w-Passw0rd!x9'},
                           token=self.victim)
            self.assertEqual(st, 200, d)
            pause.go()
            t.join(30)
        self.assertEqual(self.me(self.stolen), 401, 'the stolen session was valid again after the stamp of another session')
        self.assertEqual(self.me(self.victim), 200, 'the session that changed the password is kept')

    def test_a_session_created_by_a_sign_in_in_the_window_is_kept(self):
        with PausedAfterRead('verify_token') as pause:
            t, out = self.request_in_thread(pause, self.bystander)
            newer = self.sign_in('victim', VICTIM_PW)
            pause.go()
            t.join(30)
        self.assertTrue(self.alive(newer), 'a session created while a stamp was being made was lost')

    def test_a_session_that_is_gone_when_the_stamp_is_written_is_refused(self):
        with PausedAfterRead('verify_token') as pause:
            t, out = self.request_in_thread(pause, self.victim)
            st, d = S.call('POST', '/api/sessions/revoke', {'username': 'victim'}, token=self.admin)
            self.assertEqual(st, 200, d)
            pause.go()
            t.join(30)
        self.assertEqual(out.get('status'), 401, 'a request whose session was revoked while it was being checked is answered as the next one is')
        self.assertFalse(self.alive(self.victim), 'and the stamp did not write the session back')


class TestAnExpiryKeepsARevocation(_Sessions):
    def test_an_expired_session_is_removed_and_the_sessions_next_to_it_are_untouched(self):
        with api._LockedUpdate(api.TOKENS_FILE) as toks:
            toks[api._token_hash(self.bystander)]['created'] = int(time.time()) - 10 * 86400
            toks[api._token_hash(self.bystander)]['ttl'] = 60
        api._LOAD_CACHE.clear()
        self.assertEqual(self.me(self.bystander), 401)
        self.assertFalse(self.alive(self.bystander), 'the expired session is removed')
        self.assertTrue(self.alive(self.victim))
        self.assertTrue(self.alive(self.stolen))

    def test_the_removal_of_an_expired_session_does_not_bring_back_a_revoked_one(self):
        with api._LockedUpdate(api.TOKENS_FILE) as toks:
            toks[api._token_hash(self.bystander)]['created'] = int(time.time()) - 10 * 86400
            toks[api._token_hash(self.bystander)]['ttl'] = 60
        api._LOAD_CACHE.clear()
        with PausedAfterRead('verify_token') as pause:
            t, out = self.request_in_thread(pause, self.bystander)
            st, d = S.call('POST', '/api/sessions/revoke', {'username': 'victim'}, token=self.admin)
            self.assertEqual(st, 200, d)
            pause.go()
            t.join(30)
        self.assertEqual(out.get('status'), 401)
        self.assertFalse(self.alive(self.bystander))
        self.assertEqual(self.me(self.victim), 401, 'the revoked session came back when an expired one was removed')

    def test_an_idle_session_is_removed_without_bringing_back_a_revoked_one(self):
        self.set_cfg(idle_timeout_minutes=5)
        with api._LockedUpdate(api.TOKENS_FILE) as toks:
            toks[api._token_hash(self.bystander)]['last_seen'] = int(time.time()) - 3600
        api._LOAD_CACHE.clear()
        with PausedAfterRead('verify_token') as pause:
            t, out = self.request_in_thread(pause, self.bystander)
            st, d = S.call('POST', '/api/sessions/revoke', {'username': 'victim'}, token=self.admin)
            self.assertEqual(st, 200, d)
            pause.go()
            t.join(30)
        self.assertEqual(out.get('status'), 401)
        self.assertFalse(self.alive(self.victim), 'the revoked session came back when an idle one was removed')


class TestSignInCleanupKeepsARevocation(_Sessions):
    def _expire_one(self):
        with api._LockedUpdate(api.TOKENS_FILE) as toks:
            toks['expired-one'] = {'user': 'bystander', 'created': int(time.time()) - 10 * 86400, 'ttl': 60, 'last_seen': 0}
        api._LOAD_CACHE.clear()

    def _cleanup_in_thread(self, pause):
        def run():
            pause.ident = threading.get_ident()
            api.cleanup_tokens()

        t = threading.Thread(target=run)
        t.start()
        self.assertTrue(pause.paused.wait(30), 'cleanup_tokens never read the session store')
        return t

    def test_cleanup_removes_an_expired_session_and_only_that(self):
        """Positive control."""
        self._expire_one()
        api.cleanup_tokens()
        store = self.store()
        self.assertNotIn('expired-one', store)
        self.assertTrue(self.alive(self.victim) and self.alive(self.stolen) and self.alive(self.bystander))

    def test_cleanup_does_not_bring_back_a_revoked_session(self):
        self._expire_one()
        with PausedAfterRead('cleanup_tokens') as pause:
            t = self._cleanup_in_thread(pause)
            st, d = S.call('POST', '/api/sessions/revoke', {'username': 'victim'}, token=self.admin)
            self.assertEqual(st, 200, d)
            pause.go()
            t.join(30)
        self.assertNotIn('expired-one', self.store())
        self.assertFalse(self.alive(self.victim), 'the sign-in cleanup saved a snapshot that held the revoked session')
        self.assertFalse(self.alive(self.stolen))

    def test_cleanup_does_not_drop_a_session_created_meanwhile(self):
        self._expire_one()
        with PausedAfterRead('cleanup_tokens') as pause:
            t = self._cleanup_in_thread(pause)
            newer = self.sign_in('bystander', BYSTANDER_PW)
            pause.go()
            t.join(30)
        self.assertTrue(self.alive(newer), 'the sign-in cleanup saved a snapshot that did not hold the session created meanwhile')


class TestStepUpKeepsARevocation(_Sessions):
    def test_the_stamp_is_written_for_the_session_that_verified(self):
        """Positive control."""
        st, d = S.call('POST', '/api/auth/step-up', {'password': VICTIM_PW}, token=self.victim)
        self.assertEqual(st, 200, d)
        self.assertTrue(self.store()[api._token_hash(self.victim)].get('step_up_at'))
        self.assertFalse(self.store()[api._token_hash(self.stolen)].get('step_up_at'), 'the other session of the account is not stamped')

    def test_the_stamp_cannot_bring_back_a_session_that_ended_meanwhile(self):
        with PausedAfterRead('_step_up_token_entry') as pause:
            out = {}

            def run():
                pause.ident = threading.get_ident()
                out['r'] = S.call('POST', '/api/auth/step-up', {'password': VICTIM_PW}, token=self.stolen)

            t = threading.Thread(target=run)
            t.start()
            self.assertTrue(pause.paused.wait(30), 'the step-up never read the session store')
            st, d = S.call('POST', '/api/sessions/revoke', {'username': 'victim'}, token=self.admin)
            self.assertEqual(st, 200, d)
            pause.go()
            t.join(30)
        self.assertNotEqual(out['r'][0], 200, 'a session that ended was stamped as freshly verified')
        self.assertFalse(self.alive(self.stolen), 'the step-up saved a snapshot that held the session the administrator revoked')
        self.assertFalse(self.alive(self.victim))


if __name__ == '__main__':
    unittest.main()
