#!/usr/bin/env python3
"""One enrolment token for many hosts: `max_uses` on POST /api/enrollment-tokens.

A token used to enrol exactly one host, which does not fit group policy, Intune, a golden image or an autoscaling group, where one
install command runs on many hosts. The create call takes `max_uses`, a whole number from 1 to 1000. The default is 1, and a token
made without it is stored and behaves as it always did.

What these tests hold, all through the real create, list, revoke and register handlers (and the real routes for the last class):

* the default is unchanged: one host, the stored row has no new field, a second use is refused;
* a token with uses left enrols that many hosts and then refuses; the list says how many have been used and never shows the token;
* a revoked token and an expired one are refused although they have uses left; a host that enrols again counts as a use;
* every use is on the audit trail with the host it made, and the token itself is on none of it;
* a number that is not a whole number from 1 to 1000 is refused with a 400 and makes no token; nothing raises a cap afterwards;
* the host a use makes carries what the token carries (tenant, group, tags), for the last use as for the first;
* N requests racing for the last uses of a token enrol exactly that many hosts, with threads;
* a use that ends without a host (the fleet is at its host limit, a known host sent the wrong host token) is given back, and a
  revoked token is never brought back by that.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-enrol-many-'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_v749_enroll_source import _Enrol, api  # noqa: E402


def setUpModule():
    __import__("sys").path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
    import api_guard
    api_guard.save(__name__)


def _new_hosts(before_ids):
    api._LOAD_CACHE.clear()
    devs = api.load(api.DEVICES_FILE) or {}
    return {k: v for k, v in devs.items() if k not in before_ids}


class _Many(_Enrol):
    """`_Enrol` (test_v749_enroll_source) mints and registers through the real handlers; this adds the reads these tests keep making."""

    def setUp(self):
        super().setUp()
        self.base_ids = set((api.load(api.DEVICES_FILE) or {}).keys())

    def hosts(self):
        return _new_hosts(self.base_ids)

    def row(self):
        rows = self.stored()
        self.assertEqual(len(rows), 1, rows)
        return rows[0]

    def listing(self, who='platform'):
        st, rows = self.call(api.handle_enroll_token_list, m='GET', who=who)
        self.assertEqual(st, 200, rows)
        return rows

    def enrol_ok(self, token, name):
        st, r = self.register(token, '203.0.113.5', name=name)
        self.assertIn(st, (200, 201), r)
        return r

    def enrol_refused(self, token, name='late'):
        st, r = self.register(token, '203.0.113.5', name=name)
        self.assertEqual(st, 403, r)
        return r


class TestTheDefaultIsUnchanged(_Many):

    def test_a_token_made_without_max_uses_enrols_one_host(self):
        st, d = self.mint()
        self.assertEqual((st, d['max_uses']), (201, 1))
        self.enrol_ok(d['token'], 'only')
        self.assertEqual(len(self.hosts()), 1)
        self.assertEqual(self.stored(), [], 'a used single-use token is gone, as it always was')
        self.assertEqual(self.enrol_refused(d['token'])['error'], 'Invalid or expired enrollment token')
        self.assertEqual(len(self.hosts()), 1)

    def test_the_stored_row_of_a_default_token_has_no_new_field(self):
        self.mint()
        row = self.row()
        self.assertNotIn('max_uses', row)
        self.assertNotIn('uses', row)

    def test_max_uses_1_is_the_default_spelled_out(self):
        st, d = self.mint(max_uses=1)
        self.assertEqual((st, d['max_uses']), (201, 1))
        self.assertNotIn('max_uses', self.row())

    def test_null_is_not_given(self):
        st, d = self.mint(max_uses=None)
        self.assertEqual((st, d['max_uses']), (201, 1))

    def test_a_row_from_before_the_field_existed_is_a_single_use_token(self):
        st, d = self.mint()
        toks = api.load(api.ENROLL_TOKENS_FILE)
        for meta in toks.values():
            meta.pop('max_uses', None)
            meta.pop('uses', None)
        api.save(api.ENROLL_TOKENS_FILE, toks)
        self.enrol_ok(d['token'], 'old')
        self.enrol_refused(d['token'])


class TestAFewHosts(_Many):

    def test_it_enrols_that_many_hosts_and_then_refuses(self):
        _, d = self.mint(max_uses=3)
        self.assertEqual(d['max_uses'], 3)
        for i in range(3):
            self.enrol_ok(d['token'], f'h{i}')
        self.assertEqual(len(self.hosts()), 3)
        self.enrol_refused(d['token'])
        self.assertEqual(len(self.hosts()), 3, 'the fourth must not have enrolled')
        self.assertEqual(self.stored(), [], 'the token goes with its last use')

    def test_the_row_keeps_counting_while_uses_are_left(self):
        _, d = self.mint(max_uses=3)
        self.enrol_ok(d['token'], 'h0')
        row = self.row()
        self.assertEqual((row['max_uses'], row['uses']), (3, 1))
        self.enrol_ok(d['token'], 'h1')
        self.assertEqual(self.row()['uses'], 2)

    def test_the_list_says_used_2_of_10_and_never_shows_the_token(self):
        _, d = self.mint(max_uses=10, label='gpo rollout')
        self.mint(label='single')
        for i in range(2):
            self.enrol_ok(d['token'], f'g{i}')
        rows = {r['label']: r for r in self.listing()}
        self.assertEqual((rows['gpo rollout']['uses'], rows['gpo rollout']['max_uses'], rows['gpo rollout']['uses_left']), (2, 10, 8))
        self.assertEqual((rows['single']['uses'], rows['single']['max_uses'], rows['single']['uses_left']), (0, 1, 1))
        blob = json.dumps(rows)
        self.assertNotIn(d['token'], blob)
        self.assertNotIn(api._hash_device_token(d['token']), blob)
        self.assertTrue(all(r['prefix'].endswith('…') and len(r['prefix']) == 9 for r in rows.values()))

    def test_a_spent_row_is_not_listed(self):
        """A row can outlive its last use for a moment (the host step is still running) or until it expires (that step failed)."""
        _, d = self.mint(max_uses=2)
        toks = api.load(api.ENROLL_TOKENS_FILE)
        for meta in toks.values():
            meta['uses'] = 2
        api.save(api.ENROLL_TOKENS_FILE, toks)
        self.assertEqual(self.listing(), [])
        self.enrol_refused(d['token'])

    def test_the_host_a_use_makes_carries_what_the_token_carries_for_every_use(self):
        _, one = self.mint(default_group='web', default_tags=['prod', 'linux'])
        _, many = self.mint(default_group='web', default_tags=['prod', 'linux'], max_uses=3)
        self.enrol_ok(one['token'], 'single-0')
        for i in range(3):
            self.enrol_ok(many['token'], f'many-{i}')
        hosts = self.hosts()
        by_name = {v['name']: v for v in hosts.values()}
        want = (by_name['single-0']['group'], by_name['single-0']['tags'])
        self.assertEqual(want, ('web', ['prod', 'linux']))
        for i in range(3):
            h = by_name[f'many-{i}']
            self.assertEqual((h['group'], h['tags']), want, f'use {i + 1}')
            self.assertNotIn('tenant', h, 'tenancy is on here, but this token was made by the platform operator')

    def test_a_host_that_enrols_again_counts_as_a_use(self):
        _, d = self.mint(max_uses=2)
        first = self.enrol_ok(d['token'], 'again')
        st, r = self.call(api.handle_enroll_register, who=None, m='POST',
                          body={'enrollment_token': d['token'], 'hostname': 'again', 'name': 'again',
                                'device_id': first['device_id'], 'token': first['token']})
        self.assertEqual((st, r.get('reregistered')), (200, True), r)
        self.assertEqual(len(self.hosts()), 1, 'enrolling again is not a second host')
        self.assertEqual(self.stored(), [], 'but it was the second use of two')
        self.enrol_refused(d['token'])

    def test_every_use_is_audited_with_the_host_and_never_with_the_token(self):
        _, d = self.mint(max_uses=3)
        ids = [self.enrol_ok(d['token'], f'a{i}')['device_id'] for i in range(3)]
        lines = [a for a in self.audits if a[1] == 'enroll']
        self.assertEqual(len(lines), 3)
        for n, (line, dev_id) in enumerate(zip(lines, ids), 1):
            self.assertIn(f'device={dev_id}', line[2])
            self.assertIn(f'use={n}/3', line[2])
            self.assertIn('via=token', line[2])
        everything = json.dumps(self.audits, default=str)
        self.assertNotIn(d['token'], everything)
        self.assertNotIn(api._hash_device_token(d['token']), everything)

    def test_a_single_use_token_is_audited_the_same_way(self):
        _, d = self.mint()
        dev_id = self.enrol_ok(d['token'], 's')['device_id']
        line = [a for a in self.audits if a[1] == 'enroll'][0]
        self.assertIn(f'device={dev_id}', line[2])
        self.assertIn('use=1/1', line[2])

    def test_the_create_call_is_audited_with_the_number_above_one_only(self):
        self.mint(max_uses=40)
        self.assertIn('max_uses=40', [a for a in self.audits if a[1] == 'enrollment_token_created'][-1][2])
        self.mint()
        self.assertNotIn('max_uses', [a for a in self.audits if a[1] == 'enrollment_token_created'][-1][2])


class TestRevokeAndExpiry(_Many):

    def test_revoke_stops_further_use_and_says_how_far_it_got(self):
        _, d = self.mint(max_uses=5)
        self.enrol_ok(d['token'], 'r0')
        prefix = d['token'][:8]
        st, r = self.call(api.handle_enroll_token_revoke, prefix, m='DELETE', who='platform')
        self.assertEqual(st, 200, r)
        self.enrol_refused(d['token'])
        self.assertEqual(len(self.hosts()), 1)
        self.assertEqual(self.stored(), [])
        self.assertIn('used=1/5', [a for a in self.audits if a[1] == 'enrollment_token_revoked'][-1][2])

    def test_an_expired_token_with_uses_left_is_refused(self):
        _, d = self.mint(max_uses=5, expires_in=3600)
        toks = api.load(api.ENROLL_TOKENS_FILE)
        for meta in toks.values():
            meta['expires'] = int(time.time()) - 5
        api.save(api.ENROLL_TOKENS_FILE, toks)
        self.enrol_refused(d['token'])
        self.assertEqual(self.hosts(), {})
        self.assertEqual(self.listing(), [])

    def test_expiry_keeps_todays_bounds(self):
        for bad in (59, api.MAX_ENROLL_TOKEN_TTL + 1):
            st, d = self.mint(max_uses=3, expires_in=bad)
            self.assertEqual(st, 400, (bad, d))
        st, d = self.mint(max_uses=3, expires_in=api.MAX_ENROLL_TOKEN_TTL)
        self.assertEqual(st, 201, d)


class TestWhatMaxUsesAccepts(_Many):

    BAD = ('3', '', ' 3', '3.0', 'many', -1, -1000, 0, 1.5, 2.0, 1000.0, 1001, 10 ** 9, 10 ** 30, True, False, [], [3], {}, {'n': 3},
           float('inf'))

    def test_anything_but_a_whole_number_from_1_to_1000_is_a_400_and_makes_no_token(self):
        for bad in self.BAD:
            with self.subTest(value=repr(bad)[:30]):
                st, d = self.mint(max_uses=bad)
                self.assertEqual(st, 400, (bad, d))
                self.assertIn('max_uses', d['error'])
        self.assertEqual(self.stored(), [], 'a refused call must not leave a token behind')

    def test_the_whole_range_is_accepted(self):
        for n in (1, 2, 3, 10, 999, 1000):
            with self.subTest(n=n):
                st, d = self.mint(max_uses=n)
                self.assertEqual((st, d['max_uses']), (201, n))

    def test_the_ceiling_is_a_constant_the_error_names(self):
        self.assertEqual(api.MAX_ENROLL_TOKEN_USES, 1000)
        st, d = self.mint(max_uses=api.MAX_ENROLL_TOKEN_USES + 1)
        self.assertIn('1000', d['error'])

    def test_a_cap_that_was_hand_edited_into_a_damaged_shape_reads_the_strict_way(self):
        """A stored `max_uses` of text, a float or a boolean is one use, not whatever it spells; a `uses` that cannot be read is spent."""
        for field, broken, expect in (('max_uses', '50', (0, 1)), ('max_uses', 50.0, (0, 1)), ('max_uses', True, (0, 1)),
                                      ('max_uses', 10 ** 9, (0, 1000)), ('max_uses', -4, (0, 1)),
                                      ('uses', 'x', (2, 2)), ('uses', -1, (2, 2)), ('uses', 1.0, (2, 2)), ('uses', False, (2, 2))):
            with self.subTest(field=field, broken=repr(broken)):
                meta = {'max_uses': 2}
                meta[field] = broken
                self.assertEqual(api._enrol_token_counts(meta), expect)
        self.assertEqual(api._enrol_token_counts({}), (0, 1))
        self.assertEqual(api._enrol_token_counts(None), (0, 1))
        self.assertEqual(api._enrol_token_counts('x'), (0, 1))

    def test_a_second_call_cannot_raise_the_cap_of_a_token_that_exists(self):
        _, a = self.mint(max_uses=2, label='a')
        _, b = self.mint(max_uses=500, label='b')
        _, c = self.mint(max_uses=1000, label='c')
        caps = {r['label']: r['max_uses'] for r in self.listing()}
        self.assertEqual(caps, {'a': 2, 'b': 500, 'c': 1000})
        self.assertEqual(len({a['token'], b['token'], c['token']}), 3)

    def test_the_revoke_route_does_not_edit_anything(self):
        _, d = self.mint(max_uses=2)
        for verb in ('POST', 'PUT', 'PATCH', 'GET'):
            st, r = self.call(api.handle_enroll_token_revoke, d['token'][:8], m=verb, body={'max_uses': 900}, who='platform')
            self.assertEqual(st, 405, (verb, r))
        self.assertEqual(self.row()['max_uses'], 2)


class TestTenants(_Many):

    def test_a_tenant_admins_token_enrols_every_host_into_that_tenant(self):
        _, d = self.mint_as('badmin', max_uses=3, default_group='b-web')
        for i in range(3):
            self.enrol_ok(d['token'], f'tb{i}')
        hosts = self.hosts()
        self.assertEqual(len(hosts), 3)
        self.assertEqual({h.get('tenant') for h in hosts.values()}, {'tenantB'})
        self.assertEqual({h['group'] for h in hosts.values()}, {'b-web'})

    def test_the_token_is_stamped_with_the_tenant_of_the_admin_who_made_it_and_nobody_else_can_use_that_against_them(self):
        _, d = self.mint_as('badmin', max_uses=2)
        _, e = self.mint_as('cadmin', max_uses=2)
        self.assertEqual(sorted(r.get('tenant') for r in self.stored()), ['tenantB', 'tenantC'])
        self.enrol_ok(d['token'], 'b-host')
        self.enrol_ok(e['token'], 'c-host')
        by_name = {v['name']: v.get('tenant') for v in self.hosts().values()}
        self.assertEqual(by_name, {'b-host': 'tenantB', 'c-host': 'tenantC'})

    def test_a_tenant_admin_lists_and_revokes_only_their_own(self):
        _, mine = self.mint_as('badmin', max_uses=4, label='mine')
        _, theirs = self.mint_as('cadmin', max_uses=4, label='theirs')
        self.assertEqual([r['label'] for r in self.listing('badmin')], ['mine'])
        self.assertEqual([r['label'] for r in self.listing('cadmin')], ['theirs'])
        self.assertEqual(sorted(r['label'] for r in self.listing('platform')), ['mine', 'theirs'])
        st, _r = self.call(api.handle_enroll_token_revoke, theirs['token'][:8], m='DELETE', who='badmin')
        self.assertEqual(st, 404)
        self.enrol_ok(theirs['token'], 'still-works')
        st, _r = self.call(api.handle_enroll_token_revoke, mine['token'][:8], m='DELETE', who='badmin')
        self.assertEqual(st, 200)
        self.enrol_refused(mine['token'])

    def test_a_viewer_cannot_make_a_token_with_any_number_of_uses(self):
        api.save(api.USERS_FILE, dict(api.load(api.USERS_FILE), reader={'role': 'viewer', 'tenant_id': 'tenantB'}))
        st, d = self.call(api.handle_enroll_token_create, body={'label': 'x', 'max_uses': 50}, who='reader')
        self.assertEqual(st, 403, d)
        self.assertEqual(self.stored(), [])
        st, d = self.call(api.handle_enroll_token_list, m='GET', who='reader')
        self.assertEqual(st, 403, d)

    def mint_as(self, who, **body):
        return self.call(api.handle_enroll_token_create, body=dict({'label': 't'}, **body), who=who)


class TestRacing(_Many):
    """N requests racing for a token with N uses left enrol exactly N hosts. Real handlers, real locks, real threads."""

    def _race(self, token, n_threads, ip='203.0.113.9'):
        gate = threading.Barrier(n_threads)
        results = [None] * n_threads

        def run(i):
            api._RCTX.environ = {'REMOTE_ADDR': ip}
            try:
                gate.wait(timeout=30)
                api.handle_enroll_register()
            except api.HTTPError as e:
                results[i] = (e.status, e.body)
            except Exception as e:                      # a crash is a failed run, reported with the others
                results[i] = ('crash', repr(e))
            finally:
                api._RCTX.environ = None

        # the handlers read the body from get_json_obj(); one body for all threads, as a rollout sends one command
        body = {'enrollment_token': token, 'hostname': 'racer', 'name': 'racer'}
        api.get_json_obj = lambda: dict(body)
        api.get_json_body = lambda: dict(body)
        api.method = lambda: 'POST'
        threads = [threading.Thread(target=run, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        self.assertFalse(any(t.is_alive() for t in threads), 'a request hung')
        return results

    def test_twelve_requests_for_three_uses_enrol_exactly_three_hosts(self):
        _, d = self.mint(max_uses=3)
        results = self._race(d['token'], 12)
        statuses = sorted(str(r[0]) for r in results)
        self.assertEqual(statuses, ['201'] * 3 + ['403'] * 9, results)
        self.assertEqual(len(self.hosts()), 3)
        self.assertEqual(self.stored(), [])
        # nothing stands between the host store and the token store: what the hosts hold is what the token said
        self.assertEqual(len({v['token_hash'] for v in self.hosts().values()}), 3)

    def test_a_single_use_token_still_enrols_exactly_one_host_when_raced(self):
        _, d = self.mint()
        results = self._race(d['token'], 10)
        self.assertEqual(sorted(str(r[0]) for r in results), ['201'] + ['403'] * 9, results)
        self.assertEqual(len(self.hosts()), 1)

    def test_fewer_requests_than_uses_leaves_the_rest_for_later(self):
        _, d = self.mint(max_uses=8)
        results = self._race(d['token'], 5)
        self.assertEqual(sorted(str(r[0]) for r in results), ['201'] * 5, results)
        self.assertEqual((self.row()['uses'], self.row()['max_uses']), (5, 8))
        self.assertEqual(len(self.hosts()), 5)


class TestGivingAUseBack(_Many):

    def _limit_hosts_to(self, n):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['max_devices'] = n
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def test_a_host_refused_for_the_fleet_limit_does_not_use_one_up(self):
        _, d = self.mint(max_uses=3)
        existing = len(api.load(api.DEVICES_FILE) or {})
        self._limit_hosts_to(existing + 1)
        self.enrol_ok(d['token'], 'fits')
        r = self.enrol_refused(d['token'], 'too-many')
        self.assertIn('Host limit', r['error'])
        self.assertEqual(self.row()['uses'], 1, 'the refused host must not have counted')
        self._limit_hosts_to(existing + 10)
        self.enrol_ok(d['token'], 'after-the-limit-was-raised')
        self.assertEqual(self.row()['uses'], 2)

    def test_the_same_holds_for_a_single_use_token(self):
        _, d = self.mint()
        self._limit_hosts_to(len(api.load(api.DEVICES_FILE) or {}))      # full already
        self.assertIn('Host limit', self.enrol_refused(d['token'])['error'])
        self.assertEqual(self.row().get('uses', 0), 0)
        self._limit_hosts_to(len(api.load(api.DEVICES_FILE) or {}) + 5)
        self.enrol_ok(d['token'], 'now')
        self.assertEqual(self.stored(), [])

    def test_a_known_host_with_the_wrong_host_token_does_not_use_one_up(self):
        _, d = self.mint(max_uses=2)
        first = self.enrol_ok(d['token'], 'known')
        st, r = self.call(api.handle_enroll_register, who=None, m='POST',
                          body={'enrollment_token': d['token'], 'hostname': 'known', 'name': 'known',
                                'device_id': first['device_id'], 'token': 'not-the-host-token-at-all-0000'})
        self.assertEqual(st, 403, r)
        self.assertEqual(self.row()['uses'], 1)
        self.enrol_ok(d['token'], 'second-host')
        self.assertEqual(self.stored(), [])

    def test_giving_a_use_back_never_brings_a_revoked_token_to_life(self):
        """The use is held while the host step runs. Revoked in that window, the token has no row to give the use back to, and
        none is made."""
        _, d = self.mint(max_uses=3)
        toks = api.load(api.ENROLL_TOKENS_FILE)
        key = next(iter(toks))
        claim = (key, 1, 3, d['token'][:8])
        toks[key]['uses'] = 1
        api.save(api.ENROLL_TOKENS_FILE, toks)
        st, _r = self.call(api.handle_enroll_token_revoke, d['token'][:8], m='DELETE', who='platform')
        self.assertEqual(st, 200)
        api._settle_enrol_token_use(claim, False)
        api._settle_enrol_token_use(claim, True)
        self.assertEqual(self.stored(), [])
        self.enrol_refused(d['token'])

    def test_a_failure_while_settling_does_not_lose_the_hosts_credentials(self):
        """The host exists by then. Answering 500 would lose the credentials its agent is waiting for."""
        _, d = self.mint(max_uses=3)
        real_locked, real_settle = api._LockedUpdate, api._settle_enrol_token_use

        class _Raising:
            def __init__(self, *a, **k):
                raise OSError('the store went away')

        def _settle_with_a_broken_store(claim, ok):
            api._LockedUpdate = _Raising
            try:
                return real_settle(claim, ok)
            finally:
                api._LockedUpdate = real_locked

        api._settle_enrol_token_use = _settle_with_a_broken_store
        try:
            r = self.enrol_ok(d['token'], 'survives')
        finally:
            api._settle_enrol_token_use = real_settle
            api._LockedUpdate = real_locked
        self.assertTrue(r.get('device_id') and r.get('token'))
        self.assertEqual(len(self.hosts()), 1)
        self.assertEqual(self.row()['uses'], 1, 'the use stays taken: a use that cannot be settled errs on the side of fewer hosts')


# ── the real routes ──────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestTheRoutes(unittest.TestCase):
    """The create and list calls through the real dispatcher, with a real session, and no verb that edits a token."""

    @classmethod
    def setUpClass(cls):
        import wsgi
        cls.wsgi = wsgi
        cls.api = wsgi.api
        cls._detached = cls.api._run_detached
        cls.api._run_detached = lambda *a, **k: None
        a = cls.api
        cls.dir = Path(tempfile.mkdtemp(prefix='rp-enrol-routes-'))
        cls._saved = {n: getattr(a, n) for n in ('USERS_FILE', 'TOKENS_FILE', 'ENROLL_TOKENS_FILE', 'CONFIG_FILE', 'DEVICES_FILE',
                                                 'AUDIT_LOG_FILE', 'RATELIMIT_FILE', 'PINS_FILE')}
        for n in cls._saved:
            setattr(a, n, cls.dir / cls._saved[n].name)
        a.save(a.USERS_FILE, {'root': {'role': 'admin', 'password_hash': a.hash_password('Unused-Passw0rd!x')}})
        a.save(a.CONFIG_FILE, {'backup': {'enabled': False}})       # the scheduled backup runs inside a request; this test is not about it
        cls.tok = 'session-token-for-the-enrol-route-test'
        a.save(a.TOKENS_FILE, {a._token_hash(cls.tok): {'user': 'root', 'created': int(time.time()), 'ttl': 3600, 'ip': '192.0.2.1'}})

    @classmethod
    def tearDownClass(cls):
        for n, v in cls._saved.items():
            setattr(cls.api, n, v)
        cls.api._run_detached = cls._detached
        shutil.rmtree(cls.dir, ignore_errors=True)

    def call(self, verb, path, body=None, token=True):
        raw = json.dumps(body).encode() if body is not None else b''
        env = {'REQUEST_METHOD': verb, 'PATH_INFO': path, 'QUERY_STRING': '', 'SERVER_NAME': 'localhost', 'SERVER_PORT': '80',
               'SERVER_PROTOCOL': 'HTTP/1.1', 'REMOTE_ADDR': '127.0.0.1', 'wsgi.input': io.BytesIO(raw), 'wsgi.errors': io.BytesIO(),
               'wsgi.version': (1, 0), 'wsgi.url_scheme': 'http', 'wsgi.multithread': True, 'wsgi.multiprocess': False,
               'wsgi.run_once': False}
        if raw:
            env['CONTENT_LENGTH'] = str(len(raw))
            env['CONTENT_TYPE'] = 'application/json'
        if token:
            env['HTTP_X_TOKEN'] = self.tok
        cap = {}

        def start(status, headers):
            cap['status'] = int(status.split()[0])

        out = b''.join(self.wsgi.application(env, start))
        try:
            data = json.loads(out) if out else None
        except ValueError:
            data = out
        return cap['status'], data

    def stored(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.ENROLL_TOKENS_FILE) or {}

    def test_create_and_list_through_the_routes_carry_the_numbers(self):
        st, d = self.call('POST', '/api/enrollment-tokens', {'label': 'route', 'max_uses': 25})
        self.assertEqual((st, d['max_uses']), (201, 25), d)
        st, rows = self.call('GET', '/api/enrollment-tokens')
        self.assertEqual(st, 200)
        mine = [r for r in rows if r['label'] == 'route'][0]
        self.assertEqual((mine['uses'], mine['max_uses'], mine['uses_left']), (0, 25, 25))
        self.assertNotIn(d['token'], json.dumps(rows))

    def test_a_bad_number_is_a_400_through_the_route_too(self):
        for bad in ('9', 0, -3, 2.5, 10 ** 9, [1]):
            st, d = self.call('POST', '/api/enrollment-tokens', {'label': 'bad-route', 'max_uses': bad})
            self.assertEqual(st, 400, (bad, d))
        self.assertFalse([1 for m in self.stored().values() if m.get('label') == 'bad-route'])

    def test_no_verb_on_either_route_edits_a_token(self):
        st, d = self.call('POST', '/api/enrollment-tokens', {'label': 'fixed', 'max_uses': 2})
        self.assertEqual(st, 201)
        prefix = d['token'][:8]
        before = json.dumps(self.stored(), sort_keys=True)
        for verb, path in (('PUT', '/api/enrollment-tokens'), ('PATCH', '/api/enrollment-tokens'), ('DELETE', '/api/enrollment-tokens'),
                           ('PUT', f'/api/enrollment-tokens/{prefix}'), ('PATCH', f'/api/enrollment-tokens/{prefix}'),
                           ('POST', f'/api/enrollment-tokens/{prefix}'), ('GET', f'/api/enrollment-tokens/{prefix}')):
            with self.subTest(verb=verb, path=path[:30]):
                st, _d = self.call(verb, path, {'max_uses': 900, 'uses': 0, 'label': 'edited'})
                self.assertIn(st, (400, 404, 405), (verb, path, st))
        self.assertEqual(json.dumps(self.stored(), sort_keys=True), before, 'a verb that is not create or revoke changed a token')

    def test_the_routes_need_a_session(self):
        self.assertEqual(self.call('POST', '/api/enrollment-tokens', {'max_uses': 3}, token=False)[0], 401)
        self.assertEqual(self.call('GET', '/api/enrollment-tokens', token=False)[0], 401)


def tearDownModule():
    # api._env() reads the request context before os.environ: a context left set here is what the next module's requests would be answered from
    api._RCTX.environ = None
    import api_guard
    api_guard.restore(__name__)


if __name__ == '__main__':
    unittest.main()
