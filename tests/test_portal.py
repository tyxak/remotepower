"""W6-28 customer portal — security-focused guardrails (site isolation, token
lifecycle, feature gate, namespace separation)."""
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
import sys
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_portal", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for a in ('CONFIG_FILE', 'CONTACTS_FILE', 'TICKETS_FILE', 'PORTAL_STATE_FILE',
                  'RATELIMIT_FILE' if hasattr(api, 'RATELIMIT_FILE') else 'CONFIG_FILE'):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        self.cap = {}
        self._env_val = {}
        self._orig = {n: getattr(api, n) for n in
                      ('respond', 'method', 'get_json_obj', '_env', 'audit_log',
                       'fire_webhook', '_ip_ratelimit', '_get_client_ip', 'smtp_notifier')}

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api._ip_ratelimit = lambda *a, **k: True     # allow by default
        api._get_client_ip = lambda: '203.0.113.9'
        api._env = lambda k, d='': self._env_val.get(k, d)
        # portal on by default
        api.save(api.CONFIG_FILE, {'portal_enabled': True})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError as e:
            self._last = e
            return e.body
        return self.cap.get('b')

    def _contact(self, cid, email, site, enabled=True):
        st = api.load(api.CONTACTS_FILE) or {}
        st.setdefault('contacts', []).append(
            {'id': cid, 'name': cid, 'email': email, 'site': site, 'portal_enabled': enabled})
        api.save(api.CONTACTS_FILE, st)
        api._invalidate_load_cache(api.CONTACTS_FILE)

    def _session(self, cid, site):
        """Directly mint a portal session for a contact; return the cookie value."""
        tok = 'sess-' + cid
        st = api.load(api.PORTAL_STATE_FILE) or {}
        st.setdefault('sessions', {})[api._portal_hash(tok)] = {
            'contact_id': cid, 'expires': int(time.time()) + 3600}
        api.save(api.PORTAL_STATE_FILE, st)
        api._invalidate_load_cache(api.PORTAL_STATE_FILE)
        self._env_val['HTTP_COOKIE'] = f'rp_portal={tok}'
        return tok


class TestPortalGate(_Base):
    def test_disabled_hides_everything(self):
        api.save(api.CONFIG_FILE, {'portal_enabled': False})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'email': 'a@b.c'}
        out = self.call(api.handle_portal_magic_link)
        self.assertEqual(self._last.status, 404)


class TestMagicLink(_Base):
    def test_constant_response_regardless_of_email(self):
        api.smtp_notifier = type('X', (), {'send_email': staticmethod(lambda *a, **k: None)})
        api.method = lambda: 'POST'
        self._contact('ct_a', 'known@x.io', 's1')
        api.get_json_obj = lambda: {'email': 'known@x.io'}
        r1 = self.call(api.handle_portal_magic_link)
        api.get_json_obj = lambda: {'email': 'nobody@x.io'}
        r2 = self.call(api.handle_portal_magic_link)
        self.assertEqual(r1['message'], r2['message'])   # no enumeration oracle
        # a nonce was minted for the known email only
        st = api.load(api.PORTAL_STATE_FILE) or {}
        self.assertEqual(len(st.get('nonces') or {}), 1)

    def test_rate_limited(self):
        api._ip_ratelimit = lambda *a, **k: False
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'email': 'known@x.io'}
        self.call(api.handle_portal_magic_link)
        self.assertEqual(self._last.status, 429)


class TestSession(_Base):
    def test_valid_nonce_sets_cookie(self):
        self._contact('ct_a', 'a@x.io', 's1')
        nonce = 'link-abc'
        api.save(api.PORTAL_STATE_FILE, {'nonces': {
            api._portal_hash(nonce): {'contact_id': 'ct_a', 'expires': int(time.time()) + 600}}})
        api._invalidate_load_cache(api.PORTAL_STATE_FILE)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'token': nonce}
        self.call(api.handle_portal_session)
        self.assertEqual(self._last.status, 200)
        cookies = [v for k, v in self._last.headers if k == 'Set-Cookie']
        self.assertTrue(cookies and 'rp_portal=' in cookies[0] and 'HttpOnly' in cookies[0])
        # nonce is single-use → burned
        st = api.load(api.PORTAL_STATE_FILE) or {}
        self.assertEqual(st.get('nonces') or {}, {})

    def test_expired_nonce_rejected(self):
        self._contact('ct_a', 'a@x.io', 's1')
        nonce = 'old'
        api.save(api.PORTAL_STATE_FILE, {'nonces': {
            api._portal_hash(nonce): {'contact_id': 'ct_a', 'expires': int(time.time()) - 5}}})
        api._invalidate_load_cache(api.PORTAL_STATE_FILE)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'token': nonce}
        self.call(api.handle_portal_session)
        self.assertEqual(self._last.status, 401)

    def test_no_cookie_401(self):
        self._env_val.pop('HTTP_COOKIE', None)
        api.method = lambda: 'GET'
        self.call(api.handle_portal_tickets)
        self.assertEqual(self._last.status, 401)

    def test_revoked_contact_401(self):
        self._contact('ct_a', 'a@x.io', 's1', enabled=True)
        self._session('ct_a', 's1')
        # disable the contact after the session exists
        st = api.load(api.CONTACTS_FILE)
        st['contacts'][0]['portal_enabled'] = False
        api.save(api.CONTACTS_FILE, st)
        api._invalidate_load_cache(api.CONTACTS_FILE)
        api.method = lambda: 'GET'
        self.call(api.handle_portal_tickets)
        self.assertEqual(self._last.status, 401)


class TestSiteIsolation(_Base):
    def _seed_tickets(self):
        api.save(api.TICKETS_FILE, {'ticket_seq': 2, 'tickets': [
            {'id': 't1', 'number': 900001, 'subject': 'A1', 'status': 'ongoing',
             'site': 's1', 'messages': []},
            {'id': 't2', 'number': 900002, 'subject': 'B1', 'status': 'ongoing',
             'site': 's2', 'messages': []},
            {'id': 't3', 'number': 900003, 'subject': 'operator', 'status': 'ongoing',
             'messages': []},   # no site → never visible in the portal
        ]})
        api._invalidate_load_cache(api.TICKETS_FILE)

    def test_list_scoped_to_own_site(self):
        self._contact('ct_a', 'a@x.io', 's1')
        self._session('ct_a', 's1')
        self._seed_tickets()
        api.method = lambda: 'GET'
        out = self.call(api.handle_portal_tickets)
        nums = {t['number'] for t in out['tickets']}
        self.assertEqual(nums, {900001})     # only s1; not s2, not the site-less one

    def test_cross_site_ticket_404(self):
        self._contact('ct_a', 'a@x.io', 's1')
        self._session('ct_a', 's1')
        self._seed_tickets()
        api.method = lambda: 'GET'
        self._env_val['PATH_INFO'] = '/api/portal/tickets/900002'
        self.call(api.handle_portal_ticket, '900002')   # s2 ticket, s1 contact
        self.assertEqual(self._last.status, 404)

    def test_create_stamps_own_site(self):
        self._contact('ct_a', 'a@x.io', 's1')
        self._session('ct_a', 's1')
        api.save(api.TICKETS_FILE, {})
        api._invalidate_load_cache(api.TICKETS_FILE)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'subject': 'help', 'message': 'hi'}
        out = self.call(api.handle_portal_tickets)
        self.assertTrue(out['ok'])
        t = (api.load(api.TICKETS_FILE) or {})['tickets'][0]
        self.assertEqual(t['site'], 's1')
        self.assertEqual(t['portal_contact'], 'ct_a')
        self.assertTrue(str(t['created_by']).startswith('portal:'))

    def test_reply_reopens_and_is_scoped(self):
        self._contact('ct_a', 'a@x.io', 's1')
        self._session('ct_a', 's1')
        api.save(api.TICKETS_FILE, {'tickets': [
            {'id': 't1', 'number': 900001, 'subject': 'A', 'status': 'resolved',
             'site': 's1', 'messages': []}]})
        api._invalidate_load_cache(api.TICKETS_FILE)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'message': 'still broken'}
        self._env_val['PATH_INFO'] = '/api/portal/tickets/900001/reply'
        self.call(api.handle_portal_ticket, '900001')
        t = (api.load(api.TICKETS_FILE) or {})['tickets'][0]
        self.assertEqual(t['status'], 'ongoing')            # reopened
        self.assertEqual(t['messages'][-1]['body'], 'still broken')


class TestPortalViewHidesInternal(_Base):
    def test_internal_notes_never_cross(self):
        view = api._portal_ticket_view({
            'number': 1, 'subject': 's', 'status': 'ongoing', 'messages': [
                {'author': 'portal:ct_a', 'body': 'customer msg', 'at': 1},
                {'author': 'jakob', 'body': 'INTERNAL note', 'internal': True, 'at': 2},
                {'author': 'jakob', 'body': 'public reply', 'at': 3}]})
        bodies = [m['body'] for m in view['messages']]
        self.assertIn('customer msg', bodies)
        self.assertIn('public reply', bodies)
        self.assertNotIn('INTERNAL note', bodies)          # internal note dropped
        self.assertNotIn('assignee', view)                 # no operator internals


if __name__ == '__main__':
    unittest.main()
