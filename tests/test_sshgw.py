"""SSH gateway — pure helpers and the API side.

The daemon holds no policy: it asks /api/sshgw/authorize for every login and
every channel. So the tests that matter most are the authorize ones, and they
stub only IDENTITY (verify_token / the daemon secret header) so the real role,
scope and tenant logic runs. A stubbed require_* gate would pass a handler that
had no gate at all.
"""
import base64
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-sshgw-'))

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import sshgw  # noqa: E402

SECRET = 'a' * 40


def _fresh_api():
    import importlib.util
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-sshgw-api-')
    spec = importlib.util.spec_from_file_location('api_sshgw', _CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ssh_string(b):
    return struct.pack('>I', len(b)) + b


def _ed25519_line(seed=b'\x01', comment='alice@laptop'):
    blob = _ssh_string(b'ssh-ed25519') + _ssh_string((seed * 32)[:32])
    return f'ssh-ed25519 {base64.b64encode(blob).decode()} {comment}', blob


def _rsa_line(bits):
    n = (1 << (bits - 1)) | 1
    nb = n.to_bytes((bits + 7) // 8, 'big')
    if nb[0] & 0x80:
        nb = b'\x00' + nb
    blob = _ssh_string(b'ssh-rsa') + _ssh_string(b'\x01\x00\x01') + _ssh_string(nb)
    return f'ssh-rsa {base64.b64encode(blob).decode()}'


# ── pure helpers ───────────────────────────────────────────────────────────────

class TestPublicKeyParsing(unittest.TestCase):
    def test_ed25519_parses_with_openssh_fingerprint(self):
        line, blob = _ed25519_line()
        k = sshgw.parse_public_key(line)
        self.assertEqual(k['type'], 'ssh-ed25519')
        self.assertEqual(k['comment'], 'alice@laptop')
        self.assertTrue(sshgw.valid_fingerprint(k['fingerprint']))
        self.assertEqual(k['blob'], blob)

    def test_fingerprint_matches_asyncssh(self):
        try:
            import asyncssh
        except ImportError:
            self.skipTest('asyncssh not installed')
        key = asyncssh.generate_private_key('ssh-ed25519')
        line = key.export_public_key().decode().strip()
        self.assertEqual(sshgw.parse_public_key(line)['fingerprint'],
                         key.get_fingerprint('sha256'))

    def test_rejections(self):
        line, _ = _ed25519_line()
        bad = {
            '': 'empty',
            'ssh-dss AAAA': 'DSA',
            'ssh-foo AAAA': 'unsupported',
            'ssh-ed25519 !!!!': 'base64',
            'from="x" ' + line: 'unsupported',
            line + '\n' + line: 'one key',
            _rsa_line(1024): '2048',
        }
        for text, needle in bad.items():
            with self.assertRaises(ValueError, msg=text[:30]) as cm:
                sshgw.parse_public_key(text)
            self.assertIn(needle, str(cm.exception), text[:30])
        # type in the line disagrees with the type inside the blob
        blob = _ssh_string(b'ssh-rsa') + _ssh_string(b'x' * 32)
        with self.assertRaises(ValueError):
            sshgw.parse_public_key('ssh-ed25519 ' + base64.b64encode(blob).decode())

    def test_rsa_2048_accepted(self):
        self.assertEqual(sshgw.parse_public_key(_rsa_line(2048))['bits'], 2048)


class TestTargets(unittest.TestCase):
    DEVS = {
        'd1': {'name': 'web01', 'hostname': 'web01.corp.example'},
        'd2': {'name': 'db', 'hostname': 'db01'},
        'd3': {'name': 'dup', 'hostname': 'x1'},
        'd4': {'name': 'dup', 'hostname': 'x2'},
    }

    def test_suffix_and_name_forms(self):
        for t in ('web01', 'web01.rp', 'WEB01.RP', 'web01.corp.example', 'd1'):
            self.assertEqual(sshgw.resolve_target(self.DEVS, t), ('d1', None), t)
        self.assertEqual(sshgw.resolve_target(self.DEVS, 'db01.rp')[0], 'd2')

    def test_ambiguous_name_is_refused_not_guessed(self):
        did, why = sshgw.resolve_target(self.DEVS, 'dup')
        self.assertIsNone(did)
        self.assertIn('2 devices', why)

    def test_unknown_and_invalid(self):
        self.assertIsNone(sshgw.resolve_target(self.DEVS, 'nope')[0])
        self.assertIsNone(sshgw.resolve_target(self.DEVS, '../etc')[0])
        self.assertIsNone(sshgw.resolve_target(self.DEVS, '')[0])


class TestFrames(unittest.TestCase):
    def test_round_trip(self):
        f = sshgw.encode_frame(sshgw.FRAME_DATA, 7, b'hello')
        self.assertEqual(sshgw.decode_frame(f), (sshgw.FRAME_DATA, 7, b'hello'))

    def test_malformed(self):
        for buf in (b'', b'\x04\x00\x00', b'\x09\x00\x00\x00\x01',
                    b'\x04\x00\x00\x00\x00',
                    sshgw.FRAME_HEADER.pack(4, 1) + b'x' * (sshgw.MAX_FRAME_PAYLOAD + 1),
                    'text'):
            with self.assertRaises(ValueError):
                sshgw.decode_frame(buf)
        with self.assertRaises(ValueError):
            sshgw.encode_frame(sshgw.FRAME_DATA, 0)

    def test_agent_copy_of_the_frame_constants_matches(self):
        """The agent is one file and cannot import sshgw.py, so it carries its
        own copy of the frame kinds. They must agree or every tunnel breaks."""
        import re
        src = (_CGI.parent.parent / 'client' / 'remotepower-agent.py').read_text()
        found = dict(re.findall(r'^_SSHGW_FRAME_([A-Z_]+) = (\d+)$', src, re.M))
        self.assertTrue(found, 'agent frame constants not found')
        for name, val in found.items():
            self.assertEqual(int(val), getattr(sshgw, 'FRAME_' + name), name)
        self.assertEqual(set(found), {'OPEN', 'OPEN_OK', 'OPEN_FAIL', 'DATA',
                                      'CLOSE', 'PAUSE', 'RESUME'})


# ── API side ───────────────────────────────────────────────────────────────────

class _Case(unittest.TestCase):
    def setUp(self):
        self.api = api = _fresh_api()
        self.cap = {}
        self.audit = []

        def _respond(status, data=None):
            self.cap['status'] = status
            self.cap['data'] = data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.audit_log = lambda *a, **k: self.audit.append(a)
        api.fire_webhook = lambda *a, **k: None
        api.get_token_from_request = lambda: 'tok'
        self.env = {'HTTP_X_SSHGW_SECRET': SECRET}
        api._env = lambda k, d='': self.env.get(k, d)
        self.alice_line, _ = _ed25519_line(b'\x01')
        self.alice_fp = sshgw.parse_public_key(self.alice_line)['fingerprint']
        self.bob_line, _ = _ed25519_line(b'\x02', 'bob')
        self.bob_fp = sshgw.parse_public_key(self.bob_line)['fingerprint']
        api.save(api.CONFIG_FILE, {'sshgw_enabled': True, 'sshgw_daemon_secret': SECRET})
        api.save(api.ROLES_FILE, {'roles': [
            {'name': 'ssh-web', 'permissions': ['ssh'],
             'scope': {'type': 'groups', 'values': ['web']}},
            {'name': 'patcher', 'permissions': ['patch'], 'scope': {'type': 'all'}},
        ]})
        key = lambda fp: [{'fingerprint': fp, 'type': 'ssh-ed25519', 'name': 'k'}]
        api.save(api.USERS_FILE, {
            'alice': {'role': 'admin', 'sshgw_keys': key(self.alice_fp)},
            'bob': {'role': 'ssh-web', 'sshgw_keys': key(self.bob_fp)},
        })
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'group': 'web', 'os': 'Ubuntu 24.04',
                   'token': 'dtok', 'sshgw_enabled': True},
            'd2': {'name': 'db01', 'group': 'db', 'os': 'Debian 12',
                   'token': 'dtok2', 'sshgw_enabled': True},
            'd3': {'name': 'off01', 'group': 'web', 'os': 'Debian 12', 'token': 'x'},
            'd4': {'name': 'win01', 'os': 'Windows 11', 'token': 'x'},
        })
        api._LOAD_CACHE.clear()

    def call(self, fn, method='POST', body=None, *args):
        self.api.method = lambda: method
        self.api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        try:
            fn(*args)
        except self.api.HTTPError:
            pass
        self.api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def authorize(self, user, fp, target=''):
        return self.call(self.api.handle_sshgw_authorize, 'POST',
                         {'username': user, 'fingerprint': fp, 'target': target,
                          'client_ip': '198.51.100.7'})

    def as_role(self, user, role):
        self.api.verify_token = lambda _t=None: (user, role)


class TestDaemonSecret(_Case):
    def test_wrong_or_missing_secret_is_refused_on_every_daemon_endpoint(self):
        for env in ({}, {'HTTP_X_SSHGW_SECRET': 'b' * 40}):
            self.env = env
            for fn in (self.api.handle_sshgw_authorize, self.api.handle_sshgw_agent_check,
                       self.api.handle_sshgw_audit):
                self.assertEqual(self.call(fn)[0], 403, fn.__name__)

    def test_unset_secret_refuses_even_a_matching_empty_header(self):
        self.api.save(self.api.CONFIG_FILE, {'sshgw_enabled': True})
        self.env = {'HTTP_X_SSHGW_SECRET': ''}
        self.assertEqual(self.authorize('alice', self.alice_fp)[0], 403)

    def test_module_off_404s_the_whole_prefix(self):
        self.api.save(self.api.CONFIG_FILE, {'sshgw_enabled': False,
                                             'sshgw_daemon_secret': SECRET})
        self.api._LOAD_CACHE.clear()
        self.cap.clear()
        with self.assertRaises(self.api.HTTPError):
            self.api._enforce_module_gate('/api/sshgw/authorize')
        self.assertEqual(self.cap['status'], 404)


class TestAuthorize(_Case):
    def test_login_without_target_checks_key_ownership(self):
        self.assertEqual(self.authorize('alice', self.alice_fp)[0], 200)
        # bob's key presented as alice, and an unknown account, get one answer
        st1, d1 = self.authorize('alice', self.bob_fp)
        st2, d2 = self.authorize('mallory', self.bob_fp)
        self.assertEqual((st1, st2), (403, 403))
        self.assertEqual(d1['error'], d2['error'])

    def test_admin_reaches_an_opted_in_device(self):
        st, d = self.authorize('alice', self.alice_fp, 'web01.rp')
        self.assertEqual(st, 200)
        self.assertEqual(d['device_id'], 'd1')
        self.assertTrue(d['session_id'])
        self.assertTrue(any(a[1] == 'sshgw_open' for a in self.audit))
        users = self.api.load(self.api.USERS_FILE)
        self.assertGreater(users['alice']['sshgw_keys'][0].get('last_used', 0), 0)

    def test_device_not_opted_in_is_refused(self):
        st, _ = self.authorize('alice', self.alice_fp, 'off01')
        self.assertEqual(st, 403)
        self.assertTrue(any(a[1] == 'sshgw_denied' for a in self.audit))

    def test_role_scope_applies(self):
        self.assertEqual(self.authorize('bob', self.bob_fp, 'web01')[0], 200)
        self.assertEqual(self.authorize('bob', self.bob_fp, 'db01')[0], 403)

    def test_role_without_ssh_permission_is_refused(self):
        for role in ('viewer', 'auditor', 'patcher'):
            users = self.api.load(self.api.USERS_FILE)
            users['bob']['role'] = role
            self.api.save(self.api.USERS_FILE, users)
            self.api._LOAD_CACHE.clear()
            self.assertEqual(self.authorize('bob', self.bob_fp, 'web01')[0], 403, role)

    def test_disabled_account_is_refused_at_login(self):
        users = self.api.load(self.api.USERS_FILE)
        users['alice']['disabled'] = True
        self.api.save(self.api.USERS_FILE, users)
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.authorize('alice', self.alice_fp)[0], 403)

    def test_quarantined_device_is_refused(self):
        devs = self.api.load(self.api.DEVICES_FILE)
        self.api._device_quarantined = lambda dev: dev.get('name') == 'web01'
        self.api.save(self.api.DEVICES_FILE, devs)
        self.assertEqual(self.authorize('alice', self.alice_fp, 'web01')[0], 403)

    def test_tenancy_another_tenants_device_reads_like_a_missing_one(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['tenancy_enforced'] = True
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api.save(self.api.TENANTS_FILE, {'t1': {'name': 'T1'}, 't2': {'name': 'T2'}})
        users = self.api.load(self.api.USERS_FILE)
        users['bob']['role'] = 'admin'
        users['bob']['tenant_id'] = 't1'
        self.api.save(self.api.USERS_FILE, users)
        devs = self.api.load(self.api.DEVICES_FILE)
        devs['d1']['tenant'] = 't1'
        devs['d2']['tenant'] = 't2'
        self.api.save(self.api.DEVICES_FILE, devs)
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.authorize('bob', self.bob_fp, 'web01')[0], 200)
        st, d = self.authorize('bob', self.bob_fp, 'db01')
        st_missing, d_missing = self.authorize('bob', self.bob_fp, 'nothere')
        self.assertEqual((st, st_missing), (403, 403))
        self.assertEqual(d['error'].replace('db01', 'X'),
                         d_missing['error'].replace('nothere', 'X'))
        # the platform superadmin (admin in the default tenant) reaches both
        self.assertEqual(self.authorize('alice', self.alice_fp, 'db01')[0], 200)


class TestAgentCheckAndAudit(_Case):
    def test_agent_check(self):
        b = {'device_id': 'd1', 'token': 'dtok'}
        self.assertEqual(self.call(self.api.handle_sshgw_agent_check, 'POST', b)[0], 200)
        st = self.api.load(self.api.SSHGW_STATE_FILE)
        self.assertGreater(st['d1']['tunnel_seen'], 0)
        b['token'] = 'wrong'
        self.assertEqual(self.call(self.api.handle_sshgw_agent_check, 'POST', b)[0], 403)
        b = {'device_id': 'd3', 'token': 'x'}
        self.assertEqual(self.call(self.api.handle_sshgw_agent_check, 'POST', b)[0], 403)

    def test_audit_records_and_caps(self):
        body = {'session_id': 's1', 'username': 'alice', 'device_id': 'd1',
                'started': 1000, 'duration_s': 5, 'bytes_in': 10, 'bytes_out': 20,
                'reason': 'closed'}
        self.assertEqual(self.call(self.api.handle_sshgw_audit, 'POST', body)[0], 200)
        rows = self.api.load(self.api.SSHGW_SESSIONS_FILE)['sessions']
        self.assertEqual(rows[-1]['bytes_out'], 20)
        self.assertTrue(any(a[1] == 'sshgw_session' for a in self.audit))
        self.api.save(self.api.SSHGW_SESSIONS_FILE,
                      {'sessions': [dict(body, session_id=str(i))
                                    for i in range(self.api.sshgw_handlers_mod.SESSIONS_CAP)]})
        self.call(self.api.handle_sshgw_audit, 'POST', body)
        rows = self.api.load(self.api.SSHGW_SESSIONS_FILE)['sessions']
        self.assertEqual(len(rows), self.api.sshgw_handlers_mod.SESSIONS_CAP)

    def test_sessions_list_is_admin_or_auditor(self):
        self.api.save(self.api.SSHGW_SESSIONS_FILE, {'sessions': [
            {'session_id': 's', 'device_id': 'd1', 'started': 1}]})
        self.as_role('v', 'viewer')
        self.assertEqual(self.call(self.api.handle_sshgw_sessions, 'GET')[0], 403)
        self.as_role('a', 'auditor')
        st, d = self.call(self.api.handle_sshgw_sessions, 'GET')
        self.assertEqual((st, len(d['sessions'])), (200, 1))


class TestKeys(_Case):
    def setUp(self):
        super().setUp()
        users = self.api.load(self.api.USERS_FILE)
        users['carol'] = {'role': 'admin',
                          'password_hash': self.api.hash_password('pw-carol-123')}
        self.api.save(self.api.USERS_FILE, users)
        self.api._LOAD_CACHE.clear()
        self.as_role('carol', 'admin')
        self.api._step_up_token_entry = lambda: ('tk', {}, {})
        self.line, _ = _ed25519_line(b'\x05', 'carol@box')

    def add(self, **kw):
        body = {'public_key': self.line, 'name': 'laptop', 'password': 'pw-carol-123'}
        body.update(kw)
        return self.call(self.api.handle_sshgw_keys, 'POST', body)

    def test_add_list_delete(self):
        st, d = self.add()
        self.assertEqual(st, 200, d)
        fp = d['key']['fingerprint']
        st, d = self.call(self.api.handle_sshgw_keys, 'GET')
        self.assertEqual([k['fingerprint'] for k in d['keys']], [fp])
        self.assertNotIn('key', d['keys'][0])   # the listing is metadata only
        self.assertEqual(self.add()[0], 409)      # same key twice
        st, _ = self.call(self.api.handle_sshgw_keys, 'DELETE', {'fingerprint': fp})
        self.assertEqual(st, 200)
        self.assertEqual(self.call(self.api.handle_sshgw_keys, 'DELETE',
                                   {'fingerprint': fp})[0], 404)

    def test_wrong_password_refused(self):
        self.assertEqual(self.add(password='nope')[0], 403)

    def test_api_key_caller_refused(self):
        self.api._step_up_token_entry = lambda: (None, None, None)
        self.assertEqual(self.add()[0], 403)

    def test_read_only_role_refused(self):
        self.as_role('carol', 'viewer')
        self.assertEqual(self.add()[0], 403)

    def test_cannot_register_a_key_someone_else_holds(self):
        self.line = self.alice_line
        self.assertEqual(self.add()[0], 409)

    def test_non_admin_cannot_revoke_another_users_key(self):
        self.as_role('bob', 'ssh-web')
        st, _ = self.call(self.api.handle_sshgw_keys, 'DELETE',
                          {'fingerprint': self.alice_fp, 'username': 'alice'})
        self.assertEqual(st, 403)


class TestDeviceOptIn(_Case):
    def test_admin_only_and_linux_only(self):
        self.as_role('bob', 'ssh-web')
        st, _ = self.call(self.api.handle_device_sshgw, 'PATCH', {'enabled': True}, 'd3')
        self.assertEqual(st, 403)
        self.as_role('alice', 'admin')
        st, _ = self.call(self.api.handle_device_sshgw, 'PATCH', {'enabled': True}, 'd3')
        self.assertEqual(st, 200)
        self.assertTrue(self.api.load(self.api.DEVICES_FILE)['d3']['sshgw_enabled'])
        st, _ = self.call(self.api.handle_device_sshgw, 'PATCH', {'enabled': True}, 'd4')
        self.assertEqual(st, 409)

    def test_heartbeat_advertises_only_when_module_on_and_device_opted_in(self):
        def beat(dev_id, token):
            self.api.method = lambda: 'POST'
            self.api.get_json_body = lambda: {'device_id': dev_id, 'token': token}
            self.api.get_json_obj = self.api.get_json_body
            self.cap.clear()
            try:
                self.api.handle_heartbeat()
            except (self.api.HTTPError, SystemExit):
                pass
            self.api._LOAD_CACHE.clear()
            self.assertEqual(self.cap.get('status'), 200, self.cap)
            return self.cap['data']
        self.assertTrue(beat('d1', 'dtok').get('sshgw_enabled'))
        self.assertFalse(beat('d3', 'x').get('sshgw_enabled'))
        self.api.save(self.api.CONFIG_FILE, {'sshgw_enabled': False})
        self.api._LOAD_CACHE.clear()
        self.assertFalse(beat('d1', 'dtok').get('sshgw_enabled'))


if __name__ == '__main__':
    unittest.main()
