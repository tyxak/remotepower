"""SNMPv3 / USM (v5.8.0) — key derivation, envelope, and full protocol flow.

Three layers:
  * RFC 3414 Appendix A.3 key-localization test vectors (pins the password →
    Ku → Kul derivation independently of our own encoder);
  * credential validation (DES rejected, privacy-requires-auth, RFC minimum
    password length);
  * an in-process fake SNMPv3 agent on a loopback UDP socket that speaks the
    real wire protocol (engine discovery REPORT, HMAC verification, AES-CFB
    decryption, GetResponse/GETNEXT, usmStats REPORTs), driving snmp_get /
    snmp_walk end-to-end for noAuthNoPriv, authNoPriv and authPriv — plus the
    tamper / wrong-password / time-window-resync failure paths.

Plus the api.py wiring: _device_snmp_target v3 dispatch and the
/devices/<id>/snmp GET redaction + PATCH validation surface.
"""
import hashlib
import importlib.util
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import snmp as S  # noqa: E402

try:
    from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False


# ── RFC 3414 A.3 key-localization vectors ────────────────────────────────────

class TestKeyLocalization(unittest.TestCase):
    ENGINE = bytes.fromhex('000000000000000000000002')

    def test_rfc3414_a31_md5(self):
        kul = S._usm_localize_key(hashlib.md5, 'maplesyrup', self.ENGINE)
        self.assertEqual(kul.hex(), '526f5eed9fcce26f8964c2930787d82b')

    def test_rfc3414_a32_sha1(self):
        kul = S._usm_localize_key(hashlib.sha1, 'maplesyrup', self.ENGINE)
        self.assertEqual(kul.hex(), '6695febc9288e36282235fc7151f128497b38f3f')


# ── credential validation ────────────────────────────────────────────────────

class TestValidation(unittest.TestCase):
    def _creds(self, **kw):
        base = {'user': 'monitor', 'auth_proto': 'sha256',
                'auth_secret': 'authpass123', 'priv_proto': 'aes',
                'priv_secret': 'privpass123'}
        base.update(kw)
        return base

    def test_ok(self):
        S._v3_validate(self._creds())

    def test_user_required(self):
        with self.assertRaisesRegex(S.SnmpError, 'user required'):
            S._v3_validate(self._creds(user=''))

    def test_des_rejected(self):
        with self.assertRaisesRegex(S.SnmpError, 'DES.*not supported'):
            S._v3_validate(self._creds(priv_proto='des'))

    def test_priv_requires_auth(self):
        with self.assertRaisesRegex(S.SnmpError, 'privacy requires auth'):
            S._v3_validate(self._creds(auth_proto='none'))

    def test_min_password_length(self):
        with self.assertRaisesRegex(S.SnmpError, 'at least 8'):
            S._v3_validate(self._creds(auth_secret='short'))

    def test_unknown_protocols(self):
        with self.assertRaisesRegex(S.SnmpError, 'unsupported auth'):
            S._v3_validate(self._creds(auth_proto='sha3'))


# ── fake SNMPv3 agent (loopback UDP) ─────────────────────────────────────────

ENGINE_ID = bytes.fromhex('80001f8880c0ffee00112233')
BOOTS, ETIME = 7, 1000


def _vb(oid, val):
    if val is None:
        v = S._encode_null()
    elif isinstance(val, int):
        v = S._encode_integer(val)
    else:
        v = S._encode_octet_string(val)
    return S._encode_tlv(S.TAG_SEQUENCE, S._encode_oid(oid) + v)


def _pdu(tag, rid, vbs):
    return S._encode_tlv(tag, (
        S._encode_integer(rid) + S._encode_integer(0) + S._encode_integer(0) +
        S._encode_tlv(S.TAG_SEQUENCE, b''.join(vbs))))


def _oid_key(oid):
    return tuple(int(x) for x in oid.split('.'))


class FakeV3Agent(threading.Thread):
    """Speaks just enough USM to exercise the client: discovery, request
    authentication/decryption, GetResponse/GETNEXT, and scripted misbehaviour."""

    TABLE = {
        '1.3.6.1.2.1.1.1.0': 'FakeOS v1 router',
        '1.3.6.1.2.1.1.5.0': 'fake-sw01',
        '1.3.6.1.2.1.1.6.0': 'lab shelf',
    }

    def __init__(self, auth_proto='none', auth_secret='', priv=False,
                 priv_secret='', misbehave=None):
        super().__init__(daemon=True)
        self.auth_proto, self.auth_secret = auth_proto, auth_secret
        self.priv, self.priv_secret = priv, priv_secret
        self.misbehave = misbehave      # 'bad_mac' | 'time_window_once' | 'wrong_digest'
        self.requests = 0
        self._stopped = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]

    def stop(self):
        self._stopped = True

    def run(self):
        while not self._stopped:
            try:
                buf, addr = self.sock.recvfrom(65536)
            except socket.timeout:
                continue
            try:
                out = self._handle(buf)
            except Exception:
                continue
            if out:
                self.sock.sendto(out, addr)
        self.sock.close()

    # -- message assembly -----------------------------------------------------
    def _send(self, msg_id, flags, msg_data, priv_params=b'', user=b''):
        if self.auth_proto != 'none' and (flags & 0x01):
            hash_fn, trunc = S._V3_AUTH[self.auth_proto]
            kul = S._usm_localize_key(hash_fn, self.auth_secret, ENGINE_ID)
            m0 = S._v3_encode(msg_id, flags, ENGINE_ID, BOOTS, ETIME, user,
                              b'\x00' * trunc, priv_params, msg_data)
            import hmac
            mac = hmac.new(kul, m0, hash_fn).digest()[:trunc]
            if self.misbehave == 'bad_mac':
                mac = bytes([mac[0] ^ 0xFF]) + mac[1:]
            return S._v3_encode(msg_id, flags, ENGINE_ID, BOOTS, ETIME, user,
                                mac, priv_params, msg_data)
        return S._v3_encode(msg_id, flags, ENGINE_ID, BOOTS, ETIME, user,
                            b'', priv_params, msg_data)

    def _report(self, msg_id, rid, stats_oid, flags=0x00):
        pdu = _pdu(S.PDU_REPORT, rid, [_vb(stats_oid, 1)])
        scoped = S._v3_scoped_pdu(ENGINE_ID, b'', pdu)
        return self._send(msg_id, flags, scoped)

    # -- request handling -----------------------------------------------------
    def _handle(self, buf):
        parts = S._v3_parse(buf)
        msg_id = parts['msg_id']
        if not parts['engine_id']:      # discovery
            return self._report(msg_id, msg_id, '1.3.6.1.6.3.15.1.1.4.0')
        self.requests += 1
        if self.misbehave == 'time_window_once' and self.requests == 1:
            return self._report(msg_id, msg_id, '1.3.6.1.6.3.15.1.1.2.0')

        # authenticate the request like a real agent
        if self.auth_proto != 'none':
            import hmac
            hash_fn, trunc = S._V3_AUTH[self.auth_proto]
            kul = S._usm_localize_key(hash_fn, self.auth_secret, ENGINE_ID)
            a = parts['auth_params_abs']
            got = parts['auth_params']
            zeroed = buf[:a] + b'\x00' * len(got) + buf[a + len(got):]
            want = hmac.new(kul, zeroed, hash_fn).digest()[:trunc]
            if got != want:
                return self._report(msg_id, msg_id, '1.3.6.1.6.3.15.1.1.5.0')

        # decrypt if needed
        data = parts['data']
        if parts['data_tag'] == S.TAG_OCTET_STRING:
            hash_fn, _tr = S._V3_AUTH[self.auth_proto]
            pkul = S._usm_localize_key(hash_fn, self.priv_secret, ENGINE_ID)
            iv = struct.pack('>II', parts['boots'], parts['time']) + parts['priv_params']
            plain = S._aes_cfb(pkul[:16], iv, data, encrypt=False)
            _t, data, _ = S._decode_tlv(plain, 0)

        # scopedPDU body → PDU
        off = 0
        _t, _ceid, off = S._decode_tlv(data, off)
        _t, _cname, off = S._decode_tlv(data, off)
        pdu_tag, pdu_body, _ = S._decode_tlv(data, off)
        inner = 0
        _t, rid_b, inner = S._decode_tlv(pdu_body, inner)
        rid = S._decode_integer(rid_b)
        _t, _es, inner = S._decode_tlv(pdu_body, inner)
        _t, _ei, inner = S._decode_tlv(pdu_body, inner)
        _t, vb_body, inner = S._decode_tlv(pdu_body, inner)
        oids = []
        vo = 0
        while vo < len(vb_body):
            _t, one, vo = S._decode_tlv(vb_body, vo)
            _t2, oid_b, _ = S._decode_tlv(one, 0)
            oids.append(S._decode_oid(oid_b))

        if pdu_tag == S.PDU_GET_NEXT:
            cur = oids[0]
            nxt = min((o for o in self.TABLE if _oid_key(o) > _oid_key(cur)),
                      key=_oid_key, default=None)
            vbs = ([_vb(nxt, self.TABLE[nxt])] if nxt
                   else [S._encode_tlv(S.TAG_SEQUENCE,
                                       S._encode_oid(cur) + S._encode_tlv(0x82, b''))])
        else:
            vbs = [_vb(o, self.TABLE.get(o, 'x')) for o in oids] or [_vb('1.3.6.1.2.1.1.5.0', 'fake-sw01')]
        pdu = _pdu(S.PDU_GET_RESPONSE, rid, vbs)
        scoped = S._v3_scoped_pdu(ENGINE_ID, b'', pdu)

        flags = 0x00
        priv_params = b''
        msg_data = scoped
        if self.auth_proto != 'none':
            flags |= 0x01
            if self.priv:
                flags |= 0x02
                hash_fn, _tr = S._V3_AUTH[self.auth_proto]
                pkul = S._usm_localize_key(hash_fn, self.priv_secret, ENGINE_ID)
                salt = os.urandom(8)
                iv = struct.pack('>II', BOOTS, ETIME) + salt
                msg_data = S._encode_octet_string(
                    S._aes_cfb(pkul[:16], iv, scoped, encrypt=True))
                priv_params = salt
        return self._send(msg_id, flags, msg_data, priv_params, parts['user'])


class _AgentCase(unittest.TestCase):
    AGENT_KW: dict = {}

    def setUp(self):
        S._V3_ENGINE_CACHE.clear()
        self.agent = FakeV3Agent(**self.AGENT_KW)
        self.agent.start()

    def tearDown(self):
        self.agent.stop()
        self.agent.join(timeout=2)


class TestNoAuthNoPriv(_AgentCase):
    AGENT_KW = {}

    def test_get(self):
        creds = {'user': 'monitor'}
        got = S.snmp_get('127.0.0.1', creds, ['1.3.6.1.2.1.1.5.0'],
                         port=self.agent.port, timeout=1.0, retries=0)
        self.assertEqual(got['1.3.6.1.2.1.1.5.0'], 'fake-sw01')

    def test_walk(self):
        creds = {'user': 'monitor'}
        got = S.snmp_walk('127.0.0.1', creds, '1.3.6.1.2.1.1',
                          port=self.agent.port, timeout=1.0, retries=0)
        self.assertEqual(got, FakeV3Agent.TABLE)

    def test_engine_cache_reused(self):
        creds = {'user': 'monitor'}
        S.snmp_get('127.0.0.1', creds, ['1.3.6.1.2.1.1.5.0'],
                   port=self.agent.port, timeout=1.0, retries=0)
        self.assertEqual(len(S._V3_ENGINE_CACHE), 1)
        ent = next(iter(S._V3_ENGINE_CACHE.values()))
        self.assertEqual(ent['engine_id'], ENGINE_ID)
        self.assertEqual(ent['boots'], BOOTS)


class TestAuthNoPriv(_AgentCase):
    AGENT_KW = {'auth_proto': 'sha256', 'auth_secret': 'authpass123'}

    def _creds(self, secret='authpass123'):
        return {'user': 'monitor', 'auth_proto': 'sha256', 'auth_secret': secret}

    def test_get_authenticated(self):
        got = S.snmp_get('127.0.0.1', self._creds(), ['1.3.6.1.2.1.1.1.0'],
                         port=self.agent.port, timeout=1.0, retries=0)
        self.assertEqual(got['1.3.6.1.2.1.1.1.0'], 'FakeOS v1 router')

    def test_wrong_password_reported(self):
        with self.assertRaisesRegex(S.SnmpError, 'wrong digest'):
            S.snmp_get('127.0.0.1', self._creds('wrongpass123'),
                       ['1.3.6.1.2.1.1.1.0'],
                       port=self.agent.port, timeout=1.0, retries=0)


class TestAuthNoPrivMd5(_AgentCase):
    AGENT_KW = {'auth_proto': 'md5', 'auth_secret': 'authpass123'}

    def test_md5_get(self):
        creds = {'user': 'monitor', 'auth_proto': 'md5', 'auth_secret': 'authpass123'}
        got = S.snmp_get('127.0.0.1', creds, ['1.3.6.1.2.1.1.5.0'],
                         port=self.agent.port, timeout=1.0, retries=0)
        self.assertEqual(got['1.3.6.1.2.1.1.5.0'], 'fake-sw01')


class TestTamperedResponse(_AgentCase):
    AGENT_KW = {'auth_proto': 'sha256', 'auth_secret': 'authpass123',
                'misbehave': 'bad_mac'}

    def test_tampered_mac_rejected(self):
        creds = {'user': 'monitor', 'auth_proto': 'sha256',
                 'auth_secret': 'authpass123'}
        with self.assertRaisesRegex(S.SnmpError, 'authentication failed'):
            S.snmp_get('127.0.0.1', creds, ['1.3.6.1.2.1.1.5.0'],
                       port=self.agent.port, timeout=1.0, retries=0)


@unittest.skipUnless(HAVE_CRYPTO, 'cryptography not installed')
class TestAuthPriv(_AgentCase):
    AGENT_KW = {'auth_proto': 'sha', 'auth_secret': 'authpass123',
                'priv': True, 'priv_secret': 'privpass123'}

    def _creds(self):
        return {'user': 'monitor', 'auth_proto': 'sha',
                'auth_secret': 'authpass123', 'priv_proto': 'aes',
                'priv_secret': 'privpass123'}

    def test_encrypted_get(self):
        got = S.snmp_get('127.0.0.1', self._creds(),
                         ['1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.6.0'],
                         port=self.agent.port, timeout=1.0, retries=0)
        self.assertEqual(got['1.3.6.1.2.1.1.5.0'], 'fake-sw01')
        self.assertEqual(got['1.3.6.1.2.1.1.6.0'], 'lab shelf')

    def test_encrypted_walk(self):
        got = S.snmp_walk('127.0.0.1', self._creds(), '1.3.6.1.2.1.1',
                          port=self.agent.port, timeout=1.0, retries=0)
        self.assertEqual(got, FakeV3Agent.TABLE)


class TestTimeWindowResync(_AgentCase):
    AGENT_KW = {'auth_proto': 'sha256', 'auth_secret': 'authpass123',
                'misbehave': 'time_window_once'}

    def test_resyncs_and_succeeds(self):
        creds = {'user': 'monitor', 'auth_proto': 'sha256',
                 'auth_secret': 'authpass123'}
        got = S.snmp_get('127.0.0.1', creds, ['1.3.6.1.2.1.1.5.0'],
                         port=self.agent.port, timeout=1.0, retries=0)
        self.assertEqual(got['1.3.6.1.2.1.1.5.0'], 'fake-sw01')
        self.assertEqual(self.agent.requests, 2)   # REPORT, then the retry


# ── api.py wiring ─────────────────────────────────────────────────────────────

def _load_api():
    spec = importlib.util.spec_from_file_location('api_snmpv3', _CGI / 'api.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestApiWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _load_api()

    def test_target_v2c_unchanged(self):
        t = self.api._device_snmp_target(
            {'ip': '192.0.2.9', 'snmp': {'enabled': True, 'community': 'pub'}})
        self.assertEqual(t, ('192.0.2.9', 'pub', 161))

    def test_target_v3_builds_creds_dict(self):
        t = self.api._device_snmp_target(
            {'ip': '192.0.2.9', 'snmp': {
                'enabled': True, 'version': '3', 'v3_user': 'monitor',
                'v3_auth_proto': 'sha256', 'v3_auth_secret': 'authpass123',
                'v3_priv_proto': 'aes', 'v3_priv_secret': 'privpass123'}})
        host, creds, port = t
        self.assertEqual(host, '192.0.2.9')
        self.assertEqual(port, 161)
        self.assertEqual(creds['user'], 'monitor')
        self.assertEqual(creds['auth_proto'], 'sha256')
        self.assertEqual(creds['priv_proto'], 'aes')

    def test_target_v3_without_user_is_none(self):
        t = self.api._device_snmp_target(
            {'ip': '192.0.2.9', 'snmp': {'enabled': True, 'version': '3'}})
        self.assertIsNone(t)

    def test_get_redaction_never_echoes_v3_secrets(self):
        # Source-level pin: the GET response must only carry has_* booleans
        # for the v3 passwords, never the values. handle_device_snmp moved to
        # snmp_device_handlers.py — read the combined source.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from apisrc import api_source
        src = api_source()
        self.assertIn("'has_v3_auth_secret': bool(snmp_cfg.get('v3_auth_secret'))", src)
        self.assertIn("'has_v3_priv_secret': bool(snmp_cfg.get('v3_priv_secret'))", src)
        self.assertNotIn("'v3_auth_secret': snmp_cfg.get", src)
        self.assertNotIn("'v3_priv_secret': snmp_cfg.get", src)


if __name__ == '__main__':
    unittest.main()
