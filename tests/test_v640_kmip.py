"""v6.4.0 — KMIP key server: daemon protocol codec, control-plane handlers,
auth gates, per-client scoping, activity log and the recovery bundle.

Two halves:
  * The SIDECAR (`server/kmip/remotepower-kmipd.py`) is loaded standalone — it
    imports nothing from api.py by design — and driven with real TTLV bytes.
  * The CONTROL PLANE (`kmip_handlers.py`, bound into api.py) is driven through
    the real handlers. Per CLAUDE.md, gate tests stub ONLY `verify_token`
    (identity): stubbing require_admin_auth would happily pass a handler with
    no gate at all, which is exactly the bug being hunted.
"""

import base64
import importlib.machinery
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

# MUST be set before api.py is exec'd — import-time ensure_default_user() writes
# to DATA_DIR, and without this the test would target a real install.
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'

_ldr = importlib.machinery.SourceFileLoader('api', str(_CGI / 'api.py'))
_spec = importlib.util.spec_from_loader('api', _ldr)
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

# The daemon has a hyphenated filename, so it is not importable normally.
_dspec = importlib.util.spec_from_file_location(
    'kmipd', str(_ROOT / 'server' / 'kmip' / 'remotepower-kmipd.py'))
kmipd = importlib.util.module_from_spec(_dspec)
_dspec.loader.exec_module(kmipd)


# ── TTLV codec + protocol ────────────────────────────────────────────────────
class TestTtlvCodec(unittest.TestCase):
    def test_round_trip_every_supported_type(self):
        items = [
            (kmipd.T_UNIQUE_IDENTIFIER, kmipd.TY_TEXT, 'uid-42'),
            (kmipd.T_KEY_MATERIAL, kmipd.TY_BYTES, b'\x00\x01\xffraw'),
            (kmipd.T_CRYPTO_LENGTH, kmipd.TY_INT, 256),
            (kmipd.T_OPERATION, kmipd.TY_ENUM, kmipd.OP_GET),
            (kmipd.T_TIME_STAMP, kmipd.TY_DATETIME, 1750000000),
            (kmipd.T_PROTOCOL_VERSION, kmipd.TY_STRUCT, [
                (kmipd.T_PROTOCOL_VERSION_MAJOR, kmipd.TY_INT, 1),
                (kmipd.T_PROTOCOL_VERSION_MINOR, kmipd.TY_INT, 4)]),
        ]
        self.assertEqual(kmipd.ttlv_decode(kmipd.ttlv_encode(items)), items)

    def test_items_are_eight_byte_aligned(self):
        """KMIP requires 8-byte alignment; a client rejects a short item."""
        blob = kmipd.ttlv_encode([(kmipd.T_UNIQUE_IDENTIFIER, kmipd.TY_TEXT, 'x')])
        self.assertEqual(len(blob) % 8, 0)

    def test_decode_rejects_overrunning_length(self):
        blob = bytearray(kmipd.ttlv_encode(
            [(kmipd.T_UNIQUE_IDENTIFIER, kmipd.TY_TEXT, 'abc')]))
        blob[4:8] = (9999).to_bytes(4, 'big')     # claim a huge payload
        with self.assertRaises(ValueError):
            kmipd.ttlv_decode(bytes(blob))


def _request(op, payload_items, pv=(1, 4)):
    """Build a one-item KMIP RequestMessage."""
    return kmipd.ttlv_encode([(kmipd.T_REQUEST_MESSAGE, kmipd.TY_STRUCT, [
        (kmipd.T_REQUEST_HEADER, kmipd.TY_STRUCT, [
            (kmipd.T_PROTOCOL_VERSION, kmipd.TY_STRUCT, [
                (kmipd.T_PROTOCOL_VERSION_MAJOR, kmipd.TY_INT, pv[0]),
                (kmipd.T_PROTOCOL_VERSION_MINOR, kmipd.TY_INT, pv[1])]),
            (kmipd.T_BATCH_COUNT, kmipd.TY_INT, 1)]),
        (kmipd.T_BATCH_ITEM, kmipd.TY_STRUCT, [
            (kmipd.T_OPERATION, kmipd.TY_ENUM, op),
            (kmipd.T_REQUEST_PAYLOAD, kmipd.TY_STRUCT, payload_items)])])])


def _batch_items(raw):
    top = kmipd.ttlv_decode(raw)
    msg = kmipd._find_val(top, kmipd.T_RESPONSE_MESSAGE)
    return [v for t, _ty, v in msg if t == kmipd.T_BATCH_ITEM]


class _FakeApi:
    """Stand-in for the loopback control plane."""

    def __init__(self, reply=None):
        self.calls = []
        self.events = []
        self.reply = reply or {'ok': True}

    def op(self, payload):
        self.calls.append(payload)
        return self.reply

    def event(self, payload):
        self.events.append(payload)


_CLIENT = {'id': 'kc-abc', 'name': 'nas-01', 'fingerprint': 'ff' * 32}


class TestDaemonProtocol(unittest.TestCase):
    def test_query_and_discover_need_no_control_plane(self):
        """A client's first two calls must work even if the API is down —
        otherwise a restart storm looks like a protocol failure."""
        class _Dead:
            def op(self, p):
                raise AssertionError('must not call the control plane')

        for raw in (_request(kmipd.OP_QUERY, []),
                    _request(kmipd.OP_DISCOVER_VERSIONS, [])):
            items = _batch_items(kmipd.handle_message(raw, _CLIENT, _Dead()))
            self.assertEqual(len(items), 1)
            self.assertEqual(kmipd._find_val(items[0], kmipd.T_RESULT_STATUS),
                             kmipd.RS_SUCCESS)

    def test_query_advertises_every_supported_operation(self):
        raw = _request(kmipd.OP_QUERY, [(kmipd.T_QUERY_FUNCTION, kmipd.TY_ENUM, 1)])
        payload = kmipd._find_val(_batch_items(
            kmipd.handle_message(raw, _CLIENT, _FakeApi()))[0],
            kmipd.T_RESPONSE_PAYLOAD)
        advertised = {v for t, _ty, v in payload if t == kmipd.T_OPERATION}
        self.assertEqual(advertised, set(kmipd.OP_NAMES))

    def test_register_forwards_material_and_returns_uid(self):
        material = b'\x01\x02\x03\x04' * 8
        raw = _request(kmipd.OP_REGISTER, [
            (kmipd.T_SYMMETRIC_KEY, kmipd.TY_STRUCT, [
                (kmipd.T_KEY_BLOCK, kmipd.TY_STRUCT, [
                    (kmipd.T_KEY_FORMAT_TYPE, kmipd.TY_ENUM, kmipd.KF_RAW),
                    (kmipd.T_KEY_VALUE, kmipd.TY_STRUCT, [
                        (kmipd.T_KEY_MATERIAL, kmipd.TY_BYTES, material)]),
                    (kmipd.T_CRYPTO_ALGORITHM, kmipd.TY_ENUM, 3),
                    (kmipd.T_CRYPTO_LENGTH, kmipd.TY_INT, 256)])])])
        fake = _FakeApi({'ok': True, 'uid': '7'})
        items = _batch_items(kmipd.handle_message(raw, _CLIENT, fake))
        self.assertEqual(kmipd._find_val(items[0], kmipd.T_RESULT_STATUS),
                         kmipd.RS_SUCCESS)
        call = fake.calls[0]
        self.assertEqual(call['op'], 'register')
        self.assertEqual(call['client_id'], 'kc-abc')
        self.assertEqual(base64.b64decode(call['params']['material_b64']), material)
        self.assertEqual(call['params']['object_type'], 'symmetric_key')

    def test_register_parses_transparent_symmetric_key_material(self):
        """DSM sends TransparentSymmetricKey (a nested struct), not raw bytes —
        reading only the raw form would drop the key silently."""
        material = b'k' * 32
        raw = _request(kmipd.OP_REGISTER, [
            (kmipd.T_SYMMETRIC_KEY, kmipd.TY_STRUCT, [
                (kmipd.T_KEY_BLOCK, kmipd.TY_STRUCT, [
                    (kmipd.T_KEY_FORMAT_TYPE, kmipd.TY_ENUM,
                     kmipd.KF_TRANSPARENT_SYMMETRIC),
                    (kmipd.T_KEY_VALUE, kmipd.TY_STRUCT, [
                        (kmipd.T_KEY_MATERIAL, kmipd.TY_STRUCT, [
                            (kmipd.T_KEY, kmipd.TY_BYTES, material)])])])])])
        fake = _FakeApi({'ok': True, 'uid': '1'})
        kmipd.handle_message(raw, _CLIENT, fake)
        self.assertEqual(
            base64.b64decode(fake.calls[0]['params']['material_b64']), material)

    def test_get_returns_the_material_in_a_key_block(self):
        material = b'\xaa' * 32
        fake = _FakeApi({'ok': True, 'object': {
            'uid': '3', 'object_type': 'symmetric_key', 'key_format': 1,
            'algorithm': 3, 'length': 256, 'state': 'active',
            'material_b64': base64.b64encode(material).decode()}})
        raw = _request(kmipd.OP_GET,
                       [(kmipd.T_UNIQUE_IDENTIFIER, kmipd.TY_TEXT, '3')])
        payload = kmipd._find_val(_batch_items(
            kmipd.handle_message(raw, _CLIENT, fake))[0], kmipd.T_RESPONSE_PAYLOAD)
        sym = kmipd._find_val(payload, kmipd.T_SYMMETRIC_KEY)
        kb = kmipd._find_val(sym, kmipd.T_KEY_BLOCK)
        kv = kmipd._find_val(kb, kmipd.T_KEY_VALUE)
        self.assertEqual(kmipd._find_val(kv, kmipd.T_KEY_MATERIAL), material)

    def test_id_placeholder_chains_locate_into_get(self):
        """KMIP lets a batch omit the uid and reuse the previous result."""
        fake = _FakeApi({'ok': True, 'uids': ['9']})
        raw = _request(kmipd.OP_LOCATE, [])
        kmipd.handle_message(raw, _CLIENT, fake)
        result, placeholder = kmipd._handle_op(
            kmipd.OP_LOCATE, [], _CLIENT, fake, None)
        self.assertEqual(placeholder, '9')

    def test_control_plane_failure_becomes_a_kmip_error_not_a_crash(self):
        class _Broken:
            def op(self, p):
                raise OSError('connection refused')

        raw = _request(kmipd.OP_GET,
                       [(kmipd.T_UNIQUE_IDENTIFIER, kmipd.TY_TEXT, '1')])
        items = _batch_items(kmipd.handle_message(raw, _CLIENT, _Broken()))
        self.assertEqual(kmipd._find_val(items[0], kmipd.T_RESULT_STATUS),
                         kmipd.RS_FAILED)
        self.assertEqual(kmipd._find_val(items[0], kmipd.T_RESULT_REASON),
                         kmipd.RR_GENERAL_FAILURE)

    def test_api_reason_maps_to_the_kmip_result_reason(self):
        fake = _FakeApi({'ok': False, 'reason': 'not_found', 'message': 'nope'})
        raw = _request(kmipd.OP_GET,
                       [(kmipd.T_UNIQUE_IDENTIFIER, kmipd.TY_TEXT, '1')])
        items = _batch_items(kmipd.handle_message(raw, _CLIENT, fake))
        self.assertEqual(kmipd._find_val(items[0], kmipd.T_RESULT_REASON),
                         kmipd.RR_ITEM_NOT_FOUND)

    def test_malformed_request_gets_a_response_not_an_exception(self):
        items = _batch_items(kmipd.handle_message(b'\x00' * 16, _CLIENT, _FakeApi()))
        self.assertEqual(kmipd._find_val(items[0], kmipd.T_RESULT_STATUS),
                         kmipd.RS_FAILED)

    def test_unsupported_operation_is_reported_as_such(self):
        raw = _request(0x99, [])
        items = _batch_items(kmipd.handle_message(raw, _CLIENT, _FakeApi()))
        self.assertEqual(kmipd._find_val(items[0], kmipd.T_RESULT_REASON),
                         kmipd.RR_OP_NOT_SUPPORTED)

    def test_response_echoes_the_negotiated_protocol_version(self):
        raw = _request(kmipd.OP_QUERY, [], pv=(1, 2))
        top = kmipd.ttlv_decode(kmipd.handle_message(raw, _CLIENT, _FakeApi()))
        header = kmipd._find_val(
            kmipd._find_val(top, kmipd.T_RESPONSE_MESSAGE), kmipd.T_RESPONSE_HEADER)
        pv = kmipd._find_val(header, kmipd.T_PROTOCOL_VERSION)
        self.assertEqual(kmipd._find_val(pv, kmipd.T_PROTOCOL_VERSION_MINOR), 2)


# ── control plane ────────────────────────────────────────────────────────────
class _KmipHandlerCase(unittest.TestCase):
    """Drives the real handlers; only identity is stubbed."""

    def setUp(self):
        self.cap = {}
        self._real = {
            'respond': api.respond,
            'verify_token': api.verify_token,
            'audit_log': api.audit_log,
            'env': api._env,
            'method': api.method,
        }
        self.headers = {}
        self.env_extra = {}

        def _resp(status, body=None):
            self.cap['s'], self.cap['b'] = status, body
            raise api.HTTPError(status, body)
        api.respond = _resp
        api.audit_log = lambda *a, **k: None
        api._env = lambda k, d='': (self.env_extra.get(k)
                                    or self.headers.get(k) or d)
        api.method = lambda: self.env_extra.get('REQUEST_METHOD', 'POST')
        # A real admin identity — the gates themselves are NOT stubbed.
        # verify_token returns (username, role); require_auth resolves the role
        # record itself, so the admin check is the REAL one.
        api.verify_token = lambda *a, **k: ('admin', 'admin')

        for f in (api.KMIP_FILE, api.KMIP_OBJECTS_FILE, api.KMIP_LOG_FILE):
            api.save(f, {})
        try:
            api.KMIP_MASTER_KEY_FILE.unlink()
        except OSError:
            pass
        os.environ['RP_KMIP_SECRET'] = 'unit-test-secret'

    def tearDown(self):
        api.respond = self._real['respond']
        api.verify_token = self._real['verify_token']
        api.audit_log = self._real['audit_log']
        api._env = self._real['env']
        api.method = self._real['method']
        os.environ.pop('RP_KMIP_SECRET', None)

    def call(self, fn, *a, method='POST', body=None, headers=None):
        self.cap.clear()
        self.env_extra['REQUEST_METHOD'] = method
        self.headers = headers or {}
        if body is not None:
            api.get_json_obj = lambda: body
            api._read_valid = lambda model: body
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')

    def enable_kmip(self):
        return self.call(api.handle_kmip_config,
                         body={'enabled': True, 'port': 5696, 'hosts': 'kms.test'})

    def daemon_hdr(self):
        return {'HTTP_X_KMIP_SECRET': 'unit-test-secret'}


class TestDaemonChecksInWhileIdle(unittest.TestCase):
    """Field bug: "Installed, but the sidecar has not checked in" about a
    daemon that was running fine.

    The state fetch IS the heartbeat, but it only ran lazily when a client
    connected — and the accept loop BLOCKS in sock.accept(). With no KMIP
    clients yet (the normal state right after install) the daemon never called
    the control plane at all. The poll has to be driven by a clock, not by
    traffic.
    """

    class _CountingApi:
        def __init__(self):
            self.calls = 0

        def state(self):
            self.calls += 1
            return {'enabled': False, 'rev': 0, 'port': 5696, 'clients': []}

    def test_a_single_tick_calls_the_control_plane(self):
        api_ = self._CountingApi()
        st = kmipd.ServerState(api_)
        self.assertEqual(api_.calls, 0)
        kmipd.state_refresher(st, once=True)
        self.assertEqual(api_.calls, 1, 'the heartbeat must not need traffic')

    class _LetNTicks:
        """Stop-event stand-in that allows exactly N loop passes.

        Deterministic on purpose — an earlier version of this test slept and
        counted real ticks, which passed alone and failed under parallel load.
        A wall-clock assertion in a test suite is a flake generator, and a
        flaky guardrail is worse than none: it trains you to ignore it.
        """

        def __init__(self, n):
            self.left = n

        def wait(self, timeout=None):
            self.left -= 1
            return self.left <= 0

    def test_it_keeps_ticking_with_no_client_ever_connecting(self):
        api_ = self._CountingApi()
        kmipd.state_refresher(kmipd.ServerState(api_), stop=self._LetNTicks(3))
        self.assertEqual(api_.calls, 3,
                         'must poll once per tick while idle, not once ever')

    def test_refresher_survives_a_control_plane_error(self):
        """A thrown exception must not kill the heartbeat thread — that would
        turn a transient API restart into a permanently 'dead' sidecar."""
        class _Broken:
            def __init__(self):
                self.calls = 0

            def state(self):
                self.calls += 1
                raise OSError('connection refused')
        api_ = _Broken()
        kmipd.state_refresher(kmipd.ServerState(api_), once=True)
        self.assertEqual(api_.calls, 1)      # returned normally, no raise

    def test_serve_starts_the_refresher_thread(self):
        """Source pin: the wiring is what actually fixes the reported bug."""
        src = (_ROOT / 'server' / 'kmip' / 'remotepower-kmipd.py').read_text()
        serve = src[src.index('def serve('):]
        self.assertIn('target=state_refresher', serve,
                      'serve() must start the heartbeat thread')
        self.assertIn('daemon=True', serve)

    def test_rejected_secret_is_logged_loudly(self):
        """A 403 is the one failure an operator cannot guess from outside."""
        src = (_ROOT / 'server' / 'kmip' / 'remotepower-kmipd.py').read_text()
        self.assertIn("getattr(e, 'code', None) == 403", src)
        self.assertIn('REJECTED our secret', src)


class TestDaemonSecretResolution(unittest.TestCase):
    """Field bug: the sidecar ran fine but the page said "Not installed".

    The install snippet derived the env file's group from `api.env` — which is
    root:root, because only systemd ever reads THAT too — so kmipd.env landed
    unreadable by the gunicorn user. The API then saw no secret, reported the
    sidecar missing, and 403'd every daemon state fetch. The API must never
    depend on reading a root-owned file: systemd feeds it to the daemon as
    root, so the API keeps its own copy in config.
    """

    def setUp(self):
        self._etc = tempfile.mkdtemp()
        self._envf = Path(self._etc) / 'kmipd.env'
        self._prev = (os.environ.get('RP_KMIP_SECRET_FILE'),
                      os.environ.get('RP_KMIP_SECRET'))
        os.environ['RP_KMIP_SECRET_FILE'] = str(self._envf)
        os.environ.pop('RP_KMIP_SECRET', None)
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def tearDown(self):
        for k, v in zip(('RP_KMIP_SECRET_FILE', 'RP_KMIP_SECRET'), self._prev):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _set_config_secret(self, value):
        with api._LockedUpdate(api.CONFIG_FILE) as cfg:
            cfg['kmip_daemon_secret'] = value
        api._invalidate_load_cache(api.CONFIG_FILE)

    def test_config_secret_works_with_no_readable_file(self):
        """THE regression: file unreadable/absent, API still knows the secret."""
        self._set_config_secret('cfg-secret')
        self.assertEqual(api._kmip_daemon_secret(), 'cfg-secret')

    def test_readable_file_wins_and_is_adopted(self):
        """systemd hands the FILE's value to the daemon, so it must win — and
        get copied into config so a later permission change can't blind us."""
        self._set_config_secret('stale-cfg')
        self._envf.write_text('RP_KMIP_SECRET=from-file\n')
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(api._kmip_daemon_secret(), 'from-file')
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual((api.load(api.CONFIG_FILE) or {}).get('kmip_daemon_secret'),
                         'from-file', 'a readable file must be adopted into config')

    def test_env_beats_everything(self):
        self._set_config_secret('cfg')
        self._envf.write_text('RP_KMIP_SECRET=file\n')
        os.environ['RP_KMIP_SECRET'] = 'env'
        self.assertEqual(api._kmip_daemon_secret(), 'env')

    def test_snippet_persists_and_never_rotates(self):
        """Re-opening the dialog must not mint a new secret — that would
        silently invalidate a working install the moment someone looked."""
        cap = {}
        real_resp, real_vt, real_env, real_method = (
            api.respond, api.verify_token, api._env, api.method)

        def _resp(s, b=None):
            cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.verify_token = lambda *a, **k: ('admin', 'admin')
        api._env = lambda k, d='': d
        api.method = lambda: 'GET'
        try:
            def snippet():
                cap.clear()
                try:
                    api.handle_kmip_install_snippet()
                except api.HTTPError:
                    pass
                return cap['b']['snippet']
            first, second = snippet(), snippet()
            self.assertEqual(first, second, 'snippet must be stable')
            stored = (api.load(api.CONFIG_FILE) or {}).get('kmip_daemon_secret')
            self.assertTrue(stored, 'the snippet must persist the secret')
            self.assertIn(stored, first, 'the snippet must show the STORED secret')
            self.assertIn('-o root -g root -m 600', first,
                          'the env file needs no group grant — systemd reads '
                          'it as root')
            self.assertNotIn('api.env', first,
                             "never derive a group from api.env — it is "
                             "root:root and says nothing about the app user")
        finally:
            (api.respond, api.verify_token, api._env, api.method) = (
                real_resp, real_vt, real_env, real_method)

    def test_secret_is_redacted_from_config_reads(self):
        self._set_config_secret('top-secret-value')
        scrubbed = dict(api.load(api.CONFIG_FILE) or {})
        api._scrub_config_secrets(scrubbed)
        self.assertNotIn('kmip_daemon_secret', scrubbed)

    def test_no_secret_anywhere_is_falsy(self):
        self.assertEqual(api._kmip_daemon_secret(), '')


class TestKmipSetupAndPki(_KmipHandlerCase):
    def test_enabling_generates_master_key_ca_and_server_cert(self):
        out = self.enable_kmip()
        self.assertTrue(out['enabled'])
        self.assertTrue(out['master_key'])
        self.assertTrue(out['ca'])
        self.assertTrue(out['server_cert'])
        self.assertIn('kms.test', out['server_cert']['hosts'])

    def test_master_key_file_is_0600(self):
        self.enable_kmip()
        mode = api.KMIP_MASTER_KEY_FILE.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600, 'KMIP master key must not be group/world readable')

    def test_ca_private_key_is_encrypted_at_rest(self):
        self.enable_kmip()
        raw = json.dumps(api.load(api.KMIP_FILE))
        self.assertNotIn('PRIVATE KEY', raw,
                         'CA/server private keys must never be stored in cleartext')
        self.assertIn('key_enc', json.dumps(api.load(api.KMIP_FILE)['ca']))

    def test_status_is_readable_without_leaking_key_material(self):
        self.enable_kmip()
        out = self.call(api.handle_kmip_status, method='GET')
        blob = json.dumps(out)
        self.assertNotIn('PRIVATE KEY', blob)
        self.assertNotIn('key_enc', blob)


class TestCryptographyVersionCompat(unittest.TestCase):
    """`not_valid_after_utc` only exists from cryptography 42 (Jan 2024).
    Debian 12 ships 38.x, where reading it raises AttributeError — which
    surfaced as a bare 500 the first time an operator clicked Enable on a
    stock distro. The read must work across the supported range."""

    def test_expiry_reader_handles_the_pre_42_api(self):
        class _Old:
            """A cert exposing only the legacy naive property."""
            import datetime as _d
            not_valid_after = _d.datetime(2030, 1, 1, 12, 0, 0)

        got = api._cert_not_after_epoch(_Old())
        import datetime as _dt
        want = int(_dt.datetime(2030, 1, 1, 12, 0, 0,
                                tzinfo=_dt.timezone.utc).timestamp())
        self.assertEqual(got, want,
                         'a naive not_valid_after is UTC — do not let the '
                         'local timezone shift the recorded expiry')

    def test_expiry_reader_prefers_the_modern_api(self):
        import datetime as _dt
        aware = _dt.datetime(2031, 6, 1, tzinfo=_dt.timezone.utc)

        class _New:
            not_valid_after_utc = aware
            not_valid_after = _dt.datetime(1999, 1, 1)   # must be ignored
        self.assertEqual(api._cert_not_after_epoch(_New()),
                         int(aware.timestamp()))

    def test_builder_is_fed_naive_utc(self):
        """The builder takes naive UTC on every version; that keeps one code
        path from 38.x through current."""
        src = (_CGI / 'kmip_handlers.py').read_text()
        self.assertIn('def _kmip_utcnow', src)
        self.assertIn('replace(tzinfo=None)', src)
        self.assertNotIn('now = dt.datetime.now(dt.timezone.utc)', src)

    def test_no_raw_utc_property_reads_remain(self):
        src = (_CGI / 'kmip_handlers.py').read_text()
        code = '\n'.join(l for l in src.splitlines()
                          if not l.lstrip().startswith('#'))
        self.assertNotIn('cert.not_valid_after_utc', code,
                         'read expiry through _cert_not_after_epoch')


class TestKmipClients(_KmipHandlerCase):
    def _new_client(self, name='nas-01', kind='synology'):
        return self.call(api.handle_kmip_client_create,
                         body={'name': name, 'kind': kind})

    def test_client_create_returns_a_usable_bundle_once(self):
        self.enable_kmip()
        out = self._new_client()
        for k in ('ca_pem', 'cert_pem', 'key_pem', 'fingerprint', 'id'):
            self.assertIn(k, out)
        self.assertIn('BEGIN PRIVATE KEY', out['key_pem'])
        # ...and the private key is NOT retained server-side.
        stored = api.load(api.KMIP_FILE)['clients'][out['id']]
        self.assertNotIn('key_pem', stored)

    def test_client_id_is_non_numeric_by_construction(self):
        """A numeric-looking id is coerced to Number by the data-arg
        dispatcher, corrupting it before the handler sees it."""
        self.enable_kmip()
        cid = self._new_client()['id']
        self.assertTrue(cid.startswith('kc-'))
        self.assertFalse(cid.replace('-', '').isdigit())

    def test_unknown_kind_is_rejected(self):
        self.enable_kmip()
        self.call(api.handle_kmip_client_create,
                  body={'name': 'x', 'kind': 'nope'})
        self.assertEqual(self.cap['s'], 400)

    def test_reissue_keeps_the_client_id_so_keys_survive(self):
        self.enable_kmip()
        first = self._new_client()
        again = self.call(api.handle_kmip_client_reissue, first['id'])
        self.assertEqual(again['id'], first['id'])
        self.assertNotEqual(again['fingerprint'], first['fingerprint'])

    def test_revoke_marks_the_client_and_daemon_state_reflects_it(self):
        self.enable_kmip()
        cid = self._new_client()['id']
        self.call(api.handle_kmip_client_revoke, cid)
        state = self.call(api.handle_kmip_daemon_state, method='GET',
                          headers=self.daemon_hdr())
        entry = [c for c in state['clients'] if c['id'] == cid][0]
        self.assertTrue(entry['revoked'])

    def test_reissue_of_a_missing_client_404s(self):
        self.enable_kmip()
        self.call(api.handle_kmip_client_reissue, 'kc-nope')
        self.assertEqual(self.cap['s'], 404)


class TestKmipDaemonAuth(_KmipHandlerCase):
    """The daemon endpoints are the only unauthenticated-by-session surface."""

    def test_state_requires_the_shared_secret(self):
        self.enable_kmip()
        self.call(api.handle_kmip_daemon_state, method='GET', headers={})
        self.assertEqual(self.cap['s'], 403)

    def test_wrong_secret_is_rejected(self):
        self.enable_kmip()
        self.call(api.handle_kmip_daemon_state, method='GET',
                  headers={'HTTP_X_KMIP_SECRET': 'wrong'})
        self.assertEqual(self.cap['s'], 403)

    def test_op_requires_the_shared_secret(self):
        self.enable_kmip()
        self.call(api.handle_kmip_daemon_op, body={'op': 'get'}, headers={})
        self.assertEqual(self.cap['s'], 403)

    def test_state_serves_tls_material_only_over_the_secret(self):
        self.enable_kmip()
        out = self.call(api.handle_kmip_daemon_state, method='GET',
                        headers=self.daemon_hdr())
        self.assertIn('BEGIN PRIVATE KEY', out['server_key_pem'])
        self.assertIn('BEGIN CERTIFICATE', out['ca_pem'])


class TestKmipOperations(_KmipHandlerCase):
    def setUp(self):
        super().setUp()
        self.enable_kmip()
        self.c1 = self.call(api.handle_kmip_client_create,
                            body={'name': 'nas-01', 'kind': 'synology'})
        self.c2 = self.call(api.handle_kmip_client_create,
                            body={'name': 'nas-02', 'kind': 'truenas'})

    def op(self, client, op, params=None):
        return self.call(api.handle_kmip_daemon_op, headers=self.daemon_hdr(),
                         body={'client_id': client['id'],
                               'fingerprint': client['fingerprint'],
                               'op': op, 'params': params or {}})

    def test_register_then_get_round_trips_the_material(self):
        material = b'\x11' * 32
        reg = self.op(self.c1, 'register', {
            'material_b64': base64.b64encode(material).decode(),
            'object_type': 'symmetric_key', 'name': 'vol1'})
        self.assertTrue(reg['ok'])
        got = self.op(self.c1, 'get', {'uid': reg['uid']})
        self.assertEqual(base64.b64decode(got['object']['material_b64']), material)

    def test_material_is_encrypted_in_the_store(self):
        material = b'SUPERSECRETKEYMATERIAL0123456789'
        self.op(self.c1, 'register', {
            'material_b64': base64.b64encode(material).decode()})
        raw = json.dumps(api.load(api.KMIP_OBJECTS_FILE))
        self.assertNotIn(base64.b64encode(material).decode(), raw)
        self.assertNotIn(material.decode(), raw)

    def test_create_generates_a_key_of_the_requested_length(self):
        out = self.op(self.c1, 'create', {'length': 256, 'algorithm': 3})
        got = self.op(self.c1, 'get', {'uid': out['uid']})
        self.assertEqual(len(base64.b64decode(got['object']['material_b64'])), 32)

    def test_a_client_cannot_read_another_clients_key(self):
        reg = self.op(self.c1, 'register', {
            'material_b64': base64.b64encode(b'x' * 32).decode()})
        stolen = self.op(self.c2, 'get', {'uid': reg['uid']})
        self.assertFalse(stolen['ok'])
        self.assertEqual(stolen['reason'], 'not_found')

    def test_locate_only_returns_the_callers_own_objects(self):
        self.op(self.c1, 'register', {
            'material_b64': base64.b64encode(b'a' * 32).decode(), 'name': 'shared'})
        self.assertEqual(self.op(self.c2, 'locate', {'name': 'shared'})['uids'], [])

    def test_revoked_client_is_refused_even_with_a_valid_fingerprint(self):
        self.call(api.handle_kmip_client_revoke, self.c1['id'])
        out = self.op(self.c1, 'create', {'length': 256})
        self.assertFalse(out['ok'])
        self.assertEqual(out['reason'], 'denied')

    def test_fingerprint_mismatch_is_refused(self):
        out = self.call(api.handle_kmip_daemon_op, headers=self.daemon_hdr(),
                        body={'client_id': self.c1['id'], 'fingerprint': 'ab' * 32,
                              'op': 'create', 'params': {'length': 256}})
        self.assertFalse(out['ok'])
        self.assertEqual(out['reason'], 'denied')

    def test_disabled_server_refuses_every_operation(self):
        self.call(api.handle_kmip_config, body={'enabled': False, 'port': 5696})
        out = self.op(self.c1, 'create', {'length': 256})
        self.assertFalse(out['ok'])
        self.assertEqual(out['reason'], 'denied')

    def test_activate_then_destroy_is_refused_while_active(self):
        reg = self.op(self.c1, 'create', {'length': 256})
        self.op(self.c1, 'activate', {'uid': reg['uid']})
        out = self.op(self.c1, 'destroy', {'uid': reg['uid']})
        self.assertFalse(out['ok'], 'KMIP forbids destroying an Active object')
        self.op(self.c1, 'revoke', {'uid': reg['uid'], 'reason_code': 1})
        self.assertTrue(self.op(self.c1, 'destroy', {'uid': reg['uid']})['ok'])

    def test_destroyed_key_can_no_longer_be_fetched(self):
        reg = self.op(self.c1, 'create', {'length': 256})
        self.op(self.c1, 'destroy', {'uid': reg['uid']})
        out = self.op(self.c1, 'get', {'uid': reg['uid']})
        self.assertFalse(out['ok'])
        self.assertEqual(out['reason'], 'state')

    def test_oversized_material_is_rejected(self):
        out = self.op(self.c1, 'register', {
            'material_b64': base64.b64encode(b'x' * 70000).decode()})
        self.assertFalse(out['ok'])

    def test_admin_key_list_never_exposes_material(self):
        self.op(self.c1, 'register', {
            'material_b64': base64.b64encode(b'z' * 32).decode()})
        out = self.call(api.handle_kmip_keys, method='GET')
        self.assertTrue(out['keys'])
        self.assertNotIn('material', json.dumps(out))


class TestKmipActivityLog(_KmipHandlerCase):
    """Every action must be traceable — for review and for debugging."""

    def setUp(self):
        super().setUp()
        self.enable_kmip()
        self.c1 = self.call(api.handle_kmip_client_create,
                            body={'name': 'nas-01', 'kind': 'synology'})

    def entries(self):
        return self.call(api.handle_kmip_log_list, method='GET')['entries']

    def test_admin_actions_are_logged(self):
        kinds = {(e.get('kind'), e.get('op')) for e in self.entries()}
        self.assertIn(('admin', 'config'), kinds)
        self.assertIn(('admin', 'client_create'), kinds)

    def test_key_operations_are_logged_with_client_and_uid(self):
        reg = self.call(api.handle_kmip_daemon_op, headers=self.daemon_hdr(),
                        body={'client_id': self.c1['id'],
                              'fingerprint': self.c1['fingerprint'],
                              'op': 'create', 'params': {'length': 256}})
        hit = [e for e in self.entries()
               if e.get('kind') == 'op' and e.get('uid') == reg['uid']]
        self.assertTrue(hit, 'a key operation must appear in the activity log')
        self.assertEqual(hit[0]['client'], 'nas-01')

    def test_rejected_client_is_logged_as_an_auth_failure(self):
        self.call(api.handle_kmip_daemon_op, headers=self.daemon_hdr(),
                  body={'client_id': 'kc-ghost', 'fingerprint': 'ab' * 32,
                        'op': 'get', 'params': {'uid': '1'}})
        self.assertTrue([e for e in self.entries() if e.get('kind') == 'auth_fail'])

    def test_daemon_events_are_logged(self):
        self.call(api.handle_kmip_daemon_event, headers=self.daemon_hdr(),
                  body={'kind': 'auth_fail', 'peer': '10.0.0.9',
                        'detail': 'unknown client certificate'})
        hit = [e for e in self.entries() if e.get('peer') == '10.0.0.9']
        self.assertTrue(hit)

    def test_unknown_event_kind_is_rejected(self):
        self.call(api.handle_kmip_daemon_event, headers=self.daemon_hdr(),
                  body={'kind': 'made-up'})
        self.assertEqual(self.cap['s'], 400)

    def test_log_is_capped(self):
        api.save(api.KMIP_LOG_FILE,
                 {'entries': [{'ts': 1, 'kind': 'op'}] * (api.MAX_KMIP_LOG + 50)})
        api._kmip_log('op', op='create')
        self.assertLessEqual(
            len(api.load(api.KMIP_LOG_FILE)['entries']), api.MAX_KMIP_LOG)


class TestKmipRecoveryBundle(_KmipHandlerCase):
    def setUp(self):
        super().setUp()
        self.enable_kmip()
        self.c1 = self.call(api.handle_kmip_client_create,
                            body={'name': 'nas-01', 'kind': 'synology'})
        self.material = b'\x42' * 32
        self.reg = self.call(
            api.handle_kmip_daemon_op, headers=self.daemon_hdr(),
            body={'client_id': self.c1['id'],
                  'fingerprint': self.c1['fingerprint'], 'op': 'register',
                  'params': {'material_b64':
                             base64.b64encode(self.material).decode()}})

    def _export(self, passphrase='correct horse battery'):
        """handle_kmip_export writes the bytes straight to stdout and exits."""
        import io
        import sys
        buf = io.BytesIO()

        class _Out:
            buffer = buf

            def write(self, *a):
                pass

            def flush(self):
                pass

        real_out, real_exit = sys.stdout, sys.exit
        sys.stdout = _Out()
        sys.exit = lambda *a: (_ for _ in ()).throw(SystemExit(0))
        try:
            api.handle_kmip_export()
        except (SystemExit, api.HTTPError):
            pass
        finally:
            sys.stdout, sys.exit = real_out, real_exit
        return buf.getvalue()

    def test_short_passphrase_is_rejected(self):
        self.call(api.handle_kmip_export, body={'passphrase': 'short'})
        self.assertEqual(self.cap['s'], 400)

    def test_bundle_is_encrypted_and_restores_the_keys(self):
        self.cap.clear()
        self.env_extra['REQUEST_METHOD'] = 'POST'
        self.headers = {}
        body = {'passphrase': 'correct horse battery'}
        api.get_json_obj = lambda: body
        api._read_valid = lambda model: body
        blob = self._export()
        self.assertTrue(blob, 'export produced no bytes')
        # Encrypted: neither the key material nor the JSON structure is visible.
        self.assertNotIn(base64.b64encode(self.material), blob)
        self.assertNotIn(b'master_key_hex', blob)

        # Wipe the server, then restore.
        api.save(api.KMIP_FILE, {})
        api.save(api.KMIP_OBJECTS_FILE, {})
        api.KMIP_MASTER_KEY_FILE.unlink()

        out = self.call(api.handle_kmip_import,
                        body={'passphrase': 'correct horse battery',
                              'bundle_b64': base64.b64encode(blob).decode()})
        self.assertTrue(out['ok'])
        self.assertEqual(out['objects'], 1)
        self.assertEqual(out['clients'], 1)
        # The restored key still decrypts to the original material.
        got = self.call(api.handle_kmip_daemon_op, headers=self.daemon_hdr(),
                        body={'client_id': self.c1['id'],
                              'fingerprint': self.c1['fingerprint'],
                              'op': 'get', 'params': {'uid': self.reg['uid']}})
        self.assertEqual(base64.b64decode(got['object']['material_b64']),
                         self.material)

    def test_wrong_passphrase_is_refused(self):
        body = {'passphrase': 'correct horse battery'}
        api.get_json_obj = lambda: body
        api._read_valid = lambda model: body
        blob = self._export()
        self.call(api.handle_kmip_import,
                  body={'passphrase': 'wrong passphrase here',
                        'bundle_b64': base64.b64encode(blob).decode()})
        self.assertEqual(self.cap['s'], 400)

    def test_import_refuses_to_clobber_a_live_store_without_confirm(self):
        body = {'passphrase': 'correct horse battery'}
        api.get_json_obj = lambda: body
        api._read_valid = lambda model: body
        blob = self._export()
        out = self.call(api.handle_kmip_import,
                        body={'passphrase': 'correct horse battery',
                              'bundle_b64': base64.b64encode(blob).decode()})
        self.assertEqual(self.cap['s'], 409)
        self.assertTrue(out['needs_confirm'])

    def test_non_bundle_input_is_rejected(self):
        self.call(api.handle_kmip_import,
                  body={'passphrase': 'correct horse battery',
                        'bundle_b64': base64.b64encode(b'not a bundle').decode()})
        self.assertEqual(self.cap['s'], 400)


class TestKmipBackupExclusion(unittest.TestCase):
    """The master key must never ride into a generic backup — otherwise one
    stolen archive holds both the ciphertext and the key to it."""

    def test_master_key_is_in_the_download_filter_exclude_set(self):
        self.assertIn('kmip_master.key', api._BACKUP_EXCLUDE_NAMES)

    def test_master_key_is_excluded_from_the_tarball_walk(self):
        src = (_CGI / 'backups_handlers.py').read_text()
        self.assertIn("excluded_names = {'backups', 'kmip_master.key'}", src)

    def test_encrypted_objects_still_ride_into_backups(self):
        """Only the KEY is withheld — the ciphertext is still backed up, or a
        restore would silently lose every stored object."""
        self.assertNotIn('kmip_objects.json', api._BACKUP_EXCLUDE_NAMES)


# ── wiring ───────────────────────────────────────────────────────────────────
class TestModuleWiring(unittest.TestCase):
    def test_handlers_come_from_the_bound_module(self):
        import inspect
        for n in ('handle_kmip_status', 'handle_kmip_config',
                  'handle_kmip_daemon_op', 'handle_kmip_export',
                  '_kmip_log', '_kmip_master_key'):
            fn = getattr(api, n, None)
            self.assertTrue(callable(fn), f'{n} not bound into api')
            self.assertEqual(fn.__module__, 'kmip_handlers',
                             f'{n} must live in the kmip_handlers module')
            inspect.getsource(fn)

    def test_routes_registered(self):
        routes = api._build_exact_routes()
        for r in (('GET', '/api/kmip/status'), ('POST', '/api/kmip/config'),
                  ('GET', '/api/kmip/clients'), ('POST', '/api/kmip/clients'),
                  ('GET', '/api/kmip/keys'), ('GET', '/api/kmip/log'),
                  ('POST', '/api/kmip/export'), ('POST', '/api/kmip/import'),
                  ('GET', '/api/kmip/daemon/state'),
                  ('POST', '/api/kmip/daemon/op'),
                  ('POST', '/api/kmip/daemon/event')):
            self.assertIn(r, routes, f'{r} not registered')

    def test_pattern_routes_registered(self):
        pats = {(a, b) for kind, methods, a, b, fn in api._build_pattern_routes()
                if a and a.startswith('/api/kmip/')}
        self.assertIn(('/api/kmip/clients/', '/revoke'), pats)
        self.assertIn(('/api/kmip/clients/', '/reissue'), pats)
        self.assertIn(('/api/kmip/keys/', ''), pats)

    def test_vault_byte_helpers_round_trip(self):
        import secrets
        key = secrets.token_bytes(32)
        for blob in (b'\x00\xff' * 16, b'', b'x' * 1000):
            enc = api.cmdb_vault.encrypt_bytes(key, blob)
            self.assertEqual(api.cmdb_vault.decrypt_bytes(key, enc), blob)

    def test_vault_byte_helpers_reject_a_wrong_key(self):
        import secrets
        enc = api.cmdb_vault.encrypt_bytes(secrets.token_bytes(32), b'secret')
        with self.assertRaises(api.cmdb_vault.VaultKeyError):
            api.cmdb_vault.decrypt_bytes(secrets.token_bytes(32), enc)


class TestOpsWiring(unittest.TestCase):
    """Mirrors test_v630_syslogd.TestOpsWiring — the static-unit contract and
    the deploy/update paths that keep an installed sidecar current."""

    UNIT = (_ROOT / 'packaging' / 'remotepower-kmipd.service')

    def test_unit_is_static_and_sandboxed(self):
        u = self.UNIT.read_text()
        self.assertIn('DynamicUser=yes', u)
        self.assertNotIn('User=r', u, 'unit must NOT be install-time rendered')
        self.assertIn('ProtectSystem=strict', u)
        self.assertIn('NoNewPrivileges=yes', u)
        self.assertIn('EnvironmentFile=/etc/remotepower/kmipd.env', u)

    def test_unit_has_no_data_dir_access(self):
        """Unlike syslogd/flowd the KMIP daemon needs NO store access at all —
        granting it would widen the blast radius for nothing."""
        u = self.UNIT.read_text()
        self.assertNotIn('ReadOnlyPaths=/var/lib/remotepower', u)
        self.assertNotIn('RP_DATA_DIR', u)

    def test_installer_flag_exists_and_is_opt_in(self):
        s = (_ROOT / 'install-server.sh').read_text()
        self.assertIn('--with-kmip', s)
        self.assertIn('WITH_KMIP="${RP_WITH_KMIP:-0}"', s)
        self.assertIn('--with-syslogd', s)
        self.assertIn('--with-flowd', s)

    def test_deploy_refreshes_and_update_restarts(self):
        self.assertIn('remotepower-kmipd',
                      (_ROOT / 'deploy-server.sh').read_text())
        self.assertIn('remotepower-kmipd',
                      (_ROOT / 'packaging' / 'remotepower-server-update.sh').read_text())

    def test_deploy_never_rewrites_the_daemon_secret(self):
        """Refreshing code must not rotate a secret the API verifies against."""
        s = (_ROOT / 'deploy-server.sh').read_text()
        start = s.index('remotepower-kmipd')
        self.assertNotIn('kmipd.env', s[start:start + 1200])

    def test_rp_cli_knows_the_component(self):
        s = (_ROOT / 'server' / 'rp').read_text()
        self.assertIn('remotepower-kmipd', s)
        self.assertIn('[remotepower-kmipd]=5696', s)
        self.assertIn('_ingest_summary', s)

    def test_docs_exist_and_warn_about_availability_coupling(self):
        d = (_ROOT / 'docs' / 'kmip.md').read_text()
        self.assertIn('reachable', d)
        self.assertIn('recovery bundle', d.lower())
        # The circular-dependency trap must be stated, not implied.
        self.assertIn('never run', d.lower())


class TestUiWiring(unittest.TestCase):
    INDEX = (_ROOT / 'server' / 'html' / 'index.html').read_text()
    JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-kmip.js').read_text()

    def test_nav_and_page_present(self):
        self.assertIn('data-page="kmip"', self.INDEX)
        self.assertIn('id="page-kmip"', self.INDEX)

    def test_nav_item_is_alphabetical_within_security(self):
        block = self.INDEX.split('data-group="security"')[1].split('</div>\n    </div>')[0]
        import re
        labels = re.findall(r'<span>([^<]+)</span>', block)
        labels = [l for l in labels if l != 'Security']
        self.assertEqual(labels, sorted(labels, key=str.lower),
                         f'Security nav items must stay alphabetical: {labels}')

    def test_modals_live_at_body_level(self):
        """A fixed overlay inside .container is sealed below the sidebar."""
        app_end = self.INDEX.index('<!-- /app -->')
        for mid in ('kmip-wizard-modal', 'kmip-export-modal',
                    'kmip-import-modal', 'kmip-config-modal',
                    'kmip-install-modal'):
            self.assertGreater(self.INDEX.index(f'id="{mid}"'), app_end,
                               f'{mid} must be a direct child of <body>')

    def test_no_inline_handlers_or_styles(self):
        page = self.INDEX[self.INDEX.index('id="page-kmip"'):]
        page = page[:page.index('id="page-risk"')]
        self.assertNotIn('onclick=', page)
        self.assertNotIn('style="', page)

    def test_wizard_offers_every_client_type(self):
        for kind in ('synology', 'truenas', 'vsphere', 'generic'):
            self.assertIn(f'value="{kind}"', self.INDEX)
            self.assertIn(f'{kind}:', self.JS)

    def test_tables_are_scroll_capped(self):
        page = self.INDEX[self.INDEX.index('id="page-kmip"'):]
        page = page[:page.index('id="page-risk"')]
        self.assertEqual(page.count('scrollable-table-wrap audit-scroll'), 3,
                         'every variable-length KMIP table must scroll-cap')

    def test_sortable_tables_are_wired(self):
        for t in ('kmip-clients', 'kmip-keys', 'kmip-log'):
            self.assertIn(f"wireSortOnly('{t}-thead'", self.JS)

    def test_lazy_module_registered(self):
        app = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("kmip: ['app-kmip.js']", app)
        self.assertIn("if (name === 'kmip')", app)
        # A module in BOTH the lazy map and a <script> tag loads twice.
        self.assertNotIn('src="static/js/app-kmip.js', self.INDEX)

    def test_no_call_site_trusts_a_bare_truthy_response(self):
        """api() resolves the parsed body for EVERY status, so `if (!r) return`
        lets a 500 through — and the code after it toasted success and closed
        the modal. That shipped: enabling the server 500'd while the UI said
        "KMIP server enabled" and left the checkbox unticked."""
        self.assertIn('function _kmipOk', self.JS)
        self.assertNotIn('if (!r) return;', self.JS,
                         'every KMIP response must go through _kmipOk')

    def test_every_api_call_is_guarded(self):
        import re
        calls = len(re.findall(r'await api\(', self.JS))
        guards = self.JS.count('_kmipOk(')
        self.assertGreaterEqual(guards, calls - 1,
                                f'{calls} api() calls but only {guards} guards '
                                '(the polling one may go unguarded)')

    def test_destructive_actions_confirm(self):
        for fn in ('kmipRevokeClient', 'kmipDestroyKey'):
            body = self.JS[self.JS.index(f'async function {fn}'):]
            body = body[:body.index('\n}\n')]
            self.assertIn('uiConfirm', body, f'{fn} must confirm before acting')


if __name__ == '__main__':
    unittest.main()
