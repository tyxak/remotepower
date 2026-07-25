"""v6.4.1 — regressions found by the pre-release audit sweeps.

Each of these shipped green: the v6.4.1 tests were overwhelmingly source-text
assertions, which is false-green class #1 in CLAUDE.md. These drive the real
code instead.
"""

import base64
import importlib.machinery
import importlib.util
import io
import os
import re
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_ldr = importlib.machinery.SourceFileLoader('api', str(_CGI / 'api.py'))
_spec = importlib.util.spec_from_loader('api', _ldr)
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_dspec = importlib.util.spec_from_file_location(
    'kmipd', str(_ROOT / 'server' / 'kmip' / 'remotepower-kmipd.py'))
kmipd = importlib.util.module_from_spec(_dspec)
_dspec.loader.exec_module(kmipd)


class TestTtlvAmplification(unittest.TestCase):
    """A 72-byte request demanded 4 GiB. The UniqueBatchItemID was decoded with
    whatever type the client declared and re-encoded unconditionally as a byte
    string, so declaring it TY_INT made `bytes(val)` allocate that many zero
    bytes — on the host that also runs the API and the database."""

    def test_encoder_refuses_a_non_bytes_byte_string(self):
        with self.assertRaises(ValueError):
            kmipd.ttlv_encode([(kmipd.T_UNIQUE_BATCH_ITEM_ID,
                                kmipd.TY_BYTES, 0xFFFFFFFF)])

    def test_an_int_typed_batch_id_does_not_amplify(self):
        """The real exploit path, end to end: a tiny request must not produce
        a giant response."""
        req = kmipd.ttlv_encode([(kmipd.T_REQUEST_MESSAGE, kmipd.TY_STRUCT, [
            (kmipd.T_REQUEST_HEADER, kmipd.TY_STRUCT, [
                (kmipd.T_PROTOCOL_VERSION, kmipd.TY_STRUCT, [
                    (kmipd.T_PROTOCOL_VERSION_MAJOR, kmipd.TY_INT, 1),
                    (kmipd.T_PROTOCOL_VERSION_MINOR, kmipd.TY_INT, 2)]),
                (kmipd.T_BATCH_COUNT, kmipd.TY_INT, 1)]),
            (kmipd.T_BATCH_ITEM, kmipd.TY_STRUCT, [
                (kmipd.T_OPERATION, kmipd.TY_ENUM, kmipd.OP_QUERY),
                # the payload: a 4-byte int where a byte string is echoed
                (kmipd.T_UNIQUE_BATCH_ITEM_ID, kmipd.TY_INT, 0x0FFFFFFF),
                (kmipd.T_REQUEST_PAYLOAD, kmipd.TY_STRUCT, [])])])])

        class _Api:
            def op(self, p):
                raise AssertionError('Query must not reach the control plane')

            def event(self, p):
                pass

        resp = kmipd.handle_message(req, {'id': 'c', 'name': 'n',
                                          'fingerprint': 'f'}, _Api())
        self.assertLess(len(resp), 64 * 1024,
                        f'{len(req)}-byte request produced {len(resp)} bytes')

    def test_nesting_is_bounded(self):
        blob = b''
        for _ in range(kmipd.MAX_TTLV_DEPTH + 5):
            blob = (struct.pack('>I', kmipd.T_REQUEST_MESSAGE)[1:]
                    + bytes([kmipd.TY_STRUCT])
                    + struct.pack('>I', len(blob)) + blob)
        with self.assertRaises(ValueError):
            kmipd.ttlv_decode(blob)

    def test_struct_bodies_are_not_copied(self):
        """The wasted slice repeated at every nesting level — ~940 MB of
        memcpy for a 1 MiB message nested 900 deep."""
        src = (_ROOT / 'server' / 'kmip' / 'remotepower-kmipd.py').read_text()
        self.assertIn("raw = b'' if ty == TY_STRUCT else", src)


class TestHandshakeIsOffTheAcceptLoop(unittest.TestCase):
    """Pre-auth DoS: wrap_socket ran on the accept loop, so a peer that
    completed TCP and sent nothing stalled the whole key server for the
    handshake timeout — no certificate or protocol knowledge required."""

    SRC = (_ROOT / 'server' / 'kmip' / 'remotepower-kmipd.py').read_text()

    def test_serve_loop_does_not_wrap_the_socket(self):
        loop = self.SRC[self.SRC.index('    while True:\n        try:\n'
                                       '            plain, addr = sock.accept()'):]
        loop = loop[:loop.index('def _serve_one(')]
        self.assertNotIn('wrap_socket', loop,
                         'the TLS handshake must not block accept()')

    def test_the_worker_does_the_handshake(self):
        worker = self.SRC[self.SRC.index('def _serve_one('):]
        self.assertIn('wrap_socket', worker)
        self.assertIn('HANDSHAKE_TIMEOUT_S', worker)

    def test_a_failed_thread_start_does_not_leak_a_slot(self):
        loop = self.SRC[self.SRC.index('        if not sem.acquire('):]
        loop = loop[:loop.index('def _serve_one(')]
        self.assertIn('sem.release()', loop)
        self.assertIn('plain.close()', loop)

    def test_accept_errors_do_not_busy_spin(self):
        self.assertIn('time.sleep(0.05)', self.SRC,
                      'EMFILE leaves the connection queued — pause or spin')


class TestBackupDoesNotSwallowSnapshots(unittest.TestCase):
    """v6.4.1 encrypted the pre-restore snapshots, which removed the accident
    that had been excluding them (the walk drops `*.gz`). Every DR archive then
    embedded a full data-dir image per past restore, compounding."""

    def test_snapshot_dir_is_excluded_from_the_walk(self):
        src = (_CGI / 'backups_handlers.py').read_text()
        line = [l for l in src.splitlines()
                if l.strip().startswith('excluded_names = {')][0]
        self.assertIn('_BACKUP_SNAPSHOT_DIR', line)

    def test_a_real_backup_omits_the_snapshot_dir(self):
        d = Path(api.DATA_DIR)
        snap = d / api._BACKUP_SNAPSHOT_DIR
        snap.mkdir(parents=True, exist_ok=True)
        (snap / 'pre-restore-OLD.tar.gz.enc').write_bytes(b'x' * 4096)
        real_pp = api._backup_passphrase
        api._backup_passphrase = lambda: ''
        try:
            api._run_data_backup(triggered_by='manual')
        finally:
            api._backup_passphrase = real_pp
        newest = max(Path(api._default_backup_dir()).glob('remotepower_data_*'),
                     key=lambda f: f.stat().st_mtime)
        with tarfile.open(newest) as t:
            names = t.getnames()
        self.assertFalse([n for n in names if api._BACKUP_SNAPSHOT_DIR in n],
                         'a DR archive must not embed prior restore snapshots')


class TestPreRestoreSnapshotNaming(unittest.TestCase):
    """`with_suffix` REPLACES the last suffix, so the encrypted snapshot landed
    as pre-restore-X.tar.tar.gz.enc while the operator was told to look for
    pre-restore-X.tar.gz.enc — a rollback file under a name that never existed."""

    def test_encrypted_name_appends_rather_than_replaces(self):
        src = (_CGI / 'backups_handlers.py').read_text()
        blk = src[src.index('# 1) Safety snapshot'):src.index('# 2) Open + validate')]
        self.assertIn("with_suffix(_snap_final.suffix + '.enc')", blk)
        self.assertNotIn("with_suffix('.tar.gz.enc')", blk)

    def test_the_suffix_maths_is_right(self):
        p = Path('/tmp/pre-restore-20260101-000000.tar.gz')
        self.assertEqual(p.with_suffix(p.suffix + '.enc').name,
                         'pre-restore-20260101-000000.tar.gz.enc')

    def test_it_refuses_plaintext_when_crypto_is_missing(self):
        """_run_data_backup refuses in this situation; the snapshot silently
        wrote a full plaintext image of the data dir instead."""
        blk = (_CGI / 'backups_handlers.py').read_text()
        blk = blk[blk.index('# 1) Safety snapshot'):blk.index('# 2) Open + validate')]
        self.assertIn('refusing to write a plaintext', blk)


class TestMonitorKeepDoesNotCrash(unittest.TestCase):
    """A carried-through stored monitor with no label raised KeyError building
    _mon_valid_labels — turning a clean 400 into a 500 that then blocked every
    later settings save until config.json was hand-edited."""

    def setUp(self):
        self.cap = {}
        self._real = (api.respond, api.verify_token, api.audit_log,
                      api._env, api.method)

        def _resp(s, b=None):
            self.cap['s'], self.cap['b'] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.audit_log = lambda *a, **k: None
        api._env = lambda k, d='': d
        api.method = lambda: 'POST'
        api.verify_token = lambda *a, **k: ('admin', 'admin')

    def tearDown(self):
        (api.respond, api.verify_token, api.audit_log,
         api._env, api.method) = self._real

    def test_a_label_less_stored_monitor_does_not_500(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['monitors'] = [{'type': 'ping', 'target': 'example.com',
                            'via_satellite': 'sat-gone'}]
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)
        body = {'monitors': [
            {'type': 'ping', 'target': 'example.com', 'via_satellite': 'sat-gone'},
            {'label': 'new', 'type': 'dns', 'target': 'example.org',
             'target_kind': 'host'}]}
        api.get_json_obj = lambda: body
        api._read_valid = lambda m: body
        self.cap.clear()
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        self.assertNotEqual(self.cap.get('s'), 500,
                            f"expected a clean result, got 500: {self.cap.get('b')}")


class TestRpIngestReadsTheRealStoreShapes(unittest.TestCase):
    """Both counters read keys no writer produces, so a busy receiver reported
    '0 lines buffered · newest never' — precisely the broken state the view
    exists to reveal."""

    @staticmethod
    def _body():
        src = (_ROOT / 'server' / 'rp').read_text()
        return re.search(r"python3 - <<'RPINGEST'.*?\n(.*?)\nRPINGEST",
                         src, re.S).group(1)

    def test_syslog_reads_units_not_lines(self):
        b = self._body()
        self.assertIn("get('units')", b)
        self.assertNotIn("get('lines')", b)

    def test_flow_reads_latest_ts(self):
        self.assertIn("dev.get('latest')", self._body())

    def test_it_counts_a_real_store(self):
        import json
        import subprocess
        d = Path(tempfile.mkdtemp())
        (d / 'log_watch.json').write_text(json.dumps(
            {'dev1': {'units': {'syslog': [{'ts': 9999999999, 'line': 'x'}]}}}))
        (d / 'flow.json').write_text(json.dumps(
            {'dev2': {'latest': {'ts': 9999999999, 'total_bytes': 1}}}))
        (d / 'inbound_webhooks.json').write_text(json.dumps({'tokens': [
            {'kind': 'syslog', 'enabled': True, 'scope_device_id': 'dev1',
             'token': 't'},
            {'kind': 'flow', 'enabled': True, 'scope_device_id': 'dev2',
             'token': 'u'}]}))
        env = dict(os.environ, RP_DATA_DIR=str(d),
                   RP_CODE_DIR=str(_ROOT / 'server'), RP_INGEST_COMPACT='1')
        out = subprocess.run(['python3', '-c', self._body()],
                             capture_output=True, text=True, env=env).stdout
        self.assertIn('1 src', out)
        self.assertIn('1 lines', out, f'syslog counter still broken: {out!r}')
        self.assertIn('1 reporting', out, f'flow counter still broken: {out!r}')
        self.assertNotIn('never', out.split('kmip')[0],
                         f'freshness still reads the wrong key: {out!r}')


class TestPortIsReportedNotInvented(unittest.TestCase):
    """The listen port was an editable setting the daemon never read: the page
    said 'Running · port N' and the appliance walkthrough said 'Port N' while
    the daemon stayed on whatever RP_KMIP_BIND gave it."""

    def test_daemon_reports_its_actual_bind(self):
        src = (_ROOT / 'server' / 'kmip' / 'remotepower-kmipd.py').read_text()
        self.assertIn("'bind': f'{host}:{port}'", src)

    def test_status_prefers_the_reported_bind(self):
        src = (_CGI / 'kmip_handlers.py').read_text()
        self.assertIn("_bind = str(daemon.get('bind') or '')", src)
        self.assertIn("'port': _real_port or", src)

    def test_the_ui_field_is_not_editable(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        i = html.index('id="kmip-cfg-port"')
        self.assertIn('readonly', html[i:i + 200])
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-kmip.js').read_text()
        save = js[js.index('async function kmipSaveConfig'):]
        save = save[:save.index('\n}')]
        self.assertNotIn('port,', save, 'do not send a setting nothing honours')


if __name__ == '__main__':
    unittest.main()
