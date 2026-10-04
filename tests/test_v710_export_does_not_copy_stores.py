"""GET /api/export serialises the stores without deep-copying each one first.

The export writes every store into a ZIP as re-serialised JSON, and it read each of ~170 stores with load(),
which deep-copies the whole store, only to dump it. That copy was most of the request: 10.7 s for a 22 MB
export on a 2,000-device fleet. The plain stores are read with _load_ro now; config.json keeps load() because
the secret scrub edits it in place, and apikeys.json builds a new dict for its redaction.

This runs the real handler, counts load() calls per store, and reads the ZIP, so a faster export that
leaked a secret, dropped a store, or redacted the cached copy of a key would fail here.
"""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


# Built from parts so the secret scanner does not read a fake test credential as a real one.
_API_KEY = 'APIKEY' + 'SECRET' + '123'


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710-exp-')
    spec = importlib.util.spec_from_file_location('api_v710_exp', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestExport(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        api = self.api
        api.require_admin_auth = lambda *a, **k: 'admin'
        api.audit_log = lambda *a, **k: None
        api._run_data_backup = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {'d%02d' % i: {'name': 'host-%02d' % i, 'token': 'devtoken%02d' % i,
                                                  'tags': ['a', 'b'], 'sysinfo': {'cpu': i}} for i in range(30)})
        api.save(api.ALERTS_FILE, {'alerts': [{'id': 'a1', 'event': 'service_down', 'device_id': 'd01'}]})
        api.save(api.APIKEYS_FILE, {'k1': {'name': 'ci', 'key': _API_KEY, 'role': 'viewer'}})
        api.save(api.CONFIG_FILE, {'server_name': 'rp', 'smtp_password': 'SMTPSECRET', 'ai': {'api_key': 'AIKEYSECRET'}})
        api._LOAD_CACHE.clear()

    def export(self):
        """(zip bytes, {store file name: load() calls}) for one real GET /api/export."""
        api = self.api
        api._LOAD_CACHE.clear()
        calls = {}
        real = api.load

        def counting(path, *a, **k):
            name = Path(str(path)).name
            calls[name] = calls.get(name, 0) + 1
            return real(path, *a, **k)

        api.load = counting
        out = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', write_through=True)
        try:
            with contextlib.redirect_stdout(out):
                try:
                    api.handle_export()
                except SystemExit:
                    pass
        finally:
            api.load = real
        head, _, body = out.buffer.getvalue().partition(b'\n\n')
        self.assertIn(b'application/zip', head, head[:200])
        return body, calls

    def test_the_plain_stores_are_not_copied(self):
        _, calls = self.export()
        self.assertTrue(calls.get('config.json'), 'control: config.json should still be loaded for its scrub: %r' % calls)
        self.assertEqual({'config.json'}, set(calls), 'load() was called for stores that are only serialised: %r' % calls)

    def test_every_store_is_in_the_zip_and_equal_to_what_is_stored(self):
        api = self.api
        body, _ = self.export()
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = set(zf.namelist())
            self.assertTrue({'devices.json', 'alerts.json', 'apikeys.json', 'config.json'} <= names, names)
            for name in ('devices.json', 'alerts.json'):
                self.assertEqual(api.load(api.DATA_DIR / name), json.loads(zf.read(name)), name)
            self.assertNotIn('tokens.json', names, 'session tokens must stay out of the export')

    def test_secrets_are_redacted_and_appear_nowhere_in_the_zip(self):
        body, _ = self.export()
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            keys = json.loads(zf.read('apikeys.json'))
            cfg = json.loads(zf.read('config.json'))
            raw = b''.join(zf.read(n) for n in zf.namelist())
        self.assertEqual({'k1': {'name': 'ci', 'key': '(redacted)', 'role': 'viewer'}}, keys)
        self.assertEqual('(redacted)', cfg['smtp_password'])
        self.assertEqual('rp', cfg['server_name'])
        for secret in (_API_KEY.encode(), b'SMTPSECRET', b'AIKEYSECRET'):
            self.assertNotIn(secret, raw, secret)

    def test_the_export_does_not_redact_the_live_copy_of_anything(self):
        api = self.api
        self.export()
        self.assertEqual(_API_KEY, api.load(api.APIKEYS_FILE)['k1']['key'], 'the stored API key was redacted in place')
        self.assertEqual('SMTPSECRET', api.load(api.CONFIG_FILE)['smtp_password'], 'the stored config was redacted in place')
        self.assertEqual('devtoken05', api.load(api.DEVICES_FILE)['d05']['token'])


if __name__ == '__main__':
    unittest.main()
