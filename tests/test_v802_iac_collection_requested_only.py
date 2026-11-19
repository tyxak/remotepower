#!/usr/bin/env python3
"""8.0.2 review (ST-05): a host's IaC answer is kept only for a request an administrator made for that host, and once.

The heartbeat wrote every `iac_data` document a host sent under a name the host picked (up to 1.9 MiB each, inside the host-store lock) and nothing pruned them: one host
filled the disk and held up every other host's heartbeat. The request now records its id in the host's `iac_pending` (newest eight, one hour), and the heartbeat keeps a
document only for an id in that list, takes the id out, and writes the file after the lock is released.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-iac-requested-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(_ROOT / 'tests'))

import api  # noqa: E402
import srcpin  # noqa: E402

TOKEN = 'iac-token-' + 'a' * 30


class _Captured(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


def _beat(body):
    api._begin_request()
    os.environ['REQUEST_METHOD'] = 'POST'
    os.environ['PATH_INFO'] = '/api/heartbeat'
    os.environ['REMOTE_ADDR'] = '203.0.113.50'
    raw = json.dumps(body).encode()
    os.environ['CONTENT_LENGTH'] = str(len(raw))
    api.sys.stdin = _Stdin(raw)

    def fake(status, data=None, *a, **k):
        raise _Captured(status, data)
    orig = api.respond
    api.respond = fake
    try:
        api.handle_heartbeat()
    except _Captured as c:
        return c.status
    finally:
        api.respond = orig


class TestOnlyARequestedAnswerIsKept(unittest.TestCase):

    def setUp(self):
        d = tempfile.mkdtemp(prefix='rp-iac-requested-')
        self._saved = {}
        for name in dir(api):
            v = getattr(api, name)
            if name.endswith('_FILE') and isinstance(v, Path):
                self._saved[name] = v
                setattr(api, name, Path(d) / v.name)
        self._dir = api.IAC_COLLECTION_DIR
        self._saved['IAC_COLLECTION_DIR'] = self._dir
        api.IAC_COLLECTION_DIR = Path(d) / 'iac_collection'
        api._begin_request()
        api.ensure_default_user()
        api.save(api.DEVICES_FILE, {'h1': {'id': 'h1', 'name': 'h1', 'os': 'Debian 12', 'token_hash': api._hash_device_token(TOKEN),
                                           'last_seen': int(time.time())}})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def beat(self, rid, size=100):
        return _beat({'device_id': 'h1', 'token': TOKEN, 'os': 'Debian 12', 'version': '8.0.2',
                      'iac_data': {'request_id': rid, 'categories': ['packages'], 'data': {'blob': 'x' * size}}})

    def written(self, rid):
        api._LOAD_CACHE.clear()
        return api.backend_exists(api.IAC_COLLECTION_DIR / f'{rid}.json')

    def test_a_document_nobody_asked_for_is_not_written(self):
        self.assertEqual(self.beat('made-up-by-the-host', 5000), 200)
        self.assertFalse(self.written('made-up-by-the-host'))
        for i in range(5):
            self.beat(f'more-{i}')
        self.assertFalse(api.IAC_COLLECTION_DIR.exists() and any(api.IAC_COLLECTION_DIR.iterdir()), 'a host cannot make files under names it picks')

    def test_the_answer_to_a_request_is_written_once_and_the_id_is_used_up(self):
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs['h1']['iac_pending'] = {'req-1': int(time.time())}
        api._LOAD_CACHE.clear()
        self.assertEqual(self.beat('req-1'), 200)
        self.assertTrue(self.written('req-1'), 'the control: the answer to a real request is kept')
        self.assertEqual(api.load(api.IAC_COLLECTION_DIR / 'req-1.json')['device_id'], 'h1')
        api._LOAD_CACHE.clear()
        self.assertNotIn('iac_pending', api.load(api.DEVICES_FILE)['h1'])
        (api.IAC_COLLECTION_DIR / 'req-1.json').unlink(missing_ok=True)
        self.beat('req-1')
        self.assertFalse(self.written('req-1') and (api.IAC_COLLECTION_DIR / 'req-1.json').exists(), 'the same id is not accepted twice')

    def test_the_request_records_the_id_and_keeps_the_newest_eight_for_an_hour(self):
        body = srcpin.py_function((_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text(), 'handle_iac_request')
        self.assertIn("dev['iac_pending']", body)
        self.assertIn('[-8:]', body)
        self.assertIn('< 3600', body)


if __name__ == '__main__':
    unittest.main()
