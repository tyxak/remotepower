#!/usr/bin/env python3
"""8.0.0: the declarative export, the support bundle and the backup hide the same credentials.

A webhook destination can carry an Authorization or X-API-Key header and, for Pushover, a user key. Neither field has a secret-shaped name, so the name-based pass of the redactors
misses them. 6.4.2 masked them in the support bundle and the backup and left the declarative export, whose own note says it is safe to commit, with the header values in plain text.
Apprise destinations (8.0.0) are the likely place for such a header, so the gap mattered more. The cases here put one marker in each such field and read every surface.
"""

import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-dechdr-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

HDR, KEY, USER, PATH, PW = 'MARKERBEARERVALUE', 'MARKERXAPIKEY', 'MARKERPUSHOVERUSER', 'MARKERAPPRISEKEY', 'MARKERBASICPASSWORD'
MARKERS = (HDR, KEY, USER, PATH, PW)


def config():
    return {
        'webhook_urls': [
            {'label': 'ap', 'fmt': 'apprise', 'enabled': True, 'url': 'https://apprise.example/notify/' + PATH, 'headers': {'Authorization': 'Bearer ' + HDR, 'X-Api-Key': KEY}},
            {'label': 'po', 'fmt': 'pushover', 'enabled': True, 'url': 'https://api.pushover.net/1/messages.json', 'pushover_user': USER},
        ],
        'integrations': [{'id': 'i1', 'type': 'prometheus', 'url': 'https://scrape:%s@prom.example/metrics' % PW}],
    }


class _Base(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self._had = os.environ.pop('RP_CONFIG_KEY', None)
        self.api.save(self.api.CONFIG_FILE, config())
        self.api._LOAD_CACHE.clear()

    def tearDown(self):
        os.environ.pop('RP_CONFIG_KEY', None)
        if self._had is not None:
            os.environ['RP_CONFIG_KEY'] = self._had

    def dest(self, doc, label):
        return next(d for d in doc['resources']['webhook_destinations'] if d['label'] == label)


class TestWithoutAMasterKey(_Base):

    def test_no_marker_is_in_the_document_and_the_names_of_the_headers_are(self):
        doc = self.api._build_declarative_config()
        text = json.dumps(doc)
        for m in MARKERS:
            self.assertNotIn(m, text, m)
        self.assertEqual(self.dest(doc, 'ap')['headers'], {'Authorization': '(redacted)', 'X-Api-Key': '(redacted)'}, 'the names stay, so a reader sees which headers are set')
        self.assertEqual(self.dest(doc, 'po')['pushover_user'], '(redacted)')
        self.assertEqual(self.dest(doc, 'ap')['url'], 'https://apprise.example', 'host only, as before')

    def test_a_destination_without_these_fields_is_left_as_it_was(self):
        self.api.save(self.api.CONFIG_FILE, {'webhook_urls': [{'label': 'plain', 'enabled': True, 'url': 'https://hooks.example/x/SECRETPATH'}, 'junk', {'label': 'h', 'headers': 'x'}]})
        self.api._LOAD_CACHE.clear()
        doc = self.api._build_declarative_config()
        self.assertNotIn('SECRETPATH', json.dumps(doc))
        self.assertEqual(self.dest(doc, 'h').get('headers'), 'x', 'a headers value that is not a map is not this code to rewrite')


class TestWithAMasterKey(_Base):

    def setUp(self):
        super().setUp()
        os.environ['RP_CONFIG_KEY'] = 'unit-test-master-key-8f2b1c9de4a6'
        self.api._LOAD_CACHE.clear()

    def test_the_values_are_ciphertext_and_come_back_whole(self):
        doc = self.api._build_declarative_config()
        text = json.dumps(doc)
        for m in MARKERS:
            self.assertNotIn(m, text, m)
        ap = self.dest(doc, 'ap')
        for name, plain in (('Authorization', 'Bearer ' + HDR), ('X-Api-Key', KEY)):
            self.assertTrue(ap['headers'][name].startswith('enc:v2:'), ap['headers'])
            self.assertEqual(self.api._cfg_dec(ap['headers'][name]), plain, 'lossless: an import gets the header back')
        self.assertEqual(self.api._cfg_dec(self.dest(doc, 'po')['pushover_user']), USER)

    def test_importing_the_document_gives_the_headers_back(self):
        doc = self.api._build_declarative_config()
        res = self.api._declarative_apply(copy.deepcopy(doc), 'tester', dry_run=False)
        self.assertTrue(res['ok'], res)
        self.api._LOAD_CACHE.clear()
        stored = self.api.load(self.api.CONFIG_FILE)['webhook_urls']
        ap = next(d for d in stored if d['label'] == 'ap')
        self.assertEqual(ap['headers'], {'Authorization': 'Bearer ' + HDR, 'X-Api-Key': KEY}, 'lossless: not the placeholder, not ciphertext')
        self.assertEqual(next(d for d in stored if d['label'] == 'po')['pushover_user'], USER)
        self.assertEqual(ap['url'], 'https://apprise.example/notify/' + PATH)


class TestWithAKeyAndNoCryptoLibrary(_Base):
    """_cfg_enc returns the text unchanged when it cannot encrypt, and that must never end up in a document meant to be committed."""

    def setUp(self):
        super().setUp()
        os.environ['RP_CONFIG_KEY'] = 'unit-test-master-key-8f2b1c9de4a6'
        self._avail = self.api.backup_crypto.available
        self.api.backup_crypto.available = lambda: False

    def tearDown(self):
        self.api.backup_crypto.available = self._avail
        super().tearDown()

    def test_it_fails_closed(self):
        doc = self.api._build_declarative_config()
        text = json.dumps(doc)
        for m in MARKERS:
            self.assertNotIn(m, text, m)
        self.assertEqual(self.dest(doc, 'ap')['headers']['Authorization'], '(redacted)')
        self.assertEqual(self.dest(doc, 'ap')['url'], 'https://apprise.example')


class TestEverySurfaceAgrees(_Base):
    """The rule, over the three surfaces 6.4.2 named: the support bundle, the backup and the declarative document."""

    def raw(self, fn):
        bio = io.BytesIO()
        out = io.TextIOWrapper(bio, encoding='utf-8', write_through=True)
        with contextlib.redirect_stdout(out):
            try:
                _run(self.api, fn, None, method='GET', env={'HTTP_AUTHORIZATION': 'Bearer k'})
            except SystemExit:
                pass                    # a handler that writes its own response and leaves
        out.flush()
        data = bio.getvalue()
        text = data.decode('latin-1')
        i = data.find(b'PK\x03\x04')
        if i >= 0:
            with zipfile.ZipFile(io.BytesIO(data[i:])) as z:
                for n in z.namelist():
                    text += '\n[[%s]]\n' % n + z.read(n).decode('latin-1')
        return text

    def test_no_marker_leaves_by_any_of_them(self):
        self.api.verify_token = lambda t: ('admin', 'admin') if t == 'k' else (None, None)
        self.api.audit_log = lambda *a, **k: None
        self.api.save(self.api.DEVICES_FILE, {'web01': {'id': 'web01', 'name': 'web01', 'os': 'Ubuntu', 'token': 't', 'last_seen': int(time.time()), 'sysinfo': {}}})
        self.api._LOAD_CACHE.clear()
        surfaces = {'support bundle': self.raw(self.api.handle_diagnostics_bundle), 'backup': self.raw(self.api.handle_export),
                    'declarative document': json.dumps(self.api._build_declarative_config())}
        for name, text in surfaces.items():
            self.assertIn('apprise', text, 'control: %s carries the destinations at all (%d chars)' % (name, len(text)))
            for m in MARKERS:
                self.assertNotIn(m, text, '%s shows %s' % (name, m))


if __name__ == '__main__':
    unittest.main()
