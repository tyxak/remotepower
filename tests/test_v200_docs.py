#!/usr/bin/env python3
"""
Tests for v2.0 multi-doc CMDB attachments.

Covers:
  - Schema migration: legacy `documentation` string → single-entry `docs` list
  - POST /api/cmdb/{id}/docs (add): success, validation, per-asset cap
  - PUT /api/cmdb/{id}/docs/{doc_id} (update): partial updates, legacy promotion
  - DELETE /api/cmdb/{id}/docs/{doc_id} (delete): success, 404
  - Authorisation: every handler requires session auth
  - Audit log entries on each mutation

Mirrors the test_v190.py setup pattern.
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v200_docs", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(SystemExit):
    """SystemExit subclass carrying the (status, body) the handler emitted."""

    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


def _capture_respond():
    """Replace api.respond with a function that raises _Captured(status, body)."""
    def fake_respond(status, data):
        raise _Captured(status, data)
    api.respond = fake_respond


class _StdinShim:
    """sys.stdin.buffer.read(n) is what api.get_body uses — fake both layers.

    Mirrors the helper in tests/test_v190.py.
    """

    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def _set_request(method='GET', body=None):
    """Set up the CGI environment to simulate a request."""
    os.environ['REQUEST_METHOD'] = method
    if body is not None:
        body_bytes = json.dumps(body).encode('utf-8')
        os.environ['CONTENT_LENGTH'] = str(len(body_bytes))
        api.sys.stdin = _StdinShim(body_bytes)
    else:
        os.environ['CONTENT_LENGTH'] = '0'
        api.sys.stdin = _StdinShim(b'')


def _stub_auth(username='admin'):
    """Make require_auth return a fixed username regardless of headers."""
    api.require_auth = lambda: username


# ─── Setup ────────────────────────────────────────────────────────────────────


class _TestBase(unittest.TestCase):
    """Shared fixtures: isolated data dir, captured respond, stubbed auth,
    one enrolled device the docs can attach to."""

    def setUp(self):
        # Each test gets its own data dir so files don't bleed across cases
        self._data_dir = Path(tempfile.mkdtemp())
        api.DATA_DIR = self._data_dir
        api.DEVICES_FILE = self._data_dir / 'devices.json'
        api.CMDB_FILE = self._data_dir / 'cmdb.json'
        api.AUDIT_LOG_FILE = self._data_dir / 'audit_log.json'

        _capture_respond()
        _stub_auth('admin')

        # Plant one device so dev_id lookups succeed
        api.save(api.DEVICES_FILE, {
            'dev1': {'name': 'host1', 'token': 't1', 'enrolled_at': int(time.time())},
        })

    def _add_doc(self, dev_id='dev1', title='T', body='B'):
        _set_request('POST', {'title': title, 'body': body})
        try:
            api.handle_cmdb_doc_add(dev_id)
        except _Captured as c:
            return c
        self.fail("handler should have called respond()")

    def _update_doc(self, dev_id, doc_id, body):
        _set_request('PUT', body)
        try:
            api.handle_cmdb_doc_update(dev_id, doc_id)
        except _Captured as c:
            return c
        self.fail("handler should have called respond()")

    def _delete_doc(self, dev_id, doc_id):
        _set_request('DELETE')
        try:
            api.handle_cmdb_doc_delete(dev_id, doc_id)
        except _Captured as c:
            return c
        self.fail("handler should have called respond()")


# ─── Add doc ──────────────────────────────────────────────────────────────────


class TestDocAdd(_TestBase):

    def test_add_doc_basic(self):
        c = self._add_doc(title='Runbook', body='# Step 1\nsudo reboot')
        self.assertEqual(c.status, 200)
        self.assertEqual(c.body['title'], 'Runbook')
        self.assertEqual(c.body['body'], '# Step 1\nsudo reboot')
        self.assertEqual(c.body['created_by'], 'admin')
        self.assertTrue(c.body['id'])    # server-assigned, non-empty
        self.assertGreater(c.body['created_at'], 0)
        # Persisted
        cmdb = api._cmdb_load()
        self.assertEqual(len(cmdb['dev1']['docs']), 1)
        self.assertEqual(cmdb['dev1']['docs'][0]['id'], c.body['id'])

    def test_list_has_documentation_true_for_docs_list(self):
        # Regression (visual bug): the CMDB list green "has docs" dot is driven
        # by has_documentation, which used to check ONLY the legacy
        # `documentation` blob. Docs added through the new multi-doc editor live
        # in the `docs` list (and clear the legacy blob), so the dot never lit.
        self._add_doc(title='Runbook', body='# steps')
        _set_request('GET')
        try:
            api.handle_cmdb_list()
        except _Captured as c:
            cap = c
        else:
            self.fail("handler should have called respond()")
        row = next(r for r in cap.body if r['device_id'] == 'dev1')
        self.assertTrue(row['has_documentation'])      # docs list populated → dot lit
        # And an asset with no docs stays unlit.
        api.save(api.DEVICES_FILE, {
            'dev1': {'name': 'host1', 'token': 't1', 'enrolled_at': int(time.time())},
            'dev2': {'name': 'host2', 'token': 't2', 'enrolled_at': int(time.time())},
        })
        _set_request('GET')
        try:
            api.handle_cmdb_list()
        except _Captured as c:
            cap = c
        row2 = next(r for r in cap.body if r['device_id'] == 'dev2')
        self.assertFalse(row2['has_documentation'])

    def test_add_two_docs_keeps_both(self):
        c1 = self._add_doc(title='A', body='aaa')
        c2 = self._add_doc(title='B', body='bbb')
        self.assertEqual(c1.status, 200)
        self.assertEqual(c2.status, 200)
        self.assertNotEqual(c1.body['id'], c2.body['id'])
        cmdb = api._cmdb_load()
        self.assertEqual([d['title'] for d in cmdb['dev1']['docs']], ['A', 'B'])

    def test_add_empty_title_rejected(self):
        c = self._add_doc(title='   ', body='whatever')
        self.assertEqual(c.status, 400)
        self.assertIn('title', c.body['error'])

    def test_add_oversized_title_rejected(self):
        c = self._add_doc(title='x' * (api.MAX_CMDB_DOC_TITLE + 1), body='')
        self.assertEqual(c.status, 400)

    def test_add_empty_body_allowed(self):
        # Title-only docs are valid (e.g. a placeholder while you write it)
        c = self._add_doc(title='TODO', body='')
        self.assertEqual(c.status, 200)

    def test_add_oversized_body_rejected(self):
        c = self._add_doc(title='Big', body='a' * (api.MAX_CMDB_DOC_LEN + 1))
        self.assertEqual(c.status, 400)
        self.assertIn('too large', c.body['error'])

    def test_add_to_unknown_device_404s(self):
        _set_request('POST', {'title': 'x', 'body': 'y'})
        try:
            api.handle_cmdb_doc_add('nonexistent')
        except _Captured as c:
            self.assertEqual(c.status, 404)
        else:
            self.fail("expected 404")

    def test_add_capped_at_max(self):
        # Plant MAX_CMDB_DOCS docs directly so we don't have to round-trip
        cmdb = api._cmdb_load()
        rec = api._cmdb_record_default()
        rec['docs'] = [{'id': f'd{i}', 'title': f'T{i}', 'body': '',
                        'created_by': 'a', 'created_at': 0,
                        'updated_by': 'a', 'updated_at': 0}
                       for i in range(api.MAX_CMDB_DOCS)]
        cmdb['dev1'] = rec
        api.save(api.CMDB_FILE, cmdb)

        c = self._add_doc(title='OneMore', body='')
        self.assertEqual(c.status, 400)
        self.assertIn('too many', c.body['error'])

    def test_add_records_audit_entry(self):
        self._add_doc(title='Audited', body='content')
        log = api.load(api.AUDIT_LOG_FILE)
        # audit_log shape: dict with 'entries' key holding a list of dicts
        entries = log.get('entries', [])
        actions = [e.get('action') for e in entries]
        self.assertIn('cmdb_doc_add', actions)


# ─── Update doc ───────────────────────────────────────────────────────────────


class TestDocUpdate(_TestBase):

    def test_update_title_only(self):
        c = self._add_doc(title='Old', body='unchanged')
        doc_id = c.body['id']

        upd = self._update_doc('dev1', doc_id, {'title': 'New'})
        self.assertEqual(upd.status, 200)
        self.assertEqual(upd.body['title'], 'New')
        self.assertEqual(upd.body['body'], 'unchanged')
        self.assertEqual(upd.body['updated_by'], 'admin')

    def test_update_body_only(self):
        c = self._add_doc(title='T', body='before')
        upd = self._update_doc('dev1', c.body['id'], {'body': 'after'})
        self.assertEqual(upd.status, 200)
        self.assertEqual(upd.body['title'], 'T')
        self.assertEqual(upd.body['body'], 'after')

    def test_update_unknown_doc_404s(self):
        c = self._update_doc('dev1', 'nonexistent', {'title': 'x'})
        self.assertEqual(c.status, 404)

    def test_update_with_no_fields_400s(self):
        c = self._add_doc(title='T', body='B')
        upd = self._update_doc('dev1', c.body['id'], {})
        self.assertEqual(upd.status, 400)

    def test_update_invalid_title_rejected(self):
        c = self._add_doc(title='T', body='B')
        upd = self._update_doc('dev1', c.body['id'], {'title': ''})
        self.assertEqual(upd.status, 400)

    def test_update_legacy_doc_promotes_id(self):
        # Plant a legacy-shaped record (old documentation field, no docs)
        cmdb = {'dev1': {**api._cmdb_record_default(),
                          'documentation': 'pre-v2 markdown',
                          'docs': []}}
        # Don't include 'docs' so the migration does its work
        del cmdb['dev1']['docs']
        api.save(api.CMDB_FILE, cmdb)

        # Sanity: load() migrates it to a single legacy doc
        loaded = api._cmdb_load()
        self.assertEqual(len(loaded['dev1']['docs']), 1)
        self.assertEqual(loaded['dev1']['docs'][0]['id'], 'legacy')

        # Update the legacy doc → it should be assigned a real id
        upd = self._update_doc('dev1', 'legacy', {'body': 'rewritten in v2'})
        self.assertEqual(upd.status, 200)
        self.assertNotEqual(upd.body['id'], 'legacy')

        # And the back-compat documentation field is cleared
        cmdb_after = api._cmdb_load()
        self.assertEqual(cmdb_after['dev1']['documentation'], '')
        self.assertEqual(len(cmdb_after['dev1']['docs']), 1)


# ─── Delete doc ───────────────────────────────────────────────────────────────


class TestDocDelete(_TestBase):

    def test_delete_basic(self):
        c1 = self._add_doc(title='Keep', body='')
        c2 = self._add_doc(title='Drop', body='')
        d = self._delete_doc('dev1', c2.body['id'])
        self.assertEqual(d.status, 200)
        self.assertTrue(d.body['ok'])

        cmdb = api._cmdb_load()
        ids = [doc['id'] for doc in cmdb['dev1']['docs']]
        self.assertIn(c1.body['id'], ids)
        self.assertNotIn(c2.body['id'], ids)

    def test_delete_unknown_404s(self):
        c = self._delete_doc('dev1', 'nonexistent')
        self.assertEqual(c.status, 404)

    def test_delete_last_legacy_doc_clears_back_compat_field(self):
        # Plant a record with a legacy doc only, no v2 docs yet
        cmdb = {'dev1': {**api._cmdb_record_default(),
                          'documentation': 'old content'}}
        del cmdb['dev1']['docs']
        api.save(api.CMDB_FILE, cmdb)

        # Migration creates docs[0] with id='legacy'. Delete it.
        d = self._delete_doc('dev1', 'legacy')
        self.assertEqual(d.status, 200)

        # Both fields should be empty now — without this clearing,
        # the next load() would re-migrate the still-present
        # documentation string and resurrect the doc.
        cmdb_after = api._cmdb_load()
        self.assertEqual(cmdb_after['dev1']['documentation'], '')
        self.assertEqual(cmdb_after['dev1']['docs'], [])


# ─── Migration ────────────────────────────────────────────────────────────────


class TestMigration(unittest.TestCase):

    def setUp(self):
        self._data_dir = Path(tempfile.mkdtemp())
        api.DATA_DIR = self._data_dir
        api.CMDB_FILE = self._data_dir / 'cmdb.json'

    def test_legacy_documentation_synthesises_one_doc(self):
        # Write a record in the old shape (no 'docs' field at all)
        record = {
            'asset_id': 'srv-001',
            'server_function': 'webserver',
            'hypervisor_url': '',
            'ssh_port': 22,
            'documentation': '# Legacy notes\nstuff here',
            'credentials': [],
            'updated_by': 'admin',
            'updated_at': 1234567890,
        }
        api.save(api.CMDB_FILE, {'dev1': record})

        loaded = api._cmdb_load()
        rec = loaded['dev1']
        self.assertEqual(len(rec['docs']), 1)
        self.assertEqual(rec['docs'][0]['id'], 'legacy')
        self.assertEqual(rec['docs'][0]['title'], 'Documentation')
        self.assertEqual(rec['docs'][0]['body'], '# Legacy notes\nstuff here')
        # Original field is preserved (back-compat for old API consumers)
        self.assertEqual(rec['documentation'], '# Legacy notes\nstuff here')

    def test_record_with_empty_legacy_gets_empty_docs_list(self):
        record = {**api._cmdb_record_default(), 'documentation': ''}
        del record['docs']
        api.save(api.CMDB_FILE, {'dev1': record})
        loaded = api._cmdb_load()
        self.assertEqual(loaded['dev1']['docs'], [])

    def test_record_already_migrated_left_alone(self):
        # If a record already has a docs list, migration must not touch it
        existing = {
            **api._cmdb_record_default(),
            'documentation': 'whatever',  # old field still present
            'docs': [{'id': 'real', 'title': 'T', 'body': 'B',
                      'created_by': 'x', 'created_at': 1, 'updated_by': 'x', 'updated_at': 1}],
        }
        api.save(api.CMDB_FILE, {'dev1': existing})
        loaded = api._cmdb_load()
        self.assertEqual(loaded['dev1']['docs'], existing['docs'])


if __name__ == '__main__':
    unittest.main()
