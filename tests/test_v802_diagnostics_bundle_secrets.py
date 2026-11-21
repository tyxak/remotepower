#!/usr/bin/env python3
"""8.0.2: the support bundle (GET /api/diagnostics) holds no secret of the settings, in every field the code lists as one that can hold it.

The fields whose names no rule knows (an address with a token in its path, a header value, a key under a name such as `agentless_ssh_key`) are listed once, in
`_nonname_config_secret_sites`, and the bundle, the backup and the declarative export all read that list. Two older tests pinned the names of those fields in the source text of the
helper that used to hold them, and went red when the list moved. This holds what they were for with the real handler: a marker is planted in every field of the list, the bundle is
downloaded as an administrator, and none of the markers is in it.

The fixture is read against the list the code gives. A field the code lists and the fixture does not fill (a new key of the settings, or a new key in a container the fixture has) fails
`test_the_fixture_plants_a_marker_in_every_field_the_code_lists`, so it cannot be passed over. One gap is left: a new list of containers (as `webhook_urls` is) that the fixture has no entry
for lists nothing, and is not seen here.
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-bundle-secrets-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

MARKER = re.compile(r'PLANTED\d\d')


def planted():
    """A settings document with a marker, PLANTEDnn, in each field `_nonname_config_secret_sites` lists, and beside some of them a field that is not a secret."""
    count = iter(range(1, 100))

    def mark():
        return 'PLANTED%02d' % next(count)
    cfg: dict = {k: 'https://hooks.example/%s' % mark() for k in ('webhook_url', 'healthchecks_url', 'siem_url', 'audit_forward_url', 'otlp_endpoint')}
    cfg['agentless_ssh_key'] = '-----BEGIN OPENSSH PRIVATE KEY----- %s' % mark()
    cfg['warranty_lenovo_client_id'] = mark()
    cfg['metrics_push'] = {'url': 'https://m.example/%s' % mark(), 'interval': 60}
    cfg['gitops'] = {'auth_header': 'Bearer %s' % mark(), 'repo': 'git@example.org:ops/config.git'}
    cfg['webhook_urls'] = [{'label': 'slack', 'url': 'https://hooks.slack.com/services/%s' % mark(), 'pushover_user': mark(), 'headers': {'Authorization': mark()}}]
    cfg['integrations'] = [{'type': 'unifi', 'label': 'the gateway', 'url': 'https://admin:%s@gw.example/' % mark()}]
    cfg['cloud_accounts'] = [{'label': 'prod', 'secret_key': mark()}]
    return cfg


class TestTheBundleHoldsNoSecretOfTheSettings(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self.api.verify_token = lambda t: {'k': ('admin', 'admin'), 'v': ('vera', 'viewer')}.get(t, (None, None))
        self.api.audit_log = lambda *a, **k: None
        self.cfg = planted()
        self.api.save(self.api.CONFIG_FILE, self.cfg)
        self.api._LOAD_CACHE.clear()

    def bundle(self, token='k'):
        """(status the handler answered with, or None when it wrote the bundle itself, what it wrote, the bundle as a document or None)."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status, _body = _run(self.api, lambda: self.api.handle_diagnostics_bundle(), None, method='GET', env={'HTTP_AUTHORIZATION': 'Bearer ' + token})
        text = out.getvalue()
        return status, text, (json.loads(text.split('\n\n', 1)[1]) if '\n\n' in text else None)

    def test_the_fixture_plants_a_marker_in_every_field_the_code_lists(self):
        sites = self.api._nonname_config_secret_sites(self.cfg)
        unplanted = [k for c, k, _is_map, _userinfo in sites if not (isinstance(c, dict) and c.get(k))]
        self.assertEqual(unplanted, [], 'the code lists a field of the settings that this fixture puts no marker in: plant one, or the bundle is not tested for it')
        self.assertGreaterEqual(len(sites), 14, 'the list of fields was not read')
        markers = MARKER.findall(json.dumps(self.cfg))
        self.assertEqual(len(sites), len(markers), 'one marker for each field the code lists, and none anywhere else')
        stored = json.dumps(self.api.load(self.api.CONFIG_FILE))
        for m in markers:
            self.assertIn(m, stored, 'control: %s is in the settings themselves, so its absence from the bundle means something' % m)

    def test_none_of_the_markers_is_in_the_bundle_a_real_download_answers(self):
        status, text, doc = self.bundle()
        self.assertIsNone(status, 'the handler answered with a status instead of writing the bundle: %r' % (status,))
        self.assertIn('Status: 200 OK', text)
        assert doc is not None
        self.assertIn('config_scrubbed', doc)
        self.assertEqual(MARKER.findall(text), [], 'a secret of the settings is in the support bundle')
        for leak in ('BEGIN OPENSSH', 'hooks.slack.com', 'admin:', 'Bearer '):
            self.assertNotIn(leak, text, leak)

    def test_what_is_not_a_secret_is_still_there_so_the_bundle_is_not_just_empty(self):
        _status, _text, doc = self.bundle()
        assert doc is not None
        cfg = doc['config_scrubbed']
        self.assertEqual(cfg['integrations'][0]['type'], 'unifi')
        self.assertEqual(cfg['integrations'][0]['label'], 'the gateway')
        self.assertEqual(cfg['webhook_urls'][0]['label'], 'slack')
        self.assertEqual(cfg['metrics_push'].get('interval'), 60)
        self.assertEqual(cfg['gitops'].get('repo'), 'git@example.org:ops/config.git')

    def test_the_bundle_is_for_an_administrator_and_a_viewer_is_given_none(self):
        status, text, doc = self.bundle('v')
        self.assertEqual(status, 403, 'a viewer was not refused with a 403 (the control that the administrator above is let in is the test above)')
        self.assertIsNone(doc, 'a viewer was given a bundle')
        self.assertEqual(MARKER.findall(text), [])
        self.assertEqual(text, '', 'nothing is written for a viewer')


if __name__ == '__main__':
    unittest.main()
