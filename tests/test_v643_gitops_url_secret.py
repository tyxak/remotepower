#!/usr/bin/env python3
"""A Git manifest URL is a credential, and it was handed to every role.

`GET /api/gitops` carefully masked `auth_header` down to a boolean and then
returned `url` verbatim to anyone holding a token — viewer, auditor, finance,
MCP. A Git URL routinely carries the credential inline:

    https://user:ghp_xxxxxxxxxxxx@github.com/org/repo.git

which makes the URL itself a reusable secret, exactly like the webhook URLs,
`siem_url`, `otlp_endpoint` and `metrics_push.url` that this codebase already
withholds from non-admins. GitOps simply never got the same treatment — the
hazard was understood, the rule was written down, and one field was missed.

Admins still receive it, deliberately: the Settings editor round-trips the value
on save, which is the same reason `webhook_urls[].url` stays visible to them. A
non-admin cannot save it back (PUT is require_admin_auth), so blanking it for
them cannot destroy a stored credential.

The second half is the audit log. `gitops_set` recorded the full URL, and an
audit log is rotated, shipped off-box and read by people who are not entitled to
the token in it. It now records the URL with the userinfo stripped, which still
names the repository — the thing an audit actually needs to answer.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-gitops-'))

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402

SECRET = 'ghp_liveTokenThatMustNotLeak'
URL = f'https://gituser:{SECRET}@github.com/acme/fleet-manifests.git'


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-go-'))
        self._saved = {}
        for name in ('CONFIG_FILE', 'USERS_FILE', 'GITOPS_STATE_FILE',
                     'AUDIT_LOG_FILE'):
            self._saved[name] = getattr(api, name)
            setattr(api, name, self.d / f'{name.lower()}.json')
        api.save(api.CONFIG_FILE, {'gitops': {
            'enabled': True, 'url': URL, 'interval': 900,
            'auth_header': 'Bearer somethingelse'}})
        api.save(api.USERS_FILE, {'boss': {'role': 'admin'},
                                  'watcher': {'role': 'viewer'}})
        self._rvt, self._rgt = api.verify_token, api.get_token_from_request
        self._rm = api.method
        api.get_token_from_request = lambda: 'tok'
        self._role = 'viewer'
        api.verify_token = lambda t: (
            'boss' if self._role == 'admin' else 'watcher', self._role)
        api.method = lambda: 'GET'

    def tearDown(self):
        api.verify_token, api.get_token_from_request = self._rvt, self._rgt
        api.method = self._rm
        for k, v in self._saved.items():
            setattr(api, k, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError as e:
            return e.status, e.body
        return None, None


class TestManifestUrlIsAdminOnly(_Base):

    def test_admin_still_receives_the_url(self):
        """POSITIVE CONTROL. Blanking it for everyone would also make the
        assertion below pass, while breaking the Settings editor that
        round-trips this value on save."""
        self._role = 'admin'
        st, body = self.call(api.handle_gitops_get)
        self.assertEqual(st, 200)
        self.assertEqual(body['url'], URL,
                         'the admin editor round-trips this value on save')

    def test_read_only_role_does_not_receive_the_url(self):
        self._role = 'viewer'
        st, body = self.call(api.handle_gitops_get)
        self.assertEqual(st, 200)
        self.assertNotIn(SECRET, repr(body),
                         f'the live token reached a read-only role: {body}')
        self.assertEqual(body['url'], '')

    def test_read_only_role_still_learns_that_one_is_configured(self):
        """Withholding the value must not hide the FACT — the UI still needs to
        say "configured" rather than imply GitOps is unset."""
        self._role = 'viewer'
        _, body = self.call(api.handle_gitops_get)
        self.assertTrue(body['url_set'])

    def test_auth_header_stays_masked_for_everyone(self):
        for role in ('admin', 'viewer'):
            self._role = role
            _, body = self.call(api.handle_gitops_get)
            self.assertNotIn('somethingelse', repr(body), role)
            self.assertTrue(body['auth_header_set'], role)


class TestUserinfoRedactionHelper(unittest.TestCase):
    """The helper keeps the PATH on purpose: for a Git manifest the repository
    is the useful, non-secret part, unlike a Slack webhook where the path IS the
    secret (which is why _redact_url_to_host drops it)."""

    def test_strips_credentials_keeps_repository(self):
        out = api._url_without_userinfo(URL)
        self.assertNotIn(SECRET, out)
        self.assertNotIn('gituser', out)
        self.assertIn('github.com', out)
        self.assertIn('/acme/fleet-manifests.git', out)

    def test_leaves_a_credential_free_url_alone(self):
        plain = 'https://github.com/acme/fleet-manifests.git'
        self.assertEqual(api._url_without_userinfo(plain), plain)

    def test_a_non_url_is_returned_unchanged_not_silently_cleaned(self):
        """A malformed value must not come back looking like a clean URL — that
        would hide a misconfiguration behind something reassuring."""
        self.assertEqual(api._url_without_userinfo('not a url'), 'not a url')

    def test_port_and_query_survive(self):
        out = api._url_without_userinfo('https://u:p@host:8443/a/b?ref=main')
        self.assertNotIn(':p@', out)
        self.assertIn('host:8443', out)
        self.assertIn('ref=main', out)


if __name__ == '__main__':
    unittest.main()
