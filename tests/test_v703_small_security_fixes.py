#!/usr/bin/env python3
"""Four smaller findings from the v7.0.3 whole-project audit.

None is dramatic on its own. Each is a rule this codebase already applies
everywhere else and missed in exactly one place, which is the shape that
survives review — the correct sites make the file read as though the rule is
enforced.

  * the deadman ping compared its credential with `==`;
  * running an Ansible playbook resolved targets and read two stores before any
    authentication, so an unauthenticated caller could tell an existing
    playbook id from a missing one by the status code;
  * a scoped credential's "applies to N hosts" count was computed over the
    unfiltered device store while the rows beside it were tenant-filtered;
  * the web terminal installer wrote its shared secret with a plain `>` and
    passed it on a command line.
"""
import ast
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_API = _ROOT / 'server' / 'cgi-bin' / 'api.py'
_CMDB = _ROOT / 'server' / 'cgi-bin' / 'cmdb_handlers.py'
_INSTALL = _ROOT / 'packaging' / 'install-webterm.sh'


def _body(path, name):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.unparse(node)
    raise AssertionError(f'{name} not found in {path.name}')


class TestTokenComparisonsAreConstantTime(unittest.TestCase):

    def test_the_deadman_ping_uses_compare_digest(self):
        body = _body(_API, 'handle_deadman_ping')
        self.assertIn('hmac.compare_digest', body)
        self.assertNotIn("j.get('token') == tok", body)

    def test_no_handler_authenticates_a_token_with_equals(self):
        """The class, so the next one is caught rather than reviewed.

        A `token ==` inside a function that ALSO uses compare_digest is not a
        credential check — the two inbound-webhook sites match on an already
        authenticated token to bump its hit counter. Flag only a function that
        compares a token and never does it in constant time anywhere.
        """
        tree = ast.parse(_API.read_text(encoding='utf-8'))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            body = ast.unparse(node)
            if re.search(r"get\('token'\)\s*==\s*\w", body) \
                    and 'compare_digest' not in body:
                offenders.append(node.name)
        self.assertEqual(sorted(offenders), [],
                         f'token compared with == and nowhere in constant '
                         f'time: {sorted(offenders)}')

    def test_the_detector_separates_the_two_cases(self):
        """The control. It must flag a bare comparison and must NOT flag one in
        a function that authenticates properly and then matches the same token
        again to update a counter — otherwise it is noise, and a noisy gate
        gets switched off."""
        bare = ("def h(tok, jobs):\n"
                "    return next(j for j in jobs if j.get('token') == tok)\n")
        guarded = ("def h(tok, toks):\n"
                   "    m = [t for t in toks if hmac.compare_digest(t['token'], tok)]\n"
                   "    for t in toks:\n"
                   "        if t.get('token') == tok:\n"
                   "            t['hits'] += 1\n")

        def flags(src):
            fn = ast.parse(src).body[0]
            body = ast.unparse(fn)
            return bool(re.search(r"get\('token'\)\s*==\s*\w", body)
                        and 'compare_digest' not in body)

        self.assertTrue(flags(bare), 'the detector misses the real shape')
        self.assertFalse(flags(guarded), 'the detector flags a counter bump')


class TestAuthComesBeforeWork(unittest.TestCase):

    def test_playbook_run_authenticates_before_reading_any_store(self):
        body = _body(_API, 'handle_ansible_playbook_run')
        gate = body.index('require_write_role')
        for marker in ('_ansible_load()', 'load(DEVICES_FILE)',
                       '_resolve_targets'):
            self.assertIn(marker, body)
            self.assertLess(
                gate, body.index(marker),
                f'{marker} runs before any authentication, so an anonymous '
                'caller reaches it — and the 404-vs-400 difference tells them '
                'whether a playbook id exists')

    def test_the_per_device_permission_check_is_still_there(self):
        """The coarse gate is an addition, not a replacement. Dropping the
        per-device check would pass the test above and be much worse."""
        body = _body(_API, 'handle_ansible_playbook_run')
        self.assertIn("require_perm('script', ids)", body)


class TestAggregateCountsAreScoped(unittest.TestCase):

    def test_the_credential_applies_to_count_uses_the_filtered_store(self):
        body = _body(_CMDB, 'handle_scoped_credentials_list')
        self.assertIn('_scope_filter_devices', body,
                      'the applies_to count is computed over the device store; '
                      'unfiltered, it reports how many of ANOTHER tenant\'s '
                      'hosts a credential would match')
        self.assertIn('applies_to', body)


class TestTheWebtermSecretIsNeverWorldReadable(unittest.TestCase):

    def setUp(self):
        self.src = _INSTALL.read_text()

    def test_the_secret_file_is_created_under_a_tight_umask(self):
        """A plain `>` creates the file 0644 under root's default umask, so the
        secret is world-readable between the write and the chmod two lines
        later. install-server.sh fixed exactly this for the KMIP secret."""
        self.assertIn('umask 077', self.src)
        self.assertNotIn("printf '%s' \"$SECRET\" > \"$SECRET_FILE\"\n",
                         self.src.replace('( umask 077; ', ''))

    def test_the_secret_is_not_passed_on_a_command_line(self):
        """argv is world-readable in /proc/<pid>/cmdline for the life of the
        process. docker/agent-entrypoint.sh documents the same rule."""
        self.assertNotIn("cfg['webterm_daemon_secret'] = '$SECRET'", self.src)
        self.assertIn('sys.stdin.read()', self.src)


class TestTheStaleWindowsInstallerIsGone(unittest.TestCase):
    """It installed the LINUX agent as a Windows service and downloaded nssm
    over the network with no hash or signature check, as SYSTEM. The current
    installer, client/install-windows.ps1, verifies both. Shipping the old one
    in the release tarball made it reachable by anyone following a stale link."""

    def test_the_root_level_installer_no_longer_exists(self):
        self.assertFalse((_ROOT / 'install-client.ps1').exists())

    def test_the_real_installer_is_still_there_and_still_verifies(self):
        real = _ROOT / 'client' / 'install-windows.ps1'
        self.assertTrue(real.exists())
        src = real.read_text(encoding='utf-8', errors='replace')
        self.assertIn('GetCertHashString', src)

    def test_no_doc_points_at_the_deleted_file(self):
        for rel in ('docs/architecture.md', 'README.md', 'docs/install.md'):
            path = _ROOT / rel
            if path.exists():
                self.assertNotIn('install-client.ps1', path.read_text(), rel)


if __name__ == '__main__':
    unittest.main()
