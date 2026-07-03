"""v5.8.0 (B1.1): agent-side standalone-container update (pull + recreate).

Drives _run_container_update / _container_run_argv with a fake subprocess so no
docker is needed: verifies the compose-refusal, the already-up-to-date no-op,
the argv reconstruction from inspect data, and the recreate happy path.
"""
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CLIENT = _ROOT / 'client'
sys.path.insert(0, str(_CLIENT))

# Import the agent module (extensionless twin is byte-identical; load the .py).
_spec = importlib.util.spec_from_file_location(
    'rp_agent_cu', _CLIENT / 'remotepower-agent.py')
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class _Result:
    def __init__(self, rc=0, out='', err=''):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


def _inspect_json(**over):
    obj = {
        'Name': '/myapp',
        'Config': {
            'Image': 'nginx:latest',
            'Env': ['FOO=bar', 'TZ=UTC'],
            'Labels': {'maintainer': 'me',
                       'com.docker.compose.oci': 'x'},   # not the project label
            'Cmd': ['nginx', '-g', 'daemon off;'],
            'Entrypoint': None,
        },
        'HostConfig': {
            'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0},
            'Binds': ['/srv/data:/data', '/etc/app.conf:/etc/app.conf:ro'],
            'PortBindings': {'80/tcp': [{'HostIp': '', 'HostPort': '8080'}]},
            'NetworkMode': 'bridge',
            'Privileged': False,
        },
        'Mounts': [],
    }
    obj.update(over)
    return json.dumps([obj])


class TestArgvReconstruction(unittest.TestCase):
    def test_argv_covers_common_fields(self):
        info = json.loads(_inspect_json())[0]
        argv, image = agent._container_run_argv('docker', info)
        self.assertEqual(image, 'nginx:latest')
        s = ' '.join(argv)
        self.assertTrue(s.startswith('docker run -d'))
        self.assertIn('--name myapp', s)
        self.assertIn('--restart unless-stopped', s)
        self.assertIn('-e FOO=bar', s)
        self.assertIn('-v /srv/data:/data', s)
        self.assertIn('-v /etc/app.conf:/etc/app.conf:ro', s)
        self.assertIn('-p 8080:80/tcp', s)
        self.assertIn('--label maintainer=me', s)
        # compose/opencontainers labels are filtered out
        self.assertNotIn('com.docker.compose', s)
        # image precedes the command
        self.assertLess(argv.index('nginx:latest'), argv.index('daemon off;'))

    def test_no_image_aborts(self):
        info = {'Config': {}, 'HostConfig': {}}
        argv, reason = agent._container_run_argv('docker', info)
        self.assertIsNone(argv)


class _FakeRunner:
    """Scriptable subprocess.run: matches on the verb in argv[0:2]."""
    def __init__(self, mapping, before_id='sha256:AAA', after_id='sha256:BBB'):
        self.mapping = mapping
        self.calls = []
        self._ids = [before_id, after_id]   # image inspect returns these in order

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        verb = argv[1] if len(argv) > 1 else ''
        if verb == 'inspect':
            return _Result(0, self.mapping['inspect'])
        if argv[1:3] == ['image', 'inspect']:
            return _Result(0, self._ids.pop(0) if self._ids else 'sha256:BBB')
        if verb == 'pull':
            return _Result(*self.mapping.get('pull', (0, 'Pulled', '')))
        if verb in ('stop', 'rm'):
            return _Result(0, '')
        if verb == 'run':
            return _Result(*self.mapping.get('run', (0, 'newcontainerid', '')))
        return _Result(0, '')


class TestUpdateFlow(unittest.TestCase):
    def setUp(self):
        self._run = agent.subprocess.run
        self._which = agent._which
        agent._which = lambda p, **k: '/usr/bin/' + p

    def tearDown(self):
        agent.subprocess.run = self._run
        agent._which = self._which

    def test_compose_managed_refused(self):
        info = json.loads(_inspect_json())[0]
        info['Config']['Labels']['com.docker.compose.project'] = 'mystack'
        agent.subprocess.run = _FakeRunner({'inspect': json.dumps([info])})
        r = agent._run_container_update('container:docker:update:myapp',
                                        'docker', 'myapp')
        self.assertEqual(r['rc'], -1)
        self.assertIn('compose', r['output'])

    def test_already_up_to_date_no_recreate(self):
        fake = _FakeRunner({'inspect': _inspect_json()},
                           before_id='sha256:SAME', after_id='sha256:SAME')
        agent.subprocess.run = fake
        r = agent._run_container_update('container:docker:update:myapp',
                                        'docker', 'myapp')
        self.assertEqual(r['rc'], 0)
        self.assertIn('up to date', r['output'])
        self.assertNotIn(['docker', 'run', '-d'], [c[:3] for c in fake.calls])

    def test_recreate_happy_path(self):
        fake = _FakeRunner({'inspect': _inspect_json(), 'pull': (0, 'Pulled', ''),
                            'run': (0, 'deadbeef', '')})
        agent.subprocess.run = fake
        r = agent._run_container_update('container:docker:update:myapp',
                                        'docker', 'myapp')
        self.assertEqual(r['rc'], 0)
        self.assertIn('recreated', r['output'])
        verbs = [c[1] for c in fake.calls if len(c) > 1]
        self.assertIn('pull', verbs)
        self.assertIn('stop', verbs)
        self.assertIn('rm', verbs)
        self.assertIn('run', verbs)

    def test_pull_failure_leaves_container(self):
        fake = _FakeRunner({'inspect': _inspect_json(),
                            'pull': (1, '', 'manifest unknown')})
        agent.subprocess.run = fake
        r = agent._run_container_update('container:docker:update:myapp',
                                        'docker', 'myapp')
        self.assertNotEqual(r['rc'], 0)
        self.assertIn('pull failed', r['output'])
        # never touched the running container
        self.assertNotIn('rm', [c[1] for c in fake.calls if len(c) > 1])


class TestWiring(unittest.TestCase):
    def test_update_in_agent_allowlist(self):
        self.assertIn('update', agent.CONTAINER_ALLOWED_ACTIONS)

    def test_update_in_server_allowlist(self):
        import re as _re
        src = (_ROOT / 'server/cgi-bin/api.py').read_text()
        m = _re.search(r'CONTAINER_ACTION_ALLOWED\s*=\s*\(([^)]*)\)', src)
        self.assertIsNotNone(m, 'CONTAINER_ACTION_ALLOWED tuple not found')
        self.assertIn("'update'", m.group(1))

    def test_extensionless_in_sync(self):
        self.assertEqual((_CLIENT / 'remotepower-agent.py').read_bytes(),
                         (_CLIENT / 'remotepower-agent').read_bytes())


if __name__ == '__main__':
    unittest.main()
