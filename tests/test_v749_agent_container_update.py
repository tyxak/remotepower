#!/usr/bin/env python3
"""7.4.9 agent security pass: updating a container must not quietly make it less locked down.

The Containers page can update a standalone container: pull the image, stop and remove the old container, and start a new one from a
command line rebuilt out of `docker inspect`. The rebuild carried the name, restart policy, environment, labels, network mode,
privileged flag, ports, mounts, entrypoint and command, and nothing else, while its docstring promised "if inspect reveals config we
can't faithfully reproduce, the caller aborts". Nothing aborted. A container started with `--user 1000`, `--cap-drop ALL`,
`--read-only`, `--security-opt no-new-privileges`, a memory limit or another runtime came back as a root container with the default
capabilities, a writable root filesystem and no limits, on one click, and the operator's toast said it was recreated on the new image.
(The Windows agent refuses the verb outright for the same reason.) The rebuild also kept only the first word of a multi-word
entrypoint (`tini -- /entrypoint.sh` came back as `tini`), so a container could start without the arguments it needs.

The update now refuses when the container has a setting it cannot carry over, says which, and leaves the container running; the
entrypoint arguments go in front of the command, where the engine puts them.
"""
import copy
import importlib.machinery
import importlib.util
import json
import os
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get('RP_TEST_AGENT') or ROOT / 'client' / 'remotepower-agent.py')


def load_agent():
    loader = importlib.machinery.SourceFileLoader('agent_container_update', str(AGENT))
    spec = importlib.util.spec_from_loader('agent_container_update', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load_agent()

# What `docker inspect` prints for `docker run -d --name web -p 8080:80 nginx:1.27`, trimmed to the keys the rebuild reads and the
# defaults of the keys it does not (empty, null, zero or the engine's own default).
PLAIN = {
    'Name': '/web',
    'Config': {'Image': 'nginx:1.27', 'User': '', 'Env': ['PATH=/usr/local/sbin:/usr/bin', 'NGINX_VERSION=1.27'],
               'Cmd': ['nginx', '-g', 'daemon off;'], 'Entrypoint': ['/docker-entrypoint.sh'],
               'Labels': {'maintainer': 'NGINX Docker Maintainers'}},
    'HostConfig': {
        'Binds': None, 'NetworkMode': 'bridge', 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
        'PortBindings': {'80/tcp': [{'HostIp': '', 'HostPort': '8080'}]}, 'Privileged': False,
        'CapAdd': None, 'CapDrop': None, 'SecurityOpt': None, 'Devices': [], 'DeviceRequests': None,
        'DeviceCgroupRules': None, 'Tmpfs': None, 'Sysctls': None, 'GroupAdd': None, 'ExtraHosts': None, 'Links': None,
        'VolumesFrom': None, 'Dns': [], 'DnsSearch': [], 'DnsOptions': [], 'ReadonlyRootfs': False, 'Init': None,
        'PidMode': '', 'UsernsMode': '', 'UTSMode': '', 'IpcMode': 'private', 'Runtime': 'runc', 'CgroupParent': '',
        'Cgroup': '', 'Memory': 0, 'MemorySwap': 0, 'NanoCpus': 0, 'CpuQuota': 0, 'PidsLimit': None,
    },
    'NetworkSettings': {'Networks': {'bridge': {'Aliases': None}}},
}

# One change at a time: (what to set, where, to what, the word the refusal must contain).
HARDENED = [
    ('user', ('Config', 'User'), '1000:1000', 'user'),
    ('cap-drop', ('HostConfig', 'CapDrop'), ['ALL'], 'cap-drop'),
    ('cap-add', ('HostConfig', 'CapAdd'), ['NET_ADMIN'], 'cap-add'),
    ('security-opt', ('HostConfig', 'SecurityOpt'), ['no-new-privileges:true'], 'security-opt'),
    ('read-only', ('HostConfig', 'ReadonlyRootfs'), True, 'read-only'),
    ('device', ('HostConfig', 'Devices'), [{'PathOnHost': '/dev/fuse'}], 'dev nodes'),
    ('gpu', ('HostConfig', 'DeviceRequests'), [{'Driver': 'nvidia'}], 'accelerator'),
    ('tmpfs', ('HostConfig', 'Tmpfs'), {'/run': ''}, 'tmpfs'),
    ('sysctl', ('HostConfig', 'Sysctls'), {'net.core.somaxconn': '1024'}, 'sysctls'),
    ('group-add', ('HostConfig', 'GroupAdd'), ['video'], 'group-add'),
    ('extra host', ('HostConfig', 'ExtraHosts'), ['db:10.0.0.5'], 'extra hosts'),
    ('volumes-from', ('HostConfig', 'VolumesFrom'), ['data'], 'volumes-from'),
    ('dns', ('HostConfig', 'Dns'), ['10.0.0.53'], 'dns'),
    ('init', ('HostConfig', 'Init'), True, 'init'),
    ('pid host', ('HostConfig', 'PidMode'), 'host', 'pid mode'),
    ('userns', ('HostConfig', 'UsernsMode'), 'host', 'user namespace'),
    ('ipc host', ('HostConfig', 'IpcMode'), 'host', 'ipc mode'),
    ('runtime', ('HostConfig', 'Runtime'), 'runsc', 'runtime'),
    ('cgroup parent', ('HostConfig', 'CgroupParent'), '/limited', 'cgroup'),
    ('memory', ('HostConfig', 'Memory'), 268435456, 'memory limit'),
    ('cpus', ('HostConfig', 'NanoCpus'), 500000000, 'cpu limit'),
    ('pids', ('HostConfig', 'PidsLimit'), 100, 'pids limit'),
]


def variant(path, value):
    info = copy.deepcopy(PLAIN)
    info[path[0]][path[1]] = value
    return info


class TestWhatTheRebuildCanCarryOver(unittest.TestCase):

    def test_an_ordinary_container_is_still_rebuilt(self):
        argv, image = agent._container_run_argv('docker', copy.deepcopy(PLAIN))
        self.assertIsNotNone(argv, image)
        self.assertEqual(image, 'nginx:1.27')
        self.assertEqual(argv[:5], ['docker', 'run', '-d', '--name', 'web'])
        self.assertIn('8080:80/tcp', argv)

    def test_a_container_started_with_a_setting_the_rebuild_drops_is_refused(self):
        for name, path, value, word in HARDENED:
            with self.subTest(setting=name):
                argv, reason = agent._container_run_argv('docker', variant(path, value))
                self.assertIsNone(argv, f'{name}: the rebuild went ahead and dropped it: {argv}')
                self.assertIn(word, reason)

    def test_a_second_network_is_refused(self):
        info = copy.deepcopy(PLAIN)
        info['NetworkSettings']['Networks']['backend'] = {'Aliases': ['web']}
        argv, reason = agent._container_run_argv('docker', info)
        self.assertIsNone(argv)
        self.assertIn('network', reason)

    def test_the_entrypoint_keeps_its_arguments(self):
        info = copy.deepcopy(PLAIN)
        info['Config']['Entrypoint'] = ['tini', '--', '/entrypoint.sh']
        info['Config']['Cmd'] = ['serve', '--port', '80']
        argv, _ = agent._container_run_argv('docker', info)
        tail = argv[argv.index('nginx:1.27'):]
        self.assertEqual(tail, ['nginx:1.27', '--', '/entrypoint.sh', 'serve', '--port', '80'])
        self.assertEqual(argv[argv.index('--entrypoint') + 1], 'tini')


class TestTheUpdateLeavesARefusedContainerRunning(unittest.TestCase):

    def run_update(self, info):
        calls = []
        ids = iter(['sha256:' + 'a' * 64, 'sha256:' + 'b' * 64])

        def fake_run(argv, *a, **k):
            calls.append(list(argv))
            out = ''
            if argv[1:2] == ['inspect']:
                out = json.dumps([info])
            elif argv[1:3] == ['image', 'inspect']:
                out = next(ids)
            return types.SimpleNamespace(returncode=0, stdout=out, stderr='')
        with mock.patch.object(agent, '_which', lambda p: '/usr/bin/' + p), mock.patch.object(agent.subprocess, 'run', fake_run):
            res = agent._run_container_update('container:docker:update:web', 'docker', 'web')
        return res, calls

    def test_nothing_is_stopped_or_removed_when_the_rebuild_cannot_be_faithful(self):
        for name, path, value, word in HARDENED[:6]:
            with self.subTest(setting=name):
                res, calls = self.run_update(variant(path, value))
                verbs = [c[1] for c in calls]
                self.assertNotIn('stop', verbs, f'{name}: the container was stopped')
                self.assertNotIn('rm', verbs, f'{name}: the container was removed')
                self.assertNotIn('run', verbs, f'{name}: a new container was started without the setting')
                self.assertNotEqual(res['rc'], 0)
                self.assertIn('cannot safely recreate', res['output'])
                self.assertIn(word, res['output'])

    def test_the_control_an_ordinary_container_is_recreated(self):
        res, calls = self.run_update(copy.deepcopy(PLAIN))
        verbs = [c[1] for c in calls]
        self.assertEqual([v for v in verbs if v in ('stop', 'rm', 'run')], ['stop', 'rm', 'run'], calls)
        self.assertEqual(res['rc'], 0, res)


if __name__ == '__main__':
    unittest.main()
