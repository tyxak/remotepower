#!/usr/bin/env python3
"""A stand-in for the docker command line, for the tests of the agent's compose verbs (8.0.0).

It is not Docker. It models what `compose:update` and `compose:rollback` ask of it, no more: images by id, the tags that point at them, the
containers of a compose project with the image each was created from, and what `docker compose pull` and `docker compose up -d` do to them. It
answers only the exact argument lists the agent sends and refuses any other, so a changed call in the agent fails here instead of being guessed at.

One rule is the model of compose that the rollback depends on and is NOT checked against a real daemon: `up -d` recreates a service's container
when the image its reference now points at is not the image the container was created from, and creates a missing one. That is how a compose update
moves a project onto a pulled image, and it is why pointing the old reference back at the old image and running `up -d` recreates the container on it.

State is one JSON file (FAKE_DOCKER_STATE) and every call is appended to a log (FAKE_DOCKER_LOG), so a test can read what was asked, in order.

    images      {id: {}}
    tags        {reference: image id}
    registry    {reference: image id}            what `compose pull` fetches for a reference
    projects    {directory: {service: reference}}
    containers  {container id: {image, ref, service, dir, oneoff}}
    fail        {subcommand: true}               ps, inspect, image_inspect, tag, pull, up: exit 1; up_after: do what up does, then exit 1
    ps_extra    [text]                           more lines in the answer of `docker ps -q`, for what is not a container id
"""
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import NoReturn

INSPECT_FORMAT = '{{.Image}}|{{.Config.Image}}|{{index .Config.Labels "com.docker.compose.service"}}'
DIR_LABEL = 'label=com.docker.compose.project.working_dir='
ONEOFF_LABEL = 'label=com.docker.compose.oneoff=False'


def _die(message, code=1) -> NoReturn:
    sys.stderr.write(message + '\n')
    sys.exit(code)


def _load():
    return json.loads(Path(os.environ['FAKE_DOCKER_STATE']).read_text())


def _save(state):
    Path(os.environ['FAKE_DOCKER_STATE']).write_text(json.dumps(state))


def _service_containers(state, directory):
    return {cid: c for cid, c in state['containers'].items() if c['dir'] == directory and not c.get('oneoff')}


def _failing(state, name):
    if (state.get('fail') or {}).get(name):
        _die('fake docker: %s was told to fail' % name)


def _up(state, directory, pull_never):
    services = (state['projects'].get(directory) or {})
    if not services:
        _die('no configuration file provided: not found')
    out = []
    for service, ref in sorted(services.items()):
        resolved = state['tags'].get(ref)
        if resolved is None:
            if pull_never:
                _die('image %s not found locally and --pull never was given' % ref)
            fetched = state['registry'].get(ref)
            if fetched is None:
                _die('pull access denied for %s' % ref)
            state['images'].setdefault(fetched, {})
            state['tags'][ref] = resolved = fetched
        mine = [(cid, c) for cid, c in _service_containers(state, directory).items() if c['service'] == service]
        if mine and all(c['image'] == resolved for _, c in mine):
            out.append('Container %s  Running' % service)
            continue
        for cid, _ in mine:
            del state['containers'][cid]
        state['containers'][secrets.token_hex(32)] = {'image': resolved, 'ref': ref, 'service': service, 'dir': directory, 'oneoff': False}
        out.append('Container %s  %s' % (service, 'Recreated' if mine else 'Started'))
    print('\n'.join(out))


def main(argv):
    state = _load()
    with open(os.environ['FAKE_DOCKER_LOG'], 'a') as fh:
        fh.write(json.dumps({'argv': argv, 'cwd': os.getcwd()}) + '\n')
    if argv[:1] == ['ps']:
        _failing(state, 'ps')
        if argv[:4] != ['ps', '-a', '-q', '--no-trunc'] or len(argv) != 8 or argv[4] != '--filter' or argv[6] != '--filter':
            _die('fake docker: unsupported ps arguments %r' % (argv,), 2)
        if not argv[5].startswith(DIR_LABEL) or argv[7] != ONEOFF_LABEL:
            _die('fake docker: unsupported ps filters %r' % (argv,), 2)
        directory = argv[5][len(DIR_LABEL):]
        print('\n'.join(list(_service_containers(state, directory)) + list(state.get('ps_extra') or [])))
    elif argv[:1] == ['inspect']:
        _failing(state, 'inspect')
        if argv[1:3] != ['--format', INSPECT_FORMAT] or len(argv) < 4:
            _die('fake docker: unsupported inspect arguments %r' % (argv,), 2)
        for cid in argv[3:]:
            c = state['containers'].get(cid)
            if c is None:
                _die('Error: No such object: %s' % cid)
            print('%s|%s|%s' % (c['image'], c['ref'], c['service']))
    elif argv[:2] == ['image', 'inspect']:
        _failing(state, 'image_inspect')
        if argv[2:4] != ['--format', '{{.Id}}'] or len(argv) != 5:
            _die('fake docker: unsupported image inspect arguments %r' % (argv,), 2)
        if argv[4] not in state['images']:
            _die('Error: No such image: %s' % argv[4])
        print(argv[4])
    elif argv[:1] == ['tag']:
        _failing(state, 'tag')
        if len(argv) != 3 or argv[1].startswith('-') or argv[2].startswith('-'):
            _die('fake docker: unsupported tag arguments %r' % (argv,), 2)
        if argv[1] not in state['images']:
            _die('Error response from daemon: No such image: %s' % argv[1])
        state['tags'][argv[2]] = argv[1]
        _save(state)
    elif argv[:2] == ['compose', 'pull'] and len(argv) == 2:
        _failing(state, 'pull')
        directory = os.getcwd()
        for ref in sorted((state['projects'].get(directory) or {}).values()):
            fetched = state['registry'].get(ref)
            if fetched and '@' not in ref:
                state['images'].setdefault(fetched, {})
                state['tags'][ref] = fetched
        _save(state)
        print('Pulled')
    elif argv[:3] == ['compose', 'up', '-d'] and argv[3:] in ([], ['--pull', 'never']):
        _failing(state, 'up')
        _up(state, os.getcwd(), argv[3:] == ['--pull', 'never'])
        _save(state)
        if (state.get('fail') or {}).get('up_after'):
            _die('fake docker: up recreated some containers and then failed')
    else:
        _die('fake docker: unsupported command %r' % (argv,), 2)


class FakeDocker:
    """What a test holds: the shim on a PATH of its own, the state file and the log."""

    def __init__(self, root):
        self.root = Path(root)
        self.bin = self.root / 'bin'
        self.bin.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / 'state.json'
        self.log_path = self.root / 'calls.jsonl'
        shim = self.bin / 'docker'
        shim.write_text('#!/bin/sh\nexec "%s" "%s" "$@"\n' % (sys.executable, Path(__file__).resolve()))
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.log_path.write_text('')

    def env(self, with_docker=True):
        path = os.environ.get('PATH', '')
        if not with_docker:
            return {'PATH': os.pathsep.join(p for p in path.split(os.pathsep) if p and not os.path.exists(os.path.join(p, 'docker'))) or '/nonexistent'}
        return {'FAKE_DOCKER_STATE': str(self.state_path), 'FAKE_DOCKER_LOG': str(self.log_path), 'PATH': str(self.bin) + os.pathsep + path}

    def write(self, state):
        self.state_path.write_text(json.dumps(state))

    def read(self):
        return json.loads(self.state_path.read_text())

    def calls(self):
        return [json.loads(line) for line in self.log_path.read_text().splitlines() if line.strip()]

    def subcommands(self):
        """The calls as 'ps', 'inspect', 'tag', 'compose pull', 'compose up' ..., in order."""
        out = []
        for c in self.calls():
            a = c['argv']
            out.append(' '.join(a[:2]) if a[:1] in (['compose'], ['image']) else a[0])
        return out


if __name__ == '__main__':
    main(sys.argv[1:])
