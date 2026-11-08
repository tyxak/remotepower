#!/usr/bin/env python3
"""8.0.0: app discovery. The agent says which apps its host runs, and the server offers a monitor and a connector for each.

What has to hold, each with a test that fails when it does not:

  the CATALOG     every entry is well formed, names a connector that exists, and is recognised by each of its own signs and by no other app; a port that many apps use
                  recognises nothing by itself; an image, a process name (as `ss` cuts it to 15 characters) and a service (with an `@instance`) are signs;
  the AGENT       carries a copy of the matcher that tools/sync-app-catalog.py writes (a stale copy fails), and the copy answers exactly as the module does on any facts;
                  it reads the running services with one `systemctl list-units` and says nothing where systemd is not there;
  the SERVER      keeps from a heartbeat only what the catalog knows, works the apps out for an older agent from the ports and containers it did report, offers a connector with
                  an address only for an app the server can reach, offers a monitor only where a host's agent could run it, creates a monitor only for what the host reports now
                  (the port is never taken from the request), does not double a monitor or a connector that is already there, and lets only an administrator write.

The monitor and the connector are checked against the same validators a saved monitor and a saved integration go through; no app was installed to test them.
"""
import copy
import importlib.machinery
import importlib.util
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-app-discovery-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import app_catalog as C  # noqa: E402
import integrations as I  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

ROOT = _TESTS.parent
KINDS = {'web', 'database', 'observability', 'network', 'media', 'download', 'home', 'storage', 'cloud', 'dev', 'messaging', 'orchestration'}


def listener(port, process='', scope='lan', proto='tcp'):
    return {'port': port, 'proto': proto, 'process': process, 'scope': scope}


def ids(found):
    return [f['id'] for f in found]


class TestTheCatalogIsWellFormed(unittest.TestCase):

    def test_the_population_is_not_empty_and_the_ids_are_unique(self):
        self.assertGreaterEqual(len(C.APPS), 45)
        self.assertEqual(len({a['id'] for a in C.APPS}), len(C.APPS))

    def test_every_entry_is_made_of_the_right_kinds_of_things(self):
        for a in C.APPS:
            with self.subTest(app=a['id']):
                self.assertRegex(a['id'], r'^[a-z0-9_]{1,32}$')
                self.assertTrue(a['name'].strip())
                self.assertIn(a['kind'], KINDS)
                self.assertTrue(all(isinstance(p, int) and 0 < p < 65536 for p in a['ports']))
                self.assertTrue(all(0 < len(n) <= 15 for n in a['procs']), 'ss prints the first 15 characters of a process name')
                self.assertTrue(all(i == i.lower() and i.strip('/') == i and i for i in a['images']))
                self.assertFalse(any(u.endswith('.service') or '@' in u for u in a['units']), 'a service is named without .service and without @instance')
                self.assertIn(a['scheme'], ('', 'https'))
                self.assertTrue(a['procs'] or a['images'] or a['units'] or (a['distinct'] and a['ports']), 'every app has a sign that recognises it')
                self.assertTrue(not a['distinct'] or a['ports'])

    def test_every_connector_the_catalog_names_is_registered(self):
        named = {a['connector'] for a in C.APPS if a['connector']}
        self.assertGreaterEqual(len(named), 25)
        self.assertEqual(sorted(n for n in named if n not in I.CONNECTORS), [])

    def test_each_sign_of_an_app_recognises_that_app_and_no_other(self):
        checked = 0
        for a in C.APPS:
            probes = []
            for name in a['procs']:
                probes.append(('process', [listener((a['ports'] or (4242,))[0], name)], [], []))
            for image in a['images']:
                probes.append(('image', [], [{'image': 'ghcr.io/someone/' + image.split('/')[-1] + ':latest' if '/' not in image else 'docker.io/' + image + ':1', 'name': 'x', 'ports': [], 'status': 'running'}], []))
            for unit in a['units']:
                probes.append(('unit', [], [], [unit + '.service']))
            if a['distinct']:
                probes.append(('port', [listener(a['ports'][0], 'unknownproc')], [], []))
            for what, ports, containers, units in probes:
                with self.subTest(app=a['id'], sign=what):
                    got = ids(C.discover(ports, containers, units))
                    self.assertEqual(got, [a['id']], 'exactly this app, nothing else')
                    checked += 1
        self.assertGreaterEqual(checked, 180, 'the check looked at the signs: %d' % checked)

    def test_a_port_that_many_apps_use_recognises_nothing_by_itself(self):
        for port in (80, 443, 8080, 3000, 8000, 5000, 9090, 81, 8443):
            self.assertEqual(C.discover([listener(port, 'unknownproc')], [], []), [], port)
        for port, app in ((8096, 'jellyfin'), (32400, 'plex'), (8123, 'homeassistant'), (2283, 'immich'), (5432, 'postgres'), (8384, 'syncthing')):
            self.assertEqual(ids(C.discover([listener(port, 'x')], [], [])), [app], port)

    def test_a_shared_port_is_a_sign_when_another_sign_agrees(self):
        found = C.discover([listener(80, 'nginx'), listener(3000, 'x')], [], [])
        self.assertEqual(ids(found), ['nginx'])
        self.assertEqual(found[0]['via'], ['process', 'port'])
        found = C.discover([listener(3000, 'x')], [], ['grafana-server.service'])
        self.assertEqual((ids(found), found[0]['via'], found[0]['port']), (['grafana'], ['unit', 'port'], 3000))


class TestTheSigns(unittest.TestCase):

    def test_a_process_name_is_matched_whatever_its_case_and_as_ss_cuts_it(self):
        self.assertEqual(ids(C.discover([listener(32400, 'Plex Media Serv')], [], [])), ['plex'])
        self.assertEqual(ids(C.discover([listener(32400, 'plex media server (longer than ss prints)')], [], [])), ['plex'])
        self.assertEqual(ids(C.discover([listener(8989, 'SONARR')], [], [])), ['sonarr'])
        self.assertEqual(C.discover([listener(4242, 'jellyfin-other')], [], []), [])

    def test_only_tcp_listeners_count(self):
        self.assertEqual(C.discover([listener(8096, 'jellyfin', proto='udp')], [], []), [])
        self.assertEqual(ids(C.discover([listener(8096, 'jellyfin', proto='tcp6')], [], [])), ['jellyfin'])

    def test_an_image_is_matched_by_its_repository_in_every_spelling(self):
        for image in ('jellyfin', 'jellyfin/jellyfin', 'jellyfin/jellyfin:10.10', 'lscr.io/linuxserver/jellyfin:latest', 'ghcr.io/jellyfin/jellyfin@sha256:' + 'a' * 64,
                      'registry.lan:5000/team/jellyfin:v1', 'DOCKER.IO/Jellyfin/Jellyfin'):
            self.assertEqual(ids(C.discover([], [{'image': image, 'name': 'jf', 'ports': [], 'status': 'running'}], [])), ['jellyfin'], image)

    def test_an_image_that_only_contains_a_name_is_not_that_app(self):
        for image in ('jc21/nginx-proxy-manager', 'nginxinc/nginx-unprivileged', 'myorg/jellyfin-exporter', 'redis-commander/redis-commander'):
            self.assertNotIn(image.split('/')[-1] and 'nginx', ids(C.discover([], [{'image': image, 'ports': [], 'status': 'running'}], []))) if image.startswith('jc21') else None
        self.assertEqual(ids(C.discover([], [{'image': 'jc21/nginx-proxy-manager:latest', 'ports': []}], [])), ['npm'], 'it is Nginx Proxy Manager and not nginx')
        self.assertEqual(C.discover([], [{'image': 'nginxinc/nginx-unprivileged', 'ports': []}], []), [])
        self.assertEqual(C.discover([], [{'image': 'myorg/jellyfin-exporter', 'ports': []}], []), [])

    def test_a_container_that_is_not_running_is_not_an_app_that_runs(self):
        for status in ('exited', 'Exited (0) 3 hours ago', 'dead', 'created', 'paused', 'removing'):
            self.assertEqual(C.discover([], [{'image': 'jellyfin/jellyfin', 'ports': [], 'status': status}], []), [], status)
        for status in ('running', 'Up 2 hours', 'Up 2 hours (healthy)', '', None):
            self.assertEqual(ids(C.discover([], [{'image': 'jellyfin/jellyfin', 'ports': [], 'status': status}], [])), ['jellyfin'], repr(status))

    def test_the_published_ports_of_a_container_are_read_from_dockers_own_text(self):
        self.assertEqual(C._published_ports(['0.0.0.0:8096->8096/tcp, :::8096->8096/tcp']), [8096])
        self.assertEqual(C._published_ports(['0.0.0.0:18096->8096/tcp', '127.0.0.1:5432->5432/tcp']), [18096, 5432])
        self.assertEqual(C._published_ports(['0.0.0.0:53->53/udp', '8096/tcp', 'garbage', '', None, '0.0.0.0:99999->1/tcp', '0.0.0.0:0->1/tcp']), [])

    def test_the_port_of_a_container_is_the_published_one_that_belongs_to_the_app_else_the_first_published(self):
        c = {'image': 'jellyfin/jellyfin', 'name': 'jf', 'ports': ['0.0.0.0:9999->9999/tcp', '0.0.0.0:8096->8096/tcp'], 'status': 'running'}
        self.assertEqual(C.discover([listener(8096, 'docker-proxy', 'world')], [c], [])[0]['port'], 8096)
        c['ports'] = ['0.0.0.0:18096->8096/tcp']
        found = C.discover([listener(18096, 'docker-proxy', 'world')], [c], [])[0]
        self.assertEqual((found['port'], found['scope'], found['container']), (18096, 'world', 'jf'))
        c['ports'] = []
        self.assertIsNone(C.discover([], [c], [])[0]['port'], 'a container on the host network with nothing listening in the list has no port to say')

    def test_a_service_is_matched_with_or_without_the_suffix_and_the_instance(self):
        for unit in ('syncthing', 'syncthing.service', 'syncthing@jmo.service', 'syncthing@jmo'):
            self.assertEqual(ids(C.discover([], [], [unit])), ['syncthing'], unit)
        self.assertEqual(ids(C.discover([], [], ['postgresql@16-main.service'])), ['postgres'])
        self.assertEqual(C.discover([], [], ['syncthing-other.service', 'nginx-helper']), [])

    def test_the_result_is_in_the_order_of_the_catalog_with_the_signs_in_a_fixed_order_and_each_app_once(self):
        found = C.discover([listener(8096, 'jellyfin', 'world'), listener(80, 'nginx')], [{'image': 'jellyfin/jellyfin', 'name': 'jf', 'ports': [], 'status': 'running'}],
                           ['nginx.service', 'jellyfin.service'])
        self.assertEqual(ids(found), ['nginx', 'jellyfin'])
        self.assertEqual([f['via'] for f in found], [['process', 'unit', 'port'], ['process', 'container', 'unit', 'port']])
        order = [a['id'] for a in C.APPS]
        got = ids(C.discover([listener(5432, 'postgres'), listener(8096, 'jellyfin'), listener(80, 'nginx')], [], []))
        self.assertEqual(got, sorted(got, key=order.index))

    def test_the_scope_is_the_one_of_the_listener_and_an_app_with_no_listener_has_none(self):
        found = C.discover([listener(8096, 'jellyfin', 'local')], [], [])
        self.assertEqual((found[0]['port'], found[0]['scope']), (8096, 'local'))
        found = C.discover([], [], ['syncthing.service'])
        self.assertEqual((found[0]['port'], found[0]['scope']), (None, ''))

    def test_junk_in_never_raises_and_finds_nothing(self):
        for args in ((None, None, None), ('x', 5, {}), ([None, 5, 'x', {}, {'port': 'x'}, {'port': True, 'process': 'jellyfin'}], [None, 7, {'image': None}, {'image': 5, 'ports': 'x'}], [None, 5, ['a']]),
                     ([{'port': 8096, 'proto': None, 'process': None}], [{'image': '', 'ports': None}], [''])):
            got = C.discover(*args)
            self.assertIsInstance(got, list)
        self.assertEqual(ids(C.discover([{'port': 8096, 'proto': None, 'process': None}], [], [])), ['jellyfin'], 'a listener with no protocol is a TCP one, as the agent sends it')

    def test_a_hostile_amount_of_facts_is_bounded(self):
        ports = [listener(p, 'jellyfin') for p in range(1, 5000)]
        containers = [{'image': a['images'][0], 'name': 'c', 'ports': [], 'status': 'running'} for a in C.APPS if a['images']] * 20
        self.assertLessEqual(len(C.discover(ports, containers, ['nginx'] * 5000)), len(C.APPS), 'each app once, however much it is told')


class TestWhatAnAgentSaysIsCleaned(unittest.TestCase):

    def test_only_entries_the_catalog_knows_survive_in_the_shape_it_states(self):
        raw = [{'id': 'jellyfin', 'via': ['unit', 'process', 'telepathy', 5], 'port': 8096, 'scope': 'lan', 'container': 'jf'},
               {'id': 'jellyfin', 'port': 1}, {'id': 'not-an-app'}, {'id': 5}, 'x', None, {'id': 'plex', 'port': 70000, 'scope': 'moon', 'container': 'pé\x00'},
               {'id': 'syncthing', 'port': True, 'via': 'process', 'container': 'c' * 200}]
        got = C.clean_found(raw)
        self.assertEqual(got[0], {'id': 'jellyfin', 'via': ['process', 'unit'], 'port': 8096, 'scope': 'lan', 'container': 'jf'})
        self.assertEqual(got[1], {'id': 'plex', 'via': [], 'port': None, 'scope': '', 'container': ''})
        self.assertEqual(got[2], {'id': 'syncthing', 'via': [], 'port': None, 'scope': '', 'container': 'c' * 64})
        self.assertEqual(len(got), 3, 'an app once, and nothing the catalog does not know')

    def test_a_value_that_is_not_a_list_is_nothing_and_the_list_is_bounded(self):
        for raw in (None, 'jellyfin', {'id': 'jellyfin'}, 5, True):
            self.assertEqual(C.clean_found(raw), [])
        many = [{'id': a['id']} for a in C.APPS] * 3
        self.assertLessEqual(len(C.clean_found(many)), len(C.APPS))


def _agent():
    loader = importlib.machinery.SourceFileLoader('rp_agent_app_discovery', str(ROOT / 'client' / 'remotepower-agent.py'))
    spec = importlib.util.spec_from_loader('rp_agent_app_discovery', loader)
    mod = importlib.util.module_from_spec(spec)             # type: ignore[arg-type]
    loader.exec_module(mod)                                  # type: ignore[union-attr]
    return mod


class TestTheAgentsCopy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = _agent()

    def test_the_copy_is_what_the_tool_writes(self):
        r = subprocess.run([sys.executable, str(ROOT / 'tools' / 'sync-app-catalog.py'), '--check'], capture_output=True, text=True, timeout=60)
        self.assertEqual((r.returncode, r.stderr), (0, ''))

    def test_the_tool_sees_a_stale_copy(self):
        sys.path.insert(0, str(ROOT / 'tools'))
        spec = importlib.util.spec_from_file_location('sync_app_catalog', ROOT / 'tools' / 'sync-app-catalog.py')
        tool = importlib.util.module_from_spec(spec)         # type: ignore[arg-type]
        spec.loader.exec_module(tool)                         # type: ignore[union-attr]
        text = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertEqual(tool.splice(text, tool.render()), text)
        stale = text.replace("'jellyfin', 'Jellyfin', 'media'", "'jellyfin', 'Jellyfin?', 'media'")
        self.assertNotEqual(stale, text, 'the demonstration changed the copy')
        self.assertNotEqual(tool.splice(stale, tool.render()), stale)

    def test_the_agents_matcher_answers_exactly_as_the_module_does_on_any_facts(self):
        rng = random.Random(8)
        names = sorted({n for a in C.APPS for n in a['procs']} | {'docker-proxy', 'sshd', 'python3', ''})
        images = sorted({i for a in C.APPS for i in a['images']} | {'busybox', 'myorg/own'})
        units = sorted({u for a in C.APPS for u in a['units']} | {'cron', 'sshd'})
        ports = sorted({p for a in C.APPS for p in a['ports']} | {22, 4242})
        for n in range(400):
            ls = [listener(rng.choice(ports), rng.choice(names), rng.choice(('local', 'lan', 'world'))) for _ in range(rng.randint(0, 8))]
            cs = [{'image': rng.choice(images) + rng.choice(('', ':1', ':latest')), 'name': 'c%d' % i, 'status': rng.choice(('running', 'exited', 'Up 1h')),
                   'ports': ['0.0.0.0:%d->%d/tcp' % (rng.choice(ports), rng.choice(ports))] if rng.random() < .7 else []} for i in range(rng.randint(0, 5))]
            us = [rng.choice(units) + rng.choice(('', '.service', '@x.service')) for _ in range(rng.randint(0, 6))]
            self.assertEqual(self.agent.discover_apps(copy.deepcopy(ls), copy.deepcopy(cs), us), C.discover(copy.deepcopy(ls), copy.deepcopy(cs), us), (n, ls, cs, us))

    def test_the_agent_names_the_catalog_with_its_own_prefix_and_leaves_its_other_names_alone(self):
        self.assertEqual(len(self.agent._ac_APPS), len(C.APPS))
        self.assertTrue(callable(self.agent._ac_discover))
        self.assertFalse(hasattr(self.agent, 'APPS'))
        self.assertFalse(hasattr(self.agent, 'clean_found'), 'the part only the server needs is not copied')

    def test_discover_apps_takes_missing_lists(self):
        self.assertEqual(self.agent.discover_apps(None, None, None), [])


class TestRunningUnits(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = _agent()

    def run_with(self, stdout='', rc=0, which='/usr/bin/systemctl', error=None):
        def fake(argv, **kw):
            self.calls.append(argv)
            if error:
                raise error
            return subprocess.CompletedProcess(argv, rc, stdout, '')
        self.calls = []
        with mock.patch.object(self.agent, '_which', return_value=which), mock.patch.object(self.agent.subprocess, 'run', side_effect=fake):
            return self.agent._running_units()

    def test_the_service_names_of_what_systemd_runs_are_read_with_one_read_only_call(self):
        out = self.run_with('nginx.service loaded active running A high performance web server\n'
                            '  syncthing@jmo.service loaded active running Syncthing\n'
                            'user@1000.service loaded active running User Manager\n'
                            'docker.socket loaded active listening Docker Socket\n\n')
        self.assertEqual(out, ['nginx.service', 'syncthing@jmo.service', 'user@1000.service'])
        self.assertEqual(self.calls, [['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain', '--no-pager']])

    def test_where_systemd_is_not_there_or_does_not_answer_it_says_nothing(self):
        self.assertEqual(self.run_with(which=None), [])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.run_with('nginx.service x', rc=1), [])
        self.assertEqual(self.run_with(error=subprocess.TimeoutExpired('systemctl', 5)), [])
        self.assertEqual(self.run_with(error=OSError('gone')), [])

    def test_a_name_that_is_too_long_is_dropped_and_the_list_is_bounded(self):
        self.assertEqual(self.run_with('a%s.service l a r d\nb.service l a r d\n' % ('x' * 200)), ['b.service'])
        many = ''.join('svc%d.service l a r d\n' % i for i in range(1000))
        self.assertEqual(len(self.run_with(many)), 400)

    def test_the_heartbeat_puts_the_discovery_in_sysinfo_after_the_host_facts_it_reads(self):
        src = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        call = "sysinfo['discovered'] = discover_apps(sysinfo.get('listening_ports'), _LAST_CONTAINERS, _running_units())"
        self.assertEqual(src.count(call), 1)
        self.assertLess(src.index("sysinfo.update(get_host_health())"), src.index(call), 'after the listening ports are in sysinfo')
        self.assertLess(src.index("        if send_sysinfo:\n            sysinfo = {"), src.index(call), 'inside `if send_sysinfo:` and after `sysinfo = {...}`')
        self.assertEqual(src.count("_LAST_CONTAINERS[:] = payload['containers']"), 1)
        self.assertEqual((ROOT / 'client' / 'remotepower-agent').read_text(), src)


# ── the server ──────────────────────────────────────────────────────────────────────────────────────────────────────────────

def device(**kw):
    base = {'id': 'jf01', 'name': 'jf01', 'hostname': 'jf01.lan', 'os': 'Ubuntu 24.04', 'ip': '10.0.0.5', 'token': 'tok', 'last_seen': int(time.time()), 'sysinfo': {}}
    base.update(kw)
    return base


JF = {'id': 'jellyfin', 'via': ['process', 'port'], 'port': 8096, 'scope': 'lan', 'container': ''}
NG = {'id': 'nginx', 'via': ['process', 'port'], 'port': 80, 'scope': 'world', 'container': ''}


class _Server(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self.api.verify_token = lambda token: {'k': ('admin', 'admin'), 'v': ('vera', 'viewer')}.get(token, (None, None))
        self.audits = []
        self.api.audit_log = lambda *a, **k: self.audits.append(a)
        self.put({'jf01': device(sysinfo={'discovered': [JF, NG]})})

    def put(self, devices, **cfg):
        Path(self.api.DEVICES_FILE).write_text(json.dumps(devices))
        Path(self.api.CONFIG_FILE).write_text(json.dumps(cfg))
        self.api._LOAD_CACHE.clear()

    def cfg(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.CONFIG_FILE)

    def call(self, fn, *args, body=None, method='POST', token='k'):
        env = {'HTTP_AUTHORIZATION': 'Bearer ' + token}
        return _run(self.api, lambda: fn(*args), body, method=method, env=env)

    def apps(self, dev_id='jf01', token='k'):
        st, body = self.call(self.api.handle_device_apps, dev_id, method='GET', token=token)
        self.assertEqual(st, 200, body)
        return body


class TestTheHeartbeatKeepsWhatTheCatalogKnows(_Server):

    def beat(self, **si):
        st, _ = _run(self.api, self.api.handle_heartbeat, {'device_id': 'jf01', 'token': 'tok', 'version': '8.0.0', 'sysinfo': dict({'hostname': 'jf01'}, **si)})
        self.assertEqual(st, 200)
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.DEVICES_FILE)['jf01']['sysinfo']

    def test_unknown_ids_bad_ports_and_junk_are_dropped_and_the_rest_is_kept(self):
        kept = self.beat(discovered=[JF, {'id': 'not-an-app', 'port': 1}, {'id': 'nginx', 'port': 'x', 'via': ['unit', 'rot13'], 'scope': 'moon'}, 'x', None])['discovered']
        self.assertEqual(kept, [JF, {'id': 'nginx', 'via': ['unit'], 'port': None, 'scope': '', 'container': ''}])

    def test_a_value_that_is_not_a_list_is_stored_as_nothing_and_an_agent_that_says_nothing_stores_nothing(self):
        self.assertEqual(self.beat(discovered='jellyfin')['discovered'], [])
        self.assertNotIn('discovered', self.beat())

    def test_the_host_list_does_not_carry_it_and_the_hosts_own_route_does(self):
        self.beat(discovered=[JF])
        st, rows = _run(self.api, self.api.handle_devices_list, method='GET', env={'HTTP_AUTHORIZATION': 'Bearer k'})
        self.assertEqual(st, 200)
        row = {r['id']: r for r in rows}['jf01']
        self.assertNotIn('discovered', row['sysinfo'], 'a list of every host polled every minute does not carry it')
        self.assertEqual([a['id'] for a in self.apps()['apps']], ['jellyfin'])


class TestTheHostsApps(_Server):

    def test_each_app_comes_with_its_state_and_what_can_be_done(self):
        body = self.apps()
        self.assertEqual((body['source'], body['monitor_problem']), ('agent', ''))
        jf, ng = body['apps']
        self.assertEqual((jf['id'], jf['name'], jf['kind'], jf['port'], jf['scope'], jf['via']), ('jellyfin', 'Jellyfin', 'media', 8096, 'lan', ['process', 'port']))
        self.assertEqual((jf['can_monitor'], jf['monitored'], jf['dismissed']), (True, False, False))
        self.assertEqual(jf['connector'], {'type': 'jellyfin', 'label': 'Jellyfin', 'url': 'http://10.0.0.5:8096', 'reachable': True, 'connected': False})
        self.assertIsNone(ng['connector'], 'nginx has no connector')

    def test_an_app_that_listens_on_the_host_only_cannot_be_reached_by_the_server_and_says_so(self):
        self.put({'jf01': device(sysinfo={'discovered': [dict(JF, scope='local')]})})
        c = self.apps()['apps'][0]['connector']
        self.assertEqual((c['reachable'], c['url']), (False, ''))

    def test_a_host_with_no_address_gives_no_url(self):
        self.put({'jf01': device(ip='', hostname='', sysinfo={'discovered': [JF]})})
        self.assertEqual(self.apps()['apps'][0]['connector']['url'], '')

    def test_an_address_in_a_tls_port_or_an_app_that_speaks_tls_gets_https(self):
        self.put({'jf01': device(sysinfo={'discovered': [dict(JF, port=8920), {'id': 'k3s', 'via': ['unit'], 'port': 6443, 'scope': 'lan', 'container': ''}]})})
        urls = [a['connector']['url'] for a in self.apps()['apps']]
        self.assertEqual(urls, ['https://10.0.0.5:8920', 'https://10.0.0.5:6443'])

    def test_an_older_agent_gets_its_apps_worked_out_from_the_ports_and_containers_it_did_report(self):
        self.put({'jf01': device(sysinfo={'listening_ports': [listener(8096, 'jellyfin', 'lan'), listener(80, 'nginx', 'world')]})})
        Path(self.api.CONTAINERS_FILE).write_text(json.dumps({'jf01': {'ts': 1, 'items': [{'name': 'pg', 'image': 'postgres', 'tag': '16', 'ports': ['127.0.0.1:5432->5432/tcp'], 'status': 'running'}]}}))
        self.api._LOAD_CACHE.clear()
        body = self.apps()
        self.assertEqual(body['source'], 'server')
        self.assertEqual([a['id'] for a in body['apps']], ['nginx', 'postgres', 'jellyfin'])

    def test_a_windows_or_macos_host_has_nothing_worked_out_for_it_the_catalog_is_linuxs(self):
        for os_name in ('Windows 11 Pro', 'macOS 15.2', 'Darwin 24'):
            self.put({'jf01': device(os=os_name, sysinfo={'listening_ports': [listener(8096, 'jellyfin'), listener(80, 'nginx')]})})
            body = self.apps()
            self.assertEqual((body['source'], body['apps']), ('server', []), os_name)

    def test_an_agent_that_says_it_found_nothing_is_believed_and_the_server_does_not_guess(self):
        self.put({'jf01': device(sysinfo={'discovered': [], 'listening_ports': [listener(8096, 'jellyfin')]})})
        body = self.apps()
        self.assertEqual((body['source'], body['apps']), ('agent', []))

    def test_a_host_the_caller_does_not_know_is_a_404_and_a_wrong_method_a_405_and_a_viewer_may_read(self):
        st, _ = self.call(self.api.handle_device_apps, 'nope', method='GET')
        self.assertEqual(st, 404)
        st, _ = self.call(self.api.handle_device_apps, 'bad id!', method='GET')
        self.assertEqual(st, 404)
        st, _ = self.call(self.api.handle_device_apps, 'jf01', method='POST')
        self.assertEqual(st, 405)
        self.assertEqual(len(self.apps(token='v')['apps']), 2)
        st, _ = self.call(self.api.handle_device_apps, 'jf01', method='GET', token='nobody')
        self.assertEqual(st, 401)

    def test_a_monitor_that_looks_at_the_port_marks_the_app_monitored(self):
        for mon in ({'type': 'tcp', 'target': '127.0.0.1:8096', 'via_host': 'jf01', 'label': 'a'}, {'type': 'tcp', 'target': '10.0.0.5:8096', 'label': 'b'},
                    {'type': 'http', 'target': 'http://jf01.lan:8096/health', 'label': 'c'}, {'type': 'tcp', 'target': 'jf01:8096', 'label': 'd'}):
            self.put({'jf01': device(sysinfo={'discovered': [JF]})}, monitors=[mon])
            self.assertTrue(self.apps()['apps'][0]['monitored'], mon)
        for mon in ({'type': 'tcp', 'target': '127.0.0.1:8096', 'label': 'a'}, {'type': 'tcp', 'target': '10.0.0.9:8096', 'label': 'b'}, {'type': 'tcp', 'target': '10.0.0.5:8097', 'label': 'c'},
                    {'type': 'tcp', 'target': '10.0.0.5:8096', 'via_satellite': 'sat1', 'label': 'd'}, {'type': 'ping', 'target': '10.0.0.5', 'label': 'e'}, {'type': 'tcp', 'target': 'x', 'label': 'f'},
                    {'type': 'tcp', 'target': '127.0.0.1:8096', 'via_host': 'other', 'label': 'g'}, 'junk', None):
            self.put({'jf01': device(sysinfo={'discovered': [JF]})}, monitors=[mon])
            self.assertFalse(self.apps()['apps'][0]['monitored'], mon)

    def test_an_integration_bound_to_the_host_or_pointed_at_its_address_marks_the_connector_connected(self):
        for inst in ({'type': 'jellyfin', 'device_id': 'jf01', 'url': 'http://elsewhere:1'}, {'type': 'jellyfin', 'url': 'http://10.0.0.5:8096'}, {'type': 'jellyfin', 'url': 'https://jf01.lan:8096/'},
                     {'type': 'jellyfin', 'url': 'http://jf01'}):
            self.put({'jf01': device(sysinfo={'discovered': [JF]})}, integrations=[dict(inst, id='i1', label='x', enabled=True)])
            self.assertTrue(self.apps()['apps'][0]['connector']['connected'], inst)
        for inst in ({'type': 'plex', 'url': 'http://10.0.0.5:8096'}, {'type': 'jellyfin', 'url': 'http://10.0.0.5:9999'}, {'type': 'jellyfin', 'url': 'http://10.0.0.6:8096'},
                     {'type': 'jellyfin', 'device_id': 'other', 'url': 'http://x'}, 'junk'):
            self.put({'jf01': device(sysinfo={'discovered': [JF]})}, integrations=[inst if isinstance(inst, str) else dict(inst, id='i1', label='x', enabled=True)])
            self.assertFalse(self.apps()['apps'][0]['connector']['connected'], inst)

    def test_a_host_that_cannot_run_a_probe_says_why_and_offers_no_monitor(self):
        for kw, word in ((dict(agentless=True), 'no agent'), (dict(os='Windows Server 2022'), 'Linux agent'), (dict(sysinfo={'discovered': [JF], 'audit_mode': True}), 'audit mode')):
            self.put({'jf01': device(**dict({'sysinfo': {'discovered': [JF]}}, **kw))})
            body = self.apps()
            self.assertIn(word, body['monitor_problem'], kw)
            self.assertFalse(body['apps'][0]['can_monitor'], kw)

    def test_with_the_integrations_switched_off_no_connector_is_offered_anywhere(self):
        self.put({'jf01': device(sysinfo={'discovered': [JF, NG]})}, show_homelab=False)
        body = self.apps()
        self.assertIs(body['show_homelab'], False)
        self.assertEqual([a['connector'] for a in body['apps']], [None, None])
        self.assertTrue(body['apps'][0]['can_monitor'], 'a monitor is still on offer: it is not an integration')
        st, fleet = self.call(self.api.handle_app_discovery, method='GET')
        self.assertEqual((st, fleet['apps'], fleet['show_homelab']), (200, [], False))
        self.put({'jf01': device(sysinfo={'discovered': [JF]})}, show_homelab=True)
        self.assertIs(self.apps()['show_homelab'], True)
        self.put({'jf01': device(sysinfo={'discovered': [JF]})})
        self.assertIs(self.apps()['show_homelab'], True, 'on unless it was switched off')

    def test_an_app_with_no_port_has_nothing_to_monitor(self):
        self.put({'jf01': device(sysinfo={'discovered': [{'id': 'syncthing', 'via': ['unit'], 'port': None, 'scope': '', 'container': ''}]})})
        row = self.apps()['apps'][0]
        self.assertEqual((row['can_monitor'], row['monitored']), (False, False))
        self.assertFalse(row['connector']['reachable'])


class TestMonitoringAnApp(_Server):

    def monitor(self, app='jellyfin', token='k', dev='jf01', **extra):
        return self.call(self.api.handle_device_app_monitor, dev, body=dict({'app': app}, **extra), token=token)

    def test_a_tcp_monitor_of_the_apps_port_is_made_to_run_from_the_hosts_own_agent(self):
        st, body = self.monitor()
        self.assertEqual(st, 200, body)
        mons = self.cfg()['monitors']
        self.assertEqual(len(mons), 1)
        self.assertEqual(mons[0], {'type': 'tcp', 'target': '127.0.0.1:8096', 'target_kind': 'host', 'paused': False, 'via_host': 'jf01', 'label': 'Jellyfin on jf01'})
        self.assertEqual((body['existing'], body['label']), (False, 'Jellyfin on jf01'))
        self.assertEqual([a[1] for a in self.audits], ['app_discovery_monitor'])
        self.assertTrue(self.apps()['apps'][0]['monitored'], 'the list now says so')

    def test_what_it_made_is_what_the_monitor_validators_accept(self):
        self.monitor()
        m = self.cfg()['monitors'][0]
        target, why = self.api._sanitize_monitor_target('tcp', m['target'], with_reason=True, allow_loopback=True)
        self.assertEqual((target, why), (m['target'], None))
        self.assertEqual(self.api.host_probe_validate('jf01', 'tcp', m), '')

    def test_a_second_press_answers_the_monitor_that_is_there_and_does_not_double_it(self):
        self.monitor()
        st, body = self.monitor()
        self.assertEqual((st, body['existing'], body['label']), (200, True, 'Jellyfin on jf01'))
        self.assertEqual(len(self.cfg()['monitors']), 1)
        self.assertEqual(len(self.audits), 1, 'nothing was done, so nothing is audited')

    def test_a_label_that_is_taken_gets_a_number(self):
        self.put({'jf01': device(sysinfo={'discovered': [JF]})}, monitors=[{'type': 'ping', 'target': '10.0.0.5', 'label': 'Jellyfin on jf01'}])
        st, body = self.monitor()
        self.assertEqual((st, body['label']), (200, 'Jellyfin on jf01 (2)'))
        self.assertEqual(len(self.cfg()['monitors']), 2, 'what was there is kept')

    def test_the_port_comes_from_what_the_host_reports_and_never_from_the_request(self):
        st, body = self.monitor(port=22, target='10.9.9.9:1', via_host='other', type='ping', label='mine')
        self.assertEqual(st, 200)
        m = self.cfg()['monitors'][0]
        self.assertEqual((m['target'], m['via_host'], m['type'], m['label']), ('127.0.0.1:8096', 'jf01', 'tcp', 'Jellyfin on jf01'))

    def test_an_app_the_host_does_not_report_is_a_404_and_an_app_that_is_not_in_the_catalog_a_400(self):
        self.assertEqual(self.monitor('plex')[0], 404)
        for junk in ('', 'not-an-app', '../../etc', 'JELLYFIN', 'x' * 100, 5, None):
            self.assertEqual(self.monitor(junk)[0], 400, repr(junk))
        self.assertNotIn('monitors', self.cfg())

    def test_an_app_with_no_known_port_is_a_400_in_words(self):
        self.put({'jf01': device(sysinfo={'discovered': [{'id': 'syncthing', 'via': ['unit'], 'port': None, 'scope': '', 'container': ''}]})})
        st, body = self.monitor('syncthing')
        self.assertEqual(st, 400)
        self.assertIn('no listening port', body['error'])

    def test_a_host_that_cannot_run_the_probe_is_refused_with_the_reason_and_nothing_is_saved(self):
        for kw, word in ((dict(agentless=True), 'no agent'), (dict(os='Windows Server 2022'), 'Linux agent'), (dict(sysinfo={'discovered': [JF], 'audit_mode': True}), 'audit mode')):
            self.put({'jf01': device(**dict({'sysinfo': {'discovered': [JF]}}, **kw))})
            st, body = self.monitor()
            self.assertEqual(st, 400, kw)
            self.assertIn(word, body['error'])
            self.assertNotIn('monitors', self.cfg())

    def test_only_an_administrator_writes_and_a_viewer_is_refused(self):
        st, _ = self.monitor(token='v')
        self.assertIn(st, (401, 403))
        st, _ = self.monitor(token='nobody')
        self.assertEqual(st, 401)
        self.assertNotIn('monitors', self.cfg())

    def test_the_wrong_method_and_an_unknown_host(self):
        st, _ = self.call(self.api.handle_device_app_monitor, 'jf01', method='GET')
        self.assertEqual(st, 405)
        self.assertEqual(self.monitor(dev='nope')[0], 404)

    def test_a_full_monitor_list_is_not_added_to(self):
        self.put({'jf01': device(sysinfo={'discovered': [JF]})}, monitors=[{'type': 'ping', 'target': '10.0.0.%d' % (i % 250), 'label': 'm%d' % i} for i in range(500)])
        st, body = self.monitor()
        self.assertEqual(st, 400)
        self.assertEqual(len(self.cfg()['monitors']), 500)


class TestHidingAnApp(_Server):

    def dismiss(self, app='jellyfin', token='k', **extra):
        return self.call(self.api.handle_device_app_dismiss, 'jf01', body=dict({'app': app}, **extra), token=token)

    def test_a_dismissed_app_moves_to_the_hidden_list_and_comes_back_with_dismissed_false(self):
        self.assertEqual(self.dismiss()[0], 200)
        body = self.apps()
        self.assertEqual(([a['id'] for a in body['apps']], [a['id'] for a in body['dismissed']]), (['nginx'], ['jellyfin']))
        self.assertEqual(self.cfg()['app_discovery_dismissed'], {'jf01': ['jellyfin']})
        st, out = self.dismiss(dismissed=False)
        self.assertEqual((st, out['dismissed']), (200, False))
        body = self.apps()
        self.assertEqual(([a['id'] for a in body['apps']], body['dismissed']), (['jellyfin', 'nginx'], []))
        self.assertEqual(self.cfg()['app_discovery_dismissed'], {}, 'nothing hidden leaves no entry')

    def test_hiding_twice_keeps_one_entry_and_each_host_has_its_own(self):
        self.dismiss()
        self.dismiss()
        self.dismiss('nginx')
        self.assertEqual(self.cfg()['app_discovery_dismissed'], {'jf01': ['jellyfin', 'nginx']})
        self.put({'jf01': device(sysinfo={'discovered': [JF]}), 'jf02': device(id='jf02', name='jf02', sysinfo={'discovered': [JF]})}, app_discovery_dismissed={'jf01': ['jellyfin']})
        st, body = self.call(self.api.handle_device_apps, 'jf02', method='GET')
        self.assertEqual([a['id'] for a in body['apps']], ['jellyfin'])

    def test_only_a_json_false_shows_it_again_and_the_rest_hides(self):
        for said in (None, True, 'false', 0, [], 'no'):
            self.dismiss(dismissed=said)
            self.assertEqual(self.cfg()['app_discovery_dismissed'], {'jf01': ['jellyfin']}, repr(said))
        self.dismiss(dismissed=False)
        self.assertEqual(self.cfg()['app_discovery_dismissed'], {})

    def test_a_setting_of_the_wrong_kind_hides_nothing_and_breaks_nothing(self):
        for junk in ('x', [1], {'jf01': 'jellyfin'}, {'jf01': [5, None]}, 5):
            self.put({'jf01': device(sysinfo={'discovered': [JF]})}, app_discovery_dismissed=junk)
            self.assertEqual(len(self.apps()['apps']), 1, repr(junk))
            self.assertEqual(self.dismiss()[0], 200, repr(junk))

    def test_the_catalog_the_method_the_role_and_the_host_are_checked(self):
        self.assertEqual(self.dismiss('not-an-app')[0], 400)
        self.assertEqual(self.dismiss('')[0], 400)
        self.assertIn(self.dismiss(token='v')[0], (401, 403))
        self.assertEqual(self.dismiss(token='nobody')[0], 401)
        self.assertEqual(self.call(self.api.handle_device_app_dismiss, 'nope', body={'app': 'jellyfin'})[0], 404)
        self.assertEqual(self.call(self.api.handle_device_app_dismiss, 'jf01', method='GET')[0], 405)
        self.assertNotIn('app_discovery_dismissed', self.cfg())

    def test_the_change_is_audited(self):
        self.dismiss()
        self.dismiss(dismissed=False)
        self.assertEqual([a[1] for a in self.audits], ['app_discovery_dismiss', 'app_discovery_dismiss'])


class TestFoundOnYourHosts(_Server):

    def fleet(self, token='k'):
        st, body = self.call(self.api.handle_app_discovery, method='GET', token=token)
        self.assertEqual(st, 200, body)
        return body

    def setUp(self):
        super().setUp()
        self.devices = {'jf01': device(sysinfo={'discovered': [JF, NG]}),
                        'ha01': device(id='ha01', name='ha01', ip='10.0.0.6', sysinfo={'discovered': [{'id': 'homeassistant', 'via': ['container'], 'port': 8123, 'scope': 'lan', 'container': 'ha'}]}),
                        'loc': device(id='loc', name='loc', ip='10.0.0.7', sysinfo={'discovered': [dict(JF, scope='local')]}),
                        'gone': device(id='gone', name='gone', ip='10.0.0.8', decommissioned=True, sysinfo={'discovered': [JF]}),
                        'sw': device(id='sw', name='sw', ip='10.0.0.9', agentless=True, sysinfo={'discovered': [JF]})}
        self.put(self.devices)

    def test_the_apps_a_connector_could_read_on_hosts_the_server_can_reach_are_listed_with_the_address(self):
        body = self.fleet()
        self.assertEqual([(a['device_id'], a['id'], a['connector']['url']) for a in body['apps']], [('ha01', 'homeassistant', 'http://10.0.0.6:8123'), ('jf01', 'jellyfin', 'http://10.0.0.5:8096')])
        self.assertEqual((body['hosts'], body['found']), (2, 4), 'found counts every app of the hosts that were looked at')

    def test_an_app_that_is_connected_or_hidden_is_not_offered(self):
        self.put(self.devices, integrations=[{'id': 'i1', 'type': 'jellyfin', 'label': 'x', 'enabled': True, 'url': 'http://10.0.0.5:8096'}], app_discovery_dismissed={'ha01': ['homeassistant']})
        self.assertEqual(self.fleet()['apps'], [])

    def test_a_host_the_caller_may_not_see_is_not_listed(self):
        seen = []

        def only_ha(devs):
            seen.append(sorted(devs))
            return {k: v for k, v in devs.items() if k == 'ha01'}
        self.api._scope_filter_devices = only_ha
        self.assertEqual([a['device_id'] for a in self.fleet()['apps']], ['ha01'])
        self.assertEqual(len(seen), 1, 'the host set went through the scope and tenant filter')

    def test_the_list_is_bounded_and_a_viewer_may_read_it(self):
        devs = {'h%03d' % i: device(id='h%03d' % i, name='h%03d' % i, sysinfo={'discovered': [JF]}) for i in range(260)}
        self.put(devs)
        self.assertEqual(len(self.fleet()['apps']), 200)
        self.assertEqual(len(self.fleet(token='v')['apps']), 200)
        st, _ = self.call(self.api.handle_app_discovery, method='GET', token='nobody')
        self.assertEqual(st, 401)
        st, _ = self.call(self.api.handle_app_discovery, method='POST')
        self.assertEqual(st, 405)


class TestTheRoutes(unittest.TestCase):

    def test_the_four_routes_are_in_the_table_with_their_methods_and_in_the_documentation_of_the_api(self):
        api = _fresh_api()
        rows = {r[4]: r for r in api._PATTERN_ROUTE_DEFS}
        for name, methods in (('handle_device_apps', ('GET',)), ('handle_device_app_monitor', ('POST',)), ('handle_device_app_dismiss', ('POST',)), ('handle_app_discovery', ('GET',))):
            self.assertIn(name, rows)
            self.assertEqual(rows[name][1], methods, name)
            self.assertTrue(callable(getattr(api, name)), name)
        documented = set(api._dispatcher_routes())
        for pair in (('GET', '/api/devices/{device_id}/apps'), ('POST', '/api/devices/{device_id}/apps/monitor'), ('POST', '/api/devices/{device_id}/apps/dismiss'), ('GET', '/api/app-discovery')):
            self.assertIn(pair, documented)


class TestTheGuide(unittest.TestCase):

    GUIDE = (ROOT / 'docs' / 'app-discovery.md').read_text()

    def test_every_app_of_the_catalog_is_named_in_the_guide_with_its_connector_mark(self):
        missing = [a['name'] for a in C.APPS if a['name'] + (' \u2731' if a['connector'] else '') not in self.GUIDE]
        self.assertEqual(missing, [], 'an app the catalog knows and the guide does not name (or names without the right mark)')

    def test_the_number_in_the_feature_table_is_the_catalogs(self):
        features = (ROOT / 'docs' / 'features.md').read_text()
        self.assertIn('(%d in the catalog,' % len(C.APPS), features)

    def test_the_guide_is_in_the_docs_index_and_its_routes_are_the_real_ones(self):
        self.assertIn('[app-discovery.md](app-discovery.md)', (ROOT / 'docs' / 'README.md').read_text())
        for route in ('GET /api/devices/<id>/apps', 'GET /api/app-discovery', 'POST /api/devices/<id>/apps/monitor', 'POST /api/devices/<id>/apps/dismiss'):
            self.assertIn('`%s`' % route, self.GUIDE)


if __name__ == '__main__':
    unittest.main()
