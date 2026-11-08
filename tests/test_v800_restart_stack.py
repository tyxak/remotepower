#!/usr/bin/env python3
"""8.0.0: the "Restart the stack" command on the Server status page names every sidecar that is in use on this server.

The command was built from five conditions written out one by one (the scan worker, the push daemon, the syslog receiver, the flow receiver and the two units every
install has), so the SSH gateway, the KMIP key server and the web terminal were never in it: copying the command restarted the app and left three daemons on old code.
It is one list now (`_selfRestartUnits` in app-self.js), and what this file holds is the rule behind the bug:

  * each sidecar in use adds its own unit, and only a sidecar in use does (a unit systemctl does not know would fail the whole command, so the syslog, flow and KMIP
    daemons, which may run on another host, count only while their unit is active here);
  * the page's command, the sentence above it and the copy button name the same units;
  * every unit RemotePower ships as a systemd unit is either in the list or excused here with a reason, so the next sidecar cannot be left out the same way;
  * the web terminal daemon, which the page never mentioned, is reported by the server (an answer on its port) and has a row of its own.

The page code is run in a V8 isolate against the payload shapes the server sends (the harness of tests/test_v642_self_ui.py); nothing here greps for a string.
"""
import json
import os
import re
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-restart-stack-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_v642_self_ui import MiniRacer, _call, _ctx  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402

_ROOT = _TESTS.parent
BASE = ['remotepower-wsgi', 'remotepower-scheduler']
ALL_IN_ORDER = BASE + ['remotepower-scanner', 'remotepower-push', 'remotepower-sshgw', 'remotepower-webterm', 'remotepower-syslogd', 'remotepower-flowd', 'remotepower-kmipd']

# One sidecar in use at a time: (what the server reports, the unit it adds)
IN_USE = [
    ({'satellites': {'scanners': {'total': 2, 'online': 1}}}, 'remotepower-scanner'),
    ({'push': {'enabled': True, 'port': 8766, 'reachable': True}}, 'remotepower-push'),
    ({'sshgw': {'enabled': True, 'port': 8767, 'reachable': False}}, 'remotepower-sshgw'),
    ({'webterm': {'reachable': True, 'port': 8765}}, 'remotepower-webterm'),
    ({'syslog': {'unit': 'active', 'sources': 1}}, 'remotepower-syslogd'),
    ({'flow': {'unit': 'active', 'sources': 1}}, 'remotepower-flowd'),
    ({'kmip': {'unit': 'active', 'clients': 1, 'keys': 2}}, 'remotepower-kmipd'),
]
# What reads as "not in use here": a sidecar that is off, or that is not on this server
NOT_HERE = [
    {'satellites': {'scanners': {'total': 0, 'online': 0}}},
    {'push': {'enabled': False}},
    {'sshgw': {'enabled': False}},
    {'webterm': {'reachable': False, 'port': 8765}},
    {'syslog': {'unit': 'inactive', 'sources': 3}},
    {'flow': {'unit': 'failed', 'sources': 3}},
    {'kmip': {'unit': 'unknown', 'clients': 1, 'keys': 2}},
]
# Units that are shipped and are not part of restarting the stack, each with the reason
EXCUSED = {
    'remotepower-server-restart-run': 'the one-shot unit that performs a restart request: it is what the in-app Restart server button starts',
    'remotepower-server-update-run': 'the one-shot unit that performs an update request',
}


def _status(sub):
    return {'server_version': '8.0.0', 'runtime': {'storage_backend': 'sqlite', 'server_tier': 'wsgi', 'scheduler_configured': True, 'scheduler_running': True},
            'backup': {'last_run': 1, 'stores': 5}, 'subsystems': sub, 'cadence_jobs': {}}


def _page(sub):
    ctx = _ctx()
    ctx.eval("__mkel('self-status-body');")
    ctx.eval("__apiReplies['/self/status'] = " + json.dumps(_status(sub)) + ";")
    ctx.eval("__apiReplies['/version'] = {};")
    ctx.eval("loadSelfStatus();")
    return ctx, ctx.eval("__DOM['self-status-body'].innerHTML")


def _units(ctx, sub):
    return [u['unit'] for u in _call(ctx, "_selfRestartUnits(%s)" % json.dumps(sub))]


@unittest.skipIf(MiniRacer is None, "py_mini_racer not installed")
class TestTheCommandNamesTheSidecarsInUse(unittest.TestCase):

    def setUp(self):
        self.ctx = _ctx()

    def test_a_server_with_no_sidecar_restarts_the_two_units_every_install_has(self):
        for sub in ({}, None, {'error': 'probe failed'}):
            self.assertEqual(_units(self.ctx, sub), BASE, repr(sub))

    def test_each_sidecar_in_use_adds_its_own_unit_and_nothing_else(self):
        for sub, unit in IN_USE:
            self.assertEqual(_units(self.ctx, sub), BASE + [unit], unit)

    def test_a_sidecar_that_is_off_or_not_on_this_server_adds_nothing(self):
        for sub in NOT_HERE:
            self.assertEqual(_units(self.ctx, sub), BASE, json.dumps(sub))

    def test_the_gateway_is_named_while_it_is_switched_on_even_if_it_does_not_answer_because_a_restart_is_what_that_calls_for(self):
        self.assertEqual(_units(self.ctx, {'sshgw': {'enabled': True, 'reachable': False}}), BASE + ['remotepower-sshgw'])

    def test_all_in_use_is_every_unit_once_in_the_order_of_the_command(self):
        sub = {}
        for one, _unit in IN_USE:
            sub.update(one)
        got = _units(self.ctx, sub)
        self.assertEqual(got, ALL_IN_ORDER)
        self.assertEqual(len(got), len(set(got)))

    def test_the_page_prints_the_command_the_sentence_and_the_copy_button_from_the_same_units(self):
        sub = {}
        for one, _unit in IN_USE:
            sub.update(one)
        _ctx_, html = _page(sub)
        cmd = 'sudo systemctl restart ' + ' '.join(ALL_IN_ORDER)
        self.assertIn('<code class="self-restart-cmd">%s</code>' % cmd, html)
        self.assertIn('data-arg="%s"' % cmd, html)
        self.assertIn('This cleanly restarts the app workers, the out-of-band scheduler, the scan worker, the push daemon, the SSH gateway, the web terminal, '
                      'the syslog receiver, the flow receiver and the KMIP key server —', html)

    def test_the_page_of_a_server_with_nothing_else_says_the_two_it_restarts(self):
        _ctx_, html = _page({})
        self.assertIn('<code class="self-restart-cmd">sudo systemctl restart remotepower-wsgi remotepower-scheduler</code>', html)
        self.assertIn('This cleanly restarts the app workers and the out-of-band scheduler —', html)

    def test_a_single_sidecar_reads_as_a_sentence(self):
        _ctx_, html = _page({'kmip': {'unit': 'active', 'clients': 1, 'keys': 2}})
        self.assertIn('This cleanly restarts the app workers, the out-of-band scheduler and the KMIP key server —', html)
        self.assertIn('sudo systemctl restart remotepower-wsgi remotepower-scheduler remotepower-kmipd</code>', html)

    def test_a_row_for_the_web_terminal_is_ok_when_it_answers_and_muted_when_it_does_not_and_never_a_fault(self):
        def row(sub):
            self.ctx.eval("_selfStatusLast = %s;" % json.dumps(_status(sub)))
            rows = [r for r in _call(self.ctx, "_selfSidecarRows(_selfStatusLast)") if r['key'] == 'webterm-daemon']
            self.assertEqual(len(rows), 1, 'exactly one row for it')
            return rows[0]
        up = row({'webterm': {'reachable': True, 'port': 8765}})
        self.assertEqual((up['state'], up['status']), ('ok', 'Running'))
        self.assertIn('8765', up['detail'])
        for sub in ({'webterm': {'reachable': False, 'port': 8765}}, {}):          # the second is a server from before the probe
            down = row(sub)
            self.assertEqual((down['state'], down['status']), ('muted', 'Not detected locally'), json.dumps(sub))


class TestEveryShippedUnitIsRestartedOrExcused(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.shipped = sorted({p.stem for d in ('packaging', 'server/conf') for p in (_ROOT / d).glob('remotepower-*.service')})

    def listed(self):
        ctx = _ctx()
        sub = {}
        for one, _unit in IN_USE:
            sub.update(one)
        return _units(ctx, sub)

    @unittest.skipIf(MiniRacer is None, "py_mini_racer not installed")
    def test_every_unit_that_is_shipped_is_in_the_list_or_excused_with_a_reason(self):
        self.assertGreaterEqual(len(self.shipped), 8, "the population is not empty: %r" % self.shipped)
        listed = set(self.listed())
        unlisted = [u for u in self.shipped if u not in listed and u not in EXCUSED]
        self.assertEqual(unlisted, [], "a unit that ships and is not in the restart command (add it to _selfRestartUnits, or excuse it here with the reason)")

    def test_an_excused_unit_is_still_shipped_so_the_list_only_shrinks(self):
        gone = [u for u in EXCUSED if u not in self.shipped]
        self.assertEqual(gone, [], "an excused unit that is not shipped any more is an entry to delete")

    @unittest.skipIf(MiniRacer is None, "py_mini_racer not installed")
    def test_every_listed_unit_is_one_that_an_installer_creates(self):
        installers = " ".join(p.read_text() for p in (_ROOT / "packaging").glob("*.sh")) + (_ROOT / "install-server.sh").read_text()
        bad = [u for u in self.listed() if u not in self.shipped and (u + ".service") not in installers]
        self.assertEqual(bad, [], "a name in the command that no installer creates would fail the whole systemctl call")

    @unittest.skipIf(MiniRacer is None, "py_mini_racer not installed")
    def test_the_check_sees_a_unit_that_is_left_out(self):
        # the control: with the gateway taken out of the list the first test's rule reports it
        listed = set(self.listed()) - {"remotepower-sshgw"}
        self.assertEqual([u for u in self.shipped if u not in listed and u not in EXCUSED], ["remotepower-sshgw"])


class TestTheServerReportsTheWebTerminal(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self._env = os.environ.get('WEBTERM_PORT')
        os.environ['WEBTERM_PORT'] = str(self.port)

    def tearDown(self):
        self.sock.close()
        if self._env is None:
            os.environ.pop('WEBTERM_PORT', None)
        else:
            os.environ['WEBTERM_PORT'] = self._env

    def test_a_daemon_that_answers_on_its_port_is_reported_reachable_with_that_port(self):
        got = self.api._subsystems_status(int(time.time()))['webterm']
        self.assertEqual(got, {'reachable': True, 'port': self.port})

    def test_nothing_listening_is_reported_as_not_reachable_not_as_an_error(self):
        self.sock.close()
        got = self.api._subsystems_status(int(time.time()))['webterm']
        self.assertEqual(got, {'reachable': False, 'port': self.port})

    def test_the_default_port_is_the_one_the_daemon_listens_on(self):
        os.environ.pop('WEBTERM_PORT', None)
        daemon = (_ROOT / 'server' / 'webterm' / 'remotepower-webterm.py').read_text()
        self.assertIn('DEFAULT_BIND_PORT = 8765', daemon)
        got = self.api._subsystems_status(int(time.time()))['webterm']
        self.assertEqual(got['port'], 8765)
        self.assertTrue(re.search(r"WEBTERM_PORT", daemon), "the daemon reads the same variable")


if __name__ == '__main__':
    unittest.main()
