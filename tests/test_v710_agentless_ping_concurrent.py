"""The agentless reachability sweep pings with no lock held, and the pings run together.

`run_agentless_reachability_if_due` called `_ping_host` for each agentless device inside
`with _LockedUpdate(DEVICES_FILE)`. A host that is down waits out its timeout (two to four seconds), so a
fleet with a handful of down hosts held the devices lock for tens of seconds once a minute: every heartbeat
and every device edit queued behind it, and 446 agentless devices on a 2,000-device fleet kept the first
request from answering at all. Of the 601 lock blocks in server/cgi-bin it was the only one that waited on
the network.

It also stopped on a bad hostname. `socket.getaddrinfo('nas..lan')` raises UnicodeEncodeError, which is not
an OSError, so it escaped the probe, aborted the locked update and saved nothing for any device. The
agentless form stores whatever hostname it is given, so one typo ended agentless monitoring for the fleet.

These drive the real sweep with stand-in probes, so what is measured is the lock scope, the elapsed time,
what the sweep writes, and what it does when a device changes while its probe is in flight.
"""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_CGI_BIN = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util   # noqa: E402

_spec = importlib.util.spec_from_file_location("api_v710_agentless", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_DELAY = 0.3


def _seed(n):
    devs = {'al_%d' % i: {'name': 'h%d' % i, 'agentless': True, 'ip': '192.0.2.%d' % (i + 1),
                          'reachability': 'icmp', 'monitored': True} for i in range(n)}
    api.save(api.DEVICES_FILE, devs)
    return devs


class _Sweep(unittest.TestCase):

    def setUp(self):
        for f in (api.DEVICES_FILE, api.CONFIG_FILE):
            api.save(f, {})
        for name in ('fire_webhook', '_record_uptime'):
            p = patch.object(api, name)
            p.start()
            self.addCleanup(p.stop)

    def sweep(self, probe):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['last_agentless_ping'] = 0
        api.save(api.CONFIG_FILE, cfg)
        with patch.object(api, '_ping_host', probe):
            api.run_agentless_reachability_if_due()
        return api.load(api.DEVICES_FILE)


class TestNoLockWhileProbing(_Sweep):

    def test_no_probe_runs_inside_a_devices_lock_scope(self):
        _seed(5)
        log = []
        real = api._LockedUpdate

        def spy(path, non_blocking=False):
            cm = real(path, non_blocking)
            if path != api.DEVICES_FILE:
                return cm

            class _Scope:
                def __enter__(self_):
                    doc = cm.__enter__()
                    log.append('enter')
                    return doc

                def __exit__(self_, *exc):
                    log.append('exit')
                    return cm.__exit__(*exc)
            return _Scope()

        def probe(host, *a, **k):
            log.append('probe')
            return True

        with patch.object(api, '_LockedUpdate', spy):
            devs = self.sweep(probe)
        depth = inside = 0
        for event in log:
            if event == 'enter':
                depth += 1
            elif event == 'exit':
                depth -= 1
            elif depth > 0:
                inside += 1
        self.assertEqual(5, log.count('probe'), 'the stand-in probe never ran, so this proved nothing')
        self.assertEqual(1, log.count('enter'), 'the answers should be written in one locked update: %r' % log)
        self.assertEqual(0, inside, 'a probe ran while the devices lock was held: %r' % log)
        self.assertTrue(all(d['reachable'] for d in devs.values()))

    def test_a_device_can_be_written_while_its_probe_is_in_flight(self):
        """The same property seen from the other side: another writer gets the lock mid-sweep."""
        _seed(2)
        outcome = {}

        def probe(host, *a, **k):
            if 'tried' not in outcome:
                outcome['tried'] = True
                try:
                    with api._LockedUpdate(api.DEVICES_FILE, non_blocking=True) as store:
                        store['al_0']['notes'] = 'edited during the sweep'
                    outcome['ok'] = True
                except Exception as e:                         # LockBusy, or a nested-transaction error
                    outcome['error'] = type(e).__name__
            return True

        devs = self.sweep(probe)
        self.assertTrue(outcome.get('tried'))
        self.assertEqual({'tried': True, 'ok': True}, outcome, 'the devices lock was held while probing')
        self.assertEqual('edited during the sweep', devs['al_0']['notes'])
        self.assertTrue(devs['al_0']['reachable'])


class TestProbesRunTogether(_Sweep):

    def test_six_probes_finish_in_about_one_delay_not_six(self):
        _seed(6)
        threads = set()

        def probe(host, *a, **k):
            threads.add(threading.current_thread().name)
            time.sleep(_DELAY)
            return True

        t0 = time.monotonic()
        devs = self.sweep(probe)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, _DELAY * 6 / 2, 'six waits of %.1fs took %.2fs: they ran one after another' % (_DELAY, elapsed))
        self.assertGreaterEqual(elapsed, _DELAY, 'finished faster than one probe can: the stand-in did not wait')
        self.assertGreater(len(threads), 1, threads)
        self.assertEqual(6, sum(1 for d in devs.values() if d.get('reachable')))

    def test_every_device_gets_its_own_answer(self):
        _seed(8)
        down = {'192.0.2.2', '192.0.2.5'}
        devs = self.sweep(lambda host, *a, **k: host not in down)
        got = {d['ip']: d.get('reach_fails', 0) for d in devs.values()}
        self.assertEqual({'192.0.2.2': 1, '192.0.2.5': 1}, {ip: n for ip, n in got.items() if n})
        self.assertEqual(8, len(got))


class TestABadHostnameDoesNotEndTheSweep(_Sweep):

    def test_the_real_probe_raises_for_a_name_with_an_empty_label(self):
        """Control: the failure being guarded is real, not something the stand-in invents."""
        with self.assertRaises(Exception) as cm:
            api._ping_host('nas..lan', timeout=1)
        self.assertNotIsInstance(cm.exception, OSError)

    def test_one_malformed_hostname_counts_as_down_and_the_others_are_written(self):
        devs = _seed(3)
        devs['al_1']['ip'] = 'nas..lan'
        api.save(api.DEVICES_FILE, devs)
        real = api._ping_host

        def probe(host, *a, **k):
            return real(host, timeout=1) if host == 'nas..lan' else True

        out = self.sweep(probe)
        self.assertTrue(out['al_0']['reachable'] and out['al_2']['reachable'])
        self.assertEqual(0, out['al_0']['reach_fails'])
        self.assertEqual(0, out['al_2']['reach_fails'])
        self.assertEqual(1, out['al_1']['reach_fails'], 'the bad name should count as one failed probe')


class TestADeviceChangedMidSweepIsLeftAlone(_Sweep):

    def test_deleted_readdressed_and_manual_devices_keep_their_state(self):
        _seed(5)

        def probe(host, *a, **k):
            if not getattr(probe, 'edited', False):
                probe.edited = True
                with api._LockedUpdate(api.DEVICES_FILE, non_blocking=True) as store:
                    store['al_0']['ip'] = '192.0.2.200'            # re-addressed
                    del store['al_1']                              # deleted
                    store['al_2']['reachability'] = 'manual'       # switched to manual
                    store['al_3']['notes'] = 'edited'              # an unrelated edit must survive
            return False

        devs = self.sweep(probe)
        self.assertTrue(getattr(probe, 'edited', False))
        self.assertNotIn('reach_fails', devs['al_0'], 'the answer was about the old address and must be dropped')
        self.assertEqual('192.0.2.200', devs['al_0']['ip'])
        self.assertNotIn('al_1', devs, 'a device deleted during the sweep came back')
        self.assertNotIn('reach_fails', devs['al_2'])
        self.assertEqual('manual', devs['al_2']['reachability'])
        self.assertEqual('edited', devs['al_3']['notes'])
        self.assertEqual(1, devs['al_3']['reach_fails'])
        self.assertEqual(1, devs['al_4']['reach_fails'])


if __name__ == '__main__':
    unittest.main()
