"""v6.4.0 — two monitor-save defects found from a field report ("adding a
monitor 400s, only for http/https checks").

1. **The rejection message could not be acted on.** Every bad target produced
   `Invalid monitor target: <url>`, which does not distinguish a typo'd URL
   from a perfectly good one that THIS SERVER's resolver answers with a
   blocked address. The reporter's site resolved to loopback on the
   RemotePower host, so the fix was one checkbox — but nothing in the error
   said so.

2. **One stale monitor blocked every other monitor edit.** The editor re-posts
   the WHOLE list, so a single pre-existing entry that no longer validates
   (deleted satellite, older-schema tcp entry without a port, a target whose
   DNS answer changed) 400'd the entire save — and the error named the OTHER
   monitor. An untouched broken entry is now carried through with a warning;
   only the entry the operator actually touched hard-fails.
"""

import importlib.machinery
import importlib.util
import os
import socket
import tempfile
import unittest

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_ldr = importlib.machinery.SourceFileLoader(
    'api', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'server', 'cgi-bin', 'api.py'))
_spec = importlib.util.spec_from_loader('api', _ldr)
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_REAL_GETADDRINFO = socket.getaddrinfo


def _fake_dns(mapping):
    """Resolve only the hosts in `mapping`; everything else really resolves."""
    def f(host, *a, **k):
        if host in mapping:
            return [(socket.AF_INET, 1, 6, '', (mapping[host], 0))]
        return _REAL_GETADDRINFO(host, *a, **k)
    return f


class _SaveCase(unittest.TestCase):
    def setUp(self):
        self.cap = {}
        self._real = {n: getattr(api, n) for n in
                      ('respond', 'verify_token', 'audit_log', '_env', 'method',
                       'get_json_obj')}

        def _resp(status, body=None):
            self.cap['s'], self.cap['b'] = status, body
            raise api.HTTPError(status, body)
        api.respond = _resp
        api.audit_log = lambda *a, **k: None
        api._env = lambda k, d='': d
        api.method = lambda: 'POST'
        # Only identity is stubbed — the real admin gate runs.
        api.verify_token = lambda *a, **k: ('admin', 'admin')
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def tearDown(self):
        for n, v in self._real.items():
            setattr(api, n, v)
        socket.getaddrinfo = _REAL_GETADDRINFO

    def save(self, monitors):
        api.get_json_obj = lambda: {'monitors': monitors}
        self.cap.clear()
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        return self.cap.get('s'), self.cap.get('b') or {}

    def stored(self):
        api._invalidate_load_cache(api.CONFIG_FILE)
        return (api.load(api.CONFIG_FILE) or {}).get('monitors') or []

    def seed(self, monitors):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['monitors'] = monitors
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)


class TestRejectionMessagesAreActionable(_SaveCase):
    """The reported symptom: a 400 the operator cannot act on."""

    def test_loopback_target_names_the_ip_and_the_setting(self):
        socket.getaddrinfo = _fake_dns({'bymanden.dk': '127.0.0.1'})
        status, body = self.save([{'label': 'site', 'type': 'http',
                                   'target': 'https://bymanden.dk',
                                   'target_kind': 'host'}])
        self.assertEqual(status, 400)
        err = body['error']
        self.assertIn('127.0.0.1', err, 'must name what it resolved to')
        self.assertIn('loopback', err)
        # The whole point: tell them the exact setting that permits it.
        self.assertIn('Allow monitoring of internal / loopback targets', err)

    def test_enabling_the_setting_makes_that_exact_save_succeed(self):
        """The message promises a fix — the fix must actually work, or the
        text is the 'UI that lies' class all over again."""
        socket.getaddrinfo = _fake_dns({'bymanden.dk': '127.0.0.1'})
        mon = [{'label': 'site', 'type': 'http', 'target': 'https://bymanden.dk',
                'target_kind': 'host'}]
        self.assertEqual(self.save(mon)[0], 400)
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['allow_internal_monitors'] = True
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(self.save(mon)[0], 200)

    def test_filtered_resolver_answer_is_explained(self):
        """Pi-hole/AdGuard answer 0.0.0.0 for a blocked domain — the operator
        would otherwise have no idea why a public site is 'invalid'."""
        socket.getaddrinfo = _fake_dns({'ads.example': '0.0.0.0'})
        status, body = self.save([{'label': 'a', 'type': 'http',
                                   'target': 'https://ads.example',
                                   'target_kind': 'host'}])
        self.assertEqual(status, 400)
        self.assertIn('0.0.0.0', body['error'])
        self.assertIn('resolver', body['error'].lower())

    def test_link_local_is_named_as_metadata(self):
        socket.getaddrinfo = _fake_dns({'meta.example': '169.254.169.254'})
        status, body = self.save([{'label': 'm', 'type': 'http',
                                   'target': 'http://meta.example',
                                   'target_kind': 'host'}])
        self.assertEqual(status, 400)
        self.assertIn('link-local', body['error'])

    def test_bad_scheme_says_what_a_url_needs(self):
        status, body = self.save([{'label': 'x', 'type': 'http',
                                   'target': 'ftp://files.example',
                                   'target_kind': 'host'}])
        self.assertEqual(status, 400)
        self.assertIn('http://', body['error'])
        self.assertIn('ftp', body['error'])

    def test_tcp_without_a_port_says_so(self):
        status, body = self.save([{'label': 'n', 'type': 'tcp',
                                   'target': 'nas.lan', 'target_kind': 'host'}])
        self.assertEqual(status, 400)
        self.assertIn('host:port', body['error'])

    def test_error_names_the_offending_monitor(self):
        """With a whole list posted, the operator must know WHICH row broke."""
        status, body = self.save([{'label': 'the-broken-one', 'type': 'tcp',
                                   'target': 'nope', 'target_kind': 'host'}])
        self.assertEqual(status, 400)
        self.assertIn('the-broken-one', body['error'])
        self.assertEqual(body.get('monitor'), 'the-broken-one')

    def test_unresolvable_host_is_still_allowed(self):
        """Regression: 'cannot classify' must not become 'reject' — that would
        break monitoring anything this server can't currently resolve."""
        def _boom(host, *a, **k):
            raise socket.gaierror('no such host')
        socket.getaddrinfo = _boom
        status, _ = self.save([{'label': 'u', 'type': 'http',
                                'target': 'https://not-yet.example',
                                'target_kind': 'host'}])
        self.assertEqual(status, 200)

    def test_public_target_is_unaffected(self):
        socket.getaddrinfo = _fake_dns({'ok.example': '141.95.63.19'})
        self.assertEqual(self.save([{'label': 'p', 'type': 'http',
                                     'target': 'https://ok.example',
                                     'target_kind': 'host'}])[0], 200)

    def test_rfc1918_lan_target_still_allowed_by_design(self):
        socket.getaddrinfo = _fake_dns({'nas.lan': '192.168.1.50'})
        self.assertEqual(self.save([{'label': 'lan', 'type': 'http',
                                     'target': 'http://nas.lan',
                                     'target_kind': 'host'}])[0], 200)


class TestStaleMonitorDoesNotBlockTheSave(_SaveCase):
    """The editor re-posts the whole list; one rotten entry used to veto it."""

    NEW = {'label': 'bymanden.dk', 'type': 'dns', 'target': 'bymanden.dk',
           'target_kind': 'host'}

    def _stored_entry(self, **over):
        """Round-trip an entry through a save so it matches the STORED shape
        byte-for-byte (that equality is what marks it 'untouched')."""
        base = {'label': 'x', 'type': 'ping', 'target': '10.0.0.1',
                'target_kind': 'host'}
        base.update(over)
        self.save([base])
        return self.stored()[0]

    def test_deleted_satellite_no_longer_vetoes_an_unrelated_add(self):
        sats = api.load(api.SATELLITES_FILE) or {}
        sats['sat-1'] = {'name': 'edge'}
        api.save(api.SATELLITES_FILE, sats)
        api._invalidate_load_cache(api.SATELLITES_FILE)
        stale = self._stored_entry(label='via-edge', via_satellite='sat-1')
        api.save(api.SATELLITES_FILE, {})            # satellite goes away
        api._invalidate_load_cache(api.SATELLITES_FILE)
        self.seed([stale])

        status, body = self.save([stale, self.NEW])
        self.assertEqual(status, 200, 'an untouched broken entry must not veto')
        self.assertIn('bymanden.dk', [m['label'] for m in self.stored()])
        self.assertIn('via-edge', [m['label'] for m in self.stored()],
                      'the broken monitor must be KEPT, not dropped')
        self.assertTrue(body.get('monitor_warnings'))
        self.assertIn('via-edge', body['monitor_warnings'][0])

    def test_stale_entry_kept_verbatim(self):
        stale = {'label': 'old', 'type': 'tcp', 'target': 'nas.lan',
                 'target_kind': 'host', 'paused': False}
        self.seed([stale])
        self.assertEqual(self.save([stale, self.NEW])[0], 200)
        kept = [m for m in self.stored() if m['label'] == 'old'][0]
        self.assertEqual(kept, stale, 'carried through unchanged, not rewritten')

    def test_touching_the_broken_entry_still_hard_fails(self):
        """The operator editing a broken monitor must be TOLD, not silently
        handed a success while their edit is discarded."""
        stale = {'label': 'old', 'type': 'tcp', 'target': 'nas.lan',
                 'target_kind': 'host', 'paused': False}
        self.seed([stale])
        edited = dict(stale, target='still-no-port')
        status, body = self.save([edited, self.NEW])
        self.assertEqual(status, 400)
        self.assertIn('old', body['error'])

    def test_a_brand_new_broken_monitor_hard_fails(self):
        self.seed([])
        status, _ = self.save([{'label': 'fresh', 'type': 'tcp',
                                'target': 'no-port', 'target_kind': 'host'}])
        self.assertEqual(status, 400)

    def test_deleting_a_monitor_works_despite_an_unrelated_stale_one(self):
        """Deletion posts the surviving list — it used to 400 for the same
        reason, trapping the operator with a monitor they could not remove."""
        stale = {'label': 'broken', 'type': 'tcp', 'target': 'nas.lan',
                 'target_kind': 'host', 'paused': False}
        good = {'label': 'good', 'type': 'ping', 'target': '10.0.0.9',
                'target_kind': 'host', 'paused': False}
        self.seed([stale, good])
        status, _ = self.save([stale])           # 'good' removed
        self.assertEqual(status, 200)
        self.assertEqual([m['label'] for m in self.stored()], ['broken'])

    def test_multiple_stale_entries_all_reported(self):
        a = {'label': 'a', 'type': 'tcp', 'target': 'x', 'target_kind': 'host',
             'paused': False}
        b = {'label': 'b', 'type': 'tcp', 'target': 'y', 'target_kind': 'host',
             'paused': False}
        self.seed([a, b])
        status, body = self.save([a, b, self.NEW])
        self.assertEqual(status, 200)
        self.assertEqual(len(body.get('monitor_warnings') or []), 2)

    def test_no_warnings_key_when_everything_is_clean(self):
        self.seed([])
        status, body = self.save([self.NEW])
        self.assertEqual(status, 200)
        self.assertNotIn('monitor_warnings', body)


class TestClientSurfacesTheWarning(unittest.TestCase):
    """A carried-through broken monitor must not rot unseen in the UI."""

    JS = None

    @classmethod
    def setUpClass(cls):
        import pathlib
        cls.JS = (pathlib.Path(__file__).resolve().parent.parent / 'server'
                  / 'html' / 'static' / 'js' / 'app.js').read_text()

    def test_helper_exists(self):
        self.assertIn('function _warnStaleMonitors', self.JS)

    def test_every_monitor_save_path_surfaces_warnings(self):
        # add, flow-add and delete all post the whole list, so all three can
        # come back with warnings.
        self.assertEqual(self.JS.count('_warnStaleMonitors(res.monitor_warnings)'), 3)


if __name__ == '__main__':
    unittest.main()
