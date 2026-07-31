"""v6.4.2 — per-container alert mutes ("mute everything for this container").

A container mute is a row in the SAME alert_mutes.json store, carrying a
`container` instead of an `event`. It silences every alert that names that
container on that host — inbox, webhook, push, needs-attention — while
fleet_events, the SIEM stream and auto-resolve keep working exactly as they do
for the older per-(host, event) mute.

Everything here DRIVES THE REAL PATH (_record_alert / fire_webhook /
_compute_attention / the handlers). A source-text assertion proves a line
exists, never that it works — and this feature is entirely about a decision
taken at runtime.
"""

# Pin RP_DATA_DIR at module scope BEFORE api.py is exec'd — its import-time
# ensure_default_user() writes to DATA_DIR.
import os as _rp_os, tempfile as _rp_tempfile
_rp_os.environ.setdefault("RP_DATA_DIR", _rp_tempfile.mkdtemp())
import importlib.util
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_ctr_mute', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_EV = 'container_stopped'


def _reset():
    api.save(api.ALERT_MUTES_FILE, {'mutes': []})
    api.save(api.ALERTS_FILE, {'alerts': []})
    api._ALERT_MUTE_SET_CACHE.update({'mtime': None, 'set': frozenset(),
                                      'cset': frozenset(), 'checked': 0})


class TestContainerMuteSet(unittest.TestCase):
    def setUp(self):
        _reset()
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'cm1', 'device_id': 'd1', 'event': '', 'container': 'decluttarr'},
        ]})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None   # force a rebuild

    def tearDown(self):
        _reset()

    def test_container_set_holds_the_pair(self):
        self.assertIn(('d1', 'decluttarr'), api._container_mute_set())

    def test_container_row_does_not_pollute_the_event_set(self):
        # The two sets must stay disjoint — a container row with event '' used to
        # be filtered out by the `and m.get('event')` guard; keep it that way, or
        # every event on that host would read as muted.
        self.assertEqual(api._alert_mute_set(), frozenset())

    def test_every_event_naming_the_container_is_muted(self):
        for ev in ('container_stopped', 'container_restarting',
                   'container_recovered', 'container_restarting_cleared'):
            self.assertTrue(
                api._alert_muted(ev, {'device_id': 'd1', 'container': 'decluttarr'}),
                f'{ev} should be muted')

    def test_other_containers_and_hosts_are_untouched(self):
        self.assertFalse(api._alert_muted(_EV, {'device_id': 'd1', 'container': 'sonarr'}))
        self.assertFalse(api._alert_muted(_EV, {'device_id': 'd2', 'container': 'decluttarr'}))
        # A host-level event with no container must not be swept up either.
        self.assertFalse(api._alert_muted('containers_stale', {'device_id': 'd1'}))

    def test_an_expired_container_mute_stops_muting(self):
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'cm1', 'device_id': 'd1', 'container': 'decluttarr',
             'expires_at': 1},
        ]})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        self.assertNotIn(('d1', 'decluttarr'), api._container_mute_set())


class TestInboxSuppressionRealPath(unittest.TestCase):
    """Drive _record_alert itself — a hand-built alert dict would bypass both
    the mute gate and the coalesce identity and give a false green."""

    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def _open(self):
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts') or []
                if not a.get('resolved_at')]

    def test_unmuted_container_still_alerts(self):
        api._record_alert(_EV, {'device_id': 'd1', 'device_name': 'h1',
                                'container': 'decluttarr'})
        self.assertEqual(len(self._open()), 1)

    def test_muted_container_records_nothing(self):
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'cm1', 'device_id': 'd1', 'container': 'decluttarr'}]})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        api._record_alert(_EV, {'device_id': 'd1', 'device_name': 'h1',
                                'container': 'decluttarr'})
        self.assertEqual(self._open(), [])

    def test_a_sibling_container_on_the_same_host_still_alerts(self):
        # The whole point of a per-container mute: one noisy workload goes quiet
        # without taking the rest of the host's containers with it.
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'cm1', 'device_id': 'd1', 'container': 'decluttarr'}]})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        api._record_alert(_EV, {'device_id': 'd1', 'device_name': 'h1',
                                'container': 'decluttarr'})
        api._record_alert(_EV, {'device_id': 'd1', 'device_name': 'h1',
                                'container': 'sonarr'})
        rows = self._open()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['payload'].get('container'), 'sonarr')


class TestFleetEventsAndAutoResolveSurvive(unittest.TestCase):
    """A mute is a PAGING decision. History must still record, and a recover
    event must still be able to close a row opened before the mute — otherwise
    muting a container strands its open alert forever."""

    def setUp(self):
        _reset()
        api.save(api.FLEET_EVENTS_FILE, {'events': []})

    def tearDown(self):
        _reset()
        api.save(api.FLEET_EVENTS_FILE, {'events': []})

    def test_fleet_event_records_even_when_muted(self):
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'cm1', 'device_id': 'd1', 'container': 'decluttarr'}]})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        api.fire_webhook(_EV, {'device_id': 'd1', 'device_name': 'h1',
                               'container': 'decluttarr'})
        evs = (api.load(api.FLEET_EVENTS_FILE) or {}).get('events') or []
        self.assertTrue(any(e.get('event') == _EV for e in evs),
                        'fleet_events must record a muted container event')

    def test_recover_still_resolves_a_pre_mute_alert(self):
        api.fire_webhook(_EV, {'device_id': 'd1', 'device_name': 'h1',
                               'container': 'decluttarr'})
        self.assertTrue([a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts')
                         if not a.get('resolved_at')])
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'cm1', 'device_id': 'd1', 'container': 'decluttarr'}]})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        api.fire_webhook('container_recovered', {'device_id': 'd1', 'device_name': 'h1',
                                                 'container': 'decluttarr'})
        still_open = [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts')
                      if not a.get('resolved_at')]
        self.assertEqual(still_open, [],
                         'auto-resolve runs before the mute gate, so a recover '
                         'event must still close the pre-mute alert')


class TestNeedsAttentionDropsMutedContainers(unittest.TestCase):
    """Fleet health is derived purely from needs-attention items, so a muted
    container that still counted toward "N containers stopped" would depress the
    score with no operator recourse (the v6.1.2 lesson)."""

    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def _summaries(self):
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        return [i['summary'] for i in api._compute_attention()
                if i.get('kind') == 'container']

    def test_stopped_container_appears_then_disappears_when_muted(self):
        import time as _t
        dev = {'id': 'dctr', 'name': 'h1', 'monitored': True,
               'last_seen': int(_t.time()), 'os': 'linux'}
        api.save(api.DEVICES_FILE, {'dctr': dev})
        api.save(api.CONTAINERS_FILE, {'dctr': {
            'ts': int(_t.time()),
            'items': [{'name': 'decluttarr', 'status': 'Exited (1) 3s ago',
                       'runtime': 'docker'}],
        }})
        self.assertTrue(any('stopped' in s for s in self._summaries()),
                        'a stopped container should raise a needs-attention item')
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'cm1', 'device_id': 'dctr', 'container': 'decluttarr'}]})
        self.assertFalse(any('stopped' in s for s in self._summaries()),
                         'muting the container must drop it from the digest')


class TestHandlerAcceptsAContainerMute(unittest.TestCase):
    def setUp(self):
        _reset()
        self._orig = (api.require_admin_auth, api.audit_log, api.method,
                      api.get_json_body, api._tenant_visible, api._caller_scope)
        api.require_admin_auth = lambda *a, **k: 'tester'
        api.audit_log = lambda *a, **k: None
        api.method = lambda: 'POST'
        api._tenant_visible = lambda d: True
        api._caller_scope = lambda: None
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'h1'}})

    def tearDown(self):
        (api.require_admin_auth, api.audit_log, api.method,
         api.get_json_body, api._tenant_visible, api._caller_scope) = self._orig
        _reset()

    def _post(self, body):
        api.get_json_body = lambda: dict(body)
        try:
            api.handle_alert_mutes()
        except (SystemExit, api.HTTPError) as e:
            return getattr(e, 'status', None), getattr(e, 'body', None)
        return None, None

    def test_container_mute_is_stored_event_less(self):
        status, _ = self._post({'device_id': 'd1', 'container': 'decluttarr'})
        self.assertEqual(status, 200)
        mutes = api._alert_mutes_load()['mutes']
        self.assertEqual(len(mutes), 1)
        self.assertEqual(mutes[0]['container'], 'decluttarr')
        self.assertEqual(mutes[0]['event'], '')

    def test_it_is_idempotent(self):
        self._post({'device_id': 'd1', 'container': 'decluttarr'})
        self._post({'device_id': 'd1', 'container': 'decluttarr'})
        self.assertEqual(len(api._alert_mutes_load()['mutes']), 1)

    def test_a_container_mute_and_an_event_mute_coexist(self):
        self._post({'device_id': 'd1', 'container': 'decluttarr'})
        self._post({'device_id': 'd1', 'event': 'device_offline'})
        self.assertEqual(len(api._alert_mutes_load()['mutes']), 2)

    def test_a_bad_container_name_is_rejected(self):
        status, body = self._post({'device_id': 'd1', 'container': 'evil name; rm -rf /'})
        self.assertEqual(status, 400)
        self.assertIn('container', (body or {}).get('error', ''))

    def test_an_over_long_name_is_rejected_not_truncated(self):
        # A silently-truncated name becomes a mute that can never match, so the
        # operator sees "muted" and keeps being paged — the worst outcome of the
        # three (reject / truncate / accept).
        status, _ = self._post({'device_id': 'd1', 'container': 'a' * 200})
        self.assertEqual(status, 400)
        self.assertEqual(api._alert_mutes_load()['mutes'], [])

    def test_muting_clears_that_container_s_open_alerts_only(self):
        api._record_alert(_EV, {'device_id': 'd1', 'device_name': 'h1',
                                'container': 'decluttarr'})
        api._record_alert(_EV, {'device_id': 'd1', 'device_name': 'h1',
                                'container': 'sonarr'})
        status, body = self._post({'device_id': 'd1', 'container': 'decluttarr'})
        self.assertEqual(status, 200)
        self.assertEqual(body.get('resolved'), 1)
        still_open = [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts')
                      if not a.get('resolved_at')]
        self.assertEqual([a['payload'].get('container') for a in still_open], ['sonarr'])

    def test_device_id_is_still_required(self):
        status, _ = self._post({'container': 'decluttarr'})
        self.assertEqual(status, 400)


class TestDrawerStampsTheMuteId(unittest.TestCase):
    """The Un-mute button DELETEs by mute id, so the id has to travel with the
    container row — there is no delete-by-(device, container) endpoint."""

    def setUp(self):
        _reset()
        self._orig = (api.require_auth, api.method)
        api.require_auth = lambda *a, **k: 'tester'
        api.method = lambda: 'GET'
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'h1'}})
        api.save(api.CONTAINERS_FILE, {'d1': {'ts': 1, 'items': [
            {'name': 'decluttarr', 'status': 'Up 6 hours', 'runtime': 'docker'},
            {'name': 'sonarr', 'status': 'Up 2 hours', 'runtime': 'docker'},
        ]}})

    def tearDown(self):
        (api.require_auth, api.method) = self._orig
        _reset()

    def test_muted_flag_and_id_on_the_right_row(self):
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'cm-xyz', 'device_id': 'd1', 'container': 'decluttarr'}]})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        try:
            api.handle_device_containers('d1')
            body = None
        except (SystemExit, api.HTTPError) as e:
            body = getattr(e, 'body', None)
        rows = {c['name']: c for c in (body or {}).get('items', [])}
        self.assertTrue(rows['decluttarr']['muted'])
        self.assertEqual(rows['decluttarr']['mute_id'], 'cm-xyz')
        self.assertFalse(rows['sonarr']['muted'])
        self.assertNotIn('mute_id', rows['sonarr'])


if __name__ == '__main__':
    unittest.main()
