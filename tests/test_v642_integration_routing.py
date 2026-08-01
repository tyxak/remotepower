#!/usr/bin/env python3
"""v6.4.2 — integration host-binding, scoped shared destinations, enrollment event.

Three gaps, all driven through the REAL handlers/paths (a source-text assertion
would prove only that a line exists):

1. An integration instance can be BOUND to a device (and/or a site). Bound, its
   integration_down/_recovered events carry a device_id, so a maintenance window
   and a per-(host, event) mute finally silence them — before this, rebooting the
   NAS inside a declared window still paged once per app running on it. An
   UNBOUND instance must behave exactly as it did.
2. Shared notification destinations (webhook list + the global smtp_recipients)
   can carry an optional group/tag/site/tenant filter, applied at the delivery
   chokepoint. Absent = everything, so existing destinations are untouched.
3. A NEW device joining the fleet writes an audit row and fires `device_enrolled`
   — neither existed, so a first appearance left no trace anywhere.
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')

_spec = importlib.util.spec_from_file_location('api_v642_introute', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_REAL_RESPOND = api.respond


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class _StdinShim:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


def _set_request(method, path, body=None, headers=None):
    os.environ['REQUEST_METHOD'] = method
    os.environ['PATH_INFO'] = path
    raw = b'' if body is None else json.dumps(body).encode()
    os.environ['CONTENT_LENGTH'] = str(len(raw))
    api.sys.stdin = _StdinShim(raw)
    # Some handlers read the body TWICE (handle_config_save: _read_valid then
    # get_json_obj). stdin is read-once, so mirror what wsgi.py does and put the
    # re-readable bytes in the request context — otherwise the second read
    # silently sees an empty body and the handler saves nothing while returning
    # 200, which is exactly the false-green this test is meant to catch.
    api._RCTX.stdin = raw
    os.environ.pop('HTTP_X_TOKEN', None)
    for k, v in (headers or {}).items():
        os.environ[k] = v


def _call(handler, *args, **kwargs):
    def fake(status, data):
        raise _Captured(status, data)
    api.respond = fake
    try:
        handler(*args, **kwargs)
    except _Captured as c:
        return c.status, c.body
    finally:
        api.respond = _REAL_RESPOND
    raise AssertionError(f'{handler.__name__} did not call respond()')


_STORES = ('USERS_FILE', 'TOKENS_FILE', 'DEVICES_FILE', 'CONFIG_FILE',
           'AUDIT_LOG_FILE', 'ALERTS_FILE', 'ALERT_MUTES_FILE', 'MAINT_FILE',
           'INTEG_STATE_FILE', 'FLEET_EVENTS_FILE', 'WEBHOOK_LOG_FILE',
           'PINS_FILE', 'ENROLL_TOKENS_FILE', 'SUPPRESSION_LOG_FILE',
           'USER_NOTIFY_FILE')


def _isolate(t):
    d = tempfile.mkdtemp()
    os.environ['RP_DATA_DIR'] = d
    for name in _STORES:
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    # Every cached read/mute set must come from the NEW data dir, or a previous
    # test's store answers this one's question (the shared-store class).
    api._LOAD_CACHE.clear()
    api._ALERT_MUTE_SET_CACHE['mtime'] = None
    api._ALERT_MUTE_SET_CACHE['checked'] = 0
    t._data_dir = d


def _seed_admin():
    api.ensure_default_user()
    users = api.load(api.USERS_FILE)
    user = next(iter(users))
    token = api.make_token()
    tokens = api.load(api.TOKENS_FILE)
    tokens[token] = {'user': user, 'created': int(time.time()),
                     'ttl': 3600, 'admin': True, 'remember': False}
    api.save(api.TOKENS_FILE, tokens)
    return user, token


def _entries(store):
    """Rows out of a wrapped-list store ({'entries': [...]}) or a bare list."""
    if isinstance(store, dict):
        return store.get('entries') or []
    return store if isinstance(store, list) else []


def _open_alerts(event):
    store = api.load(api.ALERTS_FILE) or {}
    return [a for a in (store.get('alerts') or [])
            if a.get('event') == event and not a.get('resolved_at')]


def _seed_devices():
    api.save(api.DEVICES_FILE, {
        'nas1': {'name': 'nas1', 'hostname': 'nas1', 'group': 'storage',
                 'site': 'hq', 'tags': ['prod'], 'last_seen': int(time.time())},
        'web1': {'name': 'web1', 'hostname': 'web1', 'group': 'web',
                 'site': 'dc2', 'tags': ['prod'], 'last_seen': int(time.time())},
    })
    api._invalidate_load_cache(api.DEVICES_FILE)


class TestIntegrationBinding(unittest.TestCase):
    """1. The instance schema carries an optional device/site binding."""

    def setUp(self):
        _isolate(self)
        _, self.token = _seed_admin()
        _seed_devices()

    def _save(self, instances):
        _set_request('POST', '/api/integrations',
                     body={'integrations': instances},
                     headers={'HTTP_X_TOKEN': self.token})
        return _call(api.handle_integrations_save)

    def test_binding_is_persisted(self):
        status, _ = self._save([{'id': 'i1', 'type': 'truenas', 'label': 'TrueNAS',
                                 'url': 'http://10.0.0.9', 'enabled': True,
                                 'device_id': 'nas1', 'site': 'hq'}])
        self.assertEqual(status, 200)
        inst = api._get_integrations(api.load(api.CONFIG_FILE))[0]
        self.assertEqual(inst['device_id'], 'nas1')
        self.assertEqual(inst['site'], 'hq')

    def test_binding_is_optional(self):
        status, _ = self._save([{'id': 'i1', 'type': 'truenas', 'label': 'TrueNAS',
                                 'url': 'http://10.0.0.9', 'enabled': True}])
        self.assertEqual(status, 200)
        inst = api._get_integrations(api.load(api.CONFIG_FILE))[0]
        self.assertEqual(inst['device_id'], '')
        self.assertEqual(inst['site'], '')

    def test_unknown_device_rejected(self):
        status, body = self._save([{'id': 'i1', 'type': 'truenas', 'label': 'TrueNAS',
                                    'url': 'http://10.0.0.9', 'device_id': 'ghost'}])
        self.assertEqual(status, 400)
        self.assertIn('device_id', body['error'])
        # A rejected save must not have half-written the instance list.
        self.assertEqual(api._get_integrations(api.load(api.CONFIG_FILE)), [])

    def test_traversal_device_id_rejected(self):
        status, body = self._save([{'id': 'i1', 'type': 'truenas', 'label': 'T',
                                    'url': 'http://10.0.0.9', 'device_id': '../../etc'}])
        self.assertEqual(status, 400)
        self.assertIn('invalid device_id', body['error'])

    def test_redaction_exposes_binding_not_secret(self):
        safe = api._redact_integration({'id': 'i1', 'type': 'truenas', 'secret': 'x',
                                        'device_id': 'nas1', 'site': 'hq'})
        self.assertEqual(safe['device_id'], 'nas1')
        self.assertEqual(safe['site'], 'hq')
        self.assertNotIn('secret', safe)


class TestBoundIntegrationEvents(unittest.TestCase):
    """The binding reaches the fired payload and makes suppression work."""

    def setUp(self):
        _isolate(self)
        _seed_admin()
        _seed_devices()
        cfg = api.load(api.CONFIG_FILE)
        cfg['integrations'] = [
            {'id': 'i1', 'type': 'truenas', 'label': 'TrueNAS', 'url': 'http://x',
             'enabled': True, 'device_id': 'nas1', 'site': 'hq'},
            {'id': 'i2', 'type': 'sonarr', 'label': 'Sonarr', 'url': 'http://y',
             'enabled': True},
        ]
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _poll(self, iid, label, status, detail='detail'):
        api._persist_integration_results([{
            'id': iid, 'label': label, 'type': 'truenas', 'status': status,
            'detail': detail, 'checked': int(time.time()), 'metrics': {}}])

    def test_payload_carries_binding(self):
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, p: fired.append((ev, p))
        try:
            self._poll('i1', 'TrueNAS', api.integrations_mod.CRIT)
            self._poll('i2', 'Sonarr', api.integrations_mod.CRIT)
        finally:
            api.fire_webhook = real
        bound = dict(fired)['integration_down'] if len(fired) == 1 else None
        self.assertEqual(len(fired), 2)
        by_id = {p['integration_id']: p for _ev, p in fired}
        self.assertEqual(by_id['i1']['device_id'], 'nas1')
        self.assertEqual(by_id['i1']['site'], 'hq')
        # UNBOUND: the payload keys must be exactly what they always were.
        self.assertNotIn('device_id', by_id['i2'])
        self.assertNotIn('site', by_id['i2'])
        self.assertIsNone(bound)

    def test_maintenance_window_now_suppresses_a_bound_integration(self):
        """The headline bug: a device window silences the host's own events but
        used to page once per app running on it."""
        now = int(time.time())
        api.save(api.MAINT_FILE, {'windows': [{
            'id': 'w1', 'scope': 'device', 'target': 'nas1', 'reason': 'NAS reboot',
            'start': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 600)),
            'end':   time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 600)),
        }]})
        api._invalidate_load_cache(api.MAINT_FILE)
        self.assertIsNotNone(api.in_maintenance('device_offline', {'device_id': 'nas1'}),
                             'precondition: the window covers the host itself')
        mw = api.in_maintenance('integration_down',
                                {'device_id': 'nas1', 'integration_id': 'i1'})
        self.assertIsNotNone(mw, 'a bound integration must fall under the host window')
        self.assertEqual(mw['target'], 'nas1')
        # ...and an UNBOUND instance is unaffected by that same window.
        self.assertIsNone(api.in_maintenance('integration_down', {'integration_id': 'i2'}))

    def test_mute_now_silences_a_bound_integration(self):
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'm1', 'device_id': 'nas1', 'event': 'integration_down'}]})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        self.assertTrue(api._alert_muted('integration_down',
                                         {'device_id': 'nas1', 'integration_id': 'i1'}))
        # Drive the REAL firing path: a muted (host, event) records no alert row.
        self._poll('i1', 'TrueNAS', api.integrations_mod.CRIT)
        self.assertEqual(_open_alerts('integration_down'), [])
        # The unbound sibling still alerts — the mute is per host, not global.
        self._poll('i2', 'Sonarr', api.integrations_mod.CRIT)
        self.assertEqual(len(_open_alerts('integration_down')), 1)

    def test_recovery_resolves_through_the_real_path(self):
        self._poll('i1', 'TrueNAS', api.integrations_mod.CRIT)
        self._poll('i2', 'Sonarr', api.integrations_mod.CRIT)
        self.assertEqual(len(_open_alerts('integration_down')), 2)
        self._poll('i1', 'TrueNAS', api.integrations_mod.OK, 'healthy')
        still_open = _open_alerts('integration_down')
        self.assertEqual([a['payload']['integration_id'] for a in still_open], ['i2'],
                         'only the recovered integration must close')

    def test_recovery_resolves_an_alert_recorded_before_the_binding(self):
        """Binding an instance AFTER its down-alert was recorded must not strand
        that alert: the stored row has no device_id, the recovery now has one."""
        api.fire_webhook('integration_down', {'label': 'TrueNAS', 'severity': 'high',
                                              'integration_id': 'i1', 'detail': 'down'})
        self.assertEqual(len(_open_alerts('integration_down')), 1)
        api.fire_webhook('integration_recovered', {'label': 'TrueNAS', 'device_id': 'nas1',
                                                   'site': 'hq', 'integration_id': 'i1'})
        self.assertEqual(_open_alerts('integration_down'), [])

    def test_recovery_still_targets_only_its_own_integration(self):
        api.fire_webhook('integration_down', {'label': 'A', 'severity': 'high',
                                              'integration_id': 'i1', 'device_id': 'nas1'})
        api.fire_webhook('integration_down', {'label': 'B', 'severity': 'high',
                                              'integration_id': 'i2', 'device_id': 'web1'})
        api.fire_webhook('integration_recovered', {'label': 'A', 'integration_id': 'i1',
                                                   'device_id': 'nas1'})
        self.assertEqual([a['payload']['integration_id']
                          for a in _open_alerts('integration_down')], ['i2'])

    def test_site_survives_the_record_alert_whitelist(self):
        api.fire_webhook('integration_down', {'label': 'A', 'severity': 'high',
                                              'integration_id': 'i1', 'site': 'hq'})
        self.assertEqual(_open_alerts('integration_down')[0]['payload'].get('site'), 'hq')

    def test_events_are_suppressible(self):
        for ev in ('integration_down', 'integration_recovered'):
            self.assertIn(ev, api.SUPPRESSIBLE_EVENTS)


class TestScopedSharedDestinations(unittest.TestCase):
    """2. Shared webhook destinations + email routes honour a scope filter."""

    def setUp(self):
        _isolate(self)
        _, self.token = _seed_admin()
        _seed_devices()
        self.sent = []
        self._real_dispatch = api._dispatch_one_webhook
        api._dispatch_one_webhook = lambda ev, dest, *a, **k: self.sent.append(dest['id'])

    def tearDown(self):
        api._dispatch_one_webhook = self._real_dispatch

    def _fan_out(self, payload, dests):
        cfg = {'webhook_urls': dests}
        api._send_webhook_to_url('device_offline', payload, 'msg', cfg)
        return list(self.sent)

    def _dests(self):
        return [
            {'id': 'all', 'url': 'https://hooks.example/all', 'enabled': True},
            {'id': 'storage', 'url': 'https://hooks.example/storage', 'enabled': True,
             'scope_filter': {'type': 'groups', 'values': ['storage']}},
            {'id': 'dc2', 'url': 'https://hooks.example/dc2', 'enabled': True,
             'scope_filter': {'type': 'sites', 'values': ['dc2']}},
        ]

    def test_unscoped_destination_still_gets_everything(self):
        got = self._fan_out({'device_id': 'nas1'}, [self._dests()[0]])
        self.assertEqual(got, ['all'])
        self.sent.clear()
        got = self._fan_out({}, [self._dests()[0]])
        self.assertEqual(got, ['all'], 'a fleet event still reaches an unscoped dest')

    def test_group_scope_routes_by_device(self):
        got = self._fan_out({'device_id': 'nas1'}, self._dests())
        self.assertEqual(sorted(got), ['all', 'storage'])
        self.sent.clear()
        got = self._fan_out({'device_id': 'web1'}, self._dests())
        self.assertEqual(sorted(got), ['all', 'dc2'])

    def test_site_scope_matches_a_payload_site_without_a_device(self):
        """An integration bound to a site (not a host) still routes."""
        got = self._fan_out({'site': 'dc2', 'integration_id': 'i9'}, self._dests())
        self.assertEqual(sorted(got), ['all', 'dc2'])

    def test_unattributable_event_skips_scoped_destinations(self):
        got = self._fan_out({}, self._dests())
        self.assertEqual(got, ['all'])

    def test_an_event_that_reaches_nobody_is_logged_once(self):
        """Visible, not silent — but ONE row: a row per skipped destination
        would drown the webhook log (and cost a store write) on every event."""
        self.assertEqual(self._fan_out({}, self._dests()[1:]), [])
        filtered = [r for r in _entries(api.load(api.WEBHOOK_LOG_FILE))
                    if r.get('status') == 'filtered']
        self.assertEqual(len(filtered), 1)
        self.assertIn('scoped', filtered[0]['detail'])
        # A delivered event logs no scope row at all.
        self.sent.clear()
        self._fan_out({'device_id': 'nas1'}, self._dests()[1:])
        self.assertEqual(len([r for r in _entries(api.load(api.WEBHOOK_LOG_FILE))
                              if r.get('status') == 'filtered']), 1)

    def test_operator_test_event_ignores_scope(self):
        """Pressing "Send test" at a scoped destination must actually send —
        a test event has no device, so scoping it would make the one control an
        operator uses to prove the destination works always report nothing."""
        api._send_webhook_to_url('test', {'triggered_by': 'admin'}, 'msg',
                                 {'webhook_urls': self._dests()})
        self.assertEqual(sorted(self.sent), ['all', 'dc2', 'storage'])

    def test_tenant_scope(self):
        devices = api.load(api.DEVICES_FILE)
        devices['nas1']['tenant'] = 't-acme'
        api.save(api.DEVICES_FILE, devices)
        api._invalidate_load_cache(api.DEVICES_FILE)
        dests = [{'id': 'acme', 'url': 'https://hooks.example/acme', 'enabled': True,
                  'tenants': ['t-acme']}]
        self.assertEqual(self._fan_out({'device_id': 'nas1'}, dests), ['acme'])
        self.sent.clear()
        self.assertEqual(self._fan_out({'device_id': 'web1'}, dests), [])

    def test_config_save_persists_and_sanitizes_the_filter(self):
        _set_request('POST', '/api/config', headers={'HTTP_X_TOKEN': self.token},
                     body={'webhook_urls': [
                         {'id': 'w1', 'url': 'https://hooks.example/a', 'format': 'generic',
                          'scope_filter': {'type': 'groups', 'values': ['storage', '']},
                          'tenants': ['t-acme']},
                         {'id': 'w2', 'url': 'https://hooks.example/b', 'format': 'generic',
                          'scope_filter': {'type': 'bogus', 'values': ['x']}},
                     ]})
        status, _ = _call(api.handle_config_save)
        self.assertEqual(status, 200)
        saved = {d['id']: d for d in api.load(api.CONFIG_FILE)['webhook_urls']}
        self.assertEqual(saved['w1']['scope_filter'], {'type': 'groups', 'values': ['storage']})
        self.assertEqual(saved['w1']['tenants'], ['t-acme'])
        # An unusable filter must WIDEN to everything, never narrow to nothing.
        self.assertNotIn('scope_filter', saved['w2'])

    def test_email_routes_split_by_scope(self):
        cfg = {'smtp_recipients': 'noc@example.com',
               'email_routes': [
                   {'id': 'r1', 'recipients': 'storage-team@example.com',
                    'scope_filter': {'type': 'groups', 'values': ['storage']}},
                   {'id': 'r2', 'recipients': 'web-team@example.com',
                    'scope_filter': {'type': 'groups', 'values': ['web']}},
               ]}
        self.assertEqual(api._event_email_routes(cfg, {'device_id': 'nas1'}),
                         [['noc@example.com'], ['storage-team@example.com']])
        self.assertEqual(api._event_email_routes(cfg, {'device_id': 'web1'}),
                         [['noc@example.com'], ['web-team@example.com']])

    def test_email_route_addresses_are_deduped_across_routes(self):
        cfg = {'smtp_recipients': 'noc@example.com',
               'email_routes': [{'id': 'r1', 'recipients': 'NOC@example.com, x@example.com',
                                 'scope_filter': {'type': 'groups', 'values': ['storage']}}]}
        self.assertEqual(api._event_email_routes(cfg, {'device_id': 'nas1'}),
                         [['noc@example.com'], ['x@example.com']])

    def test_scoping_the_global_recipient_list(self):
        cfg = {'smtp_recipients': 'noc@example.com',
               'smtp_scope_filter': {'type': 'sites', 'values': ['hq']}}
        self.assertEqual(api._event_email_routes(cfg, {'device_id': 'nas1'}),
                         [['noc@example.com']])
        self.assertEqual(api._event_email_routes(cfg, {'device_id': 'web1'}), [])
        # Unscoped (every install today) → unchanged.
        self.assertEqual(api._event_email_routes({'smtp_recipients': 'noc@example.com'},
                                                 {'device_id': 'web1'}),
                         [['noc@example.com']])

    def test_send_event_email_sends_once_per_route(self):
        calls = []
        real = api.smtp_notifier.send_email
        api.smtp_notifier.send_email = (
            lambda cfg, rcpts, subj, body, **kw: calls.append(list(rcpts)))
        try:
            api._send_event_email('device_offline', {'device_id': 'nas1', 'name': 'nas1'},
                                  'msg', {'smtp_recipients': 'noc@example.com',
                                          'email_routes': [
                                              {'id': 'r1', 'recipients': 'storage@example.com',
                                               'scope_filter': {'type': 'groups',
                                                                'values': ['storage']}},
                                              {'id': 'r2', 'recipients': 'web@example.com',
                                               'scope_filter': {'type': 'groups',
                                                                'values': ['web']}}]},
                                  'RemotePower')
        finally:
            api.smtp_notifier.send_email = real
        self.assertEqual(calls, [['noc@example.com'], ['storage@example.com']])

    def test_operator_test_email_ignores_scope(self):
        calls = []
        real = api.smtp_notifier.send_email
        api.smtp_notifier.send_email = (
            lambda cfg, rcpts, subj, body, **kw: calls.append(list(rcpts)))
        try:
            api._send_event_email('test', {}, 'msg',
                                  {'smtp_recipients': 'noc@example.com',
                                   'smtp_scope_filter': {'type': 'sites', 'values': ['hq']}},
                                  'RemotePower')
        finally:
            api.smtp_notifier.send_email = real
        self.assertEqual(calls, [['noc@example.com']])

    def test_email_routes_save_validation(self):
        _set_request('POST', '/api/config', headers={'HTTP_X_TOKEN': self.token},
                     body={'email_routes': [{'id': 'r1', 'recipients': 'not-an-address'}]})
        status, body = _call(api.handle_config_save)
        self.assertEqual(status, 400)
        self.assertIn('recipients', body['error'])
        _set_request('POST', '/api/config', headers={'HTTP_X_TOKEN': self.token},
                     body={'email_routes': [
                         {'id': 'r1', 'name': 'Storage', 'recipients': 'a@example.com',
                          'scope_filter': {'type': 'tags', 'values': ['prod']}}]})
        status, _ = _call(api.handle_config_save)
        self.assertEqual(status, 200)
        saved = api.load(api.CONFIG_FILE)['email_routes'][0]
        self.assertEqual(saved['recipients'], 'a@example.com')
        self.assertEqual(saved['scope_filter'], {'type': 'tags', 'values': ['prod']})
        self.assertTrue(saved['enabled'])


class TestDeviceEnrolledEvent(unittest.TestCase):
    """3. A host joining the fleet is recorded (audit row + fleet event)."""

    def setUp(self):
        _isolate(self)
        _, self.token = _seed_admin()

    def _enroll(self, hostname='new-host'):
        _set_request('POST', '/api/enrollment-tokens', body={'label': 'test'},
                     headers={'HTTP_X_TOKEN': self.token})
        _, resp = _call(api.handle_enroll_token_create)
        _set_request('POST', '/api/enroll/register', body={
            'enrollment_token': resp['token'], 'hostname': hostname, 'name': hostname,
            'os': 'Linux', 'ip': '10.0.0.5', 'version': '6.4.2'})
        return _call(api.handle_enroll_register)

    def test_registry_entry_is_complete(self):
        spec = api.EVENT_REGISTRY['device_enrolled']
        self.assertEqual(spec['lifecycle'], 'point')   # nothing "clears" an enrollment
        self.assertIn(spec['kind'], {k for k, _l, _g in api.CHANNEL_KIND_DEFS})
        self.assertIn('device_enrolled', api.WEBHOOK_EVENT_NAMES)
        self.assertEqual(api._ALERT_RULES['device_enrolled'][0], 'low')
        self.assertNotIn('device_enrolled', api._AUTO_RESOLVABLE_EVENTS)
        self.assertFalse(api._kind_default(spec['kind'])['needs_attention'],
                         'an enrollment is news, not a fault to work off')

    def test_enrollment_writes_an_audit_row(self):
        status, body = self._enroll()
        self.assertEqual(status, 201)
        rows = [r for r in _entries(api.load(api.AUDIT_LOG_FILE))
                if r.get('action') == 'enroll']
        self.assertEqual(len(rows), 1, 'a first enrollment must be auditable')
        self.assertIn(body['device_id'], rows[0]['detail'])
        self.assertIn('new-host', rows[0]['detail'])

    def test_enrollment_fires_the_event(self):
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, p: fired.append((ev, p))
        try:
            status, body = self._enroll()
        finally:
            api.fire_webhook = real
        self.assertEqual(status, 201)
        self.assertEqual([e for e, _ in fired], ['device_enrolled'])
        p = fired[0][1]
        self.assertEqual(p['device_id'], body['device_id'])
        self.assertEqual(p['host'], 'new-host')
        self.assertEqual(p['source'], 'token')

    def test_event_reaches_the_activity_feed_and_the_inbox(self):
        """Drive the REAL fire_webhook so the fleet-event + alert whitelists are
        exercised, not a stub's idea of them."""
        status, body = self._enroll()
        self.assertEqual(status, 201)
        feed = api.load(api.FLEET_EVENTS_FILE)
        rows = [e for e in (feed.get('events') if isinstance(feed, dict) else feed)
                if e.get('event') == 'device_enrolled']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['payload'].get('device_id'), body['device_id'])
        self.assertEqual(len(_open_alerts('device_enrolled')), 1)

    def test_reenrollment_is_not_a_new_enrollment(self):
        _, first = self._enroll()
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, p: fired.append(ev)
        try:
            _set_request('POST', '/api/enrollment-tokens', body={'label': 't2'},
                         headers={'HTTP_X_TOKEN': self.token})
            _, resp = _call(api.handle_enroll_token_create)
            _set_request('POST', '/api/enroll/register', body={
                'enrollment_token': resp['token'], 'device_id': first['device_id'],
                'token': first['token'], 'hostname': 'new-host', 'name': 'new-host',
                'os': 'Linux', 'ip': '10.0.0.5', 'version': '6.4.2'})
            status, body = _call(api.handle_enroll_register)
        finally:
            api.fire_webhook = real
        self.assertEqual(status, 200)
        self.assertTrue(body['reregistered'])
        self.assertEqual(fired, [], 're-enrollment must not read as a new device')
        actions = [r.get('action') for r in _entries(api.load(api.AUDIT_LOG_FILE))]
        self.assertIn('reenroll', actions)


if __name__ == '__main__':
    unittest.main()
