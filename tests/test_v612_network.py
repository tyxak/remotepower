"""v6.1.2 batch C — network/homelab features.

Covers the WAN watch state machine, the inbound dead-man's-switch, duplicate-MAC
detection, and the Docker destructive-prune confirmation gate. Every test drives
the REAL handler/sweep (no hand-built state dicts) — the whole point of several of
these features is an edge-trigger, and an edge-trigger that is asserted against a
hand-made fixture proves nothing about the code path that actually runs.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))


def _fresh_api():
    """Import api.py against a private data dir (each test class gets its own)."""
    import importlib.util
    d = tempfile.mkdtemp(prefix='rp-v612-net-')
    os.environ['RP_DATA_DIR'] = d
    path = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin' / 'api.py'
    spec = importlib.util.spec_from_file_location('api_v612_net', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _ApiCase(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.fired = []
        self.api.fire_webhook = lambda ev, pl=None: self.fired.append((ev, pl or {}))
        self.api.audit_log = lambda *a, **k: None
        self.captured = {}

        def _respond(status, data=None):
            self.captured['status'] = status
            self.captured['data'] = data
            raise self.api.HTTPError(status, data)
        self.api.respond = _respond
        self.api.require_auth = lambda *a, **k: 'admin'
        self.api.require_admin_auth = lambda *a, **k: 'admin'
        self.api.require_write_role = lambda *a, **k: 'admin'
        self.api.require_perm = lambda *a, **k: 'admin'

    def events(self, name):
        return [p for e, p in self.fired if e == name]


class TestWanWatch(_ApiCase):
    """Public-IP watch: IP-change, outage and recovery are all EDGE-triggered."""

    def setUp(self):
        super().setUp()
        self.api.save(self.api.CONFIG_FILE, {'wan_watch_enabled': True})
        self.api._LOAD_CACHE.clear()

    def _tick(self, ip):
        """Force the sweep to be due and run it with a stubbed public-IP fetch."""
        self.api._fetch_public_ip = lambda: ip
        st = self.api.load(self.api.WAN_STATE_FILE) or {}
        st['checked'] = 0
        self.api.save(self.api.WAN_STATE_FILE, st)
        self.fired.clear()
        self.api.run_wan_ip_check_if_due()

    def test_disabled_by_default_makes_no_outbound_call(self):
        self.api.save(self.api.CONFIG_FILE, {})
        self.api._LOAD_CACHE.clear()
        called = []
        self.api._fetch_public_ip = lambda: called.append(1)
        self.api.run_wan_ip_check_if_due()
        self.assertEqual(called, [], 'WAN watch must not phone home when disabled')

    def test_first_sample_does_not_fire(self):
        self._tick('1.2.3.4')
        self.assertEqual(self.events('wan_ip_changed'), [],
                         'the first-ever sample is a baseline, not a change')

    def test_ip_change_fires_once_with_old_and_new(self):
        self._tick('1.2.3.4')
        self._tick('5.6.7.8')
        ev = self.events('wan_ip_changed')
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]['old_ip'], '1.2.3.4')
        self.assertEqual(ev[0]['new_ip'], '5.6.7.8')
        self._tick('5.6.7.8')                      # unchanged -> silent
        self.assertEqual(self.events('wan_ip_changed'), [])

    def test_outage_then_recovery_is_edge_triggered_and_logged(self):
        self._tick('1.2.3.4')
        self._tick(None)                           # internet down
        self.assertEqual(len(self.events('wan_down')), 1)
        self._tick(None)                           # still down -> must NOT re-fire
        self.assertEqual(self.events('wan_down'), [],
                         'wan_down must be edge-triggered, not repeated every sweep')
        self._tick('1.2.3.4')                      # back
        self.assertEqual(len(self.events('wan_up')), 1)

        st = self.api.load(self.api.WAN_STATE_FILE) or {}
        outages = st.get('outages') or []
        self.assertEqual(len(outages), 1, 'the outage must be recorded for the log')
        self.assertTrue(outages[0].get('end'), 'a recovered outage must be closed out')

    def test_status_handler_reports_uptime_and_outage_count(self):
        self._tick('1.2.3.4')
        self._tick(None)
        self._tick('1.2.3.4')
        try:
            self.api.handle_wan_status()
        except self.api.HTTPError:
            pass
        d = self.captured['data']
        self.assertTrue(d['enabled'])
        self.assertEqual(d['ip'], '1.2.3.4')
        self.assertTrue(d['online'])
        self.assertEqual(d['outage_count_30d'], 1)
        self.assertLessEqual(d['uptime_pct_30d'], 100.0)

    def test_ddns_skips_loudly_when_the_vault_is_sealed(self):
        """A sealed vault must SKIP the DNS update and say so — never fail silently,
        and never leave the operator believing DNS followed the new IP."""
        self.api.save(self.api.CONFIG_FILE, {
            'wan_watch_enabled': True,
            'ddns': {'provider': 'cloudflare', 'zone': 'z1', 'record': 'home.example.com'},
        })
        self.api._LOAD_CACHE.clear()
        self.api._vault_get = lambda *a, **k: None        # sealed / no secret
        self._tick('1.2.3.4')
        self._tick('5.6.7.8')
        self.assertEqual(len(self.events('wan_ip_changed')), 1,
                         'the IP-change event must fire even when DDNS cannot run')
        st = self.api.load(self.api.WAN_STATE_FILE) or {}
        ddns = st.get('ddns') or {}
        self.assertFalse(ddns.get('ok'), 'a sealed vault must not report success')
        self.assertTrue(ddns.get('error'),
                        'the skip must be recorded with a reason, not swallowed')

    def test_ddns_runs_from_the_config_shape_the_settings_ui_actually_saves(self):
        """REGRESSION: the Settings UI models "off" as an empty provider select and
        sends {provider, zone, record} with NO `enabled` key. _run_auto_ddns used to
        require `enabled`, so auto-DDNS could never fire for anyone configuring it
        through the UI — the classic "feature that can never fire". A config with a
        provider+zone must RUN (here: reach the credentials check and report a real
        reason), not return None."""
        cfg = {'ddns': {'provider': 'cloudflare', 'zone': 'z1',
                        'record': 'home.example.com'}}      # note: no 'enabled'
        res = self.api._run_auto_ddns('5.6.7.8', cfg)
        self.assertIsNotNone(
            res, 'a provider+zone config must be treated as enabled')
        self.assertIn('error', res)

        # …and an explicit opt-out must still win.
        cfg['ddns']['enabled'] = False
        self.assertIsNone(self.api._run_auto_ddns('5.6.7.8', cfg))

    def test_settings_save_derives_enabled_from_the_provider(self):
        body = {'ddns': {'provider': 'cloudflare', 'zone': 'z1', 'record': 'h.ex.com'}}
        self.api.get_json_obj = lambda: body
        self.api.method = lambda: 'POST'
        try:
            self.api.handle_config_save()
        except (self.api.HTTPError, SystemExit):
            pass
        saved = (self.api.load(self.api.CONFIG_FILE) or {}).get('ddns') or {}
        self.assertTrue(saved.get('enabled'),
                        'choosing a provider IS the enable switch')
        # The "Off" option clears the provider — which must disable it.
        body['ddns'] = {'provider': '', 'zone': '', 'record': ''}
        try:
            self.api.handle_config_save()
        except (self.api.HTTPError, SystemExit):
            pass
        saved = (self.api.load(self.api.CONFIG_FILE) or {}).get('ddns') or {}
        self.assertFalse(saved.get('enabled'))


class TestDeadmanSwitch(_ApiCase):
    """Inbound check-ins for jobs that live OUTSIDE the fleet."""

    def _make_job(self, name='NAS backup', period=1440, grace=60):
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {
            'name': name, 'period_minutes': period, 'grace_minutes': grace}
        self.api._request_base_url = lambda: 'https://rp.example'
        try:
            self.api.handle_deadman_jobs()
        except self.api.HTTPError:
            pass
        return self.captured['data']

    def _ping(self, token):
        self.api.method = lambda: 'GET'
        try:
            self.api.handle_deadman_ping(token)
        except self.api.HTTPError:
            pass

    def _age_out(self, job_id):
        st = self.api.load(self.api.DEADMAN_FILE) or {}
        for j in st.get('jobs', []):
            if j['id'] == job_id:
                j['last_ping'] = int(time.time()) - 10 ** 7
        st['checked'] = 0
        self.api.save(self.api.DEADMAN_FILE, st)

    def test_create_returns_a_usable_ping_url(self):
        d = self._make_job()
        self.assertIn('/api/ping/', d['url'])
        self.assertTrue(d['job']['token'])

    def test_job_id_is_not_numeric_looking(self):
        """The frontend data-arg dispatcher coerces numeric-looking strings to
        Number ('1e5000000000' -> Infinity), which would corrupt the id on DELETE.
        The id must be non-numeric BY CONSTRUCTION, not by luck."""
        for _ in range(20):
            d = self._make_job(name='j')
            jid = d['job']['id']
            with self.assertRaises(ValueError):
                float(jid)

    def test_never_pinged_job_is_not_late(self):
        """The clock starts at the FIRST check-in. A job created at 23:00 for a
        03:00 cron must not page you at 23:01."""
        self._make_job()
        self.fired.clear()
        self.api.run_deadman_check_if_due()
        self.assertEqual(self.events('ping_missed'), [])

    def test_missed_checkin_fires_once_then_recovers(self):
        d = self._make_job()
        job, token = d['job'], d['job']['token']
        self._ping(token)
        self._age_out(job['id'])

        self.fired.clear()
        self.api.run_deadman_check_if_due()
        ev = self.events('ping_missed')
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]['job'], 'NAS backup')

        st = self.api.load(self.api.DEADMAN_FILE) or {}
        st['checked'] = 0
        self.api.save(self.api.DEADMAN_FILE, st)
        self.fired.clear()
        self.api.run_deadman_check_if_due()
        self.assertEqual(self.events('ping_missed'), [],
                         'a late job must not re-alert on every sweep')

        self.fired.clear()
        self._ping(token)                       # the job comes back
        self.assertEqual(len(self.events('ping_recovered')), 1)

    def test_unknown_token_404s_without_leaking(self):
        self._make_job()
        self.api.method = lambda: 'GET'
        try:
            self.api.handle_deadman_ping('not-a-real-token')
        except self.api.HTTPError:
            pass
        self.assertEqual(self.captured['status'], 404)
        self.assertNotIn('NAS backup', str(self.captured['data']))


class TestMacNormalisation(_ApiCase):
    def test_formats_normalise_to_one_canonical_form(self):
        for raw in ('AA-BB-cc:DD:ee:FF', 'aabbccddeeff', 'AA:BB:CC:DD:EE:FF'):
            self.assertEqual(self.api._normalize_mac(raw), 'aa:bb:cc:dd:ee:ff')

    def test_junk_and_meaningless_macs_are_rejected(self):
        # All-zero and multicast/broadcast MACs are not device identities — treating
        # them as such would report a "conflict" across every host that reports one.
        for raw in ('', None, 'xx', '00:00:00:00:00:00',
                    'ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:01'):
            self.assertIsNone(self.api._normalize_mac(raw), raw)


class TestMacConflict(_ApiCase):
    def test_cloned_vm_with_the_same_mac_is_detected_once(self):
        # NOTE: no subnets are defined. A duplicate MAC is wrong regardless of
        # IPAM config, and requiring a subnet would mean most homelabs (which
        # never define one) silently got no detection at all.
        self.api.save(self.api.DEVICES_FILE, {
            'a': {'name': 'vm-a', 'mac': 'AA:BB:CC:DD:EE:FF'},
            # same MAC, different notation, and reported via interfaces[] not mac
            'b': {'name': 'vm-b', 'interfaces': [{'mac': 'aa-bb-cc-dd-ee-ff'}]},
            'c': {'name': 'vm-c', 'mac': '11:22:33:44:55:66'},
        })
        self.api.save(self.api.IPAM_STATE_FILE, {})
        self.api.run_ipam_conflicts_if_due()
        ev = self.events('mac_conflict')
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]['mac'], 'aa:bb:cc:dd:ee:ff')
        self.assertIn('vm-a', ev[0]['name'])
        self.assertIn('vm-b', ev[0]['name'])

    def test_conflict_does_not_re_fire_while_it_persists(self):
        self.api.save(self.api.DEVICES_FILE, {
            'a': {'name': 'vm-a', 'mac': 'AA:BB:CC:DD:EE:FF'},
            'b': {'name': 'vm-b', 'mac': 'aa:bb:cc:dd:ee:ff'},
        })
        self.api.save(self.api.IPAM_STATE_FILE, {})
        self.api.run_ipam_conflicts_if_due()
        self.assertEqual(len(self.events('mac_conflict')), 1)
        st = self.api.load(self.api.IPAM_STATE_FILE) or {}
        st['last_run'] = 0
        self.api.save(self.api.IPAM_STATE_FILE, st)
        self.fired.clear()
        self.api.run_ipam_conflicts_if_due()
        self.assertEqual(self.events('mac_conflict'), [])


class TestDockerPruneSafety(_ApiCase):
    """Volume deletion is the one Docker cleanup that destroys data you cannot get
    back. The confirmation must be enforced SERVER-side — a browser confirm() is
    theatre, since anything can POST to the endpoint."""

    def _prune(self, scope, confirm=None):
        body = {'scope': scope}
        if confirm is not None:
            body['confirm'] = confirm
        self.api.get_json_obj = lambda: body
        self.api.method = lambda: 'POST'
        self.api.save(self.api.DEVICES_FILE, {'d1': {'name': 'nas', 'token': 't'}})
        self.captured.clear()
        try:
            self.api.handle_device_docker_prune('d1')
        except self.api.HTTPError:
            pass
        return self.captured.get('status')

    def test_safe_scopes_need_no_confirmation(self):
        for scope in self.api._DOCKER_PRUNE_SAFE:
            self.assertEqual(self._prune(scope), 200, scope)

    def test_destructive_scopes_are_refused_without_the_typed_confirmation(self):
        for scope in self.api._DOCKER_PRUNE_DESTRUCTIVE:
            self.assertEqual(self._prune(scope), 400, scope)
            self.assertEqual(self._prune(scope, confirm='yes'), 400, scope)
            self.assertEqual(self._prune(scope, confirm=''), 400, scope)

    def test_destructive_scopes_proceed_with_the_exact_confirmation(self):
        for scope in self.api._DOCKER_PRUNE_DESTRUCTIVE:
            self.assertEqual(
                self._prune(scope, confirm=self.api._DOCKER_PRUNE_CONFIRM), 200, scope)

    def test_unknown_scope_is_rejected(self):
        self.assertEqual(self._prune('rm -rf /'), 400)

    def test_scheduled_prune_can_never_delete_volumes(self):
        """A scheduled prune runs unattended, so it is restricted to the SAFE set —
        nobody is there to type the confirmation. Pin the dispatcher branch itself:
        if someone ever points it at the 'full' scope, a nightly cron starts
        silently deleting volumes."""
        self.assertIn('docker_prune', self.api.SCHED_STATIC_COMMANDS)
        src = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin' / 'api.py'
        text = src.read_text()
        self.assertIn("elif command == 'docker_prune':", text)
        idx = text.index("elif command == 'docker_prune':")
        branch = text[idx:idx + 200]
        self.assertIn('_DOCKER_PRUNE_SAFE', branch,
                      'the scheduled prune must draw from the SAFE table')
        self.assertNotIn('_DOCKER_PRUNE_DESTRUCTIVE', branch)
        for cmd in self.api._DOCKER_PRUNE_SAFE.values():
            self.assertNotIn('--volumes', cmd)


class TestNewEndpointPermissions(unittest.TestCase):
    """Permission gates on everything batch C adds.

    Deliberately does NOT stub require_auth / require_perm / require_admin_auth —
    the other classes in this file do, and a stubbed gate would happily "pass" a
    handler that has no gate at all. Only IDENTITY (verify_token) is stubbed, so
    the real RBAC logic runs.
    """

    def setUp(self):
        self.api = _fresh_api()
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'] = status
            self.cap['data'] = data
            raise self.api.HTTPError(status, data)
        self.api.respond = _respond
        self.api.get_token_from_request = lambda: 'tok'
        self.api.audit_log = lambda *a, **k: None
        self.api.fire_webhook = lambda *a, **k: None
        self.api._request_base_url = lambda: 'https://rp.example'
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'nas', 'token': 't', 'tenant': 't1'},
            'd2': {'name': 'their-nas', 'token': 't', 'tenant': 't2'},
        })
        self.api.save(self.api.ROLES_FILE, {'roles': [
            {'name': 'containers-op', 'permissions': ['containers'],
             'scope': {'type': 'all'}},
            {'name': 'patch-only', 'permissions': ['patch'], 'scope': {'type': 'all'}},
        ]})
        self.api._LOAD_CACHE.clear()

    def _as(self, role):
        self.api.verify_token = lambda _t=None, _r=role: ('u_' + _r, _r)

    def _status(self, fn):
        self.cap.clear()
        try:
            fn()
            return 200
        except self.api.HTTPError:
            return self.cap.get('status')

    # ── the mutating one: docker prune ───────────────────────────────────────
    def _prune(self):
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'scope': 'images'}
        return self._status(lambda: self.api.handle_device_docker_prune('d1'))

    def test_read_only_roles_cannot_prune(self):
        """The read-only-role WRITE-gate class: viewer/mcp/auditor/finance must not
        reach a handler that mutates host state."""
        for role in ('viewer', 'mcp', 'auditor', 'finance'):
            self._as(role)
            self.assertEqual(self._prune(), 403, role)

    def test_a_role_holding_the_containers_permission_CAN_prune(self):
        """The other direction — the feature must actually be usable by the role
        that is supposed to have it, not admin-only by accident."""
        self._as('containers-op')
        self.assertEqual(self._prune(), 200)

    def test_a_role_without_the_containers_permission_cannot_prune(self):
        self._as('patch-only')
        self.assertEqual(self._prune(), 403)

    def test_admin_can_prune(self):
        self._as('admin')
        self.assertEqual(self._prune(), 200)

    # ── dead-man's-switch job management is admin-only ───────────────────────
    def test_creating_and_deleting_jobs_is_admin_only(self):
        for role in ('viewer', 'mcp', 'auditor', 'finance', 'containers-op'):
            self._as(role)
            self.api.method = lambda: 'POST'
            self.api.get_json_obj = lambda: {'name': 'j', 'period_minutes': 60}
            self.assertEqual(self._status(self.api.handle_deadman_jobs), 403, role)
            self.api.method = lambda: 'DELETE'
            self.assertEqual(
                self._status(lambda: self.api.handle_deadman_job('dm-abc')), 403, role)

    def test_any_authed_role_can_read_the_new_views(self):
        self.api.method = lambda: 'GET'
        for role in ('admin', 'viewer', 'auditor', 'containers-op'):
            self._as(role)
            self.assertEqual(self._status(self.api.handle_wan_status), 200, role)
            self.assertEqual(self._status(self.api.handle_mdns_services), 200, role)
            self.assertEqual(self._status(self.api.handle_deadman_jobs), 200, role)

    def test_unauthenticated_callers_are_rejected(self):
        self.api.verify_token = lambda _t=None: (None, None)
        self.api.method = lambda: 'GET'
        self.assertEqual(self._status(self.api.handle_wan_status), 401)
        self.assertEqual(self._status(self.api.handle_deadman_jobs), 401)

    # ── tenant isolation on the device action ────────────────────────────────
    def test_tenant_admin_cannot_act_on_another_tenants_host(self):
        """A tenant admin has role scope None, so scope checks alone would let this
        through — the pre-dispatch tenant gate is what stops it."""
        self.api._tenant_gate = lambda: 't1'
        self._as('admin')
        self.api.path_info = lambda: '/api/devices/d1/docker/prune'
        self.assertEqual(self._status(self.api._enforce_device_scope), 200)
        self.api.path_info = lambda: '/api/devices/d2/docker/prune'
        self.assertEqual(self._status(self.api._enforce_device_scope), 403)

    # ── the ping endpoint must survive the IP allowlist ──────────────────────
    def test_ping_path_is_exempt_from_the_ip_allowlist(self):
        """REGRESSION: the check-in comes from a cron job on a router/VPS — exactly
        the arbitrary source IP the allowlist rejects. Without the exemption, turning
        the allowlist on 403s every check-in and the switch then reports those jobs
        as LATE: a false alarm indistinguishable from a real backup failure.
        The exempt list is EXACT-match, so a path-carried token can never match it."""
        self.api.save(self.api.CONFIG_FILE, {
            'ip_allowlist_enabled': True, 'ip_allowlist': ['10.0.0.0/24']})
        self.api._LOAD_CACHE.clear()
        self.api._get_client_ip = lambda: '203.0.113.9'      # off-fleet router

        self.api.path_info = lambda: '/api/ping/sometoken'
        self.assertEqual(self._status(self.api._enforce_ip_allowlist), 200)

        # …but the allowlist must still protect everything else, and the trailing
        # slash must stop a look-alike path from sneaking through.
        self.api.path_info = lambda: '/api/devices'
        self.assertEqual(self._status(self.api._enforce_ip_allowlist), 403)
        self.api.path_info = lambda: '/api/pingXYZ'
        self.assertEqual(self._status(self.api._enforce_ip_allowlist), 403)


if __name__ == '__main__':
    unittest.main()
