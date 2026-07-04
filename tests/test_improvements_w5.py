"""Wave-5 improvement-program guardrails (fleet, CMDB & topology)."""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys

ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_w5", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _HandlerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'DEVICES_FILE',
                     'DEVICE_PROFILES_FILE', 'SMART_GROUPS_FILE', 'SITES_FILE',
                     'RACKS_FILE', 'CMDB_FILE', 'SUBNETS_FILE', 'IPAM_STATE_FILE',
                     'LLDP_NEIGHBORS_FILE', 'LLDP_DISMISS_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', 'verify_token',
                       'get_token_from_request', 'audit_log', 'fire_webhook',
                       'respond', 'method', 'get_json_body', 'get_json_obj')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestDeviceProfiles(_HandlerBase):
    """W5-7: named device-config profiles + stamp-on-apply."""

    def _create(self, body):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: body
        return self.call(api.handle_device_profiles)

    def test_create_validates_and_stores(self):
        out = self._create({'name': 'web tier', 'poll_interval': 120,
                            'services_watched': ['nginx.service', 'php-fpm.service'],
                            'metric_thresholds': {'mem_warn_percent': 70, 'mem_crit_percent': 90}})
        self.assertTrue(out.get('id'))
        profs = api.load(api.DEVICE_PROFILES_FILE) or {}
        p = list(profs.values())[0]
        self.assertEqual(p['name'], 'web tier')
        self.assertEqual(p['poll_interval'], 120)
        self.assertEqual(p['metric_thresholds']['mem_warn_percent'], 70)

    def test_create_requires_name(self):
        out = self._create({'poll_interval': 60})
        self.assertIn('name', str(out))

    def test_bad_poll_interval_rejected(self):
        out = self._create({'name': 'x', 'poll_interval': 5})
        self.assertIn('poll_interval', str(out))

    def test_apply_stamps_fields(self):
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'a', 'poll_interval': 60, 'metric_state': {'mem': 'warning'}},
            'd2': {'name': 'b', 'poll_interval': 60}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        pid = self._create({'name': 'p', 'poll_interval': 300,
                            'services_watched': ['sshd.service'],
                            'metric_thresholds': {'mem_warn_percent': 80}})['id']
        api._invalidate_load_cache(api.DEVICE_PROFILES_FILE)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'device_ids': ['d1', 'd2', 'ghost']}
        out = self.call(api.handle_device_profile_apply, pid)
        self.assertEqual(out['applied'], 2)
        devs = api.load(api.DEVICES_FILE)
        self.assertEqual(devs['d1']['poll_interval'], 300)
        self.assertEqual(devs['d1']['services_watched'], ['sshd.service'])
        # metric_state cleared because thresholds changed
        self.assertNotIn('metric_state', devs['d1'])

    def test_apply_is_one_shot_copy(self):
        # editing a device after apply does not touch the profile
        prof = {'poll_interval': 300}
        dev = {'name': 'a', 'poll_interval': 60}
        updated = api._apply_profile_to_device(dev, prof)
        self.assertEqual(updated['poll_interval'], 300)
        self.assertEqual(dev['poll_interval'], 60)   # original untouched

    def test_patch_replaces_present_fields(self):
        pid = self._create({'name': 'p', 'poll_interval': 120})['id']
        api._invalidate_load_cache(api.DEVICE_PROFILES_FILE)
        api.method = lambda: 'PATCH'
        api.get_json_obj = lambda: {'poll_interval': 600, 'name': 'p2'}
        self.call(api.handle_device_profile, pid)
        p = (api.load(api.DEVICE_PROFILES_FILE) or {})[pid]
        self.assertEqual(p['poll_interval'], 600)
        self.assertEqual(p['name'], 'p2')

    def test_delete(self):
        pid = self._create({'name': 'p'})['id']
        api._invalidate_load_cache(api.DEVICE_PROFILES_FILE)
        api.method = lambda: 'DELETE'
        self.call(api.handle_device_profile, pid)
        self.assertNotIn(pid, api.load(api.DEVICE_PROFILES_FILE) or {})


class TestSmartGroups(_HandlerBase):
    """W5-6: saved-query dynamic groups."""

    def _devs(self):
        return {
            'd1': {'name': 'web1', 'group': 'web', 'tags': ['prod'],
                   'sysinfo': {'mem_percent': 92}},
            'd2': {'name': 'web2', 'group': 'web', 'tags': ['prod'],
                   'sysinfo': {'mem_percent': 40}},
            'd3': {'name': 'db1', 'group': 'db', 'tags': ['prod'],
                   'sysinfo': {'mem_percent': 95}},
        }

    def test_predicate_group_and_mem(self):
        devs = self._devs()
        self.assertTrue(api._smart_group_match(devs['d1'], {'group': 'web', 'mem_gt': 90}))
        self.assertFalse(api._smart_group_match(devs['d2'], {'group': 'web', 'mem_gt': 90}))
        self.assertFalse(api._smart_group_match(devs['d3'], {'group': 'web', 'mem_gt': 90}))

    def test_materialize(self):
        members = api._materialize_smart_group({'mem_gt': 90}, self._devs())
        self.assertEqual(members, ['d1', 'd3'])

    def test_create_and_members(self):
        api.save(api.DEVICES_FILE, self._devs())
        api._invalidate_load_cache(api.DEVICES_FILE)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'name': 'Hot-Web!', 'rules': {'group': 'web', 'mem_gt': 90}}
        out = self.call(api.handle_smart_groups)
        self.assertEqual(out['name'], 'hot-web')
        self.assertEqual(out['scope_value'], 'smart:hot-web')
        st = api.load(api.SMART_GROUPS_FILE) or {}
        self.assertEqual(st['hot-web']['members'], ['d1'])

    def test_create_requires_a_rule(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'name': 'x', 'rules': {}}
        out = self.call(api.handle_smart_groups)
        self.assertIn('rule', str(out))

    def test_scope_resolves_smart_value(self):
        api.save(api.SMART_GROUPS_FILE, {'hot': {'rules': {'mem_gt': 90}, 'members': []}})
        api._invalidate_load_cache(api.SMART_GROUPS_FILE)
        scope = {'type': 'groups', 'values': ['smart:hot']}
        self.assertTrue(api._device_in_scope(scope, {'sysinfo': {'mem_percent': 95}}))
        self.assertFalse(api._device_in_scope(scope, {'sysinfo': {'mem_percent': 10}}))
        # static group value still works alongside
        scope2 = {'type': 'groups', 'values': ['web', 'smart:hot']}
        self.assertTrue(api._device_in_scope(scope2, {'group': 'web'}))

    def test_cadence_rematerializes(self):
        api.save(api.SMART_GROUPS_FILE, {'g': {'rules': {'group': 'web'}, 'members': []}})
        api.save(api.DEVICES_FILE, self._devs())
        api._invalidate_load_cache(api.SMART_GROUPS_FILE)
        api._invalidate_load_cache(api.DEVICES_FILE)
        api.run_smart_groups_if_due()
        st = api.load(api.SMART_GROUPS_FILE) or {}
        self.assertEqual(st['g']['members'], ['d1', 'd2'])

    def test_delete(self):
        api.save(api.SMART_GROUPS_FILE, {'g': {'rules': {'group': 'web'}, 'members': []}})
        api._invalidate_load_cache(api.SMART_GROUPS_FILE)
        api.method = lambda: 'DELETE'
        self.call(api.handle_smart_group, 'g')
        self.assertNotIn('g', api.load(api.SMART_GROUPS_FILE) or {})


class TestSiteMap(_HandlerBase):
    """W5-5: geographic site map — lat/lng + rolled-up health."""

    def test_create_stores_coords(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'name': 'HQ', 'lat': 55.6, 'lng': 12.6}
        out = self.call(api.handle_site_create)
        sid = out['id']
        s = (api.load(api.SITES_FILE) or {})[sid]
        self.assertEqual(s['lat'], 55.6)
        self.assertEqual(s['lng'], 12.6)

    def test_bad_coords_rejected(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'name': 'X', 'lat': 200, 'lng': 0}
        out = self.call(api.handle_site_create)
        self.assertIn('lat', str(out))

    def test_map_tallies_health(self):
        api.save(api.SITES_FILE, {
            's1': {'name': 'A', 'lat': 10, 'lng': 20},
            's2': {'name': 'B', 'lat': 30, 'lng': 40},
            's3': {'name': 'NoCoords'}})
        now = int(__import__('time').time())
        api.save(api.DEVICES_FILE, {
            'd1': {'site': 's1', 'last_seen': now},          # online
            'd2': {'site': 's1', 'last_seen': now - 999999}, # offline
            'd3': {'site': 's2', 'last_seen': now - 999999}, # all offline
        })
        api._invalidate_load_cache(api.SITES_FILE)
        api._invalidate_load_cache(api.DEVICES_FILE)
        saved = api._scope_filter_devices
        api._scope_filter_devices = lambda d: d
        try:
            out = self.call(api.handle_sites_map)
        finally:
            api._scope_filter_devices = saved
        by = {s['id']: s for s in out['sites']}
        self.assertNotIn('s3', by)                # no coords → excluded
        self.assertEqual(by['s1']['health'], 'degraded')  # 1 of 2 offline
        self.assertEqual(by['s2']['health'], 'down')      # all offline

    def test_update_clears_coords(self):
        api.save(api.SITES_FILE, {'s1': {'name': 'A', 'lat': 10, 'lng': 20}})
        api._invalidate_load_cache(api.SITES_FILE)
        api.method = lambda: 'PUT'
        api.get_json_obj = lambda: {'name': 'A', 'lat': '', 'lng': ''}
        self.call(api.handle_site_update, 's1')
        s = (api.load(api.SITES_FILE) or {})['s1']
        self.assertNotIn('lat', s)


class TestRackElevation(_HandlerBase):
    """W5-3: rack registry + elevation view with conflict detection."""

    def test_create_and_list(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'name': 'R1', 'height_u': 42}
        out = self.call(api.handle_racks)
        rid = out['id']
        self.assertIn(rid, api.load(api.RACKS_FILE) or {})

    def test_elevation_conflict_detection(self):
        api.save(api.RACKS_FILE, {'r1': {'name': 'R1', 'height_u': 42}})
        api.save(api.CMDB_FILE, {
            'd1': {'rack_id': 'r1', 'rack_unit': 1, 'rack_height_u': 2},   # U1-2
            'd2': {'rack_id': 'r1', 'rack_unit': 2, 'rack_height_u': 1},   # U2 — overlaps d1
            'd3': {'rack_id': 'r1', 'rack_unit': 10, 'rack_height_u': 1},  # U10 — clear
            'd4': {'rack_id': 'other', 'rack_unit': 1, 'rack_height_u': 1}})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a'}, 'd2': {'name': 'b'},
                                    'd3': {'name': 'c'}, 'd4': {'name': 'd'}})
        for f in (api.RACKS_FILE, api.CMDB_FILE, api.DEVICES_FILE):
            api._invalidate_load_cache(f)
        out = self.call(api.handle_rack_elevation, 'r1')
        self.assertEqual(out['height_u'], 42)
        ids = {a['device_id'] for a in out['assets']}
        self.assertEqual(ids, {'d1', 'd2', 'd3'})   # d4 is in another rack
        conflicted = {a['device_id'] for a in out['assets'] if a['conflict']}
        self.assertEqual(conflicted, {'d1', 'd2'})
        self.assertIn(2, out['conflicts'])

    def test_pure_elevation(self):
        rack = {'height_u': 10}
        cmdb = {'x': {'rack_id': 'r', 'rack_unit': 3, 'rack_height_u': 2}}
        m = api._rack_elevation(rack, 'r', cmdb, {'x': {'name': 'xn'}})
        self.assertEqual(m['assets'][0]['top_u'], 4)
        self.assertEqual(m['conflicts'], [])

    def test_delete_unplaces_assets(self):
        api.save(api.RACKS_FILE, {'r1': {'name': 'R1', 'height_u': 42}})
        api.save(api.CMDB_FILE, {'d1': {'rack_id': 'r1', 'rack_unit': 5, 'rack_height_u': 1}})
        api._invalidate_load_cache(api.RACKS_FILE)
        api._invalidate_load_cache(api.CMDB_FILE)
        api.method = lambda: 'DELETE'
        self.call(api.handle_rack, 'r1')
        self.assertNotIn('r1', api.load(api.RACKS_FILE) or {})
        rec = (api.load(api.CMDB_FILE) or {})['d1']
        self.assertEqual(rec['rack_id'], '')
        self.assertEqual(rec['rack_unit'], 0)


class TestIpam(_HandlerBase):
    """W5-2: IPAM subnets + occupancy + conflict detection."""

    def test_assignments_from_device_and_cmdb(self):
        devices = {'d1': {'name': 'a', 'ip': '10.0.0.5'},
                   'd2': {'name': 'b', 'ip': '10.0.0.6'}}
        cmdb = {'d1': {'interfaces': [{'ip': '10.0.0.5', 'nat_ip': '1.2.3.4'}]}}
        a = api._ipam_assignments(devices, cmdb)
        self.assertIn('10.0.0.5', a)
        self.assertIn('1.2.3.4', a)
        self.assertEqual(len(a['10.0.0.5']), 2)   # device + nic

    def test_occupancy_counts(self):
        subnet = {'cidr': '10.0.0.0/29', 'reservations': {'10.0.0.3': 'gateway'}}
        assignments = {'10.0.0.5': [{'device_id': 'd1', 'name': 'a', 'source': 'device'}],
                       '192.168.0.1': [{'device_id': 'x', 'name': 'x', 'source': 'device'}]}
        occ = api._ipam_occupancy(subnet, assignments)
        self.assertEqual(occ['used'], 1)   # only 10.0.0.5 is in-range
        self.assertEqual(occ['reserved'], 1)
        ips = {a['ip'] for a in occ['addresses']}
        self.assertEqual(ips, {'10.0.0.5', '10.0.0.3'})

    def test_occupancy_flags_conflict(self):
        subnet = {'cidr': '10.0.0.0/24'}
        assignments = {'10.0.0.9': [{'device_id': 'd1', 'name': 'a', 'source': 'device'},
                                    {'device_id': 'd2', 'name': 'b', 'source': 'device'}]}
        occ = api._ipam_occupancy(subnet, assignments)
        self.assertTrue(occ['addresses'][0]['conflict'])

    def test_create_validates_cidr(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'cidr': 'not-a-network'}
        out = self.call(api.handle_ipam_subnets)
        self.assertIn('cidr', str(out))

    def test_conflict_cadence_fires_once(self):
        api.save(api.SUBNETS_FILE, {'s1': {'cidr': '10.0.0.0/24'}})
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'a', 'ip': '10.0.0.9'},
            'd2': {'name': 'b', 'ip': '10.0.0.9'}})   # duplicate
        api.save(api.CMDB_FILE, {})
        for f in (api.SUBNETS_FILE, api.DEVICES_FILE, api.CMDB_FILE, api.IPAM_STATE_FILE):
            api._invalidate_load_cache(f)
        fired = []
        api.fire_webhook = lambda ev, p: fired.append((ev, p))
        api.run_ipam_conflicts_if_due()
        self.assertEqual([e for e, _ in fired], ['ip_conflict'])
        self.assertEqual(fired[0][1]['ip'], '10.0.0.9')
        # second run: already flagged → no re-fire
        fired.clear()
        api._invalidate_load_cache(api.IPAM_STATE_FILE)
        # bypass the 300s throttle by resetting last_run
        st = api.load(api.IPAM_STATE_FILE) or {}
        st['last_run'] = 0
        api.save(api.IPAM_STATE_FILE, st)
        api._invalidate_load_cache(api.IPAM_STATE_FILE)
        api.run_ipam_conflicts_if_due()
        self.assertEqual(fired, [])


def _load_agent():
    s = importlib.util.spec_from_file_location(
        "rpagent_w5", ROOT / "client" / "remotepower-agent.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class TestLldp(_HandlerBase):
    """W5-1: LLDP topology discovery — agent parse + server suggestions."""

    def test_agent_parses_keyvalue(self):
        agent = _load_agent()
        sample = ("lldp.eth0.via=LLDP\n"
                  "lldp.eth0.chassis.name=core-switch\n"
                  "lldp.eth0.chassis.mgmt-ip=10.0.0.1\n"
                  "lldp.eth0.port.ifname=Gi0/1\n"
                  "lldp.eth1.chassis.name=access-sw\n"
                  "lldp.eth1.port.ifname=Gi0/2\n")
        import subprocess
        orig_co, orig_which = subprocess.check_output, agent._which
        subprocess.check_output = lambda *a, **k: sample
        agent._which = lambda prog, _cache={}: '/usr/sbin/lldpctl'
        try:
            rows = agent.collect_lldp_neighbors()
        finally:
            subprocess.check_output = orig_co
            agent._which = orig_which
        by = {r['local_if']: r for r in rows}
        self.assertEqual(by['eth0']['peer_name'], 'core-switch')
        self.assertEqual(by['eth0']['mgmt_ip'], '10.0.0.1')
        self.assertEqual(by['eth0']['peer_port'], 'Gi0/1')

    def test_agent_skips_without_lldpctl(self):
        agent = _load_agent()
        orig = agent._which
        agent._which = lambda prog, _cache={}: None
        try:
            self.assertEqual(agent.collect_lldp_neighbors(), [])
        finally:
            agent._which = orig

    def test_server_suggests_edge_by_mgmt_ip(self):
        api.save(api.DEVICES_FILE, {
            'host': {'name': 'host1', 'ip': '10.0.0.50'},
            'sw':   {'name': 'core-switch', 'ip': '10.0.0.1'}})
        api.save(api.LLDP_NEIGHBORS_FILE, {
            'host': {'ts': 1, 'neighbors': [
                {'local_if': 'eth0', 'peer_name': 'core-switch',
                 'peer_port': 'Gi0/1', 'mgmt_ip': '10.0.0.1'}]}})
        for f in (api.DEVICES_FILE, api.LLDP_NEIGHBORS_FILE):
            api._invalidate_load_cache(f)
        sugg = api._lldp_suggestions()
        self.assertEqual(len(sugg), 1)
        self.assertEqual(sugg[0]['device_id'], 'host')
        self.assertEqual(sugg[0]['peer_id'], 'sw')

    def test_accept_sets_connected_to(self):
        api.save(api.DEVICES_FILE, {'host': {'name': 'h'}, 'sw': {'name': 's'}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'device_id': 'host', 'peer_id': 'sw', 'action': 'accept'}
        self.call(api.handle_lldp_suggestions)
        self.assertEqual((api.load(api.DEVICES_FILE) or {})['host']['connected_to'], 'sw')

    def test_dismiss_suppresses_suggestion(self):
        api.save(api.DEVICES_FILE, {
            'host': {'name': 'h', 'ip': '10.0.0.50'}, 'sw': {'name': 'sw', 'ip': '10.0.0.1'}})
        api.save(api.LLDP_NEIGHBORS_FILE, {
            'host': {'ts': 1, 'neighbors': [{'local_if': 'eth0', 'peer_name': 'sw',
                                             'mgmt_ip': '10.0.0.1'}]}})
        api.save(api.LLDP_DISMISS_FILE, {'pairs': ['host:sw']})
        for f in (api.DEVICES_FILE, api.LLDP_NEIGHBORS_FILE, api.LLDP_DISMISS_FILE):
            api._invalidate_load_cache(f)
        self.assertEqual(api._lldp_suggestions(), [])


if __name__ == '__main__':
    unittest.main()
