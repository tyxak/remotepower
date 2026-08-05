"""v6.4.2 — the fleet-ops bound module (server/cgi-bin/fleet_ops_handlers.py).

Four capabilities, all driven through the REAL handlers against a real store:

  1. POST /api/devices/bulk-attrs   — bulk device ATTRIBUTE edit
  2. GET  /api/taxonomy + POST /api/taxonomy/groups/{rename,merge,delete}
  3. GET/POST /api/patch-approvals (+ /delete) — per-package patch approval,
     CONSUMED by _autopatch_queue
  4. log_buffer_retention_hours / log_buffer_max_bytes_per_unit tunables and
     GET /api/logs/export

WHY THIS FILE IS SHAPED THE WAY IT IS. The previous attempt at this subsystem
appended 17 handlers to api.py with ZERO routes registered — every handler's
only reference was its own `def`. It parsed, it linted, and it was completely
unreachable. So TestRoutesResolve drives the REAL dispatcher for every path,
and every other class calls the handler api.py re-imported (never the module
object directly), which is the same object the route table holds.

TestTenantAndScope deliberately stubs ONLY verify_token. Stubbing
require_auth / require_admin_auth / require_write_role would happily "pass" a
handler with no gate at all — the false-green class this repo keeps shipping.
"""
import importlib.util
import io
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# MUST be set before api.py is exec'd — import-time ensure_default_user() writes
# to DATA_DIR, so without this the tests target the REAL /var/lib/remotepower.
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v642-fleetops-'))


def _fresh_api():
    """api.py exec'd against a private data dir (one per test class)."""
    d = tempfile.mkdtemp(prefix='rp-v642-fleetops-')
    os.environ['RP_DATA_DIR'] = d
    spec = importlib.util.spec_from_file_location(
        'api_v642_fleetops', _ROOT / 'server' / 'cgi-bin' / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Case(unittest.TestCase):
    """Auth stubbed WIDE (these classes test behaviour, not gates).
    TestTenantAndScope below stubs only verify_token and tests the gates."""

    def setUp(self):
        self.api = _fresh_api()
        self.cap = {}
        self.audit = []

        def _respond(status, data=None):
            self.cap['status'] = status
            self.cap['data'] = data
            raise self.api.HTTPError(status, data)
        self.api.respond = _respond
        self.api.audit_log = lambda *a, **k: self.audit.append((a, k))
        self.api.fire_webhook = lambda *a, **k: None
        self.api.log_command = lambda *a, **k: None
        self.api.require_auth = lambda *a, **k: 'admin'
        self.api.require_admin_auth = lambda *a, **k: 'admin'
        self.api.require_write_role = lambda *a, **k: 'admin'
        self.api.require_perm = lambda *a, **k: 'admin'
        self.api.method = lambda: 'POST'

    def call(self, fn, *a):
        """Run a handler, returning (status, body). `.body` on the HTTPError is
        the already-decoded dict, not a JSON string."""
        self.cap.clear()
        try:
            fn(*a)
        except self.api.HTTPError as e:
            return e.status, e.body
        except SystemExit:
            return self.cap.get('status'), self.cap.get('data')
        return 200, None

    def body(self, obj):
        self.api.get_json_obj = lambda: obj
        self.api.get_json_body = lambda: obj

    def devices(self):
        return self.api.load(self.api.DEVICES_FILE)


# ─────────────────────────── 1. bulk attribute edit ──────────────────────────

class TestBulkAttrs(_Case):
    def setUp(self):
        super().setUp()
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'one', 'token': 't', 'group': 'old', 'tags': ['a'],
                   'monitored': True, 'notes': 'keep me'},
            'd2': {'name': 'two', 'token': 't', 'group': 'old', 'tags': ['a', 'b'],
                   'monitored': True, 'notes': 'keep me too'},
            'd3': {'name': 'three', 'token': 't', 'group': 'other', 'tags': [],
                   'monitored': True},
        })
        self.api.save(self.api.SITES_FILE, {'hq': {'name': 'HQ'}})
        self.api._LOAD_CACHE.clear()

    def test_only_keys_present_are_written(self):
        self.body({'device_ids': ['d1', 'd2'], 'group': 'prod'})
        st, out = self.call(self.api.handle_devices_bulk_attrs)
        self.assertEqual(st, 200)
        self.assertEqual(out['updated'], 2)
        self.assertEqual(out['fields'], ['group'])
        d = self.devices()
        self.assertEqual(d['d1']['group'], 'prod')
        self.assertEqual(d['d2']['group'], 'prod')
        # untouched keys survive — "missing key = don't touch"
        self.assertEqual(d['d1']['tags'], ['a'])
        self.assertEqual(d['d1']['notes'], 'keep me')
        self.assertTrue(d['d1']['monitored'])
        # and a device that wasn't named is not touched at all
        self.assertEqual(d['d3']['group'], 'other')

    def test_empty_list_clears_but_a_missing_key_does_not(self):
        self.body({'device_ids': ['d1'], 'tags': []})
        self.assertEqual(self.call(self.api.handle_devices_bulk_attrs)[0], 200)
        self.assertEqual(self.devices()['d1']['tags'], [])
        self.assertEqual(self.devices()['d2']['tags'], ['a', 'b'])   # not named

    def test_tag_add_remove_set_merge(self):
        self.body({'device_ids': ['d1', 'd2'], 'tags_add': ['prod'],
                   'tags_remove': ['a']})
        self.assertEqual(self.call(self.api.handle_devices_bulk_attrs)[0], 200)
        d = self.devices()
        self.assertEqual(d['d1']['tags'], ['prod'])
        self.assertEqual(d['d2']['tags'], ['b', 'prod'])

    def test_sanitisers_match_the_per_device_handler(self):
        self.body({'device_ids': ['d1'], 'group': 'pr od!@#/x',
                   'tags': ['a b', 'ok', '', 'x!@#y']})
        self.assertEqual(self.call(self.api.handle_devices_bulk_attrs)[0], 200)
        d = self.devices()['d1']
        self.assertEqual(d['group'], 'prod/x')
        self.assertEqual(d['tags'], ['ab', 'ok', 'xy'])
        # identical to what _clean_group / _clean_tags would produce alone
        self.assertEqual(d['group'], self.api._clean_group('pr od!@#/x'))
        self.assertEqual(d['tags'], self.api._clean_tags(['a b', 'ok', '', 'x!@#y']))

    def test_decommission_forces_monitored_false(self):
        self.body({'device_ids': ['d1'], 'decommissioned': True, 'monitored': True})
        self.assertEqual(self.call(self.api.handle_devices_bulk_attrs)[0], 200)
        self.assertFalse(self.devices()['d1']['monitored'])
        self.assertTrue(self.devices()['d1']['decommissioned'])

    def test_unknown_site_is_rejected_before_any_write(self):
        self.body({'device_ids': ['d1'], 'site': 'nowhere'})
        st, out = self.call(self.api.handle_devices_bulk_attrs)
        self.assertEqual(st, 400)
        self.assertIn('site', out['error'])
        self.assertNotIn('site', self.devices()['d1'])

    def test_out_of_range_poll_interval_400s_and_writes_nothing(self):
        self.body({'device_ids': ['d1'], 'group': 'prod', 'poll_interval': 5})
        self.assertEqual(self.call(self.api.handle_devices_bulk_attrs)[0], 400)
        self.assertEqual(self.devices()['d1']['group'], 'old')  # no partial write

    def test_600_ids_are_not_silently_truncated_to_100(self):
        """_resolve_targets caps at 100 — using it here would report success on
        a 600-host selection while touching 100. This endpoint must not."""
        many = {f'x{i}': {'name': f'x{i}', 'token': 't', 'group': 'old'}
                for i in range(600)}
        self.api.save(self.api.DEVICES_FILE, many)
        self.api._LOAD_CACHE.clear()
        self.body({'device_ids': sorted(many), 'group': 'prod'})
        st, out = self.call(self.api.handle_devices_bulk_attrs)
        self.assertEqual(st, 200)
        self.assertEqual(out['updated'], 600)
        d = self.devices()
        self.assertEqual(sum(1 for v in d.values() if v.get('group') == 'prod'), 600)

    def test_no_editable_field_400s(self):
        self.body({'device_ids': ['d1']})
        self.assertEqual(self.call(self.api.handle_devices_bulk_attrs)[0], 400)

    def test_empty_device_ids_400s(self):
        self.body({'device_ids': [], 'group': 'prod'})
        self.assertEqual(self.call(self.api.handle_devices_bulk_attrs)[0], 400)

    def test_audit_row_is_written(self):
        self.body({'device_ids': ['d1'], 'group': 'prod'})
        self.call(self.api.handle_devices_bulk_attrs)
        self.assertTrue(any('devices_bulk_attrs' in str(a) for a, _ in self.audit))

    def test_get_is_405(self):
        self.api.method = lambda: 'GET'
        self.body({'device_ids': ['d1'], 'group': 'p'})
        self.assertEqual(self.call(self.api.handle_devices_bulk_attrs)[0], 405)


# ────────────────────────────── 2. taxonomy ──────────────────────────────────

class TestTaxonomy(_Case):
    def setUp(self):
        super().setUp()
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'one', 'token': 't', 'group': 'prod', 'tags': ['web']},
            'd2': {'name': 'two', 'token': 't', 'group': 'prod', 'tags': ['web', 'db']},
            'd3': {'name': 'three', 'token': 't', 'group': 'staging', 'tags': []},
            'd4': {'name': 'four', 'token': 't', 'group': '', 'tags': ['db'],
                   'site': 'hq'},
        })
        self.api._LOAD_CACHE.clear()

    def test_list(self):
        self.api.method = lambda: 'GET'
        st, out = self.call(self.api.handle_taxonomy_list)
        self.assertEqual(st, 200)
        self.assertEqual(out['groups'],
                         [{'name': 'prod', 'device_count': 2},
                          {'name': 'staging', 'device_count': 1}])
        self.assertEqual(out['tags'],
                         [{'name': 'db', 'device_count': 2},
                          {'name': 'web', 'device_count': 2}])
        self.assertEqual(out['ungrouped'], 1)
        self.assertEqual(out['untagged'], 1)
        self.assertEqual(out['sites'], [{'name': 'hq', 'device_count': 1}])
        self.assertEqual(out['devices'], 4)

    def test_rename_moves_every_member_in_one_call(self):
        self.body({'from': 'prod', 'to': 'production'})
        st, out = self.call(self.api.handle_taxonomy_group_rename)
        self.assertEqual(st, 200)
        self.assertEqual(out['updated'], 2)
        d = self.devices()
        self.assertEqual(d['d1']['group'], 'production')
        self.assertEqual(d['d2']['group'], 'production')
        self.assertEqual(d['d3']['group'], 'staging')   # untouched

    def test_merge_folds_many_groups_into_one(self):
        self.body({'from': ['prod', 'staging'], 'to': 'all'})
        st, out = self.call(self.api.handle_taxonomy_group_merge)
        self.assertEqual(st, 200)
        self.assertEqual(out['updated'], 3)
        self.assertEqual({v['group'] for k, v in self.devices().items() if k != 'd4'},
                         {'all'})

    def test_delete_clears_the_label_and_keeps_the_devices(self):
        self.body({'group': 'prod'})
        st, out = self.call(self.api.handle_taxonomy_group_delete)
        self.assertEqual(st, 200)
        self.assertEqual(out['updated'], 2)
        d = self.devices()
        self.assertEqual(d['d1']['group'], '')
        self.assertIn('d1', d)          # the device survives
        self.assertEqual(len(d), 4)

    def test_unknown_group_404s(self):
        self.body({'from': 'ghost', 'to': 'x'})
        self.assertEqual(self.call(self.api.handle_taxonomy_group_rename)[0], 404)

    def test_rename_to_itself_400s(self):
        self.body({'from': 'prod', 'to': 'prod'})
        self.assertEqual(self.call(self.api.handle_taxonomy_group_rename)[0], 400)

    def test_rename_rejects_multiple_sources(self):
        self.body({'from': ['prod', 'staging'], 'to': 'x'})
        self.assertEqual(self.call(self.api.handle_taxonomy_group_rename)[0], 400)

    def test_names_go_through_the_same_sanitiser_as_the_per_device_handler(self):
        self.body({'from': 'prod', 'to': 'pro d!@#uction'})
        st, out = self.call(self.api.handle_taxonomy_group_rename)
        self.assertEqual(st, 200)
        self.assertEqual(out['to'], 'production')
        self.assertEqual(self.devices()['d1']['group'], 'production')

    def test_orphan_references_are_reported_not_silently_broken(self):
        """A group is the selector for role scopes / auto-patch targets /
        rollout rings / smart groups. The rename does NOT rewrite them — it
        REPORTS them, so the operator is told instead of finding out later."""
        self.api.save(self.api.ROLES_FILE, {'roles': [
            {'name': 'prod-op', 'permissions': ['exec'],
             'scope': {'type': 'groups', 'values': ['prod']}}]})
        self.api.save(self.api.AUTOPATCH_FILE, {'policies': [
            {'id': 'p1', 'name': 'nightly', 'target': {'type': 'group', 'value': 'prod'}}]})
        self.api._LOAD_CACHE.clear()
        self.body({'from': 'prod', 'to': 'production'})
        st, out = self.call(self.api.handle_taxonomy_group_rename)
        self.assertEqual(st, 200)
        stores = {r['store']: r['references'] for r in out['orphan_references']}
        self.assertEqual(stores.get('roles'), 1)
        self.assertEqual(stores.get('autopatch_policies'), 1)
        # and the references really are still pointing at the old name
        self.assertEqual(
            self.api.load(self.api.ROLES_FILE)['roles'][0]['scope']['values'], ['prod'])

    def test_no_orphans_reported_when_nothing_references_the_group(self):
        self.body({'from': 'prod', 'to': 'production'})
        self.assertEqual(self.call(self.api.handle_taxonomy_group_rename)[1]
                         ['orphan_references'], [])


class TestGroupRenameIsAtomic(_Case):
    """A client-side PATCH-per-device loop can half-apply and leave a group
    split across two names. The whole reason this is a server endpoint is that
    it is ONE _LockedUpdate read-modify-write: on any failure, NOTHING moves."""

    def setUp(self):
        super().setUp()
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'one', 'token': 't', 'group': 'prod'},
            'd2': {'name': 'two', 'token': 't', 'group': 'prod'},
            'd3': {'name': 'three', 'token': 't', 'group': 'prod'},
        })
        self.api._LOAD_CACHE.clear()

    def test_all_three_move_in_one_call(self):
        self.body({'from': 'prod', 'to': 'production'})
        self.assertEqual(self.call(self.api.handle_taxonomy_group_rename)[1]['updated'], 3)
        self.assertEqual({v['group'] for v in self.devices().values()}, {'production'})

    def _patch_lock(self, abort=False):
        """Wrap the REAL _LockedUpdate so we can (a) count how many times the
        handler opens one on DEVICES_FILE and (b) optionally make the commit
        fail — delegating the failure into the real __exit__, which is the code
        that actually decides whether to write."""
        real = self.api._LockedUpdate
        opened = []

        class _Wrap:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                return self.inner.__enter__()

            def __exit__(self, et, ev, tb):
                if abort and et is None:
                    err = RuntimeError('storage exploded mid-commit')
                    self.inner.__exit__(RuntimeError, err, None)
                    raise err
                return self.inner.__exit__(et, ev, tb)

        def _factory(path, *a, **k):
            inner = real(path, *a, **k)
            if path == self.api.DEVICES_FILE:
                opened.append(path)
                return _Wrap(inner)
            return inner
        self.api._LockedUpdate = _factory
        self.addCleanup(setattr, self.api, '_LockedUpdate', real)
        return opened

    def test_the_whole_rename_takes_exactly_ONE_devices_lock(self):
        opened = self._patch_lock()
        self.body({'from': 'prod', 'to': 'production'})
        self.assertEqual(self.call(self.api.handle_taxonomy_group_rename)[0], 200)
        self.assertEqual(len(opened), 1,
                         'a per-device lock loop can half-apply — the point of '
                         'this endpoint is one read-modify-write')

    def test_a_failure_mid_operation_leaves_NOTHING_half_renamed(self):
        self._patch_lock(abort=True)
        self.body({'from': 'prod', 'to': 'production'})
        with self.assertRaises(RuntimeError):
            self.api.handle_taxonomy_group_rename()
        self.api._LOAD_CACHE.clear()
        groups = {v.get('group') for v in self.devices().values()}
        self.assertEqual(groups, {'prod'},
                         'a failed rename must leave every device on the OLD '
                         f'group, got {groups}')


# ───────────────────────── 3. per-package patch approval ─────────────────────

class TestPatchApprovals(_Case):
    def setUp(self):
        super().setUp()
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'one', 'token': 't', 'group': 'prod', 'os': 'Debian'},
        })
        self.api._LOAD_CACHE.clear()

    def _set(self, packages, state, note=''):
        self.body({'packages': packages, 'state': state, 'note': note})
        return self.call(self.api.handle_patch_approval_set)

    def test_set_then_list_round_trip(self):
        self.assertEqual(self._set(['linux-image-amd64'], 'declined',
                                   'breaks the raid driver')[0], 200)
        self.assertEqual(self._set('nginx curl', 'approved')[0], 200)
        self.api.method = lambda: 'GET'
        st, out = self.call(self.api.handle_patch_approvals_list)
        self.assertEqual(st, 200)
        self.assertEqual(out['approved'], 2)
        self.assertEqual(out['declined'], 1)
        row = next(r for r in out['approvals'] if r['package'] == 'linux-image-amd64')
        self.assertEqual(row['state'], 'declined')
        self.assertEqual(row['note'], 'breaks the raid driver')
        self.assertTrue(row['ts'] > 0)

    def test_clear_removes_the_decision(self):
        self._set(['nginx'], 'declined')
        self.body({'packages': ['nginx']})
        st, out = self.call(self.api.handle_patch_approval_clear)
        self.assertEqual(st, 200)
        self.assertEqual(out['removed'], 1)
        self.assertEqual(self.api._patch_approvals(), {})

    def test_bad_state_400s(self):
        self.assertEqual(self._set(['nginx'], 'maybe')[0], 400)

    def test_shell_metacharacters_in_a_package_name_are_rejected(self):
        st, out = self._set(['nginx; rm -rf /'], 'declined')
        self.assertEqual(st, 400)
        self.assertIn('invalid package name', out['error'])

    def test_declined_packages_are_PINNED_by_the_real_autopatch_sweep(self):
        """Drive _autopatch_queue, do not read its source: the feature is only
        real if the queued command actually holds the declined package."""
        self._set(['linux-image-amd64'], 'declined')
        self._set(['nginx'], 'approved')
        self.api._LOAD_CACHE.clear()
        pol = {'id': 'p1', 'name': 'nightly', 'enabled': True,
               'target': {'type': 'all'}, 'reboot': False}
        n = self.api._autopatch_queue(pol, 'tester')
        self.assertEqual(n, 1)
        queued = (self.api.load(self.api.CMDS_FILE) or {}).get('d1') or []
        self.assertTrue(queued, 'auto-patch queued nothing at all')
        cmd = queued[-1]
        self.assertIn('apt-mark hold linux-image-amd64', cmd)
        self.assertIn('apt-mark unhold nginx', cmd)          # state converges
        self.assertIn('upgrade-packages', cmd)               # the upgrade still runs
        self.assertLess(cmd.index('apt-mark hold'), cmd.index('upgrade-packages'),
                        'the pin must be applied BEFORE the upgrade')

    def test_no_approvals_leaves_the_autopatch_command_byte_identical(self):
        pol = {'id': 'p1', 'name': 'nightly', 'enabled': True,
               'target': {'type': 'all'}, 'reboot': False}
        self.api._autopatch_queue(pol, 'tester')
        cmd = (self.api.load(self.api.CMDS_FILE) or {})['d1'][-1]
        self.assertEqual(cmd, 'exec:' + self.api._SCHED_UPGRADE_CMD)
        self.assertEqual(self.api._autopatch_pin_prefix(), '')

    def test_a_hand_edited_store_cannot_smuggle_a_metacharacter_into_the_shell(self):
        """_patch_approval_sets re-validates on the way OUT — the names are
        interpolated into a shell command by _build_hold_cmd."""
        self.api.save(self.api.PATCH_APPROVALS_FILE,
                      {'packages': {'evil; rm -rf /': {'state': 'declined'},
                                    'nginx': {'state': 'declined'}}})
        self.api._LOAD_CACHE.clear()
        _approved, declined = self.api._patch_approval_sets()
        self.assertEqual(declined, {'nginx'})
        self.assertNotIn('rm -rf', self.api._autopatch_pin_prefix())

    def test_patch_catalog_carries_the_decision(self):
        self._set(['nginx'], 'declined')
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'one', 'token': 't',
                   'sysinfo': {'packages': {'upgradable_names': ['nginx', 'curl']}}}})
        self.api._LOAD_CACHE.clear()
        self.api.method = lambda: 'GET'
        st, out = self.call(self.api.handle_patch_catalog)
        self.assertEqual(st, 200)
        states = {r['package']: r['approval'] for r in out['packages']}
        self.assertEqual(states['nginx'], 'declined')
        self.assertEqual(states['curl'], '')
        self.assertEqual(out['declined_packages'], 1)


class TestPatchApprovalWriteGate(unittest.TestCase):
    """The read-only-role WRITE-gate class. Only verify_token is stubbed — a
    stubbed require_write_role would pass a handler with no gate at all."""

    def setUp(self):
        self.api = _fresh_api()
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'] = status
            self.cap['data'] = data
            raise self.api.HTTPError(status, data)
        self.api.respond = _respond
        self.api.audit_log = lambda *a, **k: None
        self.api.get_token_from_request = lambda: 'tok'
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'packages': ['nginx'], 'state': 'declined'}
        self.api.get_json_body = self.api.get_json_obj
        self.api.save(self.api.ROLES_FILE, {'roles': [
            {'name': 'patch-op', 'permissions': ['patch'], 'scope': {'type': 'all'}},
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

    def test_read_only_roles_cannot_set_an_approval(self):
        for role in ('viewer', 'mcp', 'auditor', 'finance'):
            self._as(role)
            self.assertEqual(
                self._status(self.api.handle_patch_approval_set), 403, role)
            self.assertEqual(
                self._status(self.api.handle_patch_approval_clear), 403, role)

    def test_an_operator_role_CAN_set_an_approval(self):
        """The under-permissive direction — it must not be admin-only by accident."""
        self._as('patch-op')
        self.assertEqual(self._status(self.api.handle_patch_approval_set), 200)

    def test_admin_can_set_an_approval(self):
        self._as('admin')
        self.assertEqual(self._status(self.api.handle_patch_approval_set), 200)

    def test_a_read_only_role_CAN_still_read_the_list(self):
        self._as('viewer')
        self.api.method = lambda: 'GET'
        self.assertEqual(self._status(self.api.handle_patch_approvals_list), 200)


class TestPatchApprovalIsInstanceWidePolicy(unittest.TestCase):
    """The approvals store has no tenant dimension, and _autopatch_pin_prefix()
    folds it into the command queued for EVERY tenant's Linux hosts.

    A tenant admin has role == 'admin', so require_write_role admits them and
    _caller_scope() is None — without a superadmin gate, one tenant declining
    `openssl` would pin it across the whole instance and approving it would
    un-pin it for everyone else. Same shape as handle_config_save's
    sso_group_roles branch.

    Tenancy is driven for REAL here (config + USERS_FILE); only verify_token is
    stubbed, so a handler that lost its gate entirely would fail this.
    """

    def setUp(self):
        self.api = _fresh_api()
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'] = status
            self.cap['data'] = data
            raise self.api.HTTPError(status, data)
        self.api.respond = _respond
        self.api.audit_log = lambda *a, **k: None
        self.api.get_token_from_request = lambda: 'tok'
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'packages': ['openssl'], 'state': 'declined'}
        self.api.get_json_body = self.api.get_json_obj
        # The tenant must EXIST in the registry — _user_tenant falls back to
        # DEFAULT_TENANT for an unknown id, which would silently make the
        # "tenant admin" a superadmin and turn this whole class green for the
        # wrong reason.
        self.api.save(self.api.TENANTS_FILE, {
            't2': {'name': 'Tenant Two', 'status': 'active', 'created': 0},
        })
        self.api.save(self.api.USERS_FILE, {
            'root':    {'role': 'admin', 'tenant_id': self.api.DEFAULT_TENANT},
            'tadmin':  {'role': 'admin', 'tenant_id': 't2'},
        })
        self.api._LOAD_CACHE.clear()

    def _as(self, user, role='admin'):
        self.api.verify_token = lambda _t=None, _u=user, _r=role: (_u, _r)

    def _tenancy(self, on):
        cfg = self.api.load(self.api.CONFIG_FILE) or {}
        cfg['tenancy_enforced'] = bool(on)
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def _status(self, fn):
        self.cap.clear()
        try:
            fn()
            return 200
        except self.api.HTTPError:
            return self.cap.get('status')

    def test_tenant_admin_cannot_change_instance_wide_policy(self):
        self._tenancy(True)
        self._as('tadmin')
        self.assertEqual(self._status(self.api.handle_patch_approval_set), 403)
        self.assertEqual(self._status(self.api.handle_patch_approval_clear), 403)
        self.assertIn('instance-wide', str(self.cap.get('data', {}).get('error', '')))

    def test_platform_superadmin_can(self):
        self._tenancy(True)
        self._as('root')
        self.assertEqual(self._status(self.api.handle_patch_approval_set), 200)

    def test_single_tenant_install_is_unaffected(self):
        """The overwhelmingly common deployment — the gate must be a no-op."""
        self._tenancy(False)
        self._as('tadmin')
        self.assertEqual(self._status(self.api.handle_patch_approval_set), 200)

    def test_a_tenant_admin_can_still_READ_the_policy(self):
        """Seeing the policy that governs your own hosts is legitimate."""
        self._tenancy(True)
        self._as('tadmin')
        self.api.method = lambda: 'GET'
        self.assertEqual(self._status(self.api.handle_patch_approvals_list), 200)


# ──────────────────── 4. log-ring retention tunables + export ────────────────

class TestLogRetentionTunable(_Case):
    """Drives the REAL handle_config_save → handle_config_get round trip. That
    is the only thing that catches the silent save-whitelist drop, where a
    Settings field appears to work and the value never persists."""

    def setUp(self):
        super().setUp()
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'one', 'token': 'tok1'}})
        self.api._LOAD_CACHE.clear()

    def _save_config(self, obj):
        self.body(obj)
        return self.call(self.api.handle_config_save)

    def test_defaults_match_the_constants(self):
        self.assertEqual(self.api._log_buffer_ttl(), self.api.LOG_BUFFER_TTL)
        self.assertEqual(self.api._log_buffer_unit_cap(), 0)

    def test_round_trip_through_the_real_save_and_get(self):
        self.assertEqual(self._save_config({'log_buffer_retention_hours': 24,
                                            'log_buffer_max_bytes_per_unit': 4096})[0],
                         200)
        self.api._LOAD_CACHE.clear()
        # persisted…
        cfg = self.api.load(self.api.CONFIG_FILE)
        self.assertEqual(cfg['log_buffer_retention_hours'], 24)
        self.assertEqual(cfg['log_buffer_max_bytes_per_unit'], 4096)
        # …surfaced to the Settings UI…
        self.api.method = lambda: 'GET'
        self.api.verify_token = lambda *a, **k: ('admin', 'admin')
        st, out = self.call(self.api.handle_config_get)
        self.assertEqual(st, 200)
        self.assertEqual(out['log_buffer_retention_hours'], 24)
        self.assertEqual(out['log_buffer_max_bytes_per_unit'], 4096)
        # …and honoured by the reader
        self.assertEqual(self.api._log_buffer_ttl(), 24 * 3600)
        self.assertEqual(self.api._log_buffer_unit_cap(), 4096)

    def test_config_get_surfaces_the_default_on_a_stock_install(self):
        self.api.method = lambda: 'GET'
        self.api.verify_token = lambda *a, **k: ('admin', 'admin')
        out = self.call(self.api.handle_config_get)[1]
        self.assertEqual(out['log_buffer_retention_hours'],
                         self.api.LOG_BUFFER_TTL // 3600)
        self.assertEqual(out['log_buffer_max_bytes_per_unit'], 0)

    def test_out_of_range_is_rejected(self):
        self.assertEqual(self._save_config({'log_buffer_retention_hours': 9999})[0], 400)

    def test_ingest_evicts_at_the_CONFIGURED_ttl_not_the_constant(self):
        """The whole point: a line 10h old survives under a 24h retention and is
        gone under the 6h default. Driven through the REAL ingest handler."""
        now = int(time.time())
        old = now - 10 * 3600

        def _submit():
            self.body({'device_id': 'd1', 'token': 'tok1',
                       'units': {'nginx': ['fresh line']}})
            return self.call(self.api.handle_log_submit)

        # seed a 10h-old line directly into the ring, then ingest to trigger the trim
        self.api.save(self.api.LOG_WATCH_FILE, {'d1': {'units': {'nginx': [
            {'ts': old, 'line': 'ten hours old', 'sig': 'aaaa'}]}, 'updated_at': old}})
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self._save_config({'log_buffer_retention_hours': 24})[0], 200)
        self.api._LOAD_CACHE.clear()
        _submit()
        lines = [e['line'] for e in
                 self.api.load(self.api.LOG_WATCH_FILE)['d1']['units']['nginx']]
        self.assertIn('ten hours old', lines, 'a 24h retention must keep a 10h line')

        # now drop retention back to the 6h default and re-ingest
        self.api.save(self.api.LOG_WATCH_FILE, {'d1': {'units': {'nginx': [
            {'ts': old, 'line': 'ten hours old', 'sig': 'aaaa'}]}, 'updated_at': old}})
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self._save_config({'log_buffer_retention_hours': 6})[0], 200)
        self.api._LOAD_CACHE.clear()
        _submit()
        lines = [e['line'] for e in
                 self.api.load(self.api.LOG_WATCH_FILE)['d1']['units']['nginx']]
        self.assertNotIn('ten hours old', lines, 'a 6h retention must evict a 10h line')

    def test_per_unit_byte_cap_keeps_the_NEWEST_lines(self):
        cap = 200
        entries = [{'ts': 100 + i, 'line': 'x' * 40, 'sig': str(i)} for i in range(20)]
        out = self.api._trim_unit_buffer(entries, cap)
        self.assertLess(len(out), len(entries))
        self.assertEqual(out[-1], entries[-1])          # newest survives
        self.assertNotIn(entries[0], out)               # oldest dropped

    def test_byte_cap_of_zero_is_a_no_op(self):
        entries = [{'ts': i, 'line': 'x' * 4096} for i in range(50)]
        self.assertEqual(self.api._trim_unit_buffer(entries, 0), entries)

    def test_byte_cap_never_empties_a_unit(self):
        entries = [{'ts': 1, 'line': 'y' * 10000}]
        self.assertEqual(len(self.api._trim_unit_buffer(entries, 10)), 1)


class _ExportCase(_Case):
    """Captures a download handler's raw CGI output (it writes to sys.stdout and
    exits, bypassing respond() entirely)."""

    class _Cap:
        def __init__(self):
            self.buffer = io.BytesIO()
            self._t = io.StringIO()

        def write(self, s):
            self._t.write(s)

        def flush(self):
            pass

        def value(self):
            return self._t.getvalue() + self.buffer.getvalue().decode('utf-8', 'replace')

    def download(self, fn, *a):
        cap = self._Cap()
        real = self.api.sys.stdout
        self.api.sys.stdout = cap
        try:
            fn(*a)
        except SystemExit:
            pass
        except self.api.HTTPError as e:
            return e.status, e.body, ''
        finally:
            self.api.sys.stdout = real
        return 200, None, cap.value()


class TestLogExport(_ExportCase):
    def setUp(self):
        super().setUp()
        self.api.method = lambda: 'GET'
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'nas', 'token': 't'},
            'd2': {'name': 'router', 'token': 't'},
        })
        now = int(time.time())
        self.api.save(self.api.LOG_WATCH_FILE, {
            'd1': {'units': {'nginx': [
                {'ts': now, 'line': 'GET /health 200'},
                {'ts': now - 100, 'line': '=cmd|/c calc'},   # formula injection
            ]}, 'updated_at': now},
            'd2': {'units': {'sshd': [
                {'ts': now, 'line': 'accepted publickey for root'},
            ]}, 'updated_at': now},
        })
        self.api._LOAD_CACHE.clear()
        self.qs = ''
        self.api._env = lambda k, d=None: self.qs if k == 'QUERY_STRING' else d

    def test_csv_contains_the_seeded_lines(self):
        st, _b, text = self.download(self.api.handle_logs_export)
        self.assertEqual(st, 200)
        self.assertIn('Content-Type: text/csv', text)
        self.assertIn('GET /health 200', text)
        self.assertIn('accepted publickey for root', text)
        self.assertIn('nas', text)
        self.assertIn('router', text)

    def test_csv_escapes_a_leading_formula_character(self):
        _st, _b, text = self.download(self.api.handle_logs_export)
        self.assertIn("'=cmd|/c calc", text,
                      'a log line starting with = must be prefixed so a '
                      'spreadsheet renders it as text')

    def test_ndjson_format(self):
        self.qs = 'format=ndjson'
        _st, _b, text = self.download(self.api.handle_logs_export)
        self.assertIn('Content-Type: application/x-ndjson', text)
        self.assertIn('"line": "GET /health 200"', text)
        self.assertIn('"device_id": "d1"', text)

    def test_device_filter(self):
        self.qs = 'device=d2'
        _st, _b, text = self.download(self.api.handle_logs_export)
        self.assertIn('accepted publickey', text)
        self.assertNotIn('GET /health 200', text)

    def test_unknown_device_404s(self):
        self.qs = 'device=nope'
        st, body, _t = self.download(self.api.handle_logs_export)
        self.assertEqual(st, 404, body)

    def test_regex_filter_and_bad_regex(self):
        self.qs = 'q=publickey'
        _st, _b, text = self.download(self.api.handle_logs_export)
        self.assertIn('accepted publickey', text)
        self.assertNotIn('GET /health 200', text)
        self.qs = 'q=%5B'          # '['
        st, _b, _t = self.download(self.api.handle_logs_export)
        self.assertEqual(st, 400)

    def test_since_filter(self):
        self.qs = f'since={int(time.time()) - 50}'
        _st, _b, text = self.download(self.api.handle_logs_export)
        self.assertIn('GET /health 200', text)
        self.assertNotIn('cmd|/c calc', text)

    def test_post_is_405(self):
        self.api.method = lambda: 'POST'
        st, _b, _t = self.download(self.api.handle_logs_export)
        self.assertEqual(st, 405)


# ─────────────────────── cross-tenant / scope enforcement ────────────────────

class TestTenantAndScope(unittest.TestCase):
    """The important one. ONLY verify_token is stubbed, so the real RBAC and
    tenancy code runs. A tenant admin has role='admin' → _caller_scope() is
    None, so every `if scope is not None:` gate waves them straight through —
    the exact shape that produced a confirmed cross-tenant RCE in this repo.
    """

    def setUp(self):
        self.api = _fresh_api()
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'] = status
            self.cap['data'] = data
            raise self.api.HTTPError(status, data)
        self.api.respond = _respond
        self.api.audit_log = lambda *a, **k: None
        self.api.fire_webhook = lambda *a, **k: None
        self.api.get_token_from_request = lambda: 'tok'
        self.api.method = lambda: 'POST'
        self.api.save(self.api.CONFIG_FILE, {'tenancy_enforced': True})
        self.api.save(self.api.TENANTS_FILE, {
            'default': {'name': 'Default', 'status': 'active', 'builtin': True},
            't2': {'name': 'Other', 'status': 'active'},
        })
        self.api.save(self.api.USERS_FILE, {
            'boss':  {'role': 'admin', 'tenant_id': 'default'},
            'other': {'role': 'admin', 'tenant_id': 't2'},
            'scoped': {'role': 'prod-op', 'tenant_id': 'default'},
        })
        self.api.save(self.api.ROLES_FILE, {'roles': [
            {'name': 'prod-op', 'permissions': ['exec'],
             'scope': {'type': 'groups', 'values': ['prod']}},
        ]})
        self.api.save(self.api.DEVICES_FILE, {
            'mine':   {'name': 'mine', 'token': 't', 'group': 'prod', 'tenant': 'default'},
            'theirs': {'name': 'theirs', 'token': 't', 'group': 'prod', 'tenant': 't2'},
            'other-group': {'name': 'og', 'token': 't', 'group': 'staging',
                            'tenant': 'default'},
        })
        self.api.save(self.api.LOG_WATCH_FILE, {
            'mine':   {'units': {'a': [{'ts': 1, 'line': 'MINE-LINE'}]}, 'updated_at': 1},
            'theirs': {'units': {'a': [{'ts': 1, 'line': 'THEIRS-LINE'}]}, 'updated_at': 1},
        })
        self.api._LOAD_CACHE.clear()
        self.qs = ''
        self.api._env = lambda k, d=None: self.qs if k == 'QUERY_STRING' else d

    def _as(self, user, role='admin'):
        self.api.verify_token = lambda _t=None, _u=user, _r=role: (_u, _r)
        self.api._begin_request()

    def call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
        except self.api.HTTPError as e:
            return e.status, e.body
        except SystemExit:
            return self.cap.get('status'), self.cap.get('data')
        return 200, None

    def body(self, obj):
        self.api.get_json_obj = lambda: obj
        self.api.get_json_body = lambda: obj

    # ── GET /api/taxonomy ────────────────────────────────────────────────────
    def test_taxonomy_hides_the_other_tenants_groups(self):
        self.api.method = lambda: 'GET'
        self._as('other')
        out = self.call(self.api.handle_taxonomy_list)[1]
        self.assertEqual(out['devices'], 1)
        self.assertEqual([g['name'] for g in out['groups']], ['prod'])
        self.assertEqual(out['groups'][0]['device_count'], 1)   # only 'theirs'

    def test_taxonomy_respects_a_role_scope_too(self):
        self.api.method = lambda: 'GET'
        self._as('scoped', role='prod-op')
        out = self.call(self.api.handle_taxonomy_list)[1]
        self.assertEqual([g['name'] for g in out['groups']], ['prod'])
        self.assertEqual(out['devices'], 1)     # 'mine' only, not 'other-group'

    # ── group rename / merge / delete ────────────────────────────────────────
    def test_a_tenant_admin_renaming_a_shared_group_name_only_moves_its_own(self):
        self._as('other')
        self.body({'from': 'prod', 'to': 'production'})
        st, out = self.call(self.api.handle_taxonomy_group_rename)
        self.assertEqual(st, 200)
        self.assertEqual(out['updated'], 1)
        d = self.api.load(self.api.DEVICES_FILE)
        self.assertEqual(d['theirs']['group'], 'production')
        self.assertEqual(d['mine']['group'], 'prod',
                         "another tenant's device must not be renamed")

    def test_a_group_that_exists_only_in_another_tenant_404s(self):
        self._as('other')
        self.body({'from': 'staging', 'to': 'x'})   # 'staging' is default-tenant only
        st, _ = self.call(self.api.handle_taxonomy_group_rename)
        self.assertEqual(st, 404)
        self.assertEqual(
            self.api.load(self.api.DEVICES_FILE)['other-group']['group'], 'staging')

    def test_delete_cannot_clear_another_tenants_group(self):
        self._as('other')
        self.body({'group': 'prod'})
        self.assertEqual(self.call(self.api.handle_taxonomy_group_delete)[0], 200)
        d = self.api.load(self.api.DEVICES_FILE)
        self.assertEqual(d['theirs']['group'], '')
        self.assertEqual(d['mine']['group'], 'prod')

    def test_merge_cannot_pull_another_tenants_devices_in(self):
        self._as('other')
        self.body({'from': ['prod', 'staging'], 'to': 'all'})
        st, out = self.call(self.api.handle_taxonomy_group_merge)
        self.assertEqual(st, 200)
        self.assertEqual(out['updated'], 1)
        d = self.api.load(self.api.DEVICES_FILE)
        self.assertEqual(d['other-group']['group'], 'staging')
        self.assertEqual(d['mine']['group'], 'prod')

    # ── bulk attrs ───────────────────────────────────────────────────────────
    def test_bulk_attrs_drops_a_cross_tenant_id(self):
        self._as('other')
        self.body({'device_ids': ['mine', 'theirs'], 'group': 'pwned'})
        st, out = self.call(self.api.handle_devices_bulk_attrs)
        self.assertEqual(st, 200)
        self.assertEqual(out['updated'], 1)
        d = self.api.load(self.api.DEVICES_FILE)
        self.assertEqual(d['theirs']['group'], 'pwned')
        self.assertEqual(d['mine']['group'], 'prod')

    def test_bulk_attrs_drops_an_out_of_role_scope_id(self):
        self._as('scoped', role='prod-op')
        self.body({'device_ids': ['mine', 'other-group'], 'monitored': False})
        # a scoped operator is not an admin — require_admin_auth must refuse
        self.assertEqual(self.call(self.api.handle_devices_bulk_attrs)[0], 403)

    def test_bulk_delete_still_drops_a_cross_tenant_id_after_the_move(self):
        self._as('other')
        self.body({'device_ids': ['mine', 'theirs']})
        st, out = self.call(self.api.handle_devices_bulk_delete)
        self.assertEqual(st, 200)
        self.assertEqual(out['deleted'], 1)
        self.assertIn('mine', self.api.load(self.api.DEVICES_FILE))

    def test_bulk_tags_still_drops_a_cross_tenant_id_after_the_move(self):
        self._as('other')
        self.body({'device_ids': ['mine', 'theirs'], 'add': ['x']})
        self.assertEqual(self.call(self.api.handle_devices_bulk_tags)[0], 200)
        d = self.api.load(self.api.DEVICES_FILE)
        self.assertEqual(d['theirs']['tags'], ['x'])
        self.assertEqual(d['mine'].get('tags', []), [])

    # ── log export ───────────────────────────────────────────────────────────
    def _export(self):
        cap = _ExportCase._Cap()
        real = self.api.sys.stdout
        self.api.sys.stdout = cap
        try:
            self.api.handle_logs_export()
        except SystemExit:
            pass
        except self.api.HTTPError as e:
            return e.status, ''
        finally:
            self.api.sys.stdout = real
        return 200, cap.value()

    def test_fleet_export_only_carries_this_tenants_lines(self):
        self.api.method = lambda: 'GET'
        self._as('other')
        st, text = self._export()
        self.assertEqual(st, 200)
        self.assertIn('THEIRS-LINE', text)
        self.assertNotIn('MINE-LINE', text)

    def test_export_of_a_cross_tenant_device_is_refused(self):
        self.api.method = lambda: 'GET'
        self._as('other')
        self.qs = 'device=mine'
        st, text = self._export()
        self.assertIn(st, (403, 404), text)
        self.assertNotIn('MINE-LINE', text)

    def test_a_scoped_operator_can_export_its_OWN_device(self):
        """The under-permissive direction — the gate must not lock out the role
        that is supposed to be able to use it."""
        self.api.method = lambda: 'GET'
        self._as('scoped', role='prod-op')
        self.qs = 'device=mine'
        st, text = self._export()
        self.assertEqual(st, 200)
        self.assertIn('MINE-LINE', text)

    def test_a_scoped_operator_cannot_export_an_out_of_scope_device(self):
        self.api.method = lambda: 'GET'
        self._as('scoped', role='prod-op')
        self.qs = 'device=other-group'
        st, _text = self._export()
        self.assertIn(st, (403, 404))


# ───────────────────────────── route registration ────────────────────────────

class TestRoutesResolve(unittest.TestCase):
    """The check the reverted 17-handler batch would have failed: every handler
    is reachable through the REAL dispatcher, not merely defined."""

    EXPECT = (
        ('POST', '/api/devices/bulk-attrs',          'handle_devices_bulk_attrs'),
        ('POST', '/api/devices/bulk-delete',         'handle_devices_bulk_delete'),
        ('POST', '/api/devices/bulk-tags',           'handle_devices_bulk_tags'),
        ('GET',  '/api/taxonomy',                    'handle_taxonomy_list'),
        ('POST', '/api/taxonomy/groups/rename',      'handle_taxonomy_group_rename'),
        ('POST', '/api/taxonomy/groups/merge',       'handle_taxonomy_group_merge'),
        ('POST', '/api/taxonomy/groups/delete',      'handle_taxonomy_group_delete'),
        ('GET',  '/api/patch-approvals',             'handle_patch_approvals_list'),
        ('POST', '/api/patch-approvals',             'handle_patch_approval_set'),
        ('POST', '/api/patch-approvals/delete',      'handle_patch_approval_clear'),
        ('GET',  '/api/logs/export',                 'handle_logs_export'),
    )

    def test_every_route_resolves_through_the_dispatcher(self):
        from routing_harness import resolve_route
        for m, p, h in self.EXPECT:
            self.assertEqual(resolve_route(m, p)[0], h, f'{m} {p}')

    def test_every_route_is_in_the_exact_route_table(self):
        """_build_exact_routes() is fed verbatim into the OpenAPI spec, so an
        entry here is also the endpoint's documentation."""
        import api
        table = api._build_exact_routes()
        for m, p, h in self.EXPECT:
            self.assertIn((m, p), table, f'{m} {p} missing from _build_exact_routes')
            self.assertEqual(table[(m, p)].__name__, h)

    def test_handlers_live_in_the_bound_module_and_are_re_imported(self):
        import api
        import inspect
        for name in ('handle_devices_bulk_attrs', 'handle_devices_bulk_delete',
                     'handle_devices_bulk_tags', 'handle_taxonomy_list',
                     'handle_taxonomy_group_rename', 'handle_taxonomy_group_merge',
                     'handle_taxonomy_group_delete', 'handle_patch_approvals_list',
                     'handle_patch_approval_set', 'handle_patch_approval_clear',
                     'handle_logs_export', '_log_buffer_ttl', '_log_buffer_unit_cap',
                     '_trim_unit_buffer', '_autopatch_pin_prefix',
                     '_patch_approval_sets', '_patch_approvals', '_clean_tags',
                     '_clean_group', '_visible_devices', '_group_reference_report'):
            obj = getattr(api, name, None)
            self.assertIsNotNone(obj, f'{name} was not re-imported into api.py')
            self.assertEqual(obj.__module__, 'fleet_ops_handlers', name)
            self.assertTrue(inspect.getsource(obj))

    def test_api_py_no_longer_defines_the_moved_handlers_inline(self):
        src = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        for name in ('handle_devices_bulk_delete', 'handle_devices_bulk_tags'):
            self.assertNotIn(f'\ndef {name}(', src,
                             f'{name} moved to fleet_ops_handlers.py — the '
                             'ratchet comment says 627→625')


if __name__ == '__main__':
    unittest.main()
