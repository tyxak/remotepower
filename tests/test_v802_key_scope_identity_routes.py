#!/usr/bin/env python3
"""A key limited to part of the fleet hands out access inside that part and nothing more.

8.0.2 says it in the release notes: a key can be given part of the fleet, and that scope confines even an administrator's key. It fixed the
routes that read the fleet. The routes that WRITE access were never brought under the rule, so the confinement lasted until the key asked
for more, in six ways (each driven here on the real stack before it was closed):

* `PATCH /api/apikeys/<id>` on its own key with scope all, or with the scope removed;
* `POST /api/apikeys` for an administrator key that has no scope;
* `POST /api/apikeys/<id>/rotate` of a key that has no scope, which answers with the secret of the new key;
* `POST /api/users` for a viewer, or for an account whose custom role reaches every host: the key chooses the password and signs in;
* `PATCH /api/users/<name>` moving an account it can sign in as to such a role;
* `POST /api/roles` and `PUT /api/roles/<name>` with scope all, for the role those accounts hold.

A key (or a role, or the role of an account) written by a key limited to part of the fleet reaches inside that part. What this holds, with
real keys and sessions through the real route table and the real token check (a process of its own on a data directory of its own):

* every one of those routes refuses what reaches beyond the key (403, `beyond_key_scope`) and changes nothing: the stored scope, the keys,
  the accounts and the roles are as they were, and a key that was made reads inside the part and not outside it;
* a key that asks for no scope gets its own part (nothing is refused, nothing is wider), and what stays inside the part still works: a
  narrower or equal scope, a key rotated or renamed inside the part, an account with a role inside it, a role inside it;
* a scope of another kind (tags for groups) is refused, since it cannot be compared with the hosts unknown;
* a key with no scope, and a signed-in session, are not changed by any of it;
* the comparison itself is sound over every pair of 184 scopes of a small fleet (what `inside` says is inside is inside), and exact for two
  scopes of one kind;
* the class: the functions that write the keys or the roles, and the administrator routes that give an account a role, are listed by syntax
  tree, and each either compares with the caller's scope or is on the list of those that give nothing out; and every writer of the keys
  holds the keys' lock (create and update wrote with a bare load and save before).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import credential_scan  # noqa: E402
import real_stack  # noqa: E402

_DRIVER = r'''
GROUPS = lambda *v: {'type': 'groups', 'values': list(v)}
own_id = add_key('SKEY', 'svc', scope=GROUPS('prod'))        # an administrator key limited to the group prod
wide_id = add_key('WIDE', 'boss')                             # an administrator key with no scope
viewer_id = add_key('VIEWKEY', 'viewbot', role='viewer')      # a read-only key with no scope
keys = lambda: get('APIKEYS_FILE')
reads = lambda token: [call('GET', '/api/devices/%s/sysinfo' % h, token)[0] for h in ('web1', 'db1')]     # inside the part, outside it
out['control_reach'] = reads('SKEY')
out['wide_reach'] = reads('WIDE')

# ---- keys: its own record
out['patch_own_to_all'] = call('PATCH', '/api/apikeys/' + own_id, 'SKEY', {'scope': {'type': 'all'}})
out['patch_own_to_null'] = call('PATCH', '/api/apikeys/' + own_id, 'SKEY', {'scope': None})
out['patch_own_wider'] = call('PATCH', '/api/apikeys/' + own_id, 'SKEY', {'scope': GROUPS('prod', 'dev')})
out['patch_own_other_kind'] = call('PATCH', '/api/apikeys/' + own_id, 'SKEY', {'scope': {'type': 'tags', 'values': ['prod']}})      # a tag called prod is not the group prod
out['own_scope_after_refusals'] = keys()[own_id].get('scope')
out['reach_after_refusals'] = reads('SKEY')
out['patch_own_name'] = call('PATCH', '/api/apikeys/' + own_id, 'SKEY', {'name': 'renamed'})
out['patch_own_same_scope'] = call('PATCH', '/api/apikeys/' + own_id, 'SKEY', {'scope': GROUPS('prod')})
out['own_after_allowed'] = {'name': keys()[own_id]['name'], 'scope': keys()[own_id].get('scope')}

# ---- keys: making one
out['create_no_scope'] = call('POST', '/api/apikeys', 'SKEY', {'name': 'child', 'role': 'admin'})
child_id, child_secret = (out['create_no_scope'][1] or {}).get('id'), (out['create_no_scope'][1] or {}).get('key')
out['child_scope'] = (keys().get(child_id) or {}).get('scope')
out['child_reach'] = reads(child_secret)
before_count = len(keys())
out['create_all'] = call('POST', '/api/apikeys', 'SKEY', {'name': 'x-all', 'role': 'admin', 'scope': {'type': 'all'}})
out['create_other_group'] = call('POST', '/api/apikeys', 'SKEY', {'name': 'x-dev', 'role': 'admin', 'scope': GROUPS('dev')})
out['create_wider'] = call('POST', '/api/apikeys', 'SKEY', {'name': 'x-wider', 'role': 'admin', 'scope': GROUPS('prod', 'dev')})
out['create_other_kind'] = call('POST', '/api/apikeys', 'SKEY', {'name': 'x-tags', 'role': 'admin', 'scope': {'type': 'tags', 'values': ['prod']}})
out['keys_made_by_refusals'] = len(keys()) - before_count
out['create_same'] = call('POST', '/api/apikeys', 'SKEY', {'name': 'same', 'role': 'viewer', 'scope': GROUPS('prod')})
out['same_scope'] = (keys().get((out['create_same'][1] or {}).get('id')) or {}).get('scope')

# ---- keys: rotating one and editing one that reaches more
out['rotate_wide'] = call('POST', '/api/apikeys/%s/rotate' % wide_id, 'SKEY', {})
out['wide_after'] = {'active': keys()[wide_id]['active'], 'rotated_to': keys()[wide_id].get('rotated_to'),
                     'copies': sum(1 for k in keys().values() if k['name'] == 'WIDE'), 'still_reads': reads('WIDE')}
out['rotate_inside'] = call('POST', '/api/apikeys/%s/rotate' % child_id, 'SKEY', {})
out['rename_viewer_key'] = call('PATCH', '/api/apikeys/' + viewer_id, 'SKEY', {'name': 'renamed'})
out['promote_viewer_key'] = call('PATCH', '/api/apikeys/' + viewer_id, 'SKEY', {'role': 'admin'})
out['viewer_key_after'] = {k: keys()[viewer_id].get(k) for k in ('name', 'role', 'scope')}

# ---- accounts
mk = lambda name, role: call('POST', '/api/users', 'SKEY', {'username': name, 'password': 'Start-%s-Passw0rd!1' % name, 'role': role})
out['user_viewer'] = mk('zed1', 'viewer')
out['user_every_host_role'] = mk('zed2', 'ro-all')
out['user_ops'] = mk('zed3', 'ops')
out['user_admin'] = mk('zed4', 'admin')
out['user_inside_role'] = mk('zed5', 'ro-prod')
out['users_made'] = sorted(u for u in get('USERS_FILE') if u.startswith('zed'))
out['move_to_ops'] = call('PATCH', '/api/users/vera', 'SKEY', {'role': 'ops'})
out['vera_after_refusal'] = get('USERS_FILE')['vera']['role']
out['move_inside'] = call('PATCH', '/api/users/vera', 'SKEY', {'role': 'ro-prod'})
out['vera_after_allowed'] = get('USERS_FILE')['vera']['role']

# ---- roles
role = lambda name, scope: call('POST', '/api/roles', 'SKEY', {'name': name, 'permissions': ['command'], 'scope': scope})
out['role_all'] = role('all-power', {'type': 'all'})
out['role_without_scope'] = call('POST', '/api/roles', 'SKEY', {'name': 'noscope', 'permissions': ['command']})
out['role_wider'] = role('wider', GROUPS('prod', 'dev'))
out['role_other_kind'] = role('bytag', {'type': 'tags', 'values': ['prod']})
out['role_inside'] = role('prod-ops', GROUPS('prod'))
out['put_role_to_all'] = call('PUT', '/api/roles/ro-prod', 'SKEY', {'permissions': [], 'scope': {'type': 'all'}})
out['ro_prod_after_refusal'] = [r for r in get('ROLES_FILE')['roles'] if r['name'] == 'ro-prod'][0]
out['put_role_inside'] = call('PUT', '/api/roles/ro-prod', 'SKEY', {'permissions': ['patch'], 'scope': GROUPS('prod')})
out['roles_after'] = sorted(r['name'] for r in get('ROLES_FILE')['roles'])

# ---- callers with no limit are not changed
other_id = add_key('SKEY2', 'svc2', scope=GROUPS('prod'))
out['session_widens_a_key'] = call('PATCH', '/api/apikeys/' + other_id, SESS['admin'], {'scope': {'type': 'all'}})
out['session_widened_reach'] = reads('SKEY2')
out['session_makes_an_unscoped_key'] = call('POST', '/api/apikeys', SESS['admin'], {'name': 'by-a-session', 'role': 'admin'})
out['unscoped_key_makes_a_key'] = call('POST', '/api/apikeys', 'WIDE', {'name': 'by-a-key', 'role': 'admin'})
out['unscoped_key_made'] = (keys().get((out['unscoped_key_makes_a_key'][1] or {}).get('id')) or {}).get('scope', 'none')
out['unscoped_key_makes_an_account'] = call('POST', '/api/users', 'WIDE', {'username': 'wide-user', 'password': 'Start-wide-Passw0rd!1', 'role': 'viewer'})
out['unscoped_key_makes_a_role'] = call('POST', '/api/roles', 'WIDE', {'name': 'wide-role', 'permissions': ['command'], 'scope': {'type': 'all'}})
out['unscoped_key_rotates_a_key'] = call('POST', '/api/apikeys/%s/rotate' % other_id, 'WIDE', {})[0]
add_key('ACME-KEY', 'acme-ci', tenant='acme')
out['tenant_key_makes_a_key'] = call('POST', '/api/apikeys', 'ACME-KEY', {'name': 'by-acme', 'role': 'admin'})[0]

# ---- the last step rotates its own key (the old secret stops working)
out['rotate_own'] = call('POST', '/api/apikeys/%s/rotate' % own_id, 'SKEY', {})
new_secret = (out['rotate_own'][1] or {}).get('key')
out['rotated_scope'] = (keys().get((out['rotate_own'][1] or {}).get('id')) or {}).get('scope')
out['rotated_reach'] = reads(new_secret)
'''

_PURE = r'''
import itertools
# the same strings name a group, a tag and a site, so a comparison that forgets which kind it holds is wrong for some pair
GROUPS, TAGS, SITES = ['a', 'b', 'c'], ['a', 'b'], ['a', 'b']
devices = [{'group': g, 'tags': list(t), 'site': s}
           for g in GROUPS + [''] for t in ([], ['a'], ['b'], ['a', 'b']) for s in SITES + ['']]
subsets = lambda vals: [list(c) for n in range(1, len(vals) + 1) for c in itertools.combinations(vals, n)]
base = ([{'type': 'groups', 'values': v} for v in subsets(GROUPS)] + [{'type': 'tags', 'values': v} for v in subsets(TAGS)]
        + [{'type': 'sites', 'values': v} for v in subsets(SITES)])
scopes = [None, {'type': 'all'}] + base + [{'type': 'all_of', 'scopes': [a, b]} for a in base for b in base]
adm = [frozenset(i for i, d in enumerate(devices) if api._device_in_scope(s, d)) for s in scopes]
unsound, mismatch, said_inside, truly_inside = [], [], 0, 0
for i, a in enumerate(scopes):
    for j, b in enumerate(scopes):
        inside = api._scope_within(a, b)
        truly = adm[i] <= adm[j]
        said_inside += bool(inside)
        truly_inside += bool(truly)
        if inside and not truly:
            unsound.append([a, b])
        kind = lambda s: s.get('type') if isinstance(s, dict) else None
        if kind(a) == kind(b) and kind(a) in ('groups', 'tags', 'sites') and inside != truly:
            mismatch.append([a, b])
out['scopes'] = len(scopes)
out['pairs'] = len(scopes) ** 2
out['said_inside'] = said_inside
out['truly_inside'] = truly_inside
out['unsound'] = unsound[:3]
out['same_kind_mismatch'] = mismatch[:3]
P = {'type': 'groups', 'values': ['prod']}
w = api._scope_within
out['edge'] = {
    'prod_in_none': w(P, None), 'prod_in_all': w(P, {'type': 'all'}), 'none_in_prod': w(None, P), 'all_in_prod': w({'type': 'all'}, P),
    'string_values': w({'type': 'groups', 'values': 'prod'}, P), 'no_values': w({'type': 'groups'}, P), 'non_dict': w('x', P),
    'outer_non_dict': w(P, 'x'), 'smart_same': w({'type': 'groups', 'values': ['smart:web']}, {'type': 'groups', 'values': ['smart:web']}),
    'smart_vs_plain': w({'type': 'groups', 'values': ['smart:web']}, P), 'non_str_values': w({'type': 'groups', 'values': [1, None]}, P),
    'unknown_type': w({'type': 'bogus', 'values': ['x']}, P),
    'part_of_outer_composite_only': w(P, {'type': 'all_of', 'scopes': [P, {'type': 'tags', 'values': ['web']}]}),
    'composite_inner_one_part': w({'type': 'all_of', 'scopes': [P, {'type': 'tags', 'values': ['web']}]}, P),
}
'''


class TestTheConfinementOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('flask is not installed')
        cls.out = real_stack.run(_DRIVER)

    def refused(self, name):
        st, body = self.out[name]
        self.assertEqual((st, (body or {}).get('code')), (403, 'beyond_key_scope'), (name, st, body))

    def test_the_control_the_key_is_limited_and_the_wide_one_is_not(self):
        self.assertEqual(self.out['control_reach'], [200, 403], 'a key limited to prod reads a prod host and not a dev host')
        self.assertEqual(self.out['wide_reach'], [200, 200])

    def test_a_key_cannot_widen_or_clear_its_own_scope(self):
        for name in ('patch_own_to_all', 'patch_own_to_null', 'patch_own_wider', 'patch_own_other_kind'):
            with self.subTest(attempt=name):
                self.refused(name)
        self.assertEqual(self.out['own_scope_after_refusals'], {'type': 'groups', 'values': ['prod']})
        self.assertEqual(self.out['reach_after_refusals'], [200, 403], 'the confinement held')

    def test_a_key_can_still_edit_its_own_record_inside_its_part(self):
        self.assertEqual(self.out['patch_own_name'], [200, {'ok': True}])
        self.assertEqual(self.out['patch_own_same_scope'], [200, {'ok': True}])
        self.assertEqual(self.out['own_after_allowed'], {'name': 'renamed', 'scope': {'type': 'groups', 'values': ['prod']}})

    def test_a_key_that_asks_for_no_scope_makes_a_key_with_its_own_part(self):
        """What it asked for was an administrator key, and it got one that reaches what it does: not refused, and not wider."""
        st, body = self.out['create_no_scope']
        self.assertEqual(st, 201, body)
        self.assertEqual(self.out['child_scope'], {'type': 'groups', 'values': ['prod']})
        self.assertEqual(self.out['child_reach'], [200, 403], 'the key it made reads inside the part and not outside it')

    def test_a_key_cannot_make_a_key_that_reaches_more(self):
        for name in ('create_all', 'create_other_group', 'create_wider', 'create_other_kind'):
            with self.subTest(attempt=name):
                self.refused(name)
        self.assertEqual(self.out['keys_made_by_refusals'], 0, 'a refused request made a key')

    def test_a_key_can_make_a_key_inside_its_part(self):
        self.assertEqual(self.out['create_same'][0], 201)
        self.assertEqual(self.out['same_scope'], {'type': 'groups', 'values': ['prod']})

    def test_a_key_cannot_rotate_a_key_that_reaches_more_and_so_cannot_be_handed_its_secret(self):
        self.refused('rotate_wide')
        after = self.out['wide_after']
        self.assertEqual((after['active'], after['rotated_to'], after['copies']), (True, None, 1), 'the wide key was rotated or copied')
        self.assertEqual(after['still_reads'], [200, 200])

    def test_a_key_rotates_keys_inside_its_part_and_its_own(self):
        st, body = self.out['rotate_inside']
        self.assertEqual(st, 201, body)
        self.assertEqual(self.out['rotate_own'][0], 201)
        self.assertEqual(self.out['rotated_scope'], {'type': 'groups', 'values': ['prod']})
        self.assertEqual(self.out['rotated_reach'], [200, 403], 'the replacement of the key carries the scope')

    def test_a_key_cannot_change_a_key_that_reaches_more(self):
        """Not renamed, and not promoted to administrator: the key that comes out would still reach more than the caller."""
        self.refused('rename_viewer_key')
        self.refused('promote_viewer_key')
        self.assertEqual(self.out['viewer_key_after'], {'name': 'VIEWKEY', 'role': 'viewer', 'scope': None})

    def test_a_key_cannot_make_an_account_that_reaches_more(self):
        for name in ('user_viewer', 'user_every_host_role', 'user_ops'):
            with self.subTest(role=name):
                self.refused(name)
        st, body = self.out['user_admin']
        self.assertEqual((st, (body or {}).get('code')), (403, 'step_up_required'), 'an administrator account is still the step-up of a key that cannot')

    def test_a_key_can_make_an_account_with_a_role_inside_its_part(self):
        self.assertEqual(self.out['user_inside_role'][0], 201)
        self.assertEqual(self.out['users_made'], ['zed5'], 'only the account inside the part was made')

    def test_a_key_cannot_move_an_account_to_a_role_that_reaches_more_but_can_move_one_inside(self):
        self.refused('move_to_ops')
        self.assertEqual(self.out['vera_after_refusal'], 'viewer')
        self.assertEqual(self.out['move_inside'][0], 200)
        self.assertEqual(self.out['vera_after_allowed'], 'ro-prod')

    def test_a_key_cannot_make_or_widen_a_role_past_its_part(self):
        for name in ('role_all', 'role_without_scope', 'role_wider', 'role_other_kind', 'put_role_to_all'):
            with self.subTest(attempt=name):
                self.refused(name)
        self.assertEqual(self.out['ro_prod_after_refusal']['scope'], {'type': 'groups', 'values': ['prod']})

    def test_a_key_makes_and_edits_roles_inside_its_part(self):
        self.assertEqual(self.out['role_inside'][0], 200)
        self.assertEqual(self.out['put_role_inside'][0], 200)
        names = self.out['roles_after']
        self.assertIn('prod-ops', names)
        for refused in ('all-power', 'noscope', 'wider', 'bytag'):
            self.assertNotIn(refused, names, 'a refused request made the role ' + refused)

    def test_a_session_and_a_key_with_no_scope_are_not_changed(self):
        self.assertEqual(self.out['session_widens_a_key'], [200, {'ok': True}])
        self.assertEqual(self.out['session_widened_reach'], [200, 200], 'a person widens a key as before')
        self.assertEqual(self.out['session_makes_an_unscoped_key'][0], 201)
        self.assertEqual(self.out['unscoped_key_makes_a_key'][0], 201)
        self.assertEqual(self.out['unscoped_key_made'], 'none', 'a key with no scope makes keys with none, as before')
        self.assertEqual(self.out['unscoped_key_makes_an_account'][0], 201)
        self.assertEqual(self.out['unscoped_key_makes_a_role'][0], 200)
        self.assertEqual(self.out['unscoped_key_rotates_a_key'], 201)
        self.assertEqual(self.out['tenant_key_makes_a_key'], 201)


class TestTheComparison(unittest.TestCase):
    """`_scope_within(inner, outer)`: is everything `inner` admits admitted by `outer`. It is the whole of the rule, so it is checked against
    the real admission test (`_device_in_scope`) over every pair of a small fleet's scopes, not against a table written by hand."""

    @classmethod
    def setUpClass(cls):
        cls.out = real_stack.run(_PURE)

    def test_the_instrument_sees_something(self):
        """Controls: it compared every pair, and both answers occur, so a function that always said yes (or no) would be caught."""
        self.assertEqual((self.out['scopes'], self.out['pairs']), (184, 33856))
        self.assertGreater(self.out['said_inside'], 1000)
        self.assertGreater(self.out['pairs'] - self.out['truly_inside'], 10000, 'most pairs are not inside one another')

    def test_nothing_it_calls_inside_is_outside(self):
        self.assertEqual(self.out['unsound'], [], 'a scope called inside another admits a host the other does not')

    def test_for_two_scopes_of_one_kind_it_is_exact(self):
        self.assertEqual(self.out['same_kind_mismatch'], [])

    def test_the_edges(self):
        e = self.out['edge']
        self.assertEqual({k: e[k] for k in ('prod_in_none', 'prod_in_all', 'outer_non_dict')}, {'prod_in_none': True, 'prod_in_all': True, 'outer_non_dict': True},
                         'a scope inside no limit')
        for k in ('none_in_prod', 'all_in_prod', 'non_dict', 'unknown_type', 'smart_vs_plain', 'part_of_outer_composite_only'):
            self.assertFalse(e[k], k)
        for k in ('smart_same', 'no_values', 'non_str_values', 'composite_inner_one_part'):
            self.assertTrue(e[k], k)
        self.assertFalse(e['string_values'], 'a stored scope whose values are not a list is not known to be inside anything')


# ── the class ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

_COMPARES = {'_refuse_beyond_caller_scope', '_refuse_beyond_scope', '_bound_key_scope', '_scope_within'}
_BOUND = ('handle_apikeys_create', 'handle_apikeys_update', 'handle_apikeys_rotate', 'handle_role_create', 'handle_role_update',
          'handle_user_create', 'handle_user_update')
# The writers that give nothing out, each with the reason.
_GIVES_NOTHING_OUT = {
    'handle_apikeys_delete': 'removes a key',
    'handle_role_delete': 'removes a role (and refuses while an account holds it)',
    '_migrate_legacy_apikey': 'stores the hash of a key at its first use, which makes and changes no key',
    'verify_token': 'checks a token; the migration above is nested in it',
    '_purge_old_data': 'retention: removes keys long past their expiry',
}


class TestEveryWriterOfAccessComparesOrGivesNothingOut(unittest.TestCase):

    @staticmethod
    def population():
        found = set(credential_scan.store_writers('APIKEYS_FILE', 'ROLES_FILE'))
        found |= {name for name, calls in credential_scan.users_store_writers_of_credentials().items() if 'require_admin_auth' in calls}
        return found

    def test_every_member_is_accounted_for_and_the_listed_ones_still_write(self):
        found = self.population()
        self.assertGreaterEqual(len(found), 10, 'the scan sees nothing: %s' % sorted(found))
        for name in _BOUND:
            self.assertIn(name, found, 'the scan no longer sees %s, which it must (the control of this scan)' % name)
        unaccounted = sorted(n for n in found if n not in _BOUND and n not in _GIVES_NOTHING_OUT)
        self.assertEqual(unaccounted, [], 'a function now writes keys, roles or the role of an account and neither compares with the caller\'s scope nor is listed: %s' % unaccounted)
        stale = sorted(n for n in _GIVES_NOTHING_OUT if n not in found)
        self.assertEqual(stale, [], 'listed, but no longer writes keys or roles: %s' % stale)

    def test_the_ones_that_give_access_out_compare_with_the_callers_scope(self):
        writers = {**credential_scan.store_writers('APIKEYS_FILE', 'ROLES_FILE'), **credential_scan.users_store_writers_of_credentials()}
        for name in _BOUND:
            with self.subTest(handler=name):
                self.assertTrue(_COMPARES & writers[name], '%s writes access and never compares with the caller\'s scope' % name)

    def test_no_function_writes_the_keys_without_the_lock(self):
        """The routes that write keys read the store, change it and write it back. Delete and rotate took the keys' lock in 7.0.2 and create
        and update did not, so a key made at the same moment as another was lost. Every writer holds it now."""
        self.assertGreaterEqual(len(credential_scan.store_writers('APIKEYS_FILE')), 6, 'control: the scan sees the writers of the keys')
        self.assertEqual(credential_scan.bare_saves('APIKEYS_FILE'), [])

    def test_the_list_of_those_that_give_nothing_out_is_not_a_way_round_the_rule(self):
        writers = credential_scan.store_writers('APIKEYS_FILE', 'ROLES_FILE')
        for name in _GIVES_NOTHING_OUT:
            with self.subTest(function=name):
                self.assertFalse(_COMPARES & writers[name], '%s compares already: it belongs with the ones that do' % name)


if __name__ == '__main__':
    unittest.main()
