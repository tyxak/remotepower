#!/usr/bin/env python3
"""A key with a host scope cannot change the smart group that its own scope names.

A scope can name a smart group (`smart:webs`): the hosts that a saved set of rules matches right now. The name stands for a predicate that
anyone who may edit the group can change, so a key whose scope names a smart group could PATCH the rules of that group to match every
monitored host, and its scope then admitted the whole fleet: it read the hosts it had been refused a moment before. Driven on the real
stack before it was closed:

    key scope groups [smart:webs]        reads web1 (200), db1 (403)
    PATCH /api/smart-groups/webs {rules: {monitored: true}}   -> 200
    the same key                         reads web1 (200), db1 (200)

Deleting the group and making it again, or making it when it does not exist yet, reaches the same place. What this holds, with real keys and
sessions through the real route table in a process of its own:

* the three routes that write a smart group (create, change the rules, delete) refuse a key whose scope names that group (403,
  `beyond_key_scope`), in whatever spelling the routes read as the same name, the group is as it was, and the key reads exactly what it read
  before; with the group gone, the key's scope matches nothing and not everything;
* a group that the key's scope does not name is the key's to make, edit and delete as before (8.0.2 gave such a key those routes on purpose,
  and narrows what it reads of the members), and a key can still list the groups, read the members it can see and preview a set of rules;
* a key with no scope and a signed-in administrator make, change and delete smart groups as before, and a key whose group a person widened
  reads what the group now matches, as it always did;
* `_scope_names_smart_group` reads the shapes a scope has (a scope of groups, one part of a composite, a spelling that differs in case or
  punctuation) and nothing else;
* the class: every function that writes the smart groups is listed by syntax tree, and each either refuses a caller whose scope names the
  group or is on the list of those that run with no caller (the cadence that works out the members).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import credential_scan  # noqa: E402
import real_stack  # noqa: E402

_DRIVER = r'''
SMART = {'type': 'groups', 'values': ['smart:webs']}
add_key('SMARTKEY', 'svc', scope=SMART)              # an administrator key whose scope names the smart group webs
add_key('WIDE', 'boss')                               # an administrator key with no scope
reads = lambda: [call('GET', '/api/devices/%s/sysinfo' % h, 'SMARTKEY')[0] for h in ('web1', 'db1')]
code = lambda r: (r[1] or {}).get('code')
rules = lambda name='webs': (get('SMART_GROUPS_FILE').get(name) or {}).get('rules')

out['create_by_person'] = call('POST', '/api/smart-groups', SESS['admin'], {'name': 'webs', 'rules': {'group': 'prod'}})[0]
out['control_reach'] = reads()                        # web1 is in the group prod, db1 is not

# the key tries to change the group its scope names
r = call('PATCH', '/api/smart-groups/webs', 'SMARTKEY', {'rules': {'monitored': True}})
out['patch_by_key'] = [r[0], code(r)]
out['rules_after_patch'] = rules()
out['reach_after_patch'] = reads()
r = call('DELETE', '/api/smart-groups/webs', 'SMARTKEY')
out['delete_by_key'] = [r[0], code(r)]
out['group_after_delete'] = rules()

# the group goes, and the key makes it again wide, in the spellings the routes read as the same name
out['delete_by_person_first'] = call('DELETE', '/api/smart-groups/webs', SESS['admin'])[0]
out['reach_with_the_group_gone'] = reads()            # a scope that names no group matches nothing
out['recreate_by_key'] = {}
for spelling in ('webs', ' Webs', 'WEBS!'):
    r = call('POST', '/api/smart-groups', 'SMARTKEY', {'name': spelling, 'rules': {'monitored': True}})
    out['recreate_by_key'][spelling] = [r[0], code(r)]
out['webs_exists_after_the_attempts'] = rules() is not None
out['reach_after_the_attempts'] = reads()
out['recreate_by_person'] = call('POST', '/api/smart-groups', SESS['admin'], {'name': 'webs', 'rules': {'group': 'prod'}})[0]

# a group its scope does not name is its own to make, edit and delete
r = call('POST', '/api/smart-groups', 'SMARTKEY', {'name': 'everything', 'rules': {'monitored': True}})
out['create_other_by_key'] = [r[0], code(r)]
out['patch_other_by_key'] = call('PATCH', '/api/smart-groups/everything', 'SMARTKEY', {'rules': {'group': 'dev'}})[0]
out['rules_of_the_other'] = rules('everything')
out['delete_other_by_key'] = call('DELETE', '/api/smart-groups/everything', 'SMARTKEY')[0]
out['reach_after_the_other'] = reads()                # its own group was never touched

# what the key may still do
out['list_by_key'] = call('GET', '/api/smart-groups', 'SMARTKEY')[0]
out['members_by_key'] = call('GET', '/api/smart-groups/webs/members', 'SMARTKEY')[0]
out['preview_by_key'] = call('POST', '/api/smart-groups/preview', 'SMARTKEY', {'rules': {'monitored': True}})[0]

# a key with no scope, and a person, are not changed
out['create_by_wide_key'] = call('POST', '/api/smart-groups', 'WIDE', {'name': 'wide', 'rules': {'group': 'dev'}})[0]
out['patch_by_wide_key'] = call('PATCH', '/api/smart-groups/wide', 'WIDE', {'rules': {'group': 'prod'}})[0]
out['rules_after_wide_patch'] = rules('wide')
out['delete_by_wide_key'] = call('DELETE', '/api/smart-groups/wide', 'WIDE')[0]
out['patch_by_person'] = call('PATCH', '/api/smart-groups/webs', SESS['admin'], {'rules': {'monitored': True}})[0]
out['reach_after_person_widens'] = reads()            # the group is wider now, so the key reads what it matches
out['delete_by_person'] = call('DELETE', '/api/smart-groups/webs', SESS['admin'])[0]
'''

_PURE = r'''
G = lambda *v: {'type': 'groups', 'values': list(v)}
n = api._scope_names_smart_group
out['names'] = {
    'plain': n(G('smart:web'), 'web'), 'among_others': n(G('prod', 'smart:web', 'dev'), 'web'), 'other_group': n(G('smart:web'), 'db'),
    'a_plain_group_of_that_name': n(G('web'), 'web'), 'upper_case': n(G('Smart:Web'), 'web'), 'punctuation': n(G('smart:web!'), 'web'),
    'a_longer_name': n(G('smart:webs'), 'web'), 'tags_scope': n({'type': 'tags', 'values': ['smart:web']}, 'web'),
    'sites_scope': n({'type': 'sites', 'values': ['smart:web']}, 'web'),
    'composite_one_part': n({'type': 'all_of', 'scopes': [G('prod'), G('smart:web')]}, 'web'),
    'composite_no_part': n({'type': 'all_of', 'scopes': [G('prod'), G('dev')]}, 'web'),
    'none': n(None, 'web'), 'a_string': n('smart:web', 'web'), 'values_a_string': n({'type': 'groups', 'values': 'smart:web'}, 'web'),
    'a_value_that_is_not_text': n(G(5, None), 'web'), 'no_values': n({'type': 'groups'}, 'web'),
}
'''


class TestAKeyCannotChangeWhatItsOwnScopeNames(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('flask is not installed')
        cls.out = real_stack.run(_DRIVER)

    def test_the_control_the_key_reads_the_group_and_not_the_other_host(self):
        self.assertEqual(self.out['create_by_person'], 201)
        self.assertEqual(self.out['control_reach'], [200, 403])

    def test_the_key_cannot_change_the_rules_of_its_group(self):
        self.assertEqual(self.out['patch_by_key'], [403, 'beyond_key_scope'])
        self.assertEqual(self.out['rules_after_patch'], {'group': 'prod'}, 'the refused change was written')
        self.assertEqual(self.out['reach_after_patch'], [200, 403], 'the key reads the host outside its scope')

    def test_the_key_cannot_delete_its_group(self):
        self.assertEqual(self.out['delete_by_key'], [403, 'beyond_key_scope'])
        self.assertEqual(self.out['group_after_delete'], {'group': 'prod'}, 'the refused delete removed the group')

    def test_the_key_cannot_make_its_group_again_in_any_spelling(self):
        self.assertEqual(self.out['delete_by_person_first'], 200)
        self.assertEqual(self.out['reach_with_the_group_gone'], [403, 403], 'a scope that names no group matches nothing')
        self.assertEqual(sorted(self.out['recreate_by_key']), sorted(['webs', ' Webs', 'WEBS!']))
        for spelling, answer in self.out['recreate_by_key'].items():
            with self.subTest(spelling=spelling):
                self.assertEqual(answer, [403, 'beyond_key_scope'])
        self.assertFalse(self.out['webs_exists_after_the_attempts'], 'a refused create made the group')
        self.assertEqual(self.out['reach_after_the_attempts'], [403, 403])
        self.assertEqual(self.out['recreate_by_person'], 201)

    def test_a_group_the_scope_does_not_name_is_the_keys_to_make_edit_and_delete(self):
        self.assertEqual(self.out['create_other_by_key'], [201, None])
        self.assertEqual(self.out['patch_other_by_key'], 200)
        self.assertEqual(self.out['rules_of_the_other'], {'group': 'dev'})
        self.assertEqual(self.out['delete_other_by_key'], 200)
        self.assertEqual(self.out['reach_after_the_other'], [200, 403], 'its own group was not touched')

    def test_the_key_can_still_list_read_and_preview(self):
        for name in ('list_by_key', 'members_by_key', 'preview_by_key'):
            with self.subTest(route=name):
                self.assertEqual(self.out[name], 200)

    def test_a_key_with_no_scope_and_a_person_are_not_changed(self):
        self.assertEqual(self.out['create_by_wide_key'], 201)
        self.assertEqual(self.out['patch_by_wide_key'], 200)
        self.assertEqual(self.out['rules_after_wide_patch'], {'group': 'prod'})
        self.assertEqual(self.out['delete_by_wide_key'], 200)
        self.assertEqual(self.out['patch_by_person'], 200)
        self.assertEqual(self.out['reach_after_person_widens'], [200, 200], 'a person widened the group, and the key reads what it now matches')
        self.assertEqual(self.out['delete_by_person'], 200)


class TestWhichScopesNameAGroup(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.out = real_stack.run(_PURE)

    def test_the_shapes(self):
        n = self.out['names']
        for name in ('plain', 'among_others', 'upper_case', 'punctuation', 'composite_one_part'):
            self.assertTrue(n[name], name)
        for name in ('other_group', 'a_plain_group_of_that_name', 'a_longer_name', 'tags_scope', 'sites_scope', 'composite_no_part', 'none', 'a_string',
                     'values_a_string', 'a_value_that_is_not_text', 'no_values'):
            self.assertFalse(n[name], name)


# ── the class ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

_REFUSES = {'_refuse_scope_naming_smart_group'}
_BOUND = ('handle_smart_groups', 'handle_smart_group')
_RUNS_WITH_NO_CALLER = {
    'run_smart_groups_if_due': 'the cadence that works out the members of every group from its rules; it changes no rule and runs with no caller',
}


class TestEveryWriterOfASmartGroupRefusesAScopedCallerOrRunsWithNone(unittest.TestCase):

    @staticmethod
    def population():
        return credential_scan.store_writers('SMART_GROUPS_FILE')

    def test_every_member_is_accounted_for_and_the_listed_ones_still_write(self):
        found = self.population()
        for name in _BOUND:
            self.assertIn(name, found, 'the scan no longer sees %s, which it must (the control of this scan)' % name)
        unaccounted = sorted(n for n in found if n not in _BOUND and n not in _RUNS_WITH_NO_CALLER)
        self.assertEqual(unaccounted, [], 'a function now writes the smart groups and neither refuses a caller whose scope names the group '
                                          'nor is listed: %s' % unaccounted)
        stale = sorted(n for n in _RUNS_WITH_NO_CALLER if n not in found)
        self.assertEqual(stale, [], 'listed, but no longer writes the smart groups: %s' % stale)

    def test_the_handlers_refuse_a_caller_whose_scope_names_the_group(self):
        found = self.population()
        for name in _BOUND:
            with self.subTest(handler=name):
                self.assertTrue(_REFUSES & found[name], '%s writes smart groups and never asks whether the caller\'s scope names the group' % name)

    def test_the_listed_ones_run_with_no_caller(self):
        found = self.population()
        for name in _RUNS_WITH_NO_CALLER:
            with self.subTest(function=name):
                self.assertFalse({'require_admin_auth', 'require_auth', 'require_perm'} & found[name], '%s checks a caller, so it answers a request' % name)
                self.assertFalse(_REFUSES & found[name], '%s refuses already: it belongs with the ones that do' % name)


if __name__ == '__main__':
    unittest.main()
