#!/usr/bin/env python3
"""tests/api_guard.py puts back what a module changed on the one `api` of the process: functions, paths, strings and flags, and nothing else."""
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api_guard  # noqa: E402


def a_module():
    m = types.ModuleType('fake_api')
    m.__file__ = '/repo/server/cgi-bin/api.py'      # a copy that was loaded from the file, as every real one is
    m.respond = lambda *a: 'real respond'
    m.USERS_FILE = Path('/data/users.json')
    m.LABEL = 'real'
    m.FLAG = True
    m.LOAD_CACHE = {'a': 1}
    m.COUNT = 3
    m.Boom = type('Boom', (Exception,), {})
    return m


class TestApiGuard(unittest.TestCase):

    def test_what_a_module_changed_is_put_back_and_it_says_what(self):
        api = a_module()
        real = api.respond
        api_guard.save('m', api)
        api.respond = lambda *a: 'a stub'
        api.USERS_FILE = Path('/tmp/elsewhere/users.json')
        api.LABEL = 'changed'
        api.FLAG = False
        self.assertEqual(sorted(api_guard.restore('m')), ['FLAG', 'LABEL', 'USERS_FILE', 'respond'])
        self.assertIs(api.respond, real)
        self.assertEqual((api.USERS_FILE, api.LABEL, api.FLAG), (Path('/data/users.json'), 'real', True))

    def test_what_did_not_change_is_not_touched_and_a_second_restore_does_nothing(self):
        api = a_module()
        api_guard.save('m', api)
        self.assertEqual(api_guard.restore('m'), [])
        self.assertEqual(api_guard.restore('m'), [], 'nothing is saved under the name any more')
        self.assertEqual(api_guard.restore('never saved'), [])

    def test_containers_numbers_and_classes_and_new_names_are_left_alone(self):
        api = a_module()
        cache, boom = api.LOAD_CACHE, api.Boom
        api_guard.save('m', api)
        api.LOAD_CACHE['b'] = 2
        api.COUNT = 99
        api.Boom = type('Other', (Exception,), {})
        api.NEW = 'added by the module'
        self.assertEqual(api_guard.restore('m'), [])
        self.assertIs(api.LOAD_CACHE, cache)
        self.assertEqual((api.COUNT, api.NEW), (99, 'added by the module'))
        self.assertIsNot(api.Boom, boom, 'a class is not put back: the guard is for functions, stores and flags')

    def test_a_flag_that_became_a_number_or_a_string_that_became_a_path_is_put_back(self):
        api = a_module()
        api_guard.save('m', api)
        api.FLAG = 1               # equal to True and not the same kind of value
        api.LABEL = Path('real')   # a path, not the string
        self.assertEqual(sorted(api_guard.restore('m')), ['FLAG', 'LABEL'])
        self.assertIs(api.FLAG, True)
        self.assertEqual(api.LABEL, 'real')
        self.assertIsInstance(api.LABEL, str)

    def test_a_name_that_was_deleted_comes_back(self):
        api = a_module()
        api_guard.save('m', api)
        del api.respond
        self.assertEqual(api_guard.restore('m'), ['respond'])
        self.assertEqual(api.respond(), 'real respond')

    def test_with_no_api_in_the_process_it_saves_nothing_and_does_not_fail(self):
        saved = sys.modules.pop('api', None)
        try:
            api_guard.save('m')
            self.assertEqual(api_guard.restore('m'), [])
        finally:
            if saved is not None:
                sys.modules['api'] = saved

    def test_two_modules_are_kept_apart_by_name(self):
        a, b = a_module(), a_module()
        api_guard.save('first', a)
        api_guard.save('second', b)
        a.LABEL = 'x'
        b.LABEL = 'y'
        self.assertEqual(api_guard.restore('second'), ['LABEL'])
        self.assertEqual((a.LABEL, b.LABEL), ('x', 'real'))
        self.assertEqual(api_guard.restore('first'), ['LABEL'])
        self.assertEqual(a.LABEL, 'real')


    def test_the_storage_module_of_the_process_is_guarded_with_api(self):
        fake_api, fake_storage = a_module(), types.ModuleType('storage')
        fake_storage.DATA_DIR = Path('/data')
        fake_storage._ATEXIT_REGISTERED = False
        had = {n: sys.modules.get(n) for n in ('api', 'storage')}
        sys.modules['api'], sys.modules['storage'] = fake_api, fake_storage
        try:
            api_guard.save('m')
            fake_api.LABEL = 'changed'
            fake_storage.DATA_DIR = Path('/tmp/another/dir')
            fake_storage._ATEXIT_REGISTERED = True
            self.assertEqual(sorted(api_guard.restore('m')), ['DATA_DIR', 'LABEL'])
            self.assertEqual((fake_api.LABEL, fake_storage.DATA_DIR), ('real', Path('/data')))
            self.assertIs(fake_storage._ATEXIT_REGISTERED, True, 'the flag that says the handler of atexit was registered is not cleared: it would be registered twice')
        finally:
            for n, m in had.items():
                if m is None:
                    sys.modules.pop(n, None)
                else:
                    sys.modules[n] = m


    # ── the copy that a module really uses ──────────────────────────────────────────────────────────────────────────────────

    def _with_modules(self, **entries):
        """Put fake modules into sys.modules for the length of one test; whatever was there is back afterwards."""
        had = {n: sys.modules.get(n, api_guard._MISSING) for n in entries}
        for n, m in entries.items():
            sys.modules[n] = m

        def undo():
            for n, m in had.items():
                if m is api_guard._MISSING:
                    sys.modules.pop(n, None)
                else:
                    sys.modules[n] = m
        self.addCleanup(undo)

    def test_the_copy_a_module_holds_is_guarded_when_sys_modules_names_another_copy(self):
        first, second = a_module(), a_module()
        holder = types.ModuleType('a_test_module_of_the_suite')
        holder.api = first                       # imported before `api` was loaded again: the test module keeps the first copy
        self._with_modules(api=second, a_test_module_of_the_suite=holder)
        api_guard.save('a_test_module_of_the_suite')
        first.USERS_FILE = Path('/tmp/the/module/moved/it/users.json')
        second.LABEL = 'changed too'
        self.assertEqual(sorted(api_guard.restore('a_test_module_of_the_suite')), ['LABEL', 'USERS_FILE'])
        self.assertEqual(first.USERS_FILE, Path('/data/users.json'), 'the copy the module used is the one that was left changed in the suite')
        self.assertEqual(second.LABEL, 'real')

    def test_the_copy_that_wsgi_holds_is_guarded_too(self):
        served = a_module()
        wsgi = types.ModuleType('wsgi')
        wsgi.api = served
        self._with_modules(wsgi=wsgi)
        api_guard.save('m')
        served.USERS_FILE = Path('/elsewhere/users.json')
        self.assertEqual(api_guard.restore('m'), ['USERS_FILE'])
        self.assertEqual(served.USERS_FILE, Path('/data/users.json'))

    def test_a_copy_under_a_name_of_its_own_is_found_by_its_file(self):
        copy = a_module()
        copy.__name__ = '_api_under_test'
        copy.__file__ = '/repo/server/cgi-bin/api.py'
        holder = types.ModuleType('a_test_module_of_the_suite')
        holder.A = copy                          # an alias, and not under the name `api`
        self._with_modules(a_test_module_of_the_suite=holder)
        api_guard.save('a_test_module_of_the_suite')
        copy.LABEL = 'changed'
        self.assertEqual(api_guard.restore('a_test_module_of_the_suite'), ['LABEL'])

    def test_a_module_that_is_not_a_copy_of_the_shared_ones_is_not_touched(self):
        other = types.ModuleType('something_else')
        other.LABEL = 'real'
        holder = types.ModuleType('a_test_module_of_the_suite')
        holder.other = other
        self._with_modules(a_test_module_of_the_suite=holder)
        api_guard.save('a_test_module_of_the_suite')
        other.LABEL = 'changed'
        self.assertEqual(api_guard.restore('a_test_module_of_the_suite'), [])
        self.assertEqual(other.LABEL, 'changed')

    def test_the_entries_of_sys_modules_that_a_reimport_replaced_are_put_back(self):
        before_api, before_storage = a_module(), types.ModuleType('storage')
        self._with_modules(api=before_api, storage=before_storage)
        api_guard.save('m')
        sys.modules['api'] = a_module()                       # `sys.modules.pop('api'); import api`: another copy under the name
        sys.modules.pop('storage')                            # taken out, and nothing imported it again yet
        self.assertEqual(sorted(api_guard.restore('m')), ["sys.modules['api']", "sys.modules['storage']"])
        self.assertIs(sys.modules['api'], before_api)
        self.assertIs(sys.modules['storage'], before_storage)

    def test_an_entry_that_was_not_there_is_taken_out_again(self):
        self._with_modules(api=a_module())
        had_storage = sys.modules.pop('storage', None)
        self.addCleanup(lambda: sys.modules.__setitem__('storage', had_storage) if had_storage is not None else None)
        api_guard.save('m')
        sys.modules['storage'] = types.ModuleType('storage')
        self.assertEqual(api_guard.restore('m'), ["sys.modules['storage']"])
        self.assertNotIn('storage', sys.modules)

    def test_the_rp_variables_are_put_back_and_no_other_variable_is(self):
        import os
        keep = {k: os.environ.get(k) for k in ('RP_A_TEST_ONLY', 'RP_B_TEST_ONLY', 'RP_C_TEST_ONLY', 'NOT_RP_TEST_ONLY')}

        def undo():
            for k, v in keep.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.addCleanup(undo)
        os.environ['RP_A_TEST_ONLY'] = 'one'
        os.environ['RP_B_TEST_ONLY'] = 'two'
        os.environ.pop('RP_C_TEST_ONLY', None)
        api_guard.save('m')
        os.environ['RP_A_TEST_ONLY'] = 'changed'              # a module that points RP_DATA_DIR at a directory of its own
        del os.environ['RP_B_TEST_ONLY']
        os.environ['RP_C_TEST_ONLY'] = 'added'
        os.environ['NOT_RP_TEST_ONLY'] = 'left'
        self.assertEqual(sorted(api_guard.restore('m')), ['$RP_A_TEST_ONLY', '$RP_B_TEST_ONLY', '$RP_C_TEST_ONLY'])
        self.assertEqual((os.environ['RP_A_TEST_ONLY'], os.environ['RP_B_TEST_ONLY']), ('one', 'two'))
        self.assertNotIn('RP_C_TEST_ONLY', os.environ)
        self.assertEqual(os.environ['NOT_RP_TEST_ONLY'], 'left')

    def test_a_module_given_by_the_caller_leaves_sys_modules_and_the_environment_alone(self):
        import os
        keep = os.environ.get('RP_A_TEST_ONLY')
        self.addCleanup(lambda: os.environ.pop('RP_A_TEST_ONLY', None) if keep is None else os.environ.__setitem__('RP_A_TEST_ONLY', keep))
        api = a_module()
        api_guard.save('m', api)
        os.environ['RP_A_TEST_ONLY'] = 'set by the test'
        self.assertEqual(api_guard.restore('m'), [])
        self.assertEqual(os.environ['RP_A_TEST_ONLY'], 'set by the test')


if __name__ == '__main__':
    unittest.main()
