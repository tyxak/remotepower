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


if __name__ == '__main__':
    unittest.main()
