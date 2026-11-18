#!/usr/bin/env python3
"""A name defined twice at the top level of a program replaces its first definition for every caller, and nothing says so.

The Windows registry check defined `_reg_text(s)` and `_reg_number(v)` beside two older helpers of the same names that take a registry key and a value name
(`_reg_text(winreg, key, name)`). The later definitions won: the installed-software inventory, the Windows version and build, and the Windows Update source all called
the new ones with three arguments. The first two raised TypeError, and `_wu_source` swallowed it and answered "windows-update-agent" for a host that is told to use WSUS.
Every test of the registry check passed, `ruff --select F` passed (it counts a use inside a function body as a use of the first definition), and the module imported.

Two things hold the class here:

  * a ratchet at ceiling zero over every Python program the product ships (derived from the tree, not listed): no top-level function or class name appears twice;
  * the three callers that broke, driven with a fake `winreg` through the real functions, so that a rename that fixes the names but breaks a caller is seen too.
"""
import ast
import collections
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parent.parent
_ROOTS = ('server', 'client', 'mcp', 'tools', 'packaging')


def shipped_python():
    """Every Python program under the shipped directories: `*.py`, and the extensionless scripts that start with a python shebang."""
    found = []
    for top in _ROOTS:
        for p in sorted((_ROOT / top).rglob('*')):
            if not p.is_file() or '__pycache__' in p.parts:
                continue
            if p.suffix == '.py':
                found.append(p)
            elif p.suffix == '' and p.stat().st_size > 0:
                with open(p, 'rb') as f:
                    if f.read(64).startswith(b'#!/usr/bin/env python'):
                        found.append(p)
    return found


def names_defined_twice(source):
    """{name: [line, ...]} for the functions and classes that are direct children of the module and share a name. A definition under an `if` or a `try` (the alternatives
    a platform or an optional import chooses between) is not a direct child and is not counted."""
    seen = collections.defaultdict(list)
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            seen[node.name].append(node.lineno)
    return {k: v for k, v in seen.items() if len(v) > 1}


class TestNoNameIsDefinedTwice(unittest.TestCase):
    def test_the_population_is_the_tree_and_is_not_empty(self):
        files = shipped_python()
        self.assertGreater(len(files), 100, 'a derivation that finds nothing would pass for ever')
        rel = {str(p.relative_to(_ROOT)) for p in files}
        for must in ('client/remotepower-agent-win.py', 'client/remotepower-agent.py', 'client/remotepower-agent-mac.py', 'client/remotepower-agent',
                     'server/cgi-bin/api.py', 'server/cgi-bin/persistence.py'):
            self.assertIn(must, rel)

    def test_the_scanner_sees_a_name_defined_twice_and_leaves_alternatives_alone(self):
        self.assertEqual(names_defined_twice('def f(a):\n    pass\n\n\ndef g():\n    pass\n\n\ndef f(a, b, c):\n    pass\n'), {'f': [1, 9]})
        self.assertEqual(names_defined_twice('class A:\n    pass\n\n\ndef A():\n    pass\n'), {'A': [1, 5]})
        self.assertEqual(names_defined_twice('try:\n    import x\n    def f():\n        pass\nexcept ImportError:\n    def f():\n        pass\n'), {}, 'alternatives under try')
        self.assertEqual(names_defined_twice('import sys\nif sys.platform == "win32":\n    def f():\n        pass\nelse:\n    def f():\n        pass\n'), {}, 'alternatives under if')
        self.assertEqual(names_defined_twice('class A:\n    def m(self):\n        pass\n\n    def m(self, x):\n        pass\n'), {}, 'a method is not a module-level name')

    def test_no_shipped_program_defines_a_name_twice(self):
        found = {}
        for p in shipped_python():
            dups = names_defined_twice(p.read_text(encoding='utf-8'))
            if dups:
                found[str(p.relative_to(_ROOT))] = dups
        self.assertEqual(found, {}, 'a later definition replaces the first one for every caller; rename one of them (and check the callers of both)')


class FakeWinreg(types.ModuleType):
    """Enough of winreg for the three readers: keys with values and subkeys, the end-of-list error and the access constants."""
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_SZ, REG_DWORD = 0x80000002, 0x20019, 0x100, 1, 4
    UNINSTALL = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    NT = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
    WU = 'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate'

    def __init__(self):
        super().__init__('winreg')
        self.keys = {
            self.UNINSTALL: (['Chrome'], {}),
            self.UNINSTALL + '\\Chrome': ([], {'DisplayName': 'Google Chrome', 'DisplayVersion': '120.0.1', 'Publisher': 'Google LLC', 'InstallDate': '20260115'}),
            self.NT: ([], {'CurrentBuildNumber': '22631', 'UBR': 3007, 'DisplayVersion': '23H2', 'EditionID': 'Professional', 'ProductName': 'Windows 10 Pro',
                           'InstallationType': 'Client'}),
            self.WU: (['AU'], {'WUServer': 'http://wsus.example.test'}),
            self.WU + '\\AU': ([], {'UseWUServer': 1}),
        }

    def OpenKey(self, parent, path, reserved=0, access=0):
        full = path if parent == self.HKEY_LOCAL_MACHINE else parent[1] + '\\' + path
        if full not in self.keys:
            raise FileNotFoundError(2, 'The system cannot find the file specified')
        return ('key', full)

    def EnumKey(self, key, i):
        subs = self.keys[key[1]][0]
        if i >= len(subs):
            raise OSError(259, 'No more data is available')
        return subs[i]

    def QueryValueEx(self, key, name):
        values = self.keys[key[1]][1]
        if name not in values:
            raise FileNotFoundError(2, 'The system cannot find the file specified')
        v = values[name]
        return v, (self.REG_DWORD if isinstance(v, int) else self.REG_SZ)

    def CloseKey(self, key):
        pass


def load_agent():
    spec = importlib.util.spec_from_file_location('rp_win_agent_dupes', _ROOT / 'client' / 'remotepower-agent-win.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTheOlderRegistryReadersStillWork(unittest.TestCase):
    """The readers the registry check's helpers used to replace, through the real functions."""

    @classmethod
    def setUpClass(cls):
        cls.win = load_agent()

    def setUp(self):
        self.reg = FakeWinreg()
        patcher = mock.patch.dict(sys.modules, {'winreg': self.reg})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_installed_software_is_read_with_its_name_version_and_publisher(self):
        rows, skipped = self.win._read_uninstall_key(self.reg, FakeWinreg.UNINSTALL, 0, 'x64')
        self.assertEqual((rows, skipped), ([{'name': 'Google Chrome', 'version': '120.0.1', 'arch': 'x64', 'manager': 'windows', 'publisher': 'Google LLC', 'installed': rows[0].get('installed')}], 0))
        self.assertTrue(rows[0]['installed'], 'the install date is read too')

    def test_the_windows_version_is_read_with_its_build_and_update_revision(self):
        self.assertEqual(self.win.get_win_build(), {'build': '22631', 'ubr': 3007, 'display_version': '23H2', 'edition': 'Professional', 'product': 'Windows 10 Pro',
                                                    'installation_type': 'Client'})

    def test_a_host_told_to_use_wsus_says_so(self):
        self.assertEqual(self.win._wu_source(), 'wsus')
        self.reg.keys[FakeWinreg.WU + '\\AU'] = ([], {'UseWUServer': 0})
        self.assertEqual(self.win._wu_source(), 'windows-update-agent')

    def test_the_registry_checks_own_helpers_have_names_of_their_own(self):
        self.assertEqual(self.win._reg_report_text('a\x07b\u2028c'), 'a b c')
        self.assertEqual((self.win._reg_parse_number('0x10'), self.win._reg_parse_number('7'), self.win._reg_parse_number('x')), (16, 7, None))
        self.assertEqual(self.win._reg_text(self.reg, ('key', FakeWinreg.NT), 'EditionID'), 'Professional', 'the older helper that takes a key is still the one called _reg_text')
        self.assertEqual(self.win._reg_number(self.reg, ('key', FakeWinreg.NT), 'UBR'), 3007)


if __name__ == '__main__':
    unittest.main()
