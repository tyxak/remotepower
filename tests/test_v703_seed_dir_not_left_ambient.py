#!/usr/bin/env python3
"""A seeded fixture directory must not stay the ambient RP_DATA_DIR.

431 test modules pin their data dir with `os.environ.setdefault('RP_DATA_DIR',
tempfile.mkdtemp())`, which is the documented pattern — api.py writes at import
and must never target `/var/lib/remotepower`. 103 modules ASSIGN it instead. For
a module that assigns a fresh empty temp dir, both are harmless.

It is not harmless when the directory is a SEEDED FIXTURE. pytest and unittest
discover import every module before running a single test, so whichever module
assigned RP_DATA_DIR last hands its directory to every module imported after it.
Those modules then write devices, configs and alerts into the fixture the
assertions read back.

`test_v702_seeder_contracts.py` did exactly that, and
`test_every_reported_custom_check_result_names_a_defined_check` found zero
reported results in one selection and all of them in another — a real
order-dependent failure that looked like a seeder bug.

The rule this file holds: a module that runs the demo seeder at import time must
put RP_DATA_DIR back after api.py has captured its paths. The seeded dir stays
correct for that module (its `*_FILE` globals are already bound) and stops being
everyone else's scratch space.
"""
import ast
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent

# Anything that shells out to the demo seeder is building a fixture directory.
_SEEDER_MARKERS = ('seed-demo-data.py', '_SEEDER')


def _module_source(path):
    try:
        return path.read_text(encoding='utf-8')
    except OSError:                                        # pragma: no cover
        return ''


def _assigns_data_dir_at_module_scope(tree):
    """`os.environ['RP_DATA_DIR'] = …` at module level (not setdefault)."""
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (isinstance(target, ast.Subscript)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == 'RP_DATA_DIR'):
                return True
    return False


def _restores_data_dir(src):
    """Puts the previous value back, either branch of it."""
    return ("os.environ.pop('RP_DATA_DIR'" in src
            or 'os.environ.pop("RP_DATA_DIR"' in src)


def seeding_modules():
    """Test modules that run the demo seeder at import time."""
    out = []
    for path in sorted(_TESTS.glob('test_*.py')):
        src = _module_source(path)
        if not any(m in src for m in _SEEDER_MARKERS):
            continue
        # Only import-time seeding matters: a seeder run inside a test method
        # happens after every module is imported.
        try:
            tree = ast.parse(src)
        except SyntaxError:                                # pragma: no cover
            continue
        if 'subprocess.run' not in ast.unparse(ast.Module(body=tree.body,
                                                          type_ignores=[])):
            continue
        out.append((path.name, src, tree))
    return out


class TestNoSeededFixtureIsLeftAmbient(unittest.TestCase):

    def test_every_import_time_seeder_restores_the_data_dir(self):
        offenders = []
        for name, src, tree in seeding_modules():
            if _assigns_data_dir_at_module_scope(tree) and not _restores_data_dir(src):
                offenders.append(name)
        self.assertEqual(
            offenders, [],
            "these modules seed a fixture directory and leave it as the "
            "ambient RP_DATA_DIR, so every module imported after them writes "
            "into the fixture: " + str(offenders))

    def test_the_population_is_not_empty(self):
        """The control. If the seeder-module detection breaks, the check above
        passes while looking at nothing — the failure mode this whole class of
        test exists to close."""
        names = [n for n, _s, _t in seeding_modules()]
        self.assertGreaterEqual(
            len(names), 1,
            'no import-time seeding module found; the detector is broken')
        self.assertIn('test_v702_seeder_contracts.py', names)

    def test_the_detectors_recognise_both_idioms(self):
        """Controls for the two predicates, so neither can go blind."""
        assigns = ast.parse("import os\nos.environ['RP_DATA_DIR'] = '/x'\n")
        setdefaults = ast.parse(
            "import os\nos.environ.setdefault('RP_DATA_DIR', '/x')\n")
        self.assertTrue(_assigns_data_dir_at_module_scope(assigns))
        self.assertFalse(_assigns_data_dir_at_module_scope(setdefaults))
        self.assertTrue(_restores_data_dir("os.environ.pop('RP_DATA_DIR', None)"))
        self.assertFalse(_restores_data_dir("os.environ['RP_DATA_DIR'] = d"))


if __name__ == '__main__':
    unittest.main()
