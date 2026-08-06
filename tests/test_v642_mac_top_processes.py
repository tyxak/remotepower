"""v6.4.2 (parity): the macOS agent now sends top_processes + proc_names.

macOS was the only agent not sending them (Linux/Windows both do), so every
Mac's server-side `process` custom-check returned 'unknown' and the
Top-Processes drawer/fleet view rendered empty. psutil is already imported on
the mac agent, so it is fully portable — the exact repeat of the v6.2.0 Windows
fix.
"""

import ast
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAC = ROOT / "client" / "remotepower-agent-mac.py"


class TestMacTopProcesses(unittest.TestCase):
    def test_get_top_processes_yields_the_shared_shape(self):
        spec = importlib.util.spec_from_file_location("rpmac_tp", MAC)
        mac = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mac)
        except SystemExit:
            pass
        top, names = mac.get_top_processes(limit=5)
        self.assertTrue(top, "no processes returned")
        self.assertEqual(set(top[0]), {"pid", "name", "cpu", "mem"})
        self.assertIsInstance(names, list)

    def test_collect_sysinfo_sets_both_keys(self):
        """Source-level: the collector is CALLED inside collect_sysinfo and its
        results stored — not merely defined (a defined-but-uncalled collector is
        the dead-feature class)."""
        src = MAC.read_text()
        self.assertIn("info['top_processes'] = _top", src)
        self.assertIn("info['proc_names'] = _names", src)
        self.assertIn("get_top_processes()", src)

    def test_the_call_is_after_info_is_assigned(self):
        """The documented UnboundLocalError trap: a collector referencing `info`
        before `info = {...}` dies under the try and ships the field dead."""
        src = MAC.read_text()
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "collect_sysinfo")
        info_assign_line = min(
            n.targets[0].lineno for n in ast.walk(fn)
            if isinstance(n, ast.Assign) and n.targets
            and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "info")
        call_line = next(n.lineno for n in ast.walk(fn)
                         if isinstance(n, ast.Call)
                         and isinstance(n.func, ast.Name)
                         and n.func.id == "get_top_processes")
        self.assertGreater(call_line, info_assign_line)


if __name__ == "__main__":
    unittest.main()
