#!/usr/bin/env python3
"""7.4.9: where the CPUs spent their time, on Windows and macOS.

The Linux agent reads /proc/stat and sends seven shares. The Windows and macOS agents have psutil, whose cpu_times_percent gives the
shares of the time since the previous call for the states the system has: user, system, idle, interrupt and dpc on Windows; user,
nice, system and idle on macOS. Neither system has an I/O wait or a steal state, so those two keys are left out (not sent as zeros,
which would say they were measured) and the server draws and judges only what it is sent.

psutil is replaced by an object with the namedtuple each platform returns, so the real collector runs against the real shapes. Not run
on a real Windows or macOS host.
"""
import collections
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
WinTimes = collections.namedtuple("scputimes", "user system idle interrupt dpc")
MacTimes = collections.namedtuple("scputimes", "user nice system idle")


def load(fname, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "client" / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fake_psutil(value=None, error=None):
    mod = types.ModuleType("psutil")
    mod.calls = 0

    def cpu_times_percent(interval=None, percpu=False):
        mod.calls += 1
        if error:
            raise error
        return value
    mod.cpu_times_percent = cpu_times_percent
    mod.cpu_percent = lambda interval=None: 5.0
    return mod


class _Both(unittest.TestCase):
    AGENT = ("remotepower-agent-win.py", "rp_win_ct")
    SHAPE = WinTimes

    @classmethod
    def setUpClass(cls):
        cls.agent = load(*cls.AGENT)

    def setUp(self):
        self.agent._cpu_time_last = None

    def read(self, value=None, error=None, at=1000.0, keep=False):
        """One reading. The baseline is forgotten first, so each read stands alone, unless `keep` is given: a loop that did not do this
        would be answered by the five-second rule after its first read and every later case would pass for the wrong reason."""
        if not keep:
            self.agent._cpu_time_last = None
        mod = fake_psutil(value, error)
        with mock.patch.dict(sys.modules, {"psutil": mod}), mock.patch.object(self.agent.time, "monotonic", return_value=at):
            out = self.agent.collect_cpu_time()
        return out, mod.calls


class TestWindows(_Both):
    AGENT = ("remotepower-agent-win.py", "rp_win_ct")

    def test_the_states_windows_has(self):
        got, _ = self.read(WinTimes(user=12.34, system=4.56, idle=80.0, interrupt=1.2, dpc=2.0))
        self.assertEqual(got, {"cpu_user": 12.3, "cpu_system": 4.6, "cpu_idle": 80.0, "cpu_irq": 3.2})

    def test_interrupts_and_dpc_are_one_share_and_the_states_it_lacks_are_not_sent(self):
        got, _ = self.read(WinTimes(10, 5, 80, 3, 2))
        self.assertEqual(got["cpu_irq"], 5.0, "interrupt time and deferred procedure calls together")
        for k in ("cpu_iowait", "cpu_steal", "cpu_nice"):
            self.assertNotIn(k, got, "windows has no such state: not sent, and not sent as zero")

    def test_a_dpc_alone_is_the_irq_share(self):
        got, _ = self.read(types.SimpleNamespace(user=10.0, system=5.0, idle=84.0, dpc=1.0))
        self.assertEqual(got["cpu_irq"], 1.0)

    def test_no_interrupt_states_at_all_is_no_irq_key(self):
        got, _ = self.read(types.SimpleNamespace(user=10.0, system=5.0, idle=85.0))
        self.assertEqual(sorted(got), ["cpu_idle", "cpu_system", "cpu_user"])


class TestMacOs(_Both):
    AGENT = ("remotepower-agent-mac.py", "rp_mac_ct")

    def test_the_states_macos_has(self):
        got, _ = self.read(MacTimes(user=10.04, nice=1.0, system=4.0, idle=84.96))
        self.assertEqual(got, {"cpu_user": 10.0, "cpu_nice": 1.0, "cpu_system": 4.0, "cpu_idle": 85.0})

    def test_the_states_it_lacks_are_not_sent(self):
        got, _ = self.read(MacTimes(10, 1, 4, 85))
        for k in ("cpu_iowait", "cpu_steal", "cpu_irq"):
            self.assertNotIn(k, got)


class _Shared:
    """The same cases for both agents: they carry the same function."""

    def good(self):
        return WinTimes(10, 5, 85, 0, 0) if self.AGENT[0].endswith("win.py") else MacTimes(10, 0, 5, 85)

    def test_psutil_missing_is_no_reading(self):
        with mock.patch.dict(sys.modules, {"psutil": None}):
            self.assertEqual(self.agent.collect_cpu_time(), {})

    def test_psutil_failing_is_no_reading(self):
        got, calls = self.read(error=OSError("no counters"))
        self.assertEqual((got, calls), ({}, 1))
        got, _ = self.read(error=RuntimeError("x"))
        self.assertEqual(got, {})

    def test_user_system_and_idle_are_needed(self):
        for missing in ("user", "system", "idle"):
            fields = {"user": 10.0, "system": 5.0, "idle": 85.0}
            fields.pop(missing)
            got, _ = self.read(types.SimpleNamespace(**fields))
            self.assertEqual(got, {}, missing)

    def test_a_share_that_is_not_a_number_in_range_is_no_reading_when_it_is_one_of_the_three(self):
        for bad in ("lots", None, True, -1, 101, [5], float("nan"), float("inf")):
            for field in ("user", "system", "idle"):
                fields = {"user": 10.0, "system": 5.0, "idle": 85.0}
                fields[field] = bad
                got, _ = self.read(types.SimpleNamespace(**fields))
                self.assertEqual(got, {}, (field, bad))

    def test_an_optional_share_that_is_bad_is_left_out_and_the_rest_is_kept(self):
        for bad in ("x", None, True, -1, 101, float("nan")):
            got, _ = self.read(types.SimpleNamespace(user=10.0, system=5.0, idle=85.0, nice=bad, interrupt=bad, dpc=bad))
            self.assertEqual(sorted(got), ["cpu_idle", "cpu_system", "cpu_user"], repr(bad))

    def test_a_reading_of_all_zeros_is_no_reading(self):
        """psutil keeps a baseline for each thread, so the first call from another one comes back empty."""
        got, _ = self.read(types.SimpleNamespace(user=0.0, system=0.0, idle=0.0))
        self.assertEqual(got, {})

    def test_the_first_call_after_the_start_has_an_interval(self):
        got, calls = self.read(self.good())
        self.assertEqual(calls, 1)
        self.assertIn("cpu_user", got)
        self.assertEqual(self.agent._cpu_time_last, 1000.0)

    def test_a_report_closer_than_five_seconds_is_left_to_the_next_and_does_not_reset_the_baseline(self):
        self.read(self.good(), at=1000.0)
        got, calls = self.read(self.good(), at=1003.0, keep=True)
        self.assertEqual((got, calls), ({}, 0), "psutil is not even asked, so its baseline stays")
        self.assertEqual(self.agent._cpu_time_last, 1000.0)
        got, calls = self.read(self.good(), at=1005.0, keep=True)
        self.assertEqual(calls, 1)
        self.assertIn("cpu_user", got)

    def test_a_share_is_never_above_a_hundred(self):
        got, _ = self.read(types.SimpleNamespace(user=60.0, system=30.0, idle=10.0, interrupt=60.0, dpc=50.0))
        self.assertLessEqual(got["cpu_irq"], 100.0)

    def test_the_reading_goes_into_the_system_information(self):
        import inspect
        src = inspect.getsource(self.agent.collect_sysinfo)
        self.assertIn("info.update(collect_cpu_time())", src)
        self.assertLess(src.index("cpu_percent"), src.index("collect_cpu_time"), "after psutil is known to be there")

    def test_the_baseline_is_taken_when_the_agent_starts(self):
        src = Path(ROOT / "client" / self.AGENT[0]).read_text()
        self.assertIn("_psutil_prime.cpu_times_percent(interval=None)", src)
        self.assertIn("_cpu_time_last = time.monotonic()", src)


class TestWindowsShared(_Shared, TestWindows):
    pass


class TestMacOsShared(_Shared, TestMacOs):
    pass


class TestTheServerTakesWhatTheyReport(unittest.TestCase):
    """The ingest keeps a share whichever agent sent it; nothing in it needs the Linux-only states."""

    def test_the_other_agents_keys_are_the_linux_agents_keys(self):
        linux = (ROOT / "client" / "remotepower-agent.py").read_text()
        for rel in ("remotepower-agent-win.py", "remotepower-agent-mac.py"):
            src = (ROOT / "client" / rel).read_text()
            for key in ("cpu_user", "cpu_system", "cpu_idle"):
                self.assertIn(f"'{key}'", src, f"{rel}: {key}")
                self.assertIn(f"'{key}'", linux)

    def test_the_agents_do_not_send_what_their_system_does_not_have(self):
        for rel in ("remotepower-agent-win.py", "remotepower-agent-mac.py"):
            src = (ROOT / "client" / rel).read_text()
            body = src[src.index("def collect_cpu_time"):src.index("# Prime the non-blocking CPU sampler")]
            self.assertNotIn("cpu_iowait", body, rel)
            self.assertNotIn("cpu_steal", body, rel)


if __name__ == "__main__":
    unittest.main()
