#!/usr/bin/env python3
"""8.0.0: the browser harness parks the old heap before it starts a stack.

The suite runs in one process. By the time the browser modules come it holds millions of objects (14.6 million and 12 GB after 2,400 tests on the exact discover order, one full
collection 3.5 s, 90 pauses of more than 0.2 s, the longest 5 s), and the harness answers the browser from threads of that process: the static files and the proxy to gunicorn. A full
collection therefore stops every request for seconds, and a test that waits a second or two for an answer loses at random. The cron words test failed in two full runs, one of them a
real `make pre-release` on a quiet machine, and in no run of its module on its own; the same test, run inside that process with the answer held back, fails with the same message
whatever the machine is doing. `park_the_old_heap()` freezes what exists (`gc.freeze()`), so the collector looks only at what a module makes itself.
"""
import gc
import sys
import unittest
import weakref
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))

import e2e_harness as H  # noqa: E402
import srcpin  # noqa: E402


class TestTheHarnessParksTheOldHeap(unittest.TestCase):

    def test_what_exists_when_a_stack_starts_is_frozen(self):
        keep = [{"n": i, "pair": [i, i]} for i in range(200_000)]          # tracked containers, the kind the suite leaves behind
        try:
            before = gc.get_freeze_count()
            self.assertLess(before, len(keep) * 2, "control: this list was not frozen before the call")
            H.park_the_old_heap()
            self.assertGreaterEqual(gc.get_freeze_count() - before, len(keep), "the objects that existed at the call are out of the collector's sight")
        finally:
            del keep

    def test_a_second_call_looks_only_at_what_came_since(self):
        H.park_the_old_heap()
        first = gc.get_freeze_count()
        newer = [{"n": i} for i in range(50_000)]
        try:
            H.park_the_old_heap()
            self.assertGreaterEqual(gc.get_freeze_count() - first, len(newer))
        finally:
            del newer

    def test_garbage_that_is_waiting_is_freed_and_not_parked_for_good(self):
        class Node:
            other = None
        refs = []
        a = b = None
        was_enabled = gc.isenabled()
        gc.disable()                                                        # so that the cycles below are certainly still waiting when the harness is called
        try:
            for _ in range(2_000):
                a, b = Node(), Node()
                a.other, b.other = b, a                                     # a cycle: only the collector can free it
                refs.append(weakref.ref(a))
            del a, b
            self.assertTrue(any(r() is not None for r in refs), "control: the cycles are alive until a collection runs")
        finally:
            if was_enabled:
                gc.enable()
        H.park_the_old_heap()
        self.assertTrue(all(r() is None for r in refs), "they were collected before the freeze and not parked with the rest")

    def test_start_stack_parks_the_heap_first(self):
        src = (_TESTS / "e2e_harness.py").read_text()
        body = srcpin.py_function(src, "start_stack")
        self.assertIn("park_the_old_heap()", body)
        self.assertLess(body.index("park_the_old_heap()"), body.index("subprocess.Popen"), "before the stack's own processes and threads exist")


if __name__ == "__main__":
    unittest.main()
