"""Keystone: the storage connection cache is thread-safe.

sqlite3 connections are bound to their creating thread; a shared cache across
threads raises "SQLite objects created in a thread can only be used in that same
thread" (which crashed a threaded WSGI worker). The cache is now keyed per
(dir, pid, thread). This guards that under the SQLite backend (the PG backend is
exercised the same way via storage_pg's threading.local, but make test has no PG).
"""
import sys
import tempfile
import threading
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import storage  # noqa: E402


class TestStorageThreadSafe(unittest.TestCase):
    def test_concurrent_save_load_across_threads(self):
        d = tempfile.mkdtemp(prefix="rp-ts-")
        storage.DATA_DIR = Path(d)
        errs = []

        def worker(tid):
            try:
                for i in range(25):
                    p = Path(d) / f"k_{tid}_{i}.json"
                    storage.save(p, {"tid": tid, "i": i})
                    g = storage.load(p)
                    assert g.get("tid") == tid and g.get("i") == i, (tid, i, g)
            except Exception as e:  # the pre-fix failure is an exception here
                errs.append((tid, repr(e)))

        ts = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errs, [], f"thread errors: {errs[:2]}")

    def test_source_keys_by_thread_and_pid(self):
        src = (_CGI / "storage.py").read_text()
        self.assertIn("os.getpid(), threading.get_ident()", src)
        pg = (_CGI / "storage_pg.py").read_text()
        self.assertIn("_LOCAL = threading.local()", pg)
        self.assertIn("_DSN_GEN", pg)


if __name__ == "__main__":
    unittest.main()
