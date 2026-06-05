"""Guard: the split client JS must load clean in declaration order.

Catches the failure mode an app.js split can introduce — a function or
top-level let/const moved to a later file but referenced at LOAD time by an
earlier one. Skips when py_mini_racer (V8) isn't installed, so it never blocks
environments without it; CI / dev with it installed get the check.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import py_mini_racer  # noqa: F401
    _HAVE_V8 = True
except Exception:
    _HAVE_V8 = False

import _jsload_harness  # noqa: E402


class TestClientJsLoadOrder(unittest.TestCase):
    @unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
    def test_loads_clean(self):
        err = _jsload_harness.check()
        self.assertIsNone(err, f"client JS load-order error:\n{err}")


if __name__ == "__main__":
    unittest.main()
