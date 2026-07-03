"""Issue #8 — device-write handlers must do their read-modify-write of
DEVICES_FILE under _LockedUpdate(DEVICES_FILE), not a bare load()/save() pair.

A bare RMW loses concurrent writes (the documented last_seen-revert class) and,
on the SQL backend, save() reconciles the *whole* device set — deleting any row
absent from the stale snapshot (e.g. a device that enrolled mid-edit). The fix
moved every handler onto the lock; this guardrail keeps them there.

The ONE permitted bare `save(DEVICES_FILE, ...)` is _rollout_tick, which writes
DEVICES while already holding _LockedUpdate(ROLLOUTS_FILE) and therefore cannot
take a second (nested) DEVICES lock under SQLite. It's allowlisted explicitly.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
import sys as _as_sys
from pathlib import Path as _as_Path
_as_sys.path.insert(0, str(_as_Path(__file__).resolve().parent))
from apisrc import api_source as _apisrc_combined   # api.py + *_handlers.py bound modules (decomposition-safe pins)
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location("api_devlocks", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

API_SRC = _apisrc_combined()

# Functions allowed to contain a bare `save(DEVICES_FILE, ...)`.
_ALLOWED_BARE = {"_rollout_tick"}


def _enclosing_func(src_lines, idx):
    for j in range(idx, -1, -1):
        m = re.match(r"def ([A-Za-z_][A-Za-z0-9_]*)\(", src_lines[j])
        if m:
            return m.group(1)
    return "?"


class TestNoBareDevicesSave(unittest.TestCase):
    def test_only_rollout_tick_has_a_bare_devices_save(self):
        lines = API_SRC.split("\n")
        offenders = {}
        for i, l in enumerate(lines):
            # (?:A\.)? — inside the bound *_handlers modules api services are
            # accessed via the A namespace; the invariant must keep seeing
            # bare device saves THERE too, not go blind on extraction.
            if re.match(r"\s*(?:A\.)?save\((?:A\.)?DEVICES_FILE,", l):
                fn = _enclosing_func(lines, i)
                if fn not in _ALLOWED_BARE:
                    offenders[fn] = i + 1
        self.assertEqual(
            offenders, {},
            f"bare save(DEVICES_FILE, ...) outside a lock in: {offenders} — wrap "
            f"the read-modify-write in `with _LockedUpdate(DEVICES_FILE) as devices:`")

    def test_allowlisted_rollout_save_still_present(self):
        # If _rollout_tick is ever refactored off the bare save, drop it from the
        # allowlist (don't let the allowlist rot into a silent escape hatch).
        self.assertIn("def _rollout_tick(", API_SRC)
        i = API_SRC.index("def _rollout_tick(")
        self.assertRegex(API_SRC[i:i + 2000],
                         r"(?:A\.)?save\((?:A\.)?DEVICES_FILE, devices\)")


class TestConvertedHandlerBehaviour(unittest.TestCase):
    """Drive a converted handler end-to-end (JSON backend) and confirm it both
    persists its change and leaves sibling devices intact — i.e. the write is a
    real RMW, not a stale full-store overwrite that drops other rows."""

    def _call(self, handler, dev_id, body, method="PATCH"):
        cap = {}

        def _resp(status, payload=None):
            cap["status"] = status
            cap["body"] = payload
            raise api.HTTPError(status, payload)

        orig = {n: getattr(api, n) for n in
                ("require_admin_auth", "method", "get_json_obj", "respond")}
        api.require_admin_auth = lambda: "admin"
        api.method = lambda: method
        api.get_json_obj = lambda: body
        api.respond = _resp
        try:
            try:
                handler(dev_id)
            except api.HTTPError:
                pass
        finally:
            for n, v in orig.items():
                setattr(api, n, v)
        return cap

    def test_tags_persist_and_sibling_survives(self):
        api.save(api.DEVICES_FILE, {
            "dev-a": {"name": "a", "tags": []},
            "dev-b": {"name": "b", "tags": ["keep"]},
        })
        cap = self._call(api.handle_device_tags, "dev-a", {"tags": ["prod", "web"]})
        self.assertEqual(cap.get("status"), 200, cap.get("body"))
        after = api.load(api.DEVICES_FILE)
        self.assertEqual(after["dev-a"]["tags"], ["prod", "web"])
        # The sibling, untouched by this request, must still be there.
        self.assertIn("dev-b", after)
        self.assertEqual(after["dev-b"]["tags"], ["keep"])

    def test_unknown_device_404s_and_writes_nothing(self):
        api.save(api.DEVICES_FILE, {"dev-b": {"name": "b", "tags": ["keep"]}})
        cap = self._call(api.handle_device_tags, "ghost", {"tags": ["x"]})
        self.assertEqual(cap.get("status"), 404)
        after = api.load(api.DEVICES_FILE)
        self.assertEqual(after, {"dev-b": {"name": "b", "tags": ["keep"]}})


if __name__ == "__main__":
    unittest.main()
