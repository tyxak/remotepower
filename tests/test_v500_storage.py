"""v5.0.0: one-click ZFS/Btrfs pool maintenance — handle_device_storage_action.

The (kind, action) pair maps to a FIXED command template; the only interpolated
value is the pool / mountpoint / snapshot, each strictly validated so nothing the
operator picks can break out of the constructed `exec:` command. These tests drive
the handler directly and assert the exact command queued + that injection / bad
input is rejected.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v500_storage", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_API_SRC = (_CGI / "api.py").read_text()


class _Stop(Exception):
    pass


class TestStorageAction(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(api, k) for k in
                       ('require_perm', 'method', 'get_json_body', 'audit_log',
                        '_queue_command', '_validate_id', 'respond')}
        self.queued = []
        self.resp = {}
        api.require_perm = lambda *a, **k: "admin"
        api.method = lambda: "POST"
        api.audit_log = lambda *a, **k: None
        api._validate_id = lambda x: True
        api._queue_command = lambda dev_id, cmd, actor: self.queued.append((dev_id, cmd))

        def _resp(status, body=None):
            self.resp = {"status": status, "body": body}
            raise _Stop()
        api.respond = _resp

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def _run(self, body):
        api.get_json_body = lambda: body
        try:
            api.handle_device_storage_action("dev1")
        except _Stop:
            pass

    def test_zfs_scrub(self):
        self._run({"kind": "zfs", "action": "scrub", "target": "tank"})
        self.assertEqual(self.queued, [("dev1", "exec:zpool scrub tank")])

    def test_btrfs_balance(self):
        self._run({"kind": "btrfs", "action": "balance", "target": "/mnt/data"})
        self.assertEqual(self.queued,
                         [("dev1", "exec:btrfs balance start -dusage=50 /mnt/data")])

    def test_zfs_snapshot_destroy(self):
        self._run({"kind": "zfs", "action": "destroy", "target": "tank",
                   "snapshot": "tank/data@auto-2026-06-01"})
        self.assertEqual(self.queued,
                         [("dev1", "exec:zfs destroy tank/data@auto-2026-06-01")])

    def test_btrfs_snapshot_delete(self):
        self._run({"kind": "btrfs", "action": "delete", "target": "/mnt/data",
                   "snapshot": "/mnt/data/.snapshots/2026-06-01"})
        self.assertEqual(self.queued,
                         [("dev1", "exec:btrfs subvolume delete /mnt/data/.snapshots/2026-06-01")])

    def test_injection_target_rejected(self):
        self._run({"kind": "zfs", "action": "scrub", "target": "tank; rm -rf /"})
        self.assertEqual(self.resp["status"], 400)
        self.assertEqual(self.queued, [])

    def test_zfs_destroy_requires_at(self):
        # A ZFS destroy without '@' could nuke a whole dataset, not a snapshot.
        self._run({"kind": "zfs", "action": "destroy", "target": "tank",
                   "snapshot": "tank/data"})
        self.assertEqual(self.resp["status"], 400)
        self.assertEqual(self.queued, [])

    def test_unknown_action_rejected(self):
        self._run({"kind": "zfs", "action": "nuke", "target": "tank"})
        self.assertEqual(self.resp["status"], 400)
        self.assertEqual(self.queued, [])

    def test_bad_kind_rejected(self):
        self._run({"kind": "ext4", "action": "scrub", "target": "/"})
        self.assertEqual(self.resp["status"], 400)
        self.assertEqual(self.queued, [])


class TestStorageActionWiring(unittest.TestCase):
    def test_route_registered(self):
        self.assertIn("endswith('/storage-action') and m == 'POST'", _API_SRC)

    def test_handler_exists(self):
        self.assertTrue(hasattr(api, "handle_device_storage_action"))

    def test_overview_carries_target(self):
        self.assertIn("'target': target", _API_SRC)


if __name__ == "__main__":
    unittest.main(verbosity=2)
