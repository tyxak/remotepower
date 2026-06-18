"""Anti-regression contract for handle_heartbeat's `saved_dev` snapshot.

The single most recurring class of bug in this project has been a *read with
no matching write*: handle_heartbeat reads a field via ``saved_dev.get('X')``
after releasing the DEVICES_FILE lock, but nobody cached ``saved_dev['X']``
inside the lock — so the read always saw the default and the feature silently
did nothing. mailbox_paths, force_agent_upgrade, host_config and the
listening-port audit all shipped broken exactly this way.

This test makes that impossible to merge: every key read off ``saved_dev`` in
the handler must be satisfied by an explicit assignment, the
``_HEARTBEAT_PASSTHROUGH_FIELDS`` contract table, or the small documented
special-case set below.
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402

API_SRC = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()

# Reads that are intentionally satisfied somewhere other than the handler's own
# assignments / the contract table. Keep this EMPTY unless there's a genuine
# reason; every entry is a hole in the guarantee, so document each one.
_ALLOWED_UNWRITTEN: set[str] = set()


def _heartbeat_body() -> str:
    lines = API_SRC.splitlines()
    start = next(i for i, l in enumerate(lines)
                 if l.startswith('def handle_heartbeat'))
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith('def ')), len(lines))
    return '\n'.join(lines[start:end])


class TestHeartbeatContract(unittest.TestCase):
    def setUp(self):
        self.body = _heartbeat_body()
        # A field is "referenced" if it's read via .get OR via subscript
        # (saved_dev['X']) — both are how the handler consumes the snapshot.
        self.referenced = (
            set(re.findall(r"saved_dev\.get\(['\"]([a-z_]+)['\"]", self.body)) |
            set(re.findall(r"saved_dev\[['\"]([a-z_]+)['\"]\]", self.body)))
        # "assigned" = an explicit literal write inside the handler.
        self.assigned = set(re.findall(r"saved_dev\[['\"]([a-z_]+)['\"]\]\s*=", self.body))
        # The contract table drives a loop that writes the rest.
        self.table = set(api._HEARTBEAT_PASSTHROUGH_FIELDS.keys())

    def test_sanity_parsed_something(self):
        # Guard against the slicing/regex silently matching nothing, which would
        # make the real assertions below vacuously pass.
        self.assertGreater(len(self.referenced), 8, "no saved_dev refs parsed")
        self.assertGreater(len(self.assigned), 4, "no saved_dev assignments parsed")
        self.assertGreater(len(self.table), 0, "contract table is empty")

    def test_every_read_has_a_write(self):
        # THE bug-class guard: every field the handler reads off saved_dev must
        # be written — by an explicit assignment, or by the contract-table loop.
        satisfied = self.assigned | self.table | _ALLOWED_UNWRITTEN
        orphaned = self.referenced - satisfied
        self.assertEqual(
            orphaned, set(),
            f"saved_dev reads with no matching cache write: {sorted(orphaned)}. "
            f"Add the field to _HEARTBEAT_PASSTHROUGH_FIELDS or assign "
            f"saved_dev['<key>'] inside the DEVICES_FILE lock.")

    def test_no_dead_contract_entries(self):
        # The loop must actually drive the table, and every table field must be
        # consumed — caching a field nothing reads is dead work (this caught two
        # such fields, agentless + cmd_allowlist, when the contract was added).
        self.assertIn('_HEARTBEAT_PASSTHROUGH_FIELDS.items()', self.body)
        dead = self.table - self.referenced
        self.assertEqual(dead, set(),
                         f"contract fields cached but never read: {sorted(dead)}")

    def test_passthrough_factories_yield_fresh_objects(self):
        # Each call must produce a distinct mutable default so two devices in
        # one process can't alias the same list/dict.
        for key, factory in api._HEARTBEAT_PASSTHROUGH_FIELDS.items():
            a, b = factory(), factory()
            if isinstance(a, (list, dict)):
                self.assertIsNot(a, b, f"{key} factory returns a shared object")


if __name__ == '__main__':
    unittest.main()
