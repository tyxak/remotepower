"""v6.1.1 (#1) -- pure unit tests for server/push/remotepower-push.py, the
companion async daemon for the agent wake-nudge push channel (docs/master-
improvement-scoping-internal.md #1).

The module is deliberately importable without the optional `websockets`
library installed (see its own comment on the import block) -- only its
auth/caching/nudge-dedup logic is pure Python; actually RUNNING the daemon
(main()) still hard-fails with install instructions if websockets is
missing, same as before. These tests exercise exactly that pure logic
directly, with no real network I/O and no websockets dependency.
"""
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location(
    "remotepower_push", _ROOT / "server" / "push" / "remotepower-push.py")
push = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(push)

_api_spec = importlib.util.spec_from_file_location("api_v611_push", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_api_spec)
_api_spec.loader.exec_module(api)


class TestModuleImportableWithoutWebsockets(unittest.TestCase):
    def test_module_loaded(self):
        # If this test class runs at all, the module import above already
        # succeeded despite websockets not necessarily being installed --
        # the real assertion is implicit (no ImportError/SystemExit raised
        # at import time).
        self.assertTrue(hasattr(push, '_WS_AVAILABLE'))


class TestDeviceTokenParity(unittest.TestCase):
    """The daemon ports api.py's exact _hash_device_token/_device_token_ok
    logic (it can't import api.py directly -- separate process, shares only
    on-disk DATA_DIR files). A divergence here would silently split which
    tokens the daemon accepts vs. what the main API accepts, so these tests
    pin BOTH implementations against the same cases."""

    def test_hash_matches_api_py(self):
        self.assertEqual(push._hash_device_token('abc123'), api._hash_device_token('abc123'))

    def test_hash_is_sha256_hex(self):
        self.assertEqual(push._hash_device_token('x'), hashlib.sha256(b'x').hexdigest())

    def test_hashed_token_match(self):
        dev = {'token_hash': push._hash_device_token('secret1')}
        self.assertTrue(push._device_token_ok(dev, 'secret1'))
        self.assertEqual(push._device_token_ok(dev, 'secret1'),
                         api._device_token_ok(dev, 'secret1'))

    def test_hashed_token_mismatch(self):
        dev = {'token_hash': push._hash_device_token('secret1')}
        self.assertFalse(push._device_token_ok(dev, 'wrong'))
        self.assertEqual(push._device_token_ok(dev, 'wrong'),
                         api._device_token_ok(dev, 'wrong'))

    def test_legacy_plaintext_token_match(self):
        dev = {'token': 'plain-legacy'}
        self.assertTrue(push._device_token_ok(dev, 'plain-legacy'))
        self.assertEqual(push._device_token_ok(dev, 'plain-legacy'),
                         api._device_token_ok(dev, 'plain-legacy'))

    def test_no_presented_token_rejected(self):
        dev = {'token_hash': push._hash_device_token('secret1')}
        self.assertFalse(push._device_token_ok(dev, ''))
        self.assertFalse(push._device_token_ok(dev, None))

    def test_missing_device_rejected(self):
        self.assertFalse(push._device_token_ok(None, 'anything'))
        self.assertFalse(push._device_token_ok({}, 'anything'))

    def test_hashed_form_preferred_over_legacy(self):
        # A device with BOTH fields (mid-migration) must only accept the
        # hashed form, matching api.py's own precedence.
        dev = {'token_hash': push._hash_device_token('new'), 'token': 'old'}
        self.assertTrue(push._device_token_ok(dev, 'new'))
        self.assertFalse(push._device_token_ok(dev, 'old'))


class TestLoadJson(unittest.TestCase):
    def test_missing_file_returns_empty_dict(self):
        self.assertEqual(push._load_json('/nonexistent/path/x.json'), {})

    def test_valid_file_parsed(self):
        d = Path(tempfile.mkdtemp())
        f = d / 'x.json'
        f.write_text(json.dumps({'a': 1}))
        self.assertEqual(push._load_json(f), {'a': 1})

    def test_corrupt_file_returns_empty_dict(self):
        d = Path(tempfile.mkdtemp())
        f = d / 'x.json'
        f.write_text('{not valid json')
        self.assertEqual(push._load_json(f), {})


class TestDeviceStore(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.f = self.d / 'devices.json'
        self.token_hash = push._hash_device_token('tok1')
        self.f.write_text(json.dumps({'dev1': {'token_hash': self.token_hash}}))
        # v6.1.1: DeviceStore now reads through a backend-aware StoreReader; the
        # temp dir has no storage marker → JSON backend → flat-file + mtime path,
        # so all the mtime-keyed cache semantics below are unchanged.
        self.reader = push.StoreReader(self.d)

    def test_valid_token_accepted(self):
        store = push.DeviceStore(self.reader)
        self.assertTrue(store.check_token('dev1', 'tok1'))

    def test_invalid_token_rejected(self):
        store = push.DeviceStore(self.reader)
        self.assertFalse(store.check_token('dev1', 'wrong'))

    def test_unknown_device_rejected(self):
        store = push.DeviceStore(self.reader)
        self.assertFalse(store.check_token('ghost', 'tok1'))

    def test_unchanged_file_is_not_reparsed(self):
        # mtime-keyed, not time-keyed -- an unchanged file must not trigger
        # a re-parse on every single check_token call (auth is on the hot
        # connection-attempt path).
        store = push.DeviceStore(self.reader)
        store.check_token('dev1', 'tok1')
        orig_load_json = push._load_json
        calls = []
        push._load_json = lambda p: (calls.append(p), orig_load_json(p))[1]
        try:
            store.check_token('dev1', 'tok1')
            store.check_token('dev1', 'tok1')
        finally:
            push._load_json = orig_load_json
        self.assertEqual(calls, [], 'an unchanged file must not be re-parsed')

    def test_rotated_token_takes_effect_immediately(self):
        # No time-based staleness window: a token that just rotated must
        # stop authenticating (and the new one must start) on the very next
        # check, not after some cache TTL elapses -- this is the correctness
        # property a plain time-based TTL would have silently violated.
        store = push.DeviceStore(self.reader)
        self.assertTrue(store.check_token('dev1', 'tok1'))
        new_hash = push._hash_device_token('tok2')
        self.f.write_text(json.dumps({'dev1': {'token_hash': new_hash}}))
        self.assertFalse(store.check_token('dev1', 'tok1'),
                         'the old token must stop working the instant the file changes')
        self.assertTrue(store.check_token('dev1', 'tok2'))

    def test_newly_enrolled_device_recognized_immediately(self):
        store = push.DeviceStore(self.reader)
        self.assertFalse(store.check_token('dev2', 'tok9'))   # doesn't exist yet
        devs = json.loads(self.f.read_text())
        devs['dev2'] = {'token_hash': push._hash_device_token('tok9')}
        self.f.write_text(json.dumps(devs))
        self.assertTrue(store.check_token('dev2', 'tok9'))


class TestStoreReaderBackend(unittest.TestCase):
    """v6.1.1 fix: the daemon must read devices/commands through the SAME
    storage backend the app uses. Under Postgres/SQLite the flat *.json files
    don't exist, so a direct file read rejected every device (fails closed →
    push silently dead). StoreReader picks the backend from the storage marker."""

    def test_no_marker_is_json_backend_flat_file(self):
        d = Path(tempfile.mkdtemp())
        (d / 'devices.json').write_text(json.dumps({'dev1': {'token_hash': 'h'}}))
        r = push.StoreReader(d)
        self.assertEqual(r.backend, 'json')
        self.assertIsNone(r._mod)                       # flat-file path
        self.assertEqual(r.load('devices.json'), {'dev1': {'token_hash': 'h'}})
        self.assertIsNotNone(r.mtime('devices.json'))   # real file → real mtime

    def test_sqlite_marker_selects_storage_backend(self):
        d = Path(tempfile.mkdtemp())
        # Mirror the on-disk storage marker the app writes.
        (d / 'storage_backend.json').write_text(json.dumps({'backend': 'sqlite'}))
        r = push.StoreReader(d)
        self.assertEqual(r.backend, 'sqlite')
        self.assertIsNotNone(r._mod)                    # delegates to storage
        self.assertIsNone(r.mtime('devices.json'))      # DB → no file mtime → TTL


class TestPendingContentKey(unittest.TestCase):
    def test_empty_list_is_none(self):
        self.assertIsNone(push._pending_content_key([]))
        self.assertIsNone(push._pending_content_key(None))

    def test_nonempty_list_has_a_key(self):
        key = push._pending_content_key(['reboot'])
        self.assertIsNotNone(key)
        self.assertEqual(key, (1, 'reboot'))

    def test_key_changes_when_a_new_command_is_appended(self):
        k1 = push._pending_content_key(['reboot'])
        k2 = push._pending_content_key(['reboot', 'exec:uptime'])
        self.assertNotEqual(k1, k2)

    def test_key_stable_for_the_same_pending_list(self):
        self.assertEqual(push._pending_content_key(['reboot']),
                         push._pending_content_key(['reboot']))


class TestShouldNudge(unittest.TestCase):
    def test_no_pending_work_no_nudge(self):
        self.assertIsNone(push._should_nudge([], None, now=100.0))

    def test_never_nudged_before_nudges(self):
        decision = push._should_nudge(['reboot'], None, now=100.0)
        self.assertIsNotNone(decision)
        self.assertEqual(decision, ((1, 'reboot'), 100.0))

    def test_same_content_within_cooldown_does_not_renudge(self):
        last = ((1, 'reboot'), 100.0)
        decision = push._should_nudge(['reboot'], last, now=105.0, cooldown_s=30)
        self.assertIsNone(decision)

    def test_same_content_after_cooldown_renudges(self):
        last = ((1, 'reboot'), 100.0)
        decision = push._should_nudge(['reboot'], last, now=131.0, cooldown_s=30)
        self.assertIsNotNone(decision)

    def test_new_content_within_cooldown_still_renudges(self):
        # A NEW command arriving must not wait out the old command's cooldown.
        last = ((1, 'reboot'), 100.0)
        decision = push._should_nudge(['reboot', 'exec:uptime'], last, now=105.0, cooldown_s=30)
        self.assertIsNotNone(decision)
        self.assertEqual(decision[0], (2, 'exec:uptime'))

    def test_work_cleared_no_nudge_even_if_previously_nudged(self):
        last = ((1, 'reboot'), 100.0)
        decision = push._should_nudge([], last, now=105.0)
        self.assertIsNone(decision)


if __name__ == "__main__":
    unittest.main()
