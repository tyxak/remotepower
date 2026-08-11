#!/usr/bin/env python3
"""Rotating the vault passphrase must not destroy the vault.

FOUR stores are encrypted under the CMDB vault passphrase. The rotation
re-encrypted ONE:

    CMDB_FILE          per-device credentials            (was rotated)
    SCOPED_VAULT_FILE  group/tag-scoped credentials      (was orphaned)
    CONFIG_FILE        dns_vault_creds provider tokens   (was orphaned)
    KMIP_FILE          the KMIP CA and server-cert PRIVATE KEYS, plus every
    KMIP_OBJECTS_FILE  stored key object's material      (was orphaned)

and because it replaces the vault salt and canary in place, the old key becomes
underivable. So EVERY ORDINARY, ENTIRELY SUCCESSFUL ROTATION permanently
destroyed three of the four, while the response said `{"ok": true}` and the UI
toasted "Passphrase rotated."

The KMIP one is the worst: that CA key is what the key server signs client
certificates with. Losing it means appliances stop being able to fetch their
keys and encrypted volumes fail to mount at the next reboot — a failure that
surfaces days later, at a reboot, with no obvious connection to the rotation.

TWO MORE DEFECTS IN THE SAME HANDLER:

  * A value that would not decrypt was DROPPED (`except VaultError: continue`),
    logged as a corrupt entry. The realistic way to reach that state is a
    previous half-finished rotation — so the operator's natural response,
    retrying, deleted every secret it could not read and returned 200. The
    reproduction of THAT is the test this file exists for.
  * The new metadata was written FIRST, and the docstring claimed this left the
    vault "openable with the old passphrase". The reverse was true.

Every test drives the real handler and then tries to DECRYPT with the new key —
asserting on the ciphertext, not on the response body, because the response
said everything was fine throughout.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643vault-'))

_spec = importlib.util.spec_from_file_location('api_v643_vault', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

import cmdb_vault  # noqa: E402

OLD = 'old-passphrase-1234'
NEW = 'new-passphrase-5678'


class _Base(unittest.TestCase):
    def setUp(self):
        self.cap = {}
        # There is no is_installed() — I invented that name. The module signals
        # a missing `cryptography` by raising VaultNotInstalledError from the
        # first call that needs it, so ask it the only way it answers.
        try:
            meta = cmdb_vault.setup_vault(OLD)
        except cmdb_vault.VaultNotInstalledError:
            self.skipTest('cryptography not installed')
        meta['created_at'], meta['created_by'] = 1, 'root'
        api.save(api.CMDB_VAULT_FILE, meta)
        self.k_old = cmdb_vault.derive_key_from_meta(OLD, meta)

        # Every store, in the shape the PRODUCING code actually writes.
        # (The first draft of this fixture keyed SCOPED_VAULT_FILE by id; the
        # real shape is {'creds': [...]}, and with the invented one the scoped
        # credential silently fell outside the rotation and the test blamed the
        # fix.)
        api.save(api.CMDB_FILE, {'d1': {'credentials': [
            dict(id='c1', label='root pw',
                 **cmdb_vault.encrypt(self.k_old, 'device-secret'))]}})
        api.save(api.SCOPED_VAULT_FILE, {'creds': [
            dict(id='scred_1', scope_type='group', scope_value='web',
                 **cmdb_vault.encrypt(self.k_old, 'scoped-secret'))]})
        api.save(api.CONFIG_FILE, {'dns_vault_creds': {'cloudflare': {
            'api_token': cmdb_vault.encrypt(self.k_old, 'cf-token')}}})
        api.save(api.KMIP_FILE, {'enabled': True,
                                 'ca': {'key_enc': cmdb_vault.encrypt(
                                     self.k_old, '-----BEGIN PRIVATE KEY-----')}})
        api.save(api.KMIP_OBJECTS_FILE, {'uid1': {
            'material': cmdb_vault.encrypt_bytes(self.k_old, b'\x01\x02rawkey')}})
        self._bust()

        self._orig = {k: getattr(api, k) for k in (
            'require_admin_auth', 'method', 'get_json_obj', 'respond', 'audit_log')}
        api.require_admin_auth = lambda *a, **k: 'root'
        api.method = lambda: 'POST'
        api.audit_log = lambda *a, **k: None

        def _r(status, data=None, *a, **k):
            self.cap['s'], self.cap['d'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _r

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _bust(self):
        for f in (api.CMDB_VAULT_FILE, api.CMDB_FILE, api.SCOPED_VAULT_FILE,
                  api.CONFIG_FILE, api.KMIP_FILE, api.KMIP_OBJECTS_FILE):
            api._invalidate_load_cache(f)

    def _rotate(self, old=OLD, new=NEW, **extra):
        api.get_json_obj = lambda: dict(
            {'old_passphrase': old, 'new_passphrase': new}, **extra)
        try:
            api.handle_cmdb_vault_change()
        except (SystemExit, api.HTTPError):
            pass
        self._bust()
        return self.cap

    def _new_key(self, pw=NEW):
        return cmdb_vault.derive_key_from_meta(pw, api.load(api.CMDB_VAULT_FILE))

    def _readable(self, key):
        """Which of the five secrets decrypt under `key`."""
        out = {}
        try:
            c = (api.load(api.CMDB_FILE)['d1']['credentials'] or [{}])[0]
            cmdb_vault.decrypt(key, c); out['cmdb'] = True
        except Exception:
            out['cmdb'] = False
        try:
            c = (api.load(api.SCOPED_VAULT_FILE).get('creds') or [{}])[0]
            cmdb_vault.decrypt(key, c); out['scoped'] = True
        except Exception:
            out['scoped'] = False
        try:
            b = api.load(api.CONFIG_FILE)['dns_vault_creds']['cloudflare']['api_token']
            cmdb_vault.decrypt(key, b); out['dns'] = True
        except Exception:
            out['dns'] = False
        try:
            cmdb_vault.decrypt(key, api.load(api.KMIP_FILE)['ca']['key_enc'])
            out['kmip_ca'] = True
        except Exception:
            out['kmip_ca'] = False
        try:
            cmdb_vault.decrypt_bytes(
                key, api.load(api.KMIP_OBJECTS_FILE)['uid1']['material'])
            out['kmip_obj'] = True
        except Exception:
            out['kmip_obj'] = False
        return out


class TestEveryStoreIsRotated(_Base):
    def test_all_five_secrets_survive(self):
        r = self._rotate()
        self.assertEqual(r.get('s'), 200, r.get('d'))
        readable = self._readable(self._new_key())
        self.assertEqual(readable, {'cmdb': True, 'scoped': True, 'dns': True,
                                    'kmip_ca': True, 'kmip_obj': True},
                         'a successful rotation orphaned a store: ' + str(readable))

    def test_the_kmip_ca_key_specifically(self):
        """Called out on its own because losing it does not fail loudly — the
        key server keeps serving until an appliance next needs a certificate,
        and then encrypted volumes do not mount at the following reboot."""
        self._rotate()
        cmdb_vault.decrypt(self._new_key(),
                           api.load(api.KMIP_FILE)['ca']['key_enc'])

    def test_the_count_reflects_every_store(self):
        r = self._rotate()
        self.assertEqual(r['d'].get('rotated'), 5,
                         'the response undercounted, which is how "rotated: 1" '
                         'looked like success while three stores were lost')
        self.assertGreaterEqual(r['d'].get('stores', 0), 4)

    def test_the_old_passphrase_no_longer_opens_it(self):
        """The positive control for the whole file: rotation must actually
        rotate. A no-op that wrote nothing would pass every test above."""
        self._rotate()
        meta = api.load(api.CMDB_VAULT_FILE)
        self.assertFalse(
            cmdb_vault.verify_key(cmdb_vault.derive_key_from_meta(OLD, meta), meta))


class TestAnUndecryptableSecretAbortsRatherThanDrops(_Base):
    def test_nothing_is_written_and_nothing_is_lost(self):
        """The retry path, which is how an operator turned a half-finished
        rotation into total loss. The old code caught VaultError, called the
        value corrupt, dropped it, and returned 200."""
        store = api.load(api.SCOPED_VAULT_FILE)
        store['creds'][0]['ct'] = 'AAAA' + store['creds'][0]['ct'][4:]  # corrupt
        api.save(api.SCOPED_VAULT_FILE, store)
        self._bust()

        r = self._rotate()
        self.assertEqual(r.get('s'), 409,
                         'an undecryptable secret must abort the rotation')
        # the vault is untouched: the ORIGINAL passphrase still works
        meta = api.load(api.CMDB_VAULT_FILE)
        self.assertTrue(
            cmdb_vault.verify_key(cmdb_vault.derive_key_from_meta(OLD, meta), meta),
            'the rotation changed the vault metadata despite aborting')
        readable = self._readable(cmdb_vault.derive_key_from_meta(OLD, meta))
        self.assertTrue(readable['cmdb'], 'a secret was lost by an aborted run')
        self.assertTrue(readable['dns'])
        self.assertTrue(readable['kmip_ca'])

    def test_the_error_tells_the_operator_what_to_do(self):
        store = api.load(api.SCOPED_VAULT_FILE)
        store['creds'][0]['ct'] = 'AAAA' + store['creds'][0]['ct'][4:]
        api.save(api.SCOPED_VAULT_FILE, store)
        self._bust()
        r = self._rotate()
        msg = str(r.get('d'))
        self.assertIn('nothing was changed', msg)
        self.assertIn('backup', msg,
                      'the operator needs to be told the recovery route, not '
                      'just that it failed')

    def test_a_second_attempt_still_loses_nothing(self):
        """The specific sequence that destroyed a credential store: fail, then
        retry because the first one failed."""
        store = api.load(api.SCOPED_VAULT_FILE)
        store['creds'][0]['ct'] = 'AAAA' + store['creds'][0]['ct'][4:]
        api.save(api.SCOPED_VAULT_FILE, store)
        self._bust()
        for _ in range(3):
            self._rotate()
        meta = api.load(api.CMDB_VAULT_FILE)
        k = cmdb_vault.derive_key_from_meta(OLD, meta)
        self.assertTrue(self._readable(k)['cmdb'])
        self.assertEqual(
            len(api.load(api.CMDB_FILE)['d1']['credentials']), 1,
            'a credential was dropped by a retried rotation')


class TestTheDryRun(_Base):
    def test_preview_changes_nothing(self):
        r = self._rotate(preview=True)
        self.assertEqual(r.get('s'), 200, r.get('d'))
        self.assertTrue(r['d'].get('preview'))
        meta = api.load(api.CMDB_VAULT_FILE)
        self.assertTrue(
            cmdb_vault.verify_key(cmdb_vault.derive_key_from_meta(OLD, meta), meta),
            'the preview rotated the vault')

    def test_preview_reports_what_it_would_touch(self):
        r = self._rotate(preview=True)
        self.assertEqual(r['d'].get('would_rotate'), 5)
        self.assertGreaterEqual(len(r['d'].get('stores') or []), 4)


class TestCrashRecoveryMetadata(_Base):
    def test_the_previous_salt_is_retained(self):
        """Several stores cannot be written in one transaction, so a crash
        between them still splits the state. Keeping the previous salt/canary
        is what makes that recoverable instead of terminal — without it the old
        key is underivable and the un-rotated ciphertext is gone for good.

        It grants nothing on its own: deriving the old key still needs the old
        passphrase."""
        self._rotate()
        prev = (api.load(api.CMDB_VAULT_FILE) or {}).get('previous')
        self.assertIsInstance(prev, dict)
        self.assertTrue(cmdb_vault.verify_key(
            cmdb_vault.derive_key_from_meta(OLD, prev), prev),
            'the retained metadata does not actually derive the old key')

    def test_metadata_is_written_after_the_ciphertext(self):
        import inspect
        src = inspect.getsource(api.handle_cmdb_vault_change)
        body = '\n'.join(l for l in src.splitlines()
                         if not l.strip().startswith('#'))
        self.assertLess(body.index('for path, doc in writes'),
                        body.index('A.save(A.CMDB_VAULT_FILE'),
                        'metadata must be committed LAST — writing it first is '
                        'what made a crash unrecoverable')


if __name__ == '__main__':
    unittest.main()
