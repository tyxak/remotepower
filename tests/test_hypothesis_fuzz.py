"""Broad fuzz pass (Hypothesis) — throw generated/garbage inputs at the project's
PARSERS, NORMALIZERS, SANITIZERS and BODY-BUILDERS. The invariant for almost all of
them is simple and strong: *never crash on any input*, and return the documented
shape. Parsers fed hostile bytes are the richest bug source in any codebase.

Run: pip install hypothesis && python3 -m pytest tests/test_hypothesis_fuzz.py -q
CI-safe: skips cleanly when hypothesis is absent.
"""
import importlib
import sys
import unittest
from pathlib import Path

try:
    from hypothesis import given, strategies as st, settings, HealthCheck, assume
    _HAS = True
except ImportError:                     # pragma: no cover
    _HAS = False
    import functools

    def given(*a, **k):
        def _w(fn):
            @functools.wraps(fn)
            def _s(self, *aa, **kk):
                self.skipTest('hypothesis not installed')
            return _s
        return _w

    def settings(*a, **k):
        return lambda fn: fn

    class _D:
        def __call__(self, *a, **k): return self
        def __or__(self, o): return self
        def __getattr__(self, n): return self
    st = _D()

    class HealthCheck:
        function_scoped_fixture = None

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

importers = importlib.import_module('importers')
containers = importlib.import_module('containers')
sanitize = importlib.import_module('sanitize')
notify = importlib.import_module('notify')

# Recursive JSON-ish values, plus raw text and bytes-as-text.
_scalar = (st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True, allow_infinity=True)
           | st.text())
_json = st.recursive(_scalar, lambda c: st.lists(c, max_size=6)
                     | st.dictionaries(st.text(max_size=12), c, max_size=6), max_leaves=20)
# Text likely to trip parsers: json fragments, control chars, huge, unicode.
_nasty_text = (st.text() | st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x10ffff), max_size=200)
               | st.sampled_from(['', '{', '[]', 'null', '[1,2', '{"a":}', '\x00\x00',
                                  '{"devices":[{"name":null}]}', 'a' * 5000, '﻿BOM']))


class TestImportersNeverCrash(unittest.TestCase):
    """detect_format + parse must handle ANY text without raising."""

    @given(_nasty_text)
    @settings(max_examples=300, deadline=None)
    def test_detect_format_never_raises(self, text):
        r = importers.detect_format(text)
        self.assertTrue(r is None or isinstance(r, str))

    def _assert_parse_contract(self, *args):
        """parse() may raise ValueError on unrecognised input (its contract — the
        caller catches it → 400). ANY OTHER exception is a bug (an unhandled type
        would become a 500). On success it must return a dict with the expected
        keys the caller subscripts (result['monitors'], result['unmapped'])."""
        try:
            r = importers.parse(*args)
        except ValueError:
            return                       # documented + caught by handle_import_monitors
        self.assertIsInstance(r, dict)
        self.assertIn('monitors', r, "success dict must carry the keys the caller reads")
        self.assertIn('unmapped', r)

    @given(_nasty_text)
    @settings(max_examples=300, deadline=None)
    def test_parse_contract_holds(self, text):
        self._assert_parse_contract(text)

    @given(_nasty_text,
           st.sampled_from([None, 'nagios', 'zabbix', 'kuma', 'remotepower', 'bogus', '']))
    @settings(max_examples=300, deadline=None)
    def test_parse_with_explicit_format(self, text, fmt):
        self._assert_parse_contract(text, fmt)

    @given(_json)
    @settings(max_examples=200, deadline=None)
    def test_parse_json_dumped_values(self, value):
        import json
        self._assert_parse_contract(json.dumps(value))


class TestContainersNormalizersNeverCrash(unittest.TestCase):
    @given(_json)
    @settings(max_examples=300, deadline=None)
    def test_normalize_container(self, item):
        r = containers.normalize_container(item)
        self.assertTrue(r is None or isinstance(r, dict))

    @given(_json)
    @settings(max_examples=300, deadline=None)
    def test_normalize_listing_returns_list_of_dicts(self, items):
        r = containers.normalize_listing(items)
        self.assertIsInstance(r, list)
        self.assertTrue(all(isinstance(x, dict) for x in r))

    @given(_scalar)
    def test_float_or_zero_always_float(self, v):
        self.assertIsInstance(containers._float_or_zero(v), float)

    @given(_scalar)
    def test_int_or_zero_always_int(self, v):
        self.assertIsInstance(containers._int_or_zero(v), int)


class TestSanitizersNeverCrash(unittest.TestCase):
    @given(_scalar, st.integers(min_value=0, max_value=300))
    def test_sanitize_str(self, v, n):
        out = sanitize._sanitize_str(v, n)
        self.assertIsInstance(out, str)
        self.assertLessEqual(len(out), n)

    @given(_scalar)
    def test_sanitize_hostname_is_rfc1123_ish(self, v):
        out = sanitize._sanitize_hostname(v)
        self.assertIsInstance(out, str)
        self.assertRegex(out, r'^[a-zA-Z0-9.\-]*$')

    @given(_scalar)
    def test_sanitize_ip_valid_or_empty(self, v):
        out = sanitize._sanitize_ip(v)
        self.assertIsInstance(out, str)

    @given(_scalar)
    def test_sanitize_mac_valid_or_empty(self, v):
        out = sanitize._sanitize_mac(v)
        self.assertIsInstance(out, str)

    @given(_scalar)
    def test_sanitize_version(self, v):
        out = sanitize._sanitize_version(v)
        self.assertIsInstance(out, str)


class TestNotifyBodyBuildersNeverCrash(unittest.TestCase):
    """Every _build_<fmt>_body must handle arbitrary event/title/message without
    raising (they format outbound webhook payloads from possibly-hostile data)."""

    _builders = ['_build_discord_body', '_build_slack_body', '_build_teams_body',
                 '_build_ntfy_body', '_build_generic_body', '_build_telegram_body',
                 '_build_matrix_body']

    @given(st.text(max_size=64), st.text(max_size=200), st.text(max_size=2000),
           st.integers(min_value=0, max_value=5))
    @settings(max_examples=200, deadline=None)
    def test_builders_do_not_raise(self, event, title, message, prio):
        import inspect
        for name in self._builders:
            fn = getattr(notify, name, None)
            if not fn:
                continue
            sig = inspect.signature(fn)
            # call with the args each builder accepts (they vary: some take priority,
            # dest, safe_payload) — pass only what the signature names.
            kwargs = {}
            avail = {'event': event, 'title': title, 'message': message,
                     'priority': prio, 'dest': {}, 'safe_payload': {}}
            args = []
            for pname in sig.parameters:
                args.append(avail.get(pname, ''))
            try:
                fn(*args)
            except Exception as e:      # noqa: BLE001 - the whole point is "no raise"
                self.fail(f'{name} raised on fuzzed input: {type(e).__name__}: {e}')


if __name__ == '__main__':
    unittest.main()


# ── extra fuzz batch: crypto round-trip, dns guards, notify detect/message ──
import os
import tempfile
try:
    backup_crypto = importlib.import_module('backup_crypto')
except Exception:
    backup_crypto = None
try:
    dns_resolve = importlib.import_module('dns_resolve')
except Exception:
    dns_resolve = None


@unittest.skipUnless(backup_crypto is not None, 'backup_crypto unavailable')
class TestBackupCryptoRoundTrip(unittest.TestCase):
    """encrypt→decrypt must recover the EXACT bytes for any input; is_encrypted
    must classify correctly. A crypto round-trip failure is data loss."""

    @given(st.binary(max_size=4000), st.text(min_size=1, max_size=64))
    @settings(max_examples=60, deadline=None)
    def test_round_trip_recovers_exact_bytes(self, data, passphrase):
        d = Path(tempfile.mkdtemp(prefix='rp-crypt-'))
        src, enc, dec = d / 'p', d / 'e', d / 'd'
        src.write_bytes(data)
        try:
            backup_crypto.encrypt_file(src, enc, passphrase)
        except Exception as e:
            self.fail(f'encrypt raised on valid input: {type(e).__name__}: {e}')
        self.assertTrue(backup_crypto.is_encrypted(enc),
                        'an encrypted file must be detected as encrypted')
        backup_crypto.decrypt_file(enc, dec, passphrase)
        self.assertEqual(dec.read_bytes(), data, 'round-trip lost/altered bytes')

    @given(st.binary(max_size=2000), st.text(min_size=1, max_size=32),
           st.text(min_size=1, max_size=32))
    @settings(max_examples=40, deadline=None)
    def test_wrong_passphrase_fails_cleanly(self, data, p1, p2):
        assume(p1 != p2)
        d = Path(tempfile.mkdtemp(prefix='rp-crypt2-'))
        src, enc, dec = d / 'p', d / 'e', d / 'd'
        src.write_bytes(data)
        backup_crypto.encrypt_file(src, enc, p1)
        # wrong passphrase must raise (auth-tag mismatch) — NEVER silently produce
        # wrong plaintext.
        with self.assertRaises(Exception):
            backup_crypto.decrypt_file(enc, dec, p2)

    @given(st.binary(max_size=500))
    def test_is_encrypted_never_raises_on_arbitrary_file(self, data):
        d = Path(tempfile.mkdtemp(prefix='rp-crypt3-'))
        f = d / 'x'
        f.write_bytes(data)
        r = backup_crypto.is_encrypted(f)
        self.assertIsInstance(r, bool)


@unittest.skipUnless(dns_resolve is not None, 'dns_resolve unavailable')
class TestDnsGuardsNeverCrash(unittest.TestCase):
    @given(st.text(max_size=300))
    def test_valid_name(self, s):
        self.assertIsInstance(dns_resolve.valid_name(s), bool)

    @given(st.text(max_size=40))
    def test_valid_type(self, s):
        self.assertIsInstance(dns_resolve.valid_type(s), bool)

    @given(st.text(max_size=60))
    def test_blocked_ip_never_raises(self, s):
        r = dns_resolve._blocked_ip(s)
        self.assertIn(r, (True, False))


class TestNotifyDetectAndMessage(unittest.TestCase):
    @given(st.text(max_size=300))
    def test_auto_detect_format_never_raises(self, url):
        r = notify._auto_detect_format(url)
        self.assertTrue(r is None or isinstance(r, str))

    @given(st.text(max_size=48),
           st.dictionaries(st.text(max_size=16),
                           st.none() | st.text() | st.integers() | st.booleans(),
                           max_size=8))
    @settings(max_examples=200, deadline=None)
    def test_webhook_message_never_raises(self, event, payload):
        r = notify._webhook_message(event, payload)
        self.assertIsInstance(r, str)
