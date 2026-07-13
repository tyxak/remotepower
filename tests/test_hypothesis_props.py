"""Property-based tests (Hypothesis) — a DEEP-testing workflow demo.

Instead of asserting specific inputs, these state INVARIANTS that must hold for ALL
inputs and let Hypothesis generate thousands of cases (including nasty edges: empty
strings, unicode, huge ints, floats, control chars, deeply nested dicts) to try to
break them. A failure prints a minimal reproducing counterexample.

Run:  python3 -m pytest tests/test_hypothesis_props.py -q
      (add --hypothesis-seed=0 to reproduce, HYPOTHESIS_PROFILE for more examples)
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Optional: this is the DEEP-testing workflow (property-based). It's not a hard gate
# dependency — a machine/CI without hypothesis skips the whole module cleanly rather
# than erroring. Install it to run the deep pass:  pip install hypothesis
try:
    from hypothesis import given, strategies as st, settings, HealthCheck
    _HAS_HYPOTHESIS = True
except ImportError:                     # pragma: no cover
    _HAS_HYPOTHESIS = False
    import functools

    def given(*a, **k):                 # no-op decorators so the class body parses
        def _wrap(fn):
            @functools.wraps(fn)
            def _skip(self, *aa, **kk):
                self.skipTest('hypothesis not installed (pip install hypothesis)')
            return _skip
        return _wrap

    def settings(*a, **k):
        return lambda fn: fn

    class _Dummy:
        """Chainable no-op so module-level strategy definitions
        (`st.none() | st.text()`, `st.recursive(...)`) parse without hypothesis."""
        def __call__(self, *a, **k):
            return self

        def __or__(self, other):
            return self

        def __getattr__(self, _n):
            return self
    st = _Dummy()

    class HealthCheck:
        function_scoped_fixture = None

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))

# _fresh_api() mutates RP_STORAGE_BACKEND / RP_DATA_DIR; capture the originals and
# restore them at module teardown so this file can't leak a 'sqlite' backend into
# whatever test file runs next (the isolation-leak class this workflow exists to
# catch — don't reintroduce it here).
_ORIG_ENV = {k: os.environ.get(k) for k in ('RP_STORAGE_BACKEND', 'RP_DATA_DIR')}


def tearDownModule():
    for k, v in _ORIG_ENV.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _fresh_api(backend=None):
    d = tempfile.mkdtemp(prefix='rp-hyp-')
    os.environ['RP_DATA_DIR'] = d
    if backend:
        os.environ['RP_STORAGE_BACKEND'] = backend
        (Path(d) / '.storage_backend').write_text(backend)
    else:
        os.environ.pop('RP_STORAGE_BACKEND', None)
    spec = importlib.util.spec_from_file_location('api_hyp', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_API = _fresh_api()

# JSON-safe values the storage layer is expected to round-trip.
_json_scalars = (st.none() | st.booleans() | st.integers(min_value=-10**15, max_value=10**15)
                 | st.floats(allow_nan=False, allow_infinity=False, width=64)
                 | st.text())
_json_values = st.recursive(
    _json_scalars,
    lambda children: st.lists(children, max_size=6)
    | st.dictionaries(st.text(min_size=1, max_size=20), children, max_size=6),
    max_leaves=25,
)


class TestNormalizeMacProperties(unittest.TestCase):
    """_normalize_mac: the identity used for the mac_conflict detector."""

    @given(st.text())
    def test_never_raises_and_output_is_canonical(self, s):
        out = _API._normalize_mac(s)
        if out is not None:
            # canonical form: lowercase, colon-separated, 6 octets
            self.assertRegex(out, r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')

    @given(st.text())
    def test_idempotent(self, s):
        once = _API._normalize_mac(s)
        if once is not None:
            self.assertEqual(_API._normalize_mac(once), once,
                             'normalizing an already-normalized MAC must be a no-op')

    @given(st.lists(st.sampled_from('0123456789abcdefABCDEF'), min_size=12, max_size=12))
    def test_separator_invariance(self, hexchars):
        """The SAME 12 hex digits in different separator styles must normalize
        identically — that's what lets the detector match a cloned VM's MAC across
        report formats."""
        h = ''.join(hexchars)
        colon = ':'.join(h[i:i+2] for i in range(0, 12, 2))
        dash = '-'.join(h[i:i+2] for i in range(0, 12, 2))
        forms = [h, colon, dash, h.upper(), colon.upper()]
        outs = {_API._normalize_mac(f) for f in forms}
        self.assertEqual(len(outs), 1, f'same MAC, different forms disagreed: {outs}')


class TestSanitizeStrProperties(unittest.TestCase):
    @given(st.text(), st.integers(min_value=0, max_value=500))
    def test_respects_length_cap_and_never_raises(self, s, n):
        out = _API._sanitize_str(s, n)
        self.assertIsInstance(out, str)
        self.assertLessEqual(len(out), n, 'sanitized string exceeded its length cap')

    @given(st.text(), st.integers(min_value=1, max_value=200))
    def test_second_pass_only_ever_shrinks(self, s, n):
        """_sanitize_str is strip-THEN-truncate, so it is NOT idempotent — a
        truncation can re-introduce trailing whitespace that a second pass strips
        (Hypothesis found "a   b" with cap 3: → "a  " → "a"). That's within its
        documented "truncate and strip" contract, not a bug. The invariant that DOES
        hold and matters: a second pass never GROWS the string or exceeds the cap."""
        once = _API._sanitize_str(s, n)
        twice = _API._sanitize_str(once, n)
        self.assertLessEqual(len(twice), len(once))
        self.assertLessEqual(len(twice), n)
        self.assertTrue(once.startswith(twice) or twice == once.strip())

    @given(st.text(max_size=80))
    def test_matches_its_documented_contract(self, s):
        """_sanitize_str's contract is "Truncate and strip" — length + surrounding
        whitespace only (charset filtering is _sanitize_hostname/_ip/_mac's job).
        Pin exactly that: the result equals str(s).strip()[:cap].

        (Hypothesis surfaced that control chars — NUL/ESC — DO flow through this
        function; that's by contract, not a bug, but a note-worthy hardening
        candidate for anything that reaches a terminal/log unescaped.)"""
        cap = 40
        self.assertEqual(_API._sanitize_str(s, cap), str(s).strip()[:cap])


class TestStorageRoundTripAndBackendAgreement(unittest.TestCase):
    """The highest-value property: for ANY JSON value, save→load round-trips, AND
    the JSON and SQLite backends agree. A divergence here is a real cross-backend
    bug (the class that caused prod-only failures before)."""

    def setUp(self):
        self.json_api = _fresh_api()
        self.sqlite_api = _fresh_api('sqlite')

    @settings(max_examples=200, deadline=None,
              suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(_json_values)
    def test_json_backend_round_trips(self, value):
        f = self.json_api.CONFIG_FILE
        self.json_api.save(f, value if isinstance(value, dict) else {'v': value})
        self.json_api._invalidate_load_cache(f)
        got = self.json_api.load(f)
        exp = value if isinstance(value, dict) else {'v': value}
        self.assertEqual(got, exp)

    @settings(max_examples=200, deadline=None,
              suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(st.dictionaries(st.text(min_size=1, max_size=16), _json_values, max_size=6))
    def test_both_backends_agree(self, d):
        jf = self.json_api.CONFIG_FILE
        sf = self.sqlite_api.CONFIG_FILE
        self.json_api.save(jf, d); self.json_api._invalidate_load_cache(jf)
        self.sqlite_api.save(sf, d); self.sqlite_api._invalidate_load_cache(sf)
        self.assertEqual(self.json_api.load(jf), self.sqlite_api.load(sf),
                         'JSON and SQLite backends disagreed on a round-trip')


class TestPydanticValidateNeverCrashes(unittest.TestCase):
    """request_models.validate() must turn ANY body into either (True, None) or
    (False, message) — never a raw exception. Fuzz it with arbitrary dicts against
    a real model (BillingPaymentWebhookRequest: a required float + coerced strs)."""

    def setUp(self):
        import importlib
        self.rm = importlib.import_module('request_models')

    @given(st.dictionaries(st.text(max_size=12),
                           _json_scalars | st.lists(_json_scalars, max_size=4),
                           max_size=8))
    def test_arbitrary_body_is_ok_or_clean_error(self, body):
        ok, err = self.rm.validate(self.rm.BillingPaymentWebhookRequest, body)
        self.assertIsInstance(ok, bool)
        if ok:
            self.assertIsNone(err)
        else:
            self.assertIsInstance(err, str)
            self.assertTrue(err, 'a rejection must carry a non-empty message')


class TestAlertCoalesceInvariants(unittest.TestCase):
    """list_coalesce_or_append (the O(1) alert write path) must preserve the ledger
    shape under a stream of appends + coalesces on both DB backends."""

    def setUp(self):
        self.api = _fresh_api('sqlite')

    @settings(max_examples=60, deadline=None,
              suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(st.lists(st.integers(min_value=0, max_value=5), min_size=1, max_size=30))
    def test_row_count_never_exceeds_distinct_keys(self, key_stream):
        m = self.api._dbmod()
        f = self.api.ALERTS_FILE
        # Reset per example: Hypothesis runs many examples inside ONE setUp, so the
        # store would otherwise accumulate rows across them (the function_scoped_
        # fixture health-check warns about exactly this — a classic Hypothesis
        # stateful-fixture pitfall this workflow is meant to teach).
        self.api.save(f, {'alerts': []})
        self.api._invalidate_load_cache(f)
        # each integer is an alert "key"; coalesce merges a repeat, append adds new
        for k in key_stream:
            def coalesce(doc, _k=k):
                return doc if doc.get('key') == _k else None

            def build(meta, _k=k):
                return {'key': _k, 'count': 1}
            m.list_coalesce_or_append(f, coalesce, build, cap=100)
        rows = (self.api.load(f) or {}).get('alerts') or []
        distinct = len(set(key_stream))
        self.assertEqual(len(rows), distinct,
                         'coalesce/append produced the wrong number of rows')


if __name__ == '__main__':
    unittest.main()
