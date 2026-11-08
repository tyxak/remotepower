#!/usr/bin/env python3
"""8.0.0: one reading of the proxy's scheme header, and one place for the link builders' fallback.

Five places decided whether a request came in over http or https, and no two read `X-Forwarded-Proto` the same way. The install links and the portal link took it raw (so `HTTPS`
in capitals, or a chain such as `https, http`, fell through to a guess), WebAuthn took it raw and built the origin `https, http://host` out of a chain, and the SAML and OIDC
callbacks lower-cased it but dropped a chain. The link builder also spelled its fallback as `'https' if HTTPS in ('on', '1') else 'https'`, three times, with the same word in both
arms. All five now read the header through `_scheme_word`, and the three link builders share `_scheme_of`. What each does when nobody says anything stays as it was, because the
reasons differ: a link that guessed http would carry an enrolment token in clear, WebAuthn compares against the origin the browser reports (plain http on a local box), and the
identity providers want https.

The table is driven through the real functions; the source checks derive their population from the syntax tree, not from a list kept here.
"""
import ast
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v800sch-"))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402

HOST = "rp.test"

# (what the request carries, the link builders, WebAuthn, SAML and OIDC)
CASES = [
    ("nothing says", {}, "https", "http", "https"),
    ("proxy says http", {"HTTP_X_FORWARDED_PROTO": "http"}, "http", "http", "http"),
    ("proxy says https", {"HTTP_X_FORWARDED_PROTO": "https"}, "https", "https", "https"),
    ("proxy writes it in capitals", {"HTTP_X_FORWARDED_PROTO": "HTTPS"}, "https", "https", "https"),
    ("proxy pads it", {"HTTP_X_FORWARDED_PROTO": " http "}, "http", "http", "http"),
    ("a chain, client side first: https", {"HTTP_X_FORWARDED_PROTO": "https, http"}, "https", "https", "https"),
    ("a chain, client side first: http", {"HTTP_X_FORWARDED_PROTO": "http, https"}, "http", "http", "http"),
    ("the header is not a scheme", {"HTTP_X_FORWARDED_PROTO": "javascript"}, "https", "http", "https"),
    ("the server holds TLS", {"HTTPS": "on"}, "https", "https", "https"),
    ("the server says it does not", {"HTTPS": "off"}, "https", "http", "http"),
    ("only the link builders read REQUEST_SCHEME", {"REQUEST_SCHEME": "http"}, "http", "http", "https"),
    ("the proxy outranks REQUEST_SCHEME", {"HTTP_X_FORWARDED_PROTO": "https", "REQUEST_SCHEME": "http"}, "https", "https", "https"),
    ("a header that is not a scheme falls through to REQUEST_SCHEME", {"HTTP_X_FORWARDED_PROTO": "javascript", "REQUEST_SCHEME": "http"}, "http", "http", "https"),
]


def _grab(pattern, text):
    m = re.search(pattern, text)
    assert m, f"{pattern} not found in the rendered script"
    return m.group(1)


class _WithEnv(unittest.TestCase):
    def _fake_env(self, env):
        full = {"HTTP_HOST": HOST, **env}
        return mock.patch.object(api, "_env", lambda k, d=None: full.get(k, d))


class TestTheLinkBuildersAgree(_WithEnv):
    def test_the_portal_link_the_sh_installer_and_the_ps1_installer_use_the_same_scheme(self):
        for label, env, want_link, *_ in CASES:
            full = {"HTTP_HOST": HOST, **env}
            # `_request_base_url` falls back to the live environment for a key the dict lacks, and other modules leave request variables in it
            with self.subTest(case=label), self._fake_env(env):
                self.assertEqual(api._request_base_url(full), f"{want_link}://{HOST}")
                sh = _grab(r'RP_SERVER="([^"]+)"', api._render_agent_install(full))
                ps = _grab(r"\$Server = '([^']+)'", api._render_win_install(full))
                self.assertEqual((sh, ps), (f"{want_link}://{HOST}", f"{want_link}://{HOST}"))

    def test_a_link_never_guesses_plain_http_for_a_request_that_said_nothing(self):
        self.assertEqual(api._scheme_of({}.get), "https")


class TestTheWebAuthnOriginAndTheIdentityProviderCallbacks(_WithEnv):
    def test_webauthn_origin(self):
        for label, env, _link, want, _idp in CASES:
            with self.subTest(case=label), self._fake_env(env), mock.patch.object(api, "load", lambda *_a, **_k: {}):
                rp_id, origin = api._webauthn_rp()
                self.assertEqual((rp_id, origin), (HOST, f"{want}://{HOST}"))

    def test_saml_base_url_and_oidc_callback(self):
        for label, env, _link, _wa, want in CASES:
            with self.subTest(case=label), self._fake_env(env):
                self.assertEqual(api._saml_base_url(), f"{want}://{HOST}")
                self.assertEqual(api._oidc_redirect_uri(), f"{want}://{HOST}/api/auth/oidc/callback")

    def test_the_configured_webauthn_origin_still_wins(self):
        with self._fake_env({"HTTP_X_FORWARDED_PROTO": "http"}), mock.patch.object(api, "load", lambda *_a, **_k: {"webauthn_origin": "https://sso.example", "webauthn_rp_id": "example"}):
            self.assertEqual(api._webauthn_rp(), ("example", "https://sso.example"))


class TestTheHeaderParser(unittest.TestCase):
    def test_what_it_accepts_and_what_it_ignores(self):
        for raw, want in [("http", "http"), ("https", "https"), ("HTTPS", "https"), (" Http ", "http"), ("https,http", "https"), ("http , https", "http"), ("", ""), (None, ""), ("ws", ""), ("httpss", ""), ("https://x", ""), (5, "")]:
            with self.subTest(raw=raw):
                self.assertEqual(api._scheme_word(raw), want)


def _module_functions():
    tree = ast.parse((_ROOT / "server" / "cgi-bin" / "api.py").read_text())
    return [n for n in tree.body if isinstance(n, ast.FunctionDef)]


def _constants(fn):
    return {n.value for n in ast.walk(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _calls(fn):
    return {n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}


class TestNoScopeReadsTheHeaderItsOwnWay(unittest.TestCase):
    """Every function that names the header goes through `_scheme_word`, and the REQUEST_SCHEME fallback lives in one function."""

    def test_every_reader_of_the_header_parses_it_with_the_shared_function(self):
        readers = [f for f in _module_functions() if "HTTP_X_FORWARDED_PROTO" in _constants(f) and f.name != "_scheme_word"]
        names = sorted(f.name for f in readers)
        # the control: the population must contain the places known to read it, or this passes over nothing
        for known in ("_scheme_of", "_webauthn_rp", "_saml_base_url", "_oidc_redirect_uri"):
            self.assertIn(known, names, f"the scan no longer sees {known}: {names}")
        offenders = [f.name for f in readers if "_scheme_word" not in _calls(f)]
        self.assertEqual(offenders, [], f"{len(offenders)} of {len(readers)} readers of the header parse it themselves")

    def test_request_scheme_is_spelled_in_one_function(self):
        spelled = sorted(f.name for f in _module_functions() if "REQUEST_SCHEME" in _constants(f))
        self.assertEqual(spelled, ["_scheme_of"])

    def test_the_three_link_builders_call_it(self):
        callers = {f.name for f in _module_functions() if "_scheme_of" in _calls(f)}
        self.assertTrue({"_request_base_url", "_render_agent_install", "_render_win_install"} <= callers, callers)


if __name__ == "__main__":
    unittest.main()
