#!/usr/bin/env python3
"""A monitor that says only "403" sends the operator to the wrong place.

The bug this release opens with: a monitor pointed at a host behind Cloudflare
failed continuously while the same URL loaded fine in a browser. Two causes,
both fixed — the probe identified itself as `Python-urllib` and it was putting
an older TLS version back on the wire. What the operator saw either way was a
bare `403`, which reads exactly like a host that is down, and the origin's
access log had nothing in it because the request never arrived.

The response already said who refused it. Cloudflare sets `cf-mitigated` on a
challenge and identifies itself in `server`. The monitor detail now says so.

The rule kept here is the restraint: only claim an edge refusal when a header
actually says so. A guard that cannot distinguish two causes must not name one —
this project shipped a patching guard that blamed systemd for a healthy Arch
kernel upgrade, and that is the same mistake pointed the other way.

Also pinned: `except Exception: detail = 'error'` named nothing at all, and a
DNS failure, a refused connection and a timeout are different problems with
different first moves.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from email.message import Message
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v703-edge-'))
for _k, _v in (('REQUEST_METHOD', 'GET'), ('PATH_INFO', '/'),
               ('CONTENT_LENGTH', '0')):
    os.environ.setdefault(_k, _v)
_spec = importlib.util.spec_from_file_location('api_v703_edge', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _headers(**kw):
    """A real email.message.Message, which is what HTTPError.headers is."""
    m = Message()
    for k, v in kw.items():
        m[k.replace('_', '-')] = v
    return m


class TestTheEdgeIsNamedWhenItSaysSo(unittest.TestCase):

    def test_cf_mitigated_is_reported_with_its_own_word(self):
        d = api._edge_refusal_detail(403, _headers(cf_mitigated='challenge'))
        self.assertIsNotNone(d)
        self.assertIn('403', d)
        self.assertIn('challenge', d,
                      'pass the edge\'s own word through — it is what the edge '
                      'dashboard shows')
        self.assertIn('origin', d)

    def test_a_cloudflare_403_without_the_header_is_still_named(self):
        d = api._edge_refusal_detail(403, _headers(server='cloudflare'))
        self.assertIsNotNone(d)
        self.assertIn('Cloudflare', d)

    def test_a_503_from_cloudflare_counts_too(self):
        self.assertIsNotNone(
            api._edge_refusal_detail(503, _headers(server='cloudflare')))


class TestItDoesNotGuess(unittest.TestCase):
    """The restraint half. Naming a cause you do not have is the failure this
    release is about."""

    def test_a_plain_403_from_the_origin_is_not_blamed_on_an_edge(self):
        self.assertIsNone(api._edge_refusal_detail(403, _headers()))
        self.assertIsNone(api._edge_refusal_detail(403, _headers(server='nginx')))

    def test_a_cloudflare_404_is_the_origins_answer_not_a_refusal(self):
        """Cloudflare fronts the site for every response it proxies. A 404 came
        FROM the origin through it, and calling that an edge refusal would send
        the operator away from the real problem."""
        self.assertIsNone(
            api._edge_refusal_detail(404, _headers(server='cloudflare')))

    def test_missing_or_broken_headers_never_raise(self):
        for h in (None, object()):
            self.assertIsNone(api._edge_refusal_detail(403, h))

    def test_a_hostile_header_value_cannot_stretch_the_detail(self):
        d = api._edge_refusal_detail(403, _headers(cf_mitigated='x' * 500))
        self.assertLess(len(d), 200, 'the header value must be bounded')


class TestTheProbeUsesIt(unittest.TestCase):

    def _probe_source(self):
        import ast
        tree = ast.parse((_CGI / 'api.py').read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and '_edge_refusal_detail(' in ast.unparse(node)
                    and node.name != '_edge_refusal_detail'):
                return ast.unparse(node)
        self.fail('no probe calls _edge_refusal_detail')

    def test_the_http_error_branch_calls_it(self):
        src = self._probe_source()
        self.assertIn('_edge_refusal_detail(e.code', src)
        self.assertIn('or str(e.code)', src,
                      'fall back to the bare status when the response does not '
                      'say who refused')

    def test_the_generic_http_failure_names_the_exception(self):
        """Scoped to the HTTP branch. The ping and tcp branches have their own
        `detail = 'error'` / `'closed'`, which are accurate for what they
        measure — a blanket assertion over the whole function would fail on
        those and say nothing about this one."""
        src = self._probe_source()
        http = src[src.index("elif mtype == 'http':"):]
        http = http[:http.index("elif mtype == 'http_flow'")]
        self.assertNotIn("detail = 'error'", http,
                         "'error' names nothing; a DNS failure, a refused "
                         'connection and a timeout are different problems')
        self.assertIn('type(e).__name__', http)


if __name__ == '__main__':
    unittest.main()
