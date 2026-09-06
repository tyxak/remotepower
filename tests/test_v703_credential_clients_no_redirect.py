#!/usr/bin/env python3
"""Every outbound client that carries a credential must refuse a 3xx.

The rule is old and was written down inside `client/remotepower-scanner.py`:
"_api posts the satellite TOKEN, so a redirect must never replay it to another
host." That comment then asserted the class was closed — "every other
RemotePower component that carries a credential does this ... the scanner was
the lone outlier."

It was not closed. `mcp/remotepower-mcp.py` sent the RemotePower API token in
BOTH `X-Token` and `Authorization` through `urllib.request.urlopen`, which is
the default opener, which follows redirects. Reproduced with two loopback
servers: the redirect target received both headers in full. Two sidecar clients
carrying a shared secret were on the default opener as well.

A prose claim of completeness is how the next one is missed. This enumerates
instead: every module that attaches a credential header to an outbound request
must build an opener that refuses redirects, and the enumeration has a control
so it cannot go blind.
"""
import ast
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

# Where the product's own outbound clients live. The population is DERIVED from
# these directories rather than listed, because a list is the thing that goes
# stale — the MCP client existed for releases while a comment elsewhere said the
# class was closed. Sweeping every .py would drag in the request-HANDLING side,
# where "redirect" means something else entirely.
_CLIENT_DIRS = ('client', 'mcp', 'server/webterm', 'server/kmip',
                'server/push', 'server/flow', 'server/syslog')

# Building a Request or opening an HTTPS connection is what makes a file a
# client. Every one of these carries something worth stealing — a device token,
# an API token, a shared secret, or an ingest payload — in a header, a body or
# the URL path, so the rule is the same for all of them and the population does
# not have to guess which.
_MAKES_REQUESTS = re.compile(
    r'(?:urllib\.)?request\.Request\(|HTTPSConnection\(')

# Both import idioms ship here: `import urllib.request` in most modules and
# `from urllib import request` in the Linux agent. A first version of this
# pattern knew only the first and reported the agent — which has refused
# redirects since v4 — as unguarded. The instrument was wrong before the code.
_REFUSES_REDIRECTS = re.compile(
    r'class\s+\w*NoRedirect\w*\s*\(\s*(?:urllib\.)?request\.'
    r'HTTPRedirectHandler\s*\)')

_DEFAULT_OPENER = re.compile(r'(?:urllib\.)?request\.urlopen\s*\(')


def credential_bearing_clients():
    """Every file under the client directories that makes an outbound request.

    The extensionless agent copy is skipped: it is a byte-identical duplicate of
    the .py, gated by its own test, and counting it twice makes the ratio lie.
    """
    out = []
    for d in _CLIENT_DIRS:
        base = _ROOT / d
        if not base.exists():
            continue
        for path in sorted(base.rglob('*')):
            if not path.is_file() or path.name == 'remotepower-agent':
                continue
            try:
                src = path.read_text(encoding='utf-8')
            except (OSError, UnicodeDecodeError):
                continue
            if _MAKES_REQUESTS.search(src):
                out.append((str(path.relative_to(_ROOT)), src))
    return out


class TestNoCredentialRidesARedirect(unittest.TestCase):

    def test_every_credential_client_defines_a_no_redirect_handler(self):
        missing = [rel for rel, src in credential_bearing_clients()
                   if not _REFUSES_REDIRECTS.search(src)]
        self.assertEqual(
            missing, [],
            'these clients make outbound requests carrying a token, a secret '
            'or an ingest payload and do not refuse 3xx, so a redirect sends '
            f'it wherever the redirect points: {missing}')

    def test_no_credential_client_still_calls_the_default_opener(self):
        """Defining the handler is not using it. `urlopen` is the DEFAULT
        opener and follows redirects however many custom openers exist in the
        file."""
        offenders = []
        for rel, src in credential_bearing_clients():
            for i, line in enumerate(src.splitlines(), 1):
                stripped = line.lstrip()
                if stripped.startswith('#') or stripped.startswith('"""'):
                    continue
                if _DEFAULT_OPENER.search(line):
                    offenders.append(f'{rel}:{i}')
        self.assertEqual(
            offenders, [],
            'urllib.request.urlopen is the default opener and follows '
            f'redirects — use the module opener instead: {offenders}')


class TestTheEnumerationIsHonest(unittest.TestCase):
    """Both assertions above are "this list is empty", which is exactly what a
    broken detector produces."""

    def test_the_derivation_finds_every_client_we_know_of(self):
        rels = [rel for rel, _ in credential_bearing_clients()]
        for known in ('client/remotepower-agent.py',
                      'client/remotepower-agent-win.py',
                      'client/remotepower-agent-mac.py',
                      'client/remotepower-scanner.py',
                      'client/remotepower-satellite.py',
                      'mcp/remotepower-mcp.py',
                      'server/webterm/remotepower-webterm.py',
                      'server/kmip/remotepower-kmipd.py',
                      'server/flow/remotepower-flowd.py',
                      'server/syslog/remotepower-syslogd.py'):
            self.assertIn(known, rels,
                          f'{known} makes outbound requests and the derivation '
                          'no longer sees it')
        self.assertGreaterEqual(len(rels), 10, rels)

    def test_the_detectors_recognise_the_shapes_they_look_for(self):
        self.assertTrue(_MAKES_REQUESTS.search('req = urllib.request.Request(u)'))
        self.assertTrue(_MAKES_REQUESTS.search('c = HTTPSConnection(host)'))
        self.assertFalse(_MAKES_REQUESTS.search('x = json.dumps(body)'))
        self.assertTrue(_REFUSES_REDIRECTS.search(
            'class _NoRedirect(urllib.request.HTTPRedirectHandler):'))
        self.assertTrue(_REFUSES_REDIRECTS.search(
            'class _NoRedirect(request.HTTPRedirectHandler):'),
            'the `from urllib import request` idiom must be recognised too')
        self.assertFalse(_REFUSES_REDIRECTS.search('class _Thing(object):'))
        self.assertTrue(_DEFAULT_OPENER.search(
            '    with urllib.request.urlopen(req) as r:'))
        self.assertTrue(_DEFAULT_OPENER.search('    request.urlopen(req)'))


if __name__ == '__main__':
    unittest.main()
