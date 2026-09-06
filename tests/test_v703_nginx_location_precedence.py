#!/usr/bin/env python3
"""A regex location beats a plain prefix location. Both shipped configs forgot.

`location ~* \\.(json|tmp)$ { deny all; }` was added to stop the data directory
being served if it ever landed inside the web root. It is a REGEX location, and
nginx resolves a request in this order:

    1. exact           `location = /x`      wins outright
    2. prefix with `^~`                     wins, and STOPS regex evaluation
    3. regex           `location ~ …`       first match in file order wins
    4. longest remembered prefix            only if no regex matched

`location /api/` carries neither `=` nor `^~`, so it is merely *remembered* and
the regex won. Three live paths were answered with 403 on every install:

    /api/openapi.json   both configs   the API reference the Swagger page fetches
    /manifest.json      Docker only    the PWA manifest
    /static/*.json      Docker only    any JSON asset

The bare-metal config escaped the last two by accident — it happens to have an
exact-match location for the manifest and `^~ /static/`, both added for
unrelated header reasons.

Verified against a real nginx 1.30 before and after the fix: `/api/openapi.json`
403 -> 200, and a stray `/leaked.json` in the document root still 403. This file
holds the same conclusion without needing nginx installed, and its control feeds
the model the OLD rule to prove the model can see the defect at all.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CONFIGS = {
    'bare-metal': _ROOT / 'server' / 'conf' / 'remotepower-locations.conf',
    'docker': _ROOT / 'docker' / 'nginx-docker-locations.conf',
}

_LOC = re.compile(r'^\s*location\s+(?:(=)\s+|(\^~)\s+|(~\*|~)\s+)?(\S+)\s*\{',
                  re.M)


def parse_locations(text):
    """[(kind, pattern)] in file order. kind: exact | stop_prefix | regex | prefix."""
    out = []
    for m in _LOC.finditer(text):
        eq, stop, rx, pat = m.groups()
        if eq:
            out.append(('exact', pat))
        elif stop:
            out.append(('stop_prefix', pat))
        elif rx:
            out.append(('regex', pat, rx == '~*'))
        else:
            out.append(('prefix', pat))
    return out


def resolve(locations, uri):
    """Which location nginx would use. Mirrors the documented algorithm."""
    for loc in locations:
        if loc[0] == 'exact' and loc[1] == uri:
            return loc
    best = None
    for loc in locations:
        if loc[0] in ('prefix', 'stop_prefix') and uri.startswith(loc[1]):
            if best is None or len(loc[1]) > len(best[1]):
                best = loc
    if best is not None and best[0] == 'stop_prefix':
        return best
    for loc in locations:
        if loc[0] == 'regex':
            flags = re.I if loc[2] else 0
            if re.search(loc[1], uri, flags):
                return loc
    return best


def _strip_nested_blocks(body):
    """Drop nested `{ … }` groups.

    `limit_except GET POST { deny all; }` restricts METHODS, not paths. A first
    version of this helper counted it as a path deny and reported `/api/home` —
    which a real nginx serves — as denied. The model was wrong, not the config.
    """
    out, depth = [], 0
    for ch in body:
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return ''.join(out)


def denies(text, uri):
    """True when the winning location for `uri` denies the request outright."""
    locs = parse_locations(text)
    win = resolve(locs, uri)
    if win is None:
        return False
    # Find that block's body and look for `deny all`.
    for m in _LOC.finditer(text):
        pat = m.group(4)
        kind = ('exact' if m.group(1) else 'stop_prefix' if m.group(2)
                else 'regex' if m.group(3) else 'prefix')
        if pat == win[1] and kind == win[0]:
            depth, i = 0, m.end() - 1
            while i < len(text):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            return 'deny all' in _strip_nested_blocks(text[m.end():i])
    return False


# Paths the app actually answers, which must never hit a deny block.
_MUST_SERVE = (
    '/api/openapi.json',
    '/api/home',
    '/manifest.json',
    '/static/js/app.js',
    '/static/vendor/swagger-ui/swagger-ui-bundle.min.js',
)

# Paths the deny block exists for.
_MUST_DENY = (
    '/devices.json',
    '/alerts.json',
    '/config.tmp',
    '/cgi-bin/api.py',
)


class TestNoLiveRouteIsDeniedByARegexLocation(unittest.TestCase):

    def test_every_real_route_is_served(self):
        for label, path in _CONFIGS.items():
            text = path.read_text()
            for uri in _MUST_SERVE:
                with self.subTest(config=label, uri=uri):
                    self.assertFalse(
                        denies(text, uri),
                        f"{label}: {uri} resolves to a `deny all` location. A "
                        "regex location outranks every plain prefix — only `=` "
                        "and `^~` beat it.")

    def test_the_deny_block_still_bites(self):
        """The other direction. A fix that simply deletes the rule passes the
        test above and removes the protection it was added for."""
        for label, path in _CONFIGS.items():
            text = path.read_text()
            for uri in _MUST_DENY:
                with self.subTest(config=label, uri=uri):
                    self.assertTrue(
                        denies(text, uri),
                        f"{label}: {uri} is no longer denied — a stray data "
                        "file in the web root would be served")


class TestTheModelCanSeeTheDefect(unittest.TestCase):
    """The control. A precedence model that always returns "served" passes the
    first test while measuring nothing."""

    _OLD = '''
location /api/ {
    proxy_pass http://127.0.0.1:8090;
}
location ^~ /static/ {
    expires 1y;
}
location / {
    try_files $uri /index.html;
}
location ~* \\.(json|tmp)$ {
    deny all;
}
'''

    def test_the_old_rule_is_reported_as_denying_the_api_reference(self):
        self.assertTrue(denies(self._OLD, '/api/openapi.json'),
                        "the model no longer reproduces the shipped bug, so it "
                        "cannot be trusted to say the fix works")

    def test_the_old_rule_still_served_what_it_should(self):
        self.assertFalse(denies(self._OLD, '/api/home'))
        self.assertFalse(denies(self._OLD, '/static/js/app.js'))

    def test_precedence_order_is_the_documented_one(self):
        locs = parse_locations(
            'location = /a { }\nlocation ^~ /b/ { }\n'
            'location ~ ^/c { }\nlocation /c { }\nlocation / { }\n')
        self.assertEqual(resolve(locs, '/a')[0], 'exact')
        self.assertEqual(resolve(locs, '/b/x')[0], 'stop_prefix')
        # A regex beats the longer plain prefix — the whole point.
        self.assertEqual(resolve(locs, '/c')[0], 'regex')


if __name__ == '__main__':
    unittest.main()
