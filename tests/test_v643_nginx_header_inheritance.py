"""v6.4.3 pentest: two nginx locations silently dropped every security header.

nginx's `add_header` does not merge — a location that sets ANY add_header
discards every add_header inherited from the enclosing server block. The shipped
config knows this: it says so in a comment above `location /` ("do NOT add_header
here"), and again above `location ^~ /static/`, which re-emits the whole security
set for exactly this reason.

Two locations set a caching header and never re-emitted the set:

  * ``= /sw.js`` — the SERVICE WORKER. A service worker's own execution context
    takes its policy from the headers on the script response, so serving it
    without a Content-Security-Policy runs a persistent, origin-scoped,
    network-intercepting context with no policy at all. Of everything on this
    server it is the single worst response to send unrestricted.
  * ``= /manifest.json`` — sets an explicit Content-Type and then drops
    `X-Content-Type-Options: nosniff`, which is precisely the defence for a
    JSON response a browser might sniff.

Neither is a high-severity hole on its own — both are defence-in-depth, and the
document CSP still governs the page that registers the worker. They are worth
fixing because they are free, and worth a gate because the trap is invisible in
review: each location reads as correct in isolation, and the header loss happens
in nginx's merge rules rather than in anything written in the file.

The gate is therefore structural, not a list of known-bad locations: ANY location
that emits an add_header must emit the full security set.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CONFS = [
    _ROOT / "server" / "conf" / "remotepower-locations.conf",
    _ROOT / "docker" / "nginx-docker-locations.conf",
]

# The set a response must carry. Kept deliberately short: these are the ones the
# server block emits, so "re-emit what you dropped" is the whole rule.
_REQUIRED = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)

# Locations that legitimately emit no body a browser renders or executes.
_EXEMPT_PATTERNS = (
    # A download of the CA certificate: an attachment, not a document, and it
    # sets Content-Disposition rather than a cache policy.
    "ca.crt",
)


def _locations(text):
    """[(location-spec, body)] for every location block that has a body."""
    out = []
    for m in re.finditer(r"location\s+([^\s{]+(?:\s+[^\s{]+)?)\s*\{", text):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        out.append((m.group(1).strip(), text[start : i - 1]))
    return out


def _strip_comments(body):
    return "\n".join(ln for ln in body.splitlines() if not ln.strip().startswith("#"))


class TestTheParserSeesTheConfig(unittest.TestCase):
    """Positive controls — this reads live config with a hand-rolled brace
    walker, and a silent parse failure would make every check below vacuous."""

    def setUp(self):
        self.confs = [c for c in _CONFS if c.exists()]
        if not self.confs:
            self.skipTest("nginx config excluded from this tree")

    def test_locations_are_found(self):
        for c in self.confs:
            locs = _locations(c.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(locs), 5, f"{c.name}: parsed {len(locs)}")

    def test_the_known_good_location_is_seen_as_compliant(self):
        """`/static/` deliberately re-emits the full set. If the checker cannot
        see that, it is not measuring what it claims to."""
        for c in self.confs:
            for spec, body in _locations(c.read_text(encoding="utf-8")):
                if "/static/" in spec:
                    for h in _REQUIRED:
                        self.assertIn(h, body, f"{c.name} {spec} missing {h}")
                    return
        self.skipTest("no /static/ location in these configs")

    def test_at_least_one_location_emits_add_header(self):
        found = any(
            "add_header" in body
            for c in self.confs
            for _spec, body in _locations(c.read_text(encoding="utf-8"))
        )
        self.assertTrue(found, "no add_header seen at all — parser is broken")


class TestEveryAddHeaderLocationReEmitsTheSecuritySet(unittest.TestCase):
    def setUp(self):
        self.confs = [c for c in _CONFS if c.exists()]
        if not self.confs:
            self.skipTest("nginx config excluded from this tree")

    def test_no_location_silently_drops_the_headers(self):
        offenders = []
        for c in self.confs:
            for spec, body in _locations(c.read_text(encoding="utf-8")):
                body = _strip_comments(body)
                if "add_header" not in body:
                    continue  # inherits the server-level set intact
                if any(p in spec or p in body for p in _EXEMPT_PATTERNS):
                    continue
                missing = [h for h in _REQUIRED if h not in body]
                if missing:
                    offenders.append(f"{c.name} `location {spec}` is missing {missing}")
        self.assertEqual(
            [],
            offenders,
            "nginx discards EVERY inherited add_header in a location that sets "
            "one of its own, so these responses ship with no security headers "
            "at all:\n  " + "\n  ".join(offenders),
        )

    def test_the_service_worker_carries_a_policy(self):
        """Named explicitly: a service worker takes its execution policy from
        the headers on its own script response, and it is the most privileged
        thing this origin serves."""
        for c in self.confs:
            for spec, body in _locations(c.read_text(encoding="utf-8")):
                if spec.replace(" ", "").endswith("/sw.js"):
                    self.assertIn(
                        "Content-Security-Policy",
                        _strip_comments(body),
                        f"{c.name}: the service worker is served with no CSP",
                    )


if __name__ == "__main__":
    unittest.main()
