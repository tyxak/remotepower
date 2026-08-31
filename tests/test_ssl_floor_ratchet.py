#!/usr/bin/env python3
"""No bare `x.minimum_version = …` in the shipped sources — hold the class at 0.

A TLS floor written as a plain assignment sets it in BOTH directions: it lifts
a permissive host up to 1.2 and drops a host the operator pinned to 1.3 back
down to it. That shipped in `_get_ssl_context()` and took monitoring with it —
putting TLS 1.2 back into the ClientHello changes the JA3/JA4 fingerprint, and
Cloudflare Bot Fight Mode answers the result with 403 `cf-mitigated:
challenge`, so every monitor on a Cloudflare-fronted host read as down. The fix
is one line ahead of the assignment:

    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

That fix landed at one site. Ten more carried the same bare assignment, each
with a comment saying it was a floor — a rule applied in most places and missed
in the rest, which is the shape that survives review because the correct sites
make the file read as though it is enforced. This gate covers the class rather
than the site: every assignment to `.minimum_version` under server/ and client/
must sit inside an `if …minimum_version < …:` guard, or be named in
ALLOWED_BARE with its reason.

The controls matter as much as the rule. An AST walk that stops matching — a
renamed attribute, a new idiom, a parse that silently fails — finds nothing and
reports success. So the population, a known-good guarded site, and the
allowlist's own premises are all asserted before any verdict is trusted.
"""
import ast
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

# Sites that LOWER the floor for a legacy appliance class, on purpose. Both are
# self-signed LAN boxes where the trust model is "LAN + API credentials", not
# the certificate, and both sit beside a matching `set_ciphers(SECLEVEL=1)`.
#
# An exemption is not permanent. If either site stops needing it, delete the
# entry — test_allowlisted_sites_are_still_bare fails on a stale one rather
# than letting it sit here unread.
ALLOWED_BARE = {
    'server/cgi-bin/routeros.py':
        'old RouterOS firmware negotiates TLS 1.0 only; the site drops to '
        'TLSv1 to match `curl -k`, with cert verification already off',
    'server/cgi-bin/opnsense.py':
        'OPNsense default self-signed cert and occasionally legacy TLS — same '
        'LAN-plus-credentials trust model as routeros.py',
}

# The extensionless agent is a byte-identical copy of the .py and ships as the
# executable, so it is part of the class even though it does not glob as *.py.
_EXTRA_FILES = ('client/remotepower-agent',)

_GUARD_IDIOM = (
    "    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:\n"
    "        ctx.minimum_version = ssl.TLSVersion.TLSv1_2")


def _candidate_files():
    """Every shipped source that mentions the attribute at all.

    Filtering on the ATTRIBUTE is filtering on the population; filtering on
    "files that lack the guard" would be filtering on the symptom, and would
    empty itself as the fix is applied.
    """
    out = []
    for top in ('server', 'client'):
        d = _ROOT / top
        if not d.is_dir():
            continue                       # excluded from the dist tree
        out.extend(p for p in sorted(d.rglob('*.py'))
                   if '__pycache__' not in p.parts)
    out.extend(_ROOT / rel for rel in _EXTRA_FILES)
    keep = []
    for p in out:
        if not p.is_file():
            continue
        try:
            if 'minimum_version' in p.read_text(encoding='utf-8', errors='replace'):
                keep.append(p)
        except OSError:
            continue
    return keep


def _guarded_assign_ids(tree):
    """ids of Assign nodes sitting under an `if <…>.minimum_version < …:`."""
    guarded = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            continue
        if not isinstance(test.ops[0], (ast.Lt, ast.LtE)):
            continue
        left = test.left
        if not (isinstance(left, ast.Attribute) and left.attr == 'minimum_version'):
            continue
        for stmt in node.body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Assign):
                    guarded.add(id(sub))
    return guarded


def _scan(path):
    """(bare_linenos, total_sites) for one file."""
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    guarded = _guarded_assign_ids(tree)
    bare, total = [], 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Attribute) and t.attr == 'minimum_version'
                   for t in node.targets):
            continue
        total += 1
        if id(node) not in guarded:
            bare.append(node.lineno)
    return bare, total


def _survey():
    """rel path -> (bare linenos, total sites), for every file with a site."""
    out = {}
    for p in _candidate_files():
        bare, total = _scan(p)
        if total:
            out[p.relative_to(_ROOT).as_posix()] = (bare, total)
    return out


class TestTLSFloorIsRaisedNeverAssigned(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.survey = _survey()

    # ---------------------------------------------------------------- the rule
    def test_no_bare_minimum_version_assignment(self):
        offenders = {rel: bare for rel, (bare, _) in self.survey.items()
                     if bare and rel not in ALLOWED_BARE}
        self.assertEqual(
            offenders, {},
            "a TLS floor was written as an assignment, which also LOWERS a "
            "host pinned above it:\n"
            + "\n".join(f"  {rel}:{','.join(map(str, ls))}"
                        for rel, ls in sorted(offenders.items()))
            + "\n\nRaise it instead:\n" + _GUARD_IDIOM
            + "\n\nIf the site lowers the floor on purpose for a legacy "
              "appliance, add it to ALLOWED_BARE in this file with a reason.")

    # -------------------------------------------------------------- the controls
    def test_population_is_not_empty(self):
        """A walk that matches nothing would pass every assertion above it."""
        files = len(self.survey)
        sites = sum(total for _, total in self.survey.values())
        self.assertGreaterEqual(
            files, 9,
            f"only {files} files with a minimum_version assignment were found "
            f"({sorted(self.survey)}). The AST walk has stopped seeing the "
            "class — fix the scan before trusting the verdict.")
        self.assertGreaterEqual(
            sites, 10,
            f"only {sites} assignment sites found across {files} files; the "
            "scan is measuring less than the class it is supposed to hold.")

    def test_a_known_good_site_is_recognised_as_guarded(self):
        """Positive control: prove the guard detector can say 'guarded'.

        Without this, a detector that marked EVERYTHING unguarded would still
        pass the rule for any file in ALLOWED_BARE, and a detector that marked
        everything guarded would pass it for all of them.
        """
        api = self.survey.get('server/cgi-bin/api.py')
        self.assertIsNotNone(api, "api.py no longer registers a site at all")
        bare, total = api
        self.assertGreaterEqual(
            total, 1, "api.py no longer contains the assignment the scan is "
                      "supposed to see — _raise_tls_floor() owns the only one")
        self.assertEqual(bare, [], "api.py has an unguarded site again")

    def test_the_detector_can_still_say_unguarded(self):
        """Negative control: a bare assignment must be reported as bare.

        Parsed from a literal here rather than a file, so the two directions of
        the detector are both exercised on every run.
        """
        tree = ast.parse("import ssl\nctx.minimum_version = ssl.TLSVersion.TLSv1_2\n")
        self.assertEqual(len(_guarded_assign_ids(tree)), 0)
        guarded = ast.parse(
            "import ssl\n"
            "if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:\n"
            "    ctx.minimum_version = ssl.TLSVersion.TLSv1_2\n")
        self.assertEqual(len(_guarded_assign_ids(guarded)), 1)

    def test_extensionless_agent_is_in_the_population(self):
        """It ships as the executable and does not glob as *.py."""
        if not (_ROOT / 'client' / 'remotepower-agent').is_file():
            self.skipTest('extensionless agent not present in this tree')
        self.assertIn('client/remotepower-agent', self.survey,
                      "the extensionless agent copy dropped out of the scan — "
                      "it is a byte-identical copy of the .py and carries the "
                      "same site")

    def test_allowlisted_sites_are_still_bare(self):
        """A stale exemption is a finding, not a harmless leftover."""
        for rel, reason in sorted(ALLOWED_BARE.items()):
            if not (_ROOT / rel).is_file():
                continue                   # excluded from the dist tree
            entry = self.survey.get(rel)
            self.assertIsNotNone(
                entry, f"{rel} is exempted but no longer has a site at all — "
                       "delete its ALLOWED_BARE entry")
            bare, _total = entry
            self.assertTrue(
                bare, f"{rel} is exempted as lowering the floor on purpose "
                      f"({reason}) but every site in it is now guarded — "
                      "delete its ALLOWED_BARE entry")


if __name__ == '__main__':
    unittest.main()
