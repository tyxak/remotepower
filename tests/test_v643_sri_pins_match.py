#!/usr/bin/env python3
"""An SRI hash that does not match its file makes the browser refuse the file.

`swagger.html` pins sha384 Subresource Integrity for the vendored Swagger UI
bundle and stylesheet. That is the right call for a third-party blob. It also
means updating the vendored file WITHOUT recomputing the hash does not degrade
gracefully: the browser refuses the resource outright and the page renders
blank, with the only evidence a console message nobody sees in CI.

That is not hypothetical. Bumping swagger-ui 5.32.6 -> 5.32.13 for the DOMPurify
advisories did exactly this on the first attempt — both files replaced, both
hashes stale, API Reference completely blank. A file-level diff looked perfect.

So: every SRI pin in every served HTML page must match the file it pins. Cheap,
and it catches the one failure mode that a vendored-file update reliably
produces.
"""
import base64
import hashlib
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML_DIR = _ROOT / 'server' / 'html'

_TAG = re.compile(
    r'<(?:script|link)\b[^>]*?(?:src|href)="(/static/[^"?]+)[^"]*"[^>]*?'
    r'integrity="(sha(?:256|384|512))-([A-Za-z0-9+/=]+)"', re.S)
_TAG_REV = re.compile(
    r'<(?:script|link)\b[^>]*?integrity="(sha(?:256|384|512))-([A-Za-z0-9+/=]+)"'
    r'[^>]*?(?:src|href)="(/static/[^"?]+)[^"]*"', re.S)


def _pins():
    out = []
    for page in sorted(_HTML_DIR.glob('*.html')):
        src = page.read_text()
        for m in _TAG.finditer(src):
            out.append((page.name, m.group(1), m.group(2), m.group(3)))
        for m in _TAG_REV.finditer(src):
            out.append((page.name, m.group(3), m.group(1), m.group(2)))
    # de-duplicate (a tag can match both orderings)
    return sorted(set(out))


class TestEverySriPinMatchesItsFile(unittest.TestCase):
    def test_there_are_pins_to_check(self):
        """Positive control. If the regex stops matching — an attribute order
        changes, a quote style changes — every assertion below passes over an
        empty list and this file silently stops guarding anything."""
        self.assertGreaterEqual(len(_pins()), 2,
                                'no SRI-pinned resources found; has the markup '
                                'changed shape?')

    def test_each_pinned_file_exists(self):
        for page, path, _alg, _digest in _pins():
            with self.subTest(page=page, resource=path):
                self.assertTrue((_HTML_DIR / path.lstrip('/')).is_file(),
                                f'{page} pins {path}, which is not in the tree')

    def test_each_hash_matches_the_file_on_disk(self):
        bad = []
        for page, path, alg, digest in _pins():
            f = _HTML_DIR / path.lstrip('/')
            if not f.is_file():
                continue
            want = base64.b64encode(
                hashlib.new(alg, f.read_bytes()).digest()).decode()
            if want != digest:
                bad.append(f'{page}: {path}\n      pinned {alg}-{digest}\n'
                           f'      actual {alg}-{want}')
        self.assertEqual(bad, [], '\n'.join([
            'These SRI pins do not match their files. The browser will REFUSE '
            'the resource and the page will render blank:', *('  ' + b for b in bad),
            '',
            'Recompute with:  openssl dgst -sha384 -binary <file> | openssl base64 -A']))


if __name__ == '__main__':
    unittest.main()
