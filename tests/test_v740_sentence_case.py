#!/usr/bin/env python3
"""7.4.0: card headings and action buttons are in sentence case.

The typography rule has said so since v7.1.0 ("Card/panel headers use .section-title ... plain 13px
sentence-case ink heading"), and it was kept for most of the interface: "Network Metrics", "Server
status", "Knowledge base". Eighteen strings had slipped through in Title Case ("Listening Ports",
"Top Processes", "Print / Save as PDF", the host drawer's "System Info" and "Drift State"). Each is a
dictionary key, so re-casing one means re-keying it in all six languages; that was done with them.

Left in Title Case on purpose, and listed in NAMES with the reason:
  * the NAMES OF PAGES (the sidebar label, the page title, and the buttons that open them): "Needs
    Attention", "Data Explorer", "WG Access". 12 of 25 multi-word sidebar labels are written that way and
    the rest were in sentence case. The owner chose Title Case for page names (2026-10-23), so
    "Threat Intel" and "Server Status" follow "Needs Attention"; test_every_page_name_is_title_case holds it.
  * product, protocol and standard names ("Proxmox Backup Server", "OpenID Connect", "WebAuthn").
"""
import html.parser
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / 'server' / 'html'
JS = HTML / 'static' / 'js'

SMALL = {'a', 'an', 'the', 'of', 'and', 'or', 'to', 'in', 'on', 'for', 'with', 'by', 'at', 'from', 'as', 'via',
         'vs', 'per', 'is', 'are'}

# Title Case that is right here, with the reason.
NAMES = {
    'OIDC / OpenID Connect': 'a protocol and its name',
    'Passkeys (WebAuthn)': 'a standard and its name',
    'Proxmox Backup Server': 'a product name',
    'VMware / OpenShift / Cloud Director': 'three product names',
    'Copy Markdown': 'Markdown is a format name',
    'Command History': 'the name of a page, which the host drawer section opens',
    'Host Config': 'the name of a page, which the host drawer section opens',
    'My Account': 'the name of a page',
    'Needs Attention': 'the name of a page', 'Data Explorer': 'the name of a page',
    'Command Queue': 'the name of a page', 'Live Monitor': 'the name of a page',
    'Status Board': 'the name of a page', 'Package Snapshots': 'the name of a page',
    'Release Signing': 'the name of a page', 'IaC Generator': 'the name of a page',
    'WG Access': 'the name of a page', 'AI Assistant': 'the name of a page',
    'API Keys': 'the name of a page', 'API Reference': 'the name of a page',
    'Custom Scripts': 'the name of a page',
    'Threat Intel': 'the name of a page', 'Server Status': 'the name of a page',
    'Network Metrics': 'the name of a page', 'Predictive Health': 'the name of a page',
    'App Catalog': 'the name of a page', 'Tags & Groups': 'the name of a page',
    'Software Policy': 'the name of a page', 'SSH Keys': 'the name of a page',
    'SSH Gateway': 'the name of a page',
}


def is_title_case(text):
    """Two or more significant words, every one capitalised (acronyms and small words do not count)."""
    words = re.findall(r"[A-Za-z][A-Za-z'’\-]*", text)
    # an acronym (CVE), or a name written with a capital inside it (IaC, GitOps, MikroTik), is not a word to case
    words = [w for w in words if w.lower() not in SMALL and not w.isupper() and w[1:] == w[1:].lower()]
    if len(words) < 2:
        return False
    return all(w[0].isupper() for w in words)


class _Headings(html.parser.HTMLParser):
    """(line, kind, text) for section titles, subsection titles and buttons that are not navigation."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.out, self.buf = [], [], None

    def handle_starttag(self, tag, attrs):
        cls = dict(attrs).get('class') or ''
        kind = None
        if re.search(r'(^|\s)(?:sub)?section-title(\s|$)', cls):
            kind = 'heading'
        elif tag == 'button' and 'nav-btn' not in cls and 'iac-tab' not in cls.split():
            kind = 'button'
        elif tag == 'button' and 'iac-tab' in cls.split():
            kind = 'button'
        if kind and tag not in ('input', 'br', 'img'):
            self.stack.append((tag, kind, self.getpos()[0], []))

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1][0] == tag:
            _t, kind, line, parts = self.stack.pop()
            text = ' '.join(''.join(parts).split())
            if text:
                self.out.append((line, kind, text))

    def handle_data(self, data):
        if self.stack:
            self.stack[-1][3].append(data)


def html_headings(source):
    p = _Headings()
    p.feed(source)
    p.close()
    return p.out


def js_headings(source):
    """Headings built in a script: markup with a section-title, and the host drawer's audit sections."""
    out = []
    for m in re.finditer(r'class="(?:sub)?section-title[^"]*"[^>]*>([^<${}]{2,60})<', source):
        out.append((source.count('\n', 0, m.start()) + 1, 'heading', m.group(1).strip()))
    for m in re.finditer(r"""\{\s*key:\s*'[\w-]+',\s*title:\s*'([^']{2,60})'""", source):
        out.append((source.count('\n', 0, m.start()) + 1, 'audit section', m.group(1)))
    for m in re.finditer(r'<button\b[^>]*>([^<${}]{2,40})</button>', source):
        out.append((source.count('\n', 0, m.start()) + 1, 'button', m.group(1).strip()))
    return out


def findings():
    found, seen = [], 0
    for p in sorted(HTML.glob('*.html')):
        for line, kind, text in html_headings(p.read_text(encoding='utf-8')):
            seen += 1
            if is_title_case(text) and text not in NAMES:
                found.append(f'{p.name}:{line}: {kind} {text!r}')
    for p in sorted(JS.glob('app*.js')):
        for line, kind, text in js_headings(p.read_text(encoding='utf-8')):
            seen += 1
            if is_title_case(text) and text not in NAMES:
                found.append(f'{p.name}:{line}: {kind} {text!r}')
    return found, seen


class TestSentenceCase(unittest.TestCase):
    def test_no_heading_or_button_is_in_title_case(self):
        found, _seen = findings()
        self.assertEqual(found, [], 'these are in Title Case; write them in sentence case (and re-key the dictionary '
                                    'entry in all six languages), or add the name to NAMES with the reason:\n  '
                         + '\n  '.join(found[:25]))

    def test_the_scan_reads_the_interface(self):
        _found, seen = findings()
        self.assertGreater(seen, 400, 'the scan found almost no headings or buttons')

    def test_the_population_includes_the_drawer_and_the_page_headings(self):
        html_text = (HTML / 'index.html').read_text(encoding='utf-8')
        kinds = {k for _l, k, _t in html_headings(html_text)}
        self.assertEqual(kinds, {'heading', 'button'})
        app = (JS / 'app.js').read_text(encoding='utf-8')
        titles = [t for _l, k, t in js_headings(app) if k == 'audit section']
        self.assertGreater(len(titles), 12)
        self.assertIn('Listening ports', titles)

    def test_the_names_list_has_no_dead_entries(self):
        seen = set()
        for p in sorted(HTML.glob('*.html')):
            seen |= {t for _l, _k, t in html_headings(p.read_text(encoding='utf-8'))}
        for p in sorted(JS.glob('app*.js')):
            seen |= {t for _l, _k, t in js_headings(p.read_text(encoding='utf-8'))}
        # page names that only the sidebar and the page title carry are not scanned here
        scanned_elsewhere = {n for n, why in NAMES.items() if why == 'the name of a page'}
        stale = sorted(n for n in NAMES if n not in seen and n not in scanned_elsewhere)
        self.assertEqual(stale, [], 'these names are not in any scanned heading or button; delete them: ' + repr(stale))

    def test_every_page_name_is_title_case(self):
        text = (HTML / 'index.html').read_text(encoding='utf-8')
        labels = re.findall(r'<button class="nav-btn[^"]*" data-page="[^"]+"[^>]*>\s*(?:<svg.*?</svg>\s*)?<span>([^<]+)</span>',
                            text, re.S)
        self.assertGreater(len(labels), 50)
        words = lambda t: [w for w in re.findall(r"[A-Za-z][A-Za-z'’\-]*", t) if w.lower() not in SMALL]
        bad = [l for l in (x.replace('&amp;', '&') for x in labels)
               if len(words(l)) > 1 and not all(w[0].isupper() for w in words(l))]
        self.assertEqual(bad, [], 'page names are in Title Case: ' + repr(bad))

    def test_the_rule_can_say_no(self):
        self.assertTrue(is_title_case('Listening Ports'))
        self.assertTrue(is_title_case('Print / Save as PDF'))
        self.assertFalse(is_title_case('Listening ports'))
        self.assertFalse(is_title_case('Network metrics'))
        self.assertFalse(is_title_case('CVE summary'))
        self.assertFalse(is_title_case('Generate IaC'))        # a name with a capital inside is not a word to case
        self.assertFalse(is_title_case('Metrics'))
        sample = ('<div class="section-title">Top Processes</div><button>Save changes</button>'
                  '<button class="nav-btn">Needs Attention</button>')
        self.assertEqual([(k, t) for _l, k, t in html_headings(sample) if is_title_case(t)], [('heading', 'Top Processes')])


if __name__ == '__main__':
    unittest.main()
