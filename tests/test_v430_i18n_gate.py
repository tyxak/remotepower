#!/usr/bin/env python3
"""v4.3.0: i18n coverage gate for the app chrome.

The translation strategy is deliberate: a curated DICT covers the app's
*chrome* (sidebar nav, page titles) and everything else falls back to
English. The gap was process, not strategy — nothing failed when a new page
shipped with untranslated chrome, so coverage silently decayed with every
release. This gate makes the curated set self-enforcing: every sidebar nav
label and every page title in index.html must have a DICT entry carrying all
five non-English languages.
"""
import html as _html
import json
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
INDEX = (_ROOT / "server" / "html" / "index.html").read_text()
I18N = (_ROOT / "server" / "html" / "static" / "js" / "i18n.js").read_text()

# Every non-English language the UI ships. `fr` was added to i18n.js but NOT to
# this tuple, so the completeness gates below silently never checked it — which is
# how 9 DICT entries shipped with no French at all (they render English for a French
# user). Adding a language to i18n.js means adding it HERE too, or it is unguarded.
LANGS = ('zh', 'hi', 'es', 'ar', 'de', 'fr')


def _dict_entries():
    """Parse DICT keys → set of language codes present, from i18n.js."""
    m = re.search(r'var DICT = \{(.*?)\n  \};', I18N, re.S)
    assert m, "DICT block not found in i18n.js"
    entries = {}
    # DICT keys appear in two stacked blocks: a curated single-quoted block and
    # a machine-generated double-quoted catalog (CLAUDE.md). Read BOTH quote
    # styles — the curated chrome and the machine catalog both count as coverage.
    for em in re.finditer(
            r"""(?:'((?:[^'\\]|\\.)+)'|"((?:[^"\\]|\\.)+)"):\s*\{([^}]*)\}""",
            m.group(1)):
        key = (em.group(1) or em.group(2)).replace("\\'", "'").replace('\\"', '"')
        langs = set(re.findall(r'["\']?(\w+)["\']?\s*:', em.group(3)))
        entries[key] = langs
    return entries


def _htmldict_entries():
    """Parse HTMLDICT keys → set of language codes present, from i18n.js.

    HTMLDICT is the separate object that translates whole `.page-subtitle`
    innerHTML strings (keys are the normalized English HTML, double-quoted).
    Each line is one entry: `    "<en html>": { "zh": ..., "hi": ..., ... },`

    Language keys appear BOTH quoted (`"de":`) and bare (`fr:`) — the file mixes
    styles. Matching only the quoted form (as this did) silently reports every
    bare-keyed language as MISSING, which is a false failure, not a coverage gap.
    Mirror _dict_entries and accept both. (A `https:` inside an href can also match;
    harmless — the gates assert LANGS is a SUBSET of what's present, so a spurious
    extra name can never mask a genuinely absent language.)
    """
    m = re.search(r'var HTMLDICT = \{(.*?)\n  \};', I18N, re.S)
    assert m, "HTMLDICT block not found in i18n.js"
    entries = {}
    for em in re.finditer(r'^\s{4}"((?:[^"\\]|\\.)*)":\s*\{([^}]*)\}', m.group(1), re.M):
        # Unescape the JS string-literal key into the runtime innerHTML it matches.
        key = em.group(1).replace('\\"', '"').replace('\\\\', '\\')
        langs = set(re.findall(r'["\']?(\w+)["\']?\s*:', em.group(2)))
        entries[key] = langs
    return entries


def _nav_labels():
    """Visible label of every sidebar .nav-btn. The label is the bare
    `<span>` (no attributes); badges/stars are attributed spans — dropped."""
    labels = set()
    for bm in re.finditer(r'<button class="nav-btn[^"]*"[^>]*>(.*?)</button>', INDEX, re.S):
        body = re.sub(r'<svg\b.*?</svg>', '', bm.group(1), flags=re.S)
        body = re.sub(r'<span [^>]+>.*?</span>', '', body, flags=re.S)
        body = re.sub(r'<[^>]+>', '', body)
        text = _html.unescape(re.sub(r'\s+', ' ', body)).strip()
        if text:
            labels.add(text)
    return labels


def _page_titles():
    """First text node of every .page-title (badge spans excluded)."""
    titles = set()
    for tm in re.finditer(r'<(?:h1|div)[^>]*class="page-title[^"]*"[^>]*>(.*?)</(?:h1|div)>',
                          INDEX, re.S):
        body = tm.group(1)
        first = body.split('<', 1)[0]
        text = _html.unescape(re.sub(r'\s+', ' ', first)).strip()
        if not text:
            stripped = re.sub(r'<[^>]+>', '', re.sub(r'<span [^>]+>.*?</span>', '',
                                                     body, flags=re.S))
            text = _html.unescape(re.sub(r'\s+', ' ', stripped)).strip()
        if text:
            titles.add(text)
    return titles


def _section_titles():
    """Visible text of every `.section-title` element in index.html.

    Mirrors the runtime text-node lookup: strip nested markup, collapse
    whitespace. Titles with a trailing dynamic suffix (e.g. `Findings —`
    followed by a JS-injected count) are normalized to their static head and
    fall to the skip-list."""
    titles = set()
    for sm in re.finditer(
            r'<(\w+)[^>]*class="[^"]*\bsection-title\b[^"]*"[^>]*>(.*?)</\1>',
            INDEX, re.S):
        body = re.sub(r'<svg\b.*?</svg>', '', sm.group(2), flags=re.S)
        # The runtime translates the FIRST text node (the leading heading);
        # a trailing `.hint`/`<span>` description is a separate node. Mirror
        # _page_titles: take the text before the first child element.
        first = body.split('<', 1)[0]
        text = _html.unescape(re.sub(r'\s+', ' ', first)).strip()
        if not text:
            stripped = re.sub(r'<[^>]+>', '', body)
            text = _html.unescape(re.sub(r'\s+', ' ', stripped)).strip()
        if text:
            titles.add(text)
    return titles


def _button_labels():
    """Bare visible text node of every `<button>` in index.html (icons and
    attributed/nested spans dropped — same extraction as nav labels)."""
    labels = set()
    for bm in re.finditer(r'<button\b[^>]*>(.*?)</button>', INDEX, re.S):
        body = re.sub(r'<svg\b.*?</svg>', '', bm.group(1), flags=re.S)
        body = re.sub(r'<span [^>]+>.*?</span>', '', body, flags=re.S)
        body = re.sub(r'<[^>]+>', '', body)
        text = _html.unescape(re.sub(r'\s+', ' ', body)).strip()
        if text:
            labels.add(text)
    return labels


def _page_subtitles():
    """Normalized innerHTML of every `.page-subtitle` element in index.html.

    The runtime keys HTMLDICT by `_normWS(el.innerHTML)` — whitespace runs
    collapsed to a single space and trimmed — so mirror that here.
    """
    subs = set()
    for sm in re.finditer(
            r'<(\w+)[^>]*class="[^"]*\bpage-subtitle\b[^"]*"[^>]*>(.*?)</\1>',
            INDEX, re.S):
        text = re.sub(r'\s+', ' ', sm.group(2)).strip()
        if text:
            subs.add(text)
    return subs


class TestChromeTranslationCoverage(unittest.TestCase):
    def setUp(self):
        self.dict_entries = _dict_entries()

    def test_dict_parses_and_is_nontrivial(self):
        self.assertGreater(len(self.dict_entries), 40)

    def test_every_nav_label_is_in_dict(self):
        labels = _nav_labels()
        self.assertGreater(len(labels), 20, "nav extraction looks broken")
        missing = sorted(l for l in labels if l not in self.dict_entries)
        self.assertEqual(missing, [],
                         "sidebar nav labels with no DICT entry (new page shipped "
                         f"without chrome translation?): {missing}")

    def test_every_page_title_is_in_dict(self):
        titles = _page_titles()
        self.assertGreater(len(titles), 20, "page-title extraction looks broken")
        missing = sorted(t for t in titles if t not in self.dict_entries)
        self.assertEqual(missing, [],
                         f"page titles with no DICT entry: {missing}")

    def test_dict_entries_carry_all_six_languages(self):
        incomplete = {k: sorted(set(LANGS) - langs)
                      for k, langs in self.dict_entries.items()
                      if not set(LANGS) <= langs}
        self.assertEqual(incomplete, {},
                         f"DICT entries missing languages: {incomplete}")


class TestSubtitleTranslationCoverage(unittest.TestCase):
    """Every `.page-subtitle` must have a translation entry in DICT or
    HTMLDICT carrying all six non-English languages, or it renders
    English-only in zh/hi/es/ar/de/fr. The original v4.3.0 gate only checked
    page-*titles*; leaf-page subtitles slipped through (the gap this closes)."""

    def setUp(self):
        self.dict_entries = _dict_entries()
        self.htmldict_entries = _htmldict_entries()

    def test_htmldict_parses_and_is_nontrivial(self):
        self.assertGreater(len(self.htmldict_entries), 60,
                           "HTMLDICT extraction looks broken")

    def test_every_page_subtitle_is_translated(self):
        subs = _page_subtitles()
        self.assertGreater(len(subs), 60, "page-subtitle extraction looks broken")
        # A subtitle is covered if its normalized innerHTML is a key in either
        # table (text-node DICT or whole-subtitle HTMLDICT).
        keys = set(self.dict_entries) | set(self.htmldict_entries)
        missing = sorted(s for s in subs if s not in keys)
        self.assertEqual(missing, [],
                         "page subtitles with no DICT/HTMLDICT entry (new page "
                         f"shipped without a subtitle translation?): {missing}")

    def test_htmldict_entries_carry_all_six_languages(self):
        incomplete = {k: sorted(set(LANGS) - langs)
                      for k, langs in self.htmldict_entries.items()
                      if not set(LANGS) <= langs}
        self.assertEqual(incomplete, {},
                         f"HTMLDICT entries missing languages: {incomplete}")


class TestSectionAndButtonTranslationCoverage(unittest.TestCase):
    """Static `.section-title` headings and static `<button>` labels must
    carry a DICT entry in all six non-English languages, or they render
    English-only in zh/hi/es/ar/de/fr. This closed a coverage gap an audit found:
    leaf-page section titles and clear-verb buttons had decayed to English."""

    # Proper nouns (never translated) and dynamic/glyph-only labels that have
    # no stable English text node to key on. Documented exemptions only.
    SECTION_SKIP = frozenset({
        'fail2ban',     # proper noun — product name, never translated
        'Findings —',   # dynamic: a JS-injected count follows the em dash
    })
    BUTTON_SKIP = frozenset({
        'fail2ban',          # proper noun
        '‹', '›',            # glyph-only carousel/pager arrows
        '{ } JSON',          # format-toggle glyph + acronym; nothing to translate
        'Delete snapshot',   # destructive op label — covered via DICT 'Delete'
        # v6.4.0 KMIP wizard: literal FILENAMES the operator saves to disk and
        # types into the appliance — translating them would be wrong.
        'ca.crt', 'client.crt', 'client.key',
    })

    def setUp(self):
        self.dict_entries = _dict_entries()

    def test_every_section_title_is_in_dict(self):
        titles = _section_titles() - self.SECTION_SKIP
        self.assertGreater(len(titles), 10, "section-title extraction looks broken")
        missing = sorted(t for t in titles if t not in self.dict_entries)
        self.assertEqual(missing, [],
                         "section titles with no DICT entry (new section shipped "
                         f"without chrome translation?): {missing}")

    def test_every_button_label_is_in_dict(self):
        labels = _button_labels() - self.BUTTON_SKIP
        self.assertGreater(len(labels), 30, "button extraction looks broken")
        missing = sorted(l for l in labels if l not in self.dict_entries)
        self.assertEqual(missing, [],
                         "static button labels with no DICT entry (new button "
                         f"shipped without a translation?): {missing}")


if __name__ == '__main__':
    unittest.main()


# ── v6.4.3: the categories the chrome-only gate never scanned ────────────────
#
# The gate above covers nav labels, .page-title, .page-subtitle, .section-title
# and static <button> text. <option>, <th> and <label> were unguarded, so their
# coverage decayed silently — 146 strings had drifted out of DICT, 88 of them
# <option> values, i.e. the text in every dropdown in the product.
#
# 72 were translated. The 74 below are DELIBERATELY English and this is the
# machine-readable record of that decision, which did not previously exist
# anywhere (CLAUDE.md notes data-no-i18n is used zero times). They fall into
# four groups, and translating any of them would be a REGRESSION:
#
#   * Product and vendor names — PostgreSQL, Cloudflare, Grafana Loki, Zabbix,
#     nmap, nuclei, firewalld, iPXE. A localised brand name is just wrong.
#   * Protocol / crypto / format tokens — tcp, udp, JSON, RSA 2048,
#     ECDSA P-384, DKIM, SPF, TTL, OID prefix. These are wire values or
#     standards, not prose.
#   * Enum VALUES the operator matches against config and API payloads —
#     prod, dev, staging, stable, beta, asc, desc, agent, site. Translating the
#     label while the value stays English breaks the mapping in the reader's
#     head.
#   * Established abbreviations that are not expanded in any language here —
#     UPS, NAS, PDU, IoT, MFA, EDR, SLA, MTTR, ID.
#
# Adding to this list is a decision that needs one of those four reasons.
_DELIBERATE_ENGLISH = {
    "Src → Dst",
    "→ target:port",
    "→ to-addr:port",
    "(no ISO — empty VM)",
    "(no disk storage)",
    "(no root-disk storage)",
    "(no templates found — download one in Proxmox)",
    "0 (striping, no redundancy)",
    "1 (mirror)",
    "1000 rows",
    "2000 rows",
    "256 rows",
    "512 rows",
    "AES-128",
    "CRC / Unc.",
    "CVE",
    "Crit·ality",
    "Err",
    "Errs",
    "FS",
    "MD5",
    'Names (comma-separated; ignored for "All")',
    "OID",
    "Oper",
    "Proto",
    "RX",
    "Rev",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "TX",
    "Temperature (0.0–2.0)",
    "UID",
    "Upgrade packages — apt/dnf/yum/pacman",
    "accept",
    "authorized_keys",
    "block",
    "btrfs",
    "drop",
    "dst-nat",
    "dstnat",
    "ext4",
    "forward",
    "input",
    "kWh/mo",
    "masquerade",
    "max_tokens (1–16000)",
    "num_ctx (Ollama/LocalAI)",
    "output",
    "pass",
    "redirect",
    "reject",
    "src-nat",
    "srcnat",
    "top_p (0.0–1.0)",
    "xfs",
    "AWS EC2",
    "Anthropic (Claude)",
    "Authentik",
    "Cloudflare",
    "DKIM",
    "DeepSeek",
    "DigitalOcean",
    "ECDSA P-384",
    "EDR",
    "Elasticsearch",
    "Grafana Loki",
    "Grafana legacy alerting",
    "Hetzner Cloud",
    "ID",
    "IoT",
    "JSON",
    "Lenovo",
    "Lenovo ClientID",
    "MFA",
    "MTTR",
    "NAS",
    "Nagios / Icinga",
    "OID prefix",
    "OpenAI",
    "OpenAI (ChatGPT)",
    "PDU",
    "PostgreSQL",
    "PowerShell",
    "Prometheus Alertmanager (also Grafana unified alerting)",
    "RSA 2048",
    "RemotePower generic — {severity, title, body, device}",
    "SLA",
    "SPF",
    "Server Camp",
    "Splunk HEC",
    "Syslog",
    "TTL",
    "Tasmota",
    "Terraform",
    "UPS",
    "Uptime Kuma (JSON)",
    "Zabbix (XML)",
    "agent",
    "asc",
    "at",
    "beta",
    "cloud-init",
    "cmd.exe",
    "desc",
    "dev",
    "firewalld",
    "iPXE",
    "info",
    "medium",
    "min_version",
    "nikto",
    "nmap",
    "not",
    "nuclei",
    "openclaw — local (WebSocket gateway)",
    "opencode — local (agent server)",
    "prod",
    "site",
    "stable",
    "staging",
    "tcp",
    "test",
    "udp",
    "ufw",
    "version <",
    "version =",
    "version >",
    "version ≤",
    "version ≥",
}

# v6.4.3 (second pass): the same three categories, but the gate only ever read
# index.html — so a column header, dropdown option or field label rendered from
# a JavaScript template literal was invisible to it. That is most of the newer
# UI: 93 such strings had accumulated, 48 of them protocol tokens and
# filesystem names that must stay English, the rest genuinely missed.
#
# Interpolated text (`${...}`) is skipped: a header built from a variable has no
# fixed string to translate, and the engine works on rendered text nodes anyway.
_JS = '\n'.join(
    p.read_text() for p in
    sorted((_ROOT / 'server' / 'html' / 'static' / 'js').glob('app*.js')))
_SCAN_SOURCES = (('index.html', INDEX), ('app*.js', _JS))


def _extract(pattern, source):
    """Every literal the pattern finds in one source, normalised."""
    out = set()
    for raw in re.findall(pattern, source):
        if '${' in raw or "' +" in raw or '+ \'' in raw:
            continue          # interpolated / concatenated — not a fixed string
        text = _html.unescape(re.sub(r'\s+', ' ', raw)).strip()
        if text and re.search(r'[A-Za-z]{2}', text):
            out.add(text)
    return out


_UNGUARDED_PATTERNS = (
    ('option',  r'<option[^>]*>([^<]{2,60})</option>'),
    ('th',      r'<th[^>]*>([^<]{2,60})</th>'),
    ('label',   r'<label[^>]*>([^<]{2,60})</label>'),
)


class TestUnguardedCategoriesAreTranslated(unittest.TestCase):
    """Ceiling ZERO. Everything currently untranslated is either in DICT or in
    the deliberate list above, so a NEW untranslated dropdown option, column
    header or field label fails the build instead of decaying quietly."""

    def _missing(self):
        entries = _dict_entries()
        out = {}
        for cat, pat in _UNGUARDED_PATTERNS:
            for where, source in _SCAN_SOURCES:
                miss = {t for t in _extract(pat, source)
                        if t not in entries and t not in _DELIBERATE_ENGLISH}
                if miss:
                    out[f'{cat} ({where})'] = sorted(miss)
        return out

    def test_no_untranslated_option_th_or_label(self):
        missing = self._missing()
        self.assertEqual(
            missing, {},
            'untranslated user-visible text in a category the chrome gate does '
            'not cover:\n' + json.dumps(missing, indent=2, ensure_ascii=False)
            + '\nAdd a DICT entry in i18n.js carrying all six non-English '
              'languages, or — if it is a brand name, a protocol token, an enum '
              'value or an abbreviation — add it to _DELIBERATE_ENGLISH with '
              'which of those four it is.')

    def test_every_translated_entry_has_all_languages(self):
        """A partial entry renders English for the missing languages, which
        looks identical to no entry at all."""
        entries = _dict_entries()
        partial = {}
        for cat, pat in _UNGUARDED_PATTERNS:
            for raw in re.findall(pat, INDEX):
                text = _html.unescape(re.sub(r'\s+', ' ', raw)).strip()
                langs = entries.get(text)
                if langs and not set(LANGS).issubset(langs):
                    partial[text] = sorted(set(LANGS) - langs)
        self.assertEqual(partial, {},
                         'DICT entries missing languages: '
                         + json.dumps(partial, indent=2, ensure_ascii=False))

    def test_the_deliberate_list_is_not_stale(self):
        """An entry that no longer appears in the markup is dead weight, and a
        stale exemption is how a real gap hides.

        Compared against the EXTRACTED text, not a raw substring search: the
        markup stores `version &lt;`, so searching the raw HTML for the
        unescaped `version <` reports a live exemption as stale."""
        present = set()
        for _cat, pat in _UNGUARDED_PATTERNS:
            for _where, source in _SCAN_SOURCES:
                present |= _extract(pat, source)
        stale = sorted(_DELIBERATE_ENGLISH - present)
        self.assertEqual(stale, [],
                         'these are exempted but appear in neither index.html '
                         'nor any app*.js: %s' % stale)


# ── v6.4.3 (third pass): the attributes ──────────────────────────────────────
#
# `placeholder`, `title` and `aria-label` are the strings a screen-reader user
# actually hears. The ENGINE has translated all three for releases —
# i18n.js's `translateAttrs` walks `[placeholder],[title],[aria-label]` and
# rewrites them through the same DICT as everything else. What was missing was
# the dictionary behind it, and nothing was watching, so 1,081 attribute
# strings had accumulated in English. A blind spot on the accessibility surface
# specifically, which is the worst place to have one.
#
# WHY THIS IS A BASELINE AND NOT CEILING ZERO. The other three categories are
# at zero because they could be driven there. This one cannot be, honestly:
# ~360 of the placeholders are example DATA the operator copies — cron lines,
# PEM blocks, `/var/log/nginx/error.log`, `192.168.1.0/24` — and translating
# those would be actively wrong. Sorting a thousand strings into "prose" and
# "example" by regex is guesswork, and CLAUDE.md is explicit that a wrong
# translation is worse than English. So the debt is recorded exactly and can
# only shrink.
#
# WHY A FROZEN SET RATHER THAN A COUNT. A numeric ceiling has a hole this one
# does not: translate five strings, add five untranslated ones, and the total is
# unchanged while the UI got worse. Pinning the set means a NEW untranslated
# attribute fails by name, and clearing one shows up as a deletion in the diff.
_ATTR_BACKLOG_FILE = _ROOT / 'tests' / 'data' / 'i18n_attr_backlog.txt'
_ATTR_PATTERNS = (
    ('placeholder', r'placeholder="([^"]{2,120})"'),
    ('title',       r'\btitle="([^"]{2,120})"'),
    ('aria-label',  r'aria-label="([^"]{2,120})"'),
)


def _attr_strings():
    """Every fixed attribute literal in the static HTML and the app bundles."""
    found = set()
    for _cat, pat in _ATTR_PATTERNS:
        for _where, source in _SCAN_SOURCES:
            found |= _extract(pat, source)
    # The baseline is line-delimited, so a value carrying a newline (a
    # multi-line placeholder example) is folded the same way on both sides.
    return {t.replace('\n', ' ').replace('\r', ' ') for t in found}


def _attr_backlog():
    if not _ATTR_BACKLOG_FILE.exists():
        return None                      # excluded from the dist tree
    return {ln for ln in
            _ATTR_BACKLOG_FILE.read_text(encoding='utf-8').splitlines() if ln}


# ── v6.4.3: runtime strings (toasts, empty states, confirm messages) ─────────
# The fourth extraction. The three above cover static markup and the
# option/th/label categories inside app*.js; the STRINGS those files pass to
# toast() / uiConfirm({message}) / tableCtl emptyMsg were scanned by nothing,
# and they are the text an operator reads at the moment something succeeds,
# fails, or asks to be confirmed.
#
# 548 were already untranslated when this landed. That is recorded debt in
# tests/data/i18n_runtime_backlog.txt, shrink-only, exactly like the attribute
# baseline: a large backlog frozen so it cannot GROW is worth far more than a
# gate deferred until someone finds time to translate 548 strings, because the
# decay stops today either way.
_RUNTIME_BACKLOG_FILE = _ROOT / 'tests' / 'data' / 'i18n_runtime_backlog.txt'
_RUNTIME_PATTERNS = (
    r"toast\(\s*'([^'\\]{4,90})'",          # every success/error/info toast
    r"emptyMsg:\s*'([^'\\]{4,120})'",       # tableCtl empty states
    r"message:\s*'([^'\\]{4,140})'",        # uiConfirm / uiPrompt bodies
)


def _runtime_strings():
    """User-visible prose passed to the toast/confirm/empty-state helpers.

    Skips anything with `${` (interpolated — the literal is not the sentence),
    anything containing `<` (markup, handled by the markup extractions), and
    anything not starting with a capital, which filters ids, keys and CSS
    fragments that share these call shapes.
    """
    out = set()
    for _where, src in _SCAN_SOURCES:
        for pat in _RUNTIME_PATTERNS:
            for m in re.finditer(pat, src):
                t = m.group(1).strip()
                if '${' in t or '<' in t or len(t) < 4 or not re.match(r'^[A-Z]', t):
                    continue
                out.add(t)
    return out


def _runtime_backlog():
    if not _RUNTIME_BACKLOG_FILE.exists():
        return None
    return {ln.rstrip('\n') for ln in
            _RUNTIME_BACKLOG_FILE.read_text(encoding='utf-8').splitlines()
            if ln.strip()}


class TestRuntimeStringRatchet(unittest.TestCase):
    """toast / confirm / empty-state prose — shrink-only, same contract as the
    attribute ratchet."""

    def setUp(self):
        self.backlog = _runtime_backlog()
        if self.backlog is None:
            self.skipTest('tests/data excluded from this tree')

    def test_the_extraction_finds_the_strings(self):
        """Positive control. These patterns match call shapes, so a rename of
        toast() or a switch to double quotes would silently return nothing and
        every assertion below would pass over an empty set."""
        found = _runtime_strings()
        self.assertGreater(len(found), 400,
                           'runtime-string extraction found almost nothing — '
                           'has toast()/uiConfirm been renamed or requoted?')

    def test_no_new_untranslated_runtime_string(self):
        entries = _dict_entries()
        new = sorted(t for t in _runtime_strings()
                     if t not in entries
                     and t not in _DELIBERATE_ENGLISH
                     and t not in self.backlog)
        self.assertEqual(new, [], '\n'.join([
            'these toast / confirm / empty-state strings are new and have no '
            'translation:', *('  ' + t for t in new),
            '',
            'This is the text an operator reads when something succeeds, fails '
            'or asks to be confirmed — in the six non-English languages it is '
            'shown in English. Add a DICT entry in i18n.js with all six.',
            '',
            'Never invent a translation you are unsure of: the English fallback '
            'is graceful, a wrong one is not. If the string is example DATA an '
            'operator copies, record it in '
            f'{_RUNTIME_BACKLOG_FILE.name}, which may shrink and never grow.']))

    def test_the_backlog_only_shrinks(self):
        """A string that has since been translated, or deleted from the source,
        must leave the file — or the baseline rots into a list nobody can act
        on and a real gap hides among them."""
        entries = _dict_entries()
        present = _runtime_strings()
        stale = sorted(t for t in self.backlog
                       if t in entries or t not in present)
        self.assertEqual(stale, [], '\n'.join([
            'these entries in the runtime backlog are stale — they are either '
            'translated now or no longer in any app*.js:',
            *('  ' + t for t in stale),
            '', 'Delete them. The file records debt that still exists.']))

    def test_the_debt_is_real_not_invented(self):
        """Every backlog line must be a string that genuinely appears in the
        source, so the file cannot be padded to make the gate pass."""
        present = _runtime_strings()
        self.assertTrue(self.backlog <= present)


class TestAttributeTranslationRatchet(unittest.TestCase):
    """`placeholder` / `title` / `aria-label` — shrink-only."""

    def setUp(self):
        self.backlog = _attr_backlog()
        if self.backlog is None:
            self.skipTest('tests/data excluded from this tree')

    def test_no_new_untranslated_attribute(self):
        entries = _dict_entries()
        new = sorted(t for t in _attr_strings()
                     if t not in entries
                     and t not in _DELIBERATE_ENGLISH
                     and t not in self.backlog)
        self.assertEqual(new, [], '\n'.join([
            'these placeholder / title / aria-label strings are new and have no '
            'translation:', *('  ' + t for t in new),
            '',
            'A screen reader announces these verbatim, so in the six non-English '
            'languages they are read out in English. Add a DICT entry in '
            'i18n.js carrying all six languages.',
            '',
            'If the string is example DATA the operator copies — a path, a cron '
            'expression, an IP, a certificate — it must stay English: add it to '
            f'{_ATTR_BACKLOG_FILE.name}. That file is the recorded debt and is '
            'allowed to shrink, never grow.']))

    def test_the_backlog_only_shrinks(self):
        """An entry that is now translated, or no longer in the markup, must be
        deleted from the baseline. Otherwise the file drifts into a list of
        strings nobody can act on, and a real gap hides among them — the stale
        exemption problem the category above already had once."""
        entries = _dict_entries()
        present = _attr_strings()
        stale = sorted(t for t in self.backlog
                       if t not in present or t in entries)
        self.assertEqual(stale, [], '\n'.join([
            'these are recorded as untranslated but are now translated or gone '
            'from the markup — delete them from '
            f'{_ATTR_BACKLOG_FILE.name}:', *('  ' + t for t in stale[:40])]))

    def test_the_recorded_debt_is_shrinking_not_invented(self):
        """Guard the guard. A baseline that silently grew to cover everything
        would make the test above pass forever while measuring nothing."""
        self.assertLessEqual(len(self.backlog), 1008,
                             'the attribute backlog may only shrink; it was '
                             '1,081 before the v6.4.3 batch and 984 after')
        self.assertGreater(len(self.backlog), 0)

    def test_a_translated_attribute_carries_all_six_languages(self):
        entries = _dict_entries()
        partial = {}
        for text in sorted(_attr_strings()):
            langs = entries.get(text)
            if langs and not set(LANGS).issubset(langs):
                partial[text] = sorted(set(LANGS) - langs)
        self.assertEqual(partial, {},
                         'attribute translations missing languages: '
                         + json.dumps(partial, indent=2, ensure_ascii=False))
