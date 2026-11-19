"""Text that a host or a person supplies is drawn without the characters that reorder or hide it (8.0.2).

The two cleaners written in 8.0.2 for the inventories (`persistence.clean_text`, `software_inventory.clean_text`) say why they take format characters out of a host's text: "a
bidirectional override makes one name read as another". The other places that clean text a host or a person chose took out the control characters and stopped there, so a
share's name, the product text of the Hosts list, a log path of the capabilities report, the label of an enrolment token (which the Enroll dialog draws for the platform
operator), and every name and note stored through `_sanitize_str` could keep a right-to-left override, a zero width space or an isolate and read as another word. Nothing runs
(every one of them is written with escHtml or textContent), so this is spoofing of what is drawn, and the one it helps is the person who reads a name and believes it.

Two rules now, written once each:

* text a MACHINE supplied (a share, the product text, a log path, a container, a repository line) goes through `persistence.hidden`, the rule the inventories already use and the
  one the Windows agent's `_win_hidden` is held equal to: every control and format character, the separators, the fillers and the variation selectors;
* text a PERSON typed (a name, a note, a label, an attachment's file name) goes through `sanitize.strip_hidden`, which takes out what reorders or hides text and no script needs
  and keeps what writing needs: the zero width non-joiner and joiner of Persian and the Indic scripts, the left-to-right and right-to-left marks, the Arabic letter mark, the soft
  hyphen and the variation selectors. Stripping every format character from a note would break `می‌خواهم`.

Held by:

* one hostile string (`x`, a right-to-left override, a zero width space, an isolate, `y`) fed to every cleaner in a table, and each must lose the three and keep `x` and `y`, with a
  control that shows the instrument can see them;
* every code point from 0 to 0x10FFFF: what `strip_hidden` takes out is a subset of what `persistence.hidden` takes out, it takes every bidirectional embedding, override and
  isolate, and what it keeps of the format characters is exactly the list above;
* writing that needs the format characters comes out of the cleaners for a person unchanged;
* the enrolment token created through the real handler;
* a ratchet over the control-character regular expressions of the server, by syntax tree: each is either in the table above or listed with the reason it does not draw text.
"""
import ast
import functools
import importlib.util
import os
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v802-hidden-text-'))

import agent_capabilities  # noqa: E402
import container_audit  # noqa: E402
import disk_names_handlers  # noqa: E402
import persistence  # noqa: E402
import repo_inventory  # noqa: E402
import s3_client  # noqa: E402
import sanitize  # noqa: E402
import software_inventory  # noqa: E402
import time_periods  # noqa: E402
import windows_host  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_v802_hidden_text', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

RLO, ZWSP, LRI, VS16 = chr(0x202E), chr(0x200B), chr(0x2066), chr(0xFE0F)
HOSTILE = 'x' + RLO + ZWSP + LRI + 'y'
JUDGED = (RLO, ZWSP, LRI)


def flat(o):
    if isinstance(o, dict):
        return ''.join(flat(v) for v in o.values())
    if isinstance(o, (list, tuple)):
        return ''.join(flat(v) for v in o)
    return o if isinstance(o, str) else ''


def _win_build(t):
    return windows_host.os_label(windows_host.clean_win_build(
        {'build': '22631', 'ubr': 1, 'display_version': '23H2', 'product': t, 'edition': t, 'installation_type': 'Client'}))


# (name, the module whose cleaner it is, the rule it applies, the cleaner fed one text and returning what it kept). The rule is `strict` (persistence.hidden, for the text of a machine),
# `narrow` (sanitize.strip_hidden: what reorders or hides text and no script needs, for what a person typed and for a file's text, which keeps its line breaks) or `categories` (the
# older cleaner of the software inventory: every control, format, private-use and unassigned character).
CLEANERS = (
    ('persistence.clean_text', 'persistence.py', 'strict', lambda t: persistence.clean_text(t, 120)),
    ('software_inventory.clean_text', 'software_inventory.py', 'categories', lambda t: software_inventory.clean_text(t)),
    ('windows_host.clean_shares', 'windows_host.py', 'strict',
     lambda t: windows_host.clean_shares({'items': [{'name': t, 'path': t, 'description': t}], 'count': 1})),
    ('windows_host.os_label', 'windows_host.py', 'strict', _win_build),
    ('agent_capabilities.clean', 'agent_capabilities.py', 'strict',
     lambda t: agent_capabilities.clean({'logs': [{'kind': 'web', 'path': '/var/log/' + t, 'readable': True}]})),
    ('container_audit._text', 'container_audit.py', 'strict', lambda t: container_audit._text(t, 80)),
    ('repo_inventory._clean', 'repo_inventory.py', 'strict', lambda t: repo_inventory._clean(t, 80)),
    ('repo_inventory.clean_files', 'repo_inventory.py', 'narrow',
     lambda t: repo_inventory.clean_files({'/etc/apt/sources.list': 'deb http://deb.example.org/ stable main # ' + t + '\ndeb-src http://deb.example.org/ stable main\n'})),
    ('sanitize._sanitize_str', 'sanitize.py', 'narrow', lambda t: sanitize._sanitize_str(t, 128)),
    ('api._sanitize_str', 'api.py', 'narrow', lambda t: api._sanitize_str(t, 128)),
    ('disk_names_handlers._clean_name', 'disk_names_handlers.py', 'narrow', lambda t: disk_names_handlers._clean_name(t)),
    ('time_periods.clean_period', 'time_periods.py', 'narrow', lambda t: time_periods.clean_period({'name': t}, new_id='tp-0a0b0c0d')['name']),
    ('api._attach_safe_name', 'api.py', 'narrow', lambda t: api._attach_safe_name(t + '.pdf')),
    ('s3_client._clean', 's3_client.py', 'narrow', lambda t: s3_client._clean(t, 120)),
)
# what a person typed, which keeps the characters that writing needs
PERSONS = ('sanitize._sanitize_str', 'api._sanitize_str', 'disk_names_handlers._clean_name', 'time_periods.clean_period')


class TestEveryCleanerOfDrawnTextTakesThemOut(unittest.TestCase):
    def test_the_instrument_sees_what_it_looks_for(self):
        """The control: a cleaner that kept everything would show all three, and the text is `x`, then the three, then `y`."""
        out = flat(HOSTILE)
        self.assertEqual([c in out for c in JUDGED], [True, True, True])
        self.assertTrue(HOSTILE.startswith('x') and HOSTILE.endswith('y'))

    def test_each_cleaner_loses_the_three_and_keeps_the_text_around_them(self):
        self.assertGreaterEqual(len(CLEANERS), 14, 'the table measured nothing')
        for name, _module, _rule, fn in CLEANERS:
            out = flat(fn(HOSTILE))
            for char in JUDGED:
                self.assertNotIn(char, out, f'{name} keeps U+{ord(char):04X}')
            self.assertIn('x', out, name)
            self.assertIn('y', out, name)

    def test_each_cleaner_is_held_to_every_bidirectional_embedding_override_and_isolate(self):
        bidi = [chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))]
        self.assertEqual(len(bidi), 9)
        for name, _module, _rule, fn in CLEANERS:
            for char in bidi:
                self.assertNotIn(char, flat(fn('x' + char + 'y')), f'{name} keeps U+{ord(char):04X}')

    def test_the_other_hidden_characters_are_out_of_the_text_a_machine_supplied(self):
        """The strict rule of the inventories, in every cleaner that says it applies it."""
        every = [chr(0xFEFF), chr(0x200C), chr(0x200D), chr(0x200E), chr(0x200F), chr(0x2060), chr(0x061C), chr(0xFE0F), chr(0x00AD), chr(0xE0041), chr(0x3164)]
        strict = [c for c in CLEANERS if c[2] == 'strict']
        self.assertGreaterEqual(len(strict), 6)
        for name, _module, _rule, fn in strict:
            for char in every:
                self.assertNotIn(char, flat(fn('x' + char + 'y')), f'{name} keeps U+{ord(char):04X}')


class TestWritingThatNeedsTheFormatCharactersIsKept(unittest.TestCase):
    """What a person writes in Persian, Hindi, Arabic or with an emoji keeps what it needs; only what reorders or hides text goes."""

    TEXTS = {
        'a Persian note with the zero width non-joiner': 'می' + chr(0x200C) + 'خواهم',
        'a Hindi word with the zero width joiner': 'क' + chr(0x094D) + chr(0x200D) + 'ष',
        'an emoji sequence': chr(0x1F468) + chr(0x200D) + chr(0x1F469) + chr(0x200D) + chr(0x1F467),
        'an Arabic note with the right-to-left mark': 'مرحبا' + chr(0x200F) + ' (test)',
        'a note with the left-to-right mark': 'Server' + chr(0x200E) + ' 01',
        'an emoji with its presentation selector': chr(0x2764) + chr(0xFE0F) + ' ok',
        'a soft hyphen': 'infra' + chr(0x00AD) + 'structure',
    }

    def test_a_name_a_note_and_a_label_come_out_as_they_went_in(self):
        persons = [c for c in CLEANERS if c[0] in PERSONS]
        self.assertEqual(len(persons), len(PERSONS))
        for what, text in self.TEXTS.items():
            for name, _module, _rule, fn in persons:
                self.assertEqual(flat(fn(text)), text, f'{name}: {what}')

    def test_what_is_taken_out_of_a_sentence_leaves_the_sentence(self):
        text = 'Backup' + RLO + ' of ' + ZWSP + 'db' + LRI + '-01'
        self.assertEqual(sanitize._sanitize_str(text, 100), 'Backup of db-01')


class TestTheRuleForAPersonsText(unittest.TestCase):
    def test_every_code_point_it_takes_out_is_one_the_strict_rule_hides(self):
        """The text a person typed keeps less hidden than text a machine supplied, never more."""
        taken = [c for c in range(0x110000) if sanitize._HIDDEN_FROM_THE_READER.fullmatch(chr(c))]
        self.assertGreater(len(taken), 100, 'the scan found nothing')
        outside = [hex(c) for c in taken if not persistence.hidden(chr(c))]
        self.assertEqual(outside, [], 'a character taken out of a name that the strict rule does not call hidden')

    def test_it_takes_every_bidirectional_embedding_override_and_isolate(self):
        for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)):
            self.assertEqual(sanitize.strip_hidden('a' + chr(c) + 'b'), 'ab', hex(c))

    def test_it_takes_the_characters_that_hide_text_and_no_script_needs(self):
        for c in (0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0xFFF9, 0xFFFA, 0xFFFB, 0xE0041, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0):
            self.assertEqual(sanitize.strip_hidden('a' + chr(c) + 'b'), 'ab', hex(c))

    def test_what_it_keeps_of_the_format_characters_is_exactly_what_writing_needs(self):
        """The format characters and variation selectors that the strict rule hides and this one keeps are listed, so a Unicode version that adds one is seen."""
        kept = sorted(c for c in range(0x110000) if persistence.hidden(chr(c)) and not sanitize._HIDDEN_FROM_THE_READER.fullmatch(chr(c))
                      and unicodedata.category(chr(c)) not in ('Cc', 'Zl', 'Zp'))
        needed = {0x00AD, 0x061C, 0x200C, 0x200D, 0x200E, 0x200F, 0x180E, 0x180B, 0x180C, 0x180D, 0x180F}      # the soft hyphen, the Arabic letter mark, the joiners, the marks, the Mongolian format characters
        needed |= set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))                                      # the variation selectors
        needed |= {c for c in kept if unicodedata.category(chr(c)) == 'Cf' and (0x0600 <= c <= 0x0605 or c in (0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2, 0x110BD, 0x110CD))}   # the Arabic and Syriac number marks
        needed |= {c for c in kept if 0x1D173 <= c <= 0x1D17A or 0x13430 <= c <= 0x1345F or 0x1BCA0 <= c <= 0x1BCA3 or 0x0E0001 == c or 0x110BD == c}     # musical, Egyptian and shorthand format controls
        self.assertEqual([hex(c) for c in kept if c not in needed], [], 'a character the strict rule hides and this one keeps that is not on the list of what writing needs')
        for c in (0x200C, 0x200D, 0x200E, 0x200F, 0x061C, 0x00AD, 0xFE0F):
            self.assertIn(c, kept)

    def test_text_with_no_character_above_ascii_is_returned_as_it_is(self):
        text = 'plain ascii text 0123456789 !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
        self.assertIs(sanitize.strip_hidden(text), text)

    def test_the_ranges_are_written_as_code_points(self):
        """No character of the module that does this hides or reorders anything itself."""
        src = (_CGI / 'sanitize.py').read_text(encoding='utf-8')
        bad = [hex(ord(c)) for c in src if unicodedata.category(c) == 'Cf' or ord(c) in range(0x202A, 0x202F)]
        self.assertEqual(bad, [])


class TestTheEnrolmentTokenLabel(unittest.TestCase):
    """The Enroll dialog draws the label of a token for the platform operator, and an administrator of a tenant writes it."""

    def create(self, label):
        cap = {}
        api.verify_token = lambda tok=None: ('tenantadmin', 'admin')
        api.get_token_from_request = lambda: 'x'
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'label': label}
        api.audit_log = lambda *a, **k: None

        def _respond(status, data=None, headers=None):
            cap['status'], cap['data'] = status, data
            raise api.HTTPError(status, data)
        with mock.patch.object(api, 'respond', _respond):
            try:
                api.handle_enroll_token_create()
            except api.HTTPError:
                pass
        return cap

    def test_the_label_is_stored_and_answered_without_them(self):
        cap = self.create('Branch ' + RLO + 'office' + ZWSP + ' ' + LRI + 'one')
        self.assertEqual(cap['status'], 201, cap)
        self.assertEqual(cap['data']['label'], 'Branch office one')
        api._LOAD_CACHE.clear()
        stored = [t.get('label') for t in (api.load(api.ENROLL_TOKENS_FILE) or {}).values()]
        self.assertIn('Branch office one', stored)
        self.assertFalse([s for s in stored if any(c in (s or '') for c in JUDGED)])


class TestTheAttachmentName(unittest.TestCase):
    def test_a_name_that_reads_as_another_extension_is_not_one(self):
        name = api._attach_safe_name('invoice' + RLO + 'fdp.exe')
        self.assertEqual(name, 'invoicefdp.exe')
        self.assertNotIn(RLO, name)

    def test_the_rest_of_what_the_function_did_is_unchanged(self):
        self.assertEqual(api._attach_safe_name('..\\..\\etc/passwd'), 'passwd')
        self.assertEqual(api._attach_safe_name('a"b\r\nc.txt'), 'abc.txt')
        self.assertEqual(api._attach_safe_name(''), 'attachment')
        self.assertEqual(api._attach_safe_name(RLO + ZWSP), 'attachment')


# ── the control-character regular expressions of the server, each decided ────────────────────

ATTRS = {'compile', 'sub', 'search', 'match', 'fullmatch', 'findall', 'subn', 'split'}

# Each is either `cleaned` (the module has a cleaner in CLEANERS that takes the characters out) or the reason it does not draw text. A pattern is named by its file and the first
# 60 characters of its text; `windows_host.py`, `agent_capabilities.py` and `container_audit.py` held one each until 8.0.2, and are not listed because they hold none now.
KEY = 60
DECIDED = {
    ('api.py', r'^(?:[A-Za-z0-9_,\-=."/@:\[\]*]+\s+)?(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|'[:KEY]):
        'a public key line is parsed, and refused when it is not one; it is not stored as text',
    ('api.py', r'[\x00-\x1f\x7f-\x9f\u2028\u2029]'): 'a log line: one value is one line, and a log is not drawn as a name',
    ('api.py', r'[\x00-\x1f\x7f"\r\n]'): 'cleaned',                  # _attach_safe_name
    ('api.py', r'[\x00-\x1f\x7f]'): 'a check\'s parameter and search pattern: a path or a regular expression that has to match what it names, so a character in it is part of the match',
    ('disk_names_handlers.py', r'[\x00-\x1f\x7f]+'): 'cleaned',
    ('ip_intel.py', r'[\x00-\x1f\x7f]+'): 'the comment the platform operator writes for the reports sent to the two services: outbound text, not drawn as a name',
    ('proxmox_client.py', r'^[A-Za-z][^\x00-\x1f\x7f/\\]{0,63}$'): 'a snapshot action name is refused when it holds a control character; it is not stored or drawn',
    ('repo_inventory.py', r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'): 'cleaned',
    ('s3_client.py', r'[\x00-\x1f\x7f]'): 'cleaned',
    ('time_periods.py', r'[\x00-\x1f\x7f]'): 'cleaned',
}


@functools.lru_cache(maxsize=None)
def control_regexes():
    """Read once: api.py is most of a million syntax tree nodes."""
    found = set()
    for path in sorted(_CGI.glob('*.py')):
        src = path.read_text(encoding='utf-8')
        for node in ast.walk(ast.parse(src)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ATTRS and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == 're' and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                pattern = node.args[0].value
                raw = ast.get_source_segment(src, node.args[0]) or ''
                if '\\x00-\\x1f' in raw or '\\x00-\\x08' in raw or '\x00-\x1f' in pattern:
                    found.add((path.name, pattern[:KEY]))
    return frozenset(found)


class TestEveryControlCharacterPatternOfTheServerIsDecided(unittest.TestCase):
    def test_the_derivation_reads_the_server(self):
        self.assertGreaterEqual(len(control_regexes()), 8, control_regexes())

    def test_each_is_cleaned_or_listed_with_its_reason_and_the_list_has_no_stale_entry(self):
        found = control_regexes()
        self.assertEqual(sorted(found - set(DECIDED)), [], 'a control-character pattern that no one decided: does it clean text that is drawn? then it takes the hidden characters out too')
        self.assertEqual(sorted(set(DECIDED) - found), [], 'a listed pattern that the server no longer has')

    def test_the_three_modules_that_held_one_hold_none_and_use_the_rule(self):
        for module in ('windows_host.py', 'agent_capabilities.py', 'container_audit.py'):
            self.assertEqual([p for f, p in control_regexes() if f == module], [], module)
            self.assertIn('hidden(', (_CGI / module).read_text(encoding='utf-8'), module)

    def test_a_pattern_that_cleans_belongs_to_a_module_with_a_cleaner_in_the_table(self):
        modules = {m for _n, m, _r, _f in CLEANERS}
        for (module, _pattern), what in DECIDED.items():
            if what == 'cleaned':
                self.assertIn(module, modules, f'{module} is said to clean, and no cleaner of it is fed the hostile text')
            else:
                self.assertTrue(len(what) > 20, 'a reason is a sentence')


if __name__ == '__main__':
    unittest.main()
