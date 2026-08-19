#!/usr/bin/env python3
"""The Windows and macOS agents each carry a list of heartbeat-response keys they
do NOT read. This checks the list is still complete.

Both module docstrings end with "when closing one of these, also update this
list and the [other] agent's", so the list claims to be exhaustive. A list that
claims to be exhaustive and is not is worse than no list: the next audit reads
it, sees a key absent, and concludes the agent handles it.

The class it guards is the one CLAUDE.md names — a heartbeat-response field
honoured by one agent and silently dropped by another (`poll_interval` was
win/mac-only, `force_secrets_scan` was linux/mac-only). The server now refuses
the Linux-only actions honestly per-platform, so the operator is not misled; the
remaining risk is a NEW key added to the response and read by one agent, which
nothing would catch.

Recorded because it cost a detour: the docstrings use GLOBS (`du_scan_*`,
`image_scan_*`). A first version of this matched exact backtick names and
reported five keys as undocumented silent ignores when all five were covered.
That is the fifth instrument error in this sweep and the reason each hunt here
carries a positive control.
"""
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_API = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
_AGENTS = {
    'windows': _ROOT / 'client' / 'remotepower-agent-win.py',
    'macos': _ROOT / 'client' / 'remotepower-agent-mac.py',
}


def _server_sent_keys():
    """Keys the server puts in a heartbeat response."""
    keys = set(re.findall(r"common_resp\[['\"]([a-z0-9_]+)['\"]\]\s*=", _API))
    i = _API.index('common_resp = {')
    depth, j = 0, i + len('common_resp = ')
    while j < len(_API):
        if _API[j] == '{':
            depth += 1
        elif _API[j] == '}':
            depth -= 1
            if depth == 0:
                break
        j += 1
    keys |= set(re.findall(r"^\s+'([a-z0-9_]+)':", _API[i:j + 1], re.M))
    return keys


def _declared_unread(src):
    """Names in the agent's 'Still Linux-only' list, globs expanded."""
    head = src[:src.index('"""', src.index('"""') + 3)]
    m = re.search(r'Still Linux-only.*?(?=\n\n)', head, re.S)
    if not m:
        return None
    # Only names that look like KEYS. The prose backticks tool names too
    # (`oscap` is a Linux tool, no `du` on Windows), and treating those as
    # declared keys made the staleness check report them as gone. Every
    # heartbeat-response key has an underscore or a glob; no tool name does.
    return {t for t in re.findall(r'`([a-z0-9_]+\*?)`', m.group(0))
            if '_' in t or t.endswith('*')}


def _matches_declared(key, declared):
    for d in declared:
        if d == key or (d.endswith('*') and key.startswith(d[:-1])):
            return True
    return False


class TestTheScannerWorks(unittest.TestCase):

    def test_the_server_sends_a_plausible_number_of_keys(self):
        keys = _server_sent_keys()
        self.assertGreater(len(keys), 5, f'only found {keys}')

    def test_each_agent_declares_a_list_at_all(self):
        for name, path in _AGENTS.items():
            self.assertIsNotNone(_declared_unread(path.read_text()),
                                 f'{name}: the Linux-only list is gone')

    def test_glob_expansion_works(self):
        """The detour this file records. Without it every `*_scan_*` key reads
        as undocumented."""
        self.assertTrue(_matches_declared('du_scan_paths', {'du_scan_*'}))
        self.assertFalse(_matches_declared('poll_interval', {'du_scan_*'}))


class TestEveryUnreadKeyIsDeclared(unittest.TestCase):

    def test_no_key_is_silently_dropped(self):
        sent = _server_sent_keys()
        problems = []
        for name, path in _AGENTS.items():
            src = path.read_text()
            declared = _declared_unread(src) or set()
            for key in sorted(sent):
                reads = re.search(
                    rf"resp\.get\(['\"]{key}['\"]|\bresp\[['\"]{key}['\"]\]|"
                    rf"\bcfg\.get\(['\"]{key}['\"]", src)
                if reads or _matches_declared(key, declared):
                    continue
                problems.append(f'{name}: {key}')
        self.assertEqual(problems, [],
                         'the server sends these and the agent neither reads '
                         'them nor lists them as knowingly unread — either wire '
                         'them up or add them to the docstring list:\n  '
                         + '\n  '.join(problems))

    def test_the_declared_list_has_not_gone_stale(self):
        """A name listed as unread that the server no longer sends is a claim
        about nothing, and it hides the next key that inherits the name."""
        sent = _server_sent_keys()
        # Only exact names can be checked; a glob may cover keys sent from
        # elsewhere in the response (force_* flags are set individually).
        force_ish = sent | set(re.findall(r"['\"](force_[a-z0-9_]+)['\"]", _API))
        for name, path in _AGENTS.items():
            declared = _declared_unread(path.read_text()) or set()
            gone = [d for d in declared
                    if not d.endswith('*') and d not in force_ish
                    and f"'{d}'" not in _API]
            self.assertEqual(gone, [], f'{name}: listed as unread but the '
                                       f'server never sends it: {gone}')


if __name__ == '__main__':
    unittest.main()
