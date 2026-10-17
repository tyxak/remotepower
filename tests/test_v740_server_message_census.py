#!/usr/bin/env python3
"""7.4.0: one spelling and one status for every server error message, and 401 means "no session".

The same words came back spelled two ways ("Host not found" 138 times, "host not found" 65) and with
two statuses ("invalid host id" as 400 and as 404, "site not found" as 400 and 404, a bad status
token as 401 and 403). A client that wants to react to a message, or a person who greps a log for
one, had to know both. This reads every `respond(<status>, {'error': '<literal>'})` in the server
modules and fails on a message that appears in two forms.

The status half is not only tidiness. The dashboard's `api()` treats every 401 as "your session is
gone" and signs you out. Four prompts that check your own password (the step-up dialog, turning 2FA
off, new recovery codes, changing your password) answered 401 for a wrong one, so a typo threw you
back to the login page with no reason. A refused credential inside a valid session is a 403; 401 is
for a request that has no valid session or token. `ALLOWED_401` lists the messages that mean that.
test_v740_reauth_failure_e2e.py drives the real page against the real server.
"""
import ast
import functools
import unittest
from collections import defaultdict
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
SKIP = {'storage.py', 'storage_pg.py'}          # store internals raise, they do not answer a request

# 401, lower-cased: each says there is no valid session or token on the request, which is what the
# dashboard assumes when it sees one. Add a message here only if that is what it means.
ALLOWED_401 = {
    'unauthorized', 'not authenticated', 'not signed in', 'session expired', 'access revoked',
    'invalid token', 'invalid or disabled token', 'invalid satellite token', 'satellite token required',
    'invalid or expired link', 'invalid or missing status token',
    # The CMDB vault client reads this one itself (app-cmdb.js tells a locked vault from an expired
    # session by the `vault_locked` code), so it does not reach api()'s logout.
    'vault locked',
}


def sites_of(source, name='<source>'):
    """(file, line, status, message) for each respond(<int>, {'error': '<literal>'}) in `source`."""
    out = []
    for n in ast.walk(ast.parse(source)):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if (f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', '')) != 'respond' or len(n.args) < 2:
            continue
        status, body = n.args[0], n.args[1]
        if not (isinstance(status, ast.Constant) and isinstance(status.value, int) and isinstance(body, ast.Dict)):
            continue
        for k, v in zip(body.keys, body.values):
            if isinstance(k, ast.Constant) and k.value == 'error' and isinstance(v, ast.Constant) \
                    and isinstance(v.value, str):
                out.append((name, n.lineno, status.value, v.value))
    return out


def key_of(message):
    return message.strip().rstrip('.').lower()


@functools.lru_cache(maxsize=None)
def _census():
    sites = []
    for p in sorted(CGI.glob('*.py')):
        if p.name not in SKIP:
            sites += sites_of(p.read_text(encoding='utf-8'), p.name)
    return tuple(sites)


def census():
    return list(_census())


def two_spellings(sites):
    by = defaultdict(lambda: defaultdict(list))
    for f, ln, _st, msg in sites:
        by[key_of(msg)][msg].append(f'{f}:{ln}')
    return {k: dict(v) for k, v in by.items() if len(v) > 1}


def two_statuses(sites):
    by = defaultdict(lambda: defaultdict(list))
    for f, ln, st, msg in sites:
        by[key_of(msg)][st].append(f'{f}:{ln}')
    return {k: dict(v) for k, v in by.items() if len(v) > 1}


def _show(found, limit=12):
    lines = []
    for k, forms in list(found.items())[:limit]:
        lines.append(f'  {k!r}: ' + '; '.join(f'{form!r} at {", ".join(where[:3])}' for form, where in forms.items()))
    return '\n' + '\n'.join(lines)


class TestTheCensusSeesTheServer(unittest.TestCase):
    def test_the_population_is_the_whole_server(self):
        sites = census()
        self.assertGreater(len(sites), 2000, 'the census found almost nothing')
        self.assertGreater(len({key_of(s[3]) for s in sites}), 900)
        self.assertGreater(len({s[0] for s in sites}), 30)

    def test_it_reports_what_it_should(self):
        """Control: the checks below can say no."""
        src = ("def a():\n    respond(404, {'error': 'Host not found'})\n"
               "def b():\n    A.respond(404, {'error': 'host not found'})\n"
               "def c():\n    respond(400, {'error': 'Host not found.'})\n"
               "def d():\n    respond(200, {'ok': True})\n"
               "def e():\n    respond(404, {'error': f'x {1}'})\n")
        got = sites_of(src, 'x.py')
        self.assertEqual(len(got), 3)
        self.assertEqual(set(two_spellings(got)['host not found']), {'Host not found', 'host not found', 'Host not found.'})
        self.assertEqual(set(two_statuses(got)['host not found']), {404, 400})


class TestOneForm(unittest.TestCase):
    def test_one_spelling_per_message(self):
        found = two_spellings(census())
        self.assertEqual(found, {}, 'these messages are written two ways; use one (the commoner, capitalised on a tie):'
                         + _show(found))

    def test_one_status_per_message(self):
        found = two_statuses(census())
        self.assertEqual(found, {}, 'these messages answer with two statuses; a client cannot react to one:'
                         + _show(found))


class TestFourOhOneMeansNoSession(unittest.TestCase):
    def test_only_session_and_token_messages_answer_401(self):
        extra = defaultdict(list)
        for f, ln, st, msg in census():
            if st == 401 and key_of(msg) not in ALLOWED_401:
                extra[msg].append(f'{f}:{ln}')
        self.assertEqual(dict(extra), {},
                         'api() signs the person out on any 401. A refused credential inside a valid session is a 403; '
                         'if this message really means "no valid session or token", add it to ALLOWED_401: '
                         + repr(dict(extra)))

    def test_the_allow_list_is_not_stale(self):
        used = {key_of(m) for _f, _ln, st, m in census() if st == 401}
        self.assertEqual(sorted(ALLOWED_401 - used), [], 'these never answer 401 any more; delete them from ALLOWED_401')


if __name__ == '__main__':
    unittest.main()
