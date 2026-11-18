#!/usr/bin/env python3
"""No shipped text says that an enrolment token works once, or for one host, without saying what changes that.

A token enrols one host unless it was made for more (`max_uses`, 1 to 1000, "Hosts that can use it" in the Enroll dialog). Texts written
before that said "one-time token", "a token enrols one host, so mint one per host" and "one token enrols one host", and they stayed
behind in a README line, two guide pages, the in-app Documentation page and three nginx comments while the installer, the dialog and
the other guides said the new thing. The Quick install command and the Docker file now take the number, so the old sentences were
wrong the moment a person set it.

The population is read from the files: the README, every guide in docs/ except the release notes and the reviews (history is allowed to
say what was true then), the installers, the nginx snippets, the in-app Documentation page and the dialog's scripts. A line that says it
flat is a finding, unless it is listed here with the reason it is right, or listed as PENDING for a file whose owner changes it in the release
notes pass. Both lists only shrink: an entry whose text is gone fails the test, so the fix has to remove it.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

FLAT = re.compile(
    r"(?i)\b(?:one-time|single-use|single use|one time)\b[^.\n]{0,40}\btokens?\b"
    r"|\btokens?\b[^.\n]{0,40}\b(?:one-time|single-use)\b"
    r"|\b(?:one|a) tokens? enrol(?:ls|s) one host"
    r"|mint one per host|one token per host")
# what makes a line a conditional claim
CONDITION = re.compile(r"(?i)unless|max_uses|for more|made for|one by default|Hosts that can use it|works once")

# (file, text that identifies the line) -> why the line is right as written
EXEMPT = {
    ('docs/install.md', 'The same as from a single-use token'):
        'it names the kind of token a host gets nothing more from; the many-hosts section it sits in is about the other kind',
    ('server/html/static/js/app.js', "the token is one-time and expires in 24h."):
        'the arm of `uses > 1 ? ... : ...` that is shown for a token made for one host',
    ('server/html/static/js/app.js', "One-time token, expires in 24h."):
        'the arm of `uses > 1 ? ... : ...` that is shown for a token made for one host',
}

# (file, text) -> who changes it. These are still wrong today; the entry is removed in the commit that fixes the line.
PENDING = {}     # the release notes pass has changed the three lines it listed (README.md and two rows of docs/features.md); a line found later is listed here with its owner


def population():
    files = [_ROOT / 'README.md', _ROOT / 'install.sh', _ROOT / 'install-server.sh', _ROOT / 'deploy-server.sh', _ROOT / 'docker' / 'entrypoint.sh',
             _ROOT / 'server' / 'html' / 'index.html']
    files += sorted((_ROOT / 'docs').glob('*.md'))
    files += sorted((_ROOT / 'server' / 'conf').glob('*.conf')) + sorted((_ROOT / 'docker').glob('*.conf'))
    files += sorted((_ROOT / 'server' / 'html' / 'static' / 'js').glob('app*.js'))
    return [f for f in files if f.exists() and not re.match(r'(v\d|security-review)', f.name if f.parent.name == 'docs' else '')]


def flat_lines():
    """[(relative path, line number, line)] for every line that says an enrolment token is one-time or for one host, with nothing in the line
    that makes it conditional."""
    out = []
    for path in population():
        rel = str(path.relative_to(_ROOT))
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if FLAT.search(line) and not CONDITION.search(line):
                out.append((rel, n, line))
    return out


class TestNoFlatClaim(unittest.TestCase):

    def test_the_population_is_the_shipped_text(self):
        # the control: a scan that read nothing would pass the test below for the wrong reason
        files = population()
        self.assertGreater(len(files), 100, len(files))
        names = {str(f.relative_to(_ROOT)) for f in files}
        for must in ('README.md', 'docs/install.md', 'docs/docker-agent.md', 'docs/provisioning.md', 'server/html/index.html',
                     'server/conf/remotepower-locations.conf', 'docker/nginx-docker-locations.conf', 'server/html/static/js/app.js'):
            self.assertIn(must, names)
        self.assertFalse([n for n in names if re.match(r'docs/(v\d|security-review)', n)], 'release notes and reviews are not part of it')

    def test_every_flat_line_is_listed_with_a_reason_or_is_pending(self):
        listed = set(EXEMPT) | set(PENDING)
        unknown = [(rel, n, line.strip()[:120]) for rel, n, line in flat_lines() if not any(rel == f and text in line for f, text in listed)]
        self.assertEqual(unknown, [], 'these say a token is one-time or for one host and nothing else: say what changes that')

    def test_the_scan_sees_the_old_wording(self):
        # the control for the pattern itself: the sentences this module was written for are all found by it
        for old in ('A token enrols one host, so mint one per host.', 'Your server URL and a one-time token (valid for 24 hours)',
                    'replace it with a one-time token from Hosts', 'the caller supplies the one-time --token',
                    'your server URL + a one-time token pre-filled', 'script with THIS server\'s URL + one-time token baked in'):
            self.assertTrue(FLAT.search(old) and not CONDITION.search(old), old)
        for fine in ('A token enrols one host unless you made it for more', 'a token enrols as many hosts as it was made for (one by default)',
                     'Enrollment PINs are single-use', 'the enrolment token'):
            self.assertFalse(FLAT.search(fine) and not CONDITION.search(fine), fine)

    def test_a_listed_line_still_exists(self):
        lines = flat_lines()
        for (f, text), why in list(EXEMPT.items()) + list(PENDING.items()):
            self.assertTrue(why.strip())
            self.assertTrue(any(rel == f and text in line for rel, _n, line in lines),
                            'the line is gone or became conditional: remove the entry for %s (%s)' % (f, text))

    def test_the_two_exempt_arms_of_the_dialog_are_the_single_host_arms(self):
        lines = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text().splitlines()
        arms = [i for i, line in enumerate(lines) if any(text in line for (f, text) in EXEMPT if f.endswith('app.js'))]
        self.assertEqual(len(arms), 2, arms)
        for i in arms:
            self.assertTrue(lines[i].lstrip().startswith(": '"), 'not the second arm of a ternary: ' + lines[i][:80])
            self.assertTrue(lines[i - 1].lstrip().startswith('? '), 'no first arm before it: ' + lines[i - 1][:80])
            self.assertIn('uses > 1', lines[i - 2], 'the first arm is not the many-hosts one')


if __name__ == '__main__':
    unittest.main()
