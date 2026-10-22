#!/usr/bin/env python3
"""7.4.0: the log sensor tells the operator when fail2ban reports to AbuseIPDB or SniffCat itself.

RemotePower reads fail2ban's bans from its log and reports them, so a host whose fail2ban also reports
sends each address twice. The agent looks at the files an operator writes (jail.local, jail.d,
fail2ban.local), never at the package's jail.conf, which names both services in macros it does not use.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'tests'))
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

from test_v720_threat_sensor_agent import load_agent  # noqa: E402
import threat_sensor_handlers as tsh  # noqa: E402


def tree(files):
    root = Path(tempfile.mkdtemp(prefix='rp-f2b-'))
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return str(root)


class TestTheAgentFindsIt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent('agent_f2b_double')

    def found(self, files):
        return self.agent._ts_f2b_self_reports(tree(files))

    def test_an_action_in_jail_local(self):
        self.assertEqual(self.found({'jail.local': '[sshd]\nenabled = true\naction = %(action_)s\n         abuseipdb[abuseipdb_apikey="x"]\n'}),
                         ['abuseipdb'])

    def test_both_services_across_jail_d(self):
        self.assertEqual(self.found({'jail.local': '[DEFAULT]\nbanaction = x\n',
                                     'jail.d/a.conf': '[sshd]\naction = sniffcat[token=y]\n',
                                     'jail.d/b.local': '[recidive]\naction = %(action_abuseipdb)s\n'}),
                         ['abuseipdb', 'sniffcat'])

    def test_a_comment_does_not_count(self):
        self.assertEqual(self.found({'jail.local': '# action = abuseipdb[x]\n; sniffcat\n[sshd]\nenabled = true\n'}), [])

    def test_the_packages_own_jail_conf_does_not_count(self):
        self.assertEqual(self.found({'jail.conf': 'action_abuseipdb = abuseipdb\n', 'jail.local': ''}), [])

    def test_no_fail2ban_directory_is_not_an_error(self):
        self.assertEqual(self.agent._ts_f2b_self_reports('/nonexistent-f2b-root'), [])


class TestTheServerKeepsIt(unittest.TestCase):
    def row(self, extra):
        s = {'kind': 'f2b', 'path': '/var/log/fail2ban.log', 'state': 'ok', 'lines': 1, 'parsed': 1, 'events': 0}
        s.update(extra)
        return tsh._clean_sources([s])[0]

    def test_known_services_only_and_only_on_a_fail2ban_row(self):
        self.assertEqual(self.row({'self_reports': ['sniffcat', 'abuseipdb', 'evil<script>']})['self_reports'],
                         ['abuseipdb', 'sniffcat'])
        self.assertNotIn('self_reports', self.row({'self_reports': []}))
        self.assertNotIn('self_reports', self.row({'self_reports': 'abuseipdb'}))
        web = tsh._clean_sources([{'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok',
                                   'self_reports': ['abuseipdb']}])[0]
        self.assertNotIn('self_reports', web)


class TestTheCardSaysIt(unittest.TestCase):
    def test_the_note_is_wired(self):
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
        self.assertIn("_ipiPhrase('fail2ban already sends its own reports to')", js)
        self.assertIn('self_reports', js)
        agent = (_ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertIn("self_reports=sr", agent)


if __name__ == '__main__':
    unittest.main()
