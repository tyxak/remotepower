"""The scanner container must not be able to reach Postgres.

The compose stack ships Postgres with a published fallback password so that
`docker compose up -d` works with nothing configured. The scanner runs a tool that
reads responses from hosts an attacker influences, and on the shared default
network it could reach `postgres:5432` with that password, and the database holds
every device token and session. Postgres therefore sits on a private network that
only the app joins.

This reads the compose file as text. It used to import PyYAML and skip without it,
and PyYAML is not in the CI dependency list, so on the CI that gates a release the
guard never ran (found in the v7.4.1 work, where the dependency set was resolved
and checked). A guard that skips where it matters is worth less than one that
reads a file.
"""
import re
import unittest
from pathlib import Path

_COMPOSE = (Path(__file__).resolve().parent.parent / 'docker-compose.yml').read_text()


def _code(text):
    return '\n'.join(ln for ln in text.splitlines() if not ln.lstrip().startswith('#'))


def services():
    """{name: block text} for the entries under the top-level `services:` key."""
    body = re.search(r'(?m)^services:\n((?:[ \t]+.*\n|\n)+)', _code(_COMPOSE) + '\n')
    assert body, 'no services: key in docker-compose.yml'
    out = {}
    for m in re.finditer(r'(?m)^  ([A-Za-z0-9_-]+):\n((?:    .*\n|\n)+)', body.group(1)):
        out[m.group(1)] = m.group(2)
    return out


def list_under(block, key):
    """The `- item` entries under a 4-space-indented `key:` of a service block."""
    m = re.search(r'(?m)^    %s:\n((?:      - .*\n)+)' % re.escape(key), block)
    return [ln.strip()[2:].strip().strip('"\'') for ln in m.group(1).splitlines()] if m else []


class TestComposeNetworks(unittest.TestCase):
    def setUp(self):
        self.svc = services()

    def test_the_population_is_the_three_services(self):
        """A parser that found nothing would let every assertion below pass."""
        self.assertEqual(sorted(self.svc), ['postgres', 'remotepower', 'scanner'])

    def test_postgres_is_only_on_the_private_network(self):
        self.assertEqual(list_under(self.svc['postgres'], 'networks'), ['db'])
        net = re.search(r'(?m)^networks:\n((?:  .*\n|\n)+)', _code(_COMPOSE) + '\n')
        self.assertTrue(net, 'no top-level networks: key')
        db = re.search(r'(?m)^  db:\n((?:    .*\n)+)', net.group(1))
        self.assertTrue(db, 'the db network is not declared')
        self.assertRegex(db.group(1), r'(?m)^    internal:\s*true\b')

    def test_the_app_reaches_both(self):
        nets = list_under(self.svc['remotepower'], 'networks')
        self.assertIn('db', nets)
        self.assertIn('default', nets)          # browsers, agents and the scanner come in here

    def test_the_scanner_is_not_on_it(self):
        self.assertNotIn('db', list_under(self.svc['scanner'], 'networks'))

    def test_postgres_publishes_no_port(self):
        self.assertNotRegex(self.svc['postgres'], r'(?m)^    ports:')


if __name__ == '__main__':
    unittest.main()
