"""The scanner container must not be able to reach Postgres.

The compose stack ships Postgres with a published fallback password so that
`docker compose up -d` works with nothing configured. The scanner runs a tool that
reads responses from hosts an attacker influences, and on the shared default
network it could reach `postgres:5432` with that password, and the database holds
every device token and session. Postgres therefore sits on a private network that
only the app joins.
"""
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:                                   # pragma: no cover
    yaml = None

_COMPOSE = Path(__file__).resolve().parent.parent / 'docker-compose.yml'


@unittest.skipIf(yaml is None, 'PyYAML not installed')
class TestComposeNetworks(unittest.TestCase):
    def setUp(self):
        self.doc = yaml.safe_load(_COMPOSE.read_text())
        self.svc = self.doc['services']

    def test_postgres_is_only_on_the_private_network(self):
        self.assertEqual(self.svc['postgres'].get('networks'), ['db'])
        self.assertTrue(self.doc['networks']['db'].get('internal'))

    def test_the_app_reaches_both(self):
        nets = self.svc['remotepower'].get('networks')
        self.assertIn('db', nets)
        self.assertIn('default', nets)          # browsers, agents and the scanner come in here

    def test_the_scanner_is_not_on_it(self):
        self.assertNotIn('db', self.svc['scanner'].get('networks') or [])

    def test_postgres_publishes_no_port(self):
        self.assertFalse(self.svc['postgres'].get('ports'))


if __name__ == '__main__':
    unittest.main()
