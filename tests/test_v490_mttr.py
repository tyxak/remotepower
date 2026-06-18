"""v4.9.0 ResolutionMatters #4 — alert-resolution timeline (MTTR).

Route registration + the resolution-classification helper."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_v490_mttr', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestResolutionHow(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(api._alert_resolution_how({'resolved_by': 'auto'}), 'auto')
        self.assertEqual(api._alert_resolution_how({'resolved_by': 'exposure-mute'}), 'muted')
        self.assertEqual(api._alert_resolution_how({'resolved_by': 'alice'}), 'manual')
        self.assertEqual(api._alert_resolution_how({}), 'unknown')


class TestRoute(unittest.TestCase):
    def test_route_registered(self):
        self.assertIn(('GET', '/api/alerts/resolution-stats'), api._build_exact_routes())


if __name__ == '__main__':
    unittest.main()
