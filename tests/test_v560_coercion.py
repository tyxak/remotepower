"""v5.6.0 — a malformed (non-dict) JSON body must never 500 a POST handler.

A live pentest of the deployed server found `POST /api/config` and
`POST /api/integrations` returning HTTP 500 when the body was a top-level JSON
array — the `get_json_body() or {}` idiom passes a truthy array straight through
to `.get()`. These handlers (and every other `or {}` site) now use
`get_json_obj()`, which coerces any non-dict → {}. This test pins that no handler
still uses the fragile idiom.
"""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-coerce-'))

_API = (Path(__file__).parent.parent / 'server' / 'cgi-bin' / 'api.py').read_text()


class TestNoFragileBodyIdiom(unittest.TestCase):
    def test_no_get_json_body_or_empty_dict(self):
        # The idiom that 500s on a truthy non-dict body must be gone entirely.
        self.assertNotIn('get_json_body() or {}', _API,
                         "use get_json_obj() — 'get_json_body() or {}' 500s on a JSON array body")

    def test_config_and_integrations_use_coercing_reader(self):
        # Either the direct coercing reader, or the _read_valid() helper which
        # reads the body via get_json_obj() internally — both coerce a non-dict
        # body to {} and never 500 on a top-level JSON array.
        for fn in ('handle_config_save', 'handle_integrations_save'):
            seg = _API[_API.index('def ' + fn): _API.index('def ' + fn) + 400]
            self.assertTrue('get_json_obj()' in seg or '_read_valid(' in seg,
                            f'{fn} must read its body with get_json_obj() or _read_valid()')


if __name__ == '__main__':
    unittest.main()
