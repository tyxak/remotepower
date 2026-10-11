"""An anonymous caller gets 401 whether or not the thing it names exists.

These handlers looked the object up first, so `404 not found` against `401`
told anyone on the network which device ids, tickets, scans, backup jobs, tags
and groups exist. Authentication now comes first. Each case is shown red by
moving the lookup back above the check.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-authfirst-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class _Captured(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body


class _Rewindable:
    """A request body that can be read more than once, as the real server's is
    (handlers such as handle_update_device read it twice)."""

    def __init__(self, raw):
        self._raw = raw

    def read(self, n=-1):
        return self._raw if n is None or n < 0 else self._raw[:n]


class _Stdin:
    def __init__(self, raw):
        self.buffer = _Rewindable(raw)


def _request(method, body=None):
    api._begin_request()          # the body and load caches are per request
    os.environ['REQUEST_METHOD'] = method
    os.environ['PATH_INFO'] = '/api/x'
    raw = b'' if body is None else json.dumps(body).encode()
    os.environ['CONTENT_LENGTH'] = str(len(raw))
    api.sys.stdin = _Stdin(raw)
    os.environ.pop('HTTP_X_TOKEN', None)
    os.environ.pop('HTTP_AUTHORIZATION', None)


def _status(fn, *args):
    def fake(status, data=None, *a, **k):
        raise _Captured(status, data)
    orig = api.respond
    api.respond = fake
    try:
        fn(*args)
        return None
    except _Captured as c:
        return c.status
    finally:
        api.respond = orig


class TestAuthBeforeLookup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp(prefix='rp-authfirst-')
        os.environ['RP_DATA_DIR'] = d
        for name in ('USERS_FILE', 'TOKENS_FILE', 'DEVICES_FILE', 'AUDIT_LOG_FILE', 'CONFIG_FILE'):
            if hasattr(api, name):
                setattr(api, name, Path(d) / Path(getattr(api, name)).name)
        api.ensure_default_user()
        api.save(api.DEVICES_FILE, {'realdev1': {'name': 'real', 'tags': ['prod'], 'group': 'web'}})

    def test_device_subresources_do_not_say_which_ids_exist(self):
        # The handler modules are bound to api's namespace, so go through api.
        for fn in (api.handle_device_ssh, api.handle_device_snmp,
                   api.handle_device_routeros, api.handle_device_opnsense):
            for meth in ('GET', 'PATCH'):
                for dev in ('realdev1', 'nosuchdev'):
                    _request(meth)
                    self.assertEqual(_status(fn, dev), 401, (fn.__name__, meth, dev))

    def test_scan_and_backup_job_and_ticket_lookups(self):
        _request('DELETE')
        self.assertEqual(_status(api.handle_scan_delete, 'nosuchscan'), 401)
        _request('POST')
        self.assertEqual(_status(api.handle_backup_job_run, 'nosuchjob'), 401)
        for meth in ('GET', 'POST'):
            _request(meth)
            self.assertEqual(_status(api.handle_ticket_hours, 'nosuchticket'), 401, meth)

    def test_tag_and_group_names_are_not_an_oracle(self):
        # A tag that exists and one that does not must look the same.
        for body in ({'tag': 'prod'}, {'tag': 'nosuchtag'},
                     {'group': 'web'}, {'group': 'nosuchgroup'}):
            for fn in (api.handle_reboot, api.handle_shutdown, api.handle_update_device,
                       api.handle_custom_cmd):
                _request('POST', dict(body, cmd='id'))
                self.assertEqual(_status(fn), 401, (fn.__name__, body))


if __name__ == '__main__':
    unittest.main()
