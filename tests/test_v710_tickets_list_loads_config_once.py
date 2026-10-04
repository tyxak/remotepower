"""GET /api/tickets does not copy the whole config for every ticket.

Each listed ticket gets a server-computed SLA due time, and working it out read the config three times with
load(): the type-agnostic policy, the per-type policy and the business-hours calendar. load() deep-copies the
store on every call, so 74 tickets made 231 copies of an 86 KB config (0.24 s profiled) and the cost grew
with the ticket count. The three reads are read-only, so they go through _config_ro() now.

This runs the real handler and counts load() calls, then checks the SLA arithmetic that those reads feed
(a per-type override, the generic override, the defaults, and a business-hours calendar) and that the shared
config object comes out of the request unchanged.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))

HOUR = 3600
NOW = 1_800_000_000          # a Friday


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710-tkt-')
    spec = importlib.util.spec_from_file_location('api_v710_tkt', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        api = self.api
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'x'
        api.verify_token = lambda tok=None: ('alice', 'admin')
        api.require_auth = lambda *a, **k: ('alice', 'admin')
        api.method = lambda: 'GET'
        api._env = lambda k, d='': d
        self.cap = {}

        def _respond(s, d=None, headers=None):
            self.cap['s'], self.cap['d'] = s, d
            raise api.HTTPError(s, d)
        api.respond = _respond

    def seed(self, n, ttype='incident', priority=2, config=None):
        api = self.api
        api.save(api.CONFIG_FILE, config or {})
        tickets = [{'id': 't%d' % i, 'number': 1000 + i, 'subject': 's%d' % i, 'type': ttype, 'status': 'ongoing',
                    'priority': priority, 'created_at': NOW - 600, 'updated_at': NOW - i}
                   for i in range(n)]
        api.save(api.TICKETS_FILE, {'tickets': tickets})
        api._LOAD_CACHE.clear()

    def listing(self):
        """(tickets, {store file name: load() calls}) for one real GET /api/tickets."""
        api = self.api
        api._LOAD_CACHE.clear()
        calls = {}
        real = api.load

        def counting(path, *a, **k):
            name = Path(str(path)).name
            calls[name] = calls.get(name, 0) + 1
            return real(path, *a, **k)

        api.load = counting
        self.cap.clear()
        try:
            api.handle_tickets()
        except (api.HTTPError, SystemExit):
            pass
        finally:
            api.load = real
        self.assertEqual(200, self.cap.get('s'), self.cap)
        return self.cap['d']['tickets'], calls


class TestTheListDoesNotCopyTheConfigPerTicket(_Base):

    def test_config_loads_do_not_grow_with_the_number_of_tickets(self):
        self.seed(5)
        small_list, small = self.listing()
        self.seed(60)
        big_list, big = self.listing()
        self.assertEqual(5, len(small_list))
        self.assertEqual(60, len(big_list), 'control: every ticket should be listed')
        self.assertLessEqual(big.get('config.json', 0), 1, 'config was loaded %r times for 60 tickets' % big.get('config.json'))
        self.assertEqual(small, big, 'load() calls grew with the ticket count: %r -> %r' % (small, big))


class TestTheSlaArithmeticIsUnchanged(_Base):

    def due(self, **seed):
        self.seed(1, **seed)
        tickets, _ = self.listing()
        return tickets[0]['sla_due']

    def test_defaults_apply_with_no_config(self):
        self.assertEqual(NOW - 600 + 4 * HOUR, self.due(priority=2), 'P2 defaults to four hours')

    def test_the_generic_override_applies(self):
        self.assertEqual(NOW - 600 + 6 * HOUR, self.due(priority=2, config={'ticket_sla': {'2': 6}}))

    def test_a_per_type_override_beats_the_generic_one_for_its_own_type_only(self):
        cfg = {'ticket_sla': {'2': 6}, 'ticket_sla_by_type': {'incident': {'2': 2}}}
        self.assertEqual(NOW - 600 + 2 * HOUR, self.due(ttype='incident', priority=2, config=cfg))
        self.assertEqual(NOW - 600 + 6 * HOUR, self.due(ttype='request', priority=2, config=cfg))

    def test_a_business_hours_calendar_is_honoured(self):
        """Open every day all day: business time equals wall-clock time. Closed on the Friday the ticket is
        raised: the clock does not start until Saturday, so the due time moves out by more than the target."""
        always = {str(d): [[0, 1440]] for d in range(7)}
        open_cfg = {'ticket_business_hours': {'enabled': True, 'tz_offset_min': 0, 'weekly': always}}
        self.assertEqual(NOW - 600 + 4 * HOUR, self.due(priority=2, config=open_cfg))
        never_friday = dict(always)
        never_friday['4'] = []
        closed_cfg = {'ticket_business_hours': {'enabled': True, 'tz_offset_min': 0, 'weekly': never_friday}}
        self.assertGreater(self.due(priority=2, config=closed_cfg), NOW - 600 + 4 * HOUR)

    def test_the_shared_config_comes_out_of_the_request_unchanged(self):
        cfg = {'ticket_sla': {'2': 6}, 'ticket_sla_by_type': {'incident': {'2': 2}},
               'ticket_business_hours': {'enabled': True, 'tz_offset_min': 0,
                                         'weekly': {str(d): [[0, 1440]] for d in range(7)}, 'holidays': ['2030-01-01']}}
        self.seed(3, config=cfg)
        before = self.api.load(self.api.CONFIG_FILE)
        self.listing()
        self.assertEqual(before, self.api.load(self.api.CONFIG_FILE))


if __name__ == '__main__':
    unittest.main()
