#!/usr/bin/env python3
"""A receipt needs an identity. `ts` is not one.

Receipts were keyed only by `ts`, which is `int(time.time())` — a whole second.
A sweep builds every candidate's plan in the same pass, so several receipts
routinely share one. Verification then:

  1. keyed its verdict dict on ts, so N same-second receipts collapsed to a
     single verdict — whichever was computed last;
  2. wrote that verdict, its `after_checks` counts and its outcome text onto
     EVERY row with that ts, across devices and across tenants.

So a host whose remediation worked could be marked unverified and carry another
host's failing-check counts, and a host whose remediation made things worse
could be marked verified. The receipt is the one artifact whose entire purpose
is answering "why did it do that?", and it was answering about a different
machine — including one in another tenant.

The `remediation_failed` webhook was unaffected: it fires off the per-receipt
list, not the ts map. Only the PERSISTED record lied, which is the half nobody
watches in real time.

Receipts now carry `id`. Rows written before that fall back to
(ts, device_id) — still not unique in principle, but it separates the case that
actually occurs, which is one sweep touching several hosts at once.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-receipt-'))

import importlib.util  # noqa: E402

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules['api'] = api
_spec.loader.exec_module(api)
ops = api.autonomy_ops_handlers_mod

_NOW = 1800000000
_TS = _NOW - 1000          # both receipts stamped the SAME second


class _Base(unittest.TestCase):

    def setUp(self):
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {
            'devA': {'name': 'web-a', 'tenant': 'acme', 'last_seen': _NOW},
            'devB': {'name': 'db-b', 'tenant': 'globex', 'last_seen': _NOW},
        })
        self._real_summary = ops._check_summary_for
        self._real_fire = api.fire_webhook
        # devA recovered, devB regressed. Distinct on purpose: identical
        # summaries would make a cross-assigned verdict indistinguishable from
        # a correct one, and the test would pass either way.
        self._summaries = {'devA': {'failing': 0, 'total': 10},
                           'devB': {'failing': 5, 'total': 10}}
        ops._check_summary_for = lambda dev_id, dev: self._summaries[dev_id]
        self.fired = []
        api.fire_webhook = lambda ev, payload=None, **k: self.fired.append(ev)

    def tearDown(self):
        ops._check_summary_for = self._real_summary
        api.fire_webhook = self._real_fire

    def _seed(self, with_ids):
        rows = []
        for i, (did, name, tenant) in enumerate(
                (('devA', 'web-a', 'acme'), ('devB', 'db-b', 'globex'))):
            r = {'ts': _TS, 'tenant': tenant, 'device_id': did,
                 'device_name': name, 'action': 'restart_service',
                 'verdict': 'act', 'verified': None, 'verify_due': _TS + 1,
                 'before_checks': {'failing': 0, 'total': 10},
                 'outcome': 'queued'}
            if with_ids:
                r['id'] = f'rcpt_test{i}'
            rows.append(r)
        api.save(api.AUTONOMY_RECEIPTS_FILE, {'receipts': rows})
        api._LOAD_CACHE.clear()

    def _verify_and_read(self, with_ids=True):
        self._seed(with_ids)
        ops._verify_due_receipts(_NOW)
        api._LOAD_CACHE.clear()
        rows = (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []
        return {r['device_name']: r for r in rows}


class TestTheFixtureActuallyCollides(_Base):
    """Every assertion below depends on the two receipts sharing a timestamp.
    If they ever stop sharing one, the tests pass while measuring nothing."""

    def test_both_receipts_carry_the_same_ts(self):
        self._seed(with_ids=True)
        rows = (api.load(api.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts')
        self.assertEqual({r['ts'] for r in rows}, {_TS})

    def test_the_two_hosts_have_different_outcomes(self):
        self.assertNotEqual(self._summaries['devA'], self._summaries['devB'])


class TestEachReceiptGetsItsOwnVerdict(_Base):

    def test_the_recovered_host_is_verified(self):
        got = self._verify_and_read()
        self.assertIs(got['web-a']['verified'], True,
                      'its failing checks did not increase')

    def test_the_regressed_host_is_not(self):
        got = self._verify_and_read()
        self.assertIs(got['db-b']['verified'], False)

    def test_neither_carries_the_other_hosts_numbers(self):
        got = self._verify_and_read()
        self.assertEqual(got['web-a']['after_checks'], {'failing': 0, 'total': 10})
        self.assertEqual(got['db-b']['after_checks'], {'failing': 5, 'total': 10})

    def test_only_the_regressed_host_fires_the_event(self):
        self._verify_and_read()
        self.assertEqual(self.fired, ['remediation_failed'])

    def test_legacy_receipts_without_an_id_are_still_separated(self):
        """Rows written before receipts carried an id must not regress into the
        old behaviour — the (ts, device_id) fallback covers the case that
        actually happens, one sweep touching several hosts."""
        got = self._verify_and_read(with_ids=False)
        self.assertIs(got['web-a']['verified'], True)
        self.assertIs(got['db-b']['verified'], False)


class TestNewReceiptsCarryAnId(unittest.TestCase):

    def test_the_plan_stamps_one(self):
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h', 'tenant': None}})
        plan = ops._build_plan({'event': 'failed_unit', 'payload': {}},
                               'restart_service',
                               {'name': 'h'}, 'd1', {'score': 0}, None)
        self.assertTrue(str(plan.get('id', '')).startswith('rcpt_'),
                        f'plan has no id: {plan.get("id")!r}')

    def test_two_plans_in_the_same_second_differ(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h', 'tenant': None}})
        mk = lambda: ops._build_plan(  # noqa: E731
            {'event': 'failed_unit', 'payload': {}}, 'restart_service',
            {'name': 'h'}, 'd1', {'score': 0}, None)
        a, b = mk(), mk()
        self.assertEqual(a['ts'], b['ts'], 'the fixture is not testing a '
                                           'same-second collision')
        self.assertNotEqual(a['id'], b['id'])

    def test_the_receipt_carries_it_through(self):
        r = ops.autonomy.receipt({'id': 'rcpt_abc', 'ts': 1},
                                 {'verdict': 'act', 'reason': None})
        self.assertEqual(r['id'], 'rcpt_abc')


if __name__ == '__main__':
    unittest.main()
