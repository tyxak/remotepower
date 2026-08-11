#!/usr/bin/env python3
"""A NetFlow exporter that stops sending must be noticed.

Until v6.4.3 it was invisible. Nothing said "your exporter stopped": the
drawer's top-talkers view simply froze on its last window (`latest` was never
expired either — fixed in the same release), Server status showed the newest
ingest across ALL exporters so one healthy router masked every dead one, and
`_dependency_health` quietly degraded once the last window aged past
_DEP_EVIDENCE_TTL — turning a dead exporter into phantom "dependency missing"
alerts about links that were perfectly fine.

That is not theoretical. It was reported from a production host where flowd
had been dropping every packet for hours while the Self page rendered
"Flow receiver · Healthy · Running".

The sweep is edge-triggered and gated on `ever_seen`, deliberately: a token
created and never used is a configuration in progress, not an outage. The
threshold is hours because flowd skips empty windows, so an idle standby link
and a dead exporter are indistinguishable on the wire.

Every assertion below drives the REAL sweep and reads the REAL alert store —
CLAUDE.md's rule, because a hand-built {'payload': ...} dict bypasses the
_record_alert whitelist and gives a false green.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643flow-'))

_spec = importlib.util.spec_from_file_location('api_v643_flow', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

DEV = 'rtr-1'


class TestFlowExportStaleness(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        api.save(api.DEVICES_FILE, {DEV: {'name': 'edge-router', 'ip': '10.0.0.1',
                                          'last_seen': self.now}})
        api.save(api.FLOW_DEPS_FILE, {})
        api.save(api.ALERTS_FILE, {'alerts': [], 'alert_seq': 0})
        api.save(api.CONFIG_FILE, {'flow_export_check_seconds': 0})
        for f in (api.DEVICES_FILE, api.FLOW_DEPS_FILE, api.ALERTS_FILE,
                  api.CONFIG_FILE, api.INBOUND_WEBHOOKS_FILE):
            api._invalidate_load_cache(f)

    def _token(self, last_seen):
        api.save(api.INBOUND_WEBHOOKS_FILE, {'tokens': [
            {'id': 't1', 'kind': 'flow', 'enabled': True,
             'scope_device_id': DEV, 'token': 'x', 'last_seen': last_seen}]})
        api._invalidate_load_cache(api.INBOUND_WEBHOOKS_FILE)

    def _alerts(self):
        # NB the store is {'alerts': [...], 'alert_seq': N} — a dict with a
        # LIST under 'alerts', not a dict keyed by id. Reading .values() here
        # yields the list and an int and every assertion passes vacuously,
        # which is exactly what the first draft of this file did.
        st = api.load(api.ALERTS_FILE) or {}
        return [a for a in (st.get('alerts') or []) if isinstance(a, dict)]

    def _events(self):
        return [a.get('event') for a in self._alerts()]

    def _run(self):
        api._invalidate_load_cache(api.FLOW_DEPS_FILE)
        api.run_flow_export_check_if_due()
        api._invalidate_load_cache(api.ALERTS_FILE)

    def test_a_silent_exporter_fires(self):
        self._token(self.now - 5 * 3600)          # last export 5h ago
        # ever_seen must be established first — the gate is a TRANSITION
        self._run()
        self._run()
        self.assertIn('flow_export_stale', self._events())

    def test_a_healthy_exporter_does_not(self):
        """The positive control. Without it a sweep that fired unconditionally
        would satisfy the test above."""
        self._token(self.now - 60)
        self._run()
        self._run()
        self.assertNotIn('flow_export_stale', self._events())

    def test_a_token_that_never_exported_is_not_an_outage(self):
        """A capability token created while the operator is still configuring
        the router is a configuration in progress. Alerting on it would make
        the feature's own setup flow page somebody."""
        self._token(0)
        self._run()
        self._run()
        self.assertEqual(self._events(), [])

    def test_it_fires_once_not_every_sweep(self):
        self._token(self.now - 5 * 3600)
        for _ in range(4):
            self._run()
        self.assertEqual(self._events().count('flow_export_stale'), 1,
                         'edge-triggered means once per transition, not per sweep')

    def test_resuming_resolves_the_open_alert(self):
        """Drives the real _record_alert -> _auto_resolve path. A recover event
        whose match key was never whitelisted leaves the alert open forever,
        which is the documented failure mode for this whole class."""
        self._token(self.now - 5 * 3600)
        self._run(); self._run()
        self.assertIn('flow_export_stale', self._events())

        self._token(int(time.time()))             # export came back
        self._run()
        still_open = [a for a in self._alerts()
                      if a.get('event') == 'flow_export_stale'
                      and not a.get('resolved_at')]
        self.assertEqual(still_open, [],
                         'flow_export_resumed did not resolve the open alert — '
                         'check the sub_match key is in the _record_alert '
                         'whitelist')

    def test_a_deleted_token_drops_its_state(self):
        self._token(self.now - 5 * 3600)
        self._run(); self._run()
        api.save(api.INBOUND_WEBHOOKS_FILE, {'tokens': []})
        api._invalidate_load_cache(api.INBOUND_WEBHOOKS_FILE)
        self._run()
        st = (api.load(api.FLOW_DEPS_FILE) or {}).get('exporters') or {}
        self.assertNotIn(DEV, st, 'state for a removed token must be dropped, '
                                  'or it accumulates forever')

    def test_the_sweep_is_in_both_registries(self):
        """main()'s cadence AND scheduler.py's CADENCE tuple — the second one
        is the registry this project keeps forgetting."""
        self.assertIn('run_flow_export_check_if_due',
                      (_CGI / 'api.py').read_text())
        self.assertIn('run_flow_export_check_if_due',
                      (_CGI / 'scheduler.py').read_text())


if __name__ == '__main__':
    unittest.main()
