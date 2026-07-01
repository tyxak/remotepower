"""v5.6.0: custom_check_failed / custom_check_recovered alert events.

Custom Check-catalog checks (process/port/file/unit/log/job) used to be
evaluated ONLY when the Checks page was loaded — a failing check never paged
anyone. They are now edge-triggered on the heartbeat by
`_ingest_custom_check_results`, which fires `custom_check_failed` on an
ok→failing transition and `custom_check_recovered` on failing→ok.

These tests drive the REAL ingest → fire_webhook → _record_alert path (a
hand-built alert dict would bypass the payload whitelist + coalescing, giving a
false green — see the webhook-registry rules). They assert:
  * the alert names the failing check, the issue (output) and the host (hostname);
  * severity is payload-derived (critical → high, agent 'warning' → medium);
  * a repeat failing beat coalesces (one open alert, not a stack);
  * an 'unknown' beat (agent briefly stops reporting) is NOT a false failure;
  * recovery auto-resolves the open alert (per host + check id).

Imports api.py against a throwaway data dir (the established pattern); runs
under both backends via `make test-both`.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402

CHECK = {'id': 'c1', 'name': 'Caddy running', 'type': 'process',
         'param': 'caddy', 'target_kind': 'all'}


def _set_config(checks=(CHECK,)):
    api.save(api.CONFIG_FILE, {'custom_checks': list(checks)})
    api._invalidate_load_cache(api.CONFIG_FILE)


def _set_procs(dev_id, name, procs):
    """RMW the device so previously-stored custom_check_state survives (the
    edge-trigger state lives on the device record)."""
    devs = api.load(api.DEVICES_FILE) or {}
    d = devs.get(dev_id) or {'name': name, 'monitored': True}
    d['name'] = name
    d.setdefault('sysinfo', {})['proc_names'] = list(procs)
    devs[dev_id] = d
    api.save(api.DEVICES_FILE, devs)
    api._invalidate_load_cache(api.DEVICES_FILE)


def _open_alerts():
    return [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
            if not a.get('resolved_at')]


class TestCustomCheckAlert(unittest.TestCase):

    def setUp(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api._invalidate_load_cache(api.ALERTS_FILE)
        _set_config()

    def test_seed_fail_recover(self):
        dev, host = 'd-caddy', 'web01'
        # 1) first beat with caddy running → seed 'ok', no alert
        _set_procs(dev, host, ['caddy', 'sshd'])
        api._ingest_custom_check_results(dev, host)
        self.assertEqual(_open_alerts(), [], "seed must not alert")

        # 2) caddy gone → 'critical' → custom_check_failed
        _set_procs(dev, host, ['sshd'])
        api._ingest_custom_check_results(dev, host)
        opn = _open_alerts()
        self.assertEqual(len(opn), 1)
        a = opn[0]
        self.assertEqual(a['event'], 'custom_check_failed')
        self.assertEqual(a['severity'], 'high')          # the prio
        self.assertEqual(a['device_name'], host)         # the hostname
        self.assertIn('Caddy running', a['title'])       # the check name
        self.assertIn('not running', a['title'])         # the issue (output)
        self.assertEqual(a['payload'].get('check_name'), 'Caddy running')
        self.assertEqual(a['payload'].get('check_id'), 'c1')
        self.assertIn('not running', a['payload'].get('output', ''))

        # 3) caddy back → 'ok' → recover auto-resolves the open alert
        _set_procs(dev, host, ['caddy', 'sshd'])
        api._ingest_custom_check_results(dev, host)
        self.assertEqual(_open_alerts(), [], "recovery must auto-resolve")

    def test_repeat_failing_coalesces(self):
        dev, host = 'd2', 'h2'
        _set_procs(dev, host, ['caddy'])
        api._ingest_custom_check_results(dev, host)      # seed ok
        _set_procs(dev, host, [])
        api._ingest_custom_check_results(dev, host)      # fail
        api._ingest_custom_check_results(dev, host)      # still failing
        api._ingest_custom_check_results(dev, host)      # still failing
        self.assertEqual(len(_open_alerts()), 1,
                         "a still-failing check must coalesce, not stack")

    def test_unknown_is_not_a_failure(self):
        dev, host = 'd3', 'h3'
        _set_procs(dev, host, ['caddy'])
        api._ingest_custom_check_results(dev, host)      # seed ok
        # agent stops reporting proc_names → _eval_custom_check → 'unknown'
        devs = api.load(api.DEVICES_FILE) or {}
        devs[dev]['sysinfo'] = {}
        api.save(api.DEVICES_FILE, devs)
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._ingest_custom_check_results(dev, host)
        self.assertEqual(_open_alerts(), [],
                         "'unknown' (no data) must not fire a false failure")

    def test_warning_status_is_medium(self):
        # Payload-derived severity: an agent 'warning' → medium, not high.
        self.assertEqual(
            api._alert_severity('custom_check_failed', {'status': 'warning'}),
            'medium')
        self.assertEqual(
            api._alert_severity('custom_check_failed', {'status': 'critical'}),
            'high')

    def test_registry_wiring(self):
        names = {e[0] for e in api.WEBHOOK_EVENTS}
        self.assertIn('custom_check_failed', names)
        self.assertIn('custom_check_recovered', names)
        # channelable (routing matrix kind) + recover mapping
        self.assertEqual(api.EVENT_KIND_MAP.get('custom_check_failed'), 'custom_check')
        self.assertEqual(api.EVENT_KIND_MAP.get('custom_check_recovered'), 'custom_check')
        self.assertEqual(api._ALERT_RECOVER.get('custom_check_recovered'),
                         'custom_check_failed')


if __name__ == '__main__':
    unittest.main()
