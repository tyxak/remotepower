"""v5.1.0 "VigilMatters" feature tests — fail2ban_ban first-class event."""
import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v510_feat", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestFail2banEventWiring(unittest.TestCase):
    def test_in_webhook_events(self):
        self.assertIn('fail2ban_ban', api.WEBHOOK_EVENT_NAMES)

    def test_alert_severity_mapped(self):
        # 2/4 silent registries: _ALERT_RULES → severity, else no inbox alert.
        self.assertEqual(api._alert_severity('fail2ban_ban', {}), 'medium')

    def test_channel_kind_resolved(self):
        # 3/4 silent registry: CHANNEL_KINDS → EVENT_KIND_MAP row.
        self.assertEqual(api.EVENT_KIND_MAP.get('fail2ban_ban'), 'fail2ban')

    def test_webhook_title_and_message(self):
        p = {'name': 'web01', 'jail': 'sshd', 'first_ip': '1.2.3.4', 'new_count': 3}
        self.assertEqual(api._webhook_title('fail2ban_ban'), 'fail2ban Ban')
        msg = api._webhook_message('fail2ban_ban', p)
        self.assertIn('sshd', msg)
        self.assertIn('1.2.3.4', msg)
        title = api._alert_title('fail2ban_ban', p)
        self.assertIn('1.2.3.4', title)
        self.assertIn('web01', title)

    def test_not_a_recover_event(self):
        # fire-only; must not be in the recover map (no auto-resolve needed).
        self.assertNotIn('fail2ban_ban', api._ALERT_RECOVER)


class TestFail2banAlertCoalesce(unittest.TestCase):
    def test_repeat_bans_coalesce_per_host(self):
        # Two bans on the same host (different IPs) collapse to ONE open alert
        # with a bumped count — payload carries no identity field, so identity
        # is (event, device_id). Keeps a brute-force flood out of the inbox.
        a1 = api._record_alert('fail2ban_ban', {
            'device_id': 'dev-f2b-1', 'name': 'web01',
            'jail': 'sshd', 'first_ip': '1.2.3.4', 'new_count': 1})
        self.assertIsNotNone(a1)
        a2 = api._record_alert('fail2ban_ban', {
            'device_id': 'dev-f2b-1', 'name': 'web01',
            'jail': 'sshd', 'first_ip': '5.6.7.8', 'new_count': 1})
        self.assertEqual(a1['id'], a2['id'], "second ban should coalesce, not append")
        self.assertGreaterEqual(int(a2.get('count') or 1), 2)


if __name__ == "__main__":
    unittest.main()
