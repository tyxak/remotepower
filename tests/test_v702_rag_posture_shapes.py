#!/usr/bin/env python3
"""Three RAG posture lines could never appear.

`build_posture_corpus` is what lets the AI answer "is anything thermally
throttled?" or "which hosts have a decoy that failed to arm?" from fleet data.
Three of its readers were written against shapes no agent produces:

  throttle    read `.status`, a string; the agent sends decoded bit flags
  wifi        read a dict with ssid/signal_dbm; the agent sends a LIST of
              {iface, link, level_dbm, noise_dbm} — one row per interface
  canary_status  read a dict with `tripped`; it is a LIST of per-path arm
              records, and a TRIP is a different signal entirely (canary_events
              → the canary_accessed webhook)

The demo seeder wrote those same three invented shapes, which is how both sides
looked consistent while neither matched the product. Fixing one without the
other would have left the corpus empty for real fleets and full for the demo.

Driven with the AGENT's shapes, so the test fails if the agent changes and this
does not.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('rag_v702', _CGI / 'rag_index.py')
rag = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rag)


def _devices(sysinfo):
    """A LIST of device dicts, each carrying its own `id`.

    `build_live_state_corpus` takes an iterable, not the devices.json map.
    Passing the map iterates its KEYS, every `isinstance(dev, dict)` is False,
    and the builder returns nothing — so every "the old shape is not read"
    assertion passes while measuring an empty corpus. That mistake has been
    made against this exact function before.
    """
    return [{'id': 'd1', 'name': 'web01', 'sysinfo': sysinfo}]


def _corpus_text(sysinfo):
    """The per-device posture lines live in build_live_state_corpus, not
    build_posture_corpus (which is instance-level: mTLS, backup encryption).
    Naming the right builder matters — the wrong one returns three unrelated
    docs and every assertion below would be about those."""
    docs = rag.build_live_state_corpus(_devices(sysinfo), {}, now=1_700_000_000)
    text = '\n'.join(d.get('text', '') for d in docs)
    assert docs, 'the builder returned nothing — the fixture is wrong'
    return text


class TestThrottleReadsTheAgentsFlags(unittest.TestCase):

    def test_throttling_now_is_reported(self):
        txt = _corpus_text({'platform_health': {'throttle': {
            'undervolt_now': True, 'throttled_now': True,
            'undervolt_since_boot': True, 'raw': '0x50005'}}})
        self.assertIn('throttling NOW', txt)
        self.assertIn('undervolt', txt)

    def test_since_boot_is_reported_separately(self):
        """A host that browned out at 3am and recovered is a different problem
        from one throttling right now."""
        txt = _corpus_text({'platform_health': {'throttle': {
            'undervolt_since_boot': True, 'raw': '0x10000'}}})
        self.assertIn('since boot', txt)
        self.assertNotIn('NOW', txt)

    def test_a_clean_host_says_nothing(self):
        txt = _corpus_text({'platform_health': {'throttle': {
            'undervolt_now': False, 'throttled_now': False, 'raw': '0x0'}}})
        self.assertNotIn('throttl', txt.lower())

    def test_the_old_status_string_is_not_what_it_reads(self):
        """The shape that shipped. Nothing produces it, and reading it was the
        bug — so it must not quietly keep working either."""
        txt = _corpus_text({'platform_health': {
            'throttle': {'status': 'under-voltage detected'}}})
        self.assertNotIn('under-voltage detected', txt)


class TestWifiReadsTheAgentsList(unittest.TestCase):

    def test_an_interface_row_is_reported_with_snr(self):
        txt = _corpus_text({'platform_health': {'wifi': [
            {'iface': 'wlan0', 'link': 54.0,
             'level_dbm': -62.0, 'noise_dbm': -92.0}]}})
        self.assertIn('wlan0', txt)
        self.assertIn('-62 dBm', txt)
        self.assertIn('SNR 30 dB', txt)

    def test_missing_noise_still_reports_the_level(self):
        txt = _corpus_text({'platform_health': {'wifi': [
            {'iface': 'wlan1', 'level_dbm': -70.0}]}})
        self.assertIn('-70 dBm', txt)
        self.assertNotIn('SNR', txt)

    def test_the_old_dict_shape_is_not_read(self):
        txt = _corpus_text({'platform_health': {
            'wifi': {'ssid': 'lab-wifi', 'signal_dbm': -55}}})
        self.assertNotIn('lab-wifi', txt)
        self.assertNotIn('-55', txt)


class TestCanaryReadsTheArmReport(unittest.TestCase):

    def test_an_unarmed_decoy_is_reported(self):
        """The part with no other screen. A decoy the agent could not plant is
        a control the operator has stopped worrying about."""
        txt = _corpus_text({'canary_status': [
            {'path': '/srv/.backup-key.pem', 'state': 'failed',
             'detail': 'Read-only file system'},
            {'path': '/home/a/passwords.txt', 'state': 'armed', 'detail': ''}]})
        self.assertIn('NOT armed', txt)
        self.assertIn('/srv/.backup-key.pem', txt)
        self.assertIn('Read-only file system', txt)

    def test_all_armed_reports_the_count(self):
        txt = _corpus_text({'canary_status': [
            {'path': '/a', 'state': 'armed', 'detail': ''},
            {'path': '/b', 'state': 'armed', 'detail': ''}]})
        self.assertIn('2 canary', txt)
        self.assertNotIn('NOT armed', txt)

    def test_the_old_tripped_dict_is_not_read(self):
        txt = _corpus_text({'canary_status': {'tripped': True,
                                              'path': '/srv/x.pem'}})
        self.assertNotIn('/srv/x.pem', txt)


class TestTheSeederAgreesWithTheseReaders(unittest.TestCase):
    """Both sides carried the same invented shapes, which is how they looked
    consistent while neither matched the product."""

    def test_the_seeder_writes_a_canary_list(self):
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.exists():
            self.skipTest('seeder excluded from dist tree')
        src = seeder.read_text()
        self.assertNotIn("si['canary_status'] = {", src,
                         'the seeder is back to a dict')
        self.assertNotIn("'signal_dbm'", src, 'the seeder is back to the '
                                              'invented wifi shape')
        self.assertNotIn("'status': 'under-voltage detected'", src)


if __name__ == '__main__':
    unittest.main()
