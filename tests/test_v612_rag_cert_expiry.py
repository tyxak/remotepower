"""Guardrail: the RAG live-state corpus must actually carry local cert expiry.

The bug (found in the v6.1.2 data-binding sweep): `_rag_build_corpus` populated its
`cert_expiry` facet from

    certs = (d.get('sysinfo') or {}).get('cert_files')

but `cert_files` is never a sysinfo field — `_ingest_hardware` writes it to
HARDWARE_FILE. So the expression was always None, the facet was never set, and the
AI/RAG corpus never saw local certificate expiry at all, despite the comment right
above it promising exactly that. A dead read, silently producing an empty facet.

Why nothing caught it: the RAG tests exercise the pure `build_live_state_corpus`
builder (which was fine — it was never handed the data), and the api-wiring tests
are SOURCE-TEXT checks (`assertIn("f['cert_expiry']", _API_SRC)`) that see the line
present and pass without running it. The only test that can catch this class is one
that DRIVES the real path with a device whose certs live where the ingest actually
puts them — so that is what this does.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")

_spec = importlib.util.spec_from_file_location("api_v612_rag", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestLiveStateCertExpiry(unittest.TestCase):

    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        api.DEVICES_FILE = tmp / 'devices.json'
        api.HARDWARE_FILE = tmp / 'hardware.json'
        api.CVE_FINDINGS_FILE = tmp / 'cve.json'
        api.CONTAINERS_FILE = tmp / 'containers.json'
        api.SNMP_DATA_FILE = tmp / 'snmp.json'
        api.ALERTS_FILE = tmp / 'alerts.json'
        for f in (api.CVE_FINDINGS_FILE, api.CONTAINERS_FILE,
                  api.SNMP_DATA_FILE, api.ALERTS_FILE):
            api.save(f, {})

    def _corpus(self):
        return api._rag_build_corpus({'rag': {'sources': {'live_state': True}}})

    def test_cert_files_from_hardware_store_reach_the_corpus(self):
        # sysinfo is deliberately EMPTY — this is the real shape. The certs live in
        # HARDWARE_FILE, which is where _ingest_hardware puts them.
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01', 'sysinfo': {}}})
        api.save(api.HARDWARE_FILE, {'d1': {'cert_files': [
            {'path': '/etc/ssl/certs/site.pem', 'expires_in_days': 7,
             'subject': 'example.com'},
        ]}})
        blob = "\n".join(str(d) for d in self._corpus())
        self.assertIn('cert_expiry', blob,
                      'the live-state corpus carries no cert_expiry facet — the AI '
                      'cannot see local certificate expiry')
        self.assertIn('/etc/ssl/certs/site.pem', blob)

    def test_no_certs_means_no_facet(self):
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01', 'sysinfo': {}}})
        api.save(api.HARDWARE_FILE, {})
        blob = "\n".join(str(d) for d in self._corpus())
        self.assertNotIn('cert_expiry', blob)

    def test_sysinfo_cert_files_is_not_the_source(self):
        """Pins the actual bug: certs placed in sysinfo (where the old code looked)
        are NOT what the corpus reads — so a future 'fix' that reverts to sysinfo
        fails here instead of silently emptying the facet again."""
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01', 'sysinfo': {
            'cert_files': [{'path': '/wrong/place.pem', 'expires_in_days': 3}]}}})
        api.save(api.HARDWARE_FILE, {})
        blob = "\n".join(str(d) for d in self._corpus())
        self.assertNotIn('/wrong/place.pem', blob)


if __name__ == '__main__':
    unittest.main()
