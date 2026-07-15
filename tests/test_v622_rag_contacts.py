"""v6.2.2 — contacts RAG source (fill: fleet knowledge not fed to the AI).

The internal contact directory (team phonebook) is now a RAG source so the
model can answer "who do I call about host X / vendor Y / this site?". A RAG
source needs FIVE wiring spots or it half-works (CLAUDE.md); this pins all
five plus drives the builder.
"""

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import unittest

_spec = importlib.util.spec_from_file_location("rag_index_v622c", _CGI / "rag_index.py")
rag = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rag)

_API_SRC = (_CGI / "api.py").read_text()
_APP_AI = (_ROOT / "server/html/static/js/app-ai.js").read_text()
_HTML = (_ROOT / "server/html/index.html").read_text()


class TestBuilder(unittest.TestCase):
    def test_one_doc_per_contact_plus_index(self):
        store = {"contacts": [
            {"id": "c1", "name": "Dana Ops", "role": "Network vendor",
             "company": "Acme ISP", "email": "dana@acme.example", "phone": "555-1",
             "site": "dc1", "notes": "escalation for WAN issues"},
            {"id": "c2", "name": "Sam NOC", "role": "On-call"},
        ]}
        docs = rag.build_contacts_corpus(store, now=1000)
        # 2 contacts + 1 index
        self.assertEqual(len(docs), 3)
        blob = "\n".join(d.get("text", "") for d in docs)
        self.assertIn("Dana Ops", blob)
        self.assertIn("Acme ISP", blob)
        self.assertIn("escalation for WAN issues", blob)
        idx = [d for d in docs if d.get("id", "").endswith("_index")]
        self.assertEqual(len(idx), 1)
        self.assertIn("2 contact(s)", idx[0]["text"])

    def test_empty_and_malformed_safe(self):
        self.assertEqual(rag.build_contacts_corpus(None), [])
        self.assertEqual(rag.build_contacts_corpus({}), [])
        self.assertEqual(rag.build_contacts_corpus({"contacts": "nope"}), [])
        # a non-dict entry is skipped, not fatal
        docs = rag.build_contacts_corpus({"contacts": [None, {"id": "x", "name": "Y"}]})
        self.assertTrue(any("Y" in d.get("text", "") for d in docs))


class TestIncidentsBuilder(unittest.TestCase):
    def test_one_doc_per_incident_plus_index(self):
        store = {"incidents": [
            {"id": "i1", "title": "WAN outage", "impact": "major", "status": "resolved",
             "updates": [{"ts": 1, "status": "investigating", "body": "ISP down"},
                         {"ts": 2, "status": "resolved", "body": "link restored"}]},
            {"id": "i2", "title": "Slow dashboards", "impact": "minor", "status": "monitoring"},
        ]}
        docs = rag.build_incidents_corpus(store, now=1000)
        self.assertEqual(len(docs), 3)
        blob = "\n".join(d.get("text", "") for d in docs)
        self.assertIn("WAN outage", blob)
        self.assertIn("link restored", blob)
        idx = [d for d in docs if d.get("id", "").endswith("_index")]
        self.assertEqual(len(idx), 1)
        self.assertIn("2 total", idx[0]["text"])

    def test_empty_and_malformed_safe(self):
        self.assertEqual(rag.build_incidents_corpus(None), [])
        self.assertEqual(rag.build_incidents_corpus({"incidents": "x"}), [])


class TestMaintenanceBuilder(unittest.TestCase):
    def test_windows_and_index(self):
        store = {"windows": [
            {"id": "w1", "reason": "DB upgrade", "match_type": "group",
             "pattern": "dc1/prod", "cron": "0 3 * * 0", "suppress_alerts": True},
            {"id": "w2", "reason": "kernel patch", "match_type": "all", "start": 1700},
        ]}
        docs = rag.build_maintenance_corpus(store, now=1000)
        self.assertEqual(len(docs), 3)
        blob = "\n".join(d.get("text", "") for d in docs)
        self.assertIn("DB upgrade", blob)
        self.assertIn("dc1/prod", blob)
        self.assertIn("whole fleet", blob)  # match_type all
        idx = [d for d in docs if d.get("id", "").endswith("_index")]
        self.assertIn("2 defined", idx[0]["text"])

    def test_empty_and_malformed_safe(self):
        self.assertEqual(rag.build_maintenance_corpus(None), [])
        self.assertEqual(rag.build_maintenance_corpus({"windows": 5}), [])


class TestFiveSpotWiring(unittest.TestCase):
    def test_spot1_default_on(self):
        self.assertIn("'contacts':", _API_SRC)
        self.assertIn("'incidents':", _API_SRC)

    def test_spot2_staleness_file_registered(self):
        self.assertIn("if sources.get('contacts'):", _API_SRC)
        self.assertIn("files.append(CONTACTS_FILE)", _API_SRC)
        self.assertIn("if sources.get('incidents'):", _API_SRC)
        self.assertIn("files.append(INCIDENTS_FILE)", _API_SRC)
        self.assertIn("if sources.get('maintenance'):", _API_SRC)
        self.assertIn("files.append(MAINT_FILE)", _API_SRC)

    def test_spot3_builder_called_in_orchestrator(self):
        self.assertIn("rag_index.build_contacts_corpus", _API_SRC)
        self.assertIn("rag_index.build_incidents_corpus", _API_SRC)
        self.assertIn("rag_index.build_maintenance_corpus", _API_SRC)

    def test_spot4_save_whitelisted(self):
        # miss this and the Settings toggle silently never persists
        i = _API_SRC.index("cur['rag']['sources'][k] = bool")
        whitelist = _API_SRC[max(0, i - 500):i]
        self.assertIn("'contacts'", whitelist)
        self.assertIn("'incidents'", whitelist)
        self.assertIn("'maintenance'", whitelist)

    def test_spot5_ui_checkbox_and_load_and_save(self):
        for src in ("contacts", "incidents", "maintenance"):
            self.assertIn(f'id="ai-rag-src-{src}"', _HTML)
            self.assertIn(f"ai-rag-src-{src}", _APP_AI)        # _setSrc load
            self.assertIn(f"{src}:", _APP_AI)                  # save object


if __name__ == "__main__":
    unittest.main()
