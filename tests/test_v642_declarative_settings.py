"""v6.4.2 — config-as-code carries the tuning, not just the resources.

`_declarative_collections()` returned 18 operator-authored RESOURCE collections
and no scalar setting. So an operator who does exactly what the document invites
— it literally says "safe to commit to version control" — commits it, treats git
as the source of truth, and six months of tuning later rebuilds the controller
from the repo. Monitors, checks, automation rules and maintenance windows come
back exactly. Every threshold they tuned — the inode warning percent, the CVSS
bands, the disk-fill forecast R², the risk-factor weights they zeroed to kill a
false-positive class — silently reverts to its shipped default, and the fleet
starts paging on rules they retired months ago. Nothing in the export, the
import report or the docs said the scalars were not carried.

The settings block is deliberately SEPARATE from `resources` because it
reconciles differently: resources are whole-collection replace, and blanket-
replacing every config scalar would clobber the per-install infrastructure
(storage, tokens, SSO, SMTP) that shares the same file.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-declset642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestTheTunableKeySetIsDerived(unittest.TestCase):
    """Hand-keeping ~120 key names is the same class of bug one level down: the
    list drifts the first time a tunable is added through the standard path."""

    def test_it_parses_the_real_save_loop(self):
        keys = api._alert_param_config_keys()
        self.assertGreater(len(keys), 80,
                           "the parse collapsed — a self-reference or a moved "
                           "anchor, and the export silently carries almost "
                           "nothing")
        for k in ("inode_warn_percent", "cvss_band_critical", "forecast_min_r2",
                  "min_online_ttl", "command_history_max"):
            with self.subTest(key=k):
                self.assertIn(k, keys)

    def test_it_includes_the_generated_weight_keys(self):
        self.assertIn("risk_weight_offline", api._alert_param_config_keys())

    def test_the_anchor_is_not_self_referential(self):
        """The first version searched for a literal the helper itself contains,
        found ITSELF (earlier in the file), and parsed its own docstring — so
        the key set silently collapsed to the 42 weight keys."""
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def _alert_param_config_keys"):]
        fn = fn[:fn.index("\ndef ")]
        anchor = "\\n    for _tk"
        self.assertIn(anchor, fn,
                      "anchor on the STATEMENT form, or this matches the "
                      "helper's own string literal")


class TestExport(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {
            "inode_warn_percent": 88, "risk_weight_offline": 0,
            "cvss_band_critical": 9.5, "online_ttl": 600,
            "smtp_password": "hunter2", "status_token": "stok",
            "oidc_client_secret": "x", "alerts_enabled": False,
            "tickets_module_enabled": False})
        api._LOAD_CACHE.clear()

    def test_tuned_scalars_are_exported(self):
        st = api._declarative_settings()
        self.assertEqual(st["inode_warn_percent"], 88)
        self.assertEqual(st["risk_weight_offline"], 0)
        self.assertEqual(st["cvss_band_critical"], 9.5)

    def test_a_module_kill_switch_is_carried(self):
        """Read the key off _MODULES rather than naming it — the alerts module's
        key is `alerts_enabled`, and tickets uses `tickets_module_enabled`
        because the original key was poisoned by a default-false history. A
        hardcoded name here would be wrong for one of them."""
        st = api._declarative_settings()
        for _name, spec in api._MODULES.items():
            with self.subTest(module=_name):
                if spec[0] in (api.load(api.CONFIG_FILE) or {}):
                    self.assertIn(spec[0], st)

    def test_no_secret_reaches_a_document_called_safe_to_commit(self):
        st = api._declarative_settings()
        for k in ("smtp_password", "status_token", "oidc_client_secret"):
            with self.subTest(key=k):
                self.assertNotIn(k, st)

    def test_an_untuned_key_is_not_exported_at_its_default(self):
        """Exporting every default would make the document a snapshot of the
        shipped values rather than of what the operator changed — and it would
        then overwrite a NEWER default on the next upgrade."""
        self.assertNotIn("tls_warn_days", api._declarative_settings())

    def test_the_document_carries_the_block(self):
        doc = api._build_declarative_config()
        self.assertIn("settings", doc)
        self.assertIn("resources", doc)
        self.assertIsNot(doc["settings"], doc["resources"],
                         "folded into resources, which reconciles differently")


class TestImportRoundTrip(unittest.TestCase):
    def setUp(self):
        self._audit = api.audit_log
        api.audit_log = lambda *a, **k: None

    def tearDown(self):
        api.audit_log = self._audit

    def test_a_rebuild_restores_the_tuning(self):
        """The whole finding, end to end: tune, export, wipe, import."""
        api.save(api.CONFIG_FILE, {"inode_warn_percent": 88,
                                   "risk_weight_offline": 0,
                                   "online_ttl": 600})
        api._LOAD_CACHE.clear()
        doc = api._build_declarative_config()

        api.save(api.CONFIG_FILE, {"smtp_password": "set-during-the-rebuild"})
        api._LOAD_CACHE.clear()
        api._declarative_apply(doc, "jakob", dry_run=False)

        cfg = api.load(api.CONFIG_FILE) or {}
        self.assertEqual(cfg.get("inode_warn_percent"), 88)
        self.assertEqual(cfg.get("risk_weight_offline"), 0)
        self.assertEqual(cfg.get("online_ttl"), 600)

    def test_it_merges_rather_than_replacing(self):
        """A key absent from the document is left alone — the document carries
        only tuning, and the per-install infrastructure shares the same file."""
        api.save(api.CONFIG_FILE, {"smtp_password": "keep-me"})
        api._LOAD_CACHE.clear()
        api._declarative_apply(
            {"schema": api.DECLARATIVE_SCHEMA, "resources": {},
             "settings": {"online_ttl": 900}}, "jakob", dry_run=False)
        cfg = api.load(api.CONFIG_FILE) or {}
        self.assertEqual(cfg.get("smtp_password"), "keep-me")
        self.assertEqual(cfg.get("online_ttl"), 900)

    def test_a_hand_edited_document_cannot_write_anything_it_likes(self):
        """This path writes straight into config.json. Without the allowlist it
        would be a way to set a secret, or the storage backend, from a file
        somebody committed to a repo."""
        api.save(api.CONFIG_FILE, {"smtp_password": "keep-me"})
        api._LOAD_CACHE.clear()
        api._declarative_apply(
            {"schema": api.DECLARATIVE_SCHEMA, "resources": {},
             "settings": {"smtp_password": "pwned", "storage_backend": "x",
                          "inode_warn_percent": 70}},
            "jakob", dry_run=False)
        cfg = api.load(api.CONFIG_FILE) or {}
        self.assertEqual(cfg.get("smtp_password"), "keep-me")
        self.assertIsNone(cfg.get("storage_backend"))
        self.assertEqual(cfg.get("inode_warn_percent"), 70)

    def test_refusals_are_reported_not_silent(self):
        """A silently-dropped setting is one the operator believes was applied."""
        r = api._declarative_apply(
            {"schema": api.DECLARATIVE_SCHEMA, "resources": {},
             "settings": {"smtp_password": "x", "inode_warn_percent": 70}},
            "jakob", dry_run=True)
        self.assertEqual(r["report"]["settings"]["applied"], 1)
        self.assertIn("smtp_password", r["report"]["settings"]["refused"])

    def test_a_document_with_no_settings_block_still_imports(self):
        r = api._declarative_apply(
            {"schema": api.DECLARATIVE_SCHEMA, "resources": {}}, "jakob",
            dry_run=True)
        self.assertTrue(r["ok"])
        self.assertNotIn("settings", r["report"])

    def test_a_malformed_settings_block_is_reported_not_applied(self):
        r = api._declarative_apply(
            {"schema": api.DECLARATIVE_SCHEMA, "resources": {},
             "settings": ["not", "an", "object"]}, "jakob", dry_run=True)
        self.assertIn("skipped", r["report"]["settings"])

    def test_export_and_import_share_one_allowlist(self):
        """Two lists would drift, and a key exportable but not importable is a
        setting that silently does not come back — the finding, one level down."""
        src = (_CGI / "api.py").read_text()
        exp = src[src.index("def _declarative_settings():"):]
        exp = exp[:exp.index("\ndef ")]
        self.assertIn("_declarative_settings_allowed()", exp)
        imp = src[src.index("def _declarative_apply("):]
        imp = imp[:imp.index("\ndef ")]
        self.assertIn("_declarative_settings_allowed()", imp)


if __name__ == "__main__":
    unittest.main()
