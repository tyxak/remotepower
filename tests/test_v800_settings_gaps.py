#!/usr/bin/env python3
"""8.0.0: two settings that the server read and the documentation named, with no control in Settings.

A survey of every key `POST /api/config` accepts against every name the page uses found 28 the page never mentions. Most are state the server keeps for itself or secrets
that belong in the configuration file, but two were options an operator is told about and cannot set:

  viewers_can_ack_alerts   who may acknowledge, resolve and assign alerts (Settings, Alerts inbox); features.md lists "Admin-only alert mutation" as a feature
  saml_sp_entity_id        the identifier the identity provider has registered for this server (Settings, SAML); sso.md said "no Settings field"

This file holds the server's half: the switch is on until it is turned off, a save without the key leaves it alone, and the entity ID is the one the SAML configuration is built
with, falling back to the metadata URL when it is blank. tests/test_v800_settings_gaps_e2e.py presses the controls.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-settings-gaps-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))

_ROOT = Path(__file__).resolve().parent.parent
_HTML = (_ROOT / "server" / "html" / "index.html").read_text()
_APP = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()


class _Recorder:
    """Stands in for pysaml2's SPConfig and keeps the settings it is given: the question is which entity ID the server hands it, and the real class needs the xmlsec1
    program to load an identity provider's metadata, which this test must not need."""
    last = None

    def load(self, settings):
        type(self).last = settings


def _entity_id_for(rp_cfg, base):
    try:
        import saml_auth
    except ImportError as exc:                                      # pragma: no cover
        raise unittest.SkipTest("pysaml2 is not installed: %s" % exc)
    with mock.patch.object(saml_auth, "SPConfig", _Recorder):
        saml_auth._sp_config(rp_cfg, base)
    return _Recorder.last["entityid"]


class TestTheSamlEntityIdIsTheOneTheConfigurationIsBuiltWith(unittest.TestCase):

    BASE = "https://rp.example.com"

    def cfg(self, **extra):
        out = {"saml_idp_entity_id": "https://idp.example.com/meta", "saml_idp_sso_url": "https://idp.example.com/sso", "saml_idp_x509_cert": ""}
        out.update(extra)
        return out

    def test_a_blank_entity_id_falls_back_to_the_metadata_url(self):
        self.assertEqual(_entity_id_for(self.cfg(saml_sp_entity_id=""), self.BASE), self.BASE + "/api/saml/metadata")

    def test_an_entity_id_that_is_set_is_used(self):
        self.assertEqual(_entity_id_for(self.cfg(saml_sp_entity_id="urn:remotepower:prod"), self.BASE), "urn:remotepower:prod")

    def test_a_missing_key_is_a_blank_one(self):
        self.assertEqual(_entity_id_for(self.cfg(), self.BASE), self.BASE + "/api/saml/metadata")


class TestTheControlsAreInThePageAndWiredBothWays(unittest.TestCase):
    """A control that is drawn but not read on load or not sent on save does nothing; each id is checked in its four places."""

    def test_each_control_is_in_the_markup_once_and_read_on_load_and_sent_on_save(self):
        for control, key in (("cfg-viewers-can-ack", "viewers_can_ack_alerts"), ("saml-sp-entity-id", "saml_sp_entity_id")):
            self.assertEqual(len(re.findall(r'id="%s"' % control, _HTML)), 1, control)
            self.assertRegex(_APP, r"""getElementById\('%s'\)|setIf\('%s'""" % (control, control), "%s is read on load" % control)
            self.assertIn("%s:" % key, _APP, "%s is sent on save" % key)

    def test_the_switch_is_on_in_the_markup_and_stays_on_unless_the_server_says_false(self):
        self.assertRegex(_HTML, r'<input type="checkbox" id="cfg-viewers-can-ack" checked>')
        self.assertIn("data.viewers_can_ack_alerts !== false", _APP)
        self.assertIn("(document.getElementById('cfg-viewers-can-ack') || {}).checked ?? true", _APP)

    def test_the_server_names_both_keys_among_the_ones_it_saves(self):
        api = (_ROOT / "server" / "cgi-bin" / "api.py").read_text()
        self.assertIn("cfg['viewers_can_ack_alerts'] = bool(body['viewers_can_ack_alerts'])", api)
        self.assertIn("'saml_sp_entity_id'", api)

    def test_the_documentation_no_longer_says_there_is_no_field(self):
        sso = (_ROOT / "docs" / "sso.md").read_text()
        self.assertFalse("no Settings field" in sso, "docs/sso.md still says the SP entity ID has no Settings field")
        self.assertTrue("| SP entity ID | `saml_sp_entity_id` |" in sso, "docs/sso.md lists the field in the SAML table")
        features = (_ROOT / "docs" / "features.md").read_text()
        self.assertTrue("Settings, Alerts inbox" in features, "docs/features.md says where the switch is")


if __name__ == "__main__":
    unittest.main()
