#!/usr/bin/env python3
"""v7.5.0 (data binding): four more signals reach the risk score.

Security updates waiting, the Gatekeeper and System Integrity Protection settings
on a Mac, Defender's signatures, tamper protection and UAC on Windows, and a
container in a restart loop were Checks rows, alerts or Fleet Query facets and
counted for nothing in a host's score, while the same host's firewall and disk
encryption counted in full.

ECC is not one of them on purpose: the reliability score weighs it, and a hardware
fault counted in two scores makes both wrong (the 7.0.3 note beside the weights).
`TestEccStaysOut` holds that decision.

The Windows and macOS values come from each agent's own parser, and the container
record from the real report path, because a fixture is the consumer's idea of the
producer.
"""
import importlib.util
import json
import os
import pathlib
import re
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-risk-"))

_spec = importlib.util.spec_from_file_location("api_v750_risk", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "client" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


winagent = _load("rp_win_agent_v750_risk", "remotepower-agent-win.py")
macagent = _load("rp_mac_agent_v750_risk", "remotepower-agent-mac.py")

NEW = ("security_updates", "mac_protection_off", "win_protection_off", "container_crashloop")


def _win(**over):
    """Windows posture as the agent's parser builds it from the PowerShell JSON.
    Everything healthy unless overridden; a key set to None is left out."""
    raw = {"firewall": [{"name": "Domain", "enabled": True}],
           "bitlocker": [{"mount": "C:", "status": "On"}],
           "defender_realtime": True, "defender_sig_age_days": 1,
           "tamper_protection": True, "uac_enabled": True, "secure_boot": True,
           "wu_service": "Running", "wu_start": "Manual"}
    raw.update(over)
    raw = {k: v for k, v in raw.items() if v is not None}
    return winagent._parse_win_posture(json.dumps(raw))


def _mac(gatekeeper="assessments enabled", sip="System Integrity Protection status: enabled."):
    return macagent._parse_mac_posture("FileVault is On.", "Firewall is enabled. (State = 1)",
                                       gatekeeper, sip, "1")


def _risk(si, **kw):
    dev = {"name": "h1", "last_seen": int(time.time()), "monitored": True, "sysinfo": si}
    return api._device_risk("d1", dev, {}, {}, {}, int(time.time()), 180, **kw)


def _factor(res, kind):
    hit = [f for f in res["factors"] if f["kind"] == kind]
    return hit[0] if hit else None


class _CfgBase(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._files = {}
        for a in ("CONFIG_FILE", "DEVICES_FILE", "CONTAINERS_FILE", "ALERTS_FILE",
                  "FLEET_EVENTS_FILE"):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / pathlib.Path(self._files[a]).name)
        self.set_config()

    def tearDown(self):
        for a, v in self._files.items():
            setattr(api, a, v)
        api._LOAD_CACHE.clear()

    def set_config(self, **cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)


class TestRegistries(unittest.TestCase):

    def test_every_new_factor_is_weighted_capped_and_labelled(self):
        js = (ROOT / "server/html/static/js/app.js").read_text()
        for k in NEW:
            self.assertIn(k, api._RISK_WEIGHTS)
            self.assertIn(k, api._RISK_CAPS)
            self.assertGreaterEqual(api._RISK_CAPS[k], api._RISK_WEIGHTS[k])
            # assertTrue(re.search), not assertRegex: a miss would print the whole bundle.
            self.assertTrue(re.search(r"\b%s: %d\b" % (k, api._RISK_WEIGHTS[k]), js),
                            "default weight of %s missing from app.js" % k)
            self.assertTrue(re.search(r"\b%s: '\S" % k, js), "label of %s missing" % k)
            self.assertIn('id="ap-rw-%s"' % k,
                          (ROOT / "server/html/index.html").read_text())


class TestSecurityUpdates(_CfgBase):

    def test_scored_per_update_on_top_of_the_pending_count(self):
        r = _risk({"packages": {"upgradable": 10, "security_updates": 4}})
        f = _factor(r, "security_updates")
        self.assertEqual(f["points"], 12)
        self.assertIn("4 security updates waiting", f["detail"])
        self.assertIsNotNone(_factor(r, "pending_updates"))

    def test_capped(self):
        r = _risk({"packages": {"upgradable": 90, "security_updates": 60}})
        self.assertEqual(_factor(r, "security_updates")["points"],
                         api._RISK_CAPS["security_updates"])

    def test_a_host_with_no_count_scores_nothing(self):
        for pk in ({"upgradable": 5}, {"upgradable": 5, "security_updates": None},
                   {"upgradable": 5, "security_updates": 0}):
            self.assertIsNone(_factor(_risk({"packages": pk}), "security_updates"), pk)

    def test_a_count_of_the_wrong_kind_scores_nothing(self):
        for bad in (True, "7", 3.5):
            r = _risk({"packages": {"upgradable": 5, "security_updates": bad}})
            self.assertIsNone(_factor(r, "security_updates"), bad)

    def test_the_weight_is_tunable_and_zero_turns_it_off(self):
        self.set_config(risk_weight_security_updates=0)
        r = _risk({"packages": {"upgradable": 5, "security_updates": 4}},
                  weights=api._risk_weights())
        self.assertIsNone(_factor(r, "security_updates"))
        self.set_config(risk_weight_security_updates=5)
        r = _risk({"packages": {"upgradable": 5, "security_updates": 2}},
                  weights=api._risk_weights())
        self.assertEqual(_factor(r, "security_updates")["points"], 10)


class TestMacProtections(_CfgBase):

    def test_the_parser_really_reports_these_as_booleans(self):
        mp = _mac(gatekeeper="assessments disabled",
                  sip="System Integrity Protection status: disabled.")
        self.assertIs(mp["gatekeeper"], False)
        self.assertIs(mp["sip"], False)

    def test_each_protection_that_is_off_scores(self):
        r = _risk({"mac_posture": _mac(gatekeeper="assessments disabled")})
        f = _factor(r, "mac_protection_off")
        self.assertEqual(f["points"], 6)
        self.assertEqual(f["detail"], "Gatekeeper is off")
        r = _risk({"mac_posture": _mac(gatekeeper="assessments disabled",
                                       sip="System Integrity Protection status: disabled.")})
        f = _factor(r, "mac_protection_off")
        self.assertEqual(f["points"], 12)
        self.assertIn("Gatekeeper is off", f["detail"])
        self.assertIn("System Integrity Protection is disabled", f["detail"])

    def test_a_heavy_weight_is_still_capped(self):
        """At the default weight two protections just reach the cap, so only a
        tuned weight shows whether the cap is there."""
        self.set_config(risk_weight_mac_protection_off=40)
        mp = _mac(gatekeeper="assessments disabled",
                  sip="System Integrity Protection status: disabled.")
        r = _risk({"mac_posture": mp}, weights=api._risk_weights())
        self.assertEqual(_factor(r, "mac_protection_off")["points"],
                         api._RISK_CAPS["mac_protection_off"])

    def test_a_healthy_mac_scores_nothing(self):
        self.assertIsNone(_factor(_risk({"mac_posture": _mac()}), "mac_protection_off"))

    def test_a_setting_the_agent_could_not_read_scores_nothing(self):
        mp = macagent._parse_mac_posture("FileVault is On.", "", "", "", "1")
        self.assertNotIn("gatekeeper", mp)
        self.assertNotIn("sip", mp)
        self.assertIsNone(_factor(_risk({"mac_posture": mp}), "mac_protection_off"))

    def test_the_existing_mac_factors_are_unchanged(self):
        """FileVault and the firewall still score under their own names."""
        mp = macagent._parse_mac_posture("FileVault is Off.", "Firewall is disabled. (State = 0)",
                                         "assessments enabled",
                                         "System Integrity Protection status: enabled.", "1")
        r = _risk({"mac_posture": mp})
        self.assertIsNotNone(_factor(r, "encryption_off"))
        self.assertIsNotNone(_factor(r, "firewall_off"))
        self.assertIsNone(_factor(r, "mac_protection_off"))


class TestWindowsProtections(_CfgBase):

    def test_stale_signatures_score_at_the_alert_limit(self):
        self.assertIsNone(_factor(_risk({"win_posture": _win(defender_sig_age_days=6)}),
                                  "win_protection_off"))
        f = _factor(_risk({"win_posture": _win(defender_sig_age_days=7)}),
                    "win_protection_off")
        self.assertEqual(f["points"], 5)
        self.assertIn("Defender signatures 7 days old", f["detail"])

    def test_the_limit_follows_the_operators_setting(self):
        self.set_config(av_sig_stale_days=14)
        self.assertIsNone(_factor(_risk({"win_posture": _win(defender_sig_age_days=10)}),
                                  "win_protection_off"))
        self.assertIsNotNone(_factor(_risk({"win_posture": _win(defender_sig_age_days=14)}),
                                     "win_protection_off"))

    def test_tamper_protection_and_uac_score_when_off(self):
        f = _factor(_risk({"win_posture": _win(tamper_protection=False)}), "win_protection_off")
        self.assertEqual((f["points"], f["detail"]), (5, "Defender tamper protection off"))
        f = _factor(_risk({"win_posture": _win(uac_enabled=False)}), "win_protection_off")
        self.assertEqual((f["points"], f["detail"]), (5, "User Account Control off"))

    def test_all_three_are_capped(self):
        wp = _win(defender_sig_age_days=30, tamper_protection=False, uac_enabled=False)
        f = _factor(_risk({"win_posture": wp}), "win_protection_off")
        self.assertEqual(f["points"], api._RISK_CAPS["win_protection_off"])
        self.assertEqual(f["detail"].count(";"), 2)

    def test_a_heavy_weight_is_still_capped(self):
        self.set_config(risk_weight_win_protection_off=40)
        wp = _win(defender_sig_age_days=30, tamper_protection=False, uac_enabled=False)
        r = _risk({"win_posture": wp}, weights=api._risk_weights())
        self.assertEqual(_factor(r, "win_protection_off")["points"],
                         api._RISK_CAPS["win_protection_off"])

    def test_a_healthy_host_scores_nothing(self):
        self.assertIsNone(_factor(_risk({"win_posture": _win()}), "win_protection_off"))

    def test_what_the_agent_could_not_determine_scores_nothing(self):
        wp = _win(defender_sig_age_days=None, tamper_protection=None, uac_enabled=None)
        for k in ("defender_sig_age_days", "tamper_protection", "uac_enabled"):
            self.assertNotIn(k, wp)
        self.assertIsNone(_factor(_risk({"win_posture": wp}), "win_protection_off"))

    def test_the_existing_windows_factors_are_unchanged(self):
        wp = _win(bitlocker=[{"mount": "C:", "status": "Off"}],
                  firewall=[{"name": "Public", "enabled": False}])
        r = _risk({"win_posture": wp})
        self.assertIsNotNone(_factor(r, "encryption_off"))
        self.assertIsNotNone(_factor(r, "firewall_off"))
        self.assertIsNone(_factor(r, "win_protection_off"))


class TestContainerRestartLoops(_CfgBase):
    """The names come from the real report path, the way the heartbeat stores them."""

    def _report(self, rc):
        raw = [{"name": "app", "image": "x:1", "status": "Up 2 minutes",
                "runtime": "docker", "restart_count": rc},
               {"name": "worker", "image": "y:1", "status": "Up 2 minutes",
                "runtime": "docker", "restart_count": rc},
               {"name": "db", "image": "pg:16", "status": "Up 3 days",
                "runtime": "docker", "restart_count": 0}]
        return api.containers_mod.normalize_listing(raw)

    def _beat(self, rc):
        now = int(time.time())
        cur = self._report(rc)
        looping = api.process_container_report("d1", cur, now) or []
        rec = {"ts": now, "items": cur}
        if looping:
            rec["restarting_alerted"] = looping
        api.save(api.CONTAINERS_FILE, {"d1": rec})
        api._invalidate_load_cache(api.CONTAINERS_FILE)
        return rec

    def _fleet(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "host1", "last_seen": int(time.time()),
                                           "monitored": True, "sysinfo": {}}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        return {r["device_id"]: r for r in api._compute_fleet_risk()}

    def test_the_premise_the_real_path_names_the_loop(self):
        self._beat(1)
        rec = self._beat(9)
        self.assertEqual(sorted(rec["restarting_alerted"]), ["app", "worker"])

    def test_containers_in_a_loop_score_per_container(self):
        self._beat(1)
        self._beat(9)
        f = _factor(self._fleet()["d1"], "container_crashloop")
        self.assertEqual(f["points"], 8)
        self.assertIn("2 containers in a restart loop", f["detail"])
        self.assertIn("app", f["detail"])

    def test_it_stops_scoring_when_the_alert_clears(self):
        self._beat(1)
        self._beat(9)
        self._beat(9)                 # no further restarts: the loop is over
        rec = api.load(api.CONTAINERS_FILE)["d1"]
        self.assertFalse(rec.get("restarting_alerted"))
        self.assertIsNone(_factor(self._fleet()["d1"], "container_crashloop"))

    def test_a_host_with_containers_and_no_loop_scores_nothing(self):
        self._beat(0)
        self.assertIsNone(_factor(self._fleet()["d1"], "container_crashloop"))

    def test_a_host_without_containers_scores_nothing(self):
        self.assertIsNone(_factor(self._fleet()["d1"], "container_crashloop"))

    def test_capped(self):
        names = [f"c{i}" for i in range(10)]
        r = _risk({}, cont_rec={"restarting_alerted": names})
        self.assertEqual(_factor(r, "container_crashloop")["points"],
                         api._RISK_CAPS["container_crashloop"])

    def test_junk_in_the_record_scores_nothing(self):
        for junk in ({"restarting_alerted": "app"}, {"restarting_alerted": [None, ""]},
                     {"restarting_alerted": {"app": 1}}, "app", 7):
            self.assertIsNone(_factor(_risk({}, cont_rec=junk), "container_crashloop"), junk)


class TestEccStaysOut(unittest.TestCase):
    """Held on purpose, with the reason: the reliability score already weighs ECC."""

    def test_ecc_counters_do_not_move_the_risk_score(self):
        quiet = _risk({})
        noisy = _risk({"ecc": {"ce": 900, "ue": 3}})
        self.assertEqual(quiet["score"], noisy["score"])
        self.assertEqual(quiet["factors"], noisy["factors"])

    def test_the_reliability_score_weighs_them(self):
        self.assertIn("ecc_uncorrectable", api._RELIABILITY_WEIGHTS)
        self.assertIn("ecc_correctable", api._RELIABILITY_WEIGHTS)

    def test_the_risk_doc_says_so(self):
        doc = (ROOT / "docs/risk.md").read_text()
        self.assertRegex(doc, r"(?is)ECC.{0,200}reliability")


class TestTheRiskDocNamesTheNewFactors(unittest.TestCase):

    def test_each_is_described(self):
        doc = (ROOT / "docs/risk.md").read_text().lower()
        for needle in ("security updates", "gatekeeper", "tamper protection",
                       "restart loop"):
            self.assertIn(needle, doc, needle)


if __name__ == "__main__":
    unittest.main()
