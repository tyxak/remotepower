"""v6.2.2 batch 5 — final threshold sweep.

Two jobs, both guarded here:

PART A — collapse divergent duplicate literals to ONE config source each:
  * disk-fill ETA days — the NA digest (crit≤7/warn≤21), the Checks engine row
    (was crit≤2/warn≤7) and the frontend cell colour (was <30/<90) now ALL read
    ``disk_forecast_crit_days`` / ``disk_forecast_warn_days``.
  * OOM "recent" window — the ~4 hardcoded ``86400`` copies in api.py + checks.py
    now read ``oom_recent_window_seconds`` (one source; no bare 86400 in the OOM
    paths).
  * Defender signature age — the Checks row's warn cutoff is ``defender_sig_warn_days``
    and its crit cutoff is the shipped ``av_sig_stale_days`` (all Defender-staleness
    surfaces agree).

PART B — the remaining integer monitoring/NA/control-plane scalar thresholds,
each wired through the FIVE layers (model / save-block / get-default / index.html
input / _ALERT_PARAM_FIELDS row) or it silently no-ops. Three read-sites live in
files outside the allowed edit set (container_restarting_min → containers.py,
ct_fail_backoff → tls_ct_handlers.py, dmarc_pct_min → dmarc_monitor.py); those are
STAGED (config plumbing only) and only asserted on the plumbing, not the read-site.
"""

import re
import unittest
from pathlib import Path

from test_v622_alert_params import _SaveBase, api, ROOT, _CGI

_API_SRC = (_CGI / "api.py").read_text()
_CHECKS_SRC = (_CGI / "checks.py").read_text()

# key -> (non-default value to persist, ap-<slug> input id)
_KEYS = {
    "disk_forecast_crit_days":           (5,     "ap-disk-fc-crit"),
    "disk_forecast_warn_days":           (30,    "ap-disk-fc-warn"),
    "oom_recent_window_seconds":         (43200, "ap-oom-window-s"),
    "defender_sig_warn_days":            (5,     "ap-defender-warn-days"),
    "patch_na_warn_count":               (50,    "ap-patch-na-warn"),
    "container_restart_delta_threshold": (3,     "ap-container-restart-delta"),
    "container_restarting_min":          (10,    "ap-container-restarting-min"),
    "attention_event_ttl_hours":         (48,    "ap-attn-event-ttl-h"),
    "after_hours_na_window_hours":       (12,    "ap-afterhours-window-h"),
    "snmp_cpu_warn_percent":             (60,    "ap-snmp-cpu-warn"),
    "snmp_cpu_crit_percent":             (85,    "ap-snmp-cpu-crit"),
    "agentless_ping_fail_threshold":     (4,     "ap-agentless-ping-fails"),
    "ct_fail_backoff":                   (6,     "ap-ct-fail-backoff"),
    "github_new_issue_per_poll_cap":     (20,    "ap-github-issue-cap"),
    "self_high_load_ratio":              (4,     "ap-self-load-ratio"),
    "self_mem_warn_pct":                 (80,    "ap-self-mem-pct"),
    "self_online_pct_warn":              (70,    "ap-self-online-pct"),
    "compliance_tls_expiring_days":      (14,    "ap-compliance-tls-days"),
    "compliance_lookback_days":          (60,    "ap-compliance-lookback"),
    "cis_disk_pct_max":                  (85,    "ap-cis-disk-max"),
    "cis_swap_pct_max":                  (70,    "ap-cis-swap-max"),
    "dmarc_pct_min":                     (90,    "ap-dmarc-pct-min"),
    "proxmox_backup_warn_days":          (14,    "ap-pmox-backup-days"),
    "metric_recovery_buffer":            (10,    "ap-metric-recovery-buffer"),
    "min_online_ttl":                    (300,   "ap-min-online-ttl"),
    "unstable_host_returns_min":         (5,     "ap-unstable-returns"),
    "unstable_host_window_days":         (14,    "ap-unstable-window-days"),
    "reliability_reboot_churn_min":      (5,     "ap-rel-reboot-churn"),
    "reliability_wear_high_pct":         (75,    "ap-rel-wear-high"),
}

# read-site lives outside the allowed edit set → config plumbing only (staged).
_STAGED = {"container_restarting_min", "ct_fail_backoff", "dmarc_pct_min"}


# ── PART B plumbing: model / save-block / get-default (the silent gotchas) ──
class TestSavePersistsEveryKey(_SaveBase):
    def test_each_key_persists(self):
        cfg = self._save({k: v for k, (v, _s) in _KEYS.items()})
        for k, (v, _s) in _KEYS.items():
            self.assertEqual(cfg.get(k), v,
                             f"{k} did not persist (save-whitelist gotcha)")

    def test_blank_clears_override(self):
        self._save({k: v for k, (v, _s) in _KEYS.items()})
        cfg = self._save({"disk_forecast_crit_days": ""})
        self.assertNotIn("disk_forecast_crit_days", cfg)

    def test_metric_recovery_buffer_accepts_zero(self):
        cfg = self._save({"metric_recovery_buffer": "0"})
        self.assertEqual(cfg.get("metric_recovery_buffer"), 0)

    def test_out_of_range_rejected(self):
        self._save({"self_mem_warn_pct": "500"})   # > 100 max
        self.assertEqual(self.cap.get("s"), 400)

    def test_non_integer_rejected(self):
        self._save({"patch_na_warn_count": "lots"})
        self.assertEqual(self.cap.get("s"), 400)

    def test_empty_body_accepted(self):
        self._save({})
        # a bare {} must NOT 400 (additive-superset rule)
        self.assertNotEqual(self.cap.get("s"), 400)


class TestModelAcceptsEveryKey(unittest.TestCase):
    def test_model_validates_each(self):
        import request_models as rm
        for k in _KEYS:
            ok, err = rm.validate(rm.ConfigSaveRequest, {k: "5"})
            self.assertTrue(ok, f"{k}: {err}")

    def test_model_accepts_empty_body(self):
        import request_models as rm
        ok, err = rm.validate(rm.ConfigSaveRequest, {})
        self.assertTrue(ok, err)


class TestConfigGetDefaults(unittest.TestCase):
    def test_setdefault_present_in_source(self):
        get_src = _API_SRC[_API_SRC.index("def handle_config_get"):
                           _API_SRC.index("def handle_config_save")]
        for k in _KEYS:
            self.assertIn(f"setdefault('{k}'", get_src,
                          f"{k} missing from handle_config_get defaults")


# ── PART A: divergences collapsed to one source ──
class TestDiskEtaSingleSource(unittest.TestCase):
    """The NA digest, the Checks engine and the frontend cell all read the same
    disk_forecast_* keys — the three copies (7/21, 2/7, 30/90) are gone."""

    def test_na_digest_reads_disk_forecast_keys(self):
        na = _API_SRC[_API_SRC.index("def _compute_attention"):
                      _API_SRC.index("def _compute_attention") + 60000]
        na = na[:na.index("\ndef ", 100)]
        self.assertIn("disk_forecast_crit_days", na)
        self.assertIn("disk_forecast_warn_days", na)
        # the old bare ladder is gone from the disk-fill NA item
        self.assertNotIn("if d2f <= 7:", na)
        self.assertNotIn("elif d2f <= 21:", na)

    def test_checks_engine_reads_disk_forecast_keys(self):
        # the pure engine takes the cutoffs as kwargs …
        self.assertIn("disk_forecast_crit_days=", _CHECKS_SRC)
        self.assertIn("disk_forecast_warn_days=", _CHECKS_SRC)
        self.assertNotIn("disk_eta <= 2", _CHECKS_SRC)
        # … and api.py threads the config values in through both callers.
        self.assertIn("'disk_forecast_crit_days'", _API_SRC)
        self.assertIn("'disk_forecast_warn_days'", _API_SRC)
        self.assertIn("_checks_threshold_kwargs", _API_SRC)

    def test_frontend_cell_reads_delivered_bands(self):
        app = (ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn("_HW_BANDS.disk_forecast_crit", app)
        self.assertIn("_HW_BANDS.disk_forecast_warn", app)
        # the old hardcoded 30/90 ladder is gone
        self.assertNotIn("r.eta_days < 30", app)
        self.assertNotIn("r.eta_days < 90", app)

    def test_hw_bands_delivers_disk_forecast(self):
        hb = _API_SRC[_API_SRC.index("def _hw_bands"):]
        hb = hb[:hb.index("\ndef ", 10)]
        self.assertIn("'disk_forecast_crit'", hb)
        self.assertIn("'disk_forecast_warn'", hb)


class TestOomWindowSingleSource(unittest.TestCase):
    """No bare 86400 remains as an OOM recency threshold; every site reads
    oom_recent_window_seconds (via the constant / helper / kwarg)."""

    def test_no_bare_86400_in_api_oom_lines(self):
        offenders = [ln.strip() for ln in _API_SRC.splitlines()
                     if "last_oom_ts" in ln or ("_oom" in ln and "86400" in ln)]
        for ln in offenders:
            self.assertNotIn("86400", ln,
                             f"bare 86400 still in an OOM path: {ln}")
        # the config-backed forms are present
        self.assertIn("_oom_recent_window()", _API_SRC)
        self.assertIn("OOM_RECENT_WINDOW_SECONDS", _API_SRC)

    def test_no_bare_86400_in_checks_oom_block(self):
        blk = _CHECKS_SRC[_CHECKS_SRC.index('lo = si.get("last_oom_ts")'):]
        blk = blk[:blk.index("pools = ")]
        self.assertNotIn("86400", blk, "bare 86400 still in checks.py OOM block")
        self.assertIn("oom_recent_window_seconds", blk)


class TestDefenderStalenessAgrees(unittest.TestCase):
    def test_checks_row_reads_both_keys(self):
        self.assertIn("av_sig_stale_days", _CHECKS_SRC)
        self.assertIn("defender_sig_warn_days", _CHECKS_SRC)
        self.assertNotIn("age >= 7 else", _CHECKS_SRC)


# ── read-sites actually HONOUR the config (drive the real code) ──
class TestReadSitesHonourConfig(_SaveBase):
    def _bust(self):
        api._invalidate_load_cache(api.CONFIG_FILE)

    def test_min_online_ttl_floor(self):
        # online_ttl below the configured floor clamps up to the floor.
        api.save(api.CONFIG_FILE, {"online_ttl": 100, "min_online_ttl": 250})
        self._bust()
        self.assertEqual(api.get_online_ttl(), 250)
        # default floor = MIN_ONLINE_TTL when unset
        api.save(api.CONFIG_FILE, {"online_ttl": 100})
        self._bust()
        self.assertEqual(api.get_online_ttl(), api.MIN_ONLINE_TTL)

    def test_snmp_cpu_default_and_override(self):
        api.save(api.CONFIG_FILE, {"snmp_cpu_warn_percent": 55,
                                   "snmp_cpu_crit_percent": 88})
        self._bust()
        warn, crit = api._snmp_threshold_warn_crit({}, "snmp_cpu")
        self.assertEqual((warn, crit), (55.0, 88.0))
        # a per-device override still wins over the fleet default
        warn2, _ = api._snmp_threshold_warn_crit(
            {"metric_thresholds": {"snmp_cpu_warn_percent": 42}}, "snmp_cpu")
        self.assertEqual(warn2, 42.0)

    def test_metric_recovery_buffer_moves_the_verdict(self):
        # warn=80, value=72: default buffer 5 → recovered; buffer 10 → NOT.
        api.save(api.CONFIG_FILE, {})
        self._bust()
        self.assertTrue(api._below_recovery(72, 80))
        api.save(api.CONFIG_FILE, {"metric_recovery_buffer": 10})
        self._bust()
        self.assertFalse(api._below_recovery(72, 80))

    def test_oom_window_helper_reads_config(self):
        api.save(api.CONFIG_FILE, {})
        self._bust()
        self.assertEqual(api._oom_recent_window(), api.OOM_RECENT_WINDOW_SECONDS)
        api.save(api.CONFIG_FILE, {"oom_recent_window_seconds": 3600})
        self._bust()
        self.assertEqual(api._oom_recent_window(), 3600)


# ── frontend wiring (index.html inputs + _ALERT_PARAM_FIELDS) ──
class TestFrontendWiring(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "server/html/index.html").read_text()
        self.app = (ROOT / "server/html/static/js/app.js").read_text()
        m = re.search(r"_ALERT_PARAM_FIELDS\s*=\s*\[(.*?)\];", self.app, re.S)
        self.assertIsNotNone(m, "_ALERT_PARAM_FIELDS array not found")
        self.fields_src = m.group(1)

    def test_each_input_present_once(self):
        for k, (_v, slug) in _KEYS.items():
            self.assertEqual(self.html.count(f'id="{slug}"'), 1,
                             f"{slug} ({k}) not present exactly once in index.html")

    def test_each_key_in_alert_param_fields(self):
        for k, (_v, slug) in _KEYS.items():
            self.assertIn(f"'{k}'", self.fields_src,
                          f"{k} missing from _ALERT_PARAM_FIELDS")
            self.assertIn(f"'{slug}'", self.fields_src,
                          f"{slug} missing from _ALERT_PARAM_FIELDS")

    def test_every_section_has_a_save_button(self):
        i = self.html.index('id="settings-pane-alertparams"')
        j = self.html.index('id="settings-pane-ignored"', i)
        pane = self.html[i:j]
        n_sections = pane.count('class="settings-section"')
        n_saves = pane.count('data-action="saveAlertParams"')
        self.assertEqual(n_saves, n_sections,
                         "every settings-section must carry its own Save button")


class TestSectionTitlesTranslated(unittest.TestCase):
    def test_new_section_titles_have_i18n(self):
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        for title in ("Capacity & forecast", "Containers & SNMP",
                      "Monitoring cadence", "Compliance & CIS",
                      "RemotePower self-health", "Reliability tuning"):
            self.assertIn(f"'{title}'", i18n, f"{title} missing from i18n DICT")


class TestStagedKeysDocumented(unittest.TestCase):
    """The three formerly-"staged" keys are now fully wired at their read-sites
    (containers.py summarise param, tls_ct_handlers.py CT backoff, dmarc_monitor.py
    grade) — they honour the config, not just persist it."""

    def test_staged_keys_now_honour_config(self):
        _ROOT = Path(__file__).resolve().parent.parent
        _cont = (_ROOT / "server/cgi-bin/containers.py").read_text()
        _tls = (_ROOT / "server/cgi-bin/tls_ct_handlers.py").read_text()
        _dmarc = (_ROOT / "server/cgi-bin/dmarc_monitor.py").read_text()
        # containers: summarise takes a restarting_min param, api passes the config
        self.assertIn("restarting_min", _cont)
        self.assertIn("container_restarting_min", _API_SRC)
        # ct_fail_backoff read from config at the backoff gate
        self.assertIn("ct_fail_backoff", _tls)
        # dmarc grade honours a pct_min threaded from the config
        self.assertIn("pct_min", _dmarc)
        self.assertIn("dmarc_pct_min", _API_SRC)


if __name__ == "__main__":
    unittest.main()
