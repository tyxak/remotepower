"""v6.4.2 — Server-status page (app-self.js) behaviour.

These tests RUN the client code. app-self.js is loaded into a real V8 isolate
(py_mini_racer, the same engine tests/test_jsload.py uses) on top of a small
stub for the handful of globals it reaches for (escHtml, timeAgo, tableCtl,
document, api, toast), and the page functions are then called with the exact
payload shapes the server sends. A grep for a string in the source would prove
only that the string exists — the whole point of this file is to prove the
rendering DECIDES correctly: that a hollow Postgres archive is called hollow,
that a blocked privileged helper explains itself, and that every control-plane
subsystem gets its own row with its own state.

Payload shapes are pinned against the server:
  stores / last_drill_*      → backups_handlers._run_data_backup + _maybe_run_restore_drill
  privileged_mode / _help    → api.handle_version_check
  runtime / subsystems / …   → api.handle_self_status
"""

import json
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_APP_SELF = _ROOT / "server" / "html" / "static" / "js" / "app-self.js"

try:
    from py_mini_racer import MiniRacer
except Exception:                                    # pragma: no cover
    MiniRacer = None

# Just enough of the browser + app.js surface for the functions under test.
# Deliberately faithful where it matters: escHtml really escapes, so an
# escaping regression shows up as a failing assertion rather than passing.
_STUB = r"""
var __DOM = {};
var document = { getElementById: function(id){ return __DOM[id] || null; } };
function __mkel(id){
  __DOM[id] = { id: id, innerHTML: '', textContent: '', className: '',
                classList: { add: function(){}, remove: function(){} } };
  return __DOM[id];
}
function escHtml(s){
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function escAttr(s){ return escHtml(s); }
function timeAgo(ts, o){ return ts ? (ts + 's ago') : ((o && o.empty) || 'never'); }
var __wired = [];
var tableCtl = {
  wireSortOnly: function(theadId, prefs){ __wired.push([theadId, prefs]); },
  sortRows: function(name, rows){ return rows; },
};
function _icon(n, s){ return '<svg data-icon="' + n + '"></svg>'; }
function _skeletonBlock(){ return '<div class="skeleton"></div>'; }
var __toasts = [];
function toast(m, k){ __toasts.push([m, k]); }
var __apiCalls = [];
var __apiReplies = {};
function api(method, path){
  __apiCalls.push(method + ' ' + path);
  return Promise.resolve(__apiReplies[path]);
}
function uiConfirm(){ return Promise.resolve(true); }
function _downloadAuthed(){}
"""


def _ctx():
    c = MiniRacer()
    c.eval(_STUB + "\n" + _APP_SELF.read_text())
    return c


def _call(ctx, expr):
    """Evaluate `expr` and bring the result back as Python via JSON."""
    return json.loads(ctx.eval("JSON.stringify(" + expr + ")"))


@unittest.skipIf(MiniRacer is None, "py_mini_racer not installed")
class TestControlPlaneReadiness(unittest.TestCase):
    """Item 3: every subsystem handle_self_status reports gets its own row."""

    def setUp(self):
        self.ctx = _ctx()

    def _rows(self, status, obs=None):
        self.ctx.eval("_selfObsLast = " + json.dumps(obs) + ";")
        self.ctx.eval("_selfStatusLast = " + json.dumps(status) + ";")
        return _call(self.ctx, "_selfReadinessRows()")

    def test_every_control_plane_subsystem_has_its_own_row(self):
        rows = self._rows({
            "runtime": {"storage_backend": "postgres", "server_tier": "wsgi",
                        "scheduler_configured": True, "scheduler_running": True,
                        "scheduler_last_beat_s": 12},
            "cadence_jobs": {"monitors": {"stale": False}},
            "backup": {"last_run": 100, "stores": 42},
            "subsystems": {
                "satellites": {"relays": {"total": 2, "online": 2},
                               "scanners": {"total": 0, "online": 0}},
                "push": {"enabled": True, "reachable": True, "port": 8766},
                "syslog": {"unit": "active", "sources": 3, "last_ingest": 5},
                "flow": {"unit": "inactive", "sources": 0},
                "kmip": {"unit": "active", "clients": 2, "keys": 7,
                         "pki_expires_days": 300},
            },
        }, obs={"failing": 0, "tracked": 30})
        labels = [r["label"] for r in rows]
        for expected in ("Storage", "Request tier", "Maintenance scheduler",
                         "Maintenance sweeps", "Recurring jobs", "Backup & DR",
                         "Relay satellites", "Scan workers", "Agent push daemon",
                         "Syslog receiver", "Flow receiver", "KMIP key server"):
            self.assertIn(expected, labels)
        # A healthy install must not manufacture a red row.
        self.assertEqual([r["label"] for r in rows if r["state"] == "bad"], [])

    def test_dead_scheduler_and_failing_sweeps_are_degraded_rows(self):
        rows = self._rows({
            "runtime": {"storage_backend": "postgres", "server_tier": "wsgi",
                        "scheduler_configured": True, "scheduler_running": False},
            "cadence_jobs": {"monitors": {"stale": True},
                             "kev_epss_refresh": {"stale": False}},
            "backup": {"last_run": 100, "stores": 9},
        }, obs={"failing": 2, "tracked": 30})
        by = {r["label"]: r for r in rows}
        self.assertEqual(by["Maintenance scheduler"]["state"], "bad")
        self.assertEqual(by["Maintenance sweeps"]["state"], "bad")
        self.assertIn("2 of 30", by["Maintenance sweeps"]["status"])
        self.assertEqual(by["Recurring jobs"]["state"], "bad")
        self.assertIn("monitors", by["Recurring jobs"]["detail"])

    def test_sweep_health_is_muted_not_green_when_unreadable(self):
        # /self/observability is admin-only: a non-admin must not be told
        # "none failing" when the answer is simply unknown.
        rows = self._rows({"runtime": {"storage_backend": "sqlite"}}, obs=None)
        by = {r["label"]: r for r in rows}
        self.assertEqual(by["Maintenance sweeps"]["state"], "muted")

    def test_storage_row_degrades_on_read_error_and_failed_integrity(self):
        rows = self._rows({"runtime": {"storage_backend": "sqlite"},
                           "data_dir": {"error": "permission denied"}})
        by = {r["label"]: r for r in rows}
        self.assertEqual(by["Storage"]["state"], "bad")
        self.assertIn("permission denied", by["Storage"]["detail"])

        rows = self._rows({"runtime": {"storage_backend": "sqlite"},
                           "storage_backend": {"backend": "sqlite",
                                               "last_integrity": "corrupt"}})
        by = {r["label"]: r for r in rows}
        self.assertEqual(by["Storage"]["state"], "bad")
        self.assertIn("corrupt", by["Storage"]["detail"])

    def test_kmip_down_is_a_fault_while_syslog_absent_is_not(self):
        rows = self._rows({
            "runtime": {"storage_backend": "postgres"},
            "backup": {"last_run": 1, "stores": 3},
            "subsystems": {
                "kmip": {"unit": "inactive", "clients": 4, "keys": 9},
                "syslog": {"unit": "inactive", "sources": 0},
                "push": {"enabled": False},
            },
        }, obs={"failing": 0, "tracked": 5})
        by = {r["label"]: r for r in rows}
        self.assertEqual(by["KMIP key server"]["state"], "bad")
        self.assertEqual(by["Syslog receiver"]["state"], "muted")
        # A sidecar that is switched off must not wear the warning glyph.
        self.assertEqual(by["Agent push daemon"]["state"], "muted")
        self.assertIn("c-muted", self.ctx.eval("_selfStateIco('muted')"))
        self.assertIn("c-red", self.ctx.eval("_selfStateIco('bad')"))

    def test_render_writes_rows_and_counts_degraded_subsystems(self):
        self.ctx.eval("__mkel('self-readiness-rows'); __mkel('self-readiness-summary');")
        self.ctx.eval("_selfObsLast = {failing: 1, tracked: 4};")
        self.ctx.eval("_selfStatusLast = " + json.dumps({
            "runtime": {"storage_backend": "postgres", "server_tier": "wsgi",
                        "scheduler_configured": True, "scheduler_running": True},
            "cadence_jobs": {"monitors": {"stale": False}},
            "backup": {"last_run": 100, "stores": 12},
        }) + ";")
        self.ctx.eval("_renderSelfReadiness();")
        html = self.ctx.eval("__DOM['self-readiness-rows'].innerHTML")
        self.assertIn("Maintenance sweeps", html)
        self.assertIn("Backup &amp; DR", html)          # escaped, not raw
        self.assertIn("Degraded", html)
        summary = self.ctx.eval("__DOM['self-readiness-summary'].innerHTML")
        self.assertIn("1 degraded", summary)
        self.assertIn("c-red", summary)
        # Sorting is wired for the table (house rule), against its own thead.
        self.assertIn(["self-readiness-thead", "self_readiness"],
                      _call(self.ctx, "__wired"))

    def test_degraded_rows_sort_first_and_hostile_text_is_escaped(self):
        self.ctx.eval("__mkel('self-readiness-rows'); __mkel('self-readiness-summary');")
        self.ctx.eval("_selfStatusLast = " + json.dumps({
            "runtime": {"storage_backend": "postgres", "server_tier": "wsgi",
                        "scheduler_configured": True, "scheduler_running": True},
            "data_dir": {"error": "<img src=x onerror=alert(1)>"},
            "backup": {"last_run": 1, "stores": 3},
        }) + ";")
        self.ctx.eval("_renderSelfReadiness();")
        html = self.ctx.eval("__DOM['self-readiness-rows'].innerHTML")
        self.assertNotIn("<img", html)
        self.assertIn("&lt;img", html)
        self.assertLess(html.index("Storage"), html.index("Request tier"),
                        "the degraded row must sort above the healthy ones")


@unittest.skipIf(MiniRacer is None, "py_mini_racer not installed")
class TestBackupArchiveContents(unittest.TestCase):
    """Item 1: surface `stores`, and shout about a hollow database archive."""

    def setUp(self):
        self.ctx = _ctx()

    def _contents(self, backend, backup):
        return self.ctx.eval("_selfBackupContentsRow(" + json.dumps(
            {"runtime": {"storage_backend": backend}, "backup": backup}) + ")")

    def _warning(self, backend, backup):
        return self.ctx.eval("_selfHollowArchiveWarning(" + json.dumps(
            {"runtime": {"storage_backend": backend}, "backup": backup}) + ")")

    def test_store_count_is_rendered(self):
        row = self._contents("postgres", {"last_run": 1, "stores": 57})
        self.assertIn("57 logical stores", row)
        self.assertNotIn("hollow", row)

    def test_zero_stores_on_postgres_is_flagged_hollow(self):
        row = self._contents("postgres", {"last_run": 1, "stores": 0})
        self.assertIn("hollow", row)
        self.assertIn("patch-badge crit", row)
        warn = self._warning("postgres", {"last_run": 1, "stores": 0})
        self.assertIn("empty install", warn)

    def test_zero_stores_on_sqlite_is_a_caveat_not_a_catastrophe(self):
        # The .db image is in the tar, so the archive still restores — onto
        # SQLite only. Saying "hollow" here would be crying wolf.
        row = self._contents("sqlite", {"last_run": 1, "stores": 0})
        self.assertIn("database image only", row)
        self.assertNotIn("patch-badge crit", row)
        self.assertEqual(self._warning("sqlite", {"last_run": 1, "stores": 0}), "")

    def test_zero_stores_on_json_backend_is_not_a_fault(self):
        # _tar_add_logical_stores returns 0 on the JSON backend by design —
        # the data directory itself is in the archive.
        row = self._contents("json", {"last_run": 1, "stores": 0})
        self.assertNotIn("hollow", row)
        self.assertEqual(self._warning("json", {"last_run": 1, "stores": 0}), "")

    def test_row_is_omitted_when_the_server_reports_no_store_count(self):
        # A backup taken before v6.4.2 has no `stores` key; invent nothing.
        self.assertEqual(self._contents("postgres", {"last_run": 1}), "")

    def test_readiness_row_flags_a_hollow_archive_before_anything_else(self):
        # A hollow archive outranks every other backup signal: the RPO can be
        # met and the drill can pass on a tar that restores to nothing.
        st = {"runtime": {"storage_backend": "postgres"},
              "backup": {"last_run": 100, "stores": 0, "last_drill_ok": True}}
        row = _call(self.ctx, "_selfBackupReadinessRow(" + json.dumps(st) + ")")
        self.assertEqual(row["state"], "bad")
        self.assertIn("hollow", row["status"].lower())
        self.assertIn("empty install", row["detail"])
        # SQLite keeps the .db image, so the same count is only a caveat.
        st["runtime"]["storage_backend"] = "sqlite"
        row = _call(self.ctx, "_selfBackupReadinessRow(" + json.dumps(st) + ")")
        self.assertEqual(row["state"], "warn")

    def test_readiness_row_reflects_drill_failure_and_rpo_breach(self):
        st = {"runtime": {"storage_backend": "postgres"},
              "backup": {"last_run": 100, "stores": 4, "last_drill_ok": False,
                         "last_drill_at": 90, "last_drill_file": "x.tar.gz"}}
        row = _call(self.ctx, "_selfBackupReadinessRow(" + json.dumps(st) + ")")
        self.assertEqual(row["state"], "bad")
        self.assertIn("drill failed", row["status"])

        st["backup"] = {"last_run": 100, "stores": 4, "rpo_breached": True,
                        "rpo_hours": 24, "hours_since_last_backup": 90}
        row = _call(self.ctx, "_selfBackupReadinessRow(" + json.dumps(st) + ")")
        self.assertEqual(row["state"], "bad")
        self.assertIn("RPO", row["status"])

        st["backup"] = {}
        row = _call(self.ctx, "_selfBackupReadinessRow(" + json.dumps(st) + ")")
        self.assertEqual(row["state"], "warn")
        self.assertIn("Never run", row["status"])

    def test_verify_restore_renders_the_specific_server_message(self):
        self.ctx.eval("__mkel('self-verify-restore-result');")
        hollow = ("the archive contains no restorable state (no logical stores "
                  "and no database image) — a restore from it would produce an "
                  "empty install")
        self.ctx.eval("__apiReplies['/backup/test-restore'] = "
                      + json.dumps({"ok": False, "file": "a.tar.gz",
                                    "message": hollow}) + ";")
        self.ctx.eval("selfVerifyRestore();")
        el = self.ctx.eval("__DOM['self-verify-restore-result'].textContent")
        self.assertEqual(el, hollow)
        self.assertIn("c-red", self.ctx.eval(
            "__DOM['self-verify-restore-result'].className"))
        self.assertIn("POST /backup/test-restore", _call(self.ctx, "__apiCalls"))

    def test_verify_restore_reports_success(self):
        self.ctx.eval("__mkel('self-verify-restore-result');")
        self.ctx.eval("__apiReplies['/backup/test-restore'] = "
                      + json.dumps({"ok": True, "message": "Backup is restorable."})
                      + ";")
        self.ctx.eval("selfVerifyRestore();")
        self.assertEqual(self.ctx.eval("__DOM['self-verify-restore-result'].textContent"),
                         "Backup is restorable.")
        self.assertIn("c-green", self.ctx.eval(
            "__DOM['self-verify-restore-result'].className"))
        self.assertEqual(_call(self.ctx, "__toasts")[0][1], "success")


@unittest.skipIf(MiniRacer is None, "py_mini_racer not installed")
class TestRestartAvailabilityExplained(unittest.TestCase):
    """Item 2: an unavailable in-app restart must say why, not vanish."""

    def setUp(self):
        self.ctx = _ctx()

    def _avail(self, ver):
        return self.ctx.eval("_selfRestartAvailability(" + json.dumps(ver) + ")")

    def test_blocked_shows_the_servers_help_text_and_the_doc_pointer(self):
        help_text = ("this service runs with NoNewPrivileges=true, so sudo cannot "
                     "escalate — install the privileged helper units")
        out = self._avail({"restart_available": False,
                           "privileged_mode": "blocked",
                           "privileged_help": help_text})
        self.assertIn("NoNewPrivileges=true", out)
        self.assertIn("docs/upgrading.md", out)
        self.assertIn("unavailable", out.lower())

    def test_absent_keeps_the_not_set_up_wording(self):
        out = self._avail({"restart_available": False, "privileged_mode": "absent"})
        self.assertIn("not set up", out)
        self.assertNotIn("NoNewPrivileges", out)
        self.assertIn("docs/upgrading.md", out)

    def test_available_modes_point_at_the_control_that_exists(self):
        for mode in ("root", "sudo", "spool"):
            out = self._avail({"restart_available": True, "privileged_mode": mode})
            self.assertIn("Settings", out, mode)
        self.assertIn("path unit",
                      self._avail({"restart_available": True,
                                   "privileged_mode": "spool"}))

    def test_help_text_is_escaped(self):
        out = self._avail({"privileged_mode": "blocked",
                           "privileged_help": "<script>alert(1)</script>"})
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_silent_when_version_payload_lacks_the_field(self):
        # A demo/read-only instance answers /version without privileged_mode,
        # and a failed fetch yields null — neither may render a claim.
        self.assertEqual(self._avail({"current": "6.4.2", "latest": "6.4.2"}), "")
        self.assertEqual(self.ctx.eval("_selfRestartAvailability(null)"), "")


@unittest.skipIf(MiniRacer is None, "py_mini_racer not installed")
class TestPageRender(unittest.TestCase):
    """Drive loadSelfStatus() end to end against stubbed endpoints."""

    def test_page_renders_readiness_card_and_restart_guidance(self):
        ctx = _ctx()
        ctx.eval("__mkel('self-status-body');")
        ctx.eval("__apiReplies['/self/status'] = " + json.dumps({
            "server_version": "6.4.2",
            "runtime": {"storage_backend": "postgres", "server_tier": "wsgi",
                        "scheduler_configured": True, "scheduler_running": True},
            "devices": {"monitored": 3, "offline": 0},
            "backup": {"last_run": 100, "last_bytes": 1024, "stores": 0,
                       "last_drill_ok": False, "last_drill_at": 90},
            "subsystems": {"push": {"enabled": False}},
            "cadence_jobs": {"monitors": {"stale": False}},
        }) + ";")
        ctx.eval("__apiReplies['/version'] = " + json.dumps({
            "current": "6.4.2", "restart_available": False,
            "privileged_mode": "blocked",
            "privileged_help": "NoNewPrivileges=true blocks sudo here.",
        }) + ";")
        ctx.eval("loadSelfStatus();")
        html = ctx.eval("__DOM['self-status-body'].innerHTML")
        self.assertIn('id="self-readiness-rows"', html)
        self.assertIn('data-col="subsystem"', html)
        self.assertIn("Control-plane readiness", html)
        # The hollow Postgres archive is called out on the backup card itself.
        self.assertIn("hollow", html)
        self.assertIn("empty install", html)
        # The restart card explains the missing button.
        self.assertIn("NoNewPrivileges=true blocks sudo here.", html)
        self.assertIn("docs/upgrading.md", html)
        # And the failed drill is visible rather than silently dropped.
        self.assertIn("Restore drill", html)
        self.assertIn("selfVerifyRestore", html)

    def test_page_render_is_csp_safe(self):
        ctx = _ctx()
        ctx.eval("__mkel('self-status-body');")
        ctx.eval("__apiReplies['/self/status'] = " + json.dumps({
            "runtime": {"storage_backend": "sqlite", "server_tier": "wsgi"},
            "backup": {"last_run": 1, "stores": 5},
            "subsystems": {"kmip": {"unit": "inactive", "clients": 1, "keys": 2}},
            "cadence_jobs": {},
        }) + ";")
        ctx.eval("__apiReplies['/version'] = {};")
        ctx.eval("loadSelfStatus();")
        html = ctx.eval("__DOM['self-status-body'].innerHTML")
        self.assertNotIn(' style="', html)
        for handler in (" onclick=", " onchange=", " onerror=", " onload="):
            self.assertNotIn(handler, html)
        # Icons are inline SVG, never emoji.
        self.assertNotRegex(html, r"[\U0001F300-\U0001FAFF☀-➿]")


class TestSourceHygiene(unittest.TestCase):
    """Cheap source-level guards for the properties V8 cannot observe."""

    def test_no_inline_event_handlers_or_style_attributes(self):
        src = _APP_SELF.read_text()
        for bad in ('style="', ' onclick=', ' onchange=', ' oninput='):
            self.assertNotIn(bad, src, f"CSP: {bad!r} in app-self.js")

    def test_sortable_table_declares_its_columns(self):
        src = _APP_SELF.read_text()
        self.assertIn("wireSortOnly('self-readiness-thead', 'self_readiness'", src)
        for col in ("subsystem", "state", "status", "detail"):
            self.assertIn(f'data-col="{col}"', src)

    def test_readiness_table_is_height_capped(self):
        # House rule: a variable-row-count panel scrolls instead of growing.
        src = _APP_SELF.read_text()
        head = src.index('id="self-readiness-summary"')
        self.assertIn("scrollable-table-wrap audit-scroll",
                      src[head:head + 600])


if __name__ == "__main__":
    unittest.main()
