"""v6.3.0 "Fl0wMatters" — release pins.

The CURRENT release carries the strict version pins (older test_vXYZ.py files
have theirs loosened to the live version). Headline: UX wave 1 — toast action
buttons + the deferred-commit undoable delete, optimistic alert ack/resolve,
the "N of M shown" filter chip, the _errorState Retry helper, the Settings
unsaved-changes guard, and Tickets bulk actions.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v630-"))
_spec = importlib.util.spec_from_file_location("api_v630_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "6.3.0"
CODENAME = "Fl0wMatters"

_JS = _ROOT / "server/html/static/js"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _js(name):
    return (_JS / name).read_text()


class TestVersionBumps(unittest.TestCase):
    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, V)

    def test_agent_versions(self):
        self.assertIn(
            f"VERSION      = '{V}'",
            (_ROOT / "client/remotepower-agent.py").read_text(),
        )
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual(
            (_ROOT / "client/remotepower-agent.py").read_bytes(),
            (_ROOT / "client/remotepower-agent").read_bytes(),
        )

    def test_sw_and_cachebust(self):
        self.assertIn(f"remotepower-shell-v{V}", (_ROOT / "server/html/sw.js").read_text())
        self.assertIn(f"?v={V}", _html())

    def test_no_stale_cachebust(self):
        self.assertNotIn("?v=6.2.3", _html())

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{V}.md").exists())

    def test_doc_set_keeps_three_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v[0-9]*.md"))
        self.assertEqual(len(vdocs), 3, f"expected exactly 3 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{V}", _html())

    def test_whats_new_cards_capped_at_three(self):
        self.assertEqual(_html().count("What's new — v"), 3)

    def test_whats_new_card_is_doc_searchable(self):
        """The data-keywords attribute embeds the codename as a lowercase search
        term — the surface a visible-text rename always misses."""
        html = _html()
        i = html.index(f"What's new — v{V}")
        card = html[max(0, i - 2200):i]
        self.assertIn(CODENAME.lower(), card)

    def test_changelog_header(self):
        head = (_ROOT / "CHANGELOG.md").read_text()[:400]
        self.assertIn(f'## v{V} — "{CODENAME}"', head)

    def test_gen_wiki_codename(self):
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertIn(CODENAME, p.read_text(),
                      "gen-wiki.py's Home line hardcodes the codename — bump it")

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[: block.index("Full history")]
        bullets = [ln for ln in block.splitlines() if ln.startswith("- **v")]
        self.assertLessEqual(len(bullets), 5, "README 'Recent releases' caps at 5")
        self.assertTrue(bullets[0].startswith(f'- **v{V} "{CODENAME}"'))


class TestToastActions(unittest.TestCase):
    """UX wave 1 item 1: toast() grew an opts arg with an action button."""

    def test_toast_accepts_opts(self):
        from tests import srcpin
        fn = srcpin.js_function(_js("app.js"), "toast")
        self.assertIn("opts.action", fn)
        self.assertIn("onTimeout", fn)
        # settle-once: the action and the timeout can never both fire
        self.assertIn("settled", fn)

    def test_debug_wrapper_passes_opts_through(self):
        # The dbg instrumentation wrapper must forward the third arg, or every
        # action toast silently loses its button when debug mode is on.
        self.assertIn("_origToast(msg, type, opts)", _js("app.js"))

    def test_toast_action_styled(self):
        css = (_ROOT / "server/html/static/css/styles.css").read_text()
        self.assertIn(".toast-action", css)

    def test_undo_translated(self):
        self.assertIn("'Undo':", _js("i18n.js"))


class TestTopbarUndoRedo(unittest.TestCase):
    """UX wave 1b: MikroTik-style global undo/redo arrows in the topbar."""

    def test_topbar_buttons_exist(self):
        html = _html()
        self.assertIn('id="topbar-undo"', html)
        self.assertIn('id="topbar-redo"', html)
        # icon-only buttons must carry accessible names
        i = html.index('id="topbar-undo"')
        self.assertIn('aria-label', html[i:i + 200])

    def test_controller_and_wiring(self):
        app = _js("app.js")
        self.assertIn("const uiUndoCtl", app)
        self.assertIn("function uiUndoAction", app)
        self.assertIn("function uiRedoAction", app)
        # flows push entries
        self.assertIn("uiUndoCtl.push", app)
        self.assertIn("uiUndoCtl.push", _js("app-alerts.js"))

    def test_ctrl_z_skips_form_fields(self):
        app = _js("app.js")
        i = app.index("e.key.toLowerCase() !== 'z'")
        self.assertIn("isContentEditable", app[i:i + 400])

    def test_undo_redo_icons_registered(self):
        app = _js("app.js")
        self.assertIn("undo:", app)
        self.assertIn("redo:", app)


class TestUndoableDelete(unittest.TestCase):
    """UX wave 1 item 2: deferred-commit delete with an Undo toast."""

    def test_helper_exists_and_defers(self):
        from tests import srcpin
        fn = srcpin.js_function(_js("app.js"), "undoableDelete")
        # The commit must live in onTimeout — NOT run before the toast.
        self.assertIn("onTimeout", fn)
        self.assertIn("_pendingDeletes", fn)

    def test_pagehide_flushes_pending_commits(self):
        app = _js("app.js")
        i = app.index("window.addEventListener('pagehide'")
        self.assertIn("_pendingDeletes", app[i:i + 300])

    def test_wired_call_sites(self):
        self.assertIn("undoableDelete({", _js("app-tickets.js"))   # contacts
        self.assertIn("undoableDelete({", _js("app-network.js"))   # links
        # command snippets + the client-side saved-view undo
        app = _js("app.js")
        self.assertIn("undoableDelete({", app)
        from tests import srcpin
        view_fn = srcpin.js_function(app, "deleteDeviceView")
        self.assertIn("Undo", view_fn)

    def test_no_confirm_left_on_wired_deletes(self):
        # These flows moved from confirm-before to undo-after; a reintroduced
        # uiConfirm would stack both dialogs.
        from tests import srcpin
        for f, name in (("app-tickets.js", "deleteContact"),
                        ("app-network.js", "linkDelete")):
            fn = srcpin.js_function(_js(f), name)
            self.assertNotIn("uiConfirm", fn, f"{name} should be undoable, not confirmed")


class TestOptimisticAlertActions(unittest.TestCase):
    def test_kbd_ack_is_optimistic_with_undo(self):
        from tests import srcpin
        alerts = _js("app-alerts.js")
        fn = srcpin.js_function(alerts, "_ackAlertOptimistic")
        self.assertIn("/unack", fn)
        self.assertIn("renderAlerts()", fn)
        # the keyboard 'a' branch routes through it
        self.assertIn("_ackAlertOptimistic(id)", alerts)

    def test_resolve_flips_then_reverts(self):
        from tests import srcpin
        fn = srcpin.js_function(_js("app-alerts.js"), "resolveAlert")
        self.assertIn("resolved_at", fn)
        self.assertIn("uiConfirm", fn)   # no /unresolve exists — keep the confirm

    def test_server_unack_route_exists(self):
        # The Undo toast depends on this endpoint staying alive.
        from tests import apisrc
        self.assertIn("def handle_alert_unack", apisrc.api_source())


class TestFilterChipAndRetry(unittest.TestCase):
    def test_filter_info_chip(self):
        app = _js("app.js")
        self.assertIn("_renderFilterInfo", app)
        self.assertIn("tblClearFilter", app)
        self.assertIn("of ${total} shown", app)

    def test_error_state_helper(self):
        from tests import srcpin
        fn = srcpin.js_function(_js("app.js"), "_errorState")
        self.assertIn("uiRetry", fn)
        self.assertIn("Retry", fn)

    def test_retry_swept_into_modules(self):
        for f in ("app-checks.js", "app-cve.js", "app-power.js", "app-firewall.js",
                  "app-drift.js", "app-gpu.js", "app-rollouts.js", "app-tuning.js",
                  "app-compliance.js", "app-backups.js", "app-cmdb.js"):
            self.assertIn("_errorState(", _js(f), f)


class TestSettingsUnsavedGuard(unittest.TestCase):
    def test_dirty_tracking_and_guard(self):
        app = _js("app.js")
        self.assertIn("_settingsDirty", app)
        from tests import srcpin
        show = srcpin.js_function(app, "showPage")
        self.assertIn("Unsaved changes", show)

    def test_config_save_clears_flag(self):
        from tests import srcpin
        fn = srcpin.js_function(_js("app.js"), "api")
        self.assertIn("_settingsDirty = false", fn)

    def test_filter_boxes_do_not_dirty(self):
        app = _js("app.js")
        i = app.index("document.addEventListener('change'")
        self.assertIn("/filter|search/i", app[i:i + 500])


class TestTicketsBulkActions(unittest.TestCase):
    def test_bulk_bar_and_functions(self):
        tk = _js("app-tickets.js")
        for marker in ("tk-row-cb", "bulkResolveTickets", "bulkAssignTicketsMe",
                       "_tkBulkBar"):
            self.assertIn(marker, tk)
        html = _html()
        self.assertIn('id="tk-bulk-bar"', html)
        # 4 theads gained the checkbox column
        self.assertEqual(html.count('tk-th-cb'), 4)

    def test_bulk_uses_existing_patch_api(self):
        from tests import srcpin
        fn = srcpin.js_function(_js("app-tickets.js"), "_tkBulkPatch")
        self.assertIn("'PATCH', '/tickets/'", fn)


class TestWave2QuickWins(unittest.TestCase):
    """UX wave 2: Ctrl-Enter submit, auto in-flight buttons, click-to-copy,
    pager size/export, palette recents, SW update toast, skeleton blocks."""

    def test_ctrl_enter_submits_topmost_modal(self):
        app = _js("app.js")
        i = app.index("Ctrl/Cmd-Enter submits the topmost modal")
        chunk = app[i:i + 600]
        self.assertIn("_modalStackTop()", chunk)
        self.assertIn(".btn-primary:not([disabled])", chunk)

    def test_dispatcher_auto_inflight(self):
        app = _js("app.js")
        i = app.index("automatic in-flight state")
        chunk = app[i:i + 900]
        self.assertIn("btn-inflight", chunk)
        self.assertIn("aria-busy", chunk)
        # restore must run on BOTH resolve and reject
        self.assertIn("_ret.then(_restore, _restore)", chunk)

    def test_data_copy_handler_and_sites(self):
        app = _js("app.js")
        self.assertIn("closest('[data-copy]')", app)
        self.assertIn("navigator.clipboard.writeText", app)
        # at least the CVE ids and the command-library command are wired
        self.assertIn('data-copy=""', _js("app-cve.js"))
        self.assertIn('data-copy=""', app)

    def test_pager_gains_size_select_and_export(self):
        app = _js("app.js")
        self.assertIn("tablepagesize-", app)
        self.assertIn("tblExportCsv", app)
        self.assertIn("function tblPageSize", app)
        # render honors the per-table pref
        self.assertIn("prefs.pageSize || opts.pageSize || 15", app)

    def test_page_size_persisted_server_side(self):
        from tests import apisrc, srcpin
        fn = srcpin.py_function(apisrc.api_source(), "_sanitise_ui_prefs")
        self.assertIn("pageSize", fn,
                      "pageSize must be whitelisted or the pref silently drops")

    def test_export_csv_quotes_fields(self):
        app = _js("app.js")
        i = app.index("function exportCsv")
        chunk = app[i:app.index("function clearFilter")]
        self.assertIn('replace(/"/g', chunk)

    def test_palette_recents(self):
        app = _js("app.js")
        self.assertIn("_recordRecentDevice", app)
        self.assertIn("rp_recent_devices", app)
        self.assertIn("Recently viewed", app)

    def test_sw_update_toast(self):
        sw = _js("sw-register.js")
        self.assertIn("updatefound", sw)
        self.assertIn("statechange", sw)
        self.assertIn("Reload", sw)
        # only notify when an OLD worker still controls the page
        self.assertIn("navigator.serviceWorker.controller", sw)

    def test_skeleton_block_helper_swept(self):
        self.assertIn("function _skeletonBlock", _js("app.js"))
        for f in ("app-cve.js", "app-kb.js", "app-containers.js",
                  "app-drift.js", "app-dns.js", "app-remote.js"):
            self.assertIn("_skeletonBlock(", _js(f), f)


class TestWave3(unittest.TestCase):
    """UX wave 3: per-alert deep links, notification center, alert-params
    modified-from-default indicators + reset + changed-only view."""

    def test_alert_deep_link_plumbing(self):
        app = _js("app.js")
        # boot router stashes the id BEFORE showPage rewrites the hash
        self.assertIn("_pendingAlertDeepLink", app)
        self.assertIn(r"alerts\/([A-Za-z0-9_-]{1,64})", app)
        alerts = _js("app-alerts.js")
        self.assertIn("_focusPendingAlert", alerts)
        self.assertIn("copyAlertLink", alerts)
        # the copy button exists on BOTH open and resolved rows
        self.assertEqual(alerts.count('data-action="copyAlertLink"'), 2)

    def test_alert_deep_link_widens_filter_once(self):
        from tests import srcpin
        fn = srcpin.js_function(_js("app-alerts.js"), "_focusPendingAlert")
        self.assertIn("_alertDeepLinkWidened", fn)
        self.assertIn("'all'", fn)

    def test_notification_center(self):
        app = _js("app.js")
        self.assertIn("_toastHistory", app)
        self.assertIn("function toggleToastHistory", app)
        # toast() records into the history
        from tests import srcpin
        fn = srcpin.js_function(app, "toast")
        self.assertIn("_recordToast", fn)
        html = _html()
        self.assertIn('id="toast-history-btn"', html)
        self.assertIn('id="toast-history-pop"', html)
        # The popover must sit OUTSIDE .container (the z-index stacking-context
        # trap) — as a direct #app child before <main>, sibling of the sidebar,
        # so it inherits logged-out hiding and still stacks above the sidebar.
        self.assertLess(html.index('id="toast-history-pop"'),
                        html.index('<div class="container">'))

    def test_alert_params_modified_and_reset(self):
        app = _js("app.js")
        self.assertIn("_apMarkModified", app)
        self.assertIn("function apResetField", app)
        self.assertIn("function apToggleOnlyModified", app)
        # loadAlertParams marks every field after populating it
        from tests import srcpin
        fn = srcpin.js_function(app, "loadAlertParams")
        self.assertIn("_apMarkModified", fn)
        html = _html()
        self.assertIn('id="ap-only-modified"', html)
        css = (_ROOT / "server/html/static/css/styles.css").read_text()
        self.assertIn("ap-mod-only", css)
        self.assertIn(".ap-reset", css)


class TestWave4(unittest.TestCase):
    """UX wave 4: column show/hide, dashboard-layout undo, page-aware help."""

    def test_columns_menu_and_visibility(self):
        app = _js("app.js")
        self.assertIn("function _applyColumnVis", app)
        self.assertIn("function colsMenu", app)
        self.assertIn("function tblColsMenu", app)
        self.assertIn("hiddenCols", app)
        # applied on every render
        i = app.index("function render(name, rows)")
        render_fn = app[i:app.index("function _renderPager")]
        self.assertIn("_applyColumnVis", render_fn)

    def test_last_visible_column_protected(self):
        app = _js("app.js")
        i = app.index("function toggleCol")
        chunk = app[i:i + 1500]
        self.assertIn("At least one column must stay visible", chunk)

    def test_hidden_cols_persisted_server_side(self):
        from tests import apisrc, srcpin
        fn = srcpin.py_function(apisrc.api_source(), "_sanitise_ui_prefs")
        self.assertIn("hiddenCols", fn)

    def test_dashboard_layout_undoable(self):
        from tests import srcpin
        app = _js("app.js")
        fn = srcpin.js_function(app, "_dashSave")
        self.assertIn("uiUndoCtl.push", fn)
        # the snapshot must be taken BEFORE _uiPrefs.dashboard is assigned
        self.assertLess(fn.index("uiUndoCtl.push"), fn.index("_uiPrefs.dashboard = layout"))
        reset = srcpin.js_function(app, "dashReset")
        self.assertIn("uiUndoCtl.push", reset)
        self.assertIn("'Undo'", reset)

    def test_page_aware_cheat_sheet(self):
        app = _js("app.js")
        self.assertIn("const _PAGE_HELP", app)
        self.assertIn("function _pageHelpRows", app)
        from tests import srcpin
        fn = srcpin.js_function(app, "showKeyboardShortcuts")
        self.assertIn("_pageHelpRows()", fn)

    def test_page_help_docs_exist(self):
        """Every doc referenced by _PAGE_HELP must actually ship — a deleted
        guide would otherwise leave a dead link in the cheat sheet."""
        import re as _re
        app = _js("app.js")
        i = app.index("const _PAGE_HELP")
        block = app[i:app.index("function _pageHelpRows")]
        for doc in _re.findall(r"doc:\s*'([^']+)'", block):
            self.assertTrue((_ROOT / doc).exists(), doc)


class TestWave5ConfigRevisions(unittest.TestCase):
    """UX wave 5: config revision history + rollback, pinned devices."""

    def test_module_bound_and_routed(self):
        self.assertTrue(callable(api.handle_config_revisions_list))
        self.assertTrue(callable(api.handle_config_revision_restore))
        routes = api._build_exact_routes()
        self.assertIn(("GET", "/api/config/revisions"), routes)
        self.assertIn(("POST", "/api/config/revisions/restore"), routes)

    def test_recorder_stores_pre_save_state(self):
        api.record_config_revision({"x": 1}, {"x": 2, "y": 3}, "tester")
        revs = (api.load(api.CONFIG_REVS_FILE) or {}).get("revisions") or []
        self.assertTrue(revs)
        last = revs[-1]
        self.assertEqual(last["changed_keys"], ["x", "y"])
        self.assertEqual(last["config"], {"x": 1})
        self.assertTrue(str(last["id"]).startswith("rev-"))  # non-numeric id

    def test_recorder_noop_when_unchanged(self):
        before = len((api.load(api.CONFIG_REVS_FILE) or {}).get("revisions") or [])
        api.record_config_revision({"a": 1}, {"a": 1}, "tester")
        after = len((api.load(api.CONFIG_REVS_FILE) or {}).get("revisions") or [])
        self.assertEqual(before, after)

    def test_config_save_hook_present(self):
        from tests import apisrc, srcpin
        fn = srcpin.py_function(apisrc.api_source(), "handle_config_save")
        self.assertIn("record_config_revision(_cfg_before, cfg, _cfg_actor)", fn)

    def test_list_never_returns_config_bodies(self):
        src = (_CGI / "config_revisions_handlers.py").read_text()
        i = src.index("def handle_config_revisions_list")
        j = src.index("def handle_config_revision_restore")
        # the list projection must not include the stored config dicts
        self.assertNotIn("'config':", src[i:j].replace("r.get('config')", ""))

    def test_ui_wired(self):
        app = _js("app.js")
        self.assertIn("function loadConfigRevisions", app)
        self.assertIn("restoreConfigRevision", app)
        self.assertIn('id="config-revisions-list"', _html())

    def test_pinned_devices(self):
        app = _js("app.js")
        self.assertIn("function toggleDevicePin", app)
        self.assertIn("pinned_devices", app)
        self.assertIn("'Pinned'", app)
        from tests import apisrc, srcpin
        fn = srcpin.py_function(apisrc.api_source(), "_sanitise_ui_prefs")
        self.assertIn("pinned_devices", fn)


class TestWave6(unittest.TestCase):
    """UX wave 6: script duplicate + undoable delete, cross-tab alert sync."""

    def test_script_duplicate_and_undoable_delete(self):
        app = _js("app.js")
        self.assertIn("function duplicateScript", app)
        self.assertIn('data-action="duplicateScript"', app)
        from tests import srcpin
        fn = srcpin.js_function(app, "deleteScript")
        self.assertIn("undoableDelete", fn)
        self.assertNotIn("uiConfirm", fn)

    def test_cross_tab_alert_sync(self):
        app = _js("app.js")
        self.assertIn("BroadcastChannel", app)
        self.assertIn("'rp-sync'", app)
        self.assertIn("_bcast('alerts')", app)
        # sender is central in api(): any successful non-GET under /alerts
        from tests import srcpin
        fn = srcpin.js_function(app, "api")
        self.assertIn("_bcast('alerts')", fn)


class TestWave7ScriptDrafts(unittest.TestCase):
    def test_draft_autosave_wired(self):
        app = _js("app.js")
        self.assertIn("rp_draft_script_", app)
        self.assertIn("function _maybeOfferScriptDraft", app)
        # offered on BOTH editor-open paths (new + edit)
        self.assertEqual(app.count("_maybeOfferScriptDraft();"), 2)
        # cleared on successful save using the PRE-save id
        from tests import srcpin
        fn = srcpin.js_function(app, "saveScriptFromEditor")
        self.assertIn("removeItem('rp_draft_script_' + (id || 'new'))", fn)


class TestWave8(unittest.TestCase):
    """UX wave 8: KB drafts, check duplicate, theme cross-tab, purge counts."""

    def test_kb_draft_autosave(self):
        kb = _js("app-kb.js")
        self.assertIn("rp_draft_kb_", kb)
        self.assertIn("function _maybeOfferKbDraft", kb)
        self.assertEqual(kb.count("_maybeOfferKbDraft();"), 2)
        self.assertIn("removeItem('rp_draft_kb_' + (id || 'new'))", kb)

    def test_custom_check_duplicate(self):
        checks = _js("app-checks.js")
        self.assertIn("function duplicateCustomCheck", checks)
        self.assertIn('data-action="duplicateCustomCheck"', checks)
        # must detach from the source id or "duplicate" would overwrite it
        from tests import srcpin
        fn = srcpin.js_function(checks, "duplicateCustomCheck")
        self.assertIn("_ccEditId = null", fn)

    def test_theme_follows_across_tabs(self):
        app = _js("app.js")
        i = app.index("window.addEventListener('storage'")
        chunk = app[i:i + 500]
        self.assertIn("rp_theme", chunk)
        self.assertIn("applyTheme", chunk)

    def test_alert_purge_confirms_state_counts(self):
        alerts = _js("app-alerts.js")
        self.assertIn("_alertsSummary", alerts)
        from tests import srcpin
        self.assertIn("resolved", srcpin.js_function(alerts, "clearResolvedAlerts"))
        self.assertIn("acknowledged", srcpin.js_function(alerts, "clearAllAlerts"))


class TestWave9(unittest.TestCase):
    """UX wave 9: the post-program idea batch (safe variants)."""

    def test_quiet_hours_flag_in_nav_counts(self):
        from tests import apisrc, srcpin
        fn = srcpin.py_function(apisrc.api_source(), "handle_nav_counts")
        self.assertIn("quiet_hours_active", fn)
        self.assertIn('id="quiet-hours-ind"', _html())

    def test_queue_drained_and_away_digest(self):
        app = _js("app.js")
        self.assertIn("_prevCmdPending", app)
        self.assertIn("Command queue drained", app)
        self.assertIn("While you were away", app)
        self.assertIn("_awaySnap", app)

    def test_undo_history_menu(self):
        app = _js("app.js")
        self.assertIn("function _undoHistoryMenu", app)
        self.assertIn("undoMany", app)
        self.assertIn("contextmenu", app)

    def test_drawer_prev_next(self):
        app = _js("app.js")
        self.assertIn("function drawerStep", app)
        html = _html()
        self.assertEqual(html.count('data-action="drawerStep"'), 2)

    def test_table_view_extras(self):
        app = _js("app.js")
        self.assertIn("function resetView", app)
        self.assertIn("function copyJson", app)
        self.assertIn("tblResetView", app)
        self.assertIn("tblCopyJson", app)
        self.assertIn("sticky-first", app)
        css = (_ROOT / "server/html/static/css/styles.css").read_text()
        self.assertIn("sticky-first", css)

    def test_palette_prefixes(self):
        from tests import srcpin
        fn = srcpin.js_function(_js("app.js"), "_palRender")
        self.assertIn("startsWith('>')", fn)
        self.assertIn("startsWith('#')", fn)

    def test_alert_param_human_hints(self):
        app = _js("app.js")
        self.assertIn("function _apHumanHint", app)
        from tests import srcpin
        fn = srcpin.js_function(app, "_apMarkModified")
        self.assertIn("_apHumanHint", fn)

    def test_ui_scale_and_pull_to_refresh(self):
        app = _js("app.js")
        self.assertIn("rp_uiscale", app)
        self.assertIn("function applyUiScale", app)
        self.assertIn("pointer: coarse", app)
        self.assertIn('id="cfg-ui-scale"', _html())


class TestWave10EyeCandy(unittest.TestCase):
    """UX wave 10: informative eye candy — motion means something."""

    def test_fleet_pulse(self):
        app = _js("app.js")
        self.assertIn("function _drawFleetPulse", app)
        self.assertIn('id="fleet-pulse"', app)

    def test_stat_animation_and_ring(self):
        app = _js("app.js")
        self.assertIn("function animateStat", app)
        self.assertIn("function _progressRing", app)
        # reduced-motion short-circuits the interpolation
        from tests import srcpin
        self.assertIn("prefers-reduced-motion", srcpin.js_function(app, "animateStat"))
        cve = _js("app-cve.js")
        self.assertIn("animateStat('cve-stat-critical'", cve)
        self.assertIn("_progressRing(st.done / st.total)", cve)

    def test_row_flash_and_first_paint(self):
        app = _js("app.js")
        self.assertIn("row-flash", app)
        self.assertIn("first-paint", app)
        self.assertIn("_projPrev", app)

    def test_alert_crit_class_and_heat_strip(self):
        alerts = _js("app-alerts.js")
        self.assertIn("alert-crit", alerts)
        self.assertIn("function _alertsHeatStrip", alerts)
        self.assertIn("rp-empty-art", alerts)

    def test_health_bar_ticks(self):
        app = _js("app.js")
        self.assertIn("hh-bar-tick", app)
        self.assertIn("data-tickleft", app)
        # the observer applies the tick position (no inline style attrs — CSP)
        self.assertIn("data-tickleft]", app)

    def test_css_motion_is_reduced_motion_safe(self):
        css = (_ROOT / "server/html/static/css/styles.css").read_text()
        for cls in ("rp-page-in", "rp-breathe", "rp-crit-pulse", "rp-row-flash", "rp-row-in"):
            self.assertIn(cls, css)
        i = css.index("prefers-reduced-motion")
        block = css[i:i + 600]
        self.assertIn("first-paint", block)
        self.assertIn("row-flash", block)


class TestWave11(unittest.TestCase):
    """UX wave 11: the re-register blink fix + safe selection/tooltip wins."""

    def test_register_carries_render_state(self):
        # The wave-10 first-paint/row-flash state lives on the registration
        # object; tables that re-register per render (devices_minimal) must
        # carry it over or every re-render replays the entrance stagger
        # (the "table blinks on every checkbox select" bug).
        from tests import srcpin
        app = _js("app.js")
        reg = srcpin.js_function(app, "register")
        self.assertIn("prev._painted", reg)
        self.assertIn("prev._projPrev", reg)

    def test_shift_click_range_select(self):
        from tests import srcpin
        app = _js("app.js")
        ts = srcpin.js_function(app, "toggleSelect")
        self.assertIn("_rpShiftClick", ts)
        self.assertIn("_lastToggledDev", ts)
        # order comes from the DOM in BOTH densities
        self.assertIn("tr.dev-row[data-dev-id]", ts)
        self.assertIn(".device-card[data-dev-id]", ts)
        # cards actually carry the id the range walker reads
        self.assertIn('class="device-card', app)
        self.assertIn('decommissioned\' : \'\'}" data-dev-id="${escAttr(d.id)}"', app)

    def test_escape_clears_selection_guarded(self):
        app = _js("app.js")
        i = app.index("Escape clears the batch selection")
        block = app[i:i + 900]
        # every "someone else owns Escape" guard is present
        self.assertIn("_drawerDeviceId", block)
        self.assertIn("modal-open", block)
        self.assertIn("cmd-palette-overlay", block)
        self.assertIn("page-devices", block)
        self.assertIn("clearSelection()", block)

    def test_select_all_reflects_partial_selection(self):
        app = _js("app.js")
        block = app[app.index("select-all header checkbox reflect reality"):][:700]
        self.assertIn("sa.indeterminate", block)
        self.assertIn("sa.checked", block)

    def test_absolute_time_tooltips(self):
        app = _js("app.js")
        self.assertIn("function _absTs", app)
        self.assertIn('title="${escAttr(_absTs(d.last_seen))}"', app)

    def test_cache_bust_is_wave11(self):
        self.assertIn("?v=6.3.0-15", _html())
        sw = (_ROOT / "server/html/sw.js").read_text()
        self.assertIn("remotepower-shell-v6.3.0-15", sw)


class TestWave12TransientToasts(unittest.TestCase):
    """Form-validation toasts must not pollute the notification center."""

    def test_toast_skips_history_when_transient(self):
        from tests import srcpin
        t = srcpin.js_function(_js("app.js"), "toast")
        self.assertIn("if (!opts.transient) _recordToast", t)

    def test_the_reported_site_is_transient(self):
        self.assertIn(
            "toast('Subject required', 'error', {transient: true})",
            _js("app-tickets.js"))

    def test_no_validation_nag_left_without_the_flag(self):
        # Ratchet: a required/Enter/Pick/Choose/Select-at-least validation
        # toast with NO third arg would land in the bell again.
        import re
        pat = re.compile(
            r"toast\('(?:[^']*[Rr]equired[^']*|(?:Enter|Choose|Pick|Select at least)[^']*)', "
            r"'(?:error|warning)'\)")
        for f in sorted(_JS.glob("app*.js")):
            hits = pat.findall(f.read_text())
            self.assertEqual(hits, [], f"{f.name}: validation toast(s) missing transient flag: {hits}")


class TestWave13FleetVisibility(unittest.TestCase):
    """Wave 13: battery health, version-skew chip, check remediation."""

    AGENT = (_ROOT / "client/remotepower-agent.py").read_text()

    def test_battery_collector_in_agent(self):
        self.assertIn("def get_battery", self.AGENT)
        self.assertIn("/sys/class/power_supply", self.AGENT)
        # placed inside `if send_sysinfo:` AFTER sysinfo is built — the
        # AST scope guard (test_v612_agent_sysinfo_scope) enforces ordering;
        # this pins that the store happens at all.
        self.assertIn("sysinfo['battery'] = bat", self.AGENT)

    def test_battery_survives_safe_si(self):
        # safe_si is a whitelist — without this the field silently dies.
        self.assertIn("safe_si['battery']", (_CGI / "api.py").read_text())

    def test_battery_shown_in_drawer(self):
        app = _js("app.js")
        self.assertIn("['Battery', (si.battery && si.battery.length)", app)

    def test_version_skew_chip(self):
        app = _js("app.js")
        self.assertIn("function toggleSkewFilter", app)
        self.assertIn("function _verCmp", app)
        self.assertIn("_staleAgentIds", app)
        self.assertIn("agent${_staleAgentIds.size === 1 ? '' : 's'} outdated", app)

    def test_check_remediate_deep_link(self):
        checks = _js("app-checks.js")
        self.assertIn("function checkRemediate", checks)
        self.assertIn("generate_runbook", checks)
        self.assertIn("data-action=\"checkRemediate\"", checks)
        # lazy-module guard: openAIModal may not be loaded yet
        self.assertIn("_loadAllLazyJs", checks)


if __name__ == "__main__":
    unittest.main()
