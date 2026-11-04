#!/usr/bin/env python3
"""7.4.9: the upgrade mode as a checkbox in the host's own drawer, under Host settings.

The mode (Standard or Extended) used to be reachable from one place only: the Patch Report of a host, which is opened from the Patches
page. A person who presses Upgrade packages in the host's drawer and finds the kernel not installed has no reason to look there. The
drawer's Host settings section already holds the host's other checks (Monitored, Quarantine), so the mode is one of them now, and the
Patch Report's select stays: it is the same setting, written through the same route.

Three things are held here:

* the host list carries `upgrade_mode` and `upgrade_mode_applies`, decided by the function the PUT route uses, so the checkbox and the
  route cannot disagree about which hosts the mode applies to; the slim list the pages poll is unchanged;
* the drawer's row and its save, run as they are in app.js under node: the states, the sentence about what apt keeps back, the id that
  must never reach the change dispatcher as a number, a refused save that puts the checkbox back, a drawer that moved to another host;
* the wiring (the row sits with the other checks, it is not part of the form's own save) and the translations (every string the row
  shows is one the Patch Report already has, in all six languages, and the long hint is one constant).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import srcpin  # noqa: E402
from test_upgrade_mode import FLEET, _Fleet, api, call, get  # noqa: E402

NODE = shutil.which("node")
APP = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
I18N = (ROOT / "server" / "html" / "static" / "js" / "i18n.js").read_text()


# ── the host list ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestTheHostListCarriesTheMode(_Fleet):

    def rows(self, slim=False):
        os.environ["QUERY_STRING"] = "slim=1" if slim else ""
        api._LOAD_CACHE.clear()
        try:
            box = call(api.handle_devices_list, {}, verb="GET")
        finally:
            os.environ.pop("QUERY_STRING", None)
        self.assertEqual(box["status"], 200, box)
        return {r["id"]: r for r in box["body"]}

    def store(self, dev_id, **fields):
        devs = json.loads(json.dumps(FLEET))
        devs[dev_id].update(fields)
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()

    def test_an_apt_host_reads_standard_and_the_mode_applies(self):
        row = self.rows()["stdhost"]
        self.assertEqual((row["upgrade_mode"], row["upgrade_mode_applies"]), ("standard", True))

    def test_a_host_set_to_extended_reads_extended(self):
        row = self.rows()["exthost"]
        self.assertEqual((row["upgrade_mode"], row["upgrade_mode_applies"]), ("extended", True))

    def test_a_windows_host_and_a_dnf_host_get_no_checkbox(self):
        rows = self.rows()
        self.assertIs(rows["winhost"]["upgrade_mode_applies"], False)
        self.assertIs(rows["dnfhost"]["upgrade_mode_applies"], False)

    def test_a_host_that_has_not_reported_a_package_manager_is_still_an_apt_host(self):
        # an agent that has not sent its first package scan is not held against the mode
        self.assertIs(self.rows()["unkhost"]["upgrade_mode_applies"], True)

    def test_a_stored_word_that_is_not_a_mode_reads_standard(self):
        for junk in ("EXTENDED", "Extended ", "extended;rm", 5, None, True, ["extended"], {"mode": "extended"}, ""):
            with self.subTest(junk=repr(junk)):
                self.store("stdhost", upgrade_mode=junk)
                self.assertEqual(self.rows()["stdhost"]["upgrade_mode"], "standard")

    def test_the_slim_list_the_pages_poll_is_unchanged(self):
        for row in self.rows(slim=True).values():
            self.assertNotIn("upgrade_mode", row)
            self.assertNotIn("upgrade_mode_applies", row)

    def test_it_agrees_with_the_route_for_every_host(self):
        rows = self.rows()
        self.assertGreaterEqual(len(rows), 5)
        for dev_id, row in rows.items():
            with self.subTest(host=dev_id):
                box = get(dev_id)
                self.assertEqual(box["status"], 200, box)
                self.assertEqual((row["upgrade_mode"], row["upgrade_mode_applies"]), (box["body"]["mode"], box["body"]["applies"]))

    def test_the_agreement_holds_when_the_rule_changes_under_it(self):
        # the row is not a second copy of the rule: it asks the route's own function
        src = srcpin.py_function(Path(ROOT / "server" / "cgi-bin" / "api.py").read_text(), "handle_devices_list")
        self.assertIn("upgrade_mode_handlers_mod._state(dev)", src)
        self.assertNotIn("not_applicable(", src)


# ── the drawer row, run under node ───────────────────────────────────────────────────────────────────────────────────────────────
PRELUDE = r"""
function escHtml(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
function escAttr(s){return escHtml(s).replace(/'/g,"&#39;");}
const log = [];
let nextPut = null;
async function api(method, path, body){ log.push(['api', method, path, body === undefined ? null : body]); return nextPut; }
function toast(msg, kind){ log.push(['toast', msg, kind]); }
let patchReportData = null, rendered = 0;
function renderPatchTable(){ rendered++; }
let _drawerDeviceData = null, _drawerDeviceId = null;
const box = {checked: true, focused: 0, focus() { this.focused++; }};
const rowEl = {outerHTML: 'OLD'};
let hasBox = true;
const document = {getElementById: (id) => id === 'ds-upgrade-extended' ? (hasBox ? box : null) : id === 'ds-upgrade-row' ? rowEl : null};
"""

HINT = ("Standard runs apt-get upgrade, which keeps back an update that needs a package that is not installed yet, such as a new kernel image. "
        "Extended runs apt-get upgrade --with-new-pkgs, which installs those packages as well and removes nothing. The mode applies to the patch "
        "button, auto-patch, scheduled upgrades and rollouts.")


def host(**kw):
    d = {"upgrade_mode_applies": True, "upgrade_mode": "standard", "sysinfo": {"packages": {"manager": "apt", "kept_back": ["linux-image-amd64"]}}}
    d.update(kw)
    return d


@unittest.skipUnless(NODE, "node not installed")
class TestTheRowAndItsSave(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        const = re.search(r"^const _UPGRADE_MODE_HINT = .*?;\n", APP, re.M).group(0)
        row = srcpin.js_function(APP, "_drawerUpgradeRow")
        save = srcpin.js_function(APP, "setDrawerUpgradeMode")
        assert "async function setDrawerUpgradeMode" in APP, "the save is an async function"      # srcpin starts at the word `function`
        note = srcpin.js_function(APP, "_keptBackNote")
        cls.fns = const + note + "\n" + row + "\nasync " + save + "\n"

    def js(self, body):
        script = PRELUDE + self.fns + "\n(async () => {\n" + body + "\n})().catch(e => { console.error(e); process.exit(1); });"
        out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
        if out.returncode:
            raise AssertionError(out.stderr)
        return json.loads(out.stdout)

    def row(self, d, id_="h1"):
        return self.js("console.log(JSON.stringify(_drawerUpgradeRow(%s, %s)));" % (json.dumps(d), json.dumps(id_)))

    # the states
    def test_a_host_the_mode_does_nothing_for_gets_no_row(self):
        got = self.js("console.log(JSON.stringify([_drawerUpgradeRow({upgrade_mode_applies: false}, 'h'), _drawerUpgradeRow(null, 'h'), _drawerUpgradeRow({}, 'h'), _drawerUpgradeRow(undefined, 'h')]));")
        self.assertEqual(got, ["", "", "", ""])

    def test_standard_is_unticked_and_says_how_to_install_what_is_kept_back(self):
        html = self.row(host())
        self.assertIn('id="ds-upgrade-row"', html)
        self.assertIn('<input type="checkbox" id="ds-upgrade-extended" data-change="setDrawerUpgradeMode"', html)
        self.assertNotIn(" checked", html)
        self.assertIn("Packages apt keeps back:", html)
        self.assertIn("<code>linux-image-amd64</code>", html)
        self.assertIn("The standard upgrade leaves them. Switch to Extended to install them.", html)

    def test_extended_is_ticked_and_says_the_next_upgrade_installs_them(self):
        html = self.row(host(upgrade_mode="extended"))
        self.assertIn('id="ds-upgrade-extended" checked data-change', html)
        self.assertIn("The next upgrade installs them.", html)
        self.assertNotIn("Switch to Extended", html)

    def test_nothing_kept_back_means_no_line_about_it(self):
        for d in (host(sysinfo={"packages": {"manager": "apt", "kept_back": []}}), host(sysinfo={"packages": {"manager": "apt"}}),
                  host(sysinfo={}), host(sysinfo=None), host(sysinfo={"packages": None}), host(sysinfo={"packages": {"kept_back": "linux-image-amd64"}})):
            with self.subTest(sysinfo=d.get("sysinfo")):
                html = self.row(d)
                self.assertNotIn("keeps back:", html)
                self.assertIn('id="ds-upgrade-extended"', html)

    def test_a_long_list_is_cut_after_twelve(self):
        names = ["pkg%d" % i for i in range(20)]
        html = self.row(host(sysinfo={"packages": {"kept_back": names}}))
        self.assertIn("pkg11", html)
        self.assertNotIn("pkg12", html)
        self.assertIn(", …", html)

    def test_a_name_that_is_not_text_is_left_out(self):
        html = self.row(host(sysinfo={"packages": {"kept_back": [None, 5, {"x": 1}, "real-pkg", ["a"]]}}))
        self.assertIn("<code>real-pkg</code>", html)
        self.assertNotIn("null", html)
        self.assertNotIn("[object", html)

    def test_names_and_the_id_are_escaped(self):
        html = self.row(host(sysinfo={"packages": {"kept_back": ["<script>x</script>"]}}), '"><img src=x onerror=1>')
        self.assertNotIn("<img", html)
        self.assertNotIn("<script>", html)

    def test_the_host_id_goes_to_the_dispatcher_with_a_prefix_so_it_cannot_become_a_number(self):
        html = self.row(host(), "1e5000")
        self.assertIn('data-change-arg="host:1e5000"', html)
        self.assertNotIn('data-change-arg="1e5000"', html)

    def test_the_checkbox_is_named_by_its_visible_text(self):
        html = self.row(host())
        self.assertRegex(html, r'<label class="click-row-6"><input type="checkbox"[^>]*><span class="fs-12">Extended — also installs the new packages an update needs</span></label>')
        self.assertIn('<span class="drawer-setting-label">Upgrade mode</span>', html)

    def test_it_carries_no_inline_style_or_handler(self):
        html = self.row(host())
        self.assertNotIn("style=", html)
        self.assertNotRegex(html, r"\son[a-z]+=")

    def test_the_hint_is_the_one_the_patch_report_shows(self):
        html = self.row(host())
        self.assertIn('<span class="hint">%s</span>' % HINT, html)
        block = srcpin.js_function(APP, "_upgradeModeBlock")
        self.assertIn("_UPGRADE_MODE_HINT", block)
        self.assertNotIn("Standard runs apt-get upgrade", block, "the Patch Report must not carry a second copy of the sentence")

    # the save
    def test_ticking_it_sends_extended_and_unticking_sends_standard(self):
        got = self.js("""
            nextPut = {ok: true, mode: 'extended'}; box.checked = true; await setDrawerUpgradeMode('host:h1');
            nextPut = {ok: true, mode: 'standard'}; box.checked = false; await setDrawerUpgradeMode('host:h1');
            console.log(JSON.stringify(log.filter(l => l[0] === 'api')));""")
        self.assertEqual(got[0], ["api", "PUT", "/devices/h1/upgrade-mode", {"mode": "extended"}])
        self.assertEqual(got[1], ["api", "PUT", "/devices/h1/upgrade-mode", {"mode": "standard"}])

    def test_a_save_updates_the_drawers_data_the_patches_row_and_the_row_itself(self):
        got = self.js("""
            nextPut = {ok: true, mode: 'extended'}; box.checked = true;
            _drawerDeviceId = 'h1'; _drawerDeviceData = %s;
            patchReportData = {devices: [{device_id: 'h1', upgrade_mode: 'standard'}, {device_id: 'h2', upgrade_mode: 'standard'}]};
            await setDrawerUpgradeMode('host:h1');
            console.log(JSON.stringify({log, data: _drawerDeviceData.upgrade_mode, rows: patchReportData.devices.map(d => d.upgrade_mode), rendered,
                                        row: rowEl.outerHTML, focused: box.focused}));""" % json.dumps(host()))
        self.assertIn(["toast", "Upgrade mode saved", "success"], got["log"])
        self.assertEqual(got["data"], "extended")
        self.assertEqual(got["rows"], ["extended", "standard"], "only this host's row on the Patches page follows")
        self.assertEqual(got["rendered"], 1)
        self.assertIn('id="ds-upgrade-extended" checked', got["row"], "the row is drawn again from the new mode")
        self.assertIn("The next upgrade installs them.", got["row"])
        self.assertEqual(got["focused"], 1, "the row was drawn again, so the keyboard is put back on the checkbox")

    def test_a_refused_save_puts_the_checkbox_back_and_changes_nothing_else(self):
        got = self.js("""
            nextPut = {error: 'The upgrade mode applies to Linux hosts that use apt', reason: 'not_linux'}; box.checked = true;
            _drawerDeviceId = 'h1'; _drawerDeviceData = %s;
            patchReportData = {devices: [{device_id: 'h1', upgrade_mode: 'standard'}]};
            await setDrawerUpgradeMode('host:h1');
            console.log(JSON.stringify({log, checked: box.checked, data: _drawerDeviceData.upgrade_mode, row: patchReportData.devices[0].upgrade_mode,
                                        rendered, html: rowEl.outerHTML}));""" % json.dumps(host()))
        self.assertEqual(got["log"][1], ["toast", "The upgrade mode applies to Linux hosts that use apt", "error"])
        self.assertIs(got["checked"], False, "the box says what the server holds")
        self.assertEqual((got["data"], got["row"], got["rendered"], got["html"]), ("standard", "standard", 0, "OLD"))

    def test_no_answer_at_all_is_an_error_too(self):
        got = self.js("nextPut = null; box.checked = true; await setDrawerUpgradeMode('host:h1'); console.log(JSON.stringify({log, checked: box.checked}));")
        self.assertEqual(got["log"][1], ["toast", "Could not save the upgrade mode", "error"])
        self.assertIs(got["checked"], False)

    def test_an_answer_that_says_not_ok_is_not_a_save(self):
        got = self.js("nextPut = {ok: false}; box.checked = true; await setDrawerUpgradeMode('host:h1'); console.log(JSON.stringify({log, checked: box.checked}));")
        self.assertEqual(got["log"][1][0], "toast")
        self.assertEqual(got["log"][1][2], "error")
        self.assertIs(got["checked"], False)

    def test_a_drawer_that_moved_to_another_host_is_left_alone(self):
        # the save for h1 comes back after the drawer was opened on h2: h2's data and row are not h1's to change
        got = self.js("""
            nextPut = {ok: true, mode: 'extended'}; box.checked = true;
            _drawerDeviceId = 'h2'; _drawerDeviceData = %s;
            patchReportData = {devices: [{device_id: 'h1', upgrade_mode: 'standard'}]};
            await setDrawerUpgradeMode('host:h1');
            console.log(JSON.stringify({data: _drawerDeviceData.upgrade_mode, html: rowEl.outerHTML, row: patchReportData.devices[0].upgrade_mode, rendered, focused: box.focused}));""" % json.dumps(host()))
        self.assertEqual((got["data"], got["html"], got["focused"]), ("standard", "OLD", 0))
        self.assertEqual((got["row"], got["rendered"]), ("extended", 1), "the Patches page row is by host id, so it still follows")

    def test_an_id_with_characters_that_need_encoding_is_encoded(self):
        got = self.js("nextPut = {ok: true, mode: 'extended'}; await setDrawerUpgradeMode('host:a/b c'); console.log(JSON.stringify(log[0]));")
        self.assertEqual(got[2], "/devices/a%2Fb%20c/upgrade-mode")

    def test_without_the_checkbox_it_does_nothing(self):
        got = self.js("hasBox = false; await setDrawerUpgradeMode('host:h1'); console.log(JSON.stringify(log));")
        self.assertEqual(got, [])


# ── the wiring and the words ─────────────────────────────────────────────────────────────────────────────────────────────────────
class TestTheWiring(unittest.TestCase):

    def test_the_row_sits_with_the_hosts_other_checks_and_not_in_an_agentless_host(self):
        body = srcpin.js_function(APP, "_renderDrawerSettings")
        call_site = "${isAgentless ? '' : _drawerUpgradeRow(d, id)}"
        self.assertIn(call_site, body)
        self.assertLess(body.index('id="ds-quarantine"'), body.index(call_site), "after Quarantine")
        self.assertLess(body.index(call_site), body.index('id="ds-poll"'), "before the poll interval, with the checks and not among the lists")

    def test_the_row_is_saved_by_its_own_change_and_not_by_the_forms_save(self):
        # the form's Save button collects the ds-* fields; a checkbox that saves itself must not be written a second time by it
        for name in ("saveDrawerSettings", "_saveDrawerSettings"):
            m = re.search(r"(?:async )?function %s\b" % name, APP)
            if m:
                self.assertNotIn("ds-upgrade-extended", srcpin.js_function(APP, name), name)
        # the id is read twice and by nobody else: by the save, and to put the keyboard back after the row is drawn again
        self.assertEqual(len(re.findall(r"getElementById\('ds-upgrade-extended'\)", APP)), 2)

    def test_the_patch_report_still_has_its_select(self):
        self.assertGreaterEqual(APP.count("_upgradeModeBlock("), 2, "defined, and called by the dialog")
        self.assertIn('data-change="setHostUpgradeMode"', srcpin.js_function(APP, "_upgradeModeBlock"))

    def test_the_handler_is_a_function_the_dispatcher_can_reach(self):
        srcpin.js_function(APP, "setDrawerUpgradeMode")
        self.assertRegex(APP, r"\n(?:async )?function setDrawerUpgradeMode\(")


class TestTheTranslations(unittest.TestCase):
    """Every string the row shows is one the Patch Report already has, in all six languages: the row adds no translation of its own."""

    SHOWN = ["Upgrade mode", "Extended — also installs the new packages an update needs", HINT, "Packages apt keeps back:",
             "The next upgrade installs them.", "The standard upgrade leaves them. Switch to Extended to install them.",
             "Upgrade mode saved", "Could not save the upgrade mode"]

    def entry(self, key):
        return re.search(r'^\s+"%s":\s*\{(.+?)\},?\s*$' % re.escape(key), I18N, re.M)

    def test_every_string_has_all_six_languages(self):
        for key in self.SHOWN:
            m = self.entry(key)
            self.assertIsNotNone(m, key[:60])
            langs = re.findall(r'"(zh|hi|es|ar|de|fr)":\s*"', m.group(1))
            self.assertEqual(sorted(langs), ["ar", "de", "es", "fr", "hi", "zh"], key[:60])

    def test_every_literal_the_row_shows_is_in_the_list(self):
        row = srcpin.js_function(APP, "_drawerUpgradeRow") + srcpin.js_function(APP, "setDrawerUpgradeMode")
        for text in re.findall(r"<span[^>]*>([A-Z][^<$]{6,})</span>", row):
            self.assertIn(text, self.SHOWN, text)
        for text in re.findall(r"toast\('([^']+)'", row):
            self.assertIn(text, self.SHOWN, text)
        # the two sentences about what apt keeps back are in one helper that the Patch Report and the drawer both call
        note = srcpin.js_function(APP, "_keptBackNote")
        self.assertIn("'The next upgrade installs them.'", note)
        self.assertIn("'The standard upgrade leaves them. Switch to Extended to install them.'", note)
        self.assertIn("Packages apt keeps back:", note)
        for caller in ("_drawerUpgradeRow", "_upgradeModeBlock"):
            body = srcpin.js_function(APP, caller)
            self.assertIn("_keptBackNote(", body, caller)
            self.assertNotIn("Packages apt keeps back", body, caller + " carries its own copy of the sentence")
            self.assertNotIn("The standard upgrade leaves them", body, caller + " carries its own copy of the sentence")

    def test_the_hint_constant_is_the_listed_sentence(self):
        const = re.search(r"^const _UPGRADE_MODE_HINT = '(.*?)';\n", APP, re.M).group(1)
        self.assertEqual(const, HINT)


if __name__ == "__main__":
    unittest.main()
