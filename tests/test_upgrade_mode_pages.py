#!/usr/bin/env python3
"""Discussion #30: the upgrade-mode block of the Patch Report dialog and its save, run as they are in app.js.

The server side is held by test_upgrade_mode. What it cannot show is what the dialog draws and what the select sends:
the markup for each state, the id that must never reach the change dispatcher as a number, and that a failed save does
not claim success. The two functions are taken out of the file and run under node with stubs for the page helpers.
Self-skips without node.
"""
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import srcpin  # noqa: E402

NODE = shutil.which("node")
APP = ROOT / "server" / "html" / "static" / "js" / "app.js"

PRELUDE = r"""
function escHtml(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
function escAttr(s){return escHtml(s).replace(/'/g,"&#39;");}
const log = [];
let nextGet = null, nextPut = null;
async function api(method, path, body){ log.push(['api', method, path, body === undefined ? null : body]); return method === 'PUT' ? nextPut : nextGet; }
function toast(msg, kind){ log.push(['toast', msg, kind]); }
let patchReportData = null, rendered = 0;
function renderPatchTable(){ rendered++; }
const select = {value: 'extended'};
let block = {outerHTML: 'OLD'};
const document = {getElementById: (id) => id === 'device-patch-mode' ? select : id === 'upgrade-mode-block' ? block : null};
"""


@unittest.skipUnless(NODE, "node not installed")
class TestTheDialogBlock(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        src = APP.read_text()
        block = srcpin.js_function(src, "_upgradeModeBlock")
        save = srcpin.js_function(src, "setHostUpgradeMode")
        assert "async function setHostUpgradeMode" in src, "the save is an async function"   # srcpin starts at the word `function`
        # the hint is one constant, shared with the host drawer's checkbox (test_v749_upgrade_mode_drawer): take it from the file too
        hint = re.search(r"^const _UPGRADE_MODE_HINT = .*?;\n", src, re.M).group(0)
        note = srcpin.js_function(src, "_keptBackNote")
        cls.fns = hint + note + "\n" + block + "\nasync " + save + "\n"

    def js(self, body):
        script = PRELUDE + self.fns + "\n(async () => {\n" + body + "\n})().catch(e => { console.error(e); process.exit(1); });"
        out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
        if out.returncode:
            raise AssertionError(out.stderr)
        return json.loads(out.stdout)

    def test_a_host_the_mode_does_nothing_for_gets_no_block(self):
        got = self.js("console.log(JSON.stringify([_upgradeModeBlock('h', {upgrade_mode_applies: false}), _upgradeModeBlock('h', null), _upgradeModeBlock('h', {})]));")
        self.assertEqual(got, ["", "", ""])

    def test_standard_selects_standard_and_says_how_to_install_what_is_kept_back(self):
        html = self.js("console.log(JSON.stringify(_upgradeModeBlock('h1', {upgrade_mode_applies: true, upgrade_mode: 'standard', kept_back: ['linux-image-amd64']})));")
        self.assertIn('id="upgrade-mode-block"', html)
        self.assertIn('<option value="standard" selected>', html)
        self.assertNotIn('<option value="extended" selected>', html)
        self.assertIn("Packages apt keeps back:", html)
        self.assertIn("<code>linux-image-amd64</code>", html)
        self.assertIn("The standard upgrade leaves them. Switch to Extended to install them.", html)

    def test_extended_selects_extended_and_says_the_next_upgrade_installs_them(self):
        html = self.js("console.log(JSON.stringify(_upgradeModeBlock('h1', {upgrade_mode_applies: true, upgrade_mode: 'extended', kept_back: ['linux-firmware']})));")
        self.assertIn('<option value="extended" selected>', html)
        self.assertNotIn('<option value="standard" selected>', html)
        self.assertIn("The next upgrade installs them.", html)
        self.assertNotIn("Switch to Extended", html)

    def test_nothing_kept_back_means_no_line_about_it(self):
        html = self.js("console.log(JSON.stringify(_upgradeModeBlock('h1', {upgrade_mode_applies: true, upgrade_mode: 'standard', kept_back: []})));")
        self.assertNotIn("keeps back:", html)
        self.assertIn("Standard runs apt-get upgrade", html)

    def test_a_long_list_is_cut_after_twelve(self):
        names = [f"pkg{i}" for i in range(20)]
        html = self.js("console.log(JSON.stringify(_upgradeModeBlock('h1', {upgrade_mode_applies: true, kept_back: %s})));" % json.dumps(names))
        self.assertIn("pkg11", html)
        self.assertNotIn("pkg12", html)
        self.assertIn(", …", html)

    def test_names_and_the_id_are_escaped(self):
        html = self.js("""console.log(JSON.stringify(_upgradeModeBlock('"><img src=x onerror=1>', {upgrade_mode_applies: true, kept_back: ['<script>x</script>']})));""")
        self.assertNotIn("<img", html)
        self.assertNotIn("<script>", html)

    def test_the_host_id_goes_to_the_dispatcher_with_a_prefix_so_it_cannot_become_a_number(self):
        html = self.js("console.log(JSON.stringify(_upgradeModeBlock('1e5000', {upgrade_mode_applies: true})));")
        self.assertIn('data-change="setHostUpgradeMode"', html)
        self.assertIn('data-change-arg="host:1e5000"', html)
        # the dispatcher turns an argument into a number when isNaN says it is one; with the prefix it never is
        self.assertTrue(self.js("console.log(JSON.stringify(isNaN('host:1e5000')));"))
        self.assertFalse(self.js("console.log(JSON.stringify(isNaN('1e5000')));"))

    def test_the_select_has_a_name_for_screen_readers(self):
        html = self.js("console.log(JSON.stringify(_upgradeModeBlock('h1', {upgrade_mode_applies: true})));")
        self.assertIn('aria-label="Upgrade mode"', html)

    def test_saving_sends_the_chosen_mode_to_the_hosts_own_route(self):
        got = self.js("""
            nextPut = {ok: true, mode: 'extended'}; nextGet = {upgrade_mode_applies: true, upgrade_mode: 'extended', kept_back: []};
            patchReportData = {devices: [{device_id: 'h1', upgrade_mode: 'standard'}]};
            await setHostUpgradeMode('host:h1');
            console.log(JSON.stringify({log, row: patchReportData.devices[0].upgrade_mode, rendered, block: block.outerHTML.includes('selected>Extended')}));""")
        self.assertEqual(got["log"][0], ["api", "PUT", "/devices/h1/upgrade-mode", {"mode": "extended"}])
        self.assertIn(["toast", "Upgrade mode saved", "success"], got["log"])
        self.assertEqual(got["log"][-1][:3], ["api", "GET", "/patch-report/device/h1"])
        self.assertEqual((got["row"], got["rendered"]), ("extended", 1), "the table row and its badge follow the save")
        self.assertNotEqual(got["block"], None)

    def test_an_id_with_characters_that_need_encoding_is_encoded(self):
        got = self.js("nextPut = {ok: true, mode: 'extended'}; nextGet = null; await setHostUpgradeMode('host:a/b c'); console.log(JSON.stringify(log[0]));")
        self.assertEqual(got[2], "/devices/a%2Fb%20c/upgrade-mode")

    def test_a_refusal_is_shown_and_nothing_is_refreshed_as_if_it_had_worked(self):
        got = self.js("""
            nextPut = {error: 'The upgrade mode applies to Linux hosts that use apt', reason: 'not_linux'};
            patchReportData = {devices: [{device_id: 'h1', upgrade_mode: 'standard'}]};
            await setHostUpgradeMode('host:h1');
            console.log(JSON.stringify({log, row: patchReportData.devices[0].upgrade_mode, rendered}));""")
        self.assertEqual(got["log"][1], ["toast", "The upgrade mode applies to Linux hosts that use apt", "error"])
        self.assertEqual((got["row"], got["rendered"], len(got["log"])), ("standard", 0, 2))

    def test_no_answer_at_all_is_an_error_too(self):
        got = self.js("nextPut = null; await setHostUpgradeMode('host:h1'); console.log(JSON.stringify(log));")
        self.assertEqual(got[1], ["toast", "Could not save the upgrade mode", "error"])

    def test_without_the_select_it_does_nothing(self):
        got = self.js("const keep = document.getElementById; document.getElementById = () => null; await setHostUpgradeMode('host:h1'); console.log(JSON.stringify(log));")
        self.assertEqual(got, [])


class TestTheFilesStillCarryTheWiring(unittest.TestCase):
    """Source checks for what node cannot run: the dialog calls the block, the table marks the host, bulk reaches the route."""

    def setUp(self):
        self.src = APP.read_text()

    def test_the_patch_report_dialog_draws_the_block(self):
        body = srcpin.js_function(self.src, "openDevicePatchReport")
        self.assertIn("_upgradeModeBlock(devId, data)", body)

    def test_the_table_marks_an_extended_apt_host(self):
        self.assertIn("d.pkg_manager === 'apt' && d.upgrade_mode === 'extended'", self.src)
        self.assertIn("${silentBadge}${extendedBadge}${rebootBadge}", self.src)

    def test_bulk_actions_offer_both_modes_and_send_them_to_each_hosts_route(self):
        body = srcpin.js_function(self.src, "runBulkAction")
        self.assertIn("upgrade_mode_extended", body)
        self.assertIn("/upgrade-mode`, { mode }", body)
        self.assertIn('<option value="upgrade_mode_standard">', self.src)
        self.assertIn('<option value="upgrade_mode_extended">', self.src)


if __name__ == "__main__":
    unittest.main()
