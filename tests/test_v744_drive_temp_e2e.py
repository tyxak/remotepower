#!/usr/bin/env python3
"""7.4.4, issue #54: temperature lines for drives, on the pages.

The server side (the rules, the alert and its close, the handlers) is in test_v744_drive_temp. What that
cannot show is the page: that the Hardware tab colours a drive's temperature against the lines it is held
to, lists two boxes of its own for each drive (for an administrator only) with the line each would use
instead in grey, saves what was typed and takes a line away when its box is emptied, and refuses a pair
whose warning is not below its critical line; that a host's own lines and the fleet's can be set from the
Metric thresholds box and from Settings -> Alert parameters.

The page is real (a seeded instance, a signed-in browser, the drawer and the dialogs opened the way a
person opens them). Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for p in (_HERE, _ROOT / "server" / "cgi-bin"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}
HOST = "tnas"
HOST_NAME = "truenas.lab"

# What the demo seeder sets, so each test can put it back: the fleet's lines, and one drive with lines of its own.
SEEDED_FLEET = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50, "drivetemp_ssd_warn_c": 65,
                "drivetemp_ssd_crit_c": 70, "drivetemp_nvme_warn_c": 70, "drivetemp_nvme_crit_c": 80}
HOST_KEYS = ["drivetemp_warn_c", "drivetemp_crit_c", "drivetemp_hdd_warn_c", "drivetemp_hdd_crit_c",
             "drivetemp_ssd_warn_c", "drivetemp_ssd_crit_c", "drivetemp_nvme_warn_c", "drivetemp_nvme_crit_c"]


def _sign_in(browser, base, user, password):
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    return context, page, errors


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-drivetemp-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail(f"chromium not available: {exc}")
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest(f"app stack not available: {exc}")
    context, page, errors = _sign_in(browser, base, "alice", "demo")
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Page(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        # a toast from the test before would satisfy this test's wait for its own
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")

    def tearDown(self):
        try:
            self.page.evaluate("closeDeviceDrawer()")
        except Exception:
            pass
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def drives(self):
        """{device: {serial, temperature_c, lines}} as the Hardware answer gives them."""
        return self.page.evaluate("""async (id) => {
            const hw = await api('GET', `/devices/${id}/hardware`);
            const out = {};
            for (const d of hw.smart || []) out[d.device] = {serial: d.serial, temp: d.temperature_c, lines: d.lines};
            return out;
        }""", HOST)

    def host_overrides(self):
        return self.page.evaluate("async (id) => (await api('GET', `/devices/${id}/metric-thresholds`)).overrides", HOST)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheHardwareTab(_Page):

    def setUp(self):
        super().setUp()
        self.d = self.drives()
        self.sda, self.sdb, self.sdd = (self.d["/dev/sda"]["serial"], self.d["/dev/sdb"]["serial"],
                                        self.d["/dev/sdd"]["serial"])

    def tearDown(self):
        # put the seeded lines back: nothing on the first three drives, 50 and 55 on the fourth
        self.page.evaluate("""async ([id, sda, sdb, sdc, sdd]) => {
            await api('PATCH', `/devices/${id}/metric-thresholds`, {drivetemp_per_serial:
                {[sda]: null, [sdb]: null, [sdc]: null, [sdd]: {warn: 50, crit: 55}}});
            await api('PUT', `/devices/${id}/disk-names`, {names: {[sda]: '', [sdb]: ''}});
        }""", [HOST, self.sda, self.sdb, self.d["/dev/sdc"]["serial"], self.sdd])
        super().tearDown()

    def open_hardware(self, page=None):
        page = page or self.page
        page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [HOST, HOST_NAME])
        page.wait_for_selector("#audit-sec-hardware", state="attached", timeout=30000)
        if not page.eval_on_selector("#audit-sec-hardware", "d => d.open"):
            page.click("#audit-sec-hardware > summary")
        page.wait_for_selector("#hw-smart-thead", state="visible", timeout=30000)
        # The table the drawer still holds from the test before would satisfy that wait and be read as this
        # test's. Mark it, load the section again the way the page does after a save, and wait for the
        # table that replaces it.
        page.evaluate("() => { const t = document.getElementById('hw-smart-thead'); if (t) t.__stale = true; "
                      "_loadAuditSectionForce('hardware'); }")
        page.wait_for_function("() => { const t = document.getElementById('hw-smart-thead'); return !!t && !t.__stale; }",
                               timeout=30000)

    def temp_cell(self, device, page=None):
        """(class, title, text) of the Temp cell in the row whose first cell holds this device."""
        page = page or self.page
        return page.evaluate("""(device) => {
            const th = Array.from(document.querySelectorAll('#hw-smart-thead th'));
            const col = th.findIndex(x => x.dataset.col === 'temp');
            const row = Array.from(document.querySelectorAll('#hw-smart-thead')[0].closest('table').querySelectorAll('tbody tr'))
                .find(tr => tr.cells[0].innerText.includes(device));
            const c = row.cells[col];
            return [c.className, c.getAttribute('title') || '', c.innerText.trim()];
        }""", device)

    def box(self, serial, which):
        return f"#hw-diskname-form input[data-line-serial='{serial}'][data-line='{which}']"

    def save(self):
        self.page.click('#hw-diskname-form [data-action="saveDiskNames"]')

    def test_a_drive_over_its_line_is_coloured_and_says_the_lines(self):
        self.open_hardware()
        cls, title, text = self.temp_cell("/dev/sdb")
        self.assertIn("c-amber", cls.split(), (cls, text))
        self.assertEqual(title, "≥ 45 °C / ≥ 50 °C")
        for quiet in ("/dev/sda", "/dev/sdc"):
            cls, title, _ = self.temp_cell(quiet)
            self.assertNotIn("c-amber", cls.split(), quiet)
            self.assertNotIn("c-red", cls.split(), quiet)
            self.assertEqual(title, "≥ 45 °C / ≥ 50 °C", "a quiet drive still says what it is held to")

    def test_a_drive_over_its_critical_line_is_red_and_one_between_the_lines_is_amber(self):
        """The demo's drives are calm or over a warning line, so the other two colours are made here: /dev/sda
        (34 degrees) is given a critical line under its reading, /dev/sdc (30) a warning line under its."""
        self.page.evaluate("async ([id, a, c]) => { await api('PATCH', `/devices/${id}/metric-thresholds`, "
                           "{drivetemp_per_serial: {[a]: {warn: 20, crit: 30}, [c]: {warn: 25, crit: 40}}}); }",
                           [HOST, self.sda, self.d["/dev/sdc"]["serial"]])
        self.open_hardware()
        cls, title, _ = self.temp_cell("/dev/sda")
        self.assertIn("c-red", cls.split(), cls)
        self.assertNotIn("c-amber", cls.split(), "red replaces amber, it does not join it")
        self.assertEqual(title, "≥ 20 °C / ≥ 30 °C")
        cls, _title, _ = self.temp_cell("/dev/sdc")
        self.assertIn("c-amber", cls.split(), cls)
        self.assertNotIn("c-red", cls.split())

    def test_a_drive_with_lines_of_its_own_is_held_to_them(self):
        """/dev/sdd has 50 and 55 from the demo; at its reading that is calm, and the tooltip says so."""
        self.open_hardware()
        _cls, title, _ = self.temp_cell("/dev/sdd")
        self.assertEqual(title, "≥ 50 °C / ≥ 55 °C")

    def test_each_drive_has_two_boxes_and_the_empty_ones_show_the_line_they_would_use(self):
        self.open_hardware()
        self.page.wait_for_selector("#hw-diskname-form", timeout=15000)
        self.assertEqual(self.page.input_value(self.box(self.sdd, "warn")), "50")
        self.assertEqual(self.page.input_value(self.box(self.sdd, "crit")), "55")
        self.assertEqual(self.page.get_attribute(self.box(self.sdd, "warn"), "placeholder"), "45",
                         "its own boxes show what it would use without them")
        self.assertEqual(self.page.input_value(self.box(self.sda, "warn")), "")
        self.assertEqual(self.page.get_attribute(self.box(self.sda, "warn"), "placeholder"), "45")
        self.assertEqual(self.page.get_attribute(self.box(self.sda, "crit"), "placeholder"), "50")
        count = self.page.eval_on_selector_all("#hw-diskname-form input[data-line]", "els => els.length")
        self.assertEqual(count, 2 * len(self.d), "two boxes for every drive with a serial")
        label = self.page.inner_text(f"#hw-diskname-form input[data-serial='{self.sda}'] >> xpath=preceding-sibling::label[1]")
        self.assertIn("HDD", label, "the type the lines see")
        self.assertEqual(self.page.inner_text("#hw-diskname-form [data-action='saveDiskNames']").strip(),
                         "Save names and lines")

    def test_a_saved_line_is_kept_against_the_serial_and_changes_the_colour(self):
        self.open_hardware()
        self.page.wait_for_selector("#hw-diskname-form", timeout=15000)
        self.page.fill(self.box(self.sda, "warn"), "30")
        self.page.fill(self.box(self.sda, "crit"), "60")
        self.save()
        self.page.wait_for_selector(".toast.success", timeout=15000)
        self.assertEqual(self.page.inner_text(".toast.success").strip(), "Disk names and lines saved")
        self.assertEqual(self.host_overrides()["drivetemp_per_serial"][self.sda], {"warn": 30, "crit": 60})
        self.page.wait_for_function(
            "() => { const t = document.getElementById('hw-smart-thead'); return !!t && "
            "Array.from(t.closest('table').querySelectorAll('tbody tr')).some(tr => tr.cells[0].innerText.includes('/dev/sda') "
            "&& tr.innerHTML.includes('c-amber')); }", timeout=15000)
        cls, title, text = self.temp_cell("/dev/sda")
        self.assertIn("c-amber", cls.split(), (cls, text))
        self.assertEqual(title, "≥ 30 °C / ≥ 60 °C")
        self.assertEqual(self.page.input_value(self.box(self.sda, "warn")), "30", "and the box reads back")

    def test_emptying_a_box_takes_that_line_away_and_leaves_the_other(self):
        self.page.evaluate("async ([id, s]) => { await api('PATCH', `/devices/${id}/metric-thresholds`, "
                           "{drivetemp_per_serial: {[s]: {warn: 30, crit: 60}}}); }", [HOST, self.sda])
        self.open_hardware()
        self.page.wait_for_selector("#hw-diskname-form", timeout=15000)
        self.assertEqual(self.page.input_value(self.box(self.sda, "warn")), "30")
        self.page.fill(self.box(self.sda, "warn"), "")
        self.save()
        self.page.wait_for_selector(".toast.success", timeout=15000)
        self.assertEqual(self.host_overrides()["drivetemp_per_serial"][self.sda], {"crit": 60})

    def test_names_alone_are_saved_as_before_and_say_so(self):
        self.open_hardware()
        self.page.wait_for_selector("#hw-diskname-form", timeout=15000)
        self.page.fill(f"#hw-diskname-form input[data-serial='{self.sda}']", "Pool disk 2")
        self.save()
        self.page.wait_for_selector(".toast.success", timeout=15000)
        self.assertEqual(self.page.inner_text(".toast.success").strip(), "Disk names saved")
        self.assertNotIn(self.sda, self.host_overrides().get("drivetemp_per_serial", {}),
                         "no line was typed, so none was sent")

    def test_a_pair_whose_warning_is_not_below_the_critical_line_is_refused(self):
        self.open_hardware()
        self.page.wait_for_selector("#hw-diskname-form", timeout=15000)
        self.page.fill(self.box(self.sda, "warn"), "60")
        self.page.fill(self.box(self.sda, "crit"), "50")
        self.save()
        self.page.wait_for_selector(".toast.error", timeout=15000)
        self.assertNotIn(self.sda, self.host_overrides().get("drivetemp_per_serial", {}), "nothing was kept")

    def test_the_boxes_are_the_administrators_and_the_colour_is_everyones(self):
        """The route is the host's metric thresholds, which are the administrator's, so a reader with no
        write rights gets no boxes; the lines are in the Hardware answer, so the colour is the same."""
        context, viewer, errors = _sign_in(_STACK["browser"], _STACK["base"], "demo", "demo")
        try:
            self.open_hardware(viewer)
            self.assertEqual(viewer.query_selector("#hw-diskname-form"), None, "a reader gets no boxes")
            self.assertEqual(viewer.query_selector("input[data-line]"), None)
            cls, title, _ = self.temp_cell("/dev/sdb", viewer)
            self.assertIn("c-amber", cls.split())
            self.assertEqual(title, "≥ 45 °C / ≥ 50 °C")
            self.assertEqual(errors, [])
        finally:
            context.close()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheHostsOwnLines(_Page):

    def tearDown(self):
        try:
            self.page.evaluate("closeModal('metric-thresholds-modal')")
        except Exception:
            pass
        # null every line the tests may have set, and leave the drive lines of the demo alone
        self.page.evaluate("async ([id, keys]) => { const b = {}; keys.forEach(k => b[k] = null); "
                           "await api('PATCH', `/devices/${id}/metric-thresholds`, b); }", [HOST, HOST_KEYS])
        super().tearDown()

    def open_box(self):
        self.page.evaluate(f"openMetricThresholds('{HOST}', '{HOST_NAME}')")
        self.page.wait_for_function(
            "() => { const e = document.getElementById('thr-dt-hdd-warn'); return !!e && e.placeholder !== ''; }",
            timeout=15000)

    def save(self):
        self.page.click('#metric-thresholds-modal [data-action="saveMetricThresholds"]')

    def test_the_fleets_lines_are_shown_in_grey_and_the_boxes_start_empty(self):
        self.open_box()
        for stem, want in (("hdd-warn", "45"), ("hdd-crit", "50"), ("ssd-warn", "65"), ("ssd-crit", "70"),
                           ("nvme-warn", "70"), ("nvme-crit", "80"), ("warn", "0"), ("crit", "0")):
            with self.subTest(box=stem):
                self.assertEqual(self.page.get_attribute(f"#thr-dt-{stem}", "placeholder"), want)
                self.assertEqual(self.page.input_value(f"#thr-dt-{stem}"), "")

    def test_a_value_is_saved_and_emptying_the_box_removes_it(self):
        self.open_box()
        self.page.fill("#thr-dt-hdd-warn", "48")
        self.page.fill("#thr-dt-hdd-crit", "53")
        self.save()
        self.page.wait_for_selector(".toast.success", timeout=15000)
        o = self.host_overrides()
        self.assertEqual((o.get("drivetemp_hdd_warn_c"), o.get("drivetemp_hdd_crit_c")), (48, 53))
        self.assertIn("drivetemp_per_serial", o, "the drive lines set on the Hardware tab were not touched")
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")
        self.open_box()
        self.assertEqual(self.page.input_value("#thr-dt-hdd-warn"), "48")
        self.page.fill("#thr-dt-hdd-warn", "")
        self.save()
        self.page.wait_for_selector(".toast.success", timeout=15000)
        o = self.host_overrides()
        self.assertNotIn("drivetemp_hdd_warn_c", o, "an emptied box removes the host's line")
        self.assertEqual(o.get("drivetemp_hdd_crit_c"), 53, "and leaves the other one alone")

    def test_a_pair_the_wrong_way_round_is_refused_and_nothing_is_kept(self):
        self.open_box()
        self.page.fill("#thr-dt-ssd-warn", "70")
        self.page.fill("#thr-dt-ssd-crit", "65")
        self.save()
        self.page.wait_for_function(
            "() => { const e = document.getElementById('metric-thresholds-error'); "
            "return !!e && e.style.display !== 'none' && e.textContent.trim() !== ''; }", timeout=15000)
        o = self.host_overrides()
        self.assertNotIn("drivetemp_ssd_warn_c", o)
        self.assertNotIn("drivetemp_ssd_crit_c", o)

    def test_a_number_outside_one_to_150_is_refused(self):
        self.open_box()
        self.page.fill("#thr-dt-nvme-warn", "151")
        self.save()
        self.page.wait_for_function(
            "() => { const e = document.getElementById('metric-thresholds-error'); "
            "return !!e && e.style.display !== 'none' && e.textContent.trim() !== ''; }", timeout=15000)
        self.assertNotIn("drivetemp_nvme_warn_c", self.host_overrides())


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheFleetLines(_Page):

    IDS = ("hdd-warn", "hdd-crit", "ssd-warn", "ssd-crit", "nvme-warn", "nvme-crit", "warn", "crit")

    def tearDown(self):
        body = dict(SEEDED_FLEET, drivetemp_warn_c=0, drivetemp_crit_c=0)
        self.page.evaluate("async (b) => { await api('POST', '/config', b); }", body)
        super().tearDown()

    def open_pane(self):
        self.page.evaluate("showPage('settings')")
        self.page.wait_for_selector("#settings-tab-btn-alertparams", state="visible", timeout=30000)
        self.page.evaluate("(ids) => ids.forEach(k => { const e = document.getElementById('ap-drivetemp-' + k); "
                           "if (e) e.value = ''; })", list(self.IDS))
        self.page.click("#settings-tab-btn-alertparams")
        self.page.wait_for_function(
            "() => { const e = document.getElementById('ap-drivetemp-hdd-warn'); return !!e && e.value !== ''; }",
            timeout=30000)

    def config(self):
        return self.page.evaluate("async () => { const c = await api('GET', '/config'); "
                                  "return [c.drivetemp_hdd_warn_c, c.drivetemp_hdd_crit_c, c.drivetemp_nvme_warn_c, "
                                  "c.drivetemp_warn_c]; }")

    def save_from(self, ident):
        self.page.click(f"#{ident} >> xpath=ancestor::div[contains(@class,'settings-section')]"
                        "//button[@data-action='saveAlertParams']")

    def test_the_pane_shows_the_eight_values_and_its_title(self):
        self.open_pane()
        got = [self.page.input_value(f"#ap-drivetemp-{k}") for k in self.IDS]
        self.assertEqual(got, ["45", "50", "65", "70", "70", "80", "0", "0"])
        title = self.page.evaluate("() => document.getElementById('ap-drivetemp-hdd-warn').closest('.settings-section')"
                                   ".querySelector('.section-title').innerText.trim()")
        self.assertEqual(title, "Drive temperature")

    def test_a_changed_value_is_saved_and_a_line_for_any_drive_can_be_set(self):
        self.open_pane()
        self.page.fill("#ap-drivetemp-nvme-warn", "72")
        self.page.fill("#ap-drivetemp-warn", "75")
        self.page.fill("#ap-drivetemp-crit", "90")
        self.save_from("ap-drivetemp-nvme-warn")
        self.page.wait_for_selector(".toast.success", timeout=15000)
        self.assertEqual(self.config(), [45, 50, 72, 75])

    def test_a_pair_the_wrong_way_round_is_refused_and_nothing_is_kept(self):
        self.open_pane()
        self.page.fill("#ap-drivetemp-hdd-warn", "60")
        self.save_from("ap-drivetemp-hdd-warn")
        self.page.wait_for_selector(".toast.error", timeout=15000)
        self.assertEqual(self.config(), [45, 50, 70, 0], "nothing was kept")

    def test_a_value_out_of_range_is_refused(self):
        self.open_pane()
        self.page.fill("#ap-drivetemp-hdd-crit", "151")
        self.save_from("ap-drivetemp-hdd-crit")
        self.page.wait_for_selector(".toast.error", timeout=15000)
        self.assertEqual(self.config(), [45, 50, 70, 0])


if __name__ == "__main__":
    unittest.main()
