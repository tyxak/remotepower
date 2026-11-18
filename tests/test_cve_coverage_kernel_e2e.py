#!/usr/bin/env python3
"""The CVE page, in a browser, over the seeded demo: which packages a scan checked, and which kernel a host runs (8.0.2).

The scanner, the readers and the page functions are held in test_cve_package_coverage, test_cve_package_coverage_page,
test_cve_kernel_state and test_cve_kernel_state_page. What those cannot show is the page: that the numbers on the screen are the
numbers of the report, that a click on the sixth tile keeps the hosts that need a reboot, that the line under the tiles names the
hosts with the most packages not checked and each of them opens its view, that a host's view says which kernel it runs, which
packages were not checked and why, that nothing runs past the edge of a narrow screen, that German and Arabic come out (Arabic right
to left), that every new control can be reached from the keyboard and shows where the focus is, and that the page asks the server
for nothing that fails.

The demo seeder wrote its CVE records before a scan stated its packages or its kernel, so six hosts are given the records a scan
writes now. They are made by the scanner itself (`cve_scanner.scan_device`, against the recordings of the advisory data in
tests/data and advisory records written for the kernel), and planted through the product's storage layer (tests/e2e_plant.py):

  * proxmox.lab runs the older of two installed kernels, and one of them holds fixes the running kernel lacks: two findings read
    "reboot to apply", and the host says which kernel runs and which is installed beside it;
  * home-assistant.lab reports a kernel that no installed package owns: the host says it could not tell, and why;
  * opnsense.lab has an agent that sends no source names: two of its three packages were not checked;
  * jellyfin.lab has nothing found in the one package that could be checked: it says so, and does not say it is clean;
  * truenas.lab has nothing found and every package was checked: it says no vulnerabilities, as it always did;
  * design-win11 is a Windows host: its applications are listed and nothing is matched against them;
  * gitea.lab runs the older kernel and has 70 findings that the newer one holds the fix for: 50 are listed, and the 20 that
    the ceiling of a package counts instead say, in the roll-up of its view, that a reboot clears them;
  * pihole.lab was scanned before a scan stated its packages (its record has no such block): the line under the tiles says that
    it does not count such hosts, and how many they are.

Controls come first: the measure of overflow must see a box wider than the screen, the planted records must hold what each case
needs, and the focus ring detector must see a ring taken away. Self-skips without playwright, chromium and gunicorn.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for p in (_HERE, _ROOT / "server" / "cgi-bin"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import browser_required  # noqa: E402
import cve_scanner  # noqa: E402
import e2e_plant  # noqa: E402
import software_inventory as si  # noqa: E402
from osv_recording import BEHIND, DEB, Database, NotRecorded  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}
WIDTHS = (1440, 768, 390)
TILE_KEYS = ["fixable", "reboot", "newer_release", "none", "pro", "unchecked"]

PMX, HA, FW, JF, NAS, WIN, GT, PI = "pmx01", "ha01", "fw01", "jf01", "tnas", "wks01", "gt01", "pi1"
NAMES = {PMX: "proxmox.lab", HA: "home-assistant.lab", FW: "opnsense.lab", JF: "jellyfin.lab", NAS: "truenas.lab",
         WIN: "design-win11", GT: "gitea.lab", PI: "pihole.lab"}


# ── the records a scan writes ────────────────────────────────────────────────────────────────────────────────────────────
OLD, NEW = "6.1.0-40-amd64", "6.1.0-48-amd64"
KERNELS = [{"name": f"linux-image-{OLD}", "version": "6.1.158-1", "arch": "amd64", "source": "linux"},
           {"name": f"linux-image-{NEW}", "version": "6.1.192-1", "arch": "amd64", "source": "linux"},
           {"name": "linux-libc-dev", "version": "6.1.192-1", "arch": "amd64", "source": "linux"}]
OTHERS = [{"name": n, "version": v, "arch": "amd64", "source": n}
          for n, v in (("bash", "5.2.15-2+b7"), ("coreutils", "9.1-1"), ("tzdata", "2024a-0+deb12u1"), ("ca-certificates", "20230311"))]
IMG_OLD = {"name": KERNELS[0]["name"], "version": "6.1.158-1", "release": OLD}
IMG_NEW = {"name": KERNELS[1]["name"], "version": "6.1.192-1", "release": NEW}
BY_NAME = [{"name": p["name"], "version": p["version"], "arch": p["arch"]} for p in BEHIND
           if p["name"] in ("libc6", "openssh-server")] + [{"name": "sudo", "version": "1.9.13p3-1+deb12u1", "arch": "amd64"}]
# the one package of this list whose name is its source, at a version past the fix of its only advisory
PATCHED_BY_NAME = [{"name": "libc6", "version": "2.36-9+deb12u14", "arch": "amd64"},
                   {"name": "openssh-server", "version": "1:9.2p1-2+deb12u10", "arch": "amd64"},
                   {"name": "sudo", "version": "1.9.13p3-1+deb12u9", "arch": "amd64"},
                   {"name": "zlib1g", "version": "1:1.2.13.dfsg-1+b1", "arch": "amd64"}]


def _advisory(vid, fixed, urgency="high", package="linux"):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"id": vid, "details": "a flaw in " + package, "upstream": [vid.replace("DEBIAN-", "")],
            "modified": "2026-11-10T08:00:00.123456789Z", "database_specific": {"severity": urgency},
            "affected": [{"package": {"ecosystem": "Debian:12", "name": package},
                          "ranges": [{"type": "ECOSYSTEM", "events": events}], "ecosystem_specific": {"urgency": urgency}}]}


A, B, C, D, E, S = ("DEBIAN-CVE-2099-000%d" % i for i in (1, 2, 3, 4, 5, 6))
RECORDS = {A: _advisory(A, "6.1.192-1"), B: _advisory(B, "6.1.200-1"), C: _advisory(C, ""),
           D: _advisory(D, "6.1.192-1", "medium"), E: _advisory(E, "", "medium"),
           S: _advisory(S, "1.9.13p3-1+deb12u9", package="sudo")}
ANSWERS = {("Debian:12", "linux", "6.1.158-1"): [A, B, C, D, E], ("Debian:12", "linux", "6.1.192-1"): [B, C, E],
           ("Debian:12", "sudo", "1.9.13p3-1+deb12u9"): [S]}


# 70 medium findings of the kernel, each fixed in the version the newer installed kernel is at: a scan lists a reboot finding
# beside the ones an update clears, up to 50 for a package (cve_fixes.KEEP_PER_PACKAGE), and counts the rest
MANY = ["DEBIAN-CVE-2099-%04d" % (1000 + i) for i in range(70)]
MANY_RECORDS = {vid: _advisory(vid, "6.1.192-1", "medium") for vid in MANY}
MANY_ANSWERS = {("Debian:12", "linux", "6.1.158-1"): MANY, ("Debian:12", "linux", "6.1.192-1"): []}


class _Lenient(Database):
    """An answer of nothing for a package the recording never held, which is what a package with no advisory is answered."""

    def querybatch(self, body):
        out = []
        for q in body:
            try:
                out.extend(super().querybatch([q]))
            except NotRecorded:
                out.append({"vulns": []})
        return out


def _scan(packages, kernel=None, has_meta=True, answers=None, records=None):
    db = _Lenient(DEB, extra=ANSWERS if answers is None else answers, records=RECORDS if records is None else records)
    cache = Path(tempfile.mkdtemp(prefix="rp-covker-scan-"))
    try:
        with mock.patch.object(cve_scanner, "_osv_querybatch", db.querybatch), \
                mock.patch.object(cve_scanner, "_osv_vuln_details", db.details), \
                mock.patch.object(cve_scanner, "_debian_severity_fallback", lambda cve: None):
            result = cve_scanner.scan_device("h", packages, "Debian:12", cache, has_meta=has_meta, kernel=kernel)
    finally:
        shutil.rmtree(cache, ignore_errors=True)
    assert "error" not in result, result.get("error")
    return result


def _entry(packages, kernel=None, has_meta=True, manager="apt"):
    out = {"hash": "e2e", "collected_at": int(time.time()), "ecosystem": "Debian:12" if manager == "apt" else "",
           "pkg_manager": manager, "count": len(packages), "packages": packages,
           "os_id": "debian" if manager == "apt" else "", "version_id": "12" if manager == "apt" else ""}
    if has_meta and manager == "apt":
        out["sources"] = True
    if kernel:
        out["kernel"] = kernel
    return out


WINDOWS_ROWS = [{"name": f"Program {i}", "version": f"{i}.0", "publisher": "Acme Ltd", "arch": "x64"} for i in range(1, 9)]


def scenario():
    """{host: (the entry of packages.json, the record of cve_findings.json or None)}: what the scanner writes for each case."""
    running = {"release": OLD, "images": [IMG_OLD, IMG_NEW]}
    no_owner = {"release": "6.1.0-99-custom", "images": [IMG_OLD, IMG_NEW]}
    out = {}
    for host, kernel in ((PMX, running), (HA, no_owner)):
        packages = KERNELS + OTHERS
        out[host] = (_entry(packages, kernel), _scan(packages, kernel))
    out[FW] = (_entry(BY_NAME, has_meta=False), _scan(BY_NAME, has_meta=False))
    out[JF] = (_entry(PATCHED_BY_NAME, has_meta=False), _scan(PATCHED_BY_NAME, has_meta=False))
    clean = OTHERS[:3]
    out[NAS] = (_entry(clean), _scan(clean))
    out[WIN] = (_entry(si.clean_list(WINDOWS_ROWS, "windows"), manager="windows"), None)
    packages = KERNELS + OTHERS
    out[GT] = (_entry(packages, running), _scan(packages, running, answers=MANY_ANSWERS, records=MANY_RECORDS))
    # a scan from before the account of what was checked and the kernel it ran: the record has neither
    old = _scan(OTHERS[:2])
    old.pop("covered")
    old.pop("kernel", None)
    out[PI] = (_entry(OTHERS[:2]), old)
    return out


def _plant(data_dir, hosts):
    findings = e2e_plant.load(data_dir, "CVE_FINDINGS_FILE")
    packages = e2e_plant.load(data_dir, "PACKAGES_FILE")
    for host, (entry, record) in hosts.items():
        packages[host] = entry
        if record is None:
            findings.pop(host, None)
        else:
            findings[host] = record
    e2e_plant.save(data_dir, "CVE_FINDINGS_FILE", findings)
    e2e_plant.save(data_dir, "PACKAGES_FILE", packages)


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-covker-e2e-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    hosts = scenario()
    _plant(data_dir, hosts)
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
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    problems = {"console": [], "page": [], "failed": []}
    page.goto(base + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    page.on("console", lambda m: problems["console"].append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: problems["page"].append(str(e)))
    page.on("response", lambda r: problems["failed"].append(f"{r.status} {r.url}") if r.status >= 400 else None)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, problems=problems, data_dir=data_dir,
                  hosts=hosts)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()
        shutil.rmtree(_STACK["data_dir"], ignore_errors=True)


OVERFLOW = """modalId => {
  const d = document.documentElement;
  const out = {page: d.scrollWidth - window.innerWidth, dir: d.dir || document.body.dir || ''};
  if (modalId) {
    const modal = document.querySelector('#' + modalId + '.active .modal');
    out.modal = modal ? modal.scrollWidth - modal.clientWidth : null;      // null: the dialog is not open, and nothing was measured
  }
  return out;
}"""

# Where a focused control shows its ring: an outline or a shadow, and :focus-visible says the browser drew it for a keyboard.
RING = """sel => {
  const el = document.querySelector(sel);
  if (!el) return null;
  el.scrollIntoView({block: 'nearest'});
  el.focus();
  const cs = getComputedStyle(el);
  return {found: true, active: document.activeElement === el, visible: el.matches(':focus-visible'), outline: cs.outlineStyle,
          width: parseFloat(cs.outlineWidth) || 0, shadow: cs.boxShadow, tab: el.tabIndex, tag: el.tagName.toLowerCase()};
}"""


def shows_a_ring(got):
    return bool(got and got["active"] and got["visible"] and ((got["outline"] != "none" and got["width"] > 0) or got["shadow"] != "none"))


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Page(unittest.TestCase):
    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        _STACK["problems"].update(console=[], page=[], failed=[])
        self.page.set_viewport_size({"width": 1440, "height": 900})
        self.page.evaluate("() => { if (window.RPi18n) RPi18n.setLang('en', false); cveFixFilter = ''; }")

    def tearDown(self):
        try:
            self.page.evaluate("() => { try { closeModal('cve-detail-modal'); } catch (e) {} try { closeDeviceDrawer(); } catch (e) {} }")
        except Exception:
            pass
        problems = _STACK["problems"]
        self.assertEqual(problems["page"], [], "the page threw")
        self.assertEqual(problems["console"], [], "the console reported an error")
        failed = [f for f in problems["failed"] if "/api/" in f]
        self.assertEqual(failed, [], "a request failed")

    # ── the page ──
    def set_language(self, lang):
        """The dictionary is fetched when a language other than English is asked for; wait for it."""
        self.page.evaluate("async l => { const i = await _ensureI18n(); i.setLang(l, false); }", lang)
        self.page.wait_for_timeout(800)

    def report(self):
        return self.page.evaluate("async () => await api('GET', '/cve/findings')")

    def open_cve(self):
        self.page.evaluate("showPage('cve')")
        self.page.wait_for_function(
            "() => document.querySelectorAll('#cve-tbody tr td').length > 4 && !document.querySelector('#cve-tbody .skeleton')"
            " && !document.getElementById('cve-covered-note').hidden", timeout=60000)
        # a tile counts up from 0 the first time it is shown (statTiles): wait for the numbers of the report
        fix = self.report()["summary"]["fix"]
        try:
            self.page.wait_for_function(
                "fix => Object.entries(fix).every(([k, n]) => parseInt(document.getElementById('cve-fix-' + k).textContent) === n)",
                arg=fix, timeout=10000)
        except Exception:
            pass          # the comparison in the test says which tile differs

    def open_host(self, host):
        self.page.evaluate("([id, name]) => openDeviceCVE(id, name)", [host, NAMES[host]])
        self.page.wait_for_function(
            "() => { const b = document.getElementById('cve-detail-body'); return b && b.querySelector('.sysinfo-row') && !b.querySelector('.skeleton'); }",
            timeout=30000)
        self.page.wait_for_timeout(300)

    def fits(self, label, modal_id=None):
        """No horizontal overflow at the three widths, of the page and, when a dialog is open, of the dialog."""
        for width in WIDTHS:
            self.page.set_viewport_size({"width": width, "height": 900})
            self.page.wait_for_timeout(250)
            got = self.page.evaluate(OVERFLOW, modal_id)
            self.assertLessEqual(got["page"], 1, f"{label} at {width}px runs {got['page']}px past the edge")
            if modal_id:
                self.assertIsNotNone(got["modal"], f"{label}: the dialog {modal_id} was not open to measure")
                self.assertLessEqual(got["modal"], 1, f"{label} (dialog) at {width}px")
        self.page.set_viewport_size({"width": 1440, "height": 900})

    def tiles(self):
        return self.page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('#cve-fix-row .stat-card')].map(el =>
            [el.dataset.arg, {n: parseInt(el.querySelector('.stat-value').textContent), on: el.getAttribute('aria-pressed'),
                              label: el.querySelector('.stat-label').textContent.trim()}]))""")

    def hosts_shown(self):
        return self.page.evaluate("() => [...document.querySelectorAll('#cve-tbody tr td.fw-500')].map(td => td.textContent.trim())")

    def body(self):
        return self.page.evaluate("() => document.getElementById('cve-detail-body').innerText")

    def note(self):
        return self.page.evaluate("() => document.getElementById('cve-covered-note').innerText")


class TestTheControls(_Page):
    def test_a_box_wider_than_the_screen_is_seen_by_the_measure(self):
        """A measure that cannot see overflow would pass every page below it."""
        self.page.evaluate("showPage('cve')")
        self.page.evaluate("""() => { const d = document.createElement('div'); d.id = 'e2e-wide'; d.textContent = 'wide';
            d.style.cssText = 'position:absolute;left:0;top:0;width:3000px;height:4px'; document.body.appendChild(d); }""")
        try:
            self.page.set_viewport_size({"width": 390, "height": 900})
            self.page.wait_for_timeout(250)
            self.assertGreater(self.page.evaluate(OVERFLOW, None)["page"], 1000)
        finally:
            self.page.evaluate("() => { const d = document.getElementById('e2e-wide'); if (d) d.remove(); }")
        self.assertLessEqual(self.page.evaluate(OVERFLOW, None)["page"], 1)

    def test_the_planted_records_hold_what_each_case_needs(self):
        """The cases below read what the scanner wrote. A record that lacks the thing a case looks at would make that case pass by
        having nothing to show."""
        hosts = _STACK["hosts"]
        pmx = hosts[PMX][1]
        self.assertEqual(pmx["kernel"]["state"], "matched")
        self.assertEqual(pmx["kernel"]["running"], OLD)
        self.assertEqual(pmx["kernel"]["newer"], f"linux-image-{NEW} 6.1.192-1")
        self.assertGreater(pmx["kernel"]["left_out"], 0)
        self.assertEqual(sorted(f["vuln_id"] for f in pmx["findings"] if f["fix_status"] == "reboot"), [A, D])
        self.assertTrue(all(f["reboot_to"] == f"linux-image-{NEW} 6.1.192-1" for f in pmx["findings"] if f["fix_status"] == "reboot"))
        self.assertEqual(pmx["covered"]["not_checked"], 0)
        self.assertEqual(hosts[HA][1]["kernel"]["state"], "unknown")
        self.assertEqual(hosts[HA][1]["kernel"]["why"], "no_owner")
        self.assertFalse(any(f["fix_status"] == "reboot" for f in hosts[HA][1]["findings"]))
        fw = hosts[FW][1]["covered"]
        self.assertEqual((fw["listed"], fw["checked"], fw["not_checked"], fw["reasons"]), (3, 1, 2, {"no_source": 2}))
        jf = hosts[JF][1]
        self.assertEqual(jf["findings"], [])
        self.assertNotIn("rollup", jf)
        self.assertEqual((jf["covered"]["checked"], jf["covered"]["not_checked"]), (1, 3))
        nas = hosts[NAS][1]
        self.assertEqual((nas["findings"], nas["covered"]["not_checked"]), ([], 0))
        self.assertGreater(nas["covered"]["checked"], 0)
        self.assertIsNone(hosts[WIN][1])
        gt = hosts[GT][1]
        self.assertEqual((len(gt["findings"]), {f["fix_status"] for f in gt["findings"]}), (50, {"reboot"}))
        self.assertEqual(gt["rollup"]["fix"], {"reboot": 20})
        pi = hosts[PI][1]
        self.assertNotIn("covered", pi)
        self.assertNotIn("kernel", pi)

    def test_the_ring_detector_sees_a_ring_taken_away(self):
        self.open_cve()
        self.page.keyboard.press("Tab")                 # a key first, so that a script's focus() counts as the keyboard's for :focus-visible
        self.assertTrue(shows_a_ring(self.page.evaluate(RING, '#cve-fix-row [data-arg="fixable"]')))
        self.page.evaluate("""() => { const s = document.createElement('style'); s.id = 'e2e-no-ring';
            s.textContent = '*,*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}'; document.head.appendChild(s); }""")
        try:
            self.assertFalse(shows_a_ring(self.page.evaluate(RING, '#cve-fix-row [data-arg="fixable"]')))
        finally:
            self.page.evaluate("() => { const s = document.getElementById('e2e-no-ring'); if (s) s.remove(); }")


class TestTheTiles(_Page):
    def test_there_are_six_and_the_second_counts_what_a_reboot_applies(self):
        self.open_cve()
        got = self.tiles()
        self.assertEqual(list(got), TILE_KEYS)
        self.assertEqual(got["reboot"]["label"], "Reboot to apply")
        fix = self.report()["summary"]["fix"]
        self.assertEqual({k: v["n"] for k, v in got.items()}, fix)
        # the two findings of proxmox.lab that the newer kernel holds the fix for, and the 50 that gitea.lab lists
        self.assertEqual(fix["reboot"], 2 + len(_STACK["hosts"][GT][1]["findings"]))
        self.assertEqual({v["on"] for v in got.values()}, {"false"})
        # the grid of the row was written for five tiles: the sixth must not stand alone on a second row of a wide screen
        tops = self.page.evaluate("() => [...document.querySelectorAll('#cve-fix-row .stat-card')].map(el => Math.round(el.getBoundingClientRect().top))")
        self.assertEqual(len(tops), 6)
        self.assertLess(max(tops) - min(tops), 10, "the six tiles are not in one row at 1440 px: %r" % tops)      # a tone border moves one by 2 px

    def test_a_click_keeps_the_host_that_needs_a_reboot_and_a_second_click_brings_the_rest_back(self):
        self.open_cve()
        every = self.hosts_shown()
        self.assertGreater(len(every), 2)
        self.page.locator('#cve-fix-row [data-arg="reboot"]').click()
        self.assertEqual(self.tiles()["reboot"]["on"], "true")
        self.assertEqual(sorted(self.hosts_shown()), sorted([NAMES[PMX], NAMES[GT]]))
        self.page.locator('#cve-fix-row [data-arg="reboot"]').click()
        self.assertEqual(self.tiles()["reboot"]["on"], "false")
        self.assertEqual(self.hosts_shown(), every)

    def test_the_filter_follows_into_the_host_view_and_lists_the_two_findings(self):
        self.open_cve()
        self.page.locator('#cve-fix-row [data-arg="reboot"]').click()
        self.open_host(PMX)
        self.assertEqual(self.page.locator("#cve-detail-body .isl-390").count(), 2)
        self.assertIn("2 / ", self.body())


class TestTheNoteUnderTheTiles(_Page):
    def test_it_gives_the_total_the_reasons_and_the_hosts_with_the_most_not_checked(self):
        self.open_cve()
        covered = self.report()["summary"]["covered"]
        hosts = _STACK["hosts"]
        listed = sum(len(hosts[h][0]["packages"]) for h in (WIN,)) + sum(hosts[h][1]["covered"]["listed"] for h in (PMX, HA, FW, JF, NAS, GT))
        self.assertEqual(covered["listed"], listed, "the report sums the planted hosts and no other")
        self.assertEqual(covered["not_checked"], 8 + 2 + 3)
        self.assertEqual(covered["reasons"], {"no_matcher": 8, "no_source": 5})
        shown = self.page.evaluate("""() => ({total: document.getElementById('cve-covered-total').textContent,
            missed: document.getElementById('cve-covered-missed').textContent,
            reasons: document.getElementById('cve-covered-reasons').innerText,
            hosts: [...document.querySelectorAll('#cve-covered-hosts button')].map(b => b.innerText.replace(/\\s+/g, ' ').trim())})""")
        self.assertEqual(shown["total"], f"{covered['checked']} / {covered['listed']}")
        self.assertEqual(shown["missed"], "13")
        self.assertIn("No matcher for the package manager", shown["reasons"])
        self.assertIn("No source name", shown["reasons"])
        self.assertEqual(shown["hosts"], [f"{NAMES[WIN]} 8 / 8", f"{NAMES[JF]} 3 / 4", f"{NAMES[FW]} 2 / 3"])

    def test_a_host_in_it_opens_the_view_of_that_host(self):
        self.open_cve()
        self.page.locator("#cve-covered-hosts button", has_text=NAMES[JF]).click()
        self.page.wait_for_function(
            "() => { const b = document.getElementById('cve-detail-body'); return b && b.querySelector('[data-cve-covered]'); }", timeout=30000)
        self.assertIn(NAMES[JF], self.page.evaluate("() => document.getElementById('cve-detail-title').textContent"))

    def test_every_control_in_it_has_a_name_and_the_page_gains_no_button_that_is_only_an_icon(self):
        self.open_cve()
        buttons = self.page.evaluate("""() => [...document.querySelectorAll('#cve-covered-note button')].map(b => ({text: b.innerText.trim(),
            icon: !!b.querySelector('svg'), cls: b.className}))""")
        self.assertEqual(len(buttons), 3)
        for b in buttons:
            self.assertTrue(b["text"], b)                       # each is a name and two numbers, not a bare icon
            self.assertIn("btn-icon", b["cls"])


class TestTheKernelOfAHost(_Page):
    def test_a_host_that_runs_the_older_of_two_kernels_says_which_and_which_is_installed_beside_it(self):
        self.open_cve()
        self.open_host(PMX)
        line = self.page.evaluate("() => { const e = document.querySelector('#cve-detail-body [data-cve-kernel]'); return e ? {kind: e.dataset.cveKernel, text: e.innerText.replace(/\\s+/g, ' ').trim()} : null; }")
        self.assertIsNotNone(line)
        self.assertEqual(line["kind"], "matched")
        self.assertIn(f"Running kernel: {OLD}", line["text"])
        self.assertIn("Package: linux-image-6.1.0-40-amd64 6.1.158-1", line["text"])
        self.assertIn(f"Installed, not running: linux-image-{NEW} 6.1.192-1 Reboot to start it.", line["text"])
        self.assertIn("Packages of other installed kernels, not counted: 2", line["text"])

    def test_a_finding_that_the_installed_kernel_clears_says_reboot_names_it_and_offers_no_version_to_install(self):
        self.open_cve()
        self.open_host(PMX)
        rows = self.page.evaluate("""() => [...document.querySelectorAll('#cve-detail-body .isl-390')].map(r => ({
            id: (r.querySelector('code') || {}).textContent, text: r.innerText.replace(/\\s+/g, ' ').trim()}))""")
        by_id = {r["id"]: r["text"] for r in rows}
        for vid in (A, D):
            self.assertIn("Fixed by an installed kernel, reboot to apply", by_id[vid], vid)
            self.assertIn(f"linux-image-{NEW} 6.1.192-1", by_id[vid], vid)
            self.assertNotIn("fixed in", by_id[vid], vid)
        self.assertIn("fixed in 6.1.200-1", by_id[B])           # a fix the installed kernel lacks is still an update to install
        self.assertNotIn("reboot", by_id[B].lower())
        self.assertIn("No fix yet", by_id[C])

    def test_a_host_whose_kernel_no_installed_package_owns_says_it_could_not_tell_and_why(self):
        self.open_cve()
        self.open_host(HA)
        line = self.page.evaluate("() => { const e = document.querySelector('#cve-detail-body [data-cve-kernel]'); return e ? {kind: e.dataset.cveKernel, text: e.innerText.replace(/\\s+/g, ' ').trim()} : null; }")
        self.assertIsNotNone(line)
        self.assertEqual(line["kind"], "unknown")
        self.assertIn("Running kernel: 6.1.0-99-custom", line["text"])
        self.assertIn("It could not be matched to an installed package, so findings against the kernel are matched against every installed kernel.", line["text"])
        self.assertIn("No installed kernel package owns the files of the running kernel.", line["text"])
        self.assertNotIn("Fixed by an installed kernel", self.body())

    def test_a_host_with_no_kernel_in_its_list_says_nothing_of_one(self):
        self.open_cve()
        self.open_host(FW)
        self.assertEqual(self.page.locator("#cve-detail-body [data-cve-kernel]").count(), 0)


class TestThePackagesThatWereChecked(_Page):
    def test_a_host_says_how_many_of_its_packages_were_checked_and_opens_to_the_reasons_and_the_first_rows(self):
        self.open_cve()
        self.open_host(FW)
        block = self.page.locator("#cve-detail-body details[data-cve-covered]")
        self.assertEqual(block.count(), 1)
        self.assertEqual(self.page.evaluate("() => document.querySelector('#cve-detail-body details[data-cve-covered]').open"), False)
        summary = self.page.evaluate("() => document.querySelector('#cve-detail-body details[data-cve-covered] summary').innerText.replace(/\\s+/g, ' ').trim()")
        self.assertEqual(summary, "Packages checked: 1 / 3 · Not checked: 2")
        block.locator("summary").click()
        self.assertTrue(self.page.evaluate("() => document.querySelector('#cve-detail-body details[data-cve-covered]').open"))
        tables = self.page.evaluate("""() => [...document.querySelectorAll('#cve-detail-body details[data-cve-covered] table')].map(t =>
            [...t.rows].map(r => [...r.cells].map(c => c.textContent.trim())))""")      # textContent: the style sheet sets a heading in capitals
        self.assertEqual(tables[0], [["Reason", "Count"], ["No source name", "2"]])
        self.assertEqual(tables[1], [["Package", "Installed", "Reason"], ["libc6", "2.36-9+deb12u3", "No source name"],
                                     ["openssh-server", "1:9.2p1-2+deb12u2", "No source name"]])

    def test_a_host_with_nothing_found_in_the_one_package_that_could_be_checked_does_not_say_it_is_clean(self):
        self.open_cve()
        self.open_host(JF)
        body = self.body()
        self.assertIn("None found in the packages that could be checked: 1", body)
        self.assertNotIn("No vulnerabilities found", body)
        self.assertIn("Packages checked: 1 / 4 · Not checked: 3", body)

    def test_a_host_with_every_package_checked_and_nothing_found_says_no_vulnerabilities(self):
        self.open_cve()
        self.open_host(NAS)
        body = self.body()
        self.assertIn("No vulnerabilities found.", body)
        self.assertNotIn("None found in the packages that could be checked", body)
        self.assertEqual(self.page.locator("#cve-detail-body details[data-cve-covered]").count(), 0)      # nothing to open: all were checked
        self.assertRegex(body, r"Packages checked: 3 / 3")

    def test_the_list_of_a_windows_host_is_not_checked_at_all_and_says_so(self):
        self.open_cve()
        self.open_host(WIN)
        body = self.body()
        self.assertNotIn("No vulnerabilities found", body)
        self.assertIn("Packages checked: 0 / 8 · Not checked: 8", body)

    def test_the_host_drawer_reads_none_found_and_not_clean(self):
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [JF, NAMES[JF]])
        self.page.wait_for_selector("#audit-sec-cve", timeout=30000)
        self.page.evaluate("() => { const d = document.getElementById('audit-sec-cve'); d.open = true; }")
        self.page.wait_for_function("() => document.getElementById('audit-badge-cve').textContent === 'none found'", timeout=30000)
        body = self.page.evaluate("() => document.getElementById('audit-body-cve').innerText")
        self.assertIn("None found in the packages that could be checked: 1", body)
        self.assertIn("Packages not checked: 3", body)
        self.assertNotIn("No CVEs found", body)


class TestTheCountedRestOfAHostThatRunsAnOlderKernel(_Page):
    """gitea.lab lists 50 findings the newer installed kernel holds the fix for and counts 20 more: the roll-up of its view says
    that a reboot clears those too."""
    LINE = "Of these, fixed by an installed kernel, reboot to apply:"

    def rollup(self):
        return self.page.evaluate("""() => { const d = document.querySelector('#cve-detail-body details[data-cve-rollup]');
            return d ? {open: d.open, lines: [...d.querySelectorAll('div.hint')].map(e => e.innerText.replace(/\\s+/g, ' ').trim())} : null; }""")

    def test_the_view_says_that_a_reboot_clears_the_counted_rest(self):
        self.open_cve()
        self.open_host(GT)
        self.page.locator("#cve-detail-body details[data-cve-rollup] summary").click()
        got = self.rollup()
        self.assertIsNotNone(got)
        self.assertTrue(got["open"])
        self.assertEqual(got["lines"], [f"{self.LINE} 20"])
        self.fits("the roll-up of gitea.lab, opened", "cve-detail-modal")

    def test_the_line_comes_out_in_german_and_in_arabic_and_fits(self):
        from test_v710_i18n_glue import dict_rows
        row = dict_rows()[self.LINE]
        self.open_cve()
        for lang in ("de", "ar"):
            self.assertTrue(row[lang] and row[lang] != self.LINE, lang)
            self.set_language(lang)
            self.open_host(GT)
            self.page.locator("#cve-detail-body details[data-cve-rollup] summary").click()
            self.assertEqual(self.rollup()["lines"], [f"{row[lang]} 20"], lang)
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.fits(f"the roll-up of gitea.lab in {lang}", "cve-detail-modal")
            self.page.evaluate("() => closeModal('cve-detail-modal')")
        self.set_language("en")


class TestTheHostsTheNoteDoesNotCount(_Page):
    """pihole.lab was scanned before a scan stated its packages. It is in neither number of the note, and an upgrade starts no
    scan, so the note says how many scanned hosts it leaves out."""
    SENTENCE = "Hosts scanned before the upgrade, not counted until they are scanned again:"

    def shown(self):
        return self.page.evaluate("""() => { const e = document.getElementById('cve-covered-unstated');
            return {hidden: e.hidden, n: document.getElementById('cve-covered-unstated-n').textContent.trim(),
                    text: e.innerText.replace(/\\s+/g, ' ').trim(), line: !document.getElementById('cve-covered-line').hidden}; }""")

    def test_the_note_says_how_many_scanned_hosts_it_does_not_count(self):
        self.open_cve()
        unstated = self.report()["summary"]["covered"]["hosts_unstated"]
        self.assertGreaterEqual(unstated, 1)               # the control: the planted record of pihole.lab, and the demo's own
        got = self.shown()
        self.assertFalse(got["hidden"])
        self.assertTrue(got["line"])                       # the totals of the hosts that state theirs are still there
        self.assertEqual(got["n"], f"{unstated:,}".replace(",", ""))
        self.assertEqual(got["text"], f"{self.SENTENCE} {got['n']}")

    def test_it_fits_at_the_three_widths_and_comes_out_in_german_and_in_arabic(self):
        from test_v710_i18n_glue import dict_rows
        row = dict_rows()[self.SENTENCE]
        self.open_cve()
        self.fits("the note under the tiles")
        for lang in ("de", "ar"):
            self.assertTrue(row[lang] and row[lang] != self.SENTENCE, lang)
            self.set_language(lang)
            got = self.shown()
            self.assertIn(row[lang], got["text"], lang)
            self.assertNotIn(self.SENTENCE, self.note(), lang)
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.fits(f"the note under the tiles in {lang}")
        self.set_language("en")


class TestFromTheKeyboard(_Page):
    def ring(self, selector):
        self.page.keyboard.press("Tab")                 # a key first, so that a script's focus() counts as the keyboard's for :focus-visible
        got = self.page.evaluate(RING, selector)
        self.assertIsNotNone(got, selector)
        return got

    def test_the_tile_the_summary_and_the_host_buttons_take_focus_from_the_keyboard_and_show_a_ring(self):
        self.open_cve()
        got = self.ring('#cve-fix-row [data-arg="reboot"]')
        self.assertGreaterEqual(got["tab"], 0, got)
        self.assertTrue(shows_a_ring(got), got)
        got = self.ring("#cve-covered-hosts button")
        self.assertTrue(shows_a_ring(got), got)
        self.open_host(FW)
        got = self.ring("#cve-detail-body details[data-cve-covered] summary")
        self.assertTrue(shows_a_ring(got), got)

    def test_enter_on_the_tile_filters_and_enter_on_the_summary_opens_the_rows(self):
        self.open_cve()
        self.ring('#cve-fix-row [data-arg="reboot"]')
        self.page.keyboard.press("Enter")
        self.page.wait_for_function("() => document.querySelector('#cve-fix-row [data-arg=\"reboot\"]').getAttribute('aria-pressed') === 'true'", timeout=10000)
        self.assertEqual(sorted(self.hosts_shown()), sorted([NAMES[PMX], NAMES[GT]]))
        self.page.keyboard.press("Enter")
        self.page.wait_for_function("() => document.querySelector('#cve-fix-row [data-arg=\"reboot\"]').getAttribute('aria-pressed') === 'false'", timeout=10000)
        self.open_host(FW)
        self.ring("#cve-detail-body details[data-cve-covered] summary")
        self.page.keyboard.press("Enter")
        self.assertTrue(self.page.evaluate("() => document.querySelector('#cve-detail-body details[data-cve-covered]').open"))


class TestInOtherLanguages(_Page):
    def rows(self, *texts):
        """The dictionary rows of these English texts. Each has a text in German and Arabic that is not the English one: a row
        that only repeats it would make the comparison with the page pass whatever the page shows."""
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        for t in texts:
            self.assertTrue(rows.get(t), t)
            for lang in ("de", "ar"):
                self.assertTrue(rows[t].get(lang) and rows[t][lang] != t, (t, lang))
        return {t: rows[t] for t in texts}

    def test_the_tile_the_note_and_the_page_come_out_in_german_and_in_arabic_and_fit(self):
        words = self.rows("Reboot to apply", "Packages checked:", "Not checked:", "No source name", "No matcher for the package manager",
                          "Most not checked:")
        self.open_cve()
        for lang in ("de", "ar"):
            self.set_language(lang)
            self.assertEqual(self.tiles()["reboot"]["label"], words["Reboot to apply"][lang], lang)
            note = self.note()
            for text in ("Packages checked:", "Not checked:", "No source name", "No matcher for the package manager", "Most not checked:"):
                self.assertIn(words[text][lang], note, (lang, text))
                if lang == "de":
                    self.assertNotIn(text, note, (lang, text))
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.fits(f"the CVE page in {lang}")
        self.set_language("en")
        self.assertEqual(self.tiles()["reboot"]["label"], "Reboot to apply")

    def test_the_views_of_the_hosts_come_out_in_german_and_in_arabic_and_fit(self):
        words = self.rows("Running kernel:", "Package:", "Installed, not running:", "Reboot to start it.",
                          "Packages of other installed kernels, not counted:", "Fixed by an installed kernel, reboot to apply",
                          "It could not be matched to an installed package, so findings against the kernel are matched against every installed kernel.",
                          "No installed kernel package owns the files of the running kernel.",
                          "Packages checked:", "None found in the packages that could be checked:")
        self.open_cve()
        for lang in ("de", "ar"):
            self.set_language(lang)
            self.open_host(PMX)
            line = self.page.evaluate("() => document.querySelector('#cve-detail-body [data-cve-kernel]').innerText")
            for text in ("Running kernel:", "Package:", "Installed, not running:", "Reboot to start it.",
                         "Packages of other installed kernels, not counted:"):
                self.assertIn(words[text][lang], line, (lang, text))
            self.assertIn(words["Fixed by an installed kernel, reboot to apply"][lang], self.body(), lang)
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.fits(f"the view of {NAMES[PMX]} in {lang}", "cve-detail-modal")
            self.page.evaluate("() => closeModal('cve-detail-modal')")
            self.open_host(HA)
            line = self.page.evaluate("() => document.querySelector('#cve-detail-body [data-cve-kernel]').innerText")
            self.assertIn(words["It could not be matched to an installed package, so findings against the kernel are matched against every installed kernel."][lang], line, lang)
            self.assertIn(words["No installed kernel package owns the files of the running kernel."][lang], line, lang)
            self.fits(f"the view of {NAMES[HA]} in {lang}", "cve-detail-modal")
            self.page.evaluate("() => closeModal('cve-detail-modal')")
            self.open_host(JF)
            self.assertIn(words["None found in the packages that could be checked:"][lang], self.body(), lang)
            self.assertIn(words["Packages checked:"][lang], self.body(), lang)
            self.page.locator("#cve-detail-body details[data-cve-covered] summary").click()
            self.fits(f"the view of {NAMES[JF]} in {lang}, opened", "cve-detail-modal")
            self.page.evaluate("() => closeModal('cve-detail-modal')")
        self.set_language("en")

    def test_the_views_fit_in_english_with_the_rows_open(self):
        self.open_cve()
        for host in (PMX, HA, FW, JF, WIN):
            self.open_host(host)
            summary = self.page.locator("#cve-detail-body details[data-cve-covered] summary")
            if summary.count():
                summary.click()
            self.fits(f"the view of {NAMES[host]}", "cve-detail-modal")
            self.page.evaluate("() => closeModal('cve-detail-modal')")
        self.fits("the CVE page")


if __name__ == "__main__":
    unittest.main()
