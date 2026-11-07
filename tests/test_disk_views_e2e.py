"""The three disk views, in a browser, over a host that reports what a btrfs machine really reports.

Monitor -> Host metrics, Trends and the Disk I/O table of a host's hardware section all showed the disk figures
of every mount point. A btrfs volume under seven mount points (/, /home, /var/log, ...) put the same percentage
in seven places and the same line seven times on the chart, so the disk figures looked as if they never moved.

The seeded demo has no such host, so this test patches one into the demo's data directory before the stack
starts: the host gt01 reports the mount list the real agent returned on a btrfs machine (see test_disk_mounts),
the history of those mounts, and the disk I/O samples the agent sends with its system information.
Self-skips without playwright/chromium/gunicorn.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for p in (_HERE, _ROOT / "server" / "cgi-bin"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import browser_required  # noqa: E402
import disk_mounts  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}
HOST, NAME = "gt01", "gitea.lab"
CHROME = "/run/user/1000/psd/jaove-google-chrome"


def mount(path, percent, used, total, fstype="btrfs", **extra):
    return dict({"path": path, "percent": percent, "used_gb": used, "total_gb": total, "fstype": fstype}, **extra)


REAL = [
    mount("/", 49.7, 454.35, 927.4),
    mount("/data", 67.6, 12079.89, 17871.35, "cifs", network=True, server="10.0.0.5:/data"),
    mount("/boot", 23.5, 0.96, 4.09, "vfat"),
    mount("/home", 49.7, 454.35, 927.4),
    mount("/root", 49.7, 454.35, 927.4),
    mount("/run/user/1000/doc", 0.0, 0.0, 0.0, "fuse.portal"),
    mount("/run/user/1000/psd/jaove-firefox-snkiqd2t.default-release", 4.1, 0.26, 6.26, "fuse.fuse-overlayfs"),
    mount(CHROME, 4.1, 0.26, 6.26, "fuse.fuse-overlayfs"),
    mount("/srv", 49.7, 454.35, 927.4),
    mount("/var/cache", 49.7, 454.35, 927.4),
    mount("/var/log", 49.7, 454.35, 927.4),
    mount("/var/tmp", 49.7, 454.35, 927.4),
]
DISK_IO = [{"dev": "nvme0n1", "busy_pct": 0.6, "read_mbs": 0.02, "write_mbs": 0.4, "riops": 1.0, "wiops": 3.7, "await_ms": 0.3},
           {"dev": "sda", "busy_pct": 0.0, "read_mbs": 0.0, "write_mbs": 0.0, "riops": 0.0, "wiops": 0.0, "await_ms": 0.0}]


def patch_the_demo(data_dir):
    """gt01 reports a btrfs host; /home is in a warning state, so the entry of its filesystem must be amber."""
    dev_file = data_dir / "devices.json"
    devs = json.loads(dev_file.read_text())
    si = devs[HOST].setdefault("sysinfo", {})
    si.update(mounts=REAL, disk_percent=49.7, disk_io=DISK_IO)
    devs[HOST]["metric_state"] = {"disk:/home": "warning"}
    devs[HOST]["metrics_ts"] = int(time.time()) - 7 * 60      # the figures were reported seven minutes ago
    dev_file.write_text(json.dumps(devs))

    now = int(time.time())
    samples = []
    for i in range(30):
        ts = now - (29 - i) * 86400
        grown = [dict(m, percent=round(m["percent"] + (i * 0.1 if m["fstype"] == "btrfs" else 0), 1),
                      used_gb=round(m["used_gb"] + (i * 0.9 if m["fstype"] == "btrfs" else 0), 2)) for m in REAL]
        samples.append({"date": time.strftime("%Y-%m-%d", time.gmtime(ts)), "ts": ts, "mounts": grown, "mem_percent": 30 + (i * 7) % 11,
                        "swap_percent": 0.0, "loadavg_1m": 0.4, "cpu_count": 8})
    hist_file = data_dir / "metrics_history.json"
    hist = json.loads(hist_file.read_text()) if hist_file.exists() else {}
    hist[HOST] = {"samples": samples}
    hist_file.write_text(json.dumps(hist))

    io_file = data_dir / "diskio_history.json"
    io = json.loads(io_file.read_text()) if io_file.exists() else {}
    io[HOST] = {"nvme0n1": [[now - (59 - i) * 600, round(0.4 + (i % 7) * 0.3, 1), 0.02, 0.3, 1.0, 0.3] for i in range(60)],
                "sda": [[now - (59 - i) * 600, 0.0, 0.0, 0.0, 0.0, 0.0] for i in range(60)]}
    io_file.write_text(json.dumps(io))


def _sign_in(browser, base, user, password):
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
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
    data_dir = Path(tempfile.mkdtemp(prefix="rp-diskviews-"))
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", str(data_dir), "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    patch_the_demo(data_dir)
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail(f"chromium not available: {exc}")
    try:
        base, shutdown = start_stack(data_dir=str(data_dir))
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
class TestEachViewShowsEachFilesystemOnce(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def tearDown(self):
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def disks_cell(self):
        self.page.evaluate("showPage('monitor')")
        self.page.wait_for_selector("#device-metrics-tbody tr td", timeout=60000)
        self.page.wait_for_function("(name) => [...document.querySelectorAll('#device-metrics-tbody tr')].some(t => t.textContent.includes(name))",
                                    arg=NAME, timeout=60000)
        return self.page.evaluate("""(name) => {
            const tr = [...document.querySelectorAll('#device-metrics-tbody tr')].find(t => t.textContent.includes(name));
            return [...tr.querySelectorAll('td')[5].querySelectorAll('span[class^="isl-349"], span.isl-349')].map(s => ({
                text: s.textContent.replace(/\\s+/g, ' ').trim(), title: s.getAttribute('title') || '', color: s.getAttribute('data-color') || ''}));
        }""", NAME)

    def test_host_metrics_has_one_entry_for_each_filesystem(self):
        cells = self.disks_cell()
        texts = [c["text"] for c in cells]
        self.assertEqual(len(cells), 4, texts)
        root = next(c for c in cells if c["text"].startswith("/ ") or c["text"].startswith("/:") or c["text"].startswith("/+"))
        self.assertIn("+6", root["text"])
        self.assertIn("50%", root["text"])
        for other in ("/home", "/root", "/srv", "/var/log", "/var/tmp", "/var/cache"):
            self.assertIn(other, root["title"], "the other mount points are named on hover")
        self.assertTrue(any(t.startswith("⇄ /data") and "68%" in t for t in texts), texts)
        self.assertTrue(any("/boot" in t and "24%" in t for t in texts), texts)
        self.assertTrue(any("google-chrome" in t and "+1" in t for t in texts), texts)
        self.assertFalse(any("doc" in t for t in texts), "a mount of size 0 was listed")
        self.assertEqual(sum(1 for t in texts if "50%" in t), 1, "the same figure was listed again")

    def test_an_alert_on_a_mount_point_of_the_volume_colours_its_entry(self):
        """/home is in a warning state in the patched data; the entry that stands for the volume is amber."""
        cells = self.disks_cell()
        root = next(c for c in cells if "+6" in c["text"])
        self.assertEqual(root["color"], "var(--amber)")
        quiet = next(c for c in cells if "/boot" in c["text"])
        self.assertNotEqual(quiet["color"], "var(--amber)")

    def test_a_host_says_when_its_figures_were_reported(self):
        self.disks_cell()
        first_cells = self.page.evaluate("""() => [...document.querySelectorAll('#device-metrics-tbody tr')].map(tr => {
            const td = tr.querySelector('td'); return td ? td.innerText.replace(/\\s+/g, ' ').trim() : ''; })""")
        mine = next(c for c in first_cells if NAME in c)
        self.assertRegex(mine, r"Reported 7m ago", mine)   # the page's own way of writing a time
        others = [c for c in first_cells if c and NAME not in c]
        self.assertTrue(others)
        self.assertFalse([c for c in others if "Reported" in c], "a host that never reported figures has no such line")

    def test_a_search_by_any_mount_point_still_finds_the_host(self):
        self.disks_cell()
        self.page.fill("#device-metrics-filter", "/var/cache")
        self.page.wait_for_timeout(600)
        shown = self.page.evaluate("() => [...document.querySelectorAll('#device-metrics-tbody tr')].filter(t => t.offsetParent !== null).map(t => t.textContent)")
        self.assertTrue(any(NAME in t for t in shown), shown[:3])
        self.page.fill("#device-metrics-filter", "")

    def test_trends_draws_each_filesystem_once(self):
        self.page.evaluate("showPage('trends')")
        self.page.wait_for_selector(f'#trend-device option[value="{HOST}"]', state="attached", timeout=60000)
        self.page.select_option("#trend-device", HOST)
        self.page.evaluate("loadTrendDevice()")
        self.page.wait_for_function("() => document.querySelectorAll('#trend-resources .ts-leg').length >= 5", timeout=30000)
        legend = self.page.evaluate("() => [...document.querySelectorAll('#trend-resources .ts-leg')].map(e => e.textContent.trim())")
        disks = [n for n in legend if n.startswith("disk ") and n != "disk % (busiest)"]
        self.assertEqual(sorted(disks), sorted(["disk / (+6)", "disk /data (net)", "disk /boot", f"disk {disk_mounts.short_path(CHROME)} (+1)"]), legend)
        paths = self.page.evaluate("() => document.querySelectorAll('#trend-resources svg.ts-chart path').length")
        self.assertEqual(paths, len(legend), "one line for each name in the legend")

    def test_the_first_trends_option_is_not_called_raw_24h(self):
        self.page.evaluate("showPage('trends')")
        label = self.page.evaluate("() => document.querySelector('#trend-range option[value=\"raw\"]').textContent")
        self.assertEqual(label, "Daily samples (per mount)")

    def test_the_disk_io_table_says_what_its_figures_cover(self):
        html = self.page.evaluate("""async (id) => {
            const hw = await api('GET', `/devices/${id}/hardware`);
            return _renderHardwareSection(id, hw, {}, {});
        }""", HOST)
        self.assertIn("Each figure is an average over the last 10 min, reported ", html)
        self.assertRegex(html, r"reported <time datetime=\"[0-9T:.\-]+Z\"")
        self.assertIn("a short burst of I/O does not show in it.", html)


if __name__ == "__main__":
    unittest.main()
