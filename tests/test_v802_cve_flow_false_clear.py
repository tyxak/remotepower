#!/usr/bin/env python3
"""cve_cleared is announced for what a scan checked, not for what it stopped looking at.

A host's findings can leave the list because the packages were patched, or because the scan no longer asks the right question: an
agent that does not send source packages (one older than 8.0.1, or one whose `dpkg-query` timed out and fell back to plain rows),
a release that is not known, answers that were cut. The Debian advisories are filed under the source package, so a scan that asks for
`libssl3` finds nothing where `openssl` finds five. `_detect_new_cve_and_fire_webhook` decided "cleared" from the findings and the
roll-up alone and ignored the account of what was checked that the same scan stored, so a host that sent the same packages without
the `sources` mark was announced cleared, its open cve_found alert was closed by the cve_cleared event, and the notification channels
were told it was fixed, while the page said "checked 0 of 3 packages" and nothing had been patched.

What this holds, with the real ingest, the real worker and the real alert store (a process of its own; the advisory service is a stand-in):

* the same packages sent without the `sources` mark: no cve_cleared, the alert stays open;
* the controls: a host that installed the fix, and a host that removed the package, are still announced cleared and the alert closes;
* the rule as a function (`cve_fixes.clear_is_trusted`), over the account of both scans.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-fc-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import cve_fixes  # noqa: E402

_TMP = []


def tearDownModule():
    import shutil
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


_DRIVER = r"""
import json, sys, time
sys.path.insert(0, sys.argv[1])
sys.dont_write_bytecode = True
import wsgi
api = wsgi.api
now = int(time.time())


def put(attr, obj):
    api.save(getattr(api, attr), obj)
    api._invalidate_load_cache(getattr(api, attr))


put("CONFIG_FILE", {})
put("DEVICES_FILE", {"alpha": {"name": "ALPHA-WEB-1", "hostname": "alpha", "os": "Debian 12", "monitored": True, "last_seen": now,
                               "token": "T-alpha", "group": "g", "ip": "10.0.0.1"}})
OLD, NEW = "3.0.11-1~deb12u1", "3.0.15-1~deb12u1"


def body(packages, sources):
    b = {"device_id": "alpha", "token": "T-alpha", "pkg_manager": "apt",
         "ecosystem_hint": {"ID": "debian", "VERSION_ID": "12", "ID_LIKE": "", "UBUNTU_CODENAME": "", "DEBIAN_CODENAME": "",
                            "VERSION_CODENAME": ""}, "packages": packages}
    if sources:
        b["sources"] = True
    return b


def ssl(version):
    return {"name": "libssl3", "version": version, "arch": "amd64", "source": "openssl", "source_version": version}


LIBC = {"name": "libc6", "version": "2.36-9", "arch": "amd64", "source": "glibc", "source_version": "2.36-9"}
COREUTILS = {"name": "coreutils", "version": "9.1-1", "arch": "amd64"}


def querybatch(queries):
    out = []
    for q in queries:
        if q["package"]["name"] == "openssl" and q["version"] == OLD:
            out.append({"vulns": [{"id": "DEBIAN-CVE-2024-openssl-%d" % i, "modified": "2026-11-10T08:00:00.000000Z"} for i in range(5)]})
        else:
            out.append({})
    return out


def details(vid):
    return {"id": vid, "modified": "2026-11-10T08:00:00.000000Z", "published": "2024-03-01T10:00:00Z", "upstream": ["CVE-2024-1%s" % vid[-1]],
            "summary": "a flaw in openssl", "details": "A flaw was found in openssl.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}], "references": [],
            "affected": [{"package": {"ecosystem": eco, "name": "openssl", "purl": "pkg:deb/debian/openssl?arch=source"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9-1~deb%du1" % n}]}],
                          "ecosystem_specific": {"urgency": "not yet assigned"}}
                         for eco, n in (("Debian:11", 11), ("Debian:12", 12), ("Debian:13", 13))]}


api.cve_scanner._osv_querybatch = querybatch
api.cve_scanner._osv_vuln_details = details
fired = []
real_fire = api.fire_webhook


def fire(event, payload, *a, **k):
    fired.append(event)
    return real_fire(event, payload, *a, **k)


api.fire_webhook = fire


def send(packages, sources):
    st = wsgi.application.test_client().post("/api/packages", data=json.dumps(body(packages, sources)), content_type="application/json")
    assert st.status_code == 200, st.data
    store = api.load(api.PACKAGES_FILE)
    store["alpha"]["collected_at"] = int(time.time()) + len(fired) + 1 + send.n      # each list is later than the one before
    send.n += 1
    put("PACKAGES_FILE", store)


send.n = 0


def scan():
    del fired[:]
    api._cve_scan_worker("op", "alpha")
    api._invalidate_load_cache(api.CVE_FINDINGS_FILE)
    rec = api.load(api.CVE_FINDINGS_FILE)["alpha"]
    cov = rec.get("covered") or {}
    api._invalidate_load_cache(api.ALERTS_FILE)
    alerts = [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", []) if a.get("event") in ("cve_found", "cve_cleared")]
    return {"findings": len(rec.get("findings", [])), "checked": cov.get("checked"), "listed": cov.get("listed"),
            "reasons": cov.get("reasons"), "events": list(fired),
            "open_found": sum(1 for a in alerts if a.get("event") == "cve_found" and not a.get("resolved_at")),
            "resolved_found": sum(1 for a in alerts if a.get("event") == "cve_found" and a.get("resolved_at"))}


out = {}
# the host sends source packages and is found vulnerable
send([ssl(OLD), LIBC, COREUTILS], True)
out["first"] = scan()
# the same packages without the mark (an older agent, or dpkg-query that timed out): nothing was patched
send([ssl(OLD), LIBC, COREUTILS], False)
out["same_packages_no_mark"] = scan()
# the mark is back: the findings are back, and nothing was cleared in between
send([ssl(OLD), LIBC, COREUTILS], True)
out["mark_back"] = scan()
# the control: the host installs the fix
send([ssl(NEW), LIBC, COREUTILS], True)
out["fixed"] = scan()

# the control: the package is removed (fewer packages listed, all of them checked)
put("CVE_FINDINGS_FILE", {})
put("ALERTS_FILE", {"alerts": []})
send([ssl(OLD), LIBC, COREUTILS], True)
out["again_first"] = scan()
send([LIBC, COREUTILS], True)
out["removed"] = scan()
print(json.dumps(out))
"""


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        d = Path(tempfile.mkdtemp(prefix="rp-v802-fc-run-"))
        _TMP.append(d)
        (d / "driver.py").write_text(_DRIVER, encoding="utf-8")
        data = d / "data"
        data.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("REQUEST_", "HTTP_", "PATH_INFO", "QUERY_", "CONTENT_"))}
        env["RP_DATA_DIR"] = str(data)
        proc = subprocess.run([sys.executable, str(d / "driver.py"), str(_CGI)], capture_output=True, text=True, env=env, timeout=600)
        if proc.returncode != 0:
            raise AssertionError("the driver failed:\n" + proc.stderr[-2500:])
        cls.o = json.loads(proc.stdout.strip().splitlines()[-1])

    def test_the_first_scan_finds_the_host_vulnerable_and_raises_one_alert(self):
        first = self.o["first"]
        self.assertEqual((first["findings"], first["checked"], first["listed"]), (5, 3, 3))
        self.assertEqual(first["events"], ["cve_found"])
        self.assertEqual(first["open_found"], 1)

    def test_a_scan_that_checked_nothing_does_not_announce_a_clear(self):
        o = self.o["same_packages_no_mark"]
        self.assertEqual((o["findings"], o["checked"], o["listed"]), (0, 0, 3), "the scan looked for libssl3 and the advisories say openssl")
        self.assertEqual(o["reasons"], {"no_source": 3})
        self.assertNotIn("cve_cleared", o["events"], "nothing was patched; the scan stopped looking")
        self.assertEqual(o["open_found"], 1, "the alert is still open")
        self.assertEqual(o["resolved_found"], 0)

    def test_the_findings_are_back_when_the_agent_sends_the_mark_again(self):
        o = self.o["mark_back"]
        self.assertEqual(o["findings"], 5)
        self.assertEqual(o["open_found"], 1, "one alert for the host, as it was")

    def test_a_host_that_installed_the_fix_is_announced_cleared_and_the_alert_closes(self):
        o = self.o["fixed"]
        self.assertEqual((o["findings"], o["checked"], o["listed"]), (0, 3, 3))
        self.assertEqual(o["events"], ["cve_cleared"])
        self.assertEqual((o["open_found"], o["resolved_found"]), (0, 1))

    def test_a_host_that_removed_the_package_is_announced_cleared_too(self):
        self.assertEqual(self.o["again_first"]["findings"], 5)
        o = self.o["removed"]
        self.assertEqual((o["findings"], o["checked"], o["listed"]), (0, 2, 2), "two packages listed, both checked")
        self.assertEqual(o["events"], ["cve_cleared"])
        self.assertEqual(o["open_found"], 0)


def _block(listed, not_checked=0, **reasons):
    return {"listed": listed, "checked": listed - not_checked, "not_checked": not_checked, "reasons": reasons}


class TestTheRule(unittest.TestCase):
    """cve_fixes.clear_is_trusted(before, now): may a scan that lists nothing of what the scan before listed say it is cleared?"""

    def test_a_scan_that_checked_every_package_may(self):
        self.assertTrue(cve_fixes.clear_is_trusted(_block(3), _block(3)))
        self.assertTrue(cve_fixes.clear_is_trusted(None, _block(3)))

    def test_a_package_that_was_removed_is_a_clear_not_a_loss(self):
        self.assertTrue(cve_fixes.clear_is_trusted(_block(3), _block(2)))

    def test_a_reason_that_belongs_to_the_host_may_not(self):
        for reason in ("no_source", "no_release", "no_matcher"):
            self.assertFalse(cve_fixes.clear_is_trusted(_block(3), _block(3, 3, **{reason: 3})), reason)
            self.assertFalse(cve_fixes.clear_is_trusted(None, _block(3, 1, **{reason: 1})), reason)

    def test_more_packages_without_an_answer_than_before_may_not(self):
        self.assertFalse(cve_fixes.clear_is_trusted(_block(3), _block(3, 2, unanswered=2)))
        self.assertFalse(cve_fixes.clear_is_trusted(_block(3, 1, ceiling=1), _block(3, 2, ceiling=2)))

    def test_as_many_as_before_may(self):
        self.assertTrue(cve_fixes.clear_is_trusted(_block(3, 2, unanswered=2), _block(3, 2, unanswered=2)))
        self.assertTrue(cve_fixes.clear_is_trusted(_block(3, 2, unanswered=2), _block(3, 1, unanswered=1)))

    def test_a_scan_with_no_account_is_judged_as_it_always_was(self):
        self.assertTrue(cve_fixes.clear_is_trusted(_block(3), None))
        self.assertTrue(cve_fixes.clear_is_trusted(None, None))

    def test_junk_in_either_block_is_no_account(self):
        for junk in ("x", 5, [], {"reasons": "x"}, {"reasons": {"no_source": "many"}}, {"reasons": {"no_source": True}}):
            self.assertIn(cve_fixes.clear_is_trusted(junk, junk), (True, False))
        self.assertTrue(cve_fixes.clear_is_trusted(_block(3), {"reasons": {"no_source": "many"}}), "text is not a count")


if __name__ == "__main__":
    unittest.main()
