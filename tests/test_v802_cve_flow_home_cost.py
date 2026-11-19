#!/usr/bin/env python3
"""The Home page, which every open tab polls once a minute, does not read the package store.

`handle_home` builds the CVE tile from the findings. For a monitored host with no account of its packages (a Windows or macOS host,
an Arch host, a host that was not scanned yet) it read the whole package store to derive the number of packages that cannot be
checked, `when no host shows a finding`, which is the state of a quiet fleet. The comment called that "read only when the answer
changes what the tile says", and it holds only when something is found. At 24 MB of lists the route went from 5 ms to 940 ms for any
tenant's viewer; hosts can send lists of up to 10,000 packages, and every tab polls it.

The number a host that nothing is matched against would give is a property of its package list, so it is worked out when the list
arrives and kept with the host (`pkg_account`: how many packages it lists and that none can be checked). Home reads that from the host
records it already holds.

What this holds, on the real WSGI app with real API keys, the real ingest and the real route (a process of its own):

* a Home request on a quiet fleet that has a Windows host, an Arch host and a host that was not scanned reads the package store zero
  times, and the tile still gets the number: the applications of the Windows host, the packages of the Arch host, nothing for the host
  that a scan will check;
* the number follows the host: an Arch host that is reinstalled as Debian no longer has one;
* a host record that holds junk in the field does not fail the page.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-hc-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
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


def key(token, user, role, tenant):
    return {"name": token, "key_hash": api._apikey_hash(token), "user": user, "role": role, "active": True, "created": 1,
            "tenant_id": tenant}


put("CONFIG_FILE", {"tenancy_enforced": True})
put("TENANTS_FILE", {"tenantA": {"name": "Tenant A"}})
put("USERS_FILE", {"viewerA": {"role": "viewer", "tenant_id": "tenantA", "created": 1}})
put("APIKEYS_FILE", {"k3": key("T-VIEWER-A", "viewerA", "viewer", "tenantA")})


def host(dev_id, os_name):
    return {"name": dev_id.upper(), "hostname": dev_id, "os": os_name, "monitored": True, "last_seen": now, "token": "T-" + dev_id,
            "group": "g", "ip": "10.0.0.1", "tenant": "tenantA"}


DEBIANS = ["deb-%d" % i for i in range(12)]
devs = {h: host(h, "Debian 12") for h in DEBIANS}
devs.update({"win-1": host("win-1", "Windows 11"), "arch-1": host("arch-1", "Arch Linux"), "new-1": host("new-1", "Debian 12")})
put("DEVICES_FILE", devs)


def post(dev_id, packages, manager, os_id, version_id, sources=False, **extra):
    body = {"device_id": dev_id, "token": "T-" + dev_id, "pkg_manager": manager,
            "ecosystem_hint": {"ID": os_id, "VERSION_ID": version_id, "ID_LIKE": "", "UBUNTU_CODENAME": "", "DEBIAN_CODENAME": "",
                               "VERSION_CODENAME": ""}, "packages": packages}
    if sources:
        body["sources"] = True
    body.update(extra)
    c = wsgi.application.test_client()
    r = c.post("/api/packages", data=json.dumps(body), content_type="application/json")
    return r.status_code


deb = [{"name": "pkg%d" % i, "version": "1.0-1", "arch": "amd64", "source": "src%d" % i, "source_version": "1.0-1"} for i in range(40)]
out = {"ingest": {}}
for h in DEBIANS + ["new-1"]:
    out["ingest"][h] = post(h, deb, "apt", "debian", "12", sources=True)
APPS = [{"name": "App%d" % i, "version": "1.%d" % i, "arch": "x64", "manager": "windows"} for i in range(5)]
out["ingest"]["win-1"] = post("win-1", APPS, "windows", "", "", skipped=2)
ARCH = [{"name": "arch-pkg-%d" % i, "version": "1.0-1", "arch": "x86_64"} for i in range(7)]
out["ingest"]["arch-1"] = post("arch-1", ARCH, "pacman", "arch", "")

# the twelve Debian hosts were scanned and are clean; new-1 was not scanned
put("CVE_FINDINGS_FILE", {h: {"scanned_at": now, "ecosystem": "Debian:12", "findings": [],
                              "covered": {"listed": 40, "checked": 40, "not_checked": 0, "reasons": {}, "packages": [], "more": 0}}
                          for h in DEBIANS})
api._invalidate_load_cache(api.DEVICES_FILE)
out["pkg_account"] = {h: api.load(api.DEVICES_FILE)[h].get("pkg_account") for h in ("win-1", "arch-1", "new-1", "deb-0")}


def home():
    reads = []
    real_load, real_ro = api.load, api._load_ro

    def spy(real):
        def inner(path, *a, **k):
            if str(path).endswith("packages.json"):
                reads.append(1)
            return real(path, *a, **k)
        return inner

    api.load, api._load_ro = spy(real_load), spy(real_ro)
    try:
        r = wsgi.application.test_client().get("/api/home", headers={"X-Token": "T-VIEWER-A"})
    finally:
        api.load, api._load_ro = real_load, real_ro
    body = json.loads(r.data.decode("utf-8", "replace"))
    rows = {d["device_id"]: d for d in body["cves"]["devices"]}
    return {"status": r.status_code, "reads_of_the_package_store": len(reads),
            "not_checked": {h: rows[h]["not_checked"] for h in ("win-1", "arch-1", "new-1", "deb-0")}}


home()          # a first request fills the caches the page keeps (the Needs-attention digest reads the store once, for a ten-second window)
out["quiet_fleet"] = home()

# the Arch host is reinstalled as Debian
out["arch_to_debian"] = post("arch-1", deb, "apt", "debian", "12", sources=True)
api._invalidate_load_cache(api.DEVICES_FILE)
out["arch_account_after"] = api.load(api.DEVICES_FILE)["arch-1"].get("pkg_account", "absent")
home()
out["after_reinstall"] = home()

# junk in the field
d = api.load(api.DEVICES_FILE)
d["win-1"]["pkg_account"] = "junk"
d["new-1"]["pkg_account"] = {"listed": "x", "not_checked": [1]}
d["arch-1"]["pkg_account"] = {"listed": 7, "not_checked": 7}      # a good one after the first junk one: the page must get to it
put("DEVICES_FILE", d)
home()
out["junk"] = home()
print(json.dumps(out))
"""


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        d = Path(tempfile.mkdtemp(prefix="rp-v802-hc-run-"))
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

    def test_setup_worked(self):
        self.assertTrue(all(v == 200 for v in self.o["ingest"].values()), self.o["ingest"])
        self.assertEqual(self.o["quiet_fleet"]["status"], 200)

    def test_a_home_request_on_a_quiet_fleet_does_not_read_the_package_store(self):
        self.assertEqual(self.o["quiet_fleet"]["reads_of_the_package_store"], 0,
                         "the store holds every package of every host, and every open tab asks once a minute")

    def test_the_tile_still_gets_the_number_of_packages_that_cannot_be_checked(self):
        nc = self.o["quiet_fleet"]["not_checked"]
        self.assertEqual(nc["win-1"], 5, "the applications of the Windows host")
        self.assertEqual(nc["arch-1"], 7, "the packages of the Arch host")
        self.assertEqual(nc["new-1"], 0, "a host a scan will check has none yet")
        self.assertEqual(nc["deb-0"], 0, "control: a scanned host that was checked in full")

    def test_the_number_is_kept_with_the_host_when_its_list_arrives(self):
        acct = self.o["pkg_account"]
        self.assertEqual(acct["win-1"], {"listed": 5, "not_checked": 5})
        self.assertEqual(acct["arch-1"], {"listed": 7, "not_checked": 7})
        self.assertIsNone(acct["new-1"], "a host nothing is matched against is the only one that has it")
        self.assertIsNone(acct["deb-0"])

    def test_the_number_follows_the_host(self):
        o = self.o
        self.assertEqual(o["arch_to_debian"], 200)
        self.assertEqual(o["arch_account_after"], "absent", "reinstalled as Debian: a scan will check its packages")
        self.assertEqual(o["after_reinstall"]["not_checked"]["arch-1"], 0)
        self.assertEqual(o["after_reinstall"]["reads_of_the_package_store"], 0)

    def test_junk_in_the_field_does_not_fail_the_page(self):
        j = self.o["junk"]
        self.assertEqual(j["status"], 200)
        self.assertEqual((j["not_checked"]["win-1"], j["not_checked"]["new-1"]), (0, 0))
        self.assertEqual(j["not_checked"]["arch-1"], 7, "control: a host after the one with junk still gets its number")
        self.assertEqual(j["reads_of_the_package_store"], 0)


if __name__ == "__main__":
    unittest.main()
