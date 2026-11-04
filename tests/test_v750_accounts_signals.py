#!/usr/bin/env python3
"""Local accounts reach the compliance report and the risk score.

The Linux agent reads /etc/passwd and /etc/shadow (as root) and tags each account: `empty_password`, `uid0` for a second UID 0,
`stale_password`, `sudo`. The server keeps the list. It raised events and a Checks row, and counted for nothing in a host's risk
score; the compliance report said it held no inventory of standing privilege and passed a host with a login account that needs no
password. This binds the two worst lines (no password, a second UID 0) to the risk score and to the administrative-privilege
control (PCI 7, SOC 2, E8-5).

The account records come from the agent's own `get_local_accounts()` run on real-format passwd, shadow and group text, through the
real hardware ingest.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-acc-"))

import compliance  # noqa: E402
import posture_signals as ps  # noqa: E402

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
toor:x:0:0:backdoor:/root:/bin/bash
svc:x:998:998:svc:/srv:/usr/sbin/nologin
"""
SHADOW_BAD = """root:$6$x$y:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
alice:$6$a$b:19000:0:99999:7:::
bob::19500:0:99999:7:::
toor:$6$c$d:19000:0:99999:7:::
svc:!:19000:0:99999:7:::
"""
SHADOW_OK = SHADOW_BAD.replace("bob::", "bob:$6$e$f:").replace("toor:$6$c$d", "toor:!")
GROUP = "sudo:x:27:alice\n"


def _agent():
    spec = importlib.util.spec_from_file_location("rp_agent_v750_acc", ROOT / "client" / "remotepower-agent.py")
    a = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(a)
    return a


def _accounts(passwd, shadow):
    """The agent's own collector over this passwd, shadow and group text, running as root."""
    a = _agent()
    files = {"/etc/passwd": passwd, "/etc/shadow": shadow, "/etc/group": GROUP}
    a._safe_read = lambda path, limit=0: files.get(path)
    a.os = type("O", (), {"geteuid": staticmethod(lambda: 0), "__getattr__": lambda self, n: getattr(os, n)})()
    return a.get_local_accounts()


def _fresh_api():
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v750-acc-api-")
    spec = importlib.util.spec_from_file_location("api_v750_acc", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTheProducer(unittest.TestCase):

    def test_the_premise_the_agent_flags_both(self):
        flags = {a["user"]: a["flags"] for a in _accounts(PASSWD, SHADOW_BAD)}
        self.assertIn("empty_password", flags["bob"])
        self.assertIn("uid0", flags["toor"])
        self.assertNotIn("uid0", flags["root"])
        self.assertIn("sudo", flags["alice"])
        self.assertNotIn("empty_password", flags["alice"])


class TestTheHelper(unittest.TestCase):

    def test_both_lists(self):
        blank, uid0 = ps.risky_accounts({"accounts": _accounts(PASSWD, SHADOW_BAD)})
        self.assertEqual((blank, uid0), (["bob"], ["toor"]))

    def test_a_clean_host_is_empty(self):
        self.assertEqual(ps.risky_accounts({"accounts": _accounts(PASSWD, SHADOW_OK)}), ([], ["toor"]))
        clean = PASSWD.replace("toor:x:0:0:backdoor:/root:/bin/bash\n", "")
        self.assertEqual(ps.risky_accounts({"accounts": _accounts(clean, SHADOW_OK)}), ([], []))

    def test_junk_is_nothing(self):
        for junk in (None, [], "x", 5, {}, {"accounts": "x"}, {"accounts": [None, 5, {"flags": "x"}, {"user": "u"}]}):
            self.assertEqual(ps.risky_accounts(junk), ([], []), junk)

    def test_a_long_list_is_capped(self):
        accts = [{"user": f"u{i}", "flags": ["empty_password"]} for i in range(900)]
        self.assertEqual(len(ps.risky_accounts({"accounts": accts})[0]), 500)


class TestComplianceAndRisk(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = api = _fresh_api()
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            "bad": {"name": "web01", "last_seen": now, "monitored": True, "sysinfo": {"cpu_percent": 1}},
            "ok": {"name": "db01", "last_seen": now, "monitored": True, "sysinfo": {"cpu_percent": 1}},
            "mute": {"name": "win01", "last_seen": now, "monitored": True, "sysinfo": {"cpu_percent": 1}}})
        real = api.fire_webhook
        api.fire_webhook = lambda *a, **k: None
        try:
            api._ingest_hardware("bad", "web01", {"accounts": _accounts(PASSWD, SHADOW_BAD)}, now)
            clean = PASSWD.replace("toor:x:0:0:backdoor:/root:/bin/bash\n", "")
            api._ingest_hardware("ok", "db01", {"accounts": _accounts(clean, SHADOW_OK)}, now)
        finally:
            api.fire_webhook = real
        api._LOAD_CACHE.clear()
        cls.facts = api._compliance_facts(api.load(api.DEVICES_FILE))

    def test_the_facts_name_hosts_and_not_accounts(self):
        f = self.facts
        self.assertEqual(f["accounts_blank"], ["web01 (1 account)"])
        self.assertEqual(f["accounts_uid0"], ["web01 (1 account)"])
        self.assertEqual(f["accounts_data_devices"], 2)
        self.assertNotIn("bob", str(f["accounts_blank"]))
        self.assertNotIn("toor", str(f["accounts_uid0"]))

    def test_the_control_fails_with_the_hosts(self):
        st, ev = compliance._admin_privilege_control(self.facts)
        self.assertEqual(st, compliance.FAIL)
        self.assertIn("no password", ev)
        self.assertIn("UID 0", ev)
        self.assertIn("web01", ev)
        self.assertNotIn("db01", ev)

    def test_a_clean_fleet_passes_and_says_what_it_does_not_attest(self):
        facts = {"accounts_data_devices": 2, "accounts_blank": [], "accounts_uid0": [], "privileged_group_monitored": False}
        st, ev = compliance._admin_privilege_control(facts)
        self.assertEqual(st, compliance.PASS)
        self.assertIn("not a review of who holds sudo", ev)

    def test_no_account_data_and_no_baseline_is_still_not_assessed(self):
        self.assertEqual(compliance._admin_privilege_control({})[0], compliance.NOT_ASSESSED)

    def test_the_frameworks_that_map_it_all_see_it(self):
        rep = compliance.build_report(self.facts)
        by = {(fw, c["id"]): c["status"] for fw, d in rep["frameworks"].items() for c in d["controls"]}
        for key in (("e8", "E8-5"), ("smb1001", "S-access")):
            self.assertEqual(by[key], compliance.FAIL, key)

    def test_the_risk_score_counts_each_account(self):
        api = self.api
        row = {r["device_id"]: r for r in api._compute_fleet_risk()}
        f = [x for x in row["bad"]["factors"] if x["kind"] == "risky_accounts"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["points"], 2 * api._RISK_WEIGHTS["risky_accounts"])
        self.assertIn("bob", f[0]["detail"])
        self.assertIn("toor", f[0]["detail"])
        self.assertEqual([x for x in row["ok"]["factors"] if x["kind"] == "risky_accounts"], [])
        self.assertEqual([x for x in row["mute"]["factors"] if x["kind"] == "risky_accounts"], [])

    def test_the_weight_is_capped_and_tunable(self):
        api = self.api
        self.assertEqual(api._RISK_CAPS["risky_accounts"], 24)
        accts = [{"user": f"u{i}", "flags": ["empty_password"]} for i in range(9)]
        dev = {"name": "h", "last_seen": int(time.time()), "monitored": True, "sysinfo": {}}
        r = api._device_risk("x", dev, {}, {}, {}, int(time.time()), 180, hw_rec={"accounts": accts})
        f = [x for x in r["factors"] if x["kind"] == "risky_accounts"]
        self.assertEqual(f[0]["points"], 24)

    def test_registries(self):
        api = self.api
        js = (ROOT / "server/html/static/js/app.js").read_text()
        html = (ROOT / "server/html/index.html").read_text()
        self.assertIn("risky_accounts: %d" % api._RISK_WEIGHTS["risky_accounts"], js)
        self.assertIn("risky_accounts: 'Account with no password'", js)
        self.assertIn('id="ap-rw-risky_accounts"', html)


if __name__ == "__main__":
    unittest.main()
