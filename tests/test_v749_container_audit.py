#!/usr/bin/env python3
"""7.4.9: a hardening audit of how each container was started.

Nothing in the product looked at how containers were started, only at whether they ran. A container that is privileged, shares
the host's process or network namespace, holds the engine's socket or mounts the host's /etc is as exposed as the host. The Linux
agent reads each container's run options once from `inspect` and reports plain facts; container_audit.py keeps them and works out
the findings, so a rule is a server change; an administrator can accept a finding for one container.

What is real and what is not: no Docker or Podman was available where this was written. The inspect records below are written to
the layout the engines document (HostConfig, Config and Mounts keys), not captured from a running engine, so they prove the reader
against that layout and nothing about a live host. The rules are checked against the facts they read, and the agent code is run
for real with the engine's output replaced.
"""
import importlib.machinery
import importlib.util
import json
import os
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-ca-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import container_audit as CA  # noqa: E402
import containers  # noqa: E402
import store_shapes  # noqa: E402


def item(audit=None, **kw):
    base = {"name": "web", "image": "nginx", "tag": "1.27", "mem_limit_bytes": 512 * 1024 ** 2, "audit": audit}
    base.update(kw)
    return base


def facts(**kw):
    """The facts of a container started as plainly as possible, with changes."""
    f = {"v": 1, "has_healthcheck": True, "readonly_rootfs": True, "user": "1000", "security_opt": ["no-new-privileges"]}
    f.update(kw)
    return CA.clean_facts(f)


def rules(it):
    return {x["rule"]: x["severity"] for x in (CA.evaluate(it) or [])}


# ── the validator ─────────────────────────────────────────────────────────────────────────────────────────────────────
class TestFacts(unittest.TestCase):

    def test_the_marker_tells_nothing_inspected_from_nothing_to_report(self):
        for raw in (None, {}, [], "x", 5, {"privileged": True}, {"v": 2}, {"v": "1"}, {"v": True}):
            self.assertIsNone(CA.clean_facts(raw), repr(raw))
        self.assertIsNotNone(CA.clean_facts({"v": 1}), "a container with plain options still sends the marker")

    def test_defaults_when_the_agent_left_everything_out(self):
        f = CA.clean_facts({"v": 1})
        self.assertEqual((f["privileged"], f["readonly_rootfs"], f["has_healthcheck"]), (False, False, False))
        self.assertEqual((f["cap_add"], f["mounts"], f["ports"], f["devices"]), ([], [], [], []))

    def test_a_mount_is_writable_unless_it_says_otherwise(self):
        f = CA.clean_facts({"v": 1, "mounts": [{"src": "/etc", "dst": "/h"}, {"src": "/proc", "dst": "/p", "rw": False}]})
        self.assertEqual([m["rw"] for m in f["mounts"]], [True, False], "a report that leaves it out is read as the worse case")

    def test_capabilities_are_normalised(self):
        f = CA.clean_facts({"v": 1, "cap_add": ["cap_sys_admin", "NET_ADMIN", "CAP_NET_RAW", "", 5, None]})
        self.assertEqual(f["cap_add"], ["SYS_ADMIN", "NET_ADMIN", "NET_RAW"])

    def test_only_booleans_are_booleans(self):
        for v in ("true", 1, "yes", [], {}, None, 0):
            f = CA.clean_facts({"v": 1, "privileged": v, "readonly_rootfs": v, "has_healthcheck": v})
            self.assertEqual((f["privileged"], f["readonly_rootfs"], f["has_healthcheck"]), (False, False, False), repr(v))

    def test_text_is_cleaned_and_capped(self):
        f = CA.clean_facts({"v": 1, "user": "a\x00b\nc" + "x" * 500, "net_mode": "host\n", "pid_mode": "host;rm -rf",
                            "security_opt": ["seccomp=unconfined\x00" + "y" * 500]})
        self.assertNotRegex(f["user"], r"[\x00-\x1f]")
        self.assertLessEqual(len(f["user"]), 64)
        self.assertEqual(f["net_mode"], "host", "a control character is not part of a mode")
        self.assertEqual(f["pid_mode"], "", "a mode with a shell character in it is not a mode")
        self.assertLessEqual(len(f["security_opt"][0]), 80)

    def test_lists_are_capped(self):
        f = CA.clean_facts({"v": 1, "cap_add": [f"C{i}" for i in range(500)], "devices": [f"/dev/x{i}" for i in range(500)],
                            "mounts": [{"src": f"/m{i}", "dst": "/x"} for i in range(500)],
                            "ports": [{"port": 1000 + i, "proto": "tcp", "ip": ""} for i in range(500)],
                            "security_opt": [f"o{i}" for i in range(500)]})
        self.assertEqual((len(f["cap_add"]), len(f["devices"]), len(f["mounts"]), len(f["ports"]), len(f["security_opt"])),
                         (CA.MAX_CAPS, CA.MAX_DEVICES, CA.MAX_MOUNTS, CA.MAX_PORTS, CA.MAX_OPTS))

    def test_ports_must_be_ports(self):
        f = CA.clean_facts({"v": 1, "ports": [{"port": 80}, {"port": 0}, {"port": 70000}, {"port": True}, {"port": "80"},
                                              {"port": -1}, {"port": 8080, "proto": "udp", "ip": "127.0.0.1"}, "x", None]})
        self.assertEqual([(p["port"], p["proto"]) for p in f["ports"]], [(80, "tcp"), (8080, "udp")])

    def test_a_mount_needs_a_source(self):
        f = CA.clean_facts({"v": 1, "mounts": [{"dst": "/x"}, {"src": ""}, {"src": 5}, None, "x", {"src": "/data/"}]})
        self.assertEqual([m["src"] for m in f["mounts"]], ["/data"], "a trailing slash is not part of the path")

    def test_random_input_never_raises(self):
        rnd = random.Random(5)
        vals = [None, True, 0, -1, 1.5, float("nan"), "x", "host", "/etc", [], {}, [1], {"a": 1}, 10 ** 400, "\x00", "é", ["a", None]]
        keys = ("v", "privileged", "cap_add", "cap_drop", "security_opt", "devices", "user", "mounts", "ports", "net_mode",
                "pid_mode", "ipc_mode", "userns_mode", "readonly_rootfs", "has_healthcheck")
        for _ in range(600):
            raw = {k: rnd.choice(vals) for k in keys if rnd.random() < 0.6}
            raw["v"] = 1
            out = CA.clean_facts(raw)
            json.dumps(out)
            self.assertIsInstance(CA.evaluate(item(out)), list)


# ── the rules ─────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestRules(unittest.TestCase):

    def test_a_container_that_was_never_audited_is_not_clean(self):
        for it in (item(None), {"name": "x"}, None, "x", 5, {"audit": []}, {"audit": "x"}):
            self.assertIsNone(CA.evaluate(it), repr(it))

    def test_a_carefully_started_container_has_no_findings(self):
        self.assertEqual(CA.evaluate(item(facts())), [])

    def test_each_rule_fires_on_its_own_fact_and_nothing_else_does(self):
        cases = {
            "privileged": ({"privileged": True}, "critical"),
            "engine_socket": ({"mounts": [{"src": "/var/run/docker.sock", "dst": "/var/run/docker.sock"}]}, "critical"),
            "sensitive_mount": ({"mounts": [{"src": "/etc", "dst": "/h"}]}, "high"),
            "host_pid": ({"pid_mode": "host"}, "high"),
            "host_network": ({"net_mode": "host"}, "high"),
            "caps_high": ({"cap_add": ["SYS_ADMIN"]}, "high"),
            "seccomp_off": ({"security_opt": ["seccomp=unconfined", "no-new-privileges"]}, "high"),
            "apparmor_off": ({"security_opt": ["apparmor=unconfined", "no-new-privileges"]}, "medium"),
            "host_ipc": ({"ipc_mode": "host"}, "medium"),
            "host_userns": ({"userns_mode": "host"}, "medium"),
            "caps_medium": ({"cap_add": ["NET_ADMIN"]}, "medium"),
            "devices": ({"devices": ["/dev/sda"]}, "medium"),
            "open_port": ({"ports": [{"port": 8080, "proto": "tcp", "ip": ""}]}, "low"),
            "new_privileges": ({"security_opt": []}, "low"),
            "runs_as_root": ({"user": ""}, "low"),
            "writable_rootfs": ({"readonly_rootfs": False}, "low"),
            "no_healthcheck": ({"has_healthcheck": False}, "low"),
        }
        for rule, (change, sev) in cases.items():
            r = rules(item(facts(**change)))
            self.assertEqual(r.get(rule), sev, rule)
            self.assertEqual(set(r), {rule}, f"{rule} raised others: {r}")
        r = rules(item(facts(), mem_limit_bytes=0))
        self.assertEqual(r, {"no_memory_limit": "low"})
        self.assertEqual(rules(item(facts(), tag="latest")), {"latest_tag": "low"})
        self.assertEqual(rules(item(facts(), tag="")), {"latest_tag": "low"})

    def test_every_rule_in_the_table_is_reachable(self):
        seen = set()
        probes = [facts(privileged=True), facts(mounts=[{"src": "/var/run/docker.sock"}]), facts(mounts=[{"src": "/"}]),
                  facts(pid_mode="host", net_mode="host", ipc_mode="host", userns_mode="host", cap_add=["SYS_ADMIN"]),
                  facts(cap_add=["NET_ADMIN"], security_opt=["seccomp=unconfined", "apparmor=unconfined"], devices=["/dev/sda"],
                        ports=[{"port": 80, "proto": "tcp", "ip": "0.0.0.0"}], user="", readonly_rootfs=False, has_healthcheck=False)]
        for p in probes:
            seen |= set(rules(item(p, mem_limit_bytes=0, tag="latest")))
        self.assertEqual(seen, set(CA.RULES), "a rule nothing can raise is dead")

    def test_privileged_does_not_also_list_what_it_implies(self):
        r = rules(item(facts(privileged=True, cap_add=["SYS_ADMIN"])))
        self.assertIn("privileged", r)
        self.assertNotIn("caps_high", r)
        self.assertNotIn("new_privileges", r)

    def test_the_engine_socket_is_critical_read_only_too(self):
        for src in ("/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock", "/var/run/containerd/containerd.sock"):
            for rw in (True, False):
                r = rules(item(facts(mounts=[{"src": src, "dst": "/s", "rw": rw}])))
                self.assertEqual(r.get("engine_socket"), "critical", (src, rw))

    def test_how_bad_a_host_directory_is_depends_on_which_and_on_writable(self):
        def sev(src, rw):
            return rules(item(facts(mounts=[{"src": src, "dst": "/h", "rw": rw}]))).get("sensitive_mount")
        self.assertEqual(sev("/", True), "critical")
        self.assertEqual(sev("/", False), "medium")
        self.assertEqual(sev("/etc", True), "high")
        self.assertEqual(sev("/etc", False), "low")
        self.assertEqual(sev("/proc", True), "high")
        self.assertEqual(sev("/var/lib/docker", True), "high")
        for harmless in ("/etc/localtime", "/usr/share/zoneinfo", "/data", "/srv/app", "/var/lib/docker/volumes/x/_data", "/home/u"):
            self.assertIsNone(sev(harmless, True), harmless)

    def test_the_worst_of_several_mounts_decides(self):
        r = rules(item(facts(mounts=[{"src": "/", "rw": False}, {"src": "/etc", "rw": True}])))
        self.assertEqual(r["sensitive_mount"], "critical" if False else "high")
        r = rules(item(facts(mounts=[{"src": "/", "rw": True}, {"src": "/etc", "rw": False}])))
        self.assertEqual(r["sensitive_mount"], "critical")

    def test_capabilities(self):
        for cap in ("ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "BPF", "DAC_READ_SEARCH"):
            self.assertEqual(rules(item(facts(cap_add=[cap]))).get("caps_high"), "high", cap)
        for cap in ("NET_ADMIN", "NET_RAW", "SYS_TIME", "PERFMON"):
            self.assertEqual(rules(item(facts(cap_add=[cap]))).get("caps_medium"), "medium", cap)
        for cap in ("CHOWN", "NET_BIND_SERVICE", "KILL"):
            self.assertEqual(rules(item(facts(cap_add=[cap]))), {}, cap)
        r = rules(item(facts(cap_add=["NET_ADMIN", "SYS_ADMIN"])))
        self.assertIn("caps_high", r)
        self.assertNotIn("caps_medium", r, "one capability finding, the worse one")
        self.assertEqual(rules(item(facts(cap_add=["cap_sys_admin"]))).get("caps_high"), "high", "any spelling")

    def test_security_options_in_both_spellings(self):
        for opt in ("seccomp=unconfined", "seccomp:unconfined", "SECCOMP=UNCONFINED"):
            self.assertIn("seccomp_off", rules(item(facts(security_opt=[opt, "no-new-privileges"]))), opt)
        for opt in ("no-new-privileges", "no-new-privileges=true"):
            self.assertNotIn("new_privileges", rules(item(facts(security_opt=[opt]))), opt)
        self.assertNotIn("seccomp_off", rules(item(facts(security_opt=["seccomp=/etc/profile.json", "no-new-privileges"]))))

    def test_devices(self):
        self.assertEqual(rules(item(facts(devices=["/dev/dri/renderD128"]))).get("devices"), "low")
        self.assertEqual(rules(item(facts(devices=["/dev/kvm", "/dev/net/tun"]))).get("devices"), "low")
        for d in ("/dev/sda", "/dev/nvme0n1", "/dev/mem", "/dev/mapper/vg-root", "/dev/disk/by-id/x", "/dev/mmcblk0"):
            self.assertEqual(rules(item(facts(devices=[d]))).get("devices"), "medium", d)
        self.assertEqual(rules(item(facts(devices=["/dev/dri/card0", "/dev/sdb"]))).get("devices"), "medium", "the worst decides")

    def test_published_ports(self):
        def sev(ip, port):
            return rules(item(facts(ports=[{"port": port, "proto": "tcp", "ip": ip}]))).get("open_port")
        for ip in ("", "0.0.0.0", "::", "[::]"):
            self.assertEqual(sev(ip, 8080), "low", ip)
            self.assertEqual(sev(ip, 3306), "medium", ip)
        for ip in ("127.0.0.1", "192.168.1.5", "::1"):
            self.assertIsNone(sev(ip, 8080), ip)
        for port in (22, 2375, 5432, 6379, 27017):
            self.assertEqual(sev("", port), "medium", port)

    def test_user(self):
        for u, root in (("", True), ("0", True), ("root", True), ("0:0", True), ("root:root", True), ("ROOT", True),
                        ("1000", False), ("nginx", False), ("1000:1000", False), ("app:app", False)):
            self.assertEqual("runs_as_root" in rules(item(facts(user=u))), root, u)

    def test_findings_come_worst_first_with_a_title_and_evidence(self):
        out = CA.evaluate(item(facts(privileged=True, net_mode="host", cap_add=["NET_ADMIN"], user="", mounts=[{"src": "/etc", "rw": True}])))
        ranks = [CA.RANK[x["severity"]] for x in out]
        self.assertEqual(ranks, sorted(ranks))
        by = {x["rule"]: x for x in out}
        self.assertEqual(by["privileged"]["title"], "Runs privileged")
        self.assertIn("/etc (read-write)", by["sensitive_mount"]["detail"])
        for x in out:
            self.assertEqual(set(x), {"rule", "severity", "title", "detail"})
            self.assertIn(x["severity"], CA.SEVERITIES)

    def test_count_and_worst(self):
        out = CA.evaluate(item(facts(privileged=True, user="", net_mode="host")))
        c = CA.count(out)
        self.assertEqual((c["critical"], c["high"], c["low"]), (1, 1, 1))
        self.assertEqual(CA.worst(out), "critical")
        self.assertEqual(CA.worst([]), "")
        self.assertEqual(CA.count([None, {"severity": "x"}, {"severity": "low"}, 5]), {"critical": 0, "high": 0, "medium": 0, "low": 1})

    def test_the_rule_table_is_consistent(self):
        for rid, (sev, title) in CA.RULES.items():
            self.assertIn(sev, CA.SEVERITIES, rid)
            self.assertTrue(title and title[0].isupper() and not title.endswith("."), rid)
        self.assertEqual(len({t for _s, t in CA.RULES.values()}), len(CA.RULES), "one title each")


# ── the agent ─────────────────────────────────────────────────────────────────────────────────────────────────────────
DOCKER_INSPECT = [
    {   # a metrics agent: host network and pid, the root mounted read-only, an extra capability, a device
        "Id": "a" * 64,
        "Config": {"User": "", "Env": ["DB_PASSWORD=hunter2", "API_TOKEN=abc"], "Healthcheck": {"Test": ["CMD", "true"]}},
        "HostConfig": {"Privileged": False, "NetworkMode": "host", "PidMode": "host", "IpcMode": "private", "UsernsMode": "",
                       "CapAdd": ["SYS_PTRACE"], "CapDrop": None, "SecurityOpt": None, "ReadonlyRootfs": True,
                       "Devices": [{"PathOnHost": "/dev/kmsg", "PathInContainer": "/dev/kmsg", "CgroupPermissions": "rwm"}],
                       "PortBindings": {}},
        "Mounts": [{"Type": "bind", "Source": "/", "Destination": "/rootfs", "RW": False, "Propagation": "rslave"},
                   {"Type": "volume", "Name": "v", "Source": "/var/lib/docker/volumes/v/_data", "Destination": "/data", "RW": True}],
    },
    {   # a manager: the engine socket, published ports on all interfaces and one on loopback
        "Id": "b" * 64,
        "Config": {"User": "1000:1000", "Healthcheck": {"Test": ["NONE"]}},
        "HostConfig": {"Privileged": True, "NetworkMode": "bridge", "PidMode": "", "SecurityOpt": ["seccomp=unconfined"],
                       "PortBindings": {"9000/tcp": [{"HostIp": "", "HostPort": "9000"}],
                                        "8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8000"}],
                                        "53/udp": [{"HostIp": "0.0.0.0", "HostPort": "53"}, {"HostIp": "::", "HostPort": "bad"}]}},
        "Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True}],
    },
    {"Id": "c" * 64, "Config": {}, "HostConfig": {"NetworkMode": "default"}, "Mounts": []},
]


def load_agent():
    loader = importlib.machinery.SourceFileLoader("agent_ca_under_test", str(ROOT / "client" / "remotepower-agent.py"))
    spec = importlib.util.spec_from_loader("agent_ca_under_test", loader)
    agent = importlib.util.module_from_spec(spec)           # type: ignore[arg-type]
    loader.exec_module(agent)                                # type: ignore[union-attr]
    return agent


class TestTheAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()

    def setUp(self):
        self.agent._AUDIT_CACHE.clear()

    def test_facts_from_an_inspect_record(self):
        f = self.agent._audit_facts_from_inspect(DOCKER_INSPECT[0])
        self.assertEqual(f["v"], 1)
        self.assertEqual((f["net_mode"], f["pid_mode"]), ("host", "host"))
        self.assertNotIn("ipc_mode", f, "private is the default and is left out")
        self.assertEqual(f["cap_add"], ["SYS_PTRACE"])
        self.assertTrue(f["readonly_rootfs"])
        self.assertTrue(f["has_healthcheck"])
        self.assertEqual(f["devices"], ["/dev/kmsg"])
        self.assertEqual(f["mounts"][0], {"src": "/", "dst": "/rootfs", "rw": False})
        self.assertNotIn("rw", f["mounts"][1], "writable is the default")
        self.assertNotIn("user", f)
        self.assertNotIn("privileged", f)

    def test_the_environment_never_leaves_the_host(self):
        blob = json.dumps(self.agent._audit_facts_from_inspect(DOCKER_INSPECT[0]))
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("API_TOKEN", blob)
        self.assertNotIn("DB_PASSWORD", blob)

    def test_ports_and_the_engine_socket(self):
        f = self.agent._audit_facts_from_inspect(DOCKER_INSPECT[1])
        self.assertTrue(f["privileged"])
        self.assertEqual(f["user"], "1000:1000")
        self.assertNotIn("has_healthcheck", f, "Test NONE switches the check off")
        self.assertEqual(f["security_opt"], ["seccomp=unconfined"])
        ports = {(p["port"], p["proto"], p["ip"]) for p in f["ports"]}
        self.assertEqual(ports, {(9000, "tcp", ""), (8000, "tcp", "127.0.0.1"), (53, "udp", "0.0.0.0")}, "a port that is not a number is skipped")
        self.assertEqual(f["mounts"][0]["src"], "/var/run/docker.sock")

    def test_a_plain_container_sends_almost_nothing(self):
        self.assertEqual(self.agent._audit_facts_from_inspect(DOCKER_INSPECT[2]), {"v": 1})

    def test_the_agent_and_the_server_read_the_same_thing(self):
        for rec, want in ((DOCKER_INSPECT[0], {"host_network", "host_pid", "caps_high", "sensitive_mount", "devices", "runs_as_root"}),
                           (DOCKER_INSPECT[1], {"privileged", "engine_socket", "seccomp_off", "open_port"})):
            clean = CA.clean_facts(self.agent._audit_facts_from_inspect(rec))
            got = set(rules(item(clean)))
            self.assertTrue(want <= got, (want - got, got))
        self.assertNotIn("sensitive_mount", rules(item(CA.clean_facts(self.agent._audit_facts_from_inspect(DOCKER_INSPECT[1])))) | {})

    def test_only_a_real_true_is_privileged(self):
        for v in ("true", "false", "no", 1, "1", ["x"], {"a": 1}):
            f = self.agent._audit_facts_from_inspect({"HostConfig": {"Privileged": v, "ReadonlyRootfs": v}})
            self.assertNotIn("privileged", f, repr(v))
            self.assertNotIn("readonly_rootfs", f, repr(v))
        f = self.agent._audit_facts_from_inspect({"HostConfig": {"Privileged": True}})
        self.assertTrue(f["privileged"])

    def test_hostile_records_do_not_raise(self):
        for rec in ({}, {"HostConfig": "x", "Config": 5, "Mounts": "y"}, {"HostConfig": {"PortBindings": {"x": "y", "80/tcp": [None, 5]}}},
                    {"HostConfig": {"CapAdd": "SYS_ADMIN", "Devices": ["x", None, {"PathOnHost": None}]}, "Mounts": [None, {"Source": ""}, "x"]},
                    {"Config": {"Healthcheck": {"Test": None}}, "HostConfig": {"NetworkMode": None, "PortBindings": None}}):
            f = self.agent._audit_facts_from_inspect(rec)
            self.assertEqual(f["v"], 1)
            json.dumps(f)

    def _run(self, records, calls):
        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            return mock.Mock(returncode=0, stdout=json.dumps([r for r in records if r["Id"] in cmd]), stderr="")
        return fake_run

    def test_only_a_container_not_seen_before_is_inspected(self):
        calls = []
        with mock.patch.object(self.agent.subprocess, "run", self._run(DOCKER_INSPECT, calls)):
            first = self.agent._docker_audit_facts("docker", ["a" * 64, "b" * 64])
            second = self.agent._docker_audit_facts("docker", ["a" * 64, "b" * 64, "c" * 64])
            third = self.agent._docker_audit_facts("docker", ["a" * 64, "b" * 64, "c" * 64])
        self.assertEqual(len(calls), 2, "the third report is answered from what was kept")
        self.assertEqual(calls[0], ["docker", "inspect", "a" * 64, "b" * 64])
        self.assertEqual(calls[1], ["docker", "inspect", "c" * 64])
        self.assertEqual(set(first), {"a" * 64, "b" * 64})
        self.assertTrue(second["c" * 64]["v"] == 1 and third["a" * 64] == first["a" * 64])

    def test_a_container_that_is_gone_is_forgotten(self):
        with mock.patch.object(self.agent.subprocess, "run", self._run(DOCKER_INSPECT, [])):
            self.agent._docker_audit_facts("docker", ["a" * 64, "b" * 64])
            self.agent._docker_audit_facts("docker", ["b" * 64])
        self.assertEqual(set(self.agent._AUDIT_CACHE), {"b" * 64})

    def test_a_failure_leaves_the_container_unaudited_and_asks_again(self):
        calls = []

        def failing(cmd, **kw):
            calls.append(cmd)
            return mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch.object(self.agent.subprocess, "run", failing):
            out = self.agent._docker_audit_facts("docker", ["a" * 64])
            self.agent._docker_audit_facts("docker", ["a" * 64])
        self.assertEqual(out, {"a" * 64: None})
        self.assertEqual(len(calls), 2)
        with mock.patch.object(self.agent.subprocess, "run", lambda *a, **k: mock.Mock(returncode=0, stdout="not json", stderr="")):
            self.assertEqual(self.agent._docker_audit_facts("docker", ["z" * 64]), {"z" * 64: None})
        with mock.patch.object(self.agent.subprocess, "run", mock.Mock(side_effect=OSError("no docker"))):
            self.assertEqual(self.agent._docker_audit_facts("docker", ["y" * 64]), {"y" * 64: None})

    def test_the_kept_facts_are_bounded(self):
        many = [{"Id": f"{i:064x}", "Config": {}, "HostConfig": {}, "Mounts": []} for i in range(1, 160)]
        ids = [r["Id"] for r in many]
        with mock.patch.object(self.agent, "_AUDIT_CACHE_MAX", 50), \
                mock.patch.object(self.agent.subprocess, "run", lambda cmd, **k: mock.Mock(returncode=0, stdout=json.dumps(many[:100]), stderr="")):
            self.agent._docker_audit_facts("docker", ids[:100])
        self.assertLessEqual(len(self.agent._AUDIT_CACHE), 50)

    def test_the_listing_carries_the_facts(self):
        ps_line = json.dumps({"ID": "a" * 64, "Names": "agent", "Image": "gcr.io/cadvisor:v0.49", "Status": "Up 2 hours", "Ports": ""})
        real_run = self.agent.subprocess.run

        def fake_run(cmd, **kw):
            if cmd[1] == "ps":
                return mock.Mock(returncode=0, stdout=ps_line + "\n", stderr="")
            return real_run(cmd, **kw) if False else mock.Mock(returncode=1, stdout="", stderr="")
        with mock.patch.object(self.agent.subprocess, "run", fake_run), \
                mock.patch.object(self.agent, "_docker_stats", lambda p: {}), \
                mock.patch.object(self.agent, "_image_digests", lambda p: {}), \
                mock.patch.object(self.agent, "_docker_inspect_meta", lambda p, ids: {}), \
                mock.patch.object(self.agent, "_docker_audit_facts", lambda p, ids: {"a" * 64: {"v": 1, "net_mode": "host"}}):
            items = self.agent._docker_listing("docker", "docker")
        self.assertEqual(items[0]["audit"], {"v": 1, "net_mode": "host"})
        self.assertEqual(CA.clean_facts(items[0]["audit"])["net_mode"], "host")

    def test_extensionless_agent_is_the_same_file(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), (ROOT / "client" / "remotepower-agent.py").read_bytes())


# ── the server keeps it ───────────────────────────────────────────────────────────────────────────────────────────────
class TestTheContainerRecord(unittest.TestCase):

    def test_the_audit_is_kept_cleaned(self):
        c = containers.normalize_container({"name": "web", "image": "x", "audit": {"v": 1, "privileged": True, "cap_add": ["cap_sys_admin"],
                                                                                    "user": "a\x00b", "evil": "<b>"}})
        self.assertTrue(c["audit"]["privileged"])
        self.assertEqual(c["audit"]["cap_add"], ["SYS_ADMIN"])
        self.assertNotIn("evil", c["audit"])
        self.assertNotRegex(c["audit"]["user"], r"[\x00-\x1f]")

    def test_a_container_without_it_is_not_audited(self):
        for raw in (None, {}, {"v": 2}, "x", 5, []):
            self.assertIsNone(containers.normalize_container({"name": "web", "audit": raw})["audit"], repr(raw))
        self.assertIsNone(containers.normalize_container({"name": "web"})["audit"])

    def test_the_shape_of_the_accepts_store(self):
        fixed = store_shapes.normalize("container_audit_accepts.json", {"h1": [{"container": "a", "rule": "privileged", "ts": "5"}, {"rule": "x"}, "y"], "h2": "z"})
        self.assertEqual(fixed["h1"], [{"container": "a", "rule": "privileged", "ts": 5}])
        self.assertNotIn("h2", fixed)


# ── the handlers ──────────────────────────────────────────────────────────────────────────────────────────────────────
class _CA(_Base):
    STORES = _Base.STORES + ("CONTAINERS_FILE", "CONTAINER_AUDIT_ACCEPTS_FILE", "ROLES_FILE", "IGNORED_ITEMS_FILE")

    def setUp(self):
        super().setUp()
        os.environ["QUERY_STRING"] = ""
        self.audits = []
        api.audit_log = lambda *a, **k: self.audits.append(a)
        devs = api.load(api.DEVICES_FILE)
        devs["devB2"] = {"name": "b2", "tenant": "tenantB", "token_hash": "x", "monitored": False}
        api.save(api.DEVICES_FILE, devs)
        risky = facts(privileged=True, mounts=[{"src": "/var/run/docker.sock", "dst": "/s"}], user="")
        plain = facts()
        api.save(api.CONTAINERS_FILE, {
            "devB": {"ts": 100, "items": [dict(item(risky), name="portainer", image="portainer/portainer-ce", tag="2.21"),
                                          dict(item(plain), name="app", image="myapp", tag="1.0"),
                                          dict(item(None), name="old-agent"), "junk", None]},
            "devC": {"ts": 100, "items": [dict(item(risky), name="c-secret-container", image="c-image", tag="1")]},
            "devB2": {"ts": 100, "items": [dict(item(facts(net_mode="host")), name="b2-web")]},
            "ghost": {"ts": 100, "items": [dict(item(risky), name="orphan")]}})
        api.save(api.CONTAINER_AUDIT_ACCEPTS_FILE, {})
        api.save(api.ROLES_FILE, {"roles": []})
        api.save(api.USERS_FILE, dict(api.load(api.USERS_FILE), bviewer={"role": "viewer", "tenant_id": "tenantB"}))
        api._LOAD_CACHE.clear()

    def audit(self, who="badmin", query=""):
        os.environ["QUERY_STRING"] = query
        r = self.call(api.handle_container_audit, m="GET", who=who)
        os.environ["QUERY_STRING"] = ""
        return r

    def accept(self, dev, container, rule, accepted=True, who="badmin", note=""):
        return self.call(api.handle_device_container_audit, dev, body={"container": container, "rule": rule, "accepted": accepted, "note": note},
                         m="PUT", who=who)


class TestTheFleetView(_CA):

    def test_rows_findings_and_the_summary(self):
        st, d = self.audit()
        self.assertEqual(st, 200)
        by = {r["container"]: r for r in d["containers"]}
        self.assertEqual(set(by), {"portainer", "app", "b2-web"} - {"app"} | set(), "a clean container has no row at the default filter")
        p = by["portainer"]
        self.assertEqual((p["worst"], p["device"], p["image"], p["tag"]), ("critical", "b1", "portainer/portainer-ce", "2.21"))
        self.assertEqual({f["rule"] for f in p["findings"]} >= {"privileged", "engine_socket"}, True)
        self.assertEqual(d["not_audited"], 1)
        self.assertEqual(d["summary"]["critical"], 1)
        self.assertEqual(d["summary"]["high"], 1, "the host-network container")
        self.assertEqual(d["summary"]["clean"], 1, "app")
        self.assertIn("privileged", d["rules"])

    def test_worst_first(self):
        st, d = self.audit()
        self.assertEqual([r["container"] for r in d["containers"]], ["portainer", "b2-web"])

    def test_the_severity_floor(self):
        st, d = self.audit(query="min=critical")
        self.assertEqual([r["container"] for r in d["containers"]], ["portainer"])
        self.assertTrue(all(f["severity"] == "critical" for f in d["containers"][0]["findings"]))
        st, d = self.audit(query="min=high")
        self.assertEqual({r["container"] for r in d["containers"]}, {"portainer", "b2-web"})
        st, d = self.audit(query="min=nonsense")
        self.assertEqual(st, 200)
        self.assertEqual(d["summary"]["critical"], 1, "the summary does not move with the filter")

    def test_a_filter_on_host_container_or_image(self):
        for q, want in (("portainer", ["portainer"]), ("B2", ["b2-web"]), ("ce", ["portainer"]), ("nothing-like-it", [])):
            st, d = self.audit(query=f"q={q}")
            self.assertEqual([r["container"] for r in d["containers"]], want, q)

    def test_a_tenant_sees_only_its_own_hosts(self):
        for who in ("badmin", "bviewer"):
            st, d = self.audit(who)
            blob = json.dumps(d)
            self.assertNotIn("c-secret-container", blob, who)
            self.assertNotIn("orphan", blob, who)
            self.assertNotIn("c-image", blob, who)
        st, d = self.audit("cadmin")
        self.assertEqual([r["container"] for r in d["containers"]], ["c-secret-container"])
        self.assertNotIn("portainer", json.dumps(d))
        st, d = self.audit("platform")
        self.assertIn("c-secret-container", json.dumps(d))
        self.assertNotIn("orphan", json.dumps(d), "a host that no longer exists is not listed")

    def test_a_viewer_may_read_and_anonymous_may_not(self):
        self.assertEqual(self.audit("bviewer")[0], 200)
        self.assertEqual(self.audit(None)[0], 401)
        self.assertEqual(self.call(api.handle_container_audit, m="POST")[0], 405)

    def test_unmonitored_hosts_are_listed_and_flagged(self):
        st, d = self.audit()
        self.assertFalse({r["container"]: r for r in d["containers"]}["b2-web"]["monitored"])

    def test_an_ignored_host_is_left_out(self):
        api.save(api.IGNORED_ITEMS_FILE, {"devices": [{"id": "devB2", "ts": 1}]})
        st, d = self.audit()
        self.assertEqual([r["container"] for r in d["containers"]], ["portainer"])

    def test_a_hand_edited_store_does_not_break_it(self):
        api.save(api.CONTAINERS_FILE, {"devB": {"ts": "x", "items": [{"name": "a", "audit": "garbage"}, {"name": 5, "audit": {"v": 1}}, 7]},
                                       "devB2": "junk"})
        st, d = self.audit()
        self.assertEqual(st, 200, d)

    def test_the_answer_is_capped(self):
        many = [dict(item(facts(privileged=True)), name=f"c{i}") for i in range(100)]
        store = {f"dev{i}": {"ts": 1, "items": many} for i in range(14)}
        devs = api.load(api.DEVICES_FILE)
        for k in store:
            devs[k] = {"name": k, "tenant": "tenantB", "token_hash": "x"}
        api.save(api.DEVICES_FILE, devs)
        api.save(api.CONTAINERS_FILE, store)
        st, d = self.audit()
        self.assertEqual(len(d["containers"]), 1000)
        self.assertTrue(d["truncated"])


class TestAccepting(_CA):

    def test_an_accepted_finding_stays_listed_marked_and_stops_counting(self):
        self.assertEqual(self.accept("devB", "portainer", "engine_socket")[0], 200)
        st, d = self.audit()
        p = {r["container"]: r for r in d["containers"]}["portainer"]
        marked = {f["rule"]: f["accepted"] for f in p["findings"]}
        self.assertTrue(marked["engine_socket"])
        self.assertFalse(marked["privileged"])
        self.assertEqual(p["counts"]["critical"], 1, "privileged still counts")
        self.assertEqual(self.audits[-1][1:3], ("container_audit_accept", "device=devB container=portainer rule=engine_socket"))

    def test_a_container_whose_findings_are_all_accepted_stays_findable_and_stops_counting(self):
        self.accept("devB2", "b2-web", "host_network")
        st, d = self.audit(query="min=high")
        by = {r["container"]: r for r in d["containers"]}
        self.assertIn("b2-web", by, "or the acceptance could not be taken back")
        self.assertEqual(by["b2-web"]["counts"]["high"], 0)
        self.assertNotEqual(by["b2-web"]["worst"], "high", "what is left is the low findings")
        self.assertTrue(all(f["accepted"] for f in by["b2-web"]["findings"]))
        self.assertEqual(d["summary"]["high"], 0, "the header does not count it")
        self.assertEqual([r["container"] for r in d["containers"]][-1], "b2-web", "the rows that still count come first")

    def test_taking_it_back(self):
        self.accept("devB", "portainer", "engine_socket")
        st, d = self.accept("devB", "portainer", "engine_socket", accepted=False)
        self.assertEqual((st, d["accepted"]), (200, False))
        api._LOAD_CACHE.clear()
        self.assertEqual((api.load(api.CONTAINER_AUDIT_ACCEPTS_FILE) or {}), {}, "an empty list is not kept")
        self.assertEqual(self.audits[-1][1], "container_audit_unaccept")

    def test_accepting_twice_is_one_acceptance(self):
        self.accept("devB", "portainer", "privileged", note="first")
        self.accept("devB", "portainer", "privileged", note="second")
        api._LOAD_CACHE.clear()
        rows = api.load(api.CONTAINER_AUDIT_ACCEPTS_FILE)["devB"]
        self.assertEqual([(r["rule"], r["note"], r["by"]) for r in rows], [("privileged", "second", "badmin")])

    def test_only_an_administrator_may(self):
        self.assertEqual(self.accept("devB", "portainer", "privileged", who="bviewer")[0], 403)
        self.assertEqual(self.accept("devB", "portainer", "privileged", who=None)[0], 401)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.CONTAINER_AUDIT_ACCEPTS_FILE), {})

    def test_another_tenants_host_is_out_of_reach(self):
        # the route runs _enforce_device_scope before the handler; the handler checks the tenant itself as well
        st, d = self.accept("devC", "c-secret-container", "privileged", who="badmin")
        self.assertIn(st, (403, 404), (st, d))
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.CONTAINER_AUDIT_ACCEPTS_FILE), {})
        api.path_info = lambda: "/api/devices/devC/container-audit"
        st, d = self.call(api._enforce_device_scope, m="PUT", who="badmin")
        self.assertEqual(st, 403)

    def test_what_may_be_accepted(self):
        self.assertEqual(self.accept("devB", "portainer", "no-such-rule")[0], 400)
        self.assertEqual(self.accept("devB", "no-such-container", "privileged")[0], 404)
        self.assertEqual(self.accept("nope", "portainer", "privileged")[0], 404)
        self.assertEqual(self.accept("../x", "portainer", "privileged")[0], 404)
        for bad in ("yes", 1, None, "true", [], {}):
            st, _ = self.call(api.handle_device_container_audit, "devB", body={"container": "portainer", "rule": "privileged", "accepted": bad}, m="PUT")
            self.assertEqual(st, 400, repr(bad))
        st, _ = self.call(api.handle_device_container_audit, "devB", body={"container": "portainer", "rule": "privileged"}, m="PUT")
        self.assertEqual(st, 400, "a request that does not say what it wants changes nothing")
        self.assertEqual(self.call(api.handle_device_container_audit, "devB", m="POST")[0], 405)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.CONTAINER_AUDIT_ACCEPTS_FILE), {})

    def test_the_note_is_kept_short_and_clean(self):
        self.accept("devB", "portainer", "privileged", note="x" * 600 + "\x00")
        api._LOAD_CACHE.clear()
        note = api.load(api.CONTAINER_AUDIT_ACCEPTS_FILE)["devB"][0]["note"]
        self.assertLessEqual(len(note), 200)

    def test_at_most_so_many_on_one_host(self):
        rules_ = list(CA.RULES)
        many = [{"container": f"c{i}", "rule": rules_[i % len(rules_)], "by": "x", "ts": 1, "note": ""} for i in range(200)]
        api.save(api.CONTAINER_AUDIT_ACCEPTS_FILE, {"devB": many})
        st, d = self.accept("devB", "portainer", "privileged")
        self.assertEqual(st, 409, d)
        self.assertEqual(self.accept("devB", "portainer", "privileged", accepted=False)[0], 200, "taking one back is always allowed")

    def test_a_deleted_host_takes_its_acceptances_with_it(self):
        self.accept("devB", "portainer", "privileged")
        api._purge_device("devB")
        api._LOAD_CACHE.clear()
        self.assertNotIn("devB", api.load(api.CONTAINER_AUDIT_ACCEPTS_FILE) or {})


class TestRegistration(unittest.TestCase):

    def test_routes_store_and_baselines(self):
        import storage
        src = (ROOT / "server" / "cgi-bin" / "api.py").read_text()
        self.assertIn("('GET', '/api/containers/audit'): handle_container_audit", src)
        self.assertIn("'/api/devices/', '/container-audit', 'handle_device_container_audit'", src)
        self.assertIn("container_audit_accepts.json", storage.ENTITY_FILES)
        self.assertIn("container_audit_accepts.json", store_shapes.SHAPES)
        self.assertEqual((ROOT / "Makefile").read_text().count("server/cgi-bin/container_audit.py"), 2)
        self.assertIn("CONTAINER_AUDIT_ACCEPTS_FILE,   # 7.4.9", src)


def setUpModule():
    __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import env_guard

    env_guard.save(__name__)


def tearDownModule():
    import env_guard

    env_guard.restore(__name__)


if __name__ == "__main__":
    unittest.main()
