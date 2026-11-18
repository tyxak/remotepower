#!/usr/bin/env python3
"""What the agent can see: one structure per Linux host, cleaned by the server and shown in the host drawer.

Many features are invisible without some tool, and each missing one used to be its own single signal (psutil, ss) or an empty page. The
Linux agent now builds ONE structure and sends it with its system information: whether it runs as root, whether it runs in a container and
which host paths are mapped into it, which of 25 tools are on the host, which logs the threat sensor found and whether the agent can open
them (paths only), the distribution, the init system and the agent's own version and Python. The server cleans it, stores it with the
host, and answers the panel with each missing tool, the feature that needs it and an install hint for the host's package manager.

What this holds, by driving the real functions and handlers:

* The agent's builder, over fake PATH directories (some tools present, some not), fake /proc and os-release trees under a host root
  and the container flag: tool presence by executable file name, root by the effective uid, the container's mapped paths, and the
  host's own distribution and init read through host_path, not the machine the test runs on.
* Nothing is run to build it and no log is ever opened: the test records every open() the builder makes.
* A part that cannot be found out is left out and the rest is kept; the report is capped; it passes the server's cleaning unchanged.
* The server's cleaning keeps a fixed key set, fixed tool names and log kinds, booleans and short strings, and drops the rest.
* The panel names each missing tool's feature, marks an optional one, picks the hint for the host's package manager, never nags about
  another distribution's package manager, a systemd tool on a host without systemd, or the second of two tools that do the same job,
  and says "not available in a container" instead of an install command inside one.
* Through the real heartbeat and the real handler, as a tenant admin and as a read-only user.
* The agent's lists (tools, log kinds, mapped paths, caps) are the server's lists, and every string of the page is translated.
"""
import importlib.machinery
import importlib.util
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-capabilities-data-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

_TMP = tempfile.mkdtemp(prefix="rp-capabilities-")


def _load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = _load(ROOT / "client" / "remotepower-agent.py", "agent_capabilities_test")

_spec = importlib.util.spec_from_file_location("api_capabilities", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import agent_capabilities as caps_mod  # noqa: E402  (the server's own table and cleaning)
import env_guard  # noqa: E402
from i18n_engine import dict_rows  # noqa: E402
from routing_harness import routes_to  # noqa: E402

_LANGS = ("zh", "hi", "es", "ar", "de", "fr")


def setUpModule():
    env_guard.save(__name__)
    logging.disable(logging.CRITICAL)


def tearDownModule():
    logging.disable(logging.NOTSET)
    env_guard.restore(__name__)
    shutil.rmtree(_TMP, ignore_errors=True)


def make_tools(directory, *names):
    """Executable files named `names` in `directory`."""
    Path(directory).mkdir(parents=True, exist_ok=True)
    for n in names:
        p = Path(directory) / n
        p.write_text("#!/bin/sh\nexit 0\n")
        p.chmod(0o755)


# An instrument the code under test cannot fool. An audit hook sees the interpreter's own events: every file open however it was asked
# for (open, io.open, os.open, Path.read_text) and every process start (subprocess, os.system, exec, spawn). A patch of builtins.open or
# subprocess.run sees only the door that was patched, and a refusal raised inside the code under test can be swallowed by that code's own
# `except Exception`, which hides the very thing the test looks for. Hooks cannot be removed, so this one records only inside `watching()`.
_WATCH = {"on": False, "opened": [], "started": []}
_STARTS = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty")


def _audit(event, args):
    if not _WATCH["on"]:
        return
    if event == "open":
        _WATCH["opened"].append(str(args[0]))
    elif event in _STARTS:
        _WATCH["started"].append(event)


sys.addaudithook(_audit)


class watching:
    """`with watching() as w:` then w["opened"] (paths) and w["started"] (events) hold what the block did."""

    def __enter__(self):
        _WATCH.update(on=True, opened=[], started=[])
        return _WATCH

    def __exit__(self, *exc):
        _WATCH["on"] = False


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="case-", dir=_TMP))


# ── the agent's builder ──────────────────────────────────────────────────────
class TestTheAgentsReport(_Tmp):

    def report(self, dirs, **patches):
        stack = [mock.patch.object(agent, "IN_CONTAINER", patches.get("container", False))]
        if "host_root" in patches:
            stack.append(mock.patch.object(agent, "HOST_ROOT", patches["host_root"]))
        for p in stack:
            p.start()
            self.addCleanup(p.stop)
        return agent.collect_capabilities(tool_dirs=dirs, threat_cfg=patches.get("threat_cfg"))

    def test_a_tool_is_present_when_an_executable_file_of_its_name_is_on_the_path(self):
        a, b = self.d / "a", self.d / "b"
        make_tools(a, "ss", "smartctl", "ufw", "apt-get", "systemctl")
        make_tools(b, "firewall-cmd", "yum")
        tools = self.report([a, b])["tools"]
        present = {k for k, v in tools.items() if v}
        self.assertEqual(present, {"ss", "smartctl", "ufw", "apt", "systemctl", "firewalld", "dnf"})
        self.assertEqual({k for k, v in tools.items() if not v}, set(caps_mod.TOOL_KEYS) - present)

    def test_apt_is_apt_get_firewalld_is_firewall_cmd_and_dnf_is_any_of_three(self):
        for name, key in (("apt-get", "apt"), ("firewall-cmd", "firewalld"), ("dnf", "dnf"), ("dnf5", "dnf"), ("yum", "dnf")):
            with self.subTest(name=name):
                d = self.d / name
                make_tools(d, name)
                tools = self.report([d])["tools"]
                self.assertTrue(tools[key], key)
                self.assertEqual(sum(1 for v in tools.values() if v), 1, "one file is one tool")

    def test_a_file_that_is_not_an_executable_file_is_not_a_tool(self):
        d = self.d / "bin"
        d.mkdir()
        (d / "ss").write_text("not executable")                     # present, mode 644
        (d / "nft").mkdir()                                           # a directory of that name
        os.symlink(str(d / "gone"), str(d / "smartctl"))              # a link to nothing
        make_tools(d, "target-tool")
        os.symlink(str(d / "target-tool"), str(d / "lsblk"))          # a link to an executable file does count
        tools = self.report([d])["tools"]
        self.assertEqual({k for k, v in tools.items() if v}, {"lsblk"})

    def test_the_tools_are_the_servers_tools_in_the_servers_order(self):
        tools = self.report([self.d])["tools"]
        self.assertEqual(tuple(tools), caps_mod.TOOL_KEYS)
        self.assertEqual(tuple(k for k, _names in agent.CAPABILITY_TOOLS), caps_mod.TOOL_KEYS)

    def test_the_agents_lists_are_the_servers_lists(self):
        self.assertEqual(tuple(agent.CAPABILITY_LOG_KINDS), tuple(caps_mod.LOG_KINDS))
        self.assertEqual(tuple(agent.CAPABILITY_MAPPED), caps_mod.MAPPED_PATHS)
        self.assertEqual(agent.CAPABILITY_LOG_CAP, caps_mod.LOG_CAP)
        self.assertEqual(agent.CAPABILITY_PATH_CAP, caps_mod.PATH_CAP)

    def test_root_is_the_effective_user_id(self):
        for uid, expected in ((0, True), (1000, False)):
            with mock.patch.object(agent.os, "geteuid", return_value=uid):
                self.assertIs(self.report([self.d])["root"], expected)

    def test_a_native_agent_is_not_a_container_and_reports_no_mapped_paths(self):
        rep = self.report([self.d])
        self.assertIs(rep["container"], False)
        self.assertNotIn("mapped", rep)

    def _host_tree(self):
        host = self.d / "host"
        (host / "etc").mkdir(parents=True)
        (host / "etc" / "os-release").write_text('NAME="Debian"\nID=debian\nID_LIKE="ubuntu debian"\nVERSION_ID="12"\n')
        (host / "proc" / "1").mkdir(parents=True)
        (host / "proc" / "1" / "comm").write_text("openrc-init\n")       # not this machine's: a read of the wrong /proc shows
        (host / "var" / "log" / "nginx").mkdir(parents=True)
        (host / "sys").mkdir()                       # mapped but empty: nothing to read
        return host

    def test_a_container_says_which_host_paths_are_mapped_and_reads_the_host_not_its_own_image(self):
        host = self._host_tree()
        (host / "var" / "log" / "x").write_text("x")
        rep = self.report([self.d], container=True, host_root=str(host))
        self.assertIs(rep["container"], True)
        self.assertEqual(rep["mapped"], ["/etc", "/proc", "/var/log"], "/sys is empty and /var/lib is not there")
        self.assertEqual((rep["distro"], rep["like"], rep["init"]), ("debian", "ubuntu debian", "openrc-init"),
                         "read from the host tree: the machine running this test has its own os-release and init")

    def test_the_logs_the_sensor_found_and_whether_they_can_be_opened_and_never_a_line_of_them(self):
        host = self._host_tree()
        canary = "CANARY-LOG-LINE-0451 GET /secret HTTP/1.1"
        (host / "var" / "log" / "nginx" / "access.log").write_text(canary + "\n")
        (host / "etc" / "nginx").mkdir()
        (host / "etc" / "nginx" / "nginx.conf").write_text(
            "events {}\nhttp {\n  access_log /var/log/nginx/site.log;\n  server { listen 80; }\n}\n")
        with watching() as seen:
            rep = self.report([self.d], container=True, host_root=str(host))
        by_path = {e["path"]: e for e in rep["logs"]}
        self.assertEqual(by_path["/var/log/nginx/access.log"], {"kind": "web", "path": "/var/log/nginx/access.log", "readable": True})
        self.assertEqual(by_path["/var/log/nginx/site.log"]["readable"], False, "the config names it and it is not there")
        self.assertNotIn(canary, json.dumps(rep))
        logs_opened = [o for o in seen["opened"] if o.endswith(".log")]
        self.assertEqual(logs_opened, [], "a log file was opened: " + ", ".join(logs_opened))
        self.assertTrue([o for o in seen["opened"] if o.endswith("nginx.conf")], "the configuration the logs are found from is read")

    def test_the_instrument_sees_every_way_to_open_a_file_and_to_start_a_process(self):
        """The control for the two tests that say something did not happen: the same hook records a known open by each route and a
        known process start, so an empty record there is an answer and not a blind instrument."""
        probe = self.d / "probe.log"
        probe.write_text("x")
        with watching() as seen:
            open(probe).close()
            probe.read_text()
            os.close(os.open(str(probe), os.O_RDONLY))
            subprocess.run([sys.executable, "-c", "pass"], check=True)
        self.assertEqual([o for o in seen["opened"] if o == str(probe)], [str(probe)] * 3)
        self.assertIn("subprocess.Popen", seen["started"])
        with watching() as seen:
            pass
        self.assertEqual((seen["opened"], seen["started"]), ([], []))

    def test_a_log_the_operator_added_to_the_sensor_is_reported_too(self):
        """The server sends the sensor extra log paths; the sensor reads them, so the panel says whether the agent can."""
        host = self._host_tree()
        (host / "var" / "log" / "custom").mkdir()
        (host / "var" / "log" / "custom" / "app.log").write_text("x\n")
        rep = self.report([self.d], container=True, host_root=str(host), threat_cfg={"enabled": True, "paths": ["/var/log/custom/app.log"]})
        self.assertIn({"kind": "web", "path": "/var/log/custom/app.log", "readable": True}, rep["logs"])
        plain = self.report([self.d], container=True, host_root=str(host))
        self.assertNotIn("/var/log/custom/app.log", [e["path"] for e in plain["logs"]], "only the sensor's own setting adds it")
        for odd in ([], "x", 5, {"paths": "not a list"}, {"paths": ["/etc/passwd", "relative.log", 7, "/var/log/custom/gone.log"]}):
            with self.subTest(cfg=odd):
                rep = self.report([self.d], container=True, host_root=str(host), threat_cfg=odd)
                self.assertNotIn("/etc/passwd", [e["path"] for e in rep["logs"]], "a path outside /var/log is not the sensor's to read")
                self.assertEqual(caps_mod.clean(rep), rep)

    def test_a_log_the_agent_may_not_open_is_reported_as_not_readable(self):
        if os.geteuid() == 0:
            self.skipTest("root can open anything; the configured-but-missing case above covers readable=False")
        host = self._host_tree()
        log = host / "var" / "log" / "nginx" / "access.log"
        log.write_text("x\n")
        log.chmod(0)
        self.addCleanup(lambda: log.chmod(0o644))
        rep = self.report([self.d], container=True, host_root=str(host))
        self.assertEqual({e["path"]: e["readable"] for e in rep["logs"]}["/var/log/nginx/access.log"], False)

    def test_a_part_that_cannot_be_found_out_is_left_out_and_the_rest_is_kept(self):
        make_tools(self.d / "bin", "ss")
        with mock.patch.object(agent, "_ts_discover", side_effect=RuntimeError("boom")):
            rep = self.report([self.d / "bin"])
        self.assertNotIn("logs", rep)
        self.assertTrue(rep["tools"]["ss"])
        with mock.patch.object(agent, "get_os_release", side_effect=OSError("boom")):
            rep = self.report([self.d / "bin"])
        self.assertNotIn("distro", rep)
        self.assertIn("logs", rep)
        with mock.patch.object(agent.os, "geteuid", side_effect=OSError("boom")):
            self.assertNotIn("root", self.report([self.d / "bin"]))

    def test_the_report_is_capped(self):
        many = {"web": [{"path": f"/var/log/site{i}.log"} for i in range(100)], "err": [{"path": "/" + "x" * 500}]}
        with mock.patch.object(agent, "_ts_discover", return_value=many):
            rep = self.report([self.d])
        self.assertEqual(len(rep["logs"]), agent.CAPABILITY_LOG_CAP)
        self.assertTrue(all(len(e["path"]) <= agent.CAPABILITY_PATH_CAP for e in rep["logs"]))
        with mock.patch.object(agent, "_ts_discover", return_value={"web": [{"path": "/" + "y" * 500}]}):
            rep = self.report([self.d])
        self.assertEqual(len(rep["logs"][0]["path"]), agent.CAPABILITY_PATH_CAP)

    def test_a_path_that_is_not_a_path_is_not_a_log(self):
        junk = {"web": [{"path": "relative/path.log"}, {"path": 5}, {"path": ""}, "text", None, {}], "f2b": [{"path": "/var/log/fail2ban.log"}]}
        with mock.patch.object(agent, "_ts_discover", return_value=junk):
            rep = self.report([self.d])
        self.assertEqual([e["path"] for e in rep["logs"]], ["/var/log/fail2ban.log"])

    def test_nothing_is_run_to_build_it(self):
        """Not in a fixture with every tool present, a web server's configuration, fail2ban and a container either: the places a probe
        would be tempting (`nginx -T`, `fail2ban-client get logtarget`, `docker info`)."""
        host = self._host_tree()
        make_tools(self.d / "bin", *[name for _key, names in agent.CAPABILITY_TOOLS for name in names])
        (host / "etc" / "fail2ban").mkdir()
        (host / "etc" / "fail2ban" / "fail2ban.conf").write_text("[Definition]\nlogtarget = /var/log/fail2ban.log\n")
        (host / "etc" / "nginx").mkdir()
        (host / "etc" / "nginx" / "nginx.conf").write_text("http {\n  access_log /var/log/nginx/access.log;\n}\n")
        for kwargs in ({}, {"container": True, "host_root": str(host)}):
            with self.subTest(**{k: bool(v) for k, v in kwargs.items()}), watching() as seen:
                rep = self.report([self.d / "bin"], **kwargs)
            self.assertIn("tools", rep)
            self.assertTrue(all(rep["tools"].values()), "every tool was there, and none was asked to run")
            self.assertEqual(seen["started"], [], "a process was started while building the report")

    def test_the_report_is_what_the_servers_cleaning_keeps_unchanged(self):
        host = self._host_tree()
        make_tools(self.d / "bin", "ss", "apt-get")
        rep = self.report([self.d / "bin"], container=True, host_root=str(host))
        self.assertEqual(caps_mod.clean(rep), rep, "a key the server drops is a signal that never arrives")
        native = self.report([self.d / "bin"])
        self.assertEqual(caps_mod.clean(native), native)

    def test_the_agents_own_version_and_python_ride_along(self):
        rep = self.report([self.d])
        self.assertEqual(rep["agent"], {"version": agent.VERSION, "python": platform.python_version()})

    def test_the_default_lookup_does_not_raise_and_finds_what_is_on_this_machine(self):
        rep = agent.collect_capabilities()
        self.assertEqual(set(rep["tools"]), set(caps_mod.TOOL_KEYS))
        sh = shutil.which("sh")
        self.assertIsNotNone(sh)
        self.assertIn(os.path.dirname(sh), agent._capability_dirs())

    def test_the_shared_lookup_is_told_when_a_tool_has_come_or_gone(self):
        """_which remembers its answer for the life of the process: a tool installed after the agent started was missed by every
        collector until a restart. The report forgets an answer that is wrong now."""
        make_tools(self.d / "bin", "smartctl")
        cache = agent._which.__defaults__[0]
        saved = dict(cache)
        self.addCleanup(lambda: (cache.clear(), cache.update(saved)))
        cache["smartctl"] = None                                  # remembered as missing, and it is there now
        cache["ipmitool"] = "/usr/bin/ipmitool"                   # remembered as there, and it is gone
        cache["sensors"] = None                                   # missing then and now
        with mock.patch.object(agent, "_capability_dirs", lambda: [str(self.d / "bin")]), mock.patch.object(agent, "IN_CONTAINER", False), \
                mock.patch.dict(os.environ, {"PATH": str(self.d / "bin")}):
            agent.collect_capabilities()
            self.assertNotIn("smartctl", cache)
            self.assertNotIn("ipmitool", cache)
            self.assertIn("sensors", cache, "an answer that is still right is left alone")
            # PATH is searched first, so this holds on a machine that has a real smartctl too
            self.assertEqual(agent._which("smartctl"), str(self.d / "bin" / "smartctl"), "the next lookup finds the tool that was installed")


# ── the agent's loop ─────────────────────────────────────────────────────────
class _Stop(BaseException):
    """Not an Exception, so nothing in the agent's loop can swallow it."""


import threading as threading_real  # noqa: E402


class _NoThreads:
    class Thread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

    def __getattr__(self, name):
        return getattr(threading_real, name)


_QUIET = (
    "get_metrics", "get_host_health", "get_smart_status", "get_kernel_status", "get_hardware_inventory", "get_gpu_status",
    "get_cert_files", "get_local_accounts", "get_ups_status", "get_av_status", "get_ecc_errors", "get_zram",
    "get_autoupdate_posture", "get_platform_health", "get_disk_encryption", "get_ssh_config", "get_ssh_hostkeys", "get_repo_files",
    "get_usb_devices", "get_battery", "get_chassis", "get_journal", "collect_sudo_events", "collect_peer_connections",
    "collect_lldp_neighbors", "get_containers", "get_compose_projects", "get_docker_disk_usage", "get_helm_releases",
    "send_package_list", "get_mdns_services", "collect_acme_state", "collect_custom_metrics", "get_patch_info",
    "collect_disk_io", "collect_net_io", "get_network_info", "get_host_addresses", "collect_dmesg_logs", "collect_apt_history",
    "collect_web_access_logs", "submit_unit_logs", "detect_auto_watch_units", "get_local_ip", "collect_cpu_time",
    "get_third_party_updates", "collect_backup_verify", "run_restore_drills", "_burst_live_samples", "discover_apps",
    "get_os_info", "get_uptime", "get_uptime_seconds", "collect_disk_usage",
)


def drive(rounds, capabilities, every=2, threat_cfg=None, calls=None):
    """The real heartbeat() loop for `rounds` polls with a system information report on every `every`th poll. `capabilities` is a list
    of what collect_capabilities answers, one per call (an Exception in it is raised). `threat_cfg` is what the server answers as the
    threat sensor's setting, and `calls` collects the keyword arguments of every call of the collector. Returns every heartbeat body
    the agent sent."""
    tmp = Path(tempfile.mkdtemp(prefix="hb-", dir=_TMP))
    state = {"n": 0, "calls": 0}
    posts = []

    def post(url, data, timeout=10):
        if url.endswith("/api/heartbeat") and "cmd_output" not in (data or {}):
            state["n"] += 1
            posts.append(json.loads(json.dumps(data)))
            if state["n"] > rounds:
                raise _Stop()
            return dict({"delta_ok": True}, **({"threat_sensor": threat_cfg} if threat_cfg is not None else {}))
        return {}

    def fake_caps(*a, **k):
        if calls is not None:
            calls.append(k)
        item = capabilities[min(state["calls"], len(capabilities) - 1)]
        state["calls"] += 1
        if isinstance(item, Exception):
            raise item
        return item

    def quiet(*a, **k):
        return {}

    patches = [
        mock.patch.object(agent, "http_post", post), mock.patch.object(agent, "check_for_update", lambda *a, **k: False),
        mock.patch.object(agent, "threading", _NoThreads()), mock.patch.object(agent, "STATE_DIR", tmp),
        mock.patch.object(agent, "_audit_mode", lambda: False), mock.patch.object(agent, "_require_signed_commands", lambda: False),
        mock.patch.object(agent, "collect_capabilities", fake_caps), mock.patch.object(agent, "SYSINFO_EVERY", every),
        mock.patch.object(agent, "_PKG_REFRESH_LAST", None),
    ]
    for name in _QUIET:
        if hasattr(agent, name):
            patches.append(mock.patch.object(agent, name, quiet))
    for p in patches:
        p.start()
    try:
        agent.heartbeat({"server_url": "https://rp.example", "device_id": "DEVCAPS", "token": "t" * 32}, interval=0)
    except _Stop:
        pass
    finally:
        for p in reversed(patches):
            p.stop()
    return posts


CAPS = {"root": True, "container": False, "tools": {"ss": True}, "agent": {"version": "8.0.1", "python": "3.12.3"}}


class TestTheAgentsLoop(unittest.TestCase):

    def test_the_report_goes_with_the_system_information_and_only_with_it(self):
        posts = drive(rounds=3, capabilities=[CAPS], every=2)
        self.assertEqual(posts[0]["sysinfo"]["capabilities"], CAPS)
        self.assertTrue(all(("sysinfo" in p) == (i in (0, 1)) for i, p in enumerate(posts[:3])), "a report on polls 1 and 2 only")

    def test_a_report_that_changed_nothing_is_left_out_and_one_that_changed_is_sent_whole(self):
        """The agent learns the server takes omissions from its first answer, and remembers what the server confirmed from the next
        report on, so the third report is the first that can be left out."""
        newer = dict(CAPS, tools={"ss": True, "nft": True})
        posts = drive(rounds=5, capabilities=[CAPS, CAPS, CAPS, newer], every=1)
        self.assertEqual(posts[1]["sysinfo"].get("capabilities"), CAPS, "the server has not confirmed one yet")
        third = posts[2]
        self.assertNotIn("capabilities", third["sysinfo"], "unchanged: the server merges its stored copy back")
        self.assertIn("capabilities", third.get("sysinfo_omitted", {}))
        self.assertEqual(posts[3]["sysinfo"].get("capabilities"), newer, "changed: sent whole")
        self.assertNotIn("capabilities", posts[3].get("sysinfo_omitted", {}))

    def test_a_report_that_cannot_be_built_leaves_the_heartbeat_going(self):
        posts = drive(rounds=3, capabilities=[RuntimeError("boom")])
        self.assertEqual(len(posts), 4, "the loop went on past the failure")
        self.assertNotIn("capabilities", posts[0]["sysinfo"])
        self.assertIn("uptime", posts[0]["sysinfo"])

    def test_the_threat_sensors_setting_from_the_server_reaches_the_report(self):
        """The sensor's extra log paths come from the server's answer, so the first report (built before any answer has been read) has no
        setting, and every one after it carries the latest."""
        cfg = {"enabled": True, "paths": ["/var/log/custom/app.log"]}
        calls = []
        drive(rounds=3, capabilities=[CAPS], every=1, threat_cfg=cfg, calls=calls)
        self.assertGreaterEqual(len(calls), 3)
        self.assertIsNone(calls[0].get("threat_cfg"))
        self.assertEqual(calls[1].get("threat_cfg"), cfg)
        self.assertEqual(calls[-1].get("threat_cfg"), cfg)
        calls = []
        drive(rounds=2, capabilities=[CAPS], every=1, calls=calls)
        self.assertEqual([c.get("threat_cfg") for c in calls], [None] * len(calls), "a server that sends none leaves the sensor's own discovery")


# ── the server's cleaning ────────────────────────────────────────────────────
FULL = {
    "root": False, "container": True, "init": "systemd", "distro": "debian", "like": "ubuntu debian",
    "mapped": ["/etc", "/var/log"],
    "tools": {"ss": True, "smartctl": False, "ufw": True},
    "logs": [{"kind": "web", "path": "/var/log/nginx/access.log", "readable": True},
             {"kind": "f2b", "path": "/var/log/fail2ban.log", "readable": False}],
    "agent": {"version": "8.0.1", "python": "3.12.3"},
}


class TestTheServersCleaning(unittest.TestCase):

    def test_a_good_report_is_kept_as_it_is(self):
        self.assertEqual(caps_mod.clean(FULL), FULL)

    def test_what_is_not_a_report_is_not_one(self):
        for bad in (None, "x", 5, [], [1], True, {}, {"unknown": 1}):
            self.assertIsNone(caps_mod.clean(bad), bad)

    def test_a_flag_must_be_a_real_boolean(self):
        out = caps_mod.clean({"root": "yes", "container": 1, "tools": {"ss": "true", "nft": 1, "ufw": True}})
        self.assertNotIn("root", out)
        self.assertNotIn("container", out)
        self.assertEqual(out["tools"], {"ufw": True})

    def test_a_tool_the_server_has_no_row_for_is_dropped(self):
        out = caps_mod.clean({"tools": {"ss": True, "rm -rf": True, "<b>x</b>": False, "": True}})
        self.assertEqual(out["tools"], {"ss": True})

    def test_a_name_is_a_short_lower_case_word(self):
        for bad in ("Systemd", "sys temd", "x" * 33, "a;b", "<b>", "", 5, ["debian"], None):
            self.assertNotIn("init", caps_mod.clean({"root": True, "init": bad}), bad)
            self.assertNotIn("distro", caps_mod.clean({"root": True, "distro": bad}), bad)
        out = caps_mod.clean({"like": "ubuntu  debian <b> a;b rhel fedora centos"})
        self.assertEqual(out["like"], "ubuntu debian", "four words are the most looked at, and a word that is not one is dropped")
        self.assertEqual(caps_mod.clean({"like": "ubuntu debian rhel fedora centos"})["like"], "ubuntu debian rhel fedora")

    def test_a_log_has_a_known_kind_a_real_boolean_and_a_path_that_starts_with_a_slash(self):
        junk = [{"kind": "bogus", "path": "/a", "readable": True}, {"kind": "web", "path": "relative", "readable": True},
                {"kind": "web", "path": "/a", "readable": "yes"}, {"kind": "web", "path": 5, "readable": True},
                {"kind": "web", "path": "", "readable": True}, "text", None, 7, {"kind": "err", "path": "/ok", "readable": False}]
        self.assertEqual(caps_mod.clean({"logs": junk})["logs"], [{"kind": "err", "path": "/ok", "readable": False}])

    def test_a_kind_that_is_a_list_or_a_dict_or_not_text_leaves_that_log_out_and_keeps_the_rest(self):
        """The kind is looked up in a dict, which hashes it: a list or a dict (what a JSON body can hold) raised TypeError, and clean() is
        called inside the heartbeat's device update, so the whole report of the host was refused with a 500 and nothing of it was stored.
        The docstring says a wrong part is left out and the rest is kept; every kind of value that is not a known word is such a part."""
        good = {"kind": "err", "path": "/ok", "readable": False}
        for kind in (["web"], [], {"a": 1}, {}, [["web"]], {"kind": "web"}, None, True, False, 0, 1.5, float("nan"), b"web", ("web",)):
            with self.subTest(kind=repr(kind)):
                out = caps_mod.clean({"root": True, "logs": [{"kind": kind, "path": "/var/log/x.log", "readable": True}, good]})
                self.assertEqual(out, {"root": True, "logs": [good]})
        with self.assertRaises(TypeError, msg="the premise of this test: a dict lookup hashes what it is given"):
            [] in caps_mod.LOG_KINDS

    def test_a_path_loses_its_control_characters_and_is_cut(self):
        out = caps_mod.clean({"logs": [{"kind": "web", "path": "/var/log/a\n\x00b .log", "readable": True},
                                       {"kind": "web", "path": "/" + "z" * 500, "readable": True}]})
        self.assertEqual(out["logs"][0]["path"], "/var/log/ab.log")
        self.assertEqual(len(out["logs"][1]["path"]), caps_mod.PATH_CAP)

    def test_the_log_list_is_capped(self):
        out = caps_mod.clean({"logs": [{"kind": "web", "path": f"/l{i}", "readable": True} for i in range(500)]})
        self.assertEqual(len(out["logs"]), caps_mod.LOG_CAP)

    def test_mapped_paths_come_from_the_fixed_set_in_its_order(self):
        out = caps_mod.clean({"mapped": ["/var/log", "/etc", "/root", "../etc", "/etc", 5]})
        self.assertEqual(out["mapped"], ["/etc", "/var/log"])

    def test_versions_are_short_version_strings(self):
        out = caps_mod.clean({"agent": {"version": "8.0.1", "python": "3.12.3+local", "extra": "x"}})
        self.assertEqual(out["agent"], {"version": "8.0.1", "python": "3.12.3+local"})
        for bad in ("<script>", "x" * 40, " 8", "", 8, ["8"]):
            self.assertNotIn("agent", caps_mod.clean({"agent": {"version": bad}, "root": True}), bad)

    def test_a_key_the_server_has_no_use_for_does_not_survive(self):
        out = caps_mod.clean(dict(FULL, secret="s3cret", token="t", env={"PATH": "/x"}, output="y" * 9999))
        self.assertEqual(set(out), set(FULL))

    def test_a_wrong_part_is_left_out_and_the_rest_is_kept(self):
        out = caps_mod.clean({"root": True, "tools": "not a dict", "logs": "nope", "mapped": 5, "agent": [1]})
        self.assertEqual(out, {"root": True})


# The values a JSON body can hold at any position, and a few a hostile one would pick: every type, the unhashable ones (a list and a dict
# cannot be a dict key or a set member), values at the edge of a number, text with a newline or a right-to-left override.
WRONG = (None, True, False, 0, -1, 7, 1.5, float("nan"), float("inf"), 10 ** 30, "", "x", "web", "debian", "a" * 300, "‮/etc",
         "debian\n", "8.0.2\n", [], [[]], ["web"], [None], {}, {"a": 1}, {"kind": "web"}, [{}], [[1, 2]], [{"kind": ["web"]}])
GOOD = {"root": True, "container": False, "init": "systemd", "distro": "debian", "like": "debian", "mapped": ["/etc"],
        "tools": {"ss": True, "smartctl": False}, "logs": [{"kind": "web", "path": "/var/log/a.log", "readable": True}],
        "agent": {"version": "8.0.2", "python": "3.12.3"}}


def wrong_reports():
    """The good report with one position at a time replaced by each wrong value, and the same positions nested one level in."""
    for key in GOOD:
        for v in WRONG:
            yield f"{key}={v!r}", dict(GOOD, **{key: v})
    for v in WRONG:
        yield f"tools key/value {v!r}", dict(GOOD, tools={"ss": v, "smartctl": v})
        yield f"logs kind {v!r}", dict(GOOD, logs=[{"kind": v, "path": "/x", "readable": True}])
        yield f"logs path {v!r}", dict(GOOD, logs=[{"kind": "web", "path": v, "readable": True}])
        yield f"logs readable {v!r}", dict(GOOD, logs=[{"kind": "web", "path": "/x", "readable": v}])
        yield f"logs entry {v!r}", dict(GOOD, logs=[v])
        yield f"agent values {v!r}", dict(GOOD, agent={"version": v, "python": v})
        yield f"mapped element {v!r}", dict(GOOD, mapped=[v])
        yield f"like and distro {v!r}", dict(GOOD, like=v, distro=v)


class TestAWrongTypedReportIsNeverRefused(unittest.TestCase):
    """The class behind a 500 on a heartbeat: a cleaner that raises on a value of the wrong type instead of leaving it out. clean() runs
    inside the device update, so one such value froze the whole system information of the host (packages, ports, posture), while the
    host went on beating and looked online. A wrong part is left out and the rest is kept, at every position and for every type."""

    def test_the_population_is_the_reports_wrong_at_every_position(self):
        """The control for the tests below: they run over this many reports, and the premise (a dict lookup raises on an unhashable
        key) holds, so an empty or a shrunk population cannot read as success."""
        reports = list(wrong_reports())
        self.assertGreater(len(reports), 400)
        self.assertEqual(len({name for name, _r in reports}), len(reports), "a position and value tried twice")
        self.assertTrue(any(isinstance(v, (list, dict)) for _n, r in reports for v in r.values()))
        for unhashable in ([], {}):
            with self.assertRaises(TypeError):
                {"a": 1}[unhashable]

    def test_clean_never_raises_and_keeps_only_what_it_can_vouch_for(self):
        for name, rec in wrong_reports():
            with self.subTest(position=name):
                out = caps_mod.clean(rec)
                self.assertTrue(out is None or isinstance(out, dict))
                if out is None:
                    continue
                json.dumps(out)                                          # what the heartbeat stores
                self.assertEqual(caps_mod.clean(out), out, "what is kept is stable: cleaning it again changes nothing")
                self.assertLessEqual(set(out), set(GOOD))
                self.assertLessEqual(set(out.get("tools", {})), set(caps_mod.TOOL_KEYS))
                self.assertTrue(all(isinstance(e["kind"], str) and e["kind"] in caps_mod.LOG_KINDS for e in out.get("logs", [])))

    def test_the_panel_the_family_and_the_manager_of_a_host_never_raise_on_what_a_store_may_hold(self):
        """A record read back from a store is not always one this module cleaned (a restored backup, a hand edit, an older release), and
        panel(), family() and manager_of() are called with it as it stands."""
        for name, rec in wrong_reports():
            for manager in ("", "apt", "x", None, ["apt"], {"a": 1}):
                with self.subTest(position=name, manager=manager):
                    self.assertIn(caps_mod.family(rec, manager), ("",) + caps_mod.MANAGERS)
                    panel = caps_mod.panel(rec, manager if isinstance(manager, str) else "")
                    self.assertIn("reported", panel)
                    json.dumps(panel)
            with self.subTest(position=name, reader="manager_of"):
                self.assertIsInstance(caps_mod.manager_of({"packages": rec}), str)
                self.assertIsInstance(caps_mod.manager_of({"packages": {"manager": rec.get("distro")}}), str)

    def test_a_distribution_that_is_not_text_is_not_looked_up(self):
        for distro in (["debian"], {"debian": 1}, None, 5, b"debian"):
            with self.subTest(distro=repr(distro)):
                self.assertEqual(caps_mod.family({"distro": distro}, ""), "")
                self.assertEqual(caps_mod.family({"distro": distro, "like": "rhel fedora"}, ""), "dnf", "the id-like list is read next")
                self.assertEqual(caps_mod.family({"distro": distro}, "pacman"), "pacman", "and then the manager the host reported")


# ── the panel ────────────────────────────────────────────────────────────────
def panel_of(caps, manager=""):
    return caps_mod.panel(caps, manager)


def rows_of(p):
    return {r["name"]: r for r in p["tools"]}


def host(distro, present=(), **extra):
    tools = {k: (k in present) for k in caps_mod.TOOL_KEYS}
    return dict({"root": True, "container": False, "init": "systemd", "distro": distro, "tools": tools}, **extra)


class TestThePanel(unittest.TestCase):

    def test_a_host_that_has_not_reported_has_nothing_to_show(self):
        for none in (None, {}, "x", 5):
            self.assertEqual(panel_of(none), {"reported": False})

    def test_a_missing_tool_names_its_feature_and_the_install_command_of_the_hosts_package_manager(self):
        for distro, expect in (("debian", "apt install iproute2"), ("ubuntu", "apt install iproute2"), ("fedora", "dnf install iproute"),
                               ("arch", "pacman -S iproute2"), ("alpine", "apk add iproute2"), ("opensuse-leap", "zypper install iproute2")):
            with self.subTest(distro=distro):
                row = rows_of(panel_of(host(distro)))["ss"]
                self.assertEqual((row["status"], row["feature"], row["hint"]), ("missing", "Listening ports and connections", expect))

    def test_the_family_comes_from_the_id_like_list_and_then_from_the_manager_the_host_reported(self):
        self.assertEqual(panel_of(host("linuxfoo", like="rhel fedora"))["family"], "dnf")
        self.assertEqual(rows_of(panel_of(host("linuxfoo", like="debian")))["smartctl"]["hint"], "apt install smartmontools")
        self.assertEqual(panel_of(host("linuxfoo"), "pacman")["family"], "pacman")
        self.assertEqual(panel_of(host("linuxfoo"), "unknown")["family"], "")
        self.assertEqual(panel_of(host("linuxfoo"), "<b>")["family"], "")

    def test_with_no_known_family_there_is_no_hint_and_no_guess(self):
        row = rows_of(panel_of(host("linuxfoo")))["smartctl"]
        self.assertEqual((row["status"], row["hint"]), ("missing", ""))

    def test_another_distributions_package_manager_is_not_needed(self):
        rows = rows_of(panel_of(host("debian", present=("apt",))))
        self.assertEqual({k: rows[k]["status"] for k in ("apt", "dnf", "zypper", "apk", "pacman")},
                         {"apt": "present", "dnf": "not_needed", "zypper": "not_needed", "apk": "not_needed", "pacman": "not_needed"})

    def test_a_host_whose_own_package_manager_is_missing_says_so(self):
        rows = rows_of(panel_of(host("debian")))
        self.assertEqual(rows["apt"]["status"], "missing")
        self.assertEqual(rows["dnf"]["status"], "not_needed")

    def test_with_no_known_family_one_package_manager_is_enough_and_none_is_all_missing(self):
        some = rows_of(panel_of(host("linuxfoo", present=("zypper",))))
        self.assertEqual([k for k in ("apt", "dnf", "zypper", "apk", "pacman") if some[k]["status"] == "missing"], [])
        none = rows_of(panel_of(host("linuxfoo")))
        self.assertEqual([k for k in ("apt", "dnf", "zypper", "apk", "pacman") if none[k]["status"] == "missing"],
                         ["apt", "dnf", "zypper", "apk", "pacman"])

    def test_one_firewall_tool_is_enough(self):
        rows = rows_of(panel_of(host("debian", present=("ufw",))))
        self.assertEqual([rows[k]["status"] for k in ("ufw", "firewalld", "iptables", "nft")],
                         ["present", "not_needed", "not_needed", "not_needed"])
        none = rows_of(panel_of(host("debian")))
        self.assertEqual([none[k]["status"] for k in ("ufw", "firewalld", "iptables", "nft")], ["missing"] * 4)

    def test_one_container_runtime_is_enough(self):
        rows = rows_of(panel_of(host("debian", present=("podman",))))
        self.assertEqual((rows["docker"]["status"], rows["podman"]["status"]), ("not_needed", "present"))

    def test_the_systemd_tools_are_not_needed_where_the_init_system_is_another(self):
        for init, status in (("openrc", "not_needed"), ("runit", "not_needed"), ("systemd", "missing"), ("", "missing")):
            with self.subTest(init=init):
                caps = host("alpine")
                if init:
                    caps["init"] = init
                else:
                    caps.pop("init")
                rows = rows_of(panel_of(caps))
                self.assertEqual((rows["systemctl"]["status"], rows["journalctl"]["status"]), (status, status))

    def test_needrestart_belongs_to_the_apt_family(self):
        self.assertEqual(rows_of(panel_of(host("debian")))["needrestart"]["status"], "missing")
        self.assertEqual(rows_of(panel_of(host("fedora")))["needrestart"]["status"], "not_needed")

    def test_in_a_container_a_missing_tool_is_not_available_and_has_no_install_command(self):
        p = panel_of(host("debian", container=True, mapped=["/etc"]))
        row = rows_of(p)["smartctl"]
        self.assertEqual((row["status"], row["hint"]), ("unavailable", ""))
        self.assertIn(caps_mod.NOTICES["container"], p["notices"])
        self.assertEqual((p["missing"], p["unavailable"] > 0), (0, True))

    def test_not_running_as_root_is_said_once(self):
        p = panel_of(host("debian", root=False))
        self.assertEqual(p["notices"], [caps_mod.NOTICES["not_root"]])
        self.assertEqual(panel_of(host("debian"))["notices"], [])
        caps = host("debian")
        caps.pop("root")
        self.assertEqual(panel_of(caps)["notices"], [], "an agent that did not say is not accused")

    def test_an_optional_tool_is_marked_and_sorts_after_a_required_one(self):
        p = panel_of(host("debian"))
        missing = [r for r in p["tools"] if r["status"] == "missing"]
        flags = [r["optional"] for r in missing]
        self.assertEqual(flags, sorted(flags), "required first, optional after")
        self.assertTrue(rows_of(p)["lynis"]["optional"])
        self.assertFalse(rows_of(p)["ss"]["optional"])

    def test_the_rows_come_in_the_order_missing_unavailable_present_not_needed(self):
        p = panel_of(host("debian", present=("ss", "ufw")))
        order = [r["status"] for r in p["tools"]]
        self.assertEqual(order, sorted(order, key=caps_mod.STATUS_ORDER.index))

    def test_only_a_missing_tool_has_a_hint_and_only_where_the_table_has_a_command(self):
        rows = rows_of(panel_of(host("debian", present=("ss",))))
        self.assertEqual(rows["ss"]["hint"], "")
        self.assertEqual(rows["cscli"]["hint"], "", "no honest one-line install for CrowdSec")
        self.assertEqual(rows["docker"]["hint"], "apt install docker.io")

    def test_a_missing_tool_with_no_install_command_carries_a_sentence_instead(self):
        deb = rows_of(panel_of(host("debian")))
        self.assertEqual((deb["cscli"]["hint"], deb["cscli"]["note"]), ("", "Follow CrowdSec's own installation guide."))
        self.assertEqual(deb["systemctl"]["note"], "Comes with systemd.")
        self.assertEqual(deb["apt"]["note"], "Comes with the base system of the distribution.")
        self.assertEqual((deb["oscap"]["hint"], deb["oscap"]["note"]),
                         ("", "Its package name differs by release: search your package manager for openscap."))
        self.assertEqual((deb["docker"]["hint"], deb["docker"]["note"]), ("apt install docker.io", ""))
        fed = rows_of(panel_of(host("fedora")))
        self.assertEqual((fed["oscap"]["hint"], fed["oscap"]["note"]), ("dnf install openscap-scanner", ""))
        self.assertEqual((fed["docker"]["hint"], fed["docker"]["note"]),
                         ("", "Its package differs by distribution: follow Docker's installation guide."),
                         "moby-engine is Fedora's name and the rest of the rpm family does not have it")

    def test_a_sentence_never_sits_beside_a_command_or_beside_a_tool_that_is_not_missing(self):
        for distro in ("debian", "fedora", "alpine", "linuxfoo"):
            for container in (False, True):
                p = panel_of(host(distro, present=("ss", "ufw"), container=container))
                for r in p["tools"]:
                    with self.subTest(distro=distro, container=container, tool=r["name"]):
                        if r["status"] != "missing":
                            self.assertEqual((r["hint"], r["note"]), ("", ""))
                        else:
                            self.assertFalse(r["hint"] and r["note"], "a command and a sentence for one row")

    def test_a_tool_with_a_command_for_every_manager_has_no_sentence(self):
        for t in caps_mod.TOOLS:
            full = set(t["pkgs"]) == set(caps_mod.MANAGERS)
            self.assertEqual(full and bool(t.get("note")), False, t["key"])
        self.assertEqual(rows_of(panel_of(host("debian")))["smartctl"]["note"], "")

    def test_a_tool_the_agent_did_not_report_has_no_row(self):
        caps = host("debian")
        caps["tools"] = {"ss": True}
        self.assertEqual([r["name"] for r in panel_of(caps)["tools"]], ["ss"])

    def test_the_logs_carry_the_servers_label_for_their_kind(self):
        p = panel_of(FULL)
        self.assertEqual([(e["label"], e["path"], e["readable"]) for e in p["logs"]],
                         [("Web access log", "/var/log/nginx/access.log", True), ("fail2ban log", "/var/log/fail2ban.log", False)])

    def test_a_stored_record_with_junk_in_it_cannot_break_or_leak_through_the_panel(self):
        junk = dict(FULL, tools={"ss": True, "<script>": True, "nft": "yes"}, logs="x", secret="s3cret")
        p = panel_of(junk)
        self.assertNotIn("s3cret", json.dumps(p))
        self.assertNotIn("<script>", json.dumps(p))
        self.assertEqual([r["name"] for r in p["tools"]], ["ss"])

    def test_every_tool_has_a_sentence_and_packages_only_for_known_managers(self):
        for t in caps_mod.TOOLS:
            self.assertTrue(t["feature"], t["key"])
            self.assertLessEqual(set(t["pkgs"]), set(caps_mod.MANAGERS), t["key"])
            self.assertIn(t["applies"], ("", "systemd") + caps_mod.MANAGERS, t["key"])
        self.assertEqual(len(caps_mod.TOOL_KEYS), len(set(caps_mod.TOOL_KEYS)), "a tool is listed once")
        self.assertEqual(len(caps_mod.TOOL_KEYS), 25)


# ── through the real heartbeat and the real handler ──────────────────────────
NOW = int(time.time())


class _Server(unittest.TestCase):
    FILES = ("CONFIG_FILE", "DEVICES_FILE", "CMDS_FILE", "USERS_FILE", "TOKENS_FILE", "ROLES_FILE", "MAINT_FILE", "HISTORY_FILE")
    WHO, ROLE = "alice", "admin"

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="srv-", dir=_TMP))
        self._saved = {n: getattr(api, n) for n in self.FILES}
        for n in self.FILES:
            setattr(api, n, self.d / self._saved[n].name)
        self.addCleanup(self._restore)
        self.method = "POST"
        for name, value in (("verify_token", lambda token=None, *a, **k: (self.WHO, self.ROLE)),
                            ("get_token_from_request", lambda: "t"),
                            ("method", lambda: self.method),
                            ("audit_log", lambda *a, **k: None),
                            ("fire_webhook", lambda *a, **k: None)):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.body = {}
        for name in ("get_json_obj", "get_json_body"):
            p = mock.patch.object(api, name, lambda: dict(self.body))
            p.start()
            self.addCleanup(p.stop)
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01", "os": "Debian 12", "token": "tok1"},
                                    "dw": {"name": "win", "os": "Windows 11", "token": "tokw"}})
        api.save(api.USERS_FILE, {"alice": {"role": "admin"}})
        api._LOAD_CACHE.clear()

    def _restore(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def call(self, fn, *args):
        try:
            fn(*args)
        except api.HTTPError as e:
            return e.status, e.body
        self.fail(f"{getattr(fn, '__name__', fn)} answered nothing")

    def beat(self, sysinfo=None, omitted=None, dev="d1"):
        token = {"d1": "tok1", "dw": "tokw"}[dev]
        body = {"device_id": dev, "token": token, "os": "Debian 12", "version": "8.0.1"}
        if sysinfo is not None:
            body["sysinfo"] = sysinfo
        if omitted is not None:
            body["sysinfo_omitted"] = omitted
        self.body = body
        self.method = "POST"
        return self.call(api.handle_heartbeat)

    def stored(self, dev="d1"):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE)[dev].get("sysinfo") or {}).get("capabilities")


class TestTheHeartbeat(_Server):

    def test_the_report_is_cleaned_and_stored_with_the_host(self):
        self.assertEqual(self.beat(sysinfo={"uptime": "up", "capabilities": FULL})[0], 200)
        self.assertEqual(self.stored(), FULL)

    def test_hostile_values_never_reach_the_store(self):
        hostile = dict(FULL, logs=[{"kind": "web", "path": "/a\x00<script>alert(1)</script>", "readable": True}],
                       tools={"ss": True, "<img onerror=x>": True}, init="<b>", agent={"version": "<script>", "python": "3"},
                       secret="s3cret", env={"TOKEN": "t"})
        self.beat(sysinfo={"uptime": "up", "capabilities": hostile})
        stored = self.stored()
        text = json.dumps(stored)
        for bad in ("s3cret", "TOKEN", "<img", "<b>"):
            self.assertNotIn(bad, text)
        self.assertEqual(stored["tools"], {"ss": True})
        self.assertNotIn("init", stored)

    def test_what_is_not_a_report_leaves_none(self):
        for bad in ("text", 5, ["x"], {}, {"unknown": 1}):
            self.beat(sysinfo={"uptime": "up", "capabilities": bad})
            self.assertIsNone(self.stored(), bad)

    def test_a_log_whose_kind_is_a_list_or_a_dict_does_not_refuse_the_rest_of_the_hosts_report(self):
        """Through the real handler. The cleaner raised on such a kind, the update block it runs in was left without saving, and the host
        answered 500 on every beat that carried system information: its packages, ports and posture stayed frozen on the server while it
        went on beating (a host with a buggy or hostile agent looks online and is never refreshed)."""
        for kind in (["web"], {"k": 1}):
            for attempt in range(3):
                with self.subTest(kind=kind, attempt=attempt):
                    status, _body = self.beat(sysinfo={"uptime": "up", "packages": {"manager": "apt", "upgradable": 7},
                                                       "capabilities": {"root": True, "logs": [
                                                           {"kind": kind, "path": "/var/log/x.log", "readable": True},
                                                           {"kind": "web", "path": "/var/log/ok.log", "readable": True}]}})
                    self.assertEqual(status, 200)
                    self.assertEqual(self.stored(), {"root": True, "logs": [{"kind": "web", "path": "/var/log/ok.log", "readable": True}]})
                    api._LOAD_CACHE.clear()
                    dev = api.load(api.DEVICES_FILE)["d1"]
                    self.assertEqual(dev["sysinfo"]["packages"]["upgradable"], 7, "the rest of the report was stored")
                    self.assertGreater(dev.get("last_seen", 0), 0, "and the beat was counted")

    def test_a_report_with_a_wrong_part_at_any_position_is_answered_and_stored_not_refused(self):
        """The same, over every position and every kind of value (the population is held in TestAWrongTypedReportIsNeverRefused)."""
        for name, rec in wrong_reports():
            with self.subTest(position=name):
                status, _body = self.beat(sysinfo={"uptime": "up", "packages": {"manager": "apt", "upgradable": 3}, "capabilities": rec})
                self.assertEqual(status, 200)
                api._LOAD_CACHE.clear()
                self.assertEqual(api.load(api.DEVICES_FILE)["d1"]["sysinfo"]["packages"]["upgradable"], 3)

    def test_an_unchanged_report_arrives_as_an_omission_and_the_stored_copy_is_merged_back(self):
        self.beat(sysinfo={"uptime": "up", "capabilities": FULL})
        c = self.beat(sysinfo={"uptime": "up 2"}, omitted={"capabilities": "abcd1234"})
        self.assertEqual(c[0], 200)
        self.assertEqual(self.stored(), FULL, "the host still reads as it did")
        self.assertNotIn("capabilities", c[1].get("delta_resend", []))

    def test_an_omission_with_nothing_stored_asks_for_the_report_whole(self):
        c = self.beat(sysinfo={"uptime": "up"}, omitted={"capabilities": "abcd1234"})
        self.assertIn("capabilities", c[1].get("delta_resend", []))
        self.assertIsNone(self.stored())

    def test_it_is_one_of_the_fields_both_sides_may_leave_out(self):
        self.assertIn("capabilities", api._DELTA_SYSINFO_FIELDS)
        self.assertIn("capabilities", agent._DELTA_SYSINFO_FIELDS)


class TestTheEndpoint(_Server):

    def get(self, dev="d1"):
        self.method = "GET"
        return self.call(api.handle_device_capabilities, dev)

    def test_the_route_is_registered_under_the_device_prefix(self):
        self.assertEqual(routes_to("GET", "/api/devices/abc123/capabilities"), "handle_device_capabilities")

    def test_a_host_that_has_not_reported_answers_so(self):
        status, body = self.get()
        self.assertEqual((status, body["reported"], body["ok"]), (200, False, True))
        self.assertNotIn("tools", body)

    def test_a_reported_host_answers_the_panel(self):
        self.beat(sysinfo={"uptime": "up", "capabilities": host("debian", present=("ss", "ufw"), mapped=[]),
                           "packages": {"manager": "apt", "upgradable": 0}})
        status, body = self.get()
        self.assertEqual(status, 200)
        rows = rows_of(body)
        self.assertEqual(rows["ss"]["status"], "present")
        self.assertEqual((rows["smartctl"]["status"], rows["smartctl"]["hint"], rows["smartctl"]["feature"]),
                         ("missing", "apt install smartmontools", "Disk health (SMART)"))
        self.assertEqual(body["family"], "apt")
        self.assertEqual(body["missing"], sum(1 for r in body["tools"] if r["status"] == "missing"))

    def test_the_package_manager_the_host_reported_picks_the_hint_when_the_distribution_does_not(self):
        caps = host("weirdos")
        self.beat(sysinfo={"uptime": "up", "capabilities": caps, "packages": {"manager": "pacman"}})
        self.assertEqual(rows_of(self.get()[1])["smartctl"]["hint"], "pacman -S smartmontools")

    def test_it_needs_a_signed_in_user(self):
        self.WHO = None
        self.assertEqual(self.get()[0], 401)

    def test_a_read_only_user_may_read_it(self):
        self.beat(sysinfo={"uptime": "up", "capabilities": FULL})
        self.ROLE = "viewer"
        self.assertEqual(self.get()[0], 200)

    def test_an_unknown_or_malformed_host_is_not_found_and_a_post_is_refused(self):
        self.assertEqual(self.get("nope1234")[0], 404)
        self.assertEqual(self.get("../etc")[0], 404)
        self.method = "POST"
        self.assertEqual(self.call(api.handle_device_capabilities, "d1")[0], 405)

    def test_nothing_the_host_wrote_comes_back_as_text_the_server_did_not_choose(self):
        """A stored record with junk (a restored backup, a hand edit) is cleaned again on the way out. Every field the panel copies from the
        record is here with a value it would print as it stands: a name with markup, a mapped path that is not one of the five, a log of a
        kind the server has no label for, an agent block with a key of its own."""
        junk = dict(FULL, tools={"ss": True, "<script>": True}, secret="s3cret", init="<b>x</b>", distro="Deb ian",
                    mapped=["/etc", "<x>"], agent={"version": "<script>", "python": "3.12.3", "secret": "s3cret"},
                    logs=[{"kind": "web", "path": "/a\x00b", "readable": True}, {"kind": "bogus", "path": "/c", "readable": True}])
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01", "os": "Debian 12", "token": "tok1", "sysinfo": {"capabilities": junk}}})
        api._LOAD_CACHE.clear()
        status, body = self.get()
        self.assertEqual(status, 200)
        text = json.dumps(body)
        for bad in ("s3cret", "<script>", "<b>", "<x>", "Deb ian", "bogus", "\\u0000"):
            self.assertNotIn(bad, text)
        self.assertEqual([(e["label"], e["path"]) for e in body["logs"]], [("Web access log", "/ab")])
        self.assertEqual((body["init"], body["distro"], body["mapped"], body["agent"]), ("", "", ["/etc"], {"python": "3.12.3"}))


class TestAHostOutsideTheCallersTenant(unittest.TestCase):
    """The route sits under /api/devices/<id>/, which main() covers before the handler runs."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="ten-", dir=_TMP))
        self._saved = {n: getattr(api, n) for n in ("CONFIG_FILE", "DEVICES_FILE")}
        for n in self._saved:
            setattr(api, n, self.d / self._saved[n].name)
        self.addCleanup(lambda: ([setattr(api, n, v) for n, v in self._saved.items()], api._LOAD_CACHE.clear()))
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True})
        api.save(api.DEVICES_FILE, {"devA": {"name": "A", "tenant": "tenantA", "os": "Debian 12", "token": "a"},
                                    "devB": {"name": "B", "tenant": "tenantB", "os": "Debian 12", "token": "b"}})
        api._LOAD_CACHE.clear()
        for name, value in (("verify_token", lambda token=None, *a, **k: ("alice", "admin")),
                            ("get_token_from_request", lambda: "t"), ("_caller_effective_tenant", lambda u, _t="tenantA": _t)):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def gate(self, dev_id):
        with mock.patch.object(api, "path_info", lambda: f"/api/devices/{dev_id}/capabilities"):
            try:
                api._enforce_device_scope()
            except api.HTTPError as e:
                return e.status
        return None

    def test_a_tenant_admin_is_stopped_at_another_tenants_host_and_not_at_its_own(self):
        self.assertEqual(self.gate("devB"), 403)
        self.assertIsNone(self.gate("devA"))


# ── fleet knowledge ──────────────────────────────────────────────────────────
class TestTheFleetKnowledgeCorpus(unittest.TestCase):
    """"Which hosts have no smartctl" and "which agents do not run as root" are fleet questions the drawer answered and the corpus did
    not. The builder is the real one; every name in the answer comes from the server's own table."""

    @staticmethod
    def corpus(**sysinfo):
        import rag_index
        docs = rag_index.build_live_state_corpus([{"id": "d1", "name": "web01", "os": "linux", "last_seen": int(time.time()),
                                                   "monitored": True, "sysinfo": sysinfo}], now=int(time.time()))
        return "\n".join(d.get("text", "") for d in docs)

    def line(self, text, start):
        return next((ln.strip() for ln in text.splitlines() if ln.strip().startswith(start)), "")

    def test_a_missing_tool_is_named_with_the_feature_that_needs_it(self):
        text = self.corpus(capabilities=host("debian", present=("ss", "ufw", "apt", "systemctl", "journalctl")))
        self.assertIn("what the agent can see:", text)
        gone = self.line(text, "tools the agent cannot find")
        self.assertIn("smartctl (Disk health (SMART))", gone)
        self.assertNotIn("ss (", gone, "a tool that is there is not listed")
        self.assertNotIn("dnf (", gone, "another distribution's package manager is not what a person could install")
        self.assertNotIn("firewalld (", gone, "one firewall tool is enough")

    def test_the_package_manager_the_host_reported_picks_the_family_for_a_distribution_the_table_does_not_know(self):
        caps = host("weirdos", present=("ss",))
        for manager, listed, unlisted in (("pacman", "pacman (", "apt ("), ("apt", "apt (", "pacman (")):
            with self.subTest(manager=manager):
                gone = self.line(self.corpus(capabilities=caps, packages={"manager": manager}), "tools the agent cannot find")
                self.assertIn(listed, gone)
                self.assertNotIn(unlisted, gone)

    def test_not_running_as_root_and_running_in_a_container_are_said(self):
        text = self.corpus(capabilities=host("debian", present=caps_mod.TOOL_KEYS, root=False))
        self.assertIn("the agent is NOT running as root", text)
        self.assertNotIn("runs in a container", text)
        unsaid = host("debian", present=caps_mod.TOOL_KEYS)
        unsaid.pop("root")
        self.assertNotIn("NOT running as root", self.corpus(capabilities=unsaid), "an agent that did not say is not accused")
        text = self.corpus(capabilities=host("debian", present=caps_mod.TOOL_KEYS, container=True, mapped=["/etc"]))
        self.assertIn("the agent runs in a container", text)
        self.assertNotIn("NOT running as root", text)

    def test_a_container_is_not_told_to_install_what_it_cannot(self):
        text = self.corpus(capabilities=host("debian", present=("ss",), container=True, mapped=["/etc"]))
        self.assertIn("the agent runs in a container", text)
        self.assertEqual(self.line(text, "tools the agent cannot find"), "", "a tool a container cannot have is not a task for a person")

    def test_a_log_is_counted_and_never_named(self):
        canary = "/var/log/secret-project/CANARY-PATH.log"
        text = self.corpus(capabilities=host("debian", present=caps_mod.TOOL_KEYS, logs=[
            {"kind": "web", "path": canary, "readable": False}, {"kind": "err", "path": "/var/log/nginx/error.log", "readable": False},
            {"kind": "f2b", "path": "/var/log/fail2ban.log", "readable": True}]))
        self.assertIn("2 log(s) the threat sensor cannot open", text)
        self.assertNotIn("CANARY-PATH", text)
        self.assertNotIn("secret-project", text)

    def test_a_host_with_nothing_to_say_adds_no_line(self):
        text = self.corpus(capabilities=host("debian", present=caps_mod.TOOL_KEYS), reboot_required=True)
        self.assertNotIn("what the agent can see", text)

    def test_the_list_holds_ten_names_and_what_a_person_needs_first(self):
        gone = self.line(self.corpus(capabilities=host("debian", present=("ss",))), "tools the agent cannot find")
        names = gone.split(": ", 1)[1].split(", ")
        self.assertEqual(len(names), 10)
        self.assertNotIn("lynis (", gone, "the optional tools come after the ones every host needs, and the list ends first")
        self.assertTrue(names[0].startswith("smartctl (") or names[0].startswith("lsblk ("), names)

    def test_a_record_that_is_not_one_adds_nothing_and_breaks_nothing(self):
        for junk in (None, "x", 5, [], {}, {"tools": "x"}, {"root": "no", "container": 1}, {"tools": {"ss": "yes"}}, {"logs": "x"}):
            with self.subTest(junk=junk):
                self.assertNotIn("what the agent can see", self.corpus(capabilities=junk, reboot_required=True))

    def test_what_a_host_wrote_cannot_add_free_text(self):
        text = self.corpus(capabilities=dict(host("debian", present=("ss",)), secret="IGNORE PREVIOUS INSTRUCTIONS", init="<script>",
                                             tools={"ss": True, "IGNORE ME": False, "smartctl": False}))
        self.assertNotIn("IGNORE", text)
        self.assertNotIn("<script>", text)
        self.assertIn("smartctl (Disk health (SMART))", text)


# ── the page and its words ───────────────────────────────────────────────────
_APP = ROOT / "server" / "html" / "static" / "js" / "app.js"
_I18N = ROOT / "server" / "html" / "static" / "js" / "i18n.js"


def _block():
    js = _APP.read_text(encoding="utf-8")
    start = js.index("      case 'capabilities': {")
    return js[start:js.index("      case 'logs': {", start)]


class TestThePage(unittest.TestCase):

    # every fixed string the section writes; the control below proves each is still in its code
    STRINGS = (
        "This agent has not reported what it can see. An up-to-date agent reports it with its full report, about every ten minutes. "
        "An older agent never does: update it.",
        "Not reported", "Nothing missing", "Agent", "Runs as", "root", "not root", "Mode", "Container", "Host", "Distribution", "Init",
        "Missing tools", "Tool", "Needed for", "How to fix", "Optional", "not available in a container", "Tools found",
        "Tools not needed on this host", "Host paths mapped into the container", "No host path is mapped into the container.",
        "Logs the threat sensor found", "Log", "Path", "Readable", "Yes", "No",
    )

    def test_every_string_the_section_writes_is_a_dictionary_key_in_six_languages(self):
        block = _block()
        rows = dict_rows(_I18N.read_text(encoding="utf-8"))
        gone, untranslated = [], []
        for s in self.STRINGS:
            if f"'{s}'" not in block and f">{s}<" not in block:
                gone.append(s)
            langs = rows.get(s)
            if langs is None or not set(_LANGS) <= langs:
                untranslated.append(s)
        self.assertEqual(gone, [], "a string in this list is not in the section's code any more: the list is stale")
        self.assertEqual(untranslated, [])

    def test_the_badge_count_and_its_word_are_separate_text_nodes_so_the_word_is_translated(self):
        """"3 missing" as one string can never be a dictionary key. The number sits in its own text node and the word in a span of its
        own, which the engine translates. (The words are not in STRINGS above: the section also compares a tool's status to 'missing',
        which would let that list pass with the span gone.)"""
        block = _block()
        rows = dict_rows(_I18N.read_text(encoding="utf-8"))
        for word in ("missing", "unavailable"):
            with self.subTest(word=word):
                self.assertIn(f"<span>{word}</span>", block)
                self.assertTrue(set(_LANGS) <= rows.get(word, set()), f"{word}: not translated into all six languages")
        self.assertIn("badge.innerHTML", block)
        self.assertNotIn("badge.textContent = nMissing", block, "the count and the word are one string again")

    def test_the_section_is_only_offered_for_a_linux_agent(self):
        js = _APP.read_text(encoding="utf-8")
        self.assertIn("{key: 'capabilities', title: 'What this agent can see'", js)
        self.assertIn("s.key !== 'capabilities' || _linuxAgent", js)

    def test_what_the_host_wrote_is_escaped_before_it_is_drawn(self):
        block = _block()
        for field in ("t.name", "t.feature", "t.hint", "l.path", "l.label", "r.distro", "r.init", "ag.version", "ag.python", "n)", "p)"):
            self.assertRegex(block, r"escHtml\(" + re.escape(field), field)

    def test_the_lists_are_capped_to_scroll_and_a_hint_is_not_a_button(self):
        block = _block()
        self.assertGreaterEqual(block.count("scrollable-table-wrap audit-scroll"), 2)
        self.assertGreaterEqual(block.count("scroll-cap-sm"), 2)
        self.assertNotIn("<button", block, "an install command is a hint to read, not a button")


if __name__ == "__main__":
    unittest.main()
