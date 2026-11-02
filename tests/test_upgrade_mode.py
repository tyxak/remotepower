#!/usr/bin/env python3
"""Discussion #30: an upgrade mode for each host, Standard or Extended.

The report: `apt-get upgrade` keeps back an update whose new version needs a package that is not installed yet (a new
kernel image, the split linux-firmware). It installs nothing for it, prints no error and exits 0. The reporter asked for
a choice per host, for the patch button and for auto-patch: Standard (`apt-get upgrade`, the default) or Extended
(`apt-get upgrade --with-new-pkgs`).

What is held here, through the real code:

  * the two scripts: Extended is Standard with one flag added to the one apt line, and the shipped shell script, run by a
    shell with a recording apt-get, passes the flag only in Extended mode;
  * every place that queues an upgrade on a host honours the mode. Six places were found (seven code paths, because the
    patch button and the scheduled upgrade share one), which is the lesson of this codebase's half-applied rules, so
    this drives each path in both modes and a source ratchet holds that no function reaches for the raw script and that
    no new place builds an apt upgrade without being listed;
  * the route that sets it: who may, what it accepts, what it refuses, and that it audits a change and only a change;
  * what the Patch Report says: the mode, whether it applies to the host, and the packages apt keeps back;
  * the Mitigate CVE diagnostic, which listed security updates by their `Inst` lines and so missed a kept-back one.
"""
import ast
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(CGI))
sys.path.insert(0, str(ROOT / "tests"))

import api  # noqa: E402
import upgrade_mode as um  # noqa: E402
from test_v742_container_recovery import DEV as HB_DEV, _Base, _Captured, _Stdin  # noqa: E402
from test_v742_container_recovery import api as hb_api  # noqa: E402  the base class execs its own copy of api

NOW = int(time.time())
STD_APT = "apt-get $ALT -y upgrade &&"
FLAG = "--with-new-pkgs"


def extended_of(script):
    """What the extended script must be, worked out here and not by the code under test."""
    assert script.count(STD_APT) == 1
    return script.replace(STD_APT, "apt-get $ALT -y upgrade --with-new-pkgs &&")


# ── the pure parts ──────────────────────────────────────────────────────────────────────────────────────────────

class TestThePureModule(unittest.TestCase):

    def test_there_are_two_modes_and_standard_is_the_default(self):
        self.assertEqual(um.MODES, ("standard", "extended"))
        self.assertEqual(um.DEFAULT, "standard")

    def test_extended_adds_one_flag_to_the_one_apt_line_and_changes_nothing_else(self):
        script = "set -e; x; apt-get $ALT update && apt-get $ALT -y upgrade && apt-get $ALT -y autoremove; y"
        got = um.extended(script)
        self.assertEqual(got, "set -e; x; apt-get $ALT update && apt-get $ALT -y upgrade --with-new-pkgs && apt-get $ALT -y autoremove; y")
        self.assertEqual(got.replace(" --with-new-pkgs", ""), script)

    def test_a_script_without_exactly_one_apt_line_is_refused_so_extended_cannot_be_a_quiet_copy(self):
        for bad in ("", "echo hello", "apt-get -y upgrade", STD_APT + " " + STD_APT):
            with self.assertRaises(ValueError, msg=bad):
                um.extended(bad)

    def test_only_the_exact_word_extended_is_extended(self):
        self.assertEqual(um.mode_of({"upgrade_mode": "extended"}), "extended")
        for dev in ({}, {"upgrade_mode": "standard"}, {"upgrade_mode": "Extended"}, {"upgrade_mode": " extended"},
                    {"upgrade_mode": "extended "}, {"upgrade_mode": True}, {"upgrade_mode": 1}, {"upgrade_mode": ["extended"]},
                    {"upgrade_mode": None}, {"upgrade_mode": ""}, None, "extended", 5, [], {"x": "extended"}):
            self.assertEqual(um.mode_of(dev), "standard", repr(dev))

    def test_the_mode_matters_to_linux_hosts_that_use_apt_or_have_not_said(self):
        for manager in ("apt", "unknown", "", None, 5, [], {}):
            self.assertIsNone(um.not_applicable("linux", manager), repr(manager))

    def test_it_does_not_matter_to_a_windows_or_mac_host_or_a_linux_host_with_another_manager(self):
        for family in ("windows", "darwin", "", "bsd"):
            self.assertEqual(um.not_applicable(family, "apt"), "not_linux", family)
        for manager in ("dnf", "pacman", "zypper", "yum", "apk", "routeros"):
            self.assertEqual(um.not_applicable("linux", manager), "not_apt", manager)

    def test_every_reason_has_words(self):
        self.assertEqual(sorted(um.REASONS), ["not_apt", "not_linux"])


# ── the scripts, as shipped ─────────────────────────────────────────────────────────────────────────────────────

KINDS = ("manual", "scheduled", "scheduled_reboot")
STANDARD = {"manual": "_UPGRADE_CMD", "scheduled": "_SCHED_UPGRADE_CMD", "scheduled_reboot": "_SCHED_UPGRADE_REBOOT_CMD"}


class TestTheScriptsAsShipped(unittest.TestCase):

    def test_the_standard_scripts_are_the_ones_every_host_had_before(self):
        for kind in KINDS:
            self.assertIs(api._UPGRADE_CMDS[kind][0], getattr(api, STANDARD[kind]), kind)

    def test_each_extended_script_is_its_standard_one_with_one_flag(self):
        for kind in KINDS:
            std, ext = api._UPGRADE_CMDS[kind]
            self.assertNotEqual(std, ext, kind)
            self.assertEqual(ext, extended_of(std), kind)
            self.assertEqual(ext.count(FLAG), 1, kind)
            self.assertEqual(std.count(FLAG), 0, kind)

    def test_the_extended_scripts_keep_what_the_agent_looks_for_in_a_package_upgrade(self):
        """The agent gives a command a 30 minute limit and a large output cap when it contains one of these."""
        for kind in KINDS:
            self.assertIn("dnf upgrade", api._UPGRADE_CMDS[kind][1], kind)

    def test_the_helper_picks_by_the_hosts_mode(self):
        for kind in KINDS:
            std, ext = api._UPGRADE_CMDS[kind]
            self.assertEqual(api._linux_upgrade_cmd({"upgrade_mode": "extended"}, kind), ext)
            for dev in ({}, {"upgrade_mode": "standard"}, None, {"upgrade_mode": "junk"}):
                self.assertEqual(api._linux_upgrade_cmd(dev, kind), std, repr(dev))

    def test_the_default_kind_is_the_patch_button_script(self):
        self.assertEqual(api._linux_upgrade_cmd({}), api._UPGRADE_CMD)


class _Shell(unittest.TestCase):
    """Run a shipped script with a shell whose PATH holds a recording apt-get and the few tools the script uses."""

    TOOLS = ("uname", "mktemp", "rm", "mkdir", "tail", "date", "ls", "cat", "awk", "grep", "head", "sed", "sort")

    def run_script(self, script, apt_output=None):
        with tempfile.TemporaryDirectory() as d:
            bin_ = Path(d) / "bin"
            bin_.mkdir()
            for tool in self.TOOLS:
                found = shutil.which(tool)
                if found:
                    os.symlink(found, bin_ / tool)
            log = Path(d) / "apt.log"
            (bin_ / "apt-get").write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$APT_LOG"\n' + (apt_output or "") + "exit 0\n")
            for name in ("apt-get",):
                (bin_ / name).chmod((bin_ / name).stat().st_mode | stat.S_IXUSR)
            env = {"PATH": str(bin_), "APT_LOG": str(log), "HOME": d, "TMPDIR": d}
            shell = shutil.which("sh")
            res = subprocess.run([shell, "-c", script.replace("/var/log/remotepower", d + "/varlog")], env=env,
                                 capture_output=True, text=True, timeout=60)
            calls = log.read_text().splitlines() if log.exists() else []
            return res, calls


class TestTheShippedScriptRuns(_Shell):

    def check(self, kind, extended):
        script = api._UPGRADE_CMDS[kind][1 if extended else 0]
        res, calls = self.run_script(script)
        self.assertEqual(res.returncode, 0, res.stderr)
        upgrades = [c for c in calls if " upgrade" in c or c.startswith("upgrade")]
        self.assertEqual(len(upgrades), 1, calls)
        self.assertEqual(FLAG in upgrades[0], extended, calls)
        self.assertEqual([c for c in calls if FLAG in c and c is not upgrades[0]], [], "the flag goes on the upgrade call only")
        self.assertTrue(any("update" in c for c in calls) and any("autoremove" in c for c in calls), calls)
        return calls

    def test_the_patch_button_script_passes_the_flag_only_in_extended(self):
        std = self.check("manual", False)
        ext = self.check("manual", True)
        self.assertEqual(std, [c.replace(" " + FLAG, "") for c in ext], "nothing else differs between the two runs")

    def test_the_scheduled_script_passes_the_flag_only_in_extended(self):
        self.check("scheduled", False)
        self.check("scheduled", True)

    def test_the_apt_calls_wait_for_the_dpkg_lock_in_both(self):
        for extended in (False, True):
            for call in self.check("manual", extended)[:3]:
                self.assertIn("DPkg::Lock::Timeout=300", call)


# ── every place that queues an upgrade ─────────────────────────────────────────────────────────────────────────

def dev(name, *, os_="Ubuntu 24.04", manager="apt", mode=None, tags=(), group=""):
    d = {"id": name, "name": name, "hostname": name, "token": "tok-" + name, "last_seen": NOW, "enrolled": NOW,
         "tags": list(tags), "group": group, "os": os_, "monitored": True,
         "sysinfo": {"packages": {"manager": manager, "upgradable": 3}} if manager else {}}
    if mode:
        d["upgrade_mode"] = mode
    return d


FLEET = {
    "stdhost": dev("stdhost"),
    "exthost": dev("exthost", mode="extended"),
    "winhost": dev("winhost", os_="Windows 11 (Build 22631)", manager=None),
    "dnfhost": dev("dnfhost", os_="Rocky Linux 9", manager="dnf"),
    "unkhost": dev("unkhost", manager=None),
}


def call(handler, body, *path, role="admin", verb="POST", audit=None):
    """Run one handler for real with the caller's role and body. Only the token check is stubbed, so a handler with no
    gate of its own would let anyone in and the test of the gate would show it. Returns {status, body}."""
    names = ("verify_token", "get_token_from_request", "method", "get_json_body", "get_json_obj", "audit_log", "respond")
    saved = {n: getattr(api, n) for n in names}
    box = {}
    api.verify_token = (lambda t: ("alice", role)) if role else (lambda t: (None, None))
    api.get_token_from_request = lambda: "t"
    api.method = lambda: verb
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = (lambda *a, **k: audit.append((a, k))) if audit is not None else (lambda *a, **k: None)

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            handler(*path)
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    return box


class _Fleet(unittest.TestCase):

    def setUp(self):
        for f, empty in ((api.CMDS_FILE, {}), (api.CONFIG_FILE, {}), (api.SCHEDULE_FILE, {"jobs": []}),
                         (api.ALERTS_FILE, {"alerts": []})):
            api.save(f, empty)
        api.save(api.DEVICES_FILE, json.loads(json.dumps(FLEET)))
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for f, empty in ((api.CMDS_FILE, {}), (api.SCHEDULE_FILE, {"jobs": []}), (api.DEVICES_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def queued(self, dev_id):
        api._LOAD_CACHE.clear()
        return (api.load(api.CMDS_FILE) or {}).get(dev_id, [])

    def stored(self, dev_id):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {})[dev_id]


def script_for(kind, extended):
    std = getattr(api, STANDARD[kind])
    return extended_of(std) if extended else std


class TestEverySiteHonoursTheMode(_Fleet):

    def test_the_patch_button(self):
        box = call(api.handle_upgrade_device, {"device_ids": ["stdhost", "exthost"]})
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(self.queued("stdhost"), ["exec:" + script_for("manual", False)])
        self.assertEqual(self.queued("exthost"), ["exec:" + script_for("manual", True)])

    def test_the_patch_button_on_a_windows_host_is_the_native_verb_whatever_a_stored_mode_says(self):
        d = json.loads(json.dumps(FLEET))
        d["winhost"]["upgrade_mode"] = "extended"
        api.save(api.DEVICES_FILE, d)
        api._LOAD_CACHE.clear()
        self.assertEqual(call(api.handle_upgrade_device, {"device_ids": ["winhost"]})["status"], 200)
        self.assertEqual(self.queued("winhost"), ["upgrade"])

    def schedule(self, command, *hosts):
        jobs = [{"id": f"j{i}", "device_id": h, "device_name": h, "command": command, "run_at": NOW - 5,
                 "cron": None, "recurring": False, "actor": "alice", "created": NOW} for i, h in enumerate(hosts)]
        api.save(api.SCHEDULE_FILE, {"jobs": jobs})
        api._LOAD_CACHE.clear()
        api.process_schedule()

    def test_a_scheduled_upgrade(self):
        self.schedule("upgrade_packages", "stdhost", "exthost")
        self.assertEqual(self.queued("stdhost"), ["exec:" + script_for("manual", False)])
        self.assertEqual(self.queued("exthost"), ["exec:" + script_for("manual", True)])

    def test_a_scheduled_upgrade_and_reboot(self):
        self.schedule("upgrade_and_reboot", "stdhost", "exthost")
        self.assertEqual(self.queued("stdhost"), ["exec:" + script_for("scheduled_reboot", False)])
        self.assertEqual(self.queued("exthost"), ["exec:" + script_for("scheduled_reboot", True)])

    def test_a_flat_auto_patch_policy_queues_each_host_its_own_script(self):
        n = api._autopatch_queue({"id": "p1", "name": "all", "target": {"type": "all"}, "reboot": False}, "tester")
        self.assertEqual(n, len(FLEET))
        self.assertEqual(self.queued("stdhost"), ["exec:" + script_for("scheduled", False)])
        self.assertEqual(self.queued("exthost"), ["exec:" + script_for("scheduled", True)])
        self.assertEqual(self.queued("unkhost"), ["exec:" + script_for("scheduled", False)], "a host that has not said what it uses")
        self.assertEqual(self.queued("winhost"), ["upgrade"])

    def test_a_flat_auto_patch_policy_with_a_reboot(self):
        api._autopatch_queue({"id": "p1", "name": "all", "target": {"type": "all"}, "reboot": True}, "tester")
        self.assertEqual(self.queued("stdhost"), ["exec:" + script_for("scheduled_reboot", False)])
        self.assertEqual(self.queued("exthost"), ["exec:" + script_for("scheduled_reboot", True)])

    def test_a_fleet_that_uses_no_mode_queues_the_one_script_it_always_did(self):
        api.save(api.DEVICES_FILE, {k: v for k, v in json.loads(json.dumps(FLEET)).items() if k in ("stdhost", "dnfhost", "unkhost")})
        api._LOAD_CACHE.clear()
        api._autopatch_queue({"id": "p1", "name": "all", "target": {"type": "all"}, "reboot": False}, "tester")
        self.assertEqual({tuple(self.queued(h)) for h in ("stdhost", "dnfhost", "unkhost")},
                         {("exec:" + api._SCHED_UPGRADE_CMD,)})

    def test_the_approval_pin_prefix_still_comes_first(self):
        real = api._autopatch_pin_prefix
        api._autopatch_pin_prefix = lambda: "apt-mark hold foo; "
        try:
            api._autopatch_queue({"id": "p1", "name": "all", "target": {"type": "all"}, "reboot": False}, "tester")
        finally:
            api._autopatch_pin_prefix = real
        self.assertEqual(self.queued("exthost"), ["exec:apt-mark hold foo; " + script_for("scheduled", True)])

    def ring(self, reboot):
        roll = {"id": "r1", "name": "r", "action": "upgrade", "reboot": reboot, "created_by": "tester", "tenant_gate": None,
                "rings": [{"name": "all", "selector": {"type": "ids", "ids": ["stdhost", "exthost", "winhost"]}}]}
        devices = json.loads(json.dumps(FLEET))
        cmds = {}
        api._rollout_dispatch_ring(roll, 0, devices, cmds)
        return cmds

    def test_a_rollout_ring(self):
        cmds = self.ring(False)
        self.assertEqual(cmds["stdhost"], ["exec:" + script_for("manual", False)])
        self.assertEqual(cmds["exthost"], ["exec:" + script_for("manual", True)])
        self.assertEqual(cmds["winhost"], ["upgrade"])

    def test_a_rollout_ring_with_a_reboot(self):
        cmds = self.ring(True)
        self.assertEqual(cmds["stdhost"], ["exec:" + script_for("scheduled_reboot", False)])
        self.assertEqual(cmds["exthost"], ["exec:" + script_for("scheduled_reboot", True)])

    def test_the_autonomy_loops_patch_action(self):
        command_for = api.autonomy_ops_handlers_mod._command_for
        self.assertEqual(command_for("patch", "linux", FLEET["stdhost"]), "exec:" + script_for("manual", False))
        self.assertEqual(command_for("patch", "linux", FLEET["exthost"]), "exec:" + script_for("manual", True))
        self.assertEqual(command_for("patch", "linux"), "exec:" + script_for("manual", False), "no host: the standard script")
        self.assertEqual(command_for("patch", "windows", FLEET["winhost"]), "upgrade")

    def test_the_compliance_fix_for_pending_updates(self):
        for check in ("cis-patches", "cis-cve"):
            self.assertEqual(api._cis_remediation(check, FLEET["stdhost"])["command"], "exec:apt-get -y upgrade")
            self.assertEqual(api._cis_remediation(check, FLEET["exthost"])["command"], "exec:apt-get -y upgrade --with-new-pkgs")
        dnf = dict(FLEET["dnfhost"], upgrade_mode="extended")
        self.assertEqual(api._cis_remediation("cis-patches", dnf)["command"], "exec:dnf upgrade --refresh -y")

    def test_the_agents_package_upgrade_detection_still_matches_the_compliance_command(self):
        agent = (ROOT / "client" / "remotepower-agent.py").read_text()
        self.assertIn("'apt-get -y upgrade'", agent)
        self.assertTrue("apt-get -y upgrade --with-new-pkgs".startswith("apt-get -y upgrade"))


# ── the ratchet ────────────────────────────────────────────────────────────────────────────────────────────────

RAW = {"_UPGRADE_CMD", "_SCHED_UPGRADE_CMD", "_SCHED_UPGRADE_REBOOT_CMD"}
APT_UPGRADE = re.compile(r"apt-get\s[^'\"]*\bupgrade\b")

# Where a string that builds or mentions an apt upgrade may be, and why. A new place fails the ratchet: decide whether it
# honours the upgrade mode, then list it with the reason.
KNOWN_APT_UPGRADE_STRINGS = {
    ("api.py", "<module>"): "the upgrade script itself (_UPGRADE_CMD) and the Mitigate playbooks' read-only simulations",
    ("api.py", "_cis_remediation"): "the compliance fix; reads the host's mode",
    ("api.py", "handle_heartbeat"): "a list of fragments that mark a command output as a package upgrade; builds nothing",
    ("ai_provider.py", "<module>"): "prompt text for the assistant; builds nothing",
    ("openapi_spec.py", "_path_devices"): "API documentation text; builds nothing",
    ("upgrade_mode.py", "<module>"): "the two apt lines of the mode itself",
}


def _walk(tree):
    """(node, name of the enclosing function or '<module>')"""
    def go(node, scope):
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else scope
            yield child, inner
            yield from go(child, inner)
    yield from go(tree, "<module>")


def _docstrings(tree):
    ids = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body:
            first = n.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                ids.add(id(first.value))
    return ids


def scan(source=None):
    """({(file, scope): count} of references to a raw script constant, {(file, scope)} of apt-upgrade strings)"""
    raw, strings = {}, set()
    files = {p.name: p.read_text() for p in sorted(CGI.glob("*.py"))} if source is None else source
    for name, text in files.items():
        tree = ast.parse(text)
        docs = _docstrings(tree)
        for node, scope in _walk(tree):
            ident = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None
            if ident in RAW:
                raw[(name, scope)] = raw.get((name, scope), 0) + 1
            if (isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs
                    and APT_UPGRADE.search(node.value)):
                strings.add((name, scope))
    return raw, strings


class TestNoSiteCanSkipTheMode(unittest.TestCase):

    def test_no_function_reaches_for_a_raw_upgrade_script(self):
        raw, _ = scan()
        in_functions = {k: v for k, v in raw.items() if k[1] != "<module>"}
        self.assertEqual(in_functions, {}, "ask _linux_upgrade_cmd(dev, kind) for the script instead")

    def test_the_scan_sees_the_definitions_so_an_empty_answer_means_something(self):
        raw, strings = scan()
        self.assertGreaterEqual(raw.get(("api.py", "<module>"), 0), 9, raw)
        self.assertIn(("api.py", "_cis_remediation"), strings)
        print(f"\n[ratchet] {sum(v for k, v in raw.items() if k[1] != '<module>')} function-level uses of a raw script constant "
              f"(0 wanted); {len(strings)} places hold an apt upgrade string, all listed")

    def test_the_ratchet_can_fail(self):
        raw, _ = scan({"x.py": "def queue(dev):\n    return 'exec:' + _UPGRADE_CMD\n"})
        self.assertEqual(raw, {("x.py", "queue"): 1})
        raw, _ = scan({"x.py": "def queue(A):\n    return A._SCHED_UPGRADE_REBOOT_CMD\n"})
        self.assertEqual(raw, {("x.py", "queue"): 1})
        _, strings = scan({"x.py": "def fix():\n    return 'apt-get -y upgrade'\n"})
        self.assertEqual(strings, {("x.py", "fix")})
        _, strings = scan({"x.py": "def fix():\n    '''apt-get -y upgrade is only a docstring'''\n"})
        self.assertEqual(strings, set())

    def test_only_the_known_places_build_or_mention_an_apt_upgrade(self):
        _, strings = scan()
        self.assertEqual(sorted(strings - set(KNOWN_APT_UPGRADE_STRINGS)), [],
                         "a new place builds an apt upgrade: does it honour the upgrade mode? List it with the reason.")
        stale = set(KNOWN_APT_UPGRADE_STRINGS) - strings
        self.assertEqual(sorted(stale), [], "listed but gone: remove it so the list only shrinks")

    def test_the_compliance_fix_reads_the_mode(self):
        src = (CGI / "api.py").read_text()
        start = src.index("def _cis_remediation")
        self.assertIn("upgrade_mode_mod.mode_of(dev)", src[start:start + 1500])


# ── the route ──────────────────────────────────────────────────────────────────────────────────────────────────

def put(dev_id, body, **kw):
    return call(api.handle_device_upgrade_mode, body, dev_id, verb="PUT", **kw)


def get(dev_id, **kw):
    return call(api.handle_device_upgrade_mode, {}, dev_id, verb="GET", **kw)


class TestTheRoute(_Fleet):

    def test_it_is_a_route_under_the_hosts_so_the_tenant_and_role_scope_apply_first(self):
        routes = api._dispatcher_routes()
        match = [r for r in routes if "upgrade-mode" in str(r)]
        self.assertTrue(match, "the route is not registered")
        self.assertIn("/api/devices/", str(match[0]))

    def test_a_host_reads_standard_until_it_is_set(self):
        body = get("stdhost")["body"]
        self.assertEqual((body["mode"], body["applies"], body["reason"], body["manager"]), ("standard", True, "", "apt"))
        self.assertEqual(body["modes"], ["standard", "extended"])

    def test_the_answer_says_when_the_mode_does_nothing_for_the_host(self):
        self.assertEqual(get("winhost")["body"]["reason"], "not_linux")
        self.assertEqual(get("dnfhost")["body"]["reason"], "not_apt")
        self.assertTrue(get("unkhost")["body"]["applies"], "a host that has not said what it uses is not held against it")

    def test_an_administrator_sets_it_and_it_is_kept_on_the_host(self):
        box = put("stdhost", {"mode": "extended"})
        self.assertEqual(box["status"], 200, box)
        self.assertEqual((box["body"]["mode"], box["body"]["changed"]), ("extended", True))
        self.assertEqual(self.stored("stdhost")["upgrade_mode"], "extended")
        self.assertEqual(get("stdhost")["body"]["mode"], "extended")

    def test_standard_removes_the_key_so_an_untouched_host_and_a_reset_one_are_the_same(self):
        put("exthost", {"mode": "standard"})
        self.assertNotIn("upgrade_mode", self.stored("exthost"))

    def test_only_a_change_is_audited_and_without_anything_else(self):
        audit = []
        put("stdhost", {"mode": "extended"}, audit=audit)
        put("stdhost", {"mode": "extended"}, audit=audit)
        self.assertEqual(len(audit), 1, audit)
        self.assertEqual(audit[0][0][:2], ("alice", "upgrade_mode_set"))
        self.assertEqual(audit[0][1]["detail"], "host=stdhost mode=extended")
        put("stdhost", {"mode": "standard"}, audit=audit)
        put("stdhost", {"mode": "standard"}, audit=audit)
        self.assertEqual(len(audit), 2, audit)

    def test_a_setting_does_not_touch_the_rest_of_the_host(self):
        before = self.stored("stdhost")
        put("stdhost", {"mode": "extended"})
        after = self.stored("stdhost")
        after.pop("upgrade_mode")
        self.assertEqual(after, before)

    def test_a_viewer_and_a_caller_with_no_token_cannot_set_it(self):
        for role in ("viewer", None):
            box = put("stdhost", {"mode": "extended"}, role=role)
            self.assertIn(box["status"], (401, 403), (role, box))
            self.assertNotIn("upgrade_mode", self.stored("stdhost"), role)

    def test_a_viewer_can_read_it(self):
        self.assertEqual(get("exthost", role="viewer")["body"]["mode"], "extended")

    def test_a_request_that_does_not_say_what_it_wants_changes_nothing(self):
        for bad in ({}, {"mode": None}, {"mode": ""}, {"mode": "Extended"}, {"mode": " extended"}, {"mode": "EXTENDED"},
                    {"mode": 1}, {"mode": True}, {"mode": ["extended"]}, {"mode": {"a": 1}}, {"mode": "full-upgrade"},
                    {"mode": "extended; rm -rf /"}, {"Mode": "extended"}, {"mod": "extended"}, [], "extended", None):
            box = put("stdhost", bad)
            self.assertEqual(box["status"], 400, (bad, box))
            self.assertNotIn("upgrade_mode", self.stored("stdhost"), bad)
        put("exthost", {})
        self.assertEqual(self.stored("exthost")["upgrade_mode"], "extended", "an empty request did not reset it either")

    def test_a_host_the_mode_does_nothing_for_is_refused_with_the_reason(self):
        for host, reason in (("winhost", "not_linux"), ("dnfhost", "not_apt")):
            box = put(host, {"mode": "extended"})
            self.assertEqual(box["status"], 400, box)
            self.assertEqual(box["body"]["reason"], reason)
            self.assertNotIn("upgrade_mode", self.stored(host))

    def test_a_host_that_has_not_reported_what_it_uses_can_be_set(self):
        self.assertEqual(put("unkhost", {"mode": "extended"})["status"], 200)

    def test_an_unknown_host_and_a_malformed_id_are_not_found(self):
        for host in ("nosuchhost", "../etc/passwd", "a b"):
            self.assertEqual(get(host)["status"], 404, host)
            self.assertEqual(put(host, {"mode": "extended"})["status"], 404, host)

    def test_other_methods_are_refused(self):
        for verb in ("POST", "DELETE", "PATCH"):
            self.assertEqual(call(api.handle_device_upgrade_mode, {"mode": "extended"}, "stdhost", verb=verb)["status"], 405, verb)


# ── what the Patch Report says ─────────────────────────────────────────────────────────────────────────────────

class TestThePatchReport(_Fleet):

    def one(self, dev_id):
        return call(api.handle_patch_report_device, {}, dev_id, verb="GET")["body"]

    def test_a_hosts_report_carries_the_mode_and_whether_it_applies(self):
        a, b, c, d = self.one("stdhost"), self.one("exthost"), self.one("winhost"), self.one("dnfhost")
        self.assertEqual((a["upgrade_mode"], a["upgrade_mode_applies"]), ("standard", True))
        self.assertEqual((b["upgrade_mode"], b["upgrade_mode_applies"]), ("extended", True))
        self.assertEqual((c["upgrade_mode_applies"], d["upgrade_mode_applies"]), (False, False))

    def test_it_names_the_packages_apt_keeps_back(self):
        d = json.loads(json.dumps(FLEET))
        d["stdhost"]["sysinfo"]["packages"]["kept_back"] = ["linux-image-amd64", "linux-firmware", 5, None]
        api.save(api.DEVICES_FILE, d)
        api._LOAD_CACHE.clear()
        self.assertEqual(self.one("stdhost")["kept_back"], ["linux-image-amd64", "linux-firmware"])
        self.assertEqual(self.one("exthost")["kept_back"], [])

    def test_the_fleet_report_has_each_hosts_mode(self):
        rows = {r["device_id"]: r for r in call(api.handle_patch_report, {}, verb="GET")["body"]["devices"]}
        self.assertEqual({k: v["upgrade_mode"] for k, v in rows.items()},
                         {"stdhost": "standard", "exthost": "extended", "winhost": "standard", "dnfhost": "standard",
                          "unkhost": "standard"})


class TestTheHeartbeatKeepsTheKeptBackNames(_Base):

    def report(self, packages):
        raw = json.dumps({"device_id": HB_DEV, "token": "tok", "sysinfo": {"packages": packages}}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)
        hb_api.sys.stdin = _Stdin(raw)
        hb_api._LOAD_CACHE.clear()
        try:
            hb_api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            return
        self.fail("the heartbeat did not answer")

    def packages(self):
        hb_api._LOAD_CACHE.clear()
        return ((hb_api.load(hb_api.DEVICES_FILE) or {})[HB_DEV].get("sysinfo") or {}).get("packages") or {}

    def test_the_names_are_stored(self):
        self.report({"manager": "apt", "upgradable": 2, "kept_back": ["linux-image-amd64", "linux-firmware"]})
        self.assertEqual(self.packages()["kept_back"], ["linux-image-amd64", "linux-firmware"])

    def test_what_is_not_a_package_name_is_dropped_and_the_list_is_capped(self):
        self.report({"manager": "apt", "upgradable": 99, "kept_back": ["ok", "", None, 5, ["x"], {"a": 1}, "x" * 300] + [f"p{i}" for i in range(80)]})
        got = self.packages()["kept_back"]
        self.assertEqual(got[0], "ok")
        self.assertLessEqual(len(got), 50)
        self.assertTrue(all(isinstance(n, str) and n and len(n) <= 128 for n in got), got)

    def test_a_later_report_without_them_clears_them(self):
        self.report({"manager": "apt", "upgradable": 1, "kept_back": ["linux-image-amd64"]})
        self.report({"manager": "apt", "upgradable": 0})
        self.assertNotIn("kept_back", self.packages())

    def test_a_list_that_is_not_a_list_is_ignored(self):
        self.report({"manager": "apt", "upgradable": 1, "kept_back": "linux-image-amd64"})
        self.assertNotIn("kept_back", self.packages())


# ── the Mitigate CVE diagnostic ────────────────────────────────────────────────────────────────────────────────

DATA = ROOT / "tests" / "data" / "apt_real" / "ubuntu-24.04"


class TestTheCveDiagnosticSeesWhatIsKeptBack(_Shell):
    """It listed the security updates by their Inst lines, so a kept-back kernel never showed there while the total
    below it counted it. Run here with an apt-get that prints what a real apt 2.8.3 printed (tests/data/apt_real)."""

    def run_diag(self):
        diag = api._MITIGATE_PLAYBOOKS["cve"]["diagnostic"]
        with tempfile.TemporaryDirectory() as d:
            bin_ = Path(d) / "bin"
            bin_.mkdir()
            for tool in self.TOOLS + ("sh",):
                found = shutil.which(tool)
                if found:
                    os.symlink(found, bin_ / tool)
            plain = (DATA / "deferred_plain.txt").read_text()
            new = (DATA / "deferred_with_new_pkgs.txt").read_text()
            (bin_ / "apt-get").write_text("#!/bin/sh\ncase \"$*\" in\n*--with-new-pkgs*) cat <<'EOF'\n" + new + "EOF\n;;\n*) cat <<'EOF'\n"
                                          + plain + "EOF\n;;\nesac\n")
            (bin_ / "apt").write_text("#!/bin/sh\necho 'lab-kernel-meta/noble-security 2.0 all [upgradable from: 1.0]'\n")
            for name in ("apt-get", "apt"):
                (bin_ / name).chmod(0o755)
            res = subprocess.run([shutil.which("sh"), "-c", diag], env={"PATH": str(bin_), "HOME": d}, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout

    def section(self, out, title):
        """The lines under the heading `== <title...> ==`, up to the next heading."""
        sections, current = {}, None
        for line in out.splitlines():
            m = re.match(r"^== (.*) ==$", line)
            if m:
                current = m.group(1)
                sections[current] = []
            elif current is not None:
                sections[current].append(line)
        found = [k for k in sections if k.startswith(title)]
        self.assertEqual(len(found), 1, (title, list(sections)))
        return "\n".join(sections[found[0]])

    def test_the_kept_back_packages_are_listed(self):
        out = self.run_diag()
        self.assertIn("lab-kernel-meta", self.section(out, "KEPT BACK"))

    def test_the_security_updates_an_extended_upgrade_would_add_are_listed(self):
        out = self.run_diag()
        self.assertIn("Lab:noble-security", self.section(out, "SECURITY UPDATES an Extended upgrade would also install"))

    def test_the_old_list_is_what_it_was_and_still_empty_for_this_host(self):
        """The control, and the reason for the change: nothing in the first list, though a security update waits."""
        out = self.run_diag()
        self.assertEqual(self.section(out, "PENDING SECURITY UPDATES").strip(), "")

    def test_the_diagnostic_is_read_only(self):
        diag = api._MITIGATE_PLAYBOOKS["cve"]["diagnostic"]
        calls = re.findall(r"apt-get\s+-\S+[^;|]*", diag)       # an invocation with options, not `command -v apt-get` or an echo
        self.assertGreaterEqual(len(calls), 2, calls)           # the population is not empty
        for call_ in calls:
            self.assertEqual(call_.split()[1], "-s", call_)
        for call_ in calls:
            words = call_.split()
            self.assertIn("upgrade", words, call_)
            for verb in ("install", "autoremove", "dist-upgrade", "full-upgrade", "remove", "purge", "clean"):
                self.assertNotIn(verb, words, call_)

    def test_the_shell_parses(self):
        res = subprocess.run([shutil.which("sh"), "-n", "-c", api._MITIGATE_PLAYBOOKS["cve"]["diagnostic"]], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main()
