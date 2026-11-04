#!/usr/bin/env python3
"""7.5.0 agent review: what the server sends must not end the agent, and must not change how long it sleeps.

* A1  Linux. heartbeat() has no wrapper, and the lines that follow a response are outside any try. `services_watched` and
      `backup_monitors` of a shape the loop did not expect (a number, a list of lists, a dict) ended the process with a traceback.
      It started again 30 seconds later, was sent the same answer and ended again, and the host showed as online in between because
      the POST had landed. The same went for a `log_watch` rule whose unit is a list. Found by sending every key the loop reads a
      value of every type; the Windows and macOS agents always took only the entries of the right type.
* A2  Windows and macOS. The poll interval of a response was stored as sent, in the credentials file. The Linux agent and the
      `poll_interval:` command keep it between 10 and 3600 seconds; a number in the millions put the host to sleep for as long, across
      restarts, and one past what a C time_t holds made time.sleep() raise outside the try of the run loop.

RP_TEST_AGENT, RP_TEST_WIN_AGENT and RP_TEST_MAC_AGENT point the tests at another copy (a `git show HEAD:` of the old file shows them fail).
"""
import importlib.machinery
import importlib.util
import logging
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-data-"))

ROOT = Path(__file__).resolve().parent.parent
LINUX = Path(os.environ.get("RP_TEST_AGENT") or ROOT / "client" / "remotepower-agent.py")
WIN = Path(os.environ.get("RP_TEST_WIN_AGENT") or ROOT / "client" / "remotepower-agent-win.py")
MAC = Path(os.environ.get("RP_TEST_MAC_AGENT") or ROOT / "client" / "remotepower-agent-mac.py")


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def setUpModule():
    logging.disable(logging.CRITICAL)      # the agents log every config change at INFO; the tests read results, not logs


def tearDownModule():
    logging.disable(logging.NOTSET)


class _Stop(BaseException):
    """Not an Exception, so nothing in the agent's loop can swallow it."""


class _NoThreads:
    """`threading`, but a Thread starts nothing (the loop starts the push, tunnel and sensor threads on a server's say-so)."""

    class Thread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

    def __getattr__(self, name):
        return getattr(threading, name)


# Collectors that read the host or run its tools; the loop is what is under test, not they.
_COLLECTORS = (
    "get_metrics", "get_host_health", "get_smart_status", "get_kernel_status", "get_hardware_inventory", "get_gpu_status",
    "get_cert_files", "get_local_accounts", "get_ups_status", "get_av_status", "get_ecc_errors", "get_zram",
    "get_autoupdate_posture", "get_platform_health", "get_disk_encryption", "get_ssh_config", "get_ssh_hostkeys", "get_repo_files",
    "get_usb_devices", "get_battery", "get_chassis", "get_journal", "collect_sudo_events", "collect_peer_connections",
    "collect_lldp_neighbors", "get_containers", "get_compose_projects", "get_docker_disk_usage", "get_helm_releases",
    "send_package_list", "get_patch_info", "get_mdns_services", "collect_acme_state", "collect_custom_metrics",
    "collect_disk_io", "collect_net_io", "get_network_info", "get_host_addresses", "collect_dmesg_logs", "collect_apt_history",
    "collect_web_access_logs", "submit_unit_logs", "detect_auto_watch_units", "get_local_ip", "collect_cpu_time",
    "get_third_party_updates", "collect_backup_verify", "run_restore_drills", "_burst_live_samples",
)


def drive(agent, first, rounds=3, services_seen=None):
    """Run the real heartbeat() loop for `rounds` polls. The first answer is `first`, the later ones are empty. Returns the
    exception that left the loop: _Stop when it kept going until the test stopped it."""
    tmp = tempfile.TemporaryDirectory(prefix="rp-v750-hb-")
    state = {"n": 0}

    def post(url, data, timeout=10):
        if url.endswith("/api/heartbeat") and "cmd_output" not in (data or {}):
            state["n"] += 1
            if state["n"] == 1:
                return first
            if state["n"] > rounds:
                raise _Stop()
        return {}

    def quiet(*a, **k):
        return {}

    patches = [
        mock.patch.object(agent, "http_post", post),
        mock.patch.object(agent, "check_for_update", lambda *a, **k: False),
        mock.patch.object(agent, "threading", _NoThreads()),
        mock.patch.object(agent, "STATE_DIR", Path(tmp.name)),
        mock.patch.object(agent, "_audit_mode", lambda: False),
        mock.patch.object(agent, "_require_signed_commands", lambda: False),
        mock.patch.object(agent, "get_services", (lambda units: services_seen.append(list(units)) or []) if services_seen is not None else quiet),
    ]
    for name in _COLLECTORS:
        if hasattr(agent, name):
            patches.append(mock.patch.object(agent, name, quiet))
    for p in patches:
        p.start()
    try:
        agent.heartbeat({"server_url": "https://rp.example", "device_id": "DEVFUZZ", "token": "t" * 32}, interval=0)
    except BaseException as e:  # noqa: BLE001 - the point is to see what leaves the loop
        return e
    finally:
        for p in reversed(patches):
            p.stop()
        tmp.cleanup()
    return None


class TestLinuxHeartbeatSurvivesWrongShapes(unittest.TestCase):
    """A1"""

    @classmethod
    def setUpClass(cls):
        cls.agent = load(LINUX, "agent_v750_data")

    # (key, value): every one of these ended the process before 7.5.0
    HOSTILE = (
        [("services_watched", v) for v in (5, 1.5, True, [[1]], [{}], [None, 3], [{"id": "a"}])]
        + [("backup_monitors", v) for v in (5, True, "x", [None], [1], [[1]], ["x"], {"a": 1})]
        + [("log_watch", v) for v in (5, [{"unit": ["a"]}], [{"path": ["x"]}], [{"path": {"a": 1}}])]
    )

    def test_a_value_of_the_wrong_kind_does_not_end_the_loop(self):
        ended = []
        for key, value in self.HOSTILE:
            got = drive(self.agent, {key: value})
            if not isinstance(got, _Stop):
                ended.append(f"{key}={value!r} -> {type(got).__name__}: {got}")
        self.assertEqual(ended, [], "heartbeat() raised out of the loop for these answers")

    def test_control_a_good_answer_is_applied(self):
        seen = []
        got = drive(self.agent, {"services_watched": ["sshd.service", "cron.service"]}, services_seen=seen)
        self.assertIsInstance(got, _Stop)
        self.assertIn(["sshd.service", "cron.service"], seen, "the watched units of a good answer were not used")

    def test_only_the_text_entries_of_a_mixed_list_are_used(self):
        seen = []
        got = drive(self.agent, {"services_watched": ["sshd.service", 5, ["x"], None, {"a": 1}]}, services_seen=seen)
        self.assertIsInstance(got, _Stop)
        self.assertIn(["sshd.service"], seen)

    def test_the_population_is_every_key_the_loop_reads_from_a_response(self):
        """Not every key can take every value, but the two that did are in the table and the table is not empty."""
        keys = {k for k, _v in self.HOSTILE}
        self.assertEqual(keys, {"services_watched", "backup_monitors", "log_watch"})
        self.assertGreater(len(self.HOSTILE), 15)


class _Creds:
    """An in-memory stand-in for the credentials file."""

    def __init__(self, poll=60):
        self.data = {"device_id": "DEVFUZZ", "token": "t" * 32, "server_url": "https://rp.example", "poll_interval": poll}

    def load(self):
        return dict(self.data)

    def save(self, creds):
        self.data = dict(creds)


class TestPollIntervalIsKeptBetweenTenAndThirtySixHundred(unittest.TestCase):
    """A2"""

    VALUES = ((5, 10), (60, 60), (3600, 3600), (3601, 3600), (86400, 3600), (2**31, 3600), (2**63, 3600), (10**30, 3600))

    def agents(self):
        for label, path in (("windows", WIN), ("macos", MAC)):
            yield label, load(path, f"agent_v750_{label}")

    def beat(self, mod, answer):
        creds = _Creds()
        with mock.patch.object(mod, "load_creds", creds.load), mock.patch.object(mod, "save_creds", creds.save), \
                mock.patch.object(mod, "_post_json", lambda url, payload, timeout=None: dict(answer)), \
                mock.patch.object(mod, "build_heartbeat", lambda c, n, pending=None: {}), \
                mock.patch.object(mod, "_submit_file_logs", lambda *a, **k: None):
            mod.heartbeat_once(creds.load(), 1)
        return creds.data["poll_interval"]

    def test_the_stored_interval_is_clamped(self):
        for label, mod in self.agents():
            for sent, want in self.VALUES:
                with self.subTest(agent=label, sent=sent):
                    self.assertEqual(self.beat(mod, {"poll_interval": sent}), want)

    def test_control_a_sane_value_and_a_boolean(self):
        for label, mod in self.agents():
            with self.subTest(agent=label):
                self.assertEqual(self.beat(mod, {"poll_interval": 120}), 120)
                self.assertEqual(self.beat(mod, {"poll_interval": True}), 60)     # not a number: left as it was
                self.assertEqual(self.beat(mod, {}), 60)

    def test_a_value_already_stored_by_an_older_build_does_not_stretch_the_sleep(self):
        """The run loop reads the stored interval; a file written before the clamp may hold a huge number or a word."""
        for label, mod in self.agents():
            for stored in (10**12, 2**63, -7, "soon", None):
                with self.subTest(agent=label, stored=stored):
                    delays = []
                    creds = _Creds(poll=stored)

                    def stop(delay=0, delays=delays):
                        delays.append(delay)
                        raise _Stop()
                    patches = [mock.patch.object(mod, "load_creds", creds.load),
                               mock.patch.object(mod, "heartbeat_once", lambda c, n, p=None: ({}, None))]
                    if label == "windows":
                        run = lambda: mod.run(should_stop=None, wait=stop)           # noqa: E731
                    else:
                        patches += [mock.patch.object(mod, "_trim_boot_log", lambda: False),
                                    mock.patch.object(mod.time, "sleep", stop)]
                        run = mod.run
                    for p in patches:
                        p.start()
                    try:
                        with self.assertRaises(_Stop):
                            run()
                    finally:
                        for p in reversed(patches):
                            p.stop()
                    self.assertEqual(len(delays), 1)
                    self.assertTrue(10 <= delays[0] <= 3600, f"slept {delays[0]} s")


if __name__ == "__main__":
    unittest.main()
