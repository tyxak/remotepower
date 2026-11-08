#!/usr/bin/env python3
"""8.0.0: the channels that run code on a host without the agent's queue are held to the queue's refusals.

A quarantined host takes no exec, reboot or actions, and while the server is in maintenance mode no new command goes out. Both were written inside the shared predicate of the
paths that put a command on the agent's queue (`_command_block_reason`), and 7.5.0 enumerated THOSE paths by syntax tree. The channels that reach a host over SSH from the server
were outside that population, and a hand count found them:

    POST /api/devices/<id>/ssh-exec     ignored both refusals (an admin could run a command on a quarantined host, or in the middle of a maintenance drain)
    POST /api/ansible/playbooks/<id>/run  honoured quarantine per target (3.8.0) and ignored maintenance mode
    POST /api/webterm/auth              ignored quarantine, which the SSH gateway has always honoured

`_direct_block_reason` is the one predicate now (the queue's own first two checks call it, so the words cannot drift), and `TestEveryChannelThatRunsCodeOverSsh` enumerates the channels by
syntax tree, prints the ratio, and fails on a fourth that does not ask. Change approval (four-eyes) is not applied to these channels: it parks a QUEUED command for a second admin, and
none of these writes the queue; that is unchanged and said in docs/security.md.
"""
import ast
import json
import io
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-direct-exec-"))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402
import ssh_agent  # noqa: E402

PASSWORD = "correct horse battery staple 42"
QUARANTINED_WORDS = "Host is quarantined — exec/reboot/actions are disabled."


class _Captured(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


def _call(fn, body, token, args=(), method="POST"):
    api._begin_request()
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = "/api/x"
    os.environ["REMOTE_ADDR"] = "203.0.113.9"
    raw = json.dumps(body).encode()
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _Stdin(raw)
    os.environ["HTTP_X_TOKEN"] = token

    def fake(status, data=None, *a, **k):
        raise _Captured(status, data)

    orig = api.respond
    api.respond = fake
    try:
        with mock.patch("time.sleep"):
            fn(*args)
        return None, {}
    except _Captured as c:
        return c.status, c.body
    finally:
        api.respond = orig
        os.environ.pop("HTTP_X_TOKEN", None)


class _Base(unittest.TestCase):

    def setUp(self):
        d = tempfile.mkdtemp(prefix="rp-direct-exec-")
        os.environ["RP_DATA_DIR"] = d
        self._saved = {}
        for name in ("USERS_FILE", "TOKENS_FILE", "DEVICES_FILE", "AUDIT_LOG_FILE", "CONFIG_FILE", "RATELIMIT_FILE", "WEBTERM_TICKETS_FILE", "ANSIBLE_FILE", "CONFIRMATIONS_FILE"):
            if hasattr(api, name):
                self._saved[name] = getattr(api, name)
                setattr(api, name, Path(d) / Path(getattr(api, name)).name)
        api._begin_request()
        api.ensure_default_user()
        users = api.load(api.USERS_FILE)
        users["alice"] = {"password_hash": api.hash_password(PASSWORD), "role": "admin", "created": int(time.time())}
        api.save(api.USERS_FILE, users)
        self.token = api._mint_session("alice")
        self.calls = []
        self._run = ssh_agent.run
        ssh_agent.run = lambda host, user, command, key, port=22, **k: (self.calls.append(command), {"ok": True, "rc": 0, "output": "hi"})[1]

    def tearDown(self):
        ssh_agent.run = self._run
        for name, value in self._saved.items():
            setattr(api, name, value)

    def host(self, **extra):
        rec = {"name": "sw1", "ip": "10.0.0.9", "ssh_user": "root", "agentless": True, "reachability": "ssh"}
        rec.update(extra)
        api.save(api.DEVICES_FILE, {"al_1": rec})

    def config(self, **extra):
        cfg = {"agentless_ssh_enabled": True, "agentless_ssh_key": "KEY"}
        cfg.update(extra)
        api.save(api.CONFIG_FILE, cfg)


class TestSshExecIsHeldToTheQueuesRefusals(_Base):

    def ssh_exec(self, command="uptime"):
        return _call(api.handle_device_ssh_exec, {"command": command}, self.token, args=("al_1",))

    def test_a_host_that_is_neither_quarantined_nor_in_maintenance_runs_the_command(self):
        self.host()
        self.config()
        status, body = self.ssh_exec()
        self.assertEqual((status, body["ok"], body["output"]), (200, True, "hi"), body)
        self.assertEqual(self.calls, ["uptime"])

    def test_a_quarantined_host_is_refused_in_the_queues_words_and_nothing_runs(self):
        self.host(quarantined=True)
        self.config()
        status, body = self.ssh_exec()
        self.assertEqual((status, body["error"]), (409, QUARANTINED_WORDS))
        self.assertEqual(self.calls, [])

    def test_maintenance_mode_refuses_a_command_in_the_queues_words_and_nothing_runs(self):
        self.host()
        self.config(maintenance_mode=True, maintenance_reason="controller upgrade")
        status, body = self.ssh_exec()
        self.assertEqual(status, 503)
        self.assertTrue(body.get("maintenance"))
        self.assertIn("controller upgrade", body["error"])
        self.assertEqual(self.calls, [])

    def test_the_words_are_the_queues_own_not_a_copy(self):
        self.host(quarantined=True)
        self.config()
        _, body = self.ssh_exec()
        self.assertEqual(body["error"], api._command_block_reason({"quarantined": True}, "exec:x")[1])
        self.config(maintenance_mode=True, maintenance_reason="r")
        self.host()
        _, body = self.ssh_exec()
        self.assertEqual(body["error"], api._command_block_reason({}, "exec:x")[1])

    def test_lifting_the_quarantine_lets_it_run_again(self):
        self.host(quarantined=True)
        self.config()
        self.assertEqual(self.ssh_exec()[0], 409)
        self.host()
        self.assertEqual(self.ssh_exec()[0], 200)

    def test_the_read_only_poll_is_not_held_to_them(self):
        self.host(quarantined=True)
        self.config(maintenance_mode=True, maintenance_reason="r")
        ssh_agent.run = lambda *a, **k: {"ok": True, "rc": 0, "output": '{"os":"Linux 6.1"}'}
        status, body = _call(api.handle_device_ssh_poll, {}, self.token, args=("al_1",))
        self.assertEqual(status, 200, body)


class TestTheAnsibleRunIsHeldToMaintenanceMode(_Base):

    def test_maintenance_mode_refuses_a_run_before_anything_is_read(self):
        self.config(maintenance_mode=True, maintenance_reason="controller upgrade")
        with mock.patch.object(api, "_ansible_available", lambda: True):
            status, body = _call(api.handle_ansible_playbook_run, {}, self.token, args=("pb_missing",))
        self.assertEqual(status, 503)
        self.assertTrue(body.get("maintenance"))
        self.assertIn("controller upgrade", body["error"])

    def test_without_maintenance_the_same_call_reaches_the_playbook_lookup(self):
        """The control: the 503 above came from the gate and not from something else on the way."""
        self.config()
        with mock.patch.object(api, "_ansible_available", lambda: True):
            status, body = _call(api.handle_ansible_playbook_run, {}, self.token, args=("pb_missing",))
        self.assertEqual((status, body["error"]), (404, "playbook not found"))


class TestTheWebTerminalIsHeldToQuarantine(_Base):

    def auth(self, password=PASSWORD + "x"):
        return _call(api.handle_webterm_auth, {"device_id": "al_1", "admin_password": password}, self.token)

    def test_a_quarantined_host_is_refused_before_the_password_is_asked_for(self):
        self.host(quarantined=True)
        status, body = self.auth()
        self.assertEqual((status, body["error"]), (409, QUARANTINED_WORDS))

    def test_a_host_that_is_not_quarantined_gets_as_far_as_the_password(self):
        self.host()
        status, body = self.auth()
        self.assertEqual((status, body["error"]), (403, "Admin password did not match"))

    def test_maintenance_mode_does_not_stop_a_terminal(self):
        """Like the SSH gateway: an interactive session queues no command."""
        self.host()
        self.config(maintenance_mode=True, maintenance_reason="r")
        status, body = self.auth()
        self.assertEqual((status, body["error"]), (403, "Admin password did not match"))

    def test_a_good_password_for_a_host_that_is_not_quarantined_issues_a_ticket(self):
        self.host()
        status, body = self.auth(PASSWORD)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("ticket"))
        self.assertEqual(len(api.load(api.WEBTERM_TICKETS_FILE)), 1)


# ── the channels, enumerated by syntax tree ──────────────────────────────────────────────────────────────────────────────────────────────────────────
EXEMPT = {
    "handle_device_ssh_poll": "runs a fixed read-only script and changes nothing: not an action",
}


def _population():
    """{function name: (file, asks)} for every function that reaches a host over SSH from the server: it calls ssh_agent.run, builds an ansible-playbook argv, or issues a web terminal
    ticket. `asks` is whether its own body names the shared predicate (or the quarantine test the SSH gateway uses)."""
    out = {}
    for path in sorted((_ROOT / "server" / "cgi-bin").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            reaches = False
            asks = False
            for node in ast.walk(fn):
                if isinstance(node, ast.Attribute) and node.attr == "run" and isinstance(node.value, ast.Name) and node.value.id == "ssh_agent":
                    reaches = True
                if isinstance(node, ast.List) and node.elts and isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "ansible-playbook":
                    reaches = True              # the argv of a run, not a check that the program exists
                if isinstance(node, ast.Attribute) and node.attr == "WEBTERM_TICKETS_FILE" and fn.name.startswith("handle_"):
                    reaches = True
                if isinstance(node, (ast.Name, ast.Attribute)) and getattr(node, "id", getattr(node, "attr", "")) in ("_direct_block_reason", "_device_quarantined", "_command_block_reason"):
                    asks = True
            if reaches:
                out[fn.name] = (path.name, asks)
    return out


class TestEveryChannelThatRunsCodeOverSsh(unittest.TestCase):

    def test_the_population_is_the_four_channels_known_today(self):
        got = _population()
        for name in ("handle_device_ssh_exec", "handle_device_ssh_poll", "handle_ansible_playbook_run", "handle_webterm_auth"):
            self.assertIn(name, got, "the enumeration sees the channel: %r" % sorted(got))

    def test_each_asks_the_shared_predicate_or_is_exempt_with_a_reason(self):
        got = _population()
        asking = sorted(n for n, (_, asks) in got.items() if asks)
        exempt = sorted(n for n in got if n in EXEMPT)
        missing = sorted(n for n, (_, asks) in got.items() if not asks and n not in EXEMPT)
        self.assertEqual(missing, [], "%d channels, %d ask, %d are exempt (%s): these run code on a host over SSH and do not ask whether the host is quarantined"
                         % (len(got), len(asking), len(exempt), ", ".join(exempt)))

    def test_an_exemption_that_no_longer_matches_a_channel_is_taken_off_the_list(self):
        self.assertEqual(sorted(set(EXEMPT) - set(_population())), [], "an exempt name that is not a channel any more")

    def test_the_enumeration_can_say_no(self):
        """Control: a function that calls ssh_agent.run and asks nothing is in the population and does not ask."""
        tree = ast.parse("def handle_x():\n    ssh_agent.run('h', 'u', 'c', 'k')\n")
        fn = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        reaches = any(isinstance(n, ast.Attribute) and n.attr == "run" and getattr(n.value, "id", "") == "ssh_agent" for n in ast.walk(fn))
        asks = any(getattr(n, "id", getattr(n, "attr", "")) in ("_direct_block_reason", "_device_quarantined", "_command_block_reason") for n in ast.walk(fn))
        self.assertEqual((reaches, asks), (True, False))


if __name__ == "__main__":
    unittest.main()
