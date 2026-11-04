#!/usr/bin/env python3
"""v7.5.0 (docs cross-check, finding W2-F6): two ways the Ansible runner gave away more than the page says.

* `GET /api/ansible/playbooks` returned each playbook's YAML to every signed-in role: viewer, auditor, finance and the MCP key
  included. Creating, editing, deleting and running one need an administrator or the `script` permission, and a playbook is where
  addresses, variables and sometimes credentials live. The YAML now goes to an administrator and to a role with `script`; the rest
  get the list without it.
* The runner said it trusted a host's SSH key on first use and refused a changed one, but it recorded the keys in a file inside the
  run's own temporary directory, deleted afterwards, so every run started with nothing recorded and accepted whatever key the host
  presented. The keys are kept in `ansible_known_hosts` in the data directory now.

What this holds: each role against the list (with a control that an administrator sees the YAML, so the others' answer is not an
empty store), the permission read from the role and not its name, the persisted file (created 0600, the same path every run, outside
the run directory), the fallback when the data directory cannot hold it, and that the environment still turns host-key checking on.
"""

import importlib.util
import os
import pathlib
import shlex
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-ans-"))

_spec = importlib.util.spec_from_file_location("api_v750_ans", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

PLAYBOOKS = {"playbooks": [
    {"id": "p1", "name": "patch web", "content": "- hosts: all\n  vars:\n    db_password: hunter2\n", "created": 1, "created_by": "alice",
     "last_run": 0, "last_rc": None}]}


class _Base(unittest.TestCase):

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp(prefix="rp-v750-ans-d-"))
        self._saved = {n: getattr(api, n) for n in ("ANSIBLE_FILE", "ROLES_FILE", "DATA_DIR")}
        for n in ("ANSIBLE_FILE", "ROLES_FILE"):
            setattr(api, n, self.d / self._saved[n].name)   # the basename is the storage key on the SQL backends
        api.DATA_DIR = self.d
        self.addCleanup(self._restore)
        api.save(api.ANSIBLE_FILE, PLAYBOOKS)
        api.save(api.ROLES_FILE, {"roles": [
            {"name": "operator", "permissions": ["script"], "scope": {"type": "all"}},
            {"name": "watcher", "permissions": ["reboot"], "scope": {"type": "all"}}]})
        api._LOAD_CACHE.clear()
        self.role = "admin"
        for name, value in (("verify_token", lambda token=None, *a, **k: ("someone", self.role)),
                            ("get_token_from_request", lambda: "t"),
                            ("method", lambda: "GET")):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _restore(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def listing(self, role):
        self.role = role
        try:
            api.handle_ansible_playbooks_list()
        except api.HTTPError as e:
            return e.status, e.body
        self.fail("answered nothing")


class TestWhoReadsThePlaybooks(_Base):

    def test_an_administrator_gets_the_yaml(self):
        """Control: the store holds a playbook with content, so an answer without it is the gate and not an empty store."""
        status, body = self.listing("admin")
        self.assertEqual(status, 200)
        self.assertIn("hunter2", body["playbooks"][0]["content"])
        self.assertFalse(body["content_hidden"])

    def test_a_role_with_the_script_permission_gets_it_too(self):
        status, body = self.listing("operator")
        self.assertEqual(status, 200)
        self.assertIn("content", body["playbooks"][0])
        self.assertFalse(body["content_hidden"])

    def test_the_read_only_roles_and_a_role_without_script_get_the_list_and_not_the_yaml(self):
        for role in ("viewer", "auditor", "finance", "mcp", "watcher", "a-role-that-does-not-exist"):
            with self.subTest(role=role):
                status, body = self.listing(role)
                self.assertEqual(status, 200)
                self.assertTrue(body["content_hidden"])
                row = body["playbooks"][0]
                self.assertNotIn("content", row)
                self.assertEqual((row["id"], row["name"]), ("p1", "patch web"), "the list itself is still there")
                self.assertNotIn("hunter2", str(body))

    def test_the_store_is_not_changed_by_hiding(self):
        self.listing("viewer")
        api._LOAD_CACHE.clear()
        self.assertIn("content", api.load(api.ANSIBLE_FILE)["playbooks"][0])

    def test_an_unauthenticated_caller_still_gets_a_401(self):
        with mock.patch.object(api, "verify_token", lambda token=None, *a, **k: (None, None)):
            try:
                api.handle_ansible_playbooks_list()
            except api.HTTPError as e:
                self.assertEqual(e.status, 401)
                return
        self.fail("answered nothing")


class TestTheHostKeysAreRemembered(_Base):

    def test_the_keys_live_in_the_data_directory_and_not_in_the_run(self):
        run_dir = self.d / "run-1"
        run_dir.mkdir()
        env = api._ansible_ssh_env(str(run_dir))
        args = shlex.split(env["ANSIBLE_SSH_ARGS"])
        path = pathlib.Path(args[args.index("-o", args.index("StrictHostKeyChecking=accept-new") + 1) + 1].split("=", 1)[1])
        self.assertEqual(path, self.d / "ansible_known_hosts")
        self.assertNotEqual(path.parent, run_dir)
        self.assertTrue(path.is_file())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_a_second_run_uses_the_same_file_and_keeps_what_the_first_recorded(self):
        first = api._ansible_ssh_env(str(self.d / "run-1"))
        (self.d / "ansible_known_hosts").write_text("web01 ssh-ed25519 AAAAC3Nza\n")
        second = api._ansible_ssh_env(str(self.d / "run-2"))
        self.assertEqual(first["ANSIBLE_SSH_ARGS"], second["ANSIBLE_SSH_ARGS"])
        self.assertEqual((self.d / "ansible_known_hosts").read_text(), "web01 ssh-ed25519 AAAAC3Nza\n")

    def test_host_key_checking_is_still_on(self):
        env = api._ansible_ssh_env(str(self.d))
        self.assertEqual(env["ANSIBLE_HOST_KEY_CHECKING"], "True")
        self.assertIn("StrictHostKeyChecking=accept-new", env["ANSIBLE_SSH_ARGS"])
        self.assertNotIn("StrictHostKeyChecking=no", env["ANSIBLE_SSH_ARGS"])

    def test_without_a_place_to_keep_them_the_run_still_works_with_a_per_run_file(self):
        run_dir = self.d / "run-3"
        run_dir.mkdir()
        with mock.patch.object(api.os, "open", side_effect=PermissionError("read-only")):
            env = api._ansible_ssh_env(str(run_dir))
        self.assertIn(str(run_dir / "known_hosts"), shlex.split(env["ANSIBLE_SSH_ARGS"])[-1])

    def test_a_data_directory_with_a_space_in_its_name_is_one_argument(self):
        spaced = self.d / "data dir"
        spaced.mkdir()
        api.DATA_DIR = spaced
        env = api._ansible_ssh_env(str(self.d))
        last = shlex.split(env["ANSIBLE_SSH_ARGS"])[-1]
        self.assertEqual(last, f"UserKnownHostsFile={spaced / 'ansible_known_hosts'}")


if __name__ == "__main__":
    unittest.main()
