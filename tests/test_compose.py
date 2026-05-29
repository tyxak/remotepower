#!/usr/bin/env python3
"""v3.3.4: docker-compose stacks (upload + deploy).

Covers the security-critical bits: per-device opt-in gating (a deploy must
not reach a host until compose_enabled is flipped), admin-gated create,
the device-token fetch endpoint, and the up/down/redeploy → status mapping.
The agent-side deploy handler is tested in test_agent.py.
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

os.environ["RP_DATA_DIR"] = tempfile.mkdtemp()
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_compose", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}")
        self.status, self.body = status, body


def _fake_respond(status, data):
    raise _Captured(status, data)


api.respond = _fake_respond


class _Stdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


def _req(method, path, body=None, token=None):
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = path
    raw = b"" if body is None else json.dumps(body).encode()
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _Stdin(raw)
    if token:
        os.environ["HTTP_X_TOKEN"] = token
    else:
        os.environ.pop("HTTP_X_TOKEN", None)


def _call(fn, *args):
    try:
        fn(*args)
        return None, None
    except _Captured as c:
        return c.status, c.body


def _seed_admin():
    api.ensure_default_user()
    user = next(iter(api.load(api.USERS_FILE)))
    token = api.make_token()
    toks = api.load(api.TOKENS_FILE)
    toks[token] = {"user": user, "created": int(time.time()), "ttl": 3600,
                   "admin": True, "remember": False}
    api.save(api.TOKENS_FILE, toks)
    return token


def _seed_device(dev_id="dev1", compose_enabled=False):
    devs = api.load(api.DEVICES_FILE)
    devs[dev_id] = {"name": dev_id, "token": "devtok",
                    "compose_enabled": compose_enabled,
                    "enrolled": int(time.time()), "agentless": False}
    api.save(api.DEVICES_FILE, devs)


YAML = "services:\n  app:\n    image: nginx:latest\n"


class TestComposeStacks(unittest.TestCase):
    def setUp(self):
        for f in (api.DEVICES_FILE, api.COMPOSE_STACKS_FILE, api.CMDS_FILE, api.TOKENS_FILE):
            api.save(f, {})
        self.token = _seed_admin()
        _seed_device("dev1", compose_enabled=False)

    def _create(self, name="web", device="dev1", yaml=YAML):
        _req("POST", "/api/compose/stacks",
             {"name": name, "device_id": device, "yaml": yaml}, self.token)
        return _call(api.handle_compose_stack_create)

    def test_create_rejects_non_compose_yaml(self):
        _req("POST", "/api/compose/stacks",
             {"name": "x", "device_id": "dev1", "yaml": "not a compose file"}, self.token)
        st, _ = _call(api.handle_compose_stack_create)
        self.assertEqual(st, 400)

    def test_create_rejects_bad_name(self):
        st, _ = self._create(name="Bad Name")
        self.assertEqual(st, 400)

    def test_create_and_list(self):
        st, body = self._create()
        self.assertEqual(st, 200)
        sid = body["id"]
        _req("GET", "/api/compose/stacks", None, self.token)
        st, body = _call(api.handle_compose_stacks_list)
        self.assertEqual(st, 200)
        self.assertEqual(len(body["stacks"]), 1)
        self.assertEqual(body["stacks"][0]["id"], sid)
        self.assertFalse(body["stacks"][0]["compose_enabled"])
        self.assertEqual(body["stacks"][0]["status"], "created")

    def test_action_blocked_when_compose_disabled(self):
        _, body = self._create()
        sid = body["id"]
        _req("POST", f"/api/compose/stacks/{sid}/action", {"action": "up"}, self.token)
        st, _ = _call(api.handle_compose_stack_action, sid)
        self.assertEqual(st, 403)
        # the opt-in gate must mean NOTHING was queued to the host
        self.assertEqual(api.load(api.CMDS_FILE).get("dev1", []), [])

    def test_action_queues_when_enabled(self):
        _, body = self._create()
        sid = body["id"]
        _seed_device("dev1", compose_enabled=True)
        _req("POST", f"/api/compose/stacks/{sid}/action", {"action": "up"}, self.token)
        st, _ = _call(api.handle_compose_stack_action, sid)
        self.assertEqual(st, 200)
        self.assertIn(f"compose_deploy:up:{sid}", api.load(api.CMDS_FILE).get("dev1", []))
        self.assertEqual(api.load(api.COMPOSE_STACKS_FILE)[sid]["status"], "deploying")

    def test_fetch_requires_correct_device_token(self):
        _, body = self._create()
        sid = body["id"]
        _req("POST", "/api/compose/fetch",
             {"device_id": "dev1", "token": "wrong", "stack_id": sid})
        st, _ = _call(api.handle_compose_fetch)
        self.assertEqual(st, 403)
        _req("POST", "/api/compose/fetch",
             {"device_id": "dev1", "token": "devtok", "stack_id": sid})
        st, body = _call(api.handle_compose_fetch)
        self.assertEqual(st, 200)
        self.assertIn("services:", body["yaml"])

    def test_fetch_rejects_stack_from_other_device(self):
        _, body = self._create(device="dev1")
        sid = body["id"]
        _seed_device("dev2", compose_enabled=False)
        _req("POST", "/api/compose/fetch",
             {"device_id": "dev2", "token": "devtok", "stack_id": sid})
        st, _ = _call(api.handle_compose_fetch)
        self.assertEqual(st, 404)

    def test_enable_toggle(self):
        _req("PATCH", "/api/devices/dev1/compose_enabled",
             {"compose_enabled": True}, self.token)
        st, body = _call(api.handle_device_compose_enabled, "dev1")
        self.assertEqual(st, 200)
        self.assertTrue(body["compose_enabled"])
        self.assertTrue(api.load(api.DEVICES_FILE)["dev1"]["compose_enabled"])


class TestComposeStatusMapping(unittest.TestCase):
    def test_status_from_action_and_rc(self):
        self.assertEqual(api._compose_status_from("up", 0), "up")
        self.assertEqual(api._compose_status_from("redeploy", 0), "up")
        self.assertEqual(api._compose_status_from("down", 0), "down")
        self.assertEqual(api._compose_status_from("up", 1), "error")
        self.assertEqual(api._compose_status_from("down", 2), "error")


if __name__ == "__main__":
    unittest.main()
