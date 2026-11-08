#!/usr/bin/env python3
"""8.0.0: the host drawer's settings form shows what is stored, and a save does not clear what the form never showed.

The form reads `watched_services`, `watched_files`, `log_watch`, `cmd_allowlist`, `reachability`, `manual_status`, `ssh_user`, `ssh_port` and `quarantined` off the roster row
(`GET /api/devices`). The roster is a whitelist and has never carried any of them, and the host record keeps two under other names (`services_watched`, `allowed_commands`). So for
every host the form opened with no watched unit, no watched file, no log rule, no allowed command, ICMP and a blank SSH user, and "Save settings" posted those empties back. The save
documents that an empty list is an explicit clear, so changing only a host's group cleared the rest: the per-host command allowlist, the drift files, the log rules, the watched units,
and an agentless host's SSH mode, user and port. Found while building "Run command" for an SSH host, whose mode the form would not keep.

`GET /api/devices/<id>/settings` answers them under the form's own names (admin only, like the save). This file holds the route and, more to the point, the contract that would have
caught the defect: every field the form reads, and every field it posts, must be supplied by the roster or by that route. It is derived from the page's own source and the server's
syntax tree, so a tenth field added to the form without a source for it fails the build.
"""
import ast
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-drawer-settings-"))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402

PASSWORD = "correct horse battery staple 42"
_APP_JS = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(encoding="utf-8")


class _Captured(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


def _call(fn, token, args=(), method="GET", body=None):
    api._begin_request()
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = "/api/x"
    os.environ["REMOTE_ADDR"] = "203.0.113.9"
    raw = json.dumps(body or {}).encode()
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
        d = tempfile.mkdtemp(prefix="rp-drawer-settings-")
        os.environ["RP_DATA_DIR"] = d
        self._saved = {}
        for name in ("USERS_FILE", "TOKENS_FILE", "DEVICES_FILE", "AUDIT_LOG_FILE", "CONFIG_FILE", "RATELIMIT_FILE"):
            self._saved[name] = getattr(api, name)
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
        api._begin_request()
        api.ensure_default_user()
        users = api.load(api.USERS_FILE)
        users["alice"] = {"password_hash": api.hash_password(PASSWORD), "role": "admin", "created": int(time.time())}
        users["vera"] = {"password_hash": api.hash_password(PASSWORD), "role": "viewer", "created": int(time.time())}
        api.save(api.USERS_FILE, users)
        self.admin = api._mint_session("alice")
        self.viewer = api._mint_session("vera")

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(api, name, value)

    def host(self, **extra):
        rec = {"name": "web", "ip": "10.0.0.5", "token": "t", "last_seen": int(time.time())}
        rec.update(extra)
        api.save(api.DEVICES_FILE, {"d1": rec})


class TestTheSettingsRoute(_Base):

    def get(self, token=None):
        return _call(api.handle_device_settings_get, token or self.admin, args=("d1",))

    def test_it_answers_the_stored_values_under_the_names_the_form_posts_them_by(self):
        self.host(services_watched=["nginx", "sshd"], allowed_commands=["uptime", "df -h"], watched_files=["/etc/hosts"],
                  log_watch=[{"unit": "sshd", "pattern": "Failed"}], reachability="ssh", manual_status=False, ssh_user="root", ssh_port=2222, quarantined=True)
        status, body = self.get()
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {
            "watched_services": ["nginx", "sshd"], "cmd_allowlist": ["uptime", "df -h"], "watched_files": ["/etc/hosts"],
            "log_watch": [{"unit": "sshd", "pattern": "Failed"}], "reachability": "ssh", "manual_status": False, "ssh_user": "root", "ssh_port": 2222, "quarantined": True})

    def test_a_host_with_none_of_them_gets_the_defaults_the_form_has_always_shown(self):
        self.host()
        status, body = self.get()
        self.assertEqual(status, 200, body)
        self.assertEqual((body["watched_services"], body["cmd_allowlist"], body["watched_files"], body["log_watch"]), ([], [], [], []))
        self.assertEqual((body["reachability"], body["manual_status"], body["ssh_user"], body["ssh_port"], body["quarantined"]), ("icmp", True, "", 22, False))

    def test_a_record_that_holds_something_odd_is_cleaned_not_echoed(self):
        self.host(services_watched=["nginx", {"x": 1}, None, 5], allowed_commands="not a list", watched_files=[3, "/a"], log_watch=["x", {"unit": "u", "pattern": "p", "secret": "s"}],
                  reachability="bogus", ssh_port="abc", ssh_user=None)
        status, body = self.get()
        self.assertEqual(status, 200, body)
        self.assertEqual(body["watched_services"], ["nginx", "5"])
        self.assertEqual(body["cmd_allowlist"], [])
        self.assertEqual(body["watched_files"], ["/a"])
        self.assertEqual(body["log_watch"], [{"unit": "u", "pattern": "p"}])
        self.assertEqual((body["reachability"], body["ssh_port"], body["ssh_user"]), ("icmp", 22, ""))

    def test_only_an_administrator_may_read_them_as_only_an_administrator_may_save_them(self):
        self.host(allowed_commands=["uptime"])
        status, body = self.get(self.viewer)
        self.assertEqual(status, 403, body)
        self.assertNotIn("cmd_allowlist", body)

    def test_an_unknown_host_is_a_404_and_the_wrong_method_a_405(self):
        self.host()
        status, _ = _call(api.handle_device_settings_get, self.admin, args=("nope",))
        self.assertEqual(status, 404)
        status, _ = _call(api.handle_device_settings_get, self.admin, args=("d1",), method="POST")
        self.assertEqual(status, 405)

    def test_what_it_answers_is_what_a_save_of_the_same_form_leaves_unchanged(self):
        """The round trip the form makes: read, post the same values back, read again."""
        self.host(services_watched=["nginx"], allowed_commands=["uptime"], watched_files=["/etc/hosts"], log_watch=[{"unit": "sshd", "pattern": "Failed"}],
                  reachability="ssh", ssh_user="root", ssh_port=2222)
        _, before = self.get()
        post = {k: v for k, v in before.items() if k != "quarantined"}
        status, body = _call(api.handle_device_save_bulk, self.admin, args=("d1",), method="POST", body=post)
        self.assertEqual(status, 200, body)
        _, after = self.get()
        self.assertEqual(after, before)

    def test_the_route_is_in_the_dispatch_table(self):
        self.assertIn(("GET", "/api/devices/{device_id}/settings"), [tuple(x) for x in api._dispatcher_routes() if isinstance(x, (list, tuple))])


# ── the contract, from the page's own source and the server's syntax tree ───────────────────────────────────────────────────────────────────────────
def _js_function(name):
    i = _APP_JS.index("function %s(" % name)
    j = _APP_JS.index("\n}\n", i)
    return _APP_JS[i:j]


def _form_reads():
    return set(re.findall(r"\bd\.([a-zA-Z_][a-zA-Z0-9_]*)", _js_function("_renderDrawerSettings")))


def _form_posts():
    save = _js_function("_drawerSaveSettings")
    literal = save[save.index("const body = {"):save.index("\n  };", save.index("const body = {"))]
    keys = set(re.findall(r"^\s{4}([a-z_]+)\s*[:,]", literal, re.M)) | set(re.findall(r"^\s{4}([a-z_]+),?\s*$", literal, re.M))
    keys |= set(re.findall(r"\bbody\.([a-z_]+)\s*=", save))
    return keys


def _server_function(name):
    tree = ast.parse((_ROOT / "server" / "cgi-bin" / "api.py").read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)


def _roster_keys():
    out = set()
    for node in ast.walk(_server_function("handle_devices_list")):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "row" for t in node.targets) and isinstance(node.value, ast.Dict):
            out |= {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == "row" and isinstance(t.slice, ast.Constant):
                    out.add(t.slice.value)
    return out


def _settings_route_keys():
    out = set()
    for node in ast.walk(_server_function("handle_device_settings_get")):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "respond" and len(node.args) == 2 and isinstance(node.args[1], ast.Dict):
            out |= {k.value for k in node.args[1].keys if isinstance(k, ast.Constant)}
    return out


# what the form reads that is not a host field at all
_NOT_A_FIELD = {"id"}                 # the drawer's own id, the same as the roster's
# what the form posts that is the form's own, not something the host record stores under that name
_POSTED_BY_THE_FORM_ITSELF = {"name"}


class TestEveryFieldTheFormReadsOrPostsHasASource(unittest.TestCase):

    def test_the_derivations_find_something(self):
        reads, posts, roster, route = _form_reads(), _form_posts(), _roster_keys(), _settings_route_keys()
        self.assertGreater(len(reads), 15, sorted(reads))
        self.assertGreater(len(posts), 10, sorted(posts))
        self.assertGreater(len(roster), 30, sorted(roster))
        self.assertGreaterEqual(len(route), 9, sorted(route))
        for known in ("group", "tags", "monitored", "poll_interval"):
            self.assertIn(known, reads)
            self.assertIn(known, roster)
        for known in ("cmd_allowlist", "watched_services", "reachability", "ssh_port"):
            self.assertIn(known, reads)
            self.assertIn(known, posts)

    def test_every_field_the_form_reads_is_in_the_roster_or_the_settings_route(self):
        reads, roster, route = _form_reads() - _NOT_A_FIELD, _roster_keys(), _settings_route_keys()
        unsourced = sorted(reads - roster - route)
        self.assertEqual(unsourced, [], "the form reads %d fields; the roster supplies %d of them and the settings route %d: these come from nowhere, so the form opens empty for them"
                         % (len(reads), len(reads & roster), len(reads & route)))

    def test_every_field_the_form_posts_is_one_it_can_read_back(self):
        posts, roster, route = _form_posts() - _POSTED_BY_THE_FORM_ITSELF, _roster_keys(), _settings_route_keys()
        # the save handler's own names for them are the keys it tests with `'x' in body`
        accepted = {n.left.value for n in ast.walk(_server_function("handle_device_save_bulk"))
                    if isinstance(n, ast.Compare) and isinstance(n.left, ast.Constant) and isinstance(n.left.value, str) and any(isinstance(o, ast.In) for o in n.ops)}
        self.assertTrue(posts <= accepted | {"name"}, "the form posts a field the save does not take: %s" % sorted(posts - accepted))
        unreadable = sorted(posts - roster - route)
        self.assertEqual(unreadable, [], "the form posts %d fields back; these cannot be read: a save of the form clears them" % len(posts))

    def test_the_check_can_say_no(self):
        """Control: with the settings route taken away the nine fields of the defect are reported."""
        reads, roster = _form_reads() - _NOT_A_FIELD, _roster_keys()
        self.assertEqual(sorted(reads - roster), ["cmd_allowlist", "log_watch", "manual_status", "quarantined", "reachability", "ssh_port", "ssh_user", "watched_files", "watched_services"])


if __name__ == "__main__":
    unittest.main()
