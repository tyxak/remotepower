"""
Regression tests for the mitigate / batch-tracker RBAC fixes and CSV
formula-injection hardening.

Same harness style as tests/test_authz_smoke.py: import api.py as a module,
point its flat-file paths at a tmp dir, monkeypatch the auth helpers so a given
identity is "logged in", and drive the handlers directly.

Covers:
  * handle_mitigate_investigate / handle_mitigate_fix — a read-only viewer and
    an out-of-scope custom (operator) role both get 403; an in-scope operator
    is NOT blocked by RBAC.
  * handle_exec_batch_status — a scoped caller never sees per-device entries for
    out-of-scope devices.
  * handle_batch_jobs_list — a scoped caller's job counts are recomputed over
    in-scope targets only, and jobs with zero in-scope targets are omitted.
  * _csv_safe — leading =, +, -, @, tab, CR are neutralized with a leading
    single quote; benign values are untouched.
"""
import importlib.util
import os
import sys
import tempfile
import time
import pathlib
import pytest

# api.py creates DATA_DIR at import time; point it at a throwaway tmp dir so the
# import doesn't try to mkdir the production path (/var/lib/remotepower).
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

REPO  = pathlib.Path(__file__).resolve().parents[1]
APIPY = REPO / "server" / "cgi-bin" / "api.py"

spec  = importlib.util.spec_from_file_location("rp_api_mitigate", APIPY)
api   = importlib.util.module_from_spec(spec)
sys.modules["rp_api_mitigate"] = api
spec.loader.exec_module(api)

# Batch jobs carry a `created` epoch and are purged once older than the TTL, so
# tests must stamp them "now" or the handler prunes them before we ever see them.
NOW = int(time.time())


@pytest.fixture
def tmp_state(tmp_path, monkeypatch):
    """Point all relevant api.py flat-file paths at a fresh tmp dir and provide
    seed/caller helpers. Mirrors the test_authz_smoke harness.

    api.load() calls Path.exists(), so the *_FILE attributes must be Path
    objects; we seed via api.save() so writes go through the same path the
    server uses (and invalidate the per-request load cache)."""
    for attr, fn in [
        ("DEVICES_FILE", "devices.json"), ("ROLES_FILE", "roles.json"),
        ("CMDS_FILE", "cmds.json"), ("CMD_OUTPUT_FILE", "cmd_output.json"),
        ("BATCH_JOBS_FILE", "batch_jobs.json"), ("SCRIPTS_FILE", "scripts.json"),
        ("HISTORY_FILE", "history.json"), ("AUDIT_LOG_FILE", "audit.json"),
        ("WEBHOOKS_FILE", "webhooks.json"),
    ]:
        monkeypatch.setattr(api, attr, tmp_path / fn, raising=False)

    helpers = {}

    def seed_devices(devs):
        api.save(api.DEVICES_FILE, devs)

    def seed_roles(roles):
        api.save(api.ROLES_FILE, {"roles": roles})

    def seed_batch_jobs(jobs):
        api.save(api.BATCH_JOBS_FILE, {"jobs": jobs})

    def set_caller(username, role):
        monkeypatch.setattr(api, "get_token_from_request", lambda: "tok", raising=False)
        monkeypatch.setattr(api, "verify_token", lambda tok: (username, role), raising=False)

    helpers["seed_devices"]    = seed_devices
    helpers["seed_roles"]      = seed_roles
    helpers["seed_batch_jobs"] = seed_batch_jobs
    helpers["set_caller"]      = set_caller
    return helpers


def call(handler, *args):
    """Invoke a handler, returning ('ok', body) or ('http', status, body).
    api.HTTPError carries the response payload on `.body`."""
    try:
        handler(*args)
    except api.HTTPError as e:
        return ("http", e.status, e.body)
    return ("ok", None, None)


def _body(monkeypatch, payload):
    monkeypatch.setattr(api, "get_json_body", lambda: dict(payload), raising=False)


# ── mitigate investigate / fix: viewer + out-of-scope blocked ───────────────
def test_mitigate_investigate_viewer_blocked(tmp_state, monkeypatch):
    tmp_state["seed_devices"]({"dev1": {"name": "n1", "group": "prod"}})
    tmp_state["set_caller"]("v", "viewer")
    _body(monkeypatch, {"kind": "service_down", "target": "nginx"})
    kind, status, _ = call(api.handle_mitigate_investigate, "dev1")
    assert kind == "http" and status == 403


def test_mitigate_fix_viewer_blocked(tmp_state, monkeypatch):
    tmp_state["seed_devices"]({"dev1": {"name": "n1", "group": "prod"}})
    tmp_state["set_caller"]("v", "viewer")
    _body(monkeypatch, {"kind": "service_down", "target": "nginx",
                        "command": "systemctl restart nginx", "confirmation": "RUN"})
    kind, status, _ = call(api.handle_mitigate_fix, "dev1")
    assert kind == "http" and status == 403


def test_mitigate_investigate_out_of_scope_blocked(tmp_state, monkeypatch):
    tmp_state["seed_devices"]({
        "dev1": {"name": "n1", "group": "prod"},
        "dev2": {"name": "n2", "group": "dev"},
    })
    tmp_state["seed_roles"]([
        {"name": "op", "permissions": ["exec"], "scope": {"type": "groups", "values": ["prod"]}},
    ])
    tmp_state["set_caller"]("o", "op")
    _body(monkeypatch, {"kind": "service_down", "target": "nginx"})
    kind, status, _ = call(api.handle_mitigate_investigate, "dev2")
    assert kind == "http" and status == 403


def test_mitigate_fix_out_of_scope_blocked(tmp_state, monkeypatch):
    tmp_state["seed_devices"]({
        "dev1": {"name": "n1", "group": "prod"},
        "dev2": {"name": "n2", "group": "dev"},
    })
    tmp_state["seed_roles"]([
        {"name": "op", "permissions": ["exec"], "scope": {"type": "groups", "values": ["prod"]}},
    ])
    tmp_state["set_caller"]("o", "op")
    _body(monkeypatch, {"kind": "service_down", "target": "nginx",
                        "command": "systemctl restart nginx", "confirmation": "RUN"})
    kind, status, _ = call(api.handle_mitigate_fix, "dev2")
    assert kind == "http" and status == 403


def test_mitigate_investigate_in_scope_operator_not_rbac_blocked(tmp_state, monkeypatch):
    """An in-scope operator with 'exec' must NOT be blocked by RBAC. The call may
    still 400 (e.g. no playbook for the kind) but never 403."""
    tmp_state["seed_devices"]({"dev1": {"name": "n1", "group": "prod"}})
    tmp_state["seed_roles"]([
        {"name": "op", "permissions": ["exec"], "scope": {"type": "groups", "values": ["prod"]}},
    ])
    tmp_state["set_caller"]("o", "op")
    _body(monkeypatch, {"kind": "service_down", "target": "nginx"})
    kind, status, _ = call(api.handle_mitigate_investigate, "dev1")
    assert not (kind == "http" and status == 403)


# ── exec_batch_status: out-of-scope per_device entries hidden ───────────────
def test_batch_status_hides_out_of_scope_devices(tmp_state, monkeypatch):
    tmp_state["seed_devices"]({
        "dev1": {"name": "n1", "group": "prod"},
        "dev2": {"name": "n2", "group": "dev"},
    })
    tmp_state["seed_roles"]([
        {"name": "op", "permissions": ["exec"], "scope": {"type": "groups", "values": ["prod"]}},
    ])
    tmp_state["seed_batch_jobs"]({
        "job1": {
            "kind": "install", "label": "install nginx", "created": NOW, "actor": "admin",
            "match_cmd": "exec:apt-get install -y nginx",
            "per_device": {
                "dev1": {"queued": True},
                "dev2": {"queued": True},
            },
        },
    })
    tmp_state["set_caller"]("o", "op")
    kind, status, data = call(api.handle_exec_batch_status, "job1")
    assert kind == "http" and status == 200
    assert set(data["per_device"].keys()) == {"dev1"}


def test_batch_status_admin_sees_all(tmp_state, monkeypatch):
    tmp_state["seed_devices"]({
        "dev1": {"name": "n1", "group": "prod"},
        "dev2": {"name": "n2", "group": "dev"},
    })
    tmp_state["seed_batch_jobs"]({
        "job1": {
            "kind": "install", "label": "install nginx", "created": NOW, "actor": "admin",
            "match_cmd": "exec:apt-get install -y nginx",
            "per_device": {"dev1": {"queued": True}, "dev2": {"queued": True}},
        },
    })
    tmp_state["set_caller"]("a", "admin")
    kind, status, data = call(api.handle_exec_batch_status, "job1")
    assert kind == "http" and status == 200
    assert set(data["per_device"].keys()) == {"dev1", "dev2"}


# ── batch jobs list: counts scoped, zero-in-scope jobs omitted ──────────────
def test_batch_jobs_list_scopes_counts_and_omits(tmp_state, monkeypatch):
    tmp_state["seed_devices"]({
        "dev1": {"name": "n1", "group": "prod"},
        "dev2": {"name": "n2", "group": "dev"},
        "dev3": {"name": "n3", "group": "dev"},
    })
    tmp_state["seed_roles"]([
        {"name": "op", "permissions": ["exec"], "scope": {"type": "groups", "values": ["prod"]}},
    ])
    tmp_state["seed_batch_jobs"]({
        # mixed job: one in-scope (dev1), one out (dev2) → total counts only dev1
        "jobA": {
            "kind": "install", "label": "install nginx", "created": NOW, "actor": "admin",
            "match_cmd": "exec:apt-get install -y nginx",
            "per_device": {"dev1": {"queued": True}, "dev2": {"queued": True}},
        },
        # entirely out-of-scope job → omitted from a scoped caller's view
        "jobB": {
            "kind": "install", "label": "install secret-pkg", "created": NOW - 10, "actor": "admin",
            "match_cmd": "exec:apt-get install -y secret-pkg",
            "per_device": {"dev2": {"queued": True}, "dev3": {"queued": True}},
        },
    })
    tmp_state["set_caller"]("o", "op")
    kind, status, data = call(api.handle_batch_jobs_list)
    assert kind == "http" and status == 200
    jobs = {j["id"]: j for j in data["jobs"]}
    assert set(jobs.keys()) == {"jobA"}          # jobB omitted (no in-scope target)
    assert jobs["jobA"]["total"] == 1            # only dev1 counted
    # the out-of-scope package label must not leak
    assert all("secret-pkg" not in j["label"] for j in data["jobs"])


def test_batch_jobs_list_admin_unchanged(tmp_state, monkeypatch):
    tmp_state["seed_devices"]({
        "dev1": {"name": "n1", "group": "prod"},
        "dev2": {"name": "n2", "group": "dev"},
    })
    tmp_state["seed_batch_jobs"]({
        "jobA": {
            "kind": "install", "label": "install nginx", "created": NOW, "actor": "admin",
            "match_cmd": "exec:apt-get install -y nginx",
            "per_device": {"dev1": {"queued": True}, "dev2": {"queued": True}},
        },
    })
    tmp_state["set_caller"]("a", "admin")
    kind, status, data = call(api.handle_batch_jobs_list)
    assert kind == "http" and status == 200
    jobs = {j["id"]: j for j in data["jobs"]}
    assert jobs["jobA"]["total"] == 2


# ── CSV formula-injection neutralization ────────────────────────────────────
@pytest.mark.parametrize("raw", ["=cmd()", "+1+1", "-2+3", "@SUM(A1)", "\tfoo", "\rbar"])
def test_csv_safe_quotes_dangerous_leading_chars(raw):
    out = api._csv_safe(raw)
    assert out == "'" + raw


@pytest.mark.parametrize("raw", ["nginx", "web-01", "prod", "Ubuntu 22.04", ""])
def test_csv_safe_leaves_benign_untouched(raw):
    assert api._csv_safe(raw) == raw


def test_csv_safe_passes_non_strings(tmp_state):
    assert api._csv_safe(5) == 5
    assert api._csv_safe(None) is None
