#!/usr/bin/env python3
"""Stand-ins and drivers shared by the tests of what a Windows agent reports about its host.

The Windows agent cannot run here, so each test replaces what it reads with the thing's real shape and runs the agent's own functions on it:

  * `FakeWinreg` is the standard library's `winreg` as far as the agent uses it, and behaves as the real module does: a key that is not there is
    FileNotFoundError, a value that is not there is FileNotFoundError, paths and value names are not case sensitive, a handle that was closed
    cannot be read, and any name of the real module the agent reaches for that is not read-only (SetValueEx, CreateKey, DeleteKey, ...) is
    recorded and is not there.
  * `beat` sends a heartbeat through the real handler and `call` runs a real handler as a caller of a given role; both put back what they set.

This module does not import api.py: the test module that does pins RP_DATA_DIR first and passes the module in.
"""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / "server" / "cgi-bin"
WIN_AGENT = ROOT / "client" / "remotepower-agent-win.py"

SZ, DWORD = 1, 4
# the access bits that write: set value, create subkey, create link, delete, write dac, write owner
WRITE_BITS = 0x2 | 0x4 | 0x20 | 0x10000 | 0x40000 | 0x80000


def load_agent(name="rp_win_host_agent", path=WIN_AGENT):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeWinreg:
    """`winreg` for HKEY_LOCAL_MACHINE. `tree` is {key path: {value name: (value, type)}}; a key exists when it is in the tree or when a
    key below it is."""

    HKEY_LOCAL_MACHINE = 0x80000002
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x0100
    KEY_WOW64_32KEY = 0x0200
    REG_SZ = SZ
    REG_DWORD = DWORD

    def __init__(self, tree):
        self.tree = {path.lower(): {name.lower(): item for name, item in values.items()} for path, values in tree.items()}
        self.opened = []
        self.access = []
        self.reached_for = []
        self.reads = []

    def __getattr__(self, name):
        if not name.startswith("__"):
            self.reached_for.append(name)
        raise AttributeError(name)

    class _Handle:
        def __init__(self, path):
            self.path, self.closed = path, False

    def OpenKey(self, key, sub_key, reserved=0, access=0x20019):  # noqa: N802 (the real name)
        self.access.append(access)
        if reserved != 0:
            raise OSError(87, "The parameter is incorrect")
        if key == self.HKEY_LOCAL_MACHINE:
            full = sub_key.lower()
        else:
            if key.closed:
                raise OSError("handle is closed")
            full = key.path + "\\" + sub_key.lower()
        if not any(p == full or p.startswith(full + "\\") for p in self.tree):
            raise FileNotFoundError(2, "The system cannot find the file specified")
        handle = self._Handle(full)
        self.opened.append(handle)
        return handle

    def QueryValueEx(self, key, name):  # noqa: N802
        if key.closed:
            raise OSError("handle is closed")
        self.reads.append((key.path, name))
        try:
            return self.tree[key.path][name.lower()]
        except KeyError:
            raise FileNotFoundError(2, "The system cannot find the file specified") from None

    def CloseKey(self, key):  # noqa: N802
        key.closed = True

    @property
    def leaked(self):
        """The handles that were opened and not closed."""
        return [h.path for h in self.opened if not h.closed]

    @property
    def wrote(self):
        """Whether any key was opened with a right that writes."""
        return any(a & WRITE_BITS for a in self.access)


# ── what a real Windows 11 host writes under the key the build comes from ────────────────────────────────────────────────
NT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def nt_values(**over):
    """The values of HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion on a Windows 11 23H2 Pro host. Windows 11 keeps writing
    "Windows 10 Pro" into ProductName, which is why the family is read from the build number."""
    values = {
        "CurrentBuildNumber": ("22631", SZ),
        "CurrentBuild": ("22631", SZ),
        "UBR": (3593, DWORD),
        "DisplayVersion": ("23H2", SZ),
        "ReleaseId": ("2009", SZ),
        "ProductName": ("Windows 10 Pro", SZ),
        "EditionID": ("Professional", SZ),
        "InstallationType": ("Client", SZ),
    }
    values.update(over)
    return {k: v for k, v in values.items() if v is not None}


# ── drivers for the real handlers ────────────────────────────────────────────────────────────────────────────────────────
def beat(api, dev_id, token, sysinfo, **extra):
    """Send one heartbeat through the real handler. Returns (status, body)."""
    body = {"device_id": dev_id, "token": token, "sysinfo": sysinfo}
    body.update(extra)
    saved = {n: getattr(api, n) for n in ("respond", "get_json_obj", "method")}
    box = {}

    def respond(status, data=None):
        box["answer"] = (status, data)
        raise api.HTTPError(status, data)

    api.respond = respond
    api.get_json_obj = lambda: json.loads(json.dumps(body))
    api.method = lambda: "POST"
    try:
        try:
            api.handle_heartbeat()
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box["answer"]


def call(api, handler, *path, role="admin", verb="GET", query="", body=None, user="alice"):
    """Run one handler for real as a caller of `role`. Only verify_token is stubbed, so the handler's own gates run. Returns (status, body)."""
    saved = {n: getattr(api, n) for n in ("verify_token", "respond", "get_json_obj", "get_json_body", "audit_log")}
    box = {}

    def respond(status, data=None):
        box["answer"] = (status, data)
        raise api.HTTPError(status, data)

    api.verify_token = lambda token: (user, role)
    api.respond = respond
    api.get_json_obj = lambda: json.loads(json.dumps(body or {}))
    api.get_json_body = api.get_json_obj
    api.audit_log = lambda *a, **k: None
    api._RCTX.environ = {"REQUEST_METHOD": verb, "QUERY_STRING": query, "HTTP_X_TOKEN": "t"}
    try:
        try:
            handler(*path)
        except api.HTTPError as e:
            # a conditional GET raises HTTPError itself, with the body on the exception
            if "answer" not in box and getattr(e, "body", None) is not None:
                box["answer"] = (e.status, e.body)
    finally:
        api._RCTX.environ = None
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box.get("answer", (None, None))
