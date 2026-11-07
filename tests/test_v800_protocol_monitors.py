#!/usr/bin/env python3
"""8.0.0: the smtp, imap, ssh and ntp monitor types through the product: the target sanitizer, the save validator, the runner and the form.

test_v800_protocol_probes holds the handshakes themselves against real sockets. This holds what the product does around them:

* the target is `host` or `host:port` with the protocol's own port when none is given, and the SSRF guard of a tcp monitor applies (metadata and
  link-local always refused, loopback only when allowed);
* a save keeps `tls` and `verify_tls` for smtp and imap, `max_offset_ms` for ntp, only when they differ from the default, and refuses a value that
  is not one of the choices or a sane number;
* these types run from the server: a host's agent and a satellite do not run them, and say so;
* the runner reaches the probe with the address check wired to the server's setting, and a monitor is a result with the same keys as any other;
* the form has the four types, shows each type's own fields, and the step-by-step form owns them.
"""
import io
import json
import os
import re
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v700_documented_config_keys as cfgkeys  # noqa: E402
import test_v800_protocol_probes as pp  # noqa: E402

api = cfgkeys.api
ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / "server" / "html" / "static" / "js"


def setUpModule():
    pp.setUpModule()


def tearDownModule():
    pp.tearDownModule()


def set_internal(allow):
    api.save(api.CONFIG_FILE, {"allow_internal_monitors": bool(allow)})
    api._LOAD_CACHE.clear()


class TestTheTarget(unittest.TestCase):

    def target(self, mtype, raw):
        set_internal(False)
        return api._sanitize_monitor_target(mtype, raw, with_reason=True)

    def test_the_protocols_own_port_is_used_when_none_is_given(self):
        for mtype, raw, want in (("smtp", "mail.example.org", "mail.example.org:25"), ("imap", "imap.example.org", "imap.example.org:143"),
                                 ("ssh", "10.1.2.3", "10.1.2.3:22"), ("ntp", "pool.ntp.org", "pool.ntp.org:123"),
                                 ("smtp", "mail.example.org:587", "mail.example.org:587"), ("imap", "h.example:993", "h.example:993"),
                                 ("ntp", "ntp.example:1123", "ntp.example:1123"), ("ssh", " host.example : 2222", "host.example:2222")):
            with self.subTest(mtype=mtype, raw=raw):
                self.assertEqual(self.target(mtype, raw), (want, None))

    def test_a_target_that_is_not_an_address_is_refused_with_the_reason(self):
        for mtype in pp.P.TYPES:
            for raw in ("", "-oProxyCommand=x", "host:abc", "host:0", "host:65536", "host:-1", "host:1e3"):
                with self.subTest(mtype=mtype, raw=raw):
                    got, why = self.target(mtype, raw)
                    self.assertIsNone(got)
                    self.assertTrue(why)

    def test_metadata_and_link_local_are_always_refused_and_loopback_only_when_allowed(self):
        for mtype in pp.P.TYPES:
            with self.subTest(mtype=mtype):
                self.assertIsNone(self.target(mtype, "169.254.169.254")[0])
                self.assertIsNone(self.target(mtype, "169.254.10.10:25")[0])
                self.assertIsNone(self.target(mtype, "127.0.0.1")[0])
                set_internal(True)
                self.assertIsNotNone(api._sanitize_monitor_target(mtype, "127.0.0.1"))
                self.assertIsNone(api._sanitize_monitor_target(mtype, "169.254.169.254"), "metadata is refused even when loopback is allowed")
                set_internal(False)

    def test_a_private_lan_address_is_fine(self):
        for mtype in pp.P.TYPES:
            self.assertEqual(self.target(mtype, "192.168.1.20")[0].split(":")[0], "192.168.1.20")

    def test_shell_characters_never_survive(self):
        got, _ = self.target("ssh", "host;rm -rf /$(x)`y`")
        self.assertEqual(got, "hostrm-rfxy:22", "everything but letters, digits, dots and dashes is dropped")
        self.assertNotRegex(got, r"[;$` /()]")


class TestTheSave(cfgkeys._Base):

    def mon(self, **kw):
        m = {"label": "m1", "type": "smtp", "target": "mail.example.org"}
        m.update(kw)
        return m

    def saved(self, **kw):
        st, cfg = self.save({"monitors": [self.mon(**kw)]})
        return st, (cfg.get("monitors") or [None])[0]

    def test_a_plain_smtp_monitor_stores_nothing_extra(self):
        st, m = self.saved()
        self.assertEqual(st, 200)
        self.assertEqual(m, {"label": "m1", "type": "smtp", "target": "mail.example.org:25", "target_kind": "host", "paused": False})

    def test_the_connection_security_is_stored_only_when_it_is_not_none(self):
        self.assertNotIn("tls", self.saved(tls="none")[1])
        for mode in ("starttls", "tls"):
            for mtype in ("smtp", "imap"):
                st, m = self.saved(type=mtype, tls=mode)
                self.assertEqual((st, m["tls"]), (200, mode))

    def test_an_unknown_connection_security_is_refused_by_name(self):
        for bad in ("STARTTLS", "ssl", "starttls ", True, 5, ["tls"], {"a": 1}):
            with self.subTest(bad=repr(bad)):
                st, m = self.saved(tls=bad)
                self.assertEqual(st, 400)

    def test_not_checking_the_certificate_is_kept_only_with_encryption(self):
        self.assertEqual(self.saved(tls="starttls", verify_tls=False)[1]["verify_tls"], False)
        self.assertNotIn("verify_tls", self.saved(tls="none", verify_tls=False)[1], "nothing to verify on a plain connection")
        self.assertNotIn("verify_tls", self.saved(tls="starttls", verify_tls=True)[1], "checking is the default and is not stored")
        self.assertNotIn("verify_tls", self.saved(tls="starttls", verify_tls="no")[1], "only a real false turns the check off")

    def test_ssh_and_ntp_take_no_connection_security(self):
        for mtype in ("ssh", "ntp"):
            self.assertNotIn("tls", self.saved(type=mtype, tls="starttls")[1])

    def test_the_largest_offset_is_kept_for_ntp_as_a_whole_number(self):
        self.assertEqual(self.saved(type="ntp", max_offset_ms=250)[1]["max_offset_ms"], 250)
        self.assertEqual(self.saved(type="ntp", max_offset_ms=250.9)[1]["max_offset_ms"], 250)
        self.assertEqual(self.saved(type="ntp", max_offset_ms=pp.P.MAX_OFFSET_MS)[1]["max_offset_ms"], pp.P.MAX_OFFSET_MS)
        for none in (None, ""):
            self.assertNotIn("max_offset_ms", self.saved(type="ntp", max_offset_ms=none)[1])

    def test_an_offset_that_is_not_a_sane_number_is_refused(self):
        for bad in (True, False, 0, -1, pp.P.MAX_OFFSET_MS + 1, "100", [], {}, float("nan"), float("inf")):
            with self.subTest(bad=repr(bad)):
                self.assertEqual(self.saved(type="ntp", max_offset_ms=bad)[0], 400)

    def test_other_types_do_not_keep_the_new_fields(self):
        for mtype, target in (("tcp", "h:22"), ("ping", "h"), ("dns", "h"), ("ssh", "h")):
            m = self.saved(type=mtype, target=target, tls="starttls", max_offset_ms=100)[1]
            self.assertNotIn("max_offset_ms", m)
            self.assertNotIn("tls", m)

    def test_a_tag_or_a_group_cannot_be_a_handshake_target(self):
        for mtype in pp.P.TYPES:
            for kind in ("tag", "group"):
                self.assertEqual(self.saved(type=mtype, target_kind=kind, target="prod")[0], 400, (mtype, kind))

    def test_a_target_that_is_refused_is_a_400_with_the_reason(self):
        st, _ = self.saved(type="ntp", target="169.254.169.254")
        self.assertEqual(st, 400)
        self.assertEqual(self.captured[-1][1]["monitor"], "m1")

    def test_a_monitor_of_an_unknown_type_is_still_dropped(self):
        st, cfg = self.save({"monitors": [self.mon(type="ftp")]})
        self.assertEqual((st, cfg.get("monitors")), (200, []))


class TestWhereTheyMayRun(unittest.TestCase):
    """The four handshakes run from the server, and from a host's agent or a satellite that says it runs them: an older one drops a type it does
    not know without a word, and its monitor would wait for a first result for ever, so the server assigns it none and says why."""

    ALL = ["tcp", "http", "ping", "smtp", "imap", "ssh", "ntp"]

    def setUp(self):
        api.save(api.DEVICES_FILE, {"old": {"id": "old", "name": "old", "os": "Ubuntu 24.04", "sysinfo": {}, "tags": []},
                                    "new": {"id": "new", "name": "new", "os": "Ubuntu 24.04", "sysinfo": {"probe_types": self.ALL}, "tags": []},
                                    "some": {"id": "some", "name": "some", "os": "Ubuntu 24.04", "sysinfo": {"probe_types": ["tcp", "http", "ping", "ntp"]}, "tags": []},
                                    "junk": {"id": "junk", "name": "junk", "os": "Ubuntu 24.04", "sysinfo": {"probe_types": "smtp"}, "tags": []}})
        api.save(api.SATELLITES_FILE, {"sat-old": {"name": "old"}, "sat-new": {"name": "new", "probe_types": self.ALL}, "sat-junk": {"name": "junk", "probe_types": "smtp"}})
        api._LOAD_CACHE.clear()

    def sat(self, sid, mtype):
        return api.satellite_probe_validate(mtype, {"target": "h" if mtype == "ping" else "h:1", "target_kind": "host", "via_satellite": sid})

    def test_a_satellite_that_does_not_say_it_runs_a_type_is_refused_with_the_reason_and_one_that_does_is_not(self):
        for mtype in pp.P.TYPES:
            why = self.sat("sat-old", mtype)
            self.assertIn("does not say it runs %s monitors" % mtype, why, mtype)
            self.assertEqual(self.sat("sat-new", mtype), "", mtype)
        for mtype in ("tcp", "ping"):
            self.assertEqual(self.sat("sat-old", mtype), "", "the three it has always run need no word: " + mtype)
        self.assertIn("does not say it runs smtp", self.sat("sat-junk", "smtp"), "a declaration that is not a list says nothing")
        self.assertIn("tcp, http, ping, smtp, imap, ssh and ntp", self.sat("sat-new", "dns"))
        self.assertIn("does not say it runs", self.sat("sat-gone", "smtp"), "a satellite that is not registered says nothing")

    def test_an_agent_that_does_not_say_it_runs_a_type_is_refused_with_the_reason_and_one_that_does_is_not(self):
        for mtype in pp.P.TYPES:
            self.assertIn("does not say it runs %s monitors" % mtype, api.host_probe_validate("old", mtype, {"target": "h:1"}), mtype)
            self.assertEqual(api.host_probe_validate("new", mtype, {"target": "h:1"}), "", mtype)
        self.assertEqual(api.host_probe_validate("some", "ntp", {"target": "pool.ntp.org"}), "")
        self.assertIn("does not say it runs smtp", api.host_probe_validate("some", "smtp", {"target": "h:1"}))
        for mtype in ("tcp", "ping"):
            self.assertEqual(api.host_probe_validate("old", mtype, {"target": "h" if mtype == "ping" else "h:1"}), "")
        self.assertIn("does not say it runs smtp", api.host_probe_validate("junk", "smtp", {"target": "h:1"}), "a declaration that is not a list says nothing")
        self.assertIn("a host probes tcp, http, ping, smtp, imap, ssh and ntp", api.host_probe_validate("new", "dns", {"target": "h:1"}),
                      "a type no prober runs is refused as that, and not as one this host has not said")

    def test_the_target_of_a_handshake_is_a_host_or_host_and_port_and_the_metadata_address_is_never_probed(self):
        for target in ("mail.lan", "mail.lan:587", "10.0.0.5:25", "127.0.0.1:2525"):
            self.assertEqual(api.host_probe_validate("new", "smtp", {"target": target}), "", target)
        for target, words in (("", "expected host"), ("mail.lan:0", "port"), ("mail.lan:70000", "port"), ("mail.lan:abc", "expected host"), ("bad host:25", "expected host"),
                              ("169.254.169.254:25", "not allowed"), ("-x:25", "expected host")):
            self.assertIn(words, api.host_probe_validate("new", "smtp", {"target": target}), target)

    def test_the_spec_a_prober_gets_carries_the_tls_mode_and_the_offset_and_nothing_it_would_run_wrongly(self):
        spec = api.monitor_spec({"label": "mail", "type": "smtp", "target": "mail.lan:587", "tls": "starttls", "verify_tls": False})
        self.assertEqual((spec["type"], spec["target"], spec["tls"], spec["verify_tls"], spec["max_offset_ms"]), ("smtp", "mail.lan:587", "starttls", False, None))
        spec = api.monitor_spec({"label": "clock", "type": "ntp", "target": "pool.ntp.org", "max_offset_ms": 250})
        self.assertEqual((spec["max_offset_ms"], spec["tls"]), (250, None))
        spec = api.monitor_spec({"label": "x", "type": "smtp", "target": "h", "tls": "rot13", "max_offset_ms": True})
        self.assertEqual((spec["tls"], spec["max_offset_ms"]), (None, None), "a TLS mode that is not one of the three and a boolean are left out")

    def test_a_host_is_sent_the_monitors_of_the_types_its_agent_runs_and_a_satellite_those_it_says_on_the_call(self):
        cfg = {"monitors": [{"label": "a", "type": "smtp", "target": "h:25", "via_host": "old"}, {"label": "b", "type": "tcp", "target": "h:25", "via_host": "old"},
                            {"label": "c", "type": "smtp", "target": "h:25", "via_host": "new"},
                            {"label": "d", "type": "imap", "target": "h:143", "via_satellite": "sat-new"}, {"label": "e", "type": "ssh", "target": "h:22", "via_satellite": "sat-new"}]}
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        devs = api.load(api.DEVICES_FILE)
        self.assertEqual([m["label"] for m in api.host_monitors_for("old", devs["old"])], ["b"], "an older agent is sent the type it runs and not the one it would drop")
        self.assertEqual([m["label"] for m in api.host_monitors_for("new", devs["new"])], ["c"])
        self.assertEqual(api.host_probe_handlers_mod.clean_types("tcp, SMTP ,ssh,rot13,"), ["tcp", "smtp", "ssh"])
        self.assertEqual(api.host_probe_handlers_mod.clean_types(""), ["tcp", "http", "ping"])
        self.assertEqual(api.host_probe_handlers_mod.clean_types(["smtp"] * 50 + [5, None]), ["smtp"])
        self.assertEqual(api.host_probe_handlers_mod.clean_types(["rot13"]), ["tcp", "http", "ping"], "nothing it knows is what an older prober says")

    def test_a_host_and_a_satellite_still_run_the_three_they_always_did(self):
        self.assertEqual(api.host_probe_handlers_mod.SUPPORTED, ("tcp", "http", "ping"))
        self.assertEqual(api.host_probe_handlers_mod.known_types(), ("tcp", "http", "ping", "smtp", "imap", "ssh", "ntp"))


class _Captured(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


def _run(fn, body=None, env=None, method="POST"):
    """A handler run as a request: (status, body) of what it answered, or (None, None) when it returned."""
    names = ("REQUEST_METHOD", "PATH_INFO", "REMOTE_ADDR", "CONTENT_LENGTH", "HTTP_X_RP_SATELLITE", "HTTP_X_RP_PROBES")
    saved_env = {n: os.environ.get(n) for n in names}
    api._begin_request()
    raw = b"" if body is None else json.dumps(body).encode()
    os.environ.update(REQUEST_METHOD=method, PATH_INFO="/api/x", REMOTE_ADDR="203.0.113.50", CONTENT_LENGTH=str(len(raw)))
    for k in ("HTTP_X_RP_SATELLITE", "HTTP_X_RP_PROBES"):
        os.environ.pop(k, None)
    os.environ.update(env or {})
    saved_stdin, saved_respond = sys.stdin, api.respond

    def fake(status, data=None, *a, **k):
        raise _Captured(status, data)
    sys.stdin, api.respond = _Stdin(raw), fake
    try:
        try:
            fn()
            return None, None
        except _Captured as c:
            return c.status, c.body
    finally:
        sys.stdin, api.respond = saved_stdin, saved_respond
        for n, v in saved_env.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v
        api._LOAD_CACHE.clear()


class TestAssigningToAProber(cfgkeys._Base):
    """The monitor dialog offers every host and satellite for every type. The server decides: it takes a handshake monitor for a prober that says it
    runs the type and refuses it, in words, for one that does not."""

    ALL = ["tcp", "http", "ping", "smtp", "imap", "ssh", "ntp"]

    def setUp(self):
        super().setUp()
        api.save(api.DEVICES_FILE, {"old": {"id": "old", "name": "old", "os": "Ubuntu 24.04", "sysinfo": {}, "tags": []},
                                    "new": {"id": "new", "name": "new", "os": "Ubuntu 24.04", "sysinfo": {"probe_types": self.ALL}, "tags": []}})
        api.save(api.SATELLITES_FILE, {"sat-old": {"name": "o", "token_hash": "x"}, "sat-new": {"name": "n", "token_hash": "y", "probe_types": self.ALL}})
        api._LOAD_CACHE.clear()

    def mon(self, **kw):
        return dict({"label": "mail", "type": "smtp", "target": "mail.lan:25"}, **kw)

    def test_a_host_whose_agent_runs_the_type_is_assigned_it_and_one_that_does_not_is_refused_in_words(self):
        st, cfg = self.save({"monitors": [self.mon(via_host="new")]})
        self.assertEqual((st, cfg["monitors"][0].get("via_host")), (200, "new"))
        st, _ = self.save({"monitors": [self.mon(via_host="old")]})
        self.assertEqual(st, 400)
        self.assertIn("the agent on that host does not say it runs smtp monitors", json.dumps(self.captured[-1][1]))
        st, cfg = self.save({"monitors": [self.mon(via_host="old", type="tcp", target="mail.lan:25")]})
        self.assertEqual((st, cfg["monitors"][0].get("via_host")), (200, "old"), "the three it has always run need no word")

    def test_a_satellite_that_runs_the_type_is_assigned_it_and_one_that_does_not_is_refused_in_words(self):
        st, cfg = self.save({"monitors": [self.mon(via_satellite="sat-new", type="ntp", target="pool.ntp.org", max_offset_ms=500)]})
        self.assertEqual((st, cfg["monitors"][0].get("via_satellite")), (200, "sat-new"))
        st, _ = self.save({"monitors": [self.mon(via_satellite="sat-old")]})
        self.assertEqual(st, 400)
        self.assertIn("that satellite does not say it runs smtp monitors", json.dumps(self.captured[-1][1]))

    def test_only_the_json_true_says_the_agent_can_roll_back_a_compose_update(self):
        api.save(api.DEVICES_FILE, {"d1": {"id": "d1", "name": "box", "os": "Ubuntu 24.04", "token": "tok", "last_seen": 0, "sysinfo": {}}})
        api._LOAD_CACHE.clear()

        def beat(**si):
            st, _ = _run(api.handle_heartbeat, {"device_id": "d1", "token": "tok", "version": "8.0.0", "sysinfo": dict({"hostname": "box"}, **si)})
            self.assertEqual(st, 200)
            api._LOAD_CACHE.clear()
            return api.load(api.DEVICES_FILE)["d1"]["sysinfo"]
        self.assertNotIn("compose_rollback", beat())
        self.assertIs(beat(compose_rollback=True)["compose_rollback"], True)
        for said in (False, "true", "yes", 1, [True], {"a": 1}, None):
            self.assertIs(beat(compose_rollback=said)["compose_rollback"], False, said)

    def test_a_heartbeat_keeps_the_types_the_agent_says_in_a_fixed_order_and_nothing_it_does_not_know(self):
        api.save(api.DEVICES_FILE, {"d1": {"id": "d1", "name": "box", "os": "Ubuntu 24.04", "token": "tok", "last_seen": 0, "sysinfo": {}}})
        api._LOAD_CACHE.clear()
        for said, kept in ((["ntp", "tcp", "smtp", "rot13", 5, None], ["tcp", "smtp", "ntp"]), (list(self.ALL) * 3, self.ALL), ([], ["tcp", "http", "ping"]),
                           (["rot13"], ["tcp", "http", "ping"])):
            st, _ = _run(api.handle_heartbeat, {"device_id": "d1", "token": "tok", "version": "8.0.0", "sysinfo": {"hostname": "box", "probe_types": said}})
            self.assertEqual(st, 200)
            self.assertEqual(api.load(api.DEVICES_FILE)["d1"]["sysinfo"].get("probe_types"), kept, said)
        for not_a_list in ("smtp", 5, {"smtp": True}, None):
            _run(api.handle_heartbeat, {"device_id": "d1", "token": "tok", "version": "8.0.0", "sysinfo": {"hostname": "box", "probe_types": not_a_list}})
            self.assertNotIn("probe_types", api.load(api.DEVICES_FILE)["d1"]["sysinfo"], "a value that is not a list is not kept: %r" % (not_a_list,))

    def test_a_call_a_satellite_makes_says_what_it_runs_and_a_relayed_agent_call_leaves_it_alone(self):
        tok = "sat-secret-token"
        api.save(api.SATELLITES_FILE, {"sat-1": {"name": "s1", "token_hash": api._satellite_token_hash(tok), "probe_types": ["tcp", "http", "ping"]}})
        api._LOAD_CACHE.clear()
        _run(api._record_satellite, env={"HTTP_X_RP_SATELLITE": tok, "HTTP_X_RP_PROBES": "tcp, http, ping, smtp, bogus"})
        self.assertEqual(api.load(api.SATELLITES_FILE)["sat-1"]["probe_types"], ["tcp", "http", "ping", "smtp"])
        _run(api._record_satellite, env={"HTTP_X_RP_SATELLITE": tok})
        self.assertEqual(api.load(api.SATELLITES_FILE)["sat-1"]["probe_types"], ["tcp", "http", "ping", "smtp"], "an agent behind the satellite says nothing, so nothing changes")
        _run(api._record_satellite, env={"HTTP_X_RP_SATELLITE": tok, "HTTP_X_RP_PROBES": "tcp,http,ping"})
        self.assertEqual(api.load(api.SATELLITES_FILE)["sat-1"]["probe_types"], ["tcp", "http", "ping"], "a satellite that was replaced by an older one is believed again")
        st, _ = _run(api._record_satellite, env={"HTTP_X_RP_SATELLITE": "wrong", "HTTP_X_RP_PROBES": "smtp"})
        self.assertEqual(st, 401)
        self.assertEqual(api.load(api.SATELLITES_FILE)["sat-1"]["probe_types"], ["tcp", "http", "ping"], "a call with a token that is not a satellite's records nothing")

    def test_the_work_a_satellite_is_handed_is_the_types_it_says_on_that_call(self):
        tok = "sat-secret-token"
        api.save(api.SATELLITES_FILE, {"sat-1": {"name": "s1", "token_hash": api._satellite_token_hash(tok)}})
        api.save(api.CONFIG_FILE, {"monitors": [
            {"label": "a", "type": "smtp", "target": "mail.lan:587", "tls": "starttls", "verify_tls": False, "via_satellite": "sat-1"},
            {"label": "b", "type": "tcp", "target": "h:22", "via_satellite": "sat-1"},
            {"label": "c", "type": "ntp", "target": "pool.ntp.org:123", "max_offset_ms": 250, "via_satellite": "sat-1"},
            {"label": "d", "type": "imap", "target": "h:143", "via_satellite": "sat-1", "paused": True},
            {"label": "e", "type": "ssh", "target": "h:22", "via_satellite": "sat-other"}]})
        api._LOAD_CACHE.clear()
        st, body = _run(api.handle_satellite_monitor_work, env={"HTTP_X_RP_SATELLITE": tok, "HTTP_X_RP_PROBES": ",".join(self.ALL)}, method="GET")
        self.assertEqual(st, 200)
        self.assertEqual([m["label"] for m in body["monitors"]], ["a", "b", "c"], "its own, not paused, of the types it says")
        spec = {m["label"]: m for m in body["monitors"]}
        self.assertEqual((spec["a"]["tls"], spec["a"]["verify_tls"], spec["c"]["max_offset_ms"]), ("starttls", False, 250))
        st, body = _run(api.handle_satellite_monitor_work, env={"HTTP_X_RP_SATELLITE": tok}, method="GET")
        self.assertEqual([m["label"] for m in body["monitors"]], ["b"], "a satellite that says nothing is handed the three it has always run")
        st, body = _run(api.handle_satellite_monitor_work, env={"HTTP_X_RP_SATELLITE": tok, "HTTP_X_RP_PROBES": "tcp,smtp"}, method="GET")
        self.assertEqual([m["label"] for m in body["monitors"]], ["a", "b"])


class TestTheRunner(unittest.TestCase):

    def check(self, mtype, port, **m):
        entry = dict({"type": mtype, "target": "127.0.0.1:%d" % port, "label": "x"}, **m)
        return api._run_one_monitor_check(mtype, entry["target"], "x", entry)

    def setUp(self):
        set_internal(True)
        self.addCleanup(set_internal, False)

    def serve(self, handler):
        s = pp._Tcp(handler)
        self.addCleanup(s.stop)
        return s

    def test_each_type_reaches_its_probe_and_returns_the_usual_result(self):
        servers = {"smtp": self.serve(pp.smtp()), "imap": self.serve(pp.imap()), "ssh": self.serve(pp.banner(b"SSH-2.0-test\r\n"))}
        ntp = pp._Ntp()
        self.addCleanup(ntp.stop)
        for mtype, port in (("smtp", servers["smtp"].port), ("imap", servers["imap"].port), ("ssh", servers["ssh"].port), ("ntp", ntp.port)):
            with self.subTest(mtype=mtype):
                r = self.check(mtype, port)
                self.assertTrue(r["ok"], r)
                for key in ("label", "type", "target", "ok", "detail", "checked", "ms"):
                    self.assertIn(key, r)
                self.assertEqual(r["type"], mtype)

    def test_a_failing_service_is_a_failing_result_with_the_reason(self):
        r = self.check("smtp", self.serve(pp.smtp(greeting=b"554 no\r\n")).port)
        self.assertFalse(r["ok"])
        self.assertIn("554", r["detail"])
        r = self.check("ssh", self.serve(pp.banner(b"220 hello\r\n" * 9)).port)
        self.assertEqual((r["ok"], r["detail"]), (False, "no SSH banner"))

    def test_the_servers_setting_decides_whether_loopback_may_be_probed(self):
        s = self.serve(pp.banner(b"SSH-2.0-test\r\n"))
        set_internal(False)
        r = self.check("ssh", s.port)
        self.assertEqual((r["ok"], r["detail"]), (False, "blocked"))
        set_internal(True)
        self.assertTrue(self.check("ssh", s.port)["ok"])

    def test_the_certificate_is_checked_unless_the_monitor_says_not_to(self):
        s = self.serve(pp.smtp())
        r = self.check("smtp", s.port, tls="starttls")
        self.assertEqual((r["ok"], r["detail"]), (False, "TLS: the certificate was not accepted"))
        s2 = self.serve(pp.smtp())
        self.assertTrue(self.check("smtp", s2.port, tls="starttls", verify_tls=False)["ok"])

    def test_the_offset_limit_reaches_the_probe(self):
        ntp = pp._Ntp(skew=5.0)
        self.addCleanup(ntp.stop)
        r = self.check("ntp", ntp.port, max_offset_ms=1000)
        self.assertFalse(r["ok"])
        self.assertIn("limit 1000 ms", r["detail"])

    def test_a_target_that_will_not_parse_is_an_error_result_not_an_exception(self):
        r = api._run_one_monitor_check("smtp", "no-port-here", "x", {"type": "smtp"})
        self.assertEqual((r["ok"], r["detail"]), (False, "error"))

    def test_the_whole_path_from_a_saved_monitor_to_a_result(self):
        s = self.serve(pp.smtp())
        m = {"label": "mail", "type": "smtp", "target": "127.0.0.1:%d" % s.port, "target_kind": "host"}
        results = api._execute_monitor_checks([m])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["ok"], results[0])
        self.assertEqual(results[0]["label"], "mail")

    def test_a_paused_one_is_not_probed(self):
        s = self.serve(pp.smtp())
        m = {"label": "mail", "type": "smtp", "target": "127.0.0.1:%d" % s.port, "paused": True}
        self.assertEqual(api._execute_monitor_checks([m]), [])
        time.sleep(0.05)
        self.assertEqual(s.seen, [])


class TestTheForm(unittest.TestCase):

    HTML = (ROOT / "server" / "html" / "index.html").read_text()
    APP = (JS / "app.js").read_text()
    WIZ = (JS / "app-wizard.js").read_text()

    def test_the_four_types_are_offered_with_the_words_that_say_what_they_do_not_do(self):
        sel = re.search(r'<select id="mon-type"[^>]*>(.*?)</select>', self.HTML, re.S).group(1)
        offered = dict(re.findall(r'<option value="([a-z_]+)">([^<]*)</option>', sel))
        for mtype, words in (("smtp", "no mail sent"), ("imap", "no login"), ("ssh", "no login"), ("ntp", "clock offset")):
            self.assertIn(mtype, offered)
            self.assertIn(words, offered[mtype])

    def test_the_form_values_the_server_reads_are_the_ones_it_accepts(self):
        sel = re.search(r'<select id="mon-mail-tls"[^>]*>(.*?)</select>', self.HTML, re.S).group(1)
        self.assertEqual(re.findall(r'<option value="([a-z]+)"', sel), list(pp.P.TLS_MODES))
        self.assertRegex(self.HTML, r'<input type="number" id="mon-ntp-offset"[^>]*min="1"[^>]*max="%d"' % pp.P.MAX_OFFSET_MS)

    def test_each_type_shows_its_own_fields_and_the_certificate_box_only_where_it_applies(self):
        import srcpin
        body = srcpin.js_function(self.APP, "monTypeChanged")
        self.assertIn("show('mon-mailtls-grp', type === 'smtp' || type === 'imap')", body)
        self.assertIn("show('mon-ntp-grp', type === 'ntp')", body)
        self.assertIn("show('mon-tls-grp', type === 'http' || type === 'smtp' || type === 'imap')", body)

    def test_the_form_reads_and_writes_the_new_fields(self):
        import srcpin
        save = srcpin.js_function(self.APP, "addMonitor")
        self.assertIn("entry.tls = sec", save)
        self.assertIn("entry.max_offset_ms = Math.round(o)", save)
        self.assertIn("type === 'http' || type === 'smtp' || type === 'imap'", save)
        self.assertIn("set('mon-mail-tls', m.tls || 'none'); set('mon-ntp-offset', m.max_offset_ms);", self.APP)
        self.assertIn("set('mon-mail-tls', 'none'); set('mon-ntp-offset', '');", self.APP)

    def test_the_step_by_step_form_owns_both_groups(self):
        self.assertIn("'mon-mailtls-grp', 'mon-ntp-grp'", self.WIZ)

    def test_the_guide_lists_the_four_types(self):
        doc = (ROOT / "docs" / "monitors.md").read_text()
        for t in pp.P.TYPES:
            self.assertRegex(doc, r"\| `%s` \|" % t)
        self.assertIn("Mail, SSH and NTP checks", doc)


if __name__ == "__main__":
    unittest.main()
