#!/usr/bin/env python3
"""7.4.9: an enrolment token can be limited to the networks it may be used from.

A token minted for a build network or a cloud project was good from anywhere on the internet until it expired or was used, so a copy
of it taken from a log or a chat could enrol a host. `allowed_cidrs` on `POST /api/enrollment-tokens` makes it work from those
networks only. The refusal leaves the token alone: a copy used from the wrong place must not use up the token meant for the right
one. A limit that cannot be read refuses; it does not open the token to everyone.

Everything runs through the real create and register handlers, with the client address taken the way the server takes it
(REMOTE_ADDR, and the forwarded address when the peer is the local proxy).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402


class TestTheNetworkList(unittest.TestCase):

    def clean(self, raw):
        return api._clean_enroll_cidrs(raw)

    def test_addresses_and_networks_in_a_list_or_a_string(self):
        self.assertEqual(self.clean(["10.0.0.0/24", "192.168.1.5"]), (["10.0.0.0/24", "192.168.1.5/32"], None))
        self.assertEqual(self.clean("10.0.0.0/24, 192.168.1.5\n2001:db8::/32  fe80::1"),
                         (["10.0.0.0/24", "192.168.1.5/32", "2001:db8::/32", "fe80::1/128"], None))

    def test_host_bits_are_cut_and_repeats_are_one(self):
        self.assertEqual(self.clean(["10.0.0.77/24", "10.0.0.0/24", "10.0.0.5", "10.0.0.5/32"]), (["10.0.0.0/24", "10.0.0.5/32"], None))

    def test_nothing_is_no_limit(self):
        for empty in (None, "", [], "   ,  "):
            self.assertEqual(self.clean(empty), ([], None), empty)

    def test_what_cannot_be_read_is_an_error_not_a_guess(self):
        for bad in (["not-an-ip"], ["10.0.0.0/33"], ["10.0.0.0/24", "x"], [5], [None], [["10.0.0.0/8"]], {"a": 1}, 7, ["999.1.1.1"],
                    ["10.0.0.0/8; drop"], ["10.0.0.0/8\x00"]):
            out, err = self.clean(bad)
            self.assertIsNone(out, bad)
            self.assertTrue(err, bad)

    def test_a_network_that_matches_everything_is_refused(self):
        for bad in (["0.0.0.0/0"], ["::/0"], "10.0.0.0/8 0.0.0.0/0", ["0.0.0.0/0", "10.0.0.0/8"]):
            out, err = self.clean(bad)
            self.assertIsNone(out, bad)
            self.assertIn("every address", err)

    def test_the_cap(self):
        ok = [f"10.0.{i}.0/24" for i in range(api.MAX_ENROLL_CIDRS)]
        self.assertEqual(self.clean(ok)[1], None)
        self.assertIn("at most", self.clean(ok + ["10.9.9.0/24"])[1])

    def test_membership(self):
        nets = ["10.0.0.0/24", "2001:db8::/32"]
        for ip, want in (("10.0.0.5", True), ("10.0.1.5", False), ("2001:db8::1", True), ("2001:db9::1", False),
                         ("::ffff:10.0.0.9", True), ("::ffff:10.0.1.9", False), ("not an ip", False), ("", False), (None, False)):
            self.assertEqual(api._ip_in_cidrs(ip, nets), want, ip)
        self.assertFalse(api._ip_in_cidrs("10.0.0.5", []))
        self.assertFalse(api._ip_in_cidrs("10.0.0.5", ["junk", 5, None]))
        self.assertFalse(api._ip_in_cidrs("10.0.0.5", ["2001:db8::/32"]))        # a version that does not match


class _Enrol(_Base):
    STORES = _Base.STORES + ("RATELIMIT_FILE",)

    def setUp(self):
        super().setUp()
        self._env = {k: os.environ.get(k) for k in ("REMOTE_ADDR", "HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP")}
        for k in self._env:
            os.environ.pop(k, None)
        self.audits = []
        api.audit_log = lambda *a, **k: self.audits.append(a)
        self._rl = api._ip_ratelimit
        api._ip_ratelimit = lambda *a, **k: True

    def tearDown(self):
        api._ip_ratelimit = self._rl
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        super().tearDown()

    def mint(self, **body):
        st, d = self.call(api.handle_enroll_token_create, body=dict({"label": "t"}, **body), who="platform")
        return st, d

    def register(self, token, ip, name="newhost", **env):
        os.environ["REMOTE_ADDR"] = ip
        for k, v in env.items():
            os.environ[k] = v
        try:
            return self.call(api.handle_enroll_register, who=None, body={"enrollment_token": token, "hostname": name, "name": name})
        finally:
            for k in env:
                os.environ.pop(k, None)

    def stored(self):
        return list((api.load(api.ENROLL_TOKENS_FILE) or {}).values())


class TestMinting(_Enrol):

    def test_the_networks_are_stored_cleaned_and_returned(self):
        st, d = self.mint(allowed_cidrs=["10.0.0.5", "192.168.0.0/16"])
        self.assertEqual(st, 201, d)
        self.assertEqual(d["allowed_cidrs"], ["10.0.0.5/32", "192.168.0.0/16"])
        self.assertEqual(self.stored()[0]["allowed_cidrs"], ["10.0.0.5/32", "192.168.0.0/16"])
        self.assertIn("only_from", self.audits[-1][2])

    def test_a_token_without_a_limit_is_as_it_was(self):
        st, d = self.mint()
        self.assertEqual((st, d["allowed_cidrs"]), (201, []))
        self.assertNotIn("allowed_cidrs", self.stored()[0])

    def test_a_bad_list_is_refused_and_no_token_is_made(self):
        for bad in (["nope"], ["0.0.0.0/0"], [f"10.0.{i}.0/24" for i in range(30)], {"a": 1}, [5]):
            st, d = self.mint(allowed_cidrs=bad)
            self.assertEqual(st, 400, (bad, d))
        self.assertEqual(self.stored(), [])

    def test_the_list_shows_the_networks_without_the_token(self):
        self.mint(allowed_cidrs=["10.0.0.0/24"])
        self.mint()
        st, rows = self.call(api.handle_enroll_token_list, m="GET", who="platform")
        self.assertEqual(st, 200)
        self.assertEqual(sorted(len(r["allowed_cidrs"]) for r in rows), [0, 1])
        self.assertNotIn("token", rows[0])


class TestUsingIt(_Enrol):

    def test_from_the_right_network_it_enrols_and_is_used_up(self):
        _, d = self.mint(allowed_cidrs=["10.0.0.0/24"])
        st, r = self.register(d["token"], "10.0.0.7")
        self.assertIn(st, (200, 201), r)
        self.assertEqual(self.stored(), [], "a used token is gone")

    def test_from_the_wrong_network_it_is_refused_and_kept(self):
        _, d = self.mint(allowed_cidrs=["10.0.0.0/24"])
        st, r = self.register(d["token"], "203.0.113.9")
        self.assertEqual(st, 403, r)
        self.assertIn("cannot be used from this address", r["error"])
        self.assertEqual(len(self.stored()), 1, "the refusal must not use the token up")
        self.assertEqual(self.audits[-1][1], "enrollment_token_refused_source")
        self.assertIn("203.0.113.9", self.audits[-1][2])
        # the right address still works afterwards
        st, r = self.register(d["token"], "10.0.0.7")
        self.assertIn(st, (200, 201), r)

    def test_a_token_with_no_limit_works_from_anywhere(self):
        _, d = self.mint()
        st, r = self.register(d["token"], "203.0.113.9")
        self.assertIn(st, (200, 201), r)

    def test_behind_the_local_proxy_the_forwarded_address_is_the_client(self):
        _, d = self.mint(allowed_cidrs=["10.0.0.0/24"])
        st, _ = self.register(d["token"], "127.0.0.1", HTTP_X_FORWARDED_FOR="203.0.113.9")
        self.assertEqual(st, 403)
        st, r = self.register(d["token"], "127.0.0.1", HTTP_X_FORWARDED_FOR="10.0.0.20")
        self.assertIn(st, (200, 201), r)

    def test_an_address_the_server_cannot_read_is_refused(self):
        _, d = self.mint(allowed_cidrs=["10.0.0.0/24"])
        for ip in ("", "garbage", "0.0.0.0"):
            st, _ = self.register(d["token"], ip)
            self.assertEqual(st, 403, ip)
        self.assertEqual(len(self.stored()), 1)

    def test_a_limit_stored_in_a_shape_nobody_can_read_refuses(self):
        _, d = self.mint(allowed_cidrs=["10.0.0.0/24"])
        for broken in ("10.0.0.0/24", 5, {"a": 1}, ["junk"], [None, 5]):
            toks = api.load(api.ENROLL_TOKENS_FILE)
            for meta in toks.values():
                meta["allowed_cidrs"] = broken
            api.save(api.ENROLL_TOKENS_FILE, toks)
            st, r = self.register(d["token"], "10.0.0.7")
            self.assertEqual(st, 403, (broken, r))

    def test_ipv6_and_mapped_addresses(self):
        _, d = self.mint(allowed_cidrs=["2001:db8::/32"])
        self.assertEqual(self.register(d["token"], "2001:dba::1")[0], 403)
        self.assertIn(self.register(d["token"], "2001:db8::77")[0], (200, 201))
        _, d = self.mint(allowed_cidrs=["10.0.0.0/24"])
        self.assertIn(self.register(d["token"], "::ffff:10.0.0.9", name="h2")[0], (200, 201))


class TestWiring(unittest.TestCase):

    def test_the_request_model_carries_the_field_and_the_guide_says_so(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "server", "cgi-bin", "request_models.py"), encoding="utf-8") as f:
            self.assertTrue("allowed_cidrs" in f.read())
        with open(os.path.join(root, "docs", "admin-guide.md"), encoding="utf-8") as f:
            self.assertTrue("allowed_cidrs" in f.read())


if __name__ == "__main__":
    unittest.main()
