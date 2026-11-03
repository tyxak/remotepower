#!/usr/bin/env python3
"""7.4.9: the S3 client of the off-host backup copy.

The signing is checked against the examples AWS publishes for Signature Version 4 on S3 (a GET with a Range header, a PUT with
a storage class, and the two bucket queries), so a mistake in it cannot be matched by a mistake in this test. The client then
talks to a store written here: it answers PUT, GET, DELETE and a paged listing, verifies the signature of every request from the
bytes it received (the path as sent, the query, the body's digest, the Host header), and can be told to misbehave.
"""
import calendar
import datetime as dt
import hashlib
import http.client
import http.server
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import s3_client as s3  # noqa: E402

AK, SK = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
NS = "http://s3.amazonaws.com/doc/2006-03-01/"
WHEN = dt.datetime(2013, 5, 24, 0, 0, 0, tzinfo=dt.timezone.utc)


def signature_of(headers: dict) -> str:
    return headers["Authorization"].rsplit("Signature=", 1)[1]


class TestSigningAgainstThePublishedExamples(unittest.TestCase):
    """The four S3 examples of the Signature Version 4 documentation. The bucket is examplebucket and the date 24 May 2013."""

    def sign(self, method, path, query=None, headers=None, payload=s3.EMPTY_SHA256):
        return s3.sign_request(method, "examplebucket.s3.amazonaws.com", path, query or {}, headers or {}, payload, AK, SK, "us-east-1", WHEN)

    def test_get_object_with_a_range(self):
        h = self.sign("GET", "/test.txt", headers={"Range": "bytes=0-9"})
        self.assertEqual(signature_of(h), "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
        self.assertIn("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,", h["Authorization"])
        self.assertTrue(h["Authorization"].startswith(f"AWS4-HMAC-SHA256 Credential={AK}/20130524/us-east-1/s3/aws4_request, "))

    def test_put_object_with_a_storage_class_and_a_dollar_sign_in_the_name(self):
        body = b"Welcome to Amazon S3."
        h = self.sign("PUT", "/test$file.text", headers={"Date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class": "REDUCED_REDUNDANCY"},
                      payload=hashlib.sha256(body).hexdigest())
        self.assertEqual(signature_of(h), "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")
        self.assertIn("SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,", h["Authorization"])

    def test_a_bucket_query_with_no_value(self):
        h = self.sign("GET", "/", query={"lifecycle": ""})
        self.assertEqual(signature_of(h), "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543")

    def test_a_listing_with_two_parameters(self):
        h = self.sign("GET", "/", query={"max-keys": "2", "prefix": "J"})
        self.assertEqual(signature_of(h), "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")

    def test_the_instant_is_what_counts_not_the_zone_it_is_written_in(self):
        tokyo = dt.timezone(dt.timedelta(hours=9))
        same = WHEN.astimezone(tokyo)
        self.assertEqual(same, WHEN)
        a = s3.sign_request("GET", "examplebucket.s3.amazonaws.com", "/test.txt", {}, {}, s3.EMPTY_SHA256, AK, SK, "us-east-1", WHEN)
        b = s3.sign_request("GET", "examplebucket.s3.amazonaws.com", "/test.txt", {}, {}, s3.EMPTY_SHA256, AK, SK, "us-east-1", same)
        self.assertEqual(a["Authorization"], b["Authorization"])
        self.assertEqual(b["x-amz-date"], "20130524T000000Z")

    def test_the_secret_and_the_region_and_the_time_matter(self):
        base = signature_of(self.sign("GET", "/test.txt"))
        other_secret = s3.sign_request("GET", "examplebucket.s3.amazonaws.com", "/test.txt", {}, {}, s3.EMPTY_SHA256, AK, SK + "x", "us-east-1", WHEN)
        other_region = s3.sign_request("GET", "examplebucket.s3.amazonaws.com", "/test.txt", {}, {}, s3.EMPTY_SHA256, AK, SK, "eu-west-1", WHEN)
        later = s3.sign_request("GET", "examplebucket.s3.amazonaws.com", "/test.txt", {}, {}, s3.EMPTY_SHA256, AK, SK, "us-east-1", WHEN + dt.timedelta(seconds=1))
        self.assertEqual(len({base, signature_of(other_secret), signature_of(other_region), signature_of(later)}), 4)

    def test_header_values_are_trimmed_and_their_spaces_collapsed_before_signing(self):
        tidy = self.sign("PUT", "/a", headers={"x-amz-meta-note": "a b"})
        messy = self.sign("PUT", "/a", headers={"X-Amz-Meta-Note ": "  a   b \t"})
        self.assertEqual(signature_of(tidy), signature_of(messy))
        self.assertIn("x-amz-meta-note", messy["Authorization"])

    def test_the_headers_given_are_kept_and_the_secret_is_not_in_any_of_them(self):
        h = self.sign("PUT", "/a", headers={"x-amz-meta-rp-sha256": "ab"})
        self.assertEqual(h["x-amz-meta-rp-sha256"], "ab")
        self.assertNotIn(SK, " ".join(h.values()))
        self.assertEqual(h["x-amz-date"], "20130524T000000Z")


class TestEncoding(unittest.TestCase):

    def test_uri_encode(self):
        cases = {"abc-_.~09": "abc-_.~09", "a b": "a%20b", "a+b": "a%2Bb", "a/b": "a%2Fb", "$": "%24", "é": "%C3%A9", "a=b&c": "a%3Db%26c", "": "", "%": "%25"}
        for raw, want in cases.items():
            self.assertEqual(s3.uri_encode(raw), want, raw)
        self.assertEqual(s3.uri_encode("a b/c+d", keep_slash=True), "a%20b/c%2Bd")

    def test_the_query_is_sorted_after_encoding_and_keeps_an_empty_value(self):
        self.assertEqual(s3.canonical_query({"prefix": "a b", "list-type": "2", "x": ""}), "list-type=2&prefix=a%20b&x=")
        self.assertEqual(s3.canonical_query({}), "")


class TestSettings(unittest.TestCase):

    def ok(self, **kw):
        base = {"enabled": True, "endpoint": "https://s3.example.org", "bucket": "my-backups", "access_key_id": "AKIAEXAMPLE"}
        return s3.clean_settings(dict(base, **kw), resolver=lambda *a, **k: [(2, 1, 6, "", ("203.0.113.5", 0))])

    def bad(self, **kw):
        with self.assertRaises(ValueError) as cm:
            self.ok(**kw)
        return str(cm.exception)

    def test_a_good_set_in_one_shape(self):
        c = self.ok(region="eu-central-1", prefix="/rp/main", path_style=False, verify_tls=False)
        self.assertEqual(c, {"enabled": True, "endpoint": "https://s3.example.org", "bucket": "my-backups", "region": "eu-central-1", "prefix": "rp/main/",
                             "access_key_id": "AKIAEXAMPLE", "path_style": False, "verify_tls": False})
        d = self.ok()
        self.assertEqual((d["region"], d["prefix"], d["path_style"], d["verify_tls"]), ("us-east-1", "", True, True))

    def test_nothing_set_and_not_enabled_is_the_off_state(self):
        self.assertEqual(s3.clean_settings({"enabled": False}), {"enabled": False})
        self.assertEqual(s3.clean_settings({}), {"enabled": False})
        self.assertFalse(self.ok(enabled=False)["enabled"])
        self.assertTrue(self.ok(enabled=True)["enabled"])
        self.assertFalse(self.ok(enabled="yes")["enabled"], "only a real true switches it on")

    def test_the_endpoint(self):
        self.assertEqual(self.ok(endpoint="https://S3.Example.org:443/")["endpoint"], "https://s3.example.org", "the default port is dropped")
        self.assertEqual(self.ok(endpoint="https://s3.example.org:9000")["endpoint"], "https://s3.example.org:9000")
        for bad in ("", "s3.example.org", "ftp://s3.example.org", "file:///etc/passwd", "https://", "https://u:p@s3.example.org", "https://s3.example.org/bucket",
                    "https://s3.example.org?x=1", "https://s3.example.org#f", "https://s3.example.org:99999", "https://s3.example.org:abc", "https://-bad.example",
                    "https://bad_host.example", "javascript:alert(1)", "https://s3 .example.org"):
            self.bad(endpoint=bad)

    def test_plain_http_only_for_a_private_or_loopback_address(self):
        def resolver(answer):
            return lambda *a, **k: [(2, 1, 6, "", (ip, 0)) for ip in answer]
        for host, answer in (("minio.lan", ["192.168.1.9"]), ("minio.lan", ["10.0.0.4", "10.0.0.5"]), ("localhost", ["127.0.0.1"]), ("localhost", ["::1"]),
                             ("minio.lan", ["172.16.5.5"]), ("ula.lan", ["fd12:3456::1"])):
            c = s3.clean_settings({"enabled": True, "endpoint": f"http://{host}:9000", "bucket": "bkt", "access_key_id": "k"}, resolver=resolver(answer))
            self.assertEqual(c["endpoint"], f"http://{host}:9000")
        for host, answer in (("s3.example.org", ["203.0.113.5"]), ("mixed.example", ["10.0.0.4", "93.184.216.34"]), ("nowhere.example", []),
                             ("meta.example", ["169.254.169.254"]), ("cgnat.example", ["100.64.0.1"]), ("v6.example", ["2606:4700::1111"]),
                             ("linklocal6.example", ["fe80::1"])):
            with self.assertRaises(ValueError, msg=host) as cm:
                s3.clean_settings({"enabled": True, "endpoint": f"http://{host}", "bucket": "bkt", "access_key_id": "k"}, resolver=resolver(answer))
            self.assertIn("use https", str(cm.exception))

        def broken(*a, **k):
            raise OSError("no resolver")
        with self.assertRaises(ValueError):
            s3.clean_settings({"enabled": True, "endpoint": "http://down.example", "bucket": "bkt", "access_key_id": "k"}, resolver=broken)

    def test_the_bucket(self):
        for good in ("abc", "my-backups", "a.b.c", "b" * 63):
            self.assertEqual(self.ok(bucket=good)["bucket"], good)
        for bad in ("", "ab", "UPPER", "-lead", "trail-", "a..b", "has space", "b" * 64, "a/b", "..", "a_b"):
            self.bad(bucket=bad)

    def test_the_prefix(self):
        for bad in ("../x", "a/../b", "a b", "a\nb", "x" * 201, "a;b", "a%2e%2e"):
            self.bad(prefix=bad)
        self.assertEqual(self.ok(prefix="a/b/")["prefix"], "a/b/")
        self.assertEqual(self.ok(prefix="")["prefix"], "")
        self.assertEqual(self.ok(prefix="...")["prefix"], "..../".replace("....", "..."), "dots are not a parent reference")

    def test_the_region_and_the_key_id(self):
        for bad in ("", "x" * 33, "-eu", "eu west", "eu;west"):
            if bad:
                self.bad(region=bad)
        for bad in ("", "a b", "a\nb", "x" * 129, "a;b", "a'b"):
            self.bad(access_key_id=bad)
        self.assertEqual(self.ok(access_key_id="a+b/c=d.e_f-g")["access_key_id"], "a+b/c=d.e_f-g")

    def test_junk(self):
        for junk in (None, "x", 5, [], [1]):
            with self.assertRaises(ValueError):
                s3.clean_settings(junk)
        for v in (None, 5, [], {"a": 1}, True):
            self.bad(bucket=v)
            self.bad(endpoint=v)


class TestParsing(unittest.TestCase):

    def doc(self, ns=True, extra="", truncated=False, token=""):
        n = f' xmlns="{NS}"' if ns else ""
        return (f'<?xml version="1.0" encoding="UTF-8"?><ListBucketResult{n}><Name>b</Name><Prefix>p/</Prefix><KeyCount>2</KeyCount>'
                f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>" + (f"<NextContinuationToken>{token}</NextContinuationToken>" if token else "") +
                "<Contents><Key>p/remotepower_data_1.tar.gz</Key><LastModified>2026-11-01T03:00:01.000Z</LastModified><ETag>&quot;x&quot;</ETag><Size>1234</Size></Contents>"
                "<Contents><Key>p/remotepower_data_2.tar.gz.enc</Key><LastModified>2026-11-02T03:00:01Z</LastModified><Size>99</Size></Contents>" + extra +
                "</ListBucketResult>").encode()

    def test_a_listing_with_and_without_the_namespace(self):
        for ns in (True, False):
            items, truncated, token = s3.parse_list(self.doc(ns=ns))
            self.assertEqual([i["key"] for i in items], ["p/remotepower_data_1.tar.gz", "p/remotepower_data_2.tar.gz.enc"])
            self.assertEqual([i["size"] for i in items], [1234, 99])
            self.assertEqual(items[0]["mtime"], calendar.timegm((2026, 11, 1, 3, 0, 1)))
            self.assertEqual((truncated, token), (False, ""))

    def test_a_truncated_listing_names_the_next_page(self):
        _, truncated, token = s3.parse_list(self.doc(truncated=True, token="abc123=="))
        self.assertEqual((truncated, token), (True, "abc123=="))

    def test_a_size_or_a_time_that_is_junk_is_zero_and_an_entry_without_a_key_is_dropped(self):
        extra = "<Contents><Key>p/x</Key><LastModified>tomorrow</LastModified><Size>lots</Size></Contents><Contents><Size>5</Size></Contents>"
        items, _, _ = s3.parse_list(self.doc(extra=extra))
        by = {i["key"]: i for i in items}
        self.assertEqual((by["p/x"]["size"], by["p/x"]["mtime"]), (0, 0))
        self.assertEqual(len(items), 3)
        items, _, _ = s3.parse_list(self.doc(extra="<Contents><Key>p/neg</Key><Size>-5</Size></Contents>"))
        self.assertEqual({i["key"]: i["size"] for i in items}["p/neg"], 0)

    def test_what_is_not_a_listing(self):
        for body in (b"", b"not xml", b"<Error><Code>X</Code></Error>", b"<html></html>", b"\x00\x01"):
            with self.assertRaises(ValueError, msg=body):
                s3.parse_list(body)

    def test_a_document_type_is_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><ListBucketResult>&lol2;</ListBucketResult>'
        with self.assertRaises(ValueError):
            s3.parse_list(bomb)

    def test_times(self):
        self.assertEqual(s3.parse_time("2013-09-17T18:07:53.000Z"), calendar.timegm((2013, 9, 17, 18, 7, 53)))
        self.assertEqual(s3.parse_time("2013-09-17T18:07:53Z"), calendar.timegm((2013, 9, 17, 18, 7, 53)))
        for junk in ("", "x", "2013-13-45T99:99:99Z", None):
            self.assertEqual(s3.parse_time(junk), 0, junk)  # type: ignore[arg-type]


class TestPruning(unittest.TestCase):
    DAY = 86400

    def items(self, *ages, now=1_800_000_000):
        return [{"name": f"remotepower_data_{i:03d}.tar.gz", "size": 1, "mtime": now - a * self.DAY} for i, a in enumerate(ages)]

    def test_old_archives_go_and_the_newest_stays_whatever_its_age(self):
        now = 1_800_000_000
        got = s3.expired(self.items(40, 30, 20, 3, 1, now=now), now, 14)
        self.assertEqual(got, ["remotepower_data_000.tar.gz", "remotepower_data_001.tar.gz", "remotepower_data_002.tar.gz"])
        self.assertEqual(s3.expired(self.items(90, 80, now=now), now, 14), ["remotepower_data_000.tar.gz"], "the newest is kept even when it is old")

    def test_the_one_just_uploaded_is_never_deleted(self):
        now = 1_800_000_000
        it = self.items(100, 100, 100, now=now)
        got = s3.expired(it, now, 14, spare=it[0]["name"])
        self.assertNotIn(it[0]["name"], got)

    def test_only_archives_are_candidates(self):
        now = 1_800_000_000
        it = self.items(40, 1, now=now) + [{"name": "notes.txt", "size": 1, "mtime": 1}, {"name": "remotepower_data_x.tar.gz.bak", "size": 1, "mtime": 1},
                                           {"name": "sub/remotepower_data_9.tar.gz", "size": 1, "mtime": 1}, {"name": "remotepower_connection-test.txt", "size": 1, "mtime": 1}]
        self.assertEqual(s3.expired(it, now, 14), ["remotepower_data_000.tar.gz"])

    def test_a_time_of_zero_is_not_old(self):
        now = 1_800_000_000
        it = self.items(1, now=now) + [{"name": "remotepower_data_zzz.tar.gz", "size": 1, "mtime": 0}]
        self.assertEqual(s3.expired(it, now, 14), [])

    def test_a_cap_and_the_floor_on_the_days(self):
        now = 1_800_000_000
        it = self.items(*([60] * 80 + [1]), now=now)
        self.assertEqual(len(s3.expired(it, now, 14)), 50)
        self.assertEqual(len(s3.expired(it, now, 14, max_delete=3)), 3)
        ages = self.items(3, 2, 0.8, 0.2, now=now)
        self.assertEqual(s3.expired(ages, now, 0), s3.expired(ages, now, 1), "0 days means 1, not 'all'")
        self.assertEqual(s3.expired(ages, now, 0), ["remotepower_data_000.tar.gz", "remotepower_data_001.tar.gz"], "the one 0.8 days old is within a day")
        self.assertEqual(s3.expired([], now, 14), [])

    def test_newest_archive(self):
        now = 1_800_000_000
        self.assertEqual(s3.newest_archive(self.items(5, 1, 9, now=now))["name"], "remotepower_data_001.tar.gz")
        self.assertIsNone(s3.newest_archive([]))
        self.assertIsNone(s3.newest_archive([{"name": "x.txt", "size": 1, "mtime": 5}]))


# ── a store to talk to ────────────────────────────────────────────────────────────────────────────────────────────────


class FakeStore:
    """Objects, settings that make it misbehave, and a log of what it saw. Path style only: the bucket is the first path segment."""

    def __init__(self):
        self.objects: dict = {}
        self.deny: set = set()               # {"put", "get", "delete", "list"}
        self.page = 1000                     # most keys a listing page returns
        self.tamper = False                  # flip a byte of every object it returns
        self.no_namespace = False
        self.requests: list = []
        self.bad_auth = 0
        self.garbage_error: Any = None       # a body to send with a 500
        self.ignore_prefix = False           # a listing that returns every key, whatever was asked for
        self.ignore_max_keys = False         # ... and every key on one page
        self.list_padding = 0                # bytes of XML comment added to a listing
        self.short_read = False              # an object that is cut short after its headers
        self.redirect_gets_to = ""           # answer a GET with a 307 to this URL
        self.hang_up = False                 # close the connection without a word
        self.garbage_status = False          # answer with something that is not HTTP
        self.reset_midway = False            # start an answer to a GET and reset the connection in the middle of it
        self.reset_midway_writes = False     # ... and the same for the answer to a PUT or a DELETE, after the change is made


def make_server(store: FakeStore, bucket="bkt", secret=SK, tls=None):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _err(self, status, code, msg):
            body = f"<Error><Code>{code}</Code><Message>{msg}</Message></Error>".encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _verify(self, body):
            parts = urllib.parse.urlsplit(self.path)
            raw_path = urllib.parse.unquote(parts.path)
            query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
            auth = self.headers.get("Authorization", "")
            try:
                signed_names = auth.split("SignedHeaders=")[1].split(",")[0].split(";")
            except IndexError:
                return False
            extra = {n: self.headers[n] for n in signed_names if n not in ("host", "x-amz-content-sha256", "x-amz-date")}
            if self.headers.get("x-amz-content-sha256") != hashlib.sha256(body).hexdigest():
                return False
            when = dt.datetime.strptime(self.headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
            want = s3.sign_request(self.command, self.headers["Host"], raw_path, query, extra, self.headers["x-amz-content-sha256"], AK, secret, "us-east-1", when)
            return want["Authorization"] == auth

        def _handle(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            store.requests.append((self.command, self.path, dict(self.headers)))
            if store.hang_up:
                self.close_connection = True
                return None
            if store.garbage_status:
                self.wfile.write(b"this is not http\r\n\r\n")
                self.close_connection = True
                return None
            if not self._verify(body):
                store.bad_auth += 1
                return self._err(403, "SignatureDoesNotMatch", "The request signature we calculated does not match")
            if store.reset_midway and self.command == "GET":
                self.send_response(200)
                self.send_header("Content-Length", "100000")
                self.end_headers()
                self.wfile.write(b"<partial")
                self.wfile.flush()
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                self.connection.close()
                self.close_connection = True
                return None
            if store.reset_midway_writes and self.command in ("PUT", "DELETE"):
                self.send_response(200)
                self.send_header("Content-Length", "100000")
                self.end_headers()
                self.wfile.write(b"<partial")
                self.wfile.flush()
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                self.connection.close()
                self.close_connection = True
                return None
            parts = urllib.parse.urlsplit(self.path)
            segs = urllib.parse.unquote(parts.path).lstrip("/").split("/", 1)
            if segs[0] != bucket:
                return self._err(404, "NoSuchBucket", "The specified bucket does not exist")
            key = segs[1] if len(segs) > 1 else ""
            if self.command == "GET" and store.redirect_gets_to:
                self.send_response(307)
                self.send_header("Location", store.redirect_gets_to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            if self.command == "GET" and not key:
                return self._list(urllib.parse.parse_qs(parts.query))
            if self.command == "PUT":
                if "put" in store.deny:
                    return self._err(403, "AccessDenied", "Access Denied")
                if store.garbage_error is not None:
                    body500 = store.garbage_error
                    self.send_response(500)
                    self.send_header("Content-Length", str(len(body500)))
                    self.end_headers()
                    self.wfile.write(body500)
                    return None
                store.objects[key] = {"data": body, "mtime": int(time.time()) + len(store.objects), "meta": self.headers.get("x-amz-meta-rp-sha256")}
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            if self.command == "GET":
                if "get" in store.deny:
                    return self._err(403, "AccessDenied", "Access Denied")
                obj = store.objects.get(key)
                if obj is None:
                    return self._err(404, "NoSuchKey", "The specified key does not exist.")
                data = bytearray(obj["data"])
                if store.tamper and data:
                    data[0] ^= 0xFF
                self.send_response(200)
                self.send_header("Content-Length", str(len(data) + (10 if store.short_read else 0)))
                if obj["meta"]:
                    self.send_header("x-amz-meta-rp-sha256", obj["meta"])
                self.end_headers()
                self.wfile.write(bytes(data))
                if store.short_read:
                    self.close_connection = True
                return None
            if self.command == "DELETE":
                if "delete" in store.deny:
                    return self._err(403, "AccessDenied", "Access Denied")
                store.objects.pop(key, None)
                self.send_response(204)
                self.end_headers()
                return None
            return self._err(405, "MethodNotAllowed", "no")

        def _list(self, q):
            if "list" in store.deny:
                return self._err(403, "AccessDenied", "Access Denied")
            prefix = "" if store.ignore_prefix else q.get("prefix", [""])[0]
            token = q.get("continuation-token", ["0"])[0]
            maxk = 10**9 if store.ignore_max_keys else min(int(q.get("max-keys", ["1000"])[0]), store.page)
            keys = sorted(k for k in store.objects if k.startswith(prefix))
            start = int(token) if token.isdigit() else 0
            page = keys[start:start + maxk]
            more = start + maxk < len(keys)
            ns = "" if store.no_namespace else f' xmlns="{NS}"'
            xml = (f'<?xml version="1.0"?><ListBucketResult{ns}><Name>{bucket}</Name><Prefix>{prefix}</Prefix>'
                   f"<IsTruncated>{'true' if more else 'false'}</IsTruncated>" + (f"<NextContinuationToken>{start + maxk}</NextContinuationToken>" if more else ""))
            for k in page:
                o = store.objects[k]
                t = dt.datetime.fromtimestamp(o["mtime"], dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                xml += f"<Contents><Key>{k}</Key><LastModified>{t}</LastModified><Size>{len(o['data'])}</Size></Contents>"
            xml += ("<!--" + "x" * store.list_padding + "-->") if store.list_padding else ""
            xml += "</ListBucketResult>"
            body = xml.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_PUT = do_DELETE = _handle

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Base(unittest.TestCase):
    prefix = "rp/main/"

    def setUp(self):
        self.store = FakeStore()
        self.srv = make_server(self.store)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-s3-"))
        self.endpoint = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def client(self, **kw):
        args = dict(endpoint=self.endpoint, region="us-east-1", bucket="bkt", access_key=AK, secret_key=SK, prefix=self.prefix, timeout=10)
        args.update(kw)
        return s3.S3Client(**args)

    def file(self, name="remotepower_data_20261102_030001.tar.gz", data=b"archive bytes " * 1000):
        p = self.tmp / name
        p.write_bytes(data)
        return p


class TestTheClientAgainstAStore(_Base):

    def test_a_file_goes_up_and_comes_back_the_same(self):
        c = self.client()
        p = self.file()
        digest = c.put_file(p.name, str(p))
        self.assertEqual(digest, hashlib.sha256(p.read_bytes()).hexdigest())
        self.assertEqual(list(self.store.objects), [self.prefix + p.name], "stored under the prefix")
        out = self.tmp / "back.bin"
        got = c.get_file(p.name, str(out))
        self.assertEqual(out.read_bytes(), p.read_bytes())
        self.assertEqual((got["bytes"], got["sha256"], got["recorded_sha256"]), (p.stat().st_size, digest, digest))
        self.assertEqual(self.store.bad_auth, 0, "every request verified")

    def test_a_copy_that_changed_in_the_store_is_seen_as_different_from_what_was_sent(self):
        c = self.client()
        p = self.file()
        c.put_file(p.name, str(p))
        self.store.tamper = True
        got = c.get_file(p.name, str(self.tmp / "back.bin"))
        self.assertNotEqual(got["sha256"], got["recorded_sha256"])

    def test_an_object_we_did_not_upload_has_no_recorded_digest(self):
        self.store.objects[self.prefix + "other.bin"] = {"data": b"x", "mtime": 1_800_000_000, "meta": None}
        got = self.client().get_file("other.bin", str(self.tmp / "o"))
        self.assertIsNone(got["recorded_sha256"])

    def test_a_name_with_characters_that_need_encoding_is_signed_as_sent(self):
        c = self.client()
        for name in ("a b+c$d.txt", "ü ö.bin", "x=y&z.txt", "100%.txt", "a~b_c-d.txt"):
            c.put_bytes(name, b"hello")
            self.assertEqual(c.get_bytes(name), b"hello", name)
        self.assertEqual(self.store.bad_auth, 0)

    def test_a_listing_is_paged_and_relative_to_the_prefix(self):
        c = self.client()
        for i in range(7):
            c.put_bytes(f"remotepower_data_{i:02d}.tar.gz", b"x" * (i + 1))
        self.store.objects["elsewhere/remotepower_data_zz.tar.gz"] = {"data": b"y", "mtime": 1, "meta": None}
        self.store.page = 3
        items = c.list("remotepower_")
        self.assertEqual([i["name"] for i in items], [f"remotepower_data_{i:02d}.tar.gz" for i in range(7)])
        self.assertEqual([i["size"] for i in items], list(range(1, 8)))
        pages = [r for r in self.store.requests if r[0] == "GET" and "list-type" in r[1]]
        self.assertEqual(len(pages), 3, "7 keys at 3 a page")
        self.assertEqual(len(c.list("remotepower_", limit=2)), 2)
        self.store.no_namespace = True
        self.assertEqual(len(c.list()), 7, "a store that leaves the namespace out is read the same")

    def test_a_large_file_is_sent_in_small_blocks_not_read_into_memory(self):
        sizes = []
        real = http.client.HTTPConnection.send

        def spy(conn, data):
            sizes.append(len(data) if not hasattr(data, "read") else -1)
            return real(conn, data)
        http.client.HTTPConnection.send = spy      # type: ignore[method-assign]
        self.addCleanup(setattr, http.client.HTTPConnection, "send", real)
        p = self.file(data=os.urandom(3 * 1024 * 1024))
        self.client().put_file(p.name, str(p))
        self.assertGreater(len(sizes), 50, "many sends")
        self.assertLessEqual(max(sizes), 64 * 1024, "none of them a large part of the file")
        self.assertEqual(self.store.objects[self.prefix + p.name]["data"], p.read_bytes())

    def test_a_store_that_returns_more_than_was_asked_for_is_cut_to_what_was(self):
        c = self.client()
        for i in range(5):
            c.put_bytes(f"remotepower_data_{i}.tar.gz", b"x")
        self.store.objects["elsewhere/remotepower_data_9.tar.gz"] = {"data": b"y", "mtime": 1, "meta": None}
        self.store.ignore_prefix = True
        self.assertEqual(len(c.list("remotepower_")), 5, "a key outside the prefix is not ours")
        self.store.ignore_prefix = False
        self.store.ignore_max_keys = True
        self.assertEqual(len(c.list("remotepower_", limit=2)), 2, "and the limit holds when the store does not keep to it")

    def test_a_listing_that_is_far_too_large_is_refused(self):
        c = self.client()
        c.put_bytes("remotepower_data_1.tar.gz", b"x")
        self.store.list_padding = 4 * 1024 * 1024 + 100
        with self.assertRaises(s3.S3Error) as cm:
            c.list()
        self.assertEqual(cm.exception.code, "TooLarge")

    def test_an_object_that_is_cut_short_is_an_error(self):
        c = self.client()
        c.put_bytes("a.bin", b"x" * 5000)
        self.store.short_read = True
        with self.assertRaises(s3.S3Error) as cm:
            c.get_file("a.bin", str(self.tmp / "o"))
        self.assertEqual(cm.exception.code, "ShortRead")

    def test_a_listing_that_never_ends_is_stopped(self):
        c = self.client()
        c.put_bytes("remotepower_data_1.tar.gz", b"x")
        self.store.page = 1
        # the store says there is another page forever
        orig = s3.parse_list

        def endless(body):
            items, _, _ = orig(body)
            return items, True, "again"
        s3.parse_list = endless
        self.addCleanup(setattr, s3, "parse_list", orig)
        c.list()
        pages = [r for r in self.store.requests if "list-type" in r[1]]
        self.assertEqual(len(pages), s3.MAX_LIST_PAGES)

    def test_delete(self):
        c = self.client()
        c.put_bytes("a.txt", b"x")
        c.delete("a.txt")
        self.assertEqual(self.store.objects, {})
        c.delete("a.txt")          # deleting what is not there is not an error, as on S3

    def test_a_wrong_secret_is_refused_by_the_store_and_the_error_has_no_secret(self):
        c = self.client(secret_key=SK + "x")
        with self.assertRaises(s3.S3Error) as cm:
            c.put_bytes("a.txt", b"x")
        e = cm.exception
        self.assertEqual((e.status, e.code), (403, "SignatureDoesNotMatch"))
        self.assertNotIn(SK, str(e) + repr(c) + repr(e.__dict__))
        self.assertIn("403", str(e))

    def test_a_missing_object_and_a_missing_bucket(self):
        with self.assertRaises(s3.S3Error) as cm:
            self.client().get_bytes("nope.txt")
        self.assertEqual((cm.exception.status, cm.exception.code), (404, "NoSuchKey"))
        with self.assertRaises(s3.S3Error) as cm:
            self.client(bucket="other").get_bytes("x")
        self.assertEqual(cm.exception.code, "NoSuchBucket")

    def test_an_error_body_that_is_hostile_does_not_get_through(self):
        c = self.client()
        for body in (b"<!DOCTYPE x [<!ENTITY a 'b'>]><Error><Code>X</Code></Error>", b"\x00\x01\x02", b"", b"<Error>" + b"A" * 100000, b"not xml at all"):
            self.store.garbage_error = body
            with self.assertRaises(s3.S3Error) as cm:
                c.put_bytes("a.txt", b"x")
            self.assertEqual(cm.exception.status, 500, body[:20])
            self.assertLessEqual(len(str(cm.exception)), 300)
            self.assertRegex(cm.exception.code, r"^[A-Za-z0-9_.\-]{1,64}$")
            if body.startswith(b"<!DOCTYPE"):
                self.assertEqual(cm.exception.code, "HTTP500", "a document type is refused, so nothing in the body is read")

    def test_a_message_from_the_store_is_cut_and_cleaned(self):
        evil = ("<Error><Code>Odd Code!</Code><Message>" + "line one\nline\ttwo " * 200 + "</Message></Error>").encode()
        self.store.garbage_error = evil
        with self.assertRaises(s3.S3Error) as cm:
            self.client().put_bytes("a.txt", b"x")
        self.assertEqual(cm.exception.code, "OddCode")
        self.assertNotRegex(str(cm.exception), r"[\x00-\x1f]")
        self.assertLess(len(str(cm.exception)), 300)
        # a control character XML does not allow makes the body unreadable, and the answer is the status alone
        self.store.garbage_error = b"<Error><Code>X</Code><Message>bell\x07</Message></Error>"
        with self.assertRaises(s3.S3Error) as cm:
            self.client().put_bytes("a.txt", b"x")
        self.assertEqual((cm.exception.status, cm.exception.code), (500, "HTTP500"))

    def test_a_store_that_hangs_up_or_talks_nonsense_is_an_s3_error_not_another_kind(self):
        c = self.client()
        p = self.file()
        for attr in ("hang_up", "garbage_status"):
            setattr(self.store, attr, True)
            for call in (lambda: c.put_bytes("a.txt", b"x"), lambda: c.put_file(p.name, str(p)), lambda: c.get_bytes("a.txt"),
                         lambda: c.get_file("a.txt", str(self.tmp / "o")), lambda: c.delete("a.txt"), lambda: c.list(), c.check):
                with self.assertRaises(s3.S3Error) as cm:
                    call()
                self.assertEqual(cm.exception.code, "ConnectionFailed", attr)
                self.assertLess(len(str(cm.exception)), 300)
            setattr(self.store, attr, False)

    def test_a_store_that_hangs_up_or_talks_nonsense_is_named_by_the_request_not_by_the_wrapper(self):
        """The request converts what goes wrong while it is made and says the store could not be reached; the wrapper around every
        call only catches what happens later, and its words are different. A request that fell through to the wrapper would read as
        a failure of something else."""
        c = self.client()
        p = self.file()
        for attr in ("hang_up", "garbage_status"):
            setattr(self.store, attr, True)
            for call in (lambda: c.put_bytes("a.txt", b"x"), lambda: c.put_file(p.name, str(p)), lambda: c.get_bytes("a.txt"),
                         lambda: c.get_file("a.txt", str(self.tmp / "o")), lambda: c.delete("a.txt"), lambda: c.list()):
                with self.assertRaises(s3.S3Error) as cm:
                    call()
                self.assertTrue(str(cm.exception).startswith("could not connect to the store"), (attr, str(cm.exception)))
            setattr(self.store, attr, False)

    def test_a_connection_that_is_reset_while_the_answer_to_a_write_is_read_is_an_s3_error(self):
        c = self.client()
        p = self.file()
        self.store.reset_midway_writes = True
        for call in (lambda: c.put_bytes("a.txt", b"x"), lambda: c.put_file(p.name, str(p)), lambda: c.delete("a.txt")):
            with self.assertRaises(s3.S3Error) as cm:
                call()
            self.assertEqual(cm.exception.code, "ConnectionFailed")

    def test_a_connection_that_is_reset_while_an_answer_is_read_is_an_s3_error(self):
        c = self.client()
        self.store.reset_midway = True
        for call in (lambda: c.get_bytes("a.txt"), lambda: c.get_file("a.txt", str(self.tmp / "o")), lambda: c.list()):
            with self.assertRaises(s3.S3Error) as cm:
                call()
            self.assertEqual(cm.exception.code, "ConnectionFailed")

    def test_an_archive_that_cannot_be_read_is_named_for_what_it_is(self):
        with self.assertRaises(s3.S3Error) as cm:
            self.client().put_file("a.tar.gz", str(self.tmp / "nope.tar.gz"))
        self.assertEqual(cm.exception.code, "LocalFile")
        self.assertEqual(self.store.requests, [])
        unreadable = self.file("locked.bin")
        unreadable.chmod(0)
        self.addCleanup(unreadable.chmod, 0o600)
        if os.access(str(unreadable), os.R_OK):
            self.skipTest("this account reads a file with no permissions")
        with self.assertRaises(s3.S3Error) as cm:
            self.client().put_file(unreadable.name, str(unreadable))
        self.assertEqual(cm.exception.code, "LocalFile")

    def test_no_connection(self):
        c = self.client(endpoint="http://127.0.0.1:1")
        with self.assertRaises(s3.S3Error) as cm:
            c.put_bytes("a.txt", b"x")
        self.assertEqual((cm.exception.status, cm.exception.code), (0, "ConnectionFailed"))

    def test_an_archive_over_five_gib_is_refused_without_reading_it(self):
        p = self.file(data=b"x")
        real = os.path.getsize
        s3.os.path.getsize = lambda path: s3.MAX_OBJECT_BYTES + 1       # type: ignore[assignment]
        self.addCleanup(setattr, s3.os.path, "getsize", real)
        with self.assertRaises(s3.S3Error) as cm:
            self.client().put_file(p.name, str(p))
        self.assertEqual(cm.exception.code, "EntityTooLarge")
        self.assertEqual(self.store.requests, [], "nothing was sent")

    def test_a_read_past_the_limit_is_stopped(self):
        c = self.client()
        c.put_bytes("big.bin", b"x" * 5000)
        with self.assertRaises(s3.S3Error) as cm:
            c.get_file("big.bin", str(self.tmp / "o"), max_bytes=1000)
        self.assertEqual(cm.exception.code, "TooLarge")
        with self.assertRaises(s3.S3Error):
            c.get_bytes("big.bin", limit=100)

    def test_the_secret_is_not_in_the_client_or_its_requests(self):
        c = self.client()
        c.put_bytes("a.txt", b"x")
        self.assertNotIn(SK, repr(c))
        for _method, path, headers in self.store.requests:
            self.assertNotIn(SK, path + " ".join(str(v) for v in headers.values()))


class TestTheConnectionCheck(_Base):

    def test_it_writes_reads_deletes_and_lists(self):
        r = self.client().check()
        self.assertEqual(r["steps"], ["write", "read", "delete", "list"])
        self.assertTrue(r["ok"])
        self.assertEqual(self.store.objects, {}, "the test object is gone")
        names = [p for m, p, _h in self.store.requests if m == "PUT"]
        self.assertTrue(urllib.parse.unquote(names[0]).split("/bkt/")[1].startswith(self.prefix + "remotepower-connection-test-"))

    def test_each_failure_names_its_step(self):
        for deny, word in (("put", "cannot write"), ("get", "cannot read back"), ("delete", "cannot delete"), ("list", "cannot list")):
            self.store.deny = {deny}
            self.store.objects.clear()
            with self.assertRaises(s3.S3Error) as cm:
                self.client().check()
            self.assertIn(word, str(cm.exception), deny)
            self.assertIn("AccessDenied", str(cm.exception) + cm.exception.code, deny)
        self.store.deny = {"delete"}
        with self.assertRaises(s3.S3Error) as cm:
            self.client().check()
        self.assertIn("left behind", str(cm.exception))

    def test_an_object_that_reads_back_wrong_is_a_failure(self):
        self.store.tamper = True
        with self.assertRaises(s3.S3Error) as cm:
            self.client().check()
        self.assertIn("not the one written", str(cm.exception))

    def test_a_read_that_fails_does_not_leave_the_test_object(self):
        self.store.deny = {"get"}
        with self.assertRaises(s3.S3Error):
            self.client().check()
        self.assertEqual(self.store.objects, {})


class TestTargets(unittest.TestCase):
    """Where a request goes, for the two ways a bucket is named."""

    def test_path_style(self):
        c = s3.S3Client("https://s3.example.org:9000", "r", "bkt", AK, SK, prefix="p/", path_style=True)
        self.assertEqual(c._target("a b.txt", {}), ("https://s3.example.org:9000/bkt/p/a%20b.txt", "s3.example.org:9000", "/bkt/p/a b.txt"))
        self.assertEqual(c._target("", {"list-type": "2"}), ("https://s3.example.org:9000/bkt?list-type=2", "s3.example.org:9000", "/bkt"))

    def test_virtual_hosted_style(self):
        c = s3.S3Client("https://s3.eu-west-1.amazonaws.com", "r", "bkt", AK, SK, path_style=False)
        self.assertEqual(c._target("k.tar.gz", {}), ("https://bkt.s3.eu-west-1.amazonaws.com/k.tar.gz", "bkt.s3.eu-west-1.amazonaws.com", "/k.tar.gz"))
        self.assertEqual(c._target("", {})[2], "/")

    def test_an_address_cannot_carry_a_bucket_in_its_name(self):
        for ep in ("http://127.0.0.1:9000", "http://[::1]:9000", "https://10.1.2.3"):
            self.assertTrue(s3.S3Client(ep, "r", "bkt", AK, SK, path_style=False).path_style, ep)

    def test_the_default_port_is_not_in_the_host_header(self):
        self.assertEqual(s3.S3Client("https://s3.example.org:443", "r", "b", AK, SK).netloc, "s3.example.org")
        self.assertEqual(s3.S3Client("http://s3.example.org:80", "r", "b", AK, SK).netloc, "s3.example.org")
        self.assertEqual(s3.S3Client("http://[::1]:9000", "r", "b", AK, SK).netloc, "[::1]:9000")


if __name__ == "__main__":
    unittest.main()
