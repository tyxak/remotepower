"""RemotePower — an S3-compatible object store as the off-host copy of the server's own backup (7.4.9).

The server's backup could be copied to a mounted directory, which needs a mount. Most places that keep a backup off the machine
speak S3: AWS, MinIO, Backblaze B2, Wasabi, Cloudflare R2 and a NAS with an object gateway. This is the client for that, standard
library only (the request signing is AWS Signature Version 4, about forty lines), so there is no new dependency to install.

What it does: upload one file (the finished archive) in a single PUT, list a prefix, read an object back, delete one, and check
a connection by writing, reading and deleting a small object. It does not do multipart upload, so one archive can be at most
5 GiB, and a larger one is refused with that reason.

Everything the store sends back is data from outside. Error bodies and listings are read up to a limit and parsed with safe_xml, a
message that comes from the store is cut and cleaned before it is shown, and a listing is stopped after a number of pages. The
secret access key is a parameter here and is never logged, put in an error or kept; the caller takes it from the environment.
Nothing in this module imports api: the caller hands in the opener, so the connection guard (no link-local or metadata address,
no redirect) is the one the rest of the product uses.
"""

from __future__ import annotations

import datetime as _dt
import functools
import hashlib
import hmac
import http.client
import ipaddress
import os
import re
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

import safe_xml

ALGORITHM = "AWS4-HMAC-SHA256"
SERVICE = "s3"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_OBJECT_BYTES = 5 * 1024**3  # one PUT carries at most 5 GiB
LIST_PAGE = 1000
MAX_LIST_PAGES = 50  # 50,000 objects: a backup prefix never holds that many, and a listing that never ends must not exist
META_SHA = "x-amz-meta-rp-sha256"  # the digest of what was uploaded, so a copy read back can be compared with it
_ERROR_BODY_MAX = 8 * 1024
_LIST_BODY_MAX = 4 * 1024 * 1024
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
_REGION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,31}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9+/=_.\-]{1,128}$")
_PREFIX_RE = re.compile(r"^[A-Za-z0-9._\-/]{0,200}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


class S3Error(Exception):
    """A request the store refused, or could not be made. `status` is the HTTP status (0 when there was none) and `code` the store's
    error code, or a short name of ours. `str()` is a message that is safe to show."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _guarded(fn: Any) -> Any:
    """Turn a failure of the connection, whenever it happens (making the request, reading the answer, a store that talks nonsense), into an
    S3Error, so the callers have one kind of failure to handle."""

    @functools.wraps(fn)
    def inner(self: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(self, *args, **kwargs)
        except (
            OSError,
            http.client.HTTPException,
        ) as e:  # an S3Error is neither, so it passes through
            raise S3Error(
                0, "ConnectionFailed", "the connection to the store failed: " + _clean(e, 120)
            ) from None

    return inner


def _clean(text: Any, limit: int = 200) -> str:
    return _CTRL_RE.sub(" ", str(text or "")).strip()[:limit]


# ── settings ─────────────────────────────────────────────────────────────────────────────────────────────────────────


# The networks a plain http endpoint may be on: the loopback and the private ranges of a LAN. Python's is_private also covers the
# link-local range and the documentation ranges, so the list is written out.
_LAN = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128")
)


def _is_private_or_loopback(host: str, resolver: Callable[..., Any] | None = None) -> bool:
    """True when every address `host` resolves to is on a private network or the loopback. A name that does not resolve is not."""
    try:
        infos = (resolver or socket.getaddrinfo)(host, None)
    except (OSError, UnicodeError):
        return False
    found = False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError):
            return False
        found = True
        if not any(ip.version == net.version and ip in net for net in _LAN):
            return False
    return found


def clean_settings(raw: Any, resolver: Callable[..., Any] | None = None) -> dict[str, Any]:
    """The off-host S3 settings of the backup, validated and in one shape. Raises ValueError with the reason when a value cannot be
    used. The secret access key is not a setting: it is read from the environment so it never lands in the archive it protects.

    A plain http endpoint is accepted for a private or loopback address only (a MinIO on the LAN), since the archive would cross a
    public network unencrypted otherwise; the connection guard still refuses link-local and metadata addresses.
    """
    if not isinstance(raw, dict):
        raise ValueError("the S3 settings must be an object")
    out: dict[str, Any] = {"enabled": raw.get("enabled") is True}
    endpoint = str(raw.get("endpoint") or "").strip()
    bucket = str(raw.get("bucket") or "").strip()
    if not out["enabled"] and not endpoint and not bucket:
        return {"enabled": False}
    parts = urllib.parse.urlsplit(endpoint)
    try:
        port = parts.port
    except ValueError:
        raise ValueError("the endpoint has a port that is not a number") from None
    host = parts.hostname or ""
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError(
            "the endpoint must be a full URL starting with https:// (or http:// for a private address)"
        )
    if (
        parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/")
    ):
        raise ValueError(
            "the endpoint is a host name and an optional port, with no user, path or query"
        )
    if ":" not in host and not _HOST_RE.match(host):
        raise ValueError("the endpoint host is not a valid name")
    if parts.scheme == "http" and not _is_private_or_loopback(host, resolver):
        raise ValueError(
            "a plain http endpoint is only accepted for a private or loopback address: use https"
        )
    default = 443 if parts.scheme == "https" else 80
    shown = f"[{host}]" if ":" in host else host.lower()
    out["endpoint"] = f"{parts.scheme}://{shown}" + (f":{port}" if port and port != default else "")
    if not _BUCKET_RE.match(bucket) or ".." in bucket:
        raise ValueError(
            "the bucket name must be 3 to 63 lower-case letters, digits, dots and hyphens"
        )
    out["bucket"] = bucket
    region = str(raw.get("region") or "us-east-1").strip()
    if not _REGION_RE.match(region):
        raise ValueError("the region must be letters, digits and hyphens")
    out["region"] = region
    prefix = str(raw.get("prefix") or "").strip().lstrip("/")
    if not _PREFIX_RE.match(prefix) or ".." in prefix.split("/"):
        raise ValueError("the prefix may hold letters, digits and . _ - / only, and no ..")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    out["prefix"] = prefix
    key_id = str(raw.get("access_key_id") or "").strip()
    if not _KEY_ID_RE.match(key_id):
        raise ValueError("the access key id is missing or has characters a key id never has")
    out["access_key_id"] = key_id
    out["path_style"] = raw.get("path_style") is not False
    out["verify_tls"] = raw.get("verify_tls") is not False
    return out


# ── signing (AWS Signature Version 4) ────────────────────────────────────────────────────────────────────────────────


def uri_encode(text: str, keep_slash: bool = False) -> str:
    """Percent-encode every byte but the unreserved ones (and the slash of a path), with upper-case hex, as the signature wants."""
    out = []
    for byte in str(text).encode("utf-8"):
        ch = chr(byte)
        if ch in _UNRESERVED or (keep_slash and ch == "/"):
            out.append(ch)
        else:
            out.append("%%%02X" % byte)
    return "".join(out)


def canonical_query(params: dict[str, str]) -> str:
    return "&".join(
        f"{k}={v}" for k, v in sorted((uri_encode(k), uri_encode(v)) for k, v in params.items())
    )


def _hmac(key: bytes, text: str) -> bytes:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()


def sign_request(
    method: str,
    host: str,
    path: str,
    query: dict[str, str],
    headers: dict[str, str],
    payload_sha256: str,
    access_key: str,
    secret_key: str,
    region: str,
    now: _dt.datetime,
    service: str = SERVICE,
) -> dict[str, str]:
    """The headers to send with a request: the ones given, plus Host, x-amz-date, x-amz-content-sha256 and Authorization. Every
    header given is signed, so a header that must stay unsigned (Content-Length) is added by the caller afterwards. `path` is the
    raw path, and what is sent must be its `uri_encode(path, keep_slash=True)`."""
    stamp = now.astimezone(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    day = stamp[:8]
    signed = {k.lower().strip(): " ".join(str(v).split()) for k, v in headers.items()}
    signed["host"] = host
    signed["x-amz-content-sha256"] = payload_sha256
    signed["x-amz-date"] = stamp
    names = sorted(signed)
    canonical = "\n".join(
        [
            method.upper(),
            uri_encode(path, keep_slash=True),
            canonical_query(query),
            "".join(f"{n}:{signed[n]}\n" for n in names),
            ";".join(names),
            payload_sha256,
        ]
    )
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(
        [ALGORITHM, stamp, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest()]
    )
    key = _hmac(("AWS4" + secret_key).encode("utf-8"), day)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out = dict(headers)
    out["Host"] = host
    out["x-amz-content-sha256"] = payload_sha256
    out["x-amz-date"] = stamp
    out["Authorization"] = (
        f"{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={';'.join(names)}, Signature={signature}"
    )
    return out


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ── what the store answers ───────────────────────────────────────────────────────────────────────────────────────────


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_time(text: str) -> int:
    """Seconds since the epoch of an ISO 8601 time as a store writes it (`2013-09-17T18:07:53.000Z`), or 0."""
    try:
        return int(
            _dt.datetime.strptime(text.strip()[:19], "%Y-%m-%dT%H:%M:%S")
            .replace(tzinfo=_dt.timezone.utc)
            .timestamp()
        )
    except (ValueError, AttributeError):
        return 0


def parse_list(body: bytes) -> tuple[list[dict[str, Any]], bool, str]:
    """(objects, truncated, next token) of a ListObjectsV2 answer. Each object is {key, size, mtime}. Raises ValueError for a body
    that is not that. A store that leaves the XML namespace out is read the same."""
    try:
        root = safe_xml.fromstring(body)
    except (safe_xml.ParseError, ValueError):
        raise ValueError("the listing is not XML") from None
    if _local(root.tag) != "ListBucketResult":
        raise ValueError("the answer is not a listing")
    items: list[dict[str, Any]] = []
    truncated, token = False, ""
    for el in root:
        name = _local(el.tag)
        if name == "IsTruncated":
            truncated = (el.text or "").strip().lower() == "true"
        elif name == "NextContinuationToken":
            token = (el.text or "").strip()
        elif name == "Contents":
            fields = {_local(c.tag): (c.text or "") for c in el}
            key = fields.get("Key", "")
            try:
                size = int(fields.get("Size", "0"))
            except ValueError:
                size = 0
            if key:
                items.append(
                    {
                        "key": key,
                        "size": max(0, size),
                        "mtime": parse_time(fields.get("LastModified", "")),
                    }
                )
    return items, truncated, token


def _error_from(err: urllib.error.HTTPError) -> S3Error:
    """An S3Error from an HTTP error answer: the store's code and message when it sent the usual XML body, else the status."""
    code, message = "", ""
    try:
        body = err.read(_ERROR_BODY_MAX)
        root = safe_xml.fromstring(body)
        for el in root.iter():
            if _local(el.tag) == "Code" and not code:
                code = _clean(el.text, 64)
            elif _local(el.tag) == "Message" and not message:
                message = _clean(el.text)
    except (OSError, ValueError, safe_xml.ParseError):
        pass
    finally:
        try:
            err.close()
        except OSError:
            pass
    code = re.sub(r"[^A-Za-z0-9_.\-]", "", code)[:64] or f"HTTP{err.code}"
    return S3Error(
        err.code,
        code,
        f"the store answered {err.code} {code}" + (f": {message}" if message else ""),
    )


# ── the client ───────────────────────────────────────────────────────────────────────────────────────────────────────


class S3Client:
    def __init__(
        self,
        endpoint: str,
        region: str,
        bucket: str,
        access_key: str,
        secret_key: str,
        prefix: str = "",
        path_style: bool = True,
        opener: Any = None,
        timeout: float = 60.0,
    ) -> None:
        parts = urllib.parse.urlsplit(endpoint)
        host = parts.hostname or ""
        default = 443 if parts.scheme == "https" else 80
        shown = f"[{host}]" if ":" in host else host
        self.scheme = parts.scheme
        self.netloc = shown + (f":{parts.port}" if parts.port and parts.port != default else "")
        self.region, self.bucket = region, bucket
        self.access_key, self._secret = access_key, secret_key
        self.prefix = prefix
        # a bucket name in the host name needs a name to put it in front of
        self.path_style = path_style or ":" in host or bool(re.match(r"^[0-9.]+$", host))
        self.opener = opener or urllib.request.build_opener()
        self.timeout = timeout

    def __repr__(self) -> str:  # never shows the secret
        return f"S3Client({self.scheme}://{self.netloc}, bucket={self.bucket!r})"

    def _target(self, name: str, query: dict[str, str]) -> tuple[str, str, str]:
        """(url, host header, raw path) of the object `name` under the prefix, or of the bucket when `name` is empty."""
        key = self.prefix + name if name else ""
        if self.path_style:
            host, path = self.netloc, f"/{self.bucket}" + (f"/{key}" if key else "")
        else:
            host, path = f"{self.bucket}.{self.netloc}", "/" + key
        url = f"{self.scheme}://{host}{uri_encode(path, keep_slash=True)}"
        if query:
            url += "?" + canonical_query(query)
        return url, host, path

    def _send(
        self,
        method: str,
        name: str = "",
        query: dict[str, str] | None = None,
        body: Any = None,
        size: int | None = None,
        payload_sha256: str = EMPTY_SHA256,
        headers: dict[str, str] | None = None,
    ) -> Any:
        query = query or {}
        url, host, path = self._target(name, query)
        signed = sign_request(
            method,
            host,
            path,
            query,
            headers or {},
            payload_sha256,
            self.access_key,
            self._secret,
            self.region,
            _dt.datetime.now(_dt.timezone.utc),
        )
        if size is not None:
            signed["Content-Length"] = str(size)
            signed["Content-Type"] = "application/octet-stream"
        req = urllib.request.Request(url, data=body, method=method, headers=signed)
        try:
            return self.opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            raise _error_from(e) from None
        except urllib.error.URLError as e:
            raise S3Error(
                0, "ConnectionFailed", "could not connect to the store: " + _clean(e.reason, 120)
            ) from None
        except (OSError, http.client.HTTPException) as e:
            raise S3Error(
                0, "ConnectionFailed", "could not connect to the store: " + _clean(e, 120)
            ) from None

    @_guarded
    def put_bytes(self, name: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        resp = self._send(
            "PUT",
            name,
            body=data,
            size=len(data),
            payload_sha256=digest,
            headers={META_SHA: digest},
        )
        with resp:
            resp.read(_ERROR_BODY_MAX)
        return digest

    @_guarded
    def put_file(self, name: str, path: str) -> str:
        """Upload a file in one PUT and return the sha256 of its content. The digest is stored with the object, so a later read can be
        compared with what was sent."""
        try:
            size = os.path.getsize(path)
        except OSError as e:
            raise S3Error(
                0, "LocalFile", "the archive could not be read: " + _clean(e, 120)
            ) from None
        if size > MAX_OBJECT_BYTES:
            raise S3Error(
                0, "EntityTooLarge", "the archive is larger than the 5 GiB one upload takes"
            )
        try:
            digest = file_sha256(path)
            fh = open(path, "rb")
        except OSError as e:
            raise S3Error(
                0, "LocalFile", "the archive could not be read: " + _clean(e, 120)
            ) from None
        with fh:
            resp = self._send(
                "PUT", name, body=fh, size=size, payload_sha256=digest, headers={META_SHA: digest}
            )
            with resp:
                resp.read(_ERROR_BODY_MAX)
        return digest

    @_guarded
    def get_bytes(self, name: str, limit: int = 1024 * 1024) -> bytes:
        resp = self._send("GET", name)
        with resp:
            data = bytes(resp.read(limit + 1))
        if len(data) > limit:
            raise S3Error(0, "TooLarge", "the object is larger than expected")
        return data

    @_guarded
    def get_file(self, name: str, dest: str, max_bytes: int = MAX_OBJECT_BYTES) -> dict[str, Any]:
        """Read an object into `dest`. Returns {bytes, sha256, recorded_sha256}: what was read, its digest, and the digest stored with
        the object when it was uploaded (None for an object we did not upload)."""
        resp = self._send("GET", name)
        with resp:
            try:
                declared = int(resp.headers.get("Content-Length") or -1)
            except ValueError:
                declared = -1
            h = hashlib.sha256()
            total = 0
            with open(dest, "wb") as out:
                for block in iter(lambda: resp.read(1 << 20), b""):
                    total += len(block)
                    if total > max_bytes:
                        raise S3Error(0, "TooLarge", "the object is larger than expected")
                    h.update(block)
                    out.write(block)
            if declared >= 0 and total != declared:
                raise S3Error(0, "ShortRead", "the object was cut short")
            recorded = resp.headers.get(META_SHA)
        return {
            "bytes": total,
            "sha256": h.hexdigest(),
            "recorded_sha256": (recorded or "").strip().lower() or None,
        }

    @_guarded
    def delete(self, name: str) -> None:
        resp = self._send("DELETE", name)
        with resp:
            resp.read(_ERROR_BODY_MAX)

    @_guarded
    def list(self, match: str = "", limit: int = 0) -> list[dict[str, Any]]:
        """The objects under the prefix whose name starts with `match`, as {name, size, mtime}. `limit` stops after that many (0: all)."""
        out: list[dict[str, Any]] = []
        token = ""
        for _ in range(MAX_LIST_PAGES):
            query = {
                "list-type": "2",
                "max-keys": str(min(LIST_PAGE, limit) if limit else LIST_PAGE),
                "prefix": self.prefix + match,
            }
            if token:
                query["continuation-token"] = token
            resp = self._send("GET", "", query)
            with resp:
                body = bytes(resp.read(_LIST_BODY_MAX + 1))
            if len(body) > _LIST_BODY_MAX:
                raise S3Error(0, "TooLarge", "the listing is larger than expected")
            try:
                items, truncated, token = parse_list(body)
            except ValueError as e:
                raise S3Error(0, "BadListing", str(e)) from None
            for it in items:
                if it["key"].startswith(self.prefix):
                    out.append(
                        {
                            "name": it["key"][len(self.prefix) :],
                            "size": it["size"],
                            "mtime": it["mtime"],
                        }
                    )
            if (limit and len(out) >= limit) or not truncated or not token:
                break
        return out[:limit] if limit else out

    def check(self) -> dict[str, Any]:
        """Write, read and delete a small object, and list the prefix. Returns {ok, steps, ms}; raises S3Error for the first step
        that fails, with the step in the message. A failed delete leaves the test object behind and says so.
        """
        t0 = time.monotonic()
        name = "remotepower-connection-test-" + secrets.token_hex(6) + ".txt"
        data = b"RemotePower connection test\n"
        steps: list[str] = []
        try:
            self.put_bytes(name, data)
            steps.append("write")
        except S3Error as e:
            raise S3Error(e.status, e.code, f"cannot write to the bucket: {e}") from None
        try:
            if self.get_bytes(name) != data:
                raise S3Error(0, "Mismatch", "the object read back is not the one written")
            steps.append("read")
        except S3Error as e:
            self._forget(name)
            raise S3Error(e.status, e.code, f"cannot read back from the bucket: {e}") from None
        try:
            self.delete(name)
            steps.append("delete")
        except S3Error as e:
            raise S3Error(
                e.status,
                e.code,
                f"cannot delete from the bucket (the test object {name} is left behind): {e}",
            ) from None
        try:
            self.list("remotepower-", 1)
            steps.append("list")
        except S3Error as e:
            raise S3Error(
                e.status, e.code, f"cannot list the bucket, so old copies cannot be pruned: {e}"
            ) from None
        return {"ok": True, "steps": steps, "ms": int((time.monotonic() - t0) * 1000)}

    def _forget(self, name: str) -> None:
        try:
            self.delete(name)
        except S3Error:
            pass


# ── pruning ──────────────────────────────────────────────────────────────────────────────────────────────────────────

ARCHIVE_RE = re.compile(r"^remotepower_data_[0-9A-Za-z_\-]+\.tar\.gz(\.enc)?$")


def expired(
    items: list[dict[str, Any]], now: float, keep_days: int, spare: str = "", max_delete: int = 50
) -> list[str]:
    """Names of the archives to delete: older than `keep_days`, never the newest archive, never `spare` (the one just uploaded),
    at most `max_delete`. The newest is kept whatever its age so that a store whose clock is far off cannot empty the bucket.
    """
    mine = sorted(
        (i for i in items if ARCHIVE_RE.match(i["name"])), key=lambda i: (i["mtime"], i["name"])
    )
    if not mine:
        return []
    newest = mine[-1]["name"]
    cutoff = now - max(1, int(keep_days)) * 86400
    return [
        i["name"]
        for i in mine
        if i["mtime"] and i["mtime"] < cutoff and i["name"] not in (newest, spare)
    ][:max_delete]


def newest_archive(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    mine = sorted(
        (i for i in items if ARCHIVE_RE.match(i["name"])), key=lambda i: (i["mtime"], i["name"])
    )
    return mine[-1] if mine else None
