"""
RemotePower container-image registry client — v3.3.4.

Given an image reference (``image`` + ``tag`` as the agent reports them),
resolve the *current* manifest digest the registry serves for that tag.
The server compares it against the digest the agent actually pulled
(``repo_digest`` on each container) to decide whether a container is
running a stale image.

Notify-only: this module never pulls, never writes. It does one cheap
manifest HEAD per ``repo:tag`` (registry v2 API), following the standard
token-auth challenge. Supports Docker Hub, GHCR, lscr.io, Quay, and any
generic v2 registry.

Rate limits: Docker Hub throttles anonymous manifest lookups (~100/6h per
IP). The caller dedups identical images across the fleet and gates the
sweep to a long interval; operators can also configure credentials to
raise the ceiling. This module just makes the request it's told to.

SSRF: this module does NOT resolve/guard hostnames itself. The caller is
responsible for passing an ``opener`` whose connections re-validate the
peer IP at connect time and refuse redirects (RemotePower's
``_ssrf_safe_opener``), plus a ``url_guard`` callable that pre-flights any
URL we're about to fetch. Both the manifest URL **and** the bearer-token
``realm`` URL (which is attacker-controllable via the registry's
``Www-Authenticate`` header) are routed through them, so a malicious image
ref can neither point the server at a link-local / metadata address nor
exfiltrate configured registry credentials to an arbitrary realm.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request

DOCKER_HUB = "registry-1.docker.io"
USER_AGENT = "RemotePower-imagecheck/1.0"

# Manifest media types we accept. Listing the manifest-list / OCI-index
# types first means a multi-arch tag returns the *index* digest, which is
# exactly what Docker stores as the local RepoDigest — so the comparison
# is apples-to-apples.
ACCEPT_MANIFEST = ", ".join([
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
])


def parse_image_ref(image, tag):
    """Split an agent-reported (image, tag) into (registry, repository, tag).

    Examples::

        ("nginx", "1.25")                  -> (hub, "library/nginx", "1.25")
        ("linuxserver/sonarr", "")         -> (hub, "linuxserver/sonarr", "latest")
        ("lscr.io/linuxserver/radarr", "") -> ("lscr.io", "linuxserver/radarr", "latest")
        ("ghcr.io/user/app", "v2")         -> ("ghcr.io", "user/app", "v2")

    Returns ``None`` if there's nothing usable (empty image, or an image
    pinned by digest with no tag — those can't be tag-compared).
    """
    image = (image or "").strip()
    tag = (tag or "").strip() or "latest"
    if not image or image == "<none>" or "@" in image:
        return None
    first = image.split("/", 1)[0]
    if "/" in image and ("." in first or ":" in first or first == "localhost"):
        registry = first
        repository = image.split("/", 1)[1]
    else:
        registry = DOCKER_HUB
        repository = image if "/" in image else "library/" + image
    if registry in ("docker.io", "index.docker.io"):
        registry = DOCKER_HUB
    return registry, repository, tag


def manifest_url(registry, repository, tag):
    """The v2 manifest URL the caller should SSRF-check before fetching."""
    return f"https://{registry}/v2/{urllib.parse.quote(repository)}/manifests/{urllib.parse.quote(tag)}"


class BlockedURL(Exception):
    """Raised when ``url_guard`` rejects a URL we were about to fetch
    (registry manifest or bearer-token realm) as a local/metadata target."""


def remote_digest(registry, repository, tag, creds=None, timeout=4.0,
                  opener=None, url_guard=None):
    """Return the current ``sha256:…`` manifest digest for ``repo:tag``.

    ``creds`` is an optional ``{'username', 'password'}`` dict used to
    authenticate the token request (Docker Hub) or as direct Basic auth.

    ``opener`` is an optional :class:`urllib.request.OpenerDirector` used for
    every outbound fetch. The caller passes an SSRF-safe opener (peer-IP
    re-validation + no-redirect) so the registry can't rebind or 3xx-bounce
    us onto an internal address. Defaults to ``urllib.request.urlopen``
    behaviour when omitted (tests / standalone use).

    ``url_guard`` is an optional ``callable(url) -> bool`` that returns True
    if the URL targets a local/metadata address. It pre-flights both the
    manifest URL and the (attacker-controllable) token-realm URL; a blocked
    URL raises :class:`BlockedURL` instead of being fetched.

    Raises on network / HTTP errors; the caller records them as a per-image
    ``last_error`` rather than letting one bad registry abort the sweep.
    """
    url = manifest_url(registry, repository, tag)
    if url_guard and url_guard(url):
        raise BlockedURL("manifest URL resolves to a local/meta address")
    headers = {"Accept": ACCEPT_MANIFEST, "User-Agent": USER_AGENT}
    try:
        return _manifest_digest(url, headers, timeout, method="HEAD", opener=opener)
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise
        www = e.headers.get("Www-Authenticate") or e.headers.get("WWW-Authenticate") or ""
        auth = _build_auth(www, creds, timeout, opener=opener, url_guard=url_guard)
        if not auth:
            raise
        headers["Authorization"] = auth
        return _manifest_digest(url, headers, timeout, method="HEAD", opener=opener)


def _open(req, timeout, opener):
    """Fetch via the caller-supplied SSRF-safe opener. The opener is MANDATORY:
    every image-registry lookup is on an operator-configured registry URL, so it
    must ride the connect-time peer-IP / no-redirect guard. Fail closed rather
    than silently fall back to the stdlib opener (which would follow redirects
    and skip the IP recheck) if a future caller forgets to pass one."""
    if opener is None:
        raise ValueError("image_registry._open requires an SSRF-safe opener")
    return opener.open(req, timeout=timeout)


def _manifest_digest(url, headers, timeout, method="HEAD", opener=None):
    req = urllib.request.Request(url, headers=headers, method=method)
    with _open(req, timeout, opener) as resp:
        dig = resp.headers.get("Docker-Content-Digest")
        if dig and dig.strip().startswith("sha256:"):
            return dig.strip()
    # A few registries omit the digest header on HEAD — one GET retry.
    if method == "HEAD":
        return _manifest_digest(url, headers, timeout, method="GET", opener=opener)
    return None


def _parse_challenge(header):
    """Parse a ``Bearer realm="…",service="…",scope="…"`` challenge."""
    return dict(re.findall(r'(\w+)="([^"]*)"', header or ""))


def _basic(creds):
    raw = f"{creds.get('username','')}:{creds.get('password','')}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _build_auth(www_authenticate, creds, timeout, opener=None, url_guard=None):
    scheme = (www_authenticate.split(" ", 1)[0] if www_authenticate else "").lower()
    if scheme == "bearer":
        params = _parse_challenge(www_authenticate)
        realm = params.get("realm")
        if not realm:
            return None
        q = {}
        if params.get("service"):
            q["service"] = params["service"]
        if params.get("scope"):
            q["scope"] = params["scope"]
        token_url = realm + (("?" + urllib.parse.urlencode(q)) if q else "")
        # The realm comes straight from the registry's Www-Authenticate header,
        # so it's attacker-controllable. Refuse non-HTTPS realms and pre-flight
        # the URL against the same SSRF guard as the manifest before we fetch it
        # (or — worse — send configured Basic creds to it).
        if not token_url.lower().startswith("https://"):
            raise BlockedURL("bearer realm is not https")
        if url_guard and url_guard(token_url):
            raise BlockedURL("bearer realm resolves to a local/meta address")
        treq_headers = {"User-Agent": USER_AGENT}
        if creds and creds.get("username"):
            treq_headers["Authorization"] = _basic(creds)
        treq = urllib.request.Request(token_url, headers=treq_headers, method="GET")
        with _open(treq, timeout, opener) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        token = data.get("token") or data.get("access_token")
        return ("Bearer " + token) if token else None
    if scheme == "basic":
        return _basic(creds) if creds and creds.get("username") else None
    return None
