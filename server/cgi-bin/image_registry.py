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

SSRF: this module does NOT resolve/guard hostnames — the caller checks
the URL (via ``manifest_url``) against the existing SSRF guard before
invoking ``remote_digest``, so a malicious image ref can't point the
server at a link-local / metadata address.
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


def remote_digest(registry, repository, tag, creds=None, timeout=4.0):
    """Return the current ``sha256:…`` manifest digest for ``repo:tag``.

    ``creds`` is an optional ``{'username', 'password'}`` dict used to
    authenticate the token request (Docker Hub) or as direct Basic auth.
    Raises on network / HTTP errors; the caller records them as a per-image
    ``last_error`` rather than letting one bad registry abort the sweep.
    """
    url = manifest_url(registry, repository, tag)
    headers = {"Accept": ACCEPT_MANIFEST, "User-Agent": USER_AGENT}
    try:
        return _manifest_digest(url, headers, timeout, method="HEAD")
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise
        www = e.headers.get("Www-Authenticate") or e.headers.get("WWW-Authenticate") or ""
        auth = _build_auth(www, creds, timeout)
        if not auth:
            raise
        headers["Authorization"] = auth
        return _manifest_digest(url, headers, timeout, method="HEAD")


def _manifest_digest(url, headers, timeout, method="HEAD"):
    req = urllib.request.Request(url, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        dig = resp.headers.get("Docker-Content-Digest")
        if dig and dig.strip().startswith("sha256:"):
            return dig.strip()
    # A few registries omit the digest header on HEAD — one GET retry.
    if method == "HEAD":
        return _manifest_digest(url, headers, timeout, method="GET")
    return None


def _parse_challenge(header):
    """Parse a ``Bearer realm="…",service="…",scope="…"`` challenge."""
    return dict(re.findall(r'(\w+)="([^"]*)"', header or ""))


def _basic(creds):
    raw = f"{creds.get('username','')}:{creds.get('password','')}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _build_auth(www_authenticate, creds, timeout):
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
        treq_headers = {"User-Agent": USER_AGENT}
        if creds and creds.get("username"):
            treq_headers["Authorization"] = _basic(creds)
        treq = urllib.request.Request(token_url, headers=treq_headers, method="GET")
        with urllib.request.urlopen(treq, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        token = data.get("token") or data.get("access_token")
        return ("Bearer " + token) if token else None
    if scheme == "basic":
        return _basic(creds) if creds and creds.get("username") else None
    return None
