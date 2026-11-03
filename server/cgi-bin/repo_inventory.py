"""RemotePower — which package repositories each Linux host uses, and what is wrong with them (7.4.9).

An update only comes from a repository the host trusts, so the list of repositories is part of a host's attack surface: a third-party
source that ships a package named like one of the distribution's, a repository fetched over plain http, a source whose
signatures are not checked. The agent reads the repository definition files (apt `sources.list`, `sources.list.d/*.list` and
`*.sources`, dnf and yum `*.repo`, pacman `pacman.conf`) and sends them with the comments and blank lines taken out. This module
reads them into one row per repository and works out the findings, so a change to a reader or a rule is a server change and needs no
agent update.

The text is from the host: paths are checked against the few places repository files live, every file and the total are capped,
and no pattern here can backtrack on a long line. Nothing here imports api.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

SEVERITIES = ("critical", "high", "medium", "low")
RANK = {s: i for i, s in enumerate(SEVERITIES)}

MAX_FILES = 40
MAX_FILE_BYTES = 12_000
MAX_TOTAL_BYTES = 120_000
MAX_ROWS = 400

_PATH_RE = re.compile(
    r"^/etc/(?:apt/sources\.list|apt/sources\.list\.d/[A-Za-z0-9][A-Za-z0-9_.@+-]{0,100}\.(?:list|sources)|"
    r"yum\.repos\.d/[A-Za-z0-9][A-Za-z0-9_.@+-]{0,100}\.repo|dnf/dnf\.conf|yum\.conf|pacman\.conf)$"
)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

RULES = {
    "no_signature_check": ("high", "Signature checking is switched off"),
    "insecure_tls": ("high", "Certificate checking is switched off"),
    "plain_http": ("low", "Fetched over plain http"),
    "third_party": ("low", "Not a distribution repository"),
    "duplicate": ("low", "Defined more than once"),
}

# Hosts of the distributions' own repositories and of the mirror networks they point to. Anything else is a third party. This is a
# list of names, not a verdict: a vendor repository that a host needs is a third party all the same, and the finding is how it is
# found.
_KNOWN_SUFFIXES = (
    "debian.org",
    "ubuntu.com",
    "canonical.com",
    "kernel.org",
    "fedoraproject.org",
    "redhat.com",
    "centos.org",
    "almalinux.org",
    "rockylinux.org",
    "archlinux.org",
    "opensuse.org",
    "kali.org",
    "raspberrypi.com",
    "raspbian.org",
    "linuxmint.com",
    "pop-os.org",
    "oracle.com",
    "amazonaws.com",
    "rpmfusion.org",
    "ubuntu.org",
    "gentoo.org",
    "alpinelinux.org",
    "mageia.org",
    "voidlinux.org",
    "cloudflare.com",
    "tuxfamily.org",
    "mirrors.ustc.edu.cn",
    "tuna.tsinghua.edu.cn",
    "mirrors.aliyun.com",
    "mirror.rackspace.com",
)
_PPA_SUFFIXES = ("ppa.launchpad.net", "ppa.launchpadcontent.net")


def _clean(v: Any, cap: int) -> str:
    return _CTRL_RE.sub(" ", v)[:cap].strip() if isinstance(v, str) else ""


def clean_files(raw: Any) -> dict[str, str]:
    """The files a host reported, kept when the path is one a repository definition lives at, with each text and the total
    capped. {} for anything else."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    total = 0
    for path in sorted(k for k in raw if isinstance(k, str))[:MAX_FILES]:
        text = raw[path]
        if not _PATH_RE.fullmatch(path) or not isinstance(text, str):
            continue
        text = _CTRL_RE.sub(" ", text)[:MAX_FILE_BYTES]
        if total + len(text) > MAX_TOTAL_BYTES:
            break
        total += len(text)
        out[path] = text
    return out


def _host_of(url: str) -> tuple[str, str]:
    """(scheme, host) of a repository URL; ('', '') for what is not one (a mirror list, a variable, a local path)."""
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return "", ""
    host = (p.hostname or "").lower()
    # a host name is letters, digits, dots, hyphens, underscores and the colons and brackets of an address; anything else is
    # not a host, and a line that is not one is shown as text and not matched against the known names
    return (p.scheme or "").lower(), host if re.fullmatch(r"[a-z0-9._:\[\]-]{1,253}", host) else ""


def _row(file: str, kind: str, url: str, **kw: Any) -> dict[str, Any]:
    scheme, host = _host_of(url)
    row: dict[str, Any] = {
        "file": file,
        "kind": kind,
        "id": "",
        "url": _clean(url, 300),
        "scheme": scheme,
        "host": host,
        "suite": "",
        "components": [],
        "types": [],
        "enabled": True,
        "signed": True,
        "tls_verify": True,
    }
    row.update(kw)
    return row


# ── apt ──────────────────────────────────────────────────────────────────────
_OPT_RE = re.compile(r"([A-Za-z-]+)=(\S+)")


def _apt_signed(opts: dict[str, str]) -> bool:
    low = {k.lower(): v.lower() for k, v in opts.items()}
    if low.get("trusted") in ("yes", "true", "1"):
        return False
    if low.get("allow-insecure") in ("yes", "true", "1") or low.get("allow-weak") in (
        "yes",
        "true",
        "1",
    ):
        return False
    return True


def _parse_apt_list(file: str, text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if parts[0] not in ("deb", "deb-src") or len(parts) < 3:
            continue
        i = 1
        opts: dict[str, str] = {}
        if parts[1].startswith("["):
            j = 1
            buf = []
            while j < len(parts):
                buf.append(parts[j])
                if parts[j].endswith("]"):
                    break
                j += 1
            opts = dict(_OPT_RE.findall(" ".join(buf).strip("[]")))
            i = j + 1
        if len(parts) <= i + 1:
            continue
        rows.append(
            _row(
                file,
                "apt",
                parts[i],
                suite=_clean(parts[i + 1], 80),
                components=[_clean(c, 40) for c in parts[i + 2 : i + 12]],
                types=[parts[0]],
                signed=_apt_signed(opts),
            )
        )
    return rows


def _parse_deb822(file: str, text: str) -> list[dict[str, Any]]:
    rows = []
    for block in re.split(r"\n\s*\n", text):
        f: dict[str, str] = {}
        for line in block.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue
            k, _, v = line.partition(":")
            f[k.strip().lower()] = v.strip()
        if not f.get("uris"):
            continue
        enabled = f.get("enabled", "yes").lower() not in ("no", "false", "0")
        signed = f.get("trusted", "no").lower() not in ("yes", "true", "1") and f.get(
            "allow-insecure", "no"
        ).lower() not in ("yes", "true", "1")
        types = f.get("types", "deb").split()[:4]
        for uri in f["uris"].split()[:6]:
            for suite in (f.get("suites") or "").split()[:12] or [""]:
                rows.append(
                    _row(
                        file,
                        "deb822",
                        uri,
                        suite=_clean(suite, 80),
                        components=[_clean(c, 40) for c in f.get("components", "").split()[:12]],
                        types=types,
                        enabled=enabled,
                        signed=signed,
                    )
                )
    return rows


# ── dnf and yum ──────────────────────────────────────────────────────────────
def _truthy(v: str, default: bool) -> bool:
    v = v.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def _parse_repo(file: str, text: str, default_gpg: bool) -> list[dict[str, Any]]:
    rows = []
    cur: dict[str, str] | None = None
    sections: list[tuple[str, dict[str, str]]] = []
    name = ""
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            name = s[1:-1].strip()[:80]
            cur = {}
            sections.append((name, cur))
        elif cur is not None and "=" in s:
            k, _, v = s.partition("=")
            cur[k.strip().lower()] = v.strip()
    for name, kv in sections:
        if name == "main":
            continue
        url = (
            (kv.get("baseurl") or kv.get("mirrorlist") or kv.get("metalink") or "").split()[0]
            if (kv.get("baseurl") or kv.get("mirrorlist") or kv.get("metalink"))
            else ""
        )
        if not url:
            continue
        rows.append(
            _row(
                file,
                "yum",
                url,
                id=name,
                enabled=_truthy(kv.get("enabled", "1"), True),
                signed=_truthy(kv.get("gpgcheck", ""), default_gpg),
                tls_verify=_truthy(kv.get("sslverify", ""), True),
            )
        )
    return rows


def _main_gpgcheck(text: str) -> bool:
    cur = ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip().lower()
        elif cur == "main" and "=" in s and s.split("=", 1)[0].strip().lower() == "gpgcheck":
            return _truthy(s.split("=", 1)[1], True)
    return True


# ── pacman ───────────────────────────────────────────────────────────────────
def _siglevel_ok(v: str) -> bool:
    low = v.lower()
    return not ("never" in low.split() or "trustall" in low or "databasetrustall" in low)


def _parse_pacman(file: str, text: str) -> list[dict[str, Any]]:
    rows = []
    sect = ""
    global_sig = True
    repos: list[tuple[str, dict[str, str]]] = []
    kv: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and s.endswith("]"):
            sect = s[1:-1].strip()[:80]
            kv = {}
            if sect.lower() != "options":
                repos.append((sect, kv))
            continue
        if "=" in s:
            k, _, v = s.partition("=")
            k = k.strip().lower()
            if sect.lower() == "options" and k == "siglevel":
                global_sig = _siglevel_ok(v)
            elif k in ("server", "siglevel", "include") and sect.lower() != "options":
                kv.setdefault(k, v.strip())
    for name, d in repos:
        url = d.get("server", "")
        if not url and d.get("include"):
            url = "file://" + d["include"]
        if not url:
            continue
        rows.append(
            _row(
                file,
                "pacman",
                url.replace("$repo", name).replace("$arch", "x86_64"),
                id=name,
                signed=_siglevel_ok(d["siglevel"]) if "siglevel" in d else global_sig,
            )
        )
    return rows


# ── the inventory ────────────────────────────────────────────────────────────
def parse(files: dict[str, str]) -> list[dict[str, Any]]:
    """One row per repository the files define, in file order. Never raises; a file that cannot be read gives no rows."""
    rows: list[dict[str, Any]] = []
    yum_conf = files.get("/etc/dnf/dnf.conf") or files.get("/etc/yum.conf") or ""
    default_gpg = _main_gpgcheck(yum_conf) if yum_conf else True
    for path in sorted(files):
        text = files[path]
        try:
            if path.endswith(".sources"):
                rows += _parse_deb822(path, text)
            elif path.startswith("/etc/apt/"):
                rows += _parse_apt_list(path, text)
            elif path.endswith(".repo"):
                rows += _parse_repo(path, text, default_gpg)
            elif path.endswith("pacman.conf"):
                rows += _parse_pacman(path, text)
        except Exception:  # a reader fault is not a failed heartbeat
            continue
        if len(rows) >= MAX_ROWS:
            break
    return rows[:MAX_ROWS]


def is_third_party(host: str) -> bool:
    if not host:
        return False
    return not any(host == s or host.endswith("." + s) for s in _KNOWN_SUFFIXES)


def is_ppa(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in _PPA_SUFFIXES)


def key_of(row: dict[str, Any]) -> str:
    """What makes two rows the same repository: the kind of definition, the URL, the suite and the types (a `deb` line and a
    `deb-src` line for one archive are two entries, not a repeat)."""
    return "|".join(
        (
            row.get("kind", ""),
            str(row.get("url", "")).rstrip("/"),
            str(row.get("suite", "")),
            ",".join(row.get("types") or []),
        )
    )


def evaluate(rows: list[dict[str, Any]]) -> list[list[dict[str, str]]]:
    """The findings of each row, worst first, in the order of `rows`. A disabled repository has none: it is listed and does not count.
    A repository defined twice in the same host gets `duplicate` on the second definition."""
    out: list[list[dict[str, str]]] = []
    seen: set[str] = set()
    for r in rows:
        found: list[dict[str, str]] = []
        if r.get("enabled", True):
            host = str(r.get("host") or "")
            unsigned = r.get("signed") is False
            if unsigned:
                found.append(
                    _f(
                        "no_signature_check",
                        "high",
                        (
                            "gpgcheck is off"
                            if r.get("kind") == "yum"
                            else "signature checking is off"
                        ),
                    )
                )
            if r.get("tls_verify") is False:
                found.append(_f("insecure_tls", "high", "sslverify is off"))
            if r.get("scheme") in ("http", "ftp"):
                found.append(_f("plain_http", "medium" if unsigned else "low", host))
            if is_third_party(host):
                found.append(
                    _f(
                        "third_party",
                        "low",
                        ("personal package archive " if is_ppa(host) else "") + host,
                    )
                )
            k = key_of(r)
            if k in seen:
                found.append(_f("duplicate", "low", str(r.get("file") or "")))
            seen.add(k)
        found.sort(key=lambda x: (RANK[x["severity"]], x["rule"]))
        out.append(found)
    return out


def _f(rule: str, severity: str, detail: str = "") -> dict[str, str]:
    return {
        "rule": rule,
        "severity": severity,
        "title": RULES[rule][1],
        "detail": _clean(detail, 200),
    }


def count(findings: list[dict[str, Any]]) -> dict[str, int]:
    c = {s: 0 for s in SEVERITIES}
    for x in findings:
        if isinstance(x, dict) and x.get("severity") in c:
            c[x["severity"]] += 1
    return c


def worst(findings: list[dict[str, Any]]) -> str:
    c = count(findings)
    return next((s for s in SEVERITIES if c[s]), "")
