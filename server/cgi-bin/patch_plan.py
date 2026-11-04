"""RemotePower — what an upgrade would change on a Linux host, read from the package manager's dry run (7.4.9).

An operator who approves a patch run, or presses the patch button, sees the number of pending updates and nothing about
what they do: which packages move from which version to which, whether the upgrade needs a package that is not installed
yet, whether it takes something off, whether a kernel is among them and whether a reboot is likely to follow.

The server queues one fixed, read-only shell script on the host (`command()`). It asks the host's package manager for a
dry run, prints the answer in marked sections and changes nothing. This module builds that script and reads what comes
back (`parse()`), so a change to how a package manager prints is a server fix and needs no new agent.

  apt     `apt-get --simulate upgrade`, with `--with-new-pkgs` for a host whose upgrade mode is Extended, so the plan is the
          one the real run follows. The `Inst` and `Remv` lines give the versions and the source archive (whose name says
          security), the headed blocks give what is kept back, deferred for phasing and no longer required.
  dnf     `dnf upgrade --assumeno` prints the transaction table and stops. dnf 4 and dnf 5 print it differently; both are
          read, and when the rows read do not add up to the counts the table itself states the plan says so (`partial`)
          instead of passing a short list off as the whole.
  pacman  `pacman -Qu` for the versions and `pacman -Sup --print-format` for the full target list, so a new dependency shows
          up. pacman prints nothing about removals in a dry run, so none are claimed.

Everything the host prints is data from the host. Names and versions are checked against a narrow character set, every list
is capped, the input is capped, and no pattern here can backtrack on a long line. Nothing here imports api.
"""

from __future__ import annotations

import re
from typing import Any

from repo_inventory import redact as _redact

MODES = ("standard", "extended")

# The agent cuts a command's output at 32 KB and ends it with this line; seeing it means the plan below is the first part.
TRUNC_MARK = "…(output truncated)"
MAX_INPUT = 64 * 1024
MAX_ITEMS = 300  # entries kept per list
RAW_KEEP = 6000  # characters of the host's own answer kept for "show the host's output"
PENDING_TTL = 3600  # a request the host has not answered after this long reads as timed out

ID_RE = re.compile(r"^pp-[0-9a-f]{12}$")
# The tag rides at the front of the queued command and the agent echoes the whole command back with its output, so the
# result can be matched to the request. `to=<seconds>:` is the agent's optional per-command timeout prefix.
TAG_RE = re.compile(r"^(?:exec:)?(?:to=\d{1,5}:)?#patchplan:(pp-[0-9a-f]{12})#")

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:@~-]{0,127}$")
VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:~^-]{0,95}$")

# ── the script ───────────────────────────────────────────────────────────────
# POSIX sh (the agent hands it to /bin/sh, which is dash on Debian and Ubuntu). Marked sections, each capped with head, and a
# final ##end so a reader can tell a finished answer from one that was cut. Nothing is installed or removed. dnf refreshes its metadata cache when
# that is older than metadata_expire (it writes the cache and changes no package); apt reads the lists as they are.
_SCRIPT = r"""#patchplan:@ID@#
LC_ALL=C; export LC_ALL
T=$(mktemp 2>/dev/null) || exit 3
U=$(mktemp 2>/dev/null) || exit 3
trap 'rm -f "$T" "$U"' EXIT
echo "##now $(date +%s)"
if command -v apt-get >/dev/null 2>&1; then
echo "##manager apt"
echo "##mode @MODE@"
echo "##lists $(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0)"
echo "##held"
apt-mark showhold 2>/dev/null | head -n 100
apt-get --simulate --quiet @FLAG@ upgrade >"$T" 2>&1
echo "##rc $?"
echo "##plan"
grep -vE '^(Conf |Reading |Building |Calculating )' "$T" | head -n 300
if grep -q '^The following packages have been kept back' "$T"; then
apt-get --simulate --quiet -o APT::Get::Always-Include-Phased-Updates=true @FLAG@ upgrade >"$U" 2>&1 && {
echo "##unphased"
awk '/^The following packages have been kept back/{f=1;next} f&&/^ /{print;next} {f=0}' "$U" | head -n 60
}
fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
M=dnf; command -v dnf >/dev/null 2>&1 || M=yum
echo "##manager dnf"
$M upgrade --assumeno >"$T" 2>&1
echo "##rc $?"
echo "##plan"
head -n 300 "$T"
echo "##security"
$M -q check-update --security 2>/dev/null | head -n 300
elif command -v pacman >/dev/null 2>&1; then
echo "##manager pacman"
echo "##lists $(stat -c %Y /var/lib/pacman/sync 2>/dev/null || echo 0)"
echo "##plan"
pacman -Qu 2>/dev/null | head -n 300
echo "##targets"
pacman -Sup --print-format '%n %v' 2>/dev/null | head -n 300
else
echo "##manager none"
fi
echo "##end"
"""


def command(plan_id: str, mode: str = "standard") -> str:
    """The `exec:` command to queue. Both arguments are checked: the id against its fixed shape and the mode against the two
    words, so nothing a request says reaches the shell. Raises ValueError otherwise."""
    if not isinstance(plan_id, str) or not ID_RE.match(plan_id):
        raise ValueError("a patch preview id is pp- and twelve hex digits")
    if mode not in MODES:
        raise ValueError("the mode is standard or extended")
    flag = "--with-new-pkgs" if mode == "extended" else ""
    script = (
        _SCRIPT.replace("@ID@", plan_id)
        .replace("@MODE@", mode)
        .replace("@FLAG@ ", flag + " " if flag else "")
    )
    return "exec:" + script


def plan_id_of(cmd: Any) -> str:
    """The preview id a command (or an echoed command) carries, or ''."""
    m = TAG_RE.match(cmd) if isinstance(cmd, str) else None
    return m.group(1) if m else ""


# ── small readers ────────────────────────────────────────────────────────────
def _name(s: Any) -> str:
    return s if isinstance(s, str) and NAME_RE.fullmatch(s) else ""


def _ver(s: Any) -> str:
    return s if isinstance(s, str) and VER_RE.fullmatch(s) else ""


def _int(s: Any, default: int = 0) -> int:
    try:
        n = int(str(s).strip())
    except (TypeError, ValueError):
        return default
    return n if 0 <= n < 10**12 else default


_UNIT = {
    "": 1,
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "kib": 1024,
    "m": 1024**2,
    "mb": 1024**2,
    "mib": 1024**2,
    "g": 1024**3,
    "gb": 1024**3,
    "gib": 1024**3,
}


def _bytes(num: str, unit: str | None) -> int | None:
    try:
        v = float(num)
    except ValueError:
        return None
    mult = _UNIT.get((unit or "").lower())
    if mult is None or not (0 <= v < 1e7):
        return None
    return int(v * mult)


def _sections(text: str) -> dict[str, list[str]]:
    """Split the script's answer at its `##name value` marker lines. The value of a one-line marker is kept as the single
    entry of its section; the lines after a marker belong to it until the next one. A section that appears twice is joined.
    """
    out: dict[str, list[str]] = {}
    cur: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("##") and len(line) > 2 and line[2].isalpha():
            head, _, val = line[2:].partition(" ")
            cur = out.setdefault(head, [])
            if val:
                cur.append(val.strip())
        elif cur is not None:
            cur.append(line)
    return out


# ── kernel and reboot hints ──────────────────────────────────────────────────
_KERNEL_RE = re.compile(
    r"^(?:"
    r"linux-image(?:-.+)?|linux-(?:generic|lowlatency|virtual|aws|azure|gcp|oem|kvm|raspi)(?:-.+)?|linux-signed-.+|"
    r"linux-modules-.+|proxmox-kernel-.+|pve-kernel-.+|"
    r"kernel|kernel-core|kernel-modules(?:-core|-extra)?|kernel-uek(?:-core)?|"
    r"linux|linux-lts|linux-zen|linux-hardened|linux-rt|linux-cachyos(?:-(?!.*headers)[a-z0-9-]+)?"
    r")$"
)
# Packages whose update leaves the running copy in memory until a reboot: the kernel, CPU microcode, the C library, the
# service manager and the message bus. The distribution's own marker (/var/run/reboot-required) is written after the install
# and is the real answer; this list is the estimate before it.
_REBOOT_RE = re.compile(
    r"^(?:libc6|glibc|systemd|systemd-sysv|dbus|dbus-broker|dbus-daemon|intel-microcode|amd64-microcode|microcode_ctl|"
    r"intel-ucode|amd-ucode)$"
)


def _hints(names: list[str]) -> tuple[bool, bool, list[str]]:
    """(a kernel is among them, a reboot is likely, the names that say so with the kernels first)."""
    kernels = [n for n in dict.fromkeys(names) if _KERNEL_RE.match(n)]
    others = [n for n in dict.fromkeys(names) if not _KERNEL_RE.match(n) and _REBOOT_RE.match(n)]
    reasons = kernels + others
    return bool(kernels), bool(reasons), reasons[:6]


# ── apt ──────────────────────────────────────────────────────────────────────
_INST_RE = re.compile(r"^Inst (\S+)(?: \[([^\]]*)\])? \((\S+)(?: ([^\[)]*))?")
_REMV_RE = re.compile(r"^(?:Remv|Purg) (\S+)(?: \[([^\]]*)\])?")
_APT_SUMMARY_RE = re.compile(
    r"^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded"
)

_BLOCKS = (  # (start of the heading, list it fills)
    ("The following packages have been kept back", "kept_back"),
    ("The following upgrades have been deferred due to phasing", "deferred"),
    ("The following package was automatically installed and is no longer required", "autoremove"),
    (
        "The following packages were automatically installed and are no longer required",
        "autoremove",
    ),
    ("The following packages will be REMOVED", "removed_names"),
)


def _parse_apt(
    plan: list[str], held: set[str], unphased: list[str] | None = None
) -> dict[str, Any]:
    upgrades: list[dict[str, Any]] = []
    installs: list[dict[str, Any]] = []
    removals: list[dict[str, Any]] = []
    blocks: dict[str, list[str]] = {
        "kept_back": [],
        "deferred": [],
        "autoremove": [],
        "removed_names": [],
    }
    summary = None
    errors: list[str] = []
    skipped = 0
    block = None
    for line in plan:
        if line.startswith("Inst "):
            block = None
            mi = _INST_RE.match(line)
            if mi is None:
                skipped += 1
                continue
            name = _name(mi.group(1))
            new = _ver(mi.group(3))
            if not name or not new:
                skipped += 1
                continue
            origin = (mi.group(4) or "").strip()[:120]
            row: dict[str, Any] = {
                "name": name,
                "to": new,
                "security": "security" in origin.lower(),
            }
            if origin:
                row["source"] = origin
            old = _ver(mi.group(2)) if mi.group(2) else ""
            if mi.group(2) and old:
                row["from"] = old
                upgrades.append(row)
            elif mi.group(2):
                skipped += 1
            else:
                installs.append(row)
        elif line.startswith(("Remv ", "Purg ")):
            block = None
            mr = _REMV_RE.match(line)
            name = _name(mr.group(1)) if mr else ""
            if mr is None or not name:
                skipped += 1
                continue
            row = {"name": name}
            if mr.group(2) and _ver(mr.group(2)):
                row["from"] = mr.group(2)
            removals.append(row)
        elif line.startswith("The following "):
            block = next((k for head, k in _BLOCKS if line.startswith(head)), None)
        elif line.startswith("  ") and block:
            blocks[block].extend(line.split())
        else:
            block = None
            m = _APT_SUMMARY_RE.match(line)
            if m:
                summary = tuple(int(x) for x in m.groups())
            elif line.startswith("E: ") and len(errors) < 3:
                errors.append(line[3:].strip()[:160])
    known = {r["name"] for r in removals}
    for n in blocks["removed_names"]:
        if _name(n) and n not in known:
            removals.append({"name": n})
            known.add(n)
    kept_names = [n for n in dict.fromkeys(blocks["kept_back"]) if _name(n)]
    deferred = [n for n in dict.fromkeys(blocks["deferred"]) if _name(n)]
    if unphased is not None:
        # apt 2.4 (Ubuntu 22.04) lists an update it defers for phasing under "kept back". Asked again with phasing ignored, a
        # name that is no longer kept back was only deferred (the same question the agent's package scan asks).
        still = {n for line in unphased for n in line.split()}
        for n in kept_names:
            if n not in still and n not in held and n not in deferred:
                deferred.append(n)
        kept_names = [n for n in kept_names if n in still or n in held]
    kept = [{"name": n, "held": n in held} for n in kept_names]
    autoremove = [n for n in dict.fromkeys(blocks["autoremove"]) if _name(n)]
    total = (summary[0] + summary[1]) if summary else None
    return {
        "upgrades": upgrades,
        "installs": installs,
        "removals": removals,
        "kept_back": kept,
        "deferred": deferred,
        "autoremove": autoremove,
        "summary": summary,
        "total": total,
        "errors": errors,
        "skipped": skipped,
    }


# ── dnf and yum ──────────────────────────────────────────────────────────────
_DNF_ARCH = r"(?:x86_64|noarch|i[3-6]86|aarch64|ppc64le|s390x|armv[67]hl|riscv64|src)"
_DNF_HEAD_RE = re.compile(
    r"^(Installing|Upgrading|Updating|Removing|Downgrading|Reinstalling|Replacing)"
    r"(?: (?:dependencies|for dependencies|weak dependencies|dependent packages|unused dependencies))?:\s*$"
)
_DNF_ROW_RE = re.compile(
    r"^ (\S+)\s+(" + _DNF_ARCH + r")\s+(\S+)\s+(\S+)\s+([0-9.]+)\s*([A-Za-z]*)\s*$"
)
_DNF_CONT_RE = re.compile(
    r"^\s{8,}(" + _DNF_ARCH + r")\s+(\S+)\s+(\S+)\s+([0-9.]+)\s*([A-Za-z]*)\s*$"
)
_DNF_NAMEONLY_RE = re.compile(r"^ (\S+)\s*$")
_DNF_REPLACING_RE = re.compile(r"^\s{3,}replacing\s+(\S+)\s+" + _DNF_ARCH + r"\s+(\S+)")
_DNF4_COUNT_RE = re.compile(
    r"^(Install|Upgrade|Remove|Downgrade|Reinstall)\s+(\d+)\s+Packages?\s*$"
)
_DNF5_COUNT_RE = re.compile(
    r"^\s*(Installing|Upgrading|Removing|Downgrading|Reinstalling):\s+(\d+)\s+packages?\s*$"
)
_DNF_TOTAL_RE = re.compile(r"^Total download size:\s*([0-9.]+)\s*([A-Za-z]*)")
_DNF5_TOTAL_RE = re.compile(r"Need to download\s+([0-9.]+)\s*([A-Za-z]*)")
_DNF_BUCKET = {
    "Installing": "installs",
    "Upgrading": "upgrades",
    "Updating": "upgrades",
    "Removing": "removals",
}
_COUNT_KEY = {
    "Install": "installs",
    "Installing": "installs",
    "Upgrade": "upgrades",
    "Upgrading": "upgrades",
    "Remove": "removals",
    "Removing": "removals",
}


def _parse_dnf(plan: list[str], security: set[str]) -> dict[str, Any]:
    rows: dict[str, list[dict[str, Any]]] = {"installs": [], "upgrades": [], "removals": []}
    counts: dict[str, int] = {}
    bucket = None
    pending = None
    last = None
    download = None
    skipped = 0
    nothing = False
    errors: list[str] = []
    for line in plan:
        if line.startswith("Nothing to do") or line.startswith("No packages marked for"):
            nothing = True
        if line.startswith("Error") and len(errors) < 3:
            errors.append(line.strip()[:160])
        m = _DNF_HEAD_RE.match(line)
        if m:
            bucket = _DNF_BUCKET.get(m.group(1))
            pending = last = None
            continue
        c = _DNF4_COUNT_RE.match(line) or _DNF5_COUNT_RE.match(line)
        if c:
            key = _COUNT_KEY.get(c.group(1))
            if key:
                counts[key] = counts.get(key, 0) + int(c.group(2))
            bucket = None
            continue
        t = _DNF_TOTAL_RE.match(line) or _DNF5_TOTAL_RE.search(line)
        if t:
            download = _bytes(t.group(1), t.group(2))
            continue
        if (
            line.startswith("Transaction Summary")
            or line.startswith("Dependencies resolved")
            or line.startswith("=====")
        ):
            if line.startswith("Transaction Summary"):
                bucket = None
            continue
        if bucket is None:
            continue
        rep = _DNF_REPLACING_RE.match(line)
        if rep and last is not None and bucket == "upgrades":
            last["from"] = _ver(rep.group(2)) or ""
            if not last["from"]:
                last.pop("from")
            continue
        name = ver = repo = size = unit = None
        m = _DNF_ROW_RE.match(line)
        if m:
            name, _arch, ver, repo, size, unit = m.groups()
        elif pending:
            mc = _DNF_CONT_RE.match(line)
            if mc:
                name = pending
                _arch, ver, repo, size, unit = mc.groups()
        pending = None
        if name is None:
            mn = _DNF_NAMEONLY_RE.match(line)
            pending = mn.group(1) if mn else None
            continue
        if not _name(name) or not _ver(ver):
            skipped += 1
            continue
        row: dict[str, Any] = {"name": name, "to" if bucket != "removals" else "from": ver}
        if repo and not repo.startswith("@"):
            row["source"] = repo[:80]
        sz = _bytes(size, unit) if size else None
        if sz is not None and bucket != "removals":
            row["size"] = sz
        if bucket != "removals":
            row["security"] = name in security
        rows[bucket].append(row)
        last = row
    partial = any(counts.get(k, 0) != len(rows[k]) for k in counts)
    return {
        "upgrades": rows["upgrades"],
        "installs": rows["installs"],
        "removals": rows["removals"],
        "kept_back": [],
        "deferred": [],
        "autoremove": [],
        "summary": None,
        "total": None,
        "counts": counts,
        "partial": partial,
        "download": download,
        "nothing": nothing,
        "errors": errors,
        "skipped": skipped,
    }


def _dnf_security(lines: list[str]) -> set[str]:
    out: set[str] = set()
    for line in lines:
        if not line.strip() or line.startswith((" ", "Last", "Obsoleting", "Security:")):
            continue
        tok = line.split()[0]
        n = tok.rsplit(".", 1)[0] if "." in tok else tok
        if _name(n):
            out.add(n)
    return out


# ── pacman ───────────────────────────────────────────────────────────────────
_PAC_QU_RE = re.compile(r"^(\S+) (\S+) -> (\S+)( \[ignored\])?\s*$")
_PAC_TARGET_RE = re.compile(r"^(\S+) (\S+)\s*$")


def _parse_pacman(plan: list[str], targets: list[str]) -> dict[str, Any]:
    upgrades: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    skipped = 0
    for line in plan:
        if not line.strip():
            continue
        m = _PAC_QU_RE.match(line)
        if not m or not _name(m.group(1)) or not _ver(m.group(2)) or not _ver(m.group(3)):
            skipped += 1
            continue
        if m.group(4):
            kept.append({"name": m.group(1), "held": True})
        else:
            upgrades.append(
                {"name": m.group(1), "from": m.group(2), "to": m.group(3), "security": False}
            )
    names = {u["name"] for u in upgrades} | {k["name"] for k in kept}
    installs: list[dict[str, Any]] = []
    for line in targets:
        m = _PAC_TARGET_RE.match(line)
        if not m or not _name(m.group(1)) or not _ver(m.group(2)):
            continue
        if m.group(1) not in names:
            installs.append({"name": m.group(1), "to": m.group(2), "security": False})
    return {
        "upgrades": upgrades,
        "installs": installs,
        "removals": [],
        "kept_back": kept,
        "deferred": [],
        "autoremove": [],
        "summary": None,
        "total": None,
        "errors": [],
        "skipped": skipped,
    }


# ── the plan ─────────────────────────────────────────────────────────────────
def _cap(rows: list[Any]) -> tuple[list[Any], bool]:
    return (rows[:MAX_ITEMS], len(rows) > MAX_ITEMS)


def parse(output: Any) -> dict[str, Any]:
    """Read the script's answer into a plan. Never raises: an answer that cannot be read is a plan with status `failed`
    and the reason, and an answer that is not text is the same.

    `status` is `done` when a package manager answered and the plan is in `upgrades`, `installs` and `removals` (all three
    may be empty: nothing to do is an answer); `failed` otherwise. `partial` marks a plan whose rows do not match the counts
    the package manager itself printed, `truncated` one that was cut before its end, and `reboot_likely` and `kernel` are
    estimates from the package names."""
    text = output if isinstance(output, str) else ""
    marked = text.rstrip().endswith(TRUNC_MARK)
    cut = marked or len(text) > MAX_INPUT
    if marked:
        text = text.rstrip()[: -len(TRUNC_MARK)].rstrip("\n")
    text = text[:MAX_INPUT]
    if cut and "\n" in text:
        text = text[: text.rfind("\n")]  # the line before the cut is likely half a line
    sec = _sections(text)
    manager = (sec.get("manager") or [""])[0].strip()
    host_time = _int((sec.get("now") or [""])[0])
    lists_at = _int((sec.get("lists") or [""])[0])
    out: dict[str, Any] = {
        "status": "failed",
        "error": "",
        "manager": "",
        "mode": "",
        "host_time": host_time,
        "lists_at": lists_at,
        "lists_age_s": (
            (host_time - lists_at) if host_time and lists_at and host_time >= lists_at else None
        ),
        "upgrades": [],
        "installs": [],
        "removals": [],
        "kept_back": [],
        "deferred": [],
        "autoremove": [],
        "counts": {},
        "kernel": False,
        "reboot_likely": False,
        "reboot_reasons": [],
        "download_bytes": None,
        "truncated": cut or "end" not in sec,
        "partial": False,
        "skipped": 0,
        "raw": "",
    }
    mode = (sec.get("mode") or [""])[0].strip()
    out["mode"] = mode if mode in MODES else ""
    plan_lines = sec.get("plan") or []
    # A package manager prints the repository addresses it could not reach, and a repository can carry user:password@ in its URL.
    # The raw text and the first error are shown to every signed-in user, so they go through the same redaction as the inventory.
    out["raw"] = _redact("\n".join(plan_lines))[:RAW_KEEP]
    if manager not in ("apt", "dnf", "pacman"):
        out["error"] = (
            "The host has no package manager the preview reads"
            if manager == "none"
            else "The host's answer could not be read"
        )
        return out
    out["manager"] = manager
    try:
        if manager == "apt":
            held = {h.strip() for h in (sec.get("held") or []) if _name(h.strip())}
            r = _parse_apt(plan_lines, held, sec.get("unphased"))
        elif manager == "dnf":
            r = _parse_dnf(plan_lines, _dnf_security(sec.get("security") or []))
        else:
            r = _parse_pacman(plan_lines, sec.get("targets") or [])
    except Exception:  # a parser fault must not become a 500 on the heartbeat
        out["error"] = "The host's answer could not be read"
        return out
    stated = r.get("counts") or {}
    listed = len(r["upgrades"]) + len(r["installs"]) + len(r["removals"])
    answered = listed > 0 or bool(r.get("nothing")) or bool(stated)
    if manager == "apt":
        answered = answered or r["summary"] is not None
    elif manager == "pacman":
        answered = "plan" in sec  # pacman -Qu prints nothing when the host is up to date
    if not answered:
        out["error"] = _redact(
            r["errors"][0] if r.get("errors") else "The package manager did not give a plan"
        )
        return out
    for key in ("upgrades", "installs", "removals", "kept_back", "deferred", "autoremove"):
        rows, over = _cap(r[key])
        out[key] = rows
        out["truncated"] = out["truncated"] or over
    if r.get("total") is not None and len(r["upgrades"]) + len(r["installs"]) < r["total"]:
        out["truncated"] = True
    out["partial"] = bool(r.get("partial"))
    out["skipped"] = int(r.get("skipped", 0))
    out["kernel"], out["reboot_likely"], out["reboot_reasons"] = _hints(
        [x["name"] for x in out["upgrades"] + out["installs"]]
    )
    if r.get("download") is not None:
        out["download_bytes"] = r["download"]
    out["counts"] = {
        "upgrade": stated.get("upgrades", len(out["upgrades"])),
        "install": stated.get("installs", len(out["installs"])),
        "remove": stated.get("removals", len(out["removals"])),
        "kept_back": len(out["kept_back"]),
        "security": sum(1 for x in out["upgrades"] + out["installs"] if x.get("security")),
    }
    out["status"] = "done"
    return out


def summary_line(plan: dict[str, Any]) -> str:
    """A short line for the command history: what the preview found."""
    if not isinstance(plan, dict) or plan.get("status") != "done":
        return "patch preview: " + str((plan or {}).get("error") or "no plan")[:120]
    c = plan.get("counts") or {}
    return "patch preview: %d to upgrade, %d new, %d removed, %d kept back" % (
        c.get("upgrade", 0),
        c.get("install", 0),
        c.get("remove", 0),
        c.get("kept_back", 0),
    )
