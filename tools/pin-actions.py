#!/usr/bin/env python3
"""Pin every GitHub Action in .github/workflows to a commit.

A tag such as `actions/checkout@v7` is whatever its repository says it is today. Whoever controls that repository can move the
tag, and every workflow run follows it. A commit cannot move. This rewrites each line as

    uses: actions/checkout@<40 hex> # v7.0.1

Dependabot understands that shape and changes the commit and the comment together, so the pins do not go stale by themselves.

    python3 tools/pin-actions.py            # resolve with `gh api` and rewrite the workflows in place
    python3 tools/pin-actions.py --check    # no network: exit 1 if any `uses:` line is not pinned with a version comment

Needs the GitHub CLI (`gh`), logged in, for the rewrite only. Nothing else in the repository calls this; run it when a workflow
gains an action, then review the diff.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
USES = re.compile(r"^(?P<head>\s*-?\s*uses:\s*)(?P<repo>[\w.-]+/[\w./-]+)@(?P<ref>[^\s#]+)(?P<tail>\s*#.*)?$")
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"#\s*v?\d+(\.\d+)*\s*$")
SEMVER_TAG = re.compile(r"^v\d+\.\d+\.\d+$")


def workflow_files():
    return sorted(WORKFLOWS.glob("*.y*ml"))


def uses_lines(text):
    """[(line number, match)] for each remote `uses:` line; local (./) and docker:// references are not Actions to pin."""
    out = []
    for no, line in enumerate(text.splitlines(), 1):
        m = USES.match(line)
        if m and not m.group("repo").startswith(("./", "docker:")):
            out.append((no, m))
    return out


def unpinned(text):
    """Problems in one workflow's text: a ref that is not a commit, or a commit with no version comment."""
    problems = []
    for no, m in uses_lines(text):
        if not SHA.match(m.group("ref")):
            problems.append(f"line {no}: {m.group('repo')}@{m.group('ref')} is a tag or branch, not a commit")
        elif not VERSION_COMMENT.search(m.group("tail") or ""):
            problems.append(f"line {no}: {m.group('repo')}@{m.group('ref')[:12]} has no version comment for Dependabot")
    return problems


def gh(*args):
    r = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"gh api {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def resolve(repo, ref):
    """(commit sha, version tag) for `ref` of owner/repo; an action in a subdirectory (github/codeql-action/init) lives in owner/repo."""
    owner_repo = "/".join(repo.split("/")[:2])
    sha = gh(f"repos/{owner_repo}/commits/{ref}", "--jq", ".sha")
    if not SHA.match(sha):
        raise SystemExit(f"{owner_repo}@{ref} did not resolve to a commit: {sha!r}")
    tags = gh(f"repos/{owner_repo}/tags?per_page=100", "--jq", '.[] | "\\(.name)\\t\\(.commit.sha)"')
    same = []
    for line in tags.splitlines():
        name, _, csha = line.partition("\t")
        if csha == sha and SEMVER_TAG.match(name):
            same.append(name)
    version = max(same, key=lambda v: tuple(int(x) for x in v[1:].split("."))) if same else ref
    return sha, version


def main(argv):
    check = "--check" in argv
    files = workflow_files()
    if not files:
        raise SystemExit("no workflows found")
    if check:
        bad = []
        for f in files:
            bad += [f"{f.name}: {p}" for p in unpinned(f.read_text())]
        print("\n".join(bad) if bad else f"all Actions in {len(files)} workflows are pinned to a commit")
        return 1 if bad else 0

    cache = {}
    for f in files:
        text = f.read_text()
        lines = text.split("\n")
        for no, m in uses_lines(text):
            repo, ref = m.group("repo"), m.group("ref")
            if SHA.match(ref):
                continue
            key = ("/".join(repo.split("/")[:2]), ref)
            if key not in cache:
                cache[key] = resolve(repo, ref)
                print(f"  {key[0]}@{ref} -> {cache[key][0][:12]} ({cache[key][1]})")
            sha, version = cache[key]
            lines[no - 1] = f"{m.group('head')}{repo}@{sha} # {version}"
        f.write_text("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
