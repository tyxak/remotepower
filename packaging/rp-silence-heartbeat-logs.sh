#!/usr/bin/env bash
# rp-silence-heartbeat-logs.sh
#
# v2.1.1 added per-heartbeat sys.stderr.write() calls to make the
# offline bug debuggable. Under FastCGI, stderr lands in nginx's error
# log tagged [error] — because the FCGI_STDERR record type has no
# severity dimension, anything you write to fd 2 becomes "error" to
# nginx. With the offline bug now fixed in v2.1.2, those routine
# heartbeat lines are pure noise drowning out anything that actually
# matters in /var/log/nginx/*_error.log.
#
# This script gates the noisy writes behind env vars:
#
#   * Heartbeat success line  → enabled by RP_LOG_HEARTBEATS=1
#   * Lock-wait timing line   → enabled by RP_LOG_LOCK_WAITS=1
#
# Both are OFF by default after this patch. Everything else
# (OFFLINE/ONLINE transitions, LockBusy events, exception tracebacks
# from check_offline_webhooks / process_schedule / etc.) stays on
# stderr unchanged — those are real errors and you want to see them.
#
# Idempotent: re-running just reports "already patched". Always
# creates a timestamped backup before touching the file. Verifies the
# patched file parses before committing — if it doesn't, the backup
# is restored automatically.
#
# Usage:
#   sudo ./rp-silence-heartbeat-logs.sh
#   # or with a non-default path:
#   sudo API_PY=/opt/remotepower/server/cgi-bin/api.py ./rp-silence-heartbeat-logs.sh
#
# Revert:
#   sudo cp <printed backup path> $API_PY
#
# Re-enable for a debugging window (in /etc/default/fcgiwrap or your
# systemd drop-in, then `systemctl restart fcgiwrap`):
#   RP_LOG_HEARTBEATS=1
#   RP_LOG_LOCK_WAITS=1

set -euo pipefail

API_PY="${API_PY:-/var/www/remotepower/cgi-bin/api.py}"

if [[ ! -r $API_PY ]]; then
    echo "!! Cannot read $API_PY" >&2
    echo "   Set API_PY=/path/to/api.py and re-run." >&2
    exit 1
fi

if [[ ! -w $API_PY ]]; then
    echo "!! Cannot write $API_PY (run with sudo, or set API_PY to a writable copy)" >&2
    exit 1
fi

if grep -q "RP_LOG_HEARTBEATS" "$API_PY"; then
    echo "==> Already patched ('RP_LOG_HEARTBEATS' found in $API_PY)"
    echo "    Nothing to do."
    exit 0
fi

BACKUP="${API_PY}.bak-$(date +%Y%m%d-%H%M%S)"
cp -p "$API_PY" "$BACKUP"
echo "==> Backup written: $BACKUP"

# Surgery in Python — sed across multi-line stderr.write blocks is
# fragile and we want to fail loudly if the source has drifted.
export API_PY
python3 << 'PYEOF'
import os
import re
import sys

path = os.environ['API_PY']
with open(path) as f:
    src = f.read()

patched = 0
warnings = []

# Match each multi-line `sys.stderr.write(...)` block that emits a
# routine event. The regex captures the *leading indentation* (so the
# `if ...` we wrap with lines up) plus the entire write statement
# including the closing `)`.
#
# We match on the marker string inside the f-string — "heartbeat dev="
# and "lock_wait path=" are unique to these two sites in v2.1.x. Other
# stderr.write calls in api.py (OFFLINE/ONLINE/LockBusy/heartbeat 202)
# use different marker strings and are left untouched.

PATTERNS = [
    # Heartbeat success — by far the noisiest.
    ('heartbeat',
     re.compile(
         r'(?P<indent>\n[ \t]+)sys\.stderr\.write\(\s*\n'
         r'[ \t]+f"\[remotepower\] heartbeat dev=[^"]*"\s*\n'
         r'[ \t]+f"last_seen=[^"]*"\s*\n?\s*\)',
         re.MULTILINE),
     'RP_LOG_HEARTBEATS'),

    # Lock-wait timing — only fires when a save() blocks for
    # LOCK_WAIT_LOG_MS or longer (50ms by default). Useful when
    # diagnosing contention, noise otherwise.
    ('lock_wait',
     re.compile(
         r'(?P<indent>\n[ \t]+)sys\.stderr\.write\(\s*\n'
         r'[ \t]+f"\[remotepower\] lock_wait path=[^"]*"\s*\n'
         r'[ \t]+f"waited_ms=[^"]*"\s*\n?\s*\)',
         re.MULTILINE),
     'RP_LOG_LOCK_WAITS'),
]


def wrap(match, env_var):
    """Wrap the captured sys.stderr.write block in an `if env_var: ...`
    gate at the same indentation level. We add 4 spaces to every
    inner line (preserving relative indentation of the f-string
    continuation lines)."""
    indent = match.group('indent')   # leading newline + indent
    leading_nl = indent[0]
    indent_chars = indent[1:]
    stmt = match.group(0)[len(indent):]  # statement minus its leading indent
    # Re-indent every line of the statement by 4 spaces. The first
    # line gets `indent_chars + "    "`; subsequent lines were already
    # indented relative to the first, so they all get +4 too.
    body_lines = stmt.splitlines(keepends=True)
    reindented = []
    for i, line in enumerate(body_lines):
        if i == 0:
            reindented.append(indent_chars + '    ' + line)
        else:
            # Add 4 spaces after the existing indent of continuation lines.
            # The original lines start with their own indent already.
            reindented.append('    ' + line)
    return (
        f"{leading_nl}{indent_chars}"
        f"if os.environ.get({env_var!r}) == '1':\n"
        + ''.join(reindented)
    )


for label, pat, env in PATTERNS:
    new_src, n = pat.subn(lambda m: wrap(m, env), src)
    if n == 0:
        warnings.append(f"  - {label}: pattern not found "
                        f"(already gated, or version drift)")
    else:
        patched += n
        src = new_src

with open(path, 'w') as f:
    f.write(src)

print(f"==> Gated {patched} stderr.write site(s)")
for w in warnings:
    print(w)
PYEOF

# Verify the patched file still parses. If it doesn't, we have a
# regex that drifted vs the source — restore the backup and bail.
if ! python3 -c "import ast; ast.parse(open('$API_PY').read())" 2>/dev/null; then
    echo "!! Patched api.py fails to parse — restoring backup" >&2
    cp -p "$BACKUP" "$API_PY"
    echo "   Restored. Patch aborted; api.py is unchanged from before this run." >&2
    exit 1
fi

cat << EOF

==> Syntax OK. Patch applied to $API_PY

What changed
------------
  * Per-heartbeat sys.stderr.write  → gated by  RP_LOG_HEARTBEATS=1
  * Per-lock_wait sys.stderr.write  → gated by  RP_LOG_LOCK_WAITS=1

Effect on logs
--------------
  /var/log/nginx/*_error.log  will now only get:
    [error] [remotepower] OFFLINE / ONLINE …    (state transitions)
    [error] [remotepower] heartbeat 202 …       (LockBusy → 202)
    [error] [remotepower] check_offline_webhooks failed …
    [error] [remotepower] run_monitors_if_due failed …
    [error] (and any other genuine traceback)

  CGI is stateless — the next heartbeat picks up the new code. No
  service restart needed.

To re-enable per-heartbeat logging (debugging window only)
---------------------------------------------------------
  Add to /etc/default/fcgiwrap (or your systemd drop-in):
    RP_LOG_HEARTBEATS=1
    RP_LOG_LOCK_WAITS=1
  Then:
    systemctl restart fcgiwrap

To revert the patch
-------------------
  cp -p $BACKUP $API_PY

EOF
