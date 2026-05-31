#!/usr/bin/env bash
# sign-agent-release.sh — cryptographically sign the published agent binary.
#
# v3.4.2: produces a detached, armored GPG signature next to the served agent
# binary so agents with a pinned release public key can verify the download came
# from you — defending against a compromised server that swaps both the binary
# and its advertised sha256.
#
# Usage:
#   tools/sign-agent-release.sh [-k <gpg-key-id>] [-a <agent-path>]
#
#   -k  GPG key id / fingerprint / email to sign with (default: gpg's default key)
#   -a  path to the served agent binary
#       (default: /var/www/remotepower/agent/remotepower-agent)
#
# After signing, set the PUBLIC key + fingerprint in RemotePower so the server
# can self-verify and agents know which key to trust:
#   - Settings → ... or POST /api/config:
#       release_pubkey            = <armored public key block>
#       release_key_fingerprint   = <40-hex fingerprint>
#   - Pin the same public key on each agent host at:
#       /etc/remotepower/release.pub
#     (agents only enforce signatures once this file exists — opt-in, fail-closed.)
set -euo pipefail

KEY=""
AGENT="/var/www/remotepower/agent/remotepower-agent"
while getopts "k:a:h" opt; do
  case "$opt" in
    k) KEY="$OPTARG" ;;
    a) AGENT="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "see -h for usage" >&2; exit 2 ;;
  esac
done

command -v gpg >/dev/null || { echo "error: gpg not found in PATH" >&2; exit 1; }
[ -f "$AGENT" ] || { echo "error: agent binary not found: $AGENT" >&2; exit 1; }

SIG="${AGENT}.asc"
KEYARG=()
[ -n "$KEY" ] && KEYARG=(-u "$KEY")

echo "Signing $AGENT ..."
gpg --batch --yes --armor --detach-sign "${KEYARG[@]}" -o "$SIG" "$AGENT"
echo "Wrote detached signature: $SIG"

# Best-effort: show the signing key fingerprint for the config.
FPR="$(gpg --verify "$SIG" "$AGENT" 2>&1 | grep -oiE '[0-9A-F]{40}' | head -1 || true)"
echo
echo "Detached signature created. Next:"
echo "  1. Export the PUBLIC key:   gpg --armor --export ${KEY:-<key>} "
echo "  2. Set release_pubkey + release_key_fingerprint${FPR:+ ($FPR)} in RemotePower config."
echo "  3. Pin /etc/remotepower/release.pub on each agent host to enforce verification."
