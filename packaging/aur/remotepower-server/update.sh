#!/usr/bin/env bash
# Bump the AUR PKGBUILD to a new RemotePower release: set pkgver, refresh the
# tarball sha256 from the published .sha256, and regenerate .SRCINFO.
#
# Run AFTER the GitHub release for that version is published.
# Usage: ./update.sh <version>      e.g. ./update.sh 4.6.1
set -euo pipefail

ver="${1:?usage: ./update.sh <version>   (e.g. ./update.sh 4.6.1)}"
cd "$(dirname "$0")"

base="https://github.com/tyxak/remotepower/releases/download/v${ver}"
echo "==> Fetching published sha256 for v${ver}..."
sha="$(curl -fsSL "${base}/remotepower-${ver}.tar.gz.sha256" | awk '{print $1}')"
if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
  echo "!! Could not fetch a valid sha256 for v${ver}." >&2
  echo "   Is the GitHub release (with the .sha256 asset) published yet?" >&2
  exit 1
fi

sed -i -E "s/^pkgver=.*/pkgver=${ver}/" PKGBUILD
sed -i -E "s/^pkgrel=.*/pkgrel=1/" PKGBUILD
# Replace the FIRST sha256sums entry (the .tar.gz); the second ('SKIP', for the
# PGP-verified .asc) is left untouched.
sed -i -E "0,/^  '[0-9a-f]{64}'/s//  '${sha}'/" PKGBUILD

command -v makepkg >/dev/null && makepkg --printsrcinfo > .SRCINFO \
  || echo "!! makepkg not found — regenerate .SRCINFO on an Arch box before pushing."

echo "==> remotepower-server bumped to ${ver} (sha256 ${sha:0:12}…)."
echo "    Review PKGBUILD + .SRCINFO, run 'makepkg -f' to sanity-build, then push to the AUR."
