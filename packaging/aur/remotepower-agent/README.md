# AUR package — `remotepower-agent`

Arch User Repository packaging for the RemotePower agent. The package is
`arch=any` (a single self-contained Python script + systemd unit) and builds
from the **signed** GitHub release tarball, PGP-verifying it against the
maintainer key before packaging.

Files here are the source of truth; the AUR repo is a separate git repo on
`aur.archlinux.org` that you push these into.

## Validate locally

```bash
makepkg -f                 # downloads the release tarball, verifies the GPG
                           # signature, builds remotepower-agent-<ver>-1-any.pkg.tar.zst
namcap PKGBUILD            # optional lint (pacman-contrib / namcap)
makepkg --printsrcinfo > .SRCINFO
```

(`src/`, `pkg/`, downloaded tarballs and built packages are gitignored.)

## First-time publish (creates the AUR package)

Prerequisite: an account on <https://aur.archlinux.org> with your **SSH public
key** registered (My Account → SSH Public Key).

```bash
git clone ssh://aur@aur.archlinux.org/remotepower-agent.git /tmp/aur-rp-agent
cp PKGBUILD .SRCINFO remotepower-agent.install /tmp/aur-rp-agent/
cd /tmp/aur-rp-agent
git add PKGBUILD .SRCINFO remotepower-agent.install
git commit -m "Initial import: remotepower-agent 4.6.0"
git push
```

Users then install with any AUR helper: `yay -S remotepower-agent` (or
`paru -S remotepower-agent`).

## On each new release

After the GitHub release is published (so the tarball + its `.sha256` exist):

```bash
./update.sh <version>      # e.g. ./update.sh 4.6.1 — bumps pkgver, refreshes
                           # sha256sums, regenerates .SRCINFO
makepkg -f                 # sanity-build the new version
# then copy PKGBUILD + .SRCINFO (+ .install if changed) into the AUR clone:
cd /tmp/aur-rp-agent && git pull
cp <repo>/packaging/aur/remotepower-agent/{PKGBUILD,.SRCINFO,remotepower-agent.install} .
git commit -am "remotepower-agent <version>" && git push
```

The maintainer key fingerprint baked into `validpgpkeys` is
`E7B5AD456728B8462A8B54BFD488AF115D2CCDBF` — the same key that signs the release
tarballs and the git tags. Users without the key in their keyring will be
prompted to import it during `makepkg`.
