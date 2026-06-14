# AUR package — `remotepower-server`

Arch User Repository packaging for the **RemotePower server** (nginx + Python
CGI). `arch=any`, built from the **signed** GitHub release tarball and
PGP-verified against the maintainer key before packaging.

Unlike `remotepower-agent`, the server is **not turnkey** — the package installs
the code + deps + a *sample* nginx vhost + the shared locations snippet + a
tmpfiles-managed data dir, and the operator finishes setup (nginx `server_name`
/ TLS, enable `fcgiwrap.socket`, create the admin with `remotepower-passwd`). The
`.install` scriptlet prints the exact steps.

What it installs:

| Path | What |
|---|---|
| `/var/www/remotepower/` | cgi-bin (api.py + modules), static, html, docs, agent binary |
| `/usr/bin/remotepower-passwd` | symlink → the admin/user tool |
| `/etc/nginx/snippets/remotepower-locations.conf` | shared location blocks (backup-tracked) |
| `/usr/share/doc/remotepower-server/remotepower.conf.sample` | sample vhost (copy → `/etc/nginx/conf.d/`) |
| `/usr/share/doc/remotepower-server/remotepower-api.service` | optional SCGI prefork worker |
| `/usr/lib/tmpfiles.d/remotepower.conf` | creates `/var/lib/remotepower` (0700, `http`) |

Hard deps are all in the official repos; `python-webauthn` (passkeys) and
`python-pysaml2` (SAML) are AUR **optdepends**, so a plain install never pulls
from the AUR.

## Validate locally

```bash
makepkg -f --nodeps        # --nodeps: arch=any file-copy build needs no runtime
                           # deps present; it still downloads + PGP-verifies the tarball
makepkg --printsrcinfo > .SRCINFO
```

## Publish / update

Same as the agent — see `../remotepower-agent/README.md`. The package lives at
`ssh://aur@aur.archlinux.org/remotepower-server.git` (branch `master`). Per
release: `./update.sh <version>` → `makepkg -f --nodeps` → copy
`PKGBUILD`/`.SRCINFO`/`.install` into the AUR clone → push.

Install for users: `yay -S remotepower-server` (or `paru -S …`).
