# Real apt output, for the kept-back and phased-update tests

Each file is what `apt-get` or `apt-mark` printed, byte for byte, in an Ubuntu or Debian userland run without root
(a user namespace, `bwrap`), against two small local flat repositories named like Ubuntu's pockets
(`noble-updates` and `noble-security`):

| Folder | apt | Userland |
|---|---|---|
| `ubuntu-22.04` | 2.4.13 | ubuntu-base 22.04.5 |
| `ubuntu-24.04` | 2.8.3 | ubuntu-base 24.04.5 |
| `debian-13` | 3.0.3 | the official `debian:trixie-slim` image |

The packages are empty `.deb` files built for the test, installed at version 1 and then updated:

| Package | Installed | Offered | What apt does with it |
|---|---|---|---|
| `lab-plain` | 1.0 | 1.1 | upgrades it |
| `lab-kernel-meta` | 1.0 | 2.0, from the security pocket, depends on a new package `lab-kernel-image-2` | keeps it back |
| `lab-held` | 1.0 | 1.1 | on hold (`apt-mark hold`), so it is kept back |
| `lab-phased` | 1.0 | 1.1 with `Phased-Update-Percentage: 0` | defers it, or upgrades it (see below) |

Two states, because phasing is decided per machine from its machine-id:

* `deferred_*`: apt has been told the update is deferred for this machine (`APT::Get::Never-Include-Phased-Updates`),
  which is what a host sees while Ubuntu is still phasing an update in.
* `included_*`: nothing is deferred, so `lab-phased` is an ordinary update.

Files, per folder: `*_plain` is `apt-get --simulate --quiet upgrade`, the command the agent runs;
`*_ignoring_phasing` is the same with `-o APT::Get::Always-Include-Phased-Updates=true`; `*_with_new_pkgs` is
`apt-get --simulate --quiet --with-new-pkgs upgrade`; `showhold.txt` is `apt-mark showhold`.

What they show, and what the tests rely on:

* apt 2.4 (22.04) lists a package it defers for phasing under "The following packages have been kept back:", beside
  the held package and the one that needs a new package. apt 2.8 (24.04) and apt 3.0 (Debian 13) give it its own
  heading, "The following upgrades have been deferred due to phasing:".
* With phasing ignored, all three versions take the phased package, so it drops out of the kept-back block. A name that
  leaves the block that way was only deferred.
* `lab-held` is in the kept-back block and in `apt-mark showhold`.

These are the `lab-*` packages above, not captures from a production host. To rebuild them: extract the ubuntu-base
tarball (or the Debian image's layer) in a user namespace, point `sources.list` at the two repositories, install version 1, publish version 2, run
`apt-mark hold lab-held`, and run the commands above.
