# Security review — v7.5.0

7.4.9 was the release in which the whole project was reviewed. 7.5.0 reads it a second time, with a different question. The first
pass asked what a caller could do that its role should not allow. This one asked where a rule that the code already had was applied
in most places and missed in one or two, and it read the agents, the 30 server modules added since 7.4.0, the documentation and the
interface again against the code as it is. Everything below was found, reproduced and fixed on a seeded copy of the product, not on
anyone's installation.

It found **fifteen Medium issues, twenty-one Low or hardening items and three informational ones. Every one of them is fixed.** One
of the Medium issues is High on a Mac that asks for signed commands (S1). Nothing rated Medium or higher is open. "Open" lists what
is left, and none of it is a way to attack an installation. Each fix has tests, and each test was run against the code with its fix
taken out.

The agents have to be updated for the agent fixes (the agent version is 7.5.0). The server fixes need no action except where a note
in [v7.5.0.md](v7.5.0.md) says so.

## What changed that a reviewer should look at

No route was added. Four things changed what a caller or a host can do:

- **Four-eyes approval reaches more commands** (S9), and **three restore and settings routes ask for a step-up** (S10, S11). Both
  make things stricter. A client that sent a gated command and expected it to run now gets `202` with `approval_required`, as it
  already did for the commands that were held before.
- **The satellite relay opens connections to monitor targets.** A monitor assigned to a satellite is probed from the satellite's
  network, which the relay never did before. It uses the same probe engine as the host agents: a refusal of link-local and
  cloud-metadata addresses (the loopback and private ranges are allowed, because the point is to reach the network the relay is in),
  no redirect followed, and a save that refuses what the engine cannot run. `RP_SATELLITE_PROBES=0` turns it off on a relay. A test
  runs both engines over the same specs, addresses and real servers and fails if they disagree. A monitor of a satellite is a monitor of
  the organisation that owns it, so the existing tenant checks apply.
- **The Ansible runner keeps a file of SSH host keys** (`ansible_known_hosts`, mode 0600, in the data directory). A host that is
  rebuilt on purpose has to be removed from it by hand; the guide says how.
- **The AI index and the AI digest carry more of a host's own data** (ZFS datasets and cache, Docker disk use, eleven more
  conditions). They are built from numbers and fixed words. A pool state, an interface name or any other string a host sends is not
  copied into a line, and the container health output was already in the index. The redaction every AI call goes through (7.4.9)
  applies to them as to everything else.

## How it was done

**Scanners, on the final tree.**

| Scanner | What it covered | Result |
|---|---|---|
| CodeQL 2.27.4 (the version the pinned workflow action uses), Python and JavaScript, the repository's own configuration | the whole tree | no result. The raw file holds 690 results in Python and 1 in JavaScript, all under the six rules the configuration excludes, and none on a line this release wrote or changed |
| bandit (against its baseline), `make lint` (black, isort, mypy on 40 modules and ruff for undefined names and errors, all in the pinned versions), vulture | server, agents, tools | three Low results in the relay's new ping probe (the subprocess import, and a call with a fixed argument list), reviewed and annotated; nothing else new, 0 High. vulture's one report is a parameter of an overridden method |
| semgrep (python, javascript and security-audit rule sets; a known-bad file as a control, which gave 7 results) | the production code | 26 results, none on a line this release wrote or changed. They are the classes the 7.4.9 review triaged: 0700 directories, the scanner's use of environment variables, two nginx locations, a SHA-1 in the demo seeder, an AES-CFB mode that SNMPv3 requires, two reviewed web client sinks and a URL fetch in a demo tool |
| gitleaks (history and tree; three planted tokens as a control) | the whole repository | no leak; the control found all three |
| shellcheck | 25 shell scripts | no warning |
| pip-audit | the server's Python dependencies | no known vulnerability |
| nuclei 3.3.7 with 10,770 templates (the missing-headers template found 10 headers missing on a bare server, as a control) | a seeded stack behind the shipped web server configuration | 12 findings, all informational: the two headers that are off on plain HTTP (HSTS, which the HTTPS block sets, and Cross-Origin-Embedder-Policy, see "Known and unchanged"), technology matches (nginx, Swagger, Grafana), forms, the published `security.txt` and example addresses on the page |
| wapiti 3.3.0, 8 modules (exec, file, redirect, sql, ssl, upload, xss, permanentxss; ssrf and xxe are left out because they call a host on the internet; a page with a known reflected XSS is the control, and the XSS module found it) | the same stack, 150 pages | no injection, traversal, upload or redirect finding. Seven of the eight modules stopped at the ten-minute cap each, so a long payload list may not have run to its end. It reports the plain-HTTP notes of the test setup (the HTTPS block of the shipped configuration is not in it) and 60 "potential path" notes, all on the dashboard page, from example paths in its help text. Not signed in |

**Reviews, with their populations.**

- *The agents.* The three agents, the installers, the scanner, the satellite relay and the agent containers: bandit, semgrep, ruff,
  shellcheck, the real Linux agent run against a seeded local stack in a user and mount namespace, a hostile-response fuzz of the three
  heartbeat loops, a hostile-output fuzz of the collectors, and real-socket and full-file-system tests. Nothing was run as root, on a
  real Mac or on a real Windows host, so S1 (on a Mac), S21, S22 and S23 rest on the code and on the Linux behaviour they share.
  After the fixes, the 266 test modules that touch the client files (7,076 tests) pass.
- *The server code new since 7.4.0.* 30 modules, read for logic and robustness, with property tests (Hypothesis) on the pure ones: the
  business services, the time periods, the repository inventory, the container audit, the ZFS reader, the patch preview and the others.
- *Command approval, enumerated.* A syntax tree over the server lists every function that writes the command queue (29: 12 ask, 17
  are left out for a stated reason) and a test keeps the list from growing without an answer. It found the paths of S9 that the
  documents had already said were open.
- *The signal matrix.* Every signal the three agents send, followed to the eleven places that could use it (the pages, alerts and
  checks, the AI, the knowledge index, the advisory, risk, compliance, Fleet Query, the Data Explorer, Infrastructure as Code and the
  reports), by feeding each place's real function a payload that the real heartbeat handler had stored. It is a map of where a rule is
  missing, and most of what it found is not a security matter; the ones that were (a backup that cannot be restored read as passing,
  a host with security updates waiting passed the patch controls) are in the release notes.
- *The documentation.* The 144 guides were read against the code in three parts and the six in between by hand. 86 needed a
  correction, and the ones that were bugs in the product are S9 to S13, the provisioning and satellite fixes in the release notes, and
  the interface text that promised what the code did not do.
- *The interface.* A rendered pass over 86 pages, 15 settings views, 147 dialogs and the host drawer at 1440, 768 and 390 px, in
  Classic and Pilot, dark and light. Each check had a planted element that it must find. It found two layout bugs (a dialog's tabs and
  a header's buttons off a phone screen) and a focus ring that did not reach 3:1 in the light themes.
- *The authorization matrix, on the final tree.* 1,090 routed operations from the real route tables, 85,422 requests, 60 runs as 26 kinds of caller (no credential, a bad token, a
  platform administrator, a viewer, a custom role, a role with no permission, an auditor, a finance user, roles scoped to a group or a
  tag, administrators, viewers and an operator of two tenants, eight API keys and three host tokens), on a copy of the tree of this release
  (the matrix reads the server code, and the commits after the copy touch tests and documents only). The counts are the ones of the last
  run of 7.4.9, which is the check that no route was added. Controls: the platform administrator was answered 2xx by 501 to 558
  operations in each run and the anonymous caller by 16; on the 398 operations that take an id, a tenant administrator's own objects
  worked in 112 and the same call on another tenant's object was refused (403 or 404) in 107 of them; the scope check refused every
  host-path operation outside the role's scope (90 of 90 for a group role, 86 of 86 for a tag role and 12 of 12 for a scoped key); a leak
  scanner found the other tenants' planted markers in the platform operator's answer and none in a tenant administrator's. It found no
  answer to a tenant user that holds another tenant's id, name or object. 58 operations still answered some caller with a marker it should
  not hold: 13 of them answered tenant users, and each of the 13 is the caller's own input stored and read back, the content of a cloned
  host, the shared knowledge base, or a host token's own scripts; 42 answered only roles or keys scoped to groups or tags (see "Known and
  unchanged"); 3 answered the finance role (the operator's time entries, twice) or, on the Home page, every role: a planted row that the
  product had already rewritten into an alert about the installation's own service. No request answered 2xx where the handler's own
  declared gate refuses: of 697 answers that were not a refusal, 251 were 400 and 446 were 405. Eight operations answered 5xx or not at
  all, each for a reason that belongs to the harness: the SAML library is not installed (three routes), the AI provider is off in the seed
  (two), the two scans that reach out to the network were cut off by the network namespace, and key generation could not run gpg there.

## Summary

| | Count |
|---|---|
| Medium | 15 |
| Low or hardening | 21 |
| Informational | 3 |
| Open at Medium or above | 0 |


## Fixed in 7.5.0

Severity follows the 7.4.9 review: Medium is anything that lets a person or a program do or read what its role should not, or that stops
a feature from doing what it protects. "High with `require-signed-commands`" counts as Medium. Each row names the test that holds the
fix; every one was run against the code with the fix taken out.

| # | Severity | Where | What was wrong | The fix | Held by |
|---|---|---|---|---|---|
| S1 | High with `require-signed-commands` on a Mac, Medium otherwise | all three agents, the canary channel | The server's canary list plants a file as root. The macOS and Windows agents checked audit mode only, and the location rule did not know the macOS launchd and periodic places or the directories that Linux programs read and run, so a server (or anything able to change the list) could plant a job a Mac would run at boot | every agent refuses the channel under `require-signed-commands` and refuses those places; the server refuses them when you save | test_v750_agent_canary_channel, test_v750_canary_paths_server |
| S2 | Medium | Linux agent, self-update | On a filling disk the update wrote a cut-off file over the running agent (303 KB of 768 KB) and restarted | the new file is written whole, synced, read back and checked against the advertised hash; a failed update removes its half | test_v750_agent_update_write |
| S3 | Medium | Linux agent, repository inventory | Repository definitions went to the server with `user:password@` URLs, `password=` lines and tokens in URLs | the agent keeps the credential on the host | test_v750_agent_repo_secrets |
| S4 | Medium | server, `GET /api/repositories` | The server stored those credentials and showed them to every signed-in role; every backup held the text | the server redacts what it stores and what it shows, and the patch preview's text | test_v750_repo_credentials |
| S5 | Medium | scanner | `RP_SCAN_RUNNER=nuclei`, the scanner container's default, has never run a scan since 4.2.0 | the local-binary mode runs | test_v750_agent_scanner_local_runner |
| S6 | Medium | Linux agent, listening ports | Any local user could hold the heartbeat thread for 33 seconds by opening 40,000 sockets | the lookup is linear | test_v750_agent_listening_ports |
| S7 | Medium | Linux agent, host probes | Connections and pings to addresses the server names ignored `require-signed-commands` | probes are refused under the flag | test_v750_agent_probes_signed |
| S8 | Medium | server, heartbeat | A host record with a wrong-shaped `services_watched` made that host's heartbeat answer 500 every time | the store registry types it and the answer ignores what is not a name | test_v750_services_watched_shape |
| S9 | Medium | server, four-eyes approval | About a dozen paths that put a command on a host did not ask for the approval a gated kind needs: library script runs, package actions, file manager writes, the compose action, Docker clean-up, a smart plug's power-off and cycle, a scheduled command and the start of a rollout or a script rollback | one pre-flight for the block predicate and the approval; a test lists every writer of the command queue (29: 12 ask, 17 are left out with a reason) | test_v750_command_approval |
| S10 | Medium | server, settings | Saving `approval_gated_kinds` narrower (for example `scan` alone) switched four-eyes off for reboot and shutdown with no step-up, and the declarative import could set it | it is a governance key; narrowing asks for a step-up, and the import and export leave it out | test_v750_governance_gated_kinds |
| S11 | Medium | server, restore | Restoring a configuration revision swapped the whole settings document, governance switches included, and the two backup restores replaced the data directory (users, tokens, settings), all without the step-up that saving one switch asks for | a revision restore asks when a governance switch would change; both backup restores always ask, before anything is read | test_v750_restore_step_up |
| S12 | Medium | server, Ansible | `GET /api/ansible/playbooks` returned each playbook's YAML (addresses, variables, sometimes credentials) to viewer, auditor, finance and the MCP key | the content goes to an administrator and to a role with `script` | test_v750_ansible_playbooks |
| S13 | Medium | server, Ansible | The runner said it trusted an SSH host key on first use, but kept the keys in a file deleted after every run, so each run trusted whatever the host presented | the keys are kept in the data directory | test_v750_ansible_playbooks |
| S14 | Medium | server, configuration import | The import stored time periods without the check Settings applies; one with `weekly: {"0": 5}` made `GET /api/tickets` answer 500 for everyone | the import runs the check and the reader no longer trusts a day | test_v750_bughunt_mediums |
| S15 | Medium | server, business services | The nesting limit judged only the saved service, so editing the bottom of a chain made every holder deeper unchecked, and the depth walk took about 70 seconds at 40 services | every service of the trial graph is judged and the walk is memoised | test_v750_bughunt_mediums |
| S16 | Low | Linux agent | Five more places ignored a short write: the file manager, the custom scripts, saving credentials | the loop writes everything | test_v750_agent_update_write |
| S17 | Low | Linux agent | A heartbeat answer with a wrong-typed `services_watched`, `backup_monitors` and similar ended the agent | the lines are safe against wrong-typed values | test_v750_agent_server_data |
| S18 | Low | Windows and macOS agents | A `poll_interval` from the server was stored unclamped (the Linux agent keeps 10 to 3600) | clamped | test_v750_agent_server_data |
| S19 | Low | Linux agent | `apply_host_config` created 0600 files at the umask mode and changed them afterwards (a netplan file with a Wi-Fi key was 0644 for a moment) | created with the mode | test_v750_agent_hostcfg_files |
| S20 | Low | scanner | A scan target such as `-oN/some/file` was read by nmap as an option | refused | test_v750_agent_scanner_local_runner |
| S21 | Low to Medium (not run on a Mac) | macOS installer | The root-run agent was put in `/usr/local/bin`, which Homebrew gives to a user on an Intel Mac | installed where only root writes | test_v750_agent_installers |
| S22 | Low (not run on Windows) | Windows installer | `%ProgramData%\RemotePower` was restricted at the first credentials save, after other files were put in it | restricted first | test_v750_agent_installers |
| S23 | Low to Medium (not run on a Mac) | macOS agent | The root daemon ran the user-owned `brew` | it runs as the owner | test_v750_agent_mac_brew_owner |
| S24 | Low | all agents and installers | An enrolment PIN or token on the command line was visible in the process list | read from the environment, cleared after use | test_v750_agent_enroll_env |
| S25 | Low | Docker entrypoint | It wrote the data volume's settings as root, following a link the app account could have left | opens with `O_NOFOLLOW` and stops with a message | test_v750_entrypoint_links |
| S26 | Low | satellite relay | `satellite-setup.sh --self-signed` put the key where the relay's own account cannot read it | moved, and the unit is sandboxed | test_v750_satellite_setup |
| S27 | Low | server, enrolment | A refused enrolment source was never written to the audit trail | audited | test_v750_bughunt_lows |
| S28 | Low | server, host probes | Two hosts reporting probe results in the same moment each wrote the whole document back and lost the other's result | both writers hold the store's lock | test_v750_bughunt_lows2 |
| S29 | Low | server, alerts | A request that names no user (an empty body, a misspelt key) took an alert's assignment back | it answers 400 | test_v750_bughunt_lows2 |
| S30 | Low | server, settings | The text `nan` passed the range check of fourteen decimal settings, was stored, and made the save answer 500 | refused | test_v750_bughunt_lows |
| S31 | Low | server, business services | A member kind that was a list answered 500 | answers 400 | test_v750_bughunt_mediums |
| S32 | Low | server, container audit | A read-only mount of `/` lowered a container's severity from medium to low when `/etc` was added | the severity is the highest | test_v750_bughunt_lows |
| S33 | Low | server, hardware | The hottest-reading history took a raw 255 or 65535 from a USB bridge or a GPU | ignored | test_v750_bughunt_lows |
| S34 | Low | server, alerts | "passes its health check again" was sent for a container that had stopped, and "back under its line" for one whose line was switched off | the recovery says why it closed | test_v750_bughunt_lows2 |
| S35 | Low | server, activity feed | The feed's copy of an event dropped the state, parts and output the inbox kept | kept | test_v750_bughunt_lows2 |
| S36 | Low | server, time periods | A seventh range from a day before was lost on the next save, and ranges that overlap counted their shared minutes twice | merged when read | test_v750_bughunt_mediums, test_v750_bughunt_lows2 |
| S37 | Info | agents | A failed self-update on Windows and macOS left its half-written file beside the agent | removed | test_v750_agent_update_write |
| S38 | Info | server | A numeric text of 4,301 digits or more made the store repair give up on the whole store; two stores of 7.4.3 had no entry; a non-finite number reached the notification formatter | handled | test_v750_bughunt_lows2 |
| S39 | Info | server | Two small timing and copy costs and a wrong comment about dnf | fixed | test_v750_bughunt_lows2 |

## Open

Nothing rated Medium or higher is open. These are smaller, and none of them is a way to attack an installation.

- **Interface.** Chart text sized by the drawing's view box (14 to 16 px on a desktop, 4 to 5 px at phone width), a split of helper
  text between 11 and 12 pixels, buttons of one class that are 31, 33 or 34 px tall depending on where they sit, 45 table columns whose
  header text is not over the cell text, a gap of 6, 8 or 10 px between neighbouring buttons by page, and 14 truncated texts at phone
  width that have no tooltip. All measured, none of them a defect that stops a task.
- **Signals.** Places that could use data the agents already send and do not: Checks rows for ECC errors, battery wear, secrets,
  image CVEs, CPU wait, disk busy, ZFS quota and livepatch; report sections for images, backups, certificates and secrets; Data
  Explorer entities for mounts, disks, accounts, certificates, pools, timers and GPUs; more Fleet Query facets; risk, reliability and
  Needs-attention inputs from UPS, PII findings, SCAP and livepatch; compliance controls for change detection, restore testing and
  brute-force defence; IaC categories for sshd, automatic updates, fail2ban and time sync; the knowledge index for ACME state, Helm
  releases and the repository inventory. A server-side flag so the Monitor page can say that a host is not probing because it asks for
  signed commands, and the agent half of the Docker disk figures for a host that has not reported them before.
- **Tenant-owned features.** Unchanged from 7.4.9: the pages of the organisation that runs the installation are refused to a tenant's
  users, and a tenant that wants its own copy has none.
- **Translations.** The strings added in 7.5.0 are owed a read by a native speaker in each of the six languages.

## Not found

- **A way round the new approval and step-up checks.** The ratchet that lists the command queue's 29 writers, the test that walks
  every caller of the restore function, and the comparison of governance keys all failed on the old code and pass on the new.
- **A secret in the repository or its history.** gitleaks over the history and over the tree found none; a planted token was found by
  the same command.
- **Script injection from host or operator text** in the pages this release changed: the new tooltip and table cells are built with
  the escaping helpers, and the snapshot and ZFS lines of the AI index are built from numbers and a validated name.
- **A route added or removed.** The route table has 981 entries before and after.

## Known and unchanged

- A fully compromised server is root on its agents, by design (see the threat model).
- **Behind a load balancer and a web server on each node, the rightmost `X-Forwarded-For` is the balancer.** The guide for scaling
  says to use the web server's real-IP module (`set_real_ip_from` and `real_ip_header X-Forwarded-For`) so the client address is the
  real one. An outside caller cannot change what the rightmost entry is, so this cannot be used to pose as another address; it makes
  rate limits and the audit trail see the balancer on a multi-node install that has not set that up. It is a setting, not a flaw.
- **A gating window whose one-shot time has passed holds its hosts' commands until the window is removed or edited.** That is the
  strict direction: nothing runs outside an approved window. The maintenance guide says so.
- **The UPS emergency shutdown is not held for approval.** It is an unattended safety response to a power failure, and waiting for a
  second administrator would defeat it. The power guide says so. Switching a smart plug on is not held either.
- **An API key cannot step up, so it cannot restore a backup or a configuration revision.** Use a signed-in administrator.
- **A role scoped to groups, tags or sites limits what a user can change, not what they can see.** Give a person who must not see
  other hosts a tenant (see the 7.4.9 review).
- **IdP-initiated SAML sign-in** (`saml_allow_unsolicited`, off by default) cannot use the check of the 7.4.9 review's S26.
- The two web server configurations send HSTS only when you turn it on, and no `Cross-Origin-Embedder-Policy`.
- With `--no-scheduler`, a backup and its S3 copy run inside a web request, and the app server's 120-second limit can end a very
  large copy. Run the scheduler for large copies (the backup guide says so).

## The release gate

@@GATE@@

## Not run for this review

- A live probe of a running installation: none was available for this release, so every probe ran against a seeded copy.
- Real Windows and macOS hosts. S1 (on a Mac), S21, S22 and S23 were fixed from the code and from the behaviour the agents share with
  Linux; a launchd job was not loaded and Homebrew was not run. The PowerShell installers were read, not run.
- Real services behind the integrations: the S3 copy and restore ran against a store written for the tests that checks every
  signature, not against AWS, MinIO or Backblaze. The satellite relay's probes ran against local servers and a stubbed `ping`.
- Browsers other than Chromium, and a system font narrower than Arial's for the typeface option.
- SQLite and PostgreSQL under the hostile-input sweeps of 7.4.9, which were not repeated; the test suites ran on all three.
- A latency benchmark of the product.
