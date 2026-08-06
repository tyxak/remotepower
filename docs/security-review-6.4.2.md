# Security review — v6.4.2 "Ver1tyMatters"

A security review of the v6.4.2 changes and of the surfaces those changes touch.

This pass found real defects: a privacy control that redacted only part of what
it promised, an access-control gate applied to one endpoint and not to
its sibling, configuration secrets that stopped being encrypted at rest when
written through one particular path, a webhook signature that could not support
the replay protection the documentation told receiver authors to rely on, and an
export path that did not neutralise spreadsheet formula cells.

**Result: everything found is fixed in this release.** The at-rest encryption
defect had been latent since encrypt-at-rest shipped in v5.5.0, and this
release's own concurrency work would have made it routine and unattended; it was
caught first. The others are
long-standing, and the honest framing is that they existed in earlier releases
and are corrected now — not that nobody was ever exposed to them. Each is
described below by class and by remedy, with impact stated plainly and without a
working input.

## Scope

The v6.4.2 changes since v6.4.1 — a large body of work across the server, the
interface and the three agents, plus tests and documentation, reviewed in two
passes (the change review below, then the adversarial pre-release audit above).
The new or substantially changed surfaces:

| Surface | Why it was reviewed |
|---|---|
| Per-container alert mutes (`api.py`, the alert-mute store) | A new write over shared state that *suppresses a security signal* |
| The container log window (`api.py`, all three agents) | New path returning raw host output to the browser, waiting on a queued command |
| `client/remotepower-agent-win.py` container actions | Command execution on a platform that previously had none |
| `_LockedUpdate`, `_save_held`, every write to the configuration document | Secret persistence and lost-update classes |
| `integrations.py` and the shared outbound HTTP transport | Parses untrusted third-party responses under a size cap |
| `sanitize.py`, `ai_provider.redact()` | The privacy controls themselves |
| Patch-report CSV/XML, fleet SBOM, posture report, custom reports | Data leaving the instance, in a format a spreadsheet interprets |
| `fire_webhook()` delivery signing | Integrity of the deliveries receivers act on |
| Listening-socket classification and log collectors in all three agents | The inputs security alerts are computed from |

## Process

- **Static analysis.** `bandit -b .bandit-baseline.json` over `server/cgi-bin`
  and the three agents: **0 new findings, 0 High**. `gitleaks -c .gitleaks.toml`:
  **no leaks**, 1,629 commits scanned. `ruff --select F821`: **0** on all three agents
  and on every `*_handlers.py` module; the hits in `api.py` remain the documented
  bound-handler false-positive class, confirmed still confined to that one file.
- **Targeted class checks.** Source and AST analysis for each defect class this
  codebase keeps producing: a read-modify-write on the configuration document
  outside the lock; a device id taken from a request body with no scope gate; a
  success `respond()` swallowed by a broad `except`; `Path.exists()` used on a
  logical storage key; and — added after the alert-cap defect described below —
  a JSON operator applied to a TEXT column in the Postgres backend.
- **Producer-side checks.** For each key a security control consumes, the code
  that *writes* that key was confirmed to exist and to write it at the same
  nesting. This is the check that catches a control which is wired end to end
  and still silent.
- **Fix verification.** Every fix was checked against the pre-fix code: the fix
  reverted, the new test confirmed failing, the fix restored. A test that passes
  both before and after a change proves nothing, and this project has shipped
  that mistake before.
- **Full suite** on both storage backends — 9,210 tests, JSON and SQLite.

## The new surfaces

### Per-container mutes

A mute suppresses a signal, so it is treated as a privileged write rather than a
display preference. The endpoint requires an administrator. A device outside the
caller's tenant or role scope answers **404, not 403**, so a cross-tenant device
id is never confirmed to exist. The container name is validated against a strict
character class and **rejected** when it does not match, rather than truncated —
a truncated name would be stored as a mute that can never match the name the
agent actually reports, and the operator would see "muted" while continuing to be
paged. The add is a read-modify-write and takes the store's lock, so muting
several containers in quick succession cannot silently lose one.

What a mute suppresses is bounded on purpose. No inbox row, no webhook, no
e-mail, no push, and the container stops counting toward needs-attention and the
health score. Fleet-event history and SIEM forwarding are **unchanged**.
Silencing a page must not become erasing a record — otherwise a mute is an
audit gap rather than a noise control, and Monitoring → Tuning could no longer
show an operator what they have silenced.

### The container log window

This path returns raw host output into the browser, so two properties matter.

Every log line is rendered with `textContent` on its own element — never through
an HTML string — so container output cannot carry markup into the page. The
error/warning colouring is a class on that element, decided by a pattern test,
not by anything the container emits.

The wait is matched to the **exact command** that was queued, rather than to the
container name. A logs request sitting behind a queued restart therefore cannot
render the restart's output as the container's logs, and a container whose name
is a prefix of another's cannot be confused with it. When the agent's per-command
output cap bites, the **newest** lines are kept and the drop is marked — a tail
that silently returned the oldest bytes would look complete and be wrong.

### Windows container actions

The Windows agent has reported containers since v6.2.0, so the Containers page
has been drawing Start / Stop / Restart / Logs buttons for Windows hosts ever
since, and every one of them returned `unsupported command`. The actions run now.
They are argv-only — there is no shell — against a fixed action allowlist, with
the same container-id character validation the server and the Linux agent apply.
`update` (pull and recreate) is deliberately not implemented there and refuses
with a message saying so.

The server side changed with it: an action the target platform cannot perform is
now refused at the API rather than queued. A queued command that can never run
returns a success the operator will believe, which is the same failure shape as a
monitoring control that quietly evaluates nothing.

## Fixed in this release

### Configuration secrets stopped being encrypted at rest on one write path

On an install with a configured master key (`RP_CONFIG_KEY`), the ordinary save
path applies an encrypt-at-rest step to the secret-bearing fields of the
configuration document. The variant used by the locked read-modify-write path did
not. Because reads decrypt in place, a write through the lock persisted the
decrypted document — stripping encryption from the whole file, not merely from
the field being changed. The affected values are the ones that matter most:
the SMTP password, the OIDC client secret, the LDAP bind password, and webhook
URLs, which embed a token in the URL itself.

This was latent for a long time, because almost every configuration write went
through the ordinary path and a Settings save re-encrypted whatever a lock had
stripped. The concurrency work in this release moved *every* configuration write
onto the lock, which would have made it automatic and unattended. The two
database backends had the mirror-image defect: a configuration lock yielded
ciphertext, so a secret read inside the lock saw the marker string and a secret
written inside the lock was stored in the clear.

Both are fixed: the locked write applies the same encrypt-at-rest step, and the
database lock decrypts on entry like every other read. The guardrail runs each
case in a child process per backend, because the master key and the backend are
both read at import — which is precisely why the existing suite had stayed green
over it.

### A privacy control that did not redact IPv6 addresses

Settings → AI has a **send IP addresses** toggle. With it off, addresses are
meant to be replaced before any text reaches the configured provider. The matcher
recognised only the fully expanded eight-group form of an IPv6 address, so the
compressed forms — which is what anyone actually writes, and what every tool
prints — passed through verbatim while the control read as on. A long address
could also match in two halves, which looks redacted in a spot check and is not.
Validation now goes through the standard library's address parser.

The same shape appeared in the shared IP sanitiser, with the opposite effect:
its pattern matched only the expanded form, so every compressed IPv6 address was
replaced with an empty string and nothing was logged. That helper guards the
audit log's source IP, device create and update, the interface inventory and the
gateway — so on an IPv6 network those fields quietly emptied. Both now validate
through the standard library, with the old pattern retained as a fallback so
nothing previously accepted is now rejected.

### The same access-control gate, applied to one endpoint and not its sibling

Three instances of one class. In each, a restriction was implemented correctly in
one place and missing in the neighbouring place that serves the same data.

**Exports.** `GET /api/patch-report/csv`, `GET /api/patch-report/xml` and the
fleet SBOM share one helper, and that helper read the whole device store and
applied only the query string's own filters. Neither the caller's role scope nor
the tenant filter reached it, so an operator restricted to one group could
download the entire fleet's patch state and software inventory. The JSON form of
the very same report has always filtered correctly, which is what kept this
invisible: the data was right on screen and wrong in the export. The scope and
tenant filter now lives in the shared helper, so every present and future export
through it is covered.

**Retrieval.** The AI chat path deliberately withholds fleet-wide retrieval from
restricted callers, because the knowledge index is not tagged per scope or
tenant. The standalone search endpoint ran the same index behind a plain
authentication check, and the per-device runbook path had no check at all — so
device notes, listening ports and inventory for hosts outside the caller's
visibility could be returned, or placed straight into a model prompt. The refusal
moved to the retrieval chokepoint, which covers every present and future
consumer; the standalone search endpoint keeps an explicit refusal, because a
search that silently returns nothing reads as "no results". Until the index
carries scope tags, refusing is the honest answer.

**The mute list.** On Monitoring → Tuning, the noisy-events timeline is scope-
and tenant-filtered. The mute list one line below it was not, so a tenant-scoped
administrator could read other tenants' muted alerts and the hostnames attached
to them. This was the one line an earlier fix stopped short of. Both lists now
use the same visible-device gate. Nothing here was reachable without
authentication.

### A webhook signature that could not carry the replay protection the documentation promised

`docs/webhooks.md` told receiver authors to bound the delivery timestamp in order
to reject replays, and shipped a reference verifier that did exactly that. The
signature, however, covered the request **body alone**. A timestamp that travels
beside a signature without being covered by it is not authenticated, so an age
check against it cannot reject anything, and the documented verifier would accept.
That matters because replayed alert deliveries re-trigger whatever the receiver
does with them — paging, ticket reopening, remediation hooks.

The promise was made true rather than deleted. A second header binds the
timestamp into the MAC — the standard construction used by other webhook
producers — and is sent **alongside** the legacy header, so no deployed receiver
breaks. The documentation now recommends the new header, ships a verifier that
uses it, and states plainly that the body-only signature is not replay-protected
and that a receiver checking only it should move.

### An export that did not neutralise spreadsheet formula cells

A cell whose first character is one of the spreadsheet formula characters is
executed as a formula rather than shown as text when the file is opened. Every
other exporter in the product prefixes such cells so they render literally. The
posture report's CSV renderer did not — and it writes the operator-set device
name, in the export most likely to be sent to somebody else. The neutralising
step now runs in that renderer's row writer rather than at each call site, so a
row added later cannot reintroduce the gap.

### The IP allowlist blocked agents it promised never to block

The Settings hint for the optional IP allowlist says it never blocks an agent.
It did. With the allowlist on, the signature fetch that is the third leg of every
agent self-update was refused — so an agent downloaded an update and then
correctly refused to install it, unsigned, and self-update died fleet-wide while
the heartbeat kept the fleet looking healthy. Live-metric samples, file-manager
transfer chunks, and log and package ingest were refused for the same reason, on
any host whose address is not in the list.

Every one of those authenticates on the **device token in the request body**,
never on a user session, which is the same trade already accepted for the
heartbeat and for OpenSCAP result submission. They are exempt now. The matching
is exact, or an exact suffix under the device path, so the operator-facing log
endpoint stays gated and no unrelated path can back into the exemption.

### Controls that were silent

A monitoring control that evaluates nothing is worse than one that is switched
off, because it reports the same thing as "all clear". Each of these was found by
checking the producer of every value a control reads.

- **Loopback services reported as world-exposed, and a wildcard bind reported as
  LAN.** The Windows and macOS classifiers tested loopback against three literal
  strings and treated everything else as world-reachable, so ordinary loopback
  aliases and the dual-stack form of an IPv4 loopback bind each raised a "port
  exposed to the world" alert for a service bound to localhost. The server takes
  the agent's classification as given, so the alert stood. The reverse error was
  worse and older: the dual-stack spelling of a **wildcard** bind classified as
  private on all three agents, which silenced the world-exposed-port check for a
  service listening on every interface. All three agents now use the same address
  parsing, and an address that cannot be classified still counts as world — an
  exposure that cannot be read should fail loud.
- **Append-only security logs read from the beginning.** Three logs were read
  from their start under a size cap, so once such a log grew past that cap the
  parse froze permanently on old content. For the antivirus log this is not just
  a stale panel: the infection alert is edge-triggered on the count *rising*
  between heartbeats, so a frozen count can never rise and a genuine new
  detection never fires the critical alert, while a host cleaned months ago stays
  dirty in the drawer, the attention list and the AI corpus. Those three now read
  the tail.
- **The firewall inventory dropped the rules that open ports.** The rule/header
  discriminator assumed a brace could only appear in a header. An anonymous set
  puts braces in a rule — the standard modern nftables idiom, and what firewalld
  generates — so on those hosts exactly the rules that open a port or allow a
  source were missing from the inventory, from the deletable rule list, and from
  the rule count that the per-asset risk score derives from. An operator auditing
  what is open on a box saw the established-connection and loopback rules and
  concluded nothing was exposed.
- **Duplicate-MAC detection was structurally empty.** It read a field that does
  not exist on the record it was reading, so the comprehension was always empty
  and the check collapsed to the single address captured at enrolment. The
  multi-NIC cloned VM — the exact case the check exists to catch — was never
  detected. Its existing test passed only because the fixture wrote a shape that
  cannot occur; the fixture was corrected, not the code.
- **Brute-force sources were merged and then partly dropped.** IPv6 sources were
  truncated to their first group, so unrelated sources shared one counter that
  crossed the threshold on its own and fired an alert naming something nobody can
  block, while the real per-source signal was diluted away. The stricter parser
  written to fix that then dropped hostname sources entirely, which turns
  brute-force detection off on any host that logs resolved names. Both are fixed;
  the second was caught in this same cycle, and the test that had asserted the
  regression was corrected with its reason recorded.
- **Critical log-rule matches were filed as medium.** The log engine emits one
  field name and the severity resolver read another, so a rule the operator marked
  critical disagreed with its own needs-attention card, was dropped by
  minimum-priority filters, never reached web push and never broke through quiet
  hours.
- **CVSS v4 advisories scored as unknown.** Published v4 vectors fell through
  every branch of the score parser, so a critical advisory was filed as neither
  critical nor high: no risk points, no CVE alert, invisible to the SLA and
  compliance views. The v4 base metrics are now mapped onto the v3.1 formula and
  labelled as an approximation, because it is a derivation rather than an official
  score. The first version of that mapping scored an advisory whose impact falls
  entirely on a subsequent system as zero; that was caught and corrected here too.
- **The alert cap deleted open alerts.** Resolved-first eviction shipped for the
  file backend in v6.4.0; the database backends — the enterprise default — kept
  evicting oldest-overall, so past the cap the still-open alerts went and the
  resolved ones stayed, while the retention hint promises open alerts are never
  purged. All four cap sites across both backends evict resolved rows first now.
  The Postgres half of that fix was itself defective when first written — an
  uncast JSON access that could not parse, reachable only once a store passes its
  cap, and therefore invisible on a fresh install. It is fixed, its test now
  seeds a mixed set through both code paths, and a static check that runs
  everywhere fails on any uncast JSON operator against a TEXT column.
- **A hostname was silently rewritten rather than rejected.** An underscore is
  forbidden in a hostname by RFC 1123 and ubiquitous in practice; the enrolment
  path quietly removed it. Every later join on the hostname then failed against
  the machine's real name, including the EDR coverage cross-reference, which
  reported a protected host as uncovered. A false "unprotected" is what teaches an
  operator to stop reading that list.
- **Audit-log retention never armed its sweep** unless an unrelated retention key
  happened to be set, and "0 = off" was indistinguishable from unset on three
  settings, so switching one off silently restored its default.

### Concurrency defects with security consequences

- **The write lock handed back stale data.** The locked read-modify-write helper
  acquired the file lock and then read through a per-request memoiser, so it
  returned a snapshot taken *before* the lock existed and wrote that snapshot back
  on exit. That is the exact guarantee the helper exists to provide, and the
  reason roughly two dozen handlers were moved onto it. A device enrolled by a
  concurrent process was absent from the stale copy and was deleted by the locked
  write, taking its token with it; the same root cause dropped sessions created
  during a login. Both database backends already read inside their transaction;
  the file backend now agrees.
- **Twenty-three unlocked writes to the configuration document.** Each read the
  whole document, changed one thing and wrote the whole document back, with no
  lock across the pair. In the periodic sweeps this is sharpest: reads are
  memoised for the length of a request, so a sweep late in the run wrote back the
  configuration as it looked when the request started. A configuration save
  landing in that window had its keys reverted — confirmed by watching the IP
  allowlist toggle and the SMTP host turn themselves back off minutes after being
  set. Timestamp-only claims now go through a dedicated helper; the rest take the
  lock; and a configuration save applies only the keys the request actually
  changed. A static check fails the build on any function that writes the
  configuration document outside the lock.
- **The per-device store write on the heartbeat path** had the same unlocked
  shape, for sixteen device-keyed stores. Concurrent workers dropped each other's
  rows — and losing a listening-port or authorised-key baseline row is worse than
  losing telemetry, because the host re-baselines and the new-port and new-key
  detections then never fire.

### An escaping helper that corrupted the data it escaped

The helper used for values interpolated into HTML attributes emitted
JavaScript-string escapes instead of character references. That was correct for
the inline event handlers it was written for in v2.1.0; those are long gone under
the content security policy, and every surviving call site is a quoted attribute.
A browser hands those escapes back literally, so the value never round-trips: an
apostrophe in a timesheet note came back as text the parser could not read, the
edit dialog opened blank, and saving then wrote the blank over a real billing
record. Rate names, invoice prefixes and the issuer name printed on invoice PDFs
were mangled the same way, compounding on each save.

All ~850 call sites were enumerated and classified before the change — every one
is a quoted HTML attribute and none is a JavaScript string, which is what makes
emitting character references the correct escaping. Attribute-breakout safety was
re-proved in both quote styles: both quote characters are still escaped, so the
case that motivated the original helper stays closed.

### Also fixed

- The custom report CSV returned an error whenever any section was unticked —
  the exact URL the Download button builds for a saved definition with a box
  cleared.
- A certificate that could not be reached was reported as **expired**: an unknown
  expiry was encoded as zero days remaining, which is also what "expires today"
  looks like, so a transient DNS or connection failure raised a critical
  certificate-expiry alert. Fixed in both the alert path and needs-attention.
- The **Delete** button on the Firewall page refused every rule carrying a
  comment or a negation — which is most real rules on a Kubernetes node or a host
  using UFW application profiles. The rule reference is now parsed into tokens and
  each token quoted for the shell, so the command is safe by construction whatever
  the rule text holds, and the reference stays the exact rule spec rather than a
  positional index that could point at a different rule by the time it runs. The
  strict character allowlist still guards a rule being *added* — a different path
  with a different contract, unchanged here.
- The WordPress connector reported "invalid JSON" for healthy sites: it fetched
  an index that is routinely larger than the transport's read budget, so the body
  arrived truncated and the site was blamed for our cap. It now requests only the
  fields it reads, the transport can tell a complete response from a truncated
  one and says which it got, and the several distinct failures previously reported
  as one message — an HTML login page, an interstitial, an empty body, a
  truncated read, genuinely broken JSON, and a host that strips the authorisation
  header before the application sees it — each report their own cause.
- Scheduled work driven by a cron expression could silently never run. There were
  three expression evaluators with three different sets of capabilities, and all
  three accepted what they could not evaluate, so a schedule the validator allowed
  simply never matched. With command gating attached to such a window, every
  queued command and upgrade for those devices waited forever for a window that
  could not open. There is one evaluator now. Separately, six scheduled jobs fired
  only if a periodic tick happened to land inside the matching minute, which under
  the default out-of-band scheduler meant a daily job was either always or never
  sampled; they evaluate elapsed minutes now, like a real cron daemon.
- Log collectors went blind after every rotation: they persisted a position and
  seeked to it, so once the file was replaced or truncated the stale offset
  pointed past the end and every line below it was dropped. Access-log rules —
  authentication failures, 5xx spikes, scanner probes — simply stopped firing
  after each nightly rotate, with no error anywhere. The first version of that fix
  treated a missing inode as a rotation and replayed whole logs as live traffic;
  that was caught and corrected here.
- A macOS host with a custom check assigned lost most of its record: check results
  are reported every beat by design, but the server replaced the whole system
  snapshot with the partial one, wiping uptime, mounts, listening ports and every
  percentage between cadence beats. Partial beats are flagged and merged now.
- Every mount on a Windows host was dropped at ingest, because the sanitiser
  required a leading slash — so the storage view, every per-mount disk check and
  the disk-fill forecast were permanently empty, which reads as healthy.

## Additional pre-release audit

A second, adversarial pass over the whole release — a diff audit that required a
runnable reproduction for every claim, plus a fresh hunt across older code the
release did not touch — found more. All are fixed here; each is described by
class and remedy, without a working input.

### An access-control gate on one endpoint and not its sibling (again)

The live-tail log endpoint read every device's collected log lines with no scope
filter, while its search sibling had been scope-filtered since v6.2.2. Because a
read-only role and a tenant administrator both pass the plain authentication
check, either could tail log content — authentication failures, hostnames,
paths — for hosts in other scopes or other tenants, or name a specific
out-of-scope device and read its lines directly. Log content is sensitive, so
this is a content disclosure, not merely a host-count oracle. The tail endpoint
now filters the device set exactly as search does; an out-of-scope request
returns nothing. This is the same "one endpoint gated, its sibling not" shape as
the privacy finding above, found by looking specifically for it.

### A governance control that a document import could switch off

An earlier commit put the governance switches — the four-eyes change-approval
requirement, the roles that must carry MFA, the audit-retention floor — behind a
fresh step-up re-authentication on the Settings save path, so an administrator
cannot quietly turn the control that watches them off. A second commit, unaware
of the first, added three of those same keys to the declarative-import
allowlist, which applies under a plain administrator token and can run from the
scheduler where there is no session to step up. An administrator refused at
Settings could have flipped four-eyes off by importing a configuration document.
The governance keys are removed from the import allowlist and refused at
apply-time; the retention-freeze (litigation-hold) setter, which lives on its
own endpoint, gained the same step-up gate.

### A webhook credential that left the instance in clear text

A delivery destination can carry custom headers, which is where an operator puts
a bearer token or an API key for the receiving system. Header *names* are not
secret-shaped, so the redaction that scrubs the support bundle, the declarative
export and the encrypted-backup configuration missed them, and a credential
placed in a header shipped in clear text in artefacts that are meant to be safe
to share. The redaction now masks header values in both its masking and its
dropping modes; the read API already withheld them, which is why the gap in the
exports had gone unnoticed.

### A device-existence oracle before authentication

The network-appliance configuration-archive endpoint looked up the device and
returned "not found" for an unknown identifier *before* it authenticated the
caller, so an unauthenticated request could distinguish real device identifiers
from absent ones. It now authenticates first, per method, like every sibling
under the device path.

### A spool that could delete un-forwarded audit records under load

The audit-forwarding retry drained its spool by reading it, forwarding, and only
then truncating by count — all with the position check and the truncation
outside the lock. Two retry workers entering together forwarded the same records
(a duplicate delivery to the SIEM) and the position-based truncation could
discard records spooled in between without ever forwarding them. The drain now
claims its slot under the lock and evicts exactly the records it forwarded, by
identity, so a record written during a slow forward is never lost — the same
claim-under-lock discipline the network-config and interface-history sweeps in
this release already use.

### Correctness defects with an operator-trust consequence

Not vulnerabilities, but each misled the operator about the state of the fleet,
which is its own kind of unsafe:

- The **threshold-impact preview** recomputed the checks engine only — about
  seven of the ninety-odd alert parameters — and reported "no host changes
  state" for the rest, which fire through the metric, risk and attention
  engines. An operator widening a threshold could read a green preview as "safe"
  when the preview had not looked. It now lists exactly which changed thresholds
  it could not assess.
- Three control-plane recovery events (maintenance-sweep, sidecar, audit-forward)
  could never clear their alerts — they are fleet-level and hit a device-scoped
  guard — so those alerts accrued in the inbox forever. A long-standing
  server-disk recovery had the identical defect. Fixed.
- A maintenance-sweep failure alert said a sweep had failed "N times in a row"
  while counting cumulative failures since the last recovery, so an alternating
  fail/succeed sweep raised a permanent alarm claiming a streak it never had.

### Data binding as a security property

Several signals the agents already collect were reaching only the advisory list,
which pages nobody. Host firewall state, sshd hardening (root login, password
authentication, empty passwords) and the automatic-update mechanism are now
**check rows** on Linux, at parity with the Windows and macOS equivalents that
were already checks, and are **queryable fleet-wide** ("which hosts permit root
SSH login", "which have no active firewall"). The PCI 1.2.1 firewall control
stopped returning a blanket "cannot assess" — the product has reported host
firewall state since v3.12.0 — and now attests the host-firewall layer honestly
while stating that upstream firewalls are out of scope. And the declarative
export stopped claiming to cover fleet-wide log rules and operator suppression
decisions that it silently dropped, which on a rebuild would have restored muted
world-exposed ports to alerting and re-enabled disabled compliance checks.

## Verification

- **bandit**: 0 new findings against the committed baseline, **0 High**, across
  `server/cgi-bin` and all three agents.
- **gitleaks**: no leaks, over the full history (1,696 commits) as well as the
  working tree.
- **`ruff --select F821`**: 0 on all three agents and on every handler module.
- **Full suite green on both storage backends** — over 11,000 tests, JSON and
  SQLite. No Postgres server was available for this pass, so the contract the
  database-lock fix depends on is pinned at source level in both storage modules,
  and that is stated rather than claimed as executed.
- **Live pre-auth check against the maintainer's own running instance**
  (authorised, read-only). The unauthenticated surface held: the health endpoint
  discloses only a status word, the content-security policy carries no
  `unsafe-inline`, HSTS is set with preload, the framing/content-type/referrer/
  permissions headers are all present, the login endpoint returns an identical
  answer for a real and an absent user (no enumeration) and rate-limits after a
  few attempts, HTTP redirects to HTTPS, path traversal is normalised, and no
  error path returned a stack trace or a framework fingerprint. The authenticated
  surface was not re-tested in this pass — the supplied token did not
  authenticate — so that part is stated as not-done rather than claimed.
- **Per-defect checks.** The new tests were run against the pre-fix code as well
  as the fixed code and confirmed to fail there. An assertion that passes on both
  sides proves nothing, so each assertion was confirmed failing against the
  pre-fix code before being kept.
  Where a fix itself turned out to be wrong — the Postgres eviction statement, the
  log-rotation check, the CVSS v4 mapping, the stricter brute-force parser — the
  second defect is listed above alongside the first, because a fix that breaks a
  neighbouring case is the most common way a correction does harm.
- **Tests that had pinned the buggy behaviour** were corrected with the reason
  recorded in each: a certificate expiry asserted as zero days, a snapshot name
  asserted invalid, a brute-force source asserted dropped, and an availability
  metric asserted from the wrong process. A test can be the reason a defect
  survives a green suite.
- CodeQL, run through the configuration the published build uses, is not reported
  here: the last pass was against v6.4.1, where it returned no results. It runs
  again before this release is tagged.

### A note on what "reviewed" means here

The last few of these documents reported that a release's new surface held up.
This one reports that several things did not. Both are the same exercise; the
difference is what it found.

The entries above include defects that are embarrassing to write down — a control
that read as on and redacted half of what it promised, a documented verifier that
could not do what the document said, an escaping helper that had been quietly
corrupting billing records. They are here because the useful question for a
reader is not whether a release had findings, but whether they would have been
told.
