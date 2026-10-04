# Security review — v7.1.0

Every release gets a review before it ships. This one found **ten** issues
worth reporting, all **caught before release** and all fixed in the release they
are described in. None came from the field.

As with the last two reviews, most of them are older than this release. The
review covers the whole project, not the release's diff, because the diff is
where a reviewer already looks.

The bar this project holds itself to is that nothing Critical, High or Medium
ships. That bar is met.

## What was reviewed

- **The whole project.** The server and its request handling, the multi-tenant
  boundaries, the three agents, the SSH gateway and the other sidecars, threat
  intel, the installers, the container images and the web-server
  configuration.
- **The web server as it ships.** nginx was run with the shipped configuration
  files included unchanged, in front of the real application server, and
  scanned with the tools the product's own Pentest page runs — nmap with its
  HTTP scripts, nikto, and nuclei with its full HTTP template set (about
  10,000 templates) — and with wapiti, signed in and fed the API's own OpenAPI
  description, so its injection, file, command-execution, SSRF, XXE, CRLF and
  redirect modules exercised all 742 API paths rather than only the login
  page.
- **Static analysis:** CodeQL with the production query suites and
  configuration, semgrep across Python, JavaScript, shell, Dockerfiles and
  HTML, bandit against a triaged baseline, gitleaks over the full history, and
  an undefined-name check on every Python and JavaScript file.
- **The full test suite** on every storage backend, plus the browser-driven
  accessibility, layout and rendering sweeps against a populated instance.

## Summary

| # | Finding | Before the fix | Where |
|---|---|---|---|
| 1 | A tenant admin could change state that belongs to the whole install | High, multi-tenant installs only | Server |
| 2 | Signed links in alert emails took their address from the request | Medium, when the links are switched on | Server |
| 3 | A crafted SSH user name could make threat intel blame an address of the attacker's choosing | Medium | Server |
| 4 | Threat intel reported addresses it would never block | Medium | Server |
| 5 | The agent's two WebSocket channels followed redirects with the device token | Medium | Agent |
| 6 | The SSH gateway let one connection offer keys for the whole login window | Medium | SSH gateway |
| 7 | Devices enrolled by a tenant admin landed in the platform tenant | Low | Server |
| 8 | Inbound webhook tokens were listed and revoked across tenants | Low | Server |
| 9 | Manual block and unblock read the device store before authenticating | Low | Server |
| 10 | The shipped nginx configuration disclosed its version and answered 200 for every path | Low | Web server |

## The pattern worth naming

**The instance is not a tenant.** Multi-tenancy is opt-in and off by default.
When it is on, a tenant admin passes every "is this an admin?" check, because
inside their tenant they are one. The install's own configuration, signing
keys, AI provider, audit log and shared libraries are not inside any tenant,
and the checks that guard them asked the wrong question.

v7.0.2 found this on the Settings page and fixed it there. The same shape was
still open in about fifty handlers that each own one slice of that state. A
rule fixed in the most visible place and left open in the rest is the pattern
the last two reviews named too, and the answer is the same: one gate in the
place every request passes through, and a test that finds the population from
the source instead of from a list.

## 1. Tenant admins could change install-wide state

On an install with multi-tenancy enabled, a tenant admin could:

- restore an older configuration revision, including one from before tenancy
  was switched on — which switched it off;
- point the AI provider at a server they control, which would have received
  the stored provider key and every tenant's prompts;
- replace the release signing key, or turn signature enforcement off;
- redirect metrics push, the GitOps export or scheduled reports;
- clear the audit log, re-key the CMDB vault, destroy KMIP keys, or edit roles;
- rewrite a playbook, blueprint or library command that another tenant runs.

Every handler that writes install-wide configuration now requires the platform
operator. The infrastructure (KMIP, satellites, WireGuard, scanner targets),
the control plane (roles, audit and history wipes, the vault passphrase,
webhook delivery) and the shared libraries are gated once, where the request
is routed, rather than in each handler. Running or rendering a shared playbook
stays open to tenant admins, and the per-device check still decides which hosts
it may touch. The test that covers this reads the handlers from the source, so
a new one cannot be added without a decision.

## 2. Signed links in alert emails took their address from the request

Alert emails can carry one-click **Acknowledge** and **Resolve** links. They are
signed, so clicking one acts on the alert without a login. Their address was
the Host header of whichever request fired the alert, and the shipped nginx
configuration passes any Host through. Alerts fire inside agent heartbeats,
inbound webhooks, failed sign-ins and the maintenance sweeps that run on
ordinary requests, so a request with a forged Host could produce a real
email from your own server whose links pointed at someone else's site — with a
working signature for that alert attached. That is a convincing phishing email,
and a way to silence the alert it describes.

The customer portal had already solved the same problem for its sign-in link by
using a URL the operator sets. Alert links now do the same: they use the new
**Dashboard public URL** setting, and are left out of the email when it is not
set. The links cannot be switched on without it. The links are off by default,
so only installs that had turned them on were exposed.

## 3. A user name could make threat intel blame someone else

sshd writes the user name a client asks for into its log line, before the real
source address, and keeps any spaces in it. A login attempt as
`x from 203.0.113.9` produced a line with two addresses in it, and the
brute-force detector took the first one. Repeat that past the threshold and the
attempts were counted against an address of the attacker's choosing. With
automatic blocking on, that address could be blocked on the host. With
reporting on, it was reported to AbuseIPDB and SniffCat under the operator's
API key.

The SSH patterns now take the last address in the line, the one followed by
`port`, which a client cannot write. Each pattern is tested with an injected
user name.

## 4. Reporting ignored the never-block rules

Some addresses are never blocked: every address the fleet reports as its own,
the UI allow-list, the operator's never-block list, and addresses people
signed in from recently. Those rules applied to blocking and not to
reporting, so a misconfigured threshold or the injection above could report
one of your own addresses to a public abuse database. Reporting now honours the
same rules.

## 5. The agent's WebSockets followed redirects

The push channel and the SSH gateway tunnel authenticate with the device token
in a custom header. The WebSocket library follows up to ten redirects and, when
one crosses to another origin, strips only the standard credential headers, so
the device token would have gone to whatever host a redirect named. Every HTTP
call the agent makes has refused redirects for years; the WebSocket clients
came later and used the library default.

Both now refuse redirects. This was tested against four major versions of the
library with a real redirect to a second listener, using the unmodified client
as the control that shows the leak.

## 6. The SSH gateway had no limit on key offers

The gateway's SSH library has no equivalent of OpenSSH's `MaxAuthTries`, so one
unauthenticated connection could offer keys for the whole 30-second login
window. Each offer was a request to the API that reads the user store, and the
failed-login throttle counted connections, not offers.

A connection can now offer at most ten keys, and an address can have at most
ten connections still logging in at once. The second, signed request for a key
that was already accepted is answered from the connection's own record, so a
successful login costs one API call instead of two.

## 7 and 8. Two smaller tenancy gaps

- **Enrolment.** A device enrolled with a PIN or token that a tenant admin
  created joined the platform tenant, where that admin could not see it, and
  enrolment tokens were listed and revoked across tenants. PINs and tokens now
  record the tenant that created them, the device joins that tenant, and each
  tenant sees only its own tokens.
- **Inbound webhook tokens.** A token pinned to a device now belongs to that
  device's tenant. Unpinned tokens are the platform operator's.

## 9. Manual block and unblock checked permissions last

The handlers read the device store and resolved the target before checking who
was asking, so an unauthenticated request could tell an existing device ID
from a missing one by the response. They authenticate first now. Manual
threat-intel lookups, which spend the install's daily provider quota, are the
platform operator's under multi-tenancy.

## 10. What the web-server scans found

nmap, nikto, nuclei and wapiti against nginx running the shipped
configuration found no vulnerability in the application: wapiti's authenticated
pass over 1,090 resources, every API path among them, reported no injection,
no file or command execution, no SSRF and no server error. The scanners did
find four things worth changing in the configuration itself:

- **The nginx version was in every response.** `server_tokens off` is now set
  in every server block, in the bare-metal and the container configuration.
- **Every path answered 200.** Unknown paths fell back to the dashboard, which
  nothing needs because the dashboard routes by `#fragment`. That turned each
  scanner probe for a well-known file into a reported "found" result: nikto
  listed dozens. Unknown paths return 404 now.
- **`X-XSS-Protection: 1; mode=block`.** The browser feature this configures is
  gone from current browsers and, where it survives, the blocking mode can be
  misused. It is set to `0`, as OWASP and MDN recommend.
  `X-Permitted-Cross-Domain-Policies: none` was added.
- **Two nuclei matches were the login page's own words.** The page ships the
  dashboard's markup, which contained a button labelled "Power Off" and a
  smart-plug vendor's name, and two templates read those as an exposed device
  web interface. The button label now matches the rest of the interface
  ("Power off") and the vendor list is built when the dialog opens.

The same run turned up one bug that is not a security issue: the API location
allowed GET, POST, DELETE and PATCH, and the dashboard saves about thirty kinds
of edit with PUT — schedules, maintenance windows, sites, tenants, the report
schedule. On a standard install every one of those saves was refused by nginx.
PUT is allowed now, and a test checks the configuration against every method
the dashboard sends.

What remains is informational: no HSTS header on plain HTTP (it is in the
shipped HTTPS block and only means anything there), no
`Cross-Origin-Embedder-Policy` (the dashboard is already isolated with
`Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy`), and
technology fingerprints that match product names in the interface text.

## What the scans found

| Tool | Result |
|---|---|
| CodeQL (production configuration) | 0 results, Python and JavaScript |
| semgrep (851 rules: security, audit and correctness sets for Python, JavaScript, shell, Dockerfile and HTML) | 2,164 matches, all triaged; none exploitable |
| bandit (against the triaged baseline) | 0 new, 0 high |
| gitleaks (full history and working tree) | no leaks |
| undefined-name check (Python and JavaScript) | 0 |
| nmap, nikto, nuclei (shipped nginx configuration) | no findings above informational after the fixes in section 10 |
| wapiti (signed in, all 742 API paths from the OpenAPI description) | 0 vulnerabilities, 0 anomalies |

The semgrep count looks large because this run used the audit rule sets, which
flag every use of a pattern rather than an unsafe one: each `innerHTML`
assignment (the dashboard escapes what it interpolates, and tests drive the
renderers with hostile input), each `subprocess` call (argument lists, apart
from two shells that are meant to be shells: the agent's command channel, where running a shell
command is the feature, and a secret-helper command the operator sets in the
server's environment — neither takes request data). The rest are false
positives — `ipaddress`
properties read as un-called methods, NaN checks written on purpose, intended implicit
string concatenation — and one protocol-mandated cipher mode (AES-CFB is what
SNMPv3 privacy specifies).

As in earlier reviews, the table is worth reading next to the rest of this
document. Findings 1 to 9 were present while every static tool reported clean.
Scanners find the classes they encode; they do not know that a tenant admin is
not the platform operator, or which half of an sshd log line a client can
write.

## What the tests were and were not proving

Two test-suite defects were found and fixed. Neither is a product
vulnerability; both made a green result mean less than it appeared to.

- **About 190 assertions never ran in CI.** Ten test files drive the
  dashboard's real JavaScript in an embedded V8 engine and skip when it is not
  installed. CI did not install it, so those files reported success without
  running. CI installs it now.
- **One test depended on the order the suite ran in.** A dozen handler tests
  set a per-request context and left it behind, and a later test read the
  leftover request method and answered 405. The context is now cleared between
  test modules, and the tests that set it clear it themselves.

## Reporting

If you find something, please report it privately — see
[SECURITY.md](../SECURITY.md) for how. Reports are answered.
