# Wizards and step-by-step forms

Three guided flows and one switch for long forms. They sit next to the dialogs you already use. Nothing changes until you press a button or
turn the switch on, and the dialogs they sit next to are still there.

| You want to | Open | What you get |
|---|---|---|
| Add a host | **Hosts → Enroll host → Guide me**, the empty Hosts page, or **Settings → Install → Getting started** | A wizard in four steps |
| Add a notification destination | **Settings → Notifications → Webhook destinations → Guide me**, or **Settings → Install → Getting started** | A wizard in four steps |
| Add an integration | **Settings → Integrations → Guide me**, next to **Add** | A wizard in four steps |
| Set up email | **Settings → Notifications → Email notifications (SMTP) → Guide me**, or the **Email (SMTP)** card of the notification wizard | A wizard in five steps |
| Fill in a long form one part at a time | The **Step by step** switch at the top of a form | The same form, a few fields at a time |

Only administrators can make install commands, PINs, notification destinations and integrations. Someone who cannot is shown the server's refusal.

## Add a host

The Enroll dialog shows a PIN, a one-line command and a Docker file on one screen. The wizard asks one thing at a time.

1. **Type.** Linux or macOS, Windows, a Docker host, an interactive install that asks for a PIN, or a host that cannot run the agent.
   The last one opens the **Add agentless host** form (a switch, printer, camera or UPS is added by address and checked without an agent).
2. **Settings.** What the host gets when it joins:
   - **Group** and **Tags** are put on the host when it enrols. Groups that exist already are offered as you type.
   - **Only from these networks** limits where the install may connect from, for example `10.0.0.0/24`. The server checks the address the
     install connects from. A command used from somewhere else is refused and stays valid for the right place. Leave it empty to allow any address.
   - **Valid for** is one hour, 24 hours or 7 days. The command works once.

   A PIN carries none of this, so a PIN install skips this step.
3. **Install.** The command for the type you chose, with a **Copy** button. Below it the wizard waits for the host and says when it
   has checked in. After five minutes without a host it says what to look at: the installer's output on the target, whether the target can reach
   this server, and whether the token was used already.
4. **Done.** What the host got: name, group, tags, OS and address. **Open host** opens its drawer. **Add another host** starts again with the same
   settings and a new command.

Going back and forward with the same settings does not make a second token. The tokens you make here are listed with the label
`guided-add-host`. The group and tags are the token's own defaults, the same ones `POST /api/enrollment-tokens` takes
(`default_group`, `default_tags`, `allowed_cidrs`).

## Add a notification destination

**Settings → Notifications** has one card for destinations with every service's fields on it. The wizard asks for what the service needs and
shows you the answer to a test before anything real is sent.

1. **Service.** Nineteen services in five groups: chat (Discord, Slack, Mattermost, Rocket.Chat, Google Chat, Microsoft Teams, Telegram, Matrix),
   push (ntfy.sh, Pushover, Gotify), on-call (PagerDuty, Opsgenie), tickets (GitHub issues, Jira, ServiceNow, Zendesk), an Apprise API server and a generic JSON receiver.
2. **Connection.** A name, the URL, and what that service needs beyond them: a Pushover app token and user key, a GitHub, PagerDuty or Opsgenie
   key, an account and token for the ticket services, a Telegram chat ID, a Matrix access token, an optional signing secret for the generic receiver.
   A service with one fixed address has it filled in.
3. **Test.** **Send a test message** saves the destination as a draft that is **switched off** and asks the server to send one message to
   it. The answer is shown here: **Delivered** with the status code, **Not delivered** with the code and what it usually means (a refused request
   is usually a wrong or revoked address or key, a 5xx is the service's own trouble), or the server's own words when it could not connect.
4. **Finish.** The minimum severity it should receive, a summary and **Turn it on**. If the test never delivered, the summary says so.

If you close the wizard before **Turn it on**, a draft that never delivered is removed. A draft that did deliver stays, switched off, and a
message tells you where to turn it on. Destinations that were there before are kept as they were, secrets included, and a secret you typed
is stored and never shown again. Events, scope, request headers and digests stay in the editor on the same page. Email is not a webhook: the **Email (SMTP)** card on the first
step opens the email guide below.

## Set up email

**Settings → Notifications → Email notifications (SMTP)** is a form of about twenty boxes, and email is switched on per event, so a form that is
filled in and tested can still send nothing. The guide asks in order and ends with email on and the events chosen.

1. **Service.** Ten choices in three groups. Mail accounts: Gmail or Google Workspace, Microsoft 365, Fastmail, Proton Mail Bridge. Sending
   services: Brevo, Mailgun, SendGrid, Amazon SES. Your own server: another mail server, or a mail relay on this server. If email is set up already,
   the choice that matches its server is selected and the guide says it replaces those settings.
2. **Connection.** The server, the port and the TLS mode that service documents, then the user name, the password and the From address. A note at
   the top says what to get ready first: an app password for Gmail and Fastmail, the SMTP key (not the API key) for Brevo, the word `apikey` for
   SendGrid, SMTP credentials made in the SES console, the password Bridge shows for Proton. Choosing another TLS mode moves the port to its
   usual one (587, 465, 25) while the port is still a usual one. A server that takes mail without a login leaves the user name empty. **Check the
   TLS certificate** is on; turn it off for a server of your own with a self-signed certificate (Proton Mail Bridge starts with it off).
3. **Recipients.** The addresses that get the alerts, separated by commas.
4. **Test.** **Send test email** sends a real message to the first address through what you typed. The server tests these settings without
   saving them, so a wrong password or port never replaces settings that work. **Sent** names the address. **Not sent** shows the server's own
   words and one line on what to check: the login, the TLS mode against the port, the certificate, the server name, a closed port, a sender or
   a recipient the server refuses.
5. **Finish.** A summary, and which events are sent by email: **only the serious events** (what the Alerts page rates critical or high, with their
   recoveries, so a host that went offline and came back both arrive), **every event the webhooks send**, or **only the events you choose in
   Settings**. Events that are ticked already are kept in every case, and select the third choice when some are. **Turn it on** saves.

Email is saved only at **Turn it on**, with the same settings the form saves and with email switched on, so closing the guide earlier changes
nothing. The boxes of the Settings page show what was saved, so pressing **Save settings** there afterwards does not put the old values back.
A password you typed is stored and never shown again. If one is saved, leave the box empty to keep it; it is only kept for the same server and
user name, so a new server asks for the password again. If the server's environment holds `RP_SMTP_PASSWORD`, that password is used and the
box is not needed. The guide is for the platform operator, like the form.

## Add an integration

**Settings → Integrations** adds an integration with a list of every connector and a card to fill in. The wizard asks for the same things in
order.

1. **Service.** Every connector the server has, grouped (Apps, Media, Downloads, Requests, DNS, Proxies, Network, Monitoring, Orchestration,
   Storage, Backup, Security, Your own), with a search box that finds a service by its name or its type. A connector you installed as a plugin is
   in the list too. The virtualization platforms have their own page and are not here.
2. **Connection.** A name and the address (the two cloud services, Tailscale and Cloudflare Tunnel, start with theirs), then the fields that
   connector asks for: an API token, a username, a page name, up to the lines of a Prometheus check. A field that is optional says so. **Check the
   TLS certificate** is on; turn it off for a service on your network with a self-signed certificate. The note of the connector is shown above the
   fields.
3. **Test.** **Test the connection** asks the server to reach the service with what you typed and shows what it said, and saves nothing. A
   service that answers and reports a problem of its own (an Uptime Kuma with a monitor down) is reached, and says so in amber. One that
   does not answer is **Not reachable**, with the reason the server gave.
4. **Finish.** A summary and **Add it**. A test that did not pass does not stop you: the card is where you fix it.

The wizard saves only at **Add it**, so closing it earlier leaves nothing. The list that is saved is the server's own, read a moment before, with
the new integration in it, so the other integrations and their secrets stay as they were. If you have edits on the Settings page that you have not
saved, they are still there afterwards, and the new integration is in the list beside them.

## Step by step

The **Step by step** switch sits at the top of six forms: **New maintenance window**, **Add monitor target**, **New backup job**,
**New auto-patch policy**, **New rollout** and **New host profile**. It is off until you turn it on. The choice is kept in this browser and
applies to all six. The shorter dialogs (a custom role, a scheduled command, an agentless host) show a handful of controls at a time and have
no switch.

With it on, the form is the same form, shown a part at a time under a list of steps:

| Form | Steps |
|---|---|
| New maintenance window | What, When, Effects, Review |
| Add monitor target | What, Target, Checks, Alerting, Review |
| New backup job | What, How, When, Review |
| New auto-patch policy | What, When, Safety, Review |
| New rollout | What, Rings, Safety, Review |
| New host profile | What, Watches, Thresholds, Review |

- **Next** goes on, **Back** goes back, and a step that is done in the list goes back to it. Enter in a text box goes on.
- A step with nothing to show is left out. A ping monitor has no checks to set, so it has no **Checks** step; an HTTP monitor has one.
- A step says what the form itself would refuse, before the last step instead of after: no start time on a one-shot window, a monitor with no
  target, a backup job with no host, a rollout with no ring that has a target. The words are the form's own.
- **Review** lists the choices you made, step by step, and the form's own button (**Create**, **Add** or **Save**) is shown there. It saves exactly
  what the form saves. Editing an existing item opens the same way.
- Turning the switch off puts the form back as it was, with every field showing.

## Keyboard and screen readers

Escape closes a wizard, and focus goes back to where it was. Tab stays inside the dialog. **Ctrl or Cmd with Enter** presses the dialog's
last primary button: **Next** on a step, the form's own save on the review. Each step is announced by name, the step list marks the step you
are on, and a refusal is read out. On a phone only the step you are on keeps its name in the list.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
