# Wizards and step-by-step forms

Two guided flows and one switch for long forms. They sit next to the dialogs you already use. Nothing changes until you press a button or
turn the switch on, and the dialogs they sit next to are still there.

| You want to | Open | What you get |
|---|---|---|
| Add a host | **Hosts → Enroll host → Guide me**, the empty Hosts page, or **Settings → Install → Getting started** | A wizard in four steps |
| Add a notification destination | **Settings → Notifications → Webhook destinations → Guide me**, or **Settings → Install → Getting started** | A wizard in four steps |
| Fill in a long form one part at a time | The **Step by step** switch at the top of a form | The same form, a few fields at a time |

Only administrators can make install commands, PINs and notification destinations. Someone who cannot is shown the server's refusal.

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

1. **Service.** Eighteen services in five groups: chat (Discord, Slack, Mattermost, Rocket.Chat, Google Chat, Microsoft Teams, Telegram, Matrix),
   push (ntfy.sh, Pushover, Gotify), on-call (PagerDuty, Opsgenie), tickets (GitHub issues, Jira, ServiceNow, Zendesk) and a generic JSON receiver.
2. **Connection.** A name, the URL, and what that service needs beyond them: a Pushover app token and user key, a GitHub, PagerDuty or Opsgenie
   key, an account and token for the ticket services, a Telegram chat ID, a Matrix access token, an optional signing secret for the generic receiver.
   A service with one fixed address has it filled in.
3. **Test.** **Send a test message** saves the destination as a draft that is **switched off** and asks the server to send one message to
   it. The answer is shown here: **Delivered** with the status code, **Not delivered** with the code and what it usually means (a refused request
   is usually a wrong or revoked address or key, a 5xx is the service's own trouble), or the server's own words when it could not connect.
4. **Finish.** The minimum severity it should receive, a summary and **Turn it on**. If the test never delivered, the summary says so.

If you close the wizard before **Turn it on**, a draft that never delivered is removed. A draft that did deliver stays, switched off, and a
message tells you where to turn it on. Destinations that were there before are kept as they were, secrets included, and a secret you typed
is stored and never shown again. Events, scope, request headers, digests and e-mail stay in the editor on the same page. E-mail is not in the
wizard.

## Step by step

The **Step by step** switch sits at the top of four forms: **New maintenance window**, **Add monitor target**, **New backup job** and
**New auto-patch policy**. It is off until you turn it on. The choice is kept in this browser and applies to all four.

With it on, the form is the same form, shown a part at a time under a list of steps:

| Form | Steps |
|---|---|
| New maintenance window | What, When, Effects, Review |
| Add monitor target | What, Target, Checks, Alerting, Review |
| New backup job | What, How, When, Review |
| New auto-patch policy | What, When, Safety, Review |

- **Next** goes on, **Back** goes back, and a step that is done in the list goes back to it. Enter in a text box goes on.
- A step with nothing to show is left out. A ping monitor has no checks to set, so it has no **Checks** step; an HTTP monitor has one.
- A step says what the form itself would refuse, before the last step instead of after: no start time on a one-shot window, a monitor with no
  target, a backup job with no host. The words are the form's own.
- **Review** lists the choices you made, step by step, and the form's own button (**Create**, **Add** or **Save**) is shown there. It saves exactly
  what the form saves. Editing an existing item opens the same way.
- Turning the switch off puts the form back as it was, with every field showing.

## Keyboard and screen readers

Escape closes a wizard, and focus goes back to where it was. Tab stays inside the dialog. **Ctrl or Cmd with Enter** presses the dialog's
last primary button: **Next** on a step, the form's own save on the review. Each step is announced by name, the step list marks the step you
are on, and a refusal is read out. On a phone only the step you are on keeps its name in the list.

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
