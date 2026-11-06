# My Account

**My Account** holds the settings that belong to *you* rather than to the
server. Open it from the avatar menu in the top-right corner. Nothing you
change here affects other people signed in to the same instance.

The page has four tabs: **Profile**, **Security**, **Notifications** and
**Team**. Most settings save to your account, so if you sign in from a second
browser they follow you. The ones marked *this browser only* below do not.

## Profile

| Section | What it does |
| --- | --- |
| **Profile** | Your display picture. PNG, JPEG, GIF or WEBP up to 512 KB; it is downscaled in your browser before upload. The page also shows the username you are signed in as and the role you hold. |
| **Language** | The interface language. It is saved to your account. |
| **Appearance** | The theme for *this browser*. Pick a dark or a light theme, **Follow system** to track your operating system's light/dark setting, or **Time of day** to switch on the clock instead, which is what you want when the OS is pinned to dark. For **Time of day** you set the hours the day theme runs and which theme is the day one and the night one. A window that wraps midnight, such as 21 to 5, works. The **Accent** colour tints buttons and highlights on top of any theme, and **Background** adds a pattern behind the page. Under **Navigation**, **Auto-hide sidebar** (on by default on screens that can hover) collapses the sidebar to a slim rail that expands when you hover. Auto-hide pauses while alerts are open, so nothing that needs attention is hidden. Tick **Keep hiding while alerts are open** to keep the rail hidden anyway. Both navigation options are *this browser only*. |
| **Look** | Under **Appearance**. **Classic** is the interface as it has been, and it is what you get until you choose. **Pilot** is an option: a status is a lit dot and a plain word instead of a tinted pill, panels sit flat, and Home opens with the hosts online as a dot-matrix readout beside the fleet as a field of dots, one per host. Under Pilot, **Effects** can be set to *Reduced* to turn off the glow and the dot texture. The look is saved to your account, so it follows you to other browsers. If your administrator set one look for everybody, the choice is hidden. Every theme and accent works under both looks, and the logo is the same in both. |
| **Typeface** | Under **Appearance**. **System font** is what you get until you choose. **B612** is an option: a face Airbus and ENAC drew for aircraft cockpit screens, with letters that stay easy to tell apart. It is fetched only when you pick it, and it covers Latin letters; Chinese, Hindi and Arabic text and symbols use your system font. The wordmark beside the logo and monospace text do not change. The choice is saved to your account, so it follows you to other browsers, and it works under either look. |
| **Text size** | Under **Appearance**, and in the user menu at the bottom of the sidebar (**A** smaller, **A** larger). Makes everything on the page larger or smaller, buttons and tables included, in steps from 80% to 300%. 100% is what you get until you choose. It is saved in *this browser only*, because the right size depends on the screen. A narrow window holds the largest steps back so the layout keeps room: on a 1440 pixel wide window the top step is 200%, on a phone 110%. A 4K screen at its native size has room for 300%. |
| **Email signature** | An HTML block appended to ticket emails you send. It goes out as a rich HTML part with a plain-text fallback, so paste your normal contact block with links. See [ticket-system.md](ticket-system.md). |
| **SSH preferences** | Your default SSH username, used by the quick-SSH link on the Hosts page so you don't retype it. |
| **Display units** | Whether timestamps read as *3d ago* or as an absolute time, whether temperatures are shown in Celsius or Fahrenheit. The time setting covers the "last run", "created", "last seen" and "checked" columns: you see the form you picked, and the other one when you point at it. Logs and the audit trail always show the exact time, and so do expiry dates and the time of something that has not happened yet. Readings are stored and alerted on in Celsius either way, so switching the unit cannot move a threshold. |

## Security

| Section | What it does |
| --- | --- |
| **Permissions** | A read-only list of what your role lets you do. An administrator changes it under **Users & roles**; you cannot grant yourself more. |
| **Password** | Change the password you sign in with. You must enter your current password, and every other session is signed out afterwards. |
| **Two-factor authentication (2FA)** | Add a one-time code from an authenticator app. Scan the QR code, confirm one code, and store the recovery codes somewhere safe, because they are shown once. Each recovery code works once. **Regenerate recovery codes** replaces them and asks for your password. |
| **Passkeys (WebAuthn)** | Phishing-resistant sign-in with a security key, your phone, or this device's biometrics. You can register more than one and remove any of them. A passkey also satisfies a policy that requires MFA. The section is hidden when the server has no passkey support. |
| **Active sessions** | Every browser currently signed in as you, with when it was last used. Revoke anything you do not recognise, or use **Sign out all other sessions**. |

An administrator can require 2FA or a passkey for admin accounts and for any other
roles they name (**Settings → Security → Account guardrails**). If your role is on
that list and you have neither, you are asked to enrol and nothing else works until
you do. For the wider picture, read
[security.md](security.md); for company sign-in, [sso.md](sso.md).

## Notifications

| Section | What it does |
| --- | --- |
| **Browser notifications** | A desktop notification when a high or critical alert fires, even when RemotePower is not the active tab. *This browser only*: grant the permission again on each machine you use. **Send test** shows one. An administrator has to switch on **Settings → Integrations → Browser push notifications** first; until then the section says push is turned off. |
| **My notifications** | Your own webhook (Discord, Slack, ntfy or a generic URL) or email address, with your own filters, in addition to the fleet-wide routing an administrator sets up. It never turns those off. Set the **Minimum urgency** (everything, normal and up, high and up, or urgent only) and **Only hosts in** a group, a tag, a site or a list of names. You only get alerts for hosts you are allowed to see. A [maintenance window](maintenance.md) holds these too. See [alerts.md](alerts.md). |
| **New-alert announcements** | The tab badge is passive, so these are the active half: a chime and a browser notification when a new alert arrives. Both are off by default. Only a *rise* in the open-alert count announces, so opening the dashboard with alerts already open stays silent. |
| **My acknowledged alerts** | Alerts you have taken ownership of but not yet resolved, so you can find your way back to them. |

## Team

| Section | What it does |
| --- | --- |
| **My timesheet** | Opens your weekly time log, where you record billable and internal hours per day. Hours you log against a ticket appear here too. See [time-billing.md](time-billing.md). |
| **Team** | A free-text team name. The Tickets page groups "My team's open tickets" by it, so everyone who types the same name is on the same team. Leave it blank if you don't use teams. |

## Related

- [settings.md](settings.md): the server-wide settings, which need an admin role.
- [security.md](security.md): how accounts, sessions and tokens are protected.
- [ux.md](ux.md): the rest of the interface.
- [Keyboard shortcuts](keyboard-shortcuts.md): the keys that work on every page.
