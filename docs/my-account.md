# My Account

**My Account** holds the settings that belong to *you* rather than to the
server. Open it from the avatar menu in the top-right corner. Nothing you
change here affects other people signed in to the same instance.

Everything on this page saves per user. If you sign in from a second browser,
your account settings follow you; the two settings marked *this browser only*
below do not.

## Identity and profile

| Section | What it does |
| --- | --- |
| **Profile** | Your display picture. PNG, JPEG, GIF or WEBP up to 512 KB; it is downscaled in your browser before upload. The page also shows the username you are signed in as and the role you hold. |
| **Team** | A free-text team name. The Tickets page groups "My team's open tickets" by it, so everyone who types the same name is on the same team. Leave it blank if you don't use teams. |
| **Email signature** | An HTML block appended to ticket emails you send. It goes out as a rich HTML part with a plain-text fallback, so paste your normal contact block with links. See [ticket-system.md](ticket-system.md). |
| **Permissions** | A read-only list of what your role lets you do. An administrator changes it under Settings → Security; you cannot grant yourself more. |

## Signing in

| Section | What it does |
| --- | --- |
| **Password** | Change the password you sign in with. You must enter your current password, and every other session is signed out afterwards. |
| **Two-Factor Authentication (2FA)** | Add a one-time code from an authenticator app. Scan the QR code, confirm one code, and store the recovery codes somewhere safe — they are shown once. |
| **Passkeys (WebAuthn)** | Phishing-resistant sign-in with a security key, your phone, or this device's biometrics. You can register more than one and remove any of them. |
| **Active sessions** | Every browser currently signed in as you, with when it was last used. Revoke anything you do not recognise. |

An administrator can require 2FA or a passkey for everyone. If that is turned
on you will be asked to enrol at your next sign-in. For the wider picture, read
[security.md](security.md); for company sign-in, [sso.md](sso.md).

## Notifications

| Section | What it does |
| --- | --- |
| **Browser notifications** | A desktop notification when a high or critical alert fires. *This browser only* — grant the permission again on each machine you use. |
| **My notifications** | Your own webhook or email destination, with your own filters, separate from the fleet-wide routing an administrator sets up. Useful when you only want to hear about the hosts you own. See [alerts.md](alerts.md). |
| **New-alert announcements** | The tab badge is passive, so these are the active half: a chime and a browser notification when a new alert arrives. Both are off by default. Only a *rise* in the open-alert count announces, so opening the dashboard with alerts already open stays silent. |
| **My acknowledged alerts** | Alerts you have taken ownership of but not yet resolved, so you can find your way back to them. |

## Display

| Section | What it does |
| --- | --- |
| **Appearance** | The theme for *this browser*. **Follow system** tracks your operating system's light/dark setting; **Time of day** switches on the clock instead, which is what you want when the OS is pinned to dark. The accent colour tints buttons and highlights on top of any theme. |
| **Display units** | Whether timestamps read as *3d ago* or as an absolute time, and whether temperatures are shown in Celsius or Fahrenheit. Readings are stored and alerted on in Celsius either way, so switching the unit cannot move a threshold. |
| **SSH preferences** | Your default SSH username, used by the quick-SSH link on the Devices page so you don't retype it. |

## Time tracking

**My timesheet** opens your weekly time log, where you record billable and
internal hours per day. Hours you log against a ticket appear here too. See
[time-billing.md](time-billing.md).

## Related

- [settings.md](settings.md) — the server-wide settings, which need an admin role.
- [security.md](security.md) — how accounts, sessions and tokens are protected.
- [ux.md](ux.md) — the rest of the interface, including keyboard shortcuts.
