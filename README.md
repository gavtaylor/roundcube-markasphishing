# markasphishing

A [Roundcube](https://roundcube.net/) webmail plugin that adds a "Report Phishing" button and context-menu option, similar to the built-in `markasjunk` plugin. Marking a message as phishing reports it (original message attached, headers intact) to:

- the abuse desk of the mail provider that sent it, based on a configurable domain → address directory, and
- one or more national/international anti-phishing authorities (UK NCSC's Suspicious Email Reporting Service, APWG, etc. — enabled by default), regardless of sender.

Both lists are editable at runtime from a Settings page, not just a config file.

> **This project was built using agentic AI development** (Claude Code). The plugin architecture is modelled on Roundcube's own core [`markasjunk`](https://github.com/roundcube/roundcubemail/tree/master/plugins/markasjunk) plugin for consistency with the ecosystem, but the code itself is original, not copied. We're disclosing this up front because we know not everyone's comfortable with AI-authored code in something touching their inbox — review it accordingly before you install it.

## Status

Tagged `v0.1.0`. Functional and tested against a live Roundcube 1.7 instance (toolbar, context menu, settings page on desktop and mobile, and end-to-end report sends covering all post-report actions, envelope-domain spoofing detection, partial-delivery failures, and duplicate-report dedupe) — but only ever run against one instance by one admin so far, so treat config options and the DB schema as still liable to change before a 1.0.

## What it does

1. Adds a toolbar button (icon + "Phishing" label, matching how `Delete`/`Spam` look) to the open message view, and — via the [contextmenu](https://github.com/johndoh/roundcube-contextmenu) plugin if installed — a right-click menu entry (text-only there; the popup menu doesn't carry over the toolbar button's icon styling).
2. Looks up the sender's domain against a shared directory of known provider abuse addresses. Falls back to `abuse@<domain>` (the [RFC 2142](https://www.rfc-editor.org/rfc/rfc2142) standard abuse contact) if no explicit entry matches and that fallback is enabled.
3. Also checks the *envelope* sender — `Return-Path`, or a `dkim=pass` domain from `Authentication-Results` if that's absent — separately from the `From:` header, since `From:` is exactly what phishing spoofs. A report for a mail impersonating a known brand goes to that brand's abuse desk *and*, if the envelope domain differs, an RFC 2142 fallback address for whoever actually sent it — otherwise the provider who could actually act on the sending account never hears about it. Best-effort: not every mail server stamps these headers consistently, and an empty result here just means this step is skipped, not an error.
4. Always also reports to whichever global authorities are enabled in the directory.
5. Sends the original message as a `message/rfc822` attachment (not a plain forward) from the reporting user's own identity, so headers survive intact for analysis — as **one separate email per matched recipient**, not a single email with the rest Bcc'd. We have no evidence either way that abuse-desk intake systems handle a multi-recipient forward the same as an individual report, so this doesn't assume they do; a delivery failure for one recipient doesn't affect the others, and the report still counts as sent if at least one recipient received it. If some recipients succeed and others fail, the toast says so rather than reporting a flat success or failure.
6. Skips re-sending if the exact same message (matched by `Message-ID`) was already reported — by anyone on the instance, not just the same user, since the same phishing blast landing in several mailboxes shouldn't mean several redundant reports. The tracking table cleans up old entries opportunistically as the plugin gets used (`markasphishing_dedupe_retention_days`, default 90) rather than needing a cronjob.
7. Logs every individual send attempt (recipient, success/failure, and which mailbox on this instance the phishing message was reported from) to a separate table, purely to drive the admin-facing stats described below — not exposed to non-admin users, and cleaned up on the same schedule/retention window as the dedupe table above.
8. Applies the user's chosen post-report action to the original message: move to a folder, delete (to Trash), or leave in place — even for a message that was skipped as a duplicate, since the user still wanted it filed away.

The `.eml` attachment's filename is derived from the phishing message's own subject line, sanitized first since that's attacker-controlled text (not a security issue either way — it's only ever a MIME filename value, never used as an actual filesystem path — but an adversarial subject shouldn't get to produce a malformed-looking attachment name).

## Settings page

Settings → Phishing Reporting, in two parts on one page with a single Save button (sticky to the bottom of the pane):

- **My reporting preferences** (everyone) — what happens to a message after it's reported: move to a folder (name configurable, created automatically if it doesn't exist), move to Trash, or leave it where it is. The folder-name field disables itself live as you change the dropdown, without needing to save first.
- **Stats** (admins only) — reports tracked in total / last 7 / last 30 days, overall delivery success rate, and the top 5 most-reported addresses and most-targeted mailboxes on the instance. Deliberately simple: it's a direct read of the dedupe/send-log tables described above, not a separate analytics feature, and it only ever covers whatever's still within `markasphishing_dedupe_retention_days` — the hint text under the cards says so, so the numbers don't look mysteriously low after old entries age out.
- **Report directory** (read-only list for everyone; add/edit/delete only for usernames listed in `markasphishing_admins`, see below) — one row per provider or authority (not per domain — a provider that owns several domains, like Microsoft, lists them all in one row, comma-separated, so enabling/disabling it is one checkbox rather than several), with an edit and a trash icon per row. Authorities show `*` under Domain(s) since they apply to every sender, not one. Adding or editing an entry uses the same standalone form, behind an "Add a new entry" link on the main page or the per-row edit icon; kept off the main page since it's not something you do often. If you submit an edit or a new entry with an invalid domain, the form re-renders with what you typed still filled in rather than losing it.

## Report directory defaults

Seeded on install, all enabled by default. **These addresses were gathered from public support documentation and are best-effort — verify them before relying on this in a real incident, and expect some to go stale over time.** Some large providers (Google in particular) primarily want reports through their own in-client "Report phishing" flow rather than a forwarded email, so treat provider-address delivery as a courtesy notification, not a guarantee of action.

| Type | Name | Domain(s) | Report address |
|---|---|---|---|
| Provider | Gmail | gmail.com, googlemail.com | abuse@gmail.com |
| Provider | Microsoft (Outlook/Hotmail/Live) | outlook.com, hotmail.com, live.com, msn.com | phish@office365.microsoft.com |
| Provider | Yahoo | yahoo.com, yahoo.co.uk, ymail.com, rocketmail.com | abuse@yahoo.com |
| Provider | iCloud | icloud.com, me.com, mac.com | abuse@icloud.com |
| Authority | NCSC Suspicious Email Reporting Service (UK) | * | report@phishing.gov.uk |
| Authority | Anti-Phishing Working Group | * | reportphishing@apwg.org |

## Installation

```bash
cd /path/to/roundcube/plugins
git clone https://github.com/gavtaylor/roundcube-markasphishing.git markasphishing
cd markasphishing
composer install --no-dev   # if the plugin has any dependencies
```

Add `markasphishing` to `$config['plugins']` in your Roundcube `config.inc.php`. The database schema is created automatically on first use (MySQL/MariaDB only, currently).

Copy `config.inc.php.dist` to your Roundcube `config/config.inc.php` (or merge the relevant block in) and adjust as needed — see the comments in that file for every option. Notably, on a multi-user install you should set `markasphishing_admins` to a list of usernames trusted to edit the shared report directory; if left unset, any logged-in user can edit it.

## Configuration reference

See [`config.inc.php.dist`](config.inc.php.dist) for the full list of options with defaults and descriptions.

## License

[GPL-3.0-or-later](LICENSE), matching Roundcube core and the wider plugin ecosystem this integrates with.
