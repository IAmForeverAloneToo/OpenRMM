# Signed-in Users

The agent reports the Windows sessions that have a signed-in user every minute, and the server builds an observed session history from those reports. Administrators and technicians use it to see who is using a device right now and who used it recently.

## Contents

- [Overview](#overview)
- [What is collected](#what-is-collected)
- [Schedule and states](#schedule-and-states)
- [Observed history and retention](#observed-history-and-retention)
- [Using it in the dashboard](#using-it-in-the-dashboard)
- [Limits and validation](#limits-and-validation)
- [API and permissions](#api-and-permissions)
- [Turning it off](#turning-it-off)
- [Privacy](#privacy)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## Overview

- Open a device's **Users** tab and choose **Signed in** or **History**. The filter matches `DOMAIN\user`, the client name and the client address, and applies to both views.
- The device **Overview** shows a **Signed-in users** line.
- The **Devices** list has a **Signed-in user** column, and its filter box also matches users.

The same tab has **Logons** ([LOGONS.md](LOGONS.md)), **Local accounts** and **Groups** ([LOCAL-ACCOUNTS.md](LOCAL-ACCOUNTS.md)) views.

> [!NOTE]
> Signed-in users is what the agent observed once a minute, not a Windows logon audit. For the Windows logon audit (event 4624) use the **Logons** view, which belongs to the same feature.

## What is collected

The `sessions` v1 module runs inside the agent (LocalSystem). It enumerates the local sessions with the Windows Terminal Services API (`WTSEnumerateSessions`, `WTSQuerySessionInformation`) and reports each session that has a user name. The services session and listener sessions have no user and are not reported. It starts no process and writes nothing to the device.

| Field (API) | Meaning |
| --- | --- |
| `session_id` | Windows session ID. Windows reuses IDs. |
| `user`, `domain` | Signed-in user and domain (or the computer name for a local account), shown as `DOMAIN\user`. |
| `state` | `active`, `disconnected` or `other` (every other Windows state, such as connected or idle). |
| `connection` | `console`, `rdp` (Remote Desktop) or `other` (any other client protocol, or unknown). |
| `station` | Window station name, for example `Console` or `RDP-Tcp#3`; empty if longer than 64 bytes. Not shown in the dashboard. |
| `logon_at` | Logon time from Windows, Unix seconds, device clock; `0` when Windows does not provide it (shown as **Unknown**). |
| `idle_seconds` | Time since the last input; `-1` when unknown. The console often has no last-input time, so its idle time is usually **Unknown**. |
| `client_name`, `client_address` | Remote client computer name and IPv4/IPv6 address. Not read for console sessions; empty when Windows does not provide them. |

Text values are read up to 512 UTF-16 characters; a longer or unreadable value is treated as empty. A session whose user name Windows does not return is treated as having no signed-in user: it is neither reported nor counted as skipped.

## Schedule and states

- The agent collects at startup and every minute, with the shared five-second collection deadline. Linux agents report **Not supported**.
- A report is collected, failed, disabled or unsupported. A failed, disabled or unsupported report keeps the last successful list (marked stale) and does not change history.
- The **Users** tab refreshes every 30 seconds and shows the time of the last successful list. The list is marked **Stale** when the last successful report is three minutes old or more (one missed report is allowed), when the latest report was not successful, or when the device is not online.

The **Devices** list and its filter use a stricter rule: only users of `active` sessions, only from a successful report at most five minutes old, and only for online devices. Disconnected sessions are not listed there. When several users are active, the column shows the first and `+N`; hover for all.

## Observed history and retention

The server keeps the newest report per device and an observed session history: one row per session, identified by device, session ID, domain, user and logon time. Each successful report:

- adds a row for a session not seen before (**First seen** is the server's receipt time);
- updates **Last seen** and the row's details (state, connection, client, idle) for sessions still reported;
- sets **Gone by** on open rows that are missing from this report. The session ended (or changed) somewhere between **Last seen** and **Gone by**.

A row whose session appears again has its **Gone by** cleared; **First seen** stays. Times are server receipt times, except **Signed in**, which is the device's logon time. Failed, disabled or unsupported reports, and reports older than the stored one, do not change history. While the device is offline or the feature is off, open rows keep showing **Still signed in**; the next successful report then sets **Gone by** to its own time, so the interval can be long.

Limits of this approach:

- A session that starts and ends between two reports (about a minute) is not seen.
- When Windows provides no logon time (`0`), two sign-ins of the same user into a reused session ID share one row. If the logon time becomes known later, a new row starts and the old one is marked gone.
- A disconnected session that is reconnected keeps its row as long as Windows reports the same session ID and logon time; the state and client columns show the latest values only.

| Retention | Value |
| --- | --- |
| Age (by last seen) | 365 days |
| Rows per device | 2,000 (oldest **Last seen** removed first, on each successful report) |
| Rows overall | 500,000 |
| Rows shown on the device page | newest 500 by last seen |

The 365-day and overall limits are applied by the server's housekeeping every minute; the API also hides rows older than 365 days immediately. Removing a device removes its rows. Logical deletion does not securely erase SQLite pages, the WAL or backups.

Restoring a backup keeps the restored history as it was. Sessions that came and went between the backup and the restore are missing, and rows that were still open in the backup are marked **Gone by** at the first successful report after the restore if the session is no longer there.

## Using it in the dashboard

**Users** tab (`?tab=users`, `&view=history` for History):

- **Signed in:** User, State, Connection, Client (name and address), Signed in (relative, with the absolute time on hover), Idle and Session ID. Empty states read **Nobody is signed in** (a successful empty list) or **No sessions reported**.
- **History:** User, Connection, Client, Signed in, First seen, Last seen and Gone by (**Still signed in** while open).
- The toolbar shows the collection state (**Stale**, **Collection failed**, **Disabled on device**, **Not supported**, **Not reported**) and the skipped count.

**Overview → Agent capabilities → Signed-in users** lists the users of active sessions. With no active session it shows `N signed in, none active` when other sessions exist, or **Nobody signed in**; without a current successful report it shows the collection state.

## Limits and validation

At most 64 sessions are reported. The agent drops sessions with invalid details or a repeated session ID, orders the rest by session ID and keeps the first 64; everything left out is counted as `skipped` (shown next to the list). A report is at most 64 KiB.

The server decodes reports strictly:

- Every field is required; unknown fields are rejected, and an invalid report is refused as a whole.
- User is required and at most 256 bytes; domain and client name at most 256 bytes; station at most 64 bytes. Text must be valid UTF-8 without control characters or leading/trailing spaces.
- The client address must be a canonical IP address. Logon time must not be negative, idle seconds not below `-1`, and session IDs must be distinct.
- A report for a capability version other than 1 is stored as unsupported.

Usernames, domains and client names come from the device and are untrusted text; the dashboard escapes them.

## API and permissions

`GET /api/v1/devices/{id}/sessions` takes no filters and returns:

- `info`: `capability`, `status` (`ok`, `failed`, `disabled`, `unsupported` or `not_reported`), `reported_at`, `snapshot_at`, `has_snapshot`, `count`, `active_users`, `skipped` and `stale`;
- `sessions`: the last successful list (empty if none);
- `history`: up to 500 rows within 365 days, newest last-seen first, each with `id`, `session` (the fields above), `first_seen_at`, `last_seen_at` and `ended_at` (`null` while still reported);
- `history_limit` (500) and `history_days` (365).

The device detail `GET /api/v1/devices/{id}` includes the same `info` summary as `sessions`. `GET /api/v1/devices` includes `signed_in_users` per device, using the Devices-list rule above. Storage errors return HTTP 503. GET requests never trigger collection.

Access uses the device `read` scope, the same as software inventory: the administrator and every technician whose device or group scope includes the device. There is no separate permission.

## Turning it off

The feature is on by default. Switch off **Signed-in users** (key `sessions`) in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy), or lock it off on one device from an administrator PowerShell in the repository root:

```powershell
.\scripts\service.ps1 -Action configure -SessionsMode false
.\scripts\service.ps1 -Action configure -SessionsMode true   # removes the lock
```

This sets or removes the DWORD `sessions` = `0` under `HKLM\SOFTWARE\Policies\OpenRMM\Agent` (also settable by Group Policy). A lock survives MSI installs and self-updates, and a policy cannot override it; see [feature switches](WINDOWS-SERVICE.md#feature-switches). A console agent uses `-sessions=false` or `OPENRMM_AGENT_SESSIONS=false`, which also counts as a lock.

> [!NOTE]
> The same switch also stops the [logon history](LOGONS.md) collection.

When the feature is off, the agent reports **Disabled**. The last list stays (stale), the Devices column is empty, and history is kept unchanged until it ages out; switching the feature off does not delete collected data.

## Privacy

Usernames, domains, client computer names and client IP addresses are personal data.

- They are visible to the administrator and to every technician who can read the device, kept for up to 365 days, and included in backups.
- The administrator can switch the feature off per monitoring policy, and a local administrator can lock it off on a device.
- There is no action to delete history early other than removing the device.

## Upgrading

The tables are added by a schema migration; take a matched backup before upgrading, as for other migrations (see [RECOVERY.md](RECOVERY.md)). Upgrade the server before agents: an older server refuses the `sessions` report, and the agent logs a warning and tries again with a fresh collection.

An agent that predates the `sessions` key would reject a policy feature list containing it. Current agents therefore list the switchable features they understand in each heartbeat, and the server sends each agent only the switches it understands; an agent that lists none receives only the original 14 features. Switching **Signed-in users** off never affects an older agent's other switches.

## Troubleshooting

- **Not reported:** the agent does not support signed-in users yet, or has not reported yet.
- **Disabled on device:** the feature is off in the policy or locked locally; the Overview **Agent features** panel shows which.
- **Collection failed:** Windows session enumeration failed, the five-second deadline passed, or the report was invalid. Check `%ProgramData%\OpenRMM Agent\logs\agent.log`.
- **Idle Unknown** on the console and **Signed in Unknown** are expected when Windows does not provide those times.
- **Users tab shows a user, the Devices list does not:** the list shows only `active` sessions from a report at most five minutes old on online devices.
- **Still signed in on an offline device:** history changes only with a successful report; see above.
- **Skipped count shown:** sessions were left out (invalid details, a repeated ID or more than 64).

## Related

- [LOGONS.md](LOGONS.md)
- [LOCAL-ACCOUNTS.md](LOCAL-ACCOUNTS.md)
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md)
- [ORGANIZATION.md](ORGANIZATION.md)
