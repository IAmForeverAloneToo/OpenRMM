# Local Accounts and Privileged Groups

The agent reports each Windows device's local user accounts and the direct members of the **Administrators** and **Remote Desktop Users** groups. Administrators and technicians use it to review who can sign in to a device and who has administrative or remote access.

## Contents

- [Overview](#overview)
- [What is collected](#what-is-collected)
- [Schedule and states](#schedule-and-states)
- [Using it in the dashboard](#using-it-in-the-dashboard)
- [Limits and validation](#limits-and-validation)
- [Storage](#storage)
- [API and permissions](#api-and-permissions)
- [Turning it off](#turning-it-off)
- [Privacy](#privacy)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## Overview

Open a device's **Users** tab and choose **Local accounts** or **Groups**. The device **Overview** shows a **Local accounts** line with the counts.

This is a snapshot of what Windows reports on the device, taken every 15 minutes. It is not an account audit: the server keeps only the newest snapshot and no history of changes. For sign-in events see [LOGONS.md](LOGONS.md).

## What is collected

The `local_accounts` v1 module runs inside the agent (LocalSystem) and uses the Windows NetAPI (`netapi32.dll`). It starts no process and writes nothing to the device.

### Accounts

`NetUserEnum` at level 3, normal accounts only (`FILTER_NORMAL_ACCOUNT`). The SID of each account is looked up by name.

| Field (API) | Meaning |
| --- | --- |
| `name` | Account name. |
| `full_name` | Full name; empty when not set. |
| `sid` | Account SID, for example `S-1-5-21-…-1001`. |
| `enabled` | `false` when the account is disabled. |
| `locked_out` | Windows marks the account as locked out. |
| `password_last_set_at` | When the password was last set, Unix seconds, computed by the agent as its own clock minus the password age Windows reports. `0` when Windows reports an age of zero (shown as **Unknown**). |
| `password_never_expires` | The account's "password never expires" flag. |
| `password_expired` | Windows reports the password as expired. |
| `last_logon_at` | Last logon, Unix seconds; `0` means never or unknown (shown as **Never or unknown**). Windows maintains it on this machine only, so network and cached logons can be missing. |

### Groups

The two groups are found by their well-known SIDs, Administrators `S-1-5-32-544` and Remote Desktop Users `S-1-5-32-555`, so localized group names work. Members are read with `NetLocalGroupGetMembers` at level 2. Only direct members are listed; nested groups are not expanded.

| Field (API) | Meaning |
| --- | --- |
| `key` | `administrators` or `remote_desktop_users`. |
| `name` | The group's name on this device (localized); empty when Windows cannot resolve the group. |
| `members[].name` | Member as `DOMAIN\name`; empty when Windows does not resolve it (shown as **Unresolved**). |
| `members[].sid` | Member SID. |
| `members[].kind` | `user`, `group` (including local groups), `well_known` (shown as **Built-in**, for example `NT AUTHORITY\…` groups), `computer`, `deleted` (shown as **Deleted account**) or `other`. |

When Remote Desktop Users does not exist (some Windows editions), it is reported with no name and no members, and the dashboard shows **This group does not exist on the device**. Any other failure to read a group, including Administrators, fails the whole report (**Collection failed**) instead of showing an empty group.

## Schedule and states

- The agent collects at startup and every 15 minutes, with the shared five-second collection deadline. Linux agents report **Not supported**.
- A report is collected, failed, disabled or unsupported. A failed, disabled or unsupported report keeps the last successful snapshot, which is then marked stale.
- The view refreshes every 60 seconds and shows the time of the last successful snapshot. It is marked **Stale** when the snapshot is 30 minutes old or more (one missed report is allowed), when the latest report was not successful, or when the device is not online.

## Using it in the dashboard

**Users** tab (`?tab=users&view=accounts` for Local accounts, `&view=groups` for Groups):

- **Local accounts:** Account (name, with the full name below), State (**Enabled** or **Disabled**, and **Locked out**), Privileged groups (**Administrators** and **Remote Desktop Users** badges, matched by SID, so only direct membership counts), Password set (relative time with the absolute time on hover, and **Never expires** and **Expired** badges), Last logon and SID. The filter matches account and full names. Empty states read **No local accounts** (a successful empty list) or **No local accounts reported**.
- **Groups:** for each group its name (the localized name in brackets when it differs), member count and skipped count, then Member, Type and SID.
- The toolbar shows the collection state (**Stale**, **Collection failed**, **Disabled on device**, **Not supported**, **Not reported**) and the skipped count.

**Overview → Agent capabilities → Local accounts** shows `N accounts (N enabled) · N in Administrators · N in Remote Desktop Users` from the last snapshot, with **Stale** when it is stale; without a current report it shows the collection state. The group counts include every direct member, not only local accounts.

## Limits and validation

| Limit | Value |
| --- | --- |
| Accounts reported | 512 |
| Members reported per group | 256 |
| Accounts read before stopping | 2,048 |
| Members read per group before stopping | 1,024 |
| Report size | 512 KiB |

- The agent drops entries with invalid details (for example an account whose SID lookup failed) or a repeated SID, orders accounts by name (case-insensitive) and members by SID, and keeps the first 512 accounts and 256 members per group.
- Everything left out is counted as `skipped`: per report for accounts (shown next to the list) and per group for members (shown next to the group).
- Text values longer than 512 bytes are treated as empty; leading and trailing spaces are removed.

The server decodes reports strictly:

- Every field is required except the `skipped` counts; unknown fields are rejected, and an invalid report is refused as a whole.
- A report must contain both groups, in the order above.
- Account names are required and at most 256 bytes; full names and group names at most 256 bytes; member names at most 512 bytes. Text must be valid UTF-8 without control characters or leading/trailing spaces.
- SIDs must have the form `S-1-` followed by digits separated by `-` (at most 184 characters). Account SIDs must be distinct, and member SIDs distinct within a group.
- Times must not be negative.
- A report for a capability version other than 1 is stored as unsupported.

Account names, full names and member names come from the device and are untrusted text; the dashboard escapes them.

## Storage

The server keeps one row per device: the newest report's status and receipt time, and the last successful snapshot.

- A successful report replaces the snapshot; a failed, disabled or unsupported report keeps it.
- A report received earlier (by server time) than the stored one is ignored.
- There is no history, so changes between snapshots (an account added and removed again, a member added for a few minutes) are not seen.
- Removing a device removes its row. Logical deletion does not securely erase SQLite pages, the WAL or backups.

## API and permissions

`GET /api/v1/devices/{id}/local-accounts` takes no filters and returns:

- `info`: `capability`, `status` (`ok`, `failed`, `disabled`, `unsupported` or `not_reported`), `reported_at`, `snapshot_at`, `has_snapshot`, `accounts`, `enabled`, `administrators`, `remote_desktop_users` and `stale`;
- `accounts` and `groups`: the last successful snapshot (empty lists if none); a group's `skipped` is omitted when zero;
- `skipped`: accounts left out.

The device detail `GET /api/v1/devices/{id}` includes the same `info` summary as `local_accounts`. The Devices list does not include local accounts. Storage errors return HTTP 503. GET requests never trigger collection.

Access uses the device `read` scope, the same as software inventory and signed-in users: the administrator and every technician whose device or group scope includes the device. There is no separate permission.

## Turning it off

The feature is on by default. Switch off **Local accounts** (key `local_accounts`) in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy), or lock it off on one device from an administrator PowerShell in the repository root:

```powershell
.\scripts\service.ps1 -Action configure -LocalAccountsMode false
.\scripts\service.ps1 -Action configure -LocalAccountsMode true   # removes the lock
```

This sets or removes the DWORD `local_accounts` = `0` under `HKLM\SOFTWARE\Policies\OpenRMM\Agent` (also settable by Group Policy). A lock survives MSI installs and self-updates, and a policy cannot override it; see [feature switches](WINDOWS-SERVICE.md#feature-switches). A console agent uses `-local-accounts=false` or `OPENRMM_AGENT_LOCAL_ACCOUNTS=false`, which also counts as a lock.

When the feature is off, the agent reports **Disabled**. The last snapshot stays (stale); switching the feature off does not delete collected data.

## Privacy

Account names, full names, SIDs, and logon and password times are personal data.

- They are visible to the administrator and to every technician who can read the device, and included in backups.
- Only the newest snapshot is kept.
- The administrator can switch the feature off per monitoring policy, and a local administrator can lock it off on a device.
- There is no action to delete the snapshot other than removing the device.

## Upgrading

The table is added by a schema migration; take a matched backup before upgrading, as for other migrations (see [RECOVERY.md](RECOVERY.md)). Upgrade the server before agents: an older server refuses the `local_accounts` report, and the agent logs a warning and collects again at the next interval.

Agents list the switchable features they understand in each heartbeat, and the server sends each agent only the switches it understands (an agent that lists none receives only the original 14 features). An older agent that does not know the `local_accounts` key is therefore unaffected when **Local accounts** is switched off.

## Troubleshooting

- **Not reported:** the agent does not support local accounts yet, or has not reported yet.
- **Disabled on device:** the feature is off in the policy or locked locally; the Overview **Agent features** panel shows which.
- **Collection failed:** account or group enumeration failed, the five-second deadline passed, or the report was invalid. Check `%ProgramData%\OpenRMM Agent\logs\agent.log`.
- **Last logon Never or unknown** for an account that is in use: Windows records only logons on this machine; see above.
- **Password set Unknown:** Windows reported a password age of zero, which the agent reports as `0` rather than guessing.
- **Unresolved member:** Windows returned no name for the SID (for example, possibly a domain member while the domain controller is unreachable).
- **An account is an administrator but has no Administrators badge:** it is a member through a nested group (for example a domain group); only direct members are listed.
- **Skipped count shown:** entries were left out (invalid details such as a failed SID lookup, a repeated SID, or more than the limit).

## Related

- [SESSIONS.md](SESSIONS.md)
- [LOGONS.md](LOGONS.md)
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md)
- [ORGANIZATION.md](ORGANIZATION.md)
