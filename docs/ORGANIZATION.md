# Groups, Tags and Monitoring Policies

Groups and tags organize devices, and monitoring policies decide which alert rules and agent features apply to them. This page is for the primary administrator, who manages organization from **Groups & policies**.

## Contents

- [Overview](#overview)
- [Organizing devices](#organizing-devices)
- [Monitoring policies](#monitoring-policies)
- [Agent features per policy](#agent-features-per-policy)
- [Review and apply](#review-and-apply)
- [Deleting groups and policies](#deleting-groups-and-policies)
- [Limits](#limits)
- [Permissions, audit and API](#permissions-audit-and-api)
- [Upgrades and backups](#upgrades-and-backups)
- [Related](#related)

## Overview

Open **Administration → Groups & policies** (`/organization`). Groups and monitoring policies are listed on one page; selecting one opens its editor.

- A **group** is a manual, flat set of devices. A device belongs to at most one group.
- **Tags** are free labels for filtering. They never assign policies.
- A **monitoring policy** is a complete bundle of alert rules, agent feature switches and the addresses reachable while isolated ([ISOLATION.md](ISOLATION.md)). It can be assigned to a group or directly to a device.

All changes use the primary administrator's existing sign-in and MFA session, and every change is reviewed before it is applied.

## Organizing devices

### Groups

Create a group with a stable ID and a display name.

- IDs are lowercase, start with a letter, and may contain letters, digits, hyphens and underscores, up to 32 characters. `new` and `ungrouped` are reserved.
- Display names are up to 80 characters.
- Groups cannot be nested, and there is no automatic membership.

### One device

In the device console choose **More → Group, policy and tags…**. Select a group (or leave the device ungrouped), optionally assign a device policy, and enter comma-separated tags such as `windows, production, branch-office`.

### Many devices

Select devices on the **Devices** list and choose **Organize**. In one reviewed change, for up to 100 devices, you can:

- set or clear the group;
- set or clear the device policy;
- add or remove tags.

Fields left as **Leave unchanged** keep each device's current value.

### Tags

- Lowercase, unique per device and sorted.
- Up to 16 tags per device, each up to 32 characters.
- Must start with a letter or digit; dots, hyphens and underscores are also allowed.

### Filtering

On **Devices**, filter by group, or type a tag (or part of one) in the filter box. Filters are kept in the page address across refreshes.

## Monitoring policies

A new policy starts as a copy of the current global alert defaults and contains all four rules: offline, system disk space, CPU and physical RAM. For each rule you can edit the enabled state, threshold, trigger and recovery durations, severity and email. A saved policy does not follow later changes to the global defaults.

### Which policy applies

Each device uses exactly one complete bundle, chosen in this order:

1. The device's own policy override, if assigned.
2. Its group's policy, if assigned.
3. The global defaults from **Alert settings**.

There is no field-by-field merging and no competing group precedence. Clearing a device override returns the device to its group's policy; clearing a group's policy returns its inheriting members to the global defaults. The device list and device detail APIs report the selected source as `policy_source`.

### What alert rules do not do

Alert rules evaluate telemetry that is already collected. They do not change reporting intervals, modify Windows services, grant permissions, run scripts or approve updates and restarts. Missing or disabled telemetry stays Unknown. Email additionally needs a mail server configured as described in [alerts](ALERTS.md), and email must not be paused. The fixed 10% disk warning on the dashboard is independent of policy thresholds.

## Agent features per policy

A monitoring policy also decides which agent features are on. The policy editor's **Agent features** section has a switch for each of the 17 features:

| Feature | Covers |
| --- | --- |
| Inventory | Hostname, Windows version, agent version and [device information](DEVICE-INFO.md) (hardware, OS details, domain/Entra ID join, network adapters) |
| CPU | CPU usage |
| Memory | RAM usage |
| Disk space | System-drive space |
| Uptime | Uptime and last boot |
| Software inventory | Installed applications |
| Signed-in users | [Signed-in sessions](SESSIONS.md) and history |
| Local accounts | [Local accounts](LOCAL-ACCOUNTS.md) and group members |
| Services | [Service listing and control](SERVICE-MANAGEMENT.md) |
| Processes | [Process listing and termination](PROCESSES.md) |
| Event logs | [Event log queries](EVENT-LOGS.md) |
| Windows Update | [Scan, install and restart](WINDOWS-UPDATES.md) |
| Scripts | [PowerShell scripts](SCRIPTS.md) and [application deployment](APPLICATIONS.md) |
| Terminal | [Interactive PowerShell](TERMINAL.md) |
| Files | [File browsing and transfer](FILES.md) |
| Incident response | [Evidence collection](RESPONSE.md) for cases |
| Remote desktop | [Remote desktop](DESKTOP.md) |

Everything is on by default. A new policy starts with every switch on, and only switched-off features are stored. The effective setting follows the same selection as alert rules: device policy, else group policy, else global defaults (which keep every feature on).

If a policy's stored settings cannot be read (a damaged database record), the policy fails closed: its devices get the global alert rules, an empty isolation allow list and **every feature switched off**, so a lost "off" never turns a feature such as remote desktop back on. The **Organization** page marks the policy as damaged. Open it, check its settings and save it to repair it.

### How the agent applies switches

- The server returns the device's switched-off features in every heartbeat reply. Each agent lists the features it understands in its heartbeat and receives only those switches; an older agent that sends no list receives only the switches it knows.
- The agent saves the settings in `feature-settings.json` in its state folder and, when they change, restarts its work with the new settings within one heartbeat. The service process and device identity stay; after a restart the agent starts with the last saved settings.
- Restarting the work interrupts anything running on that device, such as a terminal or remote desktop session or an evidence upload, even when the change concerns a different feature. An interrupted evidence upload resumes about three minutes later if **Incident response** is still on.
- A switched-off feature stops on the device. The agent reports it as disabled and availability checks refuse work for it (for example, scripts show as unavailable). Data collected earlier is kept and marked stale.

### Local locks

A local administrator can lock a feature off on one device (registry values under `HKLM\SOFTWARE\Policies\OpenRMM\Agent`, also settable by Group Policy). A local lock always wins: a policy cannot turn a locked feature back on. The agent reports its locks in each heartbeat. See the feature switches section of [Windows agent service](WINDOWS-SERVICE.md).

The device console's **Overview** has an **Agent features** panel that shows each feature as **On**, **Off by policy** or **Locked off on device**.

## Review and apply

Every change, including a group's policy assignment, is previewed first:

1. **Review** validates the change without saving anything. It lists the new values, every monitored device and rule whose effective settings change, and for each device the agent features switched on or off.
2. **Apply** quotes the review's digest and revalidates the configuration and fleet snapshot in one transaction. A configuration change, enrollment, revocation or changed device metadata in between requires a new review. Replayed or outdated applications fail instead of overwriting another edit.

Effect on alerts:

- Only device/rule pairs whose effective rule actually changes restart qualification. For those pairs, active incidents close as `policy_changed`, pending readings and qualification are discarded, and queued emails are cancelled. No recovery is assumed or emailed. An email already handed to the sender may still reach the relay.
- Equal rule values keep incidents and qualification, even if the policy source changes.
- Tag and display-name changes do not restart rules. Global rule edits reset only devices that inherit the changed defaults.
- Changing only agent features restarts no alert rule; affected agents apply the new features within a heartbeat.
- Email delivery checks the device's effective policy, including its enabled and email settings.

## Deleting groups and policies

- **Group:** first move all active members out and remove the group from any technician account grants.
- **Policy:** first remove it from every group and every active device override.

References from revoked devices may be cleared during deletion; those devices stay revoked.

## Limits

| Item | Limit |
| --- | --- |
| Groups | 100 |
| Monitoring policies | 100 |
| Devices per bulk change | 100 |
| Tags per device | 16, each up to 32 characters |
| Organized and monitored fleet | Newest 1,000 active devices |

The device list puts active devices first, so revoked records cannot push active devices out of the monitored fleet. Membership totals include all active members, including any beyond the monitored capacity.

## Permissions, audit and API

- Organization is managed only by the primary administrator. Agent certificates cannot administer organization, and agent payloads cannot change membership, tags or policy assignment.
- Committed changes record the administrator, action, target ID, outcome and time in the bounded audit log. If the audit write fails, the configuration and incident changes are rolled back. There is no separate version history for policies.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/organization` | Revision, groups, policies (including switched-off `features`), active device metadata and global defaults. Primary administrator only. |
| `GET /api/v1/devices` | Visible devices with group, tags and `policy_source`. |
| `GET /api/v1/alert-settings` | Global default rules. Primary administrator only. |
| `POST /api/v1/organization/review` | Validate a change and return its digest. |
| `POST /api/v1/organization/apply` | Apply a reviewed change; must quote the digest. |

Write requests are JSON and need the session's `X-CSRF-Token` header. Feature settings reach the agent in the existing heartbeat reply (`disabled`), and the agent reports local locks in its heartbeat (`locked`). The device detail API returns `disabled_features` and `locked_features`.

## Upgrades and backups

An existing deployment without organization data starts with every device ungrouped, no policies, and its existing global rules. Back up before upgrading the server: an older server refuses a newer database schema, so a rollback needs the matching pre-upgrade backup and server image. See [backup and recovery](RECOVERY.md).

Automatic tag rules, nested or multiple groups per device, and policy-based script schedules are not part of this feature; [patch policies](PATCH-POLICIES.md) are configured separately. See [ROADMAP.md](../ROADMAP.md) for planned work.

## Related

- [Device alerts](ALERTS.md)
- [Windows agent service](WINDOWS-SERVICE.md)
- [Technician accounts](TECHNICIANS.md)
- [Backup and recovery](RECOVERY.md)
