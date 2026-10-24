# Device Workspace

The device workspace is the console you open by selecting a device in **Devices**. It brings together the device's live readings, collected inventory and the tools an account is allowed to use; this page is for administrators and technicians who work with individual devices.

## Overview

The console has a header, a row of tool buttons and a set of tabs. Tabs and buttons reflect the signed-in account's permissions. Opening a tab never starts an operation on the device; every action still goes through its own review, confirmation, CSRF (`X-CSRF-Token`) and dispatch checks.

### Tabs

| Tab | Content | Who sees it |
| --- | --- | --- |
| **Overview** | CPU, memory, system disk and uptime meters; device facts; active alerts; recent activity; agent features; agent capabilities. | Everyone who can open the device |
| **System** | Hardware, operating system, network adapters and security status. See [DEVICE-INFO.md](DEVICE-INFO.md) and [SECURITY-STATUS.md](SECURITY-STATUS.md). | Everyone who can open the device |
| **Users** | **Signed in**, **History**, **Logons**, **Local accounts** and **Groups** views. See [SESSIONS.md](SESSIONS.md), [LOGONS.md](LOGONS.md) and [LOCAL-ACCOUNTS.md](LOCAL-ACCOUNTS.md). | Everyone who can open the device |
| **Processes** | See [PROCESSES.md](PROCESSES.md). | Everyone who can open the device |
| **Services** | See [SERVICE-MANAGEMENT.md](SERVICE-MANAGEMENT.md). | Everyone who can open the device |
| **Event logs** | See [EVENT-LOGS.md](EVENT-LOGS.md). | Everyone who can open the device |
| **Software** | **Installed**, **Changes** and **App deployments** views. See [SOFTWARE.md](SOFTWARE.md). | Everyone who can open the device |
| **Files** | See [FILES.md](FILES.md). | Accounts with the files permission |
| **Scripts** | See [SCRIPTS.md](SCRIPTS.md). | Administrator only |
| **Metrics** | Historical CPU, memory and disk charts. See [METRICS.md](METRICS.md). | Everyone who can open the device |
| **Windows Update** | See [WINDOWS-UPDATES.md](WINDOWS-UPDATES.md). | Administrator only |

Whether an operation inside a tab is allowed (for example stopping a service) depends on the account's operation permissions; see [TECHNICIANS.md](TECHNICIANS.md).

### Header and tools

| Control | Purpose | Who sees it |
| --- | --- | --- |
| **Live response** | PowerShell as SYSTEM with built-in response commands, optionally recorded to a case. Enabled only while the device is online. See [TERMINAL.md](TERMINAL.md) and [RESPONSE.md](RESPONSE.md). | Administrator and accounts with the response permission |
| **Remote desktop** | View or control the signed-in user's screen. Enabled only while the device is online. See [DESKTOP.md](DESKTOP.md). | Accounts with the desktop permission |
| **Files** | Opens the **Files** tab. | Accounts with the files permission |
| **Run script** | Opens the **Scripts** tab ready to run a script. | Administrator only |
| **Install app** | Deploys an application to a Windows device. See [APPLICATIONS.md](APPLICATIONS.md). | Administrator only |
| **More → Isolate from network…** | See [ISOLATION.md](ISOLATION.md). | Administrator and accounts with the response permission |
| **More → Group, policy and tags…** | See [ORGANIZATION.md](ORGANIZATION.md). | Administrator only |
| **More → Revoke device…** | Revokes the device's credentials. See [ENROLLMENT.md](ENROLLMENT.md). | Administrator only |

## The Overview tab

- **Meters:** **CPU** (with the time of the sample), **Memory** (used of total), **System disk** (free of total, with **Low space** when below 10% free) and **Uptime** (with the estimated boot time). Each meter shows **Stale**, **Collection failed**, **Disabled on device**, **Not supported** or **Not reported** when the reading is not current. See [CPU.md](CPU.md), [MEMORY.md](MEMORY.md), [DISK-SPACE.md](DISK-SPACE.md) and [UPTIME.md](UPTIME.md).
- **Device:** operating system, architecture, agent version, group, tags, enrollment time, last contact and device ID.
- **Active alerts:** the device's open alerts. See [ALERTS.md](ALERTS.md).
- **Recent activity:** the newest recorded operations; see [Recent activity](#recent-activity).
- **Agent features:** each agent feature as **On**, **Off by policy** (switched off in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy)) or **Locked off on device** (a local administrator's lock, which a policy cannot override). A feature that is off is reported as disabled and its tools show as unavailable.
- **Agent capabilities:** one line per collected area: **Hardware**, **IP address**, **Signed-in users**, **Local accounts**, **Software inventory**, **Services**, **Event logs** and **Windows Update**.

## Live updates

The console requests `GET /api/v1/devices/{id}` every ten seconds, and each tab polls its own read endpoint (for example every 30 seconds for **Users** and **Software**, every 60 seconds for **Local accounts**, **Logons** and **Metrics**).

- New data replaces displayed rows without discarding search fields, selections or forms being edited.
- A failed refresh keeps the most recent data visible and marks the view as having a connection problem.
- Hidden pages suspend polling and resume when visible.
- Offline or revoked devices show stale readings, and tools that need an online device are disabled.
- An expired session, lost device scope or removed device clears the workspace and stops polling.

Background refresh is GET-only and never replays actions. Authorization is rechecked on every server request; clearing the page in the browser is not an access-control boundary. Live desktop and terminal sessions run on their own full-screen pages with their own session controls.

## Tool availability

Availability combines three things: the account's permission, the capability the agent last reported, and the device's feature settings. The agent enables services, processes, files, scripts, terminal and Windows Update installation and restart by default; remote desktop also requires the desktop companion that the agent MSI installs for signed-in users (see [DESKTOP.md](DESKTOP.md)). A recent capability report does not guarantee an operation will succeed: dispatch rechecks the authoritative state.

## Recent activity

The **Recent activity** panel lists recorded operations with their kind (service action, process action, app deployment, agent update, event log query, file transfer, Windows Update or script run), status and time. It never includes paths, script arguments or output, certificates or raw result JSON.

- Event log query metadata requires the event log permission, and file job metadata requires the files permission.
- Script and Windows Update metadata are visible to the administrator only.
- Script runs that belong to an application deployment are counted once through their deployment.
- Live desktop and terminal sessions are not listed here; they have their own session displays.

The server merges up to ten recent records from each permitted category and returns at most twenty; the Overview shows the newest eight. The **pending** badge counts retained records in the `staged`, `queued`, `dispatched` and `running` states, independently of the display limit.

| Status | Meaning |
| --- | --- |
| Staged | Awaiting review; explicit confirmation is required. |
| Queued | Waiting for the agent; the request can expire. |
| Dispatched | Sent to the agent; completion has not been confirmed. |
| Running | Last reported running; no confirmed completion yet. |
| Succeeded / Completed | Reported success; inspect the feature result and any restart requirement. |
| Failed / Timed out | Review the result before requesting another action. |
| Unknown / Interrupted | The outcome is uncertain; inspect before retrying. |
| Expired / Cancelled | Review history; cancellation cannot undo work the agent already accepted. |

The panel is a read-only view of stored states: reading it never dispatches, expires, cancels or retries a job. Each feature's own history remains the source for full outcomes. The `activity` field of `GET /api/v1/devices/{id}` applies the current technician device and group scope and is not cacheable.

## Devices list

The **Devices** list (`/devices`) refreshes every ten seconds and has these columns:

| Column | Content |
| --- | --- |
| **Device** | Hostname and device ID prefix. |
| **Status** | Online, Offline, Awaiting contact or Revoked, plus an isolation badge when applicable. See [HEARTBEATS.md](HEARTBEATS.md). |
| **Signed-in user** | Users of active sessions on online devices; the first user and `+N`, with all users on hover. See [SESSIONS.md](SESSIONS.md). |
| **IP address** | The primary IPv4 address from the last device information snapshot, kept while the device is offline. See [DEVICE-INFO.md](DEVICE-INFO.md#primary-ipv4-address). |
| **Alerts** | Active and critical alert counts. |
| **System disk** | **Low**, **OK** or **Unknown**. See [DISK-SPACE.md](DISK-SPACE.md). |
| **BitLocker**, **Defender** | Security summaries. See [SECURITY-STATUS.md](SECURITY-STATUS.md). |
| **Group** | Group and up to three tags. |
| **Platform**, **Agent**, **Last seen** | OS and architecture, agent version, and last contact (exact time on hover). |

Filters:

- The filter box matches the hostname, device ID prefix, group, tags, signed-in users, agent version, any reported IP address, MAC address (with colons, dashes or no separators) and serial number.
- Status buttons: All, Online, Offline, Awaiting, Revoked and Isolated.
- A group selector (including **Ungrouped**) and a security selector (**BitLocker off or suspended**, **Defender off or real-time off**).
- A low-disk filter, reached from the dashboard's **Low disk space** count.

The administrator can select devices and use **Organize** to change group, policy and tags for up to 100 devices at once.

**Export CSV** downloads `GET /api/v1/reports/devices.csv` with every device in the list that the account can see, without the on-screen filters. See [device CSV](DEVICE-INFO.md#device-csv).

## Security notes

- Rendered text from devices is escaped, and links are built from fixed local routes.
- Authorization is enforced by the server on every request, not by hiding tabs or buttons.
- Recent activity never exposes paths, arguments, output or certificates.

## Related

- [DEVICE-INFO.md](DEVICE-INFO.md)
- [HEARTBEATS.md](HEARTBEATS.md)
- [TECHNICIANS.md](TECHNICIANS.md)
- [ORGANIZATION.md](ORGANIZATION.md)
- [ALERTS.md](ALERTS.md)
