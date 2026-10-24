# Software Inventory

The agent reports the applications registered in each Windows device's uninstall registry, and the server records observed changes. Administrators and technicians use it to see what is installed on one device and to search the whole fleet for an application.

## Contents

- [Using it on a device](#using-it-on-a-device)
- [Fleet search](#fleet-search)
- [What is collected](#what-is-collected)
- [Freshness and change history](#freshness-and-change-history)
- [Limits](#limits)
- [Retention and backups](#retention-and-backups)
- [Permissions](#permissions)
- [Configuration](#configuration)
- [Related](#related)

## Using it on a device

Open a device's **Software** tab and choose a view:

- **Installed:** the current list with name, version, publisher and **Installed for** (machine-wide, or the user a per-user install belongs to). The filter matches name, version, publisher and user.
- **Changes:** observed changes, labelled **Installed**, **Removed**, **Version changed** or **Details changed** (API values `added`, `removed`, `version_changed`, `metadata_changed`).
- **App deployments:** see [APPLICATIONS.md](APPLICATIONS.md).

The tab refreshes every 30 seconds. The device **Overview** shows the application count under **Agent capabilities → Software inventory**.

`GET /api/v1/devices/{id}/software` returns the current entries plus the newest 200 observed changes from the last 30 days (`history_limit`, `history_days`). It accepts no filters; the console filters in the browser. The device detail API includes a small `software` status and count summary.

## Fleet search

Open **Reports → Software inventory** (`/reports/software`), enter an application name, version or publisher (at least one), optionally choose a group, and press **Search**. The page searches only when **Search** is pressed; GET requests never contact agents or trigger collection.

- The application field matches name, version or publisher as a substring; **Version contains** and **Publisher contains** narrow it further. Filters combine with AND and are case-insensitive (Go's Unicode lowercase conversion).
- Search terms are literal text, including `%`, `_` and quotes. There is no wildcard syntax, regular expression, version ordering or vulnerability judgment.
- Device links open that device's **Software** tab; the fleet search terms are not carried over.

Each device in scope gets one result:

| Result (API value) | Meaning |
| --- | --- |
| Installed (`current`) | At least one matching registration in the current inventory. |
| Installed (stale) (`retained`) | An older successful list contains a match; current presence is unconfirmed. |
| Not installed (`without`) | A current successful list has no registration matching all filters. |
| Unknown (`unknown`) | No successful list, or a stale list without a match. |

- Current inventory requires an online device, a successful latest collection and a successful snapshot less than 30 minutes old; future timestamps are stale. Failed, disabled, unsupported, restored or offline inventory can never establish absence.
- An empty successful list is evidence of absence only within the [stated coverage](#what-is-collected).
- Duplicate registrations remain separate; counts do not claim distinct products or licences.
- Rows contain matching and total registration counts, status, receipt time and at most five examples. Follow the device link for the full list and change history.

### Fleet API

`GET /api/v1/reports/software` returns every device in scope (at most 1,000) with its result. Accepted query keys:

| Key | Content |
| --- | --- |
| `q` | Name, version or publisher substring (at most 200 bytes). |
| `version`, `publisher` | Additional substrings (at most 256 and 512 bytes). |
| `group` | A group ID, or `ungrouped`. |
| `tag` | One canonical tag (input is lowercased). |
| `result` | Empty for all, or `current`, `retained`, `without`, `unknown`. |

Repeated or unknown keys and malformed filters are rejected.

`GET /api/v1/reports/software.csv` (same keys) exports the device summaries: search context, evaluation time, result, collection status, stale flag, last success, coverage, counts and at most five examples encoded as JSON in one cell. It is a bounded summary, not a full registration dump. Cells that could be read as spreadsheet formulas are prefixed with an apostrophe. Responses are marked no-store; an export and a page view are separate observations.

### Fleet search limits

- Each report scans at most 1,000 authorized active devices and 64 MiB of stored snapshot JSON, with a five-second database deadline.
- Over-limit reports return HTTP 422 asking for a narrower group or tag; a timeout or corrupt data returns HTTP 503. No partial report or inaccurate absence result is returned.
- Application and result filters reduce matching rows but not the scan budget; use a group or tag for that.

## What is collected

The `software` module (capability version 2) collects at agent startup and then every 15 minutes as LocalSystem. It writes nothing and starts no installer or shell.

- **Machine-wide:** the fixed machine-wide uninstall key in both the 64-bit and 32-bit registry views, using explicit view flags rather than addressing `Wow6432Node` directly.
- **Per-user:** the uninstall key of every **loaded** user hive under `HKEY_USERS`. A hive is loaded while its user is signed in (or a process runs as that user). Only local, domain (`S-1-5-21-…`) and Microsoft Entra ID (`S-1-12-1-…`) users are read, at most 64 per report. Per-user entries have registry view `user`, the user's `DOMAIN\name` and SID.
- The report lists the user hives it read (`users`) and counts per-user registrations and hives left out (`user_skipped`) separately from machine-wide ones (`skipped`).
- Version 1 reports from older agents (machine-wide only) are still accepted.

Each entry contains the display name, version, publisher, an opaque registration ID and the registry view. Entries without a display name and hidden `SystemComponent=1` entries are excluded.

> [!NOTE]
> Not covered: per-user installs of users who are not signed in, Store/MSIX packages, portable applications and unregistered software. A 32-bit registry view is not proof of an application's architecture, and a registration is not proof that an application is present, safe, licensed or working. Names and versions are installer-supplied, untrusted text; the dashboard escapes them.

## Freshness and change history

- The first complete successful list establishes a baseline and records no installation events.
- Later successful lists update the snapshot and record additions, disappearances, version changes and other metadata changes in one transaction. Entries are matched by registry view and key identity, not just name, so an installer that replaces its registration key may appear as a removal plus a new registration.
- Per-user entries are compared only when that user's hive was read in both reports: a user signing out and back in records no change, and upgrading an agent to version 2 records no per-user "installed" entries. A changed account name is not a change.
- No upgrade or downgrade judgment is inferred from vendor version strings.
- Each change records the previous and current successful receipt times. They bound when the difference was observed, not when the installation or removal happened; changes between samples can be missed, and registry enumeration is not atomic with concurrent installers.
- Repeated identical reports do not create duplicate changes.

Failed, disabled, unsupported or oversized reports keep the last successful list and never invent removals. The list becomes stale after 30 minutes, immediately after an unsuccessful report, or while the device is offline or revoked. An empty successful list is distinct from a failure or a missing report.

## Limits

| Limit | Value |
| --- | --- |
| Report size | 1 MiB |
| Registrations per report | 2,048 |
| Subkeys enumerated per registry view | 4,096 |
| Value read buffer | 2 KiB |
| Name and publisher | 512 UTF-8 bytes |
| Version | 256 UTF-8 bytes |
| Signed-in user hives per report | 64 |
| Collection deadline | 30 seconds (account names are resolved, which can be slow) |

- A registration with an invalid type or encoding, control characters, over-long text or denied access is skipped and counted. Registrations beyond the count or size limits are kept in ID order and the rest counted. The skipped counts are shown next to the list.
- Keys that disappear during collection are ignored. A failure to open the uninstall key itself, or the deadline, fails the collection.
- When a skipped count rises or falls between snapshots, ambiguous removals or additions are not recorded as history. The per-user skip count gates only per-user changes, so an unreadable user registration never hides a machine-wide change.

## Retention and backups

- History keeps at most 200 changes per device, 5,000 overall, and 30 days. It is not an archival software audit.
- Cleanup runs every minute and on each report; reads hide expired rows immediately.
- A stale snapshot can remain until a new successful report or the device is removed. Logical deletion does not securely erase SQLite pages, the WAL or backups.
- Restoring a backup clears the software change history, marks retained lists stale and resets the comparison baseline, so an old baseline cannot replay misleading changes. The first new complete collection starts comparison again.

Upgrade the server before agents so new capability versions are understood, and take a matched backup before upgrading (see [RECOVERY.md](RECOVERY.md)).

## Permissions

All reads require an authenticated session. Device views use the device `read` scope: the administrator and every technician whose device or group scope includes the device. Fleet reports apply the technician's current device and group scope before limits, counts and examples. There is no separate software permission.

## Configuration

The feature is on by default.

- **Installed service:** switch off **Software inventory** in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy), or lock it off on one device from an administrator PowerShell in the repository root:

  ```powershell
  .\scripts\service.ps1 -Action configure -SoftwareMode false
  .\scripts\service.ps1 -Action configure -SoftwareMode true   # removes the lock
  ```

  A running service is restarted; enrollment is kept. A lock survives MSI installs and self-updates, and a policy cannot override it; see [feature switches](WINDOWS-SERVICE.md#feature-switches).
- **Console agent:** `-software=false` or `OPENRMM_AGENT_SOFTWARE=false`.

Linux agents report **Not supported** without running any registry code.

## Related

- [APPLICATIONS.md](APPLICATIONS.md)
- [WINDOWS-UPDATES.md](WINDOWS-UPDATES.md)
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md)
- [Microsoft: uninstall registry key](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key)
- [Microsoft: accessing an alternate registry view](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view)
