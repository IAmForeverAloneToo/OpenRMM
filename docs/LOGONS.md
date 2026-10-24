# Logon History

The logon history lists successful logons from each Windows device's Security log (event 4624). Administrators, technicians and incident responders use it to see who signed in to a device, how and from where, over the past year.

## Overview

A device's **Users** tab has a **Logons** view, newest first. You can:

- filter by user, source address or workstation;
- filter by type: **Interactive**, **Remote Desktop** or **Network**;
- load older pages with **Load older**, 500 logons at a time.

Unlike [signed-in users](SESSIONS.md), which the agent observes every minute, this is the Windows logon audit. The view refreshes every 60 seconds while only the first page is loaded.

## What is collected

The `logon_history` v1 module belongs to the **Signed-in users** feature (`sessions`). Every five minutes it reads the Security log, oldest first, and sends the logons recorded after its cursor.

**Logon types kept:**

| Type | 4624 logon type | API value |
| --- | --- | --- |
| Interactive | 2 | `interactive` |
| Network | 3 | `network` |
| Network (cleartext) | 8, shown highlighted | `network_cleartext` |
| Remote Desktop | 10 | `remote` |
| Interactive (cached) | 11 | `cached` |

**Logons left out:** SYSTEM, LOCAL SERVICE, NETWORK SERVICE, anonymous logons, Window Manager and font driver host accounts (`S-1-5-90-*`, `S-1-5-96-*`), and computer accounts (names ending in `$`). These log on constantly and say nothing about who used the device. Batch, service, unlock and `runas /netonly` logons are not collected, and neither are failed logons (event 4625).

**Fields recorded for each logon:**

- time and event record ID;
- user, domain and SID;
- logon type;
- source address and port;
- workstation name;
- authentication package and logon process;
- logon ID;
- whether the token was elevated.

## Cursor and backfill

- The agent keeps its cursor in `logon-cursor.json` in its state directory. The cursor holds the record ID and exact time of the last event sent.
- The cursor advances only after the server **accepted** the report. An undelivered or refused report is collected again from the same cursor, so nothing is lost while the server is older than the agent.
- New logons are selected by **record ID**. Event times can jump (clock changes, restored virtual machines), so time is used only to detect a cleared Security log: the log is assumed cleared when the cursor's record is gone and nothing follows it, or when that record ID now holds a different event. The agent then reads once by time, and record IDs take over again from the new cursor. When the cursor's record merely rolled off a full log, newer records follow it and reading continues by record ID.
- An event whose data cannot be read, or that would produce an invalid logon, is left out; the cursor still moves past it, so one bad event never stops the history.
- A first collection without a cursor reads the last 30 days.

### Per-collection limits

| Limit | Value |
| --- | --- |
| Events scanned | 5,000 |
| Logons sent | 500 |
| Report size | 512 KiB |
| Collection time | 1 minute |

When more remain, the report says so and the view shows **Catching up** until the backlog is sent. A very busy server (for example a domain controller with many network logons) may fall behind, and the Security log may roll over before everything is sent.

## Storage and retention

- Logons are keyed by device, time and record ID, so a repeated delivery adds nothing. A second table holds each device's last report status and whether a backlog remains.
- Logons older than 365 days, or dated more than a day in the future, are dropped.
- Each device keeps at most 20,000 logons, counted separately for network logons (types 3 and 8) and for all other types, newest first. A busy server's network logons therefore never push out its interactive and Remote Desktop history.
- At most 1,000,000 logons are kept overall. Age and overall limits are applied by the server's housekeeping every minute.
- Removing a device removes its logons.

## API and permissions

`GET /api/v1/devices/{id}/logons?q=&kind=&before=<time>:<record>` requires the device `read` scope: the administrator and every technician whose device or group scope includes the device.

| Parameter | Meaning |
| --- | --- |
| `q` | Case-insensitive substring of the user, domain, `DOMAIN\user`, source address or workstation (at most 100 bytes). |
| `kind` | `interactive` (including cached), `remote` or `network` (including cleartext). |
| `before` | Paging cursor: the time and record ID of the last logon on the previous page. |

The response contains `info` (status, last collection and backlog), `logons`, `more`, `page` (500) and `days` (365). A malformed filter or cursor returns HTTP 400.

## Turning it off

Turn off **Signed-in users** in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy), or lock it off on the device as described in [SESSIONS.md](SESSIONS.md#turning-it-off). Stored history stays until it ages out.

## Privacy

User names, SIDs, source addresses and workstation names are personal data. They are visible to the administrator and every technician who can read the device, kept for up to 365 days and included in backups.

## Related

- [SESSIONS.md](SESSIONS.md)
- [LOCAL-ACCOUNTS.md](LOCAL-ACCOUNTS.md)
- [EVENT-LOGS.md](EVENT-LOGS.md)
- [HUNTING.md](HUNTING.md)
