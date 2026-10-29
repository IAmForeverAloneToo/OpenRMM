# Event Logs

The **Event logs** tab queries the Windows event logs of one device on demand, and responders can export a channel as an `.evtx` file into a case. It is for the owner and technicians who troubleshoot or investigate Windows devices; searching many devices at once is covered in [HUNTING.md](HUNTING.md).

## Contents

- [How it works](#how-it-works)
- [Querying a device](#querying-a-device)
- [Channels and XPath](#channels-and-xpath)
- [Results and paging](#results-and-paging)
- [.evtx export](#evtx-export)
- [Fleet log search](#fleet-log-search)
- [Queue, timing and retention](#queue-timing-and-retention)
- [Turning it off](#turning-it-off)
- [Permissions and audit](#permissions-and-audit)
- [Upgrading](#upgrading)
- [API routes](#api-routes)
- [Related](#related)

## How it works

- The agent checks which logs it can read at startup and every minute, but sends event contents only in response to an authenticated query. There is no continuous log shipping, event subscription or historical index on the server.
- The viewer is read-only. It does not clear logs, enable channels, change auditing, run scripts, or open arbitrary event files or remote sessions.
- The agent runs as LocalSystem, but Windows log permissions still apply: a channel that is denied or unavailable is shown as **Denied** or **Unavailable**. OpenRMM does not change Event Log Readers membership; review a denied channel's access policy on that machine.
- Queries use fixed system `wevtapi.dll` bindings through the already pinned `golang.org/x/sys` loader. Non-Windows agents report **Unsupported**.

## Querying a device

1. Open a device's **Event logs** tab.
2. Choose a log, a time range (last hour, 24 hours, 7 days or 31 days), and optionally a level, an exact provider name, an event ID and a page size (25, 100 or 250 events). Accounts with the Incident response permission also get an **XPath filter**.
3. Select **Search**.
4. Select an event for its formatted message and expand **Event XML**. Use **Older events** to continue with the same time and filter bounds.

Filter rules:

| Filter | Rule |
| --- | --- |
| Time range | At most 31 days per query. The API accepts any historical UTC window (Unix seconds). |
| Level | 0 Log always, 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose; **Any level** leaves it unrestricted; level 0 can be requested only through the API. Results also show provider-defined levels up to 255. |
| Event ID | 0–65,535 |
| Provider | Exact match, at most 256 UTF-8 bytes, no control characters or quotes |
| Page size | 25, 100 or 250 events |

The structured fields are assembled into a fixed XPath expression by the agent; file paths are never accepted as channels.

## Channels and XPath

- **Channels.** The agent reports whether it can read System, Application and 14 key channels: Security, Setup, Windows PowerShell, PowerShell/Operational, Sysmon, Task Scheduler, both Terminal Services channels, WinRM, Defender, BITS, WMI-Activity, Windows Firewall and Code Integrity. The log list shows them with their state, and **Other channel…** takes any channel name.
  - A probed channel must be readable to be queried. Any other name is tried and returns `unavailable` or `denied` when it is missing or closed.
  - Names are 1–256 characters of letters, digits, space and `-_./%()`, without `..`. Only channels are opened, never `.evtx` files.
  - The Event logs permission covers every channel, including Security.
- **XPath** (Incident response permission for the device; otherwise 403):
  - one predicate of the form `*[...]` whose outer brackets enclose the whole expression, so a top-level `or` cannot widen the time range or the paging cursor;
  - at most 4,096 characters, no control characters, balanced quotes and brackets; Windows checks the syntax;
  - the agent queries `*[System[<time, level, provider, ID, cursor>]] and <XPath>`, and returned events are still checked against the structured part;
  - the permission is checked again when the agent picks up the query.
- **Forwarded events** keep their original channel name in the ForwardedEvents log; they are bound to the queried channel by the query itself, so they are not filtered out.
- Agents that support only the first version of the event log capability offer only System and Application, 25-event pages and no XPath.

## Results and paging

- Each event includes its record ID, event ID, provider, numeric level, UTC timestamp, message status and XML.
- XML is parsed with Go's standard library; external entities are never resolved. All values are treated as untrusted and shown as escaped text.
- Messages are formatted with the device's local publisher resources, requesting English. Missing, inaccessible or oversized resources yield an unavailable message with the XML as fallback.

| Limit | Value |
| --- | --- |
| Message | 4,096 UTF-8 bytes per event (truncation is marked and keeps valid UTF-8) |
| XML | 8,192 bytes per event |
| Rendered native event | 512 KiB |
| Formatting buffer | 65,536 UTF-16 characters |
| Result | 4 MiB of JSON; a page ends early (with **Older events**) before it would exceed this |
| Query time | 20-second deadline (a single Windows call cannot be interrupted, so this is not a hard process limit) |

- A single event that is oversized, malformed or outside the filter is skipped and counted (shown as "N events skipped") instead of failing the query. Narrow the filter if necessary.
- Pages are ordered by descending record ID, which is not guaranteed to be descending time. **Older events** uses the last record ID as an exclusive cursor and keeps the original time window.
- Windows logs are live: rotation, clearing, provider removal and clock changes can affect later pages. A stale Windows query is reported as `log_changed`. No matching events is a valid, successful result.

## .evtx export

Export a whole channel, or the events matching the current filter, as case evidence.

- **Where:**
  - **Export .evtx** on the Event logs tab (owner and accounts with the Incident response permission). A dialog chooses the current filter or the whole log, and an open or new case. A case created in the dialog is closed again if the export cannot start.
  - **Event log (.evtx)** in a case's evidence form (whole channel).
  - The live response command `evtx <channel> [<xpath>]`; without a case, the export is kept for 24 hours.
- **How:** an evidence job of source `evtx` (path: the channel; query: the XPath, empty for the whole channel). The agent runs Windows' `EvtExportLog` on the channel (never a file path) into a private file in its state folder, uploads it in verified chunks like any collection (metadata method `export`, no file times) and deletes it. The filter's query is `*[System[time, level, ID, provider]]` plus any raw XPath. Downloads are named `eventlog-<channel>.evtx`.
- **Rules:** the Incident response switch, the two-collections-per-device limit, the 16 GB file limit, the quota and custody entries of [evidence collection](RESPONSE.md#evidence-collection) apply. The requested and collected custody entries name the source `event log` and the query.
- **Requirements and limits:**
  - The device must report the second version of the event log capability or later; otherwise the request is refused with a message to update the agent.
  - The device has 30 minutes after picking up the job to begin the upload (the log is exported first).
  - Before exporting, the agent reads the log file's size: over 16 GB is refused as too large, and the export needs that much free space plus 1 GiB on the drive of its state folder.
  - An interrupted export is not resumed (a new export is a different file); the job ends as `changed`.

## Fleet log search

The **Hunting** page searches the event logs of many devices at once with the same filters and XPath rules, optionally into a case. It needs the Incident response permission and agents with the third version of the event log capability. See [HUNTING.md](HUNTING.md).

## Queue, timing and retention

- A query needs an online, active device with a supported, successful availability report received within the last two minutes, including read access to the selected channel. Old reports are shown as stale.
- One event query can be outstanding per device. Event queries have their own device-bound queue, independent of service control and other collectors.
- The agent picks up a query within about a second over its mutual-TLS connection: it waits for work instead of polling ([HEARTBEATS.md](HEARTBEATS.md#waiting-for-work)). Dispatch and result writes recheck the device's active certificate. A device cannot read or complete another device's query. The agent revalidates the filters and current Windows permissions when reading.
- Queued requests expire after one minute. Dispatch happens at most once. Lost delivery, an interrupted agent or a missing result becomes **Unknown** after the one-minute result window. The viewer refreshes pending status about every two seconds and never creates a new query by itself; submit again deliberately if needed.
- Result delivery is retried without rereading the logs; identical duplicate results are accepted once, and late or conflicting results are rejected. Server or agent restarts do not repeat dispatched reads.
- Requests and results expire **15 minutes** after the request was created; expired results cannot be returned. Cleanup runs at startup and every minute.
- At most **100** query records are kept (including completed results), and new queries are refused while cached results exceed **64 MiB**, until expiry makes room.
- Expiry removes rows from the application but is not secure erasure: SQLite free pages, the WAL and backups can retain old bytes. Events can contain sensitive data; protect the database and backups. Event results never appear in health endpoints or URLs.

## Turning it off

Event log queries are the agent feature **Event logs** (`event_logs`), on by default. Switch it off in the device's monitoring policy (**Agent features → Event logs**), or lock it off on one device in an administrator PowerShell:

```powershell
.\scripts\service.ps1 -Action configure -EventLogsMode false
# Remove the lock:
.\scripts\service.ps1 -Action configure -EventLogsMode true
```

- This controls the availability reports and query polling. A lock survives MSI installs and self-updates, and a policy cannot override it; see [feature switches](WINDOWS-SERVICE.md#feature-switches).
- A console agent uses `-event-logs=false` or `OPENRMM_AGENT_EVENT_LOGS=false`; the installed service ignores interactive environment overrides.
- A Windows read already delivered cannot be undone by switching the feature off or revoking the device. Results already accepted remain viewable until they expire.
- `.evtx` export and fleet log search run as response jobs, so they also depend on the **Incident response** switch.

## Permissions and audit

- Queries need a signed-in session with MFA, same-origin requests, the session's `X-CSRF-Token` header and a client-generated query ID.
- The owner can query every device. Technicians need the **Event logs** permission and the device in their scope; XPath filters and `.evtx` export also need **Incident response**.
- Audit records contain the account, query and device IDs, channel, server time and outcome. Event messages and XML are never copied into audit records or application logs. Audit records follow the audit log retention ([ADMINISTRATOR.md](ADMINISTRATOR.md)).
- The server assigns receipt and queue times; event timestamps are data reported by the device.

## Upgrading

Take a matched backup, update the server, then update the agents. Agents too old to report event log availability show **Not reported**. Rolling back requires a matched backup. A [restore](RECOVERY.md) deletes outstanding event queries and cached results, so old requests and results are not resurrected.

## API routes

| Route | Purpose |
| --- | --- |
| `POST /api/v1/devices/{id}/event-logs` | Queue a query (JSON `id` and `filter`). |
| `GET /api/v1/devices/{id}/event-logs/{query}` | Read a retained query and its result. |
| `POST /api/v1/devices/{id}/event-logs/export` | Start an `.evtx` export. |
| `POST /api/v1/agent/event-logs/poll`, `/result` | Agent-only routes on the client-certificate listener. |

The device detail API includes `event_logs` availability and whether it is current or stale.

## Related

- [HUNTING.md](HUNTING.md): fleet log search and indicator hunts
- [RESPONSE.md](RESPONSE.md): cases and evidence collection
- [TRIAGE.md](TRIAGE.md): collecting all `.evtx` files with other artifacts
- [TECHNICIANS.md](TECHNICIANS.md): technician permissions
