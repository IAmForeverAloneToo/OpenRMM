# Hunting

The **Hunting** page (sidebar, **Investigate**) searches many devices at once: **Log search** queries Windows event logs across the fleet, and **Indicators** hunts for files, processes, network connections and persistence entries that match a list of indicators of compromise. It is for responders with the response permission.

## Contents

- [Overview](#overview)
- [Log search](#log-search)
- [Indicator hunts](#indicator-hunts)
- [Saved lists](#saved-lists)
- [Live response](#live-response)
- [Cases, retention and visibility](#cases-retention-and-visibility)
- [API](#api)
- [Storage](#storage)
- [Related](#related)

## Overview

Both kinds of search work the same way:

- **Targets:** chosen with the same picker as scripts (devices and groups), up to 500 devices including group members. **Select all shown** picks every listed Windows device.
- **Case:** none, an open case, or a new case. Without a case the results are kept for 24 hours.
- **Offline devices:** a device that is offline picks the search up when it next connects, up to 7 days after the start. After that its job expires ("did not answer").
- **One job per device:** each target that can run the search gets one evidence job (a response action). Devices that cannot are listed under **Not searched** with the reason.

| Not searched because | Meaning |
| --- | --- |
| Incident response is switched off on the device | The device's **Incident response** switch is off. |
| The device's agent cannot search event logs / run indicator hunts | The agent is too old to report the needed ability; update it. |
| Too many searches are already waiting for this device | Ten searches are already queued for the device. |

If no device can run the search, it is refused (HTTP 409, `no_targets`, with the reasons), and a case created for it is closed again. More than 500 devices including group members is refused (`too_many`).

**Technician scope.** Group members outside the technician's device access are left out silently (nothing about them is returned). A chosen device outside it, or a group with no member inside it, is refused like an unknown one. The search page shows a technician only devices still in their scope.

**Waiting and cancelling.** **Stop waiting** cancels jobs not yet handed out; searches already running finish. Closing a case cancels its searches that are still waiting. Search jobs do not count against the limit of two collections per device or 20 running collections on the server, and a device hands out other waiting work (collections, actions) before searches.

## Log search

The **Log search** tab runs one event log query on every target.

**Starting a search:**

- a log (any channel name; common ones are suggested);
- a time range of up to 31 days;
- optionally a level, event ID, provider and an XPath predicate. The same rules as the device's **Event logs** tab apply (see [EVENT-LOGS.md](EVENT-LOGS.md)).

**On the device.** The agent runs the event log query with the same reader as the **Event logs** tab (at most 2 minutes) for the newest 250 matching events, and uploads the result document like any response action: in chunks, verified by SHA-256. The device's **Event logs** switch governs it: when it is off, the result says so (`unsupported`) and no events are read.

**Results.** The page lists each device with its state and match count ("newest 250; more matched" when not all matches were returned).

- The server reads each stored result once to cache these counts. That is not an evidence access. A result over 8 MiB, or one that cannot be parsed, is cached as unreadable and not read again.
- **View** opens one device's events.
- **All events** merges every device's events, newest first, filterable (also through the event XML). It reads six devices at a time, skips and counts results that cannot be read, keeps what it read for the page (reopening reads nothing again) and loads at most 50,000 events.
- Opening a result is a download like any other: recorded in the case's custody log, or in the audit log without a case.

## Indicator hunts

The **Indicators** tab searches each target for a pasted list of indicators, or a [saved list](#saved-lists).

### Indicator format

Indicators are pasted one per line. Two other forms are accepted:

- `type:value`, for example `domain:bad.example`;
- CSV lines `type,value`.

Lines starting with `#` are ignored. Untyped values are typed automatically:

- hashes by their length (SHA-256, SHA-1, MD5);
- IP addresses and networks;
- paths, when the value contains `\` or `/` and starts with a drive (`C:\`), an environment variable (`%APPDATA%\`) or `*`;
- anything else as a name.

> [!NOTE]
> Domains need the `domain:` prefix, because `evil.com` may also be a file name.

The server parses the list with the agent's own rules and shows how many indicators of each type it found and which lines it did not understand.

| Type | Matches |
| --- | --- |
| `sha256`, `sha1`, `md5` | Files in the searched locations, process images and autostart programs. SHA-1 and MD5 are computed only when the list contains them. |
| `name` | File, process and autostart program names. `*` and `?` are wildcards; case is ignored. |
| `path` | Full paths of files, process images and autostart programs (or their command). `*`, and `%VAR%` as in `%APPDATA%\x.exe`, match any text including folders. The name part must be more than wildcards (`C:\*` is refused). |
| `ip` | Remote addresses of current TCP/UDP connections, and addresses in the DNS client cache. An address or a network such as `198.51.100.0/24`. |
| `domain` | Names in the DNS client cache, and names a cached record points to (CNAME). Either exact, or `*.example.com` for the domain and its subdomains (`*.com` is refused). |
| `cmd` | Text in process command lines and autostart commands (at least 3 characters, case ignored). |

A hunt has at most 1,000 distinct indicators and at most 128 KiB of indicator text in total. Every target's job and custody entry keeps a copy.

### What the agent searches

Each target runs the response action `hunt` in the agent's long-job worker, the same one triage packages use, so live response stays responsive. Only devices whose agent reports the `hunt` ability are targeted; others are listed as not searched.

| Source | Used for |
| --- | --- |
| Processes | Name, path, hash and `cmd` indicators. Process images are hashed through the agent's hash cache. |
| Network connections | IP indicators. |
| DNS client cache | Domain and IP indicators. Read with a fixed `Get-DnsClientCache` command. |
| Persistence report | The same autostart report as [PERSISTENCE.md](PERSISTENCE.md). |
| Files | All indicator types that match files, when **Search files in common locations** is on (the default). |

**Searched file locations:**

- every user profile's Downloads, Desktop and AppData (which holds the user's Temp and Startup folders);
- ProgramData, `Windows\Temp` and the Public profile;
- the files at the root of each fixed drive (not their subfolders).

Links and junctions are not followed, and files on other computers are never opened. With hash indicators, every file up to 100 MB is hashed by four workers; larger and unreadable files are counted as skipped. The hashes of hunted files are kept in a cache of their own (100,000 files), so a later hunt skips unchanged files and process image hashes are not pushed out.

> [!TIP]
> A hunt with only names, paths, network or command indicators does not read file contents and is much faster than a hash hunt over all common locations.

**Scheduling on the device.** A device runs one hunt at a time; the next waits until the running one has finished. A hunt may wait behind a triage package, so it gets the triage start window plus 30 minutes. While the agent keeps asking for work, the server hands it a running hunt again every 3 minutes, and the agent ignores the copy.

### Limits

| Limit | Value |
| --- | --- |
| Search time per device | 15 minutes, then the result is **Partly searched** |
| Blocked file open or folder read (for example an oplock held by another program) | Abandoned after 10 seconds; the result is reported without it |
| Files per device | 500,000, then the result is **Partly searched** |
| Largest file hashed | 100 MB |
| Matches per device | 1,000 |
| Command line or path in a match | Cut to 2 KB |

### Results

The hunt page shows, for each device, its matches (in red when there are any), whether it was partly searched, and the number of skipped files.

**All matches** loads every device's result into one table: the device, where the match was found, the indicator, what matched (path, process with PID, connection, DNS record, autostart entry and command) and details (SHA-256, size, modification time, user). Opening results is recorded like any evidence download.

## Saved lists

The **Saved lists** tab lists named indicator lists (up to 200, names unique ignoring case) with their indicator count and last change. Anyone with the response permission can manage them.

- **Hunt** opens the **Indicators** tab with the list loaded.
- **Edit** changes its name and indicators.
- **Delete** removes it.

**Save as list** on the **Indicators** tab saves the current indicators. A hunt keeps its own copy of the indicators, so later edits to a list do not change past hunts.

## Live response

In a [live response](RESPONSE.md) console, the command `hunt [-files] <indicator ...>` hunts the session's device, and `hunt [-files] -list <name>` does the same with a saved list. `-files` also searches the common file locations. The result opens in the console's results like other actions.

```text
hunt -files evil.exe 203.0.113.7 domain:bad.example
```

## Cases, retention and visibility

- **With a case:** each device's job is a case action (`action_requested` with the search ID in `hunt`, then `action_completed`). Results are hashed case evidence, listed as **Log search <channel>** for log searches, and open in the case's result viewer.
- **Without a case:** the jobs belong to the hidden case-less record used by [live response](RESPONSE.md). Audit events are written instead of custody entries, and results are kept for 24 hours after each device answered, then purged.
- **Visibility:** a search is listed and readable for the account that started it and for the owner. Reading a device's result also needs current access to that device. Results of a search with a case are also case evidence, which everyone with the response permission can open from the case.
- **Audit:** saved-list changes are audited as `ioc_list_added`, `ioc_list_changed` and `ioc_list_deleted`.

## API

All routes need the response permission.

| Route | Purpose |
| --- | --- |
| `POST /api/v1/hunts/log-search` | Start a log search: `devices`, `groups`, `filter`, and `case_id` or `case_title`. |
| `POST /api/v1/hunts/indicators` | Start an indicator hunt: `devices`, `groups`, `indicators`, `files`, and `case_id` or `case_title`. |
| `POST /api/v1/hunts/indicators/parse` | Parse an indicator list with the agent's rules. |
| `GET /api/v1/hunts` | List searches visible to the account. |
| `GET /api/v1/hunts/{id}` | One search with its targets and problems. |
| `POST /api/v1/hunts/{id}/cancel` | Stop waiting for devices. |
| `GET /api/v1/hunts/{id}/jobs/{job}/result` | Download one device's result (recorded as an evidence access). |
| `GET /api/v1/ioc-lists` | List saved indicator lists. |
| `POST /api/v1/ioc-lists` | Add a list. |
| `PUT /api/v1/ioc-lists/{id}` | Change a list. |
| `DELETE /api/v1/ioc-lists/{id}` | Delete a list. |

## Storage

- `hunts` holds each search: its kind (`log_search` or `indicators`), filter or indicators, problems and times.
- `evidence_jobs.hunt_id` (indexed) links each device's job to its search.
- `hunt_results` caches each device's match count.
- `ioc_lists` holds the saved indicator lists.

## Related

- [RESPONSE.md](RESPONSE.md): cases, evidence and live response
- [EVENT-LOGS.md](EVENT-LOGS.md): event log filters and XPath rules
- [PERSISTENCE.md](PERSISTENCE.md): the autostart report used by hunts
- [TRIAGE.md](TRIAGE.md): triage packages that share the long-job worker
