# Parsed Artifacts

The server parses collected Windows artifacts into tables you can search on the case page or download as CSV: Prefetch, registry hives (with Amcache, ShimCache, UserAssist, BAM, ShellBags, autostart entries, services and USB devices), event logs, shortcuts and jump lists, plus one combined timeline of all of them. Triage packages, registry hive collections and event log exports are parsed automatically once they are verified. It is for responders with the Incident response permission.

## Contents

- [Overview](#overview)
- [What is parsed](#what-is-parsed)
- [The combined timeline](#the-combined-timeline)
- [Viewing the results](#viewing-the-results)
- [How parsing runs](#how-parsing-runs)
- [Parsing again](#parsing-again)
- [Storage and custody](#storage-and-custody)
- [Limits](#limits)
- [API](#api)
- [Related](#related)

## Overview

- Parsing runs on the server, not on the device: the collected files stay as they were collected, and the results are stored next to them as evidence of their own.
- Each collection gets one result: a ZIP of CSV tables (one per artifact) and a `manifest.json` listing the tables, their columns and row counts, and the files that could not be parsed.
- The collection's row on the case page shows the parse's state: **Parsing queued**, **Parsing**, **Parsed** (with the number of tables and rows) or **Parsing failed** with the reason. Select **View parsed** to open the results.
- Console results (live response without a case) are parsed too and kept as long as the result, 24 hours.
- All parsers are written for OpenRMM on Go's standard library; no third-party forensic library is involved (see [DEPENDENCIES.md](DEPENDENCIES.md)).

## What is parsed

| Table | From | Contents |
| --- | --- | --- |
| Prefetch | `Windows\Prefetch\*.pf` (versions 17 to 31, including the compressed files of Windows 10 and 11) | Program, its path, hash, run count, last run and up to seven earlier runs, volumes, files loaded |
| Registry hives | Every hive | Kind, user, last written, whether it was dirty and how many log entries were applied, number of keys |
| Registry keys | Every hive | Every key's path and last write time, with its number of values and subkeys |
| Amcache files, Amcache programs | `Amcache.hve` | Files with path, SHA-1, size, publisher, product, version and link date; installed programs |
| ShimCache (AppCompatCache) | `SYSTEM` (Windows 10 and 11 format) | Paths in cache order with their modification time |
| UserAssist | `NTUSER.DAT` | Programs and shortcuts started from Explorer, with run count, focus count and time, last run |
| BAM / DAM | `SYSTEM` | Programs per user SID with their last run |
| ShellBags | `NTUSER.DAT`, `UsrClass.dat` | Folders browsed in Explorer: path, item type, MRU position, key last write, the folder's own times and MFT reference |
| Registry autostart entries | `SOFTWARE`, `NTUSER.DAT` | Run and RunOnce keys, Winlogon `Userinit` and `Shell`, `AppInit_DLLs`, Image File Execution Options debuggers, silent process exit monitors, Active Setup |
| Services | `SYSTEM` | Every service of the current control set with image path, service DLL, start type and account |
| USB devices | `SYSTEM` (`USBSTOR` and `USB`) | Device, serial number, friendly name, first install, last arrival, last removal |
| Event logs | `*.evtx` | Time, channel, event ID, level, provider, record ID, computer, user SID, process and thread, task, opcode, keywords, and the event's named data |
| Shortcuts (LNK) | Every `.lnk` in the package (Recent files, Startup folders) | Target path, arguments, working folder, the target's times and size, volume type, serial and label, network path, the machine the shortcut was made on and its network address |
| Jump lists | `*.automaticDestinations-ms`, `*.customDestinations-ms` | App ID, the DestList's path, last access, pin and access count, and each entry's shortcut |

Registry hives are read with their transaction logs (`.LOG1`, `.LOG2`): Windows writes changes to the logs first and to the hive later, so a hive copied from a running system usually lacks its latest changes. The logs of Windows 8.1 and later are replayed; the table **Registry hives** says how many entries were applied.

Event messages are not rendered: their text lives in each provider's DLLs on the device. The named data (such as `TargetUserName=alice | LogonType=10`) holds the same values.

Times are UTC with 100-nanosecond precision (`2026-11-03 09:30:00.0012345`). FAT times in shell items have 2-second precision.

## The combined timeline

The first table, **Combined timeline**, holds every timestamped event of the other tables in one list, oldest first: programs that ran (Prefetch, UserAssist, BAM), files and programs recorded (ShimCache, Amcache), registry keys written, services and autostart keys changed, USB devices installed, connected and removed, folders opened, every event log record, shortcuts written and their targets' times, and jump list entries opened. Its columns are `Time`, `Artifact`, `Event`, `Path`, `Details` and `SourceFile`.

## Viewing the results

**View parsed** opens a viewer that pages through one table at a time on the server, 100 rows at a time, with filters:

- **Contains**: any column contains the text (case ignored);
- **Column / Equals**: one column equals a value, such as `EventID` equals `4624` or `Channel` equals `Security` (case ignored; in cells with several values separated by `|`, any one);
- **From / To** (your local time): any of the table's time columns.

Download a table as CSV, or every table as the ZIP, for sorting and pivoting in other tools. The files that could not be parsed are listed with the reason.

## How parsing runs

The server parses one collection at a time, in a separate copy of its own program that receives only the collection: no database, keys or environment. That process runs with low CPU priority and, on Linux, a 6 GiB address space limit, so a crafted file can at most end that process. Every length and offset read from a file is checked before use; a damaged file, chunk or record is skipped and listed, and parsing goes on.

A parse that runs longer than two hours is stopped. A server restart restarts the parse; one that ends the server three times is given up as **crashed**.

## Parsing again

**Parse again** on the collection (or **Parse** for collections from before this feature) queues a new parse, for example after an update improved the parsers; the manifest names the parser version. Older results stay in the evidence store and in the custody log.

## Storage and custody

The results are stored by their SHA-256 like other evidence and count toward the evidence quota. A parse that would not fit in what is left of the quota ends as **quota** and stores nothing. The custody log records each parse with its result's hash, size, table counts and the number of files not parsed, each request to parse again, and each opening or download of the results.

## Limits

| Limit | Value |
| --- | --- |
| Results per collection | 4 GiB compressed, or what is left of the evidence quota |
| Parsing time | 2 hours per collection |
| Hive and transaction log | 512 MiB each |
| Event log file | 4 GiB |
| Prefetch file | 16 MiB |
| Shortcut or jump list | 64 MiB |
| Registry keys listed per hive | 3,000,000 |
| Files listed as not parsed | 1,000, then counted |
| Viewer page | Up to 500 rows (100 by default) |

## API

The routes take the collection under its case (`/api/v1/cases/{case}/collections/{job}`) or under its console session (`/api/v1/terminal/{session}/jobs/{job}`):

| Route | Purpose |
| --- | --- |
| `GET …/parsed` | The manifest; `?format=zip` downloads the results |
| `GET …/parsed/{table}` | A page of rows: `offset`, `limit` (up to 500), `q`, `column` and `equals`, `from` and `to` (RFC 3339); `?format=csv` downloads the table |
| `POST …/parse` | Parse again |

The collection listing includes each collection's `parse` state.

## Related

- [Triage packages](TRIAGE.md)
- [Incident response](RESPONSE.md)
- [Event logs](EVENT-LOGS.md)
- [NTFS artifacts](NTFS.md)
