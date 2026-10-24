# Triage Packages

A triage package collects many forensic artifacts from one Windows device in a single step and delivers them as one ZIP, ready for external analysis tools (KAPE-style collections for EZ Tools, Plaso, RegRipper and similar). It is for responders with the Incident response permission.

## Contents

- [Overview](#overview)
- [Artifact types](#artifact-types)
- [Profiles](#profiles)
- [Starting a collection](#starting-a-collection)
- [What happens on the device](#what-happens-on-the-device)
- [The package](#the-package)
- [Limits](#limits)
- [On the server](#on-the-server)
- [Related](#related)

## Overview

- One ZIP per device, with every file under its original path and a manifest (path, size, times, SHA-256 and how each file was read).
- The ZIP is uploaded, hashed and verified as one piece of case evidence, with the same custody logging as any [evidence collection](RESPONSE.md#evidence-collection).
- Files are read from a Volume Shadow Copy, so registry hives, event logs and databases in use are captured consistently as they were at one moment.

## Artifact types

| Type | What is collected |
| --- | --- |
| Prefetch | `%SystemRoot%\Prefetch\*.pf` |
| Amcache | `Amcache.hve` with `.LOG1`/`.LOG2` |
| System registry hives | `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT` from `System32\config`, each with `.LOG1`/`.LOG2` |
| User registry hives | Every user profile's `NTUSER.DAT` and `UsrClass.dat`, with logs |
| Scheduled task XML | `System32\Tasks`, all levels |
| Event log files | `System32\winevt\Logs\*.evtx` |
| SRUM | `System32\sru` |
| Browser history | Per user: Chrome and Edge `History`, `Cookies`, `Web Data`, `Shortcuts`, `Top Sites`, `Bookmarks`, `Favicons` (two levels below `User Data`); Firefox `places.sqlite`, `cookies.sqlite`, `formhistory.sqlite`, `downloads.sqlite`, `favicons.sqlite`; each SQLite database with its `-journal`, `-wal` and `-shm` files (recent history is often only there) |
| Recent files and jump lists | Per user `AppData\Roaming\Microsoft\Windows\Recent`, all levels |
| Startup folders | The all-users and every user's Startup folder |
| PowerShell console history | Per user `PSReadLine\*.txt` |
| WMI repository | `System32\wbem\Repository`, all levels |

User profiles are those in the registry's `ProfileList` for local, domain and Microsoft Entra accounts (`S-1-5-21-…`, `S-1-12-1-…`) on the system drive.

> [!NOTE]
> Saved browser passwords (`Login Data`, `logins.json`) are not collected. `Web Data` does contain autofill entries and encrypted saved payment cards, and cookie databases are included; handle packages as sensitive.

## Profiles

- One built-in profile, **Full triage**, collects every artifact type. It cannot be withdrawn.
- The owner adds narrower profiles from a checklist of artifact types under **Cases → Triage profiles**, and withdraws them.
- Everyone with the Incident response permission sees and runs the profiles.
- A package keeps the profile name it was collected with, even if the profile is later withdrawn.

## Starting a collection

- **Case page:** **Evidence → Collect → Triage package**, then choose a profile.
- **Live response console:** `triage [<profile>]` (default **Full triage**). Without a case, the package is kept for 24 hours like other case-less results; see [live response console](RESPONSE.md#live-response-console).

Requirements:

- The `response` permission and access to the device, and **Incident response** switched on for the device.
- The device's agent must report the `triage` ability in its heartbeat. Otherwise the request is refused with a message to update the agent.
- Update the server before the agents (the normal order): an older server rejects heartbeats that carry abilities.

## What happens on the device

1. **Shadow copy.** The agent makes one Volume Shadow Copy of the system drive. It is recorded in the agent's shadow-copy ledger, so a crash leaves nothing behind after restart.
2. **Listing.** The agent lists the files of the profile's artifact types in the copy.
   - Every folder before it is listed, and every file when it is opened, must resolve to exactly its own path. A junction or link anywhere above it (for example a user turning their Recent folder into a junction, which could lead out of the shadow copy) is refused and recorded as `redirected`.
   - OpenRMM's own folders (state, logs, installation) are refused, also through hard links.
   - Folders that cannot be listed are recorded as left out. At most 200,000 files are listed.
3. **Packaging.** Files are written into a ZIP in the agent's private state folder, compressed, with their modification times, and hashed while they are written. Files are added for at most 100 minutes; the rest are left out as `time_limit`.
4. **Upload.** The shadow copy is deleted, and the ZIP is uploaded in verified chunks like any collection (metadata method `triage`), then deleted from the device.

If no shadow copy can be made, files are read live with the backup privilege (method `live`); files locked by other programs are then left out, and the manifest says so.

The agent builds packages in their own worker, one at a time, so other collections, actions and live response commands keep running. A build stops when the agent restarts or stops; the job then waits to be handed out again. Shadow copies a running build uses are never removed by the start-up cleanup.

## The package

- Entries are named by their original path, for example `C/Windows/System32/config/SYSTEM`.
- `manifest.json` (format `openrmm-triage`, version 1) lists:
  - every file: path, artifact type, size, modified and created times (Unix nanoseconds), SHA-256, method (`snapshot` or `live`), and `incomplete` if reading stopped part-way or the file grew by more than 1 MiB after it was listed;
  - everything left out, with the reason: `size_limit`, `time_limit`, `redirected`, `locked`, `denied`, `gone`, `unreadable`, `folder_unreadable` or `too_many_files` (at most 10,000 listed, the rest counted in `skipped_more`);
  - the shadow copy's ID and time.
- The download is named `triage-<profile>-<job>.zip`.

## Limits

| Limit | Value |
| --- | --- |
| Package size | 16 GB (the evidence file limit), or less when the device lacks room |
| Free space on the device | The ZIP must fit on the state folder's drive with 1 GiB to spare; otherwise the job ends as `no_space` |
| Files listed | 200,000 |
| Files left out, listed by name | 10,000 |
| Packaging time | 100 minutes |
| Time to begin the upload | 2 hours after the device picks up the job |

The evidence quota, the two-jobs-per-device limit and the other evidence rules apply; see [RESPONSE.md](RESPONSE.md#storage-quota-and-limits).

## On the server

- A triage package is an evidence job with source `triage`; its path is the profile name and its query is the artifact types, comma-separated.
- An interrupted upload is not resumed, because a new package would differ; the job ends as `changed` and must be requested again.
- Custody entries name the source `triage package` and the artifact types.
- API: `GET /api/v1/triage-profiles` lists profiles; the owner adds one with `POST /api/v1/triage-profiles` (name and artifact types) and withdraws it with `POST /api/v1/triage-profiles/{id}/withdraw`. A collection is `POST /api/v1/cases/{case}/collect` with `source` `triage` and `profile`.

## Related

- [RESPONSE.md](RESPONSE.md): cases, evidence collection and chain of custody
- [EVENT-LOGS.md](EVENT-LOGS.md): exporting a single event log as `.evtx`
- [PERSISTENCE.md](PERSISTENCE.md): autostart report
- [HUNTING.md](HUNTING.md): fleet searches
