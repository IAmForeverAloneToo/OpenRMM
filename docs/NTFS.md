# NTFS Artifacts

An NTFS artifact package collects a Windows drive's file system metadata straight from the volume: the master file table (`$MFT`), the transaction log (`$LogFile`) and the USN change journal (`$UsnJrnl:$J`). The agent also turns `$MFT` and the change journal into timelines you can search in the browser or download as CSV. It is for responders with the Incident response permission.

## Contents

- [Overview](#overview)
- [Starting a collection](#starting-a-collection)
- [What happens on the device](#what-happens-on-the-device)
- [The package](#the-package)
- [Timeline columns](#timeline-columns)
- [Viewing a timeline](#viewing-a-timeline)
- [Hunts on whole drives](#hunts-on-whole-drives)
- [Limits](#limits)
- [Related](#related)

## Overview

- One ZIP per request with a folder per drive: the raw `$MFT`, `$LogFile` and `$J`, plus `mft.csv` and `usn.csv`, and a `manifest.json` with sizes, SHA-256 hashes, row counts and how each drive was read.
- The raw files open in the usual tools (MFTECmd, Timeline Explorer, analyzeMFT, LogFileParser); the timelines use the same column names as MFTECmd.
- The ZIP is uploaded, hashed and verified as one piece of case evidence, with the same custody logging as any [evidence collection](RESPONSE.md#evidence-collection).
- Deleted files whose MFT records are not reused yet appear in the `$MFT` timeline, and the change journal records recent creations, deletions and renames, including of files that no longer exist.

## Starting a collection

- **Case page:** **Evidence → Collect: NTFS artifacts**. Leave **Drives** empty for the system drive, or type drive letters (`C: D:`) or `all` for every fixed NTFS drive.
- **Live response console:** `ntfs` (system drive), `ntfs D:`, `ntfs C: D:` or `ntfs all`; see [RESPONSE.md](RESPONSE.md#built-in-commands).
- API: `POST /api/v1/cases/{case}/collect` with `"source": "ntfs"` and `"volumes"` (drive letters, or `["all"]`; empty for the system drive).

Only devices whose agent reports the `ntfs` ability accept the request; an older agent is refused until it updates.

## What happens on the device

1. The agent makes a Volume Shadow Copy of each drive and reads the copy's raw volume, so the raw files and the timelines show the same moment. If no copy can be made, it reads the live volume and the manifest says **live**; the timelines are then parsed from a second read moments later.
2. It copies `$MFT` (following its runs, also when the MFT is fragmented), `$LogFile`, and the allocated part of `$J`. The journal's earlier part is unallocated (sparse) on disk and is left out; `journal_offset` in the manifest says where the copy starts, and `usn.csv` gives each record's offset in the full stream.
3. It parses `$MFT` and the journal into `mft.csv` and `usn.csv`, building each path from the parent folders recorded in the MFT. A path whose folder was deleted and its record reused shows `<unknown>` as its folder.
4. Rows for OpenRMM's own files (the agent's program, data and log folders, and `.openrmm-*` files) are left out of the timelines and counted as excluded. The raw `$MFT` is copied whole, as it is on disk.

The agent reads the volume as SYSTEM through the Windows volume device; nothing is written to the drive except the temporary shadow copy, which is deleted afterwards. The package is built in the agent's state folder and must fit there, keeping 1 GiB free.

> [!NOTE]
> Small files (up to about 700 bytes) are stored inside their MFT record, so the raw `$MFT` holds their contents. Treat the package like any other evidence that may contain secrets from the device.

## The package

```text
manifest.json
C/$MFT
C/$LogFile
C/$J
C/mft.csv
C/usn.csv
D/...
```

The manifest lists, per drive: serial number, cluster and record size, `method` (`snapshot` or `live`) with the shadow copy's ID and time, each file's name, size and SHA-256, `journal_offset`, row counts, `damaged` (MFT records that did not decode, skipped) and `excluded`. A drive that could not be read is listed with an `error` (for example not a fixed NTFS volume) and the others are still collected.

## Timeline columns

`mft.csv`: `EntryNumber`, `SequenceNumber`, `InUse`, `ParentEntryNumber`, `ParentSequenceNumber`, `ParentPath`, `FileName`, `Extension`, `FileSize`, `IsDirectory`, `HasAds`, then four timestamps from `$STANDARD_INFORMATION` (`0x10`) and `$FILE_NAME` (`0x30`) each: `Created`, `LastModified`, `LastRecordChange`, `LastAccess`; then `SiFlags`, `NameType` and the record's `UpdateSequenceNumber` and `LogfileSequenceNumber`.

`usn.csv`: `Name`, `Extension`, `EntryNumber`, `SequenceNumber`, `ParentEntryNumber`, `ParentSequenceNumber`, `ParentPath`, `UpdateSequenceNumber`, `UpdateTimestamp`, `UpdateReasons` (such as `FileCreate|Close`), `FileAttributes` and `OffsetToData`.

Times are UTC with 100-nanosecond precision (`2026-10-30 12:00:00.0012345`). A `$STANDARD_INFORMATION` time earlier than the matching `$FILE_NAME` time can mean the times were changed (timestomping).

## Viewing a timeline

Select **View** next to the collection (case page or console results). The viewer pages through a drive's `$MFT` or change journal timeline on the server, 100 rows at a time, with filters:

- **Path contains** (case ignored);
- **From / To** (your local time): for `$MFT` any of the eight timestamps, for the journal the update time;
- **Deleted only**: MFT records not in use, or journal entries with `FileDelete`;
- **Reason** (journal).

Early pages come back quickly even for millions of rows; going far into a large timeline reads further each time. Download the CSV for sorting and pivoting in other tools. Opening the package and each CSV download are recorded in the custody log; paging is not recorded again.

## Hunts on whole drives

Indicator hunts with **Search files** on also read the MFT of every fixed NTFS drive and match name and path indicators against every file in use, not only the common locations. This needs no folder walk and is quick. Hash indicators are still checked only in the common locations, for files up to 100 MB. Matches found this way say "found in the MFT". See [HUNTING.md](HUNTING.md#what-the-agent-searches).

## Limits

| Limit | Value |
| --- | --- |
| Package size | The 16 GB evidence limit, and free space on the agent's drive minus 1 GiB |
| Building time | 100 minutes |
| Drives | Fixed NTFS volumes with a drive letter (not ReFS, FAT or removable drives) |
| Compressed or encrypted system streams | Not read (Windows does not compress `$MFT`, `$LogFile` or `$J`) |
| Viewer page | Up to 500 rows (100 by default) |

## Related

- [Incident response](RESPONSE.md)
- [Triage packages](TRIAGE.md)
- [Hunting](HUNTING.md)
