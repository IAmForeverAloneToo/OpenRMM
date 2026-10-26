# Incident Response

OpenRMM includes forensic live response for responders: cases with a tamper-evident chain-of-custody log, verified evidence collection, structured response actions and a live response console on the device's SYSTEM PowerShell terminal. This guide is for owners and technicians who investigate incidents and for operators who run the evidence store.

> [!NOTE]
> OpenRMM is a response tool, not a detection or prevention product. It helps a responder investigate and contain an endpoint; it does not judge or flag anything as malicious.

## Contents

- [Principles](#principles)
- [Permissions](#permissions)
- [Cases and chain of custody](#cases-and-chain-of-custody)
- [Evidence collection](#evidence-collection)
- [Response actions](#response-actions)
- [Live response console](#live-response-console)
- [Recorded terminal](#recorded-terminal)
- [Custody entries](#custody-entries)
- [Response job rules](#response-job-rules)
- [Feature switch](#feature-switch)
- [Threat model](#threat-model)
- [Related](#related)

## Principles

- **One SYSTEM agent.** Response capabilities run in the installed Windows agent as LocalSystem, like every other feature. They are on by default and can be switched off per monitoring policy or locked off on a device.
- **Every case action is a custody entry**: who, when (UTC), on which device, with which parameters, which evidence (hash and size) and the outcome. Live response commands run without a case are recorded in the audit log instead (see [Without a case](#without-a-case)).
- **Hash on the device, verify on the server.** Collected data is hashed while it is read on the device and verified again on the server before it is accepted.
- **Read-only by default.** Collection does not change the item where Windows allows it; actions that change the device (kill, file drop, scripts) record what changed.
- **Order of volatility.** Responders should collect in the order of RFC 3227 and NIST SP 800-86: memory and live state first, then processes, network state, signed-in users, temporary files, disk contents, logs and archival data. The responder chooses what to collect.
- **The server is trusted.** Whoever administers the server can do anything the product can do. The design limits damage from other compromises and makes later tampering detectable (see [Threat model](#threat-model)).

## Permissions

| Who | Can do |
| --- | --- |
| Owner | Everything below, plus managing the tool library and triage profiles. |
| Technician with **Incident response** (`response`) | See and work on **all** cases, whatever their device scope: open, add notes, close, reopen, export the custody log, list collections, download evidence. |
| Technician with `response` **and** access to the device | Collect evidence, run response actions, and open the live response terminal on that device. |
| Other technicians | No access to cases, evidence or live response. Read, desktop, files or services permissions do not imply it. |

- Permission and device access are checked when a job is requested **and** again when the device picks it up; a technician who lost either in between gets the job failed as `not_permitted`.
- No step-up MFA is asked for response actions. The compensating controls are the permission, case binding, the append-only custody log that names the account, and session expiry. Grant `response` only to technicians who investigate incidents.
- The custody log names technicians by a stable ID (`technician:<id>`), so renaming an account does not change the chain; the case page shows the current username next to it.
- See [TECHNICIANS.md](TECHNICIANS.md) for granting permissions.

## Cases and chain of custody

### Cases

- A **case** has an ID, a title (1–200 bytes of UTF-8, no line breaks or leading or trailing spaces), a status (open or closed), who opened it and when.
- Cases are closed, never deleted; a database trigger refuses deletion. A closed case accepts no entries until it is reopened, except evidence downloads (see [Downloads](#downloads)).
- Case-level actions recorded in the log: `case_opened`, `note`, `case_closed` (with an optional reason) and `case_reopened`.
- A case cannot be closed while any of its collections, actions or recorded terminal sessions is unfinished (queued, dispatched, uploading or verifying, or a transcript still recording or waiting to be stored). Searches still waiting for a device are cancelled automatically when the case is closed; cancel the rest or let them finish first. This guarantees that every job's end is recorded in its open case.

### Custody log format

- Each entry is stored as its exact JSON text with: version, case ID, sequence (1, 2, …), UTC time with nanoseconds, actor, device ID (empty for case-level actions), action, details (text values, keys sorted), evidence (SHA-256, size, name), outcome and the previous entry's hash.
- **Hash:** lower-case hex SHA-256 of the previous entry's hash, a newline and the entry text. The first entry's previous hash is 64 zeros. The newest hash is the case's **head**.
- Entries are append-only: database triggers refuse updates and deletes. The server re-verifies the whole chain whenever a case is opened and shows a warning if it does not verify.
- The custody log is separate from the bounded audit log, which keeps only the newest 1,000 events.
- Record the head hash outside OpenRMM (ticket, e-mail) at any time; it lets you detect a later rewrite of the chain.

### Exporting and verifying

**Export custody log** on the case page (`GET /api/v1/cases/{id}/custody.json`) downloads an export in format `openrmm-custody-export`, version 1, with the case header, every entry's text and hash, and the head.

Verify an export offline with the `openrmm-custody` tool, which needs no server, network or credentials:

```powershell
# Built by scripts/build.ps1 into dist\windows-amd64
.\dist\windows-amd64\openrmm-custody.exe verify .\custody.json
```

It checks that every entry belongs to the case, is numbered without gaps, names the previous entry's hash and matches its own hash, and that the last hash equals the recorded head. It prints the head, which should match a head recorded earlier. Exit code 0 means the chain is intact, 1 means it is not or the file is invalid.

## Evidence collection

From an open case, collect a file, an alternate data stream, a registry hive, an event log export or a triage package from one device. The file is read on the device, uploaded in chunks, verified on the server and stored by its SHA-256 in a separate evidence store.

### Requesting a collection

- Use the **Evidence** panel on the case page (`POST /api/v1/cases/{case}/collect` with `device_id` and `path`, or a `source`), or the `get`, `hive`, `evtx` and `triage` commands of the [live response console](#live-response-console).
- The device must exist, not be revoked, and have **Incident response** switched on (see [Feature switch](#feature-switch)). This is checked on request and again on pickup.
- A closed case refuses new collections.
- Other sources have their own guides: event log exports in [EVENT-LOGS.md](EVENT-LOGS.md) and triage packages in [TRIAGE.md](TRIAGE.md).

### How a collection runs

1. **Request.** The server checks the path shape and limits, creates the job as **queued** and appends `collection_requested` to the custody log in the same transaction.
2. **Dispatch once.** An agent with the feature on asks for work every 15 seconds over its mutual-TLS connection. The server re-checks permission, device access and the feature switch, then hands out the oldest queued job for that device once and marks it **dispatched**. The job carries the path, the chunk size (8 MiB), the largest allowed size (16 GiB) and a start deadline five minutes later.
3. **Open.** The agent works on one collection at a time. It opens the file read-only under the [path rules](#path-rules) and refuses a file larger than the limit. A refusal ends the job (`denied`, `not_found`, `too_large` or `failed`). Deadlines are enforced by the server's clock only.
4. **Start.** The agent sends the size, the file times and the resolved final path. The server refuses a start after the five-minute window, checks the [quota](#storage-quota-and-limits), records the details, creates an empty upload file and marks the job **uploading**.
5. **Chunked upload.** The agent reads the file once, in order, hashing each chunk and the whole file. The server accepts a chunk only if its length is exactly right for its position and its SHA-256 matches; it writes the chunk at its offset and syncs it to disk. A chunk it already holds is accepted without writing again if the hash is the same and refused if it differs.
6. **Finish.** After the last chunk, the agent checks that the file's size and modification time did not change and that nothing follows the announced size; otherwise it reports `changed`. If the file is unchanged, it sends the size and whole-file SHA-256. The server accepts this only when the size matches and every chunk has arrived, and marks the job **verifying**.
7. **Whole-file verification.** A server worker verifies one upload at a time (fewest attempts first, so one problem job does not block others). It compares size and SHA-256 with the device's values:
   - a difference fails the job (`hash_mismatch`); a missing upload fails it (`missing_upload`);
   - a read or storage error is retried, and after five failed attempts the job fails (`verify_failed`);
   - on a match the file is moved into the content-addressed store, the job becomes **succeeded** and `evidence_collected` is appended. Identical content already stored is reused only after it has been hashed again and still matches.

Per-chunk hashes are checked on arrival but not kept; the custody entry records the number of chunks and both whole-file hashes.

### How files are read

The `method` metadata records how the agent read a file:

| Method | When |
| --- | --- |
| `read` | Normal read as SYSTEM. |
| `backup` | Access was denied: the file is opened with the backup privilege, which bypasses permissions. |
| `shadow_copy` | Another program holds the file exclusively (sharing violation). The agent describes the live file through an attributes-only handle, makes a temporary Volume Shadow Copy of the drive (WMI `Win32_ShadowCopy` through Windows PowerShell), reads the file from it and deletes the copy. |
| `registry_save` | A loaded registry hive saved with `RegSaveKeyEx`. |
| `export`, `triage` | Event log exports and triage packages. |

- **The backup privilege is never enabled for the whole agent**, only on an impersonation token of the one thread doing a backup open or hive save, and it is dropped right after.
- **Privileged opens are path-checked.** A file opened by full path (backup or shadow copy) must resolve to exactly the requested path (a junction or 8.3 short name anywhere on the path is refused), must be a regular file, and all of its hard links must be outside OpenRMM's folders. A file read from a shadow copy must be at the same place inside the copy and have the same file number as the checked live file, so a junction swapped in while the copy is made is refused.
- **Shadow copy leftovers.** The copy's ID is written to a ledger (`evidence-shadows.json` in the agent's state folder) as soon as it exists; a copy left by a crash is deleted when the agent's evidence worker next starts.
- Whether reading a file updates its last-access time depends on the Windows last-access setting; the agent reads all file times before reading the content.

### Recorded metadata

The agent sends, and the server checks and writes into the `evidence_collected` entry:

- `file_modified`, `file_created`, `file_accessed` and `file_changed` (the MACB times; creation time only on Windows), `attributes`, `owner` and `owner_sid`, `method`;
- for a shadow copy, `shadow_copy` (its ID) and `shadow_copy_at`; times and owner are the live file's, the content is the copy's;
- `streams`: every alternate data stream (up to 64) as `name size sha256`. Only streams up to 1 MiB are hashed, so a planted huge stream cannot stall a collection; a larger one shows `not_hashed`, one that could not be read `unreadable`. Collect a large stream by path to hash it.

### Alternate data streams

- Collect a stream by path, for example `C:\Users\alice\Downloads\file.txt:Zone.Identifier` (also `file.txt:stream:$DATA`).
- After a file is collected, each hashed stream up to 1 MiB (at most 16) is queued as its own collection, requested by the same account, with a `collection_requested` entry by `system` naming the parent (`stream_of`). Streams that were not queued are listed in `streams_not_queued`.
- These follow-up collections do not count against the two collections per device but do count against the server's 20.
- Streams of a file read from a shadow copy are not queued (each would need its own copy).
- A downloaded stream is named `file.txt_stream`.

### Registry hives

- Choose the hive source with `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`, or a user's `NTUSER:<profile or SID>` or `USRCLASS:<profile or SID>`.
- The user's profile is found in `ProfileList`; stale `.bak` entries are ignored, and a folder name shared by several profiles is refused (use the SID).
- A loaded hive is saved with the backup privilege into `evidence-temp` in the agent's state folder, collected and deleted. Its resolved path is the registry path, such as `HKLM\SYSTEM`, and no file times are recorded.
- A user hive that is not loaded (the user is signed out) is collected as its file under the file rules.
- Downloads are named like `hive-SYSTEM.dat` or `hive-NTUSER-alice.dat`.

### Path rules

The server accepts only an absolute local Windows path: drive letter, colon and backslash (`C:\...`), no doubled or trailing backslash, no leading or trailing spaces, no control characters, none of `/ < > " | ? *`, at most one further colon (naming a stream), and at most 1,024 bytes (UTF-8). The agent then applies the same rules as [file transfer](FILES.md), except that protected names are allowed:

- Windows only, and only local **fixed** drives (no removable, network or optical drives, no UNC paths). At most 1,000 bytes after the drive and 200 bytes per name.
- Every part of the path must be a valid name: not `.` or `..`, not ending in a dot, not a reserved device name (`CON`, `NUL`, `COM1`, …) and not OpenRMM's own `.openrmm-*`.
- Names that file browsing protects (such as `.env`, `.ssh`, `.aws` and `.git`) **can** be collected as case evidence.
- No symbolic links, junctions or other reparse points anywhere on the path. The target must be an ordinary file and its resolved final path must stay on the same drive.
- A file with several hard links (common for System32 files, which are linked into WinSxS) is collected only if none of its names is inside OpenRMM's own folders; if its names cannot be listed, it is refused.
- OpenRMM's own folders are refused: the agent's state, log and program folders and, in the installed service, its data and updater folders.

### Resume after interruptions

- Start and finish requests have a two-minute deadline, chunk uploads five minutes. A failed request is retried with a growing pause (2 seconds, doubling to at most a minute) for up to ten minutes. Retries stop at once when the server refuses the job or the request, or rejects or revokes the device.
- The server keeps every chunk it has verified. If the agent repeats the start with the same size, resolved path and modification time (and, for privileged reads, the same method and shadow copy), the server returns the chunks it holds and the agent skips uploading them.
- **Across agent restarts:** an upload with no activity for three minutes is handed to its device again on its next poll. This covers a service restart, an agent update and a feature settings change. If the file's details differ, the job fails as `changed`.
- A shadow-copy or hive collection interrupted by an agent restart is read again from a new copy or save, so it ends as `changed` and must be requested again.
- If the start or upload still fails after the retries, the agent reports `failed`, which frees the device's slot.

### Outcomes

| Outcome | Status | Meaning |
| --- | --- | --- |
| `denied`, `not_found`, `too_large`, `changed`, `failed` | Failed | Reported by the agent. `denied` covers the path rules and access denied. `failed` also means the start or upload did not succeed within the agent's retries. The server also sets `changed` when a resumed start reports different file details. |
| `no_space` | Failed | Not enough disk space on the device for a staged export or package. |
| `response_off` | Failed | Incident response was switched off when the device asked for the job. |
| `not_permitted` | Failed | The requesting account no longer had the permission or device access at pickup. |
| `withdrawn` | Failed | A file drop whose library tool was withdrawn before pickup. |
| `quota` | Failed | The start would exceed the evidence quota. |
| `hash_mismatch` | Failed | Whole-file size or SHA-256 differs from the device's. |
| `missing_upload` | Failed | The upload file was missing at verification. |
| `verify_failed` | Failed | The server could not read or store the upload in five attempts. |
| `expired` | Expired | Still queued an hour after the request (device offline, feature off, older agent, or other collections still running on the device). |
| `no_response` | Failed | Dispatched but not started within the start window. |
| `stalled` | Failed | Uploading with no progress for 30 minutes. |
| `unknown` | Failed | A device-changing action (kill, drop, script) was handed out but its result never arrived. Check the device before repeating it. |
| `cancelled` | Cancelled | Cancelled while queued, dispatched or uploading. A collection being verified cannot be cancelled. |
| `server_restore` | Failed | Unfinished when the server was restored from a backup (see [RECOVERY.md](RECOVERY.md)). No custody entry is written. |

Server housekeeping applies the timeouts once a minute. A job is ended only if it is still in the status it was read in, so a job that has just moved on is never overwritten. A failed, expired or cancelled job deletes its partial upload.

### Downloads

- **Download** on a collected item (`GET /api/v1/cases/{case}/collections/{job}/file`). The server checks that the stored file exists and has its recorded size, appends `evidence_downloaded` naming the account, and only then sends the file with its SHA-256 in the `X-Content-SHA256` header.
- The file is not re-hashed on download; check the hash after downloading. A missing or wrong-size stored file is refused with a message to check the evidence volume.
- Downloads are recorded in **closed cases too**; the case stays closed.
- One entry per download: every GET that can return the first byte is recorded (no `Range` header, a range starting at byte 0, a suffix range such as `bytes=-N`, or an unrecognised header). HEAD requests and later ranges of a resumed download are not recorded again.
- A download may stream for up to 12 hours.

### Storage, quota and limits

Evidence is stored outside the database in its own directory:

| Setting | Flag / variable | Default |
| --- | --- | --- |
| Evidence directory | `-evidence-dir` / `OPENRMM_SERVER_EVIDENCE_DIR` | `.local/evidence`; with Docker Compose the `evidence` volume at `/evidence` |
| Evidence quota (whole GiB, 0–1048576; 0 = no quota) | `-evidence-quota-gb` / `OPENRMM_SERVER_EVIDENCE_QUOTA_GB` | `100` |

- Uploads in progress are `incoming/<job>.part`; stored files are `sha256/<first two hex digits>/<sha256>`, read-only (0400) in owner-only directories (0700). Case-less live response results are kept in `scratch/<job>`.
- **Content-addressed:** identical content is stored once, whichever case or device it came from.
- **Never pruned automatically,** and OpenRMM has no function to delete case evidence. Server backups do not include evidence: export it with `install.sh backup --evidence` and add it back with `install.sh restore-evidence`; see [RECOVERY.md](RECOVERY.md).

| Limit | Value |
| --- | --- |
| Per file | 16 GiB (17,179,869,184 bytes; "16 GB" in the dashboard) |
| Chunk size | 8 MiB; each chunk must arrive within five minutes, so a link slower than about 28 KB/s cannot upload |
| Unfinished collections and actions | 2 per device, 20 per server; the agent works on one collection at a time |
| Queue life | 1 hour |
| Server request slots | Start, chunk and finish requests share 8 slots (a busy server answers 429 and agents retry); file drop downloads use 4 separate slots; polls are outside these slots |
| Quota check | Once, when an upload starts: stored files plus uploads in progress or verifying, plus the new file, must fit. Identical content already stored still counts while it uploads. Free disk space is not checked. |

## Response actions

Response actions run on the device as evidence jobs. The agent writes a result document (`openrmm-response-action`, version 1, JSON) into its private state folder and uploads it through the verified evidence upload, so it is hashed, verified and stored like a collected file. The document is removed from the device after the upload; one left by an ended job is removed after a week.

- Run them from the case's **Evidence** panel (`POST /api/v1/cases/{case}/actions`) or the live response console. They need the `response` permission, device access, an open case (or a case-less console session) and **Incident response** on the device.
- Open a result with **View** (a download, recorded in the custody log). The viewer can kill processes and read subkeys.
- An action runs for at most 20 minutes, and the server waits 30 minutes for its result to start uploading.

### Read-only actions

| Action | Result |
| --- | --- |
| `processes` | PID, parent, name, start time, image path, command line, user and SID, session, SHA-256 of the image (cached per file with the same size, modification and change time; images over 512 MB are not hashed) and whether it may be killed. |
| `connections` | TCP and UDP, IPv4 and IPv6, with addresses, ports, state and owning process. |
| `services` | Services and drivers with state, start type, type, account, command line, image and its SHA-256, and a shared service's DLL and its SHA-256. |
| `tasks` | Every scheduled task definition under `%SystemRoot%\System32\Tasks` (read as files, no COM): path, enabled, hidden, author, description, principal and run level, triggers, actions, file time and SHA-256. Run history is not included. |
| `registry` | One key under HKLM, HKU or HKCR: last write time, subkeys (with last write times) and values (strings, numbers, multi-strings; anything else as hex, at most 4 KiB per value), at most 1,000 each. Read with the backup privilege when access is denied. Keys with leading or trailing spaces in their names can be read too. |
| `persistence` | Autostart entries with resolved programs, hashes and signatures; see [PERSISTENCE.md](PERSISTENCE.md). |

Network files are never opened for hashing: UNC and WebDAV paths and mapped network drives are skipped, because opening them as SYSTEM would make the computer account authenticate to whoever named the path.

### Killing processes

- `kill` ends the named process, or with **tree**, every descendant as well (processes whose parent is in the tree and that started after that parent), deepest first and the named process last, at most 1,024 (a larger tree is noted and the rest left running).
- The PID, start time and name must still match, so a reused PID is refused. Every image is hashed fresh before anything ends.
- Refused: processes Windows marks critical, OpenRMM's own processes and the agent, and protected Windows names (`lsass`, `csrss`, `svchost`, `dwm`, …) **when they run from the system folder** (System32 or SysWOW64). A disguised `svchost.exe` in another folder can be killed. (The RMM [process view](PROCESSES.md) refuses those names anywhere.) A refused named process ends nothing.
- `msiexec.exe` can be killed; the agent's self-update rolls back an interrupted install.
- Per-process outcomes: `succeeded`, `exited` (it ended on its own first), `denied`, `not_found`, `identity_changed`, `failed`.

### Tool library and file drop

- **Tool library:** the owner adds tools (**Cases → Tool library**, `POST /api/v1/response-tools`, multipart, at most 4 GiB) and withdraws them. Tools are stored by SHA-256 in the evidence store and count toward its quota; a tool upload whose declared size exceeds the quota is refused before it is written. Everyone with `response` sees the library. A withdrawn tool cannot be dropped; its file stays, as custody entries may name it. Adding and withdrawing are audited.
- **File drop** (`drop`): writes a library tool or a file already collected in the same case to the device. The server fills in the file's name, SHA-256 and size, so the spec names exactly what is written. The agent downloads it over mutual TLS (resumable), writes it to a temporary file in the destination folder, checks size and hash, then commits it:
  - create-only by default (an existing file is refused as `exists`);
  - with **overwrite**, the old file's SHA-256 is recorded just before it is replaced;
  - the written file is read back and must have the expected hash (`verified`).
- The destination folder must exist and be a real folder on a local fixed drive (no links on the way), outside OpenRMM's folders; streams are not allowed.
- Outcomes: `written`, `exists`, `denied`, `not_found`, `hash_mismatch`, `failed`.
- A drop's start window is the 30-minute action window plus time for a 512 KiB/s download of the file.

### Response scripts

- Run a library script (by version; the server copies its body, parameters and time limit into the spec) or a script typed into the case (default name "Case script", 5–300 seconds, default 60, body at most 64 KiB).
- Scripts run once as SYSTEM in the agent's contained script runner (kill-on-close Job Object, 16 processes, 512 MiB), like RMM [scripts](SCRIPTS.md).
- The result holds the body's SHA-256, arguments, outcome, exit code and output (stdout and stderr, at most 64 KB each, `truncated` beyond). For more output, have the script write a file and collect it.
- Drops and scripts are governed only by the device's **Incident response** feature; the local **Scripts** and **Files** locks do not apply to them.

### Run once

- The agent's response journal and the kept result document make a resumed job upload the same result instead of running again. An agent that stops while uploading keeps both and resumes.
- A device-changing job (kill, drop, script) handed out again is marked `resumed`, so even an agent that lost its journal does not run it again; it uploads a kept result or reports `unknown`. Such a job refused when handed out again (switch turned off, access removed) is also `unknown`.
- An action already handed to the device cannot be cancelled. Cancelling needs access to the job's device.

### Other response features

- [TRIAGE.md](TRIAGE.md): one ZIP of many forensic artifacts.
- [EVENT-LOGS.md](EVENT-LOGS.md): `.evtx` export of a channel.
- [HUNTING.md](HUNTING.md): fleet log search and indicator hunts.
- [ISOLATION.md](ISOLATION.md): network isolation of a device.

## Live response console

The device's SYSTEM PowerShell [terminal](TERMINAL.md) is the live response session: a shell plus a command bar of built-in response commands. There is no separate response shell.

### Starting a session

- On the device page, select **Live response** and choose no case, an open case or a new case title (`POST /api/v1/devices/{id}/terminal` with `{}`, `{"case_id": …}` or `{"case_title": …}`).
- On a case page, **Open live response** opens it on the device chosen in the evidence form.
- Technicians need the `response` permission and access to the device. The device's **Terminal** feature must be on; the built-in commands also need **Incident response**.

### Built-in commands

Type commands in the command bar under the shell (`POST /api/v1/terminal/{session}/command` with `{"line": …}`). Anything else is typed into PowerShell.

| Command | Does |
| --- | --- |
| `help` | Lists the commands. |
| `ps` | Process list with command lines, users and image hashes. |
| `kill <pid> [-tree]` | Ends a process or its tree. Needs a `ps` from the last 30 minutes. |
| `netstat` | TCP/UDP connections with owning processes. |
| `services` | Services and drivers with binaries and hashes. |
| `tasks` | Scheduled tasks. |
| `persistence` | Autostart entries; see [PERSISTENCE.md](PERSISTENCE.md). |
| `reg query <key>` | Reads a registry key under HKLM, HKU or HKCR (long root names accepted). |
| `get <path>` | Collects a file (`path:stream` for a stream). |
| `hive <name>` | Collects a hive: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`, `NTUSER:<user>`, `USRCLASS:<user>`. |
| `evtx <channel> [<xpath>]` | Exports an event log as `.evtx`; see [EVENT-LOGS.md](EVENT-LOGS.md). |
| `triage [<profile>]` | Collects a triage package (default **Full triage**); see [TRIAGE.md](TRIAGE.md). |
| `put <tool> <path> [-overwrite]` | Writes the newest non-withdrawn library tool with that name to the device. |
| `run <script> [Name=Value ...]` | Runs the library script with that name as SYSTEM; arguments are checked. |
| `hunt [-files] <indicator ...>` / `hunt [-files] -list <name>` | Searches this device for indicators; see [HUNTING.md](HUNTING.md). |

- Paths with spaces go in double quotes; a doubled quote inside is a literal quote. A command line is at most 8,192 bytes.
- Each command maps onto the corresponding case action or collection, with the same validation, limits, feature switch and two-jobs-per-device rule.
- `kill` takes the process's start time and name from the device's latest successful process list of the last 30 minutes, so a reused PID is never hit. The result viewer's **Kill** adds `-start <stamp>` from the row being viewed, and the command is refused when the newest list has a different process under that PID.
- A command counts as activity for the 15-minute idle limit, like typing in the shell.

### With a case

Commands are queued into the case exactly like the case page's actions and collections (custody entries, hashed evidence), and the shell is recorded as a [transcript](#recorded-terminal).

### Without a case

- Jobs belong to a built-in record (`00000000000000000000000000000000`) that is never listed or reachable as a case.
- Each step is an audit event (`live_` plus the custody action name, for example `live_action_requested`) instead of a custody entry. These events are kept for a year, outside the audit log's rolling 1,000-event limit.
- Results are verified like evidence but kept in `scratch/<job>` of the evidence directory, not in the content-addressed store. They are deleted after 24 hours (job status `expired`, outcome `purged`) and count against the evidence quota until then. The job rows (actor, device, action spec, times, hashes) stay in the database.
- The shell itself is not recorded.

### Attaching a case later

**Attach to case** in a running session (`POST /api/v1/terminal/{session}/case` with `{"case_id": …}` or `{"case_title": …}`) starts the transcript from that moment and sends later commands to the case; earlier results stay case-less. A session is attached at most once. A case created for an attach that fails is closed again with a note.

### Results

- `GET /api/v1/terminal/{session}/jobs` and `/jobs/{job}/file` list and read the session's results, only for the account that ran them and only while it may still access the device, also after the session ended (case-less results until they are purged).
- Reading a case result this way is a custody-logged download like any other.
- The page shows each result with **View** (its Kill and subkey Read buttons send console commands) and **Download**.
- A command not yet running on the device (a collection until its upload finishes) can be cancelled (`POST /api/v1/terminal/{session}/jobs/{job}/cancel`, same account only).

## Recorded terminal

A live response session with a case is recorded. The terminal header shows **Recorded**.

- **Preconditions:** the case is open, the evidence store is configured and the evidence quota has room for a whole session (48 MiB); otherwise no terminal starts.
- **Who reads it:** everyone who can see cases (the owner and technicians with `response`), even for devices outside their scope. A transcript holds everything typed and shown, including any secret typed into the shell. **Avoid typing secrets in a recorded terminal.**
- **What is recorded:** the server relays every keystroke and output chunk and records them itself, with the server's UTC time (millisecond precision), as JSON lines: output chunks (`out`), input when it is handed to the agent (`in`), and input still queued when the session ended, which never reached the device (`dropped`). Input is handed over only after it is in the transcript. The first line names the format (`openrmm-terminal-transcript`, version 1), case, device, session, account and start time; the last line gives the end reason and the byte counts. Valid UTF-8 is stored as `text`, anything else as `b64`. Pasted text is recorded as sent after confirmation.
- **Not recorded:** what the shell does beyond its output (child processes, file changes) and the browser-side rendering. `in` means the input was put in a reply to the agent; if that reply was lost, the device never got it (input is never re-sent).
- **Recording failure ends the session.** If a line cannot be written (for example a full evidence volume), the session ends with `recording_failed`; it never continues unrecorded.
- **Integrity:** the recorder keeps a running SHA-256. When the session ends, the file is hashed again and compared; a difference means the file changed on the evidence volume while open, and the transcript's custody entry gets outcome `hash_mismatch` with both hashes.
- **Storage:** the transcript is stored content-addressed and listed in the case's evidence as **Terminal transcript**, downloadable as `terminal-<job>.jsonl` with the usual download logging. If storing fails, the server retries every minute.
- **Server stop:** a transcript left open is stored at the next server start with reason `interrupted` and outcome `unverified`. If its file is gone, the job fails as `missing_upload`. A restore from backup ends it as `server_restore` without a custody entry.
- A recording does not count against the two collections per device, is never handed to the agent and cannot be cancelled. While it records or waits to be stored, the case cannot be closed.

## Custody entries

All job entries carry the device ID; details are text values.

| Action | Actor | Details | Evidence | Outcome |
| --- | --- | --- | --- | --- |
| `collection_requested` | requesting account (`system` for a queued stream) | `job`, `path`, source details | none | `success` |
| `evidence_collected` | `system` | `job`, `path`, `resolved_path`, `requested_by`, `device_sha256`, `server_sha256`, `chunks`, file times and the [metadata](#recorded-metadata) | SHA-256, size, file name | `success` |
| `collection_failed` | `system` | `job`, `path`, `reason` | none | the reason |
| `collection_expired` | `system` | `job`, `path`, `reason` | none | `expired` |
| `collection_cancelled` | cancelling account | `job`, `path` | none | `cancelled` |
| `evidence_downloaded` | downloading account | `job` | SHA-256, size, file name | `success` |
| `action_requested` | requesting account | `action` label and full `spec` (including a script body or a dropped file's hash and destination) | none | `success` |
| `action_completed` | `system` | the action and hashes; for a kill, every process as `pid name started start outcome sha256` in `killed`; for a script `script_sha256`, `script_outcome`, `exit_code`; for a drop `drop_outcome`, `drop_path`, `drop_sha256`, `verified`, `replaced_sha256` | result document | `success` |
| `action_failed`, `action_expired`, `action_cancelled` | `system` or cancelling account | the reason | none | the reason |
| `terminal_opened` | the account | `session`, `job` | none | `success` |
| `terminal_transcript` | `system` | `job`, `reason`, `inputs`, `dropped_inputs`, `output_bytes`, `verification` (and `recorder_sha256` on a mismatch) | SHA-256, size, name | `success`, `hash_mismatch` or `unverified` |

Parameters that matter for reproduction (paths, filters, limits) are recorded as details; secrets are never recorded deliberately (but see the transcript warning above).

## Response job rules

Every response job (collections, actions, exports, packages, hunts, isolation) follows these rules:

- **Device-bound.** The server stores the device with the job, hands it out only to that device over its mutual-TLS channel and names the device in the job; the agent refuses a job for another device.
- **Expiring.** The server enforces every deadline (queue life, start window, stall time) with its own clock; the agent does not drop jobs on its own clock.
- **Single use.** The server hands a job out once; an interrupted upload may be handed to the same device again to resume it.
- **Response journal.** The agent keeps `response-journal.json` in its private state folder (SYSTEM-only in the installed service) with every job it started and the result of every job it finished, written atomically before the result is sent. A job ID seen again is never run again: a finished job's recorded result is sent again; a started job resumes only if its kind is resumable; the same ID for another kind is refused. Entries are kept 30 days (at most 10,000). A journal that cannot be read stops response work on the device until it is repaired or removed, rather than risk running a job twice.
- **No extra job signature.** Jobs travel only inside mutual TLS from the trusted server; a signature would protect only against a tampered relay, which TLS already covers.
- **Checked twice.** Permission, device access and the feature switch are checked on request and again at pickup.
- **Ended with a custody entry**, including failures, expiry and cancellation, with the reason (except `server_restore`).

## Feature switch

Evidence collection and response actions are the agent feature **Incident response** (`response`). It is on by default, independent of **Files**, and can be:

- switched off in the device's monitoring policy (**Agent features → Incident response**), or
- locked off on the device in an administrator PowerShell; a policy cannot override a lock:

```powershell
.\scripts\service.ps1 -Action configure -ResponseMode false
# Remove the lock:
.\scripts\service.ps1 -Action configure -ResponseMode true
```

The lock is the `response` DWORD 0 under `HKLM\SOFTWARE\Policies\OpenRMM\Agent`. A console agent uses `-response=false` or `OPENRMM_AGENT_RESPONSE=false`. See [feature switches](WINDOWS-SERVICE.md#feature-switches).

When it is off, the agent runs no response worker and reports the lock, and the server refuses new jobs for that device. Turning it off restarts the agent's work, which interrupts an upload in progress; unfinished jobs then end by the timeouts (`expired` or `stalled`). Only a job the device asks for before it has applied the change fails at once as `response_off`.

## Threat model

### Assets

1. Endpoints and the data on them.
2. Device identities (agent certificates and keys) and the agent's SYSTEM rights.
3. Owner and technician accounts and browser sessions.
4. Evidence files and the custody log.
5. The server, its database, keys and backups.

### Compromised endpoint

An attacker with SYSTEM or administrator rights on a device controls what the agent sees and reports. Data collected from such a device can be incomplete or false, and the attacker can stop or alter the agent.

- Evidence is hashed on the device and again on the server; this proves what was received, not that the device told the truth.
- A compromised device cannot reach other devices through OpenRMM: its certificate authorizes only its own jobs and reports, and jobs are bound to one device.

### Compromised agent identity

A stolen device certificate and key lets an attacker impersonate that one device: send false reports and receive that device's jobs, including scripts and terminal sessions meant for it.

- Identity is per device; revoking the device stops it at once.
- Response jobs are device-bound, expiring and single-use, with the durable response journal on the device. A captured job cannot be replayed on another device or twice on the same one.

### Stolen browser session

An attacker with a signed-in browser session can act as that account until the session ends.

- Sign-in requires a password and TOTP; sessions expire; changes need the session's CSRF token and same-origin requests.
- Response actions need the `response` permission and (except case-less live response) an open case. There is no step-up MFA, so a stolen session can use response features within the account's permissions; every action is still recorded under that account.

### Compromised server

Accepted risk: an attacker with control of the server, or its administrator, can issue any job to any device, read all evidence and rewrite the database.

- The custody log makes **later** tampering detectable: entries are hash-chained per case, database triggers refuse changes and deletion, and the head hash can be recorded outside OpenRMM at any time. An export can be verified offline with `openrmm-custody verify`.
- A full-server attacker can still rebuild a consistent chain; only head hashes recorded elsewhere, or earlier exports, reveal that.
- Backups and evidence exports contain the database, keys and evidence; protect them like the server.

## Related

- [TERMINAL.md](TERMINAL.md): the PowerShell terminal behind live response
- [TRIAGE.md](TRIAGE.md), [PERSISTENCE.md](PERSISTENCE.md), [EVENT-LOGS.md](EVENT-LOGS.md): further collection sources
- [HUNTING.md](HUNTING.md) and [ISOLATION.md](ISOLATION.md): fleet hunts and network isolation
- [RECOVERY.md](RECOVERY.md): backing up and restoring the evidence volume
- [TECHNICIANS.md](TECHNICIANS.md): granting the Incident response permission
