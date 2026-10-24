# File Browsing and Transfer

The **Files** tab lets the owner and permitted technicians browse a Windows device's local fixed drives, download single files from it and upload single files to it. Transfers use the agent's outbound mutual-TLS connection; the feature adds no listener, service or shell command on the device.

## Contents

- [Available drives](#available-drives)
- [Browsing](#browsing)
- [Downloading](#downloading)
- [Uploading](#uploading)
- [Limits and timing](#limits-and-timing)
- [Cancellation and unknown outcomes](#cancellation-and-unknown-outcomes)
- [Retention](#retention)
- [Turning it off](#turning-it-off)
- [Permissions and audit](#permissions-and-audit)
- [Security notes](#security-notes)
- [API routes](#api-routes)
- [Related](#related)

## Available drives

- The installed agent runs as SYSTEM and offers every local **fixed** drive (`C:`, `D:` and so on), at most eight, in letter order. Removable, network and optical drives are never offered. The drive list refreshes within a minute.
- A console (non-service) agent uses the permissions of the account that started it.
- Drive paths stay on the device. The server receives drive labels, read/write flags and opaque IDs bound to the local definition; queued work cannot be redirected by reusing an old ID.
- **OpenRMM's own folders are never reachable:** the agent program folder, `ProgramData\OpenRMM Agent` (state, logs, update journal and rollback package), `ProgramData\OpenRMM Agent Updater`, and for a console agent its state, log and executable folders. The check uses the resolved native path of every opened folder or file, so short names, alternate spellings or a renamed parent cannot reach them.

## Browsing

Open a device's **Files** tab (or **Files** in the console header).

- Select a drive, then choose **Refresh** to list the current folder. Open a listed folder to navigate.
- A listing is a snapshot at the time of the request, not a live view; refresh after changes on the device.
- Each listing returns at most **500 entries** and says when it was truncated. A truncated listing is incomplete: not finding a name does not prove it is absent. Choose a narrower folder if needed.
- Breadcrumbs and **Up one level** show an existing listing without asking the device again; a folder not listed yet shows **Not listed yet** until you refresh.
- **Filter this folder** is a literal, case-insensitive match with name, size and modified sorting; it never asks the device again.
- The browser keeps listings from its latest 50 requests; refresh again if a listing has dropped out.
- New actions stay disabled until the selected drive allows them and the device is ready. The server and the device still make the authoritative checks.
- The tab polls every ten seconds (faster while work is pending) and pauses while the page is hidden. Status updates are phase changes, not byte progress.

Not supported: creating folders, recursive copy or archive, deleting, renaming, overwriting and resumable transfers.

## Downloading

1. Choose **Download** on a file row. The device reads that single file.
2. When it completes, its **Transfers** entry offers the file and its SHA-256.

- Bytes are preserved exactly; files are served as `application/octet-stream` and never rendered.
- The device checks the file's size and modification time before and after reading. This is not an application-consistent snapshot of a file that is actively changing.
- Hard-linked files are refused for download.

## Uploading

1. Choose **Upload** and select a file. It is staged on the server, not yet sent.
2. The confirmation dialog shows the exact folder, file name, byte count and SHA-256. Confirm within **five minutes**, or cancel to discard it. Only the account that staged an upload can confirm it, and only while it still has write access.
3. The device rechecks the destination, writes a temporary file in the destination folder, flushes it and commits it as a **new** entry. An existing file is never replaced: if the name exists (even if created at the same moment), the result is **exists** and the existing file is kept.

- Uploading never runs the file, but consider which other programs pick up files from the destination folder.
- A changed body or destination cannot reuse a staged request.
- An interrupted upload may leave an internal `.openrmm-*.part` file in the destination folder. These files are hidden from the browser and never run. Remove an orphan only after making sure no transfer is running. Completed operations remove their temporary files.

## Limits and timing

| Limit | Value |
| --- | --- |
| File size | 8 MiB per file |
| Pending requests | 8 staged, queued or dispatched on the server; 1 per device |
| Server staging and reservations | 32 MiB in total (a download reserves its maximum size before dispatch) |
| Concurrent large transfer handlers | 2 |
| Upload confirmation window | 5 minutes after staging |
| Queued work | Expires after 1 minute |
| Dispatched work | Result due within 2 minutes; never redelivered automatically |
| File content | Unavailable 15 minutes after staging or request |

Transfers use the normal HTTP timeouts; a slow or interrupted transfer fails rather than silently resuming.

## Cancellation and unknown outcomes

- Cancelling staged or queued work proves it was never dispatched.
- Cancelling after dispatch, or a lost result, is **Unknown**: OpenRMM cannot prove whether an upload happened. Check the destination before making another request.
- A destination can remain created after a client or server crash; the no-overwrite rule still applies.
- Results explain conflicts, local denial, missing paths, changed files and expiry. Nothing is retried silently.

## Retention

- The **Transfers** panel lists the device's recent downloads and uploads with status, size and SHA-256.
- Request metadata (account, destination, timestamps, deadlines, content expiry, sizes, hashes and outcomes) is kept for up to **24 hours or 200 requests** across the server; each device shows its latest 50. Old listings may remain visible as history after a folder is gone.
- File content becomes unavailable 15 minutes after staging or request. A once-a-minute housekeeping sweep clears the stored content even without browser activity. A cached download stays available until then even if the device goes offline; it is not a new read from the device.
- Clearing content is not guaranteed physical erasure of SQLite free pages, journals, snapshots or older backups; protect the database and backups. There is no separate encryption at rest.
- A restore from backup clears file contents, results and cached folder listings, cancels staged and queued requests, marks dispatched work Unknown and never replays a transfer.

## Turning it off

File transfer is the agent feature **Files** (`files`), on by default. Switch it off in the device's monitoring policy (**Agent features → Files**), or lock it off on one device in an administrator PowerShell (a policy cannot override a lock; see [feature switches](WINDOWS-SERVICE.md#feature-switches)):

```powershell
.\scripts\service.ps1 -Action configure -FilesMode false
# Remove the lock:
.\scripts\service.ps1 -Action configure -FilesMode true
```

A console agent uses `-files=false` or `OPENRMM_AGENT_FILES=false`.

## Permissions and audit

- The owner has access. Technicians need the **Files** permission and the device in their scope. Read-only, service, process and remote desktop permissions do not grant file access.
- Queueing, dispatch, completion, confirmation and content retrieval each recheck the acting account. Revoked devices cannot return results or serve cached downloads.
- Confirmation and cancellation are deliberate requests that need the session's `X-CSRF-Token` header.
- File paths and hashes appear in metadata and audit records; file content never appears in logs.

## Security notes

- The Windows adapter uses [Go's rooted filesystem APIs](https://pkg.go.dev/os#Root) to confine operations to the selected drive, and also checks native final paths.
- Refused: reparse points at the drive root, symbolic links and junctions, hard-linked downloads, traversal, invalid path components, UNC/network/removable drives, alternate data streams, reserved device names (`CON`, `NUL`, `COM1`, …), OpenRMM's own `.openrmm-*` names, and protected names such as `.env` (and `.env.*`), `.ssh`, `.aws` and `.git`.
- Protected names can still be collected as case evidence by accounts with the Incident response permission; see [RESPONSE.md](RESPONSE.md#path-rules).
- This is containment within the drive, not isolation from other programs that already have local access to it.

## API routes

| Route | Purpose |
| --- | --- |
| `GET /api/v1/devices/{id}/files` | Drive availability and the retained request metadata. Does not read file bytes. |
| `POST /api/v1/devices/{id}/files` | Request a listing or a download. |
| `POST /api/v1/devices/{id}/files/upload` | Stage an upload. |
| `POST /api/v1/devices/{id}/files/{request}/confirm`, `/cancel` | Confirm or cancel a request. |
| `GET /api/v1/devices/{id}/files/{request}/download` | Fetch a completed download. |

## Related

- [RESPONSE.md](RESPONSE.md): case evidence collection and file drop
- [TERMINAL.md](TERMINAL.md): SYSTEM PowerShell terminal
- [DESKTOP.md](DESKTOP.md): remote desktop
- [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md): agent service and feature switches
