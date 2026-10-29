# Windows Update Management

OpenRMM can scan a Windows device for software updates, install selected updates and request a restart, using the Windows Update Agent (WUA) on Windows x64. This page is for the primary administrator, who is the only account that can use Windows Update management. For scheduled, policy-driven patching see [patch policies](PATCH-POLICIES.md).

## Contents

- [How it works](#how-it-works)
- [Using the Windows Update tab](#using-the-windows-update-tab)
- [Scan, install and restart](#scan-install-and-restart)
- [Turning it off](#turning-it-off)
- [Delivery and local journals](#delivery-and-local-journals)
- [Limits and retention](#limits-and-retention)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## How it works

- Scan, installation and restart run inside the agent, which is a LocalSystem service. Installing the agent MSI is enough; Windows Update management is on by default.
- The agent opens no inbound network port.
- Requests cannot supply executables, paths, arguments, scripts, update sources, raw search expressions, URLs or packages.
- The agent always allows installation and restart. Server-side permissions, [patch policies](PATCH-POLICIES.md) and their maintenance windows decide whether and when they happen. Manual installation and restart are primary-administrator actions.
- The agent handles one update operation at a time. Each operation runs in a separate worker process, so WUA's COM state never mixes with the agent process.

## Using the Windows Update tab

Open a device's **Windows Update** tab. It shows:

- the device's readiness and whether installation and restart are available;
- the patch policies that include the device, and any automatic hold (manual installation does not clear an automatic hold; policy windows and restart deferrals are managed under **Patching**);
- the catalog from the latest retained scan;
- **History**, which explains uncertain outcomes, dispatch and finish times, restart observations and HRESULTs.

Behavior of the tab:

- It refreshes about every 15 seconds, and every 3 seconds while work is pending, without clearing your selection. Hidden pages pause polling.
- Refreshing never submits or retries work.
- A scan older than two hours, or dated in the future, stays visible as history but cannot be used to install (**Older than 2 hours — scan again to install**).
- A newer failed or pending scan is shown separately from the older successful one. Results cleared by a restore stay unavailable; they are never shown as a clean scan. Partial or empty results do not claim compliance.
- Update titles in history come only from the exact scan the operation used; if that scan was pruned, a fallback is shown.

Availability is checked every minute. Missing, denied, disabled, stale and unsupported states are shown explicitly.

## Scan, install and restart

### 1. Scan

Select **Scan now** to search for applicable, not-installed, not-hidden **software** updates from the device's configured update source.

- No WSUS or Microsoft Update registration, service, registry, Group Policy or automatic-update setting is changed.
- Driver updates are not included.
- A failed or partial search does not mean that no updates exist.

### 2. Review the catalog

The catalog shows titles, KB numbers, descriptions and severity when Windows provides them.

- At most 100 entries are returned; a larger catalog is marked as truncated.
- Control characters in update text are replaced with U+FFFD. An update whose identity or KB metadata is still invalid is skipped and counted ("*N* updates skipped"). Patch policies treat a scan with skipped updates as incomplete.
- A scan is usable for two hours.
- Upgrade-classified updates, interactive installers and updates that need license acceptance are shown as **blocked**. OpenRMM never accepts license terms on a user's behalf.
- Classification is Windows metadata, not an independent guarantee about an update's contents.

### 3. Install

Select up to 25 eligible updates and **Install selected**. The confirmation dialog lists the exact selection; select **Install**.

- The request names the scan and the exact update identities and revisions. Both the server and the agent check them.
- The worker searches again and rechecks eligibility immediately before downloading each update. Stale, missing or changed entries are blocked.
- Progress shows the searching, downloading and installing phases, completed counts and per-update outcomes and HRESULTs.
- Updates are installed one at a time using Windows' own delivery and trust validation, with quiet installation requested.
- A pending restart blocks a new installation. If an update requires a restart during a batch, the remaining entries are not installed.
- Successful installation never requests a restart by itself.
- Windows may also install bundled content and prerequisites of a selected update. This is not general file distribution or an independent patch verification system.

### 4. Restart

If Windows reports a pending update restart, select **Restart** and confirm **Request restart**.

- The agent rechecks WUA's restart requirement, then requests a local restart with a 60-second warning and a planned OS-upgrade reason. Applications are not force-closed.
- An accepted request is recorded as `restart_scheduled`. It does not prove that a reboot happened.
- A local administrator can cancel during the warning with Windows' normal shutdown cancellation.
- OpenRMM never restarts a device automatically outside a patch policy that requests it.

## Turning it off

- **Per policy:** switch off **Agent features → Windows Update** in the device's [monitoring policy](ORGANIZATION.md).
- **Locally on one device:** in an administrator PowerShell from the repository root:

  ```powershell
  .\scripts\service.ps1 -Action configure -WindowsUpdatesMode false
  # Remove the lock:
  .\scripts\service.ps1 -Action configure -WindowsUpdatesMode true
  ```

  See [Windows agent service](WINDOWS-SERVICE.md) for local locks.
- A console (diagnostic) agent uses `-windows-updates=false` or `OPENRMM_AGENT_WINDOWS_UPDATES=false`.

Turning the feature off keeps its journal and does not cancel work Windows has already accepted. Turn it back on to report that result; the server deadline may already have expired.

## Delivery and local journals

- The server commits a dispatch before returning it and never redelivers a job. Only result publication is retried.
- Native calls run in a separate copy of the agent executable, placed in a kill-on-close Windows Job Object before it receives a request, so a stuck call can be terminated without freezing the agent. If the agent exits, the worker is terminated. Terminating a worker does not cancel a Windows operation that was already accepted.

| Operation | Server completion deadline | Local worker limit |
| --- | --- | --- |
| Scan | 20 minutes | 15 minutes |
| Install | 125 minutes | 2 hours |
| Restart request | 3 minutes | 1 minute |

Queued jobs expire after 60 seconds.

The agent keeps two journals in its protected state folder:

- `update-job.json` records the job ID and parameters before local submission. After a restart the agent queries the job status and **never submits the journal again**.
- `windows-update-journal.json` records each job before execution and keeps bounded results. After an agent restart, unfinished records become Unknown; the agent never resumes an installation or repeats a restart request.

Lost dispatch, interrupted work and unavailable results are reported as Unknown. Inspect Windows and run a new scan before deciding to install again. Revoking a device blocks new dispatch and result publication but cannot undo an operation already under way.

Keep both journals across agent upgrades. They contain update metadata and results, not device keys. Uninstalling the agent keeps them; there is no purge option. Do not restore an old journal onto a machine to resume work. A [server restore](RECOVERY.md) cancels queued operations and marks dispatched operations Unknown.

## Limits and retention

| Item | Limit |
| --- | --- |
| Outstanding jobs per device | 1 |
| Server job queue | 1,000 active jobs (at most one per device); finished history is pruned to about 200 jobs |
| Jobs shown per device | 20 most recent |
| Completed history | 7 days (older finished jobs may be pruned earlier at capacity) |
| Local journal history | 100 records, keeping active work, the selected scan and recent submission IDs |
| Catalog entries per scan | 100 |
| Selection per installation | 25 updates |
| Progress or catalog reply | 512 KiB |
| Title / description | 512 / 1,024 bytes |

Update IDs and revisions, result identity, order and counts, schemas and device/certificate bindings are all validated. Seven-day retention is logical deletion, not secure erasure from the SQLite database, its WAL file or backups.

## Security notes

- Requests, dispatch, phase changes and final outcomes are audited. No passwords, keys or event contents are recorded.
- Displayed update metadata is escaped.
- Because the agent always allows installation and restart, access to this tab and to patch policies is the control. Only the primary administrator has it.

## Troubleshooting

- **Competing deployments.** Windows' own update orchestrator or another management product can act independently. Do not run competing update deployments. Microsoft notes that WUA-driven progress and history may not appear on the Settings Windows Update page. OpenRMM shows its own operation history; it does not claim to show the complete Windows update history or change orchestrator policy.
- **Scan fails.** A failed WUA scan may need local repair of Windows Update or the update source.
- **Missing updates.** OS support and entitlement affect which updates are offered.

References: [WUA API](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/portal-client), [WUA permissions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/aa387103%28v%3Dvs.85%29), [search semantics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/8bc81f1d-0491-463c-a347-a4486b7d83ab), [quiet installer](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/iupdateinstaller2-properties), [restart API](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-initiatesystemshutdownexw).

## Related

- [Patch policies](PATCH-POLICIES.md)
- [Windows agent service](WINDOWS-SERVICE.md)
- [Groups and monitoring policies](ORGANIZATION.md)
- [Backup and recovery](RECOVERY.md)
