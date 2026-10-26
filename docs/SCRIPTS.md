# PowerShell Scripts

OpenRMM keeps a library of immutable PowerShell script versions and runs them on Windows devices, one device at a time or as a reviewed batch across devices and groups. This page is for the primary administrator, who is the only account that can create and run scripts.

## Contents

- [Overview](#overview)
- [Create a script](#create-a-script)
- [Run on one device](#run-on-one-device)
- [Run on many devices](#run-on-many-devices)
- [Writing scripts](#writing-scripts)
- [Execution on the device](#execution-on-the-device)
- [Turning scripting off](#turning-scripting-off)
- [Delivery and recovery](#delivery-and-recovery)
- [Limits and retention](#limits-and-retention)
- [Permissions, audit and API](#permissions-audit-and-api)
- [Related](#related)

## Overview

- Each run records the device, the account that started it, the version and its hash, the exact parameter values, the status, the final standard output and error (bounded), and the exit code when known.
- Runs are never replayed automatically.
- Every script runs as **SYSTEM** inside the agent, with full control of the device.
- [Schedules](SCHEDULES.md) can run a saved version once or repeatedly on a device.

> [!WARNING]
> Scripts are trusted code with SYSTEM rights, including access to local machine data and the agent's own state. They are not a sandbox for untrusted users.

## Create a script

1. Open **Manage → Scripts** and select **New script**.
2. Enter a name, description, PowerShell body and timeout (5–300 seconds).
3. Declare up to eight string parameters, both in the form and in the script's `param(...)` block. Required parameters need non-empty values. Blank optional values are omitted so PowerShell defaults apply.
4. Select **Create script**.

A saved version cannot be changed. On a version's page, **Save as v*N*** creates the next version. The page shows the version's full SHA-256, which covers the version ID, script ID, version number and complete definition, so every new version has a new hash even if its body is unchanged.

## Run on one device

1. Open a device and select **Run script** in the console header (or on its **Scripts** tab).
2. Choose a script, enter parameter values and check the timeout.
3. Select **Run script**. This authorizes exactly those values for that version and device.

The result opens in a dialog that refreshes until the run finishes; the device's **Scripts** tab lists recent runs. Each result shows the outcome, exit code, and output and errors separately.

**Cancel run** cancels queued work immediately, or asks a running worker to stop. The script may already have finished, or changed the device, before the cancellation arrives.

## Run on many devices

Open a script version and choose **Run on devices** (`/scripts/run`). Past batches are under **Scripts → Fleet runs**.

1. Choose the exact saved version and name the batch.
2. Select individual devices and/or groups and enter arguments.
3. Select **Review**. The review lists the resolved targets and whether each is ready; a target that is not an active Windows device blocks confirmation. Overlapping groups and devices count once. Groups use their current membership within the managed fleet; later group changes never add devices.
4. Confirm with **Run on *N* devices**.

Readiness (fresh contact, scripting support and a free script slot) is checked at review and again at confirmation. Every target must be ready, or nothing is queued: if any target cannot be queued, the whole transaction rolls back and no batch or child run is created. A group or organization change before confirmation requires a new review.

> [!NOTE]
> Queuing is atomic; execution across machines is not. Contact, the device's scripting setting and local conditions can change after queueing, and each device still checks its own job before running it.

The batch page (`/scripts/runs/{batch}`) tracks each child run and refreshes while runs are active. Select a device to open its output and cancellation controls. Runs can end differently. Cancelling a queued child proves it was not dispatched; cancelling after dispatch cannot undo its effects. A batch creates no schedule, automatic retry, catch-up or local permission.

Resubmitting a confirmed batch returns the original batch and child runs, even if membership or readiness changed since, and never recreates child runs whose history was pruned. A different version, name, argument set, target selection or account cannot reuse a confirmation. If a confirmation response is lost, check **Fleet runs** before starting again: a missing response does not prove nothing was queued.

## Writing scripts

Example definition:

```powershell
param([string]$Message = 'Hello from OpenRMM')
Write-Output $Message
[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

Declare `Message` as an optional string parameter in the form.

- Use `exit 7` (or any code) to return a deliberate nonzero exit code. A terminating PowerShell error returns failure.
- Non-terminating errors and native programs follow normal PowerShell semantics, so scripts should check their own operations and return an appropriate code.
- Parameters arrive as JSON and are splatted by a fixed wrapper. OpenRMM never interpolates values into the command line or evaluates them as code.
- Parameter names are ASCII, start with a letter and are up to 32 characters. PowerShell common parameter names (such as `Verbose`, `ErrorAction` or `WhatIf`) are not allowed.

> [!IMPORTANT]
> Parameters and output are stored as plaintext application data visible to the primary administrator. Do not put passwords, tokens or private keys in them. There is no secret-parameter store and no automatic output redaction. They do not appear in audit messages or ordinary logs.

## Execution on the device

- The agent runs scripts with Windows PowerShell 5.1 from the fixed Windows system directory. OpenRMM does not install PowerShell, modules or script dependencies.
- No profile is loaded and there is no interactive input.
- The per-process `-ExecutionPolicy Bypass` does not change machine policy and is not a security boundary. Group Policy and OS application-control policies still apply. See [about execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies/).
- The environment is reduced to fixed Windows and runtime paths plus a private workspace, which is cleaned after the run. If cleanup cannot finish, remnants stay in protected storage.

### Containment

The agent starts a worker copy of its own executable and places it in a kill-on-close [Windows Job Object](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) before giving it any work. Child processes inherit the job.

| Limit | Value |
| --- | --- |
| Job memory | 512 MiB in total |
| Processes | 16 |
| Timeout | The version's timeout (5–300 seconds), measured with a monotonic clock |
| Output | 64 KiB per stream; extra bytes are discarded and the result is flagged as truncated |

The agent terminates the job on cancellation or timeout and closes it when it exits. These limits bound ordinary scripts; privileged code can still use other OS facilities, and termination cannot reverse external effects. Output is returned when the run completes, so a timeout, cancellation or crash may lose output, and no exit code is invented for those outcomes. Invalid encoding and control characters in output are normalized for safe display.

## Turning scripting off

Scripting is on by default. To turn it off:

- **Per policy:** switch off **Agent features → Scripts** in the device's [monitoring policy](ORGANIZATION.md).
- **Locally on one device:** run in an administrator PowerShell from the repository root:

  ```powershell
  .\scripts\service.ps1 -Action configure -ScriptsMode false
  # Remove the lock:
  .\scripts\service.ps1 -Action configure -ScriptsMode true
  ```

  A local lock survives MSI installs and self-updates, and a policy cannot override it. See [Windows agent service](WINDOWS-SERVICE.md).

When scripting is off, the device shows scripts as unavailable. Turning off **Scripts** also disables [application deployment](APPLICATIONS.md), which uses the same execution path.

Support status is reported about every minute; a feature change restarts the agent's work and reports it immediately. A console (diagnostic) agent uses `-scripts=false` or `OPENRMM_AGENT_SCRIPTS=false`, and runs scripts as the console account.

## Delivery and recovery

- Each run is consumed in a transaction bound to the device and its certificate before delivery.
- Queued work expires after one minute. Dispatched work gets its timeout plus 30 seconds to report a result.
- One script may be outstanding per device, including scheduled and deployment runs.
- Identical repeated requests and results are accepted once; changed parameters, versions or device IDs, and conflicting results, are rejected.
- Revoking a device stops new dispatch and results, but cannot undo an operation Windows already accepted.

Before executing, the agent writes a protected local journal entry. After an agent restart it **never re-executes** an interrupted run; it reports Unknown. Only the saved result is retried. A corrupt or unwritable journal fails closed and needs local inspection.

> [!WARNING]
> Never delete a pending local journal to force an uncertain run to execute again.

A [server restore](RECOVERY.md) cancels queued script work, marks dispatched and running work Unknown, clears old output, invalidates support status and keeps the immutable versions. Restored batches are marked as restored history and cannot be resubmitted; their original hostnames and targets remain as approved. Device journals are separate from server backups.

## Limits and retention

| Item | Limit |
| --- | --- |
| Scripts | 100 |
| Versions | 500 in total |
| Script body | 64 KiB of UTF-8 |
| Description | 2,000 bytes |
| Parameters | 8; names up to 32 ASCII characters; values up to 1,024 UTF-8 bytes |
| Timeout | 5–300 seconds |
| Run history | 2,000 runs or 30 days; the device tab shows the latest 20 |
| Batch targets | 25 devices per batch |
| Batches | 200 retained, latest 100 listed; metadata older than 30 days is pruned |

Active work is never pruned. Batch pruning also protects batches with active children and batches newer than five minutes; if those fill capacity, new batches are refused. A batch child whose run history was pruned no longer shows output, and no result or retry is invented for it. Scripts cannot be deleted or archived yet.

## Permissions, audit and API

Scripts are limited to the primary administrator; technicians cannot run scripts. State changes require the MFA-backed session, origin checks, the `X-CSRF-Token` header and bounded JSON validation. Each run request carries a client-generated run ID bound to the device, version and arguments.

Audit entries identify versions, runs, accounts and outcomes, without bodies, parameters or output. Batch metadata (including reviewed code references and arguments) is kept in protected storage, not in audit messages.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/scripts` | Script library |
| `GET /api/v1/scripts/versions/{version}` | One version |
| `POST /api/v1/scripts/versions` | Create a script or new version |
| `GET /api/v1/devices/{id}/scripts` | Device script summary |
| `POST /api/v1/devices/{id}/script-runs` | Start a run |
| `GET /api/v1/devices/{id}/script-runs/{run}` | Run result |
| `POST /api/v1/devices/{id}/script-runs/{run}/cancel` | Cancel a run |
| `GET /api/v1/script-batches` | Batch history |
| `POST /api/v1/script-batches/review` | Review a batch |
| `POST /api/v1/script-batches/apply` | Confirm a batch (quotes the review digest) |
| `GET /api/v1/script-batches/{batch}` | One batch, including reviewed code and arguments |

Dashboard pages: `/scripts`, `/scripts/new`, `/scripts/v/{version}`, `/scripts/run`, `/scripts/runs/{batch}`, `/scripts?view=runs`, and the device console's **Scripts** tab.

The agent reports capability `scripts` v1 through the feature endpoint, and uses the mTLS-only routes `POST /api/v1/agent/scripts/poll` and `POST /api/v1/agent/scripts/result`. Script workers have no network interface of their own. Non-Windows agents report scripting as unsupported.

## Related

- [Script schedules](SCHEDULES.md)
- [Application deployment](APPLICATIONS.md)
- [Windows agent service](WINDOWS-SERVICE.md)
- [Backup and recovery](RECOVERY.md)
