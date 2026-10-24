# Processes

The **Processes** tab lists the processes running on a Windows device with their CPU and memory use, and lets authorized accounts end a specific process. This page is for administrators and technicians with the **Processes** permission.

## Contents

- [What is collected](#what-is-collected)
- [Using the Processes tab](#using-the-processes-tab)
- [Ending a process](#ending-a-process)
- [Delivery and history](#delivery-and-history)
- [Turning it off](#turning-it-off)
- [Limits](#limits)
- [Permissions, audit and API](#permissions-audit-and-api)
- [Related](#related)

## What is collected

Each snapshot contains, per process:

- executable base name and PID;
- exact creation time (Windows FILETIME), when accessible;
- CPU use as a percentage of the whole machine, from a one-second sample;
- working-set memory;
- whether the process can be ended.

Command lines, environment, user names, memory contents and executable paths are **never** transmitted, and no process memory is read. Debug privilege is not enabled.

- A snapshot is taken at startup and every minute. Only the latest successful snapshot is kept.
- Snapshots become stale after two minutes, or when a report fails, the feature is disabled or the device is offline.
- Metrics that Windows denies access to show as unavailable. Listing a process does not imply that its counters can be read.
- On systems with multiple processor groups, CPU is omitted; the list and memory remain.
- Windows process enumeration is a changing view, not an atomic snapshot of the machine.

## Using the Processes tab

Open a device's **Processes** tab.

- Filter by executable name or PID.
- Sort by process, PID, CPU, memory or start time. Unavailable CPU and memory values sort last.
- The tab refreshes every 10 seconds. Past actions appear under **Process actions**.
- A stale snapshot stays readable, but termination controls are hidden.

## Ending a process

Select **End** on a row. The confirmation dialog identifies the exact process and warns about unsaved work; **End process** submits it.

> [!WARNING]
> Termination is forced. The process gets no chance to save its work.

- Each request names one exact instance: PID, creation time and name. Immediately before the single termination call, the agent checks the creation time, name and critical status on a handle to that same process.
- Child processes are not ended, and there is no tree termination or automatic restart. Windows services may have their own recovery behavior.

The agent runs as SYSTEM, so any process can be ended **except**:

| Protected | Examples |
| --- | --- |
| OpenRMM's own executables | `openrmm-agent.exe`, `openrmm-update-helper.exe` (self-update copy), `openrmm-desktop.exe` |
| Critical processes | Processes Windows marks as critical |
| Fixed system hosts | `csrss.exe`, `lsass.exe`, `services.exe`, `svchost.exe` and similar |
| The agent itself | |

Server-side permissions decide who may ask. A true "can end" flag is an observation, not a guarantee that a later request succeeds.

## Delivery and history

- Only one process action can be outstanding per device. It stays queued for one minute.
- The agent consumes the request atomically when it polls, and dispatch happens at most once.
- A dispatched action has a 90-second deadline for its outcome; the agent's local execution limit is 40 seconds.
- Only result delivery is retried. Interrupted or lost delivery becomes Unknown and is never replayed.
- Identical repeated requests and results are accepted once; conflicting results are rejected.
- A [server restore](RECOVERY.md) invalidates pending work and marks snapshots stale.
- Server timestamps are authoritative. The process creation time is a device-provided identity value, not a server timestamp.

## Turning it off

- **Per policy:** switch off **Agent features → Processes** in the device's [monitoring policy](ORGANIZATION.md).
- **Locally on one device:** in an administrator PowerShell from the repository root:

  ```powershell
  .\scripts\service.ps1 -Action configure -ProcessesMode false
  # Remove the lock:
  .\scripts\service.ps1 -Action configure -ProcessesMode true
  ```

  A local lock survives MSI installs and self-updates, and a policy cannot override it. See [Windows agent service](WINDOWS-SERVICE.md).
- A console (diagnostic) agent uses `-processes=false` or `OPENRMM_AGENT_PROCESSES=false`, and runs with the console account's own process rights.

Turning it off leaves other collectors and heartbeats running.

## Limits

| Item | Limit |
| --- | --- |
| Processes per snapshot | 4,096 |
| Snapshot size | 1 MiB |
| Action records | 1,000 globally |
| Actions shown per device | 20 most recent |

Processes with invalid names, and processes beyond 4,096 entries or the 1 MiB budget, are left out and counted ("*N* processes skipped"). The kept subset is deterministic, in ascending PID order. Incomplete enumeration or a timeout fails the whole report and keeps the previous successful snapshot. Processes that deny access or exit during collection appear with unavailable metrics.

Process collection and control are not supported on Linux.

## Permissions, audit and API

- Reading needs read access to the device. Ending a process needs the **Processes** permission for that device (the primary administrator always has it).
- Requests, dispatch, completion, expiry and uncertain outcomes are audited, without command lines or other sensitive contents.

`GET /api/v1/devices/{id}/processes` returns:

| Field | Meaning |
| --- | --- |
| `status`, `stale`, `snapshot_at`, `coverage` | Freshness metadata |
| `items` | Processes in the snapshot |
| `actions` | Recent actions |
| `can_act` | Whether the caller may end processes on this device |

Each item has `pid`, `start` (decimal FILETIME, empty when unavailable), `name`, `cpu_basis_points` (nullable; 10,000 = 100%), `working_set_bytes` (nullable) and `can_terminate`.

`POST /api/v1/devices/{id}/process-actions` requires the session's `X-CSRF-Token` header and a JSON body with a client-generated action `id` and the exact target `pid`, `start` and `name`. A fresh successful snapshot from an online, non-revoked device must show that the process can be ended.

The agent reports capability `processes` v1 through the feature endpoint and uses the mTLS-only routes `POST /api/v1/agent/process-actions/poll` and `/result`; results are accepted only when bound to the device and validated.

## Related

- [Windows service management](SERVICE-MANAGEMENT.md)
- [Technician accounts](TECHNICIANS.md)
- [Windows agent service](WINDOWS-SERVICE.md)
