# Physical Memory

The agent reports each Windows device's total and available physical RAM every minute. The reading is shown on the device **Overview**, feeds the [metrics history](METRICS.md) and can trigger [alerts](ALERTS.md).

## How it works

- The `memory` v1 module reports at agent startup and then every minute.
- The Windows adapter calls [GlobalMemoryStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex) and publishes only `ullTotalPhys` and `ullAvailPhys`.
- Available memory includes Windows' standby, free and zero page lists, so it is memory that can be reused immediately, not merely unused pages. See [MEMORYSTATUSEX](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex).
- Used percentage is calculated as `100 × (total − available) / total`.
- A reading is a point-in-time snapshot. The feature does not report the agent's own memory use, page-file size, commit limit or per-process memory.

The binding uses `windows.NewLazySystemDLL` from the pinned `golang.org/x/sys/windows` package with a fixed system DLL and function and the documented structure layout. It needs no extra privilege, external process or WMI. On other operating systems the module reports unsupported.

## Using it in the dashboard

The **Memory** meter on the device **Overview** shows the used percentage and the used and total amounts in binary units (for example GiB). `GET /api/v1/devices/{id}` returns the same data in its `memory` field; the percentage is `null` before the first successful report.

A reading is current only when the device is online, the latest report succeeded, and the server received the successful reading less than two minutes ago. Older, future-dated, failed, disabled, unsupported and offline or revoked readings are shown as stale. A failed report keeps the last successful reading with its own receipt time.

## Configuration

The feature is on by default.

- **Installed service:** switch off **Memory** in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy), or lock it off on one device from an administrator PowerShell in the repository root:

  ```powershell
  .\scripts\service.ps1 -Action configure -MemoryMode false
  .\scripts\service.ps1 -Action configure -MemoryMode true   # removes the lock
  ```

  Configuring restarts a running service and leaves a stopped service stopped. A lock survives MSI installs and self-updates, and a policy cannot override it; see [feature switches](WINDOWS-SERVICE.md#feature-switches).
- **Console agent:** `-memory=false` or `OPENRMM_AGENT_MEMORY=false`, then restart the process. The installed service ignores interactive environment variables.

A disabled worker sends one disabled report and stops; heartbeats and other features continue.

## Protocol and validation

A successful v1 report contains exactly two required integer fields:

| Field | Rule |
| --- | --- |
| `total_bytes` | Greater than zero and at most `2^53−1`. |
| `available_bytes` | From zero to `total_bytes`. Zero is valid. |

Unknown fields, client device IDs or timestamps, fractions, negative and impossible values are rejected. A newer capability version is recorded as unsupported and its payload discarded; the retained successful reading stays v1.

The server binds each report to a device through its certificate and its own clock, and rechecks the active device and certificate fingerprint inside the storage write. It keeps one row per device with the latest status and the latest successful reading. There is no database or alert engine on the agent.

## Upgrading

Take a matched backup as described in [RECOVERY.md](RECOVERY.md), then upgrade the server first. An older server rejects the memory capability; an older agent remains usable and the server shows memory as **Not reported**. The schema change is additive, but an older server refuses the newer schema, so keep the pre-upgrade backup and image for a rollback.

## Related

- [CPU.md](CPU.md)
- [DISK-SPACE.md](DISK-SPACE.md)
- [METRICS.md](METRICS.md)
- [ALERTS.md](ALERTS.md)
