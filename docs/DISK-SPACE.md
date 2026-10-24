# System Drive Disk Space

The agent reports the total and available space of each Windows device's system drive every five minutes. The dashboard uses it for the **System disk** column, the low-disk warning, the [metrics history](METRICS.md) and [alerts](ALERTS.md).

## How it works

- The `disk_space` v1 module runs at agent startup and then every five minutes, in its own worker.
- The Windows adapter finds the system Windows directory with `GetSystemWindowsDirectory` and reads that drive root with `GetDiskFreeSpaceEx`. It does not assume `C:`, read an environment variable, run PowerShell or WMI, or scan files.
- Total and available space are the pair Windows returns for the agent's account and may reflect disk quotas rather than physical capacity; the percentage stays internally consistent. See [GetDiskFreeSpaceEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw).
- Only the system drive is reported; other drives are not enumerated. There are no cleanup actions.

The server keeps one latest successful reading per device, plus the latest report outcome and server receipt time. Readings are descriptive agent data, not an independent check of disk health.

## Using it in the dashboard

- The device **Overview** has a **System disk** meter with the drive letter, the used percentage and the free and total space in binary units (GiB/TiB). Used percentage is `100 × (total − available) / total`.
- The **Devices** list has a **System disk** column showing **Low**, **OK** or **Unknown**.
- The dashboard's **Low disk space** count links to the Devices list filtered to low-disk devices.

A reading is current only when the device is online and the server received it less than ten minutes ago (two missed collections). Failed, disabled, unsupported, offline or revoked, future-dated and older readings are stale. Failures keep the previous successful values with their own receipt time; before the first success no percentage is shown.

### Low-disk warning

| Display | Condition |
| --- | --- |
| **Low** (list) / **Low space** (Overview) | A current reading with strictly less than 10% available. |
| **OK** | A current reading with 10% or more available. |
| **Unknown** | No valid reading, a failed, disabled or unsupported report, a stale or future-dated reading, or an offline or revoked device. |

- The comparison uses exact byte counts, not rounded percentages, so 9.99% available still warns.
- A stale reading can neither raise nor clear the warning. The last successful values remain visible as stale in the console.
- The warning is computed on each request, so recovery shows after the next collection plus the ten-second page refresh.
- This is a fixed dashboard threshold without notifications or a stored lifecycle. Configurable thresholds and notifications are handled by [alerts](ALERTS.md).

## Configuration

The feature is on by default.

- **Installed service:** switch off **Disk space** in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy), or lock it off on one device from an administrator PowerShell in the repository root:

  ```powershell
  .\scripts\service.ps1 -Action configure -DiskSpaceMode false
  .\scripts\service.ps1 -Action configure -DiskSpaceMode true   # removes the lock
  ```

  A running service restarts; a stopped service stays stopped. A lock survives MSI installs and self-updates, and a policy cannot override it; see [feature switches](WINDOWS-SERVICE.md#feature-switches).
- **Console agent:** `-disk-space=false` or `OPENRMM_AGENT_DISK_SPACE=false` (`true` is the default), then restart the process. The installed service ignores interactive environment variables.

Disabling disk reporting does not affect inventory, heartbeats or other features.

## API

- `GET /api/v1/devices` adds `disk_space_warning` (`low`, `ok` or `unknown`) for each device. One bounded query loads the fleet together with the latest disk state.
- `GET /api/v1/devices/{id}` adds `disk_space`, with exact byte counts, the computed `used_percent` and `warning`.

## Protocol and validation

A successful v1 report contains exactly these required fields:

| Field | Rule |
| --- | --- |
| `drive` | An uppercase Windows drive root, for example `C:\`. |
| `total_bytes` | Greater than zero and at most `2^53−1`, so JSON consumers can represent it exactly. |
| `available_bytes` | From zero to `total_bytes`. Zero (a full drive) is valid. |

Unknown fields, fractions, negative or oversized values, client identities and client receipt times are rejected. A newer capability version is recorded as unsupported and its payload discarded; the retained successful reading stays v1.

The server derives the identity and time itself and rechecks the active device and the current or overlapping certificate fingerprint inside the storage write. Device certificates cannot read dashboard APIs.

For contributors: `internal/diskspace` implements `features.Module` through a collector interface with a Windows adapter and an unsupported non-Windows adapter, so tests can substitute a fake collector.

## Upgrading

Take a matched backup as described in [RECOVERY.md](RECOVERY.md) and upgrade the server before the agents, because an older server rejects unknown capabilities. Older agents keep working and show **Not reported** until a disk report arrives. The schema change adds one table; an older server refuses the newer schema, so keep the pre-upgrade backup and image for a rollback. Update agents through [signed agent updates](AGENT-UPDATES.md) or the MSI described in [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md); device state is kept.

## Related

- [MEMORY.md](MEMORY.md)
- [METRICS.md](METRICS.md)
- [ALERTS.md](ALERTS.md)
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md)
