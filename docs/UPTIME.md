# Uptime and Last Boot

The agent reports each Windows device's uptime and an estimated last boot time every minute. Both appear on the device **Overview** and are useful for spotting devices that have not restarted.

## How it works

- The `uptime` v1 module reports at agent startup and then every minute.
- The adapter uses the `windows.DurationSinceBoot()` wrapper for [GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64) from the pinned `golang.org/x/sys/windows` package. It needs no extra privilege, process or WMI. On other operating systems the module reports unsupported.
- The estimated boot time is the device's wall clock minus its uptime.
- Collection never changes reboot or power settings.

### What uptime means

- Uptime measures the Windows session, including time spent in sleep and hibernation (see [Microsoft's timer guidance](https://learn.microsoft.com/en-us/windows/win32/sysinfo/interrupt-time)).
- Agent or service restarts do not reset it.
- [Fast Startup can restore an earlier kernel session](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation), so uptime is not the time since the last power-button press and not a guarantee of continuous powered-on time.
- Device clock adjustments can change the boot estimate without resetting uptime. The estimate is descriptive device data, not an authoritative reboot event.
- Debug or checked Windows builds can deliberately bias tick counts.

## Using it in the dashboard

The **Uptime** meter on the device **Overview** shows the uptime in days, hours, minutes and seconds **as collected**, and the estimated boot time in UTC from the device clock. The dashboard does not extrapolate uptime between readings or while the device is offline. `GET /api/v1/devices/{id}` returns the same data in its `uptime` field.

A reading is current only while the device is online and the server received the successful reading less than two minutes ago. Failed, disabled, unsupported, offline or revoked, future-dated and older readings are stale; the last successful reading stays visible with its own receipt time.

As with other features, a report retried during an outage keeps its original values, so receipt freshness does not prove when the reading was taken.

## Configuration

The feature is on by default.

- **Installed service:** switch off **Uptime** in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy), or lock it off on one device from an administrator PowerShell in the repository root:

  ```powershell
  .\scripts\service.ps1 -Action configure -UptimeMode false
  .\scripts\service.ps1 -Action configure -UptimeMode true   # removes the lock
  ```

  Configuring restarts a running service and leaves a stopped one stopped. A lock survives MSI installs and self-updates, and a policy cannot override it; see [feature switches](WINDOWS-SERVICE.md#feature-switches).
- **Console agent:** `-uptime=false` or `OPENRMM_AGENT_UPTIME=false`, then restart the process. The installed service ignores interactive environment variables.

Disabling uptime leaves heartbeats and other features running.

## Protocol and validation

A successful v1 report contains exactly two required fields:

| Field | Rule |
| --- | --- |
| `uptime_seconds` | Unsigned whole seconds, at most 9,223,372,036. Zero is valid. |
| `estimated_boot_at` | Unix seconds, greater than zero; boot estimate plus uptime must fall before the end of UTC year 9999. |

Negative or overflowing native durations fail the collection. Missing, null, fractional, negative or oversized values, unknown fields and client identity or receipt-time claims are rejected. A newer capability version is stored as unsupported and its data discarded; the retained successful reading stays v1.

The boot estimate is device data only: it can never overwrite heartbeat contact or report receipt times, and a device clock ahead of the server cannot create a future contact time. The server rechecks the active device and certificate fingerprint inside the storage write and keeps one row per device with the latest status and the latest successful reading.

## Upgrading

Take a matched backup as described in [RECOVERY.md](RECOVERY.md), upgrade the server first, then the installed agents (see [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md)). An older agent remains usable and shows uptime as **Not reported**. An older server rejects the capability and refuses the newer schema, so keep the pre-upgrade backup and image for a rollback.

## Related

- [CPU.md](CPU.md)
- [MEMORY.md](MEMORY.md)
- [WINDOWS-UPDATES.md](WINDOWS-UPDATES.md)
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md)
