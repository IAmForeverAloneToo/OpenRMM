# CPU Utilization

The agent reports each Windows device's overall CPU usage as a short sample taken every minute. It is shown on the device **Overview**, feeds the [metrics history](METRICS.md) and can trigger [alerts](ALERTS.md).

## How it works

- The `cpu` v1 module takes an approximately one-second sample at agent startup, then waits one minute between completed collections.
- The value is a point-in-time sample, not a continuous one-minute average. There are no per-core readings.
- The Windows adapter compares two [GetSystemTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes) snapshots separated by a cancellable one-second wait and calculates `100 × (Δkernel + Δuser − Δidle) / (Δkernel + Δuser)` from the raw 100 ns counters (kernel time already includes idle time).
- Zero utilization is a valid sample. Zero elapsed counters, counters that go backwards or are inconsistent, and overflow fail the collection instead of producing a made-up percentage.
- The agent records the actual measured sample duration rather than assuming exactly one second.

> [!NOTE]
> `GetSystemTimes` covers all logical processors only on machines with a single processor group. The collector checks [GetActiveProcessorGroupCount](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getactiveprocessorgroupcount) before each sample and reports **Not supported** when the count is not one, so devices with several processor groups (typically more than 64 logical processors) do not report CPU usage.

The collector uses the pinned `golang.org/x/sys/windows` system DLL loader. It needs no extra privilege, external process, performance-counter SDK or WMI. On other operating systems the module reports unsupported.

## Using it in the dashboard

The **CPU** meter on the device **Overview** shows the usage and when it was sampled. `GET /api/v1/devices/{id}` returns the same data in its `cpu` field, including the sample duration and server receipt times.

A sample is current only when the device is online and the server received it less than two minutes ago. Failed, disabled or unsupported reports, offline or revoked devices, future receipt times and older samples are shown as stale; the previous successful value stays visible with its own receipt time.

> [!NOTE]
> During a network outage the agent retries delivery of the same sample, so the receipt time does not prove when a retried sample was taken.

## Configuration

The feature is on by default.

- **Installed service:** switch off **CPU** in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy), or lock it off on one device from an administrator PowerShell in the repository root:

  ```powershell
  .\scripts\service.ps1 -Action configure -CPUMode false
  .\scripts\service.ps1 -Action configure -CPUMode true   # removes the lock
  ```

  A lock is a machine-policy value that survives MSI installs and self-updates, and a policy cannot turn it back on; a running service restarts to apply it. See [feature switches](WINDOWS-SERVICE.md#feature-switches).
- **Console agent:** `-cpu=false` or `OPENRMM_AGENT_CPU=false`, then restart the process. The installed service ignores interactive environment variables.

A disabled worker reports once and stops. CPU sampling never blocks heartbeats or the other feature workers.

## Protocol and validation

A successful v1 report contains exactly two required fields:

| Field | Rule |
| --- | --- |
| `usage_percent` | Finite number from 0 to 100 inclusive. |
| `sample_ms` | Integer from 1,000 to 5,000 milliseconds. |

Unknown fields, client identities or timestamps, missing or null fields and out-of-range values are rejected. A newer capability version is recorded as unsupported and its data discarded; the retained successful sample stays v1.

The server derives the device identity from mTLS, timestamps receipt with its own clock, and rechecks the active device and certificate fingerprint inside the storage write. It keeps one row per device with the latest status and the latest successful sample.

## Upgrading

Take a matched backup as described in [RECOVERY.md](RECOVERY.md), then upgrade the server before the agents. An older server rejects CPU reports; an older agent remains usable and the server shows **Not reported**. The schema change is additive, but an older server refuses the newer schema, so keep the pre-upgrade backup and image for a rollback.

## Related

- [MEMORY.md](MEMORY.md)
- [METRICS.md](METRICS.md)
- [ALERTS.md](ALERTS.md)
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md)
