# Basic Inventory

The basic inventory reports each Windows device's hostname, numeric Windows version and build, CPU architecture and agent version. It is for anyone who reads the device **Overview**, and for contributors who want to understand how agent features are built.

## Overview

The `inventory` v1 module is the agent's first compiled-in feature. In **Devices**, select a hostname to open its console; the **Overview** tab shows these values and refreshes every ten seconds.

The basic module does not collect usernames, installed software, files, serial numbers or usage metrics. The **Inventory** feature also covers:

- [device information](DEVICE-INFO.md) (`system_info`): hardware with serial number and system UUID, processor, operating system name, edition and build, domain and Entra ID join, and network adapters;
- [BitLocker and Defender status](SECURITY-STATUS.md) (`security_status`).

These share the Inventory switch: turning Inventory off (by policy, local lock or `-inventory=false`) stops all three.

## How it works

- Inventory runs at agent startup and then every 15 minutes after a report is delivered. Heartbeats keep their independent 30-second schedule.
- The Windows adapter reads the hostname and runtime architecture with Go, and the numeric OS version and build through the pinned `golang.org/x/sys/windows` package. Windows 10, for example, reports version `10.0` and build `19045`; this is not a marketing name, edition or update revision ([device information](DEVICE-INFO.md) reports those). Compatibility settings may affect the reported OS version.
- No WMI, shell command or extra privilege is used.

## States and freshness

| Display | Meaning |
| --- | --- |
| Not reported | No report received; the agent has not advertised this capability. Older agents can continue sending heartbeats. |
| Collected | The last report succeeded. A current snapshot also requires the device to be online and a server receipt less than 30 minutes old. |
| Collection failed | The collector failed or returned invalid data. The last successful snapshot remains visible as stale. Internal collector error details are not sent. |
| Disabled | The feature is switched off. The last successful snapshot remains visible as stale; heartbeats continue. |
| Unsupported | The collector does not support the platform, or the reported inventory version is newer than the server understands. A previous v1 snapshot remains visible as stale. |

- Offline or revoked devices, future receipt times and an age of exactly 30 minutes or more make inventory stale.
- Collection time is the server's receipt time, never a device-supplied clock.
- Only the latest successful snapshot and the latest outcome are stored; they survive a server restart.
- Heartbeat contact time is independent of inventory receipt time; an inventory report cannot make a device Online by itself.

## Configuration

### Installed service

Turn inventory off in the device's monitoring policy (**Agent features → Inventory**), or lock it off on one device from an administrator PowerShell in the repository root:

```powershell
.\scripts\service.ps1 -Action configure -InventoryMode false
# Remove the lock:
.\scripts\service.ps1 -Action configure -InventoryMode true
```

- Configuring restarts a running service and leaves a stopped service stopped.
- The lock is a machine-policy value under `HKLM\SOFTWARE\Policies\OpenRMM\Agent` that survives MSI installs and self-updates; a policy cannot turn a locked feature back on. See [feature switches](WINDOWS-SERVICE.md#feature-switches).
- The installed service always collects every 15 minutes.

### Console agent

For console debugging (stop the installed service first):

```powershell
.\dist\windows-amd64\openrmm-agent.exe -run -inventory=false
.\dist\windows-amd64\openrmm-agent.exe -run -inventory-interval 5m
```

| Option | Environment variable | Default | Range |
| --- | --- | --- | --- |
| `-inventory` | `OPENRMM_AGENT_INVENTORY` | `true` | `true` / `false` |
| `-inventory-interval` | `OPENRMM_AGENT_INVENTORY_INTERVAL` | `15m` | 1 to 15 minutes |

Environment defaults do not override the installed service's arguments. The installed service keeps its state in `%ProgramData%\OpenRMM Agent\state`; console debugging against that state requires an administrator terminal. See [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md).

## Protocol and access

- The agent posts feature reports to `POST /api/v1/agent/features` on the mTLS-only device listener, with a capability name and version, an outcome and an optional bounded payload.
- The inventory v1 payload has exactly six fields: `hostname`, `os`, `os_version`, `os_build`, `architecture` and `agent_version`. Extra JSON fields, claimed device IDs and client timestamps are rejected.
- The server derives the device identity from the verified client certificate and repeats the active-device and certificate-fingerprint checks inside the storage write, closing revocation races.
- Unknown capability names and malformed v1 reports fail; a newer inventory version is recorded as Unsupported without storing its payload.

Signed-in accounts read the values through `GET /api/v1/devices/{id}` (the console at `/devices/{id}`) with the device `read` scope. Device certificates cannot grant dashboard access, and feature routes are absent from the dashboard listener. Values are rendered as escaped text, and the detail output excludes keys, certificates and fingerprints.

## Extension boundary

This section is for contributors.

- `internal/features.Module` exposes a versioned capability and a context-aware collection operation.
- The scheduler runs separately from heartbeats, bounds each collection with a deadline (five seconds by default), and publishes through the agent's authenticated transport.
- Collection errors produce a `failed` report. Publication failures retry the same report with delays growing from one second to a one-minute cap, without re-running the collector or logging every retry.
- Each worker is sequential. Disabled and unsupported workers publish once and stop. Shutdown waits at most five seconds for a worker.
- `internal/inventory.Module` implements the interface with an `inventory.Collector`. The Windows adapter owns its Windows API call; the non-Windows stub reports unsupported. Tests replace the collector with a fake.

To add a feature, implement the module, register its worker beside inventory in agent startup, and add reviewed server validation, storage and UI. To add an operating system, implement the collector adapter plus enrollment metadata, service lifecycle, packaging and platform tests. Neither requires changes to device authentication, certificate renewal or the heartbeat loop.

> [!IMPORTANT]
> In-process modules are trusted code, not a sandbox. There is no runtime plugin loader, automatic code download or security boundary between compiled modules. Collectors must honour cancellation.

## Related

- [DEVICE-INFO.md](DEVICE-INFO.md)
- [SECURITY-STATUS.md](SECURITY-STATUS.md)
- [HEARTBEATS.md](HEARTBEATS.md)
- [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md)
