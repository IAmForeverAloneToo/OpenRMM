# Device Information

The Windows agent reports hardware identity, processor, operating system details, domain and Microsoft Entra ID join, and network adapters for each device. This page is for administrators and technicians who use the **System** tab, the device list columns and the device CSV export, and for operators who need to know what is collected and how to turn it off.

## Contents

- [Overview](#overview)
- [What is collected](#what-is-collected)
- [Schedule and states](#schedule-and-states)
- [Primary IPv4 address](#primary-ipv4-address)
- [Using it in the dashboard](#using-it-in-the-dashboard)
- [Device CSV](#device-csv)
- [Limits and validation](#limits-and-validation)
- [Storage](#storage)
- [API](#api)
- [Permissions](#permissions)
- [Turning it off](#turning-it-off)
- [Privacy](#privacy)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## Overview

Device information is a snapshot of what Windows reports on the device. The server keeps only the newest snapshot and no history of changes.

- The device's **System** tab shows the full snapshot.
- The device **Overview** shows **Hardware** and **IP address** lines.
- The **Devices** list has an **IP address** column, a filter that also matches IP addresses, MAC addresses and serial numbers, and an **Export CSV** button.

## What is collected

The `system_info` v1 module runs inside the agent (LocalSystem). It is part of the **Inventory** feature and has no switch of its own. It reads:

- the SMBIOS firmware tables (`GetSystemFirmwareTable`);
- processor counts (`GetLogicalProcessorInformationEx`, `GetActiveProcessorCount`);
- registry values under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` and `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation`;
- the join state (`NetGetJoinInformation`, `NetGetAadJoinInformation`);
- the network adapters (`GetAdaptersAddresses`).

It uses no WMI, starts no process and writes nothing to the device. Empty text and zero numbers mean Windows did not provide the value; the dashboard shows **Not provided**.

| Field (API) | Meaning |
| --- | --- |
| `hardware.manufacturer`, `hardware.model`, `hardware.serial` | SMBIOS system information (type 1): manufacturer, product name and serial number. Virtual machines and self-built PCs often report placeholder text such as "To Be Filled By O.E.M."; it is shown as reported. |
| `hardware.uuid` | SMBIOS system UUID, upper case. All-zero and all-`FF` values are treated as not set. The first three fields are decoded little-endian on SMBIOS 2.6 and later and big-endian on older firmware, as the specification requires. |
| `hardware.bios_vendor`, `hardware.bios_version`, `hardware.bios_date` | SMBIOS BIOS information (type 0). The date is the firmware's own text, usually `MM/DD/YYYY`. |
| `cpu.model` | `ProcessorNameString` of the first processor. |
| `cpu.sockets`, `cpu.cores`, `cpu.logical_processors` | Processor packages, physical cores and active logical processors across all processor groups. |
| `os.name` | `ProductName`. Windows 11 still stores "Windows 10" there; the agent reports **Windows 11** when the build is 22000 or higher and the name starts with "Windows 10". |
| `os.edition` | `EditionID`, for example `Professional`. |
| `os.display_version` | `DisplayVersion`, for example `23H2`; older builds do not have it. |
| `os.build` | `CurrentBuildNumber` and `UBR` (update revision), for example `22631.4317`. |
| `os.install_date` | `InstallDate`, Unix seconds. |
| `os.time_zone` | `TimeZoneKeyName`, for example `W. Europe Standard Time`. |
| `os.utc_offset_minutes` | The current offset from UTC in minutes (for example `60` or `-300`), read from `ActiveTimeBias` at every collection; the agent's own time zone is used only if that value is missing. |
| `domain.join`, `domain.name` | `domain`, `workgroup`, `unjoined` or `unknown`, and the domain or workgroup name. |
| `domain.entra` | Microsoft Entra ID join: `joined`, `registered` (workplace join), `none` or `unknown` (the API is missing or failed). |
| `domain.entra_tenant`, `domain.entra_tenant_id` | Tenant display name and tenant ID when joined or registered. |
| `adapters[]` | Network adapters; see below. |
| `skipped` | Adapters left out (omitted when zero). |

Each adapter:

| Field (API) | Meaning |
| --- | --- |
| `name`, `description` | Windows' friendly name (required) and the adapter description. |
| `mac` | Hardware address, upper case with colons, 6 or 8 bytes; empty otherwise. |
| `status` | `up`, `down` or `other` (every other Windows operational status). |
| `type` | `ethernet`, `wifi` or `other`. |
| `ipv4`, `ipv6` | Unicast addresses, up to 16 of each, in canonical text without a zone. Link-local addresses are included. |
| `gateways` | Default gateways (IPv4 or IPv6), up to 8. |
| `dns` | DNS servers (IPv4 or IPv6), up to 8. |
| `dhcp` | Windows' "DHCP enabled" flag for the adapter. |
| `dhcp_server` | The DHCPv4 server, only when `dhcp` is true; empty when unknown. |

Loopback and tunnel pseudo-interfaces (for example Teredo or 6to4) are not reported. Every other interface Windows lists is reported, including disconnected adapters and virtual ones such as Hyper-V switches or VPN clients. The status and type Windows assigns to a particular virtual adapter can vary.

## Schedule and states

Device information is collected with [Inventory](INVENTORY.md): at agent startup and then every 15 minutes (a console agent can use 1 to 15 minutes), with the shared five-second collection deadline. Linux agents report **Not supported**.

A report is collected, failed, disabled or unsupported. A failed, disabled or unsupported report keeps the last successful snapshot, which is then marked stale.

The device page refreshes every ten seconds. The **System** tab marks the snapshot **Stale** when:

- it is 30 minutes old or more (one missed report is allowed);
- the latest report was not successful; or
- the device is not online.

## Primary IPv4 address

The **IP address** shown in the Devices list, the Overview and the System tab is chosen from the last successful snapshot:

1. the first IPv4 address that is not link-local (`169.254.0.0/16`) on an adapter that is `up` and has an IPv4 default gateway;
2. otherwise, the first such address on any `up` adapter;
3. otherwise, nothing.

Adapters are taken in the order the agent reported them, which is Windows' order. With several connected adapters (for example Ethernet and Wi-Fi, or a VPN) this is not necessarily the address Windows uses for a given connection.

## Using it in the dashboard

**System** tab (`?tab=system`):

- **Hardware:** Manufacturer, Model, Serial number, System UUID, BIOS (vendor, version and date), Processor and Cores (sockets, cores and logical processors).
- **Operating system:** Name, Edition, Version (display version and build), Installed, Time zone (with the UTC offset), Domain and Microsoft Entra ID (state, tenant name and tenant ID).
- **Network adapters:** Adapter (name and description), Status, Type, Addresses, Gateway, DNS servers, DHCP (with the DHCP server) and MAC. Connected adapters are listed first. The panel header shows the primary IPv4 address and the skipped count.
- **Security:** BitLocker and Microsoft Defender status; see [SECURITY-STATUS.md](SECURITY-STATUS.md).
- Above the panels: the collection state (**Stale**, **Collection failed**, **Disabled on device**, **Not supported**) and the time of the last successful snapshot. Without a snapshot the tab shows only the state (or **Not reported**).

**Overview → Agent capabilities:**

- **Hardware:** manufacturer, model and `S/N` serial number from the last snapshot, with a **Stale** badge when stale; without a snapshot, the collection state.
- **IP address:** the primary IPv4 address, or `—`.

**Devices** list:

- An **IP address** column with the primary IPv4 address.
- The filter box matches any reported IPv4 or IPv6 address (substring), a MAC address written with colons, dashes or no separators, and the serial number (case-insensitive), in addition to the hostname, device ID prefix, signed-in users, group, tags and agent version.
- **Export CSV** downloads the [device CSV](#device-csv).

The list uses the last successful snapshot regardless of its age: an offline device, or one whose Inventory feature is off, keeps showing its last IP address, MACs and serial number. Signed-in users, by contrast, are shown only for online devices; see [SESSIONS.md](SESSIONS.md).

## Device CSV

`GET /api/v1/reports/devices.csv` (the **Export CSV** button on **Devices**) is available to every account.

- It exports the same devices as the Devices list: technicians get only the devices they can see; the administrator gets every device in the list, including revoked ones.
- The on-screen filters are not applied; the export always covers the whole list (the newest 1,000 devices).
- It takes no parameters; a request with a query string is refused with HTTP 400.
- The file is `openrmm-devices.csv`, UTF-8, one row per device.

| Column | Content |
| --- | --- |
| `as_of_utc` | Time of the export. |
| `device_id`, `hostname`, `status` | Device ID, hostname and `online`, `offline`, `awaiting_contact` or `revoked`. |
| `group`, `tags` | Group name and tags (comma separated); empty for revoked devices. |
| `signed_in_users` | Users of active sessions, comma separated, by the Devices-list rule (online devices, report at most five minutes old). |
| `primary_ipv4`, `addresses`, `macs` | Primary IPv4, every reported address and every MAC, comma separated. |
| `serial`, `manufacturer`, `model` | From the hardware information. |
| `os`, `architecture`, `agent_version` | From enrollment and heartbeats (for example `windows`, `amd64`), not the operating system name above. |
| `last_contact_utc` | Last heartbeat; empty when never. |
| `bitlocker`, `defender`, `security_stale` | BitLocker and Defender summaries ([SECURITY-STATUS.md](SECURITY-STATUS.md)), empty when never reported; `security_stale` is `true` when the report is old or the device is not online. |

Times are RFC 3339 UTC. Values from the last successful snapshot are included regardless of their age, and the CSV has no column for that age.

Spreadsheet formulas are neutralized: a value that starts with `=`, `+`, `-` or `@` (after leading spaces), or that contains a tab or line break, is prefixed with an apostrophe.

## Limits and validation

| Limit | Value |
| --- | --- |
| Adapters per report | 32 |
| IPv4 / IPv6 addresses per adapter | 16 each |
| Gateways / DNS servers per adapter | 8 each |
| Report size | 128 KiB (a larger report is reported as failed) |
| Text value | 256 bytes |

The agent drops adapters with invalid details, keeps the first 32 in the order Windows lists them and counts the rest as `skipped` (shown next to the adapter list). Addresses beyond 16 per family, and gateways or DNS servers beyond 8, are dropped without being counted. Text values longer than 256 bytes are treated as empty; control characters become spaces and leading and trailing spaces are removed.

The server decodes reports strictly:

- Every field is required with its JSON type except `skipped`; unknown fields are rejected, and an invalid report is refused as a whole.
- Text must be valid UTF-8 without control characters or leading/trailing spaces, at most 256 bytes.
- Addresses must be canonical IP addresses of the right family, the MAC must match the format above, and status, type and the join values must be one of the listed values.
- Counts are bounded: sockets 0 to 64, cores 0 to 4,096, logical processors 0 to 8,192. The install date must not be negative and the UTC offset must be within ±14 hours.
- A report for a capability version other than 1 is stored as unsupported.

All values come from the device and are untrusted text; the dashboard escapes them.

## Storage

The server keeps one row per device: the newest report's status and receipt time, and the last successful snapshot.

- A successful report replaces the snapshot; a failed, disabled or unsupported report keeps it.
- A report received earlier (by server time) than the stored one is ignored.
- The fleet identifiers (primary IPv4, addresses, MACs, serial, manufacturer, model) are stored in their own columns when a successful report arrives, so listing devices never decodes reports.
- Removing a device removes its row. Logical deletion does not securely erase SQLite pages, the WAL or backups.

## API

The device detail `GET /api/v1/devices/{id}` includes `system_info`: `capability`, `status` (`ok`, `failed`, `disabled`, `unsupported` or `not_reported`), `reported_at`, `snapshot_at`, `data` (the full report above, or `null`), `primary_ipv4` and `stale`. There is no separate endpoint.

`GET /api/v1/devices` includes, for each device, `primary_ipv4`, `addresses` (every IPv4 and IPv6 address, adapter by adapter), `macs`, `serial`, `manufacturer` and `model` from the last successful snapshot; they are empty when there is none. In the device detail's `device` object, `primary_ipv4`, `serial`, `manufacturer` and `model` are filled from the snapshot, but `addresses` and `macs` are always empty; use `system_info` for the full report.

Storage errors return HTTP 503. GET requests never trigger collection.

## Permissions

Access uses the device `read` scope, the same as software inventory and signed-in users: the administrator and every technician whose device or group scope includes the device. There is no separate permission.

## Turning it off

Device information follows the **Inventory** feature (key `inventory`); there is no separate switch.

- Switch off **Inventory** in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy), or
- lock it off on one device from an administrator PowerShell in the repository root:

```powershell
.\scripts\service.ps1 -Action configure -InventoryMode false
.\scripts\service.ps1 -Action configure -InventoryMode true   # removes the lock
```

See [feature switches](WINDOWS-SERVICE.md#feature-switches). A console agent uses `-inventory=false` or `OPENRMM_AGENT_INVENTORY=false`, which also counts as a lock.

> [!NOTE]
> Turning Inventory off also stops the basic [inventory](INVENTORY.md) and the [BitLocker and Defender status](SECURITY-STATUS.md).

When the feature is off, the agent reports **Disabled**. The last snapshot stays (stale), and the Devices list and CSV keep showing its values; switching the feature off does not delete collected data.

## Privacy

Serial numbers, system UUIDs, MAC addresses and IP addresses identify a device and, on a personal device, its user; tenant and domain names identify the organization.

- They are visible to the administrator and to every technician who can read the device, included in the device CSV, and included in backups.
- Only the newest snapshot is kept.
- The administrator can switch Inventory off per monitoring policy, and a local administrator can lock it off on a device.
- There is no action to delete the snapshot other than removing the device. A downloaded CSV is outside OpenRMM's control.

## Upgrading

The table is added by a schema migration; take a matched backup before upgrading, as for other migrations (see [RECOVERY.md](RECOVERY.md)). Upgrade the server before agents: an older server refuses the `system_info` report, and the agent logs a warning and collects again at the next interval. There is no new feature key, so older agents' switches are not affected.

## Troubleshooting

- **Not reported:** the agent does not support device information yet, or has not reported yet.
- **Disabled on device:** Inventory is off in the policy or locked locally; the Overview **Agent features** panel shows which.
- **Collection failed:** reading the network adapters failed, the five-second deadline passed, or the report was invalid or larger than 128 KiB. Check `%ProgramData%\OpenRMM Agent\logs\agent.log`. Missing firmware, processor, registry or join values do not fail the report; they are reported as empty.
- **Not provided** for serial number, UUID or BIOS: the firmware tables do not contain them (common on virtual machines).
- **Windows 10 shown on a Windows 11 device** (or the reverse): the name comes from the registry with the build rule above. The Overview's **Operating system** line uses the basic inventory's numeric version instead.
- **Installed date later than expected:** Windows can update `InstallDate` when a feature update is installed.
- **IP address empty:** no adapter is `up` with a non-link-local IPv4 address, or there is no snapshot.
- **Wrong IP address** on a device with several connections: see [Primary IPv4 address](#primary-ipv4-address).
- **Skipped count shown:** adapters were left out (invalid details, or more than 32).

## Related

- [INVENTORY.md](INVENTORY.md)
- [SECURITY-STATUS.md](SECURITY-STATUS.md)
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md)
- [ORGANIZATION.md](ORGANIZATION.md)
- [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md)
