# BitLocker and Defender Status

The agent reports BitLocker encryption, Microsoft Defender Antivirus and the antivirus products registered with Windows Security Center for each Windows device. Administrators and technicians use it to find devices with disk encryption or antivirus protection turned off.

## Overview

- A device's **System** tab has a **Security** panel with the full report.
- The **Devices** list has **BitLocker** and **Defender** columns and a security filter: **BitLocker off or suspended** or **Defender off or real-time off**.
- The device CSV export includes the same summaries.

The data is part of the **Inventory** feature and is visible to every account that can read the device.

## What is collected

The `security_status` v1 module runs at agent start and then every hour. It runs one fixed Windows PowerShell script that takes no input from outside the agent and reads WMI:

- **BitLocker:** each volume from `Win32_EncryptableVolume` (`root/CIMV2/Security/MicrosoftVolumeEncryption`):
  - drive letter and volume type (operating system, fixed or removable);
  - protection (on or off);
  - conversion state (not encrypted, encrypted, encrypting, decrypting, paused) and percentage;
  - encryption method.
- **Microsoft Defender Antivirus** (`MSFT_MpComputerStatus`):
  - whether the service and the antivirus are enabled;
  - real-time protection, behaviour monitoring and tamper protection;
  - running mode (normal, passive, EDR block);
  - product and signature versions;
  - when the signatures were last updated, and the last quick and full scan.
- **Security Center** (`root/SecurityCenter2`, `AntiVirusProduct`): every registered antivirus product, whether it is on, and whether its definitions are up to date. Security Center does not exist on Windows Server, so this list is empty there.

A missing namespace is reported as "not available" for BitLocker (for example on Windows Home) and as "not installed" for Defender. Any other failure is reported as "could not be read". Neither case fails the report. Dates are written as RFC 3339 UTC in the invariant culture, regardless of the device's regional settings.

### Limits

| Limit | Value |
| --- | --- |
| Collection time | 90 seconds |
| PowerShell output | 1 MiB |
| Report size | 64 KiB |
| BitLocker volumes | 64 |
| Security Center products | 16 |

Windows PowerShell runs from the system directory with `-NoProfile` and `-NonInteractive`, and without `PSModulePath`, so it never loads modules of a newer PowerShell.

## Summaries

The Devices list summarizes the **operating system volume** and Defender.

**BitLocker** (API value in brackets):

| Summary | Meaning |
| --- | --- |
| On (`on`) | Fully encrypted and protected. |
| Suspended (`suspended`) | Fully encrypted, but protection is off: the key is stored in the clear (suspended BitLocker, or device encryption waiting for activation). |
| Encrypting (`encrypting`) | Encryption in progress or paused. |
| Off (`off`) | Not encrypted, or being decrypted. |
| Not available (`not_installed`) | BitLocker is not part of this Windows edition. |
| Unknown (`unknown`) | The status could not be read. |

**Defender** (API value in brackets):

| Summary | Meaning |
| --- | --- |
| On (`on`) | Antivirus running with real-time protection. |
| Real-time off (`real_time_off`) | Real-time protection is off. |
| Off (`off`) | The service or the antivirus is off. |
| Passive (`passive`) | Usually means another antivirus product is primary. |
| Other antivirus (`other_av`) | Defender is off while Security Center lists another enabled antivirus product. Not matched by the "Defender off" filter. |
| Not installed (`absent`) | Defender Antivirus is not installed. |
| Unknown (`unknown`) | The status could not be read. |

A summary keeps its last value. It is shown faded, with "last known status" on hover, when the report is two hours old or more or the device is not online.

## Storage and API

- The server keeps the newest report per device; a failed report keeps the last successful snapshot. The summaries are stored in their own columns, so listing devices never decodes reports.
- **Device detail:** the `security_status` field of `GET /api/v1/devices/{id}`.
- **Device list:** the `bitlocker`, `defender` and `security_stale` fields of `GET /api/v1/devices`. The [device CSV](DEVICE-INFO.md#device-csv) has the same three columns.

Access uses the device `read` scope: the administrator and every technician whose device or group scope includes the device.

## Turning it off

Turn off the **Inventory** feature in the device's [monitoring policy](ORGANIZATION.md#agent-features-per-policy) or lock it off locally, as described in [DEVICE-INFO.md](DEVICE-INFO.md#turning-it-off). This also stops the basic inventory and device information. The last report stays visible as stale.

## Troubleshooting

- **Empty Security panel or Not reported:** the agent does not support security status yet, or has not completed its first collection (it runs at start, then hourly).
- **Collection failed:** PowerShell could not run, exceeded 90 seconds, or produced invalid or oversized output. Check `%ProgramData%\OpenRMM Agent\logs\agent.log`.
- **No Security Center products on a server:** expected; Windows Server has no Security Center.

## Related

- [DEVICE-INFO.md](DEVICE-INFO.md)
- [INVENTORY.md](INVENTORY.md)
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md)
- [ISOLATION.md](ISOLATION.md)
