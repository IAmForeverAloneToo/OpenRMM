# Application Deployment

Application deployment installs, verifies, updates and uninstalls reviewed, immutable **per-machine Windows MSI packages** on selected devices or groups. This page is for the primary administrator, who manages the catalog and deployments, and for technicians, who can read deployment history for their devices. Installed-software inventory is a separate feature; see [software inventory](SOFTWARE.md).

## Contents

- [Add a package](#add-a-package)
- [Deploy](#deploy)
- [What happens on the device](#what-happens-on-the-device)
- [Results and cancellation](#results-and-cancellation)
- [Limits and retention](#limits-and-retention)
- [Permissions and API](#permissions-and-api)
- [Security notes](#security-notes)
- [Related](#related)

## Add a package

Open **Manage → App deployment**, stay on **Catalog** and select **Add application** (or **New version** on an existing application). Supply:

| Field | Requirement |
| --- | --- |
| Name and description | Name up to 100 bytes; description up to 2,000 bytes |
| Installer URL | Exact HTTPS URL of an `.msi` file, up to 2,048 characters. No credentials, query string or fragment. |
| SHA-256 | The installer's hash, verified independently by you |
| ProductCode | The MSI ProductCode |
| ProductVersion | Three-part `major.minor.build`, at most `255.255.65535` (see Microsoft's [ProductVersion definition](https://learn.microsoft.com/en-us/windows/win32/msi/productversion)) |

Review and save. Saving and reviewing never download or run the installer. A saved version cannot be edited; changes create a new immutable version.

Host the installer on a trusted vendor site or a private HTTPS mirror whose certificate the device trusts. Redirects are refused. There is no package feed, package-manager bootstrap, custom installer arguments or automatic latest-version lookup.

### Supported update model

- Each package version must have a **different ProductCode**.
- Only forward **major upgrades** are supported. The installer itself must implement the major upgrade, including removing the old product.
- Same-ProductCode minor updates, MSP patches, repairs, EXE installers and per-user packages are not supported.

## Deploy

Select **Deploy** in the catalog, or **Install app** in a device console.

1. Choose the version and an **Action**: **Install**, **Update** (major update), **Uninstall** or **Verify**. **Update** also needs **Upgrade from**, the expected previous version of the same application.
2. Choose devices and/or groups. Every target must be an active Windows device; future group members are never added.
3. Review the exact hostnames and IDs, then confirm. If the package or organization changed since the review, confirm is refused and you review again.

- At most 25 devices per deployment.
- Queuing is all or nothing: one busy, offline or unsupported target rejects the whole submission. Every target must be online with scripts turned on, and no other deployment may be pending on it.
- Each job expires if it is not dispatched within one minute. The usual device certificate, capability and execution checks apply at dispatch.
- Resubmitting the same confirmed review cannot create another deployment.

## What happens on the device

Each package version generates two immutable scripts (verification and mutation) that run through the normal [script](SCRIPTS.md) path: as SYSTEM inside the agent, with the usual timeouts, containment and crash journal. These scripts are hidden from ordinary script editing and selection. The install script's SHA-256 is shown when a version is reviewed and on its details (select the version number in the catalog); review the generated code and metadata before deploying.

### Preconditions

The workflow reads ProductCode registrations from both machine-wide registry views. It does not use `Win32_Product` or MSI repair queries.

| Operation | Required registration |
| --- | --- |
| Verify | Reports which of the application's known product codes are present; absence is a valid result. |
| Install | None of the known products is present, or this exact version is already present (no change). |
| Major update | Only the selected previous ProductCode and version are present, and the target version is newer. |
| Uninstall | Only this exact ProductCode and version are present, or none of the known products is present (no change). |

"Absent" refers to the application's **known catalog product codes**. It does not rule out unregistered, per-user or other variants. Inaccessible or conflicting registrations and unrecognized versions prevent a definite result. Windows maps [uninstall registrations](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key) to product identity and version; the workflow does not validate every installed file.

### Install and update

- The installer is downloaded at execution time over OS-verified HTTPS, without ambient credentials or redirects, up to 256 MiB, through the agent's [proxy](WINDOWS-SERVICE.md#proxy) when one applies to the installer's address. Deployments of application versions saved before 0.1.5 download directly.
- The SHA-256 and the MSI's own ProductCode and ProductVersion are checked before execution using a [read-only MSI database](https://learn.microsoft.com/en-us/windows/win32/msi/installer-opendatabase).
- The staged installer runs privately with fixed quiet, per-machine and restart-suppression arguments.
- Registrations are checked again afterwards. A successful installer exit code alone never counts as a verified installation. If the previous product remains after an update, the result is Unknown.
- MSI [exit code 3010](https://learn.microsoft.com/en-us/windows/win32/msi/error-codes) means a restart is required. OpenRMM reports it but does not restart the device.

## Results and cancellation

Deployment history (**App deployment → Deployments**) and each device's **Software → App deployments** view show status, observed registrations, reason and any restart requirement. The latest observation is timestamped historical evidence; there is no continuous compliance polling. The primary administrator can open the underlying script result.

- Cancelling queued work proves it was not executed.
- After dispatch, a timeout, lost contact, cancellation, malformed or truncated result, or uncertain installer failure is **Unknown**. Windows Installer can keep running after the client process ends, so cancellation is not a rollback.
- Jobs are never retried automatically. Verify the current registration and inspect the device before choosing another operation.

A [server restore](RECOVERY.md) clears old captured observations, cancels queued work and marks dispatched or running work Unknown. Nothing is replayed. Run **Verify** on each device before relying on a restored deployment record.

## Limits and retention

| Item | Limit |
| --- | --- |
| Applications | 50 |
| Package versions | 200 in total, 20 per application |
| Targets per deployment | 25 devices |
| Installer size | 256 MiB |
| Deployment history | 2,000 records or 30 days; views show the newest 200 after applying device scope |

Each package version uses two script versions, which count toward the shared [script library](SCRIPTS.md) limits. Deployment history survives pruning of the underlying script run. Packages cannot be deleted yet, and installers are not stored by OpenRMM.

## Permissions and API

- Only the primary administrator can add packages, deploy, cancel and see installer URLs and generated scripts.
- Technicians can read deployment history for devices in their scope only.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/applications` | Catalog |
| `POST /api/v1/applications/review` | Review a new application or version |
| `POST /api/v1/applications/apply` | Save a reviewed version |
| `POST /api/v1/deployments/review` | Review a deployment and its targets |
| `POST /api/v1/deployments/apply` | Confirm a reviewed deployment |
| `GET /api/v1/deployments` | Deployment history, scoped to the account |
| `POST /api/v1/deployments/{deployment}/cancel` | Cancel a deployment job |

## Security notes

> [!WARNING]
> An installer is executable code that runs as SYSTEM. Pinning the SHA-256 proves you get the bytes you reviewed; it does not prove the installer is safe. Review installer code and custom actions independently.

> [!TIP]
> Try each new package version, including its major update and uninstall, on a disposable Windows device before deploying it widely.

## Related

- [PowerShell scripts](SCRIPTS.md)
- [Software inventory](SOFTWARE.md)
- [Groups and monitoring policies](ORGANIZATION.md)
- [Backup and recovery](RECOVERY.md)
