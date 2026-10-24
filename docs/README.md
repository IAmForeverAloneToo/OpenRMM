# OpenRMM Documentation

Guides for installing, operating and extending OpenRMM. New here? Start with **[Installing the server](INSTALL.md)**, then **[Enrolling devices](ENROLLMENT.md)**.

## Getting started

| Guide | Description |
| --- | --- |
| [Installing the server](INSTALL.md) | The one-command install on Linux with Docker, HTTPS options and the first administrator |
| [Enrolling devices](ENROLLMENT.md) | Installers for one device or a deployment, device certificates, renewal and revocation |
| [Administrator account](ADMINISTRATOR.md) | Setup, MFA, browser trust and local recovery |
| [Technicians](TECHNICIANS.md) | Additional accounts with MFA, device scope and permissions |
| [Groups and policies](ORGANIZATION.md) | Groups, tags, monitoring policies and agent feature switches |

## Operating the server

| Guide | Description |
| --- | --- |
| [Server updates](SERVER-UPDATES.md) | Signed server releases installed from the dashboard, with backup and rollback |
| [Backup and recovery](RECOVERY.md) | Verified backups, staged restore and upgrades |
| [Configuration reference](CONFIGURATION.md) | Every server and agent option |
| [Dependencies](DEPENDENCIES.md) | The dependency policy, inventory and review notes |

## The Windows agent

| Guide | Description |
| --- | --- |
| [Windows service](WINDOWS-SERVICE.md) | Installation, the MSI, feature switches and local locks |
| [Agent updates](AGENT-UPDATES.md) | Signed agent releases, pilot rings and automatic rollback |
| [Heartbeats](HEARTBEATS.md) | Online status, reconnects and certificate renewal |

## Monitoring

| Guide | Description |
| --- | --- |
| [Device workspace](DEVICE-WORKSPACE.md) | The per-device page and its tabs |
| [Inventory](INVENTORY.md) · [Device information](DEVICE-INFO.md) | Hardware, operating system, network and fleet search |
| [CPU](CPU.md) · [Memory](MEMORY.md) · [Disk space](DISK-SPACE.md) · [Uptime](UPTIME.md) | Live resource monitoring |
| [Metrics](METRICS.md) | History, charts and CSV reports |
| [Security status](SECURITY-STATUS.md) | BitLocker and Microsoft Defender |
| [Software](SOFTWARE.md) | Installed software, change history and fleet search |
| [Sessions](SESSIONS.md) · [Logons](LOGONS.md) · [Local accounts](LOCAL-ACCOUNTS.md) | Who is signed in, who signed in, and who has local rights |
| [Alerts](ALERTS.md) · [Health checks](HEALTH-CHECKS.md) | Alert rules, e-mail and service checks with remediation |

## Management

| Guide | Description |
| --- | --- |
| [Scripts](SCRIPTS.md) · [Schedules](SCHEDULES.md) | PowerShell library, fleet batches and schedules |
| [Windows Update](WINDOWS-UPDATES.md) · [Patch policies](PATCH-POLICIES.md) | Scans, installs, restarts and maintenance windows |
| [Applications](APPLICATIONS.md) | MSI deployment |
| [Services](SERVICE-MANAGEMENT.md) · [Processes](PROCESSES.md) | Start, stop and terminate |
| [Terminal](TERMINAL.md) · [Remote desktop](DESKTOP.md) · [Files](FILES.md) | Remote access |

## Incident response

| Guide | Description |
| --- | --- |
| [Incident response](RESPONSE.md) | Cases, evidence, chain of custody and the live response console |
| [Triage](TRIAGE.md) | Triage packages and profiles |
| [Persistence](PERSISTENCE.md) | The persistence report |
| [Event logs](EVENT-LOGS.md) | Queries, .evtx export and fleet log search |
| [Hunting](HUNTING.md) | Indicator hunts and saved indicator lists |
| [Network isolation](ISOLATION.md) | Isolating a device while keeping it manageable |

## Contributing

| Guide | Description |
| --- | --- |
| [Development guide](DEVELOPMENT.md) | Toolchain, layout, checks and local deployment |
| [Building and releasing](RELEASE.md) | Signed agent and server releases |
| [Web interface](UI-UX.md) | Structure and conventions of the dashboard |
| [Licensing](LICENSING.md) | AGPL-3.0-only and third-party notices |
