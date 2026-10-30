# Windows Agent Service

The OpenRMM agent runs on each Windows x64 device as one Windows service under LocalSystem. This page explains how it is installed, what it installs, how to operate and diagnose it, and how agent features are switched on and off. It is for administrators who manage devices.

## Contents

- [Overview](#overview)
- [Install from a downloaded installer](#install-from-a-downloaded-installer)
- [Install a development build](#install-a-development-build)
- [What the package installs](#what-the-package-installs)
- [Security notes](#security-notes)
- [Operate and diagnose](#operate-and-diagnose)
- [Feature switches](#feature-switches)
- [Uninstall](#uninstall)
- [Converting an older installation](#converting-an-older-installation)
- [Related](#related)

## Overview

- The agent is installed, updated and removed as one Windows Installer package, `openrmm-agent.msi`.
- Scripts, Windows Update (scan, install and restart), process and service control, the terminal, file transfer and evidence collection run inside the one `OpenRMMAgent` service. Server-side permissions, policies and maintenance windows decide who may use them.
- The service only makes outbound TLS connections and opens no inbound port.
- The desktop companion `openrmm-desktop.exe` starts minimized at every user sign-in for attended remote desktop. A session starts without a consent prompt; the companion window comes to the front as the visible sharing banner with **Stop sharing**. See [remote desktop](DESKTOP.md).
- Agent updates are signed releases that the agent installs itself, with automatic rollback; see [agent updates](AGENT-UPDATES.md).

## Install from a downloaded installer

New machines are installed and enrolled with a ZIP downloaded from **Devices → Add device**. On the machine, extract the whole ZIP, then double-click `install.cmd` (it asks for administrator approval), or run `install.cmd /quiet` as administrator or SYSTEM, for example from Intune, Group Policy or a remote shell.

The setup checks the MSI against its signed release, protects the data folder, installs the MSI silently and waits up to two minutes for the service to enroll. It needs Windows PowerShell 5.1 or later and nothing else. Steps, exit codes and the enrollment process are described in [ENROLLMENT.md](ENROLLMENT.md#install-on-the-device).

## Install a development build

For an MSI built from source, first build and sign a release with `scripts/release.ps1` ([RELEASE.md](RELEASE.md)). It produces `dist/windows-amd64/openrmm-agent.msi` and its signed release `internal/agentbundle/files/release.json`. Then, from the repository root in **PowerShell 7 as administrator**:

```powershell
.\scripts\install-agent.ps1
.\scripts\service.ps1 -Action status
```

`-Msi` and `-Release` select a different package and signed release. The script:

- checks that the signed release is an MSI release whose SHA-256 matches the package;
- if this exact release (product version `1.0.<sequence>`) is already installed, only refreshes the rollback package and stops;
- if an `OpenRMMAgent` service exists that was not installed by the MSI, converts it first (see [Converting an older installation](#converting-an-older-installation));
- runs `msiexec /i <package> /qn /norestart` with a verbose log in the temporary folder; a restart request is not acted on;
- stores the MSI and its signed release as the first rollback package in `%ProgramData%\OpenRMM Agent\packages` (`current.msi`, `current.json`), which self-update needs;
- waits up to a minute for the service to reach Running.

`install-agent.ps1` does not enroll a device. The service uses the identity already in `%ProgramData%\OpenRMM Agent\state`, or enrolls with an `enrollment.json` placed in `%ProgramData%\OpenRMM Agent` (as the downloaded installer does). To add a new machine, use a downloaded installer.

> [!WARNING]
> Never put enrollment tokens, passwords or keys in service arguments, and never run a console agent and the service with the same identity at the same time.

## What the package installs

- `openrmm-agent.exe` as the `OpenRMMAgent` service (display name **OpenRMM Agent**), running as LocalSystem with automatic start.
- `openrmm-desktop.exe`, registered under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` as **OpenRMM Desktop** (`openrmm-desktop.exe --background`). The running agent also starts the companion in signed-in sessions that have none, such as after an update.
- `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md`.
- The `state` and `logs` folders under `%ProgramData%\OpenRMM Agent`. The package never installs or removes device identity or state.

Installing any agent version replaces whichever version is installed, even a newer one, so the same package works for upgrades and for self-update rollback.

At startup, the agent itself sets delayed automatic start and crash recovery (which the MSI cannot express), locks `%ProgramData%\OpenRMM Agent` to SYSTEM and Administrators, and lets an interrupted self-update finish its rollback.

| Location | Access and purpose |
| --- | --- |
| `%ProgramFiles%\OpenRMM Agent` | Agent, desktop companion and notices. Standard Program Files permissions. |
| `%ProgramData%\OpenRMM Agent` | Protected data root. SYSTEM and Administrators only, enforced by the agent at startup. |
| `state` below the data root | Device certificate, key and trust, local journals, saved feature settings and downloaded update packages. |
| `logs` below the data root | One 1 MiB active log and two backups, at most 3 MiB from normal logging. |
| `update` below the data root | Self-update journal and replay counter, the update helper copy and Windows Installer logs. |
| `packages` below the data root | Rollback package: the installed release's MSI and signed release. |
| `device.json` in the data root | Device ID and device address (no secrets), written at every start. |

## Security notes

- LocalSystem has full control of the local machine, so scripts and terminal sessions started through OpenRMM have that control too. Device authentication still uses the agent's individual TLS certificate. See [Microsoft's LocalSystem account documentation](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account).
- Ordinary users have no access to the data folders. Local administrators and SYSTEM remain trusted; this is not a sandbox against a compromised administrator or other SYSTEM code.
- The agent never offers its own program, data, state or log folders through file transfer.
- Remote service and process management never stop the `OpenRMMAgent` service or end `openrmm-agent.exe`, `openrmm-update-helper.exe` or `openrmm-desktop.exe`.
- Service mode ignores interactive environment overrides and uses absolute arguments; the working directory does not affect credential or log paths.

## Operate and diagnose

```powershell
.\scripts\service.ps1 -Action status
.\scripts\service.ps1 -Action stop
.\scripts\service.ps1 -Action start
Get-Content "$env:ProgramData\OpenRMM Agent\logs\agent.log" -Tail 30
```

`scripts/service.ps1` reports status (including local feature locks), starts and stops the service and sets local feature locks. Installing, updating and removing go through the MSI. `start`, `stop`, `configure` and reading the protected log need administrator rights; `status` works without elevation. The script also runs on Windows PowerShell 5.1.

**Service health.** A Running service can be retrying an unreachable server. Check that the device is **Online** in **Devices**, or look for `agent connected; heartbeats active` in the log. A normal stop records `Windows service stopped cleanly`; on Stop or Shutdown the service waits up to eight seconds for its work to finish.

**Crash recovery.** Windows restarts the service after one and then two minutes, then takes no action until the failure count resets after a day without failure. Server responses never end the agent: revocation pauses it and checks again hourly, and other rejections are retried (see [heartbeats](HEARTBEATS.md)). Controlled exits for local problems, such as unreadable credentials or configuration, do not request a restart; fix the reported condition and start the service.

| Exit code | Meaning |
| --- | --- |
| 87 | Invalid service arguments. |
| 5 | The log directory is unavailable. |
| Service-specific 1 | Agent failure. |
| Service-specific 2 | Shutdown or lifecycle failure. |

Review the protected log and folder permissions. Do not disable TLS verification or grant broad directory access to work around a failure.

**Console debugging.** Stop the service first, then run the installed executable as SYSTEM with `-run -state "$env:ProgramData\OpenRMM Agent\state"` (the state folder and the device key belong to SYSTEM; an administrator account cannot use them). Stop that console before starting the service again.

**After a Windows restart.** The service starts automatically (delayed start) and retries until the server is reachable. The local development server does not start with Windows; start it with `.\scripts\local.ps1 -Action up`, and the device returns to **Online** without enrolling again.

## Proxy

The agent connects directly unless a proxy is set. It uses the first of:

1. **Machine policy.** The string value `Proxy` under `HKLM\SOFTWARE\Policies\OpenRMM\Agent`, settable by Group Policy. Every user on the machine can read this key, so prefer a proxy without a password here.
2. **Installer setting.** `install.cmd /proxy VALUE`, on a new machine or on one where the agent is already installed (it restarts the agent). The agent keeps the value encrypted with Windows DPAPI in its SYSTEM-only state folder; `install.cmd /proxy none` removes it.
3. **The machine's WinHTTP proxy** (`netsh winhttp set proxy`), including its bypass list. The per-user Internet Options proxy and automatic configuration (WPAD or PAC scripts) are not used.

`VALUE` is `http://host:port`, `http://user:password@host:port` (Basic authentication; percent-encode special characters in the password) or `direct` (no proxy, overriding the WinHTTP proxy). Proxies that require Windows sign-in (NTLM or Kerberos) are not supported; let the OpenRMM server's addresses through without sign-in.

- The connection to the server stays end-to-end TLS inside the proxy tunnel (`CONNECT`); the proxy cannot read or change it, and mutual TLS works through it.
- Changes to the policy value or the WinHTTP proxy apply within five minutes. The agent log names the proxy in use when the agent starts or renews its certificate (never the password), and policy or installer values it ignores because they are invalid.
- Enrollment, heartbeats, all agent work and agent updates use the proxy. While a device is network-isolated, the proxy's address is what stays reachable.
- Application deployments download their installers directly, not through the proxy ([applications](APPLICATIONS.md)).
## Feature switches

Every agent feature is on by default. There are two ways to turn one off.

1. **Per monitoring policy (the normal way).** In **Groups & policies**, switch features off in the **Agent features** section of a monitoring policy. A device uses its own policy, else its group's policy, else the global defaults (everything on). The server sends the switched-off features in every heartbeat reply. The agent saves them (`feature-settings.json` in its state folder) and restarts its work with the new settings within one heartbeat; the service process and its identity stay. Restarting the work interrupts an active terminal or remote desktop session on that device. See [monitoring policies](ORGANIZATION.md).
2. **Local lock on one device.** A local administrator can lock a feature off on one device, whatever its policy says. A policy cannot turn a locked feature back on.

Locks are DWORD values named after the feature under `HKLM\SOFTWARE\Policies\OpenRMM\Agent`; the value `0` locks the feature off. They can be set by Group Policy and survive MSI installs, self-updates and rollbacks. To set or remove them from an administrator PowerShell:

```powershell
.\scripts\service.ps1 -Action configure -TerminalMode false   # lock the terminal off
.\scripts\service.ps1 -Action configure -TerminalMode true    # remove the lock
.\scripts\service.ps1 -Action status                          # list local locks
```

- `false` writes the value `0`; `true` removes the value. Several features can be named in one command; features not named keep their current lock.
- `configure` restarts a running service so the agent applies the locks, and leaves a stopped service stopped.
- The agent reads the locks whenever its work starts and reports them in each heartbeat. The device page's **Agent features** panel shows them as **Locked off on device**.
- Agent command-line switches such as `-terminal=false` also count as locks; the MSI registers the service without them. `-Action status` lists only the registry locks.

| Feature (policy label) | Registry value | `service.ps1` parameter | Notes |
| --- | --- | --- | --- |
| Inventory | `inventory` | `-InventoryMode` | At startup and every 15 minutes; heartbeats continue when off. Also covers [device information](DEVICE-INFO.md). See [inventory](INVENTORY.md). |
| CPU | `cpu` | `-CPUMode` | Samples about one second, every minute. See [CPU](CPU.md). |
| Memory | `memory` | `-MemoryMode` | Physical RAM at startup and every minute. See [memory](MEMORY.md). |
| Disk space | `disk_space` | `-DiskSpaceMode` | System drive at startup and every five minutes. See [disk space](DISK-SPACE.md). |
| Uptime | `uptime` | `-UptimeMode` | At startup and every minute. See [uptime](UPTIME.md). |
| Software inventory | `software` | `-SoftwareMode` | Installed applications. See [software inventory](SOFTWARE.md). |
| Signed-in users | `sessions` | `-SessionsMode` | Signed-in Windows sessions at startup and every minute. See [signed-in users](SESSIONS.md). |
| Local accounts | `local_accounts` | `-LocalAccountsMode` | Local user accounts and members of Administrators and Remote Desktop Users, at startup and every 15 minutes. See [local accounts](LOCAL-ACCOUNTS.md). |
| Services | `services` | `-ServicesMode` | Snapshots and start/stop/restart of any service except `OpenRMMAgent`. See [service management](SERVICE-MANAGEMENT.md). |
| Processes | `processes` | `-ProcessesMode` | Snapshots and termination, except OpenRMM's own and critical processes. See [processes](PROCESSES.md). |
| Event logs | `event_logs` | `-EventLogsMode` | Access probe of System, Application and 14 key channels every minute; contents only on request. See [event logs](EVENT-LOGS.md). |
| Windows Update | `windows_updates` | `-WindowsUpdatesMode` | Scan, install and restart. Jobs already accepted by Windows are not cancelled when turned off. See [Windows Update](WINDOWS-UPDATES.md). |
| Scripts | `scripts` | `-ScriptsMode` | PowerShell scripts and application deployment as SYSTEM. See [scripts](SCRIPTS.md). |
| Terminal | `terminal` | `-TerminalMode` | Interactive PowerShell as SYSTEM. See [terminal](TERMINAL.md). |
| Files | `files` | `-FilesMode` | Every local fixed drive except OpenRMM's own folders. See [file transfer](FILES.md). |
| Remote desktop | `desktop` | `-DesktopMode` | The companion connection (installed service only). See [remote desktop](DESKTOP.md). |
| Incident response | `response` | `-ResponseMode` | Evidence collection and response actions for cases, with the same path, link and deny rules as Files; independent of Files. See [incident response](RESPONSE.md). |

A switched-off feature stops on the device: the agent reports it as disabled and the server refuses work for it. Server-side permissions, patch policies and maintenance windows still decide who may use the features that are on.

> [!NOTE]
> Any change to a device's feature settings restarts the agent's work, which interrupts an evidence upload in progress. The server hands the upload out again after three minutes without activity, and the agent resumes it from the chunks already uploaded if the feature is still on.

## Uninstall

Use **Programs and Features** (**OpenRMM Agent**) or `msiexec /x` with the agent MSI. Uninstall stops and removes the service, the program folder and the desktop companion's sign-in entry.

It keeps `%ProgramData%\OpenRMM Agent` (credentials, logs, the update journal and the rollback package) and the local feature locks under `HKLM\SOFTWARE\Policies\OpenRMM\Agent`. There is no purge option; the credentials stay until an administrator deletes the folder.

- A downloaded installer run later keeps the old folder as `%ProgramData%\OpenRMM Agent.previous-<timestamp>` and enrolls the machine as a new device.
- Deleting the folder does not revoke the device on the server. Revoke an abandoned identity in **Devices**.
- Never silently replace a service identity or merge credential bundles.

## Converting an older installation

Early development builds installed the agent with `scripts/service.ps1 -Action install`, some with separate helper services (`OpenRMMAgentUpdater`, `OpenRMMScriptRunner`, `OpenRMMUpdateBroker`). Such a device shows **Reinstall locally: agent MSI** on **Agent updates**, because it cannot install MSI releases. Convert it with the same command as a new install, from an administrator PowerShell 7 in the repository root:

```powershell
.\scripts\install-agent.ps1
.\scripts\service.ps1 -Action status
```

When `OpenRMMAgent` exists but no **OpenRMM Agent** product is installed, the script stops and deletes those services, removes `%ProgramFiles%\OpenRMM Agent` (it refuses a link there), then installs the MSI and stores the rollback package. The MSI also removes the helper services if they are still present, and the agent removes their leftover folders at startup.

- Device credentials, state and logs under `%ProgramData%\OpenRMM Agent` are kept.
- Feature switches from the old service command line are not carried over, so every feature is on afterwards. Turn features off per monitoring policy or lock them locally.
- Old policy files such as `terminal-policy.json` or `file-policy.json` are no longer read and are not deleted.
- There is no scripted way back. Take a device backup or image before converting.

Afterwards, check that the device returns to **Online** and that the badge disappears from **Agent updates**.

## Related

- [Device enrollment](ENROLLMENT.md)
- [Agent updates](AGENT-UPDATES.md)
- [Heartbeats](HEARTBEATS.md)
- [Groups and policies](ORGANIZATION.md)
- [Backup and recovery](RECOVERY.md)
