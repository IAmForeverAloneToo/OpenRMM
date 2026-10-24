# Network Isolation

Network isolation cuts a Windows device off from the network while it stays managed from OpenRMM, so responders can contain a compromised machine and keep investigating it. It is for owners and technicians with the response permission.

> [!WARNING]
> Network isolation currently runs as a **dry run**. Agents work out and report exactly what would stay reachable, but block nothing. The Windows Filtering Platform (WFP) enforcer is built, but it is switched off in code (`isolation.Enforce = false`) until it has been verified on a test machine, including reboot persistence, server reachability, release and break-glass. The dashboard says "dry run" wherever isolation appears. Do not rely on isolation to contain a device yet.

## Contents

- [Using it](#using-it)
- [What stays reachable](#what-stays-reachable)
- [Break-glass release](#break-glass-release)
- [How it works](#how-it-works)
- [API](#api)
- [Storage](#storage)
- [Related](#related)

## Using it

### Isolate a device

On the device page, choose **More → Isolate from network…**.

| Setting | Options |
| --- | --- |
| Who | Owners, and technicians with the response permission on devices in their scope. |
| Confirmation | Type the device name. The server checks the typed name too. |
| Release automatically | Never (the default), or after 1 hour, 4 hours, 24 hours or 7 days. |
| Case | None (recorded in the audit log), an open case, or a new case (recorded in its custody log). |

### While isolating and isolated

The device page shows a red banner with:

- the phase: isolating, isolated (dry run) or releasing;
- who isolated the device and when;
- the automatic release time, if any;
- the case;
- every rule that stays reachable, as reported by the agent;
- **Release**;
- for accounts that may release, the one-time **release code** with the break-glass command.

The device list shows an **Isolating**, **Isolated** or **Releasing** badge beside the status, and has an **Isolated** status filter.

### Release

Use **Release** in the banner. If the device has not yet taken the isolate action, the action is simply cancelled.

A release that does not get through (for example, it expired while the device was offline, or it was refused) can be requested again with **Release**.

### Failures

Isolation fails when the isolate action ended without the device reporting isolation and 15 minutes have passed. Typical causes: the server's address or, for a server reached by name, the DNS resolvers were unknown. The banner then says so for a day, and the device can be isolated again. A late heartbeat that does report the isolation reopens it, with its release code.

## What stays reachable

The agent works out the rules when it isolates:

| Purpose | Traffic |
| --- | --- |
| OpenRMM server | TCP to the device endpoint's addresses on its port, outbound. The addresses are the host in the agent's credentials, resolved, plus the address a test connection actually reaches. Without a server address the agent refuses to isolate. |
| DNS resolver | UDP and TCP 53 to the resolvers of the connected adapters at that moment. For a server reached by name, the agent refuses to isolate without a resolver. |
| DHCP | Only between the device's client port (68, or 546 for DHCPv6) and the server port (67, or 547): requests to 255.255.255.255 and ff02::1:2, both ways with the servers that leased the adapters' addresses, and DHCPv6 replies from link-local addresses. |
| Loopback | 127.0.0.0/8 and ::1, both ways. |
| Allow list | Every address or network in the device's monitoring policy, both ways (empty by default). |

Everything else is blocked, in both directions, for IPv4 and IPv6.

While a device is isolated, the agent works the rules out again every 15 minutes and applies them only when they changed, because server addresses and resolvers can change. A failed refresh keeps the current rules in force.

### Allow list

The allow list is edited in **Groups & policies**, in the policy's **Reachable while isolated** field, for example to keep another security tool reachable.

- Up to 64 addresses or networks.
- Networks in their base form: `203.0.113.0/24`, not `203.0.113.7/24`.
- The list in force when the device is isolated is sent with the isolate action; later policy changes do not affect a running isolation.

## Break-glass release

Each isolation has a one-time release code of 12 characters, for example `7EGA-59CC-4SM4`. The agent keeps only the code's SHA-256. If the device loses contact with the server, a local administrator runs this in an elevated prompt:

```powershell
& "C:\Program Files\OpenRMM Agent\openrmm-agent.exe" -state "C:\ProgramData\OpenRMM Agent\state" -release-isolation 7EGA-59CC-4SM4
```

- It works offline.
- Case, spaces and dashes in the code do not matter.
- A wrong code changes nothing.
- The isolation state lives in its own folder beside the state folder (`C:\ProgramData\OpenRMM Agent\isolation`). The installed service limits it to SYSTEM and Administrators, so the command needs an elevated prompt. The state folder itself stays SYSTEM-only.
- A state that cannot be read is reported as such, never as "not isolated".
- The service and the command take turns through a lock file in the isolation folder.
- When the device reconnects, its heartbeat reports the release. The server closes the isolation and records `isolation_released` in the case or audit log.
- After any release, the code is no longer shown.

> [!IMPORTANT]
> Releasing needs both local administrator rights and the release code. Give the code only to the person who will run the command on the device.

## How it works

### Actions

Isolate and release are mutating response actions: `isolate` (with the allow list, the code's hash and the optional timed release) and `release`.

- They need the agent's `isolation` ability.
- They are journaled, so they never run twice.
- The server hands them out before any other work and outside the per-device collection limits.
- The agent runs them in a worker of their own, so they never wait behind a collection.
- The code's hash goes only to the device: job listings and the result document leave it out.
- The plain code is cleared when the device reports a release.

### Agent state

The agent keeps the state in `isolation.json` in the isolation folder, shared with the break-glass command.

- Every heartbeat reports it: whether the device is isolated, the mode (`enforced` or `dry_run`), since when, the automatic release time, the rules, and the last release (`server`, `break_glass` or `timed`).
- The agent applies the isolation again when it starts.
- A timed release happens at the first state read after its time.

### Enforcer (not yet enabled)

The enforcer uses a persistent WFP provider and sublayer with the highest weight. It has permit filters for the rules and block filters at the ALE connect and receive/accept layers for IPv4 and IPv6.

- Old filters are deleted and new ones added in one transaction, so a failure leaves the previous filters in force.
- Everything is removed by fixed keys, so the break-glass process can remove it too.
- Persistent filters survive a restart of the agent and of Windows. Boot-time filters are not used.
- The enforcer mirrors the 64-bit structures, so other architectures stay a dry run.

> [!NOTE]
> Once enforcement is enabled, uninstalling the agent while a device is isolated would leave the persistent filters behind. Release the device before uninstalling.

## API

Both routes need the response permission on the device.

| Route | Body |
| --- | --- |
| `POST /api/v1/devices/{id}/isolate` | `confirm` (the device name), `release_after` (seconds, 0–604800; 0 means never), and `case_id` or `case_title`. |
| `POST /api/v1/devices/{id}/release-isolation` | None. |

The device detail has an `isolation` field: the isolation record (with the release code only for accounts that may release) and `reported` (the agent's state). The device list has `isolation` (the phase).

## Storage

- `device_isolations` records each isolation with its code, allow list, jobs, times and how it ended (`server`, `break_glass`, `timed` or `failed`).
- `devices.isolation_json` and `devices.isolated` hold the reported state.
- `monitoring_policies.isolation_allow_json` holds the policy's allow list.

## Related

- [RESPONSE.md](RESPONSE.md): cases, custody and response actions
- [ORGANIZATION.md](ORGANIZATION.md): groups and monitoring policies
- [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md): the agent service and its folders
- See [ROADMAP.md](../ROADMAP.md) for planned work.
