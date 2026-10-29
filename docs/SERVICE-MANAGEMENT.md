# Windows Service Management

The **Services** tab lists the Windows services on a device and lets authorized accounts start, stop or restart them. This page is for administrators and technicians with the **Services** permission.

## Contents

- [Service list](#service-list)
- [Start, stop and restart](#start-stop-and-restart)
- [Which services can be controlled](#which-services-can-be-controlled)
- [Delivery and history](#delivery-and-history)
- [Turning it off](#turning-it-off)
- [Permissions, audit and API](#permissions-audit-and-api)
- [Upgrades and recovery](#upgrades-and-recovery)
- [Related](#related)

## Service list

A device's **Services** tab shows each service's name, display name and state. The agent collects the list at startup and every minute; the tab refreshes every 10 seconds.

- Only the latest successful snapshot and the latest outcome are stored.
- A snapshot is fresh only when the device is online, its latest report succeeded, and the server received it less than two minutes ago. Failed, disabled, unsupported, offline, revoked, old or future-dated readings are shown as stale.
- Publication retries can deliver an older collection, so the receipt time is not an authoritative collection time.
- Windows silently omits services the agent cannot query, so the list shows **services visible to the agent**. Kernel drivers are not included.
- A stopped service is a state, not a fault. Pending and paused states are shown.

| Limit | Value |
| --- | --- |
| Services per snapshot | 2,048 |
| Native enumeration pages | 32 |
| Snapshot size | 2 MiB |

An oversized or inconsistent collection fails instead of being silently truncated. The larger size is accepted only on the authenticated feature endpoint; heartbeat, command, enrollment and other JSON requests keep their 8 KiB limit.

## Start, stop and restart

On a fresh **Services** tab, each row offers **Start**, **Stop** and **Restart** as the agent's rights allow. Select an action, check the named service in the confirmation dialog and confirm.

- The server requires an active online device, a fresh supported snapshot and the advertised rights before queueing.
- Only one action can be outstanding per device.
- The agent picks up an action within about a second over its existing outbound mTLS connection, which waits for work ([HEARTBEATS.md](HEARTBEATS.md#waiting-for-work)). There is no inbound management listener on the device.

How each action behaves:

| Action | Behavior |
| --- | --- |
| Start | Starts the service. An already-running service succeeds with its current state. Windows may also start required dependencies. |
| Stop | Stops the service. An already-stopped service succeeds. Dependent services are never force-stopped. |
| Restart | Stops a running service, waits until it is stopped, then starts it. Restarting a stopped service starts it. |

- Pending and paused services are not forced into another state.
- The agent requests only the rights needed for the chosen action, and Windows permissions are checked again at execution.
- Execution has a 40-second deadline and checks the service state after each control. A Windows call cannot be interrupted mid-call, so timing can exceed the deadline.
- A restart can stop the service and then fail to start it. The result shows the outcome and last observed state; nothing is rolled back or retried automatically.
- A successful result describes the observed transition, not that the application stays healthy. The list may lag the result until the next minute's snapshot.
- Startup type, recovery settings and other configuration are never changed.

## Which services can be controlled

The agent runs as SYSTEM, so any listed service can be controlled **except OpenRMM's own service (`OpenRMMAgent`)**, which can only be monitored. Server-side permissions decide who may ask: the primary administrator, or a technician with the **Services** permission for that device.

The agent has no capability to change service configuration or ACLs, create or delete services, manage drivers, run a shell or pass arbitrary arguments. Permission indicators refresh with the next snapshot.

> [!WARNING]
> Stopping or restarting a service can affect privileged applications and the whole machine. Check the service before you confirm.

## Delivery and history

- Queued requests expire after one minute.
- Dispatch is committed before it is sent and happens **at most once**; it is never redelivered automatically. If the dispatch response is lost, the service may never receive the action.
- A dispatched request has a 90-second result window. Lost delivery, agent shutdown or crash, or a missing result becomes **unknown** after that window. Check the current service state before requesting another action.
- Result publication may be retried; controls are not. Identical duplicate results are accepted once; conflicting, cross-device, revoked or late results are rejected. Restarting the server or agent never replays dispatched work.
- Revoking a device stops new dispatch, but cannot undo a control already in progress.

| Item | Limit |
| --- | --- |
| Actions shown per device | 20 most recent |
| Stored action records | 1,000 globally; new actions are refused until older records can be pruned safely |

## Turning it off

- **Per policy:** switch off **Agent features → Services** in the device's [monitoring policy](ORGANIZATION.md).
- **Locally on one device:** in an administrator PowerShell from the repository root:

  ```powershell
  .\scripts\service.ps1 -Action configure -ServicesMode false
  # Remove the lock:
  .\scripts\service.ps1 -Action configure -ServicesMode true
  ```

  A local lock survives MSI installs and self-updates, and a policy cannot override it. See [Windows agent service](WINDOWS-SERVICE.md).
- A console (diagnostic) agent uses `-services=false` or `OPENRMM_AGENT_SERVICES=false`. The installed service ignores interactive environment configuration.

Turning it off stops collection and new action polling; it does not reverse controls already delivered. Other collectors and heartbeats continue.

## Permissions, audit and API

- Reading the list and action history needs read access to the device. Requesting an action needs the **Services** permission for that device (the primary administrator always has it).
- Submissions require session authentication, origin checks and the session's `X-CSRF-Token` header. Each request carries a client-generated action ID; resubmitting the same ID with the same target returns the same action.
- Each request records the account, device, service, action, action ID and server time. Dispatch, result, expiry and unknown transitions are audited in the same transaction. Results reported by the agent are descriptive data from that device, not independent attestation.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/devices/{id}/service-actions` | Recent actions for the device |
| `POST /api/v1/devices/{id}/service-actions` | Request an action; JSON body with `id`, `service` and `action` (`start`, `stop` or `restart`) |

The device detail API includes `services` and `service_actions`. The agent uses mTLS-only routes (`POST /api/v1/agent/service-actions/poll` and `/result`), which accept no client-claimed device identity or receipt time.

## Upgrades and recovery

- Back up before updating the server, then update the agent with its existing credentials. Never run an old console copy of the agent credentials next to the installed service.
- A [server restore](RECOVERY.md) cancels queued actions and marks dispatched actions unknown, so an old backup cannot bring back remote controls. Windows device state is recovered separately from the server volumes.

## Related

- [Processes](PROCESSES.md)
- [Health checks](HEALTH-CHECKS.md)
- [Technician accounts](TECHNICIANS.md)
- [Windows agent service](WINDOWS-SERVICE.md)
