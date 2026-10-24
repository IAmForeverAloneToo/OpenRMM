# Health Checks

Health checks watch individual devices for conditions beyond the built-in offline, disk, CPU and RAM alerts. The current check type is **required Windows service running**, with an optional guarded response that starts the stopped service. This page is for administrators who configure checks and technicians who review their results.

## Contents

- [Create a check](#create-a-check)
- [How a check is evaluated](#how-a-check-is-evaluated)
- [Automatic start response](#automatic-start-response)
- [Editing, re-arming and restore](#editing-re-arming-and-restore)
- [Limits and retention](#limits-and-retention)
- [Permissions, audit and API](#permissions-audit-and-api)
- [Related](#related)

## Create a check

1. Open **Manage → Health checks** (`/health-checks`) and select **New check**.
2. Choose the device and the Windows service.
3. Set the name, trigger and recovery durations, severity and optional email.
4. Optionally enable the automatic start response and its cooldown.
5. Select **Review** to see exactly what will be saved, then **Save check**.

Nothing is configured automatically. Each check belongs to one device; checks are not assigned through groups or [monitoring policies](ORGANIZATION.md).

## How a check is evaluated

| Service state reported by the agent | Result |
| --- | --- |
| Running | Healthy |
| Stopped or paused | Failing |
| Missing, inaccessible, pending, or collection failed, disabled or unsupported | Unknown |
| Device offline or report stale | Unknown |

Windows lists only services the agent can query, so a missing service does not prove a failure.

- A check opens or recovers only when **two distinct server-received reports** span the trigger or recovery duration. Reports normally arrive every minute; cached readings never count.
- A reading is fresh for less than 120 seconds, and the device must be online.
- Readings are captured in the same transaction as the telemetry, so a healthy report between evaluator passes (about every 15 seconds) is never missed.
- Unknown readings, a full reading queue, an evaluator interruption, a server restart and a backward clock change all restart qualification. **Unknown never resolves an incident.**

Incidents appear in **Alerts** with the **Health check** type. They support acknowledgment and the optional opening and recovery emails described in [alerts](ALERTS.md); email is off by default and the same pause, expiry and no-blind-retry rules apply. Acknowledging an incident only records that it was seen. To stop automation, disable the response or the check.

## Automatic start response

An administrator can separately allow a check to **start this same service** when it is stopped.

- Only a **stopped** service triggers a start. Paused, missing and pending services do not.
- The latest report must show that the agent can start the service, and Windows checks permissions again at execution.
- The response grants no permissions and changes no service configuration or identity.
- OpenRMM's own service (`OpenRMMAgent`) can be monitored but never controlled.
- Arbitrary commands, stop and restart responses are not available.

### Safeguards

- **One attempt per incident.** Queueing the start, using up the incident's attempt and setting the guard happen in one transaction.
- **Cooldown.** A cooldown of 60–10,080 minutes applies across all checks for the same device and service name (case-insensitive).
- **One control at a time.** Other pending service actions on the device delay queueing.
- **Short lifetime.** Queued work expires after one minute; once dispatched, the result window is 90 seconds.
- **Rechecked at dispatch.** The check revision, active incident, fresh failing reading, online device, monitored fleet and start capability are verified again. Healthy or unknown telemetry cancels queued work immediately. Editing or disabling the check, revoking the device and restarting the server cancel work that has not been dispatched.
- **At most once.** Dispatch is committed before it is sent and is never redelivered. Work already dispatched may finish.

A start result does not prove recovery. The incident recovers only when fresh healthy reports qualify.

### The guard

| Outcome | Guard |
| --- | --- |
| Pending | Blocked |
| Confirmed success | Released; cooldown and the incident's used attempt remain |
| Failed or uncertain | Stays blocked across recovery, edits and restarts until re-armed |
| Cancelled or expired before dispatch | Released; the incident's attempt remains used |

## Editing, re-arming and restore

- The device and ID of a check cannot change; edit or disable it instead.
- Saving a change closes the current incident as `settings_changed`, cancels queued work and restarts qualification. No recovery email is sent and the guard is not cleared.
- To clear a blocked guard, review the attempt history and the actual service state, edit the check, select **Re-arm automatic starts** and save the reviewed change. Re-arming applies to all checks for that device and service, keeps the cooldown, and restarts this check's qualification. Pending work must finish or expire first.
- A [backup restore](RECOVERY.md) disables automatic responses, resets qualification, reconciles pending actions, and keeps cooldown and uncertainty evidence. Review and re-enable responses after a restore.

## Limits and retention

| Item | Limit |
| --- | --- |
| Checks | 100 in total, 10 per device (disabled checks count) |
| Check name | 80 characters (128 UTF-8 bytes) |
| Trigger duration | 1–1,440 minutes |
| Recovery duration | 1–60 minutes |
| Cooldown | 60–10,080 minutes |
| Monitored devices | Newest 1,000 active devices, as for built-in alerts |
| Reading queue | 10,000 readings, 2,000 processed per pass |
| Attempt history | Newest 2,000 attempts, plus pending actions, current incidents and latest guard evidence |
| Hard attempt cap | 10,000; new automation stops if protected evidence fills it |
| **Automatic start attempts** list | Up to 100 attempts |

Action transitions are copied into durable attempt history before ordinary service-action history is pruned.

## Permissions, audit and API

- Only the primary administrator creates, edits and re-arms checks.
- Technicians can read checks, incidents and attempt history only within their device and group scope. The **Services** permission does not allow configuring automation.
- Audit events record configuration changes, re-arming, incidents and action metadata.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/health-checks` | Checks and recent attempts, optionally filtered with `?device=`. Scope is applied before limits. |
| `POST /api/v1/health-checks/review` | Validate a change and return its digest. Nothing is saved. |
| `POST /api/v1/health-checks/apply` | Save the change; must quote the review's digest. |

## Related

- [Device alerts](ALERTS.md)
- [Windows service management](SERVICE-MANAGEMENT.md)
- [Technician accounts](TECHNICIANS.md)
- [Backup and recovery](RECOVERY.md)
