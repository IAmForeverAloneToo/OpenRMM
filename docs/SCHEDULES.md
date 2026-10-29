# Script Schedules

Schedules run a saved [script](SCRIPTS.md) version on one Windows device, either once at a set time or repeatedly at a fixed interval. This page is for the primary administrator, who is the only account that can create and manage schedules.

## Create a schedule

1. Open a device's **Scripts** tab and choose **New schedule**.
2. Enter a name, choose a saved script version and enter its parameters.
3. Set the first run time and, optionally, **Repeat**.
4. Select **Save schedule**.

Saving authorizes unattended execution on that device. A schedule always uses the version you selected; new script versions never replace it silently. All schedules are listed under **Scripts → Schedules**.

| Setting | Allowed values |
| --- | --- |
| First run | At least 5 seconds in the future and within 366 days. Entered in your browser's local time and stored as UTC. |
| Repeat | Off (run once), or every 5 minutes to 30 days (43,200 minutes) |

Repeats use elapsed UTC time anchored to the first run. There is no cron syntax, time zone or daylight-saving conversion, fleet targeting, dependency chain or automatic retry of failures.

You can create a schedule for an offline device. At each occurrence the server requires an active device with fresh online contact, working scripting support, a free script slot and room in the run history. Scheduled runs execute as SYSTEM inside the agent, exactly like manual runs; see [scripts](SCRIPTS.md) for containment, output limits and cancellation.

## Timing and missed occurrences

- The server checks schedules every five seconds.
- An occurrence can be queued up to 20 seconds after its due time, and delivered until 30 seconds after its due time. Execution is not real-time.
- A device runs one script at a time, including manually started work.
- There is no backlog or catch-up after an outage, and no automatic retry of failed, denied, timed-out or uncertain runs.

| Outcome | Meaning |
| --- | --- |
| `queued` | A run was created. Follow its link for status, output and exit code. |
| `skipped_unavailable` | The device was offline or revoked, scripting support was stale or off, another script occupied the slot, or run history was full. |
| `skipped_missed` | Evaluation happened after the 20-second queueing window. |
| `skipped_restart` | The occurrence was due when the server started, so it was skipped. |
| `skipped_paused` | Resuming moved past occurrences that elapsed while paused, without running them. |

A long gap produces one skipped record with an occurrence count, then the schedule moves to the next future interval. At startup the server also cancels undelivered scheduled runs. Work already dispatched follows the normal run protocol and is never redelivered; if its outcome cannot be confirmed it shows as Unknown.

A one-time schedule becomes **completed** once its occurrence is used, even if it was skipped. Completed means the schedule is finished, not that the script succeeded; check the linked run result. Pending one-time work can be cancelled from its run result.

## Managing schedules

| Action | Effect |
| --- | --- |
| **Pause** | Stops future occurrences and removes queued ones. Dispatched work continues; cancel it from its run result. |
| **Resume** | Skips elapsed intervals. A paused one-time schedule resumed after its due time completes without running. |
| **Edit** | Requires a new future first run and resubmitting the version, parameters and timing. Keeps the active or paused state. |
| **Cancel** (confirm with **Cancel schedule**) | Final. Removes queued occurrences. Create a new schedule if needed. |

Each schedule has a revision. If it changed elsewhere since you loaded it, the change is refused with **Changed elsewhere — refresh**. Repeated identical submissions cannot create extra schedules or reset progress.

## Limits and retention

| Item | Limit |
| --- | --- |
| Active and paused schedules | 100 |
| Retained schedules (all states) | 500; completed and cancelled schedules are deleted 30 days after they finished, with their occurrences |
| Occurrence records | 2,000 or 30 days, globally |
| Occurrences shown per schedule | Latest 50 |
| Run history | 2,000 runs or 30 days (shared with all script runs) |

When a run is pruned, its link disappears from the occurrence. Occurrences store identifiers, timing and outcomes, not code or output. Schedules cannot be deleted or archived yet.

## Reliability

- Using up an occurrence, creating its run, advancing the due time and writing the audit record happen in one SQLite transaction, so concurrent evaluations cannot queue duplicates and an interrupted transaction rolls back completely.
- A forward clock jump skips elapsed slots; a backward jump cannot revisit occurrences already used.
- Keep the server clock correct and run one server process per installation.
- A normal server restart keeps future schedules and skips work that was due.

A [server restore](RECOVERY.md) pauses all active and paused schedules, advances their revisions, clears occurrence history, cancels queued scripts and invalidates cached results and support status. Review restored schedules before resuming them; elapsed slots are skipped.

## Permissions, audit and API

Schedules are limited to the primary administrator. Requests require the MFA-backed session, origin checks and the `X-CSRF-Token` header, and carry the exact device, schedule ID and revision, version, arguments, name, start time and interval. Settings and parameters are stored as protected database data visible to the primary administrator; they are not a secret store. Audit records contain identifiers and outcomes, without code, parameters or output. The dashboard renders all values as escaped text.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/script-schedules` | All schedules |
| `POST /api/v1/devices/{id}/script-schedules` | Create or edit a schedule |
| `GET /api/v1/devices/{id}/script-schedules/{schedule}` | One schedule with its latest 50 occurrences |
| `POST /api/v1/devices/{id}/script-schedules/{schedule}/state` | Pause, resume or cancel |

## Related

- [PowerShell scripts](SCRIPTS.md)
- [Backup and recovery](RECOVERY.md)
- [Patch policies](PATCH-POLICIES.md)
