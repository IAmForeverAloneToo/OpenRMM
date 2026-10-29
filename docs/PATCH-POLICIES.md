# Patch Policies

Patch policies scan Windows devices for updates, install approved KBs and optionally request a restart, all inside a weekly maintenance window. This page is for the primary administrator, who is the only account that can configure or view patch automation. Manual Windows Update actions stay available separately; see [Windows Update management](WINDOWS-UPDATES.md).

## Create a policy

Open **Manage → Patching** (`/patching`) and select **New policy**. The wizard walks through devices, window, updates, restart and a final review.

1. **Devices.** Choose a name and ring label, then explicit device IDs and/or existing groups. Groups expand to a fixed, reviewed snapshot of at most 25 devices; every member must be an active Windows device, or the review is refused. Future group members are not added. A device can belong to only one active patch policy.
2. **Window.** Choose a weekday and a **UTC** start time, with a window of 30–240 minutes. There is no local time or daylight-saving conversion and no catch-up of missed windows. Saving or resuming selects the next window at least one minute in the future.
3. **Updates.** Choose **Scan only**, or **Install approved updates** with up to 64 numeric KB identifiers.
4. **Restart.** Restarts are manual by default. You can opt in to a non-forced restart request with a 60-second warning, sent after a deferral of 1–168 hours from the first observed pending restart and only inside a permitted window.
5. **Review.** Check the exact devices, next UTC start and settings, then confirm with **Create policy** (or **Save policy**). Changing targets or settings invalidates the review.

Installing OpenRMM never creates or enables a policy.

> [!TIP]
> Use separate policies with different windows as rings, for example a small canary policy before a broad one. Promotion between rings is a deliberate administrator action.

### Which updates are installed

- Every KB advertised by an update must be on the approved list.
- Updates without KB metadata are never approved implicitly.
- Unapproved updates are left alone.
- Installation is prevented, and the run is recorded as Unknown, if any of these apply: an update bundles approved and unapproved KBs, an approved update is blocked, the scan failed or was truncated, the restart state is unknown, or more than 25 updates would be selected.

## How a window runs

When an eligible window begins, the server:

1. starts a complete scan on each device;
2. selects the exact update identities and revisions from that scan;
3. installs only approved matches;
4. runs a fresh read-only verification scan.

Devices that are offline, busy, unavailable, or whose agent lacks windowed job support are skipped for that window, with no automatic retry. A start more than 60 seconds late is skipped. A server restart ends unfinished policy work and advances past elapsed windows; it never resumes uncertain work.

The window is checked by the policy, by the agent and again by the native worker before each search, download, install and restart call, including a monotonic local deadline. A Windows call accepted inside the window can still finish after it. The read-only verification scan may run outside the window.

### Run results

| Result | Meaning |
| --- | --- |
| `scan_only` | A complete scan was recorded. |
| `approved_complete` | The approved updates are no longer applicable in a fresh complete scan. This does not claim that every Windows update is installed or prove that a particular KB was installed. |
| `pending_restart`, `reboot_deferred` | A restart is known to be required. |
| `restart_requested` | Windows accepted a restart request. A reboot has not been observed. |
| `verification_failed`, `unknown` | A mutation failed or was interrupted, verification was incomplete, or the outcome is ambiguous. |
| `skipped` | The run did not start: the start was missed, or the device was offline or busy. |
| `blocked` | The run could not proceed, for example because installing or restarting is unavailable on the device. |
| `paused` | The policy was paused, edited or archived while the run was unfinished. |

The **Recent runs** panel shows the latest 100 runs.

## Device holds

After a pending restart, a failed or interrupted mutation, or an uncertain outcome, the device gets a **hold**: further automatic changes stop until a fresh complete scan clears a restart requirement, or the administrator reviews the hold.

- **Allow patching** acknowledges the hold after review. It never replays a job. Check the actual device before acknowledging an uncertain mutation.
- **Defer restart** postpones restart requests on that device by 1–168 hours (up to seven days).
- Holds and restart deferral clocks survive policy edits, ring changes and server restarts.
- Acknowledging or deferring is refused while update work or policy stages are still active on the device.

## Pausing, editing and archiving

**Pause**, editing and **Archive** cancel queued stages and stop further orchestration. Windows calls already dispatched can finish, and installation is not interrupted mid-call. Resuming a paused policy is labelled **Turn on**. Archived policies stop permanently and free their devices for other policies; this cannot be undone.

## Permissions and security

> [!WARNING]
> The agent runs as SYSTEM and always allows update installation and restart. Patch policies, their maintenance windows and server-side permissions are the only controls. Try a new policy on a non-critical device first, and do not add devices that must never restart unattended to a policy that requests restarts.

- Only the primary administrator can create, change, pause, archive or view policies and acknowledge or defer holds.
- Policy work needs an agent that advertises the `windowed_jobs` capability. Upgrade the server first, then the agents, and keep the agent's protected state during upgrades.
- No inbound network listener is added on devices.

## Limits and retention

| Item | Limit |
| --- | --- |
| Policies | 100, including archived policies; an archived policy is deleted 90 days after archiving, once its runs have been pruned |
| Targets per policy | 25 |
| Active policies per device | 1 |
| Approved KBs per policy | 64 |
| Window length | 30–240 minutes |
| Restart deferral | 1–168 hours |
| Run history | 2,000 runs, up to 90 days |
| Update job queue | 1,000 active jobs (queued or dispatched, at most one per device; shared with manual Windows Update work); finished history is pruned to about 200 jobs |
| Window starts | Up to 100 devices every 5 seconds; a start more than a minute late is recorded as missed |

Completed run history is pruned; device holds are separate durable state. A [server restore](RECOVERY.md) pauses all policies, ends unfinished runs as Unknown and keeps device holds.

## API

| Route | Purpose |
| --- | --- |
| `GET /api/v1/patch-policies` | Policies, recent runs and device holds |
| `POST /api/v1/patch-policies/review` | Review a policy change and return its digest |
| `POST /api/v1/patch-policies/apply` | Apply a reviewed change |
| `POST /api/v1/patch-guards/{device}/review` | Review acknowledging or deferring a hold |
| `POST /api/v1/patch-guards/{device}/apply` | Apply a reviewed hold change |

## Related

- [Windows Update management](WINDOWS-UPDATES.md)
- [Groups and monitoring policies](ORGANIZATION.md)
- [Windows agent service](WINDOWS-SERVICE.md)
- [Backup and recovery](RECOVERY.md)
