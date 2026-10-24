# Device Alerts

OpenRMM raises alerts when a device goes offline, runs low on system-drive space, or keeps CPU or RAM usage high. This page is for administrators and technicians who triage alerts, and for operators who configure alert rules and optional email notifications.

## Contents

- [How it works](#how-it-works)
- [Default rules](#default-rules)
- [Triaging alerts](#triaging-alerts)
- [Configuring rules](#configuring-rules)
- [Qualification and unknown readings](#qualification-and-unknown-readings)
- [Email notifications (optional)](#email-notifications-optional)
- [Delivery behavior](#delivery-behavior)
- [Limits and retention](#limits-and-retention)
- [Permissions and API](#permissions-and-api)
- [Backup restore](#backup-restore)
- [Related](#related)

## How it works

The server evaluates telemetry the agent already sends: authenticated heartbeats and the system-drive, CPU and RAM reports. Alerts need no extra agent collector and no extra Windows permission.

- Evaluation runs about every 15 seconds.
- One active incident is kept per device and rule.
- Fresh healthy readings resolve an incident automatically after the rule's recovery duration. There is no manual "mark healthy" button.
- A problem that returns after a confirmed recovery opens a new incident.

Rules start as global defaults. [Monitoring policies](ORGANIZATION.md) can replace them per group or per device with a complete rule bundle. The effective settings are shown for each device. Agent feature switches and local locks are separate from these server-side rules.

## Default rules

Global defaults are under **Administration → Alert settings** (`/settings/alerts`).

| Rule | Condition | Trigger duration | Recovery duration | Severity |
| --- | --- | --- | --- | --- |
| Offline | No recent heartbeat | 3 minutes after the connection timeout | 1 minute of heartbeats | Critical |
| Low disk | System-drive free space strictly below 10% | 5 minutes | 1 minute | Critical |
| CPU | Usage at least 90% | 5 minutes | 1 minute | Warning |
| RAM | Usage at least 90% | 5 minutes | 1 minute | Warning |

The default connection timeout is 120 seconds, so the default offline alert opens roughly five minutes after the last heartbeat, plus evaluation delay.

> [!NOTE]
> The fixed 10% low-disk warning on the dashboard is a separate, immediate indicator. Changing the low-disk alert threshold does not change that warning.

## Triaging alerts

Open **Alerts** in the sidebar (`/alerts`). A device console's **Overview** tab lists that device's active alerts.

### Filtering and paging

- Filter by status, acknowledgment, severity, rule type, current group, and a hostname or device ID search. The API also accepts exact device (`?device=`) and tag filters.
- Search treats `%` and `_` literally. Case-insensitive matching follows SQLite's ASCII lowercase behavior.
- Custom required-service incidents use the **Health check** type. The checks themselves are under **Manage → Health checks** (see [health checks](HEALTH-CHECKS.md)).
- Counts apply all filters before paging. A page holds at most 50 incidents, ordered active first, critical first, then by opening time and ID.
- The page address keeps the filters and page number. Each request is a fresh snapshot, so new incidents can shift later pages.
- The list and the details panel refresh every 10 seconds without resetting filters.

### Incident details

Select an incident to open its details panel. It shows:

- the rule threshold and qualification period stored with the incident;
- timestamps, acknowledgment and closure reason;
- the current linked observation, shown only when it is fresh, the evaluator is fresh, and it belongs to this active incident;
- an **Email** section with this incident's notification records.

A healthy reading on an active incident means recovery is still qualifying until the evaluator confirms it. A later recurrence never supplies evidence for an older incident.

### Acknowledging

Select **Acknowledge** in the details panel. Acknowledgment records who acknowledged and when, keeps the incident open, and suppresses an opening email that has not been attempted yet. An acknowledged row can drop out of an "unacknowledged" filter; the list keeps its filters and page. If the incident ends before you submit, the request is refused; refresh to see its current state.

### Closure reasons

| Reason | Meaning |
| --- | --- |
| `recovered` | Fresh healthy readings qualified for the recovery duration. The incident status becomes **Resolved**. |
| `settings_changed` | The global rule was changed. Recovery is not claimed. |
| `policy_changed` | The device's effective rule changed through a monitoring policy. Recovery is not claimed. |
| `not_monitored` | The device was revoked or left the monitored fleet. Recovery is not claimed. |

## Configuring rules

For each rule in **Alert settings** you can:

- enable or disable the rule;
- set the threshold (whole percent, 1–99; offline has no threshold);
- set the trigger duration (1–1,440 minutes) and recovery duration (1–60 minutes);
- set the severity (warning or critical);
- enable email for the rule.

Saving an actual change closes that rule's existing incidents as `settings_changed`, cancels their queued notices, and starts qualification again. Submitting identical values changes nothing. A save based on an outdated version of the rule is rejected. Settings changes are audited.

## Qualification and unknown readings

A metric alert opens or recovers only when at least **two distinct fresh reports** span the configured duration. Re-reading a cached sample never counts.

- CPU and RAM are reported about once a minute; disk space every five minutes. Even a one-minute disk recovery therefore needs a later disk report and usually takes about five minutes.
- A healthy reading between evaluator passes resets qualification, because readings are queued in the same transaction as the telemetry write.
- Samples describe the readings observed, not continuous measurement between them.

Missing, failed, disabled, unsupported, future-dated or stale readings are **Unknown**:

- CPU and RAM readings expire after two minutes; disk readings after ten minutes.
- Metric readings also require a recent heartbeat from the device.
- Unknown interrupts any pending trigger or recovery, **never resolves an existing incident**, and hides the displayed value until a new known reading arrives.

Qualification also restarts after a server restart, a backward clock change, an evaluator gap of more than 45 seconds, or dropped readings. Existing incidents keep their identity and acknowledgment. At startup the server discards old queued readings and waits for new reports, so an offline period it did not observe is never counted. When the evaluator is unavailable or stale, the interface says so instead of showing devices as healthy.

## Email notifications (optional)

Email is **off by default**, both for the server (no SMTP configuration) and for each rule.

### SMTP configuration file

The server reads a JSON file at startup. Example with placeholder values:

```json
{
  "host": "smtp.example.com",
  "port": 587,
  "tls": "starttls",
  "username": "SMTP_USERNAME",
  "password": "SMTP_PASSWORD",
  "from": "openrmm@example.com",
  "to": ["administrator@example.com"],
  "server_url": "https://rmm.example.com",
  "root_ca_file": ""
}
```

| Field | Notes |
| --- | --- |
| `tls` | `tls` for implicit TLS (commonly port 465) or `starttls` for mandatory STARTTLS (commonly port 587). Both verify the server name and certificate and require TLS 1.2 or newer. There is no cleartext fallback and no way to skip verification. |
| `username`, `password` | PLAIN authentication inside verified TLS only. Leave both empty for a relay that needs no authentication; setting only one is rejected. |
| `from`, `to` | Plain ASCII mailbox addresses without display names or comments. At most 10 distinct recipients. |
| `server_url` | The HTTPS origin of your OpenRMM server, used for links in messages. |
| `root_ca_file` | Optional PEM file. When set, only these roots are trusted (useful for a private relay). When empty, the native server uses the operating system trust store and the container uses the public CA bundle built into the image. |

OAuth, attachments, webhooks and cloud notification services are not supported.

### Protecting the file

> [!IMPORTANT]
> Keep real SMTP credentials out of source control. Do not put passwords in environment variables, command arguments, browser forms, logs, Compose files or the repository's root `.env` file.

- The file may be at most 16 KiB. Unknown fields or invalid values stop the server at startup with a redacted error.
- **Linux:** a regular file owned by root or the server's user, mode `0600` or stricter, in a protected directory. In the container, use owner `10001:10001` and a `0700` secrets directory.
- **Windows:** the file's owner, DACL and parent directory are checked. The service account or current user, Administrators and SYSTEM are trusted; any other reader or writer of the file, or writer of the parent, is rejected.
- Keep parent directories protected too.
- The configuration is read only at startup. Restart the server after changing it.

### Enabling email

1. Create the file with an administrator-controlled editor or secret-provisioning process.
   - **Docker Compose (repository `compose.yaml`):** place it in the `secrets` volume as `/secrets/alert-smtp.json`, owned `10001:10001`, mode `0600`. Do not copy the root `.env` file into this volume.
   - **Native server:** place it anywhere protected as described above.
2. Point the server at the file:
   - Compose: set `OPENRMM_ALERT_SMTP_CONFIG=/secrets/alert-smtp.json` in `deploy/local.env`, then start the stack (for local development, `scripts/local.ps1 -Action up`).
   - Native server: pass `-alert-smtp-config PATH` or set `OPENRMM_SERVER_ALERT_SMTP_CONFIG`.

   A configured path that is missing or unreadable stops the server. An empty path disables email.
3. In **Alert settings**, enable email on the rules you want. Notifications apply to future transitions only; existing incidents are not backfilled.
4. Check the **Email notifications** panel in **Alert settings** and each incident's **Email** section. If email was paused (by an administrator or by a restore), select **Resume email**.

Server key backups include the `secrets` volume, so protect SMTP files and their backups the same way.

## Delivery behavior

- Only two events are sent per incident: **opened** and **recovered**. There are no reminders or repeated "still unhealthy" notices.
- A recovery notice is queued only after the relay accepted the opening notice.
- If a problem recovers, or is acknowledged, before its opening notice was attempted, that notice is cancelled.
- An opening notice waits while the problem reading is unknown or stale, until the problem is confirmed again.
- A newer active incident suppresses an older queued recovery notice.
- Messages are sent one at a time, at most one every two seconds.

### Retries and uncertain outcomes

- The server marks a notice as **sending** before contacting the relay. Connection, TLS and whole-attempt deadlines are bounded.
- Temporary failures before the message is transmitted, and explicit 4xx SMTP rejections, are retried: at most five attempts, with 1, 2, 4 and 8 minute delays.
- An explicit 5xx rejection or a TLS/certificate failure is final.
- If the connection is lost after the message was transmitted, the relay may have accepted it. That outcome is **Unknown** and is never resent automatically. Sends interrupted by a restart also become Unknown. Check the relay; there is deliberately no retry button for this case.
- "Sent" means the relay accepted the message, not that it reached an inbox. Each message has a stable Message-ID to help correlation.

### Cancellation

- Unattempted notices expire after one hour.
- Changing the SMTP destination configuration cancels notices queued for the old one.
- **Pause email** cancels queued notices. **Resume email** applies to future transitions and does not replay anything.
- Rule changes, device revocation and confirmed recovery also cancel obsolete queued notices.
- A message already being sent cannot be recalled.

Device text appears only in the quoted-printable message body, never in a header.

## Limits and retention

| Item | Limit |
| --- | --- |
| Monitored devices | Newest 1,000 active devices (a capacity warning appears if there are more) |
| Reading queue | 10,000 small records, up to 2,000 processed per pass; overflow resets qualification |
| Incident page size | 50 |
| Finished incidents | 2,000 or 30 days, whichever removes them first; their delivery records go with them |
| Active incidents | Always retained |

The reading queue is not historical metric storage; see [metrics](METRICS.md) for history. Deleting old records is not secure erasure from the SQLite database, its WAL file or backups. The audit log records transitions, actors and identifiers, never SMTP passwords or message contents.

## Permissions and API

- Every account can read alerts within its current device and group scope. Scope is applied before counting and paging. Group and tag filters use current assignment, not assignment at the time the incident opened. An unknown group or tag returns no matches and grants no access. A missing or inaccessible incident returns 404.
- Acknowledging, changing alert settings and pausing or resuming email are limited to the primary administrator.
- Reading pages never sends mail, evaluates incidents or acknowledges anything.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/alerts` | One page of incidents plus counts. Query parameters: `device`, `group`, `tag`, `status`, `ack`, `severity`, `kind`, `q`, `page`. |
| `GET /api/v1/alerts/{id}` | One incident with its current observation and delivery records. |
| `POST /api/v1/alerts/{id}/acknowledge` | Acknowledge an incident. |
| `GET /api/v1/alert-settings` | Global rules and email status. |
| `POST /api/v1/alert-settings/rules/{kind}` | Change one global rule. |
| `POST /api/v1/alert-settings/mail` | Pause or resume email. |

Unknown query parameters are rejected, and responses are not cached.

## Backup restore

A [server restore](RECOVERY.md) deletes the old delivery and reading queues, marks readings Unknown without claiming recovery, and **pauses email**. Review the restored deployment, then select **Resume email** in **Alert settings**. Agent credentials, the Windows service and agent feature settings are not affected.

## Related

- [Groups, tags and monitoring policies](ORGANIZATION.md)
- [Health checks](HEALTH-CHECKS.md)
- [Heartbeats](HEARTBEATS.md)
- [Backup and recovery](RECOVERY.md)
