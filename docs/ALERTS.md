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
| `rollout_resumed` | An **Agent update failed** alert closed because automatic agent updates were resumed. |

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

Email is **off by default**, both for the server and for each rule. Configure the mail server in the dashboard; operators who prefer to provision credentials as a file can use an [SMTP configuration file](#smtp-configuration-file) instead.

### Setting up email in the dashboard

1. Open **Alert settings** and find the **Email notifications** panel (primary administrator only).
2. Fill in the mail server:

   | Field | Notes |
   | --- | --- |
   | SMTP server, Port | Host name or IP address of the relay. |
   | Encryption | **STARTTLS** (mandatory STARTTLS, commonly port 587) or **TLS** (implicit TLS, commonly port 465). Both verify the server name and certificate and require TLS 1.2 or newer. There is no cleartext fallback and no way to skip verification. |
   | User name, Password | PLAIN authentication inside verified TLS only. Leave the user name empty for a relay that needs no sign-in. |
   | Sender address, Recipients | Plain ASCII mailbox addresses without display names. At most 10 distinct recipients, separated by commas. |
   | Dashboard address | The HTTPS address of your OpenRMM server, used for links in messages. It is pre-filled from the installer settings. |

3. Tick **Send alert e-mail** and select **Save e-mail settings**. Settings take effect immediately; no restart is needed.
4. Select **Send test** to send a short test message through the saved settings. The panel shows whether the relay accepted it or why it failed (unreachable, TLS, rejected sign-in, temporary failure). Tests are limited to one every 30 seconds.
5. Enable email on the rules you want (see below).

The relay's certificate must chain to a trusted root: the operating system trust store for the native server, or the public CA bundle built into the container image. A relay with a private certificate authority needs the SMTP configuration file and its `root_ca_file`.

The password is write-only. It is stored encrypted with the server's encryption key (the same key that protects authenticator secrets) and is never returned by the API or shown again; the panel only says that a password is stored. Leave the password field empty to keep the stored one, or tick **Remove the stored password**. A database restored without its encryption key cannot decrypt the password; the panel then asks for it again.

### SMTP configuration file

When the server is started with `-alert-smtp-config`, the file takes precedence: the dashboard shows email as set by the file and its settings cannot be edited there. **Send test**, **Pause email** and **Resume email** still work. The file is read at startup. Example with placeholder values:

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

The fields match the dashboard settings above. `root_ca_file` is an optional PEM file; when set, only these roots are trusted (useful for a private relay). Setting only one of `username` and `password` is rejected.

OAuth, attachments, webhooks and cloud notification services are not supported.

> [!IMPORTANT]
> Keep real SMTP credentials out of source control. Do not put passwords in environment variables, command arguments, logs, Compose files or the repository's root `.env` file.

- The file may be at most 16 KiB. Unknown fields or invalid values stop the server at startup with a redacted error.
- **Linux:** a regular file owned by root or the server's user, mode `0600` or stricter, in a protected directory. In the container, use owner `10001:10001` and a `0700` secrets directory.
- **Windows:** the file's owner, DACL and parent directory are checked. The service account or current user, Administrators and SYSTEM are trusted; any other reader or writer of the file, or writer of the parent, is rejected.
- Keep parent directories protected too, and restart the server after changing the file.

To use the file:

- **Docker Compose (repository `compose.yaml`):** place it in the `secrets` volume as `/secrets/alert-smtp.json`, owned `10001:10001`, mode `0600`, and set `OPENRMM_ALERT_SMTP_CONFIG=/secrets/alert-smtp.json` in `deploy/local.env`. Do not copy the root `.env` file into this volume.
- **Native server:** pass `-alert-smtp-config PATH` or set `OPENRMM_SERVER_ALERT_SMTP_CONFIG`.

A configured path that is missing or unreadable stops the server. Server key backups include the `secrets` volume, so protect SMTP files and their backups the same way.

### Turning email on for rules

In **Alert settings**, tick **Email** on the rules you want. Notifications apply to future transitions only; existing incidents are not backfilled. Check the **Email notifications** panel and each incident's **Email** section. If email was paused (by an administrator or by a restore), select **Resume email**.

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
- Changing the mail server, sender, recipients or dashboard address (or turning email off) cancels notices queued for the old settings. Changing only the password keeps them.
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

The reading queue is not historical metric storage; see [metrics](METRICS.md) for history. Deleting old records is not secure erasure from the SQLite database, its WAL file or backups. The audit log records transitions, actors and identifiers (including e-mail settings changes and test messages), never SMTP passwords or message contents.

## Permissions and API

- Every account can read alerts within its current device and group scope. Scope is applied before counting and paging. Group and tag filters use current assignment, not assignment at the time the incident opened. An unknown group or tag returns no matches and grants no access. A missing or inaccessible incident returns 404.
- Acknowledging, changing alert and e-mail settings, sending test messages and pausing or resuming email are limited to the primary administrator.
- Reading pages never sends mail, evaluates incidents or acknowledges anything.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/alerts` | One page of incidents plus counts. Query parameters: `device`, `group`, `tag`, `status`, `ack`, `severity`, `kind`, `q`, `page`. |
| `GET /api/v1/alerts/{id}` | One incident with its current observation and delivery records. |
| `POST /api/v1/alerts/{id}/acknowledge` | Acknowledge an incident. |
| `GET /api/v1/alert-settings` | Global rules and email status. |
| `POST /api/v1/alert-settings/rules/{kind}` | Change one global rule. |
| `POST /api/v1/alert-settings/mail` | Pause or resume email. |
| `GET /api/v1/alert-settings/email` | Mail server settings and whether a password is stored (never the password). |
| `PUT /api/v1/alert-settings/email` | Change the mail server settings. An empty `password` keeps the stored one; `clear_password` removes it. Refused while the SMTP file is in use. |
| `POST /api/v1/alert-settings/email/test` | Send a test message with the saved settings. |

Unknown query parameters are rejected, and responses are not cached.

## Backup restore

A [server restore](RECOVERY.md) deletes the old delivery and reading queues, marks readings Unknown without claiming recovery, and **pauses email**. Review the restored deployment, then select **Resume email** in **Alert settings**. Agent credentials, the Windows service and agent feature settings are not affected.

## Related

- [Groups, tags and monitoring policies](ORGANIZATION.md)
- [Health checks](HEALTH-CHECKS.md)
- [Heartbeats](HEARTBEATS.md)
- [Backup and recovery](RECOVERY.md)
