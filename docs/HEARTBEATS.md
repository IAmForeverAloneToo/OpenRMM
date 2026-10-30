# Heartbeats and Connection Status

Heartbeats are the enrolled agent's regular authenticated check-ins with the server. They drive each device's connection status, carry automatic certificate renewal, and deliver policy feature switches back to the agent. This page is for operators running agents and servers.

## How it works

- The agent sends its first heartbeat immediately after starting and then every 30 seconds after a successful request.
- An installed Windows service starts automatically at boot and retries until the server is reachable. Enrollment persists across restarts; no new token is needed.
- The server records its own receipt time as the device's last contact and computes the status from it.

### Connection status

Open **Devices**. The list refreshes every ten seconds and shows each device's status and last contact (relative, with the exact time on hover).

| Status | Meaning |
| --- | --- |
| Awaiting contact | Enrolled, but no heartbeat has been recorded. An identity diagnostic alone does not send a heartbeat. |
| Online | Active device whose last heartbeat, as recorded by the server, is less than 120 seconds old (default). |
| Offline | Last contact is at least 120 seconds old. Stopping the agent does not delete its enrollment. |
| Revoked | An administrator revoked the device. Recent contact cannot override this status. |

After the agent stops, allow up to two minutes plus the page's ten-second refresh for the device to show Offline. Starting the agent again restores Online with the same device ID.

Status reports recent successful contact, not a guarantee that the device is reachable at the moment you view it. The page's background refreshes count as browser session activity; the absolute eight-hour session limit still applies.

### Waiting for work

Besides heartbeats and feature reports, the agent does not keep asking the server whether it has work. It holds one request open (`POST /api/v1/agent/work`) that names the kinds of work its idle workers can take: file transfers, scripts, processes, services, event logs, Windows Update, agent updates, terminal and remote desktop.

- The server answers as soon as it has work for one of them, or after 25 seconds. A change in the dashboard wakes the waiting agent at once; work queued by the server's own schedulers (script schedules, patch windows, automatic agent updates) is found within about 12 seconds.
- Only the named workers then ask for their work; the others keep sleeping. Each idle worker still checks on its own every two minutes.
- While the agent waits, the server keeps the device available for new terminal and remote desktop sessions. When nobody is connected to the desktop, the agent answers the desktop companion itself and tells the server only about changes, a session to start, and about once a minute.
- Evidence collection keeps its own check every 15 seconds.
- Measured with all features on, an idle agent sends about 25 requests a minute (most of them feature reports), down from about 170 before agent 0.1.3. With a server that does not support waits, the agent falls back to its earlier intervals.

## Running a console agent

For debugging, an enrolled agent can run in a console from the repository root (stop the installed service first and use its state directory, see [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md)):

```powershell
.\dist\windows-amd64\openrmm-agent.exe -run
```

Press Ctrl+C to stop it. A custom enrollment directory needs the same `-state` path, for example `-state .local/agent-recovery`.

## Configuration

| Setting | Where | Default | Range |
| --- | --- | --- | --- |
| `-heartbeat-interval` / `OPENRMM_AGENT_HEARTBEAT_INTERVAL` | Agent (console) | `30s` | 1 second to 5 minutes |
| `-offline-after` / `OPENRMM_SERVER_OFFLINE_AFTER` | Server | `120s` | 3 seconds to 24 hours |

```powershell
.\dist\windows-amd64\openrmm-agent.exe -run -heartbeat-interval 30s
```

For a container deployment, set `OPENRMM_SERVER_OFFLINE_AFTER` on the server service in `compose.yaml` and recreate the container. Choose an offline threshold comfortably longer than the heartbeat interval plus the request timeout.

Heartbeat requests are sequential, so a slow request adds to the interval. Feature workers (inventory and the others) run independently and may use the same authenticated HTTP client concurrently; a feature failure or a disabled feature never stops heartbeats.

## Retries and reconnects

- Network failures and temporary server or database failures trigger exponential back-off with jitter: each delay is between half and all of a growing base that starts at one second and is capped at one minute. A successful heartbeat resets the schedule.
- A throttled response waits at least one minute.
- Any other rejection (for example a 4xx from a proxy, a 403 for an unknown certificate, or an incompatible request) is retried with the same jittered back-off capped at five minutes.
- The agent logs transitions and at most one continuing-outage warning per 15 minutes; it does not log every healthy heartbeat or failed retry.
- TLS validation stays enabled during outages. The agent never erases its credentials or re-enrolls by itself.

Only cancellation (service stop) ends the heartbeat loop; no server response does.

> [!NOTE]
> When the server explicitly marks the device as revoked (HTTP 403 with `X-OpenRMM-Device-Status: revoked`), the agent logs an error, pauses all other device requests and re-checks with one heartbeat per hour. A mistaken restore or rollback therefore does not strand the device, while a real revocation still requires an authorized re-enrollment.

Job workers (services, processes, event logs, files, scripts, Windows Update, agent updates and terminal) follow the same rule: a malformed dispatch is logged and discarded without being executed, and server errors back off (5 seconds doubling to one minute for connectivity failures, five minutes for rejections) instead of ending the worker. Feature reports the server rejects are dropped and collected again at the next interval; a report that cannot be delivered for a whole interval is replaced by a fresh collection rather than delivered late.

## Automatic certificate renewal

- Before each heartbeat the agent checks its certificate's expiry. Within seven days of expiry it calls the authenticated renewal endpoint with a new key, validates and saves the replacement, and rebuilds its transport with it. The identity stays the same ([ENROLLMENT.md](ENROLLMENT.md#certificate-renewal)).
- A failed renewal is logged and retried hourly; it never prevents the heartbeat from being sent.
- If the issuing CA's own expiry prevents extending the certificate beyond the renewal window, successful checks are spaced at least six hours apart.
- After a renewal the server accepts the previous certificate for two more hours, in case the response was lost; the agent's hourly retry then receives the stored replacement. If an outage or local disk failure prevents obtaining or saving the replacement for longer than that, an administrator-authorized recovery may be needed; see [ENROLLMENT.md](ENROLLMENT.md).

The server's clock decides certificate validity. If the device clock is outside the certificate's validity window, the agent logs a warning (at most hourly) and keeps sending heartbeats. A certificate that has actually expired is rejected by the server and needs the recovery procedure in [ENROLLMENT.md](ENROLLMENT.md).

## Recorded data and security

A heartbeat contains:

- hostname, OS family, architecture and agent version;
- the features a local administrator has locked off, and the switchable features this agent understands;
- optional agent abilities and the device's network isolation state.

It contains no device ID or device timestamp. The server derives the identity from the verified client certificate and records its own receipt time; unknown JSON fields, including a claimed ID or timestamp, are rejected. The reply lists the features the device's monitoring policy switches off, limited to the features the agent says it understands. Agents ignore unknown fields in server replies (replies stay size-bounded and validated), so a newer server can add reply fields without breaking deployed agents.

The storage update rechecks the device's active status and certificate fingerprint, so a concurrent revocation cannot authorize a stale write.

Last contact and agent version survive a server restart. Status is calculated from those records and the server's clock; no background task rewrites Online/Offline rows. Clock corrections on the server cannot move a stored last-contact time backwards, and a future stored time is treated as Offline until the server clock catches up.

> [!IMPORTANT]
> Keep the server clock accurate: connection status, freshness of every report and certificate validity all depend on it.

## Related

- [ENROLLMENT.md](ENROLLMENT.md)
- [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md)
- [INVENTORY.md](INVENTORY.md)
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md)
