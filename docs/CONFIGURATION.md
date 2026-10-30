# Configuration Reference

Every option of the OpenRMM server and agent, with its environment variable and default value.

> [!TIP]
> A server installed with [`deploy/install.sh`](INSTALL.md) is configured for you through `/opt/openrmm/server.env`. Run the install command again to change it rather than editing the file by hand. Agents installed from a dashboard installer are pre-configured, and their features are switched on or off per [monitoring policy](ORGANIZATION.md).

## Contents

- [How options are resolved](#how-options-are-resolved)
- [Server](#server)
- [Agent](#agent)
- [Exit codes and logging](#exit-codes-and-logging)

## How options are resolved

- Command-line flags override environment variables, which override the defaults.
- Relative paths are resolved against the process's working directory.
- The server and the agent accept `-help`; `openrmm-updater help` lists the updater's backup commands.

## Server

### Network and TLS

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `-listen` | `OPENRMM_SERVER_LISTEN` | `127.0.0.1:8443` | Dashboard and enrollment listener. A literal loopback IP and port unless `-container-network` is set. |
| `-device-listen` | `OPENRMM_SERVER_DEVICE_LISTEN` | `127.0.0.1:8444` | Agent listener (mutual TLS with device certificates). Must differ from `-listen`. |
| `-container-network` | `OPENRMM_SERVER_CONTAINER_NETWORK` | `false` | Allows wildcard listen addresses inside a container. Do not set it for a native host process. |
| `-tls-cert`, `-tls-key` | `OPENRMM_SERVER_TLS_CERT`, `OPENRMM_SERVER_TLS_KEY` | `.local/tls/server.pem`, `.local/tls/server-key.pem` | Certificate files, used when neither ACME nor the server's own CA is configured. |
| `-tls-ca` | `OPENRMM_SERVER_TLS_CA` | empty | CA written into agent installers. Empty means agents use Windows' trusted roots. |
| `-acme-domain` | `OPENRMM_SERVER_ACME_DOMAIN` | empty | Public DNS name. Enables automatic certificates from an ACME CA (TLS-ALPN-01 on the dashboard port, which must be reachable on 443). |
| `-acme-email` | `OPENRMM_SERVER_ACME_EMAIL` | empty | Optional contact address for the ACME account. |
| `-acme-directory` | `OPENRMM_SERVER_ACME_DIRECTORY` | Let's Encrypt | ACME directory URL (`https://` only), for example a staging CA. |
| `-acme-cache` | `OPENRMM_SERVER_ACME_CACHE` | `acme` next to the database | Folder for the ACME account key and certificate. |
| `-server-hosts` | `OPENRMM_SERVER_HOSTS` | empty | Comma-separated host names or IP addresses (up to 20). Enables the server's own CA for LAN installs. Cannot be combined with `-acme-domain`. |
| `-server-ca-dir` | `OPENRMM_SERVER_CA_DIR` | `server-ca` next to the encryption key | Folder for the server's own CA and certificate. Its `ca.pem` is written into agent installers. |
| `-public-url`, `-public-device-url` | `OPENRMM_SERVER_PUBLIC_URL`, `OPENRMM_SERVER_PUBLIC_DEVICE_URL` | empty | Dashboard and agent addresses stored as the installer settings when none are set yet. Set both or neither. |

### Storage and secrets

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `-database` | `OPENRMM_SERVER_DATABASE` | `.local/data/openrmm.db` | SQLite database. Migrations apply automatically and are forward-only. |
| `-encryption-key` | `OPENRMM_SERVER_ENCRYPTION_KEY` | `.local/secrets/admin-key.bin` | Key that encrypts authenticator secrets. Back it up separately from the database. |
| `-device-authority` | `OPENRMM_SERVER_DEVICE_AUTHORITY` | `.local/secrets/device-ca/authority.pem` | Device certificate authority that issues agent identities. |
| `-evidence-dir` | `OPENRMM_SERVER_EVIDENCE_DIR` | `.local/evidence` | Case evidence store. Keep it on its own volume. |
| `-evidence-quota-gb` | `OPENRMM_SERVER_EVIDENCE_QUOTA_GB` | `100` | Total evidence quota in GiB (0 to 1048576). `0` means no quota. |

### Behaviour and integrations

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `-offline-after` | `OPENRMM_SERVER_OFFLINE_AFTER` | `120s` | A device without a heartbeat for this long is shown as offline (3s to 24h). |
| `-alert-smtp-config` | `OPENRMM_SERVER_ALERT_SMTP_CONFIG` | empty | Optional protected SMTP JSON file for alert e-mail. When set, it replaces the e-mail settings in the dashboard. See [ALERTS.md](ALERTS.md). |
| `-updater-dir` | `OPENRMM_SERVER_UPDATER_DIR` | empty | Folder shared with the updater sidecar. Empty disables updates from the dashboard. See [SERVER-UPDATES.md](SERVER-UPDATES.md). |
| `-release-keys` | `OPENRMM_SERVER_RELEASE_KEYS` | empty | Up to seven extra Ed25519 public keys (hex) trusted for server releases, next to the project key. |
| `-trusted-proxies` | `OPENRMM_SERVER_TRUSTED_PROXIES` | empty | Up to 20 IP addresses or CIDR ranges of reverse proxies in front of the dashboard. For requests from them, the client address is the rightmost `X-Forwarded-For` entry that is not itself a listed proxy. |
| `-log-level` | `OPENRMM_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |

### One-off operations

These flags run a single local task and exit. Only one may be given at a time.

| Flag | Purpose |
| --- | --- |
| `-admin-link` | Prints a one-time token for the first-administrator setup page (`/setup#<token>`, valid for one hour). |
| `-admin-setup`, `-admin-confirm`, `-admin-reset` | Local administrator setup, MFA confirmation and recovery through JSON on standard input. See [ADMINISTRATOR.md](ADMINISTRATOR.md). |
| `-health` | Checks that the running server is ready, verifying its certificate with the same trust agents use. Used as the container health check. |
| `-storage-info` | Prints local storage metadata and the schema version. |

## Agent

### Connection and state

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `-server` | `OPENRMM_AGENT_SERVER_URL` | `https://127.0.0.1:8443` | Server address used for enrollment and health checks. |
| `-device-server` | `OPENRMM_AGENT_DEVICE_URL` | `https://127.0.0.1:8444` | Agent listener address. |
| `-ca` | `OPENRMM_AGENT_CA` | `.local/tls/ca.pem` | Trusted CA bundle for the server certificate. |
| `-state` | `OPENRMM_AGENT_STATE` | `.local/agent` | Folder for the device identity and local state. |
| `-timeout` | `OPENRMM_AGENT_TIMEOUT` | `5s` | Request timeout (1s to 1m). |
| `-heartbeat-interval` | `OPENRMM_AGENT_HEARTBEAT_INTERVAL` | `30s` | Heartbeat interval (1s to 5m). |
| `-log-level` | `OPENRMM_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |

Server addresses must be HTTPS origins without credentials, query, fragment or path.

### Features

Every feature is on by default and is controlled per [monitoring policy](ORGANIZATION.md). Setting a flag to `false` (for example `-terminal=false`) is a **local lock** that no policy can override. On an installed service, the same lock is set with `scripts/service.ps1 -Action configure -<Feature>Mode false`; see [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md#feature-switches).

| Flag | Environment | What it controls |
| --- | --- | --- |
| `-inventory` | `OPENRMM_AGENT_INVENTORY` | Inventory and device information (interval set by `-inventory-interval`, default `15m`, 1m to 15m) |
| `-disk-space` | `OPENRMM_AGENT_DISK_SPACE` | System-drive space, every five minutes |
| `-memory` | `OPENRMM_AGENT_MEMORY` | Memory use, every minute |
| `-cpu` | `OPENRMM_AGENT_CPU` | CPU use, every minute |
| `-uptime` | `OPENRMM_AGENT_UPTIME` | Uptime and last boot, every minute |
| `-services` | `OPENRMM_AGENT_SERVICES` | Service snapshots and start, stop and restart |
| `-processes` | `OPENRMM_AGENT_PROCESSES` | Process snapshots and termination |
| `-software` | `OPENRMM_AGENT_SOFTWARE` | Installed software, every fifteen minutes |
| `-sessions` | `OPENRMM_AGENT_SESSIONS` | Signed-in Windows sessions, every minute |
| `-local-accounts` | `OPENRMM_AGENT_LOCAL_ACCOUNTS` | Local accounts and privileged group members, every fifteen minutes |
| `-event-logs` | `OPENRMM_AGENT_EVENT_LOGS` | On-demand event log queries |
| `-windows-updates` | `OPENRMM_AGENT_WINDOWS_UPDATES` | Windows Update scan, install and restart |
| `-scripts` | `OPENRMM_AGENT_SCRIPTS` | PowerShell script execution |
| `-terminal` | `OPENRMM_AGENT_TERMINAL` | Interactive PowerShell terminal |
| `-desktop` | `OPENRMM_AGENT_DESKTOP` | Remote desktop (installed service only) |
| `-files` | `OPENRMM_AGENT_FILES` | File browsing and transfer |
| `-response` | `OPENRMM_AGENT_RESPONSE` | Incident response: evidence, live response actions, triage, hunts and isolation |

### Operations

| Flag | Purpose |
| --- | --- |
| `-run` | Runs the agent in the console until stopped (development). |
| `-service`, `-log-directory` | Used by the installed Windows service. |
| `-enroll`, `-connect`, `-renew` | One console operation: enroll, test the device identity, or renew the device certificate. |
| `-ready` | Probes the server's `/readyz` route instead of `/healthz`. |
| `-release-isolation <code>` | Break-glass: lifts network isolation locally with the one-time release code. See [ISOLATION.md](ISOLATION.md). |

## Exit codes and logging

| Code | Meaning |
| --- | --- |
| `0` | Success, or help was shown |
| `1` | Runtime failure |
| `2` | Invalid arguments or configuration |

Logs are JSON lines on standard error. Diagnostic messages leave out raw configuration values, private keys, server response bodies and transport errors that could contain untrusted input.

## Related

- [Installing the server](INSTALL.md)
- [Development guide](DEVELOPMENT.md)
- [Windows agent service](WINDOWS-SERVICE.md)
