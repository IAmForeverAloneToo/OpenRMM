# Agent Updates

Agent updates replace the installed Windows agent with a newer signed release from your own OpenRMM server. The agent installs the release's MSI itself and rolls back automatically if the new version is not healthy. This page is for the primary administrator who rolls out updates; building and signing releases is covered in [RELEASE.md](RELEASE.md).

## Contents

- [How it works](#how-it-works)
- [Trust model](#trust-model)
- [Using it in the dashboard](#using-it-in-the-dashboard)
- [Automatic updates (rings)](#automatic-updates-rings)
- [Manual updates](#manual-updates)
- [Update results](#update-results)
- [Self-update on the device](#self-update-on-the-device)
- [Limits](#limits)
- [Permissions and audit](#permissions-and-audit)
- [Backups and restore](#backups-and-restore)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## How it works

1. A release is the agent's Windows Installer package (`openrmm-agent.msi`) plus a signed manifest (`release.json`), signed outside the server with the release key.
2. A server build carries the release it was built with and imports it into its release library at startup. Releases can also be uploaded by hand.
3. The administrator rolls a release out from **Agent updates**, manually or through automatic update rings.
4. Each device downloads the MSI over its authenticated connection, verifies it, installs it and proves that the new agent is healthy. Otherwise it reinstalls the previous release.

No cloud service, external update feed or download-time code dependency is used. Agent updates do not update the server ([SERVER-UPDATES.md](SERVER-UPDATES.md)), other applications or Windows itself.

## Trust model

- **Keys are built into the agent.** The agent is compiled with up to eight trusted Ed25519 public keys and its release sequence. There is no local setting or remote endpoint that changes the trusted keys. An agent built without keys accepts no update, and its device shows **Needs local setup**.
- **The signing key never enters the server**, its image or its backups, so even a compromised server cannot authorize agent code. Whoever controls a trusted signing key and its passphrase can; their custody is the release authority.
- **Replay protection.** Each device keeps a replay counter (the highest release sequence it has accepted) in its update journal. It starts at the release sequence built into the installed agent, or at a higher counter kept from an earlier installation. A release is accepted only if its sequence is higher than the counter. The sequence is consumed before installation starts, so a failed release uses up its sequence too, and an older signed release can never be installed again.
- **What is signed.** The manifest binds product, operating system, architecture, version, sequence, key ID, issue and expiry time, the MSI's exact size and SHA-256, and `agent_sha256`, the hash of the `openrmm-agent.exe` inside the MSI. Devices report the hash of their running agent, so `agent_sha256` is what the fleet view compares and what a successful update must produce.

> [!NOTE]
> Release signatures are independent of Windows Authenticode. The MSI and the programs are not Authenticode-signed.

## Using it in the dashboard

Open **Agent updates** in the sidebar (**Manage**). The page lists:

- **Devices**: every Windows device with its agent version and one of **Up to date**, **Update available**, **Updating**, **Offline**, **Not reported**, **No release** or **Needs local setup** (with the reason, for example an agent built without keys, an update journal that needs local recovery, or a release key the agent does not trust).
- **Automatic updates**: the ring settings and their current state.
- **Releases**: the release library with version, sequence, size, signing key and expiry. **Upload release** adds one; **Withdraw release** removes one from use.
- **Update history**: every update job with its status.

A release bundled with the server appears automatically, recorded as `system:server-build`. To make room, the server withdraws the oldest releases it imported itself that no queued job or automatic rollout uses; uploaded releases stay. Installers downloaded from **Devices → Add device** carry the newest usable release's MSI unchanged, so new machines start on it ([ENROLLMENT.md](ENROLLMENT.md)).

## Automatic updates (rings)

Automatic updates are off until you turn them on. In **Automatic updates → Settings**:

| Setting | Values |
| --- | --- |
| Automatic updates | On or off (default off) |
| Pilot groups | Up to ten device groups |
| Delay before the rest of the fleet | 1–720 hours (default 24) |

When a new release becomes the latest:

1. Eligible devices in the pilot groups are updated within a minute.
2. Once no pilot device is still pending and at least one succeeded, the delay starts. Without pilot groups, the whole fleet waits for the delay after the release appears.
3. After the delay, every other eligible device is updated.

Any update of that release that ends **failed**, **rolled back**, **denied**, **unknown** or **needing recovery** pauses automatic updates, shows the reason on the page and opens an **Agent update failed** alert on the device (emailed when alert email is configured). **Resume** clears the pause, closes those alerts and counts only failures after the resume.

Automatic batches go through the same review and checks as manual ones and are recorded as `system:rings`.

## Manual updates

1. **Select devices.** In the **Devices** list on **Agent updates**, use **Update selected** or **Update all available**.
2. **Review.** The server resolves the exact targets (at most 25 per batch), their current agent hashes and replay counters. Every target must be online with a fresh update report, run an agent that installs MSI releases, and have the release's key built in. Start with one device as a canary.
3. **Confirm.** The confirmation is bound to the actor, the release library revision, the organization revision and the exact targets; if anything changed or became stale, the whole batch is rejected. Another batch needs another review.
4. **Watch Update history.** A queued update expires after one minute if the device does not pick it up. **Cancel update** works only for updates the device has not picked up yet; a dispatched update cannot be cancelled remotely.

**Uploading a release by hand.** Select **Upload release** and provide the signed release file (`.json`), the publisher public key and the agent package (`.msi`). The server verifies signature, validity period, hash, size and package structure, and stores the bytes privately and immutably. Uploading does not install the release anywhere or change which keys devices trust.

## Update results

| Status | Meaning |
| --- | --- |
| `succeeded` | Windows Installer finished; the installed `openrmm-agent.exe` has the release's `agent_sha256`; the new service process (LocalSystem, the installed path, started after the install) reported the release's version after a successful authenticated heartbeat, and was still healthy after a ten-second settle period. |
| `rolled_back` | The new version failed and the previous release was reinstalled, with the same proof of health. |
| `failed`, `denied` | Nothing changed on the device. |
| `unknown`, `recovery_required` | Needs local inspection. Neither is success, and neither is retried automatically. |

## Self-update on the device

1. **Download.** The agent receives the job, checks that the release is fresh, signed by a built-in key and meant for the agent it is running, downloads the MSI into its state folder and verifies its hash, size and package header.
2. **Helper.** It starts the on-demand update helper: a copy of itself at `%ProgramData%\OpenRMM Agent\update\openrmm-update-helper.exe`, detached so that it survives Windows Installer stopping the agent service. Only one helper runs at a time.
3. **Record.** The helper verifies the release against the built-in keys and the replay counter, and refuses the update unless the rollback package matches the running agent. It records the transaction and consumes the sequence in its journal (`update\journal.json`) before changing anything.
4. **Install.** It stops the agent service and runs `msiexec /i <package> /qn /norestart`. A restart request from Windows Installer is never acted on. Installer logs go to the `update` folder.
5. **Prove health.** It waits up to 90 seconds for the new agent's health proof: after each successful authenticated heartbeat, the agent reports its version to the helper over a local pipe. If the install fails or the new agent is not healthy, the helper reinstalls the previous package and waits for the same proof from it.
6. **Finish.** On success the new package becomes the rollback package. The helper exits after two idle minutes.

**Rollback package.** `%ProgramData%\OpenRMM Agent\packages\current.msi` is the package of the installed release and `current.json` its signed release, which must verify against a built-in key. The downloaded installer (or `scripts/install-agent.ps1`) stores the first one; each successful update replaces it. Without a rollback package that matches the running agent, updates are denied rather than risk leaving the device without an agent. Rollback only ever reinstalls this recorded previous release, never another one from the server.

**Interruptions.** An update interrupted by a reboot or crash is resolved when the agent next starts. It restarts the helper, which restores the previous release and reports `rolled_back`, or `recovery_required` if that fails. The agent's own small journal (`agent-upgrade.json` in its state folder) lets it collect the result instead of starting again; if it cannot reconcile the result, it reports `unknown`.

**Local safeguards.** The helper requests only the service-control rights it needs and accepts only the expected `OpenRMMAgent` registration (LocalSystem, the installed `openrmm-agent.exe`, the fixed state and log paths). It requires the agent's data folder to be owned by and writable only by SYSTEM and Administrators. Missing, corrupt or inconsistent local state blocks further updates until it is inspected locally; an unreadable journal shows as **Needs local setup**. The journal keeps at most 20 records with fixed failure labels and numeric Windows error codes, without exception text, credentials or command lines.

## Limits

| Item | Limit |
| --- | --- |
| Package size | 32 MiB |
| Release validity | At most 90 days |
| Release sequence | At most 65535 (part of the MSI version `1.0.<sequence>`) |
| Active releases in the library | 8 (200 in total, including withdrawn) |
| Targets per batch | 25 |
| Queue expiry | 1 minute |
| Health proof wait on the device | 90 seconds |
| Unconfirmed dispatch | Becomes `unknown` after 10 minutes |
| Update history | At most 2,000 jobs, kept 30 days |
| Pilot groups | 10 |

Expiring a job in the history cannot undo changes that already started on a device.

## Permissions and audit

- Only the primary administrator can upload or withdraw releases, change automatic update settings, start, review or cancel updates.
- Technicians can read update history only for devices in their current scope.
- The agent listener, which accepts only device certificates, has no administrator routes. A download requires the specific dispatched job, the matching device certificate and an unexpired authorization, and stops working after completion.
- Browser changes require the session's `X-CSRF-Token` header and strictly bounded JSON or upload fields.
- Changes to the automatic update settings are audited as `agent_rings_saved`; automatic batches are recorded with the actor `system:rings`.

## Backups and restore

- Back up the agent's `%ProgramData%\OpenRMM Agent` folder (journal, rollback package, state) separately from server backups, with a protected Windows backup process.
- Never restore a lower local replay counter on purpose. Restoring an old Windows disk image can do this too, so protect device backups.
- A server restore cancels queued jobs, marks dispatched jobs `unknown` and invalidates update reports until devices report again. It cannot reset a device's replay protection or reissue a used sequence. See [RECOVERY.md](RECOVERY.md).

## Troubleshooting

- **Needs local setup**: the reason is shown on the page. An agent built without keys, or one that does not trust the release's key, must be reinstalled locally with a correctly built MSI. A journal that needs recovery must be inspected on the device.
- **Reinstall locally: agent MSI**: the device runs an agent from an early development build that cannot install MSI releases. Convert it with `scripts/install-agent.ps1` ([WINDOWS-SERVICE.md](WINDOWS-SERVICE.md#converting-an-older-installation)).
- **No release / Download installer disabled**: no usable (not withdrawn, unexpired) release exists. Build one with `scripts/release.ps1` or upload one.
- **Automatic updates paused**: review the failed update in **Update history** and on the device, then select **Resume**.

## Related

- [Building and releasing](RELEASE.md)
- [Windows agent service](WINDOWS-SERVICE.md)
- [Device enrollment](ENROLLMENT.md)
- [Server updates](SERVER-UPDATES.md)
- [Backup and recovery](RECOVERY.md)
