# Backup and Recovery

This page explains what an OpenRMM server backup contains, how backups are taken and restored, and what a restore changes so that old work is never replayed. It is for operators of a self-hosted server.

## Contents

- [What to back up](#what-to-back-up)
- [Production installs](#production-installs)
  - [Take a backup and copy it off the machine](#take-a-backup-and-copy-it-off-the-machine)
  - [Restore](#restore)
- [Local deployment: the recovery tool](#local-deployment-the-recovery-tool)
- [Take and verify a backup](#take-and-verify-a-backup)
- [Prepare the revocation list](#prepare-the-revocation-list)
- [Stage a restore](#stage-a-restore)
- [Activate and check the restored server](#activate-and-check-the-restored-server)
- [What a restore changes](#what-a-restore-changes)
- [Case evidence](#case-evidence)
- [Windows agent state](#windows-agent-state)
- [Rebuilding and upgrading the local server](#rebuilding-and-upgrading-the-local-server)
- [Related](#related)

## What to back up

A usable server backup is a matched set, taken at the same time:

| Part | Contents | Notes |
| --- | --- | --- |
| Database directory | SQLite database with its WAL/journal files | Copying only a live `.db` file can lose transactions or corrupt the copy. |
| Secrets | Administrator encryption key (`admin-key.bin`), device CA signing material, the server's own CA (LAN installs) | Without the matching key, MFA secrets cannot be decrypted and startup fails. Protect separately from the database. |
| Evidence | Collected case evidence | Can be far larger than the database; see [Case evidence](#case-evidence). |
| TLS (local deployment) | Development HTTPS certificates and keys | Production installs keep certificates in the data and secrets volumes. |
| Configuration | `install.conf`, `server.env`, `compose.yaml`, the exact image version | Needed to recreate the same deployment. |

A stopped full-volume copy, or SQLite's online backup of a running database, keeps SQLite consistent. See the SQLite guidance on [backups](https://www.sqlite.org/backup.html) and [WAL](https://www.sqlite.org/wal.html), and Docker's guidance on [backing up volumes](https://docs.docker.com/engine/storage/volumes/#back-up-restore-or-migrate-data-volumes).

> [!IMPORTANT]
> The server backup never contains agent private keys or the agent release signing key. Back up the signing key folder and its passphrase separately (see [RELEASE.md](RELEASE.md)), and back up Windows agent state with a Windows backup process (see [Windows agent state](#windows-agent-state)).

## Production installs

A server installed with `deploy/install.sh` ([INSTALL.md](INSTALL.md)) backs itself up. The updater container copies the database and the `secrets` volume into the `openrmm_backups` volume:

| Backup | When | Kept |
| --- | --- | --- |
| Nightly | Every night at the hour set in **Administration → Backups** (03:00 UTC by default). After downtime it runs as soon as the updater is back. | 7 |
| On request | **Back up now** in the dashboard, or `install.sh backup` | 5 |
| Before an update | Every update from the dashboard ([SERVER-UPDATES.md](SERVER-UPDATES.md)) | 3 |
| Before a restore | Every `install.sh restore` (the replaced state) | 3 |

Nightly and on-request backups run **while the server keeps running**: the database is copied with SQLite's online backup (`VACUUM INTO`), which gives a consistent snapshot without stopping anything. Every other file is copied and compared with its original by SHA-256, and the database copy must pass SQLite's integrity check before the backup counts. A backup that fails is discarded and shown in the dashboard; a failed nightly backup is tried again an hour later.

The **Backups** page lists the backups on the server, the result of the last one and the next scheduled run. Restores stop the server, so they are done on the server machine.

### Take a backup and copy it off the machine

```bash
sudo bash install.sh backup
```

This takes a backup now and saves it as one file, `/opt/openrmm/backups/<name>.tar.gz` (root-only), with its checksum list inside. Copy that folder to separate, protected storage regularly.

> [!IMPORTANT]
> A backup holds the server's keys (the administrator encryption key and the device and server certificate authorities). Anyone with the file can impersonate the server to your agents. Protect and encrypt copies like the server itself.

Case evidence is not part of these backups; it can be much larger. Add `--evidence` to also export the evidence stored since the last export (`/opt/openrmm/backups/evidence/evidence-<time>.tar`). Evidence files never change after collection, so each export holds only new files, and every file is checked against its SHA-256 name when it is added back.

`sudo bash install.sh backups` lists the backups in the volume and the exported files.

### Restore

```bash
sudo bash install.sh restore nightly-20270115-030000
sudo bash install.sh restore /path/to/manual-20270115-120000.tar.gz
```

The restore:

1. imports the file into the backups volume, if a file was given (a backup of the same name already there is never replaced; restore it by name);
2. stops the server and the updater;
3. verifies every file of the backup against its checksum;
4. backs up the current state as `pre-restore-<time>`;
5. reads the devices revoked in the current database, so they stay revoked;
6. replaces the `data` and `secrets` contents with the backup and applies the changes in [What a restore changes](#what-a-restore-changes);
7. starts the server and waits until it is ready.

If the restored database cannot be prepared (for example a backup from a newer version than the installed one), the previous state is put back and the server starts as it was. To undo a restore, restore its `pre-restore-` backup.

| Option | Use |
| --- | --- |
| `--revocations FILE` | The current server is lost (new machine). Give a reviewed revocation list for the backup's installation; see [Prepare the revocation list](#prepare-the-revocation-list). Without it, devices revoked after the backup was taken can connect again. |
| `--skip-safety-backup` | The current database is damaged and cannot be backed up or read. Combine with `--revocations` where possible. |

On a new machine, install the same or a newer version first, copy the backup file over, then restore it. The agents keep their saved server address, so give the new machine the same DNS name or IP address.

To add exported evidence back: `sudo bash install.sh restore-evidence` (all exports under `/opt/openrmm/backups/evidence`, in order) or `sudo bash install.sh restore-evidence FILE`. Files already present are skipped.

> [!NOTE]
> Without the updater (for example with rootless Docker) there are no nightly backups. Stop the server (`cd /opt/openrmm && sudo docker compose stop`), copy the `openrmm_data`, `openrmm_secrets` and `openrmm_evidence` volumes together with the installation folder to protected storage, then start it again. Copying volumes back by hand does not apply the revocation carry-over or the changes in [What a restore changes](#what-a-restore-changes); review revoked devices, credentials and queued work yourself before accepting traffic.

## Local deployment: the recovery tool

For development, `scripts/recovery.py` backs up and restores the local Docker deployment started with `scripts/local.ps1` (named `data`, `tls`, `secrets` and optional `evidence` volumes, ports bound to `127.0.0.1`). It:

- uses only Python's standard library and the Docker CLI, and runs inside WSL as root;
- never reads the private `.env` file, never prints keys, and never overwrites or deletes an existing deployment or backup;
- never starts a restored server automatically.

It refuses other layouts, including an installation made with `deploy/install.sh`.

## Take and verify a backup

Run from the repository root in PowerShell:

```powershell
wsl -d Ubuntu --user root --cd "$PWD" --exec python3 scripts/recovery.py backup --project openrmm-local --name before-upgrade
wsl -d Ubuntu --user root --cd "$PWD" --exec python3 scripts/recovery.py verify --name before-upgrade
```

Choose a new name every time (letters, digits, `_` and `-`); an existing name is refused. Without `--name`, a timestamped name is used.

The backup:

1. saves the exact runtime image first, to keep the outage short;
2. stops the server, copies the `data`, `tls` and (if present) `evidence` volumes and, separately, the `secrets` volume;
3. checks the copied database (`PRAGMA quick_check`) and records the installation ID and schema version;
4. writes the current revocation list and checksum manifests;
5. restarts the server if it was running. A server that was stopped stays stopped.

Installed agents keep running during the outage and retry until the server is back. Do not make other administrative changes or start the source server by hand while the backup runs.

| Root-only location | Contents |
| --- | --- |
| `/var/lib/openrmm-backups/<name>` | Database directory, HTTPS certificates and keys, evidence (if present), runtime image archive, runtime settings, revocation list (`revocations.json`) and checksum manifest. |
| `/var/lib/openrmm-key-backups/<name>` | Administrator encryption key and device CA signing material, with matching checksum metadata. |

Both sets are required. A random set ID binds them; `verify` detects corruption, extra or missing files and mismatched sets.

- The parent directories must be root-owned and mode 0700. The tool creates missing parents privately and refuses existing parents with broader permissions instead of changing them.
- Checksums detect accidental damage; they do not authenticate a backup that someone replaced on purpose. Keep backups on trusted, protected storage.
- Both locations are on the same machine. For disaster recovery, copy both sets through an encrypted backup process to separately controlled storage. The tool does not upload anything.
- Keep the exact source version, image, dependency lock files, runtime configuration and these instructions with the backup.

## Prepare the revocation list

Restoring an older database can bring back devices that were revoked later. A restore therefore requires a reviewed, current revocation list for the same installation.

- If the source server is still available, freeze administrative changes and take another backup; use its `revocations.json`.
- If the source is lost, reconstruct the list from protected incident or change records.
- Do not present the older backup's own list as current unless you have established that nothing was revoked since.

The format is:

```json
{"format":1,"instance_id":"<installation ID>","captured_at":"<UTC time>","revoked":{"<32-character device ID>":<Unix revocation time>}}
```

The list is operator-reviewed input, not cryptographic proof. The installation ID must match the backup. Devices enrolled after the older snapshot do not exist in it and cannot authenticate.

## Stage a restore

```powershell
wsl -d Ubuntu --user root --cd "$PWD" --exec python3 scripts/recovery.py restore --name before-upgrade --project openrmm-restored-trial --revocations /var/lib/openrmm-backups/current-state/revocations.json
```

Here `current-state` stands for the later backup that holds your reviewed list. The target project name must start with `openrmm-restored-`.

The restore:

1. verifies both backup sets and that they belong together;
2. copies the state to a private staging folder and applies the revocations and the changes listed in [What a restore changes](#what-a-restore-changes);
3. sets ownership to the server user and permissions to owner-only (directories 0700, files 0600);
4. loads the exact image from the backup (it is never pulled or replaced);
5. creates new volumes and a **stopped** server container with the original security settings and limits.

It refuses an existing target project or volumes, mismatched sets or installations and failed checksums. A failed attempt can leave protected staging data and stopped resources for inspection; clean up only that trial's resources and choose a new target name.

The generated configuration is `/var/lib/openrmm-restores/<project>/compose.json`. It keeps the original ports unless you pass `--admin-port` and `--agent-port` (loopback ports). Changing ports does not change the agent addresses saved on devices.

## Activate and check the restored server

Review the configuration and the reconciled credentials and revocations first. Keep the original deployment and its volumes for rollback, and stop it only when you are ready to switch:

```powershell
.\scripts\local.ps1 -Action down
.\scripts\local.ps1 -Action up -Project openrmm-restored-trial -ComposeFile /var/lib/openrmm-restores/openrmm-restored-trial/compose.json
.\scripts\local.ps1 -Action check -Project openrmm-restored-trial -ComposeFile /var/lib/openrmm-restores/openrmm-restored-trial/compose.json
```

Use the same `-Project` and `-ComposeFile` arguments for later `status`, `logs`, `down`, `up` and `ca` actions. Never run `init` against a restored deployment; its certificates were restored.

Then check:

- sign-in with the administrator password and a fresh authenticator code;
- existing devices and inventory, and fresh heartbeats from agents;
- that known revoked devices are rejected.

To return to the original server, stop the restored project with the same arguments and run `.\scripts\local.ps1 -Action up`. Never accept changes on both copies at once.

> [!NOTE]
> A backup does not extend certificate lifetimes. Expired development HTTPS certificates still need the normal renewal procedure, and devices whose certificates were renewed after the snapshot may need re-enrollment. Never weaken certificate verification to reconcile them.

## What a restore changes

The restore makes sure that nothing from the older snapshot is replayed against devices and no old credential becomes usable again.

| Area | Change |
| --- | --- |
| Devices | Revocations from the reviewed list are applied. The short overlap that accepts a just-replaced device certificate is cleared. |
| Administrator | All sessions and recovery codes are deleted, and the authenticator replay floor is advanced, so wait for a fresh code. Password and MFA from the snapshot remain. Create new recovery codes with a local reset ([ADMINISTRATOR.md](ADMINISTRATOR.md)), which also replaces MFA. |
| Technicians | All technician accounts are disabled, invitations and recovery codes are cleared, and the authenticator replay floor is advanced. Review accounts, scope and group membership before re-enabling them ([TECHNICIANS.md](TECHNICIANS.md)). |
| Enrollment | All enrollment tokens are deleted, including deployment installers. Installers downloaded before the restore stop working; download new ones. |
| Scripts | Queued runs are cancelled, dispatched or running runs become Unknown, and all stored output is cleared. Batches are marked as restored and cannot be submitted again. Script schedules are paused and their occurrence history is cleared; elapsed occurrences are skipped after you resume. |
| Patching | Patch policies are paused, unfinished runs become Unknown, and devices with an install in progress are held for review. |
| Windows Update jobs | Queued jobs are cancelled; dispatched jobs become Unknown. No installation or restart is replayed. |
| Application deployment | Queued deployments are cancelled; dispatched or running ones become Unknown. |
| File transfer | Staged and queued jobs are cancelled, dispatched jobs become Unknown, and cached file content and results are cleared. No upload is replayed. |
| Service and process actions | Queued actions are cancelled; dispatched ones become Unknown. Process snapshots are marked stale; a new termination needs a fresh snapshot. |
| Event logs | All queries and cached results are deleted. |
| Software inventory | Change history is deleted and comparison restarts; the first new collection becomes the baseline. |
| Health checks | Automatic responses are turned off, samples are deleted and conditions become Unknown. Review checks before enabling responses again. |
| Alerts | Pending samples and email deliveries are deleted, conditions become Unknown and alert email is paused. Existing incidents and acknowledgements remain. Resume email with **Resume email** in **Alert settings** after review. |
| Agent updates | Queued jobs are cancelled and dispatched jobs become Unknown. Update reports are invalidated until devices report again. A restore cannot reset a device's replay protection. |
| Case evidence | Unfinished collections end as failed (see [Case evidence](#case-evidence)). |
| Audit | A `restore_reconciled` entry is added. As always, the audit log keeps the newest 1,000 entries, plus live-response entries for a year. |
| Isolation | Isolation or release steps that had not finished end as failed. Check the actual state of isolated devices. |

Before accepting traffic, verify the actual state of endpoints and submit any new work explicitly.

> [!NOTE]
> Server snapshots may contain file-transfer content captured before its normal expiry. Clearing database references does not guarantee physical erasure from SQLite journals or earlier snapshots; protect and retain backups accordingly.

## Case evidence

The server keeps collected case evidence in its own directory (`/evidence`, the `evidence` volume). See [RESPONSE.md](RESPONSE.md).

On a server installed with `install.sh`, evidence is exported separately with `install.sh backup --evidence` and added back with `install.sh restore-evidence` ([Production installs](#production-installs)). The rest of this section describes the development recovery tool, which copies evidence with the other volumes.

- **Backup.** When the server has an `/evidence` mount, it is copied with the other volumes while the server is stopped, so evidence records and stored files match. The checksum manifest covers every evidence file. The mount's `OPENRMM_SERVER_EVIDENCE_DIR` must be `/evidence`. A deployment without an evidence volume is backed up without evidence.
- **Restore.** A backup with evidence is restored with a new `evidence` volume. Stored files get owner-only read/write permissions (0600) instead of the server's read-only mode (0400).
- **Unfinished collections.** Collections that were queued, dispatched, uploading or verifying are marked failed with outcome `server_restore`, and their upload chunks are deleted, so they are never sent to a device again or resumed. No custody entry is written for this, so the case's custody log shows the request without an end, and the **Evidence** panel shows "The server was restored from a backup." Request the file again if needed. Partial uploads remain unused in the evidence volume's `incoming` folder. Completed collections and their files are kept.
- **Size.** Evidence is never pruned automatically. Each file can be up to 16 GB, and the store is limited by the evidence quota (100 GiB by default, or unlimited with quota 0). A backup needs that much free space under `/var/lib/openrmm-backups`, and a staged restore needs it again under `/var/lib/openrmm-restores` and once more in the new volume. Every evidence file is hashed during backup (before the server restarts) and again by `verify` and `restore`, so a large evidence store lengthens the outage and the checks.
- **Time limits.** Each Docker command has a limit of 180 seconds, except the copies of the evidence volume, which have none. Copying a large evidence store can keep the server stopped for a long time; test that your backups complete and verify.
- The custody log is in the database; a custody export does not include evidence files. Protect evidence backups like the server itself.

## Windows agent state

Agent state on each device is separate from server backups.

- `%ProgramData%\OpenRMM Agent` holds the device credentials, local journals, the update journal with its replay counter, and the rollback package. Back it up with a protected Windows backup process, and stop the agent service for a consistent copy.
- Never restore a lower update replay counter on purpose. Restoring an old disk image can do this too, so protect device backups.
- Windows Update and other local journals are kept across agent updates. On startup the agent marks interrupted jobs Unknown and never replays them; restoring old journals is not a rollback of Windows updates.
- Agent installs, updates and uninstalls keep this folder and the local feature locks under `HKLM\SOFTWARE\Policies\OpenRMM\Agent`. Feature switches set per monitoring policy are restored with the server database.

See [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md) and [AGENT-UPDATES.md](AGENT-UPDATES.md).

## Rebuilding and upgrading the local server

1. Take and verify a matched backup.
2. Run `scripts/check.ps1`, `scripts/build.ps1` and `.\scripts\local.ps1 -Action build`. Before it replaces the development image tag, the build tags the existing runtime image as `<project>-retained:<image-digest>` so that later backups and rollbacks can still reach it. These tags are not pruned automatically; remove old ones only after reviewing your backups. A direct `docker build` bypasses this safeguard.
3. Run `.\scripts\local.ps1 -Action up`. The container is replaced and the volumes are kept; health and readiness checks must pass.

Database migrations are ordered, checksummed and transactional. A modified migration, or a database schema newer than the executable, stops the server at startup. Do not edit migration history, run an older binary against a newer schema, or delete data volumes to get past a failed upgrade. To go back, stage a matching pre-upgrade backup as a new project and switch explicitly.

## Related

- [Installing the server](INSTALL.md)
- [Server updates](SERVER-UPDATES.md)
- [Administrator account](ADMINISTRATOR.md)
- [Technician accounts](TECHNICIANS.md)
- [Incident response](RESPONSE.md)
