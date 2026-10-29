# Upgrading

This page explains how to move an OpenRMM server and its agents to a newer release, what to check first, and how to go back if a release misbehaves. It is for operators of a self-hosted server. Version-specific notes are at the end.

## Contents

- [Before you upgrade](#before-you-upgrade)
- [Ways to upgrade](#ways-to-upgrade)
- [Skipping versions](#skipping-versions)
- [No downgrades](#no-downgrades)
- [Going back after a bad update](#going-back-after-a-bad-update)
- [Supported versions](#supported-versions)
- [Version notes](#version-notes)
- [Related](#related)

## Before you upgrade

1. Read the release notes on the [releases page](https://github.com/IAmForeverAloneToo/OpenRMM/releases) (the dashboard shows them too) and the [version notes](#version-notes) below for every version between yours and the new one.
2. Check that the last nightly backup succeeded (**Administration → Backups**). An update from the dashboard takes its own verified backup as well. To keep a copy off the machine, run `sudo bash install.sh backup` first.
3. If you want to see the new server working before agents follow, turn off automatic agent updates (**Agent updates**) and turn them back on afterwards.

## Ways to upgrade

| Way | Use it when |
| --- | --- |
| **Administration → Server updates → Update to &lt;version&gt;** | The usual way. The updater verifies the signed release, backs up, starts the new version and rolls back automatically if it does not become healthy. See [SERVER-UPDATES.md](SERVER-UPDATES.md). |
| `sudo bash install.sh --image IMAGE:VERSION` | The installation has no updater (for example rootless Docker), or you want a specific version such as a pre-release on a test machine. Take a backup first; the script does not roll back. |

The updater follows the server to the new version by itself. On installations from 0.1.0 or earlier, whose updater cannot do that yet, run `sudo bash install.sh` (without `--image`) once after the update.

Agents follow on their own: each server release bundles a signed agent release, which reaches devices through the automatic update rings (pilot groups first) when they are on. See [AGENT-UPDATES.md](AGENT-UPDATES.md).

> [!IMPORTANT]
> After an update from the dashboard, start and repair the server with the install script, not with a plain `docker compose up`: `compose.yaml` still names the image the script wrote, and an older server refuses the newer database.

## Skipping versions

You can update from any release directly to any newer one. Database migrations are numbered and applied in order on the first start, and every release has a higher release sequence than the ones before it. There is no need to install the releases in between, but read their version notes.

## No downgrades

OpenRMM never moves to an older release on its own, and refuses to when asked:

- The updater installs only a release with a higher sequence than the last one it installed.
- A server refuses to start on a database whose schema is newer than its own (nothing is changed; it just does not start).
- Each agent keeps the highest release sequence it has accepted and never installs an older one.

Older signed releases therefore cannot be replayed against your installation. The way out of a bad release is a newer one, or a restore as described next.

## Going back after a bad update

If the new version does not become healthy, the updater rolls back by itself: the previous version runs again with the data from just before the update.

If it became healthy but misbehaves, prefer waiting for a fixed release. If you cannot wait, you can return to the previous version together with the data from before the update. **Everything changed on the server since the update is lost** (new devices enrolled, cases, collected results).

1. Turn off automatic agent updates (**Agent updates**), so the new agent release stops spreading.
2. Find the backup taken before the update, named `update-<time>-<sequence>`:

   ```bash
   sudo bash install.sh backups
   ```

3. Switch back to the previous image. If the new version changed the database, the script reports that the server did not become ready; that is expected here.

   ```bash
   sudo bash install.sh --image ghcr.io/iamforeveralonetoo/openrmm-server:PREVIOUS-VERSION
   ```

4. Restore the backup with the previous version:

   ```bash
   sudo bash install.sh restore update-<time>-<sequence>
   ```

The restore keeps the state it replaces as a `pre-restore-` backup, so this can be undone, and applies the usual restore changes (sessions end, technicians are disabled for review, queued work is cancelled; see [RECOVERY.md](RECOVERY.md#what-a-restore-changes)). Agents that already updated keep their newer version, since agents cannot be downgraded; check that they report in afterwards. The updater still remembers the newer release, so the dashboard offers only releases after it.

## Supported versions

Only the latest release receives fixes, including security fixes. Pre-releases are for testing and are never supported. See [SECURITY.md](../SECURITY.md#supported-versions).

## Version notes

### 0.1.2

Hardening; nothing to do when updating.

- **Damaged records stay local.** A database record that cannot be read no longer stops alerting, patching, schedules or agent rollouts for every device, or the server from starting. A damaged schedule or patch policy is paused, a damaged patch run ends as unknown (each recorded once in the audit log), and a damaged monitoring policy switches every feature off for its devices until it is saved again ([ORGANIZATION.md](ORGANIZATION.md)).
- **Feature reports are limited per device** (a burst of 30, then one a second; agents send about 12 a minute). One device can no longer flood the shared alert queue and reset alerting for the whole fleet.
- **Slow links.** Agent updates, installer downloads, release uploads and file transfers get more time than the 10-second default. Agent update downloads have their own, larger pool; agents from this release wait for a busy server instead of failing the update.
- **Agent update alerts are e-mailed** when alert e-mail is set up; before, the e-mail was always cancelled.

### 0.1.1

- **The updater updates itself.** After each server update, the updater sidecar replaces itself with the server's version ([SERVER-UPDATES.md](SERVER-UPDATES.md#the-updater-updates-itself)). The 0.1.0 updater cannot do this yet: after updating to 0.1.1 from the dashboard, run `sudo bash install.sh` (without `--image`) once. The **Server updates** page reminds you until it is done.

### 0.1.0

The first public release.

- **Agents installed from development builds** trust a different release key or accept release manifests valid for at most 90 days, so they refuse automatic updates to public releases. Reinstall such devices once with the MSI from the release (`install.cmd` or `scripts/install-agent.ps1`); the device keeps its identity.
- **New features** of this release that change defaults on new installations: automatic agent updates through the rings are on, nightly backups run at 03:00 UTC, and alert e-mail can be set up in **Alert settings**.

## Related

- [Server updates](SERVER-UPDATES.md)
- [Agent updates](AGENT-UPDATES.md)
- [Backup and recovery](RECOVERY.md)
- [Installing the server](INSTALL.md)
