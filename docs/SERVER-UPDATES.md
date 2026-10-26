# Server Updates

The primary administrator can update the OpenRMM server from the dashboard (**Administration → Server updates**). An updater container installed next to the server verifies the signed release, takes a verified backup, switches to the new version and rolls back automatically if it does not become healthy.

## Contents

- [How it works](#how-it-works)
- [The release check](#the-release-check)
- [What makes a release genuine](#what-makes-a-release-genuine)
- [What happens on Update now](#what-happens-on-update-now)
- [Security boundaries](#security-boundaries)
- [Permissions and audit](#permissions-and-audit)
- [Without the updater](#without-the-updater)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## How it works

The install command ([INSTALL.md](INSTALL.md)) adds a small `updater` container when the Docker socket is available. The server and the updater never talk over the network; they exchange files in the shared `updater` volume:

1. The server checks GitHub for a newer signed release and shows it on the page.
2. The administrator selects **Update now** and confirms.
3. The server writes an update request; the updater verifies the release again, backs up, replaces the server container and reports the outcome.

The **Server updates** page shows the running version, whether the updater is installed, the release check, an available update with its release notes, and the history of updates with their backups.

## The release check

- The server asks GitHub for the latest release of the project repository once a day. **Check now** runs it immediately.
- The check is on by default. Turn it off with **Check for new releases once a day**.
- The request carries no device, user or server data: only the repository path and a generic user agent.
- Release data is accepted only from `api.github.com`, `github.com` and GitHub's content hosts (`*.githubusercontent.com`), including redirects.
- The repository is fixed in the build (`serverupdate.Repository`). A build whose repository is the placeholder `OWNER/REPO` makes no request, and the page says so.

## What makes a release genuine

Each GitHub release carries `openrmm-server-release.json`, a manifest signed with the project's Ed25519 release key (the same key that signs agent releases). The manifest contains:

- the version and release sequence;
- the image repository;
- the image's content-addressed image ID, plus the registry digest used to pull it;
- release notes (at most 16 KiB), shown on the page;
- an issue and expiry time (at most 400 days apart).

The server offers a release only if:

- the signature verifies with a key the running build trusts;
- the release has not expired;
- its sequence is higher than the running build's.

The running build's version, sequence and trusted key come from the agent release bundled into it (see [RELEASE.md](RELEASE.md)). Operators who sign their own builds can add a key with `--release-key` ([INSTALL.md](INSTALL.md#options)); at most eight keys are trusted.

The updater does not rely on the server's checks. Before it changes anything it verifies again:

- the signature and the expiry;
- that the sequence is higher than the last one it installed, so an older signed release cannot be replayed;
- after the pull, that the image ID matches the manifest exactly. With Docker's containerd image store the engine reports the registry digest instead, which the manifest also pins.

Control of a registry account alone therefore cannot change what is installed.

## What happens on Update now

1. **Verify.** The updater checks the release as described above.
2. **Download.** It pulls the image by digest and checks its ID.
3. **Back up.** It stops the server, copies the `data` and `secrets` volumes into the `backups` volume and confirms that each copy's SHA-256 matches its original. A read-only SQLite integrity check then confirms the database copy. The `evidence` volume is not touched by updates and is not copied.
4. **Start.** It keeps the old container (renamed with the suffix `-previous`), creates the new one with the same settings and the new image, and waits up to 5 minutes for it to report healthy.
5. **Finish.**
   - If the new version is healthy, the updater removes the old container and records the sequence. The page shows **Updated**.
   - If not, it removes the new container, restores the backup (verified again first) and starts the previous version. The page shows **Rolled back**.

The page shows each step as it happens: **Verifying**, **Downloading**, **Backing up**, **Starting new version**.

| Behaviour | Value |
| --- | --- |
| Health wait for the new version | 5 minutes |
| Time limit per Docker call | 2 minutes |
| Time limit for the image download | 30 minutes |
| Backups kept | The three newest update backups (nightly and other backups are kept separately; see [RECOVERY.md](RECOVERY.md#production-installs)) |

The updater records each step in a journal in the `backups` volume, which the server cannot reach. A damaged journal stops updates instead of being ignored. If the updater is interrupted, for example by a host reboot, it resolves the update when it starts again: if the new version was already confirmed healthy it keeps it, otherwise it rolls back. It acts only on containers of its own Compose project and service.

During an update the dashboard and agent connections are unavailable for a few minutes. Work already running on devices continues and reports back afterwards. After an update, the agent release bundled with the new server is available on **Agent updates** and rolls out according to the agent update settings ([AGENT-UPDATES.md](AGENT-UPDATES.md)).

## Security boundaries

- The server container stays non-root and has no Docker access.
- The updater is the only part with access to the Docker socket. It runs:
  - without a network (`network_mode: none`) and without ports;
  - with a read-only file system, no capabilities and `no-new-privileges`;
  - as an unprivileged user with only the socket's group added;
  - with limits of 256 MiB memory and 64 processes.
- The server reaches the updater only through files in the `updater` volume. The server writes the request; the updater answers with a status file containing fixed messages, never raw Docker output.
- The updater writes a heartbeat about once a minute. Without a heartbeat in the last five minutes, the page treats the updater as not installed.

> [!IMPORTANT]
> Access to the Docker socket is equivalent to root on the host. The updater limits what it does with it, but protect the host and its Docker installation accordingly.

## Permissions and audit

Only the primary administrator can see the page, change the check setting and start an update. The audit log records:

| Event | When |
| --- | --- |
| `server_update_requested` | An update was started. |
| `server_update_finished` | An update ended, with its outcome. |
| `server_update_check_enabled`, `server_update_check_disabled` | The daily check was turned on or off. |

## Without the updater

Docker without `/var/run/docker.sock` (for example rootless Docker) gets no updater, and the page says that updates from the dashboard are unavailable. To update, run the install command again with a new `--image`.

A later run of the install command without `--image` keeps the version that the dashboard installed.

## Troubleshooting

- **Updater shows "Not installed"**: run the install command again; it adds the updater when the Docker socket exists.
- **An update ended as Rolled back**: the previous version is running again with the data from just before the update. Check the server log of the failed attempt before retrying.
- **An update succeeded but the new version misbehaves**: see [Going back after a bad update](UPGRADING.md#going-back-after-a-bad-update).
- **The server does not start after `docker compose up`**: after a dashboard update, `compose.yaml` still names the older image, and an older server refuses the newer database. Run the install command again without `--image`.

## Related

- [Installing the server](INSTALL.md)
- [Upgrading](UPGRADING.md)
- [Backup and recovery](RECOVERY.md)
- [Agent updates](AGENT-UPDATES.md)
- [Building and releasing](RELEASE.md)
