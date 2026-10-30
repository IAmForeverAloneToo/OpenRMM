# Installing the Server

This guide installs the OpenRMM server on a Linux host with one command. It is for operators who run their own OpenRMM instance; the install script is `deploy/install.sh` in this repository.

## Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Public server with a domain name](#public-server-with-a-domain-name)
- [LAN or lab server](#lan-or-lab-server)
- [Create the first administrator](#create-the-first-administrator)
- [Options](#options)
- [Running the script again](#running-the-script-again)
- [What is installed](#what-is-installed)
- [Backup and removal](#backup-and-removal)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## Overview

The script:

- writes the settings and a Docker Compose file to an installation folder (default `/opt/openrmm`);
- starts the server as one container and, when the Docker socket is available, an updater container for [updates from the dashboard](SERVER-UPDATES.md);
- keeps all state (database, keys, certificates, evidence) in Docker volumes;
- waits until the server reports healthy;
- prints a one-time link for creating the first administrator in the browser.

> [!NOTE]
> Without `--image`, the script installs the latest release published on GitHub, pinned to its exact image: the registry digest is taken from the release's signed server release file (`ghcr.io/iamforeveralonetoo/openrmm-server:<version>@sha256:<digest>`), so a tag moved in the registry cannot change what is installed. To run your own build instead, build the image from source (see [DEVELOPMENT.md](DEVELOPMENT.md)) and pass its exact tag to `--image`.

## Requirements

- A Linux host with Docker Engine and the `docker compose` plugin ([install Docker](https://docs.docker.com/engine/install/)).
- Run the script as root (`sudo`) or as a member of the `docker` group.
- `curl`, to find the latest release (or pass `--image` with an exact version (`IMAGE:VERSION`) or digest (`IMAGE@sha256:...`); floating tags such as `latest` are refused).
- Two TCP ports that browsers and agents can reach:

| Port | Default | Purpose |
| --- | --- | --- |
| Dashboard | 443 | Browser access, agent enrollment, installer downloads |
| Agents | 8444 | Agent connections (mutual TLS with device certificates) |

Port 80 is not used.

## Public server with a domain name

```bash
sudo bash install.sh --domain rmm.example.com --email admin@example.com
```

- The name must resolve to this host, and port 443 must be reachable from the internet.
- The server obtains its certificate from Let's Encrypt with the TLS-ALPN challenge on port 443 and renews it 30 days before it expires. The first certificate can take a minute.
- `--email` is optional; Let's Encrypt uses it for account notices.
- Agents trust the certificate through the Windows trust store, so downloaded installers carry no CA.

## LAN or lab server

```bash
sudo bash install.sh --address 192.0.2.10,rmm.lan
```

- The server creates its own certificate authority, valid for 10 years. The CA and its key stay in the `secrets` volume (`server-ca/`).
- The CA issues the server certificate for the listed addresses and names. The certificate is valid for 180 days; the server renews it 30 days before it expires.
- Agent installers downloaded from the dashboard carry this CA, so agents keep trusting the server across renewals.
- Browsers warn until you trust the CA. Import `server-ca/ca.pem` from the `secrets` volume into the browser's or the operating system's trust store.
- The first entry in `--address` is the address written into agent installers.

## Create the first administrator

When the script finishes it prints a link such as:

```text
https://rmm.example.com/setup#...
```

1. Open the link within one hour. It works once.
2. Choose a username and a password of at least 15 characters.
3. Add the shown key to an authenticator app and store the recovery codes privately.
4. Confirm with a code from the app.

Until an administrator exists, every run of the script prints a new link and the older link stops working. The secret part follows `#`, so it is never sent to the server or written to its logs. Once an administrator exists, the script prints the sign-in address instead.

To add more people, invite [technicians](TECHNICIANS.md). To recover the administrator account, see [ADMINISTRATOR.md](ADMINISTRATOR.md).

## Options

| Option | Default | Description |
| --- | --- | --- |
| `--image REF` | the latest published release | Server image with an exact version or digest. |
| `--domain NAME` | | Public DNS name; certificate from Let's Encrypt. Requires the dashboard on port 443. |
| `--email ADDRESS` | | Let's Encrypt contact address (optional, with `--domain`). |
| `--address LIST` | | Comma-separated IP addresses or host names for a LAN install; certificate from the server's own CA. |
| `--dashboard-port N` | `443` | Dashboard port on the host. Must be 443 with `--domain`. |
| `--agent-port N` | `8444` | Agent port on the host. Must differ from the dashboard port. |
| `--dir PATH` | `/opt/openrmm` | Installation folder (absolute path without spaces). |
| `--project NAME` | `openrmm` | Docker Compose project name. |
| `--acme-directory URL` | Let's Encrypt | Another ACME directory, for testing. |
| `--release-key HEX` | | An extra Ed25519 public key (64 hex characters) trusted for server releases, for operators who sign their own builds. |
| `--trusted-proxies LIST` | | Reverse proxies in front of the dashboard (IP addresses or CIDR ranges, comma-separated). Requests from them are counted against the sign-in limits by the client address in their `X-Forwarded-For` header instead of the proxy's own. Name only proxies you run: a listed address can claim any client address. `none` removes the list. |
| `-h`, `--help` | | Show the help. |

Give either `--domain` or `--address`, not both. Use `--dir` and `--project` together to run a second server on the same host.

## Running the script again

Running the script again repairs or reconfigures the installation and keeps all data. Options left out keep their earlier values, which are stored in `install.conf`.

- **Change the version:** `--image IMAGE:NEWVERSION`.
- **Switch between domain and LAN mode:** give `--domain` or `--address`; the other mode's settings are cleared.
- **Change ports:** `--dashboard-port`, `--agent-port`. Agents installed earlier keep the addresses from their installer, so settle the ports before you enroll devices.
- **Without `--image`**, a run keeps the version that is installed, including one installed from the dashboard ([SERVER-UPDATES.md](SERVER-UPDATES.md)).

`server.env` and `compose.yaml` are rewritten by every run; change settings through the script options rather than by editing these files.

> [!IMPORTANT]
> After an update from the dashboard, start the server with the script, not with a plain `docker compose up`. `compose.yaml` still names the image the script wrote, and an older server refuses the newer database (it does not start; nothing is damaged). Running the script again fixes it.

On the first start, the dashboard and agent addresses are stored as the installer settings. After that, change them in **Devices → Add device**; later runs of the script do not overwrite them.

## What is installed

| Item | Location |
| --- | --- |
| Settings | `/opt/openrmm/install.conf`, `server.env`, `compose.yaml` (folder mode 0700, files 0600) |
| Database, Let's Encrypt account and certificate | volume `openrmm_data` |
| Administrator encryption key, device CA, server CA | volume `openrmm_secrets` |
| Case evidence | volume `openrmm_evidence` |
| Backups (nightly, on request, before updates and restores) and the updater's journal | volume `openrmm_backups` (updater only) |
| Backups exported with `install.sh backup` | `/opt/openrmm/backups` (mode 0700) |
| Update requests and status | volume `openrmm_updater` (server and updater) |

The server container runs:

- as a non-root user (UID 10001);
- with a read-only file system;
- with all capabilities dropped and `no-new-privileges`;
- with limits on memory (1 GiB) and process count (256);
- with a health check (`/openrmm-server -health`) that verifies the server certificate with the same trust and name that agents use.

> [!WARNING]
> Docker publishes the dashboard and agent ports on all addresses, and its firewall rules come before `ufw` and `firewalld`. A rule such as "allow 443 only from the office" in `ufw` does **not** restrict them. To limit who can reach the ports, add rules to Docker's `DOCKER-USER` chain or use a firewall in front of the host ([Docker documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/)).

The updater container is described in [SERVER-UPDATES.md](SERVER-UPDATES.md#security-boundaries). If `/var/run/docker.sock` does not exist (for example with rootless Docker), the server is installed without the updater and updates from the dashboard are unavailable.

## Backup and removal

The updater backs up the database and the `secrets` volume every night without stopping the server (**Administration → Backups**). To take a backup and save it as a file you can copy elsewhere, and to restore one:

```bash
sudo bash install.sh backup [--evidence]
sudo bash install.sh restore NAME|FILE
```

The `secrets` volume holds the keys that agents and administrator sign-in depend on; a database without its matching secrets cannot be used. See [RECOVERY.md](RECOVERY.md#production-installs).

To stop the server and keep all volumes:

```bash
cd /opt/openrmm && sudo docker compose down
```

> [!WARNING]
> Adding `--volumes` to that command also deletes all data, keys and evidence. This cannot be undone.

## Troubleshooting

- **"the server did not become ready"**: the script prints the last 30 lines of the server log. Fix the cause (for example a DNS name that does not resolve to this host, or port 443 not reachable for Let's Encrypt) and run the script again.
- **"cannot reach Docker"**: run with `sudo` or as a member of the `docker` group.
- **"--image needs an exact version or digest"**: use `IMAGE:VERSION` or `IMAGE@sha256:...`, not `latest`.
- **Lost the setup link**: run the script again for a new one, as long as no administrator exists.

## Related

- [Server updates](SERVER-UPDATES.md)
- [Backup and recovery](RECOVERY.md)
- [Device enrollment](ENROLLMENT.md)
- [Administrator account](ADMINISTRATOR.md)
- [Building and releasing](RELEASE.md)
