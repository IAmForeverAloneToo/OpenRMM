# Development Guide

How to build, check and run OpenRMM from source. This guide is for contributors. To install a server, see [INSTALL.md](INSTALL.md).

## Contents

- [Requirements](#requirements)
- [Repository layout](#repository-layout)
- [Check and build](#check-and-build)
- [Local container deployment](#local-container-deployment)
- [Running native binaries](#running-native-binaries)
- [Developing the web interface](#developing-the-web-interface)
- [Architecture notes](#architecture-notes)
- [Troubleshooting](#troubleshooting)

## Requirements

| Tool | Version | Used for |
| --- | --- | --- |
| Go | 1.26 or newer as a launcher | The scripts select the exact pinned toolchain (`go1.27.2`) and download it into the ignored project cache on first use. |
| PowerShell | 7 or newer | All scripts in `scripts/`. Run them from the repository root. |
| Node.js with npm | Current LTS | Building and checking the web interface. Not needed at runtime. |
| Docker Engine with Compose | Current | The local container deployment and the agent MSI build. On Windows, run it inside a WSL distribution (default `Ubuntu`). |
| Windows x64 | Windows 10/11 or Windows Server | Running and testing the agent. The interactive terminal needs Windows 10 1809 or Windows Server 2019 and later (ConPTY). |

## Repository layout

```text
cmd/
  openrmm-server/     Server entry point
  openrmm-agent/      Windows agent: enrollment, console diagnostics, service and update helper
  openrmm-desktop/    Per-user remote desktop companion
  openrmm-updater/    Server update sidecar
  openrmm-release/    Offline release signer and key management
  openrmm-custody/    Offline verifier for case custody exports
  openrmm-devcert/    Disposable local TLS certificates
internal/
  server/             JSON API, agent listener, background workers, embedded web assets
  storage/            SQLite queries and embedded, versioned migrations
  auth/               Administrator and technician credentials, MFA, sessions, throttling
  devices/            Enrollment, device certificates, renewal and revocation
  agent/              Agent core: transport, scheduling, resilience
  protocol/           Versioned agent/server messages
  ...                 One package per collector or feature (inventory, eventlogs, response, ...)
web/                  React + TypeScript dashboard (built into the server binary)
installer/            Agent MSI definition and its pinned build image
deploy/               Production install script
scripts/              Build, check, release and local-operation scripts
docs/                 Documentation
```

## Check and build

```powershell
.\scripts\check.ps1   # dependency integrity, web typecheck and tests, gofmt, go vet, Go tests
.\scripts\build.ps1   # web build, then Windows and Linux binaries into dist/
```

`check.ps1` and `build.ps1` first compare the resolved Go module graph with `dependencies.lock` and run `go mod verify`. An unexpected module or version fails the command. The check also verifies the npm lockfile and audits runtime packages. See [DEPENDENCIES.md](DEPENDENCIES.md).

`build.ps1` produces:

```text
dist/windows-amd64/openrmm-server.exe
dist/windows-amd64/openrmm-agent.exe
dist/windows-amd64/openrmm-desktop.exe
dist/windows-amd64/openrmm-release.exe
dist/windows-amd64/openrmm-devcert.exe
dist/linux-amd64/openrmm-server
```

- Use `-Target windows` or `-Target linux` to build only one target.
- Go's build and module caches live under the ignored `.local/` folder.
- The agent MSI (`dist/windows-amd64/openrmm-agent.msi`) is built by `scripts/build-msi.ps1` with the pinned `wixl` image in `installer/`. `scripts/release.ps1` runs it as part of a signed release; see [RELEASE.md](RELEASE.md).

The container image (`Dockerfile`) checks the same dependency baseline and runs the full Go test suite on Linux, with networking disabled after the pinned modules are fetched.

> [!NOTE]
> The image embeds the web interface from `internal/server/webui/dist`, which is produced by `scripts/build-web.ps1` and is not committed. Run `.\scripts\build.ps1` (or `build-web.ps1`) before building the image, otherwise the server serves a placeholder page.

### Packaging checks

`scripts/package.ps1` builds a reproducible local ZIP of sources, binaries and the image ID with checksums. Before packaging it runs:

- the checks and builds;
- an isolated container test (`scripts/container-smoke.sh`);
- the pinned vulnerability scanner (`scripts/security-check.sh`).

## Local container deployment

`scripts/local.ps1` runs the server from `compose.yaml` in Docker inside WSL. Ports are published on loopback only: `127.0.0.1:8443` for the dashboard and `127.0.0.1:8444` for agents.

```powershell
.\scripts\local.ps1 -Action build   # build the image
.\scripts\local.ps1 -Action init    # create development certificates once (never overwrites)
.\scripts\local.ps1 -Action up      # start and wait for readiness
.\scripts\local.ps1 -Action check   # verified HTTPS readiness probe inside the container
```

Other actions:

| Action | Purpose |
| --- | --- |
| `status`, `logs` | Container state and the last 100 log lines |
| `storage-info` | Installation metadata and schema version |
| `ca` | Copies the public development CA to `.local/container-ca.pem` |
| `down` | Stops the server and keeps all volumes |

- **WSL session.** `up` keeps the WSL distribution alive with one hidden idle session, and `down` stops it. Run `up` again after Windows restarts.
- **Distribution.** `-Distribution` selects a different WSL distribution.
- **Docker directly.** Linux and Docker Desktop users can run `docker compose --env-file deploy/local.env -f compose.yaml ...` directly.

Create the first administrator privately, then sign in at `https://127.0.0.1:8443/`:

```powershell
.\scripts\admin.ps1 -Action setup
```

The development CA is not added to any trust store automatically. See [ADMINISTRATOR.md](ADMINISTRATOR.md) for browser trust and local recovery.

> [!NOTE]
> Compose always receives `--env-file deploy/local.env`, which contains no credentials. A private `.env` in the repository root is never loaded, passed to the server or sent in the Docker build context.

The Compose project uses four named volumes:

| Volume | Contents |
| --- | --- |
| `data` | The SQLite database |
| `tls` | The development certificates, read-only to the server |
| `secrets` | The encryption key and device CA |
| `evidence` | Case evidence |

Development certificates expire after seven days. To rotate them, generate a new set with `docker compose ... run --rm certificates -out /tls/next` and point the TLS paths in `compose.yaml` at it.

## Running native binaries

An alternative to the container for debugging. Stop the container first, or choose other loopback ports with `-listen` and `-device-listen`.

```powershell
.\dist\windows-amd64\openrmm-devcert.exe                 # once: .local/tls/{ca,server,server-key}.pem
.\dist\windows-amd64\openrmm-server.exe -tls-ca .local/tls/ca.pem
```

In a second terminal:

```powershell
.\dist\windows-amd64\openrmm-agent.exe            # health check; expects "server health check passed"
.\dist\windows-amd64\openrmm-agent.exe -ready     # database-backed readiness
```

- **Certificate helper.** `openrmm-devcert` refuses to overwrite an existing folder and never touches system trust stores. Its certificates are valid for `localhost`, `127.0.0.1` and `::1` for seven days. Use `-out .local/tls-next` to create a new set.
- **Agent and enrollment.** To run an agent against a development server, download a **One device** installer from the dashboard and enroll the console agent with `scripts/enroll.ps1 -EnrollmentFile <folder>\enrollment.json`, then run `openrmm-agent.exe -run`. To install the development agent as a Windows service, use `scripts/install-agent.ps1`. See [ENROLLMENT.md](ENROLLMENT.md) and [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md).

All options are listed in [CONFIGURATION.md](CONFIGURATION.md).

## Developing the web interface

The dashboard lives in `web/` (React, TypeScript, Vite, Tailwind CSS). `scripts/build-web.ps1` runs `npm ci --ignore-scripts` against the committed lockfile and writes the build to `internal/server/webui/dist`, where the server embeds it. See [UI-UX.md](UI-UX.md) for structure and conventions.

```powershell
cd web
npm ci --ignore-scripts
npm run typecheck
npm test
```

## Architecture notes

- **Modules.** `internal/features.Module` is the collection and scheduling interface. Collectors keep Windows APIs in `_windows.go` files, so the Linux build stays independent.
- **Storage.** SQL lives only in `internal/storage`.
- **Migrations.** They are append-only, and their names and checksums are verified at every start. Migration files use LF line endings on every platform so the checksums match.
- **Agent connections.** Agents always connect outward. The server never opens a connection to a device.
- **Authorization.** It is checked in the API handlers and again in storage, both when work is queued and when it is dispatched.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Missing certificates | Run `openrmm-devcert` from the repository root and use matching paths for server and agent. |
| TLS failure | The CA belongs to this server, the address matches the certificate, and it has not expired. Never disable verification. |
| Port in use | Choose another loopback port with `-listen` and the matching agent `-server` URL. |
| Container fails after `init` | `local.ps1 -Action logs`; confirm certificate paths and that the data volume is accessible. Do not delete volumes to troubleshoot. |
| "Newer or modified database schema" | Use the matching build or a compatible backup. Migrations are forward-only. |

## Related

- [Contributing](../CONTRIBUTING.md)
- [Configuration reference](CONFIGURATION.md)
- [Building and releasing](RELEASE.md)
- [Dependencies](DEPENDENCIES.md)
