# Building and Releasing

This guide is for maintainers and for operators who build and sign their own OpenRMM releases. It covers the build scripts, the release signing key, signed agent releases, the server image and signed server releases.

## Contents

- [Overview](#overview)
- [Publishing a release with CI](#publishing-a-release-with-ci)
  - [Withdrawing a bad release](#withdrawing-a-bad-release)
- [Prerequisites](#prerequisites)
- [Check and build](#check-and-build)
- [The release signing key](#the-release-signing-key)
- [Release the agent](#release-the-agent)
- [Build the server image](#build-the-server-image)
- [Sign and publish a server release](#sign-and-publish-a-server-release)
- [Local development package](#local-development-package)
- [Licensing of release artifacts](#licensing-of-release-artifacts)
- [Security notes](#security-notes)
- [Related](#related)

## Overview

A release consists of:

| Artifact | Produced by | Purpose |
| --- | --- | --- |
| Windows binaries (`dist/windows-amd64/`) | `scripts/build.ps1` | Agent, desktop companion, server, certificate helper (`openrmm-devcert`), offline release signer (`openrmm-release`) and custody verifier (`openrmm-custody`). |
| Linux server (`dist/linux-amd64/openrmm-server`) | `scripts/build.ps1` | Cross-compiled server binary. |
| Agent MSI (`openrmm-agent.msi`) | `scripts/build-msi.ps1` | Windows Installer package of the agent and desktop companion. |
| Signed agent release (`release.json`) | `scripts/release.ps1` | Ed25519-signed manifest binding the exact MSI. Bundled into the server build. |
| Server image | `docker build` | Runtime image with the server, the updater and the embedded web dashboard and agent release. |
| Signed server release (`openrmm-server-release.json`) | `openrmm-release -server-release` | Signed manifest pinning the server image, attached to the GitHub release. |

The agent release is the anchor of a server build: the server takes its version, release sequence and trusted release key from the bundled agent release. A server built without a bundled release reports the version `development` and offers no agent updates or installer downloads until a release is uploaded.

## Publishing a release with CI

Official releases are built, signed and published by the **Release** workflow (`.github/workflows/release.yml`) when a version tag is pushed:

```bash
git tag -s v0.1.0 -m "OpenRMM 0.1.0"
git push origin v0.1.0
```

The workflow then:

1. Takes the version from the tag and the next release sequence from the previous GitHub release (the first public release continues the local sequence).
2. Builds the Windows agent with the project's public key pinned, builds its MSI and signs the agent release (valid for one year).
3. Builds the server image with that signed agent release bundled, and pushes it to `ghcr.io/iamforeveralonetoo/openrmm-server:<version>`.
4. Signs the server release, pinning the image ID and registry digest, with release notes made from the commits since the previous tag.
5. Creates the GitHub release with the MSI, `openrmm-agent-release.json`, `openrmm-server-release.json` and `SHA256SUMS`.

Servers find the new release with their daily check and offer it under **Administration → Server updates**; the bundled agent release then reaches devices through the agent rings.

**Pre-releases.** A tag with a suffix, such as `v0.1.0-rc.1`, is published as a GitHub pre-release. Servers' update checks and the install script's default use only full releases, so a pre-release is installed only on purpose (`install.sh --image ghcr.io/iamforeveralonetoo/openrmm-server:0.1.0-rc.1`), for example on test machines. Each pre-release still uses the next release sequence.

**Dry run.** Running the workflow manually (**Actions → Release → Run workflow**) builds and signs everything with a throwaway key and publishes nothing. Use it to test the pipeline after changes.

### Withdrawing a bad release

A signed release cannot be recalled: it stays valid until it expires, and anyone holding it could still offer it to a server or device below its sequence. What you can do is stop new installations from picking it up and supersede it.

1. **Hide it.** Edit the GitHub release and select **Set as a pre-release**. Do not delete the release, its tag or its image: servers and devices that installed it keep running it, and the artifacts are needed to investigate. Servers' update checks and the install script's default use only full releases, so a server that has not installed it stops offering it at its next daily check (**Check now** on the page does it at once).
2. **Supersede it.** Publish a fixed release; it gets the next sequence. If the fix takes time and the bad release did not add a database migration, a release made from the previous good commit also works, since it too gets a new, higher sequence. Servers and agents never go back to a lower sequence, so a fixed release is the only way to move installed systems forward.
3. **Stop the agent rollout.** Each server release bundles an agent release, which spreads through the rings. A failed agent update pauses the rings by itself; to stop a rollout that does not fail, tell operators to turn off automatic agent updates or withdraw the release under **Agent updates**.
4. **Tell operators.** Add a note at the top of the release notes. Operators who must go back before a fix is out can follow [Going back after a bad update](UPGRADING.md#going-back-after-a-bad-update). For a security problem, publish a GitHub security advisory ([SECURITY.md](../SECURITY.md)).

### One-time setup: the signing secrets

The workflow signs with the project's release key, stored as two repository secrets. Set them yourself from the folder that holds the encrypted key (they are never printed or committed):

```bash
gh secret set OPENRMM_SIGNING_KEY --repo IAmForeverAloneToo/OpenRMM < signing-key.json
gh secret set OPENRMM_SIGNING_PASSPHRASE --repo IAmForeverAloneToo/OpenRMM
```

The second command prompts for the passphrase. Anyone who can change workflows on `main` or push tags can sign releases with these secrets; protect the repository accordingly.

The workflow pins the project's release public key (`RELEASE_PUBLIC_KEY` in `release.yml`) and refuses to sign with any other key. Every run, dry runs included, first checks that the secrets open that key, without signing anything (`openrmm-release -check-key`).

The project's release public key is:

```text
224cceb1234f8bc04d9c08724e73ff7945d7a2fdc43ab12c54552b0ef7d470ae
```

Official agents and servers trust exactly this key for updates.

> [!IMPORTANT]
> Agents installed from builds older than the one-year validity rule accept release manifests valid for at most 90 days, so they refuse automatic updates to public releases. Reinstall such devices once with the MSI from a public release (`install.cmd` or `scripts/install-agent.ps1`).

## Prerequisites

- Windows x64 with PowerShell 7.
- Go; the scripts pin the toolchain with `GOTOOLCHAIN=go1.27.2`.
- Node.js with npm, for the web dashboard.
- WSL with an `Ubuntu` distribution running Docker Engine, for the MSI build, the server image and the local server.

All scripts are run from the repository root.

## Check and build

```powershell
.\scripts\check.ps1
.\scripts\build.ps1
```

`scripts/check.ps1`:

- verifies that the Go module graph matches `dependencies.lock` and runs `go mod verify` (read-only module resolution; the baseline is never refreshed automatically);
- installs the web packages exactly from `package-lock.json` with lifecycle scripts disabled, runs `npm audit` for runtime packages (a high-severity advisory fails the check), the TypeScript typecheck and the web unit tests;
- runs `gofmt`, `go vet` and `go test`.

`scripts/build.ps1` repeats the dependency check, builds the web dashboard into `internal/server/webui/dist` (embedded by the server), then builds the Go programs with `-mod=readonly -trimpath`.

| Parameter | Default | Description |
| --- | --- | --- |
| `-Target` | `all` | `all`, `windows` or `linux`. |
| `-AgentVersion` | | Version embedded in the agent and reported in heartbeats. |
| `-ReleaseSequence` | `0` | Release sequence built into the agent as its update replay floor (0–65535). |
| `-PinnedKeys` | `.local/agent-updates-publisher/public.txt` if present | Up to eight comma-separated Ed25519 public keys (64 lowercase hex characters each) the agent trusts for self-updates. |

An agent built without pinned keys accepts no update; its device shows **Needs local setup** on **Agent updates**. In practice, let `scripts/release.ps1` set these parameters.

**The agent MSI.** `scripts/build-msi.ps1 -ProductVersion 1.0.<sequence> [-AgentVersion <version>]` packages the already built `openrmm-agent.exe` and `openrmm-desktop.exe` with `installer/openrmm-agent.wxs`. It runs msitools `wixl` 0.106 in a pinned image (`installer/Dockerfile`) through Docker in WSL, with networking disabled for the build container, and writes `dist/windows-amd64/openrmm-agent.msi`. `build.ps1` does not build the MSI; `release.ps1` does. See [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md) for what the package installs.

## The release signing key

Agent and server releases are signed with an Ed25519 key that never enters the server, its image or its backups. Anyone who holds the key and its passphrase can authorize code that every agent installs, so their custody is the release authority.

Create a key once:

```powershell
.\scripts\build.ps1 -Target windows
Read-Host 'Passphrase' -MaskInput | .\dist\windows-amd64\openrmm-release.exe -create-key C:\keys\openrmm-signing -passphrase-stdin
```

The key folder holds:

| File | Contents |
| --- | --- |
| `signing-key.json` | The Ed25519 seed, encrypted with AES-256-GCM under an Argon2id key derived from the passphrase (at least 15 characters). The public key is bound as additional data. |
| `public.txt` | The public key in hex. |
| `sequence.json` | The last release sequence used with this key. |

- The signer consumes the next sequence before it signs, so a sequence is never reused for different bytes, even if signing is interrupted. An explicit `-sequence` must be higher than the last one used.
- Keep the folder and the passphrase outside the repository, server data, container build inputs and server backups. Back them up separately. Losing either means agents must be rebuilt with a new key and reinstalled locally.
- `scripts/release.ps1` uses `.local/agent-updates-publisher` by default; pass `-KeyDirectory` to use another folder.
- A folder that still holds an older plaintext `private.pem` is encrypted once by `release.ps1`: it asks for the highest sequence already used and a new passphrase, keeps the same public key, verifies the encrypted copy and then deletes the plaintext file.

## Release the agent

```powershell
.\scripts\release.ps1 -Version 0.2.0            # build, sign and bundle
.\scripts\release.ps1 -Version 0.2.0 -Deploy    # also back up, verify and replace the local server
```

| Parameter | Default | Description |
| --- | --- | --- |
| `-Version` | (required) | Agent version, for example `0.2.0` (letters, digits, `.`, `_`, `+`, `-`). |
| `-KeyDirectory` | `.local/agent-updates-publisher` | Folder with `signing-key.json`, `public.txt` and `sequence.json`. |
| `-Days` | `365` | Validity of the signed release, 1–366 days. |
| `-Deploy` | off | Back up and verify the local server, then rebuild and restart it with the new release. |

The script:

1. reads the next sequence from `sequence.json` (at most 65535, because it becomes part of the MSI version);
2. runs `scripts/check.ps1`;
3. builds the agent with the version, the sequence and the key's public key built in;
4. builds the MSI with ProductVersion `1.0.<sequence>`, so every release has a distinct Windows Installer version;
5. signs the MSI with `openrmm-release -binary <msi> -agent <exe>`;
6. places `release.json`, `public.txt` and `openrmm-agent.msi` into `internal/agentbundle/files` and rebuilds, so the server embeds the release;
7. with `-Deploy`, backs up and verifies the local server with `scripts/recovery.py`, rebuilds and restarts it, and checks the server log that the bundled release was imported.

The passphrase is read from `OPENRMM_SIGNING_PASSPHRASE` when it is set; otherwise the script asks for it without echo (up to three attempts; a failed attempt uses no sequence). It reaches the signer only on standard input. Signed outputs stay in `.local/releases/<version>`; a version that was already signed is refused.

At startup, a server verifies its bundled release (signature, hash, size, package structure, validity period) and imports it into its release library as `system:server-build`. To make room, it withdraws the oldest releases it imported itself that no queued job or automatic rollout uses; uploaded releases stay. Roll the release out from **Agent updates** ([AGENT-UPDATES.md](AGENT-UPDATES.md)).

**Release format 2.** The signed manifest binds product, operating system, architecture, version, sequence, key ID, issue and expiry time, the MSI's exact size and SHA-256, and the SHA-256 of the `openrmm-agent.exe` inside the MSI (`agent_sha256`). The maximum package size is 32 MiB and the maximum validity is 366 days.

The signer can also be used directly, but the MSI version must be `1.0.<sequence>` and the agent inside it must have been built with that sequence and key, so use `release.ps1` in practice:

```powershell
Read-Host 'Passphrase' -MaskInput | .\dist\windows-amd64\openrmm-release.exe -key C:\keys\openrmm-signing\signing-key.json -passphrase-stdin -binary .\openrmm-agent.msi -agent .\openrmm-agent.exe -version 0.2.0 -days 30 -out .\release.json
```

The signer uses Go's standard-library Ed25519 and AES-GCM and `golang.org/x/crypto/argon2`. It has no network client, creates output files exclusively and never prints private material.

## Build the server image

The image builds the web dashboard itself; only the bundled agent release comes from the source tree, so run `scripts/release.ps1` first. Then build the image with Docker:

```powershell
wsl -d Ubuntu --user root --cd "$PWD" --exec docker build -t registry.example.com/openrmm-server:0.2.0 .
```

The `Dockerfile`:

- uses a digest-pinned Go builder image;
- checks the module graph against `dependencies.lock` and runs `go mod verify`;
- runs the Go tests with networking disabled, then builds the server, the updater, the certificate helper and a Linux agent binary (used by the local deployment's health check);
- produces a `scratch` image running as UID 10001, with the license files and public TLS roots.

`.dockerignore` admits only the build inputs, so `.env`, `.local` and `dist` never reach the Docker daemon.

For the local development deployment, `.\scripts\local.ps1 -Action build` builds the web dashboard and the `openrmm-local:dev` image through `compose.yaml`.

## Sign and publish a server release

1. Push the image to its registry and note:
   - the image ID: `docker image inspect --format '{{.Id}}' <image>`;
   - the registry digest: the `sha256:...` part of the pushed image's repository digest.
2. Sign the manifest with the same key and the sequence of the agent release bundled into this image:

   ```powershell
   Read-Host 'Passphrase' -MaskInput | .\dist\windows-amd64\openrmm-release.exe -server-release -key C:\keys\openrmm-signing\signing-key.json -passphrase-stdin -version 0.2.0 -sequence 12 -image registry.example.com/openrmm-server -image-id sha256:<image ID> -digest sha256:<registry digest> -notes .\notes.txt -days 365 -out .\openrmm-server-release.json
   ```

3. Attach the file to the GitHub release as `openrmm-server-release.json`.

| Flag | Rules |
| --- | --- |
| `-sequence` | Must already be used by the key's counter (the bundled agent release); a server release consumes no new sequence. Servers offer a release only if its sequence is higher than their own. |
| `-image` | Repository without tag, lowercase (for example `ghcr.io/example/openrmm-server`). |
| `-image-id` | Content-addressed image ID (`sha256:` and 64 hex characters), checked after the pull. |
| `-digest` | Registry digest used to pull. Optional only for images that are already present on the host. |
| `-notes` | Optional UTF-8 text file of at most 16 KiB, shown on **Server updates**. |
| `-days` | Validity, 1–400 days (default 30). |

Servers find releases through the GitHub repository named in the build (`serverupdate.Repository`). See [SERVER-UPDATES.md](SERVER-UPDATES.md) for how servers and the updater verify the manifest.

## Local development package

`scripts/package.ps1` creates a ZIP under `dist/` for moving a tested build to another Windows computer with the same development setup. It runs the checks, the Windows and Linux builds, the image build, a container isolation and persistence test (`scripts/container-smoke.sh`) and a pinned `govulncheck` scan of the source and the built binaries (`scripts/security-check.sh`). It then packages the source, scripts, documentation, notices, binaries, the agent MSI (if built) and the exact runtime image (`server-image.tar`). Private configuration, application state, backups, caches and generated certificates are not included.

The ZIP contains `package.json` (image ID, Go toolchain, license) and `checksums.json` covering every file; the adjacent `.sha256` file covers the ZIP itself. These detect accidental corruption when compared with a trusted copy; they are not a signature. After extracting, verify the files from the extracted folder:

```powershell
$expected = Get-Content checksums.json -Raw | ConvertFrom-Json -AsHashtable
foreach ($entry in $expected.GetEnumerator()) {
    if ((Get-FileHash -LiteralPath $entry.Key -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) {
        throw 'Package integrity check failed.'
    }
}
```

To use the package, load `server-image.tar` with Docker in WSL and tag the image ID from `package.json` as `openrmm-local:dev`, then initialize and start the local deployment with `scripts/local.ps1` (see [ADMINISTRATOR.md](ADMINISTRATOR.md)). Rebuilds use the pinned dependency baseline; byte-for-byte reproducibility across hosts and toolchains is not claimed. Never bypass a checksum or dependency-baseline failure to complete a build.

## Licensing of release artifacts

Original OpenRMM code and documentation are licensed under AGPL-3.0-only. The server image, the agent MSI and the development package include `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md`. Third-party components keep their own licenses; see [LICENSING.md](LICENSING.md) and [DEPENDENCIES.md](DEPENDENCIES.md). Anyone distributing a build must also provide the Corresponding Source as required by the AGPL.

## Security notes

- The Ed25519 release signatures are independent of Windows Authenticode. The MSI and the programs are not Authenticode-signed, and reproducible-build provenance is not claimed.
- Never put the signing key or passphrase into the repository, a container build context, server configuration or a server backup.
- Dependency changes need a reviewed update of `dependencies.lock` or `package-lock.json` and an entry in [DEPENDENCIES.md](DEPENDENCIES.md); the build scripts never refresh them automatically.

## Related

- [Agent updates](AGENT-UPDATES.md)
- [Server updates](SERVER-UPDATES.md)
- [Windows agent service](WINDOWS-SERVICE.md)
- [Installing the server](INSTALL.md)
- [Dependencies](DEPENDENCIES.md)
