# Dependencies

OpenRMM keeps its trusted code small: the Go standard library by default, a few reviewed modules where it has a real gap, and a lean, locked set of packages for the browser application. This page describes the policy, the current inventory, how changes are locked and checked, and why each significant dependency was chosen. It is for contributors and for anyone auditing the supply chain.

## Contents

- [Policy](#policy)
- [Inventory](#inventory)
  - [Go modules](#go-modules)
  - [Go toolchain and development tools](#go-toolchain-and-development-tools)
  - [npm packages](#npm-packages)
  - [Build-time images](#build-time-images)
  - [Operating system prerequisites](#operating-system-prerequisites)
- [How changes are reviewed and locked](#how-changes-are-reviewed-and-locked)
- [Review notes](#review-notes)
- [Related](#related)

## Policy

- **Standard library first.** HTTP, routing, templates, JSON, logging, configuration, testing, TLS and certificates, and small application helpers use Go's standard library.
- **Capability gap required.** A dependency is added only for a concrete capability the standard library or the existing graph cannot provide. No framework, ORM, SDK or generic abstraction package is added for convenience.
- **Whole graph reviewed.** A review covers the full dependency graph, including transitive and build/test requirements. Package count alone is not a measure of trusted code size or safety.
- **Recorded decision.** Before a module or package is added or upgraded, its purpose, alternatives, transitive impact, maintenance and security findings, and exact version are recorded on this page.
- **Cryptography.** Use standard-library cryptography or narrowly scoped, maintained implementations. Password hashing and cryptographic primitives are never implemented in-house to reduce the dependency count.
- **Pinned and verified.** Exact versions only, checksum verification always on, no floating versions, no automatic upgrades, no runtime code fetching, and no upstream install or generation scripts without a specific, reviewed need.
- **Security updates stay current** through reviewed version changes. Vulnerable versions are not frozen, and external code is not copied into the project to hide a dependency.
- **Runtime imports count too.** A new import from an already pinned module (for example a new `golang.org/x/sys/windows` API) is reviewed even when the module graph does not change.
- **Frontend exception.** The browser application in `web/` uses React + TypeScript, Vite, Tailwind CSS, react-router, TanStack Query, individual Radix UI primitives and lucide-react, plus the reviewed packages listed below. It is kept lean and locked: exact versions, a committed `package-lock.json`, `npm ci --ignore-scripts`, no lifecycle scripts, no CDN or remote fonts, a review entry for every added or upgraded package, and a preference for releases at least two weeks old. Built assets are embedded in the server binary; no Node.js runs in a runtime image.

## Inventory

### Go modules

`go.mod` declares three direct requirements. The full resolved graph in `dependencies.lock` has 29 external module versions; only the 11 below are linked into any OpenRMM binary.

**Direct requirements:**

| Module | Version | License | Purpose | Linked into |
| --- | --- | --- | --- | --- |
| `golang.org/x/crypto` | v0.58.0 | BSD-3-Clause | `argon2` (Argon2id password hashing; release signing-key encryption) and `acme` (automatic HTTPS certificates) | Server, release signer |
| `golang.org/x/sys` | v0.49.0 | BSD-3-Clause | Windows service, registry and Win32 APIs; Unix system calls used by the SQLite driver | Windows agent, desktop companion and certificate helper; server, updater and release signer |
| `modernc.org/sqlite` | v1.60.1 | BSD-3-Clause; bundled SQLite is public domain | Pure-Go SQLite driver (no C compiler), isolated in `internal/storage` | Server, updater |

**Indirect requirements linked through the SQLite driver:**

| Module | Version | License | Linked on |
| --- | --- | --- | --- |
| `modernc.org/libc` | v1.77.1 | BSD-3-Clause with upstream third-party notices | Windows, Linux |
| `modernc.org/mathutil` | v1.7.1 | BSD-3-Clause | Windows, Linux |
| `modernc.org/memory` | v1.12.1 | BSD-3-Clause with additional upstream notices | Windows, Linux |
| `github.com/dustin/go-humanize` | v1.0.1 | MIT | Windows, Linux |
| `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748-24d4a6f8daec | BSD-3-Clause | Windows, Linux |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause | Linux |
| `github.com/mattn/go-isatty` | v0.0.24 | MIT | Windows |
| `github.com/ncruces/go-strftime` | v1.0.0 | MIT | Windows |

**Per binary:**

| Binary | External modules linked |
| --- | --- |
| Server (`openrmm-server`) | 10 on Windows, 9 on Linux |
| Updater sidecar (`openrmm-updater`) | The SQLite driver and its requirements, plus `x/sys` |
| Windows agent (`openrmm-agent`) | `golang.org/x/sys` only |
| Desktop companion (`openrmm-desktop`) | `golang.org/x/sys` only |
| Release signer (`openrmm-release`) | `golang.org/x/crypto`, `golang.org/x/sys` |
| Linux diagnostic agent, Linux certificate helper, custody tool | None |

**Graph-only modules.** The remaining 18 versions in `dependencies.lock` are requirements of the modules above: upstream development and code-generation tooling (`modernc.org/cc/v4`, `ccgo/v4`, `fileutil`, `gc/v2`, `gc/v3`, `goabi0`, `opt`, `sortutil`, `strutil`, `token`; `github.com/google/pprof`; `github.com/hashicorp/golang-lru/v2`) and the wider `golang.org/x` modules (`mod`, `net`, `sync`, `term`, `text`, `tools`). They are not linked into any binary, but they stay in the baseline because they affect dependency resolution.

Upstream license texts, including the driver's and libc's aggregate notices, are collected in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md), which ships in the server image and the agent MSI.

### Go toolchain and development tools

| Tool | Version | Use |
| --- | --- | --- |
| Go toolchain | 1.27.2 | All builds. `go.mod` declares `go 1.26.0` as the minimum; the check and build scripts select `go1.27.2` exactly (`GOTOOLCHAIN`), downloading its checksum-verified distribution into the ignored project module cache when needed. The container builder uses the same version, pinned by digest. |
| `golang.org/x/vuln/cmd/govulncheck` | v1.9.0 | Source and binary reachability scans (`scripts/security-check.sh`), run in the disposable builder container with telemetry off. Not part of the application graph or any runtime image. |

### npm packages

All versions are exact (`web/.npmrc`: `save-exact=true`, `ignore-scripts=true`). Runtime packages are bundled into the embedded assets; build-only packages never ship.

**Runtime (bundled):**

| Package | Version | License | Purpose |
| --- | --- | --- | --- |
| `react`, `react-dom` | 19.3.0 | MIT | UI rendering |
| `react-router` | 8.4.0 | MIT | Client-side routes (declarative mode) |
| `@tanstack/react-query` | 5.104.1 | MIT | Cached queries, live polling, mutations |
| `@radix-ui/react-dialog` | 1.2.0 | MIT | Accessible modal dialogs and focus trapping |
| `@radix-ui/react-dropdown-menu` | 2.1.25 | MIT | Accessible menus |
| `@radix-ui/react-tooltip` | 1.3.0 | MIT | Accessible tooltips |
| `lucide-react` | 1.52.0 | ISC | SVG icons, tree-shaken into the bundle |
| `uplot` | 1.6.32 | MIT | Time-series charts for device metrics |
| `@xterm/xterm` | 6.0.0 | MIT | Terminal emulator for the PowerShell session page |
| `@codemirror/state` | 6.7.6 | MIT | Script editor |
| `@codemirror/view` | 6.43.13 | MIT | Script editor |
| `@codemirror/commands` | 6.11.1 | MIT | Script editor |
| `@codemirror/language` | 6.12.4 | MIT | Script editor |
| `@codemirror/search` | 6.7.2 | MIT | Script editor |
| `@codemirror/legacy-modes` | 6.5.4 | MIT | PowerShell syntax mode |
| `@lezer/highlight` | 1.2.5 | MIT | Syntax highlighting tags |

`web/package.json` pins the transitive `@lezer/lr` to 1.4.10 through `overrides`. All bundled code (direct and transitive) is under MIT, ISC or 0BSD licenses; the texts are in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

**Build-only (never shipped):**

| Package | Version | Purpose |
| --- | --- | --- |
| `vite` | 8.3.4 | Bundler and build tool |
| `@vitejs/plugin-react` | 6.1.2 | React support for Vite |
| `tailwindcss`, `@tailwindcss/vite` | 4.3.3 | CSS framework and its Vite plugin |
| `typescript` | 7.0.2 | Type checking |
| `@types/react`, `@types/react-dom` | 19.3.0 | React type definitions |

Build tooling licenses include MIT, Apache-2.0, ISC, BSD-3-Clause and MPL-2.0 (lightningcss). Native build tools (rolldown, lightningcss, the Tailwind oxide engine and the TypeScript native compiler) arrive as ordinary platform packages, not through install scripts. The only lockfile entry that declares an install script is `fsevents` (macOS only), and scripts are disabled anyway.

### Build-time images

| Image | Pinned reference | Use |
| --- | --- | --- |
| Web builder | `node:24.22.0-bookworm-slim@sha256:91acba91b842bec0bf7ea6f5e09c644c7ccad72c4996ed9616d861d1c7cd60d4` | Builds the web dashboard from the locked npm packages in the image's first stage (`Dockerfile`); nothing from it reaches the runtime image except the built static files |
| Go builder | `golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61` | Builds and tests the Go binaries (`Dockerfile`); source of the public CA bundle copied into the runtime image |
| Runtime base | `scratch` | Server image: OpenRMM binaries, legal files and the CA bundle only, no shell or package manager |
| MSI builder | `ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944` with `wixl=0.106+repack-2` and `wixl-data=0.106+repack-2` | Builds the agent MSI (`installer/Dockerfile`, run by `scripts/build-msi.ps1` with `--network none` as a non-root user) |

### Continuous integration

GitHub Actions run `scripts/check.ps1` on Linux and Windows and build the container image (`.github/workflows/ci.yml`). Only GitHub's own actions are used, each pinned to an exact commit, with read-only repository permissions.

| Action | Version | Commit | Use |
| --- | --- | --- | --- |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | Checks out the commit under test (credentials not persisted) |
| `actions/setup-node` | v7.1.0 | `949feb2413d6458794dcd2491c4babbbce0c15c1` | Installs Node.js 24.22.0, the same version the image's web builder uses |

The Go toolchain is not installed by an action: `check.ps1` pins `go1.27.2` through `GOTOOLCHAIN`, and the runner's preinstalled Go only launches it.

### Operating system prerequisites

These are supplied by the operating system, not bundled or installed by OpenRMM:

- **Windows PowerShell 5.1** at its fixed system-directory path, for scripts, application deployment and the terminal. No PowerShell modules are installed.
- **Windows Installer** (`msiexec`) for agent self-updates and MSI application deployment.
- **ConPTY** (Windows 10 1809 / Server 2019 or later) for the interactive terminal.
- **Docker Engine** and the Docker CLI on the server host. `deploy/install.sh` uses bash and the Docker CLI and installs nothing else.

## How changes are reviewed and locked

### Go modules

- `dependencies.lock` records every resolved external module version plus the local module. It is the reviewed baseline.
- `scripts/check-dependencies.ps1` compares `go list -mod=readonly -m all` with the baseline and runs `go mod verify`. `scripts/check.ps1` and `scripts/build.ps1` run it before compiling or testing.
- The container build performs the same comparison and `go mod verify`. Modules download in a dedicated layer; compilation and tests then run with networking disabled.
- Every build uses `-mod=readonly` and `GOWORK=off`, so a build can never edit module requirements or adopt workspace replacements.
- Checksum database verification stays enabled. Checksums prove the downloaded bytes match the expected versions; they do not prove the upstream code is benign.

### npm packages

- `web/package-lock.json` is the baseline. `scripts/build-web.ps1` runs `npm ci --ignore-scripts` and fails if the lockfile changes during install.
- It then runs `npm audit --omit=dev --audit-level=high`, a strict TypeScript check and the unit tests before building.

### Making a deliberate change

1. Establish the capability gap (or the security fix) and review the full transitive change, licenses, install scripts and maintenance state.
2. Record the decision in [Review notes](#review-notes) and update the inventory tables.
3. Commit `go.mod`, `go.sum` and `dependencies.lock` (or `package.json` and `package-lock.json`) together with the review.

A graph change fails the normal checks. The baseline has no automatic update mode, and it is never refreshed just to make a failing check pass.

Before releases, run the pinned vulnerability scanner from the repository root (after building the Windows binaries):

```bash
sh scripts/security-check.sh
```

Revisit dependencies when features change, and remove those no longer needed.

## Review notes

### Go modules and runtime imports

**`golang.org/x/crypto/argon2`.** Argon2id password hashing for administrator and technician accounts (19 MiB memory, two passes, one lane, 16-byte random salt, 32-byte result, bounded concurrent hashing, matching an [OWASP recommended configuration](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)). The standard library has no Argon2id; an authentication framework or an in-house implementation was rejected. The offline release signer also uses it to encrypt the signing key at rest with standard-library AES-GCM. TLS, AES-GCM, HKDF, TOTP, tokens and sessions use the standard library.

**`golang.org/x/crypto/acme`.** The server obtains and renews its dashboard certificate itself with a small certificate manager (`internal/acmecert`) on the upstream ACME client, answering TLS-ALPN-01 challenges on port 443. `acme/autocert` was rejected because it would make `golang.org/x/net` and `golang.org/x/text` runtime imports; writing an ACME client on the standard library was rejected because it would reimplement JWS signing.

**OpenPGP in `golang.org/x/crypto`.** The module contains unmaintained OpenPGP packages with a known advisory and no fixed version ([GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)). OpenRMM does not import them; do not add an OpenPGP import.

**`golang.org/x/sys`.** The standard library has no Windows Service Control Manager dispatcher, registry access or most Win32 APIs. The Go-maintained `windows`, `windows/svc`, `windows/svc/mgr` and `windows/registry` packages fill that gap; the module has no external requirements of its own. Where the pinned version has no typed wrapper (for example the event log API, physical memory and CPU counters, WUA COM, ConPTY attributes, GDI capture and input, and the Windows Filtering Platform), the agent uses narrow, fixed entry points loaded only from system DLLs, with explicit buffer bounds, handle cleanup and native layout tests. WMI wrappers, PowerShell collectors, metrics SDKs (such as gopsutil), COM libraries and update modules (such as PSWindowsUpdate) were rejected as larger runtime surfaces.

**`golang.org/x/sys/windows/registry` for software inventory.** The collector reads fixed HKLM uninstall keys in both registry views with a fixed buffer instead of the generic string reader, which may allocate from registry-reported sizes. Only local read and enumeration access is requested.

**`modernc.org/sqlite` (storage exception).** SQLite provides transactional persistence and recovery. The pure-Go driver keeps the Windows and Linux builds CGO-free. It is a deliberate exception to the standard-library preference, isolated in `internal/storage`; a dependency-free database would move storage correctness and recovery into application code. `modernc.org/libc` stays at exactly the version the driver's module file selects, as upstream requires. Changing drivers should compare the full trusted code and tooling footprint, not module counts.

**Updater sidecar.** `openrmm-updater` talks to the Docker Engine API with `net/http` over the Unix socket. A Docker SDK or Compose library was rejected (dozens of modules), and shelling out to the `docker` CLI is impossible in a shell-less image. It links the already pinned SQLite driver (through `internal/storage`) to run a read-only integrity check on database backups. Release signatures use `crypto/ed25519`.

**Agent self-update and release signing.** Ed25519 signatures, SHA-256, strict JSON and PE inspection use the standard library; the Windows side uses existing `x/sys` service APIs. No updater framework, package manager or Authenticode dependency is used. TLS protects transport; independently pinned signing keys authorize executable contents.

**Enrollment, heartbeats and certificates.** Enrollment tokens, CSRs, X.509 issuance, mTLS, key persistence, renewal, retries and jitter use the standard library. Jitter uses `math/rand/v2` for scheduling only; tokens and keys use cryptographic randomness.

**Agent proxy and local secrets.** Proxy use is the standard library's `http.Transport` (CONNECT tunnels, Basic authentication). The machine's WinHTTP proxy is read with one fixed entry point, `WinHttpGetDefaultProxyConfiguration` from the system `winhttp.dll` (its strings freed with `GlobalFree`); the policy value uses the existing `x/sys/windows/registry` reader. Local secrets such as a proxy password, and software device keys, are encrypted with DPAPI through the typed `CryptProtectData`/`CryptUnprotectData` wrappers in `x/sys/windows` (`internal/dpapi`). Device keys in the TPM (`internal/devicekey`) use a fixed set of CNG entry points from the system `ncrypt.dll` (open the Platform Crypto Provider, create, finalize, open, export the public half, sign, delete, free) with fixed buffer sizes and a sign-and-verify self-check before a new key is used; TPM libraries (such as go-tpm) were rejected because CNG already handles the TPM and keeps the key in Windows' own key store. Proxy auto-configuration (WPAD and PAC scripts) would need a JavaScript engine and NTLM/Kerberos proxy sign-in an SSPI client; both were left out rather than adding either.

**Mail.** Alert e-mail uses the standard library's `net/smtp` with explicit verified TLS, deadlines and bounded messages; third-party mail libraries add no needed capability. The runtime image copies the public CA bundle from the pinned builder image instead of installing a package; an explicit root CA file can restrict SMTP trust instead.

**Terminal, files, desktop and transfers.** The live terminal relay, file transfer (with `os.Root` containment), attended desktop (JPEG frames over a bounded relay) and scheduling use the standard library and existing `x/sys` APIs. WebSocket, WebRTC, codec, SFTP/SMB and remote-control products (such as MeshCentral or RustDesk) were rejected as large new trust surfaces for the current scope.

**Scheduling, reports and search.** Fixed UTC intervals, patch windows, CSV export and fleet software search use the standard library and SQLite transactions. Cron parsers, job frameworks, query builders, search engines and spreadsheet libraries were rejected.

**Go toolchain patches.** Standard-library vulnerabilities are fixed by moving to a patched toolchain. A toolchain security update is a dependency change and is pinned the same way.

### Browser application

**Frontend stack.** The dashboard needs client-side routing between live views, cached polling that updates without discarding operator state, accessible dialogs, menus and tooltips with focus management, and a token-based visual system with dark and light themes. A hand-built server-rendered interface could not meet these needs. React, react-router, TanStack Query, Tailwind CSS and headless Radix primitives fill these gaps. The `radix-ui` umbrella package (about 40 sub-packages) was rejected in favour of individual primitives; a table library was rejected (sorting is in-house); component kits such as Mantine or MUI were rejected in favour of headless components.

**CSP compatibility.** The page allows `script-src 'self'` only. Styles allow `'self'` plus a per-request nonce because dialog primitives insert a `<style>` element. No CDN, remote font or icon service is used.

**uPlot.** Device CPU, memory and disk charts. Zero dependencies, about 50 KB minified, canvas-based and CSP-compatible. Chart.js (larger) and Recharts (11 dependencies) were rejected.

**xterm.js.** Terminal emulation for the PowerShell session page, replacing a minimal hand-built display. No dependencies and no install scripts; it loads only on the terminal page in a separate chunk. It inserts `<style>` elements without a nonce option, so `web/src/main.tsx` stamps the page nonce onto `<style>` elements created through `document.createElement`. Only bundled same-origin scripts can call it, so injected markup still cannot add styles. The `fit` and `web-links` addons are not used (the terminal size is fixed at 100 × 30).

**CodeMirror.** A real code editor for scripts. Only the modules in use are installed instead of the `codemirror` meta-package; they bring the transitive packages `@lezer/common`, `@lezer/lr`, `@marijn/find-cluster-break`, `crelt`, `style-mod` and `w3c-keyname` (all MIT, no install scripts). `@lezer/lr` is held at 1.4.10 through `overrides` under the two-week rule, within `@codemirror/language`'s allowed range. Styles use `EditorView.cspNonce`. The editor loads only on the script editor page in a separate chunk.

**Vite 8.3.4.** Upgraded to fix advisories in Vite's development server and its bundled `launch-editor` (GHSA-587h-7wmj-h5pm, GHSA-698v-4r3x-3vcv, GHSA-r825-w8mm-5pxw, GHSA-rq7h-c2jc-7f22, GHSA-vfpm-58rq-9qcg, GHSA-9jrq-w75r-8gcw). OpenRMM builds only run `vite build`, so shipped assets were not affected. The upgrade changed no other lockfile package.

**Unit tests.** Pure helpers in `web/src/lib` are tested with Node's built-in test runner, which adds no package. Component-level tests would need a DOM library and remain a separate dependency decision.

### Build-time tools

**wixl (msitools) for the agent MSI.** The agent ships as a Windows Installer package, which it also uses to update itself. Go cannot write MSI databases, and a hand-written MSI writer would be a new implementation of a complex binary format. `wixl` 0.106 runs only in the pinned Ubuntu build image with networking disabled; its apt transitive set is about 21 packages, mostly already in the base image, verified through Ubuntu's signed repository metadata. Nothing from the image reaches the server image or a device except the MSI, whose contents are OpenRMM's own binaries and notices and which every release binds by its Ed25519 signature. Alternatives: the WiX Toolset (needs .NET on Windows, and recent releases add a maintenance-fee condition for some users) and NSIS (no Windows Installer transactions, no GPO/Intune MSI deployment).

Known `wixl` limits used deliberately: it ignores `Platform` on `Package` (the `-a x64` switch sets the architecture) and `KeyPath` on `Component`, and it has no `ServiceConfig`, so the agent sets its own delayed start and crash recovery at start-up. The generated `RemoveExistingProducts` runs before `InstallInitialize`, so Windows Installer does not roll back a failed upgrade itself; the agent's update helper reinstalls the previous package.

**Node.js build stage.** The server image builds the web dashboard itself, so an image built from a clean checkout is complete. The stage uses the pinned `node` image at the same version as local builds (24.22.0), installs exactly from `package-lock.json` with lifecycle scripts disabled, and builds with networking disabled. Node.js never enters the runtime image. Alternative: committing the built dashboard to the repository (rejected: generated files in the repository can drift from their sources).

**CI actions.** Only `actions/checkout` and `actions/setup-node` (both maintained by GitHub) are used, each pinned to a commit rather than a movable tag. The Go toolchain comes from the pinned `GOTOOLCHAIN`, so no third-party setup action is needed. Upgrades follow the same review rule as other dependencies.

**Install script.** `deploy/install.sh` uses bash and the Docker CLI already on the host and downloads nothing else.

## Related

- [LICENSING.md](LICENSING.md): project license and third-party notices
- [RELEASE.md](RELEASE.md): building and signing releases
- [UI-UX.md](UI-UX.md): web interface structure and conventions
- [AGENT-UPDATES.md](AGENT-UPDATES.md): signed agent updates
- [SERVER-UPDATES.md](SERVER-UPDATES.md): the updater sidecar
