# Contributing to OpenRMM

Thanks for your interest in OpenRMM! Bug reports, feature ideas, documentation fixes and code are all welcome.

## Contents

- [Ways to contribute](#ways-to-contribute)
- [Development setup](#development-setup)
- [Before you open a pull request](#before-you-open-a-pull-request)
- [Coding guidelines](#coding-guidelines)
- [Dependency policy](#dependency-policy)
- [Commits and pull requests](#commits-and-pull-requests)
- [License of contributions](#license-of-contributions)

## Ways to contribute

- **Report a bug.** Open an issue with steps to reproduce, the expected and actual behaviour, and the server and agent versions. Remove any secrets, host names or device data.
- **Suggest a feature.** Open an issue that describes the problem you want solved. Check the [roadmap](ROADMAP.md) first.
- **Report a vulnerability.** Do **not** open an issue. Follow [SECURITY.md](SECURITY.md).
- **Improve the docs.** Every page under [`docs/`](docs/README.md) can be improved with a pull request.

## Development setup

The [development guide](docs/DEVELOPMENT.md) explains the toolchain, the repository layout and how to run a local server and agent. In short:

```powershell
.\scripts\check.ps1   # everything a pull request must pass
.\scripts\build.ps1   # web interface plus Windows and Linux binaries
```

## Before you open a pull request

- [ ] `scripts/check.ps1` passes: dependency integrity, web typecheck and tests, `gofmt`, `go vet` and the Go tests.
- [ ] New behaviour has tests next to the code. Storage changes come with a migration and a test.
- [ ] User-visible changes are documented in the matching page under `docs/`.
- [ ] No secrets, personal data, host names or local paths appear in code, tests, docs or commit messages.

## Coding guidelines

- **Go standard library first.** Use it for HTTP, routing, JSON, logging, configuration and tests. See the dependency policy below.
- **Clear boundaries:**
  - SQL lives only in `internal/storage`.
  - Windows APIs live in `_windows.go` files.
  - Agent/server messages live in `internal/protocol`.
- **Migrations are append-only.** Never edit a released migration; add a new one.
- **Security by default:**
  - authorize in the handler and again in storage;
  - bound request sizes and durations;
  - never log passwords, tokens, session IDs or keys.
- **Match the surrounding code.** Follow its naming, comment density and idioms. Run `gofmt`; for the web interface, follow [UI-UX.md](docs/UI-UX.md).

## Dependency policy

Keeping dependencies to a minimum is a project requirement.

- Do not add a framework, ORM, SDK or convenience package without first showing that the standard library or existing code cannot reasonably do the job.
- Every new or upgraded dependency needs a review entry in [DEPENDENCIES.md](docs/DEPENDENCIES.md). It records the purpose, the alternatives, the effect on transitive dependencies, maintenance and security notes, and the exact version.
- Go builds run against `dependencies.lock` with read-only module resolution. A deliberate change updates `go.mod`, `go.sum` and `dependencies.lock` together.
- The web interface uses exact npm versions, a committed `package-lock.json` and `npm ci --ignore-scripts`, with no install scripts and no CDN assets. Prefer releases that are at least two weeks old.

## Commits and pull requests

- Keep each pull request focused on one change, and describe what changed and why.
- Write commit messages in the imperative mood ("Add disk space alert"), with a short summary line.
- Sign your commits (SSH or GPG) if you can; signed commits show as **Verified** on GitHub.
- A maintainer reviews every pull request. Changes that touch security boundaries, signing, migrations or dependencies get extra scrutiny.

## License of contributions

OpenRMM is licensed under [AGPL-3.0-only](LICENSE). By submitting a contribution, you agree that it is licensed under the same terms.
