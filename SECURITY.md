# Security Policy

OpenRMM manages and investigates computers with LocalSystem privileges, so its security matters a great deal. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

> [!IMPORTANT]
> Please **do not** report security issues through public GitHub issues, discussions or pull requests.

Report vulnerabilities privately through GitHub:

**[Report a vulnerability →](https://github.com/IAmForeverAloneToo/OpenRMM/security/advisories/new)**

You can also open the repository's **Security** tab and choose **Report a vulnerability**. Only the maintainers can see the report.

Please include:

- the affected version, commit or image digest;
- a description of the issue and its impact;
- steps to reproduce, ideally against disposable test devices;
- any proof-of-concept code, logs or screenshots, with secrets removed.

Never include real credentials, enrollment tokens, private keys, recovery codes, session cookies or data from real devices.

## What happens next

1. **Acknowledgement.** We aim to confirm receipt within a few days.
2. **Assessment.** We reproduce the issue in an isolated environment, assess which versions are affected, and agree a severity with you.
3. **Fix.** We prepare a fix and a regression test. Where needed, we coordinate a release date with you.
4. **Disclosure.** We publish a GitHub security advisory with the fixed versions and, if you wish, credit you by name.

OpenRMM is maintained on a volunteer basis, and there is no bug bounty programme.

## Supported versions

Only the latest release receives security fixes. While OpenRMM is at 0.x, fixes are not backported: each one ships in a new release, and servers update to it from the dashboard ([UPGRADING.md](docs/UPGRADING.md)). Pre-releases (tags such as `v0.1.0-rc.1`) are for testing and are never supported.

| Version | Supported |
| --- | --- |
| Latest release | :white_check_mark: |
| Older releases | :x: |
| Pre-releases | :x: |

## Scope

The following are in scope:

- the server, the agent and the desktop companion;
- the updater sidecar and the install script;
- the web dashboard;
- the release signing and verification process.

These are especially relevant:

- authentication, session or MFA bypass;
- privilege escalation between technician scopes, or from a technician to owner;
- bypassing release signature checks;
- remote code execution on the server or on devices;
- tampering with the evidence or chain of custody;
- escaping network isolation.

Out of scope:

- findings that need an already compromised server host or a LocalSystem-level foothold on a device;
- denial of service from a trusted administrator;
- reports from automated scanners without a demonstrated impact.

## Hardening recommendations

- Keep the server updated through **Administration → Server updates**, and agents through **Agent updates**.
- Use a public domain with an automatic certificate, or distribute the LAN CA to browsers deliberately. Never bypass certificate warnings by habit.
- Give technicians only the device scope and permissions they need. MFA is mandatory for every account.
- Check that the nightly backups succeed (**Administration → Backups**) and copy them off the machine regularly with `install.sh backup`. Backups hold the server's keys; store them securely. See [RECOVERY.md](docs/RECOVERY.md).
- Review [DEPENDENCIES.md](docs/DEPENDENCIES.md) for the dependency policy and how upstream advisories are tracked.
