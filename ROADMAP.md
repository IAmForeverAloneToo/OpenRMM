# Roadmap

OpenRMM aims to be a complete, self-hosted RMM that also gives incident responders EDR-style live response, all without detection or prevention engines. This page summarises what is available and what comes next. Plans can change; open an issue to discuss priorities.

## Available today

| Area | Highlights |
| --- | --- |
| Platform | Go server in Docker with a one-command install, automatic HTTPS (Let's Encrypt or the server's own CA), and server updates from the dashboard with a verified backup and rollback |
| Windows agent | A single LocalSystem service, installed from a pre-configured MSI, that updates itself through signed releases and pilot rings |
| Monitoring | Inventory, hardware and OS details, CPU, memory, disk, uptime, metrics history, sessions, logon history, local accounts, BitLocker and Defender status, alerts and health checks |
| Management | Scripts, schedules and fleet batches, Windows Update and patch policies, MSI deployment, services, processes, software inventory, terminal, remote desktop, file transfer |
| Incident response | Cases with a hash-chained chain of custody, evidence collection, a live response console, triage packages, persistence report, event log search across the fleet, indicator hunts |
| Access control | An owner account plus technicians, with mandatory MFA, device and group scope, and per-feature permissions |

## Next

- **Release pipeline.** Tagged releases are built, tested and signed in CI, and publish a server image together with the matching signed agent package.
- **Network isolation enforcement.** Isolation is built and runs as a dry run that reports the rules it would apply. Enforcement will be switched on once it is verified on dedicated test machines.
- **Custom release keys.** Operators who build their own releases will be able to trust their own signing key next to the project key, with no change to the update process.
- **Release documentation.** A short install guide, upgrade notes, a documented process for withdrawing a bad release, and a review of the network, certificate and secret settings recommended for internet-facing servers.

## Later

- Agents for Linux, and later macOS.
- Memory acquisition.
- YARA scanning.
- Raw NTFS artefact parsing, and artefact parsing on the server.
- Further hardening of the server and the agent.

## Not planned

- A hosted (SaaS) service.
- Multi-tenancy for managed service providers.
- Built-in malware detection or prevention. OpenRMM is a response and management tool and is meant to work alongside your security products.
