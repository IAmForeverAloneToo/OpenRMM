# Licensing

OpenRMM is free software licensed under the GNU Affero General Public License, version 3 only (**AGPL-3.0-only**). This page explains what that covers and what operators and redistributors should keep in mind.

## Project license

- **Identifier:** `AGPL-3.0-only`: version 3 specifically, with no automatic grant under later versions. The identifier follows [SPDX's version distinction](https://spdx.org/licenses/AGPL-3.0-only.html).
- **Grant:** [NOTICE](../NOTICE) states the grant for original OpenRMM source code and project documentation.
- **License text:** [LICENSE](../LICENSE) is the full, unmodified [FSF license text](https://www.gnu.org/licenses/agpl-3.0.txt) (SHA-256 `0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0`).

The license text governs. This page is a summary and adds no conditions or exceptions.

## What the AGPL means for operators

The AGPL suits an open-source, self-hosted project whose main use is as a network service:

- **Running a modified version** that users interact with over a network: section 13 requires you to prominently offer those users free access to the Corresponding Source of the version you run.
- **Distributing** OpenRMM, modified or not (for example binaries, container images or agent installers), carries the source and license obligations of the license.

> [!IMPORTANT]
> If you publish binaries, images or a hosted service based on a modified OpenRMM, make sure the complete Corresponding Source, including the required third-party source versions, is actually available through your chosen distribution or source-offer mechanism. A module checksum list alone is not a complete source delivery.

## Where the legal files ship

| Artifact | Included files |
| --- | --- |
| Server container image | `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` |
| Agent MSI | `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, installed beside the agent executable |
| Source repository | Application source, build and install scripts, pinned dependency metadata (`go.mod`, `go.sum`, `dependencies.lock`, `web/package-lock.json`) and the legal files |

## Third-party code

Third-party components keep their original licenses. [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) collects their notices.

- The Go runtime modules carry BSD-3-Clause and MIT licenses; the SQLite library bundled by the driver is public domain.
- The browser application bundles packages under MIT, ISC and 0BSD licenses.
- The wider module graph and aggregate upstream notices also describe optional development material that is not linked into OpenRMM.

The root AGPL license does not relicense any upstream component. Copied upstream legal texts and existing database migration files are not rewritten to add project license headers, so migration checksums and upstream attributions stay intact.

See [DEPENDENCIES.md](DEPENDENCIES.md) for the full dependency inventory.

## Related

- [DEPENDENCIES.md](DEPENDENCIES.md): dependency policy and inventory
- [RELEASE.md](RELEASE.md): building and signing releases
