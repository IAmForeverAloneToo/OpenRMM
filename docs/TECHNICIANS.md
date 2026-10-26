# Technician Accounts

Technician accounts let the primary administrator give other people access to OpenRMM with their own password, mandatory MFA, a device scope and individually granted operations. The primary administrator manages them under **Administration → Technicians** (`/technicians`).

## Contents

- [Overview](#overview)
- [Create and activate an account](#create-and-activate-an-account)
- [Device scope](#device-scope)
- [What every technician can see](#what-every-technician-can-see)
- [Permissions](#permissions)
- [Administrator-only functions](#administrator-only-functions)
- [Editing, disabling and audit](#editing-disabling-and-audit)
- [Security](#security)
- [Backup, restore and local reset](#backup-restore-and-local-reset)
- [Related](#related)

## Overview

- There is one primary administrator ([ADMINISTRATOR.md](ADMINISTRATOR.md)) and up to 100 technicians.
- Each technician has a device scope and a set of permissions. Every technician can read monitoring data for devices in scope; operations that change something on a device need an explicit permission.
- The agent runs as SYSTEM, so these server permissions are the main control over what a technician can do on a device. Agent features switched off by policy or locked off on the device, Windows permissions and process protections still apply.
- This is device authorization within one server, not multi-tenancy. Technicians who can read the same device share its permitted history, including colleagues' service actions and cached event log results.

## Create and activate an account

1. In **Technicians**, create an account with a unique lowercase username. Pick a role preset and adjust the permissions if needed (see [Permissions](#permissions)), then choose **All devices** or **Selected groups and devices**.
2. Review and apply. The server shows one invitation, valid for 30 minutes, as a link (`/activate#...`) and as a code. Give it privately to the technician; OpenRMM does not send email invitations. In the link the invitation is in the URL fragment, which browsers never send to the server, and the page removes it from the address bar once read. The server stores only its hash.
3. The technician opens the link (or opens `/activate` and pastes the code) and chooses a password of at least 15 characters and at most 256 UTF-8 bytes.
4. They add the displayed secret to an authenticator app, save the single-use recovery codes and confirm with a fresh six-digit code. The setup material is shown only during activation, and an invitation works only once.
5. They sign in with username, password and a fresh authenticator code or a recovery code. The code used for activation cannot be reused for sign-in.

An account that has not completed activation cannot sign in. If the invitation expires or the setup material is lost, the administrator resets the account, which issues a new invitation. A reset creates new password and MFA setup, invalidates sessions and invitations, and deletes the old recovery codes. The administrator never chooses or sees a technician's password or MFA secret.

The account list shows the state of each account: **Active**, **Invited**, **Invitation expired** or **Disabled**.

## Device scope

- Scope is the union of individual device IDs and group IDs, or **All devices** (all current and future active devices).
- Group access follows current membership, including devices added to the group later. An individual device grant survives a move to another group.
- Up to 100 device IDs and 100 group IDs can be stored per technician.
- Revoked devices are never accessible, even if their IDs remain in a technician's scope.
- Fleet lists, group selectors and aggregate alerts show only devices in scope; direct device routes enforce scope too. The fleet and monitoring lists show at most the newest 1,000 active devices.

## What every technician can see

For devices in scope, every technician can read:

- inventory, connection state, CPU, memory, disk space and uptime;
- installed software;
- signed-in users and session history ([SESSIONS.md](SESSIONS.md));
- local accounts and privileged group members ([LOCAL-ACCOUNTS.md](LOCAL-ACCOUNTS.md));
- device information: hardware and serial number, operating system, domain or Entra ID join, network adapters ([DEVICE-INFO.md](DEVICE-INFO.md));
- process snapshots, services and service action history, cached event log results and alerts.

Every technician can download the device list as CSV (**Devices → Export CSV**); it contains only devices in scope. Scoped alert API responses report `pending_samples` as `-1`, because the global queue count is not shown to technicians.

## Permissions

Each permission is granted independently.

| Permission | Allows |
| --- | --- |
| Event logs | Submitting bounded System and Application log queries. |
| Services | Starting, stopping or restarting any service except OpenRMM's own. |
| Processes | Ending an exact process instance, except OpenRMM's own, critical and fixed system processes. |
| Remote desktop | Viewing or requesting control through the visible desktop companion. There is no consent prompt on the device; the companion shows a sharing banner with **Stop sharing**, and the local user can end the session at any time. See [DESKTOP.md](DESKTOP.md). |
| Files | Browsing, downloading and uploading on the device's local fixed drives, except OpenRMM's own folders. See [FILES.md](FILES.md). |
| Incident response | Working on cases and responding on devices. See below. |

| Preset | Permissions |
| --- | --- |
| Read-only | None |
| Helpdesk | Event logs, Services, Processes, Remote desktop |
| Full technician | Event logs, Services, Processes, Remote desktop, Files |

Incident response is not part of any preset; tick it explicitly. Accounts default to no Files permission, and device read, service, process or desktop grants never include file access. Review the scope before granting Files, because the agent offers every local fixed drive.

**Incident response permission:**

- **Cases**: see and work on **all** cases (open, add notes, close, reopen, export the custody log), regardless of device scope.
- **Actions on a device** need the permission and the device in scope: collecting evidence and response actions, the recorded live response terminal, network isolation and fleet hunting (hunting silently leaves out devices outside the scope). For evidence collection, both are checked when the collection is requested and again when the device picks it up; a request whose technician lost either in between fails as `not_permitted`.
- **Reading evidence** (listing a case's collections, cancelling one and downloading collected files) needs only the permission, so a technician can download evidence collected from devices outside their scope. Every download is a custody entry.

Case entries name the technician by a stable ID; the case page shows the current username. See [RESPONSE.md](RESPONSE.md), [TERMINAL.md](TERMINAL.md), [HUNTING.md](HUNTING.md) and [ISOLATION.md](ISOLATION.md).

## Administrator-only functions

These remain with the primary administrator:

- account management and installer downloads, enrollment and deployment tokens;
- device revocation;
- groups, policies and global alert settings, including alert acknowledgement;
- scripts, script output and schedules;
- patching;
- uploading, withdrawing and rolling out agent releases, and server updates.

New feature routes are administrator-only until their authorization is explicitly reviewed.

## Editing, disabling and audit

- Every account edit requires review and confirmation, uses revision checks and is audited in the same transaction. A stale or concurrent edit fails instead of overwriting newer settings.
- Applying an edit invalidates all of that technician's sessions and cancels their work that has not been dispatched yet.
- Disabling an account also invalidates pending invitations. Re-enabling keeps confirmed credentials unless you select **New invitation** (confirmed with **Reset and invite**), which requires the account to be enabled.
- Group membership changes take effect on the next authorization check and immediately cancel the technician's queued work for devices that left their scope. Restoring the grant does not bring cancelled requests back.
- Delegated event log queries, service actions and process terminations check the technician's permission when they are queued and again just before dispatch. Lost permissions, a disabled account or removed scope cancel undispatched work, with an audit record. Work already dispatched may finish; an authorization change cannot undo an action Windows has already received.
- Remote desktop authorization is checked again during the session. Disabling or editing the account, signing out, losing scope or losing the permission ends the technician's desktop sessions. An ended session cannot be resumed.
- Usernames and IDs cannot be renamed or reused; disable accounts instead of deleting them. The audit log names technicians as `technician:<id>`, so old work never attaches to a new person. The account list shows these IDs.
- Remove a group's technician grants before deleting the group, so that a reused group ID cannot silently reactivate an old grant.

## Security

- Passwords are hashed with Argon2id. The MFA secret is encrypted with AES-GCM under the server's protected encryption key, bound to the account's ID.
- Sessions use secure cookies and CSRF protection, with an 8-hour absolute lifetime and a 30-minute idle timeout, and at most 16 sessions per account.
- Sign-in and activation attempts are rate limited.
- No invitation, password, MFA secret, recovery code or session token is ever logged.

## Backup, restore and local reset

- Server backups include technician accounts, their configuration and encrypted credentials.
- Any server restore (`install.sh restore` or the development recovery tool) disables all technicians, clears their invitations and recovery codes and advances the authenticator replay floor ([RECOVERY.md](RECOVERY.md)).
- A local reset of the primary administrator disables all technicians and invalidates their sessions and invitations ([ADMINISTRATOR.md](ADMINISTRATOR.md#recover-the-account)).

After either, review accounts, scope and group membership before re-enabling accounts or issuing new credentials. This prevents an old backup or a local recovery from silently restoring delegated access.

## Related

- [Administrator account](ADMINISTRATOR.md)
- [Groups and policies](ORGANIZATION.md)
- [Incident response](RESPONSE.md)
- [File transfer](FILES.md)
- [Backup and recovery](RECOVERY.md)
