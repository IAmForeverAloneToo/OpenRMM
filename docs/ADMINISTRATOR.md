# Administrator Account

OpenRMM has one primary administrator, the owner of the installation. This account is created and recovered locally on the server, never through a public registration or password-reset page. Other people sign in with invited [technician accounts](TECHNICIANS.md) that have their own password, mandatory MFA and scoped permissions.

## Contents

- [Create the first administrator](#create-the-first-administrator)
- [Recover the account](#recover-the-account)
- [Browser trust for the local development server](#browser-trust-for-the-local-development-server)
- [Sessions and sign-in](#sessions-and-sign-in)
- [How credentials are stored](#how-credentials-are-stored)
- [Backup](#backup)
- [Command-line reference](#command-line-reference)
- [Related](#related)

## Create the first administrator

There is no default account, default password or public registration endpoint. An account that has not confirmed its authenticator cannot sign in.

### Production install

`deploy/install.sh` prints a one-time setup link (`https://<server>/setup#...`). Open it within one hour, choose a username and a password, add the shown key to an authenticator app, store the recovery codes and confirm with a code. See [INSTALL.md](INSTALL.md#create-the-first-administrator).

### Local development deployment

Start the local server with `.\scripts\local.ps1 -Action up`, then run from the repository root in PowerShell 7:

```powershell
.\scripts\admin.ps1 -Action setup
```

1. Choose a username (default `admin`) and a password. Prompts are hidden and the password must be entered twice.
2. Add the displayed secret to your authenticator app as a time-based account (SHA1, six digits, 30 seconds).
3. Save the ten recovery codes in a password manager. Each code works once, together with the password.
4. Enter the current authenticator code to activate the account.

The wrapper sends credentials to the server process through a private pipe, never in command arguments, environment variables or files. Provisioning material is shown only by this local operation; avoid terminal recording and treat scrollback as sensitive.

The confirmation code is consumed, so wait for the next code before signing in at `https://127.0.0.1:8443/`. If confirmation fails, run `.\scripts\admin.ps1 -Action confirm` with a fresh code. If the secret was lost before confirmation, use the reset below to replace the pending setup.

| Password rule | Value |
| --- | --- |
| Minimum length | 15 characters |
| Maximum length | 256 UTF-8 bytes |

## Recover the account

A local reset replaces the username and password, the authenticator secret and the recovery codes. It immediately revokes every session, and the new authenticator must be confirmed before anyone can sign in. Old passwords and codes stop working. A reset also disables all technician accounts and invalidates their sessions and invitations; review and re-enable them afterwards ([TECHNICIANS.md](TECHNICIANS.md)).

Anyone with administrative access to the server host or its Docker installation can do this; they are trusted operators.

**Local development deployment:**

```powershell
.\scripts\admin.ps1 -Action reset
```

**Production install:** run the server's command-line mode inside the container and feed one JSON object on standard input (finish the input with Ctrl+D):

```bash
cd /opt/openrmm
sudo docker compose exec -T server /openrmm-server -admin-reset
{"username":"admin","password":"<new password of at least 15 characters>"}
```

The command prints one JSON object with the `username`, the new authenticator `secret`, its `otpauth://` link (`uri`) and the `recovery_codes`. Add the secret to your authenticator, store the codes, then confirm:

```bash
sudo docker compose exec -T server /openrmm-server -admin-confirm
{"code":"123456"}
```

> [!WARNING]
> Typed input and the provisioning output appear on the terminal. Do not run these commands in a recorded session, never put the password in a shell command line or script, and clear the terminal's scrollback afterwards.

## Browser trust for the local development server

The local development server uses its own development CA, which is not installed anywhere automatically. Export it first:

```powershell
.\scripts\local.ps1 -Action ca
```

For Edge or Chrome on Windows, you can trust this CA for the current Windows account. This is a trust-store change you make yourself; run it only for your own exported OpenRMM CA:

```powershell
$openrmmCA = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path .local/container-ca.pem).Path)
$openrmmCA.Thumbprint
Import-Certificate -FilePath .local/container-ca.pem -CertStoreLocation Cert:\CurrentUser\Root
```

To remove that trust again, while the same CA file is still available:

```powershell
$openrmmCA = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path .local/container-ca.pem).Path)
Remove-Item -LiteralPath ("Cert:\CurrentUser\Root\" + $openrmmCA.Thumbprint)
```

- Other browsers may keep their own trust store.
- The development certificates cover `localhost` and loopback addresses only; the development server certificate expires after seven days.
- When you rotate the development certificates, keep the old CA file if you trusted it, so you can remove that exact trust entry.

For production installs, see [INSTALL.md](INSTALL.md) for certificates.

## Sessions and sign-in

| Item | Value |
| --- | --- |
| Absolute session lifetime | 8 hours |
| Idle timeout | 30 minutes |
| Active sessions per account | 16 (the oldest is removed) |
| Cookies | Host-only, `Secure`, `HttpOnly`, `SameSite=Strict` |

- Sign-in (`POST /api/v1/session`) and sign-out (`DELETE /api/v1/session`) require same-origin requests. Sign-out and every other authenticated change also require the session's `X-CSRF-Token` header.
- Sign-in uses generic credential errors (a failure never says whether the password or the code was wrong) and one password check at a time. Attempts are limited to 10 a minute per network address (an IPv6 /64 counts as one address) and 5 a minute per account from one address. There is deliberately no limit across all addresses, so nobody can lock the administrator out by sending failed attempts from elsewhere. Throttle counters are kept in memory and reset when the server restarts; replay protection for authenticator codes and session state are stored in the database.
- Signing out revokes the session on the server.

## How credentials are stored

- Passwords are hashed with salted Argon2id. Recovery codes and session tokens are stored only as hashes.
- The authenticator secret is encrypted with AES-256-GCM. The 32-byte key is `/secrets/admin-key.bin`, in the `secrets` volume, separate from the database. A server started directly defaults to `.local/secrets/admin-key.bin`.
- If an administrator exists and the key is missing or wrong, the server does not start; it never creates a replacement key silently. A local reset also needs the key.
- The audit log keeps actions by people (sign-ins, failed sign-ins, administrator and technician actions) for a year and automatic events (agent dispatches and results, schedulers, server tasks) for 30 days; live-response entries are kept for a year. At most 500,000 events are kept, removing the oldest automatic events first. It never contains submitted passwords, authentication codes or session tokens, and it is not tamper-proof against the server operator.

## Backup

Back up the complete database directory together with the matching administrator encryption key, the device CA signing material, the server certificates and the evidence volume, all taken at the same time while the server is stopped. Keep key backups separate from database backups. A database backup alone cannot recover MFA secrets; restore the matching key first. Never put secrets or backups in the repository or a Docker build context.

See [RECOVERY.md](RECOVERY.md) for the backup and restore procedure.

## Command-line reference

`openrmm-server` accepts these modes instead of starting its listeners. They use the same database and encryption key settings as the running server; inside the container the program is `/openrmm-server`.

| Mode | Standard input | Output |
| --- | --- | --- |
| `-admin-setup` | `{"username":"...","password":"..."}` | JSON with `username`, `secret`, `uri` (`otpauth://` link) and `recovery_codes` |
| `-admin-reset` | `{"username":"...","password":"..."}` | Same as setup; replaces the existing administrator |
| `-admin-confirm` | `{"code":"123456"}` | `{"status":"confirmed"}` |
| `-admin-link` | none | A one-time setup token valid for one hour (used by `install.sh` to build the setup link) |

Do not save the output as an ordinary log or put a password in a shell command. On Windows, `scripts/admin.ps1` is the supported wrapper for the local development deployment.

## Related

- [Technician accounts](TECHNICIANS.md)
- [Installing the server](INSTALL.md)
- [Backup and recovery](RECOVERY.md)
- [Device enrollment](ENROLLMENT.md)
