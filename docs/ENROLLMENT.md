# Device Enrollment

Enrollment adds a Windows x64 machine to OpenRMM and gives it its own device certificate. The primary administrator downloads a pre-configured installer from **Devices → Add device**; the installer sets up the agent service, which enrolls the machine on its first start.

## Contents

- [How it works](#how-it-works)
- [Add a device with an installer](#add-a-device-with-an-installer)
- [Server trust](#server-trust)
- [Install on the device](#install-on-the-device)
- [Enrollment by the service](#enrollment-by-the-service)
- [Tokens, deployments and revocation](#tokens-deployments-and-revocation)
- [Device credentials](#device-credentials)
- [Certificate renewal](#certificate-renewal)
- [Revoking a device](#revoking-a-device)
- [Recovery and re-enrollment](#recovery-and-re-enrollment)
- [Console enrollment for developers](#console-enrollment-for-developers)
- [Related](#related)

## How it works

1. The administrator downloads an installer ZIP. It contains the signed agent MSI and an `enrollment.json` with the server addresses, the server trust and an enrollment token.
2. On the device, `install.cmd` installs the MSI and hands `enrollment.json` to the agent service.
3. The service creates its own key, enrolls with the token and receives a device certificate. It then deletes `enrollment.json`.
4. The device appears in **Devices**. It shows **Awaiting contact** until its first [heartbeat](HEARTBEATS.md), then **Online**.

## Add a device with an installer

Only the primary administrator sees **Add device**.

1. Open **Devices** and select **Add device**.
2. Check the two addresses agents use:
   - **Server address**: the HTTPS origin agents enroll with, the dashboard address as devices reach it.
   - **Device address**: the agent listener.

   Both must be different HTTPS origins without a path, for example `https://rmm.example.com` and `https://rmm.example.com:8444`. A server installed with `deploy/install.sh` presets them from the install options. Otherwise, until they are saved, the dialog fills them from the browser's address and the server's device port (`https://<browser host>:<device port>`).
3. Choose the **Installer type**:
   - **One device**: a single-use token, valid for 24 hours.
   - **Deployment (many devices)**: a name, a **Device limit** from 1 to 10,000 and a validity (**Valid for**) of 1, 7, 30, 90 or 365 days. The token can be used until its limit or expiry and can be revoked.
4. Select **Download installer**. Changed addresses are saved first as the installer settings (audited as `installer_settings_changed`) and are used for later installers too. The browser saves `OpenRMM-Agent-Setup.zip` (one device) or `OpenRMM-Agent-Deployment.zip` (deployment).

The dialog shows the agent version and release sequence the installer will carry. Without a usable signed MSI release, **Download installer** is disabled; publish an agent release first ([RELEASE.md](RELEASE.md)).

The ZIP contains:

| File | Purpose |
| --- | --- |
| `openrmm-agent.msi` | The unchanged signed MSI of the newest usable (not withdrawn, unexpired) agent release. |
| `release.json` | Its signed release. |
| `enrollment.json` | `version` (1), `server_url`, `device_url`, `server_ca` and the enrollment `token`. |
| `install.cmd` | Starts the setup: double-click it, or run `install.cmd /quiet`. |
| `install.ps1` | The setup itself (Windows PowerShell 5.1 or later). |
| `README.txt` | Short instructions for the person installing it. |

> [!WARNING]
> Keep the ZIP private. Anyone holding it can add machines to your server until its token is used up, expires or is revoked.

The token never appears in a URL: the download is a POST request whose body carries only the installer choices. The server stores only the token's hash.

## Server trust

Installers carry the CA that agents trust for both addresses, or none when the server certificate is publicly trusted:

| Server setup | CA in installers |
| --- | --- |
| `install.sh --domain` (Let's Encrypt) | None. Agents use the Windows trusted roots. |
| `install.sh --address` (LAN) | The server's own CA (`server-ca/ca.pem` in the `secrets` volume), set automatically. |
| Local development deployment (`compose.yaml`) | The development CA (`/tls/local/ca.pem`). |
| Server started directly | The PEM file named by `-tls-ca` / `OPENRMM_SERVER_TLS_CA`. Empty (the default) means none. |

The dialog shows whether installers carry a CA or rely on system trust. The server reads the CA file when an installer is downloaded, not at startup. An unreadable file, or one that is not a PEM list of CA certificates, makes the download fail with a message naming `OPENRMM_SERVER_TLS_CA`.

The server certificate must be valid for the host names in both addresses.

> [!NOTE]
> The local development deployment publishes both ports on `127.0.0.1` only, and its certificates cover only `localhost`, `127.0.0.1` and `::1`. It can therefore enroll only the computer it runs on. For a native development server with `openrmm-devcert` certificates, pass `-tls-ca .local/tls/ca.pem`; otherwise installers rely on system trust and cannot connect.

## Install on the device

Extract the whole ZIP, then either:

- double-click `install.cmd`; it asks for administrator approval (UAC) and runs the setup in a new window; or
- run `install.cmd /quiet` from the extracted folder as administrator or SYSTEM, for example from Intune, Group Policy or a remote shell. Without administrator rights it exits with code 5 instead of prompting.

Add `/proxy http://host:port` when the device reaches the server only through a proxy (see [proxy](WINDOWS-SERVICE.md#proxy)); running `install.cmd /proxy VALUE` again on an installed agent changes the setting.

`install.ps1`:

1. requires administrator rights and 64-bit Windows;
2. checks that the MSI's SHA-256 matches its MSI release in `release.json` (it does not verify the release signature itself; the agent does that for every later update);
3. exits with code 0 and changes nothing when the `OpenRMMAgent` service is installed and `C:\ProgramData\OpenRMM Agent\device.json` exists, so it is safe to run again on an enrolled machine. The enrolled agent writes `device.json` (device ID and device address, no secrets) at every start;
4. if the service is not installed but a `state` folder remains from an earlier, uninstalled agent, keeps the whole data folder as `C:\ProgramData\OpenRMM Agent.previous-<timestamp>` and enrolls the machine as a new device (revoke the old entry in **Devices**);
5. restricts `C:\ProgramData\OpenRMM Agent` to SYSTEM and Administrators before copying anything, then copies `enrollment.json` there;
6. stores the MSI and release as the first rollback package for self-updates (`packages\current.msi`, `packages\current.json`);
7. installs the MSI silently (`msiexec /i ... /qn /norestart REBOOT=ReallySuppress`, with a verbose log in the temporary folder), or restarts the `OpenRMMAgent` service if that exact release is already installed (for example after an earlier failed attempt);
8. waits up to two minutes until the service has enrolled (`enrollment.json` removed and `device.json` written).

`install.cmd` clears an inherited `PSModulePath` before starting Windows PowerShell, so it also works when started from a PowerShell 7 session.

| Exit code | Meaning |
| --- | --- |
| 0 | Installed and enrolled, or already enrolled. |
| 1 | Error. |
| 2 | Incomplete or changed download (a file is missing or the MSI does not match `release.json`). |
| 3 | Windows Installer failed; the message names its log. |
| 4 | Installed but not enrolled yet; the service keeps retrying (see `logs\agent.log` in the data folder). |
| 5 | Not run as administrator. |

## Enrollment by the service

When the installed service starts without an identity and finds `%ProgramData%\OpenRMM Agent\enrollment.json`, it:

1. restricts the data folder to SYSTEM and Administrators again;
2. checks the file (version 1, a 43-character token, two HTTPS origins, a valid CA or none);
3. enrolls into its state folder, discarding a `pending-key.pem` left by an interrupted attempt, and saves its credentials with the addresses and CA from the file;
4. deletes the file and starts normally.

Failures are retried every minute, or every 15 minutes when the server rejects the token (for example used up, expired or revoked). The file is read again on every attempt, so replacing it takes effect at the next retry. A service that already has an identity never enrolls again; it only removes a leftover file. Without an identity and without the file, the service has no credentials and stops with an error.

All agent features are on after enrollment; turn them off per monitoring policy ([feature switches](WINDOWS-SERVICE.md#feature-switches)).

## Tokens, deployments and revocation

- A single-device token is deleted when it is used. Unused ones expire after 24 hours; they are not listed and cannot be revoked.
- A deployment token counts the devices it enrolled. **Add device** lists deployments under **Deployments** with name, devices used of the limit, expiry (or revocation time), creator and state: **Active**, **Expired**, **Limit reached** or **Revoked**.
- **Revoke**, then **Confirm revoke**, on an Active or Limit reached deployment stops new enrollments with that installer. Devices it already enrolled stay; revoke them individually if needed.
- Revoked and expired deployments stay in the list for 30 days. Older entries are removed when the next installer is created.
- Each device records the token it enrolled with; the dashboard does not show it yet.

| Limit | Value |
| --- | --- |
| Unused single-device tokens | 100 at a time |
| Active deployments | 50 at a time |
| Devices per deployment | 1–10,000 |
| Enrollment requests | 20 per minute per network address (an IPv6 /64 counts as one address); no overall limit, so nobody can block enrollment for everyone |

Beyond the token limits, downloads are refused until a deployment is revoked or unused installers expire. A rate-limited agent retries a minute later, so a large deployment behind one network address enrolls about 20 machines per minute.

**Audit events:** `enrollment_token_created`, `deployment_token_created`, `deployment_token_revoked`, `installer_settings_changed` and `device_enrolled`.

**API routes** (primary administrator only):

| Route | Purpose |
| --- | --- |
| `GET /api/v1/installer` | Installer settings, device port, trust, release and deployments. |
| `PUT /api/v1/installer/settings` | Save the server and device addresses. |
| `POST /api/v1/installer/download` | Create a token and download the ZIP. |
| `POST /api/v1/installer/tokens/{id}/revoke` | Revoke a deployment. |
| `POST /api/v1/enrollment-tokens` | Create a single-device token without an installer (valid 24 hours). The dashboard does not use it. |

## Device credentials

- The agent creates an ECDSA P-256 key locally and sends a signed certificate request. The server checks the signature and uses only the public key; requested subjects, names and privileges are ignored. The server assigns a random device ID and issues a client-authentication-only certificate.
- The agent's state folder is protected before any key is written. For the installed service, the data folder is accessible only to SYSTEM and Administrators.
- `credentials.json` in the state folder holds the private key, the issued certificate, the device CA, the server trust (empty for system trust) and the device address. The token is not kept. Copying this file clones the device identity, so protect it.
- The server stores public certificates and fingerprints in its database. Its device CA signing material is `/secrets/device-ca/authority.pem` (mode 0600, owned by the server user). The CA fingerprint is bound to the database; missing or mismatched CA material prevents startup. This CA is separate from the HTTPS certificate authority and from the administrator encryption key.

## Certificate renewal

| Item | Value |
| --- | --- |
| Device certificate lifetime | 30 days, capped by the device CA's expiry |
| Renewal window | Within 7 days of expiry, with the same key |
| Overlap after renewal | The previous certificate stays valid for 5 minutes (still subject to revocation) |
| Device CA lifetime | 5 years; CA rotation is not implemented |

The agent renews automatically as part of its heartbeat loop. It validates the new certificate's issuer, identity and key before it replaces its credentials. A retry after a lost response within the overlap window returns the already issued replacement. After expiry, the device needs re-enrollment.

Replacing the CA of the server's HTTPS certificate (for example a new development CA) invalidates the server trust that agents saved; those devices need re-enrollment. Never bypass verification or edit credentials to accept an unknown issuer.

## Revoking a device

Open the device and choose **More → Revoke device…**, type the hostname and select **Revoke device**. The device becomes **Revoked**:

- every later authenticated request is rejected, including requests on an existing connection;
- it cannot renew its certificate;
- the agent pauses and checks again hourly (see [heartbeats](HEARTBEATS.md)).

Revocation cannot be undone. Revoking a device does not revoke the deployment that enrolled it, and revoking a deployment does not revoke its devices.

## Recovery and re-enrollment

Authentication failures never erase credentials, overwrite state or enroll again automatically. To give an installed device a new identity (for example after expired, lost or revoked credentials):

1. Revoke the old record in **Devices**, if it is not already revoked.
2. Uninstall the agent (**Programs and Features** or `msiexec /x`). Uninstall keeps `%ProgramData%\OpenRMM Agent`.
3. Run a newly downloaded installer. It keeps the old data folder as `OpenRMM Agent.previous-<timestamp>` and enrolls the machine as a new device.
4. Delete the old folder once nothing in it is needed for inspection.

A lost enrollment response can leave a server record even though the device did not finish enrolling; with a deployment token it also counts towards the limit. Review **Devices** and revoke such records.

## Console enrollment for developers

A development build of the agent can enroll the current computer without installing the service. It needs an installer from a server with its own CA (the local development deployment, a LAN install, or a native server with `-tls-ca`).

1. In **Devices → Add device**, download a **One device** installer and extract it.
2. From the repository root in PowerShell 7, run:

   ```powershell
   .\scripts\enroll.ps1 -EnrollmentFile <extracted folder>\enrollment.json
   ```

   The addresses, CA and token in the file replace `-Server`, `-DeviceServer`, `-CA` and the token prompt. The CA goes to a temporary file that is removed afterwards; the token reaches the agent on standard input, never in command arguments or environment variables. The script refuses a file without `server_ca`.
3. Delete the extracted folder and the ZIP; the token is used.
4. Check the saved identity:

   ```powershell
   .\dist\windows-amd64\openrmm-agent.exe -connect -state .local/agent
   .\dist\windows-amd64\openrmm-agent.exe -renew -state .local/agent
   ```

`-renew` keeps the existing certificate when it is more than seven days from expiry. Without `-EnrollmentFile`, `scripts/enroll.ps1` asks for a token in a hidden prompt and defaults to `https://127.0.0.1:8443`, `https://127.0.0.1:8444` and the CA exported by `.\scripts\local.ps1 -Action ca` (`.local/container-ca.pem`). Use `-State` to enroll into a fresh folder; console enrollment refuses to overwrite existing state.

A console agent needs only standard user rights, opens no inbound port and installs no service; its state folder is accessible only to the current account and SYSTEM. The `-server`, `-device-server` and `-ca` options configure enrollment and diagnostics only; an established identity always uses the address and trust saved in its credentials. Never run a console agent and the installed service with the same identity, and keep certificate verification enabled.

## Related

- [Windows agent service](WINDOWS-SERVICE.md)
- [Heartbeats](HEARTBEATS.md)
- [Agent updates](AGENT-UPDATES.md)
- [Installing the server](INSTALL.md)
- [Backup and recovery](RECOVERY.md)
