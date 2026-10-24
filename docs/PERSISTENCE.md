# Persistence Report

The persistence report lists the common autostart locations of a Windows device, with each program file's SHA-256 and Authenticode signature. It helps responders review what starts automatically on an endpoint. It is informational: nothing is judged or flagged as malicious, and it covers the locations in the table below, not every mechanism Windows has.

## Contents

- [Running a report](#running-a-report)
- [Viewing and filtering](#viewing-and-filtering)
- [What is listed](#what-is-listed)
- [How programs are resolved](#how-programs-are-resolved)
- [Hashes and signatures](#hashes-and-signatures)
- [Limits](#limits)
- [Related](#related)

## Running a report

- **Case page:** **Evidence → Persistence report** (`POST /api/v1/cases/{case}/actions` with `{"kind": "persistence"}`).
- **Live response console:** `persistence` (or its quick button). Without a case, the report is kept for 24 hours like other case-less results.

The report is a read-only [response action](RESPONSE.md#response-actions): it needs the `response` permission, access to the device and **Incident response** switched on, and its result is uploaded and hashed as evidence with custody entries (or audit entries without a case). The device's agent must report the `persistence` ability in its heartbeat; older agents are refused with a message to update them.

## Viewing and filtering

Each entry shows its type and location, the resolved program, its SHA-256 and its signature (signed or not, signer, valid or not). There is no baseline comparison; the viewer filters instead.

By default the viewer hides plain Microsoft-signed entries. An entry is hidden only when **all** of these hold:

- the program's signature is valid and the signer is one of Microsoft's own signer names (exact match);
- the program is not a script host or system tool that runs arbitrary commands (cmd, PowerShell, mshta, wscript/cscript, rundll32, regsvr32, msiexec, certutil and similar);
- the entry is not a shortcut or WMI consumer;
- outside service-like entries (services, drivers, service DLLs, LSA, print monitors, boot execute, AppInit/AppCert), the entry passes no arguments.

Everything else stays visible.

## What is listed

| Type | Where |
| --- | --- |
| Run key | `HKLM` and every loaded user hive (`HKU\<SID>`; users who are not signed in are not covered): `…\CurrentVersion\Run`, `RunOnce`, `Policies\Explorer\Run`; machine `RunOnceEx` (every value of its subkeys); also the 32-bit (`WOW6432Node`) machine keys |
| Winlogon | `Shell`, `Userinit`, `Taskman`, `AppSetup` (machine), `Shell` (users); comma-separated programs are separate entries |
| Windows Load/Run | Users' `Windows NT\CurrentVersion\Windows` `Load` and `Run` |
| Logon script | Users' `Environment\UserInitMprLogonScript` |
| Command Processor AutoRun | `Software\Microsoft\Command Processor\AutoRun` (machine, 32-bit machine, users) |
| AppInit DLL | `AppInit_DLLs` (64- and 32-bit) |
| AppCert DLL | `Session Manager\AppCertDlls` |
| Boot execute | `Session Manager\BootExecute` |
| LSA package | `Lsa`: Authentication, Notification and Security Packages; `Lsa\OSConfig` Security Packages |
| IFEO debugger | `Image File Execution Options\*\Debugger` (64- and 32-bit) |
| Silent process exit | `SilentProcessExit\*\MonitorProcess` |
| Active Setup | `Active Setup\Installed Components\*\StubPath` (64- and 32-bit) |
| Print monitor | `Control\Print\Monitors\*\Driver` |
| Service, driver | Every service and driver that is not disabled, with start type, state and account; service DLLs (under `Parameters` or in the service key) as their own entries |
| Scheduled task | Every task action, with its triggers and account; disabled tasks are marked; COM handler actions resolve to the class's `InprocServer32` DLL or `LocalServer32` program (classes hosted through an AppID are not resolved) |
| Startup folder | The all-users and every user profile's Startup folder, plus a redirected Startup folder of signed-in users; shortcuts are read for their target and arguments |
| WMI subscription | `root\subscription` command-line and script event consumers, with the event filters bound to them |

> [!NOTE]
> A shortcut's target is read from the link's path data, not the ID list Explorer uses, so a crafted shortcut can show a different target than Explorer would run. Shortcuts are therefore never hidden by the filter.

## How programs are resolved

- Environment variables are expanded. For a user's own entries (their Run keys, shortcuts), `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, `%HOMEPATH%` and `%HOMEDRIVE%` come from that user's profile, not from the agent's (SYSTEM's) environment.
- Quoted paths, `.exe`/`.sys`/`.dll` endings, and `\SystemRoot\`, `\??\` and `system32\` prefixes are handled.
- Bare names are looked up in `System32` and the Windows folder. DLL entries (AppInit, AppCert, LSA, print monitors) without a path are taken from `System32` (with `.dll` added).
- A `rundll32` entry reports the DLL it loads. `BootExecute` `autocheck autochk *` is `System32\autochk.exe`. A driver without an image path is `System32\drivers\<name>.sys`. A relative shortcut target is taken relative to its folder.
- Anything that is still not a full path (a bare switch, a relative DLL path) has no program.
- `arguments` marks commands that pass anything to their program.

## Hashes and signatures

- **Network files are never opened.** UNC and WebDAV paths (`\\host\…`, `\\?\UNC\…`, `\??\UNC\…`, `\Device\Mup\…`) and drive letters mapped to network shares get `hash_note: network_path` and no signature check, because the agent runs as SYSTEM and opening them would make the computer account authenticate to whoever named the path. The same guard applies to every hash the agent computes (process lists, services).
- Programs are hashed with the agent's hash cache. Files over 512 MB are neither hashed nor checked (`too_large`); a missing file is `not_found`.
- **Signature:** `WinVerifyTrust` checks the embedded Authenticode signature. When there is none, the security catalogs are searched for the file's hash (SHA-256, then SHA-1) and the catalog's signature is verified. Revocation is not checked and nothing is fetched from the network.
- Signature results:

  | Result | Meaning |
  | --- | --- |
  | `valid` | Valid signature, with the signer's name and whether it came from a catalog |
  | `unsigned` | No embedded or catalog signature |
  | `invalid` | Signature does not verify, with the Windows error code (for example `0x80096010` for a changed file) |
  | `error` | The file could not be read (for example a sharing violation) |

## Limits

| Limit | Value |
| --- | --- |
| Entries per report | 20,000 |
| Programs hashed and checked | 5,000 per report (each program once) |
| Program file size for hashing and signature checks | 512 MB |
| WMI query | Noted in the report if it fails or takes over a minute |
| Run time | 20 minutes (the response action limit); a report that reaches it keeps its entries and notes that later programs were not hashed or checked |

## Related

- [RESPONSE.md](RESPONSE.md): response actions, cases and the live response console
- [TRIAGE.md](TRIAGE.md): collecting artifacts for offline analysis
- [HUNTING.md](HUNTING.md): fleet indicator hunts
- [SERVICE-MANAGEMENT.md](SERVICE-MANAGEMENT.md): Windows services in the RMM view
