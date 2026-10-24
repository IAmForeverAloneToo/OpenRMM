# PowerShell Terminal

The terminal is an interactive Windows PowerShell session on a device, running as SYSTEM, and it is also OpenRMM's live response console. It is for the owner and for technicians with the Incident response permission who need a shell on an endpoint.

## Contents

- [Overview](#overview)
- [Opening a session](#opening-a-session)
- [Typing, pasting and copying](#typing-pasting-and-copying)
- [Execution identity](#execution-identity)
- [Turning it off](#turning-it-off)
- [Session limits](#session-limits)
- [Data handling and recording](#data-handling-and-recording)
- [Permissions and audit](#permissions-and-audit)
- [API routes](#api-routes)
- [Related](#related)

## Overview

- A persistent Windows PowerShell 5.1 process with live input and output, variables, directory changes and interactive prompts. It requires Windows 10 1809 / Windows Server 2019 or newer.
- The page renders output with the bundled xterm.js emulator on a fixed screen of 100 columns by 30 rows. Complex full-screen programs, resizing and terminal extensions are not supported. PSReadLine is removed for predictable basic console editing.
- Beside the shell, a command bar runs built-in response commands (process list, kill, connections, services, tasks, registry, file and hive collection, tool drop, library scripts and more); see [live response console](RESPONSE.md#live-response-console).
- Browser and agent traffic uses the existing HTTPS and outbound agent mutual-TLS connections with bounded JSON polls. There is no extra listener or service on the device.

## Opening a session

1. Open a device and select **Live response** in the console header. The device must be online.
2. Choose whether to record the session to no case, an open case or a new case.
3. The session opens full-screen at `/devices/{id}/terminal/{session}`. The header shows the remaining session time, and **Recorded** when the session belongs to a case.

**End session** closes the process job and its ordinary descendants. Leaving or closing the page also ends the session: loss of the browser is detected within fifteen seconds and the agent stops the shell on its next exchange. A failed agent exchange ends the shell right after its three-second request deadline. Stopping or crashing the agent closes its kill-on-close job. No command effect is undone.

Reloading the page ends the session rather than resuming it; open a new session after a disconnect.

## Typing, pasting and copying

- Click the screen to type. Enter, Backspace, Tab, arrows, Home/End, Escape and Delete are sent as typed.
- **Ctrl+C** copies a selection; with no selection it sends an interrupt to the foreground console program, which may ignore it.
- **Pasting never sends text directly.** **Send pasted text?** shows the text first; review newlines (which can execute commands), then choose **Send** or **Send and press Enter**. The 4 KiB limit includes UTF-8 encoding and the optional Enter. Hidden terminal controls and bidi overrides or isolates are rejected in pasted text.
- The browser clipboard is read only from a paste you start and written only by an explicit copy. Remote OSC 52 clipboard, link and title sequences have no effect.
- The browser keeps up to 1,000 lines of scrollback plus the live screen. Scrolling back or selecting text does not pause the shell.
- At most 4 KiB may wait in the browser while one request is in flight; a queue-full message asks you to wait. Input already accepted cannot be withdrawn, and server acceptance does not prove Windows executed it. An uncertain submission ends the session without retry; an output stall of more than five seconds also ends it.

## Execution identity

> [!WARNING]
> The shell runs as **SYSTEM** in the installed agent (a LocalSystem service). It does not impersonate the signed-in user. This is trusted code execution with full control of the device, including the agent's own state. It is not a sandbox.

- The shell is placed in a Windows Job Object at creation, with at most 16 processes, 512 MiB aggregate memory, no breakaway and kill-on-close. These limits constrain ordinary commands, not trusted code that deliberately uses other OS facilities or external systems.
- A console (non-service) agent runs the shell as the account that started it.
- Windows, PowerShell or the commands you run may keep their own history or logs.

## Turning it off

The terminal is the agent feature **Terminal** (`terminal`), on by default. Switch it off in the device's monitoring policy (**Agent features → Terminal**), or lock it off on one device in an administrator PowerShell:

```powershell
.\scripts\service.ps1 -Action configure -TerminalMode false
# Remove the lock:
.\scripts\service.ps1 -Action configure -TerminalMode true
```

- A lock survives MSI installs and self-updates, and a policy cannot override it; see [feature switches](WINDOWS-SERVICE.md#feature-switches).
- Configuring the service restarts it, and a policy change restarts the agent's work; either ends an active terminal.
- A console agent uses `-terminal=false` or `OPENRMM_AGENT_TERMINAL=false`.
- The built-in response commands additionally need the **Incident response** feature; see [RESPONSE.md](RESPONSE.md#feature-switch).

## Session limits

| Limit | Value |
| --- | --- |
| Sessions | 1 per device, 4 per server |
| Hard time limit | 2 hours |
| Idle limit (no input) | 15 minutes; output polling does not count as activity, a live response command does |
| Older agents | Agents that do not report support for the long limits get 15 minutes in total and 2 minutes idle |
| Input | At most 4 KiB per submission, four pending submissions; sequence numbers reject replays |
| Output | At most 16 KiB per chunk, 128 KiB pending on each side, 16 MiB per session; overflow ends the session |

Limits are enforced by the agent as well as the server. The server consumes input before sending it; lost or ambiguous delivery never retries commands or restarts a shell.

Each session ends with a fixed reason (for example idle, time limit, agent lost or changed, normal exit, output bound). At most 64 ending records, without input or output, are kept in server memory for one minute and can be read only by the original browser session with current device access. A server restart loses them.

## Data handling and recording

- **Without a case,** input and output stay in bounded process memory. They are not stored in the database, audit events or ordinary logs. Final output can be lost when a shell exits or a connection fails; no transcript or exit code is promised.
- **With a case** (chosen at start, or later with **Attach to case**), the whole input and output from then on is recorded with timestamps and stored as case evidence; see [recorded terminal](RESPONSE.md#recorded-terminal). A recorded session needs room for 48 MiB in the evidence quota.
- Remote bytes are interpreted only by the terminal emulator, never as HTML.
- The browser display is disposed when you leave the page; leaving ends the session, so restoring a cached page cannot resume input. After the session ends for any reason, input is disabled but the display stays available for review until you leave the page.
- Process memory is not a secure secret store. Avoid typing secrets, especially in a recorded session.
- Each session has a private workspace folder under the agent's state directory. Empty workspaces are removed; files created by commands are left for deliberate inspection rather than deleting command-controlled paths recursively.
- Server backup and restore never keep or resume live sessions.

## Permissions and audit

- The owner and technicians with the **Incident response** permission and access to the device can open and use the terminal. Read, desktop, files or services permissions do not grant it.
- Each session is bound to the device, the authenticated browser session, the agent connection, the account, the execution identity and an absolute expiry. Authorization is checked on every exchange, view and input and by a one-second sweeper. Sign-out, password or MFA reset, session expiry or inactivity, device revocation, an agent identity change and a server restart end the session. A different browser sign-in cannot read or control the session.
- State changes require same-origin requests and the session's `X-CSRF-Token` header.
- Start and end of every session are recorded in the audit log (metadata only).

## API routes

| Route | Purpose |
| --- | --- |
| `POST /api/v1/devices/{id}/terminal` | Start a session. Body `{}`, `{"case_id": …}` or `{"case_title": …}`. |
| `GET /api/v1/terminal/{session}/output` | Poll output. |
| `POST /api/v1/terminal/{session}/input` | Send input. |
| `POST /api/v1/terminal/{session}/stop` | End the session. |
| `POST /api/v1/terminal/{session}/case` | Attach a case. |
| `POST /api/v1/terminal/{session}/command` | Run a built-in response command. |
| `GET /api/v1/terminal/{session}/jobs`, `/jobs/{job}/file`, `POST /jobs/{job}/cancel` | List, read and cancel the session's response results. |
| `POST /api/v1/agent/terminal` | Agent-only exchange (device certificate). |

For contributors: `internal/terminal` separates authorization and protocol from the operating-system `Shell` adapter.

## Related

- [RESPONSE.md](RESPONSE.md): cases, evidence and the live response console
- [DESKTOP.md](DESKTOP.md): attended remote desktop
- [FILES.md](FILES.md): file browsing and transfer
- [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md): the agent service and feature switches
