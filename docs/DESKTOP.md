# Remote Desktop

Remote desktop lets the owner or a technician view, and optionally control, the screen of the user signed in at a Windows device from the OpenRMM dashboard. It is meant for support sessions on enrolled devices and uses the agent's existing connection; it does not configure RDP or open a firewall port.

## Contents

- [How it works](#how-it-works)
- [Requirements and setup](#requirements-and-setup)
- [Starting a session](#starting-a-session)
- [Controlling the device](#controlling-the-device)
- [Coverage and limits](#coverage-and-limits)
- [Turning it off](#turning-it-off)
- [Permissions and audit](#permissions-and-audit)
- [Security notes](#security-notes)
- [For contributors](#for-contributors)
- [Related](#related)

## How it works

- A small companion program, `openrmm-desktop.exe`, runs without elevation in the signed-in user's physical console session. It captures the screen and injects input on behalf of the agent.
- The companion talks to the agent service (LocalSystem) over a local named pipe. It has no device keys and no network listener. While idle it shares nothing.
- The agent relays frames and input to the server over its outbound mutual-TLS connection; the browser talks to the server over HTTPS.

> [!IMPORTANT]
> The local user is **not asked** for consent, and **nothing is shown on the device** during a session: the companion has no window, taskbar or tray icon, and there is no local Stop button. Make sure your use complies with your organisation's policies and any notice obligations towards the people using the devices.

## Requirements and setup

- A Windows x64 device with the installed agent service. Console (non-service) agents never offer remote desktop.
- The agent MSI installs the companion and registers it to start at every user sign-in (**OpenRMM Desktop** under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, which runs `openrmm-desktop.exe --background`). Install the agent from **Devices → Add device** or with its MSI; see [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md). Re-enrolling is not needed to enable the feature.
- The companion stays silent where remote desktop is unavailable, such as RDP sessions or elevated accounts. It connects to the agent service and retries every 10 seconds, because the service has a delayed start and restarts during updates. It reports the display layout (primary display first) with every exchange.
- The installed agent also starts the companion in any active signed-in session that has none, within about a minute (for example after an agent install or update stopped it), at most once every five minutes per session.
- Someone must be signed in at the console. Viewing the sign-in screen when nobody is signed in is not supported.

## Starting a session

1. Open a device and select **Remote desktop** in the console header.
2. Choose the **Display** and the **Quality**:

   | Quality | Resolution (up to) | JPEG quality |
   | --- | --- | --- |
   | Low bandwidth | 960×540 | 40 |
   | Balanced | 1280×720 | 65 |
   | Detail | 1280×720 | 85 |

3. Choose **View only** or **View and control**.

The full-screen session page opens at `/devices/{id}/desktop/{session}` and shows **Starting on the device** until the companion starts sharing.

- The header's **Display** and **Quality** selectors switch while the session runs. A display that disappears from the layout ends sharing.
- Display labels show size and primary status, not Windows Settings display numbers. Agents that report no displays offer only their primary display.
- **End session** ends it. A stopped session cannot be resumed or replayed; every session needs a new request.
- Zoom supports Fit, 100% and 150% of the received image, with scrolling. Enlarging cannot restore detail the image does not contain.
- The image does not include the Windows pointer; the browser's pointer shows where you are.

## Controlling the device

- Control starts **paused**. Choose **Enable input**, then focus the image to type. **Pause input** stops sending input without ending the view; leaving the browser window also pauses it. A stale image pauses input and requires re-enabling when fresh frames return.
- Supported: mouse movement, left/middle/right clicks, wheel, Unicode characters (including non-BMP characters), AltGr text, and complete navigation/function-key taps or Ctrl/Alt/Shift chords. Fast double-clicks within the browser's 250 ms grouping window become one double-click; slower gestures remain separate taps.
- **Not supported:** dragging, held keys or buttons, Windows-key chords. Browser-reserved shortcuts may stay in the browser.
- For IME, dead-key or composed text, type in the text box below the image, review it and choose **Send text** (up to 512 UTF-8 bytes). Nothing is sent while composing. Pasting into that box is disabled; the browser clipboard is never read or transmitted. Remote keyboard shortcuts can still use Windows' own clipboard on the device.
- Keyboard input follows the current Windows focus, which can be on another display; selecting a display limits capture, not where keys go.
- Input is skipped while the local user holds a modifier key or mouse button, to avoid interfering with them.
- Input already accepted cannot be withdrawn. An uncertain click or key may be lost; delivery is not exactly-once.

## Coverage and limits

- One unlocked console monitor at a time, about two frames per second. No audio, clipboard sharing, file transfer, multi-monitor view or remote sign-in.
- Locking the device, switching console sessions or a secure desktop (UAC prompt, sign-in screen) ends capture and control. Elevated applications are outside coverage: the companion has no UIAccess, debug privilege, desktop switching, impersonation or secure-attention-sequence mechanism.
- Oversized frames are retried once at JPEG quality 40, then the session fails closed.

| Limit | Value |
| --- | --- |
| Sessions | 1 per device, 4 per server |
| Session length | 15 minutes (hard limit) |
| Start timeout | 1 minute for the companion to start sharing, otherwise the session ends with `consent_timeout` (for example nobody is signed in) |
| Leases | Browser 30 seconds, agent 10 seconds |
| Stale frames | Frames older than 3 seconds are hidden |
| Frame size | 1 MiB, JPEG only, within the resolution limit; requests at most 1.5 MB |
| Input queue | 64 events, at most 16 per request; events expire after 1 second |

Hiding or closing the browser clears the image and sends a best-effort disconnect; the leases cover lost requests. A failed helper, pipe or network exchange ends the session; the companion reconnects but cannot resume it.

## Turning it off

Remote desktop is the agent feature **Remote desktop** (`desktop`), on by default in the installed service. Switch it off in the device's monitoring policy (**Agent features → Remote desktop**), or lock it off on the device in an administrator PowerShell:

```powershell
.\scripts\service.ps1 -Action configure -DesktopMode false
# Remove the lock:
.\scripts\service.ps1 -Action configure -DesktopMode true
```

A lock survives MSI installs and self-updates, and a policy cannot override it; see [feature switches](WINDOWS-SERVICE.md#feature-switches).

## Permissions and audit

- The owner and technicians with the **Remote desktop** permission and access to the device can start sessions. Other permissions do not grant it.
- Each session belongs to the exact authenticated browser session, not just an account name or URL. MFA/session checks and the session's `X-CSRF-Token` header precede every request and input. Sign-out, credential reset, session expiry and device revocation are rechecked on requests and by a one-second server sweep.
- Audit events `desktop_requested`, `desktop_consented` (the companion started sharing; the name is historical, no consent is asked) and `desktop_ended` record the account, device and session IDs, access mode and fixed outcomes. They use the bounded 1,000-event audit history. Starting a session requires a successful audit write.
- **There is no screen recording or keystroke log.** Frames and input are kept only in memory (latest frame and bounded input) and never stored in the database, audit events or application logs. HTTP responses use `no-store`.
- At most 64 ending records (without media or input) are kept in server memory for one minute; they require current device access and are not restored after a restart. Server restart and backup restore never resume a session.

## Security notes

- The named pipe is local-only and owned by SYSTEM; network clients are rejected. The agent uses the OS-reported client session, not a claimed session or PID.
- The companion pins the connected pipe, verifies its SYSTEM owner and matches the pipe server's PID to the running **OpenRMMAgent** service through the Service Control Manager. A per-connection random peer ID prevents a reconnect from inheriting a session. Name squatting or identity failures fail closed.
- The companion refuses to run elevated, as a service or in an RDP session.
- The technician picks a display by its index; the companion maps the index onto its own current layout every round and never takes screen geometry from the server. It compares the display layout and input desktop before and after capture and input; these are interruption guards, not an atomic snapshot.
- Another process running as the same signed-in user is inside that user's trust boundary; the companion is not an isolation boundary against a compromised signed-in user. A fully compromised server or endpoint is outside these guarantees.

## For contributors

`TestNativeWindowInput` is an opt-in diagnostic that sends generated input into a temporary test window. It briefly opens a visible window, checks foreground, process and pointer ownership before sending input, aborts if focus is lost, and does not read the clipboard or run commands. Run it only when you intend to, and clear the variable afterwards:

```powershell
$env:OPENRMM_TEST_DESKTOP_INPUT = '1'
go test -mod=readonly ./internal/desktop -run '^TestNativeWindowInput$' -count=1 -v
Remove-Item Env:OPENRMM_TEST_DESKTOP_INPUT
```

Ordinary `scripts/check.ps1` runs do not send input or open that window. Viewing the device you are working on shows a mirror effect; test control from a separate device.

## Related

- [TERMINAL.md](TERMINAL.md): SYSTEM PowerShell and live response
- [FILES.md](FILES.md): file browsing and transfer
- [WINDOWS-SERVICE.md](WINDOWS-SERVICE.md): agent installation and feature switches
- [TECHNICIANS.md](TECHNICIANS.md): technician permissions
