# Web Interface Guide

This guide is for contributors working on the OpenRMM dashboard: how the browser application in `web/` is organized, how it is built and served, and the design conventions every page follows.

## Contents

- [Stack](#stack)
- [Source layout](#source-layout)
- [Building and testing](#building-and-testing)
- [Design principles](#design-principles)
- [Layout and navigation](#layout-and-navigation)
- [Theme and design tokens](#theme-and-design-tokens)
- [Shared components](#shared-components)
- [Live data](#live-data)
- [Confirmations](#confirmations)
- [Security requirements](#security-requirements)
- [Related](#related)

## Stack

The dashboard is a React + TypeScript single-page application built with Vite and embedded in the server binary.

| Concern | Choice |
| --- | --- |
| Rendering | React |
| Routing | react-router (declarative mode) |
| Server data | TanStack Query (cached queries, live polling, mutations) |
| Dialogs, menus, tooltips | Individual Radix UI primitives |
| Styling | Tailwind CSS with semantic theme tokens |
| Icons | lucide-react |
| Charts | uPlot |
| Terminal | xterm.js |
| Script editor | CodeMirror (individual modules) |

Frontend packages are kept lean and locked. Do not add a package for convenience: every addition needs a capability gap and a review entry in [DEPENDENCIES.md](DEPENDENCIES.md).

## Source layout

| Path | Contents |
| --- | --- |
| `web/src/main.tsx` | Entry point: query client, router, theme, CSP nonce handling |
| `web/src/App.tsx` | Route table; the core pages load directly, the others are lazy-loaded |
| `web/src/app/` | Application shell (`AppShell.tsx`), navigation (`nav.ts`) and the Ctrl+K command palette |
| `web/src/components/` | Shared components: `ui.tsx` (buttons, panels, badges, fields), `status.tsx` (status badges), `Dialog.tsx`, `DataTable.tsx`, `Freshness.tsx`, `TargetPicker.tsx`, `CodeEditor.tsx` |
| `web/src/lib/` | API client, session, hooks, formatting and parsing helpers, types, theme |
| `web/src/pages/` | One file or folder per area: `device/` (device console tabs), `cases/`, `hunting/`, `scripts/`, `operations/`, `alerts/`, `reports/`, `admin/` |
| `web/src/index.css` | Theme tokens for light and dark themes |

Vite writes hashed assets to `internal/server/webui/dist`, which `go:embed` puts into the server binary. No Node.js runs in the server image.

## Building and testing

Node.js with npm is required to build. Run the scripts from the repository root:

```powershell
# Install locked packages, audit, typecheck and run unit tests (no build output)
./scripts/build-web.ps1 -CheckOnly

# Full web build into internal/server/webui/dist
./scripts/build-web.ps1

# Full project check, including the web typecheck
./scripts/check.ps1
```

- Packages install with `npm ci --ignore-scripts`; the build fails if `package-lock.json` would change.
- Pure helpers in `web/src/lib` have unit tests (`*.test.ts`) run by Node's built-in test runner (`npm test`). Component-level tests would need a DOM library and are a separate dependency decision.
- Check interface changes in a browser against a local development server.

## Design principles

- **Labels and data, not paragraphs.** Explanations belong in tooltips and dialogs at the moment they matter, not in page text.
- **Few clicks.** Every device tool is reachable from the device console header. Ctrl+K jumps to any device or page.
- **Status is never color alone.** Badges pair a color dot with text. Collection states have names: Stale, Collection failed, Disabled on device, Not supported, Not reported.
- **Navigation never performs work.** Opening a page only reads. Mutations happen only through explicit buttons, with a confirmation.
- **Balanced density for desktop and laptop screens** (1280 px and wider).

## Layout and navigation

- **Left navigation** (`web/src/app/nav.ts`): Dashboard, Devices, Alerts; then **Manage**, **Investigate**, **Reports** and **Administration** (owner only). Technicians see only sections they can use; **Investigate** needs the response permission.
- **Top bar:** global search (Ctrl+K) and the theme toggle.
- **Dashboard (home page):** fleet health, active alerts, running jobs and recent activity.
- **Device console:** a header with status, OS and group, a tool bar (**Live response**, **Remote desktop**, **Files**, **Run script**, **Install app**), a **More** menu and tabs (including processes, event logs, updates and metrics).

Navigation entries carry a state (`ready`, `rebuilding` or `soon`). Entries that are not `ready` show a quiet marker and tooltip.

## Theme and design tokens

The dark theme is the default; the toggle switches to light and the choice is remembered in the browser.

Semantic CSS variables in `web/src/index.css` define both themes and are exposed to Tailwind as colors:

| Group | Tokens |
| --- | --- |
| Surfaces | `bg`, `surface`, `surface-2`, `surface-3`, `border`, `border-strong` |
| Text | `fg`, `muted`, `faint` |
| Accent | `accent`, `accent-hover`, `accent-fg`, `accent-soft` |
| Status tones | `ok`, `warn`, `danger`, `info`, `neutral`, each with a `-soft` background variant |

Components use only these tokens, never raw colors, so both themes stay consistent. Fonts are system fonts (Segoe UI and Cascadia Mono on Windows, with platform fallbacks). There are no remote fonts, CDNs or icon services.

## Shared components

Prefer the shared components over new markup:

- `Panel`, `Toolbar`, `Field`, `Button`, `IconButton`, `Select`, `SearchInput`, `Segmented` for page structure and forms.
- `Badge` and `Dot` with a tone, and the status helpers in `status.tsx` (`DeviceStatusBadge`, `OperationStatus`, `SeverityBadge`).
- `Tip` for tooltips, `EmptyState`, `ErrorNotice` and `Spinner` for empty, error and loading states.
- `DataTable` for sortable tables. Its sort state survives live refreshes. Sorting and filtering are in-house code; there is no table library.
- `TargetPicker` for choosing devices and groups (scripts, hunts).

## Live data

- Live views poll every 10 seconds (`LIVE_INTERVAL` in `web/src/lib/hooks.ts`).
- Data updates without wiping forms, selections or sort order.
- Every live view shows its freshness with `Freshness` ("Live · 4s ago", or a warning when the last refresh failed while the most recent data stays visible).

## Confirmations

- Routine actions use a one-click confirmation dialog (`ConfirmDialog`).
- Revocation and network isolation require typing the device name (the `typed` option). The server checks typed confirmations too.

## Security requirements

These properties must be kept by every change:

- The session cookie is `__Host-openrmm-session` (Secure, HttpOnly, SameSite=Strict).
- Every mutation carries the `X-CSRF-Token` header (the API client in `web/src/lib/api.ts` adds it), on top of cross-origin protection.
- The Content-Security-Policy allows `script-src 'self'` only; no inline scripts. Styles are same-origin plus a per-request nonce, which `main.tsx` passes to libraries that insert `<style>` elements.
- Render remote data as text, never as HTML.
- Access is declared on each API route, and the default is owner-only. Technician scope is enforced in storage, not in the interface; hiding a control is a convenience, not a security boundary.

## Related

- [DEPENDENCIES.md](DEPENDENCIES.md): frontend package policy and inventory
- [DEVICE-WORKSPACE.md](DEVICE-WORKSPACE.md): the device console
- [TECHNICIANS.md](TECHNICIANS.md): technician permissions and scope
