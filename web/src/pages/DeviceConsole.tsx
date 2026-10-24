import { lazy, Suspense, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as Menu from "@radix-ui/react-dropdown-menu";
import {
  Activity,
  ArrowLeft,
  Ban,
  Bell,
  Check,
  Clock,
  Copy,
  Cpu,
  Ellipsis,
  FolderOpen,
  PackagePlus,
  Tags,
  HardDrive,
  MemoryStick,
  ScreenShare,
  ScrollText,
  SquareTerminal,
  Unplug,
} from "lucide-react";
import { ApiError, get, post } from "../lib/api";
import { LIVE_INTERVAL, useNow } from "../lib/hooks";
import { absoluteTime, alertTitle, bytes, duration, operationKind, osLabel, percent, relativeTime, utcTime } from "../lib/format";
import type { DeviceDetail, RemoteDisplay } from "../lib/types";
import { displayName, qualityNames } from "../lib/desktop";
import { AGENT_FEATURES } from "../lib/features";
import { useAccount } from "../lib/session";
import { Freshness } from "../components/Freshness";
import { ConfirmDialog } from "../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Field, Mono, Panel, Select, Spinner, Tip, cx } from "../components/ui";
import { DeviceStatusBadge, OperationStatus, SeverityBadge, snapshotState } from "../components/status";
import { ProcessesTab } from "./device/ProcessesTab";
import { ServicesTab } from "./device/ServicesTab";
import { EventLogsTab } from "./device/EventLogsTab";
import { SoftwareTab } from "./device/SoftwareTab";

import { UpdatesTab } from "./device/UpdatesTab";
import { FilesTab } from "./device/FilesTab";
import { UsersTab } from "./device/UsersTab";
import { SystemTab } from "./device/SystemTab";
import { IsolateDialog, IsolationBanner } from "./device/Isolation";
import { ScriptsTab } from "./device/ScriptsTab";
import { Modal } from "../components/Dialog";
import { DeployDialog } from "./operations/deployments";
import { OrganizeDialog } from "./admin/org";
import { StartLiveResponse } from "./LiveResponse";

// Charts (uPlot) load only when the Metrics tab is opened.
const MetricsTab = lazy(() => import("./device/MetricsTab").then((m) => ({ default: m.MetricsTab })));

type Tab = "overview" | "system" | "users" | "processes" | "services" | "events" | "software" | "files" | "scripts" | "metrics" | "updates";
const tabKeys: Tab[] = ["overview", "system", "users", "processes", "services", "events", "software", "files", "scripts", "metrics", "updates"];

function CopyID({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
      className="inline-flex items-center gap-1.5 font-mono text-[12px] text-muted hover:text-fg"
      aria-label="Copy device ID"
    >
      {value}
      {done ? <Check className="size-3.5 text-ok" /> : <Copy className="size-3.5" />}
    </button>
  );
}

function Meter({ icon, label, value, detail, used, state }: { icon: ReactNode; label: string; value: string; detail?: string; used?: number | null; state: { label: string; tone: "ok" | "warn" | "danger" | "neutral" | "info" | "accent" } | null }) {
  const level = used === undefined || used === null ? null : used;
  const tone = level === null ? "bg-neutral" : level >= 90 ? "bg-danger" : level >= 75 ? "bg-warn" : "bg-ok";
  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-[12.5px] font-medium text-muted [&>svg]:size-4">
          {icon}
          {label}
        </div>
        {state ? <Badge tone={state.tone}>{state.label}</Badge> : null}
      </div>
      <div className={cx("mt-2.5 text-[22px] leading-none font-semibold tabular-nums", state && state.label !== "Stale" ? "text-faint" : "text-fg")}>{value}</div>
      {level !== null ? (
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface-3" aria-hidden>
          <div className={cx("h-full rounded-full", tone)} style={{ width: `${Math.min(100, Math.max(0, level))}%` }} />
        </div>
      ) : null}
      {detail ? <div className="mt-2 text-[12px] text-muted">{detail}</div> : null}
    </div>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-3 py-2">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 text-fg">{children}</dd>
    </div>
  );
}


function capabilityText(status: string, value: string | undefined): string {
  if (status !== "ok") return snapshotState(status, false)?.label ?? "Not reported";
  if (!value) return "Unknown";
  return value.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
}

function Overview({ d, now }: { d: DeviceDetail; now: number }) {
  const inv = d.inventory.data;
  const cpu = d.cpu.data;
  const mem = d.memory.data;
  const disk = d.disk_space.data;
  const up = d.uptime.data;
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Meter icon={<Cpu />} label="CPU" value={cpu ? percent(cpu.usage_percent) : "—"} used={cpu?.usage_percent} detail={d.cpu.snapshot_at ? `Sampled ${relativeTime(d.cpu.snapshot_at, now)}` : undefined} state={snapshotState(d.cpu.status, d.cpu.stale)} />
        <Meter
          icon={<MemoryStick />}
          label="Memory"
          value={percent(d.memory.used_percent)}
          used={d.memory.used_percent}
          detail={mem ? `${bytes(mem.total_bytes - mem.available_bytes)} of ${bytes(mem.total_bytes)} used` : undefined}
          state={snapshotState(d.memory.status, d.memory.stale)}
        />
        <Meter
          icon={<HardDrive />}
          label={disk ? `System disk (${disk.drive})` : "System disk"}
          value={percent(d.disk_space.used_percent)}
          used={d.disk_space.used_percent}
          detail={disk ? `${bytes(disk.available_bytes)} free of ${bytes(disk.total_bytes)}` : undefined}
          state={d.disk_space.warning === "low" ? { label: "Low space", tone: "warn" } : snapshotState(d.disk_space.status, d.disk_space.stale)}
        />
        <Meter icon={<Clock />} label="Uptime" value={up ? duration(up.uptime_seconds) : "—"} detail={up ? `Booted about ${utcTime(up.estimated_boot_at)}` : undefined} state={snapshotState(d.uptime.status, d.uptime.stale)} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Panel title="Device" bodyClassName="py-1">
          <dl className="divide-y divide-border">
            <Fact label="Operating system">{inv ? osLabel(inv.os, inv.os_version, inv.os_build) : osLabel(d.device.os)}</Fact>
            <Fact label="Architecture">{d.device.architecture}</Fact>
            <Fact label="Agent version">
              <Mono>{d.device.agent_version || "—"}</Mono>
            </Fact>
            <Fact label="Group">{d.device.group_name ?? <span className="text-faint">Ungrouped</span>}</Fact>
            <Fact label="Tags">
              {(d.device.tags ?? []).length ? (
                <div className="flex flex-wrap gap-1">
                  {d.device.tags!.map((t) => (
                    <Badge key={t} tone="accent">
                      {t}
                    </Badge>
                  ))}
                </div>
              ) : (
                <span className="text-faint">None</span>
              )}
            </Fact>
            <Fact label="Enrolled">{absoluteTime(d.device.enrolled_at)}</Fact>
            <Fact label="Last contact">
              <Tip label={absoluteTime(d.device.last_contact_at)}>
                <span>{relativeTime(d.device.last_contact_at, now)}</span>
              </Tip>
            </Fact>
            <Fact label="Device ID">
              <CopyID value={d.device.id} />
            </Fact>
          </dl>
        </Panel>

        <div className="space-y-5">
          <Panel title="Active alerts" bodyClassName="p-0" actions={<Bell className="size-4 text-faint" />}>
            {d.alerts.filter((a) => a.status === "active").length === 0 ? (
              <p className="px-4 py-4 text-muted">No active alerts.</p>
            ) : (
              <ul className="divide-y divide-border">
                {d.alerts
                  .filter((a) => a.status === "active")
                  .map((a) => (
                    <li key={a.id} className="flex items-center gap-3 px-4 py-2.5">
                      <SeverityBadge severity={a.severity} />
                      <span className="flex-1 truncate text-fg">{alertTitle(a.kind, a.label)}</span>
                      <span className="text-[12px] text-muted">{relativeTime(a.opened_at, now)}</span>
                    </li>
                  ))}
              </ul>
            )}
          </Panel>
          <Panel title="Recent activity" bodyClassName="p-0" actions={d.activity.pending > 0 ? <Badge tone="info">{d.activity.pending} pending</Badge> : <Activity className="size-4 text-faint" />}>
            {d.activity.recent.length === 0 ? (
              <p className="px-4 py-4 text-muted">No recorded operations.</p>
            ) : (
              <ul className="divide-y divide-border">
                {d.activity.recent.slice(0, 8).map((op) => (
                  <li key={op.kind + op.id} className="flex items-center gap-3 px-4 py-2.5">
                    <span className="flex-1 text-fg">{operationKind(op.kind)}</span>
                    <OperationStatus status={op.status} />
                    <span className="w-16 text-right text-[12px] text-muted">{relativeTime(op.at, now)}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel title="Agent features" bodyClassName="py-1">
            <ul className="divide-y divide-border">
              {AGENT_FEATURES.map((f) => {
                const locked = d.device.locked_features?.includes(f.key);
                const off = d.device.disabled_features?.includes(f.key);
                return (
                  <li key={f.key} className="flex items-center gap-3 px-4 py-1.5 text-[12.5px]">
                    <span className="min-w-0 flex-1 truncate text-fg">{f.label}</span>
                    {locked ? (
                      <Tip label="A local administrator turned this off on the device. Its policy cannot turn it back on.">
                        <span>
                          <Badge tone="warn">Locked off on device</Badge>
                        </span>
                      </Tip>
                    ) : off ? (
                      <Badge tone="neutral">Off by policy</Badge>
                    ) : (
                      <Badge tone="ok" dot>
                        On
                      </Badge>
                    )}
                  </li>
                );
              })}
            </ul>
          </Panel>
          <Panel title="Agent capabilities" bodyClassName="py-1">
            <dl className="divide-y divide-border">
              <Fact label="Hardware">
                {d.system_info.data
                  ? [d.system_info.data.hardware.manufacturer, d.system_info.data.hardware.model, d.system_info.data.hardware.serial && `S/N ${d.system_info.data.hardware.serial}`].filter(Boolean).join(" · ") || "Not provided"
                  : capabilityText(d.system_info.status, undefined)}
                {d.system_info.stale && d.system_info.data ? <Badge tone="warn" className="ml-2">Stale</Badge> : null}
              </Fact>
              <Fact label="IP address">{d.system_info.primary_ipv4 || <span className="text-faint">—</span>}</Fact>
              <Fact label="Signed-in users">
                {d.sessions.status === "ok" ? (d.sessions.active_users.length ? d.sessions.active_users.join(", ") : d.sessions.count ? `${d.sessions.count} signed in, none active` : "Nobody signed in") : capabilityText(d.sessions.status, undefined)}
                {d.sessions.stale && d.sessions.status === "ok" ? <Badge tone="warn" className="ml-2">Stale</Badge> : null}
              </Fact>
              <Fact label="Local accounts">
                {d.local_accounts.status === "ok"
                  ? `${d.local_accounts.accounts} accounts (${d.local_accounts.enabled} enabled) · ${d.local_accounts.administrators} in Administrators · ${d.local_accounts.remote_desktop_users} in Remote Desktop Users`
                  : `${capabilityText(d.local_accounts.status, undefined)}${d.local_accounts.has_snapshot ? ` (last report: ${d.local_accounts.accounts} accounts)` : ""}`}
                {d.local_accounts.stale && d.local_accounts.has_snapshot ? <Badge tone="warn" className="ml-2">Stale</Badge> : null}
              </Fact>
              <Fact label="Software inventory">
                {d.software.status === "ok" ? `${d.software.count} applications` : capabilityText(d.software.status, undefined)}
                {d.software.stale && d.software.status === "ok" ? <Badge tone="warn" className="ml-2">Stale</Badge> : null}
              </Fact>
              <Fact label="Services">{d.services.data ? `${d.services.data.items.length} visible` : capabilityText(d.services.status, undefined)}</Fact>
              <Fact label="Event logs">
                {d.event_logs.data ? `System: ${capabilityText("ok", d.event_logs.data.system)} · Application: ${capabilityText("ok", d.event_logs.data.application)}` : capabilityText(d.event_logs.status, undefined)}
              </Fact>
              <Fact label="Windows Update">
                {d.windows_updates.data
                  ? `${capabilityText("ok", d.windows_updates.data.broker)} · install ${d.windows_updates.data.can_install ? "allowed" : "not allowed"} · restart ${d.windows_updates.data.can_restart ? "allowed" : "not allowed"}`
                  : capabilityText(d.windows_updates.status, undefined)}
              </Fact>
            </dl>
          </Panel>
        </div>
      </div>
    </div>
  );
}

export function DeviceConsole() {
  const { id = "" } = useParams();
  const account = useAccount();
  const navigate = useNavigate();
  const client = useQueryClient();
  const now = useNow();
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab") as Tab | null;
  const tab: Tab =
    requested && tabKeys.includes(requested) && (requested !== "updates" && requested !== "scripts" || account.permissions.owner) && (requested !== "files" || account.permissions.files) ? requested : "overview";
  const [launching, setLaunching] = useState<"" | "desktop">("");
  const [liveOpen, setLiveOpen] = useState(false);
  const [launchError, setLaunchError] = useState<unknown>(null);
  const [desktopOpen, setDesktopOpen] = useState(false);
  const [desktopDisplay, setDesktopDisplay] = useState(0);
  const [desktopQuality, setDesktopQuality] = useState("balanced");
  const displays = useQuery({
    queryKey: ["desktop-displays", id],
    queryFn: ({ signal }) => get<{ available: boolean; displays: RemoteDisplay[] }>(`/api/v1/devices/${id}/desktop/displays`, signal),
    enabled: desktopOpen,
    staleTime: 0,
  });
  const [installKey, setInstallKey] = useState(0);
  const [organizing, setOrganizing] = useState(false);
  const launch = async (kind: "desktop", body: object) => {
    setLaunching(kind);
    setLaunchError(null);
    try {
      const r = await post<{ id: string }>(`/api/v1/devices/${id}/${kind}`, body);
      navigate(`/devices/${id}/${kind}/${r.id}`);
    } catch (e) {
      setLaunchError(e);
    } finally {
      setLaunching("");
    }
  };
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [isolateOpen, setIsolateOpen] = useState(false);
  const q = useQuery({ queryKey: ["device", id], queryFn: ({ signal }) => get<DeviceDetail>(`/api/v1/devices/${id}`, signal), refetchInterval: LIVE_INTERVAL });

  if (q.isPending) return <div className="p-8"><Spinner label="Loading device" /></div>;
  if (q.isError && !q.data) {
    if (q.error instanceof ApiError && (q.error.status === 404 || q.error.status === 403)) {
      return (
        <div className="p-8">
          <EmptyState title={q.error.status === 404 ? "Device not found" : "No access to this device"}>
            <Link to="/devices" className="text-accent hover:underline">
              Back to devices
            </Link>
          </EmptyState>
        </div>
      );
    }
    return <div className="p-8"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></div>;
  }
  const d = q.data!;
  const tabs: { key: Tab; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "system", label: "System" },
    { key: "users", label: "Users" },
    { key: "processes", label: "Processes" },
    { key: "services", label: "Services" },
    { key: "events", label: "Event logs" },
    { key: "software", label: "Software" },
    ...(account.permissions.files ? [{ key: "files" as Tab, label: "Files" }] : []),
    ...(account.permissions.owner ? [{ key: "scripts" as Tab, label: "Scripts" }] : []),
    { key: "metrics", label: "Metrics" },
    ...(account.permissions.owner ? [{ key: "updates" as Tab, label: "Windows Update" }] : []),
  ];

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <Link to="/devices" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-fg">
        <ArrowLeft className="size-3.5" /> Devices
      </Link>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-3">
            <h1 className="truncate text-[22px] font-semibold tracking-tight text-fg">{d.device.hostname}</h1>
            <DeviceStatusBadge status={d.device.status} />
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-muted">
            <span>{d.inventory.data ? osLabel(d.inventory.data.os, d.inventory.data.os_version, d.inventory.data.os_build) : osLabel(d.device.os)}</span>
            <span className="text-faint">·</span>
            <span>{d.device.group_name ?? "Ungrouped"}</span>
            <span className="text-faint">·</span>
            <span>Last contact {relativeTime(d.device.last_contact_at, now)}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Freshness updatedAt={q.dataUpdatedAt} failed={q.isError} />
          {(account.permissions.owner || account.permissions.response) && d.device.status !== "revoked" ? (
            <Menu.Root>
              <Menu.Trigger asChild>
                <Button icon={<Ellipsis className="size-4" />} aria-label="More actions">
                  More
                </Button>
              </Menu.Trigger>
              <Menu.Portal>
                <Menu.Content align="end" sideOffset={6} className="z-50 min-w-52 rounded-md border border-border-strong bg-surface p-1 shadow-panel">
                  {d.isolation.phase === "isolating" || d.isolation.phase === "isolated" || d.isolation.phase === "releasing" ? null : (
                    <Menu.Item className="flex h-8 cursor-pointer items-center gap-2 rounded px-2 text-[13px] text-danger outline-none data-[highlighted]:bg-danger-soft" onSelect={() => setIsolateOpen(true)}>
                      <Unplug className="size-4" />
                      Isolate from network…
                    </Menu.Item>
                  )}
                  {account.permissions.owner ? (
                    <>
                      <Menu.Item className="flex h-8 cursor-pointer items-center gap-2 rounded px-2 text-[13px] text-fg outline-none data-[highlighted]:bg-surface-2" onSelect={() => setOrganizing(true)}>
                        <Tags className="size-4" />
                        Group, policy and tags…
                      </Menu.Item>
                      <Menu.Item className="flex h-8 cursor-pointer items-center gap-2 rounded px-2 text-[13px] text-danger outline-none data-[highlighted]:bg-danger-soft" onSelect={() => setRevokeOpen(true)}>
                        <Ban className="size-4" />
                        Revoke device…
                      </Menu.Item>
                    </>
                  ) : null}
                </Menu.Content>
              </Menu.Portal>
            </Menu.Root>
          ) : null}
        </div>
      </div>

      <IsolationBanner d={d} canRespond={account.permissions.owner || account.permissions.response} />
      <div className="mt-4 flex flex-wrap items-center gap-2">
        {account.permissions.owner || account.permissions.response ? (
          <Tip label="PowerShell as SYSTEM with built-in response commands (processes, connections, kill, collect files and hives, drop tools, run scripts), optionally recorded to a case">
            <span>
              <Button size="sm" icon={<SquareTerminal className="size-4" />} disabled={d.device.status !== "online"} onClick={() => setLiveOpen(true)}>
                Live response
              </Button>
            </span>
          </Tip>
        ) : null}
        {account.permissions.desktop ? (
          <Tip label="View or control the signed-in user's screen; the session starts at once and nothing is shown on the device">
            <span>
              <Button size="sm" icon={<ScreenShare className="size-4" />} loading={launching === "desktop"} disabled={d.device.status !== "online"} onClick={() => setDesktopOpen(true)}>
                Remote desktop
              </Button>
            </span>
          </Tip>
        ) : null}
        {account.permissions.files ? (
          <Button size="sm" icon={<FolderOpen className="size-4" />} onClick={() => setParams({ tab: "files" }, { replace: true })}>
            Files
          </Button>
        ) : null}
        {account.permissions.owner ? (
          <Button size="sm" icon={<ScrollText className="size-4" />} onClick={() => setParams({ tab: "scripts", run: "1" }, { replace: true })}>
            Run script
          </Button>
        ) : null}
        {account.permissions.owner && d.device.os === "windows" ? (
          <Button size="sm" icon={<PackagePlus className="size-4" />} disabled={d.device.status === "revoked"} onClick={() => setInstallKey(Date.now())}>
            Install app
          </Button>
        ) : null}
      </div>
      {launchError ? (
        <div className="mt-3">
          <ErrorNotice error={launchError} />
        </div>
      ) : null}

      <div className="mt-5 mb-5 flex gap-1 overflow-x-auto border-b border-border" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={tab === t.key}
            onClick={() => setParams(t.key === "overview" ? {} : { tab: t.key }, { replace: true })}
            className={cx("-mb-px shrink-0 border-b-2 px-3 py-2 text-[13px] font-medium whitespace-nowrap", tab === t.key ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg")}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" ? <Overview d={d} now={now} /> : null}
      {tab === "system" ? <SystemTab d={d} /> : null}
      {tab === "users" ? <UsersTab deviceId={d.device.id} /> : null}
      {tab === "processes" ? <ProcessesTab deviceId={d.device.id} /> : null}
      {tab === "services" ? <ServicesTab d={d} /> : null}
      {tab === "events" ? <EventLogsTab d={d} /> : null}
      {tab === "software" ? <SoftwareTab deviceId={d.device.id} /> : null}
      {tab === "files" ? <FilesTab deviceId={d.device.id} /> : null}
      {tab === "scripts" ? <ScriptsTab deviceId={d.device.id} hostname={d.device.hostname} /> : null}
      {tab === "metrics" ? (
        <Suspense fallback={<Spinner label="Loading charts" />}>
          <MetricsTab deviceId={d.device.id} />
        </Suspense>
      ) : null}
      {tab === "updates" ? <UpdatesTab deviceId={d.device.id} /> : null}

      {liveOpen ? <StartLiveResponse deviceId={d.device.id} open onOpenChange={setLiveOpen} /> : null}
      <Modal open={desktopOpen} onOpenChange={setDesktopOpen} title="Start remote desktop" description="Sharing starts at once and nothing is shown on the device. Display and quality can also be changed during the session.">
        <div className="mb-3 grid gap-3 sm:grid-cols-2">
          <Field label="Display">
            <Select className="w-full" value={String(desktopDisplay)} onChange={(e) => setDesktopDisplay(Number(e.target.value))} aria-label="Display">
              {(displays.data?.displays.length ? displays.data.displays : [{ index: 0, left: 0, top: 0, width: 0, height: 0, primary: true }]).map((v) => (
                <option key={v.index} value={v.index}>
                  {displayName(v)}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Quality">
            <Select className="w-full" value={desktopQuality} onChange={(e) => setDesktopQuality(e.target.value)} aria-label="Quality">
              {Object.entries(qualityNames).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        {displays.data && !displays.data.available ? <p className="mb-3 text-[12.5px] text-warn">The companion is not connected yet; it starts within a minute after a user signs in.</p> : null}
        <div className="grid gap-3 sm:grid-cols-2">
          <button type="button" className="rounded-lg border border-border p-4 text-left hover:border-accent hover:bg-surface-2" onClick={() => (setDesktopOpen(false), void launch("desktop", { mode: "view", display: desktopDisplay, quality: desktopQuality }))}>
            <div className="font-medium text-fg">View only</div>
            <div className="mt-1 text-[12.5px] text-muted">See the screen. Your mouse and keyboard are never sent.</div>
          </button>
          <button type="button" className="rounded-lg border border-border p-4 text-left hover:border-accent hover:bg-surface-2" onClick={() => (setDesktopOpen(false), void launch("desktop", { mode: "control", display: desktopDisplay, quality: desktopQuality }))}>
            <div className="font-medium text-fg">View and control</div>
            <div className="mt-1 text-[12.5px] text-muted">Also send mouse and keyboard input, once you enable it.</div>
          </button>
        </div>
      </Modal>
      {organizing ? <OrganizeDialog deviceId={d.device.id} onClose={() => setOrganizing(false)} /> : null}
      {installKey ? (
        <DeployDialog
          key={installKey}
          open
          onOpenChange={(o) => !o && setInstallKey(0)}
          device={{ id: d.device.id, hostname: d.device.hostname }}
          onDone={() => setParams({ tab: "software", view: "deployments" }, { replace: true })}
        />
      ) : null}
      {isolateOpen ? <IsolateDialog d={d} open={isolateOpen} onOpenChange={setIsolateOpen} /> : null}
      <ConfirmDialog
        open={revokeOpen}
        onOpenChange={setRevokeOpen}
        title={`Revoke ${d.device.hostname}?`}
        confirmLabel="Revoke device"
        danger
        typed={d.device.hostname}
        onConfirm={async () => {
          await post(`/api/v1/devices/${d.device.id}/revoke`, { confirm: d.device.hostname });
          await client.invalidateQueries({ queryKey: ["devices"] });
          await client.invalidateQueries({ queryKey: ["device", id] });
          navigate("/devices");
        }}
      >
        <p>The device's certificate stops working immediately. It can no longer report or receive work, and re-adding it requires a new enrollment.</p>
      </ConfirmDialog>
    </div>
  );
}
