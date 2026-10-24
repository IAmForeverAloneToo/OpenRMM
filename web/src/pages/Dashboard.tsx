import type { ReactNode } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Activity, Bell, CircleCheck, HardDrive, Monitor, PlugZap, Radar, Unplug } from "lucide-react";
import { get } from "../lib/api";
import { LIVE_INTERVAL, useNow } from "../lib/hooks";
import { alertTitle, operationKind, relativeTime, absoluteTime } from "../lib/format";
import type { Dashboard as DashboardData, Operation } from "../lib/types";
import { PageHeader } from "../app/AppShell";
import { Freshness } from "../components/Freshness";
import { Badge, EmptyState, ErrorNotice, Panel, Spinner, Tip, cx, type Tone } from "../components/ui";
import { DeviceStatusBadge, OperationStatus, SeverityBadge } from "../components/status";
import { useAccount } from "../lib/session";

function Stat({ label, value, tone, icon, to }: { label: string; value: number; tone?: Tone; icon: ReactNode; to?: string }) {
  const color = { ok: "text-ok", warn: "text-warn", danger: "text-danger", info: "text-info", neutral: "text-fg", accent: "text-accent" }[tone ?? "neutral"];
  const body = (
    <div className="flex h-full items-center gap-3.5 rounded-lg border border-border bg-surface px-4 py-3.5 transition-colors hover:border-border-strong">
      <div className="flex size-9 items-center justify-center rounded-md bg-surface-2 text-muted [&>svg]:size-4.5">{icon}</div>
      <div>
        <div className={cx("text-[22px] leading-none font-semibold tabular-nums", value > 0 ? color : "text-fg")}>{value}</div>
        <div className="mt-1 text-[12.5px] text-muted">{label}</div>
      </div>
    </div>
  );
  return to ? <Link to={to}>{body}</Link> : body;
}

const reasonLabels: Record<string, { label: string; tone: Tone }> = {
  offline: { label: "Offline", tone: "neutral" },
  low_disk: { label: "Low disk", tone: "warn" },
  critical_alert: { label: "Critical alert", tone: "danger" },
  alert: { label: "Alert", tone: "warn" },
};

function OperationRow({ op, now }: { op: Operation; now: number }) {
  return (
    <li className="flex items-center gap-3 px-4 py-2.5">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-medium text-fg">{operationKind(op.kind)}</span>
          <span className="text-faint">on</span>
          <Link to={`/devices/${op.device_id}`} className="truncate text-accent hover:underline">
            {op.hostname}
          </Link>
        </div>
        <div className="text-[12px] text-faint">by {op.actor || "system"}</div>
      </div>
      <OperationStatus status={op.status} />
      <Tip label={absoluteTime(op.at)}>
        <span className="w-16 shrink-0 text-right text-[12px] text-muted tabular-nums">{relativeTime(op.at, now)}</span>
      </Tip>
    </li>
  );
}

export function Dashboard() {
  const account = useAccount();
  const now = useNow();
  const q = useQuery({ queryKey: ["dashboard"], queryFn: ({ signal }) => get<DashboardData>("/api/v1/dashboard", signal), refetchInterval: LIVE_INTERVAL });

  if (q.isPending) return <div className="p-8"><Spinner label="Loading dashboard" /></div>;
  if (q.isError && !q.data) return <div className="p-8"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></div>;
  const d = q.data!;

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader title="Dashboard" subtitle={`Signed in as ${account.username}`} actions={<Freshness updatedAt={q.dataUpdatedAt} failed={q.isError} />} />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
        <Stat label="Devices" value={d.fleet.total} icon={<Monitor />} to="/devices" />
        <Stat label="Online" value={d.fleet.online} tone="ok" icon={<PlugZap />} to="/devices?status=online" />
        <Stat label="Offline" value={d.fleet.offline} tone="warn" icon={<Unplug />} to="/devices?status=offline" />
        <Stat label="Awaiting contact" value={d.fleet.awaiting_contact} tone="info" icon={<Radar />} to="/devices?status=awaiting_contact" />
        <Stat label="Low disk space" value={d.fleet.low_disk} tone="warn" icon={<HardDrive />} to="/devices?disk=low" />
        <Stat label="Active alerts" value={d.alert_counts.active} tone={d.alert_counts.critical_active > 0 ? "danger" : "warn"} icon={<Bell />} to="/alerts" />
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <Panel title="Needs attention" bodyClassName="p-0" actions={<span className="text-[12px] text-muted">{d.attention.length} devices</span>}>
          {d.attention.length === 0 ? (
            <EmptyState icon={<CircleCheck />} title="Nothing needs attention">
              All devices are reporting and no alerts are open.
            </EmptyState>
          ) : (
            <ul className="divide-y divide-border">
              {d.attention.map((a) => (
                <li key={a.device_id}>
                  <Link to={`/devices/${a.device_id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-surface-2">
                    <span className="min-w-0 flex-1 truncate font-medium text-fg">{a.hostname}</span>
                    <div className="flex flex-wrap justify-end gap-1.5">
                      {a.reasons
                        .filter((r) => r !== "offline")
                        .map((r) => (
                          <Badge key={r} tone={reasonLabels[r]?.tone ?? "neutral"}>
                            {reasonLabels[r]?.label ?? r}
                          </Badge>
                        ))}
                      <DeviceStatusBadge status={a.status} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Active alerts"
          bodyClassName="p-0"
          actions={
            <span className="text-[12px] text-muted">
              {d.alert_counts.critical_active} critical · {d.alert_counts.unacknowledged_active} unacknowledged
            </span>
          }
        >
          {d.alerts.length === 0 ? (
            <EmptyState icon={<Bell />} title="No active alerts" />
          ) : (
            <ul className="divide-y divide-border">
              {d.alerts.map((a) => (
                <li key={a.id} className="flex items-center gap-3 px-4 py-2.5">
                  <SeverityBadge severity={a.severity} />
                  <div className="min-w-0 flex-1">
                    <Link to={`/alerts?id=${a.id}`} className="block truncate font-medium text-fg hover:text-accent">
                      {alertTitle(a.kind, a.label)}
                    </Link>
                    <Link to={`/devices/${a.device_id}`} className="text-[12px] text-accent hover:underline">
                      {a.hostname}
                    </Link>
                  </div>
                  {a.acknowledged_at ? <Badge>Acknowledged</Badge> : null}
                  <Tip label={`Opened ${absoluteTime(a.opened_at)}`}>
                    <span className="w-16 shrink-0 text-right text-[12px] text-muted tabular-nums">{relativeTime(a.opened_at, now)}</span>
                  </Tip>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Running now" bodyClassName="p-0" actions={<span className="text-[12px] text-muted">{d.activity.running.length} in progress</span>}>
          {d.activity.running.length === 0 ? (
            <EmptyState icon={<Activity />} title="Nothing is running" />
          ) : (
            <ul className="divide-y divide-border">
              {d.activity.running.map((op) => (
                <OperationRow key={op.kind + op.id} op={op} now={now} />
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Recent activity" bodyClassName="p-0">
          {d.activity.recent.length === 0 ? (
            <EmptyState icon={<Activity />} title="No recent activity" />
          ) : (
            <ul className="divide-y divide-border">
              {d.activity.recent.map((op) => (
                <OperationRow key={op.kind + op.id} op={op} now={now} />
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
