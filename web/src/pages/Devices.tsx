import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Monitor, Plus, Search, Tags } from "lucide-react";
import { get } from "../lib/api";
import { LIVE_INTERVAL, useNow } from "../lib/hooks";
import { absoluteTime, relativeTime } from "../lib/format";
import type { DeviceStatus, DevicesResponse, FleetDevice } from "../lib/types";
import { useAccount } from "../lib/session";
import { PageHeader } from "../app/AppShell";
import { Freshness } from "../components/Freshness";
import { DataTable, type Column } from "../components/DataTable";
import { Badge, Button, EmptyState, ErrorNotice, Input, Mono, Panel, Select, Spinner, Tip, cx } from "../components/ui";
import { DeviceStatusBadge, SecurityBadge } from "../components/status";
import { BulkOrganizeDialog } from "./admin/org";
import { AddDeviceDialog } from "./AddDevice";
import { CsvLink } from "./reports/shared";

const statusFilters: { value: "" | DeviceStatus | "isolated"; label: string }[] = [
  { value: "", label: "All" },
  { value: "online", label: "Online" },
  { value: "offline", label: "Offline" },
  { value: "awaiting_contact", label: "Awaiting" },
  { value: "revoked", label: "Revoked" },
  // Isolated, isolating or releasing.
  { value: "isolated", label: "Isolated" },
];
const isolationLabels = { isolating: "Isolating", isolated: "Isolated", releasing: "Releasing" };

export function Devices() {
  const account = useAccount();
  const navigate = useNavigate();
  const now = useNow();
  const [params, setParams] = useSearchParams();
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState(false);
  const search = params.get("q") ?? "";
  const status = (params.get("status") ?? "") as "" | DeviceStatus | "isolated";
  const group = params.get("group") ?? "";
  const lowDisk = params.get("disk") === "low";
  const security = params.get("security") ?? "";

  const q = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal), refetchInterval: LIVE_INTERVAL });

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  const all = q.data?.devices ?? [];
  const counts = useMemo(() => {
    const c: Record<string, number> = { "": all.length };
    for (const d of all) {
      c[d.status] = (c[d.status] ?? 0) + 1;
      if (d.isolation) c.isolated = (c.isolated ?? 0) + 1;
    }
    return c;
  }, [all]);

  const rows = useMemo(() => {
    const term = search.trim().toLowerCase();
    return all.filter((d) => {
      if (status === "isolated" ? !d.isolation : status && d.status !== status) return false;
      if (group === "ungrouped" ? !!d.group_id : group && d.group_id !== group) return false;
      if (lowDisk && d.disk_space_warning !== "low") return false;
      if (security === "bitlocker" && d.bitlocker !== "off" && d.bitlocker !== "suspended") return false;
      if (security === "defender" && d.defender !== "off" && d.defender !== "real_time_off") return false;
      if (!term) return true;
      return (
        d.hostname.toLowerCase().includes(term) ||
        d.id.startsWith(term) ||
        (d.group_name ?? "").toLowerCase().includes(term) ||
        (d.tags ?? []).some((t) => t.includes(term)) ||
        (d.signed_in_users ?? []).some((u) => u.toLowerCase().includes(term)) ||
        (d.addresses ?? []).some((a) => a.toLowerCase().includes(term)) ||
        (d.macs ?? []).some((m) => m.toLowerCase().includes(term) || (term.replaceAll(/[:-]/g, "") !== "" && m.replaceAll(":", "").toLowerCase().includes(term.replaceAll(/[:-]/g, "")))) ||
        (d.serial ?? "").toLowerCase().includes(term) ||
        d.agent_version.toLowerCase().includes(term)
      );
    });
  }, [all, search, status, group, lowDisk, security]);

  const owner = account.permissions.owner;
  const visible = new Set(rows.map((d) => d.id));
  const chosen = [...selected].filter((id) => visible.has(id));
  const allChosen = rows.length > 0 && rows.every((d) => selected.has(d.id));
  const choose = (id: string, on: boolean) => {
    const next = new Set(selected);
    if (on) next.add(id);
    else next.delete(id);
    setSelected(next);
  };
  const columns: Column<FleetDevice>[] = [
    ...(owner
      ? [
          {
            key: "select",
            header: (
              <input
                type="checkbox"
                className="size-4 accent-[var(--accent)]"
                aria-label="Select all shown devices"
                checked={allChosen}
                onChange={(e) => setSelected(e.target.checked ? new Set([...selected, ...rows.map((d) => d.id)]) : new Set([...selected].filter((id) => !visible.has(id))))}
              />
            ),
            className: "w-px",
            cell: (d: FleetDevice) => (
              <input
                type="checkbox"
                className="size-4 accent-[var(--accent)]"
                aria-label={`Select ${d.hostname}`}
                checked={selected.has(d.id)}
                onClick={(e) => e.stopPropagation()}
                onChange={(e) => choose(d.id, e.target.checked)}
              />
            ),
          },
        ]
      : []),
    {
      key: "hostname",
      header: "Device",
      sort: (d) => d.hostname,
      cell: (d) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-fg">{d.hostname}</div>
          <Mono className="text-[11.5px] text-faint">{d.id.slice(0, 12)}</Mono>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      sort: (d) => (d.isolation ? `0${d.isolation}` : d.status),
      cell: (d) => (
        <span className="flex flex-wrap items-center gap-1">
          <DeviceStatusBadge status={d.status} />
          {d.isolation ? <Badge tone="danger">{isolationLabels[d.isolation]}</Badge> : null}
        </span>
      ),
    },
    {
      key: "user",
      header: "Signed-in user",
      sort: (d) => (d.signed_in_users ?? [])[0]?.toLowerCase() ?? "",
      cell: (d) => {
        const users = d.signed_in_users ?? [];
        if (users.length === 0) return <span className="text-faint">—</span>;
        return (
          <Tip label={users.join(", ")}>
            <span className="text-fg">
              {users[0]}
              {users.length > 1 ? <span className="text-faint"> +{users.length - 1}</span> : null}
            </span>
          </Tip>
        );
      },
    },
    {
      key: "ip",
      header: "IP address",
      sort: (d) => (d.primary_ipv4 ?? "").split(".").map((p) => p.padStart(3, "0")).join("."),
      cell: (d) => (d.primary_ipv4 ? <Mono className="text-muted">{d.primary_ipv4}</Mono> : <span className="text-faint">—</span>),
    },
    {
      key: "alerts",
      header: "Alerts",
      sort: (d) => d.critical_alerts * 1000 + d.active_alerts,
      cell: (d) =>
        d.active_alerts === 0 ? (
          <span className="text-faint">—</span>
        ) : (
          <Badge tone={d.critical_alerts > 0 ? "danger" : "warn"}>
            {d.active_alerts} active{d.critical_alerts > 0 ? ` · ${d.critical_alerts} critical` : ""}
          </Badge>
        ),
    },
    {
      key: "disk",
      header: "System disk",
      sort: (d) => d.disk_space_warning,
      cell: (d) =>
        d.disk_space_warning === "low" ? <Badge tone="warn">Low</Badge> : d.disk_space_warning === "ok" ? <span className="text-muted">OK</span> : <span className="text-faint">Unknown</span>,
    },
    { key: "bitlocker", header: "BitLocker", sort: (d) => d.bitlocker ?? "", cell: (d) => <SecurityBadge kind="bitlocker" value={d.bitlocker} stale={d.security_stale} /> },
    { key: "defender", header: "Defender", sort: (d) => d.defender ?? "", cell: (d) => <SecurityBadge kind="defender" value={d.defender} stale={d.security_stale} /> },
    {
      key: "group",
      header: "Group",
      sort: (d) => d.group_name ?? "",
      cell: (d) => (
        <div className="flex flex-wrap items-center gap-1">
          <span className={d.group_name ? "text-fg" : "text-faint"}>{d.group_name ?? "Ungrouped"}</span>
          {(d.tags ?? []).slice(0, 3).map((t) => (
            <Badge key={t} tone="accent">
              {t}
            </Badge>
          ))}
          {(d.tags ?? []).length > 3 ? <span className="text-[12px] text-faint">+{(d.tags ?? []).length - 3}</span> : null}
        </div>
      ),
    },
    { key: "os", header: "Platform", sort: (d) => d.os + d.architecture, cell: (d) => <span className="text-muted">{d.os === "windows" ? "Windows" : d.os} · {d.architecture}</span> },
    { key: "agent", header: "Agent", sort: (d) => d.agent_version, cell: (d) => <Mono className="text-muted">{d.agent_version || "—"}</Mono> },
    {
      key: "seen",
      header: "Last seen",
      sort: (d) => d.last_contact_at ?? 0,
      headerClassName: "text-right",
      className: "text-right",
      cell: (d) => (
        <Tip label={absoluteTime(d.last_contact_at)}>
          <span className="text-muted tabular-nums">{relativeTime(d.last_contact_at, now)}</span>
        </Tip>
      ),
    },
  ];

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader
        title="Devices"
        subtitle={q.data ? `${all.length} enrolled` : undefined}
        actions={
          <>
            {q.data ? <Freshness updatedAt={q.dataUpdatedAt} failed={q.isError} /> : null}
            {account.permissions.owner ? (
              <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEnrollOpen(true)}>
                Add device
              </Button>
            ) : null}
          </>
        }
      />
      <Panel bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <div className="relative w-80">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-faint" aria-hidden />
            <Input value={search} onChange={(e) => setParam("q", e.target.value)} placeholder="Filter by name, user, IP, MAC, serial, group or tag" className="pl-8" aria-label="Filter devices" maxLength={100} />
          </div>
          <div className="flex rounded-md border border-border bg-surface-2 p-0.5" role="group" aria-label="Status">
            {statusFilters.map((f) => (
              <button
                key={f.value}
                type="button"
                onClick={() => setParam("status", f.value)}
                aria-pressed={status === f.value}
                className={cx("h-7 rounded px-2.5 text-[12.5px] font-medium", status === f.value ? "bg-surface text-fg shadow-panel" : "text-muted hover:text-fg")}
              >
                {f.label} <span className="text-faint tabular-nums">{counts[f.value] ?? 0}</span>
              </button>
            ))}
          </div>
          <Select value={group} onChange={(e) => setParam("group", e.target.value)} aria-label="Group">
            <option value="">All groups</option>
            <option value="ungrouped">Ungrouped</option>
            {(q.data?.groups ?? []).map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </Select>
          <Select value={security} onChange={(e) => setParam("security", e.target.value)} aria-label="Security">
            <option value="">Any security status</option>
            <option value="bitlocker">BitLocker off or suspended</option>
            <option value="defender">Defender off or real-time off</option>
          </Select>
          {lowDisk ? (
            <Button size="sm" variant="ghost" onClick={() => setParam("disk", "")}>
              Low disk only ✕
            </Button>
          ) : null}
          <div className="flex-1" />
          {owner && chosen.length > 0 ? (
            <>
              <span className="text-[12.5px] text-fg">{chosen.length} selected</span>
              <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
                Clear
              </Button>
              <Button size="sm" variant="primary" icon={<Tags className="size-3.5" />} disabled={chosen.length > 100} onClick={() => setBulk(true)}>
                Organize
              </Button>
            </>
          ) : null}
          {q.data ? <span className="text-[12px] text-muted">{rows.length === all.length ? `${all.length} devices` : `${rows.length} of ${all.length}`}</span> : null}
          <CsvLink href="/api/v1/reports/devices.csv" />
        </div>
        {q.isPending ? (
          <div className="p-6">
            <Spinner label="Loading devices" />
          </div>
        ) : q.isError && !q.data ? (
          <div className="p-4">
            <ErrorNotice error={q.error} retry={() => void q.refetch()} />
          </div>
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(d) => d.id}
            onRowClick={(d) => navigate(`/devices/${d.id}`)}
            initialSort={{ key: "hostname", dir: "asc" }}
            empty={
              all.length === 0 ? (
                <EmptyState icon={<Monitor />} title="No devices enrolled yet">
                  {account.permissions.owner ? "Use Add device to download an installer for your first Windows device." : "Ask an administrator to grant you access to devices."}
                </EmptyState>
              ) : (
                <EmptyState title="No devices match these filters" />
              )
            }
          />
        )}
      </Panel>
      <AddDeviceDialog open={enrollOpen} onOpenChange={setEnrollOpen} />
      {bulk ? (
        <BulkOrganizeDialog
          devices={all.filter((d) => chosen.includes(d.id)).map((d) => ({ id: d.id, hostname: d.hostname }))}
          onClose={(applied) => {
            setBulk(false);
            if (applied) setSelected(new Set());
          }}
        />
      ) : null}
    </div>
  );
}
