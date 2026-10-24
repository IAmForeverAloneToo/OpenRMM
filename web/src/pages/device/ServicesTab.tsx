import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, RotateCw, Square } from "lucide-react";
import { get, post } from "../../lib/api";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { newOperationID } from "../../lib/id";
import { relativeTime } from "../../lib/format";
import type { DeviceDetail, ServiceActionsResponse, WindowsService } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, EmptyState, Mono, Panel, SearchInput, Toolbar } from "../../components/ui";
import { snapshotState } from "../../components/status";
import { ActionHistory } from "./ActionHistory";

type Pending = { service: WindowsService; action: "start" | "stop" | "restart" };
const verbs = { start: "Start", stop: "Stop", restart: "Restart" } as const;

export function ServicesTab({ d }: { d: DeviceDetail }) {
  const client = useQueryClient();
  const [filter, setFilter] = useState("");
  const [pending, setPending] = useState<Pending | null>(null);
  const actions = useQuery({
    queryKey: ["service-actions", d.device.id],
    queryFn: ({ signal }) => get<ServiceActionsResponse>(`/api/v1/devices/${d.device.id}/service-actions`, signal),
    refetchInterval: LIVE_INTERVAL,
  });
  const items = d.services.data?.items ?? [];
  const rows = useMemo(() => {
    const t = filter.trim().toLowerCase();
    return t ? items.filter((s) => s.name.toLowerCase().includes(t) || s.display_name.toLowerCase().includes(t)) : items;
  }, [items, filter]);
  const state = snapshotState(d.services.status, d.services.stale);
  const canAct = (actions.data?.can_act ?? false) && !d.services.stale && d.services.status === "ok";

  const button = (s: WindowsService, action: Pending["action"], icon: React.ReactNode, enabled: boolean) =>
    enabled ? (
      <Button
        size="sm"
        variant="ghost"
        icon={icon}
        onClick={(e) => {
          e.stopPropagation();
          setPending({ service: s, action });
        }}
      >
        {verbs[action]}
      </Button>
    ) : null;

  const columns: Column<WindowsService>[] = [
    { key: "display", header: "Service", sort: (s) => s.display_name, cell: (s) => <span className="font-medium text-fg">{s.display_name}</span> },
    { key: "name", header: "Name", sort: (s) => s.name, cell: (s) => <Mono className="text-muted">{s.name}</Mono> },
    {
      key: "state",
      header: "State",
      sort: (s) => s.state,
      cell: (s) => (
        <Badge tone={s.state === "running" ? "ok" : s.state === "stopped" ? "neutral" : "info"} dot>
          {s.state.replaceAll("_", " ")}
        </Badge>
      ),
    },
    {
      key: "act",
      header: "",
      className: "text-right whitespace-nowrap",
      cell: (s) =>
        canAct ? (
          <div className="flex justify-end gap-1">
            {button(s, "start", <Play className="size-3.5" />, s.can_start && s.state === "stopped")}
            {button(s, "stop", <Square className="size-3.5" />, s.can_stop && s.state === "running")}
            {button(s, "restart", <RotateCw className="size-3.5" />, s.can_start && s.can_stop && s.state === "running")}
          </div>
        ) : null,
    },
  ];

  return (
    <div className="space-y-5">
      <Panel bodyClassName="p-0">
        <Toolbar>
          <SearchInput value={filter} onChange={setFilter} placeholder="Filter services" />
          {state ? <Badge tone={state.tone}>{state.label}</Badge> : null}
          <div className="flex-1" />
          <span className="text-[12px] text-muted">
            {rows.length} of {items.length} · snapshot {d.services.snapshot_at ? relativeTime(d.services.snapshot_at) : "never"}
          </span>
        </Toolbar>
        <DataTable columns={columns} rows={rows} rowKey={(s) => s.name} dense initialSort={{ key: "display", dir: "asc" }} empty={<EmptyState title={items.length ? "No services match" : "No service snapshot reported"} />} />
      </Panel>
      <ActionHistory
        title="Service actions"
        rows={(actions.data?.actions ?? []).map((a) => ({ id: a.id, label: `${verbs[a.action as Pending["action"]] ?? a.action} ${a.service}`, actor: a.actor, status: a.status, outcome: a.outcome, at: a.finished_at ?? a.dispatched_at ?? a.created_at }))}
      />
      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(o) => !o && setPending(null)}
        title={pending ? `${verbs[pending.action]} ${pending.service.display_name}?` : ""}
        confirmLabel={pending ? verbs[pending.action] : "Confirm"}
        danger={pending?.action !== "start"}
        onConfirm={async () => {
          if (!pending) return;
          await post(`/api/v1/devices/${d.device.id}/service-actions`, { id: newOperationID(), service: pending.service.name, action: pending.action });
          await client.invalidateQueries({ queryKey: ["service-actions", d.device.id] });
        }}
      >
        {pending ? (
          <p>
            Sends one {pending.action} request for <span className="font-mono text-fg">{pending.service.name}</span>. Dependent services are not stopped, and the request is never retried automatically.
          </p>
        ) : null}
      </ConfirmDialog>
    </div>
  );
}
