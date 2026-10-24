import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleX } from "lucide-react";
import { get, post } from "../../lib/api";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { newOperationID } from "../../lib/id";
import { absoluteTime, bytes, relativeTime } from "../../lib/format";
import { filetimeToUnix } from "../../lib/parse";
import type { Process, ProcessesResponse } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Mono, Panel, SearchInput, Spinner, Tip, Toolbar } from "../../components/ui";
import { SkippedBadge } from "./SkippedBadge";
import { snapshotState } from "../../components/status";
import { ActionHistory } from "./ActionHistory";

export function ProcessesTab({ deviceId }: { deviceId: string }) {
  const client = useQueryClient();
  const [filter, setFilter] = useState("");
  const [target, setTarget] = useState<Process | null>(null);
  const q = useQuery({ queryKey: ["processes", deviceId], queryFn: ({ signal }) => get<ProcessesResponse>(`/api/v1/devices/${deviceId}/processes`, signal), refetchInterval: LIVE_INTERVAL });

  const rows = useMemo(() => {
    const t = filter.trim().toLowerCase();
    const items = q.data?.items ?? [];
    return t ? items.filter((p) => p.name.toLowerCase().includes(t) || String(p.pid).includes(t)) : items;
  }, [q.data, filter]);

  if (q.isPending) return <Spinner label="Loading processes" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const d = q.data!;
  const state = snapshotState(d.status, d.stale);

  const columns: Column<Process>[] = [
    { key: "name", header: "Process", sort: (p) => p.name.toLowerCase(), cell: (p) => <span className="font-medium text-fg">{p.name}</span> },
    { key: "pid", header: "PID", sort: (p) => p.pid, cell: (p) => <Mono className="text-muted">{p.pid}</Mono> },
    {
      key: "cpu",
      header: "CPU",
      sort: (p) => p.cpu_basis_points ?? -1,
      headerClassName: "text-right",
      className: "text-right tabular-nums",
      cell: (p) => (p.cpu_basis_points === null ? <span className="text-faint">—</span> : `${(p.cpu_basis_points / 100).toFixed(1)}%`),
    },
    {
      key: "mem",
      header: "Memory",
      sort: (p) => p.working_set_bytes ?? -1,
      headerClassName: "text-right",
      className: "text-right tabular-nums",
      cell: (p) => (p.working_set_bytes === null ? <span className="text-faint">—</span> : bytes(p.working_set_bytes)),
    },
    {
      key: "start",
      header: "Started",
      sort: (p) => filetimeToUnix(p.start) ?? 0,
      cell: (p) => {
        const t = filetimeToUnix(p.start);
        return t ? (
          <Tip label={absoluteTime(t)}>
            <span className="text-muted">{relativeTime(t)}</span>
          </Tip>
        ) : (
          <span className="text-faint">—</span>
        );
      },
    },
    {
      key: "act",
      header: "",
      className: "text-right",
      cell: (p) =>
        d.can_act && p.can_terminate ? (
          <Button
            size="sm"
            variant="ghost"
            icon={<CircleX className="size-3.5" />}
            onClick={(e) => {
              e.stopPropagation();
              setTarget(p);
            }}
          >
            End
          </Button>
        ) : null,
    },
  ];

  return (
    <div className="space-y-5">
      <Panel bodyClassName="p-0">
        <Toolbar>
          <SearchInput value={filter} onChange={setFilter} placeholder="Filter by name or PID" />
          {state ? <Badge tone={state.tone}>{state.label}</Badge> : null}
          <SkippedBadge count={d.skipped} one="process" many="processes" />
          <div className="flex-1" />
          <span className="text-[12px] text-muted">
            {rows.length} of {d.items.length} · snapshot {d.snapshot_at ? relativeTime(d.snapshot_at) : "never"}
          </span>
        </Toolbar>
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(p) => `${p.pid}:${p.start}`}
          dense
          initialSort={{ key: "cpu", dir: "desc" }}
          empty={<EmptyState title={d.items.length ? "No processes match" : "No process snapshot reported"} />}
        />
      </Panel>
      <ActionHistory title="Process actions" rows={d.actions.map((a) => ({ id: a.id, label: `End ${a.name} (PID ${a.pid})`, actor: a.actor, status: a.status, outcome: a.outcome, at: a.finished_at ?? a.dispatched_at ?? a.created_at }))} />
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(o) => !o && setTarget(null)}
        title={target ? `End ${target.name}?` : ""}
        confirmLabel="End process"
        danger
        onConfirm={async () => {
          if (!target) return;
          await post(`/api/v1/devices/${deviceId}/process-actions`, { id: newOperationID(), pid: target.pid, start: target.start, name: target.name });
          await client.invalidateQueries({ queryKey: ["processes", deviceId] });
        }}
      >
        {target ? (
          <p>
            Forcefully ends PID <span className="font-mono text-fg">{target.pid}</span>. Only this exact process instance is targeted; unsaved work in it is lost.
          </p>
        ) : null}
      </ConfirmDialog>
    </div>
  );
}
