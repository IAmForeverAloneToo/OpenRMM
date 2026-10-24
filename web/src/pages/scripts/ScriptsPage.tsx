import { Link, useNavigate, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Plus, ScrollText } from "lucide-react";
import { get } from "../../lib/api";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { absoluteTime, describeInterval, relativeTime } from "../../lib/format";
import type { FleetSchedule, ScriptBatchSummary, ScriptVersion } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, Button, EmptyState, ErrorNotice, Panel, Segmented, Spinner, Tip } from "../../components/ui";
import { RunAsBadge, useScriptLibrary } from "./shared";
import { ScheduleActions, ScheduleState } from "./ScheduleActions";

type View = "library" | "schedules" | "runs";

function Library() {
  const navigate = useNavigate();
  const q = useScriptLibrary();
  if (q.isPending) return <Spinner label="Loading scripts" />;
  if (q.isError) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const columns: Column<ScriptVersion>[] = [
    {
      key: "name",
      header: "Script",
      sort: (v) => v.definition.name.toLowerCase(),
      cell: (v) => (
        <div>
          <div className="font-medium text-fg">{v.definition.name}</div>
          {v.definition.description ? <div className="max-w-xl truncate text-[12px] text-muted">{v.definition.description}</div> : null}
        </div>
      ),
    },
    { key: "version", header: "Version", sort: (v) => v.number, cell: (v) => <span className="text-muted">v{v.number}</span> },
    { key: "as", header: "Runs as", sort: (v) => v.definition.run_as, cell: (v) => <RunAsBadge runAs={v.definition.run_as} /> },
    { key: "params", header: "Parameters", cell: (v) => <span className="text-muted">{v.definition.parameters.length || "—"}</span> },
    {
      key: "updated",
      header: "Updated",
      sort: (v) => v.created_at,
      cell: (v) => (
        <Tip label={`${absoluteTime(v.created_at)} by ${v.actor}`}>
          <span className="text-muted">{relativeTime(v.created_at)}</span>
        </Tip>
      ),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={q.data.scripts}
      rowKey={(v) => v.id}
      onRowClick={(v) => navigate(`/scripts/v/${v.id}`)}
      initialSort={{ key: "name", dir: "asc" }}
      empty={
        <EmptyState icon={<ScrollText />} title="No scripts yet">
          Create a PowerShell script to run on devices on demand, on a schedule, or across many devices at once.
        </EmptyState>
      }
    />
  );
}

function Schedules() {
  const q = useQuery({ queryKey: ["script-schedules"], queryFn: ({ signal }) => get<{ schedules: FleetSchedule[] }>("/api/v1/script-schedules", signal), refetchInterval: LIVE_INTERVAL });
  if (q.isPending) return <Spinner label="Loading schedules" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const columns: Column<FleetSchedule>[] = [
    { key: "name", header: "Schedule", sort: (s) => s.name.toLowerCase(), cell: (s) => <span className="font-medium text-fg">{s.name}</span> },
    {
      key: "device",
      header: "Device",
      sort: (s) => s.hostname,
      cell: (s) => (
        <Link to={`/devices/${s.device_id}?tab=scripts`} className="text-accent hover:underline" onClick={(e) => e.stopPropagation()}>
          {s.hostname || s.device_id.slice(0, 12)}
        </Link>
      ),
    },
    {
      key: "script",
      header: "Script",
      sort: (s) => s.script_name,
      cell: (s) => (
        <span className="inline-flex items-center gap-2 text-muted">
          {s.script_name} v{s.script_version} <RunAsBadge runAs={s.run_as} />
        </span>
      ),
    },
    { key: "repeat", header: "Repeats", cell: (s) => <span className="text-muted">{describeInterval(s.interval_seconds)}</span> },
    { key: "next", header: "Next run", sort: (s) => (s.state === "active" ? s.next_at : Number.MAX_SAFE_INTEGER), cell: (s) => (s.state === "active" ? <span className="text-muted">{new Date(s.next_at * 1000).toLocaleString()}</span> : <span className="text-faint">—</span>) },
    { key: "state", header: "State", sort: (s) => s.state, cell: (s) => <ScheduleState state={s.state} /> },
    { key: "act", header: "", className: "text-right", cell: (s) => <ScheduleActions schedule={s} /> },
  ];
  return <DataTable columns={columns} rows={q.data!.schedules} rowKey={(s) => s.id} empty={<EmptyState title="No schedules">Create schedules from a device's Scripts tab.</EmptyState>} />;
}

function Runs() {
  const navigate = useNavigate();
  const q = useQuery({ queryKey: ["script-batches"], queryFn: ({ signal }) => get<{ batches: ScriptBatchSummary[] }>("/api/v1/script-batches", signal), refetchInterval: LIVE_INTERVAL });
  if (q.isPending) return <Spinner label="Loading fleet runs" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const columns: Column<ScriptBatchSummary>[] = [
    { key: "name", header: "Run", sort: (b) => b.name.toLowerCase(), cell: (b) => <span className="font-medium text-fg">{b.name}</span> },
    { key: "script", header: "Script", sort: (b) => b.script, cell: (b) => <span className="text-muted">{b.script}</span> },
    { key: "targets", header: "Devices", sort: (b) => b.targets, cell: (b) => <span className="text-muted">{b.targets}</span> },
    { key: "actor", header: "By", cell: (b) => <span className="text-muted">{b.actor}</span> },
    { key: "at", header: "Started", sort: (b) => b.created_at, cell: (b) => <span className="text-muted">{relativeTime(b.created_at)}</span> },
    { key: "restored", header: "", cell: (b) => (b.restored ? <Badge tone="warn">Restored from backup</Badge> : null) },
  ];
  return (
    <DataTable
      columns={columns}
      rows={q.data!.batches}
      rowKey={(b) => b.id}
      onRowClick={(b) => navigate(`/scripts/runs/${b.id}`)}
      initialSort={{ key: "at", dir: "desc" }}
      empty={<EmptyState title="No fleet runs yet">Open a script and choose Run on devices.</EmptyState>}
    />
  );
}

export function ScriptsPage() {
  const [params, setParams] = useSearchParams();
  const view = (["library", "schedules", "runs"].includes(params.get("view") ?? "") ? params.get("view") : "library") as View;
  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader
        title="Scripts"
        actions={
          <Link to="/scripts/new">
            <Button variant="primary" icon={<Plus className="size-4" />}>
              New script
            </Button>
          </Link>
        }
      />
      <div className="mb-4">
        <Segmented
          label="Scripts view"
          value={view}
          onChange={(v) => setParams(v === "library" ? {} : { view: v }, { replace: true })}
          options={[
            { value: "library", label: "Library" },
            { value: "schedules", label: "Schedules" },
            { value: "runs", label: "Fleet runs" },
          ]}
        />
      </div>
      <Panel bodyClassName="p-0">{view === "library" ? <Library /> : view === "schedules" ? <Schedules /> : <Runs />}</Panel>
    </div>
  );
}
