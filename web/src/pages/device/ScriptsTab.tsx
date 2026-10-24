import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Play, ScrollText } from "lucide-react";
import { get } from "../../lib/api";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { absoluteTime, describeInterval, relativeTime } from "../../lib/format";
import type { DeviceScripts, ScriptRunSummary, ScriptSchedule } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, Button, EmptyState, ErrorNotice, Panel, Spinner, Tip } from "../../components/ui";
import { OperationStatus } from "../../components/status";
import { RunAsBadge, RunDetailModal, RunScriptDialog, ScheduleDialog } from "../scripts/shared";
import { ScheduleActions, ScheduleState } from "../scripts/ScheduleActions";

export function ScriptsTab({ deviceId, hostname }: { deviceId: string; hostname: string }) {
  const client = useQueryClient();
  const [runOpen, setRunOpen] = useState(false);
  const [runId, setRunId] = useState<string | null>(null);
  const [schedule, setSchedule] = useState<{ open: boolean; existing: ScriptSchedule | null }>({ open: false, existing: null });
  const [params, setParams] = useSearchParams();
  // "Run script" in the device header opens this tab with ?run=1.
  useEffect(() => {
    if (params.get("run") === "1") {
      setRunOpen(true);
      const next = new URLSearchParams(params);
      next.delete("run");
      setParams(next, { replace: true });
    }
  }, [params, setParams]);
  const q = useQuery({ queryKey: ["device-scripts", deviceId], queryFn: ({ signal }) => get<DeviceScripts>(`/api/v1/devices/${deviceId}/scripts`, signal), refetchInterval: LIVE_INTERVAL });

  if (q.isPending) return <Spinner label="Loading scripts" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const d = q.data!;

  const runColumns: Column<ScriptRunSummary>[] = [
    {
      key: "name",
      header: "Script",
      sort: (r) => r.name.toLowerCase(),
      cell: (r) => (
        <span className="font-medium text-fg">
          {r.name} <span className="text-faint">v{r.version}</span>
        </span>
      ),
    },
    { key: "as", header: "Runs as", cell: (r) => <RunAsBadge runAs={r.run_as} /> },
    { key: "status", header: "Status", sort: (r) => r.status, cell: (r) => <OperationStatus status={r.status} /> },
    { key: "exit", header: "Exit", cell: (r) => (r.exit_code === null ? <span className="text-faint">—</span> : <span className={r.exit_code === 0 ? "text-ok" : "text-danger"}>{r.exit_code}</span>) },
    { key: "actor", header: "By", cell: (r) => <span className="text-muted">{r.actor}</span> },
    {
      key: "at",
      header: "Started",
      sort: (r) => r.created_at,
      cell: (r) => (
        <Tip label={absoluteTime(r.created_at)}>
          <span className="text-muted">{relativeTime(r.created_at)}</span>
        </Tip>
      ),
    },
  ];
  const scheduleColumns: Column<ScriptSchedule>[] = [
    { key: "name", header: "Schedule", sort: (s) => s.name.toLowerCase(), cell: (s) => <span className="font-medium text-fg">{s.name}</span> },
    { key: "repeat", header: "Repeats", cell: (s) => <span className="text-muted">{describeInterval(s.interval_seconds)}</span> },
    { key: "next", header: "Next run", sort: (s) => s.next_at, cell: (s) => (s.state === "active" ? <Tip label={absoluteTime(s.next_at)}><span className="text-muted">{new Date(s.next_at * 1000).toLocaleString()}</span></Tip> : <span className="text-faint">—</span>) },
    { key: "state", header: "State", sort: (s) => s.state, cell: (s) => <ScheduleState state={s.state} /> },
    { key: "act", header: "", className: "text-right", cell: (s) => <ScheduleActions schedule={s} onEdit={() => setSchedule({ open: true, existing: s })} /> },
  ];

  return (
    <div className="space-y-5">
      <Panel>
        <div className="flex flex-wrap items-center gap-3">
          <ScrollText className="size-4 text-muted" />
          <span className="font-medium text-fg">PowerShell scripts</span>
          <Badge tone={d.available ? "ok" : "warn"} dot>
            {d.available ? "Ready" : "Not available"}
          </Badge>
          <div className="flex-1" />
          <Button icon={<CalendarClock className="size-4" />} onClick={() => setSchedule({ open: true, existing: null })}>
            New schedule
          </Button>
          <Button variant="primary" icon={<Play className="size-4" />} disabled={!d.available} onClick={() => setRunOpen(true)}>
            Run script
          </Button>
        </div>
        {!d.available ? <p className="mt-2 text-[12.5px] text-muted">Scripts need the device online and reporting, with scripts turned on in its agent settings.</p> : null}
      </Panel>

      <Panel title="Recent runs" bodyClassName="p-0">
        <DataTable
          columns={runColumns}
          rows={d.runs}
          rowKey={(r) => r.id}
          onRowClick={(r) => setRunId(r.id)}
          initialSort={{ key: "at", dir: "desc" }}
          empty={<EmptyState title="No script runs on this device yet" />}
        />
      </Panel>

      <Panel title="Schedules" bodyClassName="p-0">
        <DataTable columns={scheduleColumns} rows={d.schedules} rowKey={(s) => s.id} empty={<EmptyState title="No schedules for this device" />} />
      </Panel>

      <RunScriptDialog open={runOpen} onOpenChange={setRunOpen} deviceId={deviceId} hostname={hostname} onStarted={(id) => (setRunId(id), void client.invalidateQueries({ queryKey: ["device-scripts", deviceId] }))} />
      <RunDetailModal deviceId={deviceId} runId={runId} onClose={() => setRunId(null)} />
      <ScheduleDialog
        open={schedule.open}
        onOpenChange={(o) => setSchedule((s) => ({ ...s, open: o }))}
        deviceId={deviceId}
        hostname={hostname}
        existing={schedule.existing}
        onSaved={() => void client.invalidateQueries({ queryKey: ["device-scripts", deviceId] })}
      />
    </div>
  );
}
