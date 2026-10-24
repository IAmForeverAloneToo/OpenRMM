import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ChartColumn } from "lucide-react";
import { get } from "../../lib/api";
import { reportQuery } from "../../lib/parse";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { absoluteTime } from "../../lib/format";
import type { MetricReport, MetricReportRow, MetricSummary } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { Freshness } from "../../components/Freshness";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, EmptyState, ErrorNotice, Panel, SearchInput, Segmented, Select, Spinner, Tip, Toolbar, cx } from "../../components/ui";
import { CsvLink } from "./shared";

type Range = "24h" | "7d" | "30d";
type Kind = "cpu" | "memory" | "disk_space";

function Meter({ value, warn = 75, danger = 90 }: { value: number | null | undefined; warn?: number; danger?: number }) {
  if (value == null) return <span className="text-faint">—</span>;
  const tone = value >= danger ? "bg-danger" : value >= warn ? "bg-warn" : "bg-accent";
  return (
    <span className="flex items-center gap-2">
      <span className="h-1.5 w-14 overflow-hidden rounded-full bg-surface-3">
        <span className={cx("block h-full rounded-full", tone)} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
      </span>
      <span className={cx("w-11 text-right tabular-nums", value >= danger ? "text-danger" : value >= warn ? "text-warn" : "text-fg")}>{value.toFixed(0)}%</span>
    </span>
  );
}

function coverage(row: MetricReportRow): { label: string; tone: "neutral" | "warn" } | null {
  const all = Object.values(row.metrics) as MetricSummary[];
  if (all.every((m) => m.valid_observations === 0)) return { label: "No data", tone: "neutral" };
  if (all.some((m) => m.detected_gaps > 0 || m.unavailable_reports > 0)) return { label: "Gaps", tone: "warn" };
  return null;
}

const sortValue = (row: MetricReportRow, kind: Kind, field: "mean_percent" | "max_percent") => row.metrics[kind]?.[field] ?? -1;

export function MetricsReport() {
  const [params, setParams] = useSearchParams();
  const range = (["24h", "7d", "30d"].includes(params.get("range") ?? "") ? params.get("range") : "24h") as Range;
  const group = params.get("group") ?? "";
  const tag = params.get("tag") ?? "";
  const [filter, setFilter] = useState("");
  const query = reportQuery({ range, group, tag });
  const q = useQuery({ queryKey: ["report-metrics", query], queryFn: ({ signal }) => get<MetricReport>(`/api/v1/reports/metrics?${query}`, signal), refetchInterval: LIVE_INTERVAL * 6 });
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };
  const tags = useMemo(() => [...new Set((q.data?.devices ?? []).flatMap((d) => d.tags))].sort(), [q.data]);
  const rows = useMemo(() => {
    const t = filter.trim().toLowerCase();
    return (q.data?.devices ?? []).filter((d) => !t || d.hostname.toLowerCase().includes(t) || d.group_name.toLowerCase().includes(t));
  }, [q.data, filter]);

  const metric = (kind: Kind, label: string, field: "mean_percent" | "max_percent"): Column<MetricReportRow> => ({
    key: `${kind}-${field}`,
    header: label,
    sort: (r) => sortValue(r, kind, field),
    cell: (r) => <Meter value={r.metrics[kind]?.[field]} />,
  });
  const columns: Column<MetricReportRow>[] = [
    {
      key: "device",
      header: "Device",
      sort: (r) => r.hostname,
      cell: (r) => (
        <Link to={`/devices/${r.id}?tab=metrics`} className="font-medium text-fg hover:text-accent">
          {r.hostname}
        </Link>
      ),
    },
    { key: "group", header: "Group", sort: (r) => r.group_name, cell: (r) => <span className="text-muted">{r.group_name || "Ungrouped"}</span> },
    metric("cpu", "CPU avg", "mean_percent"),
    metric("cpu", "CPU peak", "max_percent"),
    metric("memory", "Memory avg", "mean_percent"),
    metric("memory", "Memory peak", "max_percent"),
    metric("disk_space", "Disk used", "max_percent"),
    {
      key: "coverage",
      header: "Data",
      cell: (r) => {
        const c = coverage(r);
        const last = Math.max(0, ...(Object.values(r.metrics) as MetricSummary[]).map((m) => m.last_at));
        return c ? (
          <Tip label={c.label === "Gaps" ? "Some intervals had no report or an unavailable reading; averages cover reported data only." : "Nothing was reported in this window."}>
            <span>
              <Badge tone={c.tone}>{c.label}</Badge>
            </span>
          </Tip>
        ) : (
          <span className="text-[12px] text-faint">to {absoluteTime(last)}</span>
        );
      },
    },
  ];

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader title="Metrics" subtitle="Average and peak use per device. Open a device for its charts." actions={<Freshness updatedAt={q.dataUpdatedAt} failed={q.isError} />} />
      <Panel bodyClassName="p-0">
        <Toolbar>
          <Segmented
            label="Window"
            value={range}
            onChange={(v) => set("range", v === "24h" ? "" : v)}
            options={[
              { value: "24h", label: "24 hours" },
              { value: "7d", label: "7 days" },
              { value: "30d", label: "30 days" },
            ]}
          />
          <Select value={group} onChange={(e) => set("group", e.target.value)} aria-label="Group">
            <option value="">All groups</option>
            <option value="ungrouped">Ungrouped</option>
            {(q.data?.groups ?? []).map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </Select>
          {tags.length || tag ? (
            <Select value={tag} onChange={(e) => set("tag", e.target.value)} aria-label="Tag">
              <option value="">All tags</option>
              {(tags.includes(tag) || !tag ? tags : [tag, ...tags]).map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </Select>
          ) : null}
          <SearchInput value={filter} onChange={setFilter} placeholder="Filter devices" />
          <div className="flex-1" />
          <span className="text-[12px] text-muted">Disk used is the peak for the system drive</span>
          <CsvLink href={`/api/v1/reports/metrics.csv?${query}`} />
        </Toolbar>
        {q.isPending ? (
          <div className="p-4">
            <Spinner label="Loading report" />
          </div>
        ) : q.isError && !q.data ? (
          <div className="p-4">
            <ErrorNotice error={q.error} retry={() => void q.refetch()} />
          </div>
        ) : (
          <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} initialSort={{ key: "cpu-max_percent", dir: "desc" }} empty={<EmptyState icon={<ChartColumn />} title="No devices match" />} />
        )}
      </Panel>
    </div>
  );
}
