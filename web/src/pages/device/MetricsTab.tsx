import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { Download } from "lucide-react";
import { get } from "../../lib/api";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { percent } from "../../lib/format";
import type { MetricBucket, MetricsResponse } from "../../lib/types";
import { EmptyState, ErrorNotice, Panel, Segmented, Spinner } from "../../components/ui";

type Range = "24h" | "7d" | "30d";
const kinds = [
  { kind: "cpu", label: "CPU", color: "--accent" },
  { kind: "memory", label: "Memory", color: "--info" },
  { kind: "disk_space", label: "System disk used", color: "--warn" },
] as const;

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Builds a continuous time axis so missing buckets render as gaps, not lines. */
function series(buckets: MetricBucket[], from: number, until: number, step: number) {
  const byAt = new Map(buckets.map((b) => [b.at, b]));
  const xs: number[] = [];
  const mean: (number | null)[] = [];
  const max: (number | null)[] = [];
  for (let t = from; t <= until; t += step) {
    const b = byAt.get(t);
    xs.push(t);
    mean.push(b?.mean_percent ?? null);
    max.push(b?.max_percent ?? null);
  }
  return [xs, mean, max] as uPlot.AlignedData;
}

function Chart({ data, color, syncKey }: { data: uPlot.AlignedData; color: string; syncKey: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const [theme, setTheme] = useState(() => document.documentElement.classList.contains("dark"));

  useEffect(() => {
    const obs = new MutationObserver(() => setTheme(document.documentElement.classList.contains("dark")));
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => obs.disconnect();
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const stroke = cssVar(color);
    const grid = cssVar("--border");
    const text = cssVar("--text-muted");
    const axis = { stroke: text, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid, width: 1 }, font: "11px system-ui, sans-serif" };
    const opts: uPlot.Options = {
      width: el.clientWidth,
      height: 170,
      cursor: { sync: { key: syncKey }, points: { size: 6 } },
      legend: { show: true, live: true },
      scales: { x: { time: true }, y: { range: [0, 100] } },
      axes: [axis, { ...axis, size: 42, values: (_u, v) => v.map((x) => `${x}%`) }],
      series: [
        { value: (_u, v) => (v == null ? "—" : new Date(v * 1000).toLocaleString()) },
        { label: "Average", stroke, width: 1.75, fill: stroke + "22", spanGaps: false, value: (_u, v) => percent(v, 1) },
        { label: "Peak", stroke, width: 1, dash: [4, 4], spanGaps: false, value: (_u, v) => percent(v, 1) },
      ],
    };
    plot.current = new uPlot(opts, data, el);
    const resize = new ResizeObserver(() => plot.current?.setSize({ width: el.clientWidth, height: 170 }));
    resize.observe(el);
    return () => {
      resize.disconnect();
      plot.current?.destroy();
      plot.current = null;
    };
    // Rebuild on theme or data change; uPlot reads colors at creation.
  }, [data, color, syncKey, theme]);

  return <div ref={ref} className="uplot-host w-full" />;
}

export function MetricsTab({ deviceId }: { deviceId: string }) {
  const [range, setRange] = useState<Range>("24h");
  const q = useQuery({
    queryKey: ["metrics", deviceId, range],
    queryFn: ({ signal }) => get<MetricsResponse>(`/api/v1/devices/${deviceId}/metrics?range=${range}`, signal),
    refetchInterval: LIVE_INTERVAL * 6,
  });
  const charts = useMemo(() => {
    if (!q.data) return [];
    return kinds.map((k) => {
      const buckets = q.data.buckets.filter((b) => b.kind === k.kind);
      const summary = q.data.summary.find((s) => s.kind === k.kind);
      return { ...k, buckets, summary, data: series(buckets, q.data.from, q.data.until, q.data.step_seconds) };
    });
  }, [q.data]);

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <Segmented
          label="Range"
          value={range}
          onChange={setRange}
          options={[
            { value: "24h", label: "24 hours" },
            { value: "7d", label: "7 days" },
            { value: "30d", label: "30 days" },
          ]}
        />
        <span className="text-[12px] text-muted">{range === "24h" ? "5-minute averages" : "Hourly averages"} · gaps mean no data was reported</span>
        <div className="flex-1" />
        <a
          href={`/api/v1/devices/${deviceId}/metrics.csv?range=${range}`}
          download
          className="inline-flex h-8.5 shrink-0 items-center gap-2 rounded-md border border-border bg-surface-2 px-3.5 text-[13px] font-medium whitespace-nowrap text-fg hover:bg-surface-3"
        >
          <Download className="size-4" /> Export CSV
        </a>
      </div>
      {q.isPending ? (
        <Spinner label="Loading metrics" />
      ) : q.isError && !q.data ? (
        <ErrorNotice error={q.error} retry={() => void q.refetch()} />
      ) : (
        charts.map((c) => (
          <Panel
            key={c.kind}
            title={c.label}
            actions={
              c.summary ? (
                <span className="text-[12px] text-muted tabular-nums">
                  avg {percent(c.summary.mean_percent, 1)} · min {percent(c.summary.min_percent, 1)} · max {percent(c.summary.max_percent, 1)} · {c.summary.valid_observations} samples
                  {c.summary.detected_gaps > 0 ? ` · ${c.summary.detected_gaps} gaps` : ""}
                </span>
              ) : null
            }
          >
            {c.buckets.length === 0 ? <EmptyState title="No data in this range" /> : <Chart data={c.data} color={c.color} syncKey={`metrics-${deviceId}`} />}
          </Panel>
        ))
      )}
    </div>
  );
}
