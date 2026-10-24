import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Search } from "lucide-react";
import { get } from "../../lib/api";
import { reportQuery } from "../../lib/parse";
import { useNow } from "../../lib/hooks";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { DevicesResponse, SoftwareReport as Report, SoftwareReportRow, SoftwareResult } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Mono, Panel, Select, Spinner, Tip, cx, type Tone } from "../../components/ui";
import { CsvLink } from "./shared";

const results: Record<SoftwareResult, { label: string; tone: Tone; help: string }> = {
  current: { label: "Installed", tone: "ok", help: "Found in the device's current inventory." },
  retained: { label: "Installed (stale)", tone: "warn", help: "Found in the last inventory, but that inventory is out of date." },
  without: { label: "Not installed", tone: "neutral", help: "Not found in the device's current inventory (machine-wide installs only)." },
  unknown: { label: "Unknown", tone: "neutral", help: "No current inventory, so the device can't be answered for." },
};

type Filters = { q: string; version: string; publisher: string; group: string };

export function SoftwareReport() {
  const now = useNow(30_000);
  const [params, setParams] = useSearchParams();
  const applied: Filters = { q: params.get("q") ?? "", version: params.get("version") ?? "", publisher: params.get("publisher") ?? "", group: params.get("group") ?? "" };
  const [draft, setDraft] = useState<Filters>(applied);
  const appliedKey = JSON.stringify(applied);
  useEffect(() => setDraft(JSON.parse(appliedKey) as Filters), [appliedKey]);
  const [shown, setShown] = useState<SoftwareResult | "">("");
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal) });
  const searched = !!(applied.q || applied.version || applied.publisher);
  const query = reportQuery(applied);
  const q = useQuery({ queryKey: ["report-software", query], queryFn: ({ signal }) => get<Report>(`/api/v1/reports/software?${query}`, signal), enabled: searched });

  const counts = useMemo(() => {
    const c: Record<SoftwareResult, number> = { current: 0, retained: 0, without: 0, unknown: 0 };
    for (const d of q.data?.devices ?? []) c[d.result]++;
    return c;
  }, [q.data]);
  const rows = useMemo(() => (q.data?.devices ?? []).filter((d) => !shown || d.result === shown), [q.data, shown]);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setShown("");
    setParams(reportQuery({ q: draft.q.trim(), version: draft.version.trim(), publisher: draft.publisher.trim(), group: draft.group }), { replace: true });
  };

  const order: Record<SoftwareResult, number> = { current: 0, retained: 1, unknown: 2, without: 3 };
  const columns: Column<SoftwareReportRow>[] = [
    {
      key: "device",
      header: "Device",
      sort: (r) => r.device.hostname,
      cell: (r) => (
        <Link to={`/devices/${r.device.id}?tab=software`} className="font-medium text-fg hover:text-accent">
          {r.device.hostname}
        </Link>
      ),
    },
    { key: "group", header: "Group", sort: (r) => r.group_name, cell: (r) => <span className="text-muted">{r.group_name || "Ungrouped"}</span> },
    {
      key: "result",
      header: "Result",
      sort: (r) => order[r.result],
      cell: (r) => (
        <Tip label={results[r.result].help}>
          <span>
            <Badge tone={results[r.result].tone} dot>
              {results[r.result].label}
            </Badge>
          </span>
        </Tip>
      ),
    },
    {
      key: "found",
      header: "Found",
      sort: (r) => r.matches,
      cell: (r) =>
        r.matches === 0 ? (
          <span className="text-faint">—</span>
        ) : (
          <div className="space-y-0.5">
            {r.examples.map((x) => (
              <div key={x.id} className="truncate text-[12.5px]">
                <span className="text-fg">{x.name}</span> <Mono className="text-muted">{x.version}</Mono>
                {x.registry_view === "user" ? <span className="text-faint"> · for {x.user}</span> : null}
              </div>
            ))}
            {r.matches > r.examples.length ? <div className="text-[12px] text-faint">and {r.matches - r.examples.length} more</div> : null}
          </div>
        ),
    },
    {
      key: "inventory",
      header: "Inventory",
      sort: (r) => r.snapshot_at ?? 0,
      cell: (r) =>
        r.snapshot_at ? (
          <Tip label={absoluteTime(r.snapshot_at)}>
            <span className={cx("text-[12.5px]", r.stale ? "text-warn" : "text-muted")}>{relativeTime(r.snapshot_at, now)}</span>
          </Tip>
        ) : (
          <span className="text-[12.5px] text-faint">{r.collection_status === "disabled" ? "Disabled" : "Never"}</span>
        ),
    },
  ];

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader title="Software inventory" subtitle="Find which devices have an application installed (machine-wide installs)." />
      <Panel>
        <form onSubmit={submit} className="grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_auto] items-end gap-3">
          <Field label="Application">
            <Input autoFocus value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} placeholder="Name, e.g. Chrome" maxLength={200} />
          </Field>
          <Field label="Version contains">
            <Input value={draft.version} onChange={(e) => setDraft({ ...draft, version: e.target.value })} maxLength={256} />
          </Field>
          <Field label="Publisher contains">
            <Input value={draft.publisher} onChange={(e) => setDraft({ ...draft, publisher: e.target.value })} maxLength={512} />
          </Field>
          <Field label="Group">
            <Select value={draft.group} onChange={(e) => setDraft({ ...draft, group: e.target.value })} className="w-full">
              <option value="">All groups</option>
              <option value="ungrouped">Ungrouped</option>
              {(devices.data?.groups ?? []).map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </Select>
          </Field>
          <Button type="submit" variant="primary" icon={<Search className="size-4" />} disabled={!draft.q.trim() && !draft.version.trim() && !draft.publisher.trim()}>
            Search
          </Button>
        </form>
      </Panel>

      {!searched ? (
        <div className="mt-5">
          <EmptyState icon={<Boxes />} title="Search for an application">
            Results list every device in scope: where it is installed, where it isn't, and where the inventory can't tell.
          </EmptyState>
        </div>
      ) : q.isPending ? (
        <div className="mt-5">
          <Spinner label="Searching inventories" />
        </div>
      ) : q.isError ? (
        <div className="mt-5">
          <ErrorNotice error={q.error} retry={() => void q.refetch()} />
        </div>
      ) : (
        <Panel className="mt-5" bodyClassName="p-0">
          <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
            <button type="button" onClick={() => setShown("")} className={cx("rounded-md border px-2.5 py-1 text-[12.5px]", shown === "" ? "border-accent bg-accent-soft text-fg" : "border-border text-muted hover:border-border-strong")}>
              All {q.data.devices.length}
            </button>
            {(Object.keys(results) as SoftwareResult[]).map((k) => (
              <button
                key={k}
                type="button"
                disabled={counts[k] === 0}
                onClick={() => setShown(k)}
                className={cx("rounded-md border px-2.5 py-1 text-[12.5px] disabled:opacity-40", shown === k ? "border-accent bg-accent-soft text-fg" : "border-border text-muted hover:border-border-strong")}
              >
                {results[k].label} {counts[k]}
              </button>
            ))}
            <div className="flex-1" />
            <span className="text-[12px] text-faint">as of {absoluteTime(q.data.as_of)}</span>
            <CsvLink href={`/api/v1/reports/software.csv?${reportQuery({ ...applied, result: shown })}`} />
          </div>
          <DataTable columns={columns} rows={rows} rowKey={(r) => r.device.id} initialSort={{ key: "result", dir: "asc" }} empty={<EmptyState title="No devices in scope" />} />
        </Panel>
      )}
    </div>
  );
}
