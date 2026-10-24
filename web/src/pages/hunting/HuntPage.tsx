import { useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, Eye, ListTree, Square } from "lucide-react";
import { get, post } from "../../lib/api";
import { absoluteTime, relativeTime, utcTime } from "../../lib/format";
import type { ActionResult, Hunt, HuntTarget, WindowsEvent } from "../../lib/types";
import { IndicatorText, MatchesTable, type MatchRow } from "./matches";
import { PageHeader } from "../../app/AppShell";
import { ConfirmDialog, Modal } from "../../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Mono, Panel, SearchInput, Spinner, Tip, type Tone } from "../../components/ui";
import { reasons } from "../cases/Collections";

// One log search or indicator hunt across devices. The overview shows each device's state and match count; opening
// results reads them (recorded in the case's custody log when the search has
// a case).

const LIVE = "00000000000000000000000000000000";
// At most this many events are loaded into the page.
const MAX_ROWS = 50_000;
const active = new Set(["queued", "dispatched", "uploading", "verifying"]);
const searched: Record<string, string> = {
  denied: "The device refused to read this log (permissions).",
  unavailable: "The log does not exist on the device.",
  unsupported: "Event logs are switched off on the device.",
  timed_out: "The search took too long on the device.",
  log_changed: "The log changed while it was read.",
  too_large: "The result was too large.",
  failed: "The device could not read the log.",
};
// A finished search with a usable result (a partial hunt stopped at its time
// limit but still reports what it found).
const usable = (t: HuntTarget) => t.result && (t.searched === "ok" || t.searched === "partial");

function state(t: HuntTarget): { label: string; tone: Tone } {
  if (t.status === "queued") return { label: "Waiting for device", tone: "neutral" };
  if (active.has(t.status)) return { label: "Searching", tone: "info" };
  if (t.status === "succeeded") {
    if (t.searched === "partial") return { label: "Partly searched", tone: "warn" };
    return t.searched && t.searched !== "ok" ? { label: "Not searched", tone: "warn" } : { label: "Done", tone: "ok" };
  }
  if (t.status === "cancelled") return { label: "Cancelled", tone: "neutral" };
  if (t.status === "expired") return { label: t.outcome === "purged" ? "Result removed" : "Did not answer", tone: "warn" };
  return { label: "Failed", tone: "danger" };
}

type Row = WindowsEvent & { hostname: string };

function EventsView({ rows, title, open, onClose, loading, error }: { rows: Row[]; title: string; open: boolean; onClose: () => void; loading: boolean; error: unknown }) {
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<Row | null>(null);
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return rows.filter((r) => !f || [r.hostname, r.provider, r.event_id, r.message, r.xml].some((v) => String(v).toLowerCase().includes(f))).slice(0, 2000);
  }, [rows, filter]);
  return (
    <Modal open={open} onOpenChange={(o) => !o && onClose()} title={title} width="max-w-[1200px]">
      {loading ? <Spinner label="Loading results" /> : null}
      {error ? <ErrorNotice error={error} /> : null}
      <SearchInput value={filter} onChange={setFilter} placeholder="Filter (also searches the event XML)" label="Filter" className="mb-3 max-w-md" />
      <div className="max-h-[62vh] overflow-auto">
        {shown.length === 0 && !loading ? (
          <EmptyState title="No events" />
        ) : (
          <table className="w-full text-left text-[12.5px]">
            <thead className="sticky top-0 bg-surface">
              <tr className="border-b border-border text-[11.5px] font-semibold tracking-wide text-faint uppercase">
                <th className="px-2 py-1.5">Time (UTC)</th>
                <th className="px-2 py-1.5">Device</th>
                <th className="px-2 py-1.5">Level</th>
                <th className="px-2 py-1.5">Source</th>
                <th className="px-2 py-1.5">ID</th>
                <th className="px-2 py-1.5">Message</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => (
                <tr key={`${r.hostname}-${r.record_id}`} onClick={() => setSelected(r)} className="cursor-pointer border-b border-border hover:bg-surface-2">
                  <td className="px-2 py-1.5 whitespace-nowrap tabular-nums text-muted">{utcTime(r.time)}</td>
                  <td className="px-2 py-1.5 text-fg">{r.hostname}</td>
                  <td className="px-2 py-1.5 text-muted">{r.level}</td>
                  <td className="max-w-56 truncate px-2 py-1.5 text-fg">{r.provider}</td>
                  <td className="px-2 py-1.5">
                    <Mono>{r.event_id}</Mono>
                  </td>
                  <td className="max-w-xl truncate px-2 py-1.5 text-muted">{r.message || <span className="text-faint">No message text</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {rows.length > shown.length ? <p className="mt-2 text-[12px] text-faint">Showing {shown.length} of {rows.length}; narrow the filter to see others.</p> : null}
      <Modal open={selected !== null} onOpenChange={(o) => !o && setSelected(null)} title={selected ? `${selected.hostname} · ${selected.provider} · Event ${selected.event_id}` : ""} width="max-w-3xl">
        {selected ? (
          <div className="space-y-3">
            <p className="text-[12.5px] text-muted">
              {absoluteTime(selected.time)} · record {selected.record_id} · level {selected.level}
            </p>
            <pre className="max-h-64 overflow-auto rounded-md border border-border bg-surface-2 p-3 font-sans text-[13px] whitespace-pre-wrap text-fg">{selected.message || "No message text (the event XML has the data)."}</pre>
            <pre className="max-h-80 overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[12px] whitespace-pre-wrap text-muted">{selected.xml}</pre>
          </div>
        ) : null}
      </Modal>
    </Modal>
  );
}

export function HuntPage() {
  const { hunt = "" } = useParams();
  const q = useQuery({
    queryKey: ["hunt", hunt],
    queryFn: ({ signal }) => get<Hunt>(`/api/v1/hunts/${hunt}`, signal),
    refetchInterval: (query) => (query.state.data?.targets.some((t) => active.has(t.status)) ? 5000 : false),
  });
  const [view, setView] = useState<{ title: string; targets: HuntTarget[] } | null>(null);
  const [rows, setRows] = useState<Row[]>([]);
  const [matchRows, setMatchRows] = useState<MatchRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [stopping, setStopping] = useState(false);
  const cancel = useMutation({ mutationFn: () => post(`/api/v1/hunts/${hunt}/cancel`), onSettled: () => void q.refetch() });
  // Results already read stay in memory, so reopening does not read (and
  // record) them again.
  const cache = useRef(new Map<string, ActionResult>());

  // Reads the chosen devices' results (six at a time; a device that fails is
  // skipped and counted) and merges their events, newest first.
  const open = async (title: string, targets: HuntTarget[]) => {
    setView({ title, targets });
    setRows([]);
    setMatchRows([]);
    setLoadError(null);
    setLoading(true);
    let failed = 0;
    const queue = [...targets];
    const worker = async () => {
      for (let t = queue.shift(); t; t = queue.shift()) {
        if (cache.current.has(t.job_id)) continue;
        try {
          const r = await get<ActionResult>(`/api/v1/hunts/${hunt}/jobs/${t.job_id}/result`);
          cache.current.set(t.job_id, r);
        } catch {
          failed++;
        }
      }
    };
    await Promise.all(Array.from({ length: 6 }, worker));
    const merged: Row[] = [];
    const found: MatchRow[] = [];
    for (const t of targets) {
      const r = cache.current.get(t.job_id);
      for (const ev of r?.event_log?.events ?? []) if (merged.length < MAX_ROWS) merged.push({ ...ev, hostname: t.hostname });
      for (const m of r?.hunt?.matches ?? []) if (found.length < MAX_ROWS) found.push({ ...m, hostname: t.hostname });
    }
    merged.sort((a, b) => b.time - a.time);
    setMatchRows(found);
    if (failed) setLoadError(new Error(`${failed} ${failed === 1 ? "device's result" : "devices' results"} could not be read (results without a case are kept for 24 hours).`));
    setRows(merged);
    setLoading(false);
  };

  if (q.isPending) return <div className="p-8"><Spinner label="Loading search" /></div>;
  if (q.isError) return <div className="p-8"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></div>;
  const h = q.data;
  const f = h.filter;
  const indicators = h.kind === "indicators" ? (h.spec?.indicators ?? []) : null;
  const done = h.targets.filter(usable);
  const waiting = h.targets.filter((t) => active.has(t.status)).length;
  const matches = done.reduce((n, t) => n + t.events, 0);
  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <Link to="/hunting" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-fg">
        <ArrowLeft className="size-3.5" /> Hunting
      </Link>
      <PageHeader
        title={indicators ? `Indicator hunt · ${indicators.length} ${indicators.length === 1 ? "indicator" : "indicators"}` : `Log search · ${f.channel}`}
        subtitle={
          indicators ? (
            <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
              {indicators.slice(0, 6).map((i) => (
                <IndicatorText key={`${i.type}:${i.value}`} i={i} />
              ))}
              {indicators.length > 6 ? <span className="text-faint">and {indicators.length - 6} more</span> : null}
              <span className="text-muted">{h.spec?.files ? "· files in common locations searched" : "· files not searched"}</span>
            </span>
          ) : (
          <span>
            {utcTime(f.from)} → {utcTime(f.to)}
            {f.level >= 0 ? ` · level ${f.level}` : ""}
            {f.event_id >= 0 ? ` · event ID ${f.event_id}` : ""}
            {f.provider ? ` · provider ${f.provider}` : ""}
            {f.xpath ? (
              <>
                {" · "}
                <Mono className="text-[12px]">{f.xpath}</Mono>
              </>
            ) : null}
          </span>
          )
        }
        actions={
          <span className="flex items-center gap-2">
            {h.case_id !== LIVE ? (
              <Link to={`/cases/${h.case_id}`} className="text-[13px] text-accent hover:underline">
                Open the case
              </Link>
            ) : (
              <Tip label="Results of a search without a case are kept for 24 hours after each device answers.">
                <span className="text-[12.5px] text-faint">No case</span>
              </Tip>
            )}
            <Button icon={<ListTree className="size-4" />} disabled={done.length === 0} onClick={() => void open(indicators ? "All matches" : "All matching events", done)}>
              {indicators ? "All matches" : "All events"}
            </Button>
            {!h.cancelled_at && waiting ? (
              <Button variant="danger" icon={<Square className="size-3.5" />} onClick={() => setStopping(true)}>
                Stop waiting
              </Button>
            ) : null}
          </span>
        }
      />
      <div className="mb-4 flex flex-wrap gap-x-6 gap-y-1 text-[13px] text-muted">
        <span>
          {h.targets.length - waiting} of {h.targets.length} devices answered
        </span>
        <span>
          {matches} {indicators ? "matches" : "matching events"}
        </span>
        {waiting && !h.cancelled_at ? <span>Waiting until {absoluteTime(h.expires_at)}</span> : null}
        {h.cancelled_at ? <span>Stopped {relativeTime(h.cancelled_at)}</span> : null}
        <span>
          Started {relativeTime(h.created_at)} by {h.actor}
        </span>
      </div>
      {cancel.isError ? <ErrorNotice error={cancel.error} /> : null}
      {h.problems.length ? (
        <Panel title="Not searched" className="mb-4">
          <ul className="space-y-1 text-[12.5px]">
            {h.problems.map((p) => (
              <li key={p.device_id}>
                <span className="text-fg">{p.hostname}</span> <span className="text-muted">— {p.reason}</span>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
      <Panel title="Devices" bodyClassName="p-0">
        <ul className="divide-y divide-border">
          {h.targets.map((t) => {
            const s = state(t);
            return (
              <li key={t.job_id} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-[13px]">
                <Link to={`/devices/${t.device_id}`} className="min-w-40 font-medium text-fg hover:underline">
                  {t.hostname || t.device_id.slice(0, 12)}
                </Link>
                <Badge tone={s.tone} dot={active.has(t.status)}>
                  {s.label}
                </Badge>
                {usable(t) && indicators ? (
                  <span className={t.events ? "font-medium text-danger tabular-nums" : "text-muted tabular-nums"}>
                    {t.events} {t.events === 1 ? "match" : "matches"}
                    {t.more ? " (first 1,000; more matched)" : ""}
                    <span className="font-normal text-muted">{t.skipped ? ` · ${t.skipped} files skipped` : ""}</span>
                  </span>
                ) : usable(t) ? (
                  <span className="text-muted tabular-nums">
                    {t.events} {t.events === 1 ? "event" : "events"}
                    {t.more ? " (newest 250; more matched)" : ""}
                    {t.skipped ? ` · ${t.skipped} skipped` : ""}
                  </span>
                ) : null}
                {t.searched === "partial" ? <span className="text-warn">Stopped at the 15-minute limit; not every file was searched.</span> : null}
                {t.searched && t.searched !== "ok" && t.searched !== "partial" ? <span className="text-warn">{searched[t.searched] ?? t.searched}</span> : null}
                {t.status === "failed" || (t.status === "expired" && t.outcome !== "purged") ? <span className="text-danger">{t.status === "expired" ? "The device did not come online within 7 days." : (reasons[t.outcome] ?? t.outcome)}</span> : null}
                <span className="flex-1" />
                {usable(t) && t.events > 0 ? (
                  <Button size="sm" icon={<Eye className="size-3.5" />} onClick={() => void open(t.hostname, [t])}>
                    View
                  </Button>
                ) : null}
              </li>
            );
          })}
        </ul>
      </Panel>
      <p className="mt-2 text-[12px] text-faint">{h.case_id !== LIVE ? "Opening results is recorded in the case's custody log." : "Opening results is recorded in the audit log."}</p>
      {view && !indicators ? <EventsView rows={rows} title={view.title} open onClose={() => setView(null)} loading={loading} error={loadError} /> : null}
      {view && indicators ? (
        <Modal open onOpenChange={(o) => !o && setView(null)} title={view.title} width="max-w-[1200px]">
          {loading ? <Spinner label="Loading results" /> : null}
          {loadError ? <ErrorNotice error={loadError} /> : null}
          <div className="max-h-[66vh] overflow-auto">{!loading ? <MatchesTable rows={matchRows} devices={view.targets.length > 1} /> : null}</div>
        </Modal>
      ) : null}
      <ConfirmDialog
        open={stopping}
        onOpenChange={setStopping}
        title="Stop waiting for devices"
        confirmLabel="Stop"
        danger
        onConfirm={async () => {
          await cancel.mutateAsync();
          setStopping(false);
        }}
      >
        <p className="text-[13px] text-fg">Devices that have not started the search will not run it. Searches already running finish and their results are kept.</p>
      </ConfirmDialog>
    </div>
  );
}
