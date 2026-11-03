import { useEffect, useState } from "react";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Download, Layers, RefreshCw } from "lucide-react";
import { get, post } from "../../lib/api";
import { bytes, relativeTime } from "../../lib/format";
import type { ArtefactsManifest, EvidenceCollection, TablePage } from "../../lib/types";
import { Modal } from "../../components/Dialog";
import { Badge, Button, ErrorNotice, Field, Input, Select, Spinner, Tip, type Tone } from "../../components/ui";

// Browses the artefacts the server parsed from a triage package, registry
// hive or event log: one table per artefact, paged on the server with a
// text and time filter. Opening the results and each download are recorded
// in the custody log (or, for console results, as session activity).

const parseStates: Record<string, { label: string; tone: Tone }> = {
  queued: { label: "Parsing queued", tone: "neutral" },
  running: { label: "Parsing", tone: "info" },
  succeeded: { label: "Parsed", tone: "ok" },
  failed: { label: "Parsing failed", tone: "danger" },
};

export const parseReasons: Record<string, string> = {
  quota: "The evidence store quota has no room for the parsed results.",
  output_limit: "The parsed results passed their 4 GiB limit.",
  time_limit: "Parsing took longer than two hours.",
  crashed: "The parsing process stopped three times (out of memory, or the server restarted).",
  unreadable: "The collection could not be read.",
  failed: "Parsing failed.",
};

export function parseable(c: EvidenceCollection): boolean {
  return c.status === "succeeded" && (c.source === "triage" || c.source === "hive" || c.source === "evtx");
}

// ParseStatus is the parse line of a collection: its state, and buttons to
// view the results or parse (again).
export function ParseStatus({ c, base, canParse, onView, onQueued }: { c: EvidenceCollection; base: string; canParse: boolean; onView: () => void; onQueued: () => void }) {
  const parse = useMutation({ mutationFn: () => post(`${base}/parse`, {}), onSuccess: onQueued });
  if (!parseable(c)) return null;
  const p = c.parse;
  const busy = p?.status === "queued" || p?.status === "running";
  const rows = (p?.tables ?? []).reduce((n, t) => n + t.rows, 0);
  return (
    <div className="flex flex-wrap items-center gap-2 text-muted">
      {p ? (
        <Badge tone={parseStates[p.status]?.tone ?? "neutral"} dot={busy}>
          {parseStates[p.status]?.label ?? p.status}
        </Badge>
      ) : (
        <span>Not parsed</span>
      )}
      {p?.status === "succeeded" ? (
        <span>
          {p.tables.length} {p.tables.length === 1 ? "table" : "tables"}, {rows.toLocaleString()} rows · {bytes(p.size)}
          {p.finished_at ? ` · ${relativeTime(p.finished_at)}` : ""}
        </span>
      ) : null}
      {p?.status === "failed" ? <span className="text-danger">{parseReasons[p.outcome] ?? p.outcome}</span> : null}
      {p?.status === "succeeded" ? (
        <Button size="sm" icon={<Layers className="size-3.5" />} onClick={onView}>
          View parsed
        </Button>
      ) : null}
      {canParse && !busy ? (
        <Tip label="Parse the collection on the server (again), for example after an update improved the parsers. The results count toward the evidence quota.">
          <span>
            <Button size="sm" variant="ghost" icon={<RefreshCw className="size-3.5" />} loading={parse.isPending} onClick={() => parse.mutate()}>
              {p ? "Parse again" : "Parse"}
            </Button>
          </span>
        </Tip>
      ) : null}
      {parse.isError ? <ErrorNotice error={parse.error} /> : null}
    </div>
  );
}

const cell = "max-w-[28rem] truncate border-b border-border px-2 py-1 align-top text-[12px] whitespace-nowrap";
const head = "border-b border-border-strong px-2 py-1.5 text-left text-[11.5px] font-medium text-muted whitespace-nowrap";

// datetime-local text (local time) to RFC 3339 UTC, or "" when empty.
function instant(v: string): string {
  if (!v) return "";
  const t = new Date(v);
  return isNaN(t.getTime()) ? "" : t.toISOString();
}

export function ArtefactsViewer({ base, job, open, onClose, recordedIn }: { base: string; job: EvidenceCollection; open: boolean; onClose: () => void; recordedIn?: string }) {
  const manifest = useQuery({ queryKey: ["parsed-manifest", base], queryFn: ({ signal }) => get<ArtefactsManifest>(`${base}/parsed`, signal), enabled: open, staleTime: Infinity });
  const tables = manifest.data?.tables ?? [];
  const [table, setTable] = useState("");
  useEffect(() => {
    if (!table && tables[0]) setTable(tables[0].name);
  }, [table, tables]);
  const [text, setText] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [offset, setOffset] = useState(0);
  const [errors, setErrors] = useState(false);
  const limit = 100;
  // A changed filter starts again at the first page.
  useEffect(() => setOffset(0), [table, text, from, to]);
  const params = new URLSearchParams({ offset: String(offset), limit: String(limit) });
  if (text) params.set("q", text);
  if (instant(from)) params.set("from", instant(from));
  if (instant(to)) params.set("to", instant(to));
  const url = `${base}/parsed/${table}`;
  const page = useQuery({
    queryKey: ["parsed-page", url, params.toString()],
    queryFn: ({ signal }) => get<TablePage>(`${url}?${params.toString()}`, signal),
    enabled: open && !!table,
    placeholderData: keepPreviousData,
    staleTime: Infinity,
  });
  const p = page.data;
  const current = tables.find((t) => t.name === table);
  const m = manifest.data;
  return (
    <Modal open={open} onOpenChange={(o) => !o && onClose()} title="Parsed artefacts" description={`${job.hostname || job.device_id.slice(0, 12)} · opening and downloads are recorded ${recordedIn ?? "in the custody log"}`} width="max-w-[1300px]">
      {manifest.isPending ? <Spinner label="Opening the parsed artefacts" /> : null}
      {manifest.isError ? <ErrorNotice error={manifest.error} retry={() => void manifest.refetch()} /> : null}
      {m ? (
        <div className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <Field label="Table">
              <Select value={table} onChange={(e) => setTable(e.target.value)} aria-label="Table">
                {tables.map((t) => (
                  <option key={t.name} value={t.name}>
                    {t.title} ({t.rows.toLocaleString()})
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Contains">
              <Input value={text} onChange={(e) => setText(e.target.value)} placeholder="Any column" maxLength={400} spellCheck={false} aria-label="Contains" />
            </Field>
            {current?.times.length ? (
              <>
                <Field label="From (local time)">
                  <Input type="datetime-local" step={1} value={from} onChange={(e) => setFrom(e.target.value)} aria-label="From" />
                </Field>
                <Field label="To">
                  <Input type="datetime-local" step={1} value={to} onChange={(e) => setTo(e.target.value)} aria-label="To" />
                </Field>
              </>
            ) : null}
            {table ? (
              <a href={`${url}?format=csv`} download className="mb-1 inline-flex items-center gap-1 text-[12.5px] text-accent hover:underline">
                <Download className="size-3.5" /> {table}.csv
              </a>
            ) : null}
            <a href={`${base}/parsed?format=zip`} download className="mb-1 inline-flex items-center gap-1 text-[12.5px] text-accent hover:underline">
              <Download className="size-3.5" /> All tables (ZIP)
            </a>
          </div>
          <p className="text-[12px] text-muted">
            Times are UTC{current?.times.length ? `; the time filter checks ${current.times.join(", ")}` : ""}. {current ? `${current.sources.toLocaleString()} ${current.sources === 1 ? "file" : "files"} parsed into this table. ` : ""}
            {m.errors.length ? (
              <button type="button" className="text-warn hover:underline" onClick={() => setErrors(!errors)}>
                {(m.errors.length + (m.errors_more ?? 0)).toLocaleString()} files could not be parsed
              </button>
            ) : null}
          </p>
          {errors ? (
            <ul className="max-h-40 overflow-auto rounded-md border border-border p-2 text-[11.5px] text-muted">
              {m.errors.map((e, i) => (
                <li key={i}>
                  <span className="font-mono">{e.path}</span> ({e.table}): {e.error}
                </li>
              ))}
              {m.errors_more ? <li>{m.errors_more.toLocaleString()} more not listed.</li> : null}
            </ul>
          ) : null}
          {tables.length === 0 ? <p className="text-[12.5px] text-muted">Nothing in this collection could be parsed yet.</p> : null}
          {page.isError ? <ErrorNotice error={page.error} retry={() => void page.refetch()} /> : null}
          <div className="max-h-[56vh] overflow-auto">
            {p ? (
              <table className="w-full border-collapse">
                <thead className="sticky top-0 bg-surface">
                  <tr>
                    {p.columns.map((c) => (
                      <th key={c} className={head}>
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {p.rows.map((row, i) => (
                    <tr key={i}>
                      {row.map((v, k) => (
                        <td key={k} className={cell} title={v.length > 60 ? v.replaceAll("|", "\n") : undefined}>
                          {v}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : page.isPending && table ? (
              <Spinner label="Reading the table" />
            ) : null}
            {p && p.rows.length === 0 ? <p className="p-3 text-[12.5px] text-muted">No rows match.</p> : null}
          </div>
          <div className="flex items-center justify-end gap-2 text-[12px] text-muted">
            {page.isFetching ? <Spinner label="Reading" /> : null}
            <span>{p && p.rows.length ? `Rows ${offset + 1}–${offset + p.rows.length}${p.more ? " of more" : ""}` : ""}</span>
            <Button size="sm" variant="ghost" icon={<ChevronLeft className="size-3.5" />} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
              Previous
            </Button>
            <Button size="sm" variant="ghost" icon={<ChevronRight className="size-3.5" />} disabled={!p?.more} onClick={() => setOffset(offset + limit)}>
              Next
            </Button>
          </div>
          <p className="text-[11.5px] text-faint">Parser version {m.parser}. Cells with several values separate them with |; hover a long cell to see it whole.</p>
        </div>
      ) : null}
    </Modal>
  );
}
