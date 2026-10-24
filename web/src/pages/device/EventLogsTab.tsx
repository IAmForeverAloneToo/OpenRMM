import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { FileDown, FileSearch } from "lucide-react";
import { ApiError, get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { absoluteTime, relativeTime, utcTime } from "../../lib/format";
import type { DeviceDetail, EventFilter, EventQuery, WindowsEvent } from "../../lib/types";
import { useAccount } from "../../lib/session";
import { Modal } from "../../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Mono, Panel, Segmented, Select, Spinner, Tip, Toolbar, cx, type Tone } from "../../components/ui";
import { SkippedBadge } from "./SkippedBadge";
import { CaseChoice, useCaseChoice } from "../LiveResponse";
import { OperationStatus } from "../../components/status";

const levels: Record<number, { label: string; tone: Tone }> = {
  0: { label: "Information", tone: "neutral" },
  1: { label: "Critical", tone: "danger" },
  2: { label: "Error", tone: "danger" },
  3: { label: "Warning", tone: "warn" },
  4: { label: "Information", tone: "neutral" },
  5: { label: "Verbose", tone: "neutral" },
};
const ranges = [
  { value: "3600", label: "Last hour" },
  { value: "86400", label: "Last 24 hours" },
  { value: "604800", label: "Last 7 days" },
  { value: "2678400", label: "Last 31 days" },
];

function LevelBadge({ level }: { level: number }) {
  const l = levels[level] ?? { label: `Level ${level}`, tone: "neutral" as Tone };
  return <Badge tone={l.tone}>{l.label}</Badge>;
}

// An .evtx export of the whole log or the current filter, into a
// case as evidence.
function ExportDialog({ deviceId, open, onOpenChange, filter }: { deviceId: string; open: boolean; onOpenChange: (o: boolean) => void; filter: EventFilter }) {
  const [scope, setScope] = useState<"filter" | "whole">("filter");
  const c = useCaseChoice("existing");
  const run = useMutation({ mutationFn: (body: object) => post<{ id: string; case_id: string }>(`/api/v1/devices/${deviceId}/event-logs/export`, body) });
  const body = c.body ? { ...c.body, channel: filter.channel, ...(scope === "filter" ? { filter: { ...filter, before: 0 } } : {}) } : null;
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={`Export ${filter.channel} as .evtx`}
      description="The agent exports the log with Windows' own exporter and uploads it as hashed case evidence, recorded in the custody log."
      footer={
        run.isSuccess ? (
          <Button variant="primary" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button variant="primary" icon={<FileDown className="size-4" />} disabled={!body} loading={run.isPending} onClick={() => body && run.mutate(body)}>
              Export
            </Button>
          </>
        )
      }
    >
      {run.isSuccess ? (
        <p className="text-[13px] text-fg">
          Export queued.{" "}
          <Link to={`/cases/${run.data.case_id}`} className="text-accent hover:underline">
            Open the case
          </Link>{" "}
          to follow it and download the file.
        </p>
      ) : (
        <div className="space-y-4">
          <Segmented
            label="Export"
            value={scope}
            onChange={setScope}
            options={[
              { value: "filter", label: "Current filter" },
              { value: "whole", label: "Whole log" },
            ]}
          />
          <p className="text-[12.5px] text-muted">
            {scope === "whole" ? (
              "Every event the log holds now."
            ) : (
              <>
                Events from {utcTime(filter.from)} to {utcTime(filter.to)}
                {filter.level >= 0 ? `, level ${filter.level}` : ""}
                {filter.event_id >= 0 ? `, event ID ${filter.event_id}` : ""}
                {filter.provider ? `, provider ${filter.provider}` : ""}
                {filter.xpath ? (
                  <>
                    , XPath <Mono className="text-[11.5px]">{filter.xpath}</Mono>
                  </>
                ) : null}
                .
              </>
            )}
          </p>
          <CaseChoice open={open} allowNone={false} note="The .evtx file is stored in the case; downloads are recorded in its custody log." {...c.props} />
          {run.isError ? <ErrorNotice error={run.error} /> : null}
        </div>
      )}
    </Modal>
  );
}

export function EventLogsTab({ d }: { d: DeviceDetail }) {
  const account = useAccount();
  const [params, setParams] = useSearchParams();
  const queryId = params.get("query") ?? "";
  const [channel, setChannel] = useState("System");
  const [range, setRange] = useState("86400");
  const [level, setLevel] = useState("-1");
  const [provider, setProvider] = useState("");
  const [eventId, setEventId] = useState("");
  const [other, setOther] = useState("");
  const [limit, setLimit] = useState("25");
  const [xpath, setXpath] = useState("");
  const [exporting, setExporting] = useState<EventFilter | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [selected, setSelected] = useState<WindowsEvent | null>(null);

  const q = useQuery({
    queryKey: ["event-query", d.device.id, queryId],
    queryFn: ({ signal }) => get<EventQuery>(`/api/v1/devices/${d.device.id}/event-logs/${queryId}`, signal),
    enabled: queryId !== "",
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      return s === "queued" || s === "dispatched" ? 1500 : false;
    },
  });

  const run = async (filter: EventFilter) => {
    setBusy(true);
    setError(null);
    try {
      const id = newOperationID();
      await post(`/api/v1/devices/${d.device.id}/event-logs`, { id, filter });
      const next = new URLSearchParams(params);
      next.set("query", id);
      setParams(next, { replace: true });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  // The filter in the form, or null (with the reason shown) when invalid.
  const formFilter = (): EventFilter | null => {
    const to = Math.floor(Date.now() / 1000);
    const id = eventId.trim() === "" ? -1 : Number(eventId);
    if (!Number.isInteger(id) || id < -1 || id > 65535) {
      setError(new Error("Event ID must be a number from 0 to 65535."));
      return null;
    }
    const name = channel === "other" ? other.trim() : channel;
    if (!name) {
      setError(new Error("Type the channel name, for example Microsoft-Windows-DNS-Client/Operational."));
      return null;
    }
    setError(null);
    return { channel: name, from: to - Number(range), to, level: Number(level), provider: provider.trim(), event_id: id, before: 0, limit: v2 ? Number(limit) : 25, xpath: v2 && canXPath ? xpath.trim() : "" };
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const f = formFilter();
    if (f) void run(f);
  };

  const support = d.event_logs.data;
  // Version 2 agents read any channel, take raw XPath and larger pages.
  const v2 = d.event_logs.capability.version >= 2;
  const canXPath = account.permissions.owner || account.permissions.response;
  const readable = (c: string) => (support ? (c === "System" ? support.system : c === "Application" ? support.application : (support.channels?.[c] ?? "")) : "");
  const short = (c: string) => c.replace(/^Microsoft-Windows-/, "");
  const channels = ["System", "Application", ...Object.keys(support?.channels ?? {}).sort((a, b) => (a === "Security" ? -1 : b === "Security" ? 1 : short(a).localeCompare(short(b))))];
  const readableCount = channels.filter((c) => readable(c) === "readable").length;
  const canQuery = account.permissions.events;
  const result = q.data?.result;
  const events = result?.events ?? [];
  const running = q.data && (q.data.status === "queued" || q.data.status === "dispatched");

  return (
    <div className="space-y-5">
      {canQuery ? (
        <Panel bodyClassName="p-0">
          <form onSubmit={submit}>
            <Toolbar>
              <Field label="Log">
                <Select value={channel} onChange={(e) => setChannel(e.target.value)} className="w-72" aria-label="Log">
                  {(v2 ? channels : ["System", "Application"]).map((c) => (
                    <option key={c} value={c}>
                      {short(c)}
                      {readable(c) && readable(c) !== "readable" ? ` (${readable(c)})` : ""}
                    </option>
                  ))}
                  {v2 ? <option value="other">Other channel…</option> : null}
                </Select>
              </Field>
              {channel === "other" ? (
                <Field label="Channel name">
                  <Input value={other} onChange={(e) => setOther(e.target.value)} placeholder="Microsoft-Windows-DNS-Client/Operational" className="w-80" maxLength={256} />
                </Field>
              ) : null}
              <Field label="Time range">
                <Select value={range} onChange={(e) => setRange(e.target.value)} className="w-40">
                  {ranges.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Level">
                <Select value={level} onChange={(e) => setLevel(e.target.value)} className="w-36">
                  <option value="-1">Any level</option>
                  <option value="1">Critical</option>
                  <option value="2">Error</option>
                  <option value="3">Warning</option>
                  <option value="4">Information</option>
                  <option value="5">Verbose</option>
                </Select>
              </Field>
              <Field label="Provider">
                <Input value={provider} onChange={(e) => setProvider(e.target.value)} placeholder="Any" className="w-52" maxLength={256} />
              </Field>
              <Field label="Event ID">
                <Input value={eventId} onChange={(e) => setEventId(e.target.value)} placeholder="Any" className="w-28" inputMode="numeric" maxLength={5} />
              </Field>
              {v2 ? (
                <Field label="Events">
                  <Select value={limit} onChange={(e) => setLimit(e.target.value)} className="w-24" aria-label="Events per page">
                    <option value="25">25</option>
                    <option value="100">100</option>
                    <option value="250">250</option>
                  </Select>
                </Field>
              ) : null}
              <div className="flex-1" />
              <div className="self-end">
                <span className="flex gap-2">
                  {v2 && canXPath ? (
                    <Tip label="Export the log, or the events matching this filter, as an .evtx file into a case">
                      <span>
                        <Button type="button" icon={<FileDown className="size-4" />} onClick={() => setExporting(formFilter())}>
                          Export .evtx
                        </Button>
                      </span>
                    </Tip>
                  ) : null}
                  <Button type="submit" variant="primary" icon={<FileSearch className="size-4" />} loading={busy || !!running}>
                    Search
                  </Button>
                </span>
              </div>
            </Toolbar>
            {v2 && canXPath ? (
              <details className="border-t border-border px-4 py-2" open={xpath !== ""}>
                <summary className="cursor-pointer text-[12.5px] text-muted hover:text-fg">XPath filter</summary>
                <Input
                  value={xpath}
                  onChange={(e) => setXpath(e.target.value)}
                  placeholder="*[EventData[Data[@Name='LogonType']='10']]"
                  className="mt-2 w-full font-mono text-[12.5px]"
                  maxLength={4096}
                  spellCheck={false}
                  aria-label="XPath filter"
                />
                <p className="mt-1 text-[12px] text-faint">One predicate of the form *[...], combined with the filters above by “and”.</p>
              </details>
            ) : null}
          </form>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border px-4 py-2 text-[12px] text-muted">
            {v2 ? (
              <span>
                {readableCount} of {channels.length} common logs readable{channel !== "other" && readable(channel) ? ` · ${channel}: ${readable(channel)}` : ""}
              </span>
            ) : (
              <>
                <span>System log: {readable("System") || "not reported"}</span>
                <span>Application log: {readable("Application") || "not reported"}</span>
              </>
            )}
            <span className="text-faint">Up to {v2 ? limit : 25} newest events per search · results kept 15 minutes</span>
          </div>
        </Panel>
      ) : (
        <Panel>
          <p className="text-muted">Your account cannot query event logs on this device.</p>
        </Panel>
      )}

      {error ? <ErrorNotice error={error} /> : null}

      {queryId === "" ? (
        <EmptyState icon={<FileSearch />} title="Search the device's event logs">
          Choose a log and time range, then Search. The agent reads the events directly from Windows.
        </EmptyState>
      ) : q.isPending ? (
        <Spinner label="Loading results" />
      ) : q.isError ? (
        q.error instanceof ApiError && q.error.status === 404 ? (
          <EmptyState title="These results have expired">Results are kept for 15 minutes. Run the search again.</EmptyState>
        ) : (
          <ErrorNotice error={q.error} retry={() => void q.refetch()} />
        )
      ) : (
        <Panel
          bodyClassName="p-0"
          title={
            <span className="flex items-center gap-2">
              {q.data!.filter.channel} log
              <OperationStatus status={q.data!.status} />
            </span>
          }
          actions={
            <span className="flex items-center gap-2">
              <SkippedBadge count={result?.skipped} one="event" many="events" />
              <span className="text-[12px] text-muted">
                {utcTime(q.data!.filter.from)} → {utcTime(q.data!.filter.to)}
              </span>
            </span>
          }
        >
          {running ? (
            <div className="p-4">
              <Spinner label="Waiting for the device" />
            </div>
          ) : result && result.outcome !== "ok" ? (
            <div className="p-4">
              <ErrorNotice error={new Error(`The device could not complete the query (${result.outcome.replaceAll("_", " ")}).`)} />
            </div>
          ) : events.length === 0 ? (
            <EmptyState title="No events matched" />
          ) : (
            <>
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-border text-[11.5px] font-semibold tracking-wide text-faint uppercase">
                    <th className="px-3 py-2">Time</th>
                    <th className="px-3 py-2">Level</th>
                    <th className="px-3 py-2">Source</th>
                    <th className="px-3 py-2">Event ID</th>
                    <th className="px-3 py-2">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev) => (
                    <tr key={ev.record_id} onClick={() => setSelected(ev)} className="cursor-pointer border-b border-border last:border-b-0 hover:bg-surface-2">
                      <td className="px-3 py-2 whitespace-nowrap">
                        <Tip label={absoluteTime(ev.time)}>
                          <span className="text-muted tabular-nums">{relativeTime(ev.time)}</span>
                        </Tip>
                      </td>
                      <td className="px-3 py-2">
                        <LevelBadge level={ev.level} />
                      </td>
                      <td className="max-w-56 truncate px-3 py-2 text-fg">{ev.provider}</td>
                      <td className="px-3 py-2">
                        <Mono>{ev.event_id}</Mono>
                      </td>
                      <td className="max-w-xl truncate px-3 py-2 text-muted">{ev.message || <span className="text-faint">{ev.message_status === "unavailable" ? "Message text not available on the device" : "No message text"}</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {/* A query with raw XPath continues only for those who may use XPath. */}
              {result?.more && canQuery && (!q.data!.filter.xpath || canXPath) ? (
                <div className="flex justify-center border-t border-border p-3">
                  <Button loading={busy} onClick={() => void run({ ...q.data!.filter, before: result.next_before })}>
                    Older events
                  </Button>
                </div>
              ) : null}
            </>
          )}
        </Panel>
      )}

      {exporting ? <ExportDialog deviceId={d.device.id} open onOpenChange={(o) => !o && setExporting(null)} filter={exporting} /> : null}
      <Modal open={selected !== null} onOpenChange={(o) => !o && setSelected(null)} title={selected ? `${selected.provider} · Event ${selected.event_id}` : ""} width="max-w-3xl">
        {selected ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3 text-[12.5px] text-muted">
              <LevelBadge level={selected.level} />
              <span>{absoluteTime(selected.time)}</span>
              <span>{utcTime(selected.time)}</span>
              <span>Record {selected.record_id}</span>
            </div>
            <pre className="max-h-64 overflow-auto rounded-md border border-border bg-surface-2 p-3 font-sans text-[13px] whitespace-pre-wrap text-fg">{selected.message || "Windows could not format a message for this event (the publisher's message resources are not available to the agent). The event XML below has the raw data."}
              {selected.message_status === "truncated" ? "\n\n[Message truncated]" : ""}</pre>
            <details>
              <summary className="cursor-pointer text-[12.5px] text-muted hover:text-fg">Event XML{selected.xml_truncated ? " (truncated)" : ""}</summary>
              <pre className={cx("mt-2 max-h-80 overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[12px] whitespace-pre-wrap text-muted")}>{selected.xml}</pre>
            </details>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
