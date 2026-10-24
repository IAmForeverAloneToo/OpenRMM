import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Briefcase, CornerDownLeft, Download, Eye } from "lucide-react";
import { ApiError, get, post } from "../lib/api";
import { relativeTime } from "../lib/format";
import type { CaseSummary, EvidenceCollection, ResponseAction } from "../lib/types";
import { Modal } from "../components/Dialog";
import { Badge, Button, ErrorNotice, Field, Input, Mono, Segmented, Select, Tip, type Tone } from "../components/ui";
import { ActionViewer } from "./cases/ActionViewer";
import { progress, reasons, states } from "./cases/Collections";

// The device terminal is a live response session. Built-in commands run
// response actions and collections; with a case they are case
// evidence, without one the results are shown here for 24 hours.

type Choice = "none" | "existing" | "new";
type CaseBody = { case_id?: string; case_title?: string };

// note: what happens with a case (defaults to the live response wording).
export function CaseChoice({ open, choice, setChoice, caseId, setCaseId, title, setTitle, allowNone, note, noneNote }: { open: boolean; choice: Choice; setChoice: (c: Choice) => void; caseId: string; setCaseId: (v: string) => void; title: string; setTitle: (v: string) => void; allowNone: boolean; note?: string; noneNote?: string }) {
  const cases = useQuery({ queryKey: ["cases"], queryFn: ({ signal }) => get<{ cases: CaseSummary[] }>("/api/v1/cases", signal), enabled: open });
  const openCases = (cases.data?.cases ?? []).filter((c) => c.status === "open");
  useEffect(() => {
    if (choice === "existing" && !caseId && openCases[0]) setCaseId(openCases[0].id);
  }, [choice, caseId, openCases[0]?.id]);
  const options: { value: Choice; label: string }[] = [...(allowNone ? [{ value: "none" as Choice, label: "No case" }] : []), { value: "existing", label: "Open case" }, { value: "new", label: "New case" }];
  return (
    <div className="space-y-3">
      <Segmented label="Case" value={choice} onChange={setChoice} options={options} />
      {choice === "none" ? <p className="text-[12.5px] text-muted">{noneNote ?? "Commands are recorded in the audit log only. Results are shown in the session and kept for 24 hours. You can attach a case while the session runs."}</p> : null}
      {choice === "existing" ? (
        cases.isError ? (
          <ErrorNotice error={cases.error} />
        ) : openCases.length === 0 && !cases.isPending ? (
          <p className="text-[12.5px] text-warn">There is no open case. Create a new one instead.</p>
        ) : (
          <Field label="Case">
            <Select className="w-full" value={caseId} onChange={(e) => setCaseId(e.target.value)} aria-label="Case">
              {openCases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.title}
                </option>
              ))}
            </Select>
          </Field>
        )
      ) : null}
      {choice === "new" ? (
        <Field label="Case title">
          <Input value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} placeholder="Suspicious process on WS-042" autoFocus />
        </Field>
      ) : null}
      {choice !== "none" ? <p className="text-[12.5px] text-muted">{note ?? "The PowerShell session is recorded to the case as a transcript, and every command's result is stored there as hashed evidence."}</p> : null}
    </div>
  );
}

export function useCaseChoice(initial: Choice) {
  const [choice, setChoice] = useState<Choice>(initial);
  const [caseId, setCaseId] = useState("");
  const [title, setTitle] = useState("");
  const body: CaseBody | null = choice === "none" ? {} : choice === "existing" ? (caseId ? { case_id: caseId } : null) : title.trim() ? { case_title: title.trim() } : null;
  return { props: { choice, setChoice, caseId, setCaseId, title, setTitle }, body };
}

export function StartLiveResponse({ deviceId, open, onOpenChange }: { deviceId: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate();
  const c = useCaseChoice("none");
  const start = useMutation({
    mutationFn: (body: CaseBody) => post<{ id: string }>(`/api/v1/devices/${deviceId}/terminal`, body),
    onSuccess: (r) => navigate(`/devices/${deviceId}/terminal/${r.id}`),
  });
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Start live response"
      description="A PowerShell console as SYSTEM with built-in response commands (type help). Nothing is shown on the device."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!c.body} loading={start.isPending} onClick={() => c.body && start.mutate(c.body)}>
            Start
          </Button>
        </>
      }
    >
      <CaseChoice open={open} allowNone {...c.props} />
      {start.isError ? (
        <div className="mt-3">
          <ErrorNotice error={start.error} />
        </div>
      ) : null}
    </Modal>
  );
}

export function AttachCase({ session, open, onOpenChange, onAttached }: { session: string; open: boolean; onOpenChange: (o: boolean) => void; onAttached: (caseId: string) => void }) {
  const c = useCaseChoice("existing");
  const attach = useMutation({
    mutationFn: (body: CaseBody) => post<{ case_id: string }>(`/api/v1/terminal/${encodeURIComponent(session)}/case`, body),
    onSuccess: (r) => (onAttached(r.case_id), onOpenChange(false)),
  });
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Attach to a case"
      description="From now on the console is recorded to the case and new commands store their results there. Earlier results stay in the audit log only."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!c.body} loading={attach.isPending} onClick={() => c.body && attach.mutate(c.body)}>
            Attach
          </Button>
        </>
      }
    >
      <CaseChoice open={open} allowNone={false} {...c.props} />
      {attach.isError ? (
        <div className="mt-3">
          <ErrorNotice error={attach.error} />
        </div>
      ) : null}
    </Modal>
  );
}

type LogLine = { id: number; text: string; tone: "info" | "ok" | "danger"; reply?: string };

// A registry key or path goes in double quotes; a quote inside is doubled.
const quote = (s: string) => `"${s.replace(/"/g, '""')}"`;

export function commandFor(a: ResponseAction): string {
  // The viewed row's start time makes the server refuse a PID that now
  // belongs to another process.
  if (a.kind === "kill") return `kill ${a.pid}${a.tree ? " -tree" : ""}${a.start ? ` -start ${a.start}` : ""}`;
  if (a.kind === "registry") return `reg query ${quote(a.key)}`;
  if (a.kind === "processes") return "ps";
  if (a.kind === "connections") return "netstat";
  if (a.kind === "hunt") {
    // The console takes lines up to 8,192 characters.
    const line = `hunt${a.hunt.files ? " -files" : ""} ${a.hunt.indicators.map((i) => quote(`${i.type}:${i.value}`)).join(" ")}`;
    return line.length <= 8192 ? line : `hunt (${a.hunt.indicators.length} indicators)`;
  }
  return a.kind;
}

const quick: { label: string; line: string; tip: string }[] = [
  { label: "ps", line: "ps", tip: "Processes with command lines, users and image hashes" },
  { label: "netstat", line: "netstat", tip: "TCP/UDP connections with owning processes" },
  { label: "services", line: "services", tip: "Services and drivers with binaries and hashes" },
  { label: "tasks", line: "tasks", tip: "Scheduled tasks" },
  { label: "persistence", line: "persistence", tip: "Autostart entries with programs, hashes and signatures" },
  { label: "triage", line: "triage", tip: "Collect a Full triage package (ZIP from a shadow copy)" },
  { label: "help", line: "help", tip: "All built-in commands" },
];

export function LiveConsole({ session, caseId, active }: { session: string; caseId: string; active: boolean }) {
  const qc = useQueryClient();
  const base = `/api/v1/terminal/${encodeURIComponent(session)}`;
  const [line, setLine] = useState("");
  const [log, setLog] = useState<LogLine[]>([]);
  const [history, setHistory] = useState<string[]>([]);
  const [cursor, setCursor] = useState(-1);
  const [viewing, setViewing] = useState<EvidenceCollection | null>(null);
  const logEnd = useRef<HTMLDivElement>(null);
  const counter = useRef(0);
  const jobs = useQuery({
    queryKey: ["live-jobs", session],
    queryFn: ({ signal }) => get<{ jobs: EvidenceCollection[] }>(`${base}/jobs`, signal),
    refetchInterval: (q) => (q.state.data?.jobs.some((j) => ["queued", "dispatched", "uploading", "verifying"].includes(j.status)) || active ? 2000 : false),
  });
  const run = useMutation({
    mutationFn: (text: string) => post<{ id?: string; label?: string; help?: string }>(`${base}/command`, { line: text }),
  });
  // Block body: scrollIntoView may return a promise, which is not a cleanup.
  useEffect(() => {
    logEnd.current?.scrollIntoView({ block: "nearest" });
  }, [log.length]);

  const add = (text: string, tone: LogLine["tone"], reply?: string) => setLog((l) => [...l.slice(-49), { id: ++counter.current, text, tone, reply }]);
  const submit = async (text: string) => {
    const t = text.trim();
    if (!t || run.isPending) return;
    setHistory((h) => [t, ...h.filter((x) => x !== t)].slice(0, 50));
    setCursor(-1);
    setLine("");
    try {
      const r = await run.mutateAsync(t);
      if (r.help) add(t, "info", r.help);
      else add(t, "ok", `Queued: ${r.label ?? ""}. The result appears under Results.`);
      void qc.invalidateQueries({ queryKey: ["live-jobs", session] });
    } catch (e) {
      add(t, "danger", e instanceof ApiError ? e.message : "The command could not be sent.");
    }
  };
  const queue = async (a: ResponseAction) => {
    const t = commandFor(a);
    const r = await run.mutateAsync(t);
    add(t, "ok", `Queued: ${r.label ?? ""}. The result appears under Results.`);
    void qc.invalidateQueries({ queryKey: ["live-jobs", session] });
  };

  const list = jobs.data?.jobs ?? [];
  const recordedIn = (j: EvidenceCollection) => (j.case_id === caseId && caseId ? "in the case's custody log" : "in the audit log");
  const cancel = useMutation({
    mutationFn: (job: string) => post(`${base}/jobs/${job}/cancel`),
    onSettled: () => void qc.invalidateQueries({ queryKey: ["live-jobs", session] }),
  });
  return (
    <div className="flex min-h-0 flex-col gap-3">
      <div className="rounded-lg border border-border bg-surface">
        <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-3 py-2">
          <span className="mr-1 text-[12px] font-medium text-muted">Response commands</span>
          {quick.map((q) => (
            <Tip key={q.label} label={q.tip}>
              <span>
                <Button size="sm" variant="ghost" disabled={!active || run.isPending} onClick={() => void submit(q.line)}>
                  {q.label}
                </Button>
              </span>
            </Tip>
          ))}
        </div>
        <form
          className="flex items-center gap-2 px-3 py-2"
          onSubmit={(e) => {
            e.preventDefault();
            void submit(line);
          }}
        >
          <span className="font-mono text-[13px] text-accent">&gt;</span>
          <input
            value={line}
            onChange={(e) => setLine(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowUp" && history.length) {
                e.preventDefault();
                const n = Math.min(cursor + 1, history.length - 1);
                setCursor(n);
                setLine(history[n] ?? "");
              } else if (e.key === "ArrowDown" && cursor >= 0) {
                e.preventDefault();
                const n = cursor - 1;
                setCursor(n);
                setLine(n >= 0 ? (history[n] ?? "") : "");
              }
            }}
            disabled={!active}
            maxLength={8192}
            spellCheck={false}
            autoComplete="off"
            aria-label="Response command"
            placeholder={active ? 'kill 4242 -tree · get "C:\\Users\\alice\\Downloads\\invoice.pdf" · reg query HKLM\\…\\Run · help' : "The session has ended."}
            className="h-8 min-w-0 flex-1 bg-transparent font-mono text-[13px] text-fg outline-none placeholder:text-faint"
          />
          <Button size="sm" type="submit" icon={<CornerDownLeft className="size-3.5" />} disabled={!active || !line.trim()} loading={run.isPending}>
            Run
          </Button>
        </form>
        {log.length ? (
          <div className="max-h-56 overflow-auto border-t border-border px-3 py-2 font-mono text-[12px]">
            {log.map((l) => (
              <div key={l.id} className="mb-1.5">
                <div className="text-fg">&gt; {l.text}</div>
                {l.reply ? <pre className={l.tone === "danger" ? "whitespace-pre-wrap text-danger" : l.tone === "ok" ? "whitespace-pre-wrap text-ok" : "whitespace-pre-wrap text-muted"}>{l.reply}</pre> : null}
              </div>
            ))}
            <div ref={logEnd} />
          </div>
        ) : null}
      </div>
      <div className="min-h-0 rounded-lg border border-border bg-surface">
        <div className="flex items-center justify-between border-b border-border px-3 py-2">
          <span className="text-[13px] font-medium text-fg">Results</span>
          <span className="text-[12px] text-faint">{caseId ? "New results are stored in the case" : "Not in a case: kept 24 hours"}</span>
        </div>
        {cancel.isError ? (
          <div className="p-3">
            <ErrorNotice error={cancel.error} />
          </div>
        ) : null}
        {jobs.isError ? (
          <div className="p-3">
            <ErrorNotice error={jobs.error} retry={() => void jobs.refetch()} />
          </div>
        ) : list.length === 0 ? (
          <p className="px-3 py-4 text-[12.5px] text-muted">Results of response commands appear here.</p>
        ) : (
          <ul className="max-h-[50vh] divide-y divide-border overflow-auto">
            {list.map((j) => {
              const s: { label: string; tone: Tone } = j.source === "action" && j.status === "dispatched" ? { label: "Running", tone: "info" } : states[j.status];
              const file = `${base}/jobs/${j.id}/file`;
              return (
                <li key={j.id} className="flex flex-wrap items-start gap-2 px-3 py-2 text-[12.5px]">
                  <div className="min-w-0 flex-1 space-y-0.5">
                    <div className="flex flex-wrap items-center gap-2">
                      {j.source === "hive" ? (
                        <span className="text-fg">
                          Hive <Mono>{j.path}</Mono>
                        </span>
                      ) : j.source === "triage" ? (
                        <span className="text-fg">
                          Triage package <Mono>{j.path}</Mono>
                        </span>
                      ) : j.source === "evtx" ? (
                        <span className="text-fg">
                          Event log <Mono>{j.path}</Mono>
                          {j.query ? <Mono className="ml-1 text-[11px] text-muted">{j.query}</Mono> : null}
                        </span>
                      ) : (
                        <Mono className="break-all text-fg">{j.path}</Mono>
                      )}
                      <Badge tone={s.tone} dot={["queued", "dispatched", "uploading", "verifying"].includes(j.status)}>
                        {s.label}
                        {progress(j)}
                      </Badge>
                      {j.case_id === caseId && caseId ? (
                        <Tip label="Stored in the case as hashed evidence">
                          <span>
                            <Briefcase className="size-3.5 text-muted" />
                          </span>
                        </Tip>
                      ) : null}
                    </div>
                    <div className="text-muted">{relativeTime(j.created_at)}</div>
                    {j.status === "failed" || j.status === "expired" ? <div className="text-danger">{reasons[j.outcome] ?? j.outcome}</div> : null}
                  </div>
                  {j.status === "succeeded" && j.source === "action" ? (
                    <Button size="sm" icon={<Eye className="size-3.5" />} onClick={() => setViewing(j)}>
                      View
                    </Button>
                  ) : null}
                  {j.source === "action" ? j.status === "queued" : ["queued", "dispatched", "uploading"].includes(j.status) ? (
                    <Button size="sm" variant="ghost" loading={cancel.isPending && cancel.variables === j.id} onClick={() => cancel.mutate(j.id)}>
                      Cancel
                    </Button>
                  ) : null}
                  {j.status === "succeeded" ? (
                    <a href={file} download className="inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 text-[12.5px] font-medium text-fg hover:bg-surface-3">
                      <Download className="size-3.5" /> Download
                    </a>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </div>
      {viewing ? (
        <ActionViewer
          caseId={viewing.case_id}
          job={viewing}
          open
          onClose={() => setViewing(null)}
          onQueued={() => void qc.invalidateQueries({ queryKey: ["live-jobs", session] })}
          source={{ fileUrl: `${base}/jobs/${viewing.id}/file`, queue, recordedIn: recordedIn(viewing), actionIn: caseId ? "in the case's custody log" : "in the audit log", queued: "Queued; the result appears under Results." }}
        />
      ) : null}
    </div>
  );
}
