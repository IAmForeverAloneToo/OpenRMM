import { useState } from "react";
import { Link, useParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, CircleCheck, Download, ShieldAlert } from "lucide-react";
import { get, post } from "../../lib/api";
import { absoluteTime } from "../../lib/format";
import type { CaseDetail, CustodyEntry } from "../../lib/types";
import { Modal } from "../../components/Dialog";
import { Collections } from "./Collections";
import { Badge, Button, EmptyState, ErrorNotice, Field, Mono, Panel, Spinner, Tip } from "../../components/ui";

// A case with its chain-of-custody log, notes and status.

const actions: Record<string, string> = {
  case_opened: "Case opened",
  case_closed: "Case closed",
  case_reopened: "Case reopened",
  note: "Note",
  collection_requested: "Collection requested",
  evidence_collected: "Evidence collected",
  evidence_downloaded: "Evidence downloaded",
  collection_failed: "Collection failed",
  collection_expired: "Collection expired",
  collection_cancelled: "Collection cancelled",
  terminal_opened: "Live response recorded",
  terminal_transcript: "Terminal transcript stored",
};

const textareaClass =
  "min-h-24 w-full rounded-md border border-border bg-surface px-2.5 py-2 text-[13px] text-fg placeholder:text-faint transition-colors hover:border-border-strong focus:border-accent focus:outline-none";

function Entry({ e, actors }: { e: CustodyEntry; actors: Record<string, string> }) {
  const at = Date.parse(e.at) / 1000;
  const details = Object.entries(e.details).filter(([k]) => !(e.action === "note" && k === "text") && !(e.action === "case_opened" && k === "title"));
  return (
    <li className="flex gap-3 px-4 py-3">
      <div className="w-10 shrink-0 pt-0.5 text-right text-[11.5px] text-faint tabular-nums">#{e.sequence}</div>
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
          <span className="font-medium text-fg">{actions[e.action] ?? e.action}</span>
          <Tip label={e.actor}>
            <span className="text-muted">{actors[e.actor] ?? e.actor}</span>
          </Tip>
          <Tip label={e.at}>
            <span className="text-faint tabular-nums">{absoluteTime(at)}</span>
          </Tip>
          {e.device_id ? (
            <Link to={`/devices/${e.device_id}`} className="text-accent hover:underline">
              <Mono className="text-[11.5px]">{e.device_id.slice(0, 12)}</Mono>
            </Link>
          ) : null}
          {e.outcome !== "success" ? <Badge tone="danger">{e.outcome}</Badge> : null}
        </div>
        {e.action === "note" ? <p className="text-[13px] whitespace-pre-wrap text-fg">{e.details.text}</p> : null}
        {e.action === "case_opened" ? <p className="text-[13px] text-fg">{e.details.title}</p> : null}
        {details.map(([k, v]) => (
          <p key={k} className="text-[12.5px] whitespace-pre-wrap text-muted">
            <span className="text-faint">{k}: </span>
            {v}
          </p>
        ))}
        {e.evidence.map((x) => (
          <p key={x.sha256} className="text-[12px] text-muted">
            {x.name} · {x.size} bytes · <Mono className="text-[11px]">{x.sha256}</Mono>
          </p>
        ))}
        <Mono className="block truncate text-[10.5px] text-faint">{e.hash}</Mono>
      </div>
    </li>
  );
}

export function CasePage() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const [statusOpen, setStatusOpen] = useState(false);
  const [reason, setReason] = useState("");
  const q = useQuery({ queryKey: ["case", id], queryFn: ({ signal }) => get<CaseDetail>(`/api/v1/cases/${id}`, signal) });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["case", id] });
    void qc.invalidateQueries({ queryKey: ["cases"] });
  };
  const addNote = useMutation({ mutationFn: () => post(`/api/v1/cases/${id}/notes`, { text: note.trim() }), onSuccess: () => (setNote(""), refresh()) });
  const setStatus = useMutation({
    mutationFn: (status: "open" | "closed") => post(`/api/v1/cases/${id}/status`, { status, reason: reason.trim() }),
    onSuccess: () => (setStatusOpen(false), setReason(""), refresh()),
  });

  if (q.isPending) return <Spinner label="Loading case" />;
  if (q.isError) return <div className="p-8"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></div>;
  const c = q.data;
  const closing = c.status === "open";
  return (
    <div className="mx-auto max-w-[1100px] px-6 py-6">
      <Link to="/cases" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-fg">
        <ArrowLeft className="size-3.5" /> Cases
      </Link>
      <div className="flex flex-wrap items-start justify-between gap-4 pb-5">
        <div className="min-w-0 space-y-1">
          <h1 className="text-[20px] font-semibold tracking-tight text-fg">{c.title}</h1>
          <div className="flex flex-wrap items-center gap-2 text-[12.5px] text-muted">
            {c.status === "open" ? <Badge tone="warn" dot>Open</Badge> : <Badge tone="neutral">Closed</Badge>}
            <span>
              Opened {absoluteTime(c.created_at)} by {c.created_by}
            </span>
            <Mono className="text-faint">{c.id}</Mono>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={`/api/v1/cases/${id}/custody.json`}
            download
            className="inline-flex h-8.5 items-center gap-2 rounded-md border border-border bg-surface-2 px-3.5 text-[13px] font-medium text-fg hover:bg-surface-3"
          >
            <Download className="size-4" /> Export custody log
          </a>
          <Button variant={closing ? "secondary" : "primary"} onClick={() => setStatusOpen(true)}>
            {closing ? "Close case" : "Reopen case"}
          </Button>
        </div>
      </div>

      {c.verified ? (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-[12.5px] text-muted">
          <CircleCheck className="mt-0.5 size-4 shrink-0 text-ok" />
          <span>
            Custody chain verified: {c.entries.length} entries, head <Mono className="text-fg">{c.head}</Mono>. Record the head hash outside OpenRMM to detect later changes; check an export with <Mono>openrmm-custody verify</Mono>.
          </span>
        </div>
      ) : (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-[12.5px] text-danger">
          <ShieldAlert className="mt-0.5 size-4 shrink-0" />
          <span>The custody chain does not verify: {c.problem}. The log was changed outside OpenRMM; preserve the database and backups for examination.</span>
        </div>
      )}

      {c.status === "open" ? (
        <Panel title="Add a note" className="mb-4">
          {addNote.isError ? <ErrorNotice error={addNote.error} /> : null}
          <textarea className={textareaClass} value={note} onChange={(e) => setNote(e.target.value)} maxLength={8000} placeholder="Findings, decisions, actions taken outside OpenRMM…" aria-label="Note" />
          <div className="mt-2 flex justify-end">
            <Button variant="primary" loading={addNote.isPending} disabled={!note.trim()} onClick={() => addNote.mutate()}>
              Add note
            </Button>
          </div>
        </Panel>
      ) : null}

      <Collections caseId={id} open={c.status === "open"} />

      <Panel title="Chain of custody" bodyClassName="p-0">
        {c.entries.length === 0 ? (
          <EmptyState title="No entries" />
        ) : (
          <ol className="divide-y divide-border">
            {[...c.entries].reverse().map((e) => (
              <Entry key={e.sequence} e={e} actors={c.actors} />
            ))}
          </ol>
        )}
      </Panel>

      <Modal
        open={statusOpen}
        onOpenChange={(o) => (setStatusOpen(o), setStatus.reset())}
        title={closing ? "Close the case" : "Reopen the case"}
        description={closing ? "A closed case accepts no notes or response actions until it is reopened. Both are recorded in the custody log." : "Reopening is recorded in the custody log."}
        footer={
          <>
            <Button variant="ghost" onClick={() => setStatusOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" loading={setStatus.isPending} onClick={() => setStatus.mutate(closing ? "closed" : "open")}>
              {closing ? "Close case" : "Reopen case"}
            </Button>
          </>
        }
      >
        {setStatus.isError ? <ErrorNotice error={setStatus.error} /> : null}
        <Field label="Reason (optional)">
          <textarea className={textareaClass} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} aria-label="Reason" />
        </Field>
      </Modal>
    </div>
  );
}
