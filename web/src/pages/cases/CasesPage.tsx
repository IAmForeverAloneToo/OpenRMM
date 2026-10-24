import { useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Briefcase, Plus } from "lucide-react";
import { get, post } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { CaseSummary } from "../../lib/types";
import { PageHeader } from "../../app/AppShell";
import { DataTable, type Column } from "../../components/DataTable";
import { Modal } from "../../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Mono, Panel, Spinner, Tip } from "../../components/ui";
import { ToolLibrary } from "./ToolLibrary";
import { TriageProfiles } from "./TriageProfiles";

// Cases. Every response action is bound to a case; its
// chain-of-custody log is append-only and verifiable offline.

function NewCaseDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate();
  const [title, setTitle] = useState("");
  const create = useMutation({ mutationFn: () => post<CaseSummary>("/api/v1/cases", { title: title.trim() }), onSuccess: (c) => navigate(`/cases/${c.id}`) });
  return (
    <Modal
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          setTitle("");
          create.reset();
        }
        onOpenChange(o);
      }}
      title="Open a case"
      description="A case groups the investigation of one incident. Its custody log records who did what, when, and on which device."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={create.isPending} disabled={!title.trim()} onClick={() => create.mutate()}>
            Open case
          </Button>
        </>
      }
    >
      {create.isError ? <ErrorNotice error={create.error} /> : null}
      <Field label="Title" hint="For example the alert, the affected user or device, and the date.">
        <Input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} autoFocus aria-label="Case title" />
      </Field>
    </Modal>
  );
}

export function CasesPage() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: ["cases"], queryFn: ({ signal }) => get<{ cases: CaseSummary[] }>("/api/v1/cases", signal) });
  const columns: Column<CaseSummary>[] = [
    { key: "title", header: "Case", sort: (c) => c.title.toLowerCase(), cell: (c) => (
      <div className="min-w-0">
        <div className="truncate font-medium text-fg">{c.title}</div>
        <Mono className="text-[11.5px] text-faint">{c.id.slice(0, 12)}</Mono>
      </div>
    ) },
    { key: "status", header: "Status", sort: (c) => c.status, cell: (c) => (c.status === "open" ? <Badge tone="warn" dot>Open</Badge> : <Badge tone="neutral">Closed</Badge>) },
    { key: "entries", header: "Custody entries", sort: (c) => c.entries, cell: (c) => <span className="text-muted tabular-nums">{c.entries}</span> },
    { key: "created", header: "Opened", sort: (c) => c.created_at, cell: (c) => (
      <Tip label={absoluteTime(c.created_at)}>
        <span className="text-muted">{relativeTime(c.created_at)} · {c.created_by}</span>
      </Tip>
    ) },
    { key: "updated", header: "Last activity", sort: (c) => c.updated_at, headerClassName: "text-right", className: "text-right", cell: (c) => <span className="text-muted tabular-nums">{relativeTime(c.updated_at)}</span> },
  ];
  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader
        title="Cases"
        subtitle="Incidents under investigation, each with an append-only chain-of-custody log."
        actions={
          <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setOpen(true)}>
            Open case
          </Button>
        }
      />
      <Panel bodyClassName="p-0">
        {q.isPending ? (
          <div className="p-6">
            <Spinner label="Loading cases" />
          </div>
        ) : q.isError ? (
          <div className="p-4">
            <ErrorNotice error={q.error} retry={() => void q.refetch()} />
          </div>
        ) : (
          <DataTable
            columns={columns}
            rows={q.data.cases}
            rowKey={(c) => c.id}
            onRowClick={(c) => navigate(`/cases/${c.id}`)}
            empty={<EmptyState icon={<Briefcase />} title="No cases yet">Open a case when you start investigating an incident.</EmptyState>}
          />
        )}
      </Panel>
      <ToolLibrary />
      <TriageProfiles />
      <NewCaseDialog open={open} onOpenChange={setOpen} />
    </div>
  );
}
