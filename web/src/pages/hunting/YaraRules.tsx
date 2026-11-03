import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Archive, Eye, FilePlus, Pencil, Radar } from "lucide-react";
import { get, post, put } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import { useAccount } from "../../lib/session";
import type { YaraRuleSet } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { ConfirmDialog, Modal } from "../../components/Dialog";
import { Button, EmptyState, ErrorNotice, Field, Input, Panel, Spinner, Tip } from "../../components/ui";

// YARA rule sets: the owner adds, changes and withdraws them; anyone with
// the response permission reads them and uses them in hunts and scans.

const textareaClass =
  "min-h-72 w-full rounded-md border border-border bg-surface px-2.5 py-2 font-mono text-[12.5px] text-fg placeholder:text-faint hover:border-border-strong focus:border-accent focus:outline-none";

const example = `rule example_dumper : hacktool {
  meta:
    description = "A made-up credential dumper"
  strings:
    $a = "dumpcreds::allsessions" ascii wide nocase
    $b = { 4D 5A ?? 00 [2-8] 50 45 }
  condition:
    $a or #b > 1
}`;

export function YaraRules({ onUse }: { onUse: (id: string) => void }) {
  const qc = useQueryClient();
  const owner = useAccount().permissions.owner;
  const q = useQuery({ queryKey: ["yara-rule-sets"], queryFn: ({ signal }) => get<{ sets: YaraRuleSet[] }>("/api/v1/yara-rule-sets", signal) });
  const [editing, setEditing] = useState<{ id?: string; name: string } | null>(null);
  const [viewing, setViewing] = useState<string | null>(null);
  const [withdrawing, setWithdrawing] = useState<YaraRuleSet | null>(null);
  const columns: Column<YaraRuleSet>[] = useMemo(
    () => [
      { key: "name", header: "Rule set", sort: (s) => s.name.toLowerCase(), cell: (s) => <span className="font-medium text-fg">{s.name}</span> },
      { key: "rules", header: "Rules", sort: (s) => s.rules, cell: (s) => <span className="text-muted tabular-nums">{s.rules}</span> },
      { key: "version", header: "Version", sort: (s) => s.version, cell: (s) => <span className="text-muted tabular-nums">{s.version}</span> },
      {
        key: "updated",
        header: "Changed",
        sort: (s) => s.updated_at,
        cell: (s) => (
          <Tip label={`Created ${absoluteTime(s.created_at)} by ${s.created_by}; SHA-256 ${s.sha256}`}>
            <span className="text-muted">
              {relativeTime(s.updated_at)} · {s.updated_by}
            </span>
          </Tip>
        ),
      },
      {
        key: "actions",
        header: "",
        className: "text-right",
        cell: (s) => (
          <span className="flex justify-end gap-1.5">
            <Button size="sm" icon={<Radar className="size-3.5" />} onClick={() => onUse(s.id)}>
              Hunt
            </Button>
            {owner ? (
              <>
                <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" />} onClick={() => setEditing({ id: s.id, name: s.name })}>
                  Edit
                </Button>
                <Button size="sm" variant="ghost" icon={<Archive className="size-3.5" />} onClick={() => setWithdrawing(s)}>
                  Withdraw
                </Button>
              </>
            ) : (
              <Button size="sm" variant="ghost" icon={<Eye className="size-3.5" />} onClick={() => setViewing(s.id)}>
                View
              </Button>
            )}
          </span>
        ),
      },
    ],
    [onUse, owner],
  );
  return (
    <Panel
      title="YARA rule sets"
      bodyClassName="p-0"
      actions={
        owner ? (
          <Button size="sm" icon={<FilePlus className="size-3.5" />} onClick={() => setEditing({ name: "" })}>
            New rule set
          </Button>
        ) : null
      }
    >
      {q.isPending ? (
        <div className="p-6">
          <Spinner label="Loading rule sets" />
        </div>
      ) : q.isError ? (
        <div className="p-4">
          <ErrorNotice error={q.error} retry={() => void q.refetch()} />
        </div>
      ) : (
        <DataTable
          columns={columns}
          rows={q.data.sets}
          rowKey={(s) => s.id}
          empty={
            <EmptyState title="No rule sets">
              {owner ? "Add YARA rules to scan files and process memory in hunts, the console and cases." : "The administrator adds YARA rule sets here."}
            </EmptyState>
          }
        />
      )}
      <p className="border-t border-border px-4 py-2 text-[12px] text-faint">
        Rules with text, hex and regular expression strings, conditions and the pe, dotnet, hash, math and time modules are supported. Every change is a new version, in the audit log.
      </p>
      {editing ? <RuleEditor initial={editing} onClose={() => setEditing(null)} /> : null}
      {viewing ? <RuleEditor initial={{ id: viewing, name: "" }} readOnly onClose={() => setViewing(null)} /> : null}
      <ConfirmDialog
        open={withdrawing !== null}
        onOpenChange={(o) => !o && setWithdrawing(null)}
        title="Withdraw rule set"
        confirmLabel="Withdraw"
        danger
        onConfirm={async () => {
          if (withdrawing) await post(`/api/v1/yara-rule-sets/${withdrawing.id}/withdraw`, {});
          await qc.invalidateQueries({ queryKey: ["yara-rule-sets"] });
        }}
      >
        <p>
          <span className="font-medium text-fg">{withdrawing?.name}</span> can no longer be used. Hunts that ran it keep their copy of the rules, and its versions stay on record.
        </p>
      </ConfirmDialog>
    </Panel>
  );
}

function RuleEditor({ initial, readOnly, onClose }: { initial: { id?: string; name: string }; readOnly?: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const existing = useQuery({
    queryKey: ["yara-rule-set", initial.id],
    queryFn: ({ signal }) => get<YaraRuleSet>(`/api/v1/yara-rule-sets/${initial.id}`, signal),
    enabled: !!initial.id,
  });
  // The name and rules start from the saved set once it has loaded.
  const [name, setName] = useState<string | null>(initial.id ? null : "");
  const [source, setSource] = useState<string | null>(initial.id ? null : example);
  const nameText = name ?? existing.data?.name ?? "";
  const text = source ?? existing.data?.source ?? "";
  const check = useMutation({ mutationFn: () => post<{ rules: number }>("/api/v1/yara/check", { source: text }) });
  const save = useMutation({
    mutationFn: () => (initial.id ? put(`/api/v1/yara-rule-sets/${initial.id}`, { name: nameText, source: text }) : post("/api/v1/yara-rule-sets", { name: nameText, source: text })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["yara-rule-sets"] });
      void qc.invalidateQueries({ queryKey: ["yara-rule-set", initial.id] });
      onClose();
    },
  });
  const title = readOnly ? (existing.data?.name ?? "Rule set") : initial.id ? "Edit rule set" : "New rule set";
  return (
    <Modal
      open
      onOpenChange={(o) => !o && onClose()}
      title={title}
      description={existing.data ? `Version ${existing.data.version} · ${existing.data.rules} rules` : "Checked when saved; each save is a new version."}
      width="max-w-[900px]"
      footer={
        readOnly ? (
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={() => check.mutate()} loading={check.isPending} disabled={!text.trim()}>
              Check
            </Button>
            <Button variant="primary" onClick={() => save.mutate()} loading={save.isPending} disabled={!text.trim() || !nameText.trim()}>
              Save
            </Button>
          </>
        )
      }
    >
      {existing.isPending && initial.id ? <Spinner label="Loading the rules" /> : null}
      <div className="space-y-3">
        {readOnly ? null : (
          <Field label="Name">
            <Input value={nameText} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="Credential theft tools" aria-label="Name" />
          </Field>
        )}
        <textarea
          className={textareaClass}
          value={text}
          onChange={(e) => {
            setSource(e.target.value);
            check.reset();
          }}
          readOnly={readOnly}
          spellCheck={false}
          aria-label="YARA rules"
        />
        {check.isSuccess ? <p className="text-[12.5px] text-ok">The rules compile: {check.data.rules} {check.data.rules === 1 ? "rule" : "rules"}.</p> : null}
        {check.isError ? <ErrorNotice error={check.error} /> : null}
        {save.isError ? <ErrorNotice error={save.error} /> : null}
      </div>
    </Modal>
  );
}
