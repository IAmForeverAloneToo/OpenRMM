import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PackageOpen, Plus } from "lucide-react";
import { get, post } from "../../lib/api";
import { relativeTime } from "../../lib/format";
import { useAccount } from "../../lib/session";
import type { TriageItem, TriageProfile } from "../../lib/types";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Panel } from "../../components/ui";

// Triage profiles. The built-in Full triage collects every
// artifact type; the owner adds narrower profiles from the checklist.
export function useTriageProfiles(enabled = true) {
  return useQuery({ queryKey: ["triage-profiles"], queryFn: ({ signal }) => get<{ profiles: TriageProfile[]; items: TriageItem[] }>("/api/v1/triage-profiles", signal), enabled });
}

export function TriageProfiles() {
  const account = useAccount();
  const qc = useQueryClient();
  const q = useTriageProfiles();
  const [name, setName] = useState("");
  const [items, setItems] = useState<string[]>([]);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["triage-profiles"] });
  const add = useMutation({ mutationFn: () => post("/api/v1/triage-profiles", { name: name.trim(), items }), onSuccess: () => (setName(""), setItems([]), refresh()) });
  const withdraw = useMutation({ mutationFn: (id: string) => post(`/api/v1/triage-profiles/${id}/withdraw`), onSettled: refresh });
  const labels = Object.fromEntries((q.data?.items ?? []).map((i) => [i.name, i.label]));
  const profiles = q.data?.profiles ?? [];
  return (
    <Panel title="Triage profiles" className="mt-4" bodyClassName="p-0">
      {account.permissions.owner ? (
        <div className="space-y-3 border-b border-border p-4">
          {add.isError ? <ErrorNotice error={add.error} /> : null}
          <Field label="New profile name">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Quick triage" maxLength={100} className="max-w-sm" />
          </Field>
          <div className="grid gap-x-4 gap-y-1.5 sm:grid-cols-2 lg:grid-cols-3">
            {(q.data?.items ?? []).map((i) => (
              <label key={i.name} className="flex items-center gap-2 text-[13px] text-fg">
                <input type="checkbox" className="accent-[var(--accent)]" checked={items.includes(i.name)} onChange={(e) => setItems(e.target.checked ? [...items, i.name] : items.filter((x) => x !== i.name))} />
                {i.label}
              </label>
            ))}
          </div>
          <Button icon={<Plus className="size-4" />} disabled={!name.trim() || items.length === 0} loading={add.isPending} onClick={() => add.mutate()}>
            Add profile
          </Button>
        </div>
      ) : null}
      {q.isError ? (
        <div className="p-4">
          <ErrorNotice error={q.error} retry={() => void q.refetch()} />
        </div>
      ) : profiles.length === 0 ? (
        <EmptyState icon={<PackageOpen />} title="No profiles" />
      ) : (
        <ul className="divide-y divide-border">
          {profiles.map((p) => (
            <li key={p.id} className="flex flex-wrap items-start gap-3 px-4 py-3 text-[13px]">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-fg">{p.name}</span>
                  {p.built_in ? <Badge tone="neutral">Built in</Badge> : <span className="text-[12px] text-faint">added {relativeTime(p.created_at ?? 0)} by {p.created_by}</span>}
                </div>
                <div className="mt-0.5 text-[12.5px] text-muted">{p.items.map((i) => labels[i] ?? i).join(" · ")}</div>
              </div>
              {account.permissions.owner && !p.built_in ? (
                <Button size="sm" variant="ghost" loading={withdraw.isPending && withdraw.variables === p.id} onClick={() => withdraw.mutate(p.id)}>
                  Withdraw
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      <p className="border-t border-border px-4 py-2 text-[12px] text-faint">
        A triage package is one ZIP per device, read from a shadow copy of the system drive, with the original paths and a manifest of every file's hashes, times and how it was read.
      </p>
    </Panel>
  );
}
