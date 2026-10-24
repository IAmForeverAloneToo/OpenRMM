import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Upload, Wrench } from "lucide-react";
import { ApiError, csrfHeader, get, post } from "../../lib/api";
import { bytes, relativeTime } from "../../lib/format";
import { useAccount } from "../../lib/session";
import type { ResponseTool } from "../../lib/types";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Mono, Panel } from "../../components/ui";

// The response tool library. The owner adds and withdraws tools;
// cases drop them onto devices.
export function ToolLibrary() {
  const account = useAccount();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["response-tools"], queryFn: ({ signal }) => get<{ tools: ResponseTool[]; max_bytes: number }>("/api/v1/response-tools", signal) });
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const upload = useMutation({
    mutationFn: async () => {
      if (!file) return;
      const form = new FormData();
      form.append("name", name.trim() || file.name);
      form.append("description", description.trim());
      form.append("file", file);
      const r = await fetch("/api/v1/response-tools", { method: "POST", body: form, headers: csrfHeader(), credentials: "same-origin" });
      if (!r.ok) {
        const body = (await r.json().catch(() => ({}))) as { error?: string; code?: string };
        throw new ApiError(body.error ?? "Upload failed.", r.status, body.code ?? "error");
      }
    },
    onSuccess: () => (setFile(null), setName(""), setDescription(""), void qc.invalidateQueries({ queryKey: ["response-tools"] })),
  });
  const withdraw = useMutation({ mutationFn: (id: string) => post(`/api/v1/response-tools/${id}/withdraw`), onSettled: () => void qc.invalidateQueries({ queryKey: ["response-tools"] }) });
  const tools = q.data?.tools ?? [];
  return (
    <Panel title="Tool library" className="mt-4" bodyClassName="p-0">
      {account.permissions.owner ? (
        <div className="border-b border-border p-4">
          {upload.isError ? <ErrorNotice error={upload.error} /> : null}
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,200px)_minmax(0,1fr)_auto] sm:items-end">
            <Field label="File (up to 4 GiB)">
              <input type="file" className="block w-full text-[12.5px] text-muted file:mr-2 file:rounded-md file:border file:border-border file:bg-surface-2 file:px-2 file:py-1 file:text-fg" onChange={(e) => setFile(e.target.files?.[0] ?? null)} aria-label="Tool file" />
            </Field>
            <Field label="Name">
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={file?.name ?? "Autoruns64.exe"} maxLength={255} aria-label="Tool name" />
            </Field>
            <Field label="Description">
              <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Sysinternals Autoruns 14.11" maxLength={2000} aria-label="Description" />
            </Field>
            <Button variant="primary" icon={<Upload className="size-4" />} disabled={!file} loading={upload.isPending} onClick={() => upload.mutate()}>
              Add tool
            </Button>
          </div>
          <p className="mt-2 text-[12px] text-faint">Tools are stored by SHA-256 in the evidence store (they count toward its quota) and can be dropped onto a device from a case.</p>
        </div>
      ) : null}
      {q.isError ? (
        <div className="p-4">
          <ErrorNotice error={q.error} retry={() => void q.refetch()} />
        </div>
      ) : tools.length === 0 ? (
        <EmptyState icon={<Wrench />} title="No tools yet" />
      ) : (
        <ul className="divide-y divide-border">
          {tools.map((t) => (
            <li key={t.id} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-[12.5px]">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-fg">{t.name}</span>
                  {t.withdrawn_at ? <Badge tone="neutral">Withdrawn</Badge> : null}
                </div>
                <div className="text-muted">
                  {t.description ? `${t.description} · ` : ""}
                  {bytes(t.size)} · added {relativeTime(t.created_at)} by {t.actor}
                </div>
                <Mono className="block truncate text-[11px] text-faint">SHA-256 {t.sha256}</Mono>
              </div>
              {account.permissions.owner && !t.withdrawn_at ? (
                <Button size="sm" variant="ghost" loading={withdraw.isPending && withdraw.variables === t.id} onClick={() => withdraw.mutate(t.id)}>
                  Withdraw
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
