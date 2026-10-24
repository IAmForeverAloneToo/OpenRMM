import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { FileDown, Play } from "lucide-react";
import { get, post } from "../../lib/api";
import type { EvidenceCollection, ResponseAction, ResponseTool, ScriptVersion } from "../../lib/types";
import { Button, ErrorNotice, Field, Input, Select } from "../../components/ui";

// Drop a file from the tool library or the case's evidence onto
// the chosen device, and run a library or typed script there as SYSTEM.
// Both are recorded with their hashes and results in the case.

const textareaClass =
  "min-h-28 w-full rounded-md border border-border bg-surface px-2.5 py-2 font-mono text-[12.5px] text-fg placeholder:text-faint hover:border-border-strong focus:border-accent focus:outline-none";

export function DropAndScript({ caseId, device, evidence, onQueued }: { caseId: string; device: string; evidence: EvidenceCollection[]; onQueued: () => void }) {
  const tools = useQuery({ queryKey: ["response-tools"], queryFn: ({ signal }) => get<{ tools: ResponseTool[] }>("/api/v1/response-tools", signal) });
  const scripts = useQuery({ queryKey: ["response-scripts"], queryFn: ({ signal }) => get<{ scripts: ScriptVersion[] }>("/api/v1/response-scripts", signal) });
  const [source, setSource] = useState<"tool" | "evidence">("tool");
  const [ref, setRef] = useState("");
  const [path, setPath] = useState("");
  const [overwrite, setOverwrite] = useState(false);
  const [script, setScript] = useState("");
  const [body, setBody] = useState("");
  const [timeout, setTimeoutSeconds] = useState("60");
  const [args, setArgs] = useState<Record<string, string>>({});
  const run = useMutation({
    mutationFn: (action: ResponseAction) => post(`/api/v1/cases/${caseId}/actions`, { device_id: device, action }),
    onSuccess: onQueued,
  });
  const available = (tools.data?.tools ?? []).filter((t) => t.withdrawn_at === null);
  // Only files that can be written as they are: no hives (registry names), streams or files over 4 GiB.
  const files = evidence.filter((c) => c.status === "succeeded" && c.source !== "hive" && !c.path.slice(2).includes(":") && c.size <= 4 * 1024 ** 3);
  const chosen = (scripts.data?.scripts ?? []).find((s) => s.id === script);
  const argumentsReady = !chosen || chosen.definition.parameters.every((p) => !p.required || (args[p.name] ?? "").trim() !== "");
  const options = source === "tool" ? available.map((t) => [t.id, `${t.name} (${t.sha256.slice(0, 8)}…)`]) : files.map((c) => [c.id, c.path]);
  const runScript = () =>
    run.mutate(
      chosen
        ? { kind: "script", ref: chosen.id, arguments: Object.fromEntries(Object.entries(args).filter(([k, v]) => v !== "" && chosen.definition.parameters.some((p) => p.name === k))) }
        : { kind: "script", script: body, timeout: Number(timeout) || 60 },
    );

  return (
    <div className="mt-3 space-y-3 border-t border-border pt-3">
      {run.isError ? <ErrorNotice error={run.error} /> : null}
      {run.isSuccess ? <p className="text-[12.5px] text-ok">Queued; the result appears in the case's evidence list.</p> : null}
      <div className="grid gap-3 sm:grid-cols-[minmax(0,150px)_minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end">
        <Field label="Drop from">
          <Select className="w-full" value={source} onChange={(e) => (setSource(e.target.value as "tool" | "evidence"), setRef(""))} aria-label="Drop source">
            <option value="tool">Tool library</option>
            <option value="evidence">Case evidence</option>
          </Select>
        </Field>
        <Field label="File">
          <Select className="w-full" value={ref} onChange={(e) => setRef(e.target.value)} aria-label="File to drop">
            <option value="">Choose a file</option>
            {options.map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Destination path on the device">
          <Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="C:\IR\Autoruns64.exe" maxLength={1024} spellCheck={false} aria-label="Destination path" />
        </Field>
        <Button icon={<FileDown className="size-4" />} disabled={!device || !ref || !path.trim()} loading={run.isPending && run.variables?.kind === "drop"} onClick={() => run.mutate({ kind: "drop", source, ref, path: path.trim(), overwrite })}>
          Drop file
        </Button>
      </div>
      <label className="flex items-center gap-2 text-[12.5px] text-muted">
        <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} /> Replace an existing file (its hash is recorded first)
      </label>
      <div className="space-y-2">
        <Field label="Script">
          <Select className="w-full max-w-md" value={script} onChange={(e) => (setScript(e.target.value), setArgs({}))} aria-label="Script">
            <option value="">Type a PowerShell script</option>
            {(scripts.data?.scripts ?? []).map((s) => (
              <option key={s.id} value={s.id}>
                {s.definition.name} (v{s.number})
              </option>
            ))}
          </Select>
        </Field>
        {chosen ? (
          <div className="space-y-2">
            {chosen.definition.parameters.map((p) => (
              <Field key={p.name} label={`${p.name}${p.required ? " (required)" : ""}`}>
                <Input value={args[p.name] ?? ""} onChange={(e) => setArgs({ ...args, [p.name]: e.target.value })} maxLength={1024} aria-label={p.name} />
              </Field>
            ))}
            <p className="text-[12px] text-faint">Runs version {chosen.number} for up to {chosen.definition.timeout_seconds} seconds.</p>
          </div>
        ) : (
          <div className="space-y-2">
            <textarea className={textareaClass} value={body} onChange={(e) => setBody(e.target.value)} maxLength={65536} placeholder="Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" spellCheck={false} aria-label="Script" />
            <Field label="Time limit (seconds, 5–300)">
              <Input className="max-w-32" value={timeout} onChange={(e) => setTimeoutSeconds(e.target.value)} inputMode="numeric" aria-label="Time limit" />
            </Field>
          </div>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button icon={<Play className="size-4" />} disabled={!device || (chosen ? !argumentsReady : !body.trim())} loading={run.isPending && run.variables?.kind === "script"} onClick={runScript}>
          Run script as SYSTEM
        </Button>
        <span className="text-[12px] text-faint">
          {!device ? "Choose a device above first. " : chosen && !argumentsReady ? "Fill in the required arguments. " : ""}
          Windows PowerShell 5.1. The script, its hash and its output (up to 64 KB each for output and errors) are stored in the case; it runs once.
        </span>
      </div>
    </div>
  );
}
