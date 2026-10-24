import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { absoluteTime, relativeTime } from "../../lib/format";
import { argumentsComplete } from "../../lib/parse";
import type { ScriptRun, ScriptSchedule, ScriptVersion } from "../../lib/types";
import { Modal, ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, ErrorNotice, Field, Input, Mono, Select, Spinner } from "../../components/ui";
import { OperationStatus } from "../../components/status";

/** Every script runs as SYSTEM, whatever older versions stored. */
export function RunAsBadge(_: { runAs: string }) {
  return <Badge tone="warn">SYSTEM</Badge>;
}

export function useScriptLibrary(enabled = true) {
  return useQuery({ queryKey: ["scripts"], queryFn: ({ signal }) => get<{ scripts: ScriptVersion[] }>("/api/v1/scripts", signal), enabled, staleTime: 15_000 });
}

/** Parameter inputs for a script version; returns the argument map. */
export function ParameterFields({ version, values, onChange }: { version: ScriptVersion | undefined; values: Record<string, string>; onChange: (v: Record<string, string>) => void }) {
  if (!version || version.definition.parameters.length === 0) return null;
  return (
    <div className="space-y-3">
      {version.definition.parameters.map((p) => (
        <Field key={p.name} label={`${p.name}${p.required ? " *" : ""}`} hint={p.description || undefined}>
          <Input value={values[p.name] ?? ""} onChange={(e) => onChange({ ...values, [p.name]: e.target.value })} maxLength={1024} spellCheck={false} />
        </Field>
      ))}
    </div>
  );
}

/** Pick a script and parameters, then run it on one device. */
export function RunScriptDialog({
  open,
  onOpenChange,
  deviceId,
  hostname,
  onStarted,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  deviceId: string;
  hostname: string;
  onStarted: (runId: string) => void;
}) {
  const library = useScriptLibrary(open);
  const [versionId, setVersionId] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const scripts = library.data?.scripts ?? [];
  const version = scripts.find((s) => s.id === versionId);
  useEffect(() => {
    if (!open) {
      setVersionId("");
      setValues({});
      setError(null);
    }
  }, [open]);

  const run = async () => {
    if (!version) return;
    setBusy(true);
    setError(null);
    try {
      const id = newOperationID();
      await post(`/api/v1/devices/${deviceId}/script-runs`, { id, version: version.id, arguments: values });
      onOpenChange(false);
      onStarted(id);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={`Run a script on ${hostname}`}
      width="max-w-xl"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!argumentsComplete(version, values)} loading={busy} onClick={() => void run()}>
            Run script
          </Button>
        </>
      }
    >
      {library.isPending ? (
        <Spinner label="Loading scripts" />
      ) : scripts.length === 0 ? (
        <p className="text-muted">The script library is empty. Add a script under Scripts first.</p>
      ) : (
        <div className="space-y-4">
          <Field label="Script">
            <Select value={versionId} onChange={(e) => (setVersionId(e.target.value), setValues({}))} className="w-full">
              <option value="">Choose a script…</option>
              {scripts.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.definition.name} (v{s.number})
                </option>
              ))}
            </Select>
          </Field>
          {version ? (
            <div className="flex flex-wrap items-center gap-2 text-[12.5px] text-muted">
              <RunAsBadge runAs={version.definition.run_as} />
              <span>Times out after {version.definition.timeout_seconds}s</span>
              {version.definition.description ? <span>· {version.definition.description}</span> : null}
            </div>
          ) : null}
          {version ? (
            <div className="flex gap-2 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[12.5px] text-warn">
              <ShieldAlert className="mt-0.5 size-4 shrink-0" />
              <span>Runs as SYSTEM with full control of the device.</span>
            </div>
          ) : null}
          <ParameterFields version={version} values={values} onChange={setValues} />
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      )}
    </Modal>
  );
}

const finished = (s: string) => !["queued", "dispatched", "running"].includes(s);

/** Live result of one script run, with cancellation while it is active. */
export function RunDetailModal({ deviceId, runId, onClose }: { deviceId: string; runId: string | null; onClose: () => void }) {
  const client = useQueryClient();
  const [cancelOpen, setCancelOpen] = useState(false);
  const q = useQuery({
    queryKey: ["script-run", deviceId, runId],
    queryFn: ({ signal }) => get<ScriptRun>(`/api/v1/devices/${deviceId}/script-runs/${runId}`, signal),
    enabled: runId !== null,
    refetchInterval: (query) => (query.state.data && finished(query.state.data.status) ? false : 1500),
  });
  const r = q.data;
  const args = Object.entries(r?.arguments ?? {});
  return (
    <Modal open={runId !== null} onOpenChange={(o) => !o && onClose()} title={r ? `${r.version.definition.name} (v${r.version.number})` : "Script run"} width="max-w-3xl">
      {!r ? (
        q.isError ? <ErrorNotice error={q.error} /> : <Spinner label="Loading run" />
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-[12.5px] text-muted">
            <OperationStatus status={r.status} />
            <RunAsBadge runAs={r.version.definition.run_as} />
            <span>by {r.actor}</span>
            <span>· started {relativeTime(r.created_at)}</span>
            {r.finished_at ? <span>· finished {absoluteTime(r.finished_at)}</span> : null}
            {r.result?.exit_code !== null && r.result?.exit_code !== undefined ? <Badge tone={r.result.exit_code === 0 ? "ok" : "danger"}>Exit {r.result.exit_code}</Badge> : null}
            {r.cancel_requested ? <Badge tone="warn">Cancel requested</Badge> : null}
            <div className="flex-1" />
            {!finished(r.status) && !r.cancel_requested ? (
              <Button size="sm" variant="ghost" onClick={() => setCancelOpen(true)}>
                Cancel run
              </Button>
            ) : null}
          </div>
          {args.length ? (
            <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-1 text-[12.5px]">
              {args.map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted">{k}</dt>
                  <dd>
                    <Mono className="text-fg">{v}</Mono>
                  </dd>
                </div>
              ))}
            </dl>
          ) : null}
          {!finished(r.status) ? <Spinner label={r.status === "queued" ? "Waiting for the device" : "Running"} /> : null}
          {r.result ? (
            <>
              {r.result.outcome !== "ok" && r.result.outcome !== "succeeded" ? <p className="text-[12.5px] text-muted">Outcome: {r.result.outcome.replaceAll("_", " ")}</p> : null}
              <div>
                <div className="mb-1 text-[12px] font-medium text-muted">Output{r.result.truncated ? " (truncated to 64 KB)" : ""}</div>
                <pre className="max-h-80 overflow-auto rounded-md border border-border bg-[#0b0e13] p-3 font-mono text-[12.5px] whitespace-pre-wrap text-[#e6e9ef]">{r.result.stdout || "(no output)"}</pre>
              </div>
              {r.result.stderr ? (
                <div>
                  <div className="mb-1 text-[12px] font-medium text-danger">Errors</div>
                  <pre className="max-h-60 overflow-auto rounded-md border border-danger/30 bg-danger-soft p-3 font-mono text-[12.5px] whitespace-pre-wrap text-danger">{r.result.stderr}</pre>
                </div>
              ) : null}
            </>
          ) : finished(r.status) ? (
            <p className="text-muted">No result was reported. {r.status === "unknown" ? "The outcome is uncertain; check the device before running it again." : ""}</p>
          ) : null}
        </div>
      )}
      <ConfirmDialog
        open={cancelOpen}
        onOpenChange={setCancelOpen}
        title="Cancel this run?"
        confirmLabel="Cancel run"
        danger
        onConfirm={async () => {
          await post(`/api/v1/devices/${deviceId}/script-runs/${runId}/cancel`);
          await client.invalidateQueries({ queryKey: ["script-run", deviceId, runId] });
        }}
      >
        <p>The script is stopped if it hasn't finished. Changes it already made are not undone.</p>
      </ConfirmDialog>
    </Modal>
  );
}

const units = [
  { value: "60", label: "minutes" },
  { value: "3600", label: "hours" },
  { value: "86400", label: "days" },
];

function localInput(unix: number): string {
  const d = new Date(unix * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Create or edit a schedule for one device. Times are entered in local time. */
export function ScheduleDialog({ open, onOpenChange, deviceId, hostname, existing, onSaved }: { open: boolean; onOpenChange: (o: boolean) => void; deviceId: string; hostname: string; existing?: ScriptSchedule | null; onSaved?: () => void }) {
  const library = useScriptLibrary(open);
  const scripts = library.data?.scripts ?? [];
  const [name, setName] = useState("");
  const [versionId, setVersionId] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [start, setStart] = useState("");
  const [repeat, setRepeat] = useState(false);
  const [every, setEvery] = useState("1");
  const [unit, setUnit] = useState("86400");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);
    if (existing) {
      setName(existing.name);
      setVersionId(existing.version_id);
      setValues(existing.arguments ?? {});
      const startAt = existing.next_at > Date.now() / 1000 + 60 ? existing.next_at : Math.floor(Date.now() / 1000) + 600;
      setStart(localInput(startAt));
      setRepeat(existing.interval_seconds > 0);
      const u = existing.interval_seconds % 86400 === 0 ? 86400 : existing.interval_seconds % 3600 === 0 ? 3600 : 60;
      setUnit(String(u));
      setEvery(String(Math.max(1, existing.interval_seconds / u)));
    } else {
      setName("");
      setVersionId("");
      setValues({});
      setStart(localInput(Math.floor(Date.now() / 1000 / 60) * 60 + 600));
      setRepeat(false);
      setEvery("1");
      setUnit("86400");
    }
  }, [open, existing]);

  const listed = scripts.find((s) => s.id === versionId);
  // A schedule may pin an older version than the library's latest; load it directly.
  const pinned = useQuery({
    queryKey: ["script-version", versionId],
    queryFn: ({ signal }) => get<{ version: ScriptVersion }>(`/api/v1/scripts/versions/${versionId}`, signal),
    enabled: open && versionId !== "" && !listed && !library.isPending,
  });
  const version = useMemo(() => listed ?? pinned.data?.version, [listed, pinned.data]);
  const intervalSeconds = repeat ? Number(every) * Number(unit) : 0;
  const intervalValid = !repeat || (Number.isInteger(Number(every)) && intervalSeconds >= 300 && intervalSeconds <= 2592000);
  const startAt = start ? Math.floor(new Date(start).getTime() / 1000) : 0;

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await post(`/api/v1/devices/${deviceId}/script-schedules`, {
        id: existing?.id ?? newOperationID(),
        revision: existing?.revision ?? 0,
        version: versionId,
        name: name.trim(),
        start_at: startAt,
        interval_seconds: intervalSeconds,
        arguments: values,
      });
      onOpenChange(false);
      onSaved?.();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={existing ? `Edit schedule on ${hostname}` : `Schedule a script on ${hostname}`}
      width="max-w-xl"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={busy} disabled={!name.trim() || !versionId || !startAt || !intervalValid || (!!version && !argumentsComplete(version, values))} onClick={() => void save()}>
            Save schedule
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="e.g. Nightly cleanup" />
        </Field>
        <Field label="Script">
          <Select value={versionId} onChange={(e) => (setVersionId(e.target.value), setValues({}))} className="w-full">
            <option value="">Choose a script…</option>
            {existing && !scripts.some((s) => s.id === existing.version_id) ? (
              <option value={existing.version_id}>{pinned.data ? `${pinned.data.version.definition.name} (v${pinned.data.version.number}, pinned)` : "Current pinned version"}</option>
            ) : null}
            {scripts.map((s) => (
              <option key={s.id} value={s.id}>
                {s.definition.name} (v{s.number}){s.definition.run_as === "system" ? " — SYSTEM" : ""}
              </option>
            ))}
          </Select>
        </Field>
        <ParameterFields version={version} values={values} onChange={setValues} />
        <div className="grid grid-cols-2 gap-3">
          <Field label="First run (your local time)">
            <Input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
          </Field>
          <Field label="Repeat">
            <Select value={repeat ? "yes" : "no"} onChange={(e) => setRepeat(e.target.value === "yes")} className="w-full">
              <option value="no">Run once</option>
              <option value="yes">Repeat</option>
            </Select>
          </Field>
        </div>
        {repeat ? (
          <div className="flex items-end gap-2">
            <Field label="Every">
              <Input value={every} onChange={(e) => setEvery(e.target.value)} inputMode="numeric" className="w-24" />
            </Field>
            <Select value={unit} onChange={(e) => setUnit(e.target.value)}>
              {units.map((u) => (
                <option key={u.value} value={u.value}>
                  {u.label}
                </option>
              ))}
            </Select>
            {!intervalValid ? <span className="pb-2 text-[12px] text-danger">Between 5 minutes and 30 days.</span> : null}
          </div>
        ) : null}
        <p className="text-[12px] text-faint">Runs that are missed while the device is offline or busy are skipped, never queued up.</p>
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Modal>
  );
}
