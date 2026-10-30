import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Plus, Save, Send, Trash } from "lucide-react";
import { get, post } from "../../lib/api";
import { absoluteTime } from "../../lib/format";
import type { ScriptDefinition, ScriptParameter, ScriptVersion } from "../../lib/types";
import { CodeEditor } from "../../components/CodeEditor";
import { Badge, Button, ErrorNotice, Field, Input, Mono, Panel, Spinner, cx } from "../../components/ui";

const empty: ScriptDefinition = { name: "", description: "", body: "", parameters: [], timeout_seconds: 60, run_as: "system" };
const paramName = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
// PowerShell common parameters cannot be redefined.
const reserved = new Set(["debug", "verbose", "erroraction", "errorvariable", "warningaction", "warningvariable", "informationaction", "informationvariable", "outvariable", "outbuffer", "pipelinevariable", "whatif", "confirm", "progressaction",
  // Their short aliases bind the same way.
  "db", "vb", "ea", "ev", "wa", "wv", "infa", "iv", "ov", "ob", "pv", "wi", "cf", "proga"]);
const validParam = (n: string) => paramName.test(n) && !reserved.has(n.toLowerCase());

export function ScriptEditor() {
  const { version: versionId } = useParams();
  const navigate = useNavigate();
  const client = useQueryClient();
  const q = useQuery({
    queryKey: ["script-version", versionId],
    queryFn: ({ signal }) => get<{ version: ScriptVersion; history: ScriptVersion[] }>(`/api/v1/scripts/versions/${versionId}`, signal),
    enabled: !!versionId,
  });
  const [def, setDef] = useState<ScriptDefinition>(empty);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const current = q.data?.version;
  useEffect(() => {
    setDef(current ? { ...current.definition, parameters: current.definition.parameters ?? [] } : empty);
  }, [current]);

  if (versionId && q.isPending) return <div className="p-8"><Spinner label="Loading script" /></div>;
  if (versionId && q.isError) return <div className="p-8"><ErrorNotice error={q.error} /></div>;

  const latest = q.data?.history[0];
  const changed = !current || JSON.stringify(def) !== JSON.stringify(current.definition);
  const paramsValid = def.parameters.every((p) => validParam(p.name)) && new Set(def.parameters.map((p) => p.name.toLowerCase())).size === def.parameters.length;
  const valid = def.name.trim() !== "" && def.body.trim() !== "" && def.timeout_seconds >= 5 && def.timeout_seconds <= 300 && paramsValid;
  const setParam = (i: number, p: Partial<ScriptParameter>) => setDef((d) => ({ ...d, parameters: d.parameters.map((x, j) => (j === i ? { ...x, ...p } : x)) }));

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const v = await post<ScriptVersion>("/api/v1/scripts/versions", { script_id: current?.script_id ?? "", definition: { ...def, name: def.name.trim() } });
      await client.invalidateQueries({ queryKey: ["scripts"] });
      navigate(`/scripts/v/${v.id}`, { replace: !!current });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <Link to="/scripts" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-fg">
        <ArrowLeft className="size-3.5" /> Scripts
      </Link>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <h1 className="text-[20px] font-semibold tracking-tight text-fg">{current ? def.name || current.definition.name : "New script"}</h1>
        {current ? <Badge>v{current.number}</Badge> : null}
        {current && latest && latest.id !== current.id ? <Badge tone="warn">Older version — v{latest.number} is the latest</Badge> : null}
        <div className="flex-1" />
        {current ? (
          <Button icon={<Send className="size-4" />} disabled={changed} onClick={() => navigate(`/scripts/run?version=${current.id}`)}>
            Run on devices
          </Button>
        ) : null}
        <Button variant="primary" icon={<Save className="size-4" />} loading={busy} disabled={!valid || !changed} onClick={() => void save()}>
          {current ? `Save as v${(latest?.number ?? current.number) + 1}` : "Create script"}
        </Button>
      </div>
      {error ? (
        <div className="mb-4">
          <ErrorNotice error={error} />
        </div>
      ) : null}
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="Name">
              <Input value={def.name} onChange={(e) => setDef({ ...def, name: e.target.value })} maxLength={100} placeholder="e.g. Clear temp folders" />
            </Field>
            <Field label="Description">
              <Input value={def.description} onChange={(e) => setDef({ ...def, description: e.target.value })} maxLength={2000} placeholder="What it does, in one line" />
            </Field>
          </div>
          <CodeEditor value={def.body} onChange={(body) => setDef((d) => ({ ...d, body }))} minHeight={460} />
          <p className="text-[12px] text-faint">Windows PowerShell 5.1. Parameters arrive as named string arguments, for example declare them with param([string]$Path).</p>
        </div>
        <div className="space-y-5">
          <Panel title="Settings">
            <div className="space-y-4">
              <div>
                <div className="mb-1.5 text-[12.5px] font-medium text-muted">Runs as</div>
                <p className="text-[12.5px] text-fg">
                  <Badge tone="warn">SYSTEM</Badge> <span className="text-muted">Full control of the device.</span>
                </p>
              </div>
              <Field label="Timeout (seconds)" hint="5 to 300">
                <Input type="number" min={5} max={300} value={def.timeout_seconds} onChange={(e) => setDef({ ...def, timeout_seconds: Number(e.target.value) })} className="w-28" />
              </Field>
            </div>
          </Panel>
          <Panel
            title="Parameters"
            actions={
              <Button size="sm" variant="ghost" icon={<Plus className="size-3.5" />} disabled={def.parameters.length >= 8} onClick={() => setDef({ ...def, parameters: [...def.parameters, { name: "", description: "", required: false }] })}>
                Add
              </Button>
            }
          >
            {def.parameters.length === 0 ? (
              <p className="text-[12.5px] text-muted">No parameters. Add up to 8 named string parameters.</p>
            ) : (
              <div className="space-y-3">
                {def.parameters.map((p, i) => (
                  <div key={i} className="space-y-1.5 rounded-md border border-border p-2.5">
                    <div className="flex items-center gap-2">
                      <Input value={p.name} onChange={(e) => setParam(i, { name: e.target.value })} placeholder="Name" className={cx("font-mono", p.name && !validParam(p.name) && "border-danger")} maxLength={32} />
                      <label className="flex items-center gap-1.5 text-[12px] whitespace-nowrap text-muted">
                        <input type="checkbox" checked={p.required} onChange={(e) => setParam(i, { required: e.target.checked })} className="accent-[var(--accent)]" /> Required
                      </label>
                      <button type="button" aria-label="Remove parameter" className="rounded p-1 text-faint hover:bg-surface-2 hover:text-danger" onClick={() => setDef({ ...def, parameters: def.parameters.filter((_, j) => j !== i) })}>
                        <Trash className="size-4" />
                      </button>
                    </div>
                    <Input value={p.description} onChange={(e) => setParam(i, { description: e.target.value })} placeholder="Description (optional)" maxLength={256} />
                  </div>
                ))}
                {!paramsValid ? <p className="text-[12px] text-danger">Names start with a letter, use up to 32 letters, digits or _, must be unique, and can't be a PowerShell common parameter or its alias (Verbose, ErrorAction, ea…).</p> : null}
              </div>
            )}
          </Panel>
          {q.data ? (
            <Panel title="Versions" bodyClassName="p-0">
              <ul className="max-h-72 divide-y divide-border overflow-y-auto">
                {q.data.history.map((v) => (
                  <li key={v.id}>
                    <Link to={`/scripts/v/${v.id}`} className={cx("flex items-center gap-2 px-4 py-2 hover:bg-surface-2", v.id === current?.id && "bg-accent-soft")}>
                      <span className="font-medium text-fg">v{v.number}</span>
                      <span className="flex-1 truncate text-[12px] text-muted">
                        {absoluteTime(v.created_at)} · {v.actor}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
              {current ? (
                <div className="border-t border-border px-4 py-2 text-[11.5px] text-faint">
                  Versions are immutable. SHA-256 <Mono className="break-all">{current.sha256}</Mono>
                </div>
              ) : null}
            </Panel>
          ) : null}
        </div>
      </div>
    </div>
  );
}
