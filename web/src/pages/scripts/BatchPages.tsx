import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Send } from "lucide-react";
import { get, post } from "../../lib/api";
import { argumentsComplete } from "../../lib/parse";
import { newOperationID } from "../../lib/id";
import { absoluteTime } from "../../lib/format";
import type { DevicesResponse, ScriptBatch, ScriptBatchChange } from "../../lib/types";
import { Modal } from "../../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Panel, SearchInput, Select, Spinner, cx } from "../../components/ui";
import { DeviceStatusBadge, OperationStatus } from "../../components/status";
import { ParameterFields, RunAsBadge, RunDetailModal, useScriptLibrary } from "./shared";

const MAX_TARGETS = 25;

export function BatchNew() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const library = useScriptLibrary();
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal) });
  const [versionId, setVersionId] = useState(params.get("version") ?? "");
  const [name, setName] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [groups, setGroups] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const [review, setReview] = useState<{ change: ScriptBatchChange; batch: ScriptBatch } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const scripts = library.data?.scripts ?? [];
  const version = scripts.find((s) => s.id === versionId);
  const list = useMemo(() => {
    const t = filter.trim().toLowerCase();
    return (devices.data?.devices ?? []).filter((d) => d.status !== "revoked" && (!t || d.hostname.toLowerCase().includes(t) || (d.group_name ?? "").toLowerCase().includes(t)));
  }, [devices.data, filter]);
  const count = selected.size + groups.size;
  const toggle = (set: Set<string>, update: (s: Set<string>) => void, id: string) => {
    const n = new Set(set);
    if (n.has(id)) n.delete(id);
    else if (count < MAX_TARGETS) n.add(id);
    update(n);
  };

  const doReview = async () => {
    if (!version) return;
    setBusy(true);
    setError(null);
    const change: ScriptBatchChange = { id: newOperationID(), version_id: version.id, name: name.trim() || version.definition.name, devices: [...selected], groups: [...groups], arguments: values };
    try {
      const batch = await post<ScriptBatch>("/api/v1/script-batches/review", { change, digest: "" });
      setReview({ change, batch });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const apply = async () => {
    if (!review) return;
    setBusy(true);
    setError(null);
    try {
      await post<ScriptBatch>("/api/v1/script-batches/apply", { change: review.change, digest: review.batch.digest });
      navigate(`/scripts/runs/${review.change.id}`);
    } catch (e) {
      setError(e);
      setReview(null);
    } finally {
      setBusy(false);
    }
  };
  const problems = Object.entries(review?.batch.problems ?? {});

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <Link to="/scripts?view=runs" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-fg">
        <ArrowLeft className="size-3.5" /> Fleet runs
      </Link>
      <h1 className="mb-5 text-[20px] font-semibold tracking-tight text-fg">Run a script on devices</h1>
      {error ? (
        <div className="mb-4">
          <ErrorNotice error={error} />
        </div>
      ) : null}
      <div className="grid gap-5 xl:grid-cols-[400px_minmax(0,1fr)]">
        <Panel title="Script">
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
              <div className="flex items-center gap-2 text-[12.5px] text-muted">
                <RunAsBadge runAs={version.definition.run_as} /> times out after {version.definition.timeout_seconds}s
              </div>
            ) : null}
            <Field label="Run name" hint="Shown in fleet run history">
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={version?.definition.name ?? "e.g. Patch Tuesday cleanup"} maxLength={100} />
            </Field>
            <ParameterFields version={version} values={values} onChange={setValues} />
            <Button variant="primary" className="w-full" icon={<Send className="size-4" />} loading={busy} disabled={!version || count === 0 || !argumentsComplete(version, values)} onClick={() => void doReview()}>
              Review {count ? `(${count} selected)` : ""}
            </Button>
          </div>
        </Panel>
        <Panel
          title="Targets"
          bodyClassName="p-0"
          actions={<span className={cx("text-[12px]", count >= MAX_TARGETS ? "text-warn" : "text-muted")}>{count} of {MAX_TARGETS} max</span>}
        >
          {(devices.data?.groups ?? []).length ? (
            <div className="flex flex-wrap gap-2 border-b border-border p-3">
              <span className="text-[12px] text-muted">Groups:</span>
              {devices.data!.groups.map((g) => (
                <button key={g.id} type="button" onClick={() => toggle(groups, setGroups, g.id)} className={cx("rounded-md border px-2 py-0.5 text-[12.5px]", groups.has(g.id) ? "border-accent bg-accent-soft text-fg" : "border-border text-muted hover:border-border-strong")}>
                  {g.name}
                </button>
              ))}
            </div>
          ) : null}
          <div className="border-b border-border p-3">
            <SearchInput value={filter} onChange={setFilter} placeholder="Filter devices" />
          </div>
          {devices.isPending ? (
            <div className="p-4">
              <Spinner label="Loading devices" />
            </div>
          ) : list.length === 0 ? (
            <EmptyState title="No devices match" />
          ) : (
            <ul className="max-h-[520px] divide-y divide-border overflow-y-auto">
              {list.map((d) => (
                <li key={d.id}>
                  <label className="flex cursor-pointer items-center gap-3 px-4 py-2 hover:bg-surface-2">
                    <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={selected.has(d.id)} onChange={() => toggle(selected, setSelected, d.id)} />
                    <span className="flex-1 truncate text-fg">{d.hostname}</span>
                    <span className="text-[12px] text-faint">{d.group_name ?? "Ungrouped"}</span>
                    <DeviceStatusBadge status={d.status} />
                  </label>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Modal
        open={review !== null}
        onOpenChange={(o) => !o && setReview(null)}
        title={review ? `Run ${review.batch.version.definition.name} on ${review.batch.targets?.length ?? 0} devices?` : ""}
        width="max-w-2xl"
        footer={
          <>
            <Button variant="ghost" onClick={() => setReview(null)}>
              Cancel
            </Button>
            <Button variant="primary" loading={busy} disabled={problems.length > 0 || !(review?.batch.targets?.length)} onClick={() => void apply()}>
              Run on {review?.batch.targets?.length ?? 0} devices
            </Button>
          </>
        }
      >
        {review ? (
          <div className="space-y-3 text-[13px]">
            <div className="flex items-center gap-2 text-muted">
              <RunAsBadge runAs={review.batch.version.definition.run_as} /> v{review.batch.version.number} · group members are fixed now; later group changes never add devices to this run.
            </div>
            <ul className="max-h-64 divide-y divide-border overflow-y-auto rounded-md border border-border">
              {(review.batch.targets ?? []).map((t) => (
                <li key={t.device_id} className="flex items-center gap-3 px-3 py-1.5">
                  <span className="flex-1 text-fg">{t.hostname}</span>
                  {review.batch.problems?.[t.device_id] ? <Badge tone="danger">{review.batch.problems[t.device_id]}</Badge> : <Badge tone="ok">Ready</Badge>}
                </li>
              ))}
            </ul>
            {problems.length ? <p className="text-danger">Some devices aren't ready. Every target must be ready, or nothing runs. Remove them or wait, then review again.</p> : null}
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

export function BatchDetail() {
  const { batch = "" } = useParams();
  const [run, setRun] = useState<{ device: string; id: string } | null>(null);
  const q = useQuery({
    queryKey: ["script-batch", batch],
    queryFn: ({ signal }) => get<ScriptBatch>(`/api/v1/script-batches/${batch}`, signal),
    refetchInterval: (query) => ((query.state.data?.targets ?? []).some((t) => ["queued", "dispatched", "running"].includes(t.status ?? "")) ? 2000 : 15000),
  });
  if (q.isPending) return <div className="p-8"><Spinner label="Loading run" /></div>;
  if (q.isError && !q.data) return <div className="p-8"><ErrorNotice error={q.error} /></div>;
  const b = q.data!;
  const targets = b.targets ?? [];
  const counts = targets.reduce<Record<string, number>>((acc, t) => ((acc[t.status ?? "unknown"] = (acc[t.status ?? "unknown"] ?? 0) + 1), acc), {});
  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <Link to="/scripts?view=runs" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-fg">
        <ArrowLeft className="size-3.5" /> Fleet runs
      </Link>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <h1 className="text-[20px] font-semibold tracking-tight text-fg">{b.change.name}</h1>
        <span className="text-muted">
          {b.version.definition.name} v{b.version.number}
        </span>
        <RunAsBadge runAs={b.version.definition.run_as} />
        {b.restored ? <Badge tone="warn">Restored from backup</Badge> : null}
        <span className="text-[12.5px] text-faint">
          by {b.actor} · {absoluteTime(b.created_at)}
        </span>
      </div>
      <div className="mb-4 flex flex-wrap gap-2">
        {Object.entries(counts).map(([s, n]) => (
          <span key={s} className="inline-flex items-center gap-1.5">
            <OperationStatus status={s} /> <span className="text-muted">{n}</span>
          </span>
        ))}
      </div>
      <Panel bodyClassName="p-0">
        <ul className="divide-y divide-border">
          {targets.map((t) => (
            <li key={t.device_id}>
              <button type="button" className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-2" onClick={() => setRun({ device: t.device_id, id: t.run_id })}>
                <span className="flex-1 font-medium text-fg">{t.hostname}</span>
                {t.cancel_requested ? <Badge tone="warn">Cancel requested</Badge> : null}
                <OperationStatus status={t.status ?? "unknown"} />
              </button>
            </li>
          ))}
        </ul>
      </Panel>
      <RunDetailModal deviceId={run?.device ?? ""} runId={run?.id ?? null} onClose={() => setRun(null)} />
    </div>
  );
}
