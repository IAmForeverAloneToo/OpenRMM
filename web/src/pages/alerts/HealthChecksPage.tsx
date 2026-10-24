import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { HeartPulse, Plus } from "lucide-react";
import { get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { DeviceDetail, DevicesResponse, HealthCheck, HealthResponse, HealthStatus } from "../../lib/types";
import { useAccount } from "../../lib/session";
import { PageHeader } from "../../app/AppShell";
import { Freshness } from "../../components/Freshness";
import { Modal } from "../../components/Dialog";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, Button, EmptyState, ErrorNotice, Field, Input, Panel, Select, Spinner, Tip, type Tone } from "../../components/ui";
import { OperationStatus } from "../../components/status";

const conditions: Record<string, { label: string; tone: Tone }> = {
  good: { label: "Running", tone: "ok" },
  bad: { label: "Not running", tone: "danger" },
  unknown: { label: "Unknown", tone: "neutral" },
};

function CheckEditor({ open, onOpenChange, existing }: { open: boolean; onOpenChange: (o: boolean) => void; existing: HealthStatus | null }) {
  const client = useQueryClient();
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal), enabled: open });
  const [check, setCheck] = useState<HealthCheck | null>(null);
  const [rearm, setRearm] = useState(false);
  const [digest, setDigest] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const deviceDetail = useQuery({ queryKey: ["device", check?.device_id], queryFn: ({ signal }) => get<DeviceDetail>(`/api/v1/devices/${check!.device_id}`, signal), enabled: open && !!check?.device_id });
  useEffect(() => {
    if (!open) return;
    setDigest("");
    setError(null);
    setRearm(false);
    setCheck(existing ? { ...existing } : { id: newOperationID(), device_id: "", name: "", kind: "service_running", service: "", enabled: true, hold_seconds: 120, recovery_seconds: 60, severity: "warning", email: false, response: false, cooldown_seconds: 3600, revision: 0 });
  }, [open, existing]);
  const services = useMemo(() => (deviceDetail.data?.services.data?.items ?? []).slice().sort((a, b) => a.display_name.localeCompare(b.display_name)), [deviceDetail.data]);
  if (!check) return null;
  const set = (p: Partial<HealthCheck>) => {
    setCheck({ ...check, ...p });
    setDigest("");
  };
  const valid = check.device_id && check.service && check.name.trim() && check.hold_seconds >= 60 && check.hold_seconds <= 86400 && check.recovery_seconds >= 60 && check.recovery_seconds <= 3600 && check.cooldown_seconds >= 3600 && check.cooldown_seconds <= 604800;
  const change = { check: { ...check, name: check.name.trim() }, rearm };
  const step = async (op: "review" | "apply") => {
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ digest: string }>(`/api/v1/health-checks/${op}`, { change, digest: op === "apply" ? digest : "" });
      if (op === "review") setDigest(r.digest);
      else {
        await client.invalidateQueries({ queryKey: ["health-checks"] });
        onOpenChange(false);
      }
    } catch (e) {
      setError(e);
      setDigest("");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={existing ? `Edit “${existing.name}”` : "New health check"}
      description="Alerts when a required Windows service is not running, and can optionally start it once."
      width="max-w-xl"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {digest ? (
            <Button variant="primary" loading={busy} onClick={() => void step("apply")}>
              Save check
            </Button>
          ) : (
            <Button variant="primary" loading={busy} disabled={!valid} onClick={() => void step("review")}>
              Review
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        {!existing ? (
          <Field label="Device">
            <Select value={check.device_id} onChange={(e) => set({ device_id: e.target.value, service: "" })} className="w-full">
              <option value="">Choose a device…</option>
              {(devices.data?.devices ?? [])
                .filter((d) => d.status !== "revoked" && d.os === "windows")
                .map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.hostname}
                  </option>
                ))}
            </Select>
          </Field>
        ) : null}
        <Field label="Service" hint={check.device_id && services.length === 0 && !deviceDetail.isPending ? "This device hasn't reported its services yet." : undefined}>
          <Select value={check.service} onChange={(e) => set({ service: e.target.value, name: check.name || (services.find((s) => s.name === e.target.value)?.display_name ?? "") })} className="w-full" disabled={!check.device_id || !!existing}>
            <option value="">Choose a service…</option>
            {services.map((s) => (
              <option key={s.name} value={s.name}>
                {s.display_name} ({s.name})
              </option>
            ))}
            {existing && !services.some((s) => s.name === check.service) ? <option value={check.service}>{check.service}</option> : null}
          </Select>
        </Field>
        <Field label="Name">
          <Input value={check.name} onChange={(e) => set({ name: e.target.value })} maxLength={100} />
        </Field>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Alert after (min)">
            <Input type="number" min={1} max={1440} value={check.hold_seconds / 60} onChange={(e) => set({ hold_seconds: Number(e.target.value) * 60 })} />
          </Field>
          <Field label="Recover after (min)">
            <Input type="number" min={1} max={60} value={check.recovery_seconds / 60} onChange={(e) => set({ recovery_seconds: Number(e.target.value) * 60 })} />
          </Field>
          <Field label="Severity">
            <Select value={check.severity} onChange={(e) => set({ severity: e.target.value as HealthCheck["severity"] })} className="w-full">
              <option value="warning">Warning</option>
              <option value="critical">Critical</option>
            </Select>
          </Field>
        </div>
        <div className="space-y-2">
          <label className="flex items-center gap-2 text-[13px] text-fg">
            <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={check.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Check enabled
          </label>
          <label className="flex items-center gap-2 text-[13px] text-fg">
            <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={check.email} onChange={(e) => set({ email: e.target.checked })} /> Send email for this alert
          </label>
          <label className="flex items-start gap-2 text-[13px] text-fg">
            <input type="checkbox" className="mt-0.5 size-4 accent-[var(--accent)]" checked={check.response} onChange={(e) => set({ response: e.target.checked })} />
            <span>
              Try starting the service automatically
              <span className="block text-[12px] text-muted">At most once per alert. If a start fails or its result is unknown, automatic starts stop until you re-arm them.</span>
            </span>
          </label>
          {check.response ? (
            <Field label="Wait between automatic starts (hours)">
              <Input type="number" min={1} max={168} value={check.cooldown_seconds / 3600} onChange={(e) => set({ cooldown_seconds: Math.round(Number(e.target.value) * 3600) })} className="w-24" />
            </Field>
          ) : null}
          {existing?.response_blocked ? (
            <label className="flex items-center gap-2 text-[13px] text-warn">
              <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={rearm} onChange={(e) => (setRearm(e.target.checked), setDigest(""))} /> Re-arm automatic starts (blocked after a failed or uncertain attempt)
            </label>
          ) : null}
        </div>
        {digest ? <p className="rounded-md bg-accent-soft px-3 py-2 text-[12.5px] text-fg">Reviewed. Changing a check closes its open alert and starts qualification again. Choose Save check to apply.</p> : null}
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Modal>
  );
}

export function HealthChecksPage() {
  const account = useAccount();
  const [params] = useSearchParams();
  const device = params.get("device") ?? "";
  const [editor, setEditor] = useState<{ open: boolean; existing: HealthStatus | null }>({ open: false, existing: null });
  const q = useQuery({
    queryKey: ["health-checks", device],
    queryFn: ({ signal }) => get<HealthResponse>(`/api/v1/health-checks${device ? `?device=${device}` : ""}`, signal),
    refetchInterval: LIVE_INTERVAL,
  });
  const columns: Column<HealthStatus>[] = [
    { key: "name", header: "Check", sort: (c) => c.name.toLowerCase(), cell: (c) => <span className="font-medium text-fg">{c.name}</span> },
    { key: "device", header: "Device", sort: (c) => c.hostname, cell: (c) => <Link to={`/devices/${c.device_id}`} className="text-accent hover:underline" onClick={(e) => e.stopPropagation()}>{c.hostname}</Link> },
    { key: "service", header: "Service", sort: (c) => c.service, cell: (c) => <span className="font-mono text-[12.5px] text-muted">{c.service}</span> },
    {
      key: "state",
      header: "State",
      sort: (c) => c.state.condition,
      cell: (c) => {
        if (!c.enabled) return <Badge tone="neutral">Disabled</Badge>;
        const s = conditions[c.state.condition] ?? conditions.unknown!;
        return (
          <Tip label={c.state.last_sample ? `Last reading ${absoluteTime(c.state.last_sample)}` : "No reading yet"}>
            <span>
              <Badge tone={s.tone} dot>
                {s.label}
              </Badge>
            </span>
          </Tip>
        );
      },
    },
    {
      key: "response",
      header: "Auto-start",
      cell: (c) => (!c.response ? <span className="text-faint">Off</span> : c.response_blocked ? <Badge tone="warn">Blocked — needs re-arm</Badge> : <Badge tone="accent">On</Badge>),
    },
    { key: "last", header: "Last attempt", sort: (c) => c.last_attempt, cell: (c) => <span className="text-muted">{c.last_attempt ? relativeTime(c.last_attempt) : "—"}</span> },
  ];
  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader
        title="Health checks"
        subtitle="Required Windows services, with optional automatic start"
        actions={
          <>
            {q.data ? <Freshness updatedAt={q.dataUpdatedAt} failed={q.isError} /> : null}
            {account.permissions.owner ? (
              <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEditor({ open: true, existing: null })}>
                New check
              </Button>
            ) : null}
          </>
        }
      />
      {q.isPending ? (
        <Spinner label="Loading checks" />
      ) : q.isError && !q.data ? (
        <ErrorNotice error={q.error} retry={() => void q.refetch()} />
      ) : (
        <div className="space-y-5">
          <Panel bodyClassName="p-0">
            <DataTable
              columns={columns}
              rows={q.data!.checks}
              rowKey={(c) => c.id}
              onRowClick={account.permissions.owner ? (c) => setEditor({ open: true, existing: c }) : undefined}
              initialSort={{ key: "name", dir: "asc" }}
              empty={
                <EmptyState icon={<HeartPulse />} title="No health checks yet">
                  {account.permissions.owner ? "Add a check to be alerted when an important service stops." : "Ask an administrator to add checks."}
                </EmptyState>
              }
            />
          </Panel>
          {q.data!.attempts.length ? (
            <Panel title="Automatic start attempts" bodyClassName="p-0">
              <ul className="divide-y divide-border">
                {q.data!.attempts.slice(0, 20).map((a) => (
                  <li key={a.action_id} className="flex items-center gap-3 px-4 py-2.5">
                    <span className="flex-1 text-fg">
                      Start <span className="font-mono text-[12.5px]">{a.service}</span> · {a.check_name}
                    </span>
                    <OperationStatus status={a.status} />
                    <span className="w-20 text-right text-[12px] text-muted">{relativeTime(a.created_at)}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          ) : null}
        </div>
      )}
      <CheckEditor open={editor.open} onOpenChange={(o) => setEditor((e) => ({ ...e, open: o }))} existing={editor.existing} />
    </div>
  );
}
