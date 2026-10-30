import { useMemo } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { Bell, CheckCheck, ChevronLeft, ChevronRight, Settings, X } from "lucide-react";
import { get, post } from "../../lib/api";
import { LIVE_INTERVAL, useNow } from "../../lib/hooks";
import { absoluteTime, alertTitle, observedText, relativeTime, triggerText } from "../../lib/format";
import type { AlertDetail, AlertRow, AlertsResponse } from "../../lib/types";
import { useAccount } from "../../lib/session";
import { PageHeader } from "../../app/AppShell";
import { Freshness } from "../../components/Freshness";
import { Badge, Button, EmptyState, ErrorNotice, Panel, SearchInput, Segmented, Select, Spinner, Tip, cx, type Tone } from "../../components/ui";
import { OperationStatus, SeverityBadge } from "../../components/status";

const conditionText: Record<string, { label: string; tone: Tone }> = {
  bad: { label: "Problem ongoing", tone: "danger" },
  good: { label: "Recovering", tone: "ok" },
  unknown: { label: "No fresh reading", tone: "neutral" },
};

const closeReasons: Record<string, string> = {
  recovered: "Recovered — healthy readings were confirmed for the recovery period.",
  settings_changed: "Closed because alert settings changed. This does not mean it recovered.",
  policy_changed: "Closed because the device's monitoring policy changed. This does not mean it recovered.",
  not_monitored: "Closed because the device left monitoring (for example, it was revoked). This does not mean it recovered.",
  rollout_resumed: "Closed when automatic agent updates were resumed.",
};

function AlertDetailPanel({ id, onClose, owner }: { id: string; onClose: () => void; owner: boolean }) {
  const client = useQueryClient();
  const now = useNow();
  const q = useQuery({ queryKey: ["alert", id], queryFn: ({ signal }) => get<AlertDetail>(`/api/v1/alerts/${id}`, signal), refetchInterval: LIVE_INTERVAL });
  const ack = useMutation({
    mutationFn: () => post(`/api/v1/alerts/${id}/acknowledge`),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["alert", id] });
      void client.invalidateQueries({ queryKey: ["alerts"] });
      void client.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
  if (q.isPending) return <div className="p-5"><Spinner label="Loading alert" /></div>;
  if (q.isError && !q.data) return <div className="p-5"><ErrorNotice error={q.error} /></div>;
  const d = q.data!;
  const a = d.alert;
  const obs = conditionText[d.observation.condition] ?? conditionText.unknown!;
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-start gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={a.severity} />
            <OperationStatus status={a.status} />
            {a.acknowledged_at ? <Badge tone="neutral">Acknowledged</Badge> : null}
          </div>
          <h2 className="text-[16px] font-semibold text-fg">{alertTitle(a.kind, a.label)}</h2>
          <Link to={`/devices/${a.device_id}`} className="text-accent hover:underline">
            {a.hostname}
          </Link>
        </div>
        <button type="button" onClick={onClose} className="rounded p-1 text-muted hover:bg-surface-2 hover:text-fg" aria-label="Close details">
          <X className="size-4" />
        </button>
      </div>
      <div className="flex-1 space-y-5 overflow-y-auto px-5 py-4">
        {owner && a.status === "active" && !a.acknowledged_at ? (
          <div>
            <Button variant="primary" icon={<CheckCheck className="size-4" />} loading={ack.isPending} onClick={() => ack.mutate()}>
              Acknowledge
            </Button>
            <p className="mt-1.5 text-[12px] text-faint">Marks it as seen. It stays open until the device recovers; any email still queued for it is cancelled.</p>
            {ack.isError ? <ErrorNotice error={ack.error} /> : null}
          </div>
        ) : null}
        <section className="space-y-1.5">
          <h3 className="text-[12px] font-semibold tracking-wide text-faint uppercase">What happened</h3>
          <p className="text-fg">{triggerText(a, d.family)}</p>
        </section>
        {a.status === "active" ? (
          <section className="space-y-1.5">
            <h3 className="text-[12px] font-semibold tracking-wide text-faint uppercase">Right now</h3>
            <div className="flex items-center gap-2">
              <Badge tone={obs.tone} dot>
                {obs.label}
              </Badge>
              {d.observation.value !== null ? <span className="text-fg tabular-nums">{observedText(a.kind, d.observation.value, 1)}</span> : null}
              {d.observation.observed_at ? <span className="text-[12px] text-muted">reading {relativeTime(d.observation.observed_at, now)}</span> : null}
            </div>
            {d.evaluator_stale ? <p className="text-[12px] text-warn">The alert engine hasn't run recently, so current readings are unknown.</p> : null}
            {d.observation.condition === "good" ? <p className="text-[12px] text-muted">Readings look healthy; it closes once that holds for the recovery period.</p> : null}
          </section>
        ) : (
          <section className="space-y-1.5">
            <h3 className="text-[12px] font-semibold tracking-wide text-faint uppercase">Outcome</h3>
            <p className="text-fg">{closeReasons[a.close_reason] ?? a.close_reason}</p>
          </section>
        )}
        <section>
          <h3 className="mb-1.5 text-[12px] font-semibold tracking-wide text-faint uppercase">Timeline</h3>
          <dl className="grid grid-cols-[120px_1fr] gap-y-1 text-[13px]">
            <dt className="text-muted">Opened</dt>
            <dd className="text-fg">{absoluteTime(a.opened_at)}</dd>
            <dt className="text-muted">Last seen</dt>
            <dd className="text-fg">{absoluteTime(a.last_seen)}</dd>
            {a.acknowledged_at ? (
              <>
                <dt className="text-muted">Acknowledged</dt>
                <dd className="text-fg">
                  {absoluteTime(a.acknowledged_at)} by {a.acknowledged_by}
                </dd>
              </>
            ) : null}
            {a.finished_at ? (
              <>
                <dt className="text-muted">Ended</dt>
                <dd className="text-fg">{absoluteTime(a.finished_at)}</dd>
              </>
            ) : null}
          </dl>
        </section>
        <section>
          <h3 className="mb-1.5 text-[12px] font-semibold tracking-wide text-faint uppercase">Email</h3>
          {d.deliveries.length === 0 ? (
            <p className="text-[13px] text-muted">No emails for this alert.</p>
          ) : (
            <ul className="space-y-1.5">
              {d.deliveries.map((m) => (
                <li key={m.id} className="flex items-center gap-2 text-[13px]">
                  <span className="text-fg capitalize">{m.event}</span>
                  <OperationStatus status={m.status} />
                  <span className="text-[12px] text-muted">
                    {relativeTime(m.created_at, now)}
                    {m.attempts > 1 ? ` · ${m.attempts} attempts` : ""}
                    {m.reason ? ` · ${m.reason.replaceAll("_", " ")}` : ""}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}

export function AlertsPage() {
  const account = useAccount();
  const now = useNow();
  const [params, setParams] = useSearchParams();
  const selected = params.get("id");
  const status = params.get("status") ?? "active";
  const query = useMemo(() => {
    const q = new URLSearchParams();
    for (const k of ["device", "group", "severity", "ack", "kind", "q", "page"]) {
      const v = params.get(k);
      if (v) q.set(k, v);
    }
    if (status !== "all") q.set("status", status);
    return q.toString();
  }, [params, status]);
  const q = useQuery({ queryKey: ["alerts", query], queryFn: ({ signal }) => get<AlertsResponse>(`/api/v1/alerts?${query}`, signal), refetchInterval: LIVE_INTERVAL, placeholderData: (prev) => prev });

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "id" && key !== "page") next.delete("page");
    setParams(next, { replace: true });
  };
  const page = Number(params.get("page") ?? "1");
  const d = q.data;

  const Row = ({ a }: { a: AlertRow }) => (
    <li>
      <button
        type="button"
        onClick={() => set("id", a.id)}
        className={cx("flex w-full items-start gap-3 border-l-2 px-4 py-3 text-left hover:bg-surface-2", selected === a.id ? "border-accent bg-accent-soft" : "border-transparent")}
      >
        <span className={cx("mt-1.5 size-2 shrink-0 rounded-full", a.status !== "active" ? "bg-neutral" : a.severity === "critical" ? "bg-danger" : "bg-warn")} aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-medium text-fg">{alertTitle(a.kind, a.label)}</span>
            {a.acknowledged_at ? <Badge tone="neutral">Ack</Badge> : null}
          </div>
          <div className="flex items-center gap-2 text-[12px] text-muted">
            <span className="truncate">{a.hostname}</span>
            {a.status === "active" ? (
              <span className={a.observation.condition === "bad" ? "text-danger" : a.observation.condition === "good" ? "text-ok" : "text-faint"}>
                · {conditionText[a.observation.condition]?.label}
                {a.observation.value !== null ? ` ${observedText(a.kind, a.observation.value)}` : ""}
              </span>
            ) : (
              <span>· {a.status}</span>
            )}
          </div>
        </div>
        <Tip label={absoluteTime(a.opened_at)}>
          <span className="shrink-0 text-[12px] text-muted tabular-nums">{relativeTime(a.opened_at, now)}</span>
        </Tip>
      </button>
    </li>
  );

  return (
    <div className="mx-auto flex h-full max-w-[1600px] flex-col px-6 py-6">
      <PageHeader
        title="Alerts"
        subtitle={d ? `${d.counts.active} active · ${d.counts.critical_active} critical · ${d.counts.unacknowledged_active} unacknowledged` : undefined}
        actions={
          <>
            {d ? <Freshness updatedAt={q.dataUpdatedAt} failed={q.isError} /> : null}
            {account.permissions.owner ? (
              <Link to="/settings/alerts">
                <Button icon={<Settings className="size-4" />}>Alert settings</Button>
              </Link>
            ) : null}
          </>
        }
      />
      {d?.evaluator_stale ? (
        <div className="mb-3 rounded-md border border-warn/30 bg-warn-soft px-3 py-2 text-[13px] text-warn">The alert engine hasn't run in the last 45 seconds. Current conditions are shown as unknown.</div>
      ) : null}
      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[minmax(0,1fr)_420px]">
        <Panel bodyClassName="p-0 flex flex-col min-h-0" className="flex min-h-0 flex-col">
          <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
            <Segmented
              label="Status"
              value={status}
              onChange={(v) => set("status", v === "active" ? "" : v)}
              options={[
                { value: "active", label: "Active" },
                { value: "resolved", label: "Resolved" },
                { value: "closed", label: "Closed" },
                { value: "all", label: "All" },
              ]}
            />
            <Select value={params.get("severity") ?? ""} onChange={(e) => set("severity", e.target.value)} aria-label="Severity">
              <option value="">Any severity</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
            </Select>
            <Select value={params.get("kind") ?? ""} onChange={(e) => set("kind", e.target.value)} aria-label="Type">
              <option value="">Any type</option>
              <option value="offline">Offline</option>
              <option value="cpu">CPU</option>
              <option value="memory">Memory</option>
              <option value="disk_space">Disk space</option>
              <option value="health">Health check</option>
            </Select>
            <Select value={params.get("ack") ?? ""} onChange={(e) => set("ack", e.target.value)} aria-label="Acknowledgement">
              <option value="">Acknowledged or not</option>
              <option value="unacknowledged">Unacknowledged</option>
              <option value="acknowledged">Acknowledged</option>
            </Select>
            {(d?.groups ?? []).length ? (
              <Select value={params.get("group") ?? ""} onChange={(e) => set("group", e.target.value)} aria-label="Group">
                <option value="">All groups</option>
                <option value="ungrouped">Ungrouped</option>
                {d!.groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </Select>
            ) : null}
            <SearchInput value={params.get("q") ?? ""} onChange={(v) => set("q", v)} placeholder="Search device or alert" className="w-56" />
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {q.isPending ? (
              <div className="p-4">
                <Spinner label="Loading alerts" />
              </div>
            ) : q.isError && !d ? (
              <div className="p-4">
                <ErrorNotice error={q.error} retry={() => void q.refetch()} />
              </div>
            ) : d!.alerts.length === 0 ? (
              <EmptyState icon={<Bell />} title={status === "active" ? "No active alerts" : "No alerts match"} />
            ) : (
              <ul className="divide-y divide-border">
                {d!.alerts.map((a) => (
                  <Row key={a.id} a={a} />
                ))}
              </ul>
            )}
          </div>
          {d && d.counts.matching > d.page_size ? (
            <div className="flex items-center justify-between border-t border-border px-3 py-2 text-[12px] text-muted">
              <span>
                {(page - 1) * d.page_size + 1}–{Math.min(page * d.page_size, d.counts.matching)} of {d.counts.matching}
              </span>
              <div className="flex gap-1">
                <Button size="sm" variant="ghost" icon={<ChevronLeft className="size-4" />} disabled={page <= 1} onClick={() => set("page", String(page - 1))} aria-label="Previous page" />
                <Button size="sm" variant="ghost" icon={<ChevronRight className="size-4" />} disabled={page * d.page_size >= d.counts.matching} onClick={() => set("page", String(page + 1))} aria-label="Next page" />
              </div>
            </div>
          ) : null}
        </Panel>
        <section className="min-h-0 overflow-hidden rounded-lg border border-border bg-surface">
          {selected ? (
            <AlertDetailPanel id={selected} owner={account.permissions.owner} onClose={() => set("id", "")} />
          ) : (
            <EmptyState icon={<Bell />} title="Select an alert">
              Its details, current reading and email history appear here.
            </EmptyState>
          )}
        </section>
      </div>
    </div>
  );
}
