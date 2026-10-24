import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Power, RefreshCw, ShieldCheck } from "lucide-react";
import { get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { UpdateIdentity, UpdateJob, UpdatesResponse, WindowsUpdate } from "../../lib/types";
import { ConfirmDialog } from "../../components/Dialog";
import { Badge, Button, EmptyState, ErrorNotice, Panel, Spinner, Tip, cx } from "../../components/ui";
import { SkippedBadge } from "./SkippedBadge";
import { OperationStatus } from "../../components/status";

const key = (u: UpdateIdentity) => `${u.id}:${u.revision}`;

function jobLabel(j: UpdateJob): string {
  if (j.action === "scan") return "Scan for updates";
  if (j.action === "restart") return "Restart device";
  const n = j.updates?.length ?? 0;
  return `Install ${n} update${n === 1 ? "" : "s"}`;
}

function jobOutcome(j: UpdateJob): string {
  if (j.status === "queued") return "Waiting for the device";
  if (j.status === "dispatched") return j.progress ? `${j.progress.phase.replaceAll("_", " ")} · ${j.progress.completed}/${j.progress.total}` : "In progress";
  if (j.status === "unknown") return "Outcome uncertain — check the device and scan again";
  if (!j.progress) return "";
  if (j.progress.outcome === "restart_scheduled") return "Windows accepted the restart request";
  if (j.progress.outcome === "reboot_required") return "Restart required to finish";
  if (j.action === "scan" && j.progress.outcome === "ok") return j.progress.truncated ? "Partial results (over 100 updates)" : "Scan complete";
  return j.progress.outcome.replaceAll("_", " ");
}

export function UpdatesTab({ deviceId }: { deviceId: string }) {
  const client = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<"install" | "restart" | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const q = useQuery({
    queryKey: ["updates", deviceId],
    queryFn: ({ signal }) => get<UpdatesResponse>(`/api/v1/devices/${deviceId}/updates`, signal),
    refetchInterval: (query) => (query.state.data?.pending ? 3000 : 15000),
  });
  const scanID = q.data?.scan?.id;
  // A different scan invalidates any previous selection.
  useEffect(() => setSelected(new Set()), [scanID]);
  const catalog = useMemo(() => q.data?.scan?.catalog ?? [], [q.data]);

  if (q.isPending) return <Spinner label="Loading Windows Update" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const d = q.data!;
  const r = d.readiness;
  const chosen = catalog.filter((u) => selected.has(key(u)));

  const submit = async (action: "scan" | "install" | "restart") => {
    await post(`/api/v1/devices/${deviceId}/updates`, {
      id: newOperationID(),
      action,
      scan_id: action === "install" ? d.scan?.id ?? "" : "",
      updates: action === "install" ? chosen.map((u) => ({ id: u.id, revision: u.revision })) : [],
    });
    await client.invalidateQueries({ queryKey: ["updates", deviceId] });
  };
  const scan = async () => {
    setScanning(true);
    setError(null);
    try {
      await submit("scan");
    } catch (e) {
      setError(e);
    } finally {
      setScanning(false);
    }
  };
  const toggle = (u: WindowsUpdate) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(key(u))) n.delete(key(u));
      else if (n.size < 25) n.add(key(u));
      return n;
    });

  return (
    <div className="space-y-5">
      <Panel>
        <div className="flex flex-wrap items-center gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-muted" />
              <span className="font-medium text-fg">Windows Update</span>
              <Badge tone={d.support.data?.broker === "available" && !d.support.stale ? "ok" : "warn"} dot>
                {d.support.data?.broker === "available" ? (d.support.stale ? "Report stale" : "Ready") : "Unavailable"}
              </Badge>
              <Badge tone={d.support.data?.can_install ? "accent" : "neutral"}>Install {d.support.data?.can_install ? "allowed" : "off"}</Badge>
              <Badge tone={d.support.data?.can_restart ? "accent" : "neutral"}>Restart {d.support.data?.can_restart ? "allowed" : "off"}</Badge>
            </div>
            {!r.can_scan ? <p className="mt-1.5 text-[12.5px] text-muted">{r.reason}</p> : null}
          </div>
          <Button icon={<RefreshCw className="size-4" />} loading={scanning} disabled={!r.can_scan} onClick={() => void scan()}>
            Scan now
          </Button>
          <Tip label={r.can_restart ? "Ask Windows to restart (only if a restart is required)" : r.restart_reason}>
            <span>
              <Button icon={<Power className="size-4" />} disabled={!r.can_restart} onClick={() => setConfirm("restart")}>
                Restart
              </Button>
            </span>
          </Tip>
        </div>
        {d.policies.length || d.guard?.hold ? (
          <div className="mt-3 flex flex-wrap gap-2 border-t border-border pt-3 text-[12.5px] text-muted">
            {d.policies.map((p) => (
              <Badge key={p.id} tone={p.state === "active" ? "info" : "neutral"}>
                Policy: {p.definition.name} ({p.state})
              </Badge>
            ))}
            {d.guard?.hold ? <Badge tone="warn">Patch hold: {d.guard.hold.replaceAll("_", " ")}</Badge> : null}
          </div>
        ) : null}
      </Panel>

      {error ? <ErrorNotice error={error} /> : null}

      <Panel
        bodyClassName="p-0"
        title={d.scan ? `Available updates · scanned ${relativeTime(d.scan.created_at)}` : "Available updates"}
        actions={
          <div className="flex items-center gap-2">
            {d.scan && !d.scan.fresh ? <Badge tone="warn">Older than 2 hours — scan again to install</Badge> : null}
            {d.scan?.truncated ? <Badge tone="warn">Over 100 found; list is partial</Badge> : null}
            <SkippedBadge count={d.scan?.skipped} one="update" many="updates" />
            <Tip label={r.can_install ? `Install the ${chosen.length} selected update(s)` : r.install_reason}>
              <span>
                <Button size="sm" variant="primary" disabled={!r.can_install || chosen.length === 0} onClick={() => setConfirm("install")}>
                  Install selected{chosen.length ? ` (${chosen.length})` : ""}
                </Button>
              </span>
            </Tip>
          </div>
        }
      >
        {!d.scan ? (
          <EmptyState icon={<ShieldCheck />} title="No scan results yet">
            Run a scan to see which updates apply. No result does not mean the device is up to date.
          </EmptyState>
        ) : catalog.length === 0 ? (
          <EmptyState title="No applicable updates were found by the last scan" />
        ) : (
          <ul className="divide-y divide-border">
            {catalog.map((u) => {
              const on = selected.has(key(u));
              const blocked = u.blocked !== "";
              return (
                <li key={key(u)}>
                  <label className={cx("flex items-start gap-3 px-4 py-2.5", blocked ? "opacity-60" : "cursor-pointer hover:bg-surface-2")}>
                    <input type="checkbox" className="mt-1 size-4 accent-[var(--accent)]" checked={on} disabled={blocked || !r.can_install} onChange={() => toggle(u)} aria-label={`Select ${u.title}`} />
                    <div className="min-w-0 flex-1">
                      <div className="text-fg">{u.title}</div>
                      <div className="mt-0.5 flex flex-wrap gap-1.5 text-[12px] text-muted">
                        {(u.kb ?? []).map((kb) => (
                          <span key={kb} className="font-mono">
                            KB{kb}
                          </span>
                        ))}
                        {u.severity ? <Badge tone={u.severity === "Critical" ? "danger" : u.severity === "Important" ? "warn" : "neutral"}>{u.severity}</Badge> : null}
                        {blocked ? <Badge tone="neutral">Can't install remotely: {u.blocked.replaceAll("_", " ")}</Badge> : null}
                      </div>
                    </div>
                  </label>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      {d.jobs.length ? (
        <Panel title="History" bodyClassName="p-0">
          <ul className="divide-y divide-border">
            {d.jobs.slice(0, 15).map((j) => (
              <li key={j.id} className="flex items-center gap-3 px-4 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="text-fg">{jobLabel(j)}</div>
                  <div className="text-[12px] text-faint">
                    by {j.actor}
                    {jobOutcome(j) ? ` · ${jobOutcome(j)}` : ""}
                  </div>
                </div>
                <OperationStatus status={j.status} />
                <Tip label={absoluteTime(j.created_at)}>
                  <span className="w-16 text-right text-[12px] text-muted">{relativeTime(j.created_at)}</span>
                </Tip>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={confirm === "restart" ? "Restart this device?" : `Install ${chosen.length} update${chosen.length === 1 ? "" : "s"}?`}
        confirmLabel={confirm === "restart" ? "Request restart" : "Install"}
        danger={confirm === "restart"}
        onConfirm={async () => {
          if (confirm) await submit(confirm);
          if (confirm === "install") setSelected(new Set());
        }}
      >
        {confirm === "restart" ? (
          <p>Windows restarts only if it reports that a restart is required, with a 60-second warning to signed-in users.</p>
        ) : (
          <ul className="list-disc space-y-1 pl-5">
            {chosen.map((u) => (
              <li key={key(u)} className="text-fg">
                {u.title}
              </li>
            ))}
          </ul>
        )}
      </ConfirmDialog>
    </div>
  );
}
