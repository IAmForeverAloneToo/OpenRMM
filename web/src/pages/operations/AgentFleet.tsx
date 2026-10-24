import { useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, Rocket } from "lucide-react";
import { get, post } from "../../lib/api";
import { newOperationID } from "../../lib/id";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { plural } from "../../lib/format";
import type { AgentFleet as Fleet, AgentFleetDevice, AgentFleetStatus, AgentRolloutReview } from "../../lib/types";
import { ConfirmDialog } from "../../components/Dialog";
import { DataTable, type Column } from "../../components/DataTable";
import { Freshness } from "../../components/Freshness";
import { Badge, Button, EmptyState, ErrorNotice, Mono, Panel, Spinner, Tip, cx, type Tone } from "../../components/ui";

const states: Record<AgentFleetStatus, { label: string; tone: Tone }> = {
  up_to_date: { label: "Up to date", tone: "ok" },
  updating: { label: "Updating", tone: "info" },
  available: { label: "Update available", tone: "warn" },
  offline: { label: "Offline", tone: "neutral" },
  needs_local: { label: "Needs local setup", tone: "danger" },
  no_release: { label: "No release", tone: "neutral" },
  not_reported: { label: "Not reported", tone: "neutral" },
};
const order: AgentFleetStatus[] = ["available", "needs_local", "updating", "offline", "not_reported", "up_to_date", "no_release"];

/** Rolls the release out to devices in reviewed batches of at most 25. */
async function rollOut(releaseID: string, devices: string[]): Promise<void> {
  for (let i = 0; i < devices.length; i += 25) {
    const change = { id: newOperationID(), release_id: releaseID, devices: devices.slice(i, i + 25), groups: [] };
    const review = await post<AgentRolloutReview>("/api/v1/agent-rollouts/review", { change, digest: "" });
    await post("/api/v1/agent-rollouts/apply", { change, digest: review.digest });
  }
}

/** Which devices run the latest release, and one-click updates for the rest. */
export function AgentFleet() {
  const client = useQueryClient();
  const q = useQuery({ queryKey: ["agent-fleet"], queryFn: ({ signal }) => get<Fleet>("/api/v1/agent-fleet", signal), refetchInterval: LIVE_INTERVAL });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [shown, setShown] = useState<AgentFleetStatus | "">("");
  const [confirm, setConfirm] = useState<string[] | null>(null);
  const devices = useMemo(() => q.data?.devices ?? [], [q.data]);
  const counts = useMemo(() => {
    const c: Partial<Record<AgentFleetStatus, number>> = {};
    for (const d of devices) c[d.status] = (c[d.status] ?? 0) + 1;
    return c;
  }, [devices]);

  if (q.isPending) return <Panel title="Devices"><Spinner label="Loading agent status" /></Panel>;
  if (q.isError && !q.data) return <Panel title="Devices"><ErrorNotice error={q.error} retry={() => void q.refetch()} /></Panel>;

  const latest = q.data!.latest;
  const rows = devices.filter((d) => !shown || d.status === shown);
  const available = devices.filter((d) => d.status === "available").map((d) => d.id);
  const chosen = [...selected].filter((id) => available.includes(id));
  const toggle = (id: string, on: boolean) => {
    const next = new Set(selected);
    if (on) next.add(id);
    else next.delete(id);
    setSelected(next);
  };
  const columns: Column<AgentFleetDevice>[] = [
    {
      key: "select",
      header: "",
      className: "w-px",
      cell: (d) =>
        d.status === "available" ? (
          <input type="checkbox" className="size-4 accent-[var(--accent)]" aria-label={`Select ${d.hostname}`} checked={selected.has(d.id)} onChange={(e) => toggle(d.id, e.target.checked)} />
        ) : null,
    },
    {
      key: "device",
      header: "Device",
      sort: (d) => d.hostname,
      cell: (d) => (
        <Link to={`/devices/${d.id}`} className="font-medium text-fg hover:text-accent">
          {d.hostname}
        </Link>
      ),
    },
    { key: "version", header: "Agent", sort: (d) => d.agent_version, cell: (d) => <Mono className="text-muted">{d.agent_version || "—"}</Mono> },
    {
      key: "status",
      header: "Status",
      sort: (d) => order.indexOf(d.status),
      cell: (d) => (
        <span className="flex items-center gap-2">
          <Badge tone={states[d.status].tone} dot>
            {states[d.status].label}
          </Badge>
          {d.reason ? <span className="text-[12px] text-muted">{d.reason}</span> : null}
          {d.reinstall.length ? (
            <Tip label="This agent predates self-update through MSI packages. A local administrator installs the agent MSI once (scripts/install-agent.ps1); device identity and state are kept.">
              <span>
                <Badge tone="warn">Reinstall locally: {d.reinstall.join(", ")}</Badge>
              </span>
            </Tip>
          ) : null}
        </span>
      ),
    },
  ];

  return (
    <Panel
      title="Devices"
      bodyClassName="p-0"
      actions={
        <span className="flex items-center gap-2">
          <Freshness updatedAt={q.dataUpdatedAt} failed={q.isError} />
          {latest ? (
            <>
              <Button size="sm" disabled={chosen.length === 0} onClick={() => setConfirm(chosen)}>
                Update selected
              </Button>
              <Button size="sm" variant="primary" icon={<Rocket className="size-3.5" />} disabled={available.length === 0} onClick={() => setConfirm(available)}>
                Update all available ({available.length})
              </Button>
            </>
          ) : null}
        </span>
      }
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5 text-[12.5px]">
        <span className="text-muted">
          Latest release: {latest ? <span className="text-fg">{latest.release.manifest.version}</span> : "none"}
          {latest ? <span className="text-faint"> · sequence {latest.release.manifest.sequence}</span> : null}
        </span>
        <div className="flex-1" />
        <button type="button" onClick={() => setShown("")} className={cx("rounded-md border px-2 py-0.5", shown === "" ? "border-accent bg-accent-soft text-fg" : "border-border text-muted hover:border-border-strong")}>
          All {devices.length}
        </button>
        {order
          .filter((s) => counts[s])
          .map((s) => (
            <button key={s} type="button" onClick={() => setShown(s)} className={cx("rounded-md border px-2 py-0.5", shown === s ? "border-accent bg-accent-soft text-fg" : "border-border text-muted hover:border-border-strong")}>
              {states[s].label} {counts[s]}
            </button>
          ))}
      </div>
      <DataTable columns={columns} rows={rows} rowKey={(d) => d.id} initialSort={{ key: "status", dir: "asc" }} dense empty={<EmptyState icon={<CircleCheck />} title="No Windows devices" />} />
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Update ${plural(confirm?.length ?? 0, "device")} to ${latest?.release.manifest.version ?? ""}?`}
        confirmLabel="Update"
        onConfirm={async () => {
          await rollOut(latest!.id, confirm!);
          setSelected(new Set());
          await Promise.all([client.invalidateQueries({ queryKey: ["agent-fleet"] }), client.invalidateQueries({ queryKey: ["agent-upgrades"] })]);
        }}
      >
        <p>
          Each device's agent verifies the signature, installs the package and reinstalls its previous package on its own if the new agent does not come back healthy. Devices are updated in batches of 25; if a device went offline or changed since this list loaded, its batch is refused and
          nothing in it is queued.
        </p>
      </ConfirmDialog>
    </Panel>
  );
}
