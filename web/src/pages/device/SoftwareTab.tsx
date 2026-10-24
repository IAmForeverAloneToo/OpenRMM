import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { get } from "../../lib/api";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { SoftwareChange, SoftwareEntry, SoftwareResponse } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, EmptyState, ErrorNotice, Mono, Panel, SearchInput, Segmented, Spinner, Tip, Toolbar, type Tone } from "../../components/ui";
import { SkippedBadge } from "./SkippedBadge";
import { snapshotState } from "../../components/status";
import { DeploymentsTable } from "../operations/deployments";

const changeKinds: Record<SoftwareChange["kind"], { label: string; tone: Tone }> = {
  added: { label: "Installed", tone: "ok" },
  removed: { label: "Removed", tone: "danger" },
  version_changed: { label: "Version changed", tone: "info" },
  metadata_changed: { label: "Details changed", tone: "neutral" },
};

function matches(e: SoftwareEntry | null, t: string): boolean {
  return !!e && (e.name.toLowerCase().includes(t) || e.version.toLowerCase().includes(t) || e.publisher.toLowerCase().includes(t) || (e.user ?? "").toLowerCase().includes(t));
}

/** Who an install is for: everyone, or one signed-in user (per-user install). */
function Scope({ e }: { e: SoftwareEntry }) {
  if (e.registry_view !== "user") return <span className="text-faint">All users</span>;
  return (
    <Tip label={`Installed only for this user (${e.user_sid}); read from the user's registry while signed in.`}>
      <span>
        <Badge tone="accent">{e.user}</Badge>
      </span>
    </Tip>
  );
}

export function SoftwareTab({ deviceId }: { deviceId: string }) {
  const [params, setParams] = useSearchParams();
  const view = (["changes", "deployments"].includes(params.get("view") ?? "") ? params.get("view") : "installed") as "installed" | "changes" | "deployments";
  const setView = (v: typeof view) => setParams(v === "installed" ? { tab: "software" } : { tab: "software", view: v }, { replace: true });
  const [filter, setFilter] = useState("");
  const q = useQuery({ queryKey: ["software", deviceId], queryFn: ({ signal }) => get<SoftwareResponse>(`/api/v1/devices/${deviceId}/software`, signal), refetchInterval: LIVE_INTERVAL * 3 });
  const term = filter.trim().toLowerCase();
  const entries = useMemo(() => (q.data?.entries ?? []).filter((e) => !term || matches(e, term)), [q.data, term]);
  const changes = useMemo(() => (q.data?.history ?? []).filter((c) => !term || matches(c.after, term) || matches(c.before, term)), [q.data, term]);

  if (q.isPending) return <Spinner label="Loading software" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const d = q.data!;
  const state = snapshotState(d.info.status, d.info.stale);

  const columns: Column<SoftwareEntry>[] = [
    { key: "name", header: "Application", sort: (e) => e.name.toLowerCase(), cell: (e) => <span className="font-medium text-fg">{e.name}</span> },
    { key: "version", header: "Version", sort: (e) => e.version, cell: (e) => <Mono className="text-muted">{e.version || "—"}</Mono> },
    { key: "publisher", header: "Publisher", sort: (e) => e.publisher.toLowerCase(), cell: (e) => <span className="text-muted">{e.publisher || "—"}</span> },
    { key: "scope", header: "Installed for", sort: (e) => (e.registry_view === "user" ? `1${e.user}` : "0"), cell: (e) => <Scope e={e} /> },
    { key: "view", header: "Registry", sort: (e) => e.registry_view, cell: (e) => <span className="text-faint">{e.registry_view === "user" ? "user" : `${e.registry_view}-bit`}</span> },
  ];

  return (
    <Panel bodyClassName="p-0">
      <Toolbar>
        <Segmented
          label="Software view"
          value={view}
          onChange={setView}
          options={[
            { value: "installed", label: `Installed ${d.entries.length}` },
            { value: "changes", label: `Changes ${d.history.length}` },
            { value: "deployments", label: "App deployments" },
          ]}
        />
        {view !== "deployments" ? (
          <>
            <SearchInput value={filter} onChange={setFilter} placeholder="Filter by name, version, publisher or user" />
            {state ? <Badge tone={state.tone}>{state.label}</Badge> : null}
            <SkippedBadge count={d.skipped} one="entry" many="entries" />
            <div className="flex-1" />
            <span className="text-[12px] text-muted">
              <Tip label="Per-user installs are read only for users signed in when the inventory is collected.">
                <span>
                  Machine-wide installs{d.users.length ? ` + per-user for ${d.users.length} signed-in user${d.users.length === 1 ? "" : "s"}` : ""}
                </span>
              </Tip>{" "}
              · snapshot {d.info.snapshot_at ? relativeTime(d.info.snapshot_at) : "never"}
            </span>
          </>
        ) : null}
      </Toolbar>
      {view === "deployments" ? (
        <DeploymentsTable device={deviceId} compact />
      ) : view === "installed" ? (
        <DataTable columns={columns} rows={entries} rowKey={(e) => e.id} dense initialSort={{ key: "name", dir: "asc" }} empty={<EmptyState title={d.entries.length ? "No applications match" : "No software inventory reported"} />} />
      ) : changes.length === 0 ? (
        <EmptyState title="No observed changes">
          {d.info.baseline_ready ? `Changes from the last ${d.history_days} days appear here.` : "Changes are recorded after the first complete inventory."}
        </EmptyState>
      ) : (
        <ul className="divide-y divide-border">
          {changes.map((c) => {
            const k = changeKinds[c.kind];
            const entry = c.after ?? c.before;
            return (
              <li key={c.id} className="flex items-center gap-3 px-4 py-2.5">
                <Badge tone={k.tone}>{k.label}</Badge>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium text-fg">{entry?.name}</div>
                  <div className="text-[12px] text-muted">
                    {c.kind === "version_changed" ? (
                      <>
                        <Mono>{c.before?.version || "—"}</Mono> → <Mono>{c.after?.version || "—"}</Mono>
                      </>
                    ) : (
                      <>
                        <Mono>{entry?.version || "—"}</Mono>
                        {entry?.publisher ? ` · ${entry.publisher}` : ""}
                      </>
                    )}
                    {entry?.registry_view === "user" ? <span className="text-faint"> · for {entry.user}</span> : null}
                  </div>
                </div>
                <Tip label={`Observed between ${absoluteTime(c.from_at)} and ${absoluteTime(c.observed_at)}`}>
                  <span className="text-[12px] text-muted">{relativeTime(c.observed_at)}</span>
                </Tip>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
