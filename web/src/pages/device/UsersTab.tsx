import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { get } from "../../lib/api";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { absoluteTime, duration, relativeTime } from "../../lib/format";
import type { SessionRecord, SessionsResponse, WindowsSession } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, EmptyState, ErrorNotice, Mono, Panel, SearchInput, Segmented, Spinner, Tip, Toolbar } from "../../components/ui";
import { SkippedBadge } from "./SkippedBadge";
import { snapshotState } from "../../components/status";
import { LocalAccountsPanel } from "./LocalAccountsPanel";
import { LogonsPanel } from "./LogonsPanel";

// Signed-in Windows sessions and the sessions the agent observed.

const connections: Record<WindowsSession["connection"], string> = { console: "Console", rdp: "Remote Desktop", other: "Other" };

function account(s: WindowsSession): string {
  return s.domain ? `${s.domain}\\${s.user}` : s.user;
}
function client(s: WindowsSession): string {
  return [s.client_name, s.client_address].filter(Boolean).join(" · ") || "—";
}
function matches(s: WindowsSession, t: string): boolean {
  return account(s).toLowerCase().includes(t) || s.client_name.toLowerCase().includes(t) || s.client_address.includes(t);
}
function Time({ at }: { at: number | null }) {
  if (!at) return <span className="text-faint">Unknown</span>;
  return (
    <Tip label={absoluteTime(at)}>
      <span className="text-muted tabular-nums">{relativeTime(at)}</span>
    </Tip>
  );
}

export function UsersTab({ deviceId }: { deviceId: string }) {
  const [params, setParams] = useSearchParams();
  type View = "current" | "history" | "logons" | "accounts" | "groups";
  const view: View = (["history", "logons", "accounts", "groups"].includes(params.get("view") ?? "") ? params.get("view") : "current") as View;
  const setView = (v: View) => setParams(v === "current" ? { tab: "users" } : { tab: "users", view: v }, { replace: true });
  const [filter, setFilter] = useState("");
  const q = useQuery({ queryKey: ["sessions", deviceId], queryFn: ({ signal }) => get<SessionsResponse>(`/api/v1/devices/${deviceId}/sessions`, signal), refetchInterval: LIVE_INTERVAL * 3 });
  const term = filter.trim().toLowerCase();
  const current = useMemo(() => (q.data?.sessions ?? []).filter((s) => !term || matches(s, term)), [q.data, term]);
  const history = useMemo(() => (q.data?.history ?? []).filter((r) => !term || matches(r.session, term)), [q.data, term]);

  const views = (
    <Segmented
      label="Users view"
      value={view}
      onChange={setView}
      options={[
        { value: "current", label: `Signed in${q.data ? ` ${q.data.sessions.length}` : ""}` },
        { value: "history", label: `History${q.data ? ` ${q.data.history.length}` : ""}` },
        { value: "logons", label: "Logons" },
        { value: "accounts", label: "Local accounts" },
        { value: "groups", label: "Groups" },
      ]}
    />
  );
  if (view === "logons") return <LogonsPanel deviceId={deviceId} views={views} />;
  if (view === "accounts" || view === "groups") return <LocalAccountsPanel deviceId={deviceId} view={view} views={views} />;
  if (q.isPending) return <Spinner label="Loading signed-in users" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const d = q.data!;
  const state = snapshotState(d.info.status, d.info.stale);

  const sessionColumns: Column<WindowsSession>[] = [
    { key: "user", header: "User", sort: (s) => account(s).toLowerCase(), cell: (s) => <span className="font-medium text-fg">{account(s)}</span> },
    {
      key: "state",
      header: "State",
      sort: (s) => s.state,
      cell: (s) => (s.state === "active" ? <Badge tone="ok" dot>Active</Badge> : s.state === "disconnected" ? <Badge tone="neutral">Disconnected</Badge> : <Badge tone="neutral">Other</Badge>),
    },
    { key: "connection", header: "Connection", sort: (s) => s.connection, cell: (s) => <span className="text-muted">{connections[s.connection]}</span> },
    { key: "client", header: "Client", sort: (s) => client(s), cell: (s) => <Mono className="text-muted">{client(s)}</Mono> },
    { key: "logon", header: "Signed in", sort: (s) => s.logon_at, cell: (s) => <Time at={s.logon_at || null} /> },
    { key: "idle", header: "Idle", sort: (s) => s.idle_seconds, cell: (s) => <span className="text-muted tabular-nums">{s.idle_seconds < 0 ? "Unknown" : duration(s.idle_seconds)}</span> },
    { key: "id", header: "Session", sort: (s) => s.session_id, cell: (s) => <span className="text-faint tabular-nums">{s.session_id}</span> },
  ];
  const historyColumns: Column<SessionRecord>[] = [
    { key: "user", header: "User", sort: (r) => account(r.session).toLowerCase(), cell: (r) => <span className="font-medium text-fg">{account(r.session)}</span> },
    { key: "connection", header: "Connection", sort: (r) => r.session.connection, cell: (r) => <span className="text-muted">{connections[r.session.connection]}</span> },
    { key: "client", header: "Client", sort: (r) => client(r.session), cell: (r) => <Mono className="text-muted">{client(r.session)}</Mono> },
    { key: "logon", header: "Signed in", sort: (r) => r.session.logon_at, cell: (r) => <Time at={r.session.logon_at || null} /> },
    { key: "first", header: "First seen", sort: (r) => r.first_seen_at, cell: (r) => <Time at={r.first_seen_at} /> },
    { key: "last", header: "Last seen", sort: (r) => r.last_seen_at, cell: (r) => <Time at={r.last_seen_at} /> },
    {
      key: "ended",
      header: "Gone by",
      sort: (r) => r.ended_at ?? Number.MAX_SAFE_INTEGER,
      cell: (r) => (r.ended_at ? <Time at={r.ended_at} /> : <Badge tone="ok" dot>Still signed in</Badge>),
    },
  ];

  return (
    <Panel bodyClassName="p-0">
      <Toolbar>
        {views}
        <SearchInput value={filter} onChange={setFilter} placeholder="Filter by user or client" />
        {state ? <Badge tone={state.tone}>{state.label}</Badge> : null}
        <SkippedBadge count={d.info.skipped} one="session" many="sessions" />
        <div className="flex-1" />
        <span className="text-[12px] text-muted">Reported every minute · snapshot {d.info.snapshot_at ? relativeTime(d.info.snapshot_at) : "never"}</span>
      </Toolbar>
      {view === "current" ? (
        <DataTable
          columns={sessionColumns}
          rows={current}
          rowKey={(s) => String(s.session_id)}
          dense
          initialSort={{ key: "user", dir: "asc" }}
          empty={<EmptyState title={d.sessions.length ? "No sessions match" : d.info.has_snapshot ? "Nobody is signed in" : "No sessions reported"} />}
        />
      ) : (
        <>
          <DataTable
            columns={historyColumns}
            rows={history}
            rowKey={(r) => String(r.id)}
            dense
            initialSort={{ key: "last", dir: "desc" }}
            empty={<EmptyState title="No observed sessions">Sessions the agent observed in the last {d.history_days} days appear here.</EmptyState>}
          />
          <p className="border-t border-border px-4 py-2 text-[12px] text-faint">
            Observed by the agent every minute, not a Windows logon audit: “gone by” is the first report without the session. The newest {d.history_limit} of the last {d.history_days} days are shown.
          </p>
        </>
      )}
    </Panel>
  );
}
