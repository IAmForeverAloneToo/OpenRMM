import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { get } from "../../lib/api";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { GroupMember, LocalAccount, LocalAccountsResponse } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, EmptyState, ErrorNotice, Mono, Panel, SearchInput, Spinner, Tip, Toolbar } from "../../components/ui";
import { SkippedBadge } from "./SkippedBadge";
import { snapshotState } from "../../components/status";

// Local accounts and the members of the privileged groups.

const kinds: Record<GroupMember["kind"], string> = { user: "User", group: "Group", well_known: "Built-in", computer: "Computer", deleted: "Deleted account", other: "Other" };

function When({ at, never }: { at: number; never: string }) {
  if (!at) return <span className="text-faint">{never}</span>;
  return (
    <Tip label={absoluteTime(at)}>
      <span className="text-muted tabular-nums">{relativeTime(at)}</span>
    </Tip>
  );
}

export function LocalAccountsPanel({ deviceId, view, views }: { deviceId: string; view: "accounts" | "groups"; views: React.ReactNode }) {
  const [filter, setFilter] = useState("");
  const q = useQuery({ queryKey: ["local-accounts", deviceId], queryFn: ({ signal }) => get<LocalAccountsResponse>(`/api/v1/devices/${deviceId}/local-accounts`, signal), refetchInterval: LIVE_INTERVAL * 6 });
  const term = filter.trim().toLowerCase();
  const admins = useMemo(() => new Set((q.data?.groups.find((g) => g.key === "administrators")?.members ?? []).map((m) => m.sid)), [q.data]);
  const remote = useMemo(() => new Set((q.data?.groups.find((g) => g.key === "remote_desktop_users")?.members ?? []).map((m) => m.sid)), [q.data]);
  const accounts = useMemo(() => (q.data?.accounts ?? []).filter((a) => !term || a.name.toLowerCase().includes(term) || a.full_name.toLowerCase().includes(term)), [q.data, term]);

  if (q.isPending) return <Spinner label="Loading local accounts" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const d = q.data!;
  const state = snapshotState(d.info.status, d.info.stale);

  const columns: Column<LocalAccount>[] = [
    {
      key: "name",
      header: "Account",
      sort: (a) => a.name.toLowerCase(),
      cell: (a) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-fg">{a.name}</div>
          {a.full_name ? <div className="truncate text-[11.5px] text-faint">{a.full_name}</div> : null}
        </div>
      ),
    },
    {
      key: "state",
      header: "State",
      sort: (a) => (a.enabled ? 0 : 1),
      cell: (a) => (
        <div className="flex flex-wrap gap-1">
          {a.enabled ? <Badge tone="ok" dot>Enabled</Badge> : <Badge tone="neutral">Disabled</Badge>}
          {a.locked_out ? <Badge tone="danger">Locked out</Badge> : null}
        </div>
      ),
    },
    {
      key: "groups",
      header: "Privileged groups",
      sort: (a) => (admins.has(a.sid) ? 0 : remote.has(a.sid) ? 1 : 2),
      cell: (a) => (
        <div className="flex flex-wrap gap-1">
          {admins.has(a.sid) ? <Badge tone="warn">Administrators</Badge> : null}
          {remote.has(a.sid) ? <Badge tone="info">Remote Desktop Users</Badge> : null}
          {!admins.has(a.sid) && !remote.has(a.sid) ? <span className="text-faint">—</span> : null}
        </div>
      ),
    },
    {
      key: "password",
      header: "Password set",
      sort: (a) => a.password_last_set_at,
      cell: (a) => (
        <div className="flex flex-wrap items-center gap-1.5">
          <When at={a.password_last_set_at} never="Unknown" />
          {a.password_never_expires ? <Badge tone="neutral">Never expires</Badge> : null}
          {a.password_expired ? <Badge tone="warn">Expired</Badge> : null}
        </div>
      ),
    },
    { key: "logon", header: "Last logon", sort: (a) => a.last_logon_at, cell: (a) => <When at={a.last_logon_at} never="Never or unknown" /> },
    { key: "sid", header: "SID", sort: (a) => a.sid, cell: (a) => <Mono className="text-[11.5px] text-faint">{a.sid}</Mono> },
  ];
  const memberColumns: Column<GroupMember>[] = [
    { key: "name", header: "Member", sort: (m) => (m.name || m.sid).toLowerCase(), cell: (m) => <span className="font-medium text-fg">{m.name || <span className="text-faint">Unresolved</span>}</span> },
    { key: "kind", header: "Type", sort: (m) => m.kind, cell: (m) => (m.kind === "deleted" ? <Badge tone="warn">{kinds[m.kind]}</Badge> : <span className="text-muted">{kinds[m.kind]}</span>) },
    { key: "sid", header: "SID", sort: (m) => m.sid, cell: (m) => <Mono className="text-[11.5px] text-faint">{m.sid}</Mono> },
  ];

  return (
    <Panel bodyClassName="p-0">
      <Toolbar>
        {views}
        {view === "accounts" ? <SearchInput value={filter} onChange={setFilter} placeholder="Filter by account" /> : null}
        {state ? <Badge tone={state.tone}>{state.label}</Badge> : null}
        <SkippedBadge count={d.skipped} one="account" many="accounts" />
        <div className="flex-1" />
        <span className="text-[12px] text-muted">Reported every 15 minutes · snapshot {d.info.snapshot_at ? relativeTime(d.info.snapshot_at) : "never"}</span>
      </Toolbar>
      {view === "accounts" ? (
        <>
          <DataTable
            columns={columns}
            rows={accounts}
            rowKey={(a) => a.sid}
            dense
            initialSort={{ key: "name", dir: "asc" }}
            empty={<EmptyState title={d.accounts.length ? "No accounts match" : d.info.has_snapshot ? "No local accounts" : "No local accounts reported"} />}
          />
          <p className="border-t border-border px-4 py-2 text-[12px] text-faint">Windows records the last logon on this machine only; network and cached logons can be missing.</p>
        </>
      ) : d.groups.length === 0 ? (
        <EmptyState title="No privileged groups reported" />
      ) : (
        <div className="divide-y divide-border">
          {d.groups.map((g) => (
            <div key={g.key}>
              <div className="flex items-center gap-2 px-4 py-2 text-[12.5px] font-medium text-fg">
                {g.key === "administrators" ? "Administrators" : "Remote Desktop Users"}
                {g.name && g.name !== (g.key === "administrators" ? "Administrators" : "Remote Desktop Users") ? <span className="text-faint">({g.name})</span> : null}
                <Badge tone="neutral">{g.members.length}</Badge>
                <SkippedBadge count={g.skipped ?? 0} one="member" many="members" />
              </div>
              <DataTable columns={memberColumns} rows={g.members} rowKey={(m) => m.sid} dense initialSort={{ key: "name", dir: "asc" }} empty={<EmptyState title={g.name ? "No members" : "This group does not exist on the device"} />} />
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
