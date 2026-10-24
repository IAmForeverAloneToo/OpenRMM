import { useEffect, useState, type ReactNode } from "react";
import { keepPreviousData, useInfiniteQuery } from "@tanstack/react-query";
import { get } from "../../lib/api";
import { LIVE_INTERVAL } from "../../lib/hooks";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { Logon, LogonsResponse } from "../../lib/types";
import { DataTable, type Column } from "../../components/DataTable";
import { Badge, Button, EmptyState, ErrorNotice, Mono, Panel, SearchInput, Select, Spinner, Tip, Toolbar } from "../../components/ui";
import { snapshotState } from "../../components/status";

// Logons from the Windows Security log (event 4624), collected
// every five minutes and kept 365 days.

const types: Record<Logon["type"], string> = {
  interactive: "Interactive",
  cached: "Interactive (cached)",
  remote: "Remote Desktop",
  network: "Network",
  network_cleartext: "Network (cleartext)",
};

function account(l: Logon): string {
  return l.domain ? `${l.domain}\\${l.user}` : l.user;
}

export function LogonsPanel({ deviceId, views }: { deviceId: string; views: ReactNode }) {
  const [filter, setFilter] = useState("");
  const [term, setTerm] = useState("");
  const [kind, setKind] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setTerm(filter.trim()), 300);
    return () => clearTimeout(t);
  }, [filter]);
  const q = useInfiniteQuery({
    queryKey: ["logons", deviceId, term, kind],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = new URLSearchParams();
      if (term) p.set("q", term);
      if (kind) p.set("kind", kind);
      if (pageParam) p.set("before", pageParam);
      return get<LogonsResponse>(`/api/v1/devices/${deviceId}/logons?${p}`, signal);
    },
    getNextPageParam: (last) => {
      const l = last.logons[last.logons.length - 1];
      return last.more && l ? `${l.time}:${l.record_id}` : undefined;
    },
    placeholderData: keepPreviousData,
    // Refetching an infinite query reloads every page: refresh only while one
    // page is shown.
    refetchInterval: (query) => ((query.state.data?.pages.length ?? 1) > 1 ? false : LIVE_INTERVAL * 6),
  });

  const toolbar = (extra?: ReactNode) => (
    <Toolbar>
      {views}
      <SearchInput value={filter} onChange={setFilter} placeholder="Filter by user, source or workstation" />
      <Select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Logon type">
        <option value="">All logon types</option>
        <option value="interactive">Interactive</option>
        <option value="remote">Remote Desktop</option>
        <option value="network">Network</option>
      </Select>
      {extra}
    </Toolbar>
  );
  if (q.isPending) return <Spinner label="Loading logon history" />;
  if (q.isError && !q.data) return <ErrorNotice error={q.error} retry={() => void q.refetch()} />;
  const first = q.data.pages[0];
  if (!first) return <Spinner label="Loading logon history" />;
  const rows = q.data.pages.flatMap((p) => p.logons);
  const info = first.info;
  const state = info.status === "not_reported" ? { label: "Not reported", tone: "neutral" as const } : snapshotState(info.status, false);

  const columns: Column<Logon>[] = [
    {
      key: "time",
      header: "Logon",
      sort: (l) => l.time * 1e6 + (l.record_id % 1e6),
      cell: (l) => (
        <Tip label={absoluteTime(l.time)}>
          <span className="text-muted tabular-nums">{relativeTime(l.time)}</span>
        </Tip>
      ),
    },
    {
      key: "user",
      header: "User",
      sort: (l) => account(l).toLowerCase(),
      cell: (l) => (
        <Tip label={l.sid || "No SID"}>
          <span className="font-medium text-fg">
            {account(l)}
            {l.elevated ? <Badge className="ml-1.5">Elevated</Badge> : null}
          </span>
        </Tip>
      ),
    },
    { key: "type", header: "Type", sort: (l) => l.type, cell: (l) => (l.type === "network_cleartext" ? <Badge tone="warn">{types[l.type]}</Badge> : <span className="text-muted">{types[l.type]}</span>) },
    {
      key: "source",
      header: "Source",
      sort: (l) => l.source_ip || l.workstation,
      cell: (l) =>
        l.source_ip || l.workstation ? (
          <span className="whitespace-nowrap text-muted">
            {l.source_ip ? <Mono>{l.source_ip}</Mono> : null}
            {l.source_ip && l.workstation ? " · " : null}
            {l.workstation}
          </span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    { key: "auth", header: "Authentication", sort: (l) => l.auth_package, cell: (l) => <span className="text-muted">{[l.auth_package, l.logon_process].filter(Boolean).join(" · ") || "—"}</span> },
    { key: "id", header: "Logon ID", sort: (l) => l.logon_id, cell: (l) => <Mono className="text-[11.5px] text-faint">{l.logon_id || "—"}</Mono> },
  ];

  return (
    <Panel bodyClassName="p-0">
      {toolbar(
        <>
          {state ? <Badge tone={state.tone}>{state.label}</Badge> : null}
          {info.more ? (
            <Tip label="The agent is still sending older logons from the Security log, five hundred every five minutes.">
              <span>
                <Badge tone="info">Catching up</Badge>
              </span>
            </Tip>
          ) : null}
          <div className="flex-1" />
          <span className="text-[12px] text-muted">Collected every 5 minutes · last {info.collected_at ? relativeTime(info.collected_at) : "never"}</span>
        </>,
      )}
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(l) => `${l.time}:${l.record_id}`}
        dense
        initialSort={{ key: "time", dir: "desc" }}
        empty={
          <EmptyState title={term || kind ? "No logons match" : "No logons recorded"}>
            Successful interactive, Remote Desktop and network logons from the device's Security log appear here.
          </EmptyState>
        }
      />
      <div className="flex flex-wrap items-center gap-3 border-t border-border px-4 py-2 text-[12px] text-faint">
        <span>
          From the Windows Security log (event 4624), kept {first.days} days. Logons by the system, services and computer accounts are left out. A first collection reads the last 30 days.
        </span>
        <div className="flex-1" />
        {q.hasNextPage ? (
          <Button size="sm" variant="ghost" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
            {q.isFetchingNextPage ? "Loading…" : `Load older (${rows.length} shown)`}
          </Button>
        ) : null}
      </div>
    </Panel>
  );
}
