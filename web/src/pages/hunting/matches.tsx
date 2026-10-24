import { useMemo, useState } from "react";
import type { HuntMatch, HuntResult, Indicator } from "../../lib/types";
import { Badge, EmptyState, Mono, SearchInput } from "../../components/ui";

// Indicator hunt matches, for one device (action viewer) or many
// (hunt page, with a device column).

export const areas: Record<HuntMatch["area"], string> = { file: "File", process: "Process", connection: "Connection", dns: "DNS cache", persistence: "Persistence" };
export const indicatorTypes: Record<Indicator["type"], string> = {
  sha256: "SHA-256",
  sha1: "SHA-1",
  md5: "MD5",
  name: "Name",
  path: "Path",
  ip: "IP address",
  domain: "Domain",
  cmd: "Command line",
};

export function IndicatorText({ i }: { i?: Indicator }) {
  if (!i) return <span className="text-faint">—</span>;
  return (
    <span className="inline-flex max-w-full items-baseline gap-1.5">
      <span className="shrink-0 text-[11px] text-faint">{indicatorTypes[i.type]}</span>
      <span className="truncate" title={i.value}>
        <Mono className="text-[11.5px] text-fg">{i.type === "sha256" || i.type === "sha1" || i.type === "md5" ? `${i.value.slice(0, 16)}…` : i.value}</Mono>
      </span>
    </span>
  );
}

function what(m: HuntMatch): string {
  switch (m.area) {
    case "file":
      return m.path ?? "";
    case "process":
      return `${m.name ?? ""} (PID ${m.pid ?? "?"})${m.path ? ` · ${m.path}` : ""}`;
    case "connection":
      return m.detail ?? m.address ?? "";
    case "dns":
      return `${m.name ?? ""}${m.address ? ` → ${m.address}` : ""}`;
    case "persistence":
      return `${m.detail ?? ""} · ${m.name ?? ""}`;
  }
}

export type MatchRow = HuntMatch & { hostname?: string };

export function MatchesTable({ rows, devices }: { rows: MatchRow[]; devices?: boolean }) {
  const [filter, setFilter] = useState("");
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return rows.filter((m) => !f || [m.hostname, m.indicator?.value, m.path, m.name, m.command, m.address, m.user, m.sha256, m.detail].some((v) => String(v ?? "").toLowerCase().includes(f))).slice(0, 5000);
  }, [rows, filter]);
  return (
    <div>
      <SearchInput value={filter} onChange={setFilter} placeholder="Filter matches" label="Filter matches" className="mb-3 max-w-md" />
      {shown.length === 0 ? (
        <EmptyState title={rows.length ? "No matches fit the filter" : "No matches"} />
      ) : (
        <table className="w-full border-collapse text-left text-[12.5px]">
          <thead className="sticky top-0 bg-surface">
            <tr className="border-b border-border text-[11.5px] font-semibold tracking-wide text-faint uppercase">
              {devices ? <th className="px-2 py-1.5">Device</th> : null}
              <th className="px-2 py-1.5">Found in</th>
              <th className="px-2 py-1.5">Indicator</th>
              <th className="px-2 py-1.5">What matched</th>
              <th className="px-2 py-1.5">Details</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((m, i) => (
              <tr key={i} className="border-b border-border align-top hover:bg-surface-2">
                {devices ? <td className="px-2 py-1.5 font-medium whitespace-nowrap text-fg">{m.hostname}</td> : null}
                <td className="px-2 py-1.5 whitespace-nowrap">
                  <Badge tone={m.area === "file" || m.area === "process" ? "danger" : "warn"}>{areas[m.area] ?? m.area}</Badge>
                </td>
                <td className="max-w-64 px-2 py-1.5">
                  <IndicatorText i={m.indicator} />
                </td>
                <td className="max-w-xl px-2 py-1.5">
                  <Mono className="text-[11.5px] break-all text-fg">{what(m)}</Mono>
                  {m.command && m.area !== "connection" ? <div className="mt-0.5 line-clamp-3 font-mono text-[11px] break-all text-muted">{m.command}</div> : null}
                </td>
                <td className="px-2 py-1.5 text-[11.5px] text-muted">
                  {m.sha256 ? (
                    <span className="block" title={m.sha256}>
                      <Mono className="text-[11px]">SHA-256 {m.sha256.slice(0, 16)}…</Mono>
                    </span>
                  ) : null}
                  {typeof m.size === "number" ? <span className="block">{m.size.toLocaleString()} bytes</span> : null}
                  {m.modified ? <span className="block">modified {m.modified.replace("T", " ").slice(0, 19)} UTC</span> : null}
                  {m.user ? <span className="block">{m.user}</span> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {rows.length > shown.length ? <p className="mt-2 text-[12px] text-faint">Showing {shown.length} of {rows.length}; narrow the filter to see others.</p> : null}
    </div>
  );
}

/** What one device searched, for a result's header. */
export function Scanned({ r }: { r: HuntResult }) {
  const s = r.scanned;
  const parts = [
    s.processes ? `${s.processes} processes` : "",
    s.connections ? `${s.connections} connections` : "",
    s.dns ? `${s.dns} DNS records` : "",
    s.persistence ? `${s.persistence} autostart entries` : "",
    s.files ? `${s.files.toLocaleString()} files (${s.hashed.toLocaleString()} hashed)` : "",
  ].filter(Boolean);
  return (
    <p className="text-[12px] text-muted">
      Searched {parts.join(", ") || "nothing"}
      {r.skipped ? ` · ${r.skipped.toLocaleString()} files or folders skipped (larger than 100 MB or unreadable)` : ""}
      {r.outcome === "partial" ? " · stopped at the 15-minute limit: the rest of the files were not searched" : ""}
      {r.more ? " · more than 1,000 matches; the rest are not listed" : ""}
    </p>
  );
}
