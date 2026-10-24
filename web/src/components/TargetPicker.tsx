import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { get } from "../lib/api";
import type { DevicesResponse, FleetDevice } from "../lib/types";
import { EmptyState, SearchInput, Spinner, cx } from "./ui";
import { DeviceStatusBadge } from "./status";

export const MAX_TARGETS = 25;
export type Targets = { devices: string[]; groups: string[] };

/**
 * Device and group selection for fleet operations. Group members are resolved
 * by the server at review time; the combined count is capped at 25.
 */
// max: how many devices and groups may be chosen (fleet log search allows
// more than the default 25 and offers selecting every listed device).
export function TargetPicker({ value, onChange, include, height = "max-h-[420px]", max = MAX_TARGETS }: { value: Targets; onChange: (v: Targets) => void; include?: (d: FleetDevice) => boolean; height?: string; max?: number }) {
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal) });
  const [filter, setFilter] = useState("");
  const list = useMemo(() => {
    const t = filter.trim().toLowerCase();
    return (devices.data?.devices ?? []).filter((d) => d.status !== "revoked" && (!include || include(d)) && (!t || d.hostname.toLowerCase().includes(t) || (d.group_name ?? "").toLowerCase().includes(t)));
  }, [devices.data, filter, include]);
  const count = value.devices.length + value.groups.length;
  const toggle = (key: keyof Targets, id: string) => {
    const set = new Set(value[key]);
    if (set.has(id)) set.delete(id);
    else if (count < max) set.add(id);
    onChange({ ...value, [key]: [...set] });
  };
  return (
    <div className="overflow-hidden rounded-md border border-border">
      <div className="flex items-center justify-between gap-3 border-b border-border px-3 py-2">
        <SearchInput value={filter} onChange={setFilter} placeholder="Filter devices" />
        {max > MAX_TARGETS ? (
          <button type="button" className="shrink-0 text-[12px] text-accent hover:underline" onClick={() => onChange({ ...value, devices: [...new Set([...value.devices, ...list.map((d) => d.id)])].slice(0, max - value.groups.length) })}>
            Select all shown
          </button>
        ) : null}
        <span className={cx("shrink-0 text-[12px]", count >= max ? "text-warn" : "text-muted")}>
          {count} of {max}
        </span>
      </div>
      {(devices.data?.groups ?? []).length ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
          <span className="text-[12px] text-muted">Groups:</span>
          {devices.data!.groups.map((g) => (
            <button
              key={g.id}
              type="button"
              aria-pressed={value.groups.includes(g.id)}
              onClick={() => toggle("groups", g.id)}
              className={cx("rounded-md border px-2 py-0.5 text-[12.5px]", value.groups.includes(g.id) ? "border-accent bg-accent-soft text-fg" : "border-border text-muted hover:border-border-strong")}
            >
              {g.name}
            </button>
          ))}
        </div>
      ) : null}
      {devices.isPending ? (
        <div className="p-4">
          <Spinner label="Loading devices" />
        </div>
      ) : list.length === 0 ? (
        <EmptyState title="No devices match" />
      ) : (
        <ul className={cx("divide-y divide-border overflow-y-auto", height)}>
          {list.map((d) => (
            <li key={d.id}>
              <label className="flex cursor-pointer items-center gap-3 px-3 py-1.5 hover:bg-surface-2">
                <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={value.devices.includes(d.id)} onChange={() => toggle("devices", d.id)} />
                <span className="flex-1 truncate text-fg">{d.hostname}</span>
                <span className="text-[12px] text-faint">{d.group_name ?? "Ungrouped"}</span>
                <DeviceStatusBadge status={d.status} />
              </label>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Hostname lookup for rows that carry only a device ID. */
export function useHostnames(): Map<string, string> {
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal) });
  return useMemo(() => new Map((devices.data?.devices ?? []).map((d) => [d.id, d.hostname])), [devices.data]);
}
