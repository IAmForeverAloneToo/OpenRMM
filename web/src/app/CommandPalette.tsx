import { useEffect, useMemo, useRef, useState } from "react";
import * as D from "@radix-ui/react-dialog";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { CornerDownLeft, Monitor, Search } from "lucide-react";
import { get } from "../lib/api";
import type { DevicesResponse } from "../lib/types";
import type { NavSection } from "./nav";
import { cx } from "../components/ui";
import { DeviceStatusBadge } from "../components/status";

type Result = { key: string; label: string; detail?: string; to: string; kind: "page" | "device"; device?: DevicesResponse["devices"][number] };

/** Jump to any page or device. Selecting a result only navigates. */
export function CommandPalette({ open, onOpenChange, sections }: { open: boolean; onOpenChange: (o: boolean) => void; sections: NavSection[] }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => get<DevicesResponse>("/api/v1/devices", signal), enabled: open, staleTime: 10_000 });

  const results = useMemo<Result[]>(() => {
    const q = query.trim().toLowerCase();
    const pages: Result[] = sections
      .flatMap((s) => s.items)
      .filter((i) => i.state === "ready")
      .filter((i) => !q || i.label.toLowerCase().includes(q))
      .map((i) => ({ key: "page:" + i.to, label: i.label, to: i.to, kind: "page" }));
    const list = devices.data?.devices ?? [];
    const matched = list
      .filter((d) => !q || d.hostname.toLowerCase().includes(q) || d.id.startsWith(q) || (d.group_name ?? "").toLowerCase().includes(q) || (d.tags ?? []).some((t) => t.includes(q)))
      .slice(0, 8)
      .map<Result>((d) => ({ key: "device:" + d.id, label: d.hostname, detail: d.group_name, to: "/devices/" + d.id, kind: "device", device: d }));
    return [...pages, ...matched];
  }, [query, sections, devices.data]);

  useEffect(() => setIndex(0), [query]);
  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);
  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${index}"]`)?.scrollIntoView({ block: "nearest" });
  }, [index]);

  const go = (r: Result | undefined) => {
    if (!r) return;
    onOpenChange(false);
    navigate(r.to);
  };

  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-[var(--overlay)]" />
        <D.Content className="fixed top-[14vh] left-1/2 z-50 w-[calc(100vw-2rem)] max-w-xl -translate-x-1/2 overflow-hidden rounded-lg border border-border-strong bg-surface shadow-panel focus:outline-none">
          <D.Title className="sr-only">Search</D.Title>
          <D.Description className="sr-only">Search devices and pages, then press Enter to open.</D.Description>
          <div className="flex items-center gap-2 border-b border-border px-3">
            <Search className="size-4 text-faint" aria-hidden />
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setIndex((i) => Math.min(i + 1, results.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setIndex((i) => Math.max(i - 1, 0));
                } else if (e.key === "Enter") {
                  e.preventDefault();
                  go(results[index]);
                }
              }}
              placeholder="Search devices, groups, tags or pages"
              className="h-12 flex-1 bg-transparent text-[14px] text-fg placeholder:text-faint focus:outline-none"
              aria-label="Search"
              maxLength={100}
            />
          </div>
          <div ref={listRef} className="max-h-[50vh] overflow-y-auto p-1.5" role="listbox">
            {results.length === 0 ? <p className="px-3 py-6 text-center text-muted">No matches</p> : null}
            {results.map((r, i) => (
              <button
                key={r.key}
                type="button"
                role="option"
                aria-selected={i === index}
                data-index={i}
                onMouseMove={() => setIndex(i)}
                onClick={() => go(r)}
                className={cx("flex w-full items-center gap-3 rounded-md px-2.5 py-2 text-left", i === index ? "bg-surface-2" : "")}
              >
                {r.kind === "device" ? <Monitor className="size-4 text-faint" aria-hidden /> : <CornerDownLeft className="size-4 text-faint" aria-hidden />}
                <span className="flex-1 truncate text-fg">{r.label}</span>
                {r.detail ? <span className="truncate text-[12px] text-faint">{r.detail}</span> : null}
                {r.device ? <DeviceStatusBadge status={r.device.status} /> : <span className="text-[12px] text-faint">Page</span>}
              </button>
            ))}
          </div>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
