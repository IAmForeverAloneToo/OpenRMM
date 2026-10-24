import { absoluteTime, relativeTime } from "../../lib/format";
import { useNow } from "../../lib/hooks";
import { Panel, Tip } from "../../components/ui";
import { OperationStatus } from "../../components/status";

export type HistoryRow = { id: string; label: string; actor: string; status: string; outcome?: string; at: number };

/** Recent operations for one tool, newest first. */
export function ActionHistory({ title, rows }: { title: string; rows: HistoryRow[] }) {
  const now = useNow();
  if (rows.length === 0) return null;
  return (
    <Panel title={title} bodyClassName="p-0">
      <ul className="divide-y divide-border">
        {rows.slice(0, 10).map((r) => (
          <li key={r.id} className="flex items-center gap-3 px-4 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="truncate text-fg">{r.label}</div>
              <div className="text-[12px] text-faint">
                by {r.actor}
                {r.outcome && r.outcome !== r.status ? ` · ${r.outcome.replaceAll("_", " ")}` : ""}
              </div>
            </div>
            <OperationStatus status={r.status} />
            <Tip label={absoluteTime(r.at)}>
              <span className="w-16 text-right text-[12px] text-muted tabular-nums">{relativeTime(r.at, now)}</span>
            </Tip>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
