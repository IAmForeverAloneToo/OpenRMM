import { Badge, Tip } from "../../components/ui";

// Shown next to collected data when the agent left unreadable items out
// instead of failing the whole collection.
export function SkippedBadge({ count, one, many }: { count: number | null | undefined; one: string; many: string }) {
  if (!count || count <= 0) return null;
  return (
    <Tip label="Some items could not be read and were left out">
      <span>
        <Badge tone="warn">
          {count.toLocaleString()} {count === 1 ? one : many} skipped
        </Badge>
      </span>
    </Tip>
  );
}
