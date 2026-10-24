import { useNow } from "../lib/hooks";
import { relativeTime } from "../lib/format";
import { Dot, Tip } from "./ui";

/** Shows whether a live view is current: green when updating, amber when a refresh failed. */
export function Freshness({ updatedAt, failed }: { updatedAt: number; failed?: boolean }) {
  const now = useNow(1000);
  const seconds = updatedAt ? Math.floor(updatedAt / 1000) : 0;
  return (
    <Tip label={failed ? "The last refresh failed. Showing the most recent data." : "Updates automatically"}>
      <span className="inline-flex items-center gap-1.5 text-[12px] text-muted" aria-live="polite">
        <Dot tone={failed ? "warn" : "ok"} pulse={!failed} />
        {failed ? "Connection problem · " : "Live · "}
        {seconds ? relativeTime(seconds, now) : "loading"}
      </span>
    </Tip>
  );
}
