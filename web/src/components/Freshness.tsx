import { useNow } from "../lib/hooks";
import { relativeTime } from "../lib/format";
import { Dot, Tip } from "./ui";

/** Shows whether a live view is current: green when updating, amber when a refresh failed. */
export function Freshness({ updatedAt, failed }: { updatedAt: number; failed?: boolean }) {
  const now = useNow(1000);
  const seconds = updatedAt ? Math.floor(updatedAt / 1000) : 0;
  return (
    <Tip label={failed ? "The last refresh failed. Showing the most recent data." : "Updates automatically"}>
      {/* A fixed minimum width and no wrapping: the ticking text must not
          change the width, or a header that just fits wraps on and off. */}
      <span className="inline-flex min-w-[8.5rem] items-center gap-1.5 text-[12px] whitespace-nowrap text-muted tabular-nums">
        <Dot tone={failed ? "warn" : "ok"} pulse={!failed} />
        {failed ? "Connection problem · " : "Live · "}
        {seconds ? relativeTime(seconds, now) : "loading"}
      </span>
    </Tip>
  );
}
