import { useEffect, useState } from "react";

/** Current time, refreshed on an interval so relative times stay accurate. */
export function useNow(intervalMs = 5000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

/** Live data refresh interval used by list and detail pages. */
export const LIVE_INTERVAL = 10_000;
