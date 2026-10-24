import type { RemoteDisplay } from "./types";

// Remote desktop display and quality choices, made in the dashboard at the
// start of and during the session.

export const qualityNames: Record<string, string> = {
  bandwidth: "Low bandwidth (960 × 540)",
  balanced: "Balanced (1280 × 720)",
  detail: "Detail (1280 × 720, sharper)",
};

export function displayName(d: RemoteDisplay): string {
  if (!d.width) return "Primary display";
  return `${d.primary ? "Primary display" : `Display ${d.index + 1}`} (${d.width} × ${d.height})`;
}
